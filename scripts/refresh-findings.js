import { appendFile, access, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { GalleryClient } from '../scanner/gallery.js';
import {
  buildFindingsRefreshCheckpoint,
  FINDINGS_REFRESH_ID,
  mergeFindingsRefreshCheckpoint,
  mergeFindingsRefreshUpdate,
  removeRetiredFindings,
  runFindingsRefreshBatch,
  startFindingsRefresh,
} from '../scanner/findings-refresh.js';
import { loadLocalState, SITE_PUBLIC_DIRECTORY, writeSnapshot } from '../scanner/state.js';
import { nowIso } from '../scanner/util.js';

function option(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : null;
}

const checkpointDir = resolve(option('--checkpoint-dir') || join(tmpdir(), 'pwsh-findings-refresh-checkpoint'));
const resumeDir = option('--resume-dir') ? resolve(option('--resume-dir')) : null;
const artifactOnly = process.argv.includes('--artifact-only');
const requestedMinutes = Number(option('--max-minutes') || process.env.FINDINGS_REFRESH_MAX_MINUTES || 300);
const maxMinutes = Number.isFinite(requestedMinutes) ? Math.max(1, requestedMinutes) : 300;
const requestedBatchSize = Number(option('--batch-size') || 100);
const batchSize = Number.isFinite(requestedBatchSize) ? Math.max(1, Math.floor(requestedBatchSize)) : 100;

async function* readUpdates(path) {
  try {
    await access(path);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  const lines = createInterface({ input: createReadStream(path), crlfDelay: Infinity });
  for await (const line of lines) {
    if (line.trim()) yield JSON.parse(line);
  }
}

async function saveMetadata(path, checkpoint) {
  const temporary = path + '.tmp';
  await writeFile(temporary, JSON.stringify(checkpoint, null, 2) + '\n', 'utf8');
  await rename(temporary, path);
}

function log(event) {
  process.stdout.write(JSON.stringify({ time: new Date().toISOString(), ...event }) + '\n');
}

async function main() {
  const state = await loadLocalState(SITE_PUBLIC_DIRECTORY);
  if (!state.packages.size) throw new Error('A local API snapshot is required before refreshing findings.');
  await mkdir(checkpointDir, { recursive: true });
  const updatesPath = join(checkpointDir, 'updates.jsonl');
  const metadataPath = join(checkpointDir, 'checkpoint.json');
  let updateCount = 0;
  const failures = [];

  if (resumeDir) {
    const priorMetadata = JSON.parse(await readFile(join(resumeDir, 'checkpoint.json'), 'utf8'));
    if (priorMetadata.id !== FINDINGS_REFRESH_ID) throw new Error('The saved findings checkpoint is for a different ruleset.');
    const merged = mergeFindingsRefreshCheckpoint(state, { ...priorMetadata, updates: [] });
    await writeFile(updatesPath, '', 'utf8');
    const restoredProgress = state.manifest.findingsRefresh;
    const previousCursor = restoredProgress.afterKey || '';
    let uncheckpointedSuccesses = 0;
    let latestRecoveredKey = previousCursor;
    let restoredUpdatesMerged = 0;
    let restoredUpdatesStale = 0;
    for await (const update of readUpdates(join(resumeDir, 'updates.jsonl'))) {
      if (mergeFindingsRefreshUpdate(state, update)) restoredUpdatesMerged++;
      else restoredUpdatesStale++;
      await appendFile(updatesPath, JSON.stringify(update) + '\n', 'utf8');
      updateCount++;
      if (update.key && update.key > previousCursor) {
        uncheckpointedSuccesses++;
        latestRecoveredKey = update.key;
      }
    }
    if (uncheckpointedSuccesses) {
      restoredProgress.processed += uncheckpointedSuccesses;
      restoredProgress.succeeded += uncheckpointedSuccesses;
      restoredProgress.afterKey = latestRecoveredKey;
      restoredProgress.updatedAt = nowIso();
      restoredProgress.active = true;
      restoredProgress.complete = false;
      restoredProgress.completedAt = null;
    }
    removeRetiredFindings(state);
    failures.push(...(priorMetadata.failures || []));
    log({
      event: 'finding_refresh_checkpoint_restored',
      merged: merged.merged + restoredUpdatesMerged,
      stale: merged.stale + restoredUpdatesStale,
      updateCount,
      progress: merged.findingsRefresh,
    });
  } else {
    await writeFile(updatesPath, '', 'utf8');
  }

  const progress = startFindingsRefresh(state);
  const checkpointBase = {
    id: FINDINGS_REFRESH_ID,
    rulesetVersion: state.manifest.findingsRefresh.id.replace(/^finding-rules-/, ''),
    baseGeneratedAt: state.manifest.generatedAt || null,
    baseLastSuccessfulScan: state.manifest.lastSuccessfulScan || null,
    startedAt: progress.startedAt,
  };
  const attemptedKeys = new Set();
  const deadline = Date.now() + maxMinutes * 60_000;
  const gallery = new GalleryClient();

  log({ event: 'finding_refresh_started', progress, batchSize, maxMinutes, packageConcurrency: 1 });
  await saveMetadata(metadataPath, { ...checkpointBase, progress: structuredClone(progress), failures });

  while (progress.active && Date.now() < deadline) {
    const batch = await runFindingsRefreshBatch({
      state,
      gallery,
      batchSize,
      attemptedKeys,
      runPssa: true,
      log,
      onUpdate: async (update) => {
        await appendFile(updatesPath, JSON.stringify(update) + '\n', 'utf8');
        updateCount++;
      },
    });
    failures.push(...batch.failures);
    const checkpoint = buildFindingsRefreshCheckpoint(state, [], failures);
    await saveMetadata(metadataPath, {
      ...checkpointBase,
      ...checkpoint,
      progress: structuredClone(state.manifest.findingsRefresh),
      failures: failures.slice(-100),
      updateCount,
    });
    log({
      event: 'finding_refresh_checkpoint',
      ...state.manifest.findingsRefresh,
      batchProcessed: batch.processed,
      batchSucceeded: batch.succeeded,
      batchFailed: batch.failed,
      remaining: batch.remaining,
    });
    if (!batch.processed || !batch.remaining) break;
  }

  const currentCheckpoint = buildFindingsRefreshCheckpoint(state, [], failures);
  await saveMetadata(metadataPath, {
    ...checkpointBase,
    ...currentCheckpoint,
    progress: structuredClone(state.manifest.findingsRefresh),
    failures: failures.slice(-100),
    updateCount,
    checkpointedAt: nowIso(),
  });

  if (!artifactOnly) {
    removeRetiredFindings(state);
    await writeSnapshot(state, SITE_PUBLIC_DIRECTORY);
  }

  const summary = {
    findingsRefresh: state.manifest.findingsRefresh,
    updateCount,
    failures: failures.length,
    checkpointDir,
    artifactOnly,
  };
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    await appendFile(summaryPath, [
      '# PowerShell findings refresh',
      '',
      '- Ruleset: ' + state.manifest.findingsRefresh.id,
      '- Processed: ' + state.manifest.findingsRefresh.processed + '/' + state.manifest.findingsRefresh.total,
      '- Successfully refreshed: ' + state.manifest.findingsRefresh.succeeded,
      '- Failed attempts: ' + state.manifest.findingsRefresh.failed,
      '- Complete: ' + state.manifest.findingsRefresh.complete,
      '- Resume from the published snapshot on the next run; use this run ID only if this run failed before publishing its checkpoint artifact.',
      '',
    ].join('\n'), 'utf8');
  }
  process.stdout.write(JSON.stringify(summary) + '\n');
}

main().catch((error) => {
  process.stderr.write(JSON.stringify({ time: new Date().toISOString(), error: String(error.message || error) }) + '\n');
  process.exitCode = 1;
});
