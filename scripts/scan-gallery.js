import { appendFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { GalleryClient } from '../scanner/gallery.js';
import { loadLocalState, loadScanState, SITE_PUBLIC_DIRECTORY, writeSnapshot } from '../scanner/state.js';
import { runScanCycle } from '../scanner/scan-cycle.js';
import { loadCuratedAdvisories } from '../scanner/advisories.js';
import { runIncompleteRecoveryBatch, startIncompleteRecovery } from '../scanner/incomplete-recovery.js';
import { prepareLocalRecoveryEnvironment } from '../scanner/local-recovery-preflight.js';

const stateApiUrl = process.env.SCAN_STATE_API_URL
  || 'https://emdashcyber.com/pwsh-package-scanner/api/v1/';
const refreshAdvisories = process.env.REFRESH_ADVISORIES === 'true';
const runPssa = process.env.PSSCRIPTANALYZER_ENABLED !== 'false';
const RECOVERY_BATCH_SIZE = 100;
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

function log(event) {
  process.stdout.write(JSON.stringify({ time: new Date().toISOString(), ...event }) + '\n');
}

async function writeStepSummary(manifest) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;
  const coverage = manifest.coverage || {};
  const lines = [
    '# PowerShell Gallery scan',
    '',
    '- Status: **' + manifest.status + '**',
    '- Last successful scan: ' + (manifest.lastSuccessfulScan || 'none'),
    '- Listed packages: ' + coverage.listedPackages,
    '- Latest versions scanned: ' + coverage.scannedLatestVersions,
    '- Versions observed: ' + coverage.scannedVersions,
    '- Incomplete versions: ' + coverage.incompleteVersions,
    '- Binary files checked with a SHA-256 hash and ClamAV: ' + (coverage.binaryFilesChecked || 0) + '/' + (coverage.binaryFiles || 0),
    '- Dependencies not found in PowerShell Gallery: ' + (coverage.missingGalleryDependencies || 0),
    '- Completed-result rescan queue: disabled',
    '- Bootstrap complete: ' + Boolean(manifest.bootstrap?.complete),
    '- Advisory refresh cursor: ' + (manifest.advisoryRefreshCursor || 'complete'),
    '',
    'Automated results are research signals. A missing finding is not proof that a package is safe.',
    '',
  ];
  await appendFile(summaryPath, lines.join('\n'), 'utf8');
}

async function runLocalIncompleteRecovery({ restart = false } = {}) {
  const state = await loadLocalState(SITE_PUBLIC_DIRECTORY);
  if (!state.packages.size) throw new Error('A local API snapshot is required before recovering incomplete scans.');
  if (state.manifest.incompleteRecovery?.complete && !restart) {
    log({ event: 'incomplete_recovery_already_complete', ...state.manifest.incompleteRecovery });
    return;
  }

  const tools = prepareLocalRecoveryEnvironment(process.env);
  process.env.PSSCRIPTANALYZER_MODULE_PATH = tools.psscriptAnalyzerModulePath;
  process.env.CLAMAV_SCAN_COMMAND = tools.command;
  process.env.CLAMAV_DATABASE_VERSION = tools.clamDatabaseVersion;
  process.env.CLAMAV_DATABASE_DATE = tools.clamDatabaseDate;
  if (tools.clamDatabaseDirectory) process.env.CLAMAV_DATABASE_DIRECTORY = tools.clamDatabaseDirectory;
  if (tools.clamdConfigPath) process.env.CLAMAV_CLAMD_CONFIG = tools.clamdConfigPath;
  process.env.SCAN_CONCURRENCY = '1';

  const recovery = startIncompleteRecovery(state, { restart });
  log({
    event: 'incomplete_recovery_started',
    total: recovery.total,
    resumed: !restart && recovery.processed > 0,
    batchSize: RECOVERY_BATCH_SIZE,
    packageConcurrency: 1,
  });
  await writeSnapshot(state, SITE_PUBLIC_DIRECTORY);

  const gallery = new GalleryClient();
  const curatedAdvisories = await loadCuratedAdvisories();
  while (state.manifest.incompleteRecovery.active) {
    const batch = await runIncompleteRecoveryBatch({
      state,
      gallery,
      batchSize: RECOVERY_BATCH_SIZE,
      concurrency: 1,
      runPssa: true,
      curatedAdvisories,
      log,
    });
    const manifest = await writeSnapshot(state, SITE_PUBLIC_DIRECTORY);
    await writeStepSummary(manifest);
    log({
      event: 'incomplete_recovery_checkpoint',
      ...manifest.incompleteRecovery,
      batchProcessed: batch.processed,
      batchCompleted: batch.completed,
      batchFailed: batch.failed,
      remaining: batch.remaining,
    });
  }

  const validation = spawnSync(process.execPath, [
    resolve(REPO_ROOT, 'scripts/validate-api-snapshot.js'),
    resolve(SITE_PUBLIC_DIRECTORY, 'api/v1'),
  ], { encoding: 'utf8', timeout: 120_000, maxBuffer: 2 * 1024 * 1024, windowsHide: true });
  if (validation.error) throw validation.error;
  if (validation.status !== 0) throw new Error('The recovered API snapshot did not validate: ' + (validation.stderr || validation.stdout).trim());
  process.stdout.write(validation.stdout);
}

async function main() {
  const recoverIncomplete = process.argv.includes('--recover-incomplete');
  const restartRecovery = process.argv.includes('--restart');
  if (restartRecovery && !recoverIncomplete) throw new Error('--restart requires --recover-incomplete.');
  if (recoverIncomplete) {
    await runLocalIncompleteRecovery({ restart: restartRecovery });
    return;
  }

  const localBootstrap = process.argv.includes('--bootstrap-local');
  const resetBootstrap = process.argv.includes('--bootstrap');
  const { state, source } = localBootstrap
    ? { state: await loadLocalState(SITE_PUBLIC_DIRECTORY), source: 'local' }
    : await loadScanState(stateApiUrl, { publicDirectory: SITE_PUBLIC_DIRECTORY });
  if (source === 'local' && state.packages.size) log({ event: 'loaded_local_snapshot', packages: state.packages.size });
  if (resetBootstrap) {
    state.manifest.bootstrap = { complete: false, afterId: '', startedAt: state.manifest.bootstrap?.startedAt || new Date().toISOString() };
  }
  const gallery = new GalleryClient();
  const bootstrapBatchSize = Number(process.env.BOOTSTRAP_BATCH_SIZE) || 200;
  let finishBaseline = localBootstrap && !state.manifest.bootstrap?.complete;
  let batchNumber = 0;
  let manifest;
  do {
    const outcome = await runScanCycle({
      state,
      gallery,
      runPssa,
      refreshAdvisories,
      bootstrapOnly: finishBaseline,
      bootstrapBatchSize,
      reconcileBatchSize: Number(process.env.RECONCILE_BATCH_SIZE) || 200,
      updateBatchSize: Number(process.env.UPDATE_BATCH_SIZE) || 1000,
      advisoryBatchSize: Number(process.env.ADVISORY_BATCH_SIZE) || 500,
      concurrency: Number(process.env.SCAN_CONCURRENCY) || 4,
      log,
    });
    manifest = await writeSnapshot(outcome.state, SITE_PUBLIC_DIRECTORY);
    await writeStepSummary(manifest);
    batchNumber++;
    if (manifest.status === 'degraded') {
      log({
        event: 'degraded_snapshot_published',
        sourceErrors: outcome.sourceErrors,
        notice: manifest.notice,
      });
      process.stdout.write('::warning::Scanner published its last-good data with degraded status. See the API manifest for details.\n');
    }
    log({
      event: 'snapshot_published',
      status: manifest.status,
      listedPackages: manifest.coverage.listedPackages,
      scannedLatestVersions: manifest.coverage.scannedLatestVersions,
      scannedVersions: manifest.coverage.scannedVersions,
      incompleteVersions: manifest.coverage.incompleteVersions,
      binaryFilesChecked: manifest.coverage.binaryFilesChecked || 0,
      binaryFiles: manifest.coverage.binaryFiles || 0,
      missingGalleryDependencies: manifest.coverage.missingGalleryDependencies || 0,
      resultRefresh: manifest.resultRefresh,
      stateShards: manifest.stateShards.length,
      bootstrapComplete: manifest.bootstrap.complete,
    });
    if (!outcome.feedSucceeded) {
      process.exitCode = 1;
      log({ event: 'local_bootstrap_paused', reason: 'A Gallery feed failed; the saved snapshot can resume on the next run.' });
      break;
    }
    if (localBootstrap && finishBaseline && manifest.bootstrap.complete) {
      finishBaseline = false;
      log({
        event: 'local_bootstrap_complete',
        listedPackages: manifest.coverage.listedPackages,
        scannedLatestVersions: manifest.coverage.scannedLatestVersions,
        unscannedLatestVersions: manifest.coverage.unscannedLatestVersions,
        message: 'Running one incremental and reconciliation pass to catch changes published during the baseline.',
      });
      continue;
    }
    if (!localBootstrap || !finishBaseline) break;
    log({
      event: 'local_bootstrap_batch_complete',
      batchNumber,
      afterId: manifest.bootstrap.afterId,
      listedPackages: manifest.coverage.listedPackages,
      scannedLatestVersions: manifest.coverage.scannedLatestVersions,
      remaining: 'continuing until Gallery baseline is complete',
    });
  } while (localBootstrap);
}

main().catch((error) => {
  process.stderr.write(JSON.stringify({
    time: new Date().toISOString(),
    event: 'fatal_scan_error',
    error: String(error.message || error).slice(0, 2000),
  }) + '\n');
  process.exitCode = 1;
});
