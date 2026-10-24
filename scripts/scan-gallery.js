import { appendFile } from 'node:fs/promises';
import { GalleryClient } from '../scanner/gallery.js';
import { loadLocalState, loadScanState, SITE_PUBLIC_DIRECTORY, writeSnapshot } from '../scanner/state.js';
import { runScanCycle } from '../scanner/scan-cycle.js';

const stateApiUrl = process.env.SCAN_STATE_API_URL
  || 'https://emdashcyber.com/pwsh-package-scanner/api/v1/';
const refreshAdvisories = process.env.REFRESH_ADVISORIES === 'true';
const runPssa = process.env.PSSCRIPTANALYZER_ENABLED !== 'false';

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
    '- Existing-result refresh: ' + (manifest.resultRefresh?.complete ? 'complete' : (manifest.resultRefresh?.total || 0) - (manifest.lastBatch?.resultRefreshRemaining || 0) + '/' + (manifest.resultRefresh?.total || 0)),
    '- Bootstrap complete: ' + Boolean(manifest.bootstrap?.complete),
    '- Advisory refresh cursor: ' + (manifest.advisoryRefreshCursor || 'complete'),
    '',
    'Automated results are research signals. A missing finding is not proof that a package is safe.',
    '',
  ];
  await appendFile(summaryPath, lines.join('\n'), 'utf8');
}

async function main() {
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
      resultRefreshBatchSize: Number(process.env.RESULT_REFRESH_BATCH_SIZE) || 200,
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
