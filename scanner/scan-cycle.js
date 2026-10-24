import { scanGalleryPackage, SCANNER_VERSION } from './package-scanner.js';
import { loadCuratedAdvisories, refreshOsvForTargets } from './advisories.js';
import { addNotScannedVersion, findPackageRecord, findVersionRecord, mergePackageMetadata, mergePackageVersion } from './state.js';
import { compareVersions } from './versions.js';
import { mapLimit, nowIso, normalizePackageName, safeString } from './util.js';

const DEFAULT_BOOTSTRAP_BATCH = 200;
const DEFAULT_RECONCILE_BATCH = 200;
const DEFAULT_UPDATE_BATCH = 1000;
const DEFAULT_ADVISORY_BATCH = 500;
const UPDATE_OVERLAP_MS = 6 * 60 * 60 * 1000;

function packageVersionKey(record, version) {
  return normalizePackageName(record.name) + '@' + version;
}

function selectedLatest(record) {
  return record?.versions?.find((item) => item.version === record.latestVersion)
    || [...(record?.versions || [])].sort((a, b) => compareVersions(b.version, a.version))[0]
    || null;
}

function shouldRescan(item, state) {
  const existing = findVersionRecord(state, item.name, item.version);
  if (!existing || existing.assessment === 'not_scanned') return true;
  const changedAt = Date.parse(item.updatedAt || item.publishedAt || '');
  const scannedMetaAt = Date.parse(existing.metadata?.updatedAt || '');
  return Number.isFinite(changedAt) && Number.isFinite(scannedMetaAt) && changedAt > scannedMetaAt;
}

function updateFeedCursor(state, items, queryLimit, attemptedAt) {
  if (items.length >= queryLimit) {
    const lastUpdated = items.at(-1)?.updatedAt;
    state.manifest.galleryUpdatedThrough = lastUpdated || state.manifest.galleryUpdatedThrough || attemptedAt;
  } else {
    state.manifest.galleryUpdatedThrough = attemptedAt;
  }
}

function mergeUpdatedMetadata(state, item) {
  mergePackageMetadata(state, item);
  const record = findPackageRecord(state, item.name);
  if ((item.isAbsoluteLatest || item.isLatest) && item.version) record.latestVersion = item.version;
}

export async function runScanCycle({
  state,
  gallery,
  fetcher = globalThis.fetch,
  runPssa = true,
  refreshAdvisories = false,
  bootstrapOnly = false,
  bootstrapBatchSize = DEFAULT_BOOTSTRAP_BATCH,
  reconcileBatchSize = DEFAULT_RECONCILE_BATCH,
  updateBatchSize = DEFAULT_UPDATE_BATCH,
  advisoryBatchSize = DEFAULT_ADVISORY_BATCH,
  concurrency = 4,
  curatedAdvisories,
  log = () => {},
} = {}) {
  if (!state || !state.manifest || !(state.packages instanceof Map)) throw new Error('Scanner state is invalid.');
  if (!gallery) throw new Error('Gallery client is required.');
  const attemptedAt = nowIso();
  const curated = curatedAdvisories || await loadCuratedAdvisories();
  const work = new Map();
  const sourceErrors = [];
  let feedSucceeded = true;

  const processItems = (items, label) => {
    for (const item of items) {
      if (!item?.name || !item?.version) continue;
      mergeUpdatedMetadata(state, item);
      const key = packageVersionKey({ name: item.name }, item.version);
      const previous = work.get(key);
      work.set(key, previous ? { ...previous, ...item, isAbsoluteLatest: item.isAbsoluteLatest || previous.isAbsoluteLatest } : item);
    }
    log({ event: 'feed_items', source: label, count: items.length });
  };

  if (!state.manifest.bootstrap?.complete) {
    state.manifest.bootstrap = {
      complete: false,
      afterId: state.manifest.bootstrap?.afterId || '',
      startedAt: state.manifest.bootstrap?.startedAt || attemptedAt,
    };
    try {
      const items = await gallery.listLatestAfter(state.manifest.bootstrap.afterId, bootstrapBatchSize);
      processItems(items, 'bootstrap');
      if (items.length) state.manifest.bootstrap.afterId = items.at(-1).name;
      if (items.length < bootstrapBatchSize) state.manifest.bootstrap.complete = true;
    } catch (error) {
      sourceErrors.push('Initial catalog scan: ' + safeString(error.message || error, 500));
      feedSucceeded = false;
    }
  }

  if (bootstrapOnly) {
    if (!state.manifest.galleryUpdatedThrough) state.manifest.galleryUpdatedThrough = state.manifest.bootstrap.startedAt;
  } else {
    try {
      const since = state.manifest.galleryUpdatedThrough
        ? new Date(Date.parse(state.manifest.galleryUpdatedThrough) - UPDATE_OVERLAP_MS).toISOString()
        : attemptedAt;
      const updated = await gallery.listUpdatedSince(since, updateBatchSize);
      processItems(updated, 'incremental');
      updateFeedCursor(state, updated, updateBatchSize, attemptedAt);
    } catch (error) {
      sourceErrors.push('Incremental Gallery poll: ' + safeString(error.message || error, 500));
      feedSucceeded = false;
    }

    try {
      const afterId = state.manifest.reconciliation?.afterId || '';
      const latest = await gallery.listLatestAfter(afterId, reconcileBatchSize);
      processItems(latest, 'reconciliation');
      if (latest.length < reconcileBatchSize) state.manifest.reconciliation = { afterId: '' };
      else state.manifest.reconciliation = { afterId: latest.at(-1).name };
    } catch (error) {
      sourceErrors.push('Catalog reconciliation: ' + safeString(error.message || error, 500));
      feedSucceeded = false;
    }
  }

  const initiallyUnversioned = [...work.values()].filter((item) => !(findPackageRecord(state, item.name)?.versions?.length));
  const laterVersions = [];
  await mapLimit(initiallyUnversioned, concurrency, async (item) => {
    try {
      const versions = await gallery.listPackageVersions(item.name);
      const baselineStartedAt = Date.parse(state.manifest.bootstrap?.startedAt || attemptedAt);
      for (const version of versions) {
        if (!version.version || version.version === item.version) continue;
        const publishedAt = Date.parse(version.publishedAt || '');
        if (Number.isFinite(publishedAt) && publishedAt >= baselineStartedAt) laterVersions.push(version);
        else addNotScannedVersion(state, version);
      }
      const record = findPackageRecord(state, item.name);
      if (versions.length >= 1000 && record) {
        record.metadata.versionInventoryNote = 'The Gallery version listing reached the 1,000-version query limit.';
        sourceErrors.push(item.name + ': historical version inventory reached the 1,000-version query limit.');
      }
    } catch (error) {
      const record = findPackageRecord(state, item.name);
      const detail = safeString(error.message || error, 300);
      if (record) record.metadata.versionInventoryNote = 'Historical version inventory is unavailable: ' + detail;
      sourceErrors.push(item.name + ': historical version inventory is unavailable: ' + detail);
    }
  });
  gallery.clearVersionCache?.();
  if (laterVersions.length) processItems(laterVersions, 'post_launch_versions');

  const candidates = [...work.values()];
  const processed = await mapLimit(candidates, concurrency, async (item) => {
    if (!shouldRescan(item, state)) return { item, skipped: true };
    const existing = findPackageRecord(state, item.name);
    try {
      const result = await scanGalleryPackage(item, gallery, {
        previousVersions: existing?.versions || [],
        runPssa,
        fetcher,
        curatedAdvisories: curated,
        scanAdvisories: true,
        log,
      });
      mergePackageVersion(state, item, result, { replace: true });
      return { item, result, skipped: false };
    } catch (error) {
      const result = {
        package: item.name,
        version: item.version,
        assessment: 'incomplete',
        packageSha256: null,
        scannedAt: null,
        scannerVersion: SCANNER_VERSION,
        rulesetVersion: '0.1.0',
        packageUrl: 'https://www.powershellgallery.com/packages/' + encodeURIComponent(item.name) + '/' + encodeURIComponent(item.version),
        metadata: {
          title: item.title || item.name,
          description: item.description || '',
          owners: item.owners || '',
          publishedAt: item.publishedAt || null,
          updatedAt: item.updatedAt || null,
        },
        dependencies: [],
        fileInventory: [],
        findings: [],
        coverage: { archive: false, powerShellAnalysis: false, dependencyResolution: false, advisories: false },
        warnings: [safeString(error.message || error, 800)],
      };
      mergePackageVersion(state, item, result, { replace: true });
      return { item, result, skipped: false };
    }
  });
  gallery.clearVersionCache?.();

  const changed = processed.filter((entry) => !entry.skipped).length;
  const errors = processed.flatMap((entry) => entry.result?.warnings || []);

  let advisoryRefresh = { processed: 0, complete: !refreshAdvisories, remaining: 0 };
  if (refreshAdvisories) {
    advisoryRefresh = await refreshStoredAdvisories(state, {
      fetcher,
      curatedAdvisories: curated,
      batchSize: advisoryBatchSize,
      concurrency,
      log,
    });
  }

  state.manifest.lastAttemptAt = attemptedAt;
  state.manifest.bootstrap = state.manifest.bootstrap || { complete: false, afterId: '', startedAt: attemptedAt };
  state.manifest.reconciliation = state.manifest.reconciliation || { afterId: '' };
  state.manifest.sourceStatus = feedSucceeded ? 'available' : 'degraded';
  state.manifest.status = feedSucceeded && !sourceErrors.length && !errors.length && (!refreshAdvisories || advisoryRefresh.complete) ? 'ready' : 'degraded';
  state.manifest.notice = sourceErrors.length
    ? sourceErrors.join(' ')
    : errors.length
      ? 'One or more package checks were incomplete. Review per-version coverage details.'
      : refreshAdvisories && !advisoryRefresh.complete
        ? 'The daily advisory refresh is incomplete. Previously published results are retained.'
      : '';
  if (feedSucceeded) state.manifest.lastSuccessfulScan = attemptedAt;
  if (refreshAdvisories && advisoryRefresh.complete) state.manifest.advisoriesUpdatedAt = attemptedAt;
  if (sourceErrors.length) state.manifest.sourceErrors = sourceErrors.slice(0, 5);
  else delete state.manifest.sourceErrors;
  state.manifest.lastBatch = {
    attemptedAt,
    packageVersionsProcessed: changed,
    packageVersionsSkipped: processed.length - changed,
    bootstrapComplete: Boolean(state.manifest.bootstrap.complete),
    advisoryRecordsRefreshed: advisoryRefresh.processed,
    advisoryRefreshRemaining: advisoryRefresh.remaining,
  };
  return { state, feedSucceeded, changed, sourceErrors, advisoryRefresh };
}

async function refreshStoredAdvisories(state, {
  fetcher,
  curatedAdvisories,
  batchSize,
  concurrency,
  log,
}) {
  const all = [];
  for (const packageRecord of state.packages.values()) {
    for (const version of packageRecord.versions || []) {
      if (!version.scannedAt || version.assessment === 'not_scanned') continue;
      all.push({ packageRecord, version, key: packageVersionKey(packageRecord, version.version) });
    }
  }
  all.sort((a, b) => a.key.localeCompare(b.key));
  let cursor = state.manifest.advisoryRefreshCursor || '';
  if (!cursor) cursor = '';
  const remaining = all.filter((item) => item.key > cursor);
  const batch = remaining.slice(0, batchSize);
  const results = await mapLimit(batch, concurrency, async ({ packageRecord, version }) => {
    const result = await refreshOsvForTargets(version, version.dependencies || [], { fetcher, curatedAdvisories });
    if (result.complete) {
      version.findings = [
        ...(version.findings || []).filter((finding) => finding.category !== 'advisory'),
        ...result.findings,
      ];
      version.advisoryCheckedAt = result.checkedAt;
      version.advisoryError = null;
      version.coverage = { ...version.coverage, advisories: true };
      const dependenciesComplete = (version.dependencies || []).every((item) => item.status === 'resolved');
      if (version.coverage.archive && version.coverage.powerShellAnalysis && dependenciesComplete) version.assessment = 'complete';
    } else {
      version.advisoryError = result.error;
      version.coverage = { ...version.coverage, advisories: false };
      version.assessment = 'incomplete';
      version.warnings = [...new Set([...(version.warnings || []), result.error].filter(Boolean))].slice(0, 20);
    }
    log({
      event: 'advisory_refresh',
      package: packageRecord.name,
      version: version.version,
      complete: result.complete,
    });
    return result.complete;
  });
  const completed = results.every(Boolean);
  const firstFailedIndex = results.indexOf(false);
  const successfullyProcessed = firstFailedIndex === -1 ? batch.length : firstFailedIndex;
  if (successfullyProcessed > 0) {
    const lastSuccessfulKey = batch[successfullyProcessed - 1].key;
    state.manifest.advisoryRefreshCursor = remaining.length <= successfullyProcessed && completed
      ? ''
      : lastSuccessfulKey;
  }
  const refreshComplete = remaining.length <= batch.length && completed;
  return {
    processed: batch.length,
    complete: refreshComplete,
    remaining: Math.max(0, remaining.length - batch.length),
  };
}
