import { scanGalleryPackage, SCANNER_VERSION, RULESET_VERSION } from './package-scanner.js';
import { loadCuratedAdvisories, refreshOsvForTargets } from './advisories.js';
import { addNotScannedVersion, findPackageRecord, findVersionRecord, mergePackageMetadata, mergePackageVersion } from './state.js';
import { compareVersions } from './versions.js';
import { mapLimit, nowIso, normalizePackageName, safeString } from './util.js';

const DEFAULT_BOOTSTRAP_BATCH = 200;
const DEFAULT_RECONCILE_BATCH = 200;
const DEFAULT_UPDATE_BATCH = 1000;
const DEFAULT_ADVISORY_BATCH = 500;
const UPDATE_OVERLAP_MS = 6 * 60 * 60 * 1000;
const INCOMPLETE_RETRY_WINDOW_MS = 6 * 60 * 60 * 1000;

function packageVersionKey(record, version) {
  return normalizePackageName(record.name) + '@' + version;
}

function parseGalleryTimestamp(value) {
  const text = String(value || '');
  const normalized = /^\d{4}-\d{2}-\d{2}T/.test(text) && !/(?:z|[+-]\d{2}:?\d{2})$/i.test(text)
    ? text + 'Z'
    : text;
  return Date.parse(normalized);
}

function selectedLatest(record) {
  return record?.versions?.find((item) => item.version === record.latestVersion)
    || [...(record?.versions || [])].sort((a, b) => compareVersions(b.version, a.version))[0]
    || null;
}

function shouldRescan(item, state, attemptedAt) {
  const existing = findVersionRecord(state, item.name, item.version);
  if (!existing || !existing.assessment || existing.assessment === 'not_scanned') return true;
  if (existing.assessment !== 'incomplete') return false;
  const publishedAt = parseGalleryTimestamp(item.publishedAt || existing.metadata?.publishedAt);
  const currentAt = parseGalleryTimestamp(attemptedAt);
  return Number.isFinite(publishedAt)
    && Number.isFinite(currentAt)
    && publishedAt <= currentAt
    && currentAt - publishedAt <= INCOMPLETE_RETRY_WINDOW_MS;
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

  const refresh = state.manifest.resultRefresh || { id: 'binary-dependency-2026-10' };
  refresh.complete = true;
  refresh.afterKey = '';
  refresh.total = 0;
  state.manifest.resultRefresh = refresh;

  const candidates = [...work.entries()].map(([key, item]) => ({ key, item }));
  const processed = await mapLimit(candidates, concurrency, async (item) => {
    const { key, item: packageItem } = item;
    if (!shouldRescan(packageItem, state, attemptedAt)) return { item: packageItem, key, skipped: true };
    const existing = findPackageRecord(state, packageItem.name);
    try {
      const result = await scanGalleryPackage(packageItem, gallery, {
        previousVersions: existing?.versions || [],
        runPssa,
        fetcher,
        curatedAdvisories: curated,
        scanAdvisories: true,
        log,
      });
      mergePackageVersion(state, packageItem, result, { replace: true });
      return { item: packageItem, key, result, skipped: false };
    } catch (error) {
      const result = {
        package: packageItem.name,
        version: packageItem.version,
        assessment: 'incomplete',
        packageSha256: null,
        scannedAt: null,
        scannerVersion: SCANNER_VERSION,
        rulesetVersion: RULESET_VERSION,
        packageUrl: 'https://www.powershellgallery.com/packages/' + encodeURIComponent(packageItem.name) + '/' + encodeURIComponent(packageItem.version),
        metadata: {
          title: packageItem.title || packageItem.name,
          description: packageItem.description || '',
          owners: packageItem.owners || '',
          publishedAt: packageItem.publishedAt || null,
          updatedAt: packageItem.updatedAt || null,
        },
        dependencies: [],
        binaryArtifacts: [],
        fileInventory: [],
        findings: [],
        coverage: { archive: false, powerShellAnalysis: false, dependencyResolution: false, advisories: false, binaryScanning: false },
        warnings: [safeString(error.message || error, 800)],
      };
      mergePackageVersion(state, packageItem, result, { replace: true });
      return { item: packageItem, key, result, skipped: false };
    }
  });
  gallery.clearVersionCache?.();

  const changed = processed.filter((entry) => !entry.skipped).length;

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
  state.manifest.status = feedSucceeded ? 'ready' : 'degraded';
  state.manifest.notice = sourceErrors.length
    ? sourceErrors.join(' ')
    : refreshAdvisories && !advisoryRefresh.complete
      ? 'The daily advisory refresh is in progress. Previously published findings remain available.'
      : '';
  if (feedSucceeded) state.manifest.lastSuccessfulScan = attemptedAt;
  if (refreshAdvisories && advisoryRefresh.complete) state.manifest.advisoriesUpdatedAt = attemptedAt;
  if (sourceErrors.length) state.manifest.sourceErrors = sourceErrors.slice(0, 5);
  else delete state.manifest.sourceErrors;
  state.manifest.lastBatch = {
    attemptedAt,
    packageVersionsProcessed: changed,
    packageVersionsSkipped: processed.length - changed,
    resultRefreshProcessed: 0,
    resultRefreshComplete: Boolean(refresh.complete),
    resultRefreshRemaining: 0,
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
      const dependenciesComplete = (version.coverage.dependencyResolution !== false)
        && (version.dependencies || []).every((item) => ['resolved', 'package_not_found', 'no_matching_version', 'bundled'].includes(item.status));
      if (version.coverage.archive && version.coverage.powerShellAnalysis && dependenciesComplete
        && version.coverage.binaryScanning !== false) version.assessment = 'complete';
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
