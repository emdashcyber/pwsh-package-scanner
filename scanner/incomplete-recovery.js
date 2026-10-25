import { scanGalleryPackage } from './package-scanner.js';
import {
  findPackageRecord,
  findVersionRecord,
  mergePackageMetadata,
  mergePackageVersion,
} from './state.js';
import { mapLimit, nowIso, normalizePackageName, safeString } from './util.js';

export const DEFAULT_INCOMPLETE_RECOVERY_BATCH_SIZE = 100;

function packageVersionKey(record, version) {
  return normalizePackageName(record.name) + '@' + version;
}

function compareKeys(left, right) {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function listIncompleteVersions(state) {
  const items = [];
  for (const record of state.packages.values()) {
    for (const version of record.versions || []) {
      if (version.assessment !== 'incomplete') continue;
      items.push({
        record,
        version,
        key: packageVersionKey(record, version.version),
      });
    }
  }
  return items.sort((a, b) => compareKeys(a.key, b.key));
}

function attemptedSince(version, startedAt) {
  const started = Date.parse(startedAt || '');
  const attempted = Date.parse(version.lastAttemptAt || '');
  return Number.isFinite(started) && Number.isFinite(attempted) && attempted >= started;
}

function pendingRecoveryVersions(state, recovery, afterKey = '') {
  return listIncompleteVersions(state).filter((item) => item.key > afterKey
    && !attemptedSince(item.version, recovery.startedAt));
}

function countIncompleteVersions(state) {
  let count = 0;
  for (const record of state.packages.values()) {
    for (const version of record.versions || []) {
      if (version.assessment === 'incomplete') count++;
    }
  }
  return count;
}

function countPendingRecoveryVersions(state, recovery) {
  return listIncompleteVersions(state)
    .filter((item) => !attemptedSince(item.version, recovery.startedAt)).length;
}

function timestamp(value) {
  const parsed = Date.parse(value || '');
  return Number.isFinite(parsed) ? parsed : 0;
}

function mergeVersionMetadata(checkpointVersion, currentVersion) {
  const merged = { ...(checkpointVersion.metadata || {}) };
  const current = currentVersion?.metadata || {};
  for (const [key, value] of Object.entries(current)) {
    if (value === null || value === undefined || value === '') continue;
    if (key === 'updatedAt') {
      if (timestamp(value) >= timestamp(merged.updatedAt)) merged.updatedAt = value;
    } else {
      merged[key] = value;
    }
  }
  return merged;
}

/** Merge a recovery checkpoint into a newer checked-in snapshot without replacing newer scan data. */
export function mergeIncompleteRecoveryCheckpoint(currentState, checkpointState) {
  if (!currentState?.manifest || !(currentState.packages instanceof Map)
    || !checkpointState?.manifest || !(checkpointState.packages instanceof Map)) {
    throw new Error('Current and checkpoint scanner states must be valid.');
  }

  const previousRecovery = checkpointState.manifest.incompleteRecovery;
  if (!previousRecovery || !previousRecovery.startedAt) {
    throw new Error('Recovery checkpoint has no saved recovery start time.');
  }
  const startedAt = Date.parse(previousRecovery.startedAt);
  if (!Number.isFinite(startedAt)) throw new Error('Recovery checkpoint has an invalid start time.');

  let mergedAttempts = 0;
  let newerCurrentAttemptsKept = 0;
  for (const checkpointRecord of checkpointState.packages.values()) {
    let currentRecord = findPackageRecord(currentState, checkpointRecord.name);
    for (const checkpointVersion of checkpointRecord.versions || []) {
      const attemptAt = Date.parse(checkpointVersion.lastAttemptAt || '');
      if (!Number.isFinite(attemptAt) || attemptAt < startedAt) continue;

      const currentVersion = currentRecord?.versions.find((version) => version.version === checkpointVersion.version) || null;
      if (currentVersion && Math.max(timestamp(currentVersion.lastAttemptAt), timestamp(currentVersion.scannedAt)) >= attemptAt) {
        newerCurrentAttemptsKept++;
        continue;
      }

      if (!currentRecord) {
        currentRecord = {
          ...structuredClone(checkpointRecord),
          versions: [],
        };
        currentState.packages.set(normalizePackageName(currentRecord.name), currentRecord);
      }

      const mergedVersion = structuredClone(checkpointVersion);
      mergedVersion.metadata = mergeVersionMetadata(checkpointVersion, currentVersion);
      const index = currentRecord.versions.findIndex((version) => version.version === mergedVersion.version);
      if (index >= 0) currentRecord.versions[index] = mergedVersion;
      else currentRecord.versions.push(mergedVersion);
      currentRecord.versions.sort((a, b) => a.version.localeCompare(b.version, 'en', { numeric: true, sensitivity: 'base' }));
      mergedAttempts++;
    }
  }

  const recovery = structuredClone(previousRecovery);
  recovery.active = true;
  recovery.complete = false;
  recovery.afterKey = '';
  recovery.completedAt = null;
  recovery.updatedAt = nowIso();
  recovery.stillIncomplete = countIncompleteVersions(currentState);
  recovery.total = Math.max(
    Number(recovery.total) || 0,
    (Number(recovery.processed) || 0) + countPendingRecoveryVersions(currentState, recovery),
  );
  currentState.manifest.incompleteRecovery = recovery;

  return {
    mergedAttempts,
    newerCurrentAttemptsKept,
    pending: countPendingRecoveryVersions(currentState, recovery),
    stillIncomplete: recovery.stillIncomplete,
    afterKey: recovery.afterKey,
  };
}

function newRecoveryState(total, startedAt = nowIso()) {
  return {
    active: true,
    complete: false,
    afterKey: '',
    total,
    processed: 0,
    completed: 0,
    stillIncomplete: total,
    failed: 0,
    startedAt,
    updatedAt: startedAt,
    completedAt: null,
  };
}

export function startIncompleteRecovery(state, { restart = false } = {}) {
  if (!state || !state.manifest || !(state.packages instanceof Map)) {
    throw new Error('Scanner state is invalid.');
  }

  const current = state.manifest.incompleteRecovery;
  if (current?.active && !restart) return current;
  if (current?.complete && !restart) return current;

  state.manifest.incompleteRecovery = newRecoveryState(countIncompleteVersions(state));
  return state.manifest.incompleteRecovery;
}

function recordAttemptError(state, candidate, error) {
  const version = findVersionRecord(state, candidate.record.name, candidate.version.version);
  if (!version) return;
  version.lastAttemptAt = nowIso();
  version.lastAttemptError = safeString(error?.message || error, 800) || 'The recovery scan failed.';
}

export async function runIncompleteRecoveryBatch({
  state,
  gallery,
  batchSize = DEFAULT_INCOMPLETE_RECOVERY_BATCH_SIZE,
  concurrency = 1,
  runPssa = true,
  fetcher = globalThis.fetch,
  curatedAdvisories = [],
  log = () => {},
} = {}) {
  if (!state || !state.manifest || !(state.packages instanceof Map)) {
    throw new Error('Scanner state is invalid.');
  }
  if (!gallery || typeof gallery.getPackageVersion !== 'function') {
    throw new Error('Gallery client must support exact package-version metadata lookup.');
  }
  const recovery = state.manifest.incompleteRecovery;
  if (!recovery?.active || recovery.complete) throw new Error('Incomplete recovery has not been started.');

  const remaining = pendingRecoveryVersions(state, recovery, recovery.afterKey);
  const batch = remaining.slice(0, Math.max(1, Math.floor(Number(batchSize) || DEFAULT_INCOMPLETE_RECOVERY_BATCH_SIZE)));
  if (!batch.length) {
    const completedAt = nowIso();
    recovery.active = false;
    recovery.complete = true;
    recovery.stillIncomplete = countIncompleteVersions(state);
    recovery.updatedAt = completedAt;
    recovery.completedAt = completedAt;
    return {
      processed: 0,
      completed: 0,
      stillIncomplete: recovery.stillIncomplete,
      failed: 0,
      remaining: 0,
      complete: true,
    };
  }

  const results = await mapLimit(batch, concurrency, async (candidate) => {
    const currentVersion = findVersionRecord(state, candidate.record.name, candidate.version.version);
    if (!currentVersion || currentVersion.assessment !== 'incomplete') {
      return { key: candidate.key, skipped: true, completed: false, failed: false };
    }

    try {
      const galleryItem = await gallery.getPackageVersion(candidate.record.name, candidate.version.version);
      if (!galleryItem) throw new Error('Gallery no longer lists this exact package version.');
      mergePackageMetadata(state, galleryItem);
      const packageRecord = findPackageRecord(state, candidate.record.name);
      const result = await scanGalleryPackage(galleryItem, gallery, {
        previousVersions: packageRecord?.versions || [],
        runPssa,
        fetcher,
        curatedAdvisories,
        scanAdvisories: true,
        log,
      });
      mergePackageVersion(state, galleryItem, result, { replace: true });
      const updated = findVersionRecord(state, candidate.record.name, candidate.version.version);
      if (updated) {
        updated.lastAttemptAt = nowIso();
        if (result.scannedAt) delete updated.lastAttemptError;
        else updated.lastAttemptError = (result.warnings || []).join(' ').slice(0, 800)
          || 'The Gallery package version could not be scanned.';
      }
      log({
        event: 'incomplete_recovery_version',
        package: candidate.record.name,
        version: candidate.version.version,
        assessment: result.assessment,
        scannedAt: result.scannedAt,
      });
      return {
        key: candidate.key,
        skipped: false,
        completed: result.assessment === 'complete',
        failed: !result.scannedAt,
      };
    } catch (error) {
      recordAttemptError(state, candidate, error);
      log({
        event: 'incomplete_recovery_error',
        package: candidate.record.name,
        version: candidate.version.version,
        error: safeString(error?.message || error, 500),
      });
      return { key: candidate.key, skipped: false, completed: false, failed: true };
    }
  });

  const lastKey = batch.at(-1).key;
  recovery.afterKey = lastKey;
  recovery.processed += results.filter((result) => !result.skipped).length;
  recovery.completed += results.filter((result) => result.completed).length;
  recovery.failed += results.filter((result) => result.failed).length;
  recovery.stillIncomplete = countIncompleteVersions(state);
  recovery.updatedAt = nowIso();

  const nextRemaining = pendingRecoveryVersions(state, recovery, recovery.afterKey);
  if (!nextRemaining.length) {
    recovery.active = false;
    recovery.complete = true;
    recovery.completedAt = recovery.updatedAt;
  }

  return {
    processed: results.filter((result) => !result.skipped).length,
    completed: results.filter((result) => result.completed).length,
    stillIncomplete: recovery.stillIncomplete,
    failed: results.filter((result) => result.failed).length,
    remaining: nextRemaining.length,
    complete: recovery.complete,
  };
}
