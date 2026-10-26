import { inspectNupkg } from './zip.js';
import { analyzePowerShellFindings, isPowerShellFinding, RULESET_VERSION } from './package-scanner.js';
import { normalizePackageName, nowIso, safeString, sha256 } from './util.js';

export const DEFAULT_FINDINGS_REFRESH_BATCH_SIZE = 100;
export const FINDINGS_REFRESH_ID = 'finding-rules-' + RULESET_VERSION;

function versionKey(record, version) {
  return normalizePackageName(record.name) + '@' + version;
}

function compareKeys(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function listFindingsRefreshCandidates(state) {
  const items = [];
  for (const record of state.packages.values()) {
    for (const version of record.versions || []) {
      if (!version.assessment || version.assessment === 'not_scanned') continue;
      if (version.rulesetVersion === RULESET_VERSION) continue;
      items.push({ record, version, key: versionKey(record, version.version) });
    }
  }
  return items.sort((a, b) => compareKeys(a.key, b.key));
}

function newRefreshProgress(total, startedAt = nowIso(), previousErrors = []) {
  return {
    id: FINDINGS_REFRESH_ID,
    active: true,
    complete: total === 0,
    afterKey: '',
    total,
    processed: 0,
    succeeded: 0,
    failed: 0,
    startedAt,
    updatedAt: startedAt,
    completedAt: total === 0 ? startedAt : null,
    lastErrors: previousErrors.slice(-20),
  };
}

export function startFindingsRefresh(state) {
  if (!state?.manifest || !(state.packages instanceof Map)) throw new Error('Scanner state is invalid.');
  const current = state.manifest.findingsRefresh;
  if (current?.id === FINDINGS_REFRESH_ID && current.active) return current;
  const candidates = listFindingsRefreshCandidates(state);
  if (current?.id === FINDINGS_REFRESH_ID && current.complete && candidates.length === 0) return current;
  state.manifest.findingsRefresh = newRefreshProgress(candidates.length, nowIso(), current?.lastErrors || []);
  return state.manifest.findingsRefresh;
}

function replacePowerShellFindings(version, findings, analysis) {
  const preserved = (version.findings || []).filter((finding) => !isPowerShellFinding(finding)
    && !/^PSG-SUPPLY-004(?:-|$)/.test(finding.id || ''));
  version.findings = [...preserved, ...findings];
  version.rulesetVersion = RULESET_VERSION;
  version.tools = {
    ...(version.tools || {}),
    powerShell: analysis.powerShellVersion || version.tools?.powerShell || null,
    psscriptAnalyzer: analysis.analyzerVersion || version.tools?.psscriptAnalyzer || null,
    psscriptAnalyzerExpected: '1.25.0',
  };
  version.coverage = { ...(version.coverage || {}), powerShellAnalysis: analysis.complete };
  const oldWarnings = (version.warnings || []).filter((warning) => !String(warning).includes('DSC syntax validation was skipped'));
  version.warnings = [...oldWarnings, ...(analysis.warnings || [])].slice(0, 20);
}

export function mergeFindingsRefreshUpdate(state, update) {
  if (!update || typeof update.package !== 'string' || typeof update.version !== 'string') return false;
  if (typeof update.packageSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(update.packageSha256)) return false;
  const record = state.packages.get(normalizePackageName(update.package));
  const version = record?.versions?.find((item) => item.version === update.version);
  if (!version || version.assessment === 'not_scanned') return false;
  if (version.packageSha256 && version.packageSha256 !== update.packageSha256) return false;
  if (version.rulesetVersion === RULESET_VERSION) return false;
  const analysis = {
    complete: true,
    analyzerVersion: update.analyzerVersion || null,
    powerShellVersion: update.powerShellVersion || null,
    warnings: update.warnings || [],
  };
  replacePowerShellFindings(version, update.findings || [], analysis);
  return true;
}

export function removeRetiredFindings(state) {
  for (const record of state.packages.values()) {
    for (const version of record.versions || []) {
      if (Array.isArray(version.findings)) {
        version.findings = version.findings.filter((finding) => !/^PSG-SUPPLY-004(?:-|$)/.test(finding.id || ''));
      }
    }
  }
}

export function mergeFindingsRefreshCheckpoint(state, checkpoint) {
  if (!state?.manifest || !(state.packages instanceof Map) || !checkpoint || checkpoint.id !== FINDINGS_REFRESH_ID) {
    throw new Error('The findings refresh checkpoint is invalid or uses a different ruleset.');
  }
  let merged = 0;
  let stale = 0;
  for (const update of checkpoint.updates || []) {
    if (mergeFindingsRefreshUpdate(state, update)) merged++;
    else stale++;
  }
  removeRetiredFindings(state);

  const previous = state.manifest.findingsRefresh;
  const progress = checkpoint.progress;
  if (progress?.id === FINDINGS_REFRESH_ID) {
    const currentUpdated = Date.parse(previous?.updatedAt || '');
    const incomingUpdated = Date.parse(progress.updatedAt || '');
    if (!Number.isFinite(currentUpdated) || !Number.isFinite(incomingUpdated) || incomingUpdated >= currentUpdated) {
      state.manifest.findingsRefresh = { ...progress };
    }
  }
  return { merged, stale, findingsRefresh: state.manifest.findingsRefresh };
}

export async function runFindingsRefreshBatch({
  state,
  gallery,
  batchSize = DEFAULT_FINDINGS_REFRESH_BATCH_SIZE,
  attemptedKeys = new Set(),
  runPssa = true,
  log = () => {},
  onUpdate = () => {},
} = {}) {
  if (!state?.manifest || !(state.packages instanceof Map)) throw new Error('Scanner state is invalid.');
  if (!gallery || typeof gallery.downloadPackage !== 'function') throw new Error('Gallery client must support exact package downloads.');
  const progress = state.manifest.findingsRefresh;
  if (!progress?.active || progress.id !== FINDINGS_REFRESH_ID) throw new Error('The findings refresh has not been started.');

  const batch = listFindingsRefreshCandidates(state)
    .filter((candidate) => !attemptedKeys.has(candidate.key))
    .slice(0, Math.max(1, Math.floor(Number(batchSize) || DEFAULT_FINDINGS_REFRESH_BATCH_SIZE)));
  if (!batch.length) {
    const completedAt = nowIso();
    const remaining = listFindingsRefreshCandidates(state).length;
    progress.active = false;
    progress.complete = remaining === 0 && progress.failed === 0;
    progress.updatedAt = completedAt;
    progress.completedAt = progress.complete ? completedAt : null;
    return { processed: 0, succeeded: 0, failed: 0, remaining, complete: progress.complete, updates: [], failures: [] };
  }

  const updates = [];
  const failures = [];
  let succeeded = 0;
  for (const candidate of batch) {
    attemptedKeys.add(candidate.key);
    const { record, version } = candidate;
    try {
      const nupkg = await gallery.downloadPackage(record.name, version.version);
      const packageSha256 = sha256(nupkg);
      if (version.packageSha256 && version.packageSha256 !== packageSha256) {
        throw new Error('The Gallery archive hash differs from the saved scan; a full package scan is required.');
      }
      const archive = inspectNupkg(nupkg, undefined, { includeBinaries: !version.packageSha256 });
      if (!archive.complete) throw new Error((archive.warnings || []).join(' ') || 'The package archive could not be fully inspected.');
      const analysis = await analyzePowerShellFindings(archive.files, { runPssa });
      if (!analysis.complete) throw new Error(analysis.error || 'PowerShell analysis did not complete.');
      const refreshedAt = nowIso();
      const update = {
        key: candidate.key,
        package: record.name,
        version: version.version,
        packageSha256,
        findings: analysis.findings,
        analyzerVersion: analysis.analyzerVersion,
        powerShellVersion: analysis.powerShellVersion,
        warnings: analysis.warnings || [],
        refreshedAt,
      };
      await onUpdate(update);
      replacePowerShellFindings(version, analysis.findings, analysis);
      updates.push(update);
      succeeded++;
      log({ event: 'finding_refresh_version', package: record.name, version: version.version, findingCount: analysis.findings.length });
    } catch (error) {
      const detail = safeString(error?.message || error, 800) || 'PowerShell findings refresh failed.';
      failures.push({ key: candidate.key, package: record.name, version: version.version, error: detail });
      log({ event: 'finding_refresh_error', package: record.name, version: version.version, error: detail });
    }
  }

  const completedAt = nowIso();
  progress.afterKey = batch.at(-1).key;
  progress.processed += batch.length;
  progress.succeeded += succeeded;
  progress.failed += failures.length;
  progress.lastErrors = [...(progress.lastErrors || []), ...failures].slice(-20);
  progress.updatedAt = completedAt;
  const remaining = listFindingsRefreshCandidates(state).filter((candidate) => !attemptedKeys.has(candidate.key)).length;
  if (remaining === 0) {
    progress.active = false;
    progress.complete = listFindingsRefreshCandidates(state).length === 0;
    progress.completedAt = progress.complete ? completedAt : null;
  }

  return {
    processed: batch.length,
    succeeded,
    failed: failures.length,
    remaining,
    complete: progress.complete,
    updates,
    failures,
  };
}

export function buildFindingsRefreshCheckpoint(state, updates, failures = []) {
  return {
    id: FINDINGS_REFRESH_ID,
    rulesetVersion: RULESET_VERSION,
    progress: structuredClone(state.manifest.findingsRefresh),
    updates,
    failures,
  };
}
