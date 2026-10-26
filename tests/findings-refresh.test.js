import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { emptyState, getShardKey, resultPath, writeSnapshot } from '../scanner/state.js';
import { RULESET_VERSION } from '../scanner/package-scanner.js';
import {
  listFindingsRefreshCandidates,
  mergeFindingsRefreshCheckpoint,
  runFindingsRefreshBatch,
  startFindingsRefresh,
} from '../scanner/findings-refresh.js';
import { sha256 } from '../scanner/util.js';
import { createZip, packageEntries } from './helpers/zip-fixture.js';

function versionRecord({ version, assessment, rulesetVersion = '0.2.0', packageSha256, findings = [] }) {
  return {
    package: 'Example',
    version,
    assessment,
    rulesetVersion,
    packageSha256,
    scannedAt: '2026-01-01T00:00:00.000Z',
    findings,
    warnings: [],
    tools: { powerShell: '7.6.8', psscriptAnalyzer: '1.25.0' },
    coverage: { powerShellAnalysis: true },
    metadata: { publishedAt: null, updatedAt: null },
  };
}

function findingsState(versions) {
  const state = emptyState();
  state.packages.set('example', {
    name: 'Example',
    latestVersion: versions[0]?.version || null,
    metadata: {},
    versions,
  });
  return state;
}

test('refresh candidates include assessed stale versions and exclude not_scanned or current versions', () => {
  const state = findingsState([
    versionRecord({ version: '1.0.0', assessment: 'incomplete' }),
    versionRecord({ version: '2.0.0', assessment: 'complete', rulesetVersion: RULESET_VERSION }),
    versionRecord({ version: '3.0.0', assessment: 'not_scanned' }),
  ]);
  assert.deepEqual(listFindingsRefreshCandidates(state).map((item) => item.key), ['example@1.0.0']);
  const progress = startFindingsRefresh(state);
  assert.equal(progress.total, 1);
  assert.equal(progress.active, true);
});

test('one refresh batch replaces only PowerShell findings and preserves assessment and unrelated data', async () => {
  const packageBytes = createZip(packageEntries({ script: '$payload = Invoke-WebRequest $url\nInvoke-Expression $payload' }));
  const packageHash = sha256(packageBytes);
  const state = findingsState([
    versionRecord({
      version: '1.0.0',
      assessment: 'incomplete',
      packageSha256: packageHash,
      findings: [
        { id: 'PSSA-PowerShellParseError', category: 'static_rule' },
        { id: 'PSG-BEHAVIOR-001', category: 'behavior' },
        { id: 'ADVISORY-GHSA-example', category: 'advisory' },
        { id: 'PSG-SUPPLY-004', category: 'supply_chain' },
      ],
    }),
    versionRecord({ version: '2.0.0', assessment: 'not_scanned', packageSha256: null }),
  ]);
  startFindingsRefresh(state);
  const result = await runFindingsRefreshBatch({
    state,
    gallery: { downloadPackage: async () => packageBytes },
    batchSize: 1,
    runPssa: false,
  });

  const refreshed = state.packages.get('example').versions[0];
  assert.equal(result.succeeded, 1);
  assert.equal(refreshed.assessment, 'incomplete');
  assert.equal(refreshed.scannedAt, '2026-01-01T00:00:00.000Z');
  assert.equal(refreshed.rulesetVersion, RULESET_VERSION);
  assert.deepEqual(refreshed.findings.map((finding) => finding.id).sort(), [
    'ADVISORY-GHSA-example',
    'PSG-BEHAVIOR-001',
    'PSG-BEHAVIOR-002',
  ]);
  assert.equal(state.packages.get('example').versions[1].assessment, 'not_scanned');
});

test('a changed Gallery archive hash leaves the saved version unchanged and records a retryable failure', async () => {
  const packageBytes = createZip(packageEntries());
  const state = findingsState([
    versionRecord({
      version: '1.0.0',
      assessment: 'complete',
      packageSha256: sha256(Buffer.from('different saved archive')),
      findings: [{ id: 'ADVISORY-GHSA-example', category: 'advisory' }],
    }),
  ]);
  startFindingsRefresh(state);
  const result = await runFindingsRefreshBatch({
    state,
    gallery: { downloadPackage: async () => packageBytes },
    batchSize: 1,
    runPssa: false,
  });
  assert.equal(result.failed, 1);
  assert.equal(result.failures[0].version, '1.0.0');
  assert.equal(state.packages.get('example').versions[0].rulesetVersion, '0.2.0');
  assert.deepEqual(state.packages.get('example').versions[0].findings.map((finding) => finding.id), ['ADVISORY-GHSA-example']);
});

test('checkpoint merges matching hashes into current assessed versions and leaves not_scanned untouched', () => {
  const matchingHash = 'a'.repeat(64);
  const state = findingsState([
    versionRecord({ version: '1.0.0', assessment: 'incomplete', packageSha256: matchingHash }),
    versionRecord({ version: '2.0.0', assessment: 'complete', packageSha256: 'b'.repeat(64) }),
    versionRecord({ version: '3.0.0', assessment: 'not_scanned', packageSha256: null }),
  ]);
  state.packages.get('example').versions.forEach((version) => {
    version.findings = [{ id: 'PSG-SUPPLY-004', category: 'supply_chain' }];
  });
  const checkpoint = {
    id: 'finding-rules-' + RULESET_VERSION,
    progress: {
      id: 'finding-rules-' + RULESET_VERSION,
      active: true,
      complete: false,
      total: 2,
      processed: 1,
      succeeded: 1,
      failed: 0,
      updatedAt: '2026-10-26T00:00:00.000Z',
    },
    updates: [{
      package: 'Example',
      version: '1.0.0',
      packageSha256: matchingHash,
      findings: [{ id: 'PSG-BEHAVIOR-001', category: 'behavior' }],
      analyzerVersion: null,
      powerShellVersion: null,
    }, {
      package: 'Example',
      version: '2.0.0',
      packageSha256: 'c'.repeat(64),
      findings: [],
    }, {
      package: 'Example',
      version: '3.0.0',
      packageSha256: 'd'.repeat(64),
      findings: [],
    }],
  };
  const merged = mergeFindingsRefreshCheckpoint(state, checkpoint);
  assert.equal(merged.merged, 1);
  assert.equal(merged.stale, 2);
  assert.deepEqual(state.packages.get('example').versions.map((version) => version.findings.map((finding) => finding.id)), [
    ['PSG-BEHAVIOR-001'],
    [],
    [],
  ]);
  assert.equal(state.packages.get('example').versions[2].assessment, 'not_scanned');
  assert.equal(merged.findingsRefresh.active, true);
});

test('snapshot rebuild publishes refreshed result documents and catalog finding IDs', async () => {
  const packageHash = 'e'.repeat(64);
  const state = findingsState([
    versionRecord({
      version: '1.0.0',
      assessment: 'complete',
      packageSha256: packageHash,
      findings: [
        { id: 'PSSA-PowerShellParseError', category: 'static_rule' },
        { id: 'PSG-SUPPLY-004-deadbeef', category: 'supply_chain' },
      ],
    }),
  ]);
  mergeFindingsRefreshCheckpoint(state, {
    id: 'finding-rules-' + RULESET_VERSION,
    progress: {
      id: 'finding-rules-' + RULESET_VERSION,
      active: false,
      complete: true,
      total: 1,
      processed: 1,
      succeeded: 1,
      failed: 0,
      updatedAt: '2026-10-26T00:00:00.000Z',
    },
    updates: [{
      package: 'Example',
      version: '1.0.0',
      packageSha256: packageHash,
      findings: [{ id: 'PSG-BEHAVIOR-001', category: 'behavior' }],
    }],
  });

  const publicDirectory = await mkdtemp(join(tmpdir(), 'findings-refresh-snapshot-'));
  try {
    await writeSnapshot(state, publicDirectory);
    const apiRoot = join(publicDirectory, 'api', 'v1');
    const result = JSON.parse(await readFile(join(apiRoot, resultPath('Example', '1.0.0')), 'utf8'));
    const catalog = JSON.parse(await readFile(join(apiRoot, 'shards', getShardKey('Example') + '.json'), 'utf8'));
    assert.deepEqual(result.findings.map((finding) => finding.id), ['PSG-BEHAVIOR-001']);
    assert.deepEqual(catalog.packages[0].versions.find((version) => version.version === '1.0.0').findingIds, ['PSG-BEHAVIOR-001']);
  } finally {
    await rm(publicDirectory, { recursive: true, force: true });
  }
});
