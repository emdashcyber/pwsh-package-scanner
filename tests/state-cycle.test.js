import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { addNotScannedVersion, buildCoverage, emptyState, loadLocalState, loadPublishedState, loadScanState, mergePackageVersion, resultPath, writeSnapshot } from '../scanner/state.js';
import { runScanCycle } from '../scanner/scan-cycle.js';
import { createZip, packageEntries } from './helpers/zip-fixture.js';

const item = {
  name: 'Example', version: '1.0.0', title: 'Example', description: 'Package',
  updatedAt: '2026-10-10T00:00:00Z', publishedAt: '2026-10-10T00:00:00Z',
  isAbsoluteLatest: true, dependencies: [],
};

function snapshot(itemVersion = item, result = {}) {
  return {
    package: itemVersion.name,
    version: itemVersion.version,
    assessment: 'complete',
    packageSha256: 'a'.repeat(64),
    scannedAt: '2026-10-10T00:00:00Z',
    scannerVersion: '0.1.0',
    rulesetVersion: '0.1.0',
    metadata: { title: 'Example', updatedAt: itemVersion.updatedAt },
    dependencies: [],
    fileInventory: [],
    findings: [],
    coverage: { archive: true, powerShellAnalysis: true, dependencyResolution: true, advisories: true },
    warnings: [],
    ...result,
  };
}

test('overlapping update and reconciliation feeds deduplicate a package version', async () => {
  const state = emptyState();
  state.manifest.bootstrap = { complete: true, afterId: '', startedAt: '2026-10-01T00:00:00Z' };
  state.manifest.galleryUpdatedThrough = '2026-10-10T00:00:00Z';
  const bytes = createZip(packageEntries());
  let downloads = 0;
  const gallery = {
    listUpdatedSince: async () => [item, item],
    listLatestAfter: async () => [item],
    downloadPackage: async () => { downloads++; return bytes; },
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  };
  const outcome = await runScanCycle({
    state, gallery, runPssa: false,
    fetcher: async (url, options) => String(url).endsWith('/querybatch')
      ? Response.json({ results: JSON.parse(options.body).queries.map(() => ({ vulns: [] })) })
      : new Response('unexpected', { status: 404 }),
  });
  assert.equal(downloads, 1);
  assert.equal(outcome.changed, 1);
  assert.equal(state.packages.get('example').versions.length, 1);
  assert.equal(state.packages.get('example').versions[0].assessment, 'complete');
});

test('baseline lists older known versions as unscanned and scans versions published after launch', async () => {
  const state = emptyState();
  state.manifest.bootstrap = { complete: false, afterId: '', startedAt: '2026-10-01T00:00:00Z' };
  const old = { ...item, version: '1.0.0', publishedAt: '2026-09-01T00:00:00Z', updatedAt: '2026-09-01T00:00:00Z', isAbsoluteLatest: false };
  const later = { ...item, version: '1.1.0', publishedAt: '2026-10-05T00:00:00Z', updatedAt: '2026-10-05T00:00:00Z', isAbsoluteLatest: false };
  const latest = { ...item, version: '1.2.0', publishedAt: '2026-10-10T00:00:00Z', updatedAt: '2026-10-10T00:00:00Z', isAbsoluteLatest: true };
  const bytes = createZip(packageEntries());
  const downloads = [];
  const gallery = {
    listLatestAfter: async () => [latest],
    listUpdatedSince: async () => [],
    listPackageVersions: async () => [old, later, latest],
    downloadPackage: async (_name, version) => { downloads.push(version); return bytes; },
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  };
  await runScanCycle({
    state, gallery, runPssa: false,
    fetcher: async (url, options) => String(url).endsWith('/querybatch')
      ? Response.json({ results: JSON.parse(options.body).queries.map(() => ({ vulns: [] })) })
      : new Response('unexpected', { status: 404 }),
  });
  const record = state.packages.get('example');
  assert.equal(record.latestVersion, '1.2.0');
  assert.deepEqual(record.versions.map((entry) => [entry.version, entry.assessment]), [
    ['1.0.0', 'not_scanned'],
    ['1.1.0', 'complete'],
    ['1.2.0', 'complete'],
  ]);
  assert.deepEqual(downloads.sort(), ['1.1.0', '1.2.0']);
  assert.equal(buildCoverage(state).notScannedVersions, 1);
});

test('upstream failures leave the last successful timestamp and package data intact', async () => {
  const state = emptyState();
  state.manifest.status = 'ready';
  state.manifest.bootstrap = { complete: true, afterId: '', startedAt: null };
  state.manifest.lastSuccessfulScan = '2026-10-01T00:00:00Z';
  mergePackageVersion(state, item, snapshot());
  const outcome = await runScanCycle({
    state,
    gallery: {
      listUpdatedSince: async () => { throw new Error('Gallery unavailable'); },
      listLatestAfter: async () => { throw new Error('Gallery unavailable'); },
    },
  });
  assert.equal(outcome.feedSucceeded, false);
  assert.equal(state.manifest.lastSuccessfulScan, '2026-10-01T00:00:00Z');
  assert.equal(state.manifest.status, 'degraded');
  assert.equal(state.packages.get('example').versions[0].packageSha256, 'a'.repeat(64));
});

test('package-level incomplete checks do not degrade service health and failed first scans retry', async () => {
  const state = emptyState();
  state.manifest.bootstrap = { complete: true, afterId: '', startedAt: null };
  const recentPublishedAt = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const recentItem = { ...item, publishedAt: recentPublishedAt, updatedAt: recentPublishedAt };
  const oldIncomplete = {
    ...item,
    name: 'OldExample',
    version: '0.9.0',
    publishedAt: '2026-10-10T00:00:00Z',
    updatedAt: '2026-10-10T00:00:00Z',
    isAbsoluteLatest: false,
  };
  mergePackageVersion(state, oldIncomplete, snapshot(oldIncomplete, { assessment: 'incomplete', scannedAt: null }));
  const outcome = await runScanCycle({
    state,
    gallery: {
      listUpdatedSince: async () => [recentItem],
      listLatestAfter: async () => [],
      downloadPackage: async () => { throw new Error('Package endpoint timed out'); },
    },
    runPssa: false,
  });
  assert.equal(outcome.feedSucceeded, true);
  assert.equal(state.manifest.status, 'ready');
  assert.equal(state.manifest.sourceStatus, 'available');
  assert.equal(buildCoverage(state).incompleteVersions, 2);
  const downloads = [];
  const recovered = await runScanCycle({
    state,
    gallery: {
      listUpdatedSince: async () => [recentItem, oldIncomplete],
      listLatestAfter: async () => [],
      downloadPackage: async (_name, version) => {
        downloads.push(version);
        return createZip(packageEntries());
      },
      resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
    },
    fetcher: async (url, options) => String(url).endsWith('/querybatch')
      ? Response.json({ results: JSON.parse(options.body).queries.map(() => ({ vulns: [] })) })
      : new Response('unexpected', { status: 404 }),
    runPssa: false,
  });
  assert.equal(recovered.state.packages.get('example').versions[0].assessment, 'complete');
  assert.deepEqual(downloads, ['1.0.0']);
  assert.equal(recovered.state.packages.get('oldexample').versions[0].assessment, 'incomplete');
});

test('the legacy result refresh cursor closes without rescanning completed versions', async () => {
  const state = emptyState();
  state.manifest.bootstrap = { complete: true, afterId: '', startedAt: null };
  state.manifest.resultRefresh = {
    id: 'binary-dependency-2026-10',
    complete: false,
    afterKey: 'addsactiveaccountaudit@1.2.0',
    total: 17834,
  };
  const older = { ...item, version: '0.9.0', isAbsoluteLatest: false };
  mergePackageVersion(state, item, snapshot());
  mergePackageVersion(state, older, snapshot(older));
  const bytes = createZip(packageEntries());
  let downloads = 0;
  const gallery = {
    listUpdatedSince: async () => [],
    listLatestAfter: async () => [],
    downloadPackage: async () => { downloads++; return bytes; },
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  };
  const fetcher = async (url, options) => String(url).endsWith('/querybatch')
    ? Response.json({ results: JSON.parse(options.body).queries.map(() => ({ vulns: [] })) })
    : new Response('unexpected', { status: 404 });
  const outcome = await runScanCycle({ state, gallery, fetcher, runPssa: false });
  assert.equal(outcome.state.manifest.resultRefresh.complete, true);
  assert.equal(outcome.state.manifest.resultRefresh.afterKey, '');
  assert.equal(outcome.state.manifest.resultRefresh.total, 0);
  assert.equal(outcome.state.manifest.lastBatch.resultRefreshProcessed, 0);
  assert.equal(downloads, 0);
});

test('Gallery update metadata changes do not rescan completed package versions', async () => {
  const state = emptyState();
  state.manifest.status = 'ready';
  state.manifest.bootstrap = { complete: true, afterId: '', startedAt: null };
  state.manifest.galleryUpdatedThrough = '2026-10-01T00:00:00Z';
  mergePackageVersion(state, item, snapshot({ ...item, updatedAt: '2026-10-01T00:00:00Z' }));
  const updated = { ...item, updatedAt: '2026-10-10T00:00:00Z' };
  let downloads = 0;
  await runScanCycle({
    state,
    gallery: {
      listUpdatedSince: async () => [updated],
      listLatestAfter: async () => [],
      downloadPackage: async () => {
        downloads++;
        throw new Error('Completed versions should not be downloaded again.');
      },
    },
  });
  const version = state.packages.get('example').versions[0];
  assert.equal(version.assessment, 'complete');
  assert.equal(version.packageSha256, 'a'.repeat(64));
  assert.equal(version.scannedAt, '2026-10-10T00:00:00Z');
  assert.equal(version.metadata.updatedAt, updated.updatedAt);
  assert.equal(downloads, 0);
});

test('advisory refresh cursor does not skip records after OSV failures', async () => {
  const state = emptyState();
  state.manifest.status = 'ready';
  state.manifest.bootstrap = { complete: true, afterId: '', startedAt: null };
  mergePackageVersion(state, item, snapshot());
  const older = { ...item, version: '0.9.0', isAbsoluteLatest: false };
  mergePackageVersion(state, older, snapshot(older));
  const outcome = await runScanCycle({
    state,
    gallery: {
      listUpdatedSince: async () => [],
      listLatestAfter: async () => [],
    },
    refreshAdvisories: true,
    advisoryBatchSize: 2,
    fetcher: async () => new Response('OSV unavailable', { status: 503 }),
  });
  assert.equal(outcome.advisoryRefresh.complete, false);
  assert.equal(state.manifest.advisoryRefreshCursor || '', '');
  assert.equal(state.manifest.status, 'ready');
});

test('published API snapshot contains searchable catalog shards and per-version results', async () => {
  const root = await mkdtemp(join(tmpdir(), 'gallery-snapshot-test-'));
  try {
    const state = emptyState();
    mergePackageVersion(state, item, snapshot(item, { findings: [
      { id: 'PSG-SECRET-001', severity: 'high' },
      { id: 'PSSA-PSAvoidUsingInvokeExpression', severity: 'medium' },
    ] }));
    addNotScannedVersion(state, { ...item, version: '0.9.0', publishedAt: '2025-09-01T00:00:00Z' });
    assert.equal(state.packages.get('example').versions.find((version) => version.version === '0.9.0').metadata.description, undefined);
    const publicDirectory = join(root, 'public');
    await mkdir(join(publicDirectory, 'api', 'v1'), { recursive: true });
    await writeFile(join(publicDirectory, 'api', 'v1', 'openapi.json'), '{"openapi":"3.1.0"}');
    const manifest = await writeSnapshot(state, publicDirectory);
    assert.equal(manifest.shards.length, 1);
    assert.equal(manifest.stateShards.length, 1);
    assert.match(manifest.stateShards[0], /^state\/[0-9a-f]{2}\.json\.gz$/);
    const apiRoot = join(root, 'public', 'api', 'v1');
    const shard = JSON.parse(await readFile(join(apiRoot, manifest.shards[0]), 'utf8'));
    assert.equal(shard.packages[0].name, 'Example');
    assert.equal(shard.packages[0].latestAssessment, 'complete');
    assert.equal(shard.packages[0].totalFindingCount, 2);
    assert.deepEqual(shard.packages[0].versions.find((version) => version.version === '1.0.0').findingIds, [
      'PSG-SECRET-001', 'PSSA-PSAvoidUsingInvokeExpression',
    ]);
    const olderSummary = shard.packages[0].versions.find((version) => version.version === '0.9.0');
    assert.equal(olderSummary.assessment, 'not_scanned');
    assert.equal(olderSummary.resultPath, undefined);
    assert.equal(olderSummary.publishedAt, '2025-09-01T00:00:00Z');
    const result = JSON.parse(await readFile(join(apiRoot, resultPath('Example', '1.0.0')), 'utf8'));
    assert.equal(result.schemaVersion, '1.1');
    assert.match(resultPath('Example', '1.0.0'), /^packages\/[0-9a-f]{2}\/.+\/.+\.json$/);
    assert.equal(result.packageSha256, 'a'.repeat(64));
    assert.equal(result.assessment, 'complete');
    await assert.rejects(readFile(join(apiRoot, resultPath('Example', '0.9.0')), 'utf8'), { code: 'ENOENT' });
    const stateShard = JSON.parse(gunzipSync(await readFile(join(apiRoot, manifest.stateShards[0]))).toString('utf8'));
    const compactOlder = stateShard.packages[0].versions.find((version) => version.version === '0.9.0');
    assert.equal(compactOlder.metadata.description, undefined);
    const loaded = await loadLocalState(join(root, 'public'));
    assert.equal(loaded.packages.get('example').versions.find((version) => version.version === '0.9.0').assessment, 'not_scanned');
    const loadedPublished = await loadPublishedState('https://example.test/api/v1/', async (url) => {
      const parsed = new URL(url);
      const relativePath = parsed.pathname.split('/api/v1/')[1];
      if (relativePath === 'manifest.json' || relativePath.startsWith('state/')) {
        return new Response(await readFile(join(apiRoot, relativePath)));
      }
      return new Response('', { status: 404 });
    });
    assert.equal(loadedPublished.packages.get('example').versions.find((version) => version.version === '0.9.0').assessment, 'not_scanned');
    assert.equal(await readFile(join(apiRoot, 'openapi.json'), 'utf8'), '{"openapi":"3.1.0"}');

    const priorManifest = await readFile(join(apiRoot, 'manifest.json'), 'utf8');
    state.packages.get('example').metadata.self = state.packages.get('example');
    await assert.rejects(writeSnapshot(state, publicDirectory), /circular/i);
    assert.equal(await readFile(join(apiRoot, 'manifest.json'), 'utf8'), priorManifest);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('local bootstrap resumes from its saved snapshot across batches', async () => {
  const root = await mkdtemp(join(tmpdir(), 'gallery-local-bootstrap-'));
  const publicDirectory = join(root, 'public');
  const packages = [
    { ...item, name: 'Alpha', version: '1.0.0' },
    { ...item, name: 'Beta', version: '2.0.0' },
  ];
  const archive = createZip(packageEntries());
  let incrementalCalls = 0;
  let latestCalls = 0;
  const gallery = {
    listLatestAfter: async (afterId, limit) => {
      latestCalls++;
      return packages.filter((pkg) => pkg.name > afterId).slice(0, limit);
    },
    listUpdatedSince: async () => { incrementalCalls++; return []; },
    listPackageVersions: async (name) => packages.filter((pkg) => pkg.name === name),
    downloadPackage: async () => archive,
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  };
  const fetcher = async (url, options) => String(url).endsWith('/querybatch')
    ? Response.json({ results: JSON.parse(options.body).queries.map(() => ({ vulns: [] })) })
    : new Response('unexpected', { status: 404 });
  const runBatch = (state, bootstrapOnly = true) => runScanCycle({
    state,
    gallery,
    fetcher,
    runPssa: false,
    bootstrapOnly,
    bootstrapBatchSize: 1,
    reconcileBatchSize: 1,
    concurrency: 1,
  });

  try {
    let state = emptyState();
    const first = await runBatch(state);
    assert.equal(first.state.manifest.bootstrap.afterId, 'Alpha');
    assert.equal(incrementalCalls, 0);
    await writeSnapshot(state, publicDirectory);

    state = await loadLocalState(publicDirectory);
    const second = await runBatch(state);
    assert.equal(second.state.manifest.bootstrap.afterId, 'Beta');
    await writeSnapshot(state, publicDirectory);

    state = await loadLocalState(publicDirectory);
    const final = await runBatch(state);
    assert.equal(final.state.manifest.bootstrap.complete, true);
    assert.deepEqual([...final.state.packages.values()].map((record) => record.name).sort(), ['Alpha', 'Beta']);
    assert.equal(buildCoverage(final.state).unscannedLatestVersions, 0);
    assert.equal(incrementalCalls, 0);
    assert.equal(latestCalls, 3);

    await runBatch(state, false);
    assert.equal(incrementalCalls, 1);
    assert.equal(latestCalls, 4);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('checked-in snapshot is preferred over a potentially lagging Pages copy', async () => {
  const root = await mkdtemp(join(tmpdir(), 'gallery-local-fallback-'));
  const publicDirectory = join(root, 'public');
  try {
    const state = emptyState();
    mergePackageVersion(state, item, snapshot());
    await writeSnapshot(state, publicDirectory);
    let pageFetches = 0;
    const loaded = await loadScanState('https://example.test/api/v1/', {
      publicDirectory,
      fetcher: async () => { pageFetches++; throw new Error('Pages copy should not be needed.'); },
    });
    assert.equal(loaded.source, 'local');
    assert.equal(pageFetches, 0);
    assert.equal(loaded.state.packages.get('example').versions[0].assessment, 'complete');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('a network failure while loading published state is not mistaken for an empty baseline', async () => {
  await assert.rejects(loadPublishedState('https://example.test/api/v1/', async () => {
    throw new Error('offline');
  }), /offline/);
});

test('a missing published manifest is a valid empty initial baseline', async () => {
  const state = await loadPublishedState('https://example.test/api/v1/', async () => new Response('', { status: 404 }));
  assert.equal(state.manifest.status, 'bootstrap_required');
  assert.equal(state.packages.size, 0);
});
