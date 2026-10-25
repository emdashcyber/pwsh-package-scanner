import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { addNotScannedVersion, emptyState, loadLocalState, mergePackageVersion, writeSnapshot } from '../scanner/state.js';
import {
  mergeIncompleteRecoveryCheckpoint,
  runIncompleteRecoveryBatch,
  startIncompleteRecovery,
} from '../scanner/incomplete-recovery.js';
import { createZip, packageEntries } from './helpers/zip-fixture.js';

function item(name, version = '1.0.0') {
  return {
    name,
    version,
    title: name,
    description: 'Gallery package ' + name,
    owners: 'owner',
    publishedAt: '2026-10-10T00:00:00Z',
    updatedAt: '2026-10-25T00:00:00Z',
    dependencies: [],
  };
}

function incompleteSnapshot(target) {
  return {
    package: target.name,
    version: target.version,
    assessment: 'incomplete',
    packageSha256: 'b'.repeat(64),
    scannedAt: '2026-10-10T00:00:00Z',
    scannerVersion: '0.1.0',
    rulesetVersion: '0.1.0',
    metadata: { publishedAt: target.publishedAt, updatedAt: target.updatedAt },
    dependencies: [],
    binaryArtifacts: [],
    fileInventory: [],
    findings: [{ id: 'PSSA-OLD', severity: 'low' }],
    coverage: { archive: false, powerShellAnalysis: true, dependencyResolution: true, advisories: true, binaryScanning: true },
    warnings: ['Legacy scan was incomplete.'],
  };
}

test('local recovery processes only incomplete versions and resumes from its saved key', async () => {
  const root = await mkdtemp(join(tmpdir(), 'gallery-incomplete-recovery-'));
  const publicDirectory = join(root, 'public');
  const bytes = createZip(packageEntries());
  try {
    await mkdir(join(publicDirectory, 'api', 'v1'), { recursive: true });
    const state = emptyState();
    state.manifest.bootstrap = { complete: true, afterId: '', startedAt: '2026-10-01T00:00:00Z' };
    for (const name of ['Alpha', 'Beta', 'Gamma']) {
      const target = item(name);
      mergePackageVersion(state, target, incompleteSnapshot(target));
    }
    const completed = item('Completed');
    mergePackageVersion(state, completed, {
      ...incompleteSnapshot(completed),
      assessment: 'complete',
      coverage: { archive: true, powerShellAnalysis: true, dependencyResolution: true, advisories: true, binaryScanning: true },
    });
    addNotScannedVersion(state, item('Historical', '0.1.0'));

    startIncompleteRecovery(state);
    const firstLookups = [];
    const gallery = {
      getPackageVersion: async (name, version) => {
        firstLookups.push(name + '@' + version);
        return { ...item(name, version), isAbsoluteLatest: name === 'Alpha' };
      },
      downloadPackage: async () => bytes,
      resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
    };
    const fetcher = async (url, options) => String(url).endsWith('/querybatch')
      ? Response.json({ results: JSON.parse(options.body).queries.map(() => ({ vulns: [] })) })
      : new Response('unexpected', { status: 404 });

    const firstBatch = await runIncompleteRecoveryBatch({
      state,
      gallery,
      batchSize: 1,
      concurrency: 1,
      runPssa: false,
      fetcher,
      curatedAdvisories: [],
    });
    assert.equal(firstBatch.processed, 1);
    assert.equal(firstBatch.completed, 1);
    assert.equal(state.packages.get('alpha').versions[0].assessment, 'complete');
    assert.equal(state.manifest.incompleteRecovery.afterKey, 'alpha@1.0.0');

    await writeSnapshot(state, publicDirectory);
    const resumedState = await loadLocalState(publicDirectory);
    assert.equal(resumedState.manifest.incompleteRecovery.afterKey, 'alpha@1.0.0');
    const resumedLookups = [];
    const resumedGallery = {
      ...gallery,
      getPackageVersion: async (name, version) => {
        resumedLookups.push(name + '@' + version);
        if (name === 'Beta') throw new Error('Gallery temporarily unavailable.');
        return { ...item(name, version), isAbsoluteLatest: name === 'Gamma' };
      },
    };

    const secondBatch = await runIncompleteRecoveryBatch({
      state: resumedState,
      gallery: resumedGallery,
      batchSize: 1,
      concurrency: 1,
      runPssa: false,
      fetcher,
      curatedAdvisories: [],
    });
    assert.deepEqual(resumedLookups, ['Beta@1.0.0']);
    assert.equal(secondBatch.failed, 1);
    assert.equal(resumedState.packages.get('beta').versions[0].assessment, 'incomplete');
    assert.match(resumedState.packages.get('beta').versions[0].lastAttemptError, /temporarily unavailable/);

    const thirdBatch = await runIncompleteRecoveryBatch({
      state: resumedState,
      gallery: resumedGallery,
      batchSize: 1,
      concurrency: 1,
      runPssa: false,
      fetcher,
      curatedAdvisories: [],
    });
    assert.equal(thirdBatch.complete, true);
    assert.equal(resumedState.packages.get('gamma').versions[0].assessment, 'complete');
    assert.equal(resumedState.packages.get('completed').versions[0].assessment, 'complete');
    assert.equal(resumedState.packages.get('historical').versions[0].assessment, 'not_scanned');
    assert.deepEqual(firstLookups, ['Alpha@1.0.0']);
    assert.deepEqual(resumedLookups, ['Beta@1.0.0', 'Gamma@1.0.0']);
    assert.equal(resumedState.manifest.incompleteRecovery.stillIncomplete, 1);

    const restarted = startIncompleteRecovery(resumedState, { restart: true });
    assert.equal(restarted.total, 1);
    assert.equal(restarted.afterKey, '');
    const finalBatch = await runIncompleteRecoveryBatch({
      state: resumedState,
      gallery: {
        ...resumedGallery,
        getPackageVersion: async (name, version) => ({ ...item(name, version) }),
      },
      batchSize: 1,
      concurrency: 1,
      runPssa: false,
      fetcher,
      curatedAdvisories: [],
    });
    assert.equal(finalBatch.completed, 1);
    assert.equal(resumedState.packages.get('beta').versions[0].assessment, 'complete');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('merges an old checkpoint into newer main without rescanning attempted versions', async () => {
  const current = emptyState();
  current.manifest.generatedAt = '2026-10-25T11:58:34.759Z';
  const checkpoint = emptyState();
  const startedAt = '2026-10-25T06:26:37.129Z';
  checkpoint.manifest.incompleteRecovery = {
    active: true,
    complete: false,
    afterKey: 'beta@1.0.0',
    total: 4,
    processed: 2,
    completed: 1,
    stillIncomplete: 3,
    failed: 0,
    startedAt,
    updatedAt: '2026-10-25T11:47:17.456Z',
    completedAt: null,
  };

  for (const name of ['Aardvark', 'Alpha', 'Beta', 'Gamma']) {
    const target = item(name);
    mergePackageVersion(current, target, incompleteSnapshot(target));
    current.packages.get(name.toLocaleLowerCase('en-US')).versions[0].lastAttemptAt = '2026-10-25T05:00:00.000Z';
  }
  current.packages.get('alpha').metadata.title = 'Current Gallery title';
  current.packages.get('alpha').versions[0].metadata.updatedAt = '2026-10-25T11:00:00.000Z';

  const recoveredAlpha = item('Alpha');
  mergePackageVersion(checkpoint, recoveredAlpha, {
    ...incompleteSnapshot(recoveredAlpha),
    assessment: 'complete',
    scannedAt: '2026-10-25T07:00:00.000Z',
    coverage: { archive: true, powerShellAnalysis: true, dependencyResolution: true, advisories: true, binaryScanning: true },
  });
  checkpoint.packages.get('alpha').versions[0].lastAttemptAt = '2026-10-25T07:00:00.000Z';

  const recoveredBeta = item('Beta');
  mergePackageVersion(checkpoint, recoveredBeta, incompleteSnapshot(recoveredBeta));
  checkpoint.packages.get('beta').versions[0].lastAttemptAt = '2026-10-25T07:05:00.000Z';

  const outcome = mergeIncompleteRecoveryCheckpoint(current, checkpoint);
  assert.equal(outcome.mergedAttempts, 2);
  assert.equal(outcome.pending, 2);
  assert.equal(current.packages.get('alpha').versions[0].assessment, 'complete');
  assert.equal(current.packages.get('alpha').metadata.title, 'Current Gallery title');
  assert.equal(current.packages.get('alpha').versions[0].metadata.updatedAt, '2026-10-25T11:00:00.000Z');
  assert.equal(current.packages.get('beta').versions[0].lastAttemptAt, '2026-10-25T07:05:00.000Z');
  assert.equal(current.manifest.incompleteRecovery.afterKey, '');
  assert.equal(current.manifest.incompleteRecovery.active, true);

  const attempted = [];
  const batch = await runIncompleteRecoveryBatch({
    state: current,
    gallery: {
      getPackageVersion: async (name, version) => {
        attempted.push(name + '@' + version);
        throw new Error('Gallery temporarily unavailable.');
      },
    },
    batchSize: 2,
    concurrency: 1,
    runPssa: false,
  });
  assert.deepEqual(attempted, ['Aardvark@1.0.0', 'Gamma@1.0.0']);
  assert.equal(batch.processed, 2);
  assert.equal(batch.complete, true);
});
