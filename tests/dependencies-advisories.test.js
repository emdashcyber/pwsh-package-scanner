import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveDependencyGraph } from '../scanner/dependencies.js';
import { scanAdvisoriesForVersion } from '../scanner/advisories.js';
import { scanGalleryPackage } from '../scanner/package-scanner.js';
import { createZip, packageEntries } from './helpers/zip-fixture.js';

test('dependency graph resolves the highest matching version range and transitive dependencies', async () => {
  const packages = {
    Core: [
      { version: '1.5.0', dependencies: [{ name: 'Nested', versionRange: '[1.0.0,2.0.0)' }] },
      { version: '2.0.0', dependencies: [] },
    ],
    Nested: [{ version: '1.8.0', dependencies: [] }, { version: '2.0.0', dependencies: [] }],
  };
  const gallery = { listPackageVersions: async (name) => packages[name] || [] };
  const graph = await resolveDependencyGraph([{ name: 'Core', versionRange: '[1.0.0,2.0.0)' }], gallery);
  assert.equal(graph.complete, true);
  assert.deepEqual(graph.dependencies.map((item) => [item.name, item.resolvedVersion, item.depth]), [
    ['Core', '1.5.0', 1],
    ['Nested', '1.8.0', 2],
  ]);
});

test('dependency graph distinguishes Gallery-missing packages from unsupported ranges', async () => {
  const graph = await resolveDependencyGraph([
    { name: 'Unknown', versionRange: 'workspace:^' },
    { name: 'Missing', versionRange: '[1.0.0,2.0.0)' },
  ], { listPackageVersions: async () => [] });
  assert.equal(graph.complete, false);
  assert.deepEqual(graph.dependencies.map((item) => item.status), ['unsupported_range', 'package_not_found']);
  assert.equal(graph.dependencies[1].relation, 'requires');
});

test('dependency graph records a missing Gallery package only after a successful lookup', async () => {
  const graph = await resolveDependencyGraph([{ name: 'Missing', versionRange: '*' }], {
    listPackageVersions: async () => [],
  });
  assert.equal(graph.complete, true);
  assert.equal(graph.dependencies[0].status, 'package_not_found');
  const failed = await resolveDependencyGraph([{ name: 'Transient', versionRange: '*' }], {
    listPackageVersions: async () => { const error = new Error('upstream failure'); error.status = 503; throw error; },
  });
  assert.equal(failed.complete, false);
  assert.equal(failed.dependencies[0].status, 'gallery_unavailable');
});

test('ModuleList containment is recorded as bundled without a false missing-dependency finding', async () => {
  const graph = await resolveDependencyGraph([{
    name: 'Az.Accounts', versionRange: '*', relation: 'contains', declarationSources: ['ModuleList'],
  }], { listPackageVersions: async () => [] });
  assert.equal(graph.complete, true);
  assert.equal(graph.dependencies[0].status, 'bundled');
  assert.equal(graph.dependencies[0].relation, 'contains');
});

test('a Gallery-missing required package emits a scoped dependency finding', async () => {
  const bytes = createZip(packageEntries({ dependencyXml: '<dependencies><dependency id="Missing" version="*" /></dependencies>' }));
  const result = await scanGalleryPackage({ name: 'Example', version: '1.0.0' }, {
    downloadPackage: async () => bytes,
    resolveDependencyGraph: async () => ({ dependencies: [{
      name: 'Missing', versionRange: '*', relation: 'requires', status: 'package_not_found',
      declarationSources: ['nuspec'], file: null, line: null,
    }], complete: true }),
  }, { runPssa: false, scanAdvisories: false });
  const finding = result.findings.find((item) => item.id === 'PSG-DEPENDENCY-001');
  assert.ok(finding);
  assert.match(finding.description, /private repository/);
  assert.equal(result.assessment, 'complete');
});

test('OSV fixed-version ranges match affected NuGet identities and carry high confidence', async () => {
  const advisory = {
    id: 'GHSA-example',
    summary: 'Example vulnerability',
    affected: [{
      package: { ecosystem: 'NuGet', name: 'Example' },
      ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }],
    }],
    references: [{ type: 'WEB', url: 'https://example.test/advisory' }],
  };
  const fetcher = async (url, options = {}) => {
    if (String(url).endsWith('/querybatch')) {
      const request = JSON.parse(options.body);
      return Response.json({ results: request.queries.map(() => ({ vulns: [{ id: advisory.id }] })) });
    }
    if (String(url).endsWith('/' + advisory.id)) return Response.json(advisory);
    throw new Error('Unexpected URL ' + url);
  };
  const result = await scanAdvisoriesForVersion({ package: 'Example', version: '1.5.0' }, [], {
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  }, { fetcher });
  assert.equal(result.complete, true);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].confidence, 'high');
  assert.equal(result.findings[0].advisoryId, advisory.id);
});

test('OSV service failures mark advisory coverage incomplete', async () => {
  const result = await scanAdvisoriesForVersion({ package: 'Example', version: '1.0.0' }, [], {
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  }, { fetcher: async () => new Response('unavailable', { status: 503 }) });
  assert.equal(result.complete, false);
  assert.match(result.error, /503/);
});
