import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const manifest = JSON.parse(await readFile(new URL('../public/api/v1/manifest.json', import.meta.url), 'utf8'));
const openapi = JSON.parse(await readFile(new URL('../public/api/v1/openapi.json', import.meta.url), 'utf8'));

test('static API manifest matches its OpenAPI coverage and assessment contract', () => {
  const manifestSchema = openapi.components.schemas.Manifest;
  const coverageSchema = openapi.components.schemas.Coverage;
  assert.equal(manifest.schemaVersion, '1.0');
  assert.ok(manifestSchema.properties.status.enum.includes(manifest.status));
  for (const field of coverageSchema.required) assert.ok(field in manifest.coverage, 'missing coverage field ' + field);
  assert.deepEqual(openapi.components.schemas.Assessment.enum, ['complete', 'incomplete', 'not_scanned']);
  assert.ok(openapi.paths['/manifest.json']);
  assert.ok(openapi.paths['/shards/{shard}.json']);
  assert.ok(openapi.paths['/packages/{packageKey}/{versionKey}.json']);
});

test('catalog API includes assessment and evidence contracts without a safe verdict', () => {
  const packageSchema = openapi.components.schemas.CatalogPackage;
  const catalogVersionSchema = openapi.components.schemas.CatalogVersion;
  const versionSchema = openapi.components.schemas.PackageVersion;
  const findingSchema = openapi.components.schemas.Finding;
  assert.ok(packageSchema.properties.latestAssessment.$ref.endsWith('/Assessment'));
  assert.equal(catalogVersionSchema.properties.resultPath.type, 'string');
  assert.ok(!catalogVersionSchema.required.includes('resultPath'));
  assert.ok(catalogVersionSchema.properties.publishedAt);
  assert.equal(catalogVersionSchema.properties.publishedAt.format, undefined);
  assert.ok(versionSchema.required.includes('findings'));
  assert.ok(findingSchema.required.includes('confidence'));
  assert.ok(findingSchema.required.includes('evidence'));
  assert.ok(openapi.info.description.includes('not proof'));
});
