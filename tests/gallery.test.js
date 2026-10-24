import test from 'node:test';
import assert from 'node:assert/strict';
import { GalleryClient } from '../scanner/gallery.js';

function feed(name, version = '1.0.0') {
  return `<feed><entry><id>https://gallery.test/api/v2/Packages(Id='Wrong',Version='9.9.9')</id><title>Atom title</title><content><m:properties><d:Id>${name}</d:Id><d:Version>${version}</d:Version><d:LastUpdated>2026-10-10T00:00:00Z</d:LastUpdated><d:IsAbsoluteLatestVersion>true</d:IsAbsoluteLatestVersion></m:properties></content></entry></feed>`;
}

test('Gallery pagination follows same-origin OData next links', async () => {
  const calls = [];
  const client = new GalleryClient({
    apiRoot: 'https://gallery.test/api/v2',
    retryCount: 0,
    fetcher: async (url) => {
      calls.push(new URL(url));
      if (calls.length === 1) return new Response(`<feed><link rel="next" href="/api/v2/Packages?page=2" />${feed('Alpha').replace('<feed>', '').replace('</feed>', '')}</feed>`);
      return new Response(feed('Beta'));
    },
  });
  const result = await client.listLatestAfter('', 10);
  assert.deepEqual(result.map((item) => item.name), ['Alpha', 'Beta']);
  assert.equal(calls.length, 2);
  assert.match(calls[0].searchParams.get('$filter'), /IsAbsoluteLatestVersion eq true/);
  assert.equal(calls[1].pathname, '/api/v2/Packages');
});

test('latest package feed preserves Gallery order for stable resume cursors', async () => {
  const client = new GalleryClient({
    apiRoot: 'https://gallery.test/api/v2',
    retryCount: 0,
    fetcher: async () => new Response(`<feed>${feed('Zeta').replace('<feed>', '').replace('</feed>', '')}${feed('Alpha').replace('<feed>', '').replace('</feed>', '')}</feed>`),
  });
  const result = await client.listLatestAfter('', 10);
  assert.deepEqual(result.map((item) => item.name), ['Zeta', 'Alpha']);
});

test('Gallery rejects pagination links that leave the HTTPS Gallery API origin', async () => {
  const client = new GalleryClient({
    apiRoot: 'https://gallery.test/api/v2', retryCount: 0,
    fetcher: async () => new Response(`<feed><link rel="next" href="https://attacker.test/api/v2/Packages" /></feed>`),
  });
  await assert.rejects(client.listLatestAfter('', 10), /outside the expected/);
});

test('Gallery retries transient failures with bounded backoff', async () => {
  let calls = 0;
  const waits = [];
  const client = new GalleryClient({
    apiRoot: 'https://gallery.test/api/v2', retryCount: 2,
    wait: async (ms) => waits.push(ms),
    fetcher: async () => ++calls === 1 ? new Response('busy', { status: 503 }) : new Response(feed('Ready')),
  });
  const result = await client.listLatestAfter('', 10);
  assert.equal(result[0].name, 'Ready');
  assert.equal(calls, 2);
  assert.equal(waits.length, 1);
  assert.ok(waits[0] <= 30_000);
});

test('Gallery preserves not-found responses for dependency resolution without retrying', async () => {
  let calls = 0;
  const client = new GalleryClient({
    apiRoot: 'https://gallery.test/api/v2',
    fetcher: async () => { calls++; return new Response('missing', { status: 404 }); },
  });
  await assert.rejects(client.listPackageVersions('Missing'), (error) => error.status === 404);
  assert.equal(calls, 1);
});

test('historical version cache is bounded and can be cleared between scan batches', async () => {
  const client = new GalleryClient({
    apiRoot: 'https://gallery.test/api/v2',
    retryCount: 0,
    versionCacheLimit: 2,
    fetcher: async () => new Response(feed('Alpha')),
  });
  await client.listPackageVersions('Alpha');
  await client.listPackageVersions('Beta');
  await client.listPackageVersions('Gamma');
  assert.equal(client.versionCache.size, 2);
  assert.equal(client.versionCache.has('alpha'), false);
  client.clearVersionCache();
  assert.equal(client.versionCache.size, 0);
});
