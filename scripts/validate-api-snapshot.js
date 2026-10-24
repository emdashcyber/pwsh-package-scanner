import { lstat, readFile, readdir } from 'node:fs/promises';
import { join, relative, resolve, sep } from 'node:path';

const root = resolve(process.argv[2] || 'site/public/api/v1');
const files = [];

async function collect(path) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    const fullPath = join(path, entry.name);
    const metadata = await lstat(fullPath);
    if (metadata.isSymbolicLink()) throw new Error('API snapshot contains a symbolic link.');
    if (metadata.isDirectory()) await collect(fullPath);
    else if (metadata.isFile()) files.push(fullPath);
    else throw new Error('API snapshot contains an unsupported filesystem entry.');
  }
}

await collect(root);
const relativePaths = files.map((path) => relative(root, path).split(sep).join('/'));
for (const path of relativePaths) {
  if (!/^(?:manifest\.json|openapi\.json|shards\/[0-9a-f]{2}\.json|state\/[0-9a-f]{2}\.json\.gz|packages\/[0-9a-f]{2}\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\.json)$/.test(path)) {
    throw new Error('API snapshot contains a path outside the published data layout: ' + path);
  }
}
if (!relativePaths.includes('manifest.json') || !relativePaths.includes('openapi.json')) {
  throw new Error('API snapshot is missing its manifest or OpenAPI document.');
}

const manifestText = await readFile(join(root, 'manifest.json'), 'utf8');
if (manifestText.length > 2 * 1024 * 1024) throw new Error('API manifest exceeds its size limit.');
const manifest = JSON.parse(manifestText);
if (!['ready', 'degraded', 'bootstrap_required'].includes(manifest.status)) throw new Error('API manifest has an invalid service status.');
if (!Array.isArray(manifest.shards) || !Array.isArray(manifest.stateShards)) throw new Error('API manifest shard lists are invalid.');
for (const path of [...manifest.shards, ...manifest.stateShards]) {
  if (typeof path !== 'string' || path.startsWith('/') || path.split('/').includes('..')) throw new Error('API manifest references an unsafe shard path.');
  if (!relativePaths.includes(path)) throw new Error('API manifest references a missing shard: ' + path);
}

for (const path of files) {
  if (!path.endsWith('.json')) continue;
  const metadata = await lstat(path);
  if (metadata.size > 16 * 1024 * 1024) throw new Error('API JSON document exceeds its size limit: ' + relative(root, path));
  JSON.parse(await readFile(path, 'utf8'));
}
if (manifest.status === 'ready' && !manifest.lastSuccessfulScan) throw new Error('Ready manifest has no successful scan timestamp.');
process.stdout.write(JSON.stringify({ files: files.length, status: manifest.status, lastSuccessfulScan: manifest.lastSuccessfulScan }) + '\n');
