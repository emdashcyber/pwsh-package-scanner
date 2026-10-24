import { copyFile, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync, gzipSync } from 'node:zlib';
import { normalizePackageName, packageKey, sha256, versionKey, nowIso } from './util.js';

export const SITE_PUBLIC_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'site', 'public');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const MAX_STATE_SHARD_COMPRESSED_BYTES = 25 * 1024 * 1024;
const MAX_STATE_SHARD_BYTES = 100 * 1024 * 1024;
const packageVersionIndexes = new WeakMap();
const DEFAULT_MANIFEST = {
  schemaVersion: '1.0',
  status: 'bootstrap_required',
  generatedAt: null,
  lastAttemptAt: null,
  lastSuccessfulScan: null,
  galleryUpdatedThrough: null,
  advisoriesUpdatedAt: null,
  bootstrap: { complete: false, afterId: '', startedAt: null },
  reconciliation: { afterId: '' },
  coverage: {
    listedPackages: 0,
    scannedLatestVersions: 0,
    scannedVersions: 0,
    incompleteVersions: 0,
    unscannedLatestVersions: 0,
    notScannedVersions: 0,
  },
  shards: [],
  stateShards: [],
  notice: 'The initial catalog scan has not completed yet.',
};

export function emptyState() {
  return { manifest: structuredClone(DEFAULT_MANIFEST), packages: new Map() };
}

export function getShardKey(name) {
  return String(Number.parseInt(sha256(normalizePackageName(name)).slice(0, 2), 16) % 64).toString(16).padStart(2, '0');
}

export function resultPath(name, version) {
  return 'packages/' + getShardKey(name) + '/' + packageKey(name) + '/' + versionKey(version) + '.json';
}

function compactVersionRecord(version) {
  if (version.assessment !== 'not_scanned') return version;
  return {
    version: version.version,
    assessment: 'not_scanned',
    metadata: {
      publishedAt: version.metadata?.publishedAt || null,
      updatedAt: version.metadata?.updatedAt || null,
    },
  };
}

function parseStateShard(buffer, compressed) {
  if (buffer.length > (compressed ? MAX_STATE_SHARD_COMPRESSED_BYTES : MAX_STATE_SHARD_BYTES)) {
    throw new Error('State shard is too large.');
  }
  const contents = compressed
    ? gunzipSync(buffer, { maxOutputLength: MAX_STATE_SHARD_BYTES })
    : buffer;
  if (contents.length > MAX_STATE_SHARD_BYTES) throw new Error('State shard is too large.');
  const shard = JSON.parse(contents.toString('utf8'));
  if (!Array.isArray(shard.packages)) throw new Error('State shard has an invalid package list.');
  return shard;
}

function isValidStateShardPath(path) {
  return typeof path === 'string' && /^state\/[0-9a-f]{2}\.json(?:\.gz)?$/.test(path);
}

function getPackageVersionIndex(record) {
  let index = packageVersionIndexes.get(record);
  if (!index) {
    index = new Set(record.versions.map((version) => version.version));
    packageVersionIndexes.set(record, index);
  }
  return index;
}

export function mergePackageVersion(state, item, result, { replace = false } = {}) {
  const key = normalizePackageName(item.name || result.package);
  if (!key) return;
  let record = state.packages.get(key);
  if (!record) {
    record = {
      name: item.name || result.package,
      latestVersion: null,
      metadata: {},
      versions: [],
    };
    state.packages.set(key, record);
  }
  record.metadata = {
    ...record.metadata,
    title: item.title || result.metadata?.title || record.metadata.title || item.name,
    description: item.description || result.metadata?.description || record.metadata.description || '',
    owners: item.owners || result.metadata?.owners || record.metadata.owners || '',
    authors: item.authors || result.metadata?.authors || record.metadata.authors || '',
    projectUrl: item.projectUrl || result.metadata?.projectUrl || record.metadata.projectUrl || '',
    tags: item.tags || result.metadata?.tags || record.metadata.tags || [],
    updatedAt: item.updatedAt || result.metadata?.updatedAt || record.metadata.updatedAt || null,
  };
  const index = record.versions.findIndex((version) => version.version === (item.version || result.version));
  const versionRecord = { ...result, package: record.name, version: item.version || result.version };
  if (index >= 0) {
    if (replace && !versionRecord.scannedAt && record.versions[index].scannedAt) {
      record.versions[index] = {
        ...record.versions[index],
        lastAttemptAt: nowIso(),
        lastAttemptError: (versionRecord.warnings || []).join(' ').slice(0, 800) || 'The package could not be rescanned; the last successful result is retained.',
      };
    } else if (replace) record.versions[index] = versionRecord;
    else return;
  } else {
    record.versions.push(versionRecord);
    packageVersionIndexes.get(record)?.add(versionRecord.version);
  }
  record.versions.sort((a, b) => a.version.localeCompare(b.version, 'en', { numeric: true, sensitivity: 'base' }));
  if (item.isAbsoluteLatest || item.isLatest || !record.latestVersion) record.latestVersion = item.version;
}

export function mergePackageMetadata(state, item) {
  const key = normalizePackageName(item.name);
  if (!key) return;
  let record = state.packages.get(key);
  if (!record) {
    record = { name: item.name, latestVersion: null, metadata: {}, versions: [] };
    state.packages.set(key, record);
  }
  record.metadata = {
    ...record.metadata,
    title: item.title || record.metadata.title || item.name,
    description: item.description || record.metadata.description || '',
    owners: item.owners || record.metadata.owners || '',
    authors: item.authors || record.metadata.authors || '',
    projectUrl: item.projectUrl || record.metadata.projectUrl || '',
    tags: item.tags || record.metadata.tags || [],
    updatedAt: item.updatedAt || record.metadata.updatedAt || null,
  };
  if (item.isAbsoluteLatest || item.isLatest || !record.latestVersion) record.latestVersion = item.version;
}

export function addNotScannedVersion(state, item) {
  const key = normalizePackageName(item.name);
  if (!key || !item.version) return;
  let record = state.packages.get(key);
  if (!record) {
    record = { name: item.name, latestVersion: null, metadata: {}, versions: [] };
    state.packages.set(key, record);
  }
  const versionIndex = getPackageVersionIndex(record);
  if (versionIndex.has(item.version)) return;
  versionIndex.add(item.version);
  record.versions.push({
    version: item.version,
    assessment: 'not_scanned',
    metadata: {
      publishedAt: item.publishedAt || null,
      updatedAt: item.updatedAt || item.publishedAt || null,
    },
  });
}

export function findPackageRecord(state, name) {
  return state.packages.get(normalizePackageName(name)) || null;
}

export function findVersionRecord(state, name, version) {
  return findPackageRecord(state, name)?.versions.find((item) => item.version === version) || null;
}

function latestVersionRecord(record) {
  return record.versions.find((version) => version.version === record.latestVersion)
    || record.versions.at(-1)
    || null;
}

function topSeverity(findings) {
  for (const severity of SEVERITIES) {
    if ((findings || []).some((finding) => finding.severity === severity)) return severity;
  }
  return null;
}

export function buildCoverage(state) {
  const packages = [...state.packages.values()];
  let scannedLatestVersions = 0;
  let scannedVersions = 0;
  let incompleteVersions = 0;
  let unscannedLatestVersions = 0;
  let notScannedVersions = 0;
  for (const record of packages) {
    const latest = latestVersionRecord(record);
    if (!latest || latest.assessment === 'not_scanned') unscannedLatestVersions++;
    else scannedLatestVersions++;
    for (const version of record.versions) {
      if (version.assessment && version.assessment !== 'not_scanned') scannedVersions++;
      if (version.assessment === 'incomplete') incompleteVersions++;
      if (version.assessment === 'not_scanned') notScannedVersions++;
    }
  }
  return {
    listedPackages: packages.length,
    scannedLatestVersions,
    scannedVersions,
    incompleteVersions,
    unscannedLatestVersions,
    notScannedVersions,
  };
}

function catalogItem(record) {
  const latest = latestVersionRecord(record);
  const allVersions = [...record.versions].sort((a, b) => b.version.localeCompare(a.version, 'en', { numeric: true, sensitivity: 'base' }));
  return {
    name: record.name,
    title: record.metadata?.title || record.name,
    description: record.metadata?.description || '',
    owners: record.metadata?.owners || '',
    projectUrl: record.metadata?.projectUrl || '',
    tags: record.metadata?.tags || [],
    versionInventoryComplete: !record.metadata?.versionInventoryNote,
    versionInventoryNote: record.metadata?.versionInventoryNote || null,
    latestVersion: latest?.version || record.latestVersion,
    latestAssessment: latest?.assessment || 'not_scanned',
    latestFindingCount: latest?.findings?.length || 0,
    highestSeverity: topSeverity(latest?.findings),
    latestScannedAt: latest?.scannedAt || null,
    latestResultPath: latest && latest.assessment !== 'not_scanned' ? resultPath(record.name, latest.version) : null,
    versionCount: allVersions.length,
    versions: allVersions.map((version) => {
      const summary = {
        version: version.version,
        assessment: version.assessment || 'not_scanned',
      };
      if (version.assessment === 'not_scanned') {
        if (version.metadata?.publishedAt) summary.publishedAt = version.metadata.publishedAt;
        if (version.metadata?.updatedAt) summary.updatedAt = version.metadata.updatedAt;
      } else {
        summary.scannedAt = version.scannedAt || null;
        summary.publishedAt = version.metadata?.publishedAt || null;
        summary.updatedAt = version.metadata?.updatedAt || null;
        summary.findingCount = (version.findings || []).length;
        summary.highestSeverity = topSeverity(version.findings);
        summary.resultPath = resultPath(record.name, version.version);
      }
      return summary;
    }),
  };
}

export async function loadPublishedState(apiBaseUrl, fetcher = globalThis.fetch) {
  const state = emptyState();
  if (!apiBaseUrl) return state;
  const base = new URL(apiBaseUrl.endsWith('/') ? apiBaseUrl : apiBaseUrl + '/');
  const response = await fetcher(new URL('manifest.json', base), {
    headers: { accept: 'application/json', 'user-agent': 'EmDashCyber-PowerShell-Gallery-Scanner/0.1' },
    signal: AbortSignal.timeout(15_000),
  });
  if (response.status === 404) return state;
  if (!response.ok) throw new Error('Published state manifest returned HTTP ' + response.status + '.');
  const manifestText = await response.text();
  if (manifestText.length > 2 * 1024 * 1024) throw new Error('Published state manifest is too large.');
  const manifest = JSON.parse(manifestText);
  state.manifest = { ...structuredClone(DEFAULT_MANIFEST), ...manifest };
  if (!Array.isArray(manifest.stateShards) || !manifest.stateShards.length) {
    if (manifest.status === 'bootstrap_required' || manifest.coverage?.listedPackages === 0) return state;
    throw new Error('Published state manifest does not reference any state shards.');
  }
  for (const shardPath of manifest.stateShards) {
    if (!isValidStateShardPath(shardPath)) throw new Error('Published state contains an invalid shard path.');
    const url = new URL(shardPath, base);
    if (url.origin !== base.origin) throw new Error('Published state shard points outside the expected host.');
    const compressed = shardPath.endsWith('.gz');
    const shardResponse = await fetcher(url, {
      headers: { accept: compressed ? 'application/gzip, application/octet-stream' : 'application/json', 'user-agent': 'EmDashCyber-PowerShell-Gallery-Scanner/0.1' },
      signal: AbortSignal.timeout(20_000),
    });
    if (!shardResponse.ok) throw new Error('Published state shard returned HTTP ' + shardResponse.status + '.');
    const buffer = Buffer.from(await shardResponse.arrayBuffer());
    const shard = parseStateShard(buffer, compressed);
    for (const record of shard.packages) {
      if (!record || typeof record.name !== 'string' || !Array.isArray(record.versions)) continue;
      state.packages.set(normalizePackageName(record.name), record);
    }
  }
  return state;
}

export async function loadLocalState(publicDirectory = SITE_PUBLIC_DIRECTORY) {
  const state = emptyState();
  const apiRoot = resolve(publicDirectory, 'api/v1');
  let manifestText;
  try {
    manifestText = await readFile(resolve(apiRoot, 'manifest.json'), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return state;
    throw error;
  }
  if (manifestText.length > 2 * 1024 * 1024) throw new Error('Local state manifest is too large.');
  const manifest = JSON.parse(manifestText);
  state.manifest = { ...structuredClone(DEFAULT_MANIFEST), ...manifest };
  if (!Array.isArray(manifest.stateShards) || !manifest.stateShards.length) {
    if (manifest.status === 'bootstrap_required' || manifest.coverage?.listedPackages === 0) return state;
    throw new Error('Local state manifest does not reference any state shards.');
  }
  for (const shardPath of manifest.stateShards) {
    if (!isValidStateShardPath(shardPath)) throw new Error('Local state contains an invalid shard path.');
    const buffer = await readFile(resolve(apiRoot, shardPath));
    const shard = parseStateShard(buffer, shardPath.endsWith('.gz'));
    for (const record of shard.packages) {
      if (!record || typeof record.name !== 'string' || !Array.isArray(record.versions)) continue;
      state.packages.set(normalizePackageName(record.name), record);
    }
  }
  return state;
}

export async function loadScanState(apiBaseUrl, {
  publicDirectory = SITE_PUBLIC_DIRECTORY,
  fetcher = globalThis.fetch,
} = {}) {
  const published = await loadPublishedState(apiBaseUrl, fetcher);
  if (published.packages.size) return { state: published, source: 'published' };
  const local = await loadLocalState(publicDirectory);
  return local.packages.size ? { state: local, source: 'local' } : { state: published, source: 'published' };
}

export async function writeSnapshot(state, publicDirectory = SITE_PUBLIC_DIRECTORY) {
  const apiRoot = resolve(publicDirectory, 'api/v1');
  const parentDirectory = dirname(apiRoot);
  const temporaryRoot = resolve(parentDirectory, '.api-v1-tmp-' + randomUUID());
  const backupRoot = resolve(parentDirectory, '.api-v1-backup-' + randomUUID());
  await mkdir(resolve(temporaryRoot, 'shards'), { recursive: true });
  await mkdir(resolve(temporaryRoot, 'state'), { recursive: true });
  try {
  try {
    await copyFile(resolve(apiRoot, 'openapi.json'), resolve(temporaryRoot, 'openapi.json'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const groups = new Map();
  for (const record of [...state.packages.values()].sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }))) {
    const shardKey = getShardKey(record.name);
    if (!groups.has(shardKey)) groups.set(shardKey, []);
    groups.get(shardKey).push(record);
  }

  const shardPaths = [];
  const stateShardPaths = [];
  for (const [key, records] of groups) {
    const catalog = records.map(catalogItem);
    const compactRecords = records.map((record) => ({
      ...record,
      versions: record.versions.map(compactVersionRecord),
    }));
    const catalogPath = 'shards/' + key + '.json';
    const statePath = 'state/' + key + '.json.gz';
    shardPaths.push(catalogPath);
    stateShardPaths.push(statePath);
    await writeFile(resolve(temporaryRoot, catalogPath), JSON.stringify({
      schemaVersion: '1.0',
      shard: key,
      packages: catalog,
    }));
    await writeFile(resolve(temporaryRoot, statePath), gzipSync(JSON.stringify({
      schemaVersion: '1.0',
      shard: key,
      packages: compactRecords,
    })));
    for (const record of records) {
      for (const version of record.versions) {
        if (version.assessment === 'not_scanned') continue;
        const path = resolve(temporaryRoot, resultPath(record.name, version.version));
        await mkdir(dirname(path), { recursive: true });
        await writeFile(path, JSON.stringify(compactVersionRecord(version)));
      }
    }
  }

  const manifest = {
    ...state.manifest,
    schemaVersion: '1.0',
    generatedAt: nowIso(),
    coverage: buildCoverage(state),
    shards: shardPaths.sort(),
    stateShards: stateShardPaths.sort(),
  };
  await writeFile(resolve(temporaryRoot, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  let previousMoved = false;
  try {
    await rename(apiRoot, backupRoot);
    previousMoved = true;
  } catch (error) {
    if (error.code !== 'ENOENT') {
      await rm(temporaryRoot, { recursive: true, force: true });
      throw error;
    }
  }
  try {
    await rename(temporaryRoot, apiRoot);
  } catch (error) {
    if (previousMoved) await rename(backupRoot, apiRoot).catch(() => {});
    await rm(temporaryRoot, { recursive: true, force: true });
    throw error;
  }
  if (previousMoved) await rm(backupRoot, { recursive: true, force: true }).catch(() => {});
  state.manifest = manifest;
  return manifest;
  } catch (error) {
    await rm(temporaryRoot, { recursive: true, force: true });
    throw error;
  }
}
