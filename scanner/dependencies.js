import { dedupeDependencies } from './xml.js';
import { compareVersions, parseNugetRange, versionMatchesRange } from './versions.js';

const MAX_DEPENDENCY_DEPTH = 5;
const MAX_DEPENDENCY_NODES = 100;

const PLATFORM_MODULES = new Set([
  'microsoft.powershell.utility',
  'microsoft.powershell.management',
  'microsoft.powershell.core',
  'microsoft.powershell.security',
  'microsoft.powershell.diagnostics',
  'microsoft.powershell.archive',
  'microsoft.powershell.host',
  'microsoft.powershell.consolehost',
  'microsoft.wsman.management',
  'appx',
  'bitstransfer',
  'cimcmdlets',
  'configurationmanager',
  'configmanager',
  'dnsclient',
  'dnsserver',
  'failoverclusters',
  'grouppolicy',
  'hyper-v',
  'netadapter',
  'nettcpip',
  'pki',
  'smbshare',
  'storage',
  'webadministration',
]);

function exactRangeVersion(range) {
  const parsed = parseNugetRange(range || '*');
  if (parsed?.length !== 1) return null;
  const interval = parsed[0];
  return interval.min && interval.max === interval.min && interval.includeMin && interval.includeMax
    ? interval.min
    : null;
}

export async function resolveDependencyGraph(declaredDependencies, gallery, {
  maxDepth = MAX_DEPENDENCY_DEPTH,
  maxNodes = MAX_DEPENDENCY_NODES,
} = {}) {
  const resolved = [];
  const queue = dedupeDependencies(declaredDependencies || []).map((dependency) => ({
    ...dependency,
    parent: null,
    depth: 1,
  }));
  const seen = new Set();
  let incomplete = false;

  while (queue.length && resolved.length < maxNodes) {
    const current = queue.shift();
    const relation = current.relation || 'requires';
    const key = current.name.toLocaleLowerCase('en-US') + '@' + current.versionRange + '#' + relation + '#' + (current.parent || '');
    if (seen.has(key)) continue;
    seen.add(key);
    const record = {
      name: current.name,
      versionRange: current.versionRange || '*',
      relation,
      declarationSources: current.declarationSources || [],
      file: current.file || null,
      line: Number.isInteger(current.line) ? current.line : null,
      parent: current.parent,
      depth: current.depth,
      status: 'unresolved',
      resolvedVersion: null,
      sourceEcosystem: 'NuGet',
    };

    if (relation === 'contains') {
      record.status = 'bundled';
      resolved.push(record);
      continue;
    }
    if (PLATFORM_MODULES.has(current.name.toLocaleLowerCase('en-US'))) {
      record.status = 'platform_module';
      record.sourceEcosystem = 'PowerShell';
      resolved.push(record);
      continue;
    }
    if (current.depth > maxDepth) {
      record.status = 'depth_limit';
      incomplete = true;
      resolved.push(record);
      continue;
    }
    const rangeProbe = versionMatchesRange('1.0.0', current.versionRange || '*');
    if (rangeProbe === null) {
      record.status = 'unsupported_range';
      incomplete = true;
      resolved.push(record);
      continue;
    }
    let available;
    try {
      available = await gallery.listPackageVersions(current.name);
    } catch (error) {
      record.status = error?.status === 404 ? 'package_not_found' : 'gallery_unavailable';
      if (record.status !== 'package_not_found') incomplete = true;
      resolved.push(record);
      continue;
    }
    const candidates = (available || [])
      .filter((item) => item.version)
      .filter((item) => versionMatchesRange(item.version, current.versionRange || '*') === true)
      .map((item) => item.version);
    candidates.sort(compareVersions);
    let selected = candidates.at(-1);
    let exactRecord = null;
    const exactVersion = exactRangeVersion(current.versionRange);
    if (!selected && exactVersion && typeof gallery.getPackageVersion === 'function') {
      try {
        exactRecord = await gallery.getPackageVersion(current.name, exactVersion);
        if (exactRecord?.version && versionMatchesRange(exactRecord.version, current.versionRange) === true) {
          selected = exactRecord.version;
        }
      } catch (error) {
        if (error?.status !== 404) {
          record.status = 'gallery_unavailable';
          incomplete = true;
          resolved.push(record);
          continue;
        }
      }
    }
    if (!selected) {
      record.status = available.length ? 'no_matching_version' : 'package_not_found';
      resolved.push(record);
      continue;
    }
    record.status = 'resolved';
    record.resolvedVersion = selected;
    resolved.push(record);

    const selectedRecord = exactRecord?.version === selected
      ? exactRecord
      : available.find((item) => item.version === selected);
    if (selectedRecord?.dependencies?.length) {
      for (const dependency of selectedRecord.dependencies) {
        if (resolved.length + queue.length >= maxNodes) {
          incomplete = true;
          break;
        }
        queue.push({
          ...dependency,
          relation: dependency.relation || 'requires',
          declarationSources: dependency.declarationSources || ['gallery'],
          parent: current.name + '@' + selected,
          depth: current.depth + 1,
        });
      }
    }
  }

  if (queue.length) {
    incomplete = true;
    for (const item of queue) {
      resolved.push({
        name: item.name,
        versionRange: item.versionRange || '*',
        relation: item.relation || 'requires',
        declarationSources: item.declarationSources || [],
        file: item.file || null,
        line: Number.isInteger(item.line) ? item.line : null,
        parent: item.parent,
        depth: item.depth,
        status: 'node_limit',
        resolvedVersion: null,
        sourceEcosystem: 'NuGet',
      });
    }
  }
  return { dependencies: resolved, complete: !incomplete };
}
