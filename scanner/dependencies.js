import { dedupeDependencies } from './xml.js';
import { compareVersions, versionMatchesRange } from './versions.js';

const MAX_DEPENDENCY_DEPTH = 5;
const MAX_DEPENDENCY_NODES = 100;

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
    const key = current.name.toLocaleLowerCase('en-US') + '@' + current.versionRange + '#' + (current.parent || '');
    if (seen.has(key)) continue;
    seen.add(key);
    const record = {
      name: current.name,
      versionRange: current.versionRange || '*',
      parent: current.parent,
      depth: current.depth,
      status: 'unresolved',
      resolvedVersion: null,
      sourceEcosystem: 'NuGet',
    };

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
    } catch {
      record.status = 'gallery_unavailable';
      incomplete = true;
      resolved.push(record);
      continue;
    }
    const candidates = available
      .filter((item) => item.version)
      .filter((item) => versionMatchesRange(item.version, current.versionRange || '*') === true)
      .map((item) => item.version);
    candidates.sort(compareVersions);
    const selected = candidates.at(-1);
    if (!selected) {
      record.status = 'no_matching_version';
      incomplete = true;
      resolved.push(record);
      continue;
    }
    record.status = 'resolved';
    record.resolvedVersion = selected;
    resolved.push(record);

    const selectedRecord = available.find((item) => item.version === selected);
    if (selectedRecord?.dependencies?.length) {
      for (const dependency of selectedRecord.dependencies) {
        if (resolved.length + queue.length >= maxNodes) {
          incomplete = true;
          break;
        }
        queue.push({
          ...dependency,
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
