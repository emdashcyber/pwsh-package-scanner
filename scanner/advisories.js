import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mapLimit, normalizePackageName, nowIso } from './util.js';
import { versionMatchesRange } from './versions.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OSV_QUERY_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_BASE = 'https://api.osv.dev/v1/vulns/';
const BATCH_SIZE = 500;

export async function loadCuratedAdvisories(path = resolve(ROOT, 'advisories/powershell-gallery.json')) {
  try {
    const source = await readFile(path, 'utf8');
    const parsed = JSON.parse(source);
    return Array.isArray(parsed.advisories) ? parsed.advisories : [];
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

function severityFromAdvisory(advisory) {
  const raw = advisory.severity?.find((item) => item.type?.startsWith('CVSS'))?.score;
  const score = Number(raw);
  if (Number.isFinite(score)) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }
  const label = String(advisory.database_specific?.severity || '').toLocaleLowerCase('en-US');
  if (['critical', 'high', 'medium', 'low'].includes(label)) return label;
  return 'medium';
}

function advisoryMatches(advisory, target) {
  const packages = advisory.affected || [];
  return packages.some((item) => {
    const pkg = item.package || {};
    if (pkg.ecosystem && pkg.ecosystem.toLocaleLowerCase('en-US') !== 'nuget') return false;
    if (normalizePackageName(pkg.name) !== normalizePackageName(target.name)) return false;
    if (Array.isArray(item.versions) && item.versions.includes(target.version)) return true;
    if (!item.ranges?.length) return false;
    return item.ranges.some((range) => {
      let introduced = null;
      for (const event of range.events || []) {
        if (event.introduced !== undefined) introduced = event.introduced;
        if (event.fixed !== undefined && introduced !== null) {
          const afterStart = introduced === '0' || versionMatchesRange(target.version, '[' + introduced + ',)') === true;
          const beforeFix = versionMatchesRange(target.version, '(,' + event.fixed + ')');
          if (afterStart && beforeFix === true) return true;
          introduced = null;
        }
        if (event.last_affected !== undefined && introduced !== null) {
          const afterStart = introduced === '0' || versionMatchesRange(target.version, '[' + introduced + ',)') === true;
          const throughLast = versionMatchesRange(target.version, '[,' + event.last_affected + ']');
          if (afterStart && throughLast === true) return true;
          introduced = null;
        }
      }
      return introduced !== null && (introduced === '0' || versionMatchesRange(target.version, '[' + introduced + ',)') === true);
    });
  });
}

function curatedMatches(advisory, target) {
  if (normalizePackageName(advisory.package) !== normalizePackageName(target.name)) return false;
  return versionMatchesRange(target.version, advisory.affectedRange || '*') === true;
}

function toFinding(advisory, target, source) {
  const id = advisory.id || advisory.aliases?.[0] || 'UNSPECIFIED';
  const summary = advisory.summary || advisory.title || 'Known vulnerability applies to this package version.';
  const depth = Number(target.depth) > 1 ? 'transitive' : target.depth ? 'direct' : 'package';
  const refs = [
    ...(advisory.references || []).map((item) => typeof item === 'string' ? item : item.url),
    advisory.id ? 'https://osv.dev/vulnerability/' + encodeURIComponent(advisory.id) : null,
  ].filter((item) => typeof item === 'string');
  return {
    id: 'ADVISORY-' + id + '-' + normalizePackageName(target.name) + '-' + target.version,
    advisoryId: id,
    category: 'advisory',
    severity: advisory.severity ? severityFromAdvisory(advisory) : (advisory.severityLabel || 'medium'),
    confidence: 'high',
    title: summary.slice(0, 240),
    description: 'A published advisory matches the ' + depth + ' dependency ' + target.name + '@' + target.version + '. Source: ' + source + '.',
    evidence: { file: null, line: null, snippet: target.name + '@' + target.version + ' matched an affected version range.' },
    references: [...new Set(refs)].slice(0, 8),
    affectedPackage: target.name,
    affectedVersion: target.version,
    source,
  };
}

async function postJson(url, body, fetcher) {
  const response = await fetcher(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'EmDashCyber-PowerShell-Gallery-Scanner/0.1' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error('OSV query returned HTTP ' + response.status + '.');
  return response.json();
}

async function fetchOsvDetails(ids, fetcher) {
  const unique = [...new Set(ids)];
  return mapLimit(unique, 8, async (id) => {
    const response = await fetcher(OSV_VULN_BASE + encodeURIComponent(id), {
      headers: { accept: 'application/json', 'user-agent': 'EmDashCyber-PowerShell-Gallery-Scanner/0.1' },
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) throw new Error('OSV advisory lookup returned HTTP ' + response.status + '.');
    return response.json();
  });
}

export async function scanAdvisoriesForVersion(packageVersion, declaredDependencies, gallery, {
  fetcher = globalThis.fetch,
  curatedAdvisories = [],
} = {}) {
  const graph = await gallery.resolveDependencyGraph(declaredDependencies || []);
  const targets = [
    { name: packageVersion.package, version: packageVersion.version, depth: 0 },
    ...graph.dependencies.filter((item) => item.status === 'resolved').map((item) => ({
      name: item.name,
      version: item.resolvedVersion,
      depth: item.depth,
    })),
  ];
  const queries = targets.map((target) => ({
    package: { name: target.name, ecosystem: 'NuGet' },
    version: target.version,
  }));
  let findings = [];
  let complete = graph.complete;
  let error = null;

  for (const advisory of curatedAdvisories) {
    const target = targets.find((item) => curatedMatches(advisory, item));
    if (target) findings.push(toFinding(advisory, target, 'EmDash Cyber curated Gallery advisory'));
  }

  try {
    const queryResults = [];
    for (let i = 0; i < queries.length; i += BATCH_SIZE) {
      const chunk = queries.slice(i, i + BATCH_SIZE);
      const response = await postJson(OSV_QUERY_BATCH, { queries: chunk }, fetcher);
      if (!Array.isArray(response.results) || response.results.length !== chunk.length) throw new Error('OSV returned a mismatched batch response.');
      queryResults.push(...response.results);
    }
    const ids = queryResults.flatMap((result) => (result.vulns || []).map((item) => item.id)).filter(Boolean);
    const details = await fetchOsvDetails(ids, fetcher);
    const advisoryMap = new Map(details.map((item) => [item.id, item]));
    queryResults.forEach((result, index) => {
      for (const vulnerability of result.vulns || []) {
        const advisory = advisoryMap.get(vulnerability.id);
        if (!advisory || !advisoryMatches(advisory, targets[index])) continue;
        findings.push(toFinding(advisory, targets[index], 'OSV (NuGet identity match)'));
      }
    });
  } catch (cause) {
    complete = false;
    error = String(cause.message || cause).slice(0, 800);
  }

  const deduped = new Map();
  for (const finding of findings) deduped.set(finding.id, finding);
  return {
    findings: [...deduped.values()],
    dependencies: graph.dependencies,
    complete,
    checkedAt: nowIso(),
    source: 'OSV + curated Gallery advisories',
    error,
  };
}

export async function refreshOsvForTargets(packageVersion, dependencies, {
  fetcher = globalThis.fetch,
  curatedAdvisories = [],
} = {}) {
  const targets = [
    { name: packageVersion.package, version: packageVersion.version, depth: 0 },
    ...(dependencies || [])
      .filter((item) => item.status === 'resolved' && item.resolvedVersion)
      .map((item) => ({ name: item.name, version: item.resolvedVersion, depth: item.depth })),
  ];
  let findings = [];
  try {
    for (const advisory of curatedAdvisories) {
      const target = targets.find((item) => curatedMatches(advisory, item));
      if (target) findings.push(toFinding(advisory, target, 'EmDash Cyber curated Gallery advisory'));
    }
    const queryResults = [];
    const queries = targets.map((target) => ({
      package: { name: target.name, ecosystem: 'NuGet' },
      version: target.version,
    }));
    for (let i = 0; i < queries.length; i += BATCH_SIZE) {
      const chunk = queries.slice(i, i + BATCH_SIZE);
      const response = await postJson(OSV_QUERY_BATCH, { queries: chunk }, fetcher);
      if (!Array.isArray(response.results) || response.results.length !== chunk.length) throw new Error('OSV returned a mismatched batch response.');
      queryResults.push(...response.results);
    }
    const ids = queryResults.flatMap((result) => (result.vulns || []).map((item) => item.id)).filter(Boolean);
    const details = await fetchOsvDetails(ids, fetcher);
    const advisoryMap = new Map(details.map((item) => [item.id, item]));
    queryResults.forEach((result, index) => {
      for (const vulnerability of result.vulns || []) {
        const advisory = advisoryMap.get(vulnerability.id);
        if (advisory && advisoryMatches(advisory, targets[index])) {
          findings.push(toFinding(advisory, targets[index], 'OSV (NuGet identity match)'));
        }
      }
    });
    return {
      findings: [...new Map(findings.map((finding) => [finding.id, finding])).values()],
      complete: true,
      checkedAt: nowIso(),
      error: null,
    };
  } catch (error) {
    return {
      findings: [],
      complete: false,
      checkedAt: nowIso(),
      error: String(error.message || error).slice(0, 800),
    };
  }
}
