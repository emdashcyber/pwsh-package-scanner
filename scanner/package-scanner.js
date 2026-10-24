import { inspectNupkg } from './zip.js';
import { parseNuspec } from './xml.js';
import { runPSScriptAnalyzer } from './analysis.js';
import { analyzePowerShellBehavior, normalizePSScriptAnalyzerFindings, redactFinding } from './rules.js';
import { scanAdvisoriesForVersion } from './advisories.js';
import { compareVersions } from './versions.js';
import { nowIso, sha256, safeString, normalizePackageName } from './util.js';

export const SCANNER_VERSION = '0.1.0';
export const RULESET_VERSION = '0.1.0';

function emptyVersionRecord(item, status = 'incomplete', message = '') {
  return {
    package: item.name,
    version: item.version,
    assessment: status,
    packageSha256: null,
    scannedAt: null,
    scannerVersion: SCANNER_VERSION,
    rulesetVersion: RULESET_VERSION,
    tools: { powerShell: null, psscriptAnalyzer: null, psscriptAnalyzerExpected: '1.25.0' },
    packageUrl: 'https://www.powershellgallery.com/packages/' + encodeURIComponent(item.name) + '/' + encodeURIComponent(item.version),
    metadata: {
      title: safeString(item.title || item.name, 300),
      description: safeString(item.description || '', 2000),
      owners: safeString(item.owners || '', 300),
      publishedAt: item.publishedAt || null,
      updatedAt: item.updatedAt || null,
    },
    dependencies: [],
    fileInventory: [],
    findings: [],
    coverage: { archive: false, powerShellAnalysis: false, dependencyResolution: false, advisories: false },
    warnings: message ? [safeString(message, 800)] : [],
  };
}

function selectPreviousVersion(versions, newVersion) {
  return (versions || [])
    .filter((item) => item.assessment === 'complete' && item.version !== newVersion && compareVersions(item.version, newVersion) < 0)
    .sort((a, b) => compareVersions(b.version, a.version))[0] || null;
}

function compareVersionChanges(item, current, previous) {
  const findings = [];
  if (!previous) return findings;
  const previousOwners = normalizePackageName(previous.metadata?.owners || '');
  const currentOwners = normalizePackageName(current.metadata?.owners || '');
  if (previousOwners && currentOwners && previousOwners !== currentOwners) {
    findings.push({
      id: 'PSG-SUPPLY-001',
      category: 'supply_chain',
      severity: 'medium',
      confidence: 'medium',
      title: 'Package owner metadata changed between versions',
      description: 'The Gallery owner field differs from the preceding scanned version. Ownership changes can be legitimate; review the publisher context.',
      evidence: { file: null, line: null, snippet: 'Previous owners: ' + previous.metadata.owners + ' · Current owners: ' + current.metadata.owners },
      references: [item.packageUrl],
    });
  }

  const previousFiles = new Map((previous.fileInventory || []).map((file) => [file.path, file]));
  const currentFiles = current.fileInventory || [];
  const addedBinaries = currentFiles.filter((file) => /\.(?:dll|exe|msi|com|sys|bin|scr|so|dylib)$/i.test(file.path) && !previousFiles.has(file.path));
  for (const file of addedBinaries.slice(0, 10)) {
    findings.push({
      id: 'PSG-SUPPLY-002-' + sha256(file.path).slice(0, 12),
      category: 'supply_chain',
      severity: 'medium',
      confidence: 'medium',
      title: 'New executable or binary file added',
      description: 'A file with an executable or library extension was added in this version and was not inspected as PowerShell source.',
      evidence: { file: file.path, line: null, snippet: 'Added file · ' + file.size.toLocaleString('en-US') + ' bytes' },
      references: [item.packageUrl],
    });
  }

  for (const file of currentFiles.filter((entry) => previousFiles.has(entry.path)
    && (previousFiles.get(entry.path).size !== entry.size || previousFiles.get(entry.path).crc32 !== entry.crc32)).slice(0, 20)) {
    const before = previousFiles.get(file.path);
    findings.push({
      id: 'PSG-SUPPLY-004-' + sha256(file.path).slice(0, 12),
      category: 'supply_chain',
      severity: 'low',
      confidence: 'high',
      title: 'Package file changed between versions',
      description: 'The file size or ZIP checksum differs from the preceding complete version. Review the source change in context.',
      evidence: {
        file: file.path,
        line: null,
        snippet: 'Previous size/checksum: ' + before.size + '/' + before.crc32 + ' · Current: ' + file.size + '/' + file.crc32,
      },
      references: [item.packageUrl],
    });
  }

  const previousDeps = new Set((previous.dependencies || []).map((dep) => normalizePackageName(dep.name) + '@' + (dep.versionRange || '*')));
  const currentDeps = new Set((current.dependencies || []).map((dep) => normalizePackageName(dep.name) + '@' + (dep.versionRange || '*')));
  const addedDeps = [...currentDeps].filter((dep) => !previousDeps.has(dep));
  if (addedDeps.length) {
    findings.push({
      id: 'PSG-SUPPLY-003',
      category: 'supply_chain',
      severity: 'low',
      confidence: 'low',
      title: 'Declared dependency set changed',
      description: 'One or more dependency declarations changed since the preceding scanned version. Review the change in package context.',
      evidence: { file: null, line: null, snippet: addedDeps.slice(0, 5).join(', ') },
      references: [item.packageUrl],
    });
  }
  return findings;
}

function dedupeFindings(items) {
  const seen = new Set();
  return items.map(redactFinding).filter((finding) => {
    const key = finding.id + '|' + (finding.evidence?.file || '') + '|' + (finding.evidence?.line || '');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function scanGalleryPackage(item, gallery, {
  previousVersions = [],
  runPssa = true,
  fetcher = globalThis.fetch,
  curatedAdvisories = [],
  scanAdvisories = true,
  log = () => {},
} = {}) {
  const base = emptyVersionRecord(item);
  let archive;
  let archiveHash;
  try {
    const nupkg = await gallery.downloadPackage(item.name, item.version);
    archiveHash = sha256(nupkg);
    archive = inspectNupkg(nupkg);
  } catch (error) {
    base.warnings.push(safeString(error.message || error, 800));
    return base;
  }

  const nuspecs = archive.files.filter((file) => file.kind === 'nuspec');
  let nuspec = { metadata: {}, dependencies: [] };
  if (nuspecs.length !== 1) {
    archive.complete = false;
    archive.warnings.push(nuspecs.length ? 'Multiple nuspec files were found.' : 'Package nuspec was not found.');
  } else {
    try {
      nuspec = parseNuspec(nuspecs[0].text);
    } catch (error) {
      archive.complete = false;
      archive.warnings.push('Package nuspec could not be parsed: ' + error.message);
    }
  }

  const scripts = archive.files.filter((file) => file.kind === 'script');
  const behaviorFindings = analyzePowerShellBehavior(scripts);
  const pssa = await runPSScriptAnalyzer(scripts, { enabled: runPssa });
  const pssaFindings = normalizePSScriptAnalyzerFindings(pssa.findings, scripts);
  const declaredDependencies = nuspec.dependencies.length ? nuspec.dependencies : item.dependencies || [];
  let dependencyAnalysis = { dependencies: [], complete: declaredDependencies.length === 0 };
  let advisoryAnalysis = {
    findings: [],
    dependencies: dependencyAnalysis.dependencies,
    complete: !scanAdvisories,
    checkedAt: null,
    error: null,
  };
  if (scanAdvisories) {
    try {
      advisoryAnalysis = await scanAdvisoriesForVersion({
        package: item.name,
        version: item.version,
      }, declaredDependencies, gallery, { fetcher, curatedAdvisories });
      dependencyAnalysis = { dependencies: advisoryAnalysis.dependencies, complete: advisoryAnalysis.complete };
    } catch (error) {
      dependencyAnalysis = { dependencies: [], complete: false };
      advisoryAnalysis = {
        findings: [],
        dependencies: [],
        complete: false,
        checkedAt: nowIso(),
        error: String(error.message || error).slice(0, 800),
      };
    }
  }

  const result = {
    package: item.name,
    version: item.version,
    assessment: 'complete',
    packageSha256: archiveHash,
    scannedAt: nowIso(),
    scannerVersion: SCANNER_VERSION,
    rulesetVersion: RULESET_VERSION,
    tools: {
      powerShell: pssa.powerShellVersion || null,
      psscriptAnalyzer: pssa.analyzerVersion || null,
      psscriptAnalyzerExpected: '1.25.0',
    },
    packageUrl: 'https://www.powershellgallery.com/packages/' + encodeURIComponent(item.name) + '/' + encodeURIComponent(item.version),
    metadata: {
      title: safeString(item.title || nuspec.metadata.title || item.name, 300),
      description: safeString(item.description || nuspec.metadata.description || '', 2000),
      authors: safeString(item.authors || nuspec.metadata.authors || '', 300),
      owners: safeString(item.owners || nuspec.metadata.owners || '', 300),
      projectUrl: safeString(item.projectUrl || nuspec.metadata.projectUrl || '', 1000),
      publishedAt: item.publishedAt || null,
      updatedAt: item.updatedAt || null,
      tags: (item.tags || []).slice(0, 30),
    },
    dependencies: dependencyAnalysis.dependencies,
    fileInventory: archive.inventory,
    findings: dedupeFindings([
      ...behaviorFindings,
      ...pssaFindings,
      ...advisoryAnalysis.findings,
      ...compareVersionChanges(item, {
        metadata: { owners: item.owners || nuspec.metadata.owners },
        dependencies: declaredDependencies,
        fileInventory: archive.inventory,
        packageUrl: 'https://www.powershellgallery.com/packages/' + encodeURIComponent(item.name) + '/' + encodeURIComponent(item.version),
      }, selectPreviousVersion(previousVersions, item.version)),
    ]),
    coverage: {
      archive: archive.complete,
      powerShellAnalysis: pssa.complete,
      dependencyResolution: dependencyAnalysis.complete,
      advisories: advisoryAnalysis.complete,
      executableBinaries: archive.inventory.some((file) => /\.(?:dll|exe|msi|com|sys|bin|scr|so|dylib)$/i.test(file.path)) ? 'uninspected' : 'none-detected',
    },
    advisoryCheckedAt: advisoryAnalysis.checkedAt,
    advisoryError: advisoryAnalysis.error,
    warnings: [...archive.warnings, ...(pssa.error ? [pssa.error] : []), ...(advisoryAnalysis.error ? [advisoryAnalysis.error] : [])]
      .map((message) => safeString(message, 800)).slice(0, 20),
  };
  if (!archive.complete || !pssa.complete || !dependencyAnalysis.complete || !advisoryAnalysis.complete) result.assessment = 'incomplete';
  if (!scripts.length && pssa.complete) result.coverage.powerShellAnalysis = true;
  log({
    package: item.name,
    version: item.version,
    assessment: result.assessment,
    findingCount: result.findings.length,
  });
  return result;
}
