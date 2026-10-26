import { inspectNupkg } from './zip.js';
import { parseNuspec } from './xml.js';
import { runPSScriptAnalyzer } from './analysis.js';
import { analyzePowerShellBehavior, normalizePSScriptAnalyzerFindings, redactFinding } from './rules.js';
import { scanAdvisoriesForVersion } from './advisories.js';
import { scanBinaryEntries } from './binary-scanner.js';
import { parsePowerShellRequirements } from './requirements.js';
import { compareVersions } from './versions.js';
import { nowIso, sha256, safeString, normalizePackageName } from './util.js';
import { dedupeDependencies } from './xml.js';

export const SCANNER_VERSION = '0.2.0';
export const RULESET_VERSION = '0.3.0';

function emptyVersionRecord(item, status = 'incomplete', message = '') {
  return {
    package: item.name,
    version: item.version,
    assessment: status,
    packageSha256: null,
    scannedAt: null,
    scannerVersion: SCANNER_VERSION,
    rulesetVersion: RULESET_VERSION,
    tools: { powerShell: null, psscriptAnalyzer: null, psscriptAnalyzerExpected: '1.25.0', clamav: null },
    packageUrl: 'https://www.powershellgallery.com/packages/' + encodeURIComponent(item.name) + '/' + encodeURIComponent(item.version),
    metadata: {
      title: safeString(item.title || item.name, 300),
      description: safeString(item.description || '', 2000),
      owners: safeString(item.owners || '', 300),
      publishedAt: item.publishedAt || null,
      updatedAt: item.updatedAt || null,
    },
    dependencies: [],
    binaryArtifacts: [],
    fileInventory: [],
    findings: [],
    coverage: { archive: false, powerShellAnalysis: false, dependencyResolution: false, advisories: false, binaryScanning: false },
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
      id: 'PSG-SUPPLY-002',
      category: 'supply_chain',
      severity: 'medium',
      confidence: 'medium',
      title: 'New executable or binary file added',
      description: 'A file with an executable or library extension was added in this version. Review the source change and its binary hash/ClamAV result; this change signal does not establish intent.',
      evidence: { file: file.path, line: null, snippet: 'Added file · ' + file.size.toLocaleString('en-US') + ' bytes' },
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
    const affectedTarget = finding.category === 'advisory'
      ? '|' + normalizePackageName(finding.affectedPackage || '') + '@' + (finding.affectedVersion || '')
      : '';
    const key = finding.id + '|' + (finding.evidence?.file || '') + '|' + (finding.evidence?.line || '') + affectedTarget;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function isPowerShellFinding(finding) {
  return /^PSSA-/.test(finding?.id || '')
    || /^PSG-(?:SECRET-00[12]|BEHAVIOR-00[1-5])$/.test(finding?.id || '');
}

export async function analyzePowerShellFindings(files, { runPssa = true } = {}) {
  const scripts = (files || []).filter((file) => file.kind === 'script' && !/\.ps1xml$/i.test(file.path || ''));
  const behaviorFindings = analyzePowerShellBehavior(scripts);
  const pssa = await runPSScriptAnalyzer(scripts, { enabled: runPssa });
  const pssaFindings = normalizePSScriptAnalyzerFindings(pssa.findings, scripts);
  return {
    findings: dedupeFindings([...behaviorFindings, ...pssaFindings]),
    complete: pssa.complete,
    analyzerVersion: pssa.analyzerVersion || null,
    powerShellVersion: pssa.powerShellVersion || null,
    warnings: pssa.warnings || [],
    error: pssa.error || null,
  };
}

function dependencyFindings(dependencies, packageUrl) {
  return (dependencies || []).flatMap((dependency) => {
    if (dependency.relation === 'contains') return [];
    if (!['package_not_found', 'no_matching_version'].includes(dependency.status)) return [];
    const missingPackage = dependency.status === 'package_not_found';
    return [{
      id: missingPackage ? 'PSG-DEPENDENCY-001' : 'PSG-DEPENDENCY-002',
      category: 'supply_chain',
      severity: missingPackage ? 'medium' : 'low',
      confidence: 'high',
      title: missingPackage
        ? 'Declared dependency package was not found in PowerShell Gallery'
        : 'Declared dependency version range has no PowerShell Gallery match',
      description: missingPackage
        ? 'The dependency lookup completed, but no package with this identity was listed in PowerShell Gallery. It may be supplied by a private repository or another source.'
        : 'The package exists in PowerShell Gallery, but the declared version range did not match a listed version. The dependency may be supplied elsewhere.',
      evidence: {
        file: dependency.file || null,
        line: dependency.line || null,
        snippet: safeString(dependency.name + ' ' + (dependency.versionRange || '*') + ' · source: ' + (dependency.declarationSources || []).join(', '), 400),
      },
      references: [
        packageUrl,
        'https://www.powershellgallery.com/packages/' + encodeURIComponent(dependency.name),
      ],
    }];
  });
}

export async function scanGalleryPackage(item, gallery, {
  previousVersions = [],
  runPssa = true,
  fetcher = globalThis.fetch,
  curatedAdvisories = [],
  scanAdvisories = true,
  clamavScanner = null,
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
  const powerShellAnalysis = await analyzePowerShellFindings(scripts, { runPssa });
  const requirements = parsePowerShellRequirements(scripts);
  const galleryDependencies = nuspec.dependencies.length ? nuspec.dependencies : item.dependencies || [];
  const declaredDependencies = dedupeDependencies([
    ...galleryDependencies.map((dependency) => ({
      ...dependency,
      relation: 'requires',
      declarationSources: [nuspec.dependencies.length ? 'nuspec' : 'Gallery metadata'],
    })),
    ...requirements.requirements,
    ...requirements.contains,
  ]);
  const binaryAnalysis = await scanBinaryEntries(archive.binaries, { scanner: clamavScanner });
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
  } else {
    try {
      dependencyAnalysis = await gallery.resolveDependencyGraph(declaredDependencies);
    } catch (error) {
      dependencyAnalysis = { dependencies: [], complete: false };
      advisoryAnalysis = {
        ...advisoryAnalysis,
        error: safeString(error.message || error, 800),
      };
    }
  }

  const packageUrl = 'https://www.powershellgallery.com/packages/' + encodeURIComponent(item.name) + '/' + encodeURIComponent(item.version);
  const binaryFindings = binaryAnalysis.binaries.filter((binary) => binary.clamav.status === 'match').map((binary) => ({
    id: 'PSG-MALWARE-001',
    category: 'supply_chain',
    severity: 'high',
    confidence: 'medium',
    title: 'ClamAV signature match in a package binary',
    description: 'ClamAV reported a signature match for this file. Signature detections can be false positives and require human review; this is not a definitive malware verdict.',
    evidence: {
      file: binary.path,
      line: null,
      snippet: safeString((binary.clamav.signature || 'Signature match') + ' · SHA-256 ' + binary.sha256, 400),
    },
    references: [packageUrl, binary.virusTotalSearchUrl],
  }));

  const result = {
    package: item.name,
    version: item.version,
    assessment: 'complete',
    packageSha256: archiveHash,
    scannedAt: nowIso(),
    scannerVersion: SCANNER_VERSION,
    rulesetVersion: RULESET_VERSION,
    tools: {
      powerShell: powerShellAnalysis.powerShellVersion || null,
      psscriptAnalyzer: powerShellAnalysis.analyzerVersion || null,
      psscriptAnalyzerExpected: '1.25.0',
      clamav: binaryAnalysis.binaries.map((binary) => ({
        engineVersion: binary.clamav.engineVersion,
        databaseVersion: binary.clamav.databaseVersion,
        databaseDate: binary.clamav.databaseDate,
      })).find((tool) => tool.engineVersion) || null,
    },
    packageUrl,
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
    binaryArtifacts: binaryAnalysis.binaries,
    fileInventory: archive.inventory,
    findings: dedupeFindings([
      ...powerShellAnalysis.findings,
      ...binaryFindings,
      ...dependencyFindings(dependencyAnalysis.dependencies, packageUrl),
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
      powerShellAnalysis: powerShellAnalysis.complete,
      dependencyResolution: dependencyAnalysis.complete,
      advisories: advisoryAnalysis.complete,
      binaryScanning: binaryAnalysis.complete,
      executableBinaries: binaryAnalysis.binaries.length
        ? (binaryAnalysis.complete ? 'hash-and-clamav-complete' : 'incomplete')
        : 'none-detected',
    },
    advisoryCheckedAt: advisoryAnalysis.checkedAt,
    advisoryError: advisoryAnalysis.error,
    warnings: [
      ...archive.warnings,
      ...(powerShellAnalysis.error ? [powerShellAnalysis.error] : []),
      ...powerShellAnalysis.warnings,
      ...(advisoryAnalysis.error ? [advisoryAnalysis.error] : []),
      ...binaryAnalysis.binaries.filter((binary) => binary.clamav.status === 'error')
        .map((binary) => 'ClamAV could not scan ' + binary.path + ': ' + (binary.clamav.error || 'unknown scanner error')),
    ]
      .map((message) => safeString(message, 800)).slice(0, 20),
  };
  if (!archive.complete || !powerShellAnalysis.complete || !dependencyAnalysis.complete || !advisoryAnalysis.complete || !binaryAnalysis.complete) result.assessment = 'incomplete';
  if (!scripts.length && powerShellAnalysis.complete) result.coverage.powerShellAnalysis = true;
  log({
    package: item.name,
    version: item.version,
    assessment: result.assessment,
    findingCount: result.findings.length,
  });
  return result;
}
