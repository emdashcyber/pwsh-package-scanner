import { loadLocalState, SITE_PUBLIC_DIRECTORY, writeSnapshot } from '../scanner/state.js';

const state = await loadLocalState(SITE_PUBLIC_DIRECTORY);
let binaryPending = 0;

function canonicalFindingId(finding) {
  if (finding.category === 'advisory' && finding.advisoryId) return 'ADVISORY-' + finding.advisoryId;
  if (/^PSG-SUPPLY-002(?:-|$)/.test(finding.id || '')) return 'PSG-SUPPLY-002';
  if (/^PSG-SUPPLY-004(?:-|$)/.test(finding.id || '')) return 'PSG-SUPPLY-004';
  return finding.id;
}

for (const record of state.packages.values()) {
  for (const version of record.versions || []) {
    if (version.assessment === 'not_scanned') continue;
    for (const finding of version.findings || []) finding.id = canonicalFindingId(finding);
    version.dependencies = Array.isArray(version.dependencies) ? version.dependencies : [];
    version.binaryArtifacts = Array.isArray(version.binaryArtifacts) ? version.binaryArtifacts : [];
    version.tools = { ...(version.tools || {}), clamav: version.tools?.clamav || null };
    version.coverage = { ...(version.coverage || {}) };
    for (const dependency of version.dependencies) {
      dependency.relation = dependency.relation || 'requires';
      dependency.declarationSources = dependency.declarationSources || ['Gallery dependency metadata'];
      dependency.file = dependency.file || null;
      dependency.line = Number.isInteger(dependency.line) ? dependency.line : null;
    }
    const binaryFiles = (version.fileInventory || []).filter((file) =>
      /\.(?:dll|exe|msi|com|sys|bin|scr|so|dylib)$/i.test(file.path || ''));
    if (version.binaryArtifacts.length) {
      version.coverage.binaryScanning = version.binaryArtifacts.every((binary) =>
        binary.sha256 && ['clean', 'match'].includes(binary.clamav?.status));
      version.coverage.executableBinaries = version.coverage.binaryScanning ? 'hash-and-clamav-complete' : 'incomplete';
    } else if (binaryFiles.length) {
      version.coverage.binaryScanning = false;
      version.coverage.executableBinaries = 'incomplete';
      binaryPending += binaryFiles.length;
    } else if (version.scannedAt && version.coverage.archive) {
      version.coverage.binaryScanning = true;
      version.coverage.executableBinaries = 'none-detected';
    } else {
      version.coverage.binaryScanning = false;
      version.coverage.executableBinaries = 'incomplete';
    }
  }
}

state.manifest.freshnessWindowHours = 6;
state.manifest.resultRefresh = {
  id: 'binary-dependency-2026-10',
  complete: true,
  afterKey: '',
  total: 0,
};
if (state.manifest.sourceStatus === 'available' && state.manifest.lastSuccessfulScan) {
  state.manifest.status = 'ready';
  state.manifest.notice = state.manifest.coverage?.incompleteVersions
    ? 'Some package results are incomplete; review per-version coverage details.'
    : '';
}

const manifest = await writeSnapshot(state, SITE_PUBLIC_DIRECTORY);
process.stdout.write(JSON.stringify({
  listedPackages: manifest.coverage.listedPackages,
  scannedVersions: manifest.coverage.scannedVersions,
  resultRefreshTotal: manifest.resultRefresh.total,
  binaryFilesPendingRefresh: binaryPending,
  status: manifest.status,
  lastSuccessfulScan: manifest.lastSuccessfulScan,
}) + '\n');
