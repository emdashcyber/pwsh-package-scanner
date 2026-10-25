import test from 'node:test';
import assert from 'node:assert/strict';
import { ARCHIVE_LIMITS, inspectNupkg } from '../scanner/zip.js';
import { analyzePowerShellBehavior, normalizePSScriptAnalyzerFindings, redactFinding } from '../scanner/rules.js';
import { scanGalleryPackage } from '../scanner/package-scanner.js';
import { scanBinaryEntries } from '../scanner/binary-scanner.js';
import { sha256 } from '../scanner/util.js';
import { createZip, packageEntries } from './helpers/zip-fixture.js';

test('valid nupkg is inspected without executing the PowerShell payload', async () => {
  const marker = '/tmp/pwsh-package-scanner-payload-was-executed-' + process.pid + '-' + Date.now();
  const packageBytes = createZip(packageEntries({ script: `Set-Content -LiteralPath '${marker}' -Value 'executed'` }));
  const archive = inspectNupkg(packageBytes);
  assert.equal(archive.complete, true);
  assert.equal(archive.files.filter((file) => file.kind === 'script').length, 1);

  const result = await scanGalleryPackage({ name: 'Example', version: '1.0.0' }, {
    downloadPackage: async () => packageBytes,
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  }, { runPssa: false, scanAdvisories: false });
  assert.equal(result.assessment, 'complete');
  assert.equal(result.fileInventory.length, 2);
  const { access } = await import('node:fs/promises');
  await assert.rejects(access(marker));
});

test('supply-chain IDs stay canonical while per-file evidence remains distinct', async () => {
  const packageBytes = createZip([
    ...packageEntries(),
    { name: 'tools/Extra.ps1', content: 'Write-Output "extra"' },
    { name: 'tools/New.dll', content: Buffer.from([1, 2, 3]) },
  ]);
  const result = await scanGalleryPackage({ name: 'Example', version: '1.0.0', owners: 'owner', packageUrl: 'https://www.powershellgallery.com/packages/Example/1.0.0' }, {
    downloadPackage: async () => packageBytes,
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  }, {
    runPssa: false,
    scanAdvisories: false,
    clamavScanner: async () => ({ status: 'error' }),
    previousVersions: [{
      version: '0.9.0',
      assessment: 'complete',
      metadata: { owners: 'owner' },
      dependencies: [],
      fileInventory: [
        { path: 'tools/Example.ps1', size: 1, crc32: '00000000' },
        { path: 'tools/Extra.ps1', size: 1, crc32: '00000000' },
      ],
    }],
  });
  const changed = result.findings.filter((finding) => finding.id === 'PSG-SUPPLY-004');
  assert.equal(changed.length, 2);
  assert.deepEqual(changed.map((finding) => finding.evidence.file).sort(), ['tools/Example.ps1', 'tools/Extra.ps1']);
  assert.ok(changed.every((finding) => finding.confidence === 'high'));
  assert.ok(result.findings.some((finding) => finding.id === 'PSG-SUPPLY-002' && finding.evidence.file === 'tools/New.dll'));
});

test('corrupt and oversized packages do not get complete assessments', () => {
  const valid = createZip(packageEntries());
  const corrupt = Buffer.from(valid);
  const central = corrupt.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  corrupt.writeUInt32LE(0, central + 16);
  assert.equal(inspectNupkg(corrupt).complete, false);

  const oversizedContent = 'x'.repeat(ARCHIVE_LIMITS.entryBytes + 1);
  const oversized = inspectNupkg(createZip([{ name: 'large.ps1', content: oversizedContent }]));
  assert.equal(oversized.complete, false);
  assert.ok(oversized.warnings.some((item) => item.includes('per-file')));
});

test('path traversal entries are ignored and mark archive coverage incomplete', () => {
  const archive = inspectNupkg(createZip([{ name: '../escape.ps1', content: 'Invoke-Expression $x' }]));
  assert.equal(archive.complete, false);
  assert.equal(archive.files.length, 0);
  assert.ok(archive.warnings.some((item) => item.includes('Unsafe archive')));
});

test('binary entries are safely extracted, hashed, and linked to VirusTotal hash search', async () => {
  const bytes = Buffer.from([0, 1, 2, 255, 9]);
  const archive = inspectNupkg(createZip([
    { name: 'Example.nuspec', content: '<package><metadata><id>Example</id><version>1.0.0</version></metadata></package>' },
    { name: 'tools/native.dll', content: bytes },
  ]));
  assert.equal(archive.complete, true);
  assert.equal(archive.binaries.length, 1);
  assert.deepEqual(archive.binaries[0].content, bytes);
  const result = await scanBinaryEntries(archive.binaries, {
    scanner: async () => ({ status: 'clean', engineVersion: '1.4.0', databaseVersion: '12345', databaseDate: '2026-10-25' }),
  });
  assert.equal(result.complete, true);
  assert.equal(result.binaries[0].sha256, sha256(bytes));
  assert.equal(result.binaries[0].clamav.status, 'clean');
  assert.equal(result.binaries[0].clamav.databaseVersion, '12345');
  assert.equal(result.binaries[0].virusTotalSearchUrl, 'https://www.virustotal.com/gui/search/' + sha256(bytes));
});

test('ClamAV match becomes a review finding; binary scan errors leave the assessment incomplete', async () => {
  const packageBytes = createZip([
    ...packageEntries(),
    { name: 'bin/tool.exe', content: Buffer.from('test binary payload') },
  ]);
  const gallery = {
    downloadPackage: async () => packageBytes,
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  };
  const match = await scanGalleryPackage({ name: 'Example', version: '1.0.0' }, gallery, {
    runPssa: false,
    scanAdvisories: false,
    clamavScanner: async () => ({ status: 'match', signature: 'Win.Test.Sample', engineVersion: '1.4.0', databaseVersion: '9' }),
  });
  assert.equal(match.assessment, 'complete');
  assert.equal(match.findings.find((finding) => finding.id === 'PSG-MALWARE-001').confidence, 'medium');
  assert.ok(match.findings.find((finding) => finding.id === 'PSG-MALWARE-001').references.some((url) => url.includes('/gui/search/')));

  const failed = await scanGalleryPackage({ name: 'Example', version: '1.0.0' }, gallery, {
    runPssa: false,
    scanAdvisories: false,
    clamavScanner: async () => ({ status: 'error', error: 'scanner unavailable' }),
  });
  assert.equal(failed.assessment, 'incomplete');
  assert.equal(failed.coverage.binaryScanning, false);
  assert.ok(failed.warnings.some((warning) => warning.includes('ClamAV could not scan')));
});

test('binary entries above extraction limits are skipped and mark archive coverage incomplete', () => {
  const bytes = createZip([{ name: 'too-large.exe', content: 'x'.repeat(ARCHIVE_LIMITS.entryBytes + 1) }]);
  const archive = inspectNupkg(bytes);
  assert.equal(archive.complete, false);
  assert.equal(archive.binaries.length, 0);
  assert.ok(archive.warnings.some((warning) => warning.includes('per-file')));
});

test('malformed ZIP bytes are rejected', () => {
  assert.throws(() => inspectNupkg(Buffer.from('not a package')), /too small|end-of-central-directory/);
});

test('behavior rules have positive and negative examples and confidence labels', () => {
  const positive = analyzePowerShellBehavior([{ path: 'tools/a.ps1', kind: 'script', text: 'Invoke-WebRequest $u; Invoke-Expression $x' }]);
  assert.ok(positive.some((finding) => finding.id === 'PSG-BEHAVIOR-001' && finding.confidence === 'low'));
  assert.ok(positive.some((finding) => finding.id === 'PSG-BEHAVIOR-002' && finding.confidence === 'medium'));

  const negative = analyzePowerShellBehavior([{ path: 'tools/a.ps1', kind: 'script', text: 'Get-Item -Path .\n# Invoke-Expression $untrusted' }]);
  assert.equal(negative.length, 0);
});

test('secret evidence is redacted before public serialization', () => {
  const finding = analyzePowerShellBehavior([{
    path: 'tools/secret.ps1', kind: 'script', text: "$token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'",
  }]).find((item) => item.category === 'secret');
  assert.ok(finding);
  const serialized = JSON.stringify(redactFinding(finding));
  assert.doesNotMatch(serialized, /ghp_abcdefghijklmnopqrstuvwxyz/);
  assert.match(serialized, /REDACTED/);
});

test('PSScriptAnalyzer rule IDs normalize into evidence-backed findings', () => {
  const findings = normalizePSScriptAnalyzerFindings([{
    ruleId: 'PSAvoidUsingInvokeExpression',
    severity: 'Warning',
    message: 'Invoke-Expression is used.',
    file: 'tools/example.ps1',
    line: 2,
    endLine: 2,
  }], [{ path: 'tools/example.ps1', text: 'Get-Item .\nInvoke-Expression $command' }]);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, 'PSSA-PSAvoidUsingInvokeExpression');
  assert.equal(findings[0].evidence.line, 2);
  assert.equal(findings[0].evidence.snippet, 'Invoke-Expression $command');
});

test('known credential formats are detected and redacted even without credential-like variable names', () => {
  const finding = analyzePowerShellBehavior([{
    path: 'tools/config.ps1', kind: 'script', text: "$value = 'github_pat_abcdefghijklmnopqrstuvwxyz0123456789'",
  }]).find((item) => item.id === 'PSG-SECRET-002');
  assert.ok(finding);
  assert.equal(finding.confidence, 'high');
  assert.doesNotMatch(JSON.stringify(finding), /github_pat_abcdefghijklmnopqrstuvwxyz/);
});
