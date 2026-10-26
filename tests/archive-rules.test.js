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
  const packageBytes = createZip([
    ...packageEntries({ script: `Set-Content -LiteralPath '${marker}' -Value 'executed'` }),
    { name: 'tools/Example.Format.ps1xml', content: '<Configuration><View><ScriptBlock>--</ScriptBlock></View></Configuration>' },
  ]);
  const archive = inspectNupkg(packageBytes);
  assert.equal(archive.complete, true);
  assert.equal(archive.files.filter((file) => file.kind === 'script').length, 1);
  assert.equal(archive.files.find((file) => file.path.endsWith('.ps1xml')).kind, 'xml');

  const result = await scanGalleryPackage({ name: 'Example', version: '1.0.0' }, {
    downloadPackage: async () => packageBytes,
    resolveDependencyGraph: async () => ({ dependencies: [], complete: true }),
  }, { runPssa: false, scanAdvisories: false });
  assert.equal(result.assessment, 'complete');
  assert.equal(result.fileInventory.length, 3);
  assert.equal(result.findings.some((finding) => finding.id === 'PSSA-PowerShellParseError'), false);
  const { access } = await import('node:fs/promises');
  await assert.rejects(access(marker));
});

test('routine file changes are not reported while new binaries retain file evidence', async () => {
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
  assert.equal(result.findings.some((finding) => /^PSG-SUPPLY-004(?:-|$)/.test(finding.id)), false);
  assert.ok(result.findings.some((finding) => finding.id === 'PSG-SUPPLY-002' && finding.evidence.file === 'tools/New.dll'));
});

test('corrupt and oversized packages do not get complete assessments', () => {
  assert.deepEqual(ARCHIVE_LIMITS, {
    compressedBytes: 100 * 1024 * 1024,
    entryCount: 5000,
    entryBytes: 35 * 1024 * 1024,
    totalBytes: 150 * 1024 * 1024,
    compressionRatio: 500,
  });
  const valid = createZip(packageEntries());
  const corrupt = Buffer.from(valid);
  const central = corrupt.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  corrupt.writeUInt32LE(0, central + 16);
  assert.equal(inspectNupkg(corrupt).complete, false);

  const customLimits = { ...ARCHIVE_LIMITS, entryBytes: 8 };
  const oversized = inspectNupkg(createZip([{ name: 'large.ps1', content: 'x'.repeat(9) }]), customLimits);
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

test('PowerShell-only refresh can retain binary inventory without extracting binary contents', () => {
  const archive = inspectNupkg(createZip([
    ...packageEntries(),
    { name: 'bin/tool.dll', content: Buffer.from('binary content') },
  ]), undefined, { includeBinaries: false });
  assert.equal(archive.complete, true);
  assert.equal(archive.binaries.length, 0);
  assert.ok(archive.inventory.some((file) => file.path === 'bin/tool.dll'));
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

test('behavior rules require a direct download-to-execution relationship', () => {
  const direct = analyzePowerShellBehavior([{ path: 'tools/a.ps1', kind: 'script', text: '$payload = Invoke-WebRequest $u\nInvoke-Expression $payload' }]);
  assert.ok(direct.some((finding) => finding.id === 'PSG-BEHAVIOR-001' && finding.confidence === 'low'));
  assert.ok(direct.some((finding) => finding.id === 'PSG-BEHAVIOR-002' && finding.confidence === 'medium'));

  const nestedDirect = analyzePowerShellBehavior([{
    path: 'tools/a.ps1', kind: 'script', text: '[ScriptBlock]::Create((Invoke-RestMethod -Uri $u))',
  }]);
  assert.ok(nestedDirect.some((finding) => finding.id === 'PSG-BEHAVIOR-002'));

  const unrelated = analyzePowerShellBehavior([{ path: 'tools/a.ps1', kind: 'script', text: 'Invoke-WebRequest $u; Invoke-Expression $x' }]);
  assert.ok(unrelated.some((finding) => finding.id === 'PSG-BEHAVIOR-001'));
  assert.equal(unrelated.some((finding) => finding.id === 'PSG-BEHAVIOR-002'), false);

  const unrelatedDownloadAndProcess = analyzePowerShellBehavior([{
    path: 'tools/a.ps1', kind: 'script', text: "Invoke-WebRequest $u -OutFile $downloadPath\nStart-Process 'trusted-installer.exe'",
  }]);
  assert.equal(unrelatedDownloadAndProcess.some((finding) => finding.id === 'PSG-BEHAVIOR-002'), false);

  const safeLookup = analyzePowerShellBehavior([{ path: 'tools/a.ps1', kind: 'script', text: "$ExecutionContext.InvokeCommand.GetCommand('Get-Item', 'All')" }]);
  assert.equal(safeLookup.length, 0);

  const negative = analyzePowerShellBehavior([{ path: 'tools/a.ps1', kind: 'script', text: 'Get-Item -Path .\n# Invoke-Expression $untrusted' }]);
  assert.equal(negative.length, 0);
});

test('placeholder credential values are ignored while other literal values remain detectable', () => {
  const findings = analyzePowerShellBehavior([{
    path: 'tools/config.ps1',
    kind: 'script',
    text: "$password = ' ChangeMe '\n$token = \"PASSWORD\"\n$secret = 'likely-real-secret-value'",
  }]);
  assert.equal(findings.filter((finding) => finding.id === 'PSG-SECRET-001').length, 1);
  assert.equal(findings[0].evidence.line, 3);

  const plainText = normalizePSScriptAnalyzerFindings([{
    ruleId: 'PSAvoidUsingConvertToSecureStringWithPlainText',
    severity: 'Warning',
    message: 'Plain text is converted to a secure string.',
    file: 'tools/config.ps1',
    line: 1,
    endLine: 1,
  }], [{ path: 'tools/config.ps1', text: "ConvertTo-SecureString -String ' password ' -AsPlainText" }]);
  assert.equal(plainText.length, 0);

  const assignedPlaceholder = normalizePSScriptAnalyzerFindings([{
    ruleId: 'PSAvoidUsingConvertToSecureStringWithPlainText',
    message: 'Plain text is converted to a secure string.',
    file: 'tools/config.ps1',
    line: 2,
  }], [{ path: 'tools/config.ps1', text: "$password = 'PASSWORD'\nConvertTo-SecureString -String $password -AsPlainText" }]);
  assert.equal(assignedPlaceholder.length, 0);

  const changedPlaceholder = normalizePSScriptAnalyzerFindings([{
    ruleId: 'PSAvoidUsingConvertToSecureStringWithPlainText',
    message: 'Plain text is converted to a secure string.',
    file: 'tools/config.ps1',
    line: 2,
  }], [{ path: 'tools/config.ps1', text: "$password = 'password' + '-suffix'\nConvertTo-SecureString -String $password -AsPlainText" }]);
  assert.equal(changedPlaceholder.length, 1);

  const otherValue = normalizePSScriptAnalyzerFindings([{
    ruleId: 'PSAvoidUsingConvertToSecureStringWithPlainText',
    message: 'Plain text is converted to a secure string.',
    file: 'tools/config.ps1',
    line: 1,
  }], [{ path: 'tools/config.ps1', text: "ConvertTo-SecureString -String 'different-secret' -AsPlainText" }]);
  assert.equal(otherValue.length, 1);
});

test('plain-text password parameter design findings remain distinct from credential values', () => {
  const finding = normalizePSScriptAnalyzerFindings([{
    ruleId: 'PSAvoidUsingPlainTextForPassword',
    message: 'A plaintext password parameter is declared.',
    file: 'tools/config.ps1',
    line: 1,
  }], [{ path: 'tools/config.ps1', text: 'param([string]$Password)' }]);
  assert.equal(finding.length, 1);
  assert.equal(finding[0].id, 'PSSA-PSAvoidUsingPlainTextForPassword');
});

test('PEM private-key findings require a complete block with key material', () => {
  const headerOnly = analyzePowerShellBehavior([{
    path: 'tools/key.ps1', kind: 'script', text: "Write-Output '-----BEGIN RSA PRIVATE KEY-----'",
  }]);
  assert.equal(headerOnly.some((finding) => finding.id === 'PSG-SECRET-002'), false);

  const completeBlock = analyzePowerShellBehavior([{
    path: 'tools/key.ps1',
    kind: 'script',
    text: "`$key = @'\n-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAabcdefghijklmnopqrstuvwxyz0123456789+/==\n-----END RSA PRIVATE KEY-----\n'@",
  }]);
  const finding = completeBlock.find((item) => item.id === 'PSG-SECRET-002');
  assert.ok(finding);
  assert.equal(finding.evidence.snippet, '[REDACTED_PRIVATE_KEY_BLOCK]');
  assert.doesNotMatch(JSON.stringify(finding), /MIIEogIBAAKCA/);
});

test('PowerShell commands inside here-strings are ignored and code after them is analyzed', () => {
  const findings = analyzePowerShellBehavior([{
    path: 'tools/here-string.ps1',
    kind: 'script',
    text: `\$example = @"\nInvoke-Expression \$untrusted\n"@\nInvoke-Expression \$command`,
  }]);
  assert.equal(findings.filter((finding) => finding.id === 'PSG-BEHAVIOR-001').length, 1);
  assert.equal(findings[0].evidence.line, 4);
});

test('invisible Unicode findings ignore comments and strings but detect executable code', () => {
  const ignored = analyzePowerShellBehavior([{
    path: 'tools/unicode.ps1', kind: 'script', text: "# comment \u200b\n$message = 'text \u200b'",
  }]);
  assert.equal(ignored.some((finding) => finding.id === 'PSG-BEHAVIOR-005'), false);

  const active = analyzePowerShellBehavior([{
    path: 'tools/unicode.ps1', kind: 'script', text: 'Write-\u200bOutput "hello"',
  }]);
  assert.equal(active.some((finding) => finding.id === 'PSG-BEHAVIOR-005'), true);
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
