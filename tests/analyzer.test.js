import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { runPSScriptAnalyzer } from '../scanner/analysis.js';

const pwsh = process.env.PWSH_PATH || 'pwsh';
const moduleCheck = spawnSync(pwsh, [
  '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
  "if (Get-Module -ListAvailable PSScriptAnalyzer | Where-Object Version -eq '1.25.0') { exit 0 } else { exit 1 }",
], { encoding: 'utf8' });
const modulePathResult = spawnSync(pwsh, ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$env:PSModulePath'], { encoding: 'utf8' });
const hasPinnedAnalyzer = moduleCheck.status === 0 && modulePathResult.status === 0;

test('PowerShell analyzer skips format XML and DSC parser cascades but reports ordinary syntax errors', {
  skip: !hasPinnedAnalyzer && 'PSScriptAnalyzer 1.25.0 is not installed on this machine.',
}, async () => {
  const originalModulePath = process.env.PSSCRIPTANALYZER_MODULE_PATH;
  process.env.PSSCRIPTANALYZER_MODULE_PATH = modulePathResult.stdout.trim();
  try {
    const result = await runPSScriptAnalyzer([
      {
        path: 'Format.ps1xml',
        kind: 'xml',
        text: '<Configuration><View><ScriptBlock>--</ScriptBlock></View></Configuration>',
      },
      {
        path: 'Dsc.ps1',
        kind: 'script',
        text: "Configuration Sample {\n Node localhost {\n  File Example { DestinationPath = '/tmp/example' }\n }\n}",
      },
      {
        path: 'Malformed.ps1',
        kind: 'script',
        text: 'function Broken {\n Write-Output 1\n',
      },
    ], { enabled: true, pwsh });

    assert.equal(result.complete, true);
    assert.equal(result.findings.some((finding) => finding.file === 'Format.ps1xml'), false);
    assert.equal(result.findings.some((finding) => finding.file === 'Dsc.ps1'), false);
    assert.ok(result.warnings.some((warning) => warning.includes('Dsc.ps1') && warning.includes('DSC syntax validation was skipped')));
    assert.ok(result.findings.some((finding) => finding.file === 'Malformed.ps1' && finding.ruleId === 'PowerShellParseError'));
  } finally {
    if (originalModulePath === undefined) delete process.env.PSSCRIPTANALYZER_MODULE_PATH;
    else process.env.PSSCRIPTANALYZER_MODULE_PATH = originalModulePath;
  }
});
