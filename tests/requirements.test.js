import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePowerShellRequirements } from '../scanner/requirements.js';

test('module manifest distinguishes RequiredModules requirements from ModuleList containment', () => {
  const result = parsePowerShellRequirements([{
    path: 'Az/Az.psd1',
    kind: 'script',
    text: `@{
  ModuleList = @('Az.Accounts', 'Az.Resources')
  RequiredModules = @(
    @{ ModuleName = 'Cloud.Core'; ModuleVersion = '1.2.0'; MaximumVersion = '2.0.0' }
    'Legacy.Tools'
  )
}`,
  }]);
  assert.deepEqual(result.contains.map(({ name, relation }) => [name, relation]), [
    ['Az.Accounts', 'contains'],
    ['Az.Resources', 'contains'],
  ]);
  assert.deepEqual(result.requirements.map(({ name, versionRange, relation, declarationSources }) => [
    name, versionRange, relation, declarationSources[0],
  ]), [
    ['Cloud.Core', '[1.2.0,2.0.0]', 'requires', 'RequiredModules'],
    ['Legacy.Tools', '*', 'requires', 'RequiredModules'],
  ]);
  assert.equal(result.requirements[0].file, 'Az/Az.psd1');
});

test('#Requires -Modules accepts multiple names and versioned module specifications', () => {
  const result = parsePowerShellRequirements([{
    path: 'tools/setup.ps1',
    kind: 'script',
    text: `#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'PowerShellGet'; RequiredVersion = '2.2.5' }
#Requires -Modules 'Az.Accounts', 'Az.Resources'`,
  }]);
  assert.deepEqual(result.requirements.map(({ name, versionRange, line, declarationSources }) => [
    name, versionRange, line, declarationSources[0],
  ]), [
    ['PowerShellGet', '[2.2.5]', 2, '#Requires -Modules'],
    ['Az.Accounts', '*', 3, '#Requires -Modules'],
    ['Az.Resources', '*', 3, '#Requires -Modules'],
  ]);
});
