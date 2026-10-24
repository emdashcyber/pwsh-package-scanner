import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflow = await readFile(new URL('../../.github/workflows/research-scan.yml', import.meta.url), 'utf8');
const job = (name, nextName) => workflow.match(new RegExp('  ' + name + ':\\n([\\s\\S]*?)\\n  ' + nextName + ':'))?.[1] || '';

test('scan data is read-only until the validated data-commit job', () => {
  const scan = job('scan', 'commit-data');
  const commit = job('commit-data', 'build-and-deploy');
  assert.match(scan, /contents: read/);
  assert.doesNotMatch(scan, /contents: write/);
  assert.match(commit, /contents: write/);
  assert.match(commit, /validate-api-snapshot\.js/);
  assert.match(commit, /git add site\/public\/api\/v1/);
  assert.match(workflow, /paths-ignore:\n\s+- 'site\/public\/api\/v1\/\*\*'/);
});

test('deployment builds the committed snapshot at site/dist after data commit', () => {
  const build = job('build-and-deploy', 'deploy');
  const deploy = workflow.match(/  deploy:\n([\s\S]*)$/)?.[1] || '';
  assert.match(build, /needs: commit-data/);
  assert.match(build, /npm run build --prefix site/);
  assert.match(build, /path: site\/dist/);
  assert.match(deploy, /needs: build-and-deploy/);
});
