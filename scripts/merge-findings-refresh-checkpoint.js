import { access, readFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import {
  FINDINGS_REFRESH_ID,
  mergeFindingsRefreshCheckpoint,
  mergeFindingsRefreshUpdate,
  removeRetiredFindings,
} from '../scanner/findings-refresh.js';
import { loadLocalState, writeSnapshot } from '../scanner/state.js';

const checkpointDirectory = resolve(process.argv[2] || '');
const publicDirectory = resolve(process.argv[3] || 'site/public');
if (!process.argv[2]) throw new Error('Usage: node scripts/merge-findings-refresh-checkpoint.js <checkpoint-directory> [public-directory]');

const checkpoint = JSON.parse(await readFile(resolve(checkpointDirectory, 'checkpoint.json'), 'utf8'));
if (checkpoint.id !== FINDINGS_REFRESH_ID) throw new Error('The findings refresh checkpoint is for a different ruleset.');

const state = await loadLocalState(publicDirectory);
let merged = 0;
let stale = 0;
const updatesPath = resolve(checkpointDirectory, 'updates.jsonl');
let hasUpdates = true;
try {
  await access(updatesPath);
} catch (error) {
  if (error.code === 'ENOENT') hasUpdates = false;
  else throw error;
}
if (hasUpdates) {
  const lines = createInterface({ input: createReadStream(updatesPath), crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    const update = JSON.parse(line);
    if (mergeFindingsRefreshUpdate(state, update)) merged++;
    else stale++;
  }
}
const progress = mergeFindingsRefreshCheckpoint(state, { ...checkpoint, updates: [] }).findingsRefresh;
removeRetiredFindings(state);
const manifest = await writeSnapshot(state, publicDirectory);
process.stdout.write(JSON.stringify({
  merged,
  stale,
  findingsRefresh: manifest.findingsRefresh || progress,
  generatedAt: manifest.generatedAt,
}) + '\n');
