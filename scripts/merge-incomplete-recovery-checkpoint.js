import { resolve } from 'node:path';
import {
  loadLocalState,
  SITE_PUBLIC_DIRECTORY,
  writeSnapshot,
} from '../scanner/state.js';
import { mergeIncompleteRecoveryCheckpoint } from '../scanner/incomplete-recovery.js';

const checkpointPublicDirectory = process.argv[2];
if (!checkpointPublicDirectory) {
  throw new Error('Pass the public directory containing the checkpoint under api/v1/.');
}

const currentState = await loadLocalState(SITE_PUBLIC_DIRECTORY);
const checkpointState = await loadLocalState(resolve(checkpointPublicDirectory));
if (!currentState.packages.size) throw new Error('The current checked-in API snapshot is missing.');
if (!checkpointState.packages.size) throw new Error('The recovery checkpoint API snapshot is missing.');

const merge = mergeIncompleteRecoveryCheckpoint(currentState, checkpointState);
const manifest = await writeSnapshot(currentState, SITE_PUBLIC_DIRECTORY);
process.stdout.write(JSON.stringify({
  event: 'incomplete_recovery_checkpoint_merged',
  mergedAttempts: merge.mergedAttempts,
  newerCurrentAttemptsKept: merge.newerCurrentAttemptsKept,
  pending: merge.pending,
  stillIncomplete: manifest.incompleteRecovery.stillIncomplete,
  recovery: manifest.incompleteRecovery,
}) + '\n');
