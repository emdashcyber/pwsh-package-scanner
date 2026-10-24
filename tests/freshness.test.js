import test from 'node:test';
import assert from 'node:assert/strict';
import { getFreshnessState } from '../site/src/scripts/freshness.js';

test('a successful scan within six hours is recent even when the old manifest status is degraded', () => {
  const now = Date.parse('2026-10-24T18:00:00Z');
  const state = getFreshnessState({
    status: 'degraded',
    freshnessWindowHours: 6,
    lastSuccessfulScan: '2026-10-24T12:01:00Z',
  }, now);
  assert.equal(state.state, 'recent');
  assert.equal(state.freshnessWindowHours, 6);
});

test('a scan older than six hours is stale and a missing timestamp is not started', () => {
  const now = Date.parse('2026-10-24T18:01:00Z');
  assert.equal(getFreshnessState({ lastSuccessfulScan: '2026-10-24T12:00:00Z' }, now).state, 'stale');
  assert.equal(getFreshnessState({}, now).state, 'not_started');
});
