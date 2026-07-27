import test from 'node:test';
import assert from 'node:assert/strict';
import { assessSeverity, describeCapabilities, maxSeverity } from '../../src/core/capabilities.mjs';

test('no capabilities is none', () => {
  assert.equal(assessSeverity([]), 'none');
});

test('read-only access ranks low', () => {
  assert.equal(assessSeverity(['read:metadata']), 'low');
});

test('destroying data alone is severe, not catastrophic', () => {
  assert.equal(assessSeverity(['destroy:data']), 'severe');
});

test('destroying backups alone is severe, not catastrophic', () => {
  assert.equal(assessSeverity(['destroy:backups']), 'severe');
});

// The catastrophic amplifier (see INCIDENTS.md). The single most important assertion in the
// suite: data and backups under one credential is what turned nine seconds of deletion into
// a thirty-hour recovery.
test('data AND backups together is catastrophic', () => {
  assert.equal(assessSeverity(['destroy:data', 'destroy:backups']), 'catastrophic');
});

test('the amplifier survives extra capabilities', () => {
  assert.equal(
    assessSeverity(['read:metadata', 'destroy:backups', 'deploy', 'destroy:data']),
    'catastrophic',
  );
});

test('unknown verbs do not raise severity', () => {
  assert.equal(assessSeverity(['not-a-real-verb']), 'none');
});

test('describeCapabilities orders worst first and drops unknowns', () => {
  const described = describeCapabilities(['read:metadata', 'move:money', 'bogus']);
  assert.equal(described.length, 2);
  assert.equal(described[0].capability, 'move:money');
});

test('maxSeverity picks the worse of two', () => {
  assert.equal(maxSeverity('low', 'severe'), 'severe');
  assert.equal(maxSeverity('catastrophic', 'high'), 'catastrophic');
});
