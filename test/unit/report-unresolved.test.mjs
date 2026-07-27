/**
 * Regression guard for a bug found during the first CLI smoke test: discover-only mode
 * printed "worst case: NONE", which is the precise failure mode this tool exists to
 * complain about — an unassessed result skim-reading as a clean one.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { renderText } from '../../src/core/report.mjs';
import { FAKE } from '../fixtures.mjs';

const raw = {
  secret: FAKE.stripeLive,
  providerId: 'stripe',
  pattern: 'secret-live',
  confidence: 0.99,
  sources: [{ kind: 'file', path: '.env', line: 1 }],
};

test('discover-only output never claims a worst case', () => {
  const out = renderText([raw], { resolved: false });
  assert.ok(!out.includes('worst case'));
  assert.ok(!/NONE/.test(out));
  assert.ok(out.includes('severity not assessed'));
});

test('discover-only output tells the user how to get an answer', () => {
  const out = renderText([raw], { resolved: false });
  assert.ok(out.includes('--resolve'));
});
