/**
 * These tests are the mechanical half of the open-source review gate. A contributed
 * provider that fails here should never reach a human reviewer's judgement.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { validateProvider, validateCapabilityOutput, stalenessOf, daysSince } from '../../src/providers/_contract.mjs';
import { providers, loadProviders } from '../../src/providers/index.mjs';

const VALID = {
  id: 'example',
  label: 'Example',
  lastVerified: '2026-07-01',
  apiHosts: ['api.example.com'],
  changelog: { url: 'https://example.com/changelog', type: 'html' },
  patterns: [{ name: 'key', regex: /\bex_[A-Za-z0-9]{10}\b/, confidence: 0.9 }],
  introspect: async () => ({ valid: true, scopes: [], unresolved: false }),
  toCapabilities: () => [],
  remediation: () => [],
};

test('every shipped provider satisfies the contract', () => {
  assert.doesNotThrow(() => loadProviders());
  for (const provider of providers) {
    const { ok, errors } = validateProvider(provider);
    assert.ok(ok, `${provider.id}: ${errors.join('; ')}`);
  }
});

test('a well-formed module validates', () => {
  assert.ok(validateProvider(VALID).ok);
});

test('missing apiHosts is rejected', () => {
  const { ok, errors } = validateProvider({ ...VALID, apiHosts: undefined });
  assert.ok(!ok);
  assert.ok(errors.some((e) => e.includes('apiHosts')));
});

// A wildcard host would defeat the egress guard entirely, which is the one thing
// standing between a hostile PR and credential exfiltration.
test('wildcard hosts are rejected', () => {
  const { ok } = validateProvider({ ...VALID, apiHosts: ['*.example.com'] });
  assert.ok(!ok);
});

test('a missing lastVerified stamp is rejected', () => {
  const { ok } = validateProvider({ ...VALID, lastVerified: 'recently' });
  assert.ok(!ok);
});

test('a non-RegExp pattern is rejected', () => {
  const { ok } = validateProvider({ ...VALID, patterns: [{ name: 'k', regex: 'ex_', confidence: 1 }] });
  assert.ok(!ok);
});

test('a missing required function is rejected', () => {
  const { ok, errors } = validateProvider({ ...VALID, toCapabilities: undefined });
  assert.ok(!ok);
  assert.ok(errors.some((e) => e.includes('toCapabilities')));
});

test('capability output is checked against the closed vocabulary', () => {
  assert.ok(validateCapabilityOutput('example', ['destroy:data']).ok);
  const bad = validateCapabilityOutput('example', ['destroy:everything']);
  assert.ok(!bad.ok);
  assert.ok(bad.errors[0].includes('destroy:everything'));
});

test('staleness is measured from the verification stamp', () => {
  const now = new Date('2026-07-27T00:00:00Z');
  assert.equal(daysSince('2026-07-27', now), 0);
  assert.equal(stalenessOf({ lastVerified: '2026-07-20' }, now).stale, false);
  assert.equal(stalenessOf({ lastVerified: '2026-01-01' }, now).stale, true);
});
