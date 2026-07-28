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

// A regex that backtracks catastrophically passed every other gate. Measured: /^(a+)+$/
// against 41 characters took 91 seconds, and discovery runs patterns over every line of
// every file. For a scanner, a run that never finishes reads as a run that found nothing.
test('a catastrophically backtracking pattern is rejected', () => {
  const base = {
    id: 'evil', label: 'Evil', lastVerified: '2026-07-28', apiHosts: ['api.evil.test'],
    changelog: { url: 'https://evil.test/feed', type: 'rss' },
    introspect: async () => ({}), toCapabilities: () => [], remediation: () => [],
  };

  for (const bad of [/^(a+)+$/, /(x*)*y/, /([a-z]+)+@/, /(\d{2,})+z/]) {
    const { ok, errors } = validateProvider({ ...base, patterns: [{ name: 'boom', regex: bad, confidence: 0.9 }] });
    assert.equal(ok, false, `${bad} must be rejected`);
    assert.ok(errors.some((e) => /backtrack/i.test(e)), `${bad} should name the reason`);
  }
});

// The guard must not be so blunt it rejects the patterns already shipping.
test('every shipped provider pattern passes the backtracking check', () => {
  for (const mod of providers) {
    const { ok, errors } = validateProvider(mod);
    assert.ok(ok, `${mod.id}: ${errors.join('; ')}`);
  }
});
