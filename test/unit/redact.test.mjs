import test from 'node:test';
import assert from 'node:assert/strict';
import { fingerprint, scrub } from '../../src/core/redact.mjs';

const TOKEN = `ghp_${'A'.repeat(36)}`;

test('fingerprint never contains the whole secret', () => {
  const fp = fingerprint(TOKEN);
  assert.ok(!fp.includes(TOKEN));
  assert.ok(fp.length < TOKEN.length + 1);
});

test('fingerprint keeps enough to identify the key in a dashboard', () => {
  const fp = fingerprint(TOKEN);
  assert.ok(fp.startsWith('ghp_'));
  assert.ok(fp.endsWith('AAAA'));
});

test('short secrets are fully masked', () => {
  assert.equal(fingerprint('abc'), '***');
});

test('empty and non-string input is handled', () => {
  assert.equal(fingerprint(''), '<empty>');
  assert.equal(fingerprint(undefined), '<empty>');
});

// Provider error bodies routinely echo the credential back at you.
test('scrub removes secrets that leaked into error text', () => {
  const message = `Request failed: invalid token ${TOKEN} rejected`;
  const cleaned = scrub(message);
  assert.ok(!cleaned.includes(TOKEN));
  assert.ok(cleaned.includes('Request failed'));
});

test('scrub handles stripe and aws shapes', () => {
  const stripeKey = `sk_live_${'B'.repeat(24)}`;
  const awsKey = `AKIA${'C'.repeat(16)}`;
  const cleaned = scrub(`${stripeKey} and ${awsKey}`);
  assert.ok(!cleaned.includes(stripeKey));
  assert.ok(!cleaned.includes(awsKey));
});

test('scrub passes through text with no secrets', () => {
  assert.equal(scrub('nothing to see'), 'nothing to see');
});
