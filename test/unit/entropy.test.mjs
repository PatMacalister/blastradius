/**
 * The unrecognised-credential heuristic.
 *
 * The precision tests matter more than the recall ones. A heuristic that flags lockfile
 * hashes and placeholder strings gets muted within a day, and a muted warning is worse than
 * no warning at all — it manufactures the appearance of coverage.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { shannonEntropy, isSuspiciousValue, looksLikeSecretKeyName, findUnrecognised } from '../../src/core/entropy.mjs';

test('entropy rises with disorder', () => {
  assert.ok(shannonEntropy('aaaaaaaaaaaaaaaaaaaa') < 1);
  assert.ok(shannonEntropy('xK9$mQ2vLp7wRt4zYn1B') > 3.5);
});

test('secret-shaped key names are recognised, ordinary ones are not', () => {
  for (const key of ['API_SECRET', 'db_password', 'AUTH_TOKEN', 'privateKey', 'SERVICE_API_KEY']) {
    assert.ok(looksLikeSecretKeyName(key), `${key} should look secret-shaped`);
  }
  for (const key of ['NODE_ENV', 'PORT', 'user_name', 'LOG_LEVEL']) {
    assert.equal(looksLikeSecretKeyName(key), false, `${key} should not`);
  }
});

// Substring matching would flag all of these. Tokenising is what keeps the section readable.
test('key names that merely contain a secret word are not flagged', () => {
  for (const key of ['publicKey', 'PRIMARY_KEY', 'tokenizer', 'monkey', 'keyboardShortcut']) {
    assert.equal(looksLikeSecretKeyName(key), false, `${key} should not be flagged`);
  }
});

test('lockfile hashes and UUIDs are not treated as unknown credentials', () => {
  assert.equal(isSuspiciousValue('a'.repeat(40)), false);              // sha1-shaped
  assert.equal(isSuspiciousValue('0123456789abcdef'.repeat(4)), false); // sha256-shaped
  assert.equal(isSuspiciousValue('3f2504e0-4f89-11d3-9a0c-0305e82c3301'), false);
  assert.equal(isSuspiciousValue('https://example.com/some/long/path/here'), false);
});

test('placeholders are not flagged — flagging them is how a tool gets ignored', () => {
  for (const v of ['changeme', 'your-api-key-here', 'xxxxxxxxxxxxxxxxxxxxxx', '${SOME_VAR}', '<your-token>']) {
    assert.equal(isSuspiciousValue(v), false, `${v} should not be flagged`);
  }
});

test('a genuine-looking opaque credential is flagged', () => {
  assert.ok(isSuspiciousValue('hX7pQ2mK9vLw4RtZ8nB3yD6fJ1sA5gU0'));
});

test('context is required — high entropy alone is not enough', () => {
  const pairs = [
    { key: 'BUILD_HASH', value: 'hX7pQ2mK9vLw4RtZ8nB3yD6fJ1sA5gU0', source: { path: '.env' } },
    { key: 'DB_PASSWORD', value: 'hX7pQ2mK9vLw4RtZ8nB3yD6fJ1sA5gU0', source: { path: '.env' } },
  ];
  const found = findUnrecognised(pairs);
  assert.equal(found.length, 1);
  assert.equal(found[0].key, 'DB_PASSWORD');
});

test('a credential already identified by a provider is not double-reported', () => {
  const secret = 'hX7pQ2mK9vLw4RtZ8nB3yD6fJ1sA5gU0';
  const pairs = [{ key: 'API_TOKEN', value: secret, source: { path: '.env' } }];
  assert.equal(findUnrecognised(pairs).length, 1);
  assert.equal(findUnrecognised(pairs, { knownSecrets: new Set([secret]) }).length, 0);
});
