/**
 * CONTRACT TESTS — Mechanism A from DRIFT-AND-OSS-PLAN.md.
 *
 * These hit the real provider APIs with a real, deliberately low-privilege credential and
 * assert that the parsed scope still matches what the module expects. This is what catches
 * silent semantic drift — a provider renaming a key class or changing what an introspection
 * endpoint returns — which unit tests with fixtures structurally cannot see.
 *
 * They are NOT part of `npm test`. They run on a schedule in CI, and are required for any
 * PR that adds or changes a provider module.
 *
 * Per provider, supply:
 *   BLASTRADIUS_TEST_<ID>     a live credential with KNOWN, MINIMAL scope
 *   BLASTRADIUS_EXPECT_<ID>   JSON array of the scope strings that credential should yield
 *
 * e.g. BLASTRADIUS_TEST_GITHUB=ghp_...  BLASTRADIUS_EXPECT_GITHUB='["read:user"]'
 *
 * RULES for test credentials, which are not negotiable:
 *   - never grant a test credential a destructive scope. The point is to verify parsing,
 *     not to hold a loaded gun in CI.
 *   - prefer providers that issue short-lived or easily-rotated tokens.
 *   - a provider whose test credential cannot be obtained cheaply should not ship.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { providers } from '../../src/providers/index.mjs';
import { guardedFetch } from '../../src/core/resolve.mjs';
import { validateCapabilityOutput } from '../../src/providers/_contract.mjs';

const envKey = (id, prefix) => `BLASTRADIUS_${prefix}_${id.toUpperCase().replace(/-/g, '_')}`;

for (const provider of providers) {
  const secret = process.env[envKey(provider.id, 'TEST')];
  const expectRaw = process.env[envKey(provider.id, 'EXPECT')];

  test(`${provider.id}: live introspection matches expected scope`, { skip: !secret ? `no ${envKey(provider.id, 'TEST')} set` : false }, async () => {
    const introspection = await provider.introspect(secret, {
      fetchImpl: guardedFetch(provider.apiHosts),
    });

    assert.equal(introspection.valid, true, 'test credential should be live — rotate it if this fails');

    if (expectRaw) {
      const expected = JSON.parse(expectRaw);
      assert.deepEqual(
        [...introspection.scopes].sort(),
        [...expected].sort(),
        `SCOPE DRIFT: ${provider.id} returned different scopes than expected. Either the ` +
        `test credential changed, or the provider changed its API. Investigate before ` +
        `re-stamping lastVerified.`,
      );
    }

    const capabilities = provider.toCapabilities(introspection);
    const check = validateCapabilityOutput(provider.id, capabilities);
    assert.ok(check.ok, check.errors.join('; '));

    assert.doesNotThrow(() => provider.remediation(introspection));
  });

  test(`${provider.id}: rejects a bogus credential`, { skip: !secret ? 'no live credential configured' : false }, async () => {
    const introspection = await provider.introspect('obviously-not-a-real-credential', {
      fetchImpl: guardedFetch(provider.apiHosts),
    });
    assert.equal(introspection.valid, false, 'a garbage credential must not read as valid');
  });
}
