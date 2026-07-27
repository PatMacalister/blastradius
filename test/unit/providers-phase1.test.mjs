/**
 * Phase 1 provider modules.
 *
 * Every test here asserts one of two things: that a genuinely dangerous credential is
 * described in consequence terms, or that a credential whose reach we cannot establish
 * comes back `unresolved` rather than quietly empty. The second kind matters more — an
 * empty capability list renders as "harmless", and being wrong in that direction is the
 * only failure this tool has no excuse for.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import * as railway from '../../src/providers/railway.mjs';
import * as supabase from '../../src/providers/supabase.mjs';
import * as vercel from '../../src/providers/vercel.mjs';
import * as cloudflare from '../../src/providers/cloudflare.mjs';
import { assessSeverity } from '../../src/core/capabilities.mjs';
import { validateProvider } from '../../src/providers/_contract.mjs';
import { fakeResponse, recordingFetch } from '../fixtures.mjs';

const jsonFetch = (handler) => recordingFetch(async (url, options) => handler(url, options));

/* ---------------------------------------------------------------- contract */

for (const mod of [railway, supabase, vercel, cloudflare]) {
  test(`${mod.id} satisfies the provider contract`, () => {
    const { ok, errors } = validateProvider(mod);
    assert.ok(ok, errors.join('; '));
  });
}

/* ---------------------------------------------------------------- railway */

test('a Railway account token is catastrophic — it reaches data and backups together', async () => {
  const fetchImpl = jsonFetch(async () =>
    fakeResponse({ body: { data: { me: { id: 'u1', email: 'dev@example.com' } } } }));

  const intro = await railway.introspect('tok', { fetchImpl });
  assert.equal(intro.tokenClass, 'account');
  assert.equal(intro.unresolved, false);

  const caps = railway.toCapabilities(intro);
  assert.ok(caps.includes('destroy:data'));
  assert.ok(caps.includes('destroy:backups'));
  // The reference-incident shape: one credential that removes the data and the way back.
  assert.equal(assessSeverity(caps), 'catastrophic');
});

test('a Railway project token is unresolved, never assumed narrow', async () => {
  // Bearer is refused for `me` and for the bare probe; only the project header is accepted.
  const fetchImpl = jsonFetch(async (_url, options) => {
    const headers = options.headers ?? {};
    if (headers['project-access-token']) return fakeResponse({ body: { data: { __typename: 'Query' } } });
    return fakeResponse({ status: 200, body: { errors: [{ message: 'Not Authorized' }] } });
  });

  const intro = await railway.introspect('tok', { fetchImpl });
  assert.equal(intro.tokenClass, 'project');
  assert.equal(intro.unresolved, true);
  assert.deepEqual(railway.toCapabilities(intro), [], 'unresolved must not emit capabilities');
});

test('a rejected Railway token is reported inactive rather than unknown', async () => {
  const fetchImpl = jsonFetch(async () => fakeResponse({ status: 401, body: {} }));
  const intro = await railway.introspect('tok', { fetchImpl });
  assert.equal(intro.valid, false);
});

/* ---------------------------------------------------------------- supabase */

function jwt(claims) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc(claims)}.sig`;
}

test('a service_role JWT is recognised as bypassing RLS, offline', async () => {
  const token = jwt({ role: 'service_role', ref: 'abcdefgh', exp: Math.floor(Date.now() / 1000) + 9999 });
  const fetchImpl = recordingFetch(async () => { throw new Error('must not touch the network'); });

  const intro = await supabase.introspect(token, { fetchImpl });
  assert.equal(intro.keyClass, 'secret');
  assert.equal(fetchImpl.calls.length, 0, 'classification must not require a network call');

  const caps = supabase.toCapabilities(intro);
  assert.ok(caps.includes('destroy:data'));
  // Full data authority, but it cannot delete the project or its backups.
  assert.equal(assessSeverity(caps), 'severe');
});

test('an anon key is low, not silently equal to a secret key', async () => {
  const token = jwt({ role: 'anon', ref: 'abcdefgh', exp: Math.floor(Date.now() / 1000) + 9999 });
  const intro = await supabase.introspect(token, { fetchImpl: async () => fakeResponse({}) });
  assert.equal(intro.keyClass, 'publishable');
  assert.equal(assessSeverity(supabase.toCapabilities(intro)), 'low');
});

test('an expired Supabase key is inactive', async () => {
  const token = jwt({ role: 'service_role', ref: 'abcdefgh', exp: Math.floor(Date.now() / 1000) - 10 });
  const intro = await supabase.introspect(token, { fetchImpl: async () => fakeResponse({}) });
  assert.equal(intro.valid, false);
});

// Real key shapes taken from the Supabase dashboard: they contain underscores and hyphens,
// and the random portion is not especially long. A pattern tuned to a guessed length would
// miss them.
test('real-world publishable and secret key shapes are matched', () => {
  const pub = 'sb_publishable_DL1Fq_t8GpJvI8iDfD1Yfw_QZ84-Aq';
  const sec = 'sb_secret_3or9M-xK2vLpQ7wRt4zYn';
  const byName = Object.fromEntries(supabase.patterns.map((p) => [p.name, p.regex]));

  assert.equal(`KEY=${pub}`.match(byName['publishable-key'])?.[0], pub);
  assert.equal(`KEY=${sec}`.match(byName['secret-key'])?.[0], sec);
});

test('a publishable key classifies as publishable, not as a secret', async () => {
  const intro = await supabase.introspect('sb_publishable_DL1Fq_t8GpJvI8iDfD1Yfw_QZ84-Aq', {
    fetchImpl: async () => fakeResponse({}),
  });
  assert.equal(intro.keyClass, 'publishable');
  assert.deepEqual(intro.scopes, ['publishable']);
  assert.equal(assessSeverity(supabase.toCapabilities(intro)), 'low');
});

test('an sb_secret_ key is classified from its prefix without a network call', async () => {
  const fetchImpl = recordingFetch(async () => { throw new Error('must not touch the network'); });
  const intro = await supabase.introspect(`sb_secret_${'a'.repeat(30)}`, { fetchImpl });
  assert.equal(intro.keyClass, 'secret');
  assert.equal(fetchImpl.calls.length, 0);
  assert.ok(intro.notes.some((n) => /Liveness not checked/i.test(n)), 'must admit liveness is unverified');
});

// The contract harness asserts every provider rejects garbage. Without this, a random string
// under a SUPABASE_* variable would surface as a live-but-unclassifiable phantom finding.
test('a string that is not a Supabase credential is rejected, not reported as unknown', async () => {
  const intro = await supabase.introspect('obviously-not-a-real-credential', { fetchImpl: async () => fakeResponse({}) });
  assert.equal(intro.valid, false);
  assert.equal(intro.unresolved, false);
});

test('a management token is catastrophic — deleting a project takes its backups', async () => {
  const fetchImpl = jsonFetch(async () => fakeResponse({ body: [{ id: 'p1' }, { id: 'p2' }] }));
  const intro = await supabase.introspect(`sbp_${'a'.repeat(40)}`, { fetchImpl });
  assert.equal(intro.keyClass, 'management');
  assert.equal(assessSeverity(supabase.toCapabilities(intro)), 'catastrophic');
});

/* ---------------------------------------------------------------- vercel */

test('a full Vercel token reaches secrets and can delete projects', async () => {
  const fetchImpl = jsonFetch(async () => fakeResponse({ body: { user: { username: 'patrick' } } }));
  const intro = await vercel.introspect('tok', { fetchImpl });
  assert.equal(intro.unresolved, false);

  const caps = vercel.toCapabilities(intro);
  assert.ok(caps.includes('read:secrets'));
  assert.ok(caps.includes('destroy:infra'));
  assert.equal(assessSeverity(caps), 'severe');
});

test('a limited Vercel token is unresolved rather than assumed either way', async () => {
  const fetchImpl = jsonFetch(async () => fakeResponse({ body: { user: { username: 'p', limited: true } } }));
  const intro = await vercel.introspect('tok', { fetchImpl });
  assert.equal(intro.unresolved, true);
  assert.deepEqual(vercel.toCapabilities(intro), []);
});

/* ---------------------------------------------------------------- cloudflare */

test('an active Cloudflare token is unresolved — verify returns status, never scopes', async () => {
  const fetchImpl = jsonFetch(async () =>
    fakeResponse({ body: { success: true, result: { id: 'abc123', status: 'active' } } }));

  const intro = await cloudflare.introspect(`${'a'.repeat(40)}`, { fetchImpl });
  assert.equal(intro.valid, true);
  assert.equal(intro.unresolved, true, 'Cloudflare cannot enumerate its own token scopes');
  assert.deepEqual(cloudflare.toCapabilities(intro), []);
});

test('an expired Cloudflare token is inactive', async () => {
  const fetchImpl = jsonFetch(async () =>
    fakeResponse({ body: { success: true, result: { id: 'abc', status: 'expired' } } }));
  const intro = await cloudflare.introspect(`${'a'.repeat(40)}`, { fetchImpl });
  assert.equal(intro.valid, false);
});

test('a Global API Key is never sent anywhere and is flagged loudly', async () => {
  const fetchImpl = recordingFetch(async () => { throw new Error('must not touch the network'); });
  const intro = await cloudflare.introspect('0'.repeat(37), { fetchImpl });

  assert.equal(fetchImpl.calls.length, 0, 'a global key must not be transmitted without an identity');
  assert.equal(intro.unresolved, true);
  assert.ok(intro.notes.some((n) => /unrestricted/i.test(n)));
  assert.ok(cloudflare.remediation(intro).some((r) => /scoped API token/i.test(r)));
});
