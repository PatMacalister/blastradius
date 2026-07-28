import test from 'node:test';
import assert from 'node:assert/strict';
import { guardedFetch, resolveCandidate } from '../../src/core/resolve.mjs';
import { FAKE, fakeResponse, recordingFetch } from '../fixtures.mjs';

const candidate = (secret, providerId) => ({
  secret,
  providerId,
  pattern: 'test',
  confidence: 0.99,
  sources: [{ kind: 'file', path: 'test.env', line: 1 }],
});

test('guardedFetch permits a declared host', async () => {
  const impl = recordingFetch(async () => fakeResponse({}));
  const guarded = guardedFetch(['api.github.com'], { fetchImpl: impl });
  await guarded('https://api.github.com/user');
  assert.equal(impl.calls.length, 1);
});

// The single most important safety property: a provider module cannot ship a discovered
// credential anywhere it did not declare, so a hostile PR cannot exfiltrate.
test('guardedFetch blocks an undeclared host', async () => {
  const impl = recordingFetch(async () => fakeResponse({}));
  const guarded = guardedFetch(['api.github.com'], { fetchImpl: impl });
  await assert.rejects(
    () => guarded('https://collector.evil.example/steal'),
    /blocked credential egress/,
  );
  assert.equal(impl.calls.length, 0, 'blocked request must not reach fetch');
});

test('guardedFetch blocks plaintext HTTP', async () => {
  const impl = recordingFetch(async () => fakeResponse({}));
  const guarded = guardedFetch(['api.github.com'], { fetchImpl: impl });
  await assert.rejects(() => guarded('http://api.github.com/user'), /non-HTTPS/);
  assert.equal(impl.calls.length, 0);
});

test('a classic PAT resolves to consequence verbs', async () => {
  const impl = async () => fakeResponse({
    headers: { 'x-oauth-scopes': 'repo, delete_repo' },
    body: { login: 'patrick' },
  });
  const finding = await resolveCandidate(candidate(FAKE.githubClassic, 'github'), { fetchImpl: impl });
  assert.equal(finding.unresolved, false);
  assert.equal(finding.severity, 'severe');
  assert.ok(finding.capabilities.includes('destroy:infra'));
  assert.equal(finding.introspection.identity, 'user patrick');
});

// Absent scope header must not become "no capabilities", which would render as harmless.
test('a fine-grained PAT is unresolved, never harmless', async () => {
  const impl = async () => fakeResponse({ body: { login: 'patrick' } });
  const finding = await resolveCandidate(candidate(FAKE.githubFineGrained, 'github'), { fetchImpl: impl });
  assert.equal(finding.unresolved, true);
  assert.equal(finding.severity, 'unknown');
  assert.notEqual(finding.severity, 'none');
});

test('a rejected credential is reported inactive', async () => {
  const impl = async () => fakeResponse({ status: 401 });
  const finding = await resolveCandidate(candidate(FAKE.githubClassic, 'github'), { fetchImpl: impl });
  assert.equal(finding.inactive, true);
  assert.equal(finding.severity, 'none');
});

test('a network failure degrades to unknown, not to safe', async () => {
  const impl = async () => { throw new Error('ECONNRESET'); };
  const finding = await resolveCandidate(candidate(FAKE.githubClassic, 'github'), { fetchImpl: impl });
  assert.equal(finding.unresolved, true);
  assert.equal(finding.severity, 'unknown');
});

test('an error message carrying the credential is scrubbed', async () => {
  const impl = async () => { throw new Error(`bad token ${FAKE.githubClassic}`); };
  const finding = await resolveCandidate(candidate(FAKE.githubClassic, 'github'), { fetchImpl: impl });
  assert.ok(!finding.error.includes(FAKE.githubClassic));
});

test('a live unrestricted Stripe key can move money', async () => {
  const impl = async () => fakeResponse({ body: { id: 'acct_123' } });
  const finding = await resolveCandidate(candidate(FAKE.stripeLive, 'stripe'), { fetchImpl: impl });
  assert.ok(finding.capabilities.includes('move:money'));
  assert.equal(finding.severity, 'severe');
  assert.ok(finding.remediation.length > 0);
});

test('a test-mode Stripe key cannot move money', async () => {
  const impl = async () => fakeResponse({ body: { id: 'acct_123' } });
  const finding = await resolveCandidate(candidate(FAKE.stripeTest, 'stripe'), { fetchImpl: impl });
  assert.ok(!finding.capabilities.includes('move:money'));
});

// A test key reaches fabricated objects only. Rating it SEVERE — as it was, via
// admin:access — is the false positive that gets the whole scanner muted.
test('a test-mode Stripe key is low, not severe', async () => {
  const impl = async () => fakeResponse({ body: { id: 'acct_123' } });
  const finding = await resolveCandidate(candidate(FAKE.stripeTest, 'stripe'), { fetchImpl: impl });

  assert.equal(finding.severity, 'low');
  assert.deepEqual(finding.capabilities, ['read:metadata']);
  for (const cap of ['read:data', 'write:data', 'admin:access']) {
    assert.ok(!finding.capabilities.includes(cap), `test mode must not claim ${cap}`);
  }
  // The live key must be unaffected — that is the finding this tool exists to make.
  const live = await resolveCandidate(candidate(FAKE.stripeLive, 'stripe'), { fetchImpl: impl });
  assert.equal(live.severity, 'severe');
  assert.ok(live.capabilities.includes('admin:access'));
});

test('a restricted Stripe key is unresolved rather than guessed', async () => {
  const impl = async () => fakeResponse({ body: { id: 'acct_123' } });
  const finding = await resolveCandidate(candidate(FAKE.stripeRestricted, 'stripe'), { fetchImpl: impl });
  assert.equal(finding.unresolved, true);
  assert.equal(finding.severity, 'unknown');
});

// Attack surface, not hygiene: CONTRIBUTING.md tells contributors a module "physically cannot
// exfiltrate what it discovers". With redirect:'follow' that was false — the allowlist was
// checked once and fetch walked off it. These pin the promise.
test('a redirect off the allowlist is blocked, not followed', async () => {
  const impl = async (url) => (url.includes('/start')
    ? { status: 302, headers: { get: (h) => (h === 'location' ? 'https://evil.test/collect' : null) } }
    : fakeResponse({ body: { leaked: true } }));

  const guarded = guardedFetch(['api.good.test'], { fetchImpl: impl });
  await assert.rejects(
    () => guarded('https://api.good.test/start'),
    /undeclared host "evil.test"/,
    'the second hop must be checked, not just the first',
  );
});

test('a redirect that stays on an allowed host is followed', async () => {
  const seen = [];
  const impl = async (url) => {
    seen.push(url);
    return url.includes('/start')
      ? { status: 307, headers: { get: (h) => (h === 'location' ? '/moved' : null) } }
      : fakeResponse({ body: { ok: true } });
  };

  const guarded = guardedFetch(['api.good.test'], { fetchImpl: impl });
  const res = await guarded('https://api.good.test/start');
  assert.equal(res.status, 200);
  assert.equal(seen.length, 2, 'relative Location should resolve and be followed');
  assert.ok(seen[1].endsWith('/moved'));
});

test('a redirect loop terminates instead of hanging', async () => {
  const impl = async () => ({
    status: 302,
    headers: { get: (h) => (h === 'location' ? 'https://api.good.test/again' : null) },
  });
  const guarded = guardedFetch(['api.good.test'], { fetchImpl: impl });
  await assert.rejects(() => guarded('https://api.good.test/start'), /too many redirects/);
});
