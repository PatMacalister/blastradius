import test from 'node:test';
import assert from 'node:assert/strict';
import { parseFeed, parseHtml, stripTags, RELEVANT, isRelevant, scanProvider } from '../../tools/changelog-scan.mjs';

const RSS = `<?xml version="1.0"?><rss><channel>
  <item><title>Fine-grained PAT permissions updated</title><link>https://example.com/1</link>
    <description>We have changed how scopes are returned.</description></item>
  <item><title>New dashboard colour scheme</title><link>https://example.com/2</link>
    <description>Purely cosmetic.</description></item>
</channel></rss>`;

const ATOM = `<feed><entry><title>Deprecating legacy tokens</title>
  <link href="https://example.com/3"/><summary>Sunset in 90 days.</summary></entry></feed>`;

test('RSS items are parsed into title and link', () => {
  const entries = parseFeed(RSS);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].title, 'Fine-grained PAT permissions updated');
  assert.equal(entries[0].link, 'https://example.com/1');
});

test('Atom entries with href links are parsed', () => {
  const entries = parseFeed(ATOM);
  assert.equal(entries[0].title, 'Deprecating legacy tokens');
  assert.equal(entries[0].link, 'https://example.com/3');
});

// The filter is the whole design: an unfiltered watcher gets ignored, and an ignored
// watcher is worse than none because it looks like coverage.
test('auth-relevant entries match the filter', () => {
  const entries = parseFeed(RSS);
  assert.ok(RELEVANT.test(`${entries[0].title} ${entries[0].body}`));
});

test('cosmetic entries do not match the filter', () => {
  const entries = parseFeed(RSS);
  assert.ok(!RELEVANT.test(`${entries[1].title} ${entries[1].body}`));
});

test('deprecation vocabulary matches', () => {
  assert.ok(RELEVANT.test('Sunset of the v1 permissions endpoint'));
  assert.ok(RELEVANT.test('Breaking change to IAM role parsing'));
  assert.ok(!RELEVANT.test('We redesigned our marketing site'));
});

test('HTML changelogs fall back to headings', () => {
  const entries = parseHtml('<h2>Token scopes changed</h2><p>body</p><h3>Unrelated</h3>');
  assert.equal(entries.length, 2);
  assert.equal(entries[0].title, 'Token scopes changed');
});

test('stripTags removes markup and scripts', () => {
  assert.equal(stripTags('<p>hello <b>world</b></p><script>evil()</script>'), 'hello world');
});

/* --------------------------------------------------------------- the filter */

// Stripe heads its changelog entries with version identifiers ("2026-06-24.dahlia"), so a
// heading-only parse saw 38 entries and matched none of them — watched in name only.
test('HTML entries carry the prose under the heading, not just the heading', () => {
  const entries = parseHtml('<h2>2026-06-24.dahlia</h2><p>Deprecates the legacy tokens endpoint.</p>');
  assert.equal(entries[0].title, '2026-06-24.dahlia');
  assert.match(entries[0].body, /Deprecates the legacy tokens endpoint/);
  assert.ok(isRelevant(entries[0]), 'the change is described in the body, so it must still match');
});

// The two body vocabularies exist because the two sources are not equally trustworthy.
test('an untrusted HTML body needs announcement vocabulary, not merely technical words', () => {
  const codeSample = { title: 'Elements', body: 'Pass your api key and set the permission scope on the request.' };
  const announcement = { title: 'Elements', body: 'This endpoint is deprecated and will be removed.' };

  assert.equal(isRelevant(codeSample), false, 'API-docs prose is full of these words');
  assert.equal(isRelevant(announcement), true);
});

test('a curated RSS description is trusted with the full vocabulary', () => {
  const entry = { title: 'Improvements to the CLI', body: 'Changes how an access token is scoped.' };

  assert.equal(isRelevant(entry), false, 'as untrusted HTML text this is not enough');
  assert.equal(isRelevant(entry, { trustedBody: true }), true, 'as an authored summary it is');
});

/* ------------------------------------------------------- coverage self-checks */

const fakeProvider = (changelog) => ({ id: 'fake', label: 'Fake', changelog });
const respondWith = (body) => async () => ({ ok: true, status: 200, text: async () => body });

// This is the bug the first live run exposed. railway.com/changelog returns HTTP 200 and
// parses to exactly one heading — its own tagline — so a zero-entry check called it healthy
// while it was watching nothing. Silence that reads as "no news" is the failure mode the
// whole mechanism exists to avoid.
test('a source that parses to almost nothing is an error, not silence', async () => {
  const result = await scanProvider(
    fakeProvider({ url: 'https://example.com/changelog', type: 'html' }),
    { fetchImpl: respondWith('<h1>Weekly product updates since 2021</h1>') },
  );
  assert.ok(result.error, 'a one-heading parse must not pass as healthy');
  assert.match(result.error, /NOT being watched/);
});

test('a source that parses properly is not flagged', async () => {
  const result = await scanProvider(
    fakeProvider({ url: 'https://example.com/changelog', type: 'html' }),
    { fetchImpl: respondWith('<h2>Token scopes changed</h2><h2>New region</h2><h2>Pricing update</h2>') },
  );
  assert.equal(result.error, null);
});

// A provider with no machine-readable changelog is a permanent gap. Failing on it weekly
// would train the operator to ignore the warnings, so it is declared once and reported
// separately — visible, but not noise.
test('an unwatchable provider is a declared blind spot, not a weekly failure', async () => {
  const result = await scanProvider(
    fakeProvider({ url: 'https://example.com', type: 'html', unwatchable: true, note: 'no feed exists' }),
    { fetchImpl: async () => { throw new Error('must not fetch an unwatchable source'); } },
  );
  assert.equal(result.unwatchable, true);
  assert.equal(result.error, 'no feed exists');
});
