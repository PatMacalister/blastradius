import test from 'node:test';
import assert from 'node:assert/strict';
import { renderText, renderJson, exitCodeFor, sortFindings, summarise } from '../../src/core/report.mjs';
import { FAKE } from '../fixtures.mjs';

const finding = (over = {}) => ({
  secret: FAKE.githubClassic,
  providerId: 'github',
  provider: { id: 'github', label: 'GitHub', lastVerified: '2026-07-27' },
  staleness: { age: 0, stale: false },
  capabilities: ['destroy:data', 'destroy:backups'],
  severity: 'catastrophic',
  unresolved: false,
  introspection: { identity: 'user patrick', notes: [] },
  remediation: [],
  sources: [{ kind: 'file', path: '.env', line: 2 }],
  ...over,
});

test('no raw secret ever reaches text output', () => {
  const out = renderText([finding()]);
  assert.ok(!out.includes(FAKE.githubClassic));
  assert.ok(out.includes('ghp_'));
});

test('no raw secret ever reaches JSON output', () => {
  const out = renderJson([finding()]);
  assert.ok(!out.includes(FAKE.githubClassic));
  assert.equal(JSON.parse(out).findings[0].severity, 'catastrophic');
});

test('output speaks in consequences, not scopes', () => {
  const out = renderText([finding()]);
  assert.ok(out.includes('can delete databases, volumes, or bucket contents'));
  assert.ok(!out.includes('volumes:write'));
});

test('the catastrophic pairing is called out explicitly', () => {
  const out = renderText([finding()]);
  assert.ok(out.includes('unrecoverable'));
});

// The doctrine: an unverifiable credential must never skim-read as a clean result.
test('unresolved findings are not rendered as safe', () => {
  const out = renderText([finding({ unresolved: true, severity: 'unknown', capabilities: [] })]);
  assert.ok(out.includes('COULD NOT be determined'));
  assert.ok(out.includes('do not read this as safe'));
});

test('an empty result is not sold as a clean bill of health', () => {
  const out = renderText([]);
  assert.ok(out.includes('not a clean bill of health'));
});

test('stale provider modules carry a caveat into the report', () => {
  const out = renderText([finding({ staleness: { age: 200, stale: true } })]);
  assert.ok(out.includes('200 days ago'));
});

test('unresolved sorts above merely moderate findings', () => {
  const sorted = sortFindings([
    finding({ severity: 'moderate', capabilities: ['write:data'] }),
    finding({ severity: 'unknown', unresolved: true, capabilities: [] }),
  ]);
  assert.equal(sorted[0].severity, 'unknown');
});

test('summarise reports the worst case', () => {
  assert.equal(summarise([finding(), finding({ severity: 'low' })]).worst, 'catastrophic');
});

test('CI gate fails at or above the threshold', () => {
  assert.equal(exitCodeFor([finding()], { threshold: 'severe' }), 1);
  assert.equal(exitCodeFor([finding({ severity: 'low', capabilities: ['read:metadata'] })], { threshold: 'severe' }), 0);
});

test('CI gate fails on unknown by default, and can be opted out', () => {
  const unknown = [finding({ severity: 'unknown', unresolved: true, capabilities: [] })];
  assert.equal(exitCodeFor(unknown), 1);
  assert.equal(exitCodeFor(unknown, { allowUnknown: true }), 0);
});
