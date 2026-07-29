import test from 'node:test';
import assert from 'node:assert/strict';
import {
  renderText, renderJson, exitCodeFor, sortFindings, summarise, LIMITATIONS, DISCLAIMER,
} from '../../src/core/report.mjs';
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

// The disclaimer is the one piece a future edit is most likely to drop as clutter, and it is
// the difference between a report and a verdict. It must survive the empty case especially:
// "no findings" is exactly where a reader is most inclined to hear "you are safe".
test('every report states what it does not cover', () => {
  const withFindings = renderText([finding()], { resolved: true });
  const empty = renderText([], { resolved: true });

  for (const [name, out] of [['with findings', withFindings], ['empty', empty]]) {
    assert.ok(out.includes('What this report does not cover'), `${name}: heading missing`);
    for (const limit of LIMITATIONS) {
      assert.ok(out.includes(limit), `${name}: limitation dropped`);
    }
    assert.ok(out.includes(DISCLAIMER), `${name}: disclaimer dropped`);
  }
});

// A CI consumer reading only `severity` would present this as a verdict. Both formats carry
// the caveat, from the same constants, so they cannot drift apart.
test('the machine-readable report carries the same caveat', () => {
  const parsed = JSON.parse(renderJson([finding()], { resolved: true }));
  assert.deepEqual(parsed.limitations, LIMITATIONS);
  assert.equal(parsed.disclaimer, DISCLAIMER);
});

// The one output that must never lie was forgeable by the code it reports on: identity,
// notes and remediation are provider-written and printed verbatim, so `\x1b[2K\r` let a
// module erase its own CATASTROPHIC line and redraw it as something calmer.
test('a provider cannot forge the report with control characters', () => {
  const hostile = finding({
    severity: 'catastrophic',
    unresolved: true,
    introspection: {
      identity: 'evil\x1b[2K\rLOW  looks fine',
      notes: ['note\x1b[31m\x1b[2Kerased'],
    },
    remediation: ['fix\rspoofed'],
    error: 'err\x1b[1;32mgreen',
  });

  const out = renderText([hostile], { resolved: true });
  assert.ok(!/\x1b\[2K/.test(out), 'erase-line sequence must not survive');
  assert.ok(!out.includes('\r'), 'carriage return must not survive');
  assert.ok(out.includes('LOW  looks fine'), 'text is kept — only the control chars are stripped');
  assert.ok(out.includes('CATASTROPHIC'), 'the real verdict still stands');

  const parsed = JSON.parse(renderJson([hostile], { resolved: true }));
  assert.ok(!/\x1b/.test(JSON.stringify(parsed)), 'machine output must be clean too');
});

// The CI gate is the whole agent-hook contract, and exit 2 was unreachable: an unscannable
// path reported "nothing found" and exited 0, so a mistyped path or a checkout that never
// landed produced a green tick over a scan that did not happen. That is the failure this
// tool tells other people not to accept.
test('exit codes are the documented contract', () => {
  const severe = finding({ severity: 'severe', capabilities: ['admin:access'] });
  const low = finding({ severity: 'low', capabilities: ['read:metadata'] });
  const unknown = finding({ severity: 'unknown', unresolved: true, capabilities: [] });

  assert.equal(exitCodeFor([], { threshold: 'severe' }), 0, 'clean is 0');
  assert.equal(exitCodeFor([severe], { threshold: 'severe' }), 1, 'at threshold is 1');
  assert.equal(exitCodeFor([severe], { threshold: 'catastrophic' }), 0, 'below threshold is 0');
  assert.equal(exitCodeFor([low], { threshold: 'severe' }), 0);
  assert.equal(exitCodeFor([unknown], { threshold: 'severe' }), 1, 'unknown fails by default');
  assert.equal(exitCodeFor([unknown], { threshold: 'severe', allowUnknown: true }), 0);
});

// The JSON schema version is the machine contract and moves independently of the package
// version. It was bumped to 2 when `summary.worst` stopped reporting "none" for a
// discover-only run — a change that breaks any consumer treating that as a clean result.
test('the JSON payload declares its schema version', () => {
  const resolved = JSON.parse(renderJson([finding()], { resolved: true }));
  assert.equal(resolved.version, 2);
  assert.equal(resolved.summary.assessed, true);
  assert.equal(resolved.summary.worst, 'catastrophic');

  // The reason for the bump: nothing has been assessed, so there is no worst case to report.
  const discovered = JSON.parse(renderJson([finding({ severity: undefined })], { resolved: false }));
  assert.equal(discovered.summary.worst, null, 'must not claim "none" over unassessed findings');
  assert.equal(discovered.summary.assessed, false);
  assert.deepEqual(discovered.summary.counts, { unassessed: 1 });
});
