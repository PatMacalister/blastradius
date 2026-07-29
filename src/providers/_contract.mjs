/**
 * The provider-module contract.
 *
 * This file is load-bearing for the open-source plan (see DRIFT-AND-OSS-PLAN.md).
 * Community PRs adding a provider are only safe to merge mechanically if the shape of a
 * module is machine-checkable and its scope mapping is proven against the live API by a
 * contract test. This validator is the first half of that; test/contract/ is the second.
 *
 * A provider module must export:
 *
 *   id            string   — stable slug, matches the filename
 *   label         string   — human name for reports
 *   lastVerified  string   — YYYY-MM-DD, stamped by the last passing contract test
 *   apiHosts      string[] — every host this module may send the credential to
 *   changelog     object   — { url, type: 'rss' | 'html' } for the drift scanner
 *   patterns      array    — [{ name, regex, confidence }] for candidate detection.
 *                            If the regex declares a capture group, group 1 is the
 *                            credential and the rest of the match is context. Providers
 *                            whose tokens have no distinctive prefix (Railway issues bare
 *                            UUIDs; Vercel 24 alphanumerics) MUST use this form and anchor
 *                            on the variable name — matching those shapes bare would bury
 *                            every real finding under lockfile noise.
 *   introspect    async fn — (secret, { fetchImpl }) => Introspection
 *   toCapabilities   fn    — (Introspection) => string[] of capability verbs
 *   remediation      fn    — (Introspection) => string[] of least-privilege suggestions
 *
 * Introspection = { valid, identity, scopes, notes, unresolved }
 *   unresolved: true means "this credential is live but its privileges could not be
 *   determined". That must never be reported as harmless — see report.mjs.
 */

import { isKnownCapability } from '../core/capabilities.mjs';

/** Modules older than this are reported with a staleness warning rather than silent confidence. */
export const STALENESS_WARN_DAYS = 90;

const REQUIRED_FUNCTIONS = ['introspect', 'toCapabilities', 'remediation'];

/**
 * Catastrophic backtracking: an unbounded quantifier applied to a group that itself contains
 * one. `/^(a+)+$/` is the textbook case, and it passed every other check here — one match
 * against 41 characters took 91 seconds, measured. Discovery runs every pattern over every
 * line of every file, so a single such regex in a contributed module hangs the whole tool on
 * input an attacker chooses. Denial of service is a quiet failure for a security scanner: it
 * does not report the wrong answer, it reports nothing, and a run that never finishes reads
 * as a run that found nothing.
 *
 * Deliberately a source-level heuristic rather than a real analysis. JavaScript regexes are
 * synchronous and cannot be interrupted, so there is no runtime timeout to fall back on, and
 * a zero-dependency project is not going to ship a regex engine. It catches the shapes that
 * actually appear; it is not a proof of safety, which is why apiHosts and pattern review stay
 * human jobs (see CONTRIBUTING.md).
 */
function hasNestedQuantifier(source) {
  // A quantified group — ")+", ")*", "){n,}" — whose body carries an unbounded quantifier.
  const quantifiedGroup = /\(([^()]*)\)\s*(?:[+*]|\{\d+,\})/g;
  for (const [, body] of source.matchAll(quantifiedGroup)) {
    if (/[+*]|\{\d+,\}/.test(body)) return true;
  }
  return false;
}

export function validateProvider(mod) {
  const errors = [];
  const need = (cond, msg) => { if (!cond) errors.push(msg); };

  need(typeof mod.id === 'string' && /^[a-z0-9-]+$/.test(mod.id), 'id must be a lowercase slug');
  need(typeof mod.label === 'string' && mod.label.length > 0, 'label must be a non-empty string');
  need(/^\d{4}-\d{2}-\d{2}$/.test(mod.lastVerified ?? ''), 'lastVerified must be YYYY-MM-DD');

  // The egress allowlist is what makes a community-contributed module safe to merge:
  // resolve.mjs refuses to send a credential to any host not declared here, so a hostile
  // or careless PR cannot exfiltrate what it discovers. Reviewing a provider then means
  // reading one array, not auditing every fetch call in the file.
  need(
    Array.isArray(mod.apiHosts) && mod.apiHosts.length > 0,
    'apiHosts must be a non-empty array of hostnames',
  );
  for (const [i, host] of (mod.apiHosts ?? []).entries()) {
    need(
      typeof host === 'string' && /^[a-z0-9.-]+$/.test(host) && !host.includes('*'),
      `apiHosts[${i}] must be a literal hostname (no wildcards)`,
    );
  }

  need(mod.changelog && typeof mod.changelog.url === 'string', 'changelog.url is required');
  need(['rss', 'html'].includes(mod.changelog?.type), "changelog.type must be 'rss' or 'html'");
  // A provider may declare that no machine-readable changelog exists, but it must say why —
  // an undocumented blind spot is indistinguishable from an oversight six months later.
  if (mod.changelog?.unwatchable) {
    need(
      typeof mod.changelog.note === 'string' && mod.changelog.note.length > 0,
      'changelog.unwatchable requires an explanatory changelog.note',
    );
  }

  need(Array.isArray(mod.patterns) && mod.patterns.length > 0, 'patterns must be a non-empty array');
  for (const [i, p] of (mod.patterns ?? []).entries()) {
    need(typeof p?.name === 'string', `patterns[${i}].name must be a string`);
    need(p?.regex instanceof RegExp, `patterns[${i}].regex must be a RegExp`);
    if (p?.regex instanceof RegExp) {
      need(
        !hasNestedQuantifier(p.regex.source),
        `patterns[${i}].regex nests an unbounded quantifier inside a quantified group, ` +
        'which backtracks catastrophically and would hang discovery — rewrite it with a bounded length',
      );
    }
    need(
      typeof p?.confidence === 'number' && p.confidence > 0 && p.confidence <= 1,
      `patterns[${i}].confidence must be in (0, 1]`,
    );
  }

  for (const fn of REQUIRED_FUNCTIONS) {
    need(typeof mod[fn] === 'function', `${fn} must be a function`);
  }

  // Optional. Where a provider discloses which scopes an endpoint accepts, these verify that
  // a scope name is still live vocabulary using a credential that does not hold it — the only
  // live coverage possible for scopes a test credential is forbidden to carry.
  //
  // The URL is constrained to apiHosts like any other request. A probe is still a request
  // carrying the test credential, so it must not become a second, unreviewed egress path.
  if (mod.vocabularyProbes !== undefined) {
    need(Array.isArray(mod.vocabularyProbes), 'vocabularyProbes must be an array when present');
    for (const [i, probe] of (mod.vocabularyProbes ?? []).entries()) {
      need(typeof probe?.scope === 'string' && probe.scope.length > 0,
        `vocabularyProbes[${i}].scope must be a non-empty string`);
      let host = null;
      try { host = new URL(probe?.url).hostname; } catch { /* reported below */ }
      need(host !== null, `vocabularyProbes[${i}].url must be an absolute URL`);
      need(host === null || (mod.apiHosts ?? []).includes(host),
        `vocabularyProbes[${i}].url host "${host}" is not in apiHosts`);
    }
  }

  return { ok: errors.length === 0, errors };
}

/**
 * Capability verbs are a closed vocabulary. A typo'd verb would silently drop out of
 * severity assessment and under-report risk, which is the failure direction that matters.
 */
export function validateCapabilityOutput(providerId, capabilities) {
  const errors = [];
  if (!Array.isArray(capabilities)) {
    return { ok: false, errors: [`${providerId}.toCapabilities must return an array`] };
  }
  for (const cap of capabilities) {
    if (!isKnownCapability(cap)) {
      errors.push(`${providerId} returned unknown capability "${cap}" — see core/capabilities.mjs`);
    }
  }
  return { ok: errors.length === 0, errors };
}

export function daysSince(isoDate, now = new Date()) {
  const then = new Date(`${isoDate}T00:00:00Z`);
  return Math.floor((now - then) / 86_400_000);
}

export function stalenessOf(mod, now = new Date()) {
  const age = daysSince(mod.lastVerified, now);
  return { age, stale: age > STALENESS_WARN_DAYS };
}
