/**
 * Report rendering — consequence language, never scope language.
 *
 * "This token can delete your production volume", not "this token has volumes:write".
 * If a report reads like a permissions dump, it has failed: the whole thesis is that
 * nobody in the reference incident's loop knew what the credential they picked up could do.
 *
 * Three rules enforced here:
 *   1. Raw secrets never appear — everything goes through fingerprint().
 *   2. `unresolved` never renders as safe. It renders louder than "low".
 *   3. Provider staleness is always shown, so a confident-looking finding carries its
 *      own "last verified" caveat.
 */

import { fingerprint, stripControl } from './redact.mjs';
import { describeCapabilities, severityRank } from './capabilities.mjs';
import { staleProviders } from '../providers/index.mjs';

const LABEL = {
  catastrophic: 'CATASTROPHIC',
  severe: 'SEVERE      ',
  high: 'HIGH        ',
  moderate: 'MODERATE    ',
  low: 'LOW         ',
  none: 'INACTIVE    ',
  unknown: 'UNKNOWN     ',
};

const COLOUR = {
  catastrophic: '\x1b[41m\x1b[97m',
  severe: '\x1b[31m',
  high: '\x1b[33m',
  moderate: '\x1b[36m',
  low: '\x1b[32m',
  none: '\x1b[2m',
  unknown: '\x1b[35m',
};
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';

const tty = () => process.stdout.isTTY;
const colour = (sev, text) => (tty() ? `${COLOUR[sev] ?? ''}${text}${RESET}` : text);
const dim = (text) => (tty() ? `${DIM}${text}${RESET}` : text);

/** Worst first, and unknown sorts high — an unverifiable credential deserves attention. */
export function sortFindings(findings) {
  const rank = (f) => (f.severity === 'unknown' ? severityRank('high') + 0.5 : severityRank(f.severity));
  return [...findings].sort((a, b) => rank(b) - rank(a));
}

export function summarise(findings) {
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const worst = sortFindings(findings)[0]?.severity ?? 'none';
  return { total: findings.length, counts, worst };
}

/**
 * The unrecognised-credential section.
 *
 * These are high-entropy values sitting under secret-shaped key names that match no
 * provider BlastRadius ships. We cannot say what they do — there is nobody to ask — so they
 * are reported as visible ignorance and kept strictly out of the severity summary. Folding
 * a guess into the worst-case line would corrupt the one number a user actually reads.
 */
export function renderUnrecognised(unrecognised) {
  if (!unrecognised || unrecognised.length === 0) return [];
  const lines = [''];
  lines.push(`Possible unrecognised credentials (${unrecognised.length})`);
  lines.push(dim('High-entropy values under secret-shaped names, matching no provider BlastRadius knows.'));
  lines.push(dim('It cannot say what these reach — they are listed so their absence from the report above is not mistaken for safety.'));
  for (const u of unrecognised) {
    lines.push(`  ${colour('unknown', 'UNRECOGNISED')} ${u.key} ${dim(`${fingerprint(u.secret)} entropy ${u.entropy}`)}`);
    for (const src of u.sources) {
      const where = src.kind === 'env' ? `env ${src.path}`
        : src.kind === 'agent-config' ? `agent config ${src.path}`
        : `${src.path}${src.line ? `:${src.line}` : ''}`;
      lines.push(`               ${dim(`found in ${where}`)}`);
    }
  }
  return lines;
}

/**
 * The standing caveat, printed on every run.
 *
 * Deliberately specific rather than generic legal boilerplate. A paragraph of "no warranty of
 * any kind, express or implied" is skimmed by everyone and teaches nothing; naming the three
 * things this tool genuinely cannot see tells a reader where their remaining risk actually
 * lives. That is also the only version consistent with the rest of the output — a tool whose
 * whole claim is that it says "I could not determine this" out loud cannot then hide its
 * limits behind legalese.
 *
 * The second item is not hypothetical. A shapeless token stored under an unconventional
 * variable name is invisible here, and that is currently true of two live credentials in this
 * project's own contract-test config.
 *
 * It prints after the findings, so it never competes with them for attention.
 */
export const LIMITATIONS = [
  'Only the providers BlastRadius ships are recognised — run --providers to see them, and when each was last verified.',
  'Detection depends on a credential\'s format and the name it is stored under. Tokens with no distinctive shape are matched on the surrounding variable name, so one held under an unusual name is missed entirely.',
  'What a credential can actually reach depends on the account, environment and infrastructure behind it — none of which is visible from here.',
];

export const DISCLAIMER =
  'A diagnostic aid, not a security audit, and provided without warranty. Nothing here is a clean bill of health: risk may remain in setups, environments and infrastructure this tool cannot inspect.';

export function renderLimitations() {
  return [
    '',
    dim('What this report does not cover:'),
    ...LIMITATIONS.map((l) => dim(`  · ${l}`)),
    dim(DISCLAIMER),
  ];
}

export function renderText(findings, { resolved = true, unrecognised = [] } = {}) {
  const lines = [];
  const sorted = sortFindings(findings);

  if (sorted.length === 0) {
    lines.push('No credentials matched a known provider pattern.');
    lines.push(dim('This is not a clean bill of health — BlastRadius only knows the providers it ships.'));
    lines.push(...renderUnrecognised(unrecognised));
    lines.push(...renderLimitations());
    return lines.join('\n');
  }

  for (const f of sorted) {
    const sev = f.severity ?? 'unknown';
    const label = LABEL[sev] ?? LABEL.unknown;
    const who = f.provider?.label ?? f.providerId;
    lines.push(`${colour(sev, label)} ${who} ${dim(fingerprint(f.secret))}`);

    if (f.introspection?.identity) {
      lines.push(`             ${dim(stripControl(f.introspection.identity))}`);
    }

    if (!resolved) {
      lines.push(`             ${dim('not resolved — run with --resolve to determine what this can do')}`);
    } else if (f.inactive) {
      lines.push(`             ${dim('credential is not active')}`);
    } else if (f.unresolved) {
      // Deliberately worded so this cannot be skim-read as "nothing found".
      lines.push('             privileges COULD NOT be determined — do not read this as safe');
      for (const note of f.introspection?.notes ?? []) lines.push(`             ${dim(stripControl(note))}`);
      if (f.error) lines.push(`             ${dim(stripControl(f.error))}`);
    } else {
      for (const { describe } of describeCapabilities(f.capabilities)) {
        lines.push(`             can ${describe}`);
      }
      if (sev === 'catastrophic') {
        lines.push(colour('catastrophic', '             ↳ can destroy data AND its backups — unrecoverable'));
      }
    }

    for (const src of f.sources) {
      const where = src.kind === 'env' ? `env ${src.path}`
        : src.kind === 'agent-config' ? `agent config ${src.path}`
        : `${src.path}:${src.line}`;
      lines.push(`             ${dim(`found in ${where}`)}`);
    }

    for (const fix of f.remediation ?? []) lines.push(`             ${dim(`fix: ${stripControl(fix)}`)}`);

    if (f.staleness?.stale) {
      lines.push(`             ${dim(`provider module last verified ${f.staleness.age} days ago — treat with caution`)}`);
    }
    lines.push('');
  }

  const { total, worst } = summarise(sorted);
  const count = `${total} credential${total === 1 ? '' : 's'} reachable`;
  // In discover-only mode nothing has been assessed, so there is no worst case to state.
  // Printing "worst case: NONE" here would be the exact failure this tool complains about.
  lines.push(
    resolved
      ? `${count}, worst case: ${colour(worst, worst.toUpperCase())}`
      : `${count} — severity not assessed`,
  );

  const stale = staleProviders();
  if (stale.length > 0) {
    lines.push(dim(`Stale provider modules: ${stale.map((s) => `${s.id} (${s.age}d)`).join(', ')}`));
  }
  lines.push(...renderUnrecognised(unrecognised));
  lines.push(...renderLimitations());
  return lines.join('\n');
}

export function renderJson(findings, { resolved = true, unrecognised = [] } = {}) {
  return JSON.stringify({
    version: 1,
    resolved,
    summary: summarise(findings),
    // Carried in the machine-readable output too. A CI consumer that surfaces only the
    // severity would otherwise present this as a verdict, which is the reading the text
    // report works hardest to prevent.
    limitations: LIMITATIONS,
    disclaimer: DISCLAIMER,
    unrecognised: unrecognised.map((u) => ({
      key: u.key,
      fingerprint: fingerprint(u.secret),
      entropy: u.entropy,
      sources: u.sources,
    })),
    findings: sortFindings(findings).map((f) => ({
      provider: f.provider?.id ?? f.providerId,
      fingerprint: fingerprint(f.secret),
      severity: f.severity,
      unresolved: Boolean(f.unresolved),
      inactive: Boolean(f.inactive),
      identity: stripControl(f.introspection?.identity ?? null),
      capabilities: f.capabilities ?? [],
      consequences: describeCapabilities(f.capabilities ?? []).map((c) => c.describe),
      remediation: (f.remediation ?? []).map(stripControl),
      sources: f.sources,
      providerLastVerified: f.provider?.lastVerified ?? null,
      error: stripControl(f.error ?? null),
    })),
  }, null, 2);
}

/**
 * Exit codes so this is usable as a CI gate.
 *
 * `unknown` fails by default. That will annoy people, and it is still right: the whole
 * doctrine here is that an unverifiable credential is not a safe one, and a gate that
 * passes on "we couldn't tell" teaches users to trust a green tick that means nothing.
 * `--allow-unknown` exists for teams who consciously accept that trade.
 *
 * Unrecognised credentials do NOT fail the gate by default. That looks inconsistent with the
 * paragraph above, and the reasoning is that these two uncertainties are different in kind: an
 * `unknown` finding is a credential we positively identified and failed to assess, whereas an
 * unrecognised one is a guess about whether it is a credential at all. Failing on the latter
 * makes the gate fire on config noise, and a gate that cries wolf gets disabled entirely —
 * which would take the trustworthy half of the signal down with it. `--fail-on-unrecognised`
 * is there for anyone who wants the stricter posture.
 */
export function exitCodeFor(findings, { threshold = 'severe', allowUnknown = false, unrecognised = [], failOnUnrecognised = false } = {}) {
  if (failOnUnrecognised && unrecognised.length > 0) return 1;
  const { worst } = summarise(findings);
  if (worst === 'unknown') return allowUnknown ? 0 : 1;
  return severityRank(worst) >= severityRank(threshold) ? 1 : 0;
}
