/**
 * Pass 2 — privilege resolution.
 *
 * This is the only pass that puts a discovered credential on the network, and it is
 * opt-in for that reason (see cli.mjs `--resolve`). Silently authenticating with every
 * secret found on someone's laptop is exactly the surprising behaviour this tool exists
 * to complain about, and it can trip provider intrusion alerts.
 *
 * Invariant 2 from redact.mjs is enforced here mechanically: a provider module can only
 * reach the hosts it declared in `apiHosts`.
 */

import { providerById } from '../providers/index.mjs';
import { assessSeverity } from './capabilities.mjs';
import { validateCapabilityOutput, stalenessOf } from '../providers/_contract.mjs';
import { scrub } from './redact.mjs';

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

/**
 * A fetch that refuses to talk to anyone the provider did not declare. This is the
 * enforcement point that makes the open-source contribution model safe — a provider
 * module physically cannot POST a discovered credential to an attacker's collector.
 */
export function guardedFetch(allowedHosts, { fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const allowed = new Set(allowedHosts);

  const check = (url) => {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') {
      throw new Error(`blocked non-HTTPS introspection request to ${parsed.protocol}//${parsed.host}`);
    }
    if (!allowed.has(parsed.hostname)) {
      throw new Error(
        `blocked credential egress to undeclared host "${parsed.hostname}" — ` +
        `allowed: ${[...allowed].join(', ')}`,
      );
    }
    return parsed;
  };

  return async (url, options = {}) => {
    let current = check(url).href;

    // Redirects are followed by hand so that EVERY hop is checked, not just the first.
    //
    // With the default `redirect: 'follow'` the allowlist is decorative: a provider can point
    // at its own declared host, have that host answer 302, and the request lands anywhere —
    // verified, a guarded call to an allowlisted host completed at example.com. Anything the
    // module put in the URL travels with it, and on a same-origin hop so does the
    // Authorization header. That is precisely the exfiltration this guard exists to prevent,
    // and it is what makes a module from a stranger safe to merge.
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const res = await fetchImpl(current, {
        ...options,
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!REDIRECT_STATUS.has(res.status)) return res;

      const location = res.headers.get('location');
      // A redirect we cannot resolve is not silently treated as a successful response.
      if (!location) return res;

      // Relative Locations resolve against the current URL, so they stay on an allowed host;
      // absolute ones are re-checked and throw if they leave the allowlist.
      current = check(new URL(location, current).href).href;
    }

    throw new Error(`too many redirects (>${MAX_REDIRECTS}) during introspection`);
  };
}

/**
 * Resolve one candidate to a finding.
 *
 * Any failure path must produce `unresolved: true`, never an empty capability set that
 * would render as "harmless". Under-reporting is the failure direction that gets someone
 * hurt, so errors degrade to "unknown", not to "fine".
 */
export async function resolveCandidate(candidate, { fetchImpl = fetch, now = new Date() } = {}) {
  const provider = providerById(candidate.providerId);
  if (!provider) {
    return { ...candidate, provider: null, error: `unknown provider ${candidate.providerId}`, unresolved: true, capabilities: [], severity: 'unknown' };
  }

  const staleness = stalenessOf(provider, now);
  const base = {
    ...candidate,
    provider: { id: provider.id, label: provider.label, lastVerified: provider.lastVerified },
    staleness,
  };

  let introspection;
  try {
    introspection = await provider.introspect(candidate.secret, {
      fetchImpl: guardedFetch(provider.apiHosts, { fetchImpl }),
    });
  } catch (err) {
    return {
      ...base,
      introspection: null,
      capabilities: [],
      severity: 'unknown',
      unresolved: true,
      error: scrub(err?.message ?? String(err)),
    };
  }

  if (!introspection?.valid) {
    return { ...base, introspection, capabilities: [], severity: 'none', unresolved: false, inactive: true };
  }

  let capabilities = [];
  try {
    capabilities = provider.toCapabilities(introspection) ?? [];
  } catch (err) {
    return { ...base, introspection, capabilities: [], severity: 'unknown', unresolved: true, error: scrub(err?.message ?? String(err)) };
  }

  const check = validateCapabilityOutput(provider.id, capabilities);
  if (!check.ok) {
    // A module emitting a verb outside the taxonomy is a bug that would under-report.
    // Surface it rather than dropping the unknown verbs on the floor.
    return { ...base, introspection, capabilities: [], severity: 'unknown', unresolved: true, error: check.errors.join('; ') };
  }

  const unresolved = Boolean(introspection.unresolved);
  return {
    ...base,
    introspection,
    capabilities,
    severity: unresolved ? 'unknown' : assessSeverity(capabilities),
    unresolved,
    remediation: provider.remediation(introspection) ?? [],
  };
}

export async function resolveAll(candidates, opts = {}) {
  const out = [];
  // Sequential by design: parallel authentication bursts across a developer's accounts
  // look exactly like credential stuffing to provider fraud detection.
  for (const candidate of candidates) {
    out.push(await resolveCandidate(candidate, opts));
  }
  return out;
}
