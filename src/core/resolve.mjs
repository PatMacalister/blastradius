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

/**
 * A fetch that refuses to talk to anyone the provider did not declare. This is the
 * enforcement point that makes the open-source contribution model safe — a provider
 * module physically cannot POST a discovered credential to an attacker's collector.
 */
export function guardedFetch(allowedHosts, { fetchImpl = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const allowed = new Set(allowedHosts);
  return async (url, options = {}) => {
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
    const signal = AbortSignal.timeout(timeoutMs);
    return fetchImpl(url, { ...options, signal });
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
