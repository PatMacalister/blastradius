/**
 * The provider-agnostic capability taxonomy — the heart of the tool.
 *
 * Conventional scanners stop at "this token is live". BlastRadius maps each provider's
 * own scope vocabulary onto these verbs, so a Railway `volumes:write` and an AWS
 * `s3:DeleteBucket` and a Supabase service_role key can be ranked against each other
 * in consequence terms rather than provider terms.
 *
 * Adding a verb here is a breaking change for every provider module. Think hard first.
 */

export const CAPABILITIES = {
  'destroy:backups': {
    severity: 'severe',
    describe: 'delete backups or snapshots',
  },
  'destroy:data': {
    severity: 'severe',
    describe: 'delete databases, volumes, or bucket contents',
  },
  'destroy:infra': {
    severity: 'severe',
    describe: 'delete projects, services, or environments',
  },
  'move:money': {
    severity: 'severe',
    describe: 'move real money — charges, refunds, or transfers',
  },
  'admin:access': {
    severity: 'severe',
    describe: 'manage members or issue further credentials (privilege escalation)',
  },
  'read:secrets': {
    severity: 'high',
    describe: 'read environment variables or stored secrets',
  },
  'read:data': {
    severity: 'high',
    describe: 'read customer or application data',
  },
  'write:data': {
    severity: 'moderate',
    describe: 'modify application data',
  },
  'deploy': {
    severity: 'moderate',
    describe: 'trigger deployments or run code',
  },
  'read:metadata': {
    severity: 'low',
    describe: 'read non-sensitive metadata',
  },
};

export const SEVERITY_ORDER = ['none', 'low', 'moderate', 'high', 'severe', 'catastrophic'];

export function severityRank(severity) {
  const i = SEVERITY_ORDER.indexOf(severity);
  return i === -1 ? 0 : i;
}

export function maxSeverity(a, b) {
  return severityRank(a) >= severityRank(b) ? a : b;
}

/**
 * Reduce a capability set to a single blast-radius severity.
 *
 * The amplifier is the entire lesson of the reference incident (see INCIDENTS.md):
 * destroying data is recoverable, and destroying backups is survivable, but one credential
 * holding *both* turns an incident into an extinction event. Ranking those two the same as
 * any other "severe" finding is precisely the mistake that turned nine seconds of deletion
 * into a thirty-hour recovery.
 */
export function assessSeverity(capabilities) {
  const caps = new Set(capabilities);
  if (caps.size === 0) return 'none';

  if (caps.has('destroy:data') && caps.has('destroy:backups')) {
    return 'catastrophic';
  }

  let worst = 'none';
  for (const cap of caps) {
    const known = CAPABILITIES[cap];
    if (known) worst = maxSeverity(worst, known.severity);
  }
  return worst;
}

/** Human-readable consequence lines, worst first. Consequence language, never scope language. */
export function describeCapabilities(capabilities) {
  return [...new Set(capabilities)]
    .filter((cap) => CAPABILITIES[cap])
    .sort((a, b) => severityRank(CAPABILITIES[b].severity) - severityRank(CAPABILITIES[a].severity))
    .map((cap) => ({ capability: cap, ...CAPABILITIES[cap] }));
}

export function isKnownCapability(cap) {
  return Object.hasOwn(CAPABILITIES, cap);
}
