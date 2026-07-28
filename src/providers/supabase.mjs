/**
 * Supabase — the provider where the key's *class* is the finding.
 *
 * A `service_role` key maps to a Postgres role carrying the BYPASSRLS attribute: anyone
 * holding it can read or write every row in the database regardless of what Row Level
 * Security says. The new-format `sb_secret_` keys are documented the same way. So unlike
 * every other provider here, the blast radius is knowable from the credential itself and
 * needs no network call at all — which is a genuinely better privacy property, since
 * nothing leaves the machine to determine it.
 *
 * **A deliberate limitation worth understanding.** Liveness of a project key cannot be
 * verified, because doing so would mean authenticating against `<project-ref>.supabase.co`
 * — a per-project hostname. The egress allowlist in _contract.mjs forbids wildcard hosts
 * precisely so that a provider module cannot be talked into sending a credential somewhere
 * unexpected, and that same rule blocks this. The security control wins; the module reports
 * capability without claiming liveness, and says so. A rotated key therefore still shows up,
 * which is the safe direction to be wrong in.
 *
 * Management API tokens (`sbp_`) are different: they authenticate against the fixed host
 * api.supabase.com, so those are verified for real.
 */

export const id = 'supabase';
export const label = 'Supabase';
export const lastVerified = '2026-07-28';
export const apiHosts = ['api.supabase.com'];

export const changelog = {
  url: 'https://supabase.com/changelog',
  type: 'html',
};

export const patterns = [
  // The prefix is the entire discriminator here, so the length floor is deliberately low.
  // A high minimum buys no precision on a string starting `sb_secret_` and only creates a
  // way to miss a real credential if Supabase ever shortens the random portion.
  { name: 'secret-key', regex: /\bsb_secret_[A-Za-z0-9_-]{12,}/, confidence: 0.99 },
  { name: 'publishable-key', regex: /\bsb_publishable_[A-Za-z0-9_-]{12,}/, confidence: 0.99 },
  { name: 'management-token', regex: /\bsbp_[a-f0-9]{40}\b/, confidence: 0.95 },
  // Legacy anon/service_role keys are plain JWTs, far too generic to match on shape. Require
  // the variable name as context; group 1 is the credential.
  //
  // These are on a clock. Projects created since November 2025 receive no legacy keys, and
  // Supabase has them scheduled for removal in late 2026 — after which this pattern and the
  // JWT branch of introspect() become dead code. Do not delete them early: the keys that
  // already exist in the wild are exactly the long-lived credentials sitting in old .env
  // files, which is the population this tool is for.
  {
    name: 'legacy-jwt-env',
    // The signature segment length is deliberately loose. Real Supabase JWTs carry a ~43
    // character HS256 signature, but the match is already anchored on the variable name, so
    // demanding a minimum here buys no precision and silently misses hand-trimmed keys.
    regex: /SUPABASE[A-Z_]*(?:KEY|SECRET|JWT)["']?\s*[:=]\s*["']?(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)/,
    confidence: 0.9,
  },
];

/** Decode a JWT payload without verifying its signature — we are reading claims, not trusting them. */
export function decodeJwtClaims(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export async function introspect(secret, { fetchImpl = fetch } = {}) {
  if (secret.startsWith('sbp_')) {
    const res = await fetchImpl('https://api.supabase.com/v1/projects', {
      headers: { authorization: `Bearer ${secret}`, 'user-agent': 'blastradius' },
    });
    if (res.status === 401 || res.status === 403) {
      return { valid: false, identity: null, scopes: [], notes: ['token rejected'], unresolved: false, keyClass: null };
    }
    if (!res.ok) {
      return {
        valid: true, identity: null, scopes: [],
        notes: [`introspection failed with HTTP ${res.status}`],
        unresolved: true, keyClass: 'management',
      };
    }
    const body = await res.json().catch(() => []);
    const count = Array.isArray(body) ? body.length : 0;
    return {
      valid: true,
      identity: `Supabase management token — ${count} project${count === 1 ? '' : 's'} reachable`,
      scopes: ['management'],
      notes: ['A management token administers every project in the account, including deleting them.'],
      unresolved: false,
      keyClass: 'management',
      projectCount: count,
    };
  }

  if (secret.startsWith('sb_secret_')) {
    return {
      valid: true,
      identity: 'Supabase secret key',
      scopes: ['secret'],
      notes: [
        'Secret keys bypass Row Level Security and have full access to project data.',
        'Liveness not checked: verifying it would mean authenticating against a per-project host, which the egress allowlist deliberately forbids.',
      ],
      unresolved: false,
      keyClass: 'secret',
    };
  }

  if (secret.startsWith('sb_publishable_')) {
    return {
      valid: true,
      identity: 'Supabase publishable key',
      scopes: ['publishable'],
      notes: ['Publishable keys are constrained by Row Level Security and are intended to be public.'],
      unresolved: false,
      keyClass: 'publishable',
    };
  }

  const claims = decodeJwtClaims(secret);

  // Not a Supabase prefix and not a decodable JWT: this is not a Supabase credential at all.
  // Reporting it as a live-but-unclassifiable one would put a phantom finding in the report.
  if (!claims) {
    return {
      valid: false, identity: null, scopes: [],
      notes: ['not a recognisable Supabase credential'],
      unresolved: false, keyClass: null,
    };
  }

  if (!claims.role) {
    return {
      valid: true, identity: null, scopes: [],
      notes: ['decodes as a JWT but carries no Supabase role claim — could not classify'],
      unresolved: true, keyClass: null,
    };
  }

  const expired = typeof claims.exp === 'number' && claims.exp * 1000 < Date.now();
  const project = claims.ref ? ` (project ${claims.ref})` : '';

  if (expired) {
    return {
      valid: false, identity: `Supabase ${claims.role} key${project}`, scopes: [claims.role],
      notes: ['key expired'], unresolved: false, keyClass: null,
    };
  }

  if (claims.role === 'service_role') {
    return {
      valid: true,
      identity: `Supabase service_role key${project}`,
      scopes: ['service_role'],
      notes: [
        'service_role maps to a Postgres role with BYPASSRLS — it reads and writes every row regardless of Row Level Security.',
        'Liveness not checked: that would require authenticating against a per-project host, which the egress allowlist forbids.',
      ],
      unresolved: false,
      keyClass: 'secret',
    };
  }

  if (claims.role === 'anon') {
    return {
      valid: true,
      identity: `Supabase anon key${project}`,
      scopes: ['anon'],
      notes: ['anon keys are constrained by Row Level Security and are designed to ship to browsers.'],
      unresolved: false,
      keyClass: 'publishable',
    };
  }

  return {
    valid: true, identity: `Supabase key with role ${claims.role}${project}`, scopes: [claims.role],
    notes: ['unrecognised Supabase role claim — privileges not classified'],
    unresolved: true, keyClass: null,
  };
}

export function toCapabilities({ keyClass, unresolved }) {
  if (unresolved) return [];

  switch (keyClass) {
    case 'management':
      // Deleting a project takes its database and that database's backups with it.
      return [
        'destroy:data', 'destroy:backups', 'destroy:infra', 'admin:access',
        'read:secrets', 'read:data', 'write:data', 'read:metadata',
      ];
    case 'secret':
      // Full data authority, but no ability to delete the project or its backups —
      // severe rather than catastrophic, and that distinction is the point of the taxonomy.
      return ['read:data', 'write:data', 'destroy:data', 'read:metadata'];
    case 'publishable':
      return ['read:metadata'];
    default:
      return [];
  }
}

export function remediation({ keyClass, unresolved }) {
  if (unresolved) {
    return ['Could not classify this Supabase credential. Check it in the dashboard under Project Settings → API keys.'];
  }
  switch (keyClass) {
    case 'management':
      return [
        'A management token can delete every project in the account. Never place one in a repository, shell profile, or MCP server definition.',
        'Scope automation to a single project with a project-level key instead.',
      ];
    case 'secret':
      return [
        'Move this key to a server-side secret store — anything holding it reads and writes every row, RLS notwithstanding.',
        'If it has ever been committed or placed in agent-readable config, rotate it: Project Settings → API keys.',
      ];
    case 'publishable':
      return ['No action needed if Row Level Security is enabled on every table — this key class is designed to be public.'];
    default:
      return [];
  }
}
