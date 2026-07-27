/**
 * Vercel — like Railway, a provider with no granular token permissions.
 *
 * Vercel access tokens scope to a user or a team and nothing narrower; project-level
 * scoping is a long-standing open feature request, not a thing you can configure. So a
 * live token carries the authority of whoever issued it: it can read decrypted environment
 * variables across projects, trigger deployments, and delete projects outright.
 *
 * The one genuine ambiguity is the `limited` user shape. /v2/user returns a reduced object
 * when "the authentication token [is] missing privileges to read the full User data". That
 * signals a token issued through a flow with narrower rights, and since the API gives no
 * way to enumerate what it *can* still do, those are reported unresolved rather than
 * assumed either safe or maximal.
 */

export const id = 'vercel';
export const label = 'Vercel';
export const lastVerified = '2026-07-27';
export const apiHosts = ['api.vercel.com'];

export const changelog = {
  // vercel.com/changelog is a JavaScript-rendered page and parses to nothing. The Atom feed
  // is the same content in a form that can actually be watched. Verified 2026-07-27.
  url: 'https://vercel.com/atom',
  type: 'rss',
};

/**
 * Vercel tokens are 24 characters of undistinguished alphanumerics — matching that shape
 * alone would flag half of every minified bundle. Context required; group 1 is the token.
 */
export const patterns = [
  {
    name: 'vercel-token-env',
    regex: /(?:VERCEL|VC)_(?:API_)?TOKEN["']?\s*[:=]\s*["']?([A-Za-z0-9]{24})\b/,
    confidence: 0.85,
  },
];

export async function introspect(secret, { fetchImpl = fetch } = {}) {
  const res = await fetchImpl('https://api.vercel.com/v2/user', {
    headers: { authorization: `Bearer ${secret}`, 'user-agent': 'blastradius' },
  });

  if (res.status === 401 || res.status === 403) {
    return { valid: false, identity: null, scopes: [], notes: ['token rejected'], unresolved: false, limited: false };
  }
  if (!res.ok) {
    return {
      valid: true, identity: null, scopes: [],
      notes: [`introspection failed with HTTP ${res.status}`], unresolved: true, limited: false,
    };
  }

  const body = await res.json().catch(() => ({}));
  const user = body?.user ?? {};
  const identity = user.username ? `Vercel user ${user.username}` : user.email ? `Vercel user ${user.email}` : null;

  if (user.limited === true) {
    return {
      valid: true,
      identity,
      scopes: [],
      notes: ['Token has reduced privileges (Vercel returned a limited user object) and its remaining reach is not enumerable via the API.'],
      unresolved: true,
      limited: true,
    };
  }

  return {
    valid: true,
    identity,
    scopes: ['account'],
    notes: ['Vercel tokens scope to a user or team only — there is no per-project or per-permission restriction to enumerate.'],
    unresolved: false,
    limited: false,
  };
}

export function toCapabilities({ scopes = [], unresolved }) {
  if (unresolved || !scopes.includes('account')) return [];
  // Environment variables are readable in decrypted form through the projects API, which is
  // what makes this a secrets-reaching credential and not merely a deployment one.
  return ['destroy:infra', 'read:secrets', 'deploy', 'read:metadata'];
}

export function remediation({ unresolved, limited }) {
  if (limited) {
    return ['Vercel reports this token as privilege-limited but will not enumerate what it retains. Audit it under Account Settings → Tokens.'];
  }
  if (unresolved) {
    return ['Audit this token under Account Settings → Tokens.'];
  }
  return [
    'Scope this token to the single team that needs it — Vercel offers no project-level restriction, so a personal token reaches every project you can see.',
    'Set a short expiry. Vercel tokens can be issued with a fixed lifetime, and an agent-readable token with no expiry is a permanent liability.',
    'Treat it as a secrets-reading credential: it can pull decrypted environment variables for every project in scope.',
  ];
}
