/**
 * GitHub — classic PATs expose granted scopes in a response header, which makes this the
 * cleanest introspection story of any provider and a good reference implementation.
 *
 * Fine-grained PATs do NOT return that header. They are deliberately reported as
 * `unresolved` rather than assumed harmless: a fine-grained token can still hold
 * contents:write on every repo in an org.
 */

export const id = 'github';
export const label = 'GitHub';
export const lastVerified = '2026-07-27';
export const apiHosts = ['api.github.com'];

export const changelog = {
  // The per-label feed (…/changelog/label/api/feed/) 404s — verified 2026-07-27. This is
  // the whole changelog, so the RELEVANT filter does the narrowing instead.
  url: 'https://github.blog/changelog/feed/',
  type: 'rss',
};

export const patterns = [
  { name: 'classic-pat', regex: /\bghp_[A-Za-z0-9]{36}\b/, confidence: 0.99 },
  { name: 'oauth-token', regex: /\bgho_[A-Za-z0-9]{36}\b/, confidence: 0.99 },
  { name: 'user-server-token', regex: /\bghu_[A-Za-z0-9]{36}\b/, confidence: 0.95 },
  { name: 'server-token', regex: /\bghs_[A-Za-z0-9]{36}\b/, confidence: 0.95 },
  { name: 'refresh-token', regex: /\bghr_[A-Za-z0-9]{36}\b/, confidence: 0.9 },
  { name: 'fine-grained-pat', regex: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/, confidence: 0.99 },
];

export async function introspect(secret, { fetchImpl = fetch } = {}) {
  const res = await fetchImpl('https://api.github.com/user', {
    headers: {
      authorization: `Bearer ${secret}`,
      accept: 'application/vnd.github+json',
      'user-agent': 'blastradius',
    },
  });

  if (res.status === 401) {
    return { valid: false, identity: null, scopes: [], notes: ['token rejected'], unresolved: false };
  }
  if (!res.ok) {
    return {
      valid: true,
      identity: null,
      scopes: [],
      notes: [`introspection failed with HTTP ${res.status}`],
      unresolved: true,
    };
  }

  const header = res.headers.get('x-oauth-scopes');
  const body = await res.json().catch(() => ({}));
  const identity = body?.login ? `user ${body.login}` : null;

  // Absent header = fine-grained PAT or GitHub App token. Privileges are real but not
  // enumerable this way. Saying "no scopes" here would be the dangerous answer.
  if (header === null) {
    return {
      valid: true,
      identity,
      scopes: [],
      notes: ['fine-grained or app token — granted permissions are not enumerable via this endpoint'],
      unresolved: true,
    };
  }

  const scopes = header.split(',').map((s) => s.trim()).filter(Boolean);
  return { valid: true, identity, scopes, notes: [], unresolved: false };
}

export function toCapabilities({ scopes = [], unresolved }) {
  if (unresolved) return [];
  const caps = new Set();
  const has = (s) => scopes.includes(s);

  if (has('repo') || has('public_repo')) {
    caps.add('read:data');
    caps.add('write:data');
  }
  // `delete_repo` is the one that removes work irrecoverably for most teams.
  if (has('delete_repo')) caps.add('destroy:infra');
  if (has('admin:org') || has('admin:enterprise')) caps.add('admin:access');
  if (has('write:packages') || has('workflow')) caps.add('deploy');
  if (has('repo') || has('codespace') || has('admin:org')) caps.add('read:secrets');
  if (scopes.length > 0) caps.add('read:metadata');

  return [...caps];
}

export function remediation({ scopes = [], unresolved }) {
  const out = [];
  if (unresolved) {
    out.push('Re-issue as a classic PAT if you need BlastRadius to verify its scope, or audit it manually in Settings → Developer settings.');
    return out;
  }
  if (scopes.includes('delete_repo')) {
    out.push('Drop `delete_repo` — almost nothing in CI legitimately needs it.');
  }
  if (scopes.includes('repo')) {
    out.push('Replace the blanket `repo` scope with a fine-grained PAT limited to the specific repositories this credential needs.');
  }
  if (scopes.includes('admin:org')) {
    out.push('`admin:org` allows issuing further credentials — treat as an owner-equivalent secret and avoid placing it on developer machines.');
  }
  return out;
}
