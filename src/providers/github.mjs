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
export const lastVerified = '2026-07-28';
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

/**
 * Scope-vocabulary probes — verifying scope names we can never hold.
 *
 * A test credential is forbidden a destructive scope, so `admin:org` and `delete_repo` can
 * never appear in a contract test's EXPECT. That left the mappings behind the SEVERE findings
 * as the only ones with no live verification at all: if GitHub renamed `admin:org`, the module
 * would keep looking internally consistent and silently stop matching.
 *
 * GitHub closes that gap itself. `X-Accepted-OAuth-Scopes` names the scopes an endpoint will
 * accept, whether or not the caller holds any of them — so a read-only token can confirm the
 * string is still live vocabulary without ever being able to use it.
 *
 * Assert on the header alone, never on the status code: whether a probe returns 200 or 403
 * depends on what the test credential happens to hold, and that is allowed to change.
 *
 * This proves the scope still exists and still gates this endpoint. It does not prove what
 * holding it would do — nothing short of a destructive credential could, and that stays out
 * of bounds. The mapping itself is covered offline in test/unit/providers-phase1.test.mjs.
 */
export const vocabularyProbes = [
  {
    scope: 'admin:org',
    url: 'https://api.github.com/user/orgs',
    note: 'admin:org maps to admin:access — privilege escalation, and the severest thing a GitHub PAT can carry.',
  },
  {
    scope: 'codespace',
    url: 'https://api.github.com/user/codespaces',
    note: 'codespace maps to read:secrets.',
  },
  {
    scope: 'repo',
    url: 'https://api.github.com/repos/octocat/Hello-World',
    note: 'repo is the blanket scope most real tokens carry; it maps to read:data, write:data and read:secrets.',
  },
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
  if (has('delete_repo') || has('delete:packages')) caps.add('destroy:infra');

  // Anything that can grant standing access to someone else, or to a future you.
  //
  // `write:org` was previously unmapped and fell through to read:metadata alone, so a token
  // that can add and remove organisation members rated LOW. Under-reporting a scope this
  // dangerous is the one failure direction this project says it has no excuse for. The key
  // scopes are the subtler case: an attacker who can add an SSH or GPG key does not need the
  // token again afterwards, which is privilege escalation by any useful definition.
  if (has('admin:org') || has('admin:enterprise') || has('write:org')
      || has('admin:public_key') || has('write:public_key')
      || has('admin:gpg_key') || has('write:gpg_key')) {
    caps.add('admin:access');
  }

  if (has('write:packages') || has('workflow')) caps.add('deploy');
  if (has('repo') || has('codespace') || has('admin:org')) caps.add('read:secrets');

  // Reads real data rather than metadata: user profile and email, private packages, and the
  // security-event stream, which describes vulnerabilities before they are public.
  if (has('user') || has('read:user') || has('user:email')
      || has('read:packages') || has('security_events') || has('read:discussion')) {
    caps.add('read:data');
  }

  // Writes application data the account owns. Repository hooks belong here rather than under
  // deploy: a hook is a standing copy of every push event sent to a URL of the holder's
  // choosing, which is closer to modifying the repo's configuration than to shipping code.
  if (has('gist') || has('admin:repo_hook') || has('write:repo_hook')
      || has('admin:org_hook') || has('write:discussion')) {
    caps.add('write:data');
  }
  // `notifications` is deliberately NOT here. It reads notifications and marks them read —
  // rating that MODERATE inflates a finding nobody needs to act on, and noise is what gets a
  // scanner muted. It still lands at read:metadata via the catch-all below.

  if (scopes.length > 0) caps.add('read:metadata');

  return [...caps];
}

export function remediation({ scopes = [], unresolved }) {
  const out = [];
  if (unresolved) {
    out.push('Audit this token manually in Settings → Developer settings → Personal access tokens. GitHub exposes fine-grained permissions to no API, so its reach cannot be read from here.');
    // Without this second line the advice above reads as "downgrade to a classic PAT so the
    // tool can see it" — trading real scope reduction for legibility in our report. A
    // fine-grained token is the better credential even though it is the one we can say least
    // about, and a security tool should not nudge anyone the other way for its own benefit.
    out.push('Do not widen it to a classic PAT just to make this report more specific — a fine-grained token is the better credential, and UNKNOWN here reflects what GitHub will disclose, not a defect in the token.');
    return out;
  }
  if (scopes.includes('delete_repo')) {
    out.push('Drop `delete_repo` — almost nothing in CI legitimately needs it.');
  }
  if (scopes.includes('repo')) {
    out.push('Replace the blanket `repo` scope with a fine-grained PAT limited to the specific repositories this credential needs.');
    // Say this up front, or the advice looks like it contradicts itself the moment they act
    // on it: the recommended credential is one this tool reports as UNKNOWN.
    out.push('Expect the replacement to report as UNKNOWN here rather than as safe — GitHub does not expose fine-grained permissions to any API. That is a limit on what can be verified, not a reason to keep the broader scope.');
  }
  if (scopes.includes('admin:org')) {
    out.push('`admin:org` allows issuing further credentials — treat as an owner-equivalent secret and avoid placing it on developer machines.');
  }
  return out;
}
