/**
 * Cloudflare — the provider that proves the `unresolved` state was worth building.
 *
 * The execution plan expected this to be the second-cleanest introspection story after
 * GitHub, on the assumption that `/user/tokens/verify` returns the token's scopes. **It does
 * not.** The documented response is `{ id, status, expires_on, not_before }` and nothing
 * else: status is `active`, `disabled` or `expired`, with no policies, no permission groups.
 * A token cannot read its own permissions unless it happens to hold "User API Tokens Read",
 * which effectively no deployment token does.
 *
 * So the honest output for a live Cloudflare API token is: this credential is real, an agent
 * on this machine can reach it, and **its blast radius cannot be determined from the API**.
 * That is a less satisfying finding than GitHub's, and inventing a scope mapping to avoid
 * saying it would be precisely the confident-and-wrong failure this tool exists to prevent.
 *
 * The Global API Key is worse and simpler: it is the legacy all-access credential, valid for
 * every zone and account operation the user owns, and it cannot be verified without the
 * account email that accompanies it. It is reported unresolved with a loud note, because a
 * genuine Global API Key is about as dangerous as a credential gets.
 */

export const id = 'cloudflare';
export const label = 'Cloudflare';
export const lastVerified = '2026-07-27';
export const apiHosts = ['api.cloudflare.com'];

export const changelog = {
  url: 'https://developers.cloudflare.com/changelog/rss.xml',
  type: 'rss',
};

export const patterns = [
  {
    name: 'api-token-env',
    regex: /(?:CLOUDFLARE|CF)_API_TOKEN["']?\s*[:=]\s*["']?([A-Za-z0-9_-]{40})\b/,
    confidence: 0.9,
  },
  {
    name: 'global-api-key-env',
    regex: /(?:CLOUDFLARE|CF)_(?:API_KEY|GLOBAL_API_KEY)["']?\s*[:=]\s*["']?([0-9a-f]{37})\b/,
    confidence: 0.9,
  },
];

export async function introspect(secret, { fetchImpl = fetch } = {}) {
  // 37 hex characters is the Global API Key shape. Verifying it requires the account email,
  // which this module has no reliable way to obtain, so it is never sent anywhere.
  if (/^[0-9a-f]{37}$/.test(secret)) {
    return {
      valid: true,
      identity: 'Cloudflare Global API Key (unverified)',
      scopes: [],
      notes: [
        'A Global API Key grants unrestricted access to every zone and account operation its owner holds — it is the legacy all-access credential.',
        'Not verified: confirming it would require sending it alongside the account email, and this module will not guess an identity to authenticate with.',
      ],
      unresolved: true,
      keyClass: 'global',
    };
  }

  const res = await fetchImpl('https://api.cloudflare.com/client/v4/user/tokens/verify', {
    headers: { authorization: `Bearer ${secret}`, 'user-agent': 'blastradius' },
  });

  // 400 is included deliberately: Cloudflare answers a malformed bearer token with a 400
  // rather than a 401, and treating that as "could not determine" would manufacture an
  // unknown finding out of a string that is simply not a Cloudflare token.
  if (res.status === 400 || res.status === 401 || res.status === 403) {
    return { valid: false, identity: null, scopes: [], notes: ['token rejected'], unresolved: false, keyClass: 'token' };
  }
  if (!res.ok) {
    return {
      valid: true, identity: null, scopes: [],
      notes: [`introspection failed with HTTP ${res.status}`], unresolved: true, keyClass: 'token',
    };
  }

  const body = await res.json().catch(() => ({}));
  const status = body?.result?.status ?? null;

  if (status === 'expired' || status === 'disabled') {
    return {
      valid: false, identity: `Cloudflare API token (${status})`, scopes: [],
      notes: [`token is ${status}`], unresolved: false, keyClass: 'token',
    };
  }

  return {
    valid: true,
    identity: body?.result?.id ? `Cloudflare API token ${body.result.id}` : 'Cloudflare API token',
    scopes: [],
    notes: [
      'Token is active. Cloudflare\'s verify endpoint returns status only — it does not expose the token\'s permission groups, so its reach cannot be determined here.',
      'Check the token\'s permissions in the dashboard under My Profile → API Tokens.',
    ],
    unresolved: true,
    keyClass: 'token',
  };
}

/**
 * Always empty, and deliberately so: every path through introspect() for a live credential
 * returns `unresolved`, which the reporter renders louder than any capability list. If
 * Cloudflare ever exposes token policies to the token itself, this is where that mapping
 * goes — and the contract test is what would tell us it had happened.
 */
export function toCapabilities() {
  return [];
}

export function remediation({ keyClass }) {
  if (keyClass === 'global') {
    return [
      'Replace the Global API Key with a scoped API token. The Global key cannot be restricted, cannot be scoped to one zone, and is valid for everything the account owns.',
      'Rotate it if it has ever sat in a repository, shell profile, or MCP server definition — an agent that finds it holds the whole account.',
    ];
  }
  return [
    'Cloudflare does not let a token read its own permissions. Review this one in the dashboard under My Profile → API Tokens and confirm it is scoped to the minimum zone and permission set.',
    'Prefer tokens with an expiry date and an IP allowlist where the consuming system has a stable address.',
  ];
}
