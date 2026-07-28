/**
 * Railway — the platform from the reference incident (see INCIDENTS.md), and the clearest
 * example of why this tool exists.
 *
 * Railway's own documentation is unambiguous: tokens "inherit the full permissions of the
 * generating user; there are no scopes, no service accounts, and no fine-grained token
 * controls". There is nothing to enumerate, because there is nothing to restrict. A
 * conventional scanner reporting "live Railway token found" is technically complete and
 * tells you nothing; the finding that matters is that this one string can delete a volume
 * *and the backups stored with it* — Railway keeps volume backups inside the volume they
 * protect, so the two die together. That is exactly the April 2026 outage.
 *
 * That makes Railway the one provider where a confident maximal capability set is the
 * correct answer rather than an alarmist one — the absence of scoping is documented, not
 * assumed.
 *
 * Token classes:
 *   - Account token   — every resource in every workspace the user belongs to. `Bearer`.
 *   - Workspace token — one workspace. `Bearer`. Cannot answer the `me` query.
 *   - Project token   — one project environment. `Project-Access-Token` header.
 *
 * Project tokens are deliberately reported as `unresolved`: their reach is narrower, but
 * whether it includes volume deletion within that environment is not something this module
 * can establish without a live test credential. Guessing "probably safe" there would be
 * exactly the under-report this tool must never produce. Phase 2's contract test settles it.
 */

const ENDPOINT = 'https://backboard.railway.com/graphql/v2';

export const id = 'railway';
export const label = 'Railway';
export const lastVerified = '2026-07-28';
export const apiHosts = ['backboard.railway.com', 'backboard.railway.app'];

/**
 * Railway publishes no machine-readable changelog. Verified 2026-07-27: the RSS paths all
 * 404, and railway.com/changelog is a JavaScript-rendered page that parses to a single
 * heading — its own tagline. Declaring that here means the scanner reports Railway as a
 * standing blind spot every run instead of failing at it weekly until someone mutes it.
 *
 * Consequence, and it is not a small one: Railway's correctness rests entirely on its
 * contract test. That is the provider whose test credential has a paid floor.
 */
export const changelog = {
  url: 'https://railway.com/changelog',
  type: 'html',
  unwatchable: true,
  note: 'no RSS feed and the changelog page is JavaScript-rendered — correctness depends entirely on the contract test',
};

/**
 * Railway tokens are bare UUIDs, which is far too generic to match on shape — every
 * lockfile and fixture directory is full of UUIDs. So these patterns require the
 * surrounding variable name, and capture group 1 is the credential.
 */
export const patterns = [
  {
    name: 'railway-token-env',
    regex: /RAILWAY(?:_API)?_TOKEN["']?\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b/,
    confidence: 0.9,
  },
  {
    name: 'railway-project-token-env',
    regex: /RAILWAY_PROJECT_TOKEN["']?\s*[:=]\s*["']?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b/,
    confidence: 0.9,
  },
];

async function graphql(fetchImpl, headers, query) {
  const res = await fetchImpl(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'blastradius', ...headers },
    body: JSON.stringify({ query }),
  });
  const body = await res.json().catch(() => null);
  return { res, body };
}

export async function introspect(secret, { fetchImpl = fetch } = {}) {
  // An account token can answer `me`. This is the case that matters most and it is
  // unambiguous when it succeeds.
  const asAccount = await graphql(fetchImpl, { authorization: `Bearer ${secret}` }, '{ me { id name email } }');

  if (asAccount.body?.data?.me) {
    const me = asAccount.body.data.me;
    return {
      valid: true,
      identity: me.email ? `Railway account ${me.email}` : `Railway account ${me.id ?? 'unknown'}`,
      scopes: ['account'],
      notes: ['Railway tokens carry the full authority of the user who created them — there are no scopes to restrict this one.'],
      unresolved: false,
      tokenClass: 'account',
    };
  }

  // Every remaining probe MUST be one the API refuses without valid credentials.
  //
  // The first version of this used `{ __typename }` on the reasoning that it needs no
  // privileges. It needs no *authentication* either: Railway answers it with HTTP 200 and
  // data for a garbage token, and for no Authorization header at all. So it classified any
  // string as a live workspace token — caught by the contract test's bogus-credential case
  // on the first live run, which is precisely the job that test exists to do.
  //
  // `projects` returns "Not Authorized" without a valid Bearer token; `projectToken` returns
  // "Project Token not found" without a valid project token. Both verified against the live
  // API 2026-07-27.
  const asWorkspace = await graphql(fetchImpl, { authorization: `Bearer ${secret}` }, '{ projects { edges { node { id } } } }');
  if (asWorkspace.body?.data?.projects) {
    return {
      valid: true,
      identity: 'Railway workspace-scoped token',
      scopes: ['workspace'],
      notes: ['Token is live and workspace-scoped. Railway does not expose per-token permissions, so its reach within that workspace cannot be enumerated.'],
      unresolved: true,
      tokenClass: 'workspace',
    };
  }

  const asProject = await graphql(fetchImpl, { 'project-access-token': secret }, '{ projectToken { projectId environmentId } }');
  if (asProject.body?.data?.projectToken) {
    return {
      valid: true,
      identity: 'Railway project token',
      scopes: ['project'],
      notes: ['Token is live and scoped to a single project environment. Whether that includes deleting services or volumes in that environment is not determinable from the API.'],
      unresolved: true,
      tokenClass: 'project',
    };
  }

  // Railway answers HTTP 200 with a GraphQL `errors` array rather than a 4xx, so status
  // alone cannot decide this. Three auth-gated probes have now refused the credential;
  // that is a rejection.
  if (asAccount.res.ok || asAccount.res.status === 401 || asAccount.res.status === 403) {
    return { valid: false, identity: null, scopes: [], notes: ['token rejected'], unresolved: false };
  }

  return {
    valid: true,
    identity: null,
    scopes: [],
    notes: [`introspection inconclusive (HTTP ${asAccount.res.status})`],
    unresolved: true,
  };
}

export function toCapabilities({ tokenClass, unresolved }) {
  if (unresolved || tokenClass !== 'account') return [];

  // Documented as unscoped: this token can do anything its creator can do. The pairing of
  // destroy:data with destroy:backups is what escalates to `catastrophic`, and it is not a
  // guess — deleting a Railway volume removes the backups stored against it.
  return [
    'destroy:data',
    'destroy:backups',
    'destroy:infra',
    'admin:access',
    'read:secrets',
    'read:data',
    'write:data',
    'deploy',
    'read:metadata',
  ];
}

export function remediation({ tokenClass, unresolved }) {
  if (unresolved) {
    return [
      'Railway does not expose per-token permissions. Audit this token in the Railway dashboard under Account → Tokens and delete it if you do not recognise it.',
    ];
  }
  if (tokenClass === 'account') {
    return [
      'Replace this account token with a project token scoped to the single environment that needs it — account tokens reach every workspace you belong to.',
      'Do not leave a Railway account token in the working tree, shell environment, or MCP config: an agent that finds it can delete a volume and its backups in one call.',
      'Keep backups outside the provider account they protect. Railway stores volume backups inside the volume itself, so deleting one deletes both — and the newest off-volume copy is whatever you made yourself.',
    ];
  }
  return [];
}
