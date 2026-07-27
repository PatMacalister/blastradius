/**
 * Stripe — the honest case study for why this tool is harder than it looks.
 *
 * Key *mode* (live vs test) is readable from the prefix and is the single most important
 * fact: a live secret key can move real money. But Stripe restricted keys (`rk_`) carry a
 * per-resource permission set that has no clean public introspection endpoint — you learn
 * what a restricted key can do by being refused, which is not something a security tool
 * should discover by trying.
 *
 * So: `sk_live` resolves to a known-worst capability set, and `rk_live` is reported as
 * `unresolved` with its mode known. Guessing would be worse than admitting the gap.
 */

export const id = 'stripe';
export const label = 'Stripe';
export const lastVerified = '2026-07-27';
export const apiHosts = ['api.stripe.com'];

export const changelog = {
  url: 'https://docs.stripe.com/changelog',
  type: 'html',
};

export const patterns = [
  { name: 'secret-live', regex: /\bsk_live_[A-Za-z0-9]{20,}\b/, confidence: 0.99 },
  { name: 'secret-test', regex: /\bsk_test_[A-Za-z0-9]{20,}\b/, confidence: 0.99 },
  { name: 'restricted-live', regex: /\brk_live_[A-Za-z0-9]{20,}\b/, confidence: 0.99 },
  { name: 'restricted-test', regex: /\brk_test_[A-Za-z0-9]{20,}\b/, confidence: 0.99 },
];

function classify(secret) {
  const live = secret.startsWith('sk_live_') || secret.startsWith('rk_live_');
  const restricted = secret.startsWith('rk_');
  return { live, restricted };
}

export async function introspect(secret, { fetchImpl = fetch } = {}) {
  const { live, restricted } = classify(secret);

  const res = await fetchImpl('https://api.stripe.com/v1/account', {
    headers: { authorization: `Bearer ${secret}` },
  });

  if (res.status === 401) {
    return { valid: false, identity: null, scopes: [], notes: ['key rejected'], unresolved: false };
  }

  const body = await res.json().catch(() => ({}));
  const identity = body?.id ? `account ${body.id}` : null;
  const mode = live ? 'live' : 'test';

  if (restricted) {
    return {
      valid: true,
      identity,
      scopes: [`mode:${mode}`, 'restricted'],
      notes: [
        'restricted key — per-resource permissions are not introspectable; review it in the Stripe dashboard',
      ],
      unresolved: true,
    };
  }

  return {
    valid: true,
    identity,
    scopes: [`mode:${mode}`, 'full-access'],
    notes: [],
    unresolved: false,
  };
}

export function toCapabilities({ scopes = [], unresolved }) {
  if (unresolved) return [];
  const caps = new Set(['read:metadata']);
  if (!scopes.includes('full-access')) return [...caps];

  caps.add('read:data');
  caps.add('write:data');
  caps.add('admin:access');
  // Only a live key can move real money. A test key with full access is noisy, not dangerous.
  if (scopes.includes('mode:live')) caps.add('move:money');
  return [...caps];
}

export function remediation({ scopes = [], unresolved }) {
  const out = [];
  if (scopes.includes('mode:live') && scopes.includes('full-access')) {
    out.push('Replace this unrestricted live key with a restricted key granting only the resources this code path uses.');
    out.push('A live secret key on a developer machine reachable by a coding agent can issue refunds and transfers — rotate it and scope it down.');
  }
  if (unresolved) {
    out.push('Restricted-key permissions must be reviewed manually in Dashboard → Developers → API keys.');
  }
  return out;
}
