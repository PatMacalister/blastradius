/**
 * The provider registry.
 *
 * Registration is an explicit import, not a directory scan. That is deliberate: adding a
 * provider should be a visible line in a diff that a reviewer has to approve, because a
 * wrong scope mapping is the worst output this tool can produce. Convenience is not worth
 * a provider appearing by accident.
 */

import * as github from './github.mjs';
import * as stripe from './stripe.mjs';
import * as railway from './railway.mjs';
import * as supabase from './supabase.mjs';
import * as vercel from './vercel.mjs';
import * as cloudflare from './cloudflare.mjs';
import { validateProvider, stalenessOf } from './_contract.mjs';

const MODULES = [github, stripe, railway, supabase, vercel, cloudflare];

/**
 * Contract violations are a startup failure, not a warning. A malformed module would
 * otherwise degrade silently into "no findings", which reads as "you are safe".
 */
export function loadProviders() {
  const problems = [];
  for (const mod of MODULES) {
    const { ok, errors } = validateProvider(mod);
    if (!ok) problems.push(`${mod.id ?? '<unnamed>'}: ${errors.join('; ')}`);
  }
  if (problems.length > 0) {
    throw new Error(`Invalid provider module(s):\n  ${problems.join('\n  ')}`);
  }
  return MODULES;
}

export function providerById(id) {
  return MODULES.find((m) => m.id === id) ?? null;
}

export function staleProviders(now = new Date()) {
  return MODULES.map((mod) => ({ id: mod.id, label: mod.label, ...stalenessOf(mod, now) }))
    .filter((p) => p.stale);
}

export { MODULES as providers };
