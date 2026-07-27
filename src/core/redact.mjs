/**
 * Credential handling rules, enforced in one place.
 *
 * Two invariants this tool must never break, because breaking either makes BlastRadius
 * a bigger liability than the problem it reports on:
 *
 *   1. A raw secret is NEVER written to stdout, a report file, a log, or telemetry.
 *   2. A discovered secret is NEVER transmitted anywhere except the introspection
 *      endpoint of the provider that issued it. (Enforced in resolve.mjs.)
 *
 * Everything user-facing goes through fingerprint(). If you find yourself wanting the
 * raw value outside a provider module, you are about to violate invariant 1.
 */

/**
 * A stable, non-reversible-enough handle for a credential: enough for a human to work
 * out which key this is in their dashboard, not enough to use.
 */
export function fingerprint(secret) {
  if (typeof secret !== 'string' || secret.length === 0) return '<empty>';
  if (secret.length <= 8) return `${'*'.repeat(secret.length)}`;
  const head = secret.slice(0, 4);
  const tail = secret.slice(-4);
  return `${head}${'*'.repeat(Math.min(secret.length - 8, 12))}${tail}`;
}

/**
 * Defence in depth: scrub anything that looks like a known-shape credential out of
 * arbitrary text before it is printed. Provider error messages love to echo the token
 * you just sent them.
 */
const SECRETISH = [
  /\b(gh[pousr]_[A-Za-z0-9]{16,})\b/g,
  /\b(github_pat_[A-Za-z0-9_]{20,})\b/g,
  /\b([rs]k_(?:live|test)_[A-Za-z0-9]{10,})\b/g,
  /\b(sbp_[A-Za-z0-9]{20,})\b/g,
  /\b(AKIA[0-9A-Z]{16})\b/g,
  /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
];

export function scrub(text) {
  if (typeof text !== 'string') return text;
  let out = text;
  for (const pattern of SECRETISH) {
    out = out.replace(pattern, (m) => fingerprint(m));
  }
  return out;
}
