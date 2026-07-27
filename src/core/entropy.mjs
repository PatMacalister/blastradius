/**
 * The "visible ignorance" heuristic.
 *
 * Pattern matching only finds credentials whose format BlastRadius already knows. Anything
 * else is invisible — and invisible reads to a user exactly like absent, which is the
 * failure mode this whole tool exists to complain about.
 *
 * So: flag high-entropy strings that sit under a secret-shaped key name, and say plainly
 * that we do not know what they are. Never resolve them (we have no provider to ask, and
 * authenticating a random string against arbitrary hosts is absurd), and never let them
 * silently pass as findings of known severity.
 *
 * The precision/trust trade-off is deliberate and one-sided. A noisy heuristic that flags
 * every base64 blob in a lockfile gets muted, and a muted warning is worse than no warning
 * because it manufactures the appearance of coverage. So this is gated hard on *context* —
 * the key name must look like a secret — rather than on entropy alone.
 */

/**
 * Words in a key name that make a high-entropy value worth mentioning.
 *
 * Matched against *tokens*, not as substrings, after splitting camelCase and separators.
 * Substring matching is how a checker ends up flagging `monkey` and `tokenizer`.
 */
const SECRET_WORDS = new Set([
  'secret', 'secrets', 'token', 'tokens', 'password', 'passwd', 'pwd', 'passphrase',
  'credential', 'credentials', 'cred', 'creds', 'auth', 'key', 'keys', 'apikey',
  'accesskey', 'privatekey', 'signingkey', 'sessionkey', 'dsn',
]);

/**
 * Words that disqualify a key name outright. `publicKey` and `primaryKey` both contain
 * "key" and neither is a secret; flagging them is exactly the noise that gets a heuristic
 * switched off.
 */
const NOT_SECRET_WORDS = new Set([
  'public', 'primary', 'sort', 'partition', 'foreign', 'idempotency', 'cache',
  'shortcut', 'hotkey', 'keyboard', 'locale',
]);

/** `SUPABASE_service_roleKey` → ['supabase', 'service', 'role', 'key'] */
function keyTokens(key) {
  return String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((t) => t.toLowerCase());
}

/** Shapes that are high-entropy but boringly explicable — never worth a warning. */
const KNOWN_INNOCENT = [
  /^[0-9a-f]{32}$/i,                 // md5 / generic 32-hex digest
  /^[0-9a-f]{40}$/i,                 // sha1 / git object id
  /^[0-9a-f]{64}$/i,                 // sha256 — lockfile integrity hashes
  /^[0-9a-f]{128}$/i,                // sha512
  /^sha\d{3}-/i,                     // npm lockfile integrity field
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // bare UUID
  /^data:/i,
  /^https?:\/\//i,
  /^[A-Za-z]+(?:[A-Z][a-z]+)+$/,     // CamelCaseIdentifiers
  /^\d+$/,                           // pure numbers
];

/** Placeholders. Flagging these is how a tool trains people to ignore it. */
const PLACEHOLDER =
  /^(?:x{3,}|y{3,}|\.{3,}|\*{3,}|<.*>|\$\{.*\}|changeme|your[_-]?\w*|example|placeholder|todo|none|null|undefined|true|false|test|dummy|fake|sample|redacted|removed|secret|password)$/i;

const MIN_LENGTH = 20;
const MAX_LENGTH = 200;
const MIN_ENTROPY_BITS_PER_CHAR = 3.4;

/** Shannon entropy in bits per character. */
export function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** At least three of: lowercase, uppercase, digit, punctuation. Real keys mix classes. */
function characterClasses(value) {
  let classes = 0;
  if (/[a-z]/.test(value)) classes++;
  if (/[A-Z]/.test(value)) classes++;
  if (/[0-9]/.test(value)) classes++;
  if (/[_\-+/=.~]/.test(value)) classes++;
  return classes;
}

export function looksLikeSecretKeyName(key) {
  if (typeof key !== 'string') return false;
  const tokens = keyTokens(key);
  if (tokens.some((t) => NOT_SECRET_WORDS.has(t))) return false;
  return tokens.some((t) => SECRET_WORDS.has(t));
}

/**
 * Would a human call this an unrecognised credential? Context (the key name) is required —
 * see the module comment for why entropy alone is not enough to earn a user's attention.
 */
export function isSuspiciousValue(value) {
  if (typeof value !== 'string') return false;
  const v = value.trim().replace(/^["']|["']$/g, '');
  if (v.length < MIN_LENGTH || v.length > MAX_LENGTH) return false;
  if (PLACEHOLDER.test(v)) return false;
  if (KNOWN_INNOCENT.some((re) => re.test(v))) return false;
  if (/\s/.test(v)) return false;
  if (characterClasses(v) < 3) return false;
  return shannonEntropy(v) >= MIN_ENTROPY_BITS_PER_CHAR;
}

/**
 * Scan already-parsed key/value pairs. Deliberately NOT a free-text scanner: running this
 * over arbitrary source files is what produces the unusable noise described above.
 */
export function findUnrecognised(pairs, { knownSecrets = new Set() } = {}) {
  const out = [];
  for (const { key, value, source } of pairs) {
    if (!looksLikeSecretKeyName(key)) continue;
    const cleaned = String(value ?? '').trim().replace(/^["']|["']$/g, '');
    if (knownSecrets.has(cleaned)) continue;   // already identified by a provider pattern
    if (!isSuspiciousValue(cleaned)) continue;
    out.push({
      secret: cleaned,
      key,
      entropy: Number(shannonEntropy(cleaned).toFixed(2)),
      source,
    });
  }
  return out;
}

export const _internals = { KNOWN_INNOCENT, PLACEHOLDER, characterClasses, keyTokens, MIN_ENTROPY_BITS_PER_CHAR };
