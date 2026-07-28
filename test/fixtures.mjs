/**
 * Shared fixtures. These are structurally valid but entirely fake credentials — they match
 * the detection patterns and authenticate against nothing.
 */

// Assembled rather than written whole, so the file itself contains no string that matches a
// detection pattern. Without this, scanning this repo reports its own fixtures as findings —
// and a Supabase `sb_secret_` fixture rates SEVERE, because Supabase classifies offline from
// the prefix and cannot tell a fake from a live key.
const SB = 'sb_';

export const FAKE = {
  githubClassic: `ghp_${'A'.repeat(36)}`,
  githubFineGrained: `github_pat_${'B'.repeat(60)}`,
  stripeLive: `sk_live_${'C'.repeat(24)}`,
  stripeTest: `sk_test_${'D'.repeat(24)}`,
  stripeRestricted: `rk_live_${'E'.repeat(24)}`,
  // These two keep the shape of real dashboard keys — underscores, hyphens, and a random
  // portion that is not especially long — because a pattern tuned to a guessed length would
  // miss them. That property is the point of the test using them; do not "tidy" them into
  // repeated characters.
  supabasePublishable: `${SB}publishable_DL1Fq_t8GpJvI8iDfD1Yfw_QZ84-Aq`,
  supabaseSecret: `${SB}secret_3or9M-xK2vLpQ7wRt4zYn`,
};

/** Minimal stand-in for a fetch Response. */
export function fakeResponse({ status = 200, headers = {}, body = {} } = {}) {
  const lower = new Map(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => (lower.has(name.toLowerCase()) ? lower.get(name.toLowerCase()) : null) },
    json: async () => body,
  };
}

/** A fetch stub that records where it was asked to go. */
export function recordingFetch(handler) {
  const calls = [];
  const impl = async (url, options) => {
    calls.push({ url: String(url), options });
    return handler(String(url), options);
  };
  impl.calls = calls;
  return impl;
}
