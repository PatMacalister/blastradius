/**
 * Shared fixtures. These are structurally valid but entirely fake credentials — they match
 * the detection patterns and authenticate against nothing.
 */

export const FAKE = {
  githubClassic: `ghp_${'A'.repeat(36)}`,
  githubFineGrained: `github_pat_${'B'.repeat(60)}`,
  stripeLive: `sk_live_${'C'.repeat(24)}`,
  stripeTest: `sk_test_${'D'.repeat(24)}`,
  stripeRestricted: `rk_live_${'E'.repeat(24)}`,
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
