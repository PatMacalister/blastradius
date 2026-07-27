# Contributing a provider

Read this before opening a PR that adds a provider. The rules exist because of what this
tool outputs: **a wrong "this token is harmless" is worse than no answer at all.** Every
gate below is there to make that specific failure hard to ship.

## The one rule

**A provider module that cannot be contract-tested will not be merged.**

Not "should be" — will not. Review of a scope mapping otherwise requires the maintainer to
independently know your provider's permission model well enough to catch a subtle error,
which does not scale and is not reliable. The contract test proves the mapping against the
live API, and turns review into something mechanical.

## What a provider module must export

See `src/providers/_contract.mjs` for the validator — it runs in CI and in `npm test`.

| Export | Type | Notes |
|---|---|---|
| `id` | string | lowercase slug, matches filename |
| `label` | string | human name for reports |
| `lastVerified` | `YYYY-MM-DD` | stamped only after a green contract run |
| `apiHosts` | string[] | every host the module may send the credential to |
| `changelog` | `{ url, type }` | `rss` or `html`, for the drift scanner |
| `patterns` | array | `{ name, regex, confidence }` for detection |

### Patterns must not match on shape alone when the shape is generic

If your provider's token has a distinctive prefix (`ghp_`, `sk_live_`), match it directly.
If it does not — Railway issues bare UUIDs, Vercel 24 undistinguished alphanumerics —
**anchor the regex on the surrounding variable name and put the credential in capture group
1**. `discover.mjs` takes group 1 as the secret when a group is present.

```js
// Bad: matches every UUID in every fixture file.
{ name: 'token', regex: /[0-9a-f]{8}-[0-9a-f]{4}-.../, confidence: 0.5 }

// Good: matches the credential, not the shape.
{ name: 'token-env', regex: /MYPROVIDER_TOKEN["']?\s*[:=]\s*["']?([0-9a-f-]{36})\b/, confidence: 0.9 }
```

A provider that floods reports with false positives gets the whole tool switched off, which
takes the accurate findings down with it.

### If your provider has no usable changelog, say so

Set `changelog.unwatchable: true` with a mandatory `note` explaining why. The scanner then
reports it as a standing blind spot instead of failing every week until someone mutes it.
Do not point `url` at a JavaScript-rendered page and call it watched — it will fetch 200,
parse nothing, and look exactly like a quiet week. Check with `npm run changelog:scan`
before opening the PR.
| `introspect` | async fn | `(secret, { fetchImpl })` → Introspection |
| `toCapabilities` | fn | Introspection → capability verbs |
| `remediation` | fn | Introspection → least-privilege suggestions |

### `apiHosts` is a hard boundary

`resolve.mjs` wraps every module's `fetchImpl` in a guard that **refuses** to send a
credential to any host not in `apiHosts`, and refuses plaintext HTTP. Wildcards are
rejected by the validator.

This is what makes it safe to accept provider modules from strangers: a module physically
cannot exfiltrate what it discovers. Do not try to work around it — use `fetchImpl`, never
global `fetch`.

### Capability verbs are a closed vocabulary

`toCapabilities` must return verbs from `src/core/capabilities.mjs`. Unknown verbs are a
hard error, because a typo'd verb would silently drop out of severity assessment and
**under-report** risk.

Adding a new verb is a breaking change for every provider. Open an issue first.

### When you cannot determine privileges, say so

Return `unresolved: true`. Never return an empty capability set to mean "probably fine" —
empty renders as harmless, and that is the output that gets someone hurt. See
`stripe.mjs`, which refuses to guess at restricted-key permissions, and `github.mjs`,
which refuses to guess at fine-grained PATs.

## Test credentials

You must be able to supply a live credential for CI:

```
BLASTRADIUS_TEST_<ID>      a live credential with KNOWN, MINIMAL scope
BLASTRADIUS_EXPECT_<ID>    JSON array of the scope strings it should yield
```

Non-negotiable:

- **Never grant a test credential a destructive scope.** It verifies parsing; it should
  not be able to delete anything.
- Prefer providers issuing short-lived or trivially rotated tokens.
- Say in your PR **who holds the credential and who pays for the account.** If that is
  you, say what happens if you stop maintaining the module — an orphaned provider whose
  tests fail forever is worse than an unsupported one, because it trains everyone to
  ignore a red build.

A provider whose test credential cannot be obtained cheaply is a provider we should not
ship. That is a selection criterion, not a disappointment.

## Stamping `lastVerified`

Bump it **only** after a green contract run against the live API. It drives the staleness
warning users see in their reports, so an aspirational date is an actively misleading one.

If a scheduled contract run goes red, do not re-stamp to make it green. Find out whether
the provider changed or the credential expired.

## Checklist

- [ ] `npm test` passes
- [ ] `npm run test:contract` passes with your credential configured
- [ ] `apiHosts` lists only what you actually call, no wildcards
- [ ] `toCapabilities` returns only known verbs
- [ ] Unresolvable cases return `unresolved: true`, never empty
- [ ] `remediation` gives an actionable next step, not a restatement of the problem
- [ ] PR says who holds the test credential
