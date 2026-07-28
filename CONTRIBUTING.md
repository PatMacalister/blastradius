# Contributing a provider

Read this before opening a PR that adds a provider. The rules exist because of what this
tool outputs: **a wrong "this token is harmless" is worse than no answer at all.** Every
gate below is there to make that specific failure hard to ship.

## The one rule

**Every provider must have at least one mechanism that touches the live world.**

There are two, and a module needs one of them working — not both:

- **A contract test** that hits the provider's real API with a known-scope credential and
  asserts the parsed result (`test/contract/`), or
- **A watchable changelog** — RSS, Atom, or an HTML page that actually parses to entries —
  so announced auth changes surface with lead time.

A module with neither is pure assertion: correct only until someone changes something, with
nothing anywhere to notice. That is the merge blocker.

Which one you have determines what your PR must show. If your provider classifies
credentials **offline** — from a prefix or from token claims, as Supabase does — then a
contract test asserts only our own parsing and cannot detect drift. Say so in the PR and
demonstrate the changelog instead: run `npm run changelog:scan` and paste the output. If
your changelog is JavaScript-rendered or has no feed, say so and supply a contract-test
credential.

If you have a live contract test, that is what makes review mechanical: reviewing a scope
mapping otherwise requires the maintainer to independently know your provider's permission
model well enough to catch a subtle error, which does not scale and is not reliable.

## What this repo does and does not take

**Provider modules are the contribution this project wants.** Everything below is about
making those safe to merge from someone nobody here knows.

**The landing page (`public/`) is not open to contributions.** It is published copy for a
tool whose credibility rests on not overclaiming, and its wording is deliberate. Pull
requests changing it will be declined — not because they are unwelcome in spirit, but
because the register is the product. If something on the page is *wrong* — an inaccurate
claim, a broken link, a coverage overstatement — please open an issue. That is the report
this project most wants to receive.

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
| `introspect` | async fn | `(secret, { fetchImpl })` → Introspection |
| `toCapabilities` | fn | Introspection → capability verbs |
| `remediation` | fn | Introspection → least-privilege suggestions |

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

**No nested unbounded quantifiers.** The validator rejects a regex that quantifies a group
already containing `+`, `*` or `{n,}` — `/^(a+)+$/` and friends. These backtrack
catastrophically: measured here, one match against 41 characters took 91 seconds, and
discovery runs every pattern over every line of every file. A scanner that never finishes is
worse than one that fails, because a run still in progress looks like a run that found
nothing. Match a bounded length instead.

### If your provider has no usable changelog, say so

Set `changelog.unwatchable: true` with a mandatory `note` explaining why. The scanner then
reports it as a standing blind spot instead of failing every week until someone mutes it.
Do not point `url` at a JavaScript-rendered page and call it watched — it will fetch 200,
parse nothing, and look exactly like a quiet week. Check with `npm run changelog:scan`
before opening the PR.

### `apiHosts` is a hard boundary

`resolve.mjs` wraps every module's `fetchImpl` in a guard that **refuses** to send a
credential to any host not in `apiHosts`, and refuses plaintext HTTP. Wildcards are
rejected by the validator.

This is what makes it safe to accept provider modules from strangers: a module cannot ship a
discovered credential to a host you did not approve. Do not try to work around it — use
`fetchImpl`, never global `fetch`.

Every redirect hop is re-checked against the allowlist, not just the first request. That gap
was real until 2026-07-28: with the default `redirect: 'follow'`, a module could call its own
declared host, have that host answer `302`, and the request would land anywhere — anything
placed in the URL travelling with it. If your provider's API redirects, every hop must stay
within `apiHosts`.

### What the validator does *not* protect against

Stated plainly, because a contributor and a reviewer should both know where the machine stops
and judgement starts.

- **Module code runs when it is imported, before it is validated.** `index.mjs` imports
  statically; `loadProviders()` checks the shape afterwards. Any top-level statement in a
  contributed module has already executed by then. There is no sandbox.
- **`apiHosts` is checked for shape, never for legitimacy.** `api.totally-real-provider.test`
  is a valid hostname. Only a human reading the PR can tell whether it is the provider's
  actual API. This is the review step that cannot be automated, and it is why provider PRs are
  merged slowly.
- **The pattern check is a heuristic, not a proof.** It catches the backtracking shapes that
  occur in practice. It is not a safety guarantee.

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
