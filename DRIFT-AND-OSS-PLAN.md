# BlastRadius — API Drift Detection & Open-Source Plan

Added: 2026-07-27. Planning input, not yet an execution plan.

Answers the one Stage 1 score that still binds after the free-tool decision:
**maintenance burden 5 — a permanent provider-API treadmill.**

Two mechanisms, in a deliberate order. The drift scanner is a **prerequisite** for
open-sourcing, not a parallel track. Reasoning in "Sequencing" below.

---

## 1. The failure mode being defended against

The risk is not a provider API going down loudly — that surfaces immediately as an error
and gets fixed. The risk is **silent semantic drift**:

- Supabase renames or re-classes a key type
- Stripe adds a restricted-key permission that BlastRadius does not know how to read
- GitHub changes what `X-OAuth-Scopes` returns for fine-grained tokens
- A provider adds a destructive capability to a scope that was previously read-only

In each case BlastRadius keeps running, keeps returning a confident report, and is now
**wrong**. That is the false-confidence risk already recorded as open question 4 in
the project's founding case, and drift is its single most likely cause. A tool that says
"no blast radius found" and is wrong is worse than no tool.

## 2. Mechanism A — contract tests (primary, deterministic)

A scheduled CI job (weekly is sufficient — provider auth models do not change daily)
that, for each provider module:

1. Authenticates with a **known-scope test credential** held as a CI secret.
2. Calls the introspection endpoint the module depends on.
3. Asserts the parsed result equals the expected scope set — the credential's privileges
   are known in advance, so any divergence is either provider drift or a module bug.
4. Fails loudly, naming the provider and the specific assertion that broke.

This catches real breakage deterministically, including changes a provider never
announced. It is the mechanism that actually protects correctness.

**The practical obstacle, stated honestly:** this requires holding a live, deliberately
low-privilege credential for every supported provider. That means an account per provider,
some with a paid floor, and a set of long-lived CI secrets that themselves need rotation —
mildly ironic for this tool in particular, and worth designing for (short-lived tokens
where the provider supports them; never grant the test credential a destructive scope).
Providers where a test credential cannot be obtained cheaply are exactly the providers
that should not ship in v1.

## 3. Mechanism B — changelog scanner (complementary, early-warning)

Watches each integrated provider's changelog, API release notes, and deprecation feed,
filtered to auth/permission/token-relevant terms (scope, permission, token, key, deprecat*,
breaking, sunset, retire, IAM, least privilege).

This does something contract tests cannot: it catches **announced** changes *before* they
take effect, giving lead time on deprecations rather than discovering them on the cutover
date. It also covers providers where holding a test credential is impractical.

Source quality varies and the design should reflect that:

- **Machine-readable where available** — several providers publish RSS/Atom or a
  structured changelog; consume those directly.
- **Diff-and-summarise where not** — fetch the changelog page, diff against last seen
  state, and summarise only what changed. Do not re-read the whole page every run.
- **Ruthless filtering.** An unfiltered changelog watcher produces noise, gets ignored,
  and is then worse than nothing because it creates the appearance of coverage. Alerts
  must be rare enough to be read.

Output goes to a maintainer-facing digest, not to end users.

### What the first live run actually found (2026-07-27)

The scanner was run against all six providers for real, and the results revise what this
mechanism can honestly promise. Three of the six sources were broken in ways that all
produced *silence* rather than errors — which is the precise failure this section warns
about, arriving on day one.

| Provider | First run | Now |
|---|---|---|
| Supabase | ✅ 13 relevant entries | ✅ |
| Vercel | ❌ JS-rendered page, 0 entries | ✅ 14 entries — switched to `vercel.com/atom` |
| Cloudflare | ❌ feed URL 404 | ✅ 8 entries — correct path is `/changelog/rss.xml` |
| GitHub | ❌ per-label feed 404 | ✅ whole-changelog feed, filter does the narrowing |
| Stripe | ⚠️ served in **German** | ✅ fixed with an `accept-language` header |
| Railway | ❌ 1 "entry": the page tagline | ⛔ **declared unwatchable** |

Four lessons, all of which changed the code:

1. **A source yielding nothing must be an error.** Vercel, Railway and Stripe all returned
   HTTP 200 and reported no news. A watcher that fetches successfully and parses nothing is
   indistinguishable from a quiet week.
2. **Zero was the wrong threshold.** Railway parses to exactly *one* heading — "Weekly
   product updates since 2021", the page's own tagline — so a zero-check passed it as
   healthy. The guard is now `< 3 entries`, on the reasoning that no real changelog is that
   short and a handful means the parse failed.
3. **Locale is an attack on the filter.** `docs.stripe.com` served German, and every entry
   silently failed the English-vocabulary `RELEVANT` regex. The scanner now sends
   `accept-language: en-US,en;q=0.9`. Worth remembering that the filter's language is a
   dependency, not a detail.
4. **Some providers simply cannot be watched.** Railway publishes no RSS and renders its
   changelog client-side; every alternative path 404s. Rather than fail weekly until someone
   mutes it, a provider can now declare `changelog.unwatchable` with a mandatory `note`, and
   the scanner prints it as a standing blind spot on every run.

### The coverage invariant

Added 2026-07-27, after two separate scares turned out to be the same shape.

The worry was Railway: no machine-readable changelog at all, so Mechanism B cannot see it.
Then Supabase turned out to have the opposite problem — its changelog is the best of the six,
but its contract test barely tests anything, because classification is **entirely offline**.
A publishable key is identified from its prefix and a legacy key from its JWT claims, so
`introspect` never calls Supabase and the test asserts our own parsing against a stored
string. It pins the key format; it cannot detect provider drift.

Stating both together makes the actual rule obvious, and it is weaker than section 2 implies:

> **Every provider must have at least one mechanism that touches the live world.
> Not both.**

| Provider | Changelog (B) | Contract test (A) | Live coverage |
|---|---|---|---|
| GitHub | ✅ RSS | ✅ `GET /user` | both |
| Stripe | ✅ (after the locale fix) | ✅ `GET /v1/account` | both |
| Vercel | ✅ Atom | ✅ `GET /v2/user` | both |
| Cloudflare | ✅ RSS | ✅ verify endpoint | both |
| Railway | ⛔ none exists | ✅ `me` query | **A only** |
| Supabase | ✅ strong | ⚠️ offline — format pin only | **B only** |

Both edge cases satisfy the invariant, which is why neither is the crisis it first looked
like. Railway is defended by a live API call every week; Supabase is defended by a changelog
that demonstrably produces relevant hits. What would be genuinely unacceptable is a provider
with *neither* — an offline-classifying provider whose changelog is also unwatchable would
be pure assertion, correct only for as long as nobody looked.

**This is the check to run before adding any provider**, and it is now the first question in
`CONTRIBUTING.md`. "Can it be contract-tested?" was the wrong question; "which mechanism
covers this one, and does it touch reality?" is the right one.

**The Railway caveat that remains.** Its single mechanism is the one with a human dependency:
a test credential on a throwaway account that must not expire. If that credential lapses,
Railway silently drops to zero live coverage while the build stays green — the contract test
skips when no credential is configured. That specific failure is why the rotation runbook
matters more for Railway than for anyone else.

## 4. Mechanism C — staleness surfaced in the report

The cheapest and possibly highest-value piece. Every provider module carries a
`lastVerified` date, stamped by the last passing contract test, and the user-facing report
shows it:

> `stripe` — last verified against live API 2026-07-19
> `railway` — **last verified 2026-02-03 — treat this result with caution**

This converts silent wrongness into a visible caveat. Even if drift is missed entirely,
the user is told how much to trust the finding. Modules past a staleness threshold should
degrade to a warning rather than reporting confidently.

## 5. Sequencing — why the scanner comes before open-sourcing

The intent is to open-source once stable so contributors can add provider integrations by
pull request. That is the right long-term shape and the "stabilise first" ordering is
correct: opening early means shipping architecture churn onto contributors, and the
provider-module interface is exactly the thing that will churn most.

**The honest caveat:** community PRs trade maintenance burden for *review* burden, and for
a security tool that is not obviously a smaller number. A wrong community-contributed
scope mapping is a wrong "this token is harmless" — the worst output this tool can
produce, arriving through the door that is hardest to police, because reviewing it means
independently knowing a provider's permission model well enough to catch a subtle error.

What makes it tractable is the contract-test harness above. If a provider module **cannot
be merged without a passing contract test**, review becomes largely mechanical — the test
proves the mapping against the live API rather than the maintainer adjudicating someone
else's reading of a permissions doc. That is why the scanner is a prerequisite: it is the
thing that makes community contribution safe, not merely convenient.

Concrete gates before opening the repo:

1. Provider-module interface stable across at least two consecutive additions without
   a breaking change to the interface itself.
2. Contract-test harness in place, and **required** in CI for any new provider module.
3. A documented provider-module contract: required exports, the shape of a scope-to-
   consequence mapping, staleness metadata, and how to supply a test credential.
4. A stated policy on test credentials for contributed providers — who holds them, who
   pays for the account, and what happens when a contributor disappears and their
   provider's tests start failing. This is the most likely long-term failure point and
   should have an answer before the first external PR, not after.
5. `CONTRIBUTING.md` that says plainly: a module that cannot be contract-tested will not
   be merged.

## 6. Effect on the Stage 1 scoring

Maintenance was scored **5** and called the binding constraint. These mechanisms do not
eliminate the treadmill — nothing does — but they change its character from *silent
correctness decay* to *a loud, scheduled, mechanical chore*, and eventually distribute it.

The scoring should not be revised upward on the strength of a plan. Revise it if and when
the harness exists and has caught a real drift event.

## 7. Open questions this raises

1. Which providers can supply a cheap, low-privilege, long-lived test credential? This
   should now be a **selection criterion** for the v1 provider list, alongside the
   "fewer, deeper modules" principle already recorded.
2. Does the changelog scanner ship inside the repo as a maintainer tool, or as a separate
   internal service? In-repo is simpler and dogfoods the CI story.
3. Is the changelog scanner itself independently useful enough to be its own small free
   tool? Noted and deliberately **not** pursued — it is a distraction from the reason
   BlastRadius exists.
