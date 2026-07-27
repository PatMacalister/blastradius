# Rotation runbook

**What to do when a contract test goes red.**

This exists to answer one question, because getting it wrong is how a real drift event gets
waved through:

> Did the provider change, or did my test credential expire?

They look identical in CI — both are a red build on a job nobody was watching. The
temptation in both cases is to re-issue the credential, watch the build go green, and move
on. If the cause was actually drift, that re-stamp is how BlastRadius starts reporting
confidently wrong answers to users.

**The rule: never re-stamp `lastVerified` until you know which of the two it was.**

---

## 1. Read which assertion failed

The suite makes two different claims per provider, and they fail differently.

| Failing assertion | Message | Almost always means |
|---|---|---|
| `introspection.valid` | *test credential should be live — rotate it if this fails* | **Credential problem.** Expired, revoked, or wrong. |
| Scope comparison | *SCOPE DRIFT: … returned different scopes than expected* | **Either.** Go to step 2. |
| `rejects a bogus credential` | garbage read as valid | **Module bug.** Not credential, not drift — see §4. |

A `valid` failure is nearly always yours. A scope diff is the ambiguous one.

## 2. Disambiguate a scope diff

Run the introspection by hand and look at what came back:

```bash
node --env-file=ops/contract-tests.env -e "
import('./src/providers/index.mjs').then(async ({ providerById }) => {
  const p = providerById('PROVIDER_ID');
  const { guardedFetch } = await import('./src/core/resolve.mjs');
  const r = await p.introspect(process.env.BLASTRADIUS_TEST_PROVIDER_ID, {
    fetchImpl: guardedFetch(p.apiHosts),
  });
  console.log(JSON.stringify({ valid: r.valid, scopes: r.scopes, notes: r.notes }, null, 2));
});"
```

Then:

- **Scopes are a subset of what you granted, or the identity is missing** → the credential
  was edited or partially revoked. Credential problem.
- **Scopes contain a name you have never seen** → the provider renamed something. **Drift.**
- **Scopes are empty and `unresolved` is true** → the provider changed what its introspection
  endpoint returns. **Drift, and the dangerous kind** — the module has silently stopped being
  able to assess that credential class.
- **Scopes look right but the assertion still fails** → your `BLASTRADIUS_EXPECT_*` is stale.
  Neither drift nor expiry; fix the expectation. (This has already happened once: the Stripe
  template asserted `["test"]` where the module returns `["mode:test","full-access"]`.)

## 3. Per-provider signatures

Observed against the live APIs on 2026-07-27. These are what each provider actually does,
not what its docs say.

| Provider | Bad credential looks like | Notes |
|---|---|---|
| **GitHub** | `401` → `valid: false` | Clean. Classic PATs can also be *revoked for inactivity* after a year — the most likely expiry here. |
| **Stripe** | `401` → `valid: false` | Test-mode keys do not expire. A failure means the key was rolled. |
| **Railway** | **HTTP 200 with a GraphQL `errors` array**, never a 4xx | Status codes tell you nothing. Tokens do not expire, but are invalidated if the account is closed. |
| **Vercel** | `403` → `valid: false` | Tokens **can be created with an expiry date**. If you set one, this is your most likely red build. |
| **Cloudflare** | `401` with `{"code":1000,"message":"Invalid API Token"}` | Tokens can carry a TTL *and* an IP allowlist — a VPS IP change breaks a working token. |
| **Supabase** | Publishable keys are classified **offline** | Cannot fail for credential reasons. A failure here is a module bug or a format change. |

**The one to watch is Vercel**, because an expiring token is the failure mode that looks
exactly like drift and arrives on a schedule you chose months earlier and forgot.

## 4. If `rejects a bogus credential` fails

This is neither drift nor expiry — it means the module is treating garbage as live, and it is
the most serious failure the suite can report. BlastRadius would be telling users they have a
credential they do not have.

The known cause is probing with a request the API answers *unauthenticated*. Railway shipped
with exactly this: `{ __typename }` returns HTTP 200 with data for a garbage token and for no
`Authorization` header at all. Fix by finding a query the API genuinely refuses, and verify it
refuses:

```bash
# Should return an auth error, not data.
curl -s -X POST https://backboard.railway.com/graphql/v2 \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer obviously-not-a-real-credential' \
  -d '{"query":"{ projects { edges { node { id } } } }"}'
```

## 5. Rotating a credential

1. Issue the replacement **before** revoking the old one, so the window is not a red build.
2. Update `ops/contract-tests.env` (or the GitHub Actions secret — whichever you chose; do
   not maintain both, or a rotation leaves one stale and red in a way that mimics drift).
3. Update `BLASTRADIUS_EXPECT_*` **if and only if** you deliberately granted different scopes.
   Changing the expectation to match a surprise is how drift gets absorbed silently.
4. Run `npm run test:contract:local` and confirm green.
5. Revoke the old credential.
6. Only now, if the module was also changed, bump `lastVerified`.

## 6. When the cause was genuinely drift

- Fix the module so it parses the new shape.
- Add a unit test pinning the **new** behaviour, and keep the old one if both forms are live.
- Update `lastVerified`.
- Note it in `DRIFT-AND-OSS-PLAN.md` — the plan says the Stage 1 maintenance score of 5 should
  be revised only when the harness catches a real drift event. This would be that event, and
  it is worth recording that the mechanism paid for itself.

## 7. Credential inventory

Keep this current. An orphaned credential nobody recognises is one nobody dares rotate.

| Provider | Account | Issued | Expires | Where stored |
|---|---|---|---|---|
| GitHub | | | | |
| Stripe | | | test keys do not expire | |
| Railway | | | | |
| Supabase | | | | |
| Vercel | | | ← **set a reminder** | |
| Cloudflare | | | | |
