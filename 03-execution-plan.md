# BlastRadius — Execution Plan

Written: 2026-07-27. Phase 0 is complete and in this repo; Phases 1–5 are the plan.

Stage 2 is `N/A by decision` — this is a free tool. So this plan optimises for
**correctness and low maintenance**, not for revenue or growth.

---

## Guiding constraints

Three, in priority order. When they conflict, the higher one wins.

1. **A wrong "harmless" is the only unacceptable output.** Under-reporting is the failure
   direction that gets someone hurt. Over-reporting is annoying. Design every trade-off
   toward loud uncertainty.
2. **Maintenance is the binding cost** (Stage 1 scored it 5/10, the lowest score that
   survives the free-tool decision). Every provider is a permanent liability. Narrow
   coverage that stays correct beats broad coverage that rots.
3. **Never become the breach.** A tool that reads every credential on a developer's
   machine is a target. The egress guard and the redaction layer are not features.

## Non-goals — write these down so they stop coming back

- No web app, no hosted service, no accounts, no telemetry. A CLI that phones home about
  credential findings is an unacceptable product shape here.
- No paid tier. Recorded in `STATUS.md`; not to be relitigated without a new decision.
- No generic secret scanning. TruffleHog and gitleaks do that better and free. If a
  credential's provider has no module, BlastRadius should be quiet about it, not guess.
- No remediation-by-automation (rotating or revoking keys on the user's behalf) in v1.
  Enormous blast radius of its own, and it inverts the trust model.

---

## Phase 0 — Scaffold ✅ COMPLETE

In this repo, 61 unit tests passing, CLI runs end to end.

| Built | Where |
|---|---|
| Capability taxonomy + catastrophic severity amplifier | `src/core/capabilities.mjs` |
| Redaction and fingerprinting | `src/core/redact.mjs` |
| Pass 1 — reachability discovery | `src/core/discover.mjs` |
| Pass 2 — privilege resolution + egress guard | `src/core/resolve.mjs` |
| Report rendering, CI exit codes | `src/core/report.mjs` |
| Provider contract + validator | `src/providers/_contract.mjs` |
| Reference providers | `src/providers/github.mjs`, `stripe.mjs` |
| Contract-test harness | `test/contract/` |
| Changelog scanner | `tools/changelog-scan.mjs` |
| CI workflows | `.github/workflows/` |
| Contribution gates | `CONTRIBUTING.md` |

**Two design decisions worth knowing about**, both made during the build:

- **`apiHosts` egress allowlist.** Each provider declares every host it may send a
  credential to; `guardedFetch` blocks everything else and all plaintext HTTP. This was
  added specifically to make the open-source step safe — a hostile provider PR cannot
  exfiltrate, so reviewing a module means reading one array rather than auditing every
  fetch call.
- **`unresolved` as a first-class state.** Distinct from "no capabilities". A fine-grained
  GitHub PAT and a Stripe restricted key both return `unresolved`, and the reporter renders
  it louder than `low`. The first smoke test caught a violation of this in discover-only
  mode (`worst case: NONE`); fixed, with a regression test.

---

## Phase 1 — Provider coverage that stays correct
**Effort: ~1.5 weeks. Exit criteria: 5–6 providers, each with a green contract test.**

> **STATUS 2026-07-27: code complete, 6 providers shipped, 93 unit tests green.** The exit
> criterion is *not* met and cannot be met in this phase — a green contract test requires
> live test credentials, which is Phase 2 account admin. Provider modules are written
> against documented API behaviour and verified against fixtures; they are **not yet
> verified against the live APIs**. Every `lastVerified` date below is provisional until
> Phase 2 stamps it.
>
> **The plan's Cloudflare premise was wrong and it changed the design.** This phase assumed
> `/user/tokens/verify` "returns status and scopes cleanly". It does not: the documented
> response is `{id, status, expires_on, not_before}` — no policies, no permission groups. A
> token cannot read its own permissions without holding "User API Tokens Read", which
> effectively no deployment token does. Cloudflare therefore reports every live token as
> `unresolved`, which is a less satisfying finding than planned and the only honest one.
> This is precisely the failure the `unresolved` state was built for, so the design absorbed
> it without change — but it is a warning about the other entries in the table below: the
> introspection column was written from memory, not from the docs, and Cloudflare was the
> one that got checked.
>
> **AWS was cut from this phase, per the plan's own instruction to be willing to cut it.**
> Reasoning in "Open decisions" below.

Provider selection is driven by one criterion that was *not* obvious at Stage 1:
**can a low-privilege test credential be obtained cheaply and held indefinitely?** A
provider that cannot be contract-tested cannot be kept correct, so it should not ship.

Ranked by that criterion crossed with how often agents actually hold the credential:

| Provider | Test cred cost | Introspection | Status |
|---|---|---|---|
| GitHub | free | `X-OAuth-Scopes` header | ✅ built (Phase 0) |
| Stripe | free (test mode) | key prefix + `/v1/account` | ✅ built (Phase 0) |
| Railway | paid floor | `me` GraphQL query | ✅ built — resolves fully |
| Supabase | free tier | key class from prefix/JWT claims | ✅ built — resolves offline |
| Vercel | free (hobby) | `/v2/user` | ✅ built — resolves fully |
| Cloudflare | free tier | `/user/tokens/verify` | ✅ built — **always `unresolved`** |
| AWS | free tier, complex | STS + IAM policy simulation | ❌ **cut** — see below |

Tasks:

- [x] Cloudflare module. ~~Token verify returns status and scopes cleanly~~ — **it does
      not.** Verify returns status only. Module reports liveness and `unresolved`.
- [x] Vercel module. Confirmed: Vercel tokens scope to a user or team and nothing narrower
      (project-level scoping is an open feature request, not a setting). A live token reads
      decrypted env vars and can delete projects. The `limited` user shape from `/v2/user`
      is handled as `unresolved`.
- [x] Supabase module. `anon` vs `publishable` vs `service_role` — **`service_role`
      bypasses RLS entirely**, mapped to `read:data` + `write:data` + `destroy:data`.
      Resolves **entirely offline**, which is a better privacy property than planned:
      classification comes from the key prefix or JWT `role` claim, so nothing leaves the
      machine. Management tokens (`sbp_`) verify against the fixed host `api.supabase.com`
      and rate `catastrophic` — deleting a project takes its backups with it.
- [x] Railway module. Confirmed from Railway's own docs: tokens "inherit the full
      permissions of the generating user; there are no scopes, no service accounts, and no
      fine-grained token controls". An account token therefore maps to the full destructive
      set and rates `catastrophic` — data and backups in one credential, which is the
      reference-incident shape exactly. Project tokens report `unresolved`: their reach is narrower
      but whether it includes volume deletion is not determinable without a live credential,
      and guessing "probably safe" there is the one unacceptable direction.
- [x] Expand `discover.mjs` beyond regex matching: structural `.env` parsing (handles
      `export`, quoting, trailing comments) and real MCP/agent config parsing — `env`
      blocks, `--flag=value` arguments, and headers, walked structurally rather than
      regexed.
- [x] **Context-aware patterns** — not in the original plan, and required. Railway issues
      bare UUIDs and Vercel 24 undistinguished alphanumerics; matching those on shape alone
      would bury every real finding under lockfile noise. Provider patterns may now declare
      a capture group anchored on the variable name, with group 1 as the credential.
      Environment variables are matched as `KEY=value` so the name is visible to the pattern.
- [x] Entropy heuristic — shipped, gated harder than planned. See below.

**Known gap closed:** discovery is pattern-based, so a credential in an unrecognised format
was invisible. The heuristic now reports "possible unrecognised credential" in a separate
section, never resolved, never folded into the severity summary.

Two deliberate departures from how the plan described it:

1. **Context is required, not just entropy.** The key name must tokenise to something
   secret-shaped (`privateKey`, `DB_PASSWORD`), and known-innocent shapes — lockfile
   integrity hashes, git SHAs, UUIDs, placeholders — are excluded outright. Entropy alone
   flags every base64 blob in a repo, gets muted, and a muted warning is worse than none
   because it manufactures the appearance of coverage.
2. **It does not fail CI by default.** `--fail-on-unrecognised` opts in. This looks
   inconsistent with `unknown` failing by default, and the distinction is real: an `unknown`
   finding is a credential we identified and could not assess, whereas an unrecognised one
   is a guess about whether it is a credential at all. A gate that fires on config noise
   gets disabled, taking the trustworthy half of the signal with it.

---

## Phase 2 — Turn on the drift machinery
**Effort: ~3 days, mostly account admin. Exit criteria: a scheduled green contract run and one real changelog digest.**

This is the phase that makes the free tool sustainable. It is boring and it is the whole
maintenance strategy.

- [ ] Create a dedicated account per provider for test credentials. Do not use personal
      accounts — an orphaned personal credential is a permanent CI failure.
- [ ] Issue minimal-scope test credentials. **Never a destructive scope.**
- [ ] Store as repo secrets; record expected scopes as repo *variables*
      (`BLASTRADIUS_EXPECT_*`) so drift shows as an assertion diff.
- [ ] First green scheduled `contract-tests` run; stamp `lastVerified` on every module.
- [ ] First `changelog-scan` run; tune `RELEVANT` if the digest is noisy. **If the first
      digest is unreadable, fix the filter before doing anything else** — a noisy watcher
      gets ignored and then manufactures false confidence.
- [ ] Document the rotation runbook: what to do when a test credential expires, and how to
      tell that apart from real provider drift. These look identical in CI and confusing
      them is how a real drift event gets waved through.

---

## Phase 3 — Pre-flight guard — DECIDE, don't drift into it
**Effort: 1 week if yes. Recommendation: defer past v1.**

The guard (an agent checks blast radius before a destructive call) is the most interesting
piece and was flagged at Stage 1 as the most likely to over-scope the build. It is a
different product shape: a runtime integration rather than a scanner, with a per-agent
integration surface that multiplies maintenance.

**Recommendation: ship v1 without it.** Revisit only if the scanner gets real usage.

The cheap version, if the itch needs scratching: a documented exit-code contract plus a
`--fail-on catastrophic` invocation people can put in their own agent hooks. That gets
most of the value with none of the integration surface.

- [ ] Decide explicitly at the end of Phase 2, in writing, and record it here.

---

## Phase 4 — Launch
**Effort: ~4 days. Exit criteria: published, with a demo that survives skepticism.**

- [ ] Reproduce the reference scenario as a demo: a free-tier project, an over-scoped
      token, and BlastRadius flagging `catastrophic` before anything is deleted. This is
      the entire pitch and it must be real, not a mock.
- [x] **Verify the incident narrative against primary sources before publishing.** ✅ Done
      2026-07-27 — see the verification log in `INCIDENTS.md`. The mechanism, date, nine
      seconds and ~30-hour recovery all hold; the claim that the agent "scanned the
      codebase" did not and has been corrected throughout. Public copy is now told in the
      abstract, with the named account confined to `INCIDENTS.md` as a citation.
- [ ] npm publish; `npx blastradius` must work with zero install.
- [ ] Write-up leading with the incident mechanism, not the tool. Show-HN shaped.
- [ ] Submit to relevant awesome-lists and the OWASP agentic-security reading lists.

**Distribution reality check:** Stage 1 scored distribution 7/10 on the strength of the
incident hook. That hook decays. If launch slips much past the incident's news cycle, the
honest expectation is a quieter reception — that is an argument for shipping narrow and
soon rather than complete and late.

---

## Phase 5 — Open source for community providers
**Gated on Phase 2 being genuinely stable. Do not rush this.**

Reasoning and the honest caveat about review burden are in `DRIFT-AND-OSS-PLAN.md`.

Gates, all required:

- [ ] Provider interface stable across two consecutive additions with no breaking change
      to the interface itself.
- [ ] Contract tests required in CI for any new provider module.
- [ ] `CONTRIBUTING.md` live (✅ written in Phase 0).
- [ ] A written policy on who holds and pays for contributed test credentials, and what
      happens when a contributor disappears. **This is the most likely long-term failure
      point** and needs an answer before the first external PR, not after.
- [ ] A stated support posture: this is a free tool, maintained on a best-effort basis.
      Say so plainly in the README rather than accumulating silent obligation.

---

## Sequencing summary

```
Phase 1 (providers) ──► Phase 2 (drift machinery) ──► Phase 4 (launch) ──► Phase 5 (OSS)
                                    │
                                    └──► Phase 3 (guard) — decide, probably defer
```

Roughly **3 weeks** to launch with 6 providers, on the Stage 1 estimate of 2–3 weeks for
a CLI plus 8–10 provider modules. That estimate assumed provider modules were the work;
in practice the contract-test credential administration is the underestimated part.

## Open decisions

1. ~~**AWS in v1 or not?**~~ **DECIDED 2026-07-27: cut from v1.** Three reasons, in order of
   weight. (a) Introspection needs SigV4 request signing hand-rolled against the zero-
   dependency constraint, and then `iam:SimulatePrincipalPolicy` — which the credential
   being tested is usually not permitted to call, so the common outcome is `unresolved`
   anyway, after ~150 lines of crypto. (b) Mapping IAM policy to capability verbs is the
   single most likely place in this codebase to be confidently wrong, and confidently wrong
   is the one output guiding constraint #1 forbids. (c) It cannot be contract-tested without
   a dedicated AWS account, which is Phase 2 work that does not exist yet. The plan already
   said "if it exceeds 3 days, ship without it — a missing provider is better than a wrong
   one"; this is that instruction being followed rather than overridden.
   **Consequence to accept, verified not assumed:** `~/.aws/credentials` is on the discovery
   path, so the credential is *found* but never classified. Specifically —
   `aws_secret_access_key` surfaces through the unrecognised-credential heuristic (entropy
   4.66), while `aws_access_key_id` does not, because `AKIA…` is uppercase-plus-digits only
   and fails the three-character-class test. That is the right half to catch and the wrong
   half to miss quietly. Locked in by a regression test so a future entropy tweak cannot
   silently drop it. Visible ignorance is the correct failure mode here, but this remains a
   real coverage gap for the most consequential cloud provider. Revisit once Phase 2 has
   proven the contract harness.
2. **Entropy heuristic for unrecognised credentials** — improves honest coverage, risks
   false positives that erode trust. Prototype in Phase 1 and judge on real output.
3. **Pre-flight guard** — decide at end of Phase 2 (Phase 3 above).
4. **Repo public from the start, or at Phase 5?** Public early builds the launch
   narrative; public early with an unstable provider interface is what
   `DRIFT-AND-OSS-PLAN.md` warns against. Suggest: public repo at Phase 4 launch,
   *contributions* opened at Phase 5, with the distinction stated in the README.
