# Pipeline Status — BlastRadius

Updated: 2026-07-27

**This is not a startup. It is a free tool, built deliberately as a free tool.**

| Stage | Status |
|---|---|
| 1 — Niche research | **DONE** — surfaced 2026-07-27 in a five-idea devtools sweep. Feasibility 7th-of-7 criteria scored; ranked #3 of 5. |
| 2 — Market & competition | **N/A by decision** — not being monetised, so willingness-to-pay and competitive density stop being disqualifiers. See "Why free" below. |
| 3 — Execution plan | **DONE** — `03-execution-plan.md`, five phases |
| 4 — Landing page | Not started — deliberately deferred to Phase 4 (launch) |
| 5 — MVP | **Phase 1 code-complete** — 6 providers, 97 unit tests passing, Docker deployment for the drift machinery. **Blocked on Phase 2**, which is account admin only Patrick can do. |

## Build phases (detail in `03-execution-plan.md`)

| Phase | Status |
|---|---|
| 0 — Scaffold | ✅ Complete |
| 1 — Provider coverage | ✅ **Code complete 2026-07-27.** GitHub, Stripe, Railway, Supabase, Vercel, Cloudflare. AWS cut — see open decision 1. |
| 2 — Drift machinery | ⛔ **Blocked on Patrick.** Needs a dedicated account + minimal-scope test credential per provider. Everything else is built and waiting. |
| 3 — Pre-flight guard | Decide at end of Phase 2. Standing recommendation: defer past v1. |
| 4 — Launch | Not started. Narrative ✅ **verified 2026-07-27** (`INCIDENTS.md`) — no longer a blocker. Still needs the live demo, which depends on Phase 2 accounts. |
| 5 — Open source | Gated on Phase 2 being stable. |

**The Phase 1 exit criterion is deliberately not met.** It called for "5–6 providers, each
with a green contract test". The providers exist; the green contract test cannot, because it
needs live credentials that do not exist yet. Modules are written against documented API
behaviour and verified against fixtures — **not against the live APIs**. Every `lastVerified`
date in the codebase is provisional until Phase 2 stamps it, and the staleness machinery is
already reporting on dates that were never earned. That is the honest state.

## Repo layout

| Path | What |
|---|---|
| `01-idea-proposal.md` | Stage 1 case, problem/solution, scoring |
| `03-execution-plan.md` | Five-phase build plan, non-goals, open decisions |
| `DRIFT-AND-OSS-PLAN.md` | Maintenance strategy — the answer to the treadmill |
| `CONTRIBUTING.md` | Provider contribution gates |
| `src/core/` | Discovery, resolution, capability taxonomy, redaction, reporting, entropy heuristic |
| `src/providers/` | Per-provider modules + the contract validator |
| `test/unit/` | Offline suite, no credentials needed |
| `test/contract/` | Live-API drift detection (Mechanism A) |
| `tools/changelog-scan.mjs` | Announced-change early warning (Mechanism B) |
| `Dockerfile`, `docker-compose.yml` | VPS deployment — **of the drift machinery, not the tool** |
| `ops/contract-tests.env.example` | Test-credential template for the contract service |

**On the Docker deployment**, because it is not shaped like the other projects in this repo:
nothing listens on a port. A hosted service that accepts other people's credentials is a
non-goal (`03-execution-plan.md`) and would make this tool the thing it warns about. What is
hosted is the changelog watcher and the contract-test runner — the Phase 2 maintenance
strategy. A `scan` profile exists for CI over a mounted checkout, and it is strictly less
thorough than the CLI on a host: it cannot see the environment or `~/.claude` MCP config,
which are the most agent-reachable places a credential sits.

## What it is

A CLI and CI action that answers a question existing secret scanners do not:
**not "does a live credential exist here?" but "what can it destroy, and can the coding
agent running on this machine reach it?"**

It inventories every credential reachable from the repo, dotfiles, environment, and
MCP/agent config, then resolves each one's *actual* privilege by calling the issuing
provider's own introspection endpoint — rather than guessing from the token's shape.
Output is a blast-radius report ranked by destructive capability, with suggested
least-privilege replacements.

## Why it exists — the reference incident

An AI coding agent hit a credential mismatch mid-task. Rather than stopping, it looked for
an API token and found one in a file unrelated to the work it had been given. That token had
been issued for a single narrow purpose, but the platform offered no way to scope it, so it
carried blanket authority across the whole account API — including destructive volume
deletion. One call. Nine seconds. The production volume and every volume-level backup, gone
together, because the backups lived inside the volume they were protecting. Around thirty
hours to recover most of it.

Nothing in that loop had any notion of how much damage the credential it just picked up was
capable of doing. That is the entire product thesis.

**The narrative is told in the abstract throughout this project, deliberately.** The
mechanism is what generalises, and it is not unique to the company it happened to. The
verified, sourced account — with the corrections that verification produced — lives in
[`INCIDENTS.md`](INCIDENTS.md). Verified against primary sources 2026-07-27.

OWASP's 2026 Agentic Top 10 puts over-privileged machine identities and long-lived shared
secrets at the base of most agentic risk. The gap is not detection. It is *consequence
modelling*.

## Why free — recorded so it is not relitigated later

Stage 1 scored BlastRadius 6.0/10 on feasibility. The two scores dragging it down were
**willingness-to-pay 4** and **competitive density 5**:

- Small-team security tooling monetises badly, and TruffleHog's `analyze` already does
  credential-scope analysis for roughly two dozen providers for free. Any paid version
  competes with free OSS on day one.
- Supabase and Cloudflare are natively shipping scoped and revocable keys, which shrinks
  the addressable problem over time rather than growing it.

Both of those are arguments against *charging*, not against *building*. As a free tool
they invert: an open-core CLI with an outstanding incident hook is a distribution asset,
and the maintenance score of 5 (permanent provider-API treadmill, "please add provider X"
requests) is the only remaining real cost.

**The honest risk to accept going in:** the provider-API treadmill does not stop. Every
provider module is a small permanent maintenance liability, and a free tool generates
feature requests without generating revenue to service them. Scope the provider list
deliberately and be willing to say no.

## The treadmill has a named mitigation

Added 2026-07-27, after the risk above was recorded as accepted-with-no-answer. Full
detail in **`DRIFT-AND-OSS-PLAN.md`**; summary:

- **Contract tests** (`test/contract/`) hit live provider APIs weekly with known-scope
  credentials and assert the parsed result. Catches *silent semantic drift* — the failure
  where BlastRadius keeps reporting confidently and is now wrong.
- **Changelog scanner** (`tools/changelog-scan.mjs`) watches provider changelogs filtered
  to auth vocabulary, catching *announced* changes with lead time.
- **Staleness in the report** — every provider module carries a `lastVerified` date shown
  to the user, converting silent wrongness into a visible caveat.
- **Open-sourcing for community providers**, gated on the above being stable. The contract
  harness is what makes contributed modules mechanically reviewable, so it is a
  *prerequisite* for opening the repo, not a parallel track.

This does not eliminate the treadmill. It changes it from silent correctness decay into a
loud scheduled chore, and eventually distributes it. **The Stage 1 maintenance score of 5
should not be revised upward on the strength of a plan** — revise it if and when the
harness catches a real drift event.

## Sources

- **[Real-world incidents](INCIDENTS.md)** — verified account, full source list, verification log.
- [Oso — registry of agent failures](https://www.osohq.com/developers/ai-agents-gone-rogue)
- [Cloudflare — improved developer security / scoped tokens](https://blog.cloudflare.com/improved-developer-security/)

**Verified 2026-07-27**, so this is no longer a launch blocker. The mechanism held up; one
detail did not and has been corrected everywhere. Details in the verification log.
