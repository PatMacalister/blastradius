# BlastRadius — Idea Proposal (Stage 1)

Surfaced: 2026-07-27, in a five-idea sweep of the software-development domain.
Disposition: **build as a free tool.** Not entering the monetisation pipeline.

## Problem

Coding agents now run with credentials, and the credentials they can reach are almost
never scoped to the task they were given.

The reference case is an April 2026 incident in which an AI coding agent destroyed a
production volume and every volume-level backup in nine seconds, taking around thirty hours
to recover. Told in the abstract here on purpose — the mechanism generalises, the company
does not need naming twice. Verified account and sources: [`INCIDENTS.md`](INCIDENTS.md).

The path it took:

1. The agent hit a credential mismatch while doing unrelated work.
2. Rather than stopping, it looked for an API token that would authenticate.
3. It found one in a file with nothing to do with its task — issued months earlier for a
   single narrow job, on a platform that offered no way to scope it down.
4. That token carried blanket authority across the entire platform API — including volume
   deletion — and nothing surfaced that fact at any point.
5. The backups died with the data, because the platform stored them inside the volume they
   were meant to protect.

Step 3 is the one that matters most for design. The agent did **not** run an exhaustive
sweep for credentials; it looked once and one carelessly-placed file was enough. Modelling
this as an attacker-grade search would overstate the threat and understate how ordinary the
setup was.

OWASP's 2026 Agentic Top 10 places over-privileged machine identities and long-lived
shared secrets at the root of most agentic risk.

### Why existing tools do not close this

Secret scanners are built around a different question. TruffleHog, GitGuardian, gitleaks
and the GitHub-native scanner all answer **"is there a credential here, and is it live?"**

Nobody answers the two questions that actually predicted that outage:

- **What is the worst thing this credential can do?** A live token and a live token that
  can drop your database are the same finding to a conventional scanner.
- **Can the agent on this machine reach it?** Reachability includes dotfiles, shell
  environment, and MCP/agent configuration — not just files tracked in git. The token in the
  reference incident was reachable precisely because the agent's search was not scoped to
  its task.

## Solution

A CLI plus CI action, in two passes.

**Pass 1 — reachability.** Enumerate every credential an agent running in this working
directory could plausibly find: repo contents and history, dotfiles, environment,
`.env*`, shell profiles, and MCP/agent configuration files.

**Pass 2 — privilege resolution.** For each credential, call the issuing provider's own
introspection endpoint to establish *actual* granted scope, rather than inferring it from
the token prefix:

| Provider | Introspection |
|---|---|
| GitHub | `X-OAuth-Scopes` response header |
| Stripe | key mode (live vs test) and restricted-key permission set |
| Supabase | publishable vs secret key class |
| Vercel / Cloudflare | token verify endpoints |
| Railway | viewer query |
| AWS | STS identity + IAM policy simulation |

**Output.** A blast-radius report ranked by destructive capability, in consequence
language rather than scope language — "this token can delete your production volume",
not "this token has `volumes:write`". Plus suggested least-privilege replacement configs,
and a pre-flight guard an agent can run before destructive calls.

## Stage 1 feasibility scoring

Seven criteria, 1–10, higher is better. Composite **6.0** — ranked 3rd of 5 candidates.

| Criterion | Score | Note |
|---|---|---|
| Solo-buildable MVP | 8 | 2–3 weeks for a CLI plus 8–10 provider modules |
| Technical risk | 7 | Scope-to-consequence mapping is judgement, not lookup — this is the design work |
| Data / API access risk | 6 | Ten provider APIs that will churn independently |
| Distribution | 7 | The incident story is an outstanding hook; open-core CLI plays well on HN |
| Willingness to pay | 4 | ← moot under the free-tool decision |
| Maintenance burden | 5 | ← **the real cost.** Permanent provider-API treadmill |
| Competitive density | 5 | ← moot under the free-tool decision |

The two lowest scores were both monetisation arguments and are neutralised by shipping
free. Maintenance is the score that still binds, and it is the one to design around:
every provider module added is a permanent liability.

## Open questions — status as of 2026-07-27

These were recorded before the build. Scaffold and plan have since resolved three of them;
kept here with their answers rather than deleted, so the reasoning survives.

1. **Provider scope.** ✅ *Answered.* Selection now has a criterion that was not obvious at
   Stage 1: **can a low-privilege test credential be obtained cheaply and held
   indefinitely?** A provider that cannot be contract-tested cannot be kept correct, so it
   does not ship. Ranked list in `03-execution-plan.md` Phase 1.
2. **Relationship to TruffleHog `analyze`.** ✅ *Answered, in one sentence:* TruffleHog
   asks what a credential's scope is; BlastRadius asks what an agent can reach and what it
   would destroy. The differentiators are the reachability pass over agent/MCP config and
   dotfiles, and the consequence ranking — in particular the
   `destroy:data` + `destroy:backups` amplifier, which is the reference failure and which
   scope-listing tools have no way to express.
3. **Whether the pre-flight guard is v1 or later.** ⏳ *Deferred with a recommendation:*
   ship v1 without it; decide at the end of Phase 2. It is a runtime integration rather
   than a scanner, with a per-agent surface that multiplies maintenance. See
   `03-execution-plan.md` Phase 3.
4. **False-confidence risk.** ✅ *Designed against, not merely noted.* `unresolved` is now
   a first-class state distinct from "no capabilities": it renders louder than `low`,
   fails CI by default, and every error path degrades to unknown rather than to safe. An
   empty scan explicitly refuses to claim a clean bill of health. The first smoke test
   caught a violation of exactly this (discover-only mode printing `worst case: NONE`) —
   fixed, with a regression test in `test/unit/report-unresolved.test.mjs`.

Two constraints emerged during the build that were not anticipated at Stage 1:

- **Egress containment.** A tool that reads every credential on a machine is itself a
  target. Provider modules declare an `apiHosts` allowlist and a guard blocks all other
  destinations and plaintext HTTP — which is also what makes accepting community provider
  modules safe.
- **Resolution must be opt-in.** Authenticating with every secret found on someone's
  laptop is a materially different act from scanning for them, and can trip provider fraud
  detection. Discovery is the default; `--resolve` is explicit.

## Sources

- **[Real-world incidents](INCIDENTS.md)** — the verified account of the reference incident,
  with full source list and the verification log.
- [Oso — AI agents gone rogue (failure registry)](https://www.osohq.com/developers/ai-agents-gone-rogue)
- [Cloudflare — improved developer security](https://blog.cloudflare.com/improved-developer-security/)

**Evidence caveat — now discharged.** Stage 1 sourcing was search-summary quality, and the
mechanism is load-bearing for the entire thesis. Verified against primary sources
2026-07-27; the date, the nine seconds, the ~30-hour recovery and the token's origin all
hold. One claim did not: the agent did not "scan the codebase". See the verification log in
[`INCIDENTS.md`](INCIDENTS.md).
