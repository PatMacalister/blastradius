# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

BlastRadius is a zero-dependency Node CLI (Node 20+, ESM `.mjs`, `"type": "module"`) that answers "what can the credentials on this machine actually destroy, and can a coding agent reach them?" It is a free tool, deliberately not a product — see STATUS.md ("Why free"). A hosted service that accepts credentials is an explicit non-goal; nothing in this repo listens on a port.

## Commands

There is no build step, no linter, and nothing to `npm install` — zero runtime dependencies is a design decision, not an accident.

```bash
npm test                                # unit suite (107 tests), offline, no credentials
node --test test/unit/redact.test.mjs   # single test file
node --test --test-name-pattern="fingerprint" test/unit/   # single test by name

npm run test:contract                   # live provider APIs — needs BLASTRADIUS_TEST_* env vars
npm run test:contract:local             # same, loading ops/contract-tests.env (gitignored)
npm run changelog:scan                  # provider changelog drift scan (exit 1 = something relevant)

node src/cli.mjs --help                 # the CLI itself
node src/cli.mjs --providers            # supported providers + lastVerified dates
node src/cli.mjs .                      # discover only — offline, inert
```

**Do not run `node src/cli.mjs . --resolve` against this repo casually.** When
`ops/contract-tests.env` is populated it holds live contract-test credentials, so `--resolve`
authenticates against real Stripe, Supabase and Cloudflare accounts. Discovery without
`--resolve` is offline and inert.

The test scripts pass a **directory** to `node --test`, not a glob. Glob expansion in `node --test` requires Node 22+, and this project supports Node 20 (`engines`, README, and both CI workflows all pin or declare it) — a quoted glob silently becomes a literal path there and the run dies with "Could not find". Keep the directory form when editing these scripts.

Contract tests skip per-provider when `BLASTRADIUS_TEST_<ID>` is unset and still exit 0, which is deliberate: a fork's PR has no secrets and must still run the unit suite and the contract validator. They are not part of `npm test`; they run weekly in CI and on PRs touching `src/providers/**` or `src/core/capabilities.mjs`.

## Architecture

Two-pass pipeline, orchestrated by `src/cli.mjs`:

1. **Discovery** (`src/core/discover.mjs`) — offline, nothing leaves the machine. Walks the working tree *including gitignored files*, the process environment, and agent/MCP config (`~/.claude`, `~/.cursor`, `~/.aws/credentials`, …), because the question is what an agent could find, not what is committed. Provider `patterns` regexes detect candidates; `src/core/entropy.mjs` flags unrecognised high-entropy values under secret-shaped key names as *visible ignorance* rather than letting them pass silently.
2. **Resolution** (`src/core/resolve.mjs`) — opt-in via `--resolve` because it authenticates with every credential found. Calls each provider's `introspect`, maps scopes to capability verbs, assesses severity. Sequential by design: parallel auth bursts look like credential stuffing to provider fraud detection.

`src/core/report.mjs` renders in **consequence language, never scope language** ("can delete your production volume", not "has volumes:write"). Exit codes are the CI/agent-hook contract: 0 clean, 1 at/above `--fail-on` threshold, 2 error.

### Provider modules (`src/providers/`)

Each provider is a module exporting `id`, `label`, `lastVerified`, `apiHosts`, `changelog`, `patterns`, `introspect`, `toCapabilities`, `remediation`. The shape is machine-validated by `src/providers/_contract.mjs`; violations are a **startup failure**, not a warning, because a malformed module would degrade into "no findings", which reads as "you are safe".

Registration in `src/providers/index.mjs` is an explicit import list, not a directory scan — adding a provider must be a visible diff line.

Pattern rule: tokens with a distinctive prefix (`ghp_`, `sk_live_`) match directly; tokens with generic shapes (Railway bare UUIDs, Vercel 24 alphanumerics) must anchor the regex on the surrounding variable name with the credential in capture group 1 — `discover.mjs` takes group 1 as the secret when a group is present.

### Load-bearing invariants

Breaking any of these makes the tool the thing it warns about. They are enforced mechanically; do not route around them.

- **A raw secret never reaches stdout, logs, or reports.** Everything user-facing goes through `fingerprint()`; error messages pass through `scrub()` (`src/core/redact.mjs`).
- **A credential is only ever sent to its issuing provider.** `guardedFetch` in `resolve.mjs` refuses any host not in the module's declared `apiHosts` (no wildcards, HTTPS only). Provider modules must use the injected `fetchImpl`, never global `fetch`. This is what makes community-contributed modules safe to merge.
- **Errors degrade to `unresolved`/`unknown`, never to an empty capability set.** Empty renders as harmless; under-reporting is the failure direction that gets someone hurt. Never return empty capabilities to mean "probably fine" — see `stripe.mjs` (restricted keys) and `github.mjs` (fine-grained PATs) for the honest-refusal pattern.
- **Capability verbs are a closed vocabulary** (`src/core/capabilities.mjs`). Unknown verbs are a hard error because a typo'd verb would silently drop out of severity assessment. Adding a verb is a breaking change for every provider — open an issue first. The severity amplifier: `destroy:data` + `destroy:backups` together escalate to `catastrophic` (the reference incident in INCIDENTS.md).
- **`lastVerified` is stamped only after a green contract run against the live API.** Never bump it to make things look fresh; it drives the user-facing staleness warning (90 days, `STALENESS_WARN_DAYS`).

### Drift machinery

The permanent maintenance answer (DRIFT-AND-OSS-PLAN.md), and what the Docker/compose files actually deploy — they host the drift machinery on a VPS, not the tool:

- **Mechanism A** — contract tests (`test/contract/`) hit live APIs weekly with known-minimal-scope credentials (`BLASTRADIUS_TEST_<ID>` / `BLASTRADIUS_EXPECT_<ID>` pairs, template in `ops/contract-tests.env.example`). Catches silent semantic drift that fixture-based unit tests structurally cannot. The first live run found two real bugs (Railway accepting garbage tokens, Vercel misreading `limited: true`) — see STATUS.md.
- **Mechanism B** — changelog scanner (`tools/changelog-scan.mjs`) watches provider changelogs filtered to auth vocabulary, two-tier (weak terms count only in titles) to avoid the noise-then-muted failure mode. Providers with no watchable changelog declare `changelog.unwatchable: true` with a mandatory note.

Every provider must have at least one of the two mechanisms working — that is the merge blocker in CONTRIBUTING.md.

Test credentials must never hold a destructive scope, and dedicated throwaway accounts are used per provider — the rules in `ops/contract-tests.env.example` are not style preferences.

## Repo docs worth knowing

- `TODO-PATRICK.md` — current open tasks (account admin blocking Phase 2); `STATUS.md` — where things stand and why decisions were made; `03-execution-plan.md` — phases and non-goals.
- `INCIDENTS.md` — the verified reference incident. Project docs deliberately tell it in the abstract; keep it that way.
- `CONTRIBUTING.md` — provider contribution gates (contract test or watchable changelog, apiHosts review, who holds the test credential).
- `public/` — static landing page, built but held from deploy. `.impeccable.md` is its design context: clinical, never alarmist, never overclaim coverage, consequence language on the page too.

## Writing style in this codebase

Comments and docs explain *why the failure direction matters*, not what the code does — most modules open with a rationale block tying the design to the tool's trust model. Match that register: flat, precise, unwilling to overclaim.
