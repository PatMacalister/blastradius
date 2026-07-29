# BlastRadius

**What can the credentials on this machine actually destroy?**

Secret scanners answer "is there a credential here, and is it live?" BlastRadius answers
the two questions that actually predict an incident:

1. **What is the worst thing this credential can do?**
2. **Can the coding agent running here reach it?**

```
$ blastradius --resolve

CATASTROPHIC Railway ****...a4f1
             can delete databases, volumes, or bucket contents
             can delete backups or snapshots
             ↳ can destroy data AND its backups — unrecoverable
             found in scripts/legacy-deploy.sh:14
             fix: scope this token to the single service it deploys

SEVERE       Stripe  sk_l********CCCC
             can move real money — charges, refunds, or transfers
             found in env STRIPE_KEY
             fix: replace this unrestricted live key with a restricted key

2 credentials reachable, worst case: CATASTROPHIC
```

## Why

Picture an agent doing something routine. It hits a credential mismatch. Rather than
stopping, it goes looking for something that will authenticate — and finds a token in a file
that has nothing to do with the task it was given.

Someone created that token months ago for one narrow job. Nobody noticed it also carried
authority over the entire platform account, because the platform never offered a way to
scope it down. One API call later the production volume is gone, and so are the backups,
because they were stored inside the volume they were supposed to protect.

Nothing in that loop knew what the credential it picked up could do. **That is the gap** —
not detection, which is well served, but *consequence modelling*.

This is not a thought experiment. It has happened, in nine seconds, with a thirty-hour
recovery — see **[Real-world incidents](INCIDENTS.md)**.

## Install & use

Requires Node 20+. No dependencies.

```bash
npx @mediaforge/blastradius            # no install — discover only, offline, inert
npx @mediaforge/blastradius --resolve  # ask each provider what its credential can do

# or install it, after which the command is just `blastradius`
npm install -g @mediaforge/blastradius

blastradius                  # discover only — offline, nothing leaves the machine
blastradius --resolve        # ask each provider what its credential can actually do
blastradius --resolve --json # machine-readable, for CI (schema `version: 2`)
blastradius --providers      # what's supported, and when it was last verified
```

**Discovery and resolution are separate on purpose.** Discovery is inert. Resolution
authenticates with every credential it found — a materially different act that touches
third-party accounts and can trip fraud detection. Making that the default would be the
same class of surprise this tool exists to report on.

### CI gate

```bash
blastradius --resolve --fail-on severe
```

Exit 0 clean, 1 at or above threshold, 2 error. Credentials whose privileges **could not
be determined** fail by default — `--allow-unknown` opts out. A gate that passes on "we
couldn't tell" teaches people to trust a green tick that means nothing.

## What it will not do

- **It never prints a raw secret.** Everything user-facing is fingerprinted.
- **It never sends a credential anywhere except the issuing provider.** Enforced
  mechanically: each provider module declares its `apiHosts` and a guard blocks
  everything else.
- **It never reports "unknown" as "safe."** If privileges cannot be resolved, the report
  says so loudly.
- **It does not claim a clean bill of health.** An empty result means "nothing matched
  the providers we ship", and says exactly that.

## Where it looks

Not just the repo. The question is what an agent could find if it went looking, so the
search covers the working tree including gitignored files, the process environment, and —
the part repo-only scanners miss entirely — **agent and MCP configuration**. A credential
in an MCP server's `env` block is the most agent-reachable place a secret can sit.

`--no-env` and `--no-agent-config` narrow it; `--no-heuristic` turns off the search for
credentials in formats BlastRadius does not recognise.

## Supported providers

| Provider | What it can tell you |
|---|---|
| GitHub | Classic PAT scopes, in full. Fine-grained PATs report `unresolved` — the API does not expose their permissions. |
| Stripe | Live vs test mode. Restricted keys report `unresolved` rather than being guessed at. |
| Railway | **Full capability, confidently.** Railway has no token scopes at all, so an account token can delete a volume and the backups stored with it. |
| Supabase | Key class, entirely offline — `service_role` and `sb_secret_` bypass RLS; management tokens can delete whole projects. |
| Vercel | Account-level reach. Vercel has no project-level scoping, so a token reads decrypted env vars and can delete projects. |
| Cloudflare | Liveness only. **Cloudflare will not tell a token its own permissions**, so every live token reports `unresolved` — see below. |

Run `blastradius --providers` for the `lastVerified` date on each, stamped by its last
green run against the live API. Reports go stale visibly rather than silently.

Coverage is deliberately narrow. A wrong "this token is harmless" is worse than no
answer, so providers ship only when they can be contract-tested — see
[CONTRIBUTING.md](CONTRIBUTING.md).

**Cloudflare is worth calling out**, because it is the honest case. Its
`/user/tokens/verify` endpoint returns `{id, status, expires_on}` and nothing else — no
policies, no permission groups. A token cannot read its own permissions. So BlastRadius
tells you the credential is real and reachable, and says plainly that it cannot determine
the blast radius. Inventing a scope mapping to produce a tidier report would be exactly the
confident-and-wrong output this tool exists to prevent.

## Docker

```bash
docker compose up -d changelog-watch          # provider changelog watcher (no credentials)
docker compose --profile contract up -d       # weekly live-API contract tests
TARGET=/srv/myapp docker compose --profile scan run --rm scan
```

Only the landing page listens on a port, and it serves static files. No service here
accepts a credential over a network. BlastRadius is a CLI, and a hosted service that accepts
other people's credentials is a non-goal — it would make this tool the thing it warns
about. What the compose file hosts is the *drift machinery* that keeps provider modules
correct. See [DRIFT-AND-OSS-PLAN.md](DRIFT-AND-OSS-PLAN.md).

Note that a containerised scan sees only the mounted path — not the host environment or
`~/.claude` MCP config, which are the most agent-reachable places a credential sits. It is
strictly less thorough than running the CLI on the host. Use it for CI over a checkout.

## Free, and staying free

BlastRadius is not a product and has no paid tier planned. Reasoning is recorded in
[STATUS.md](STATUS.md); the maintenance strategy that makes a free tool sustainable is in
[DRIFT-AND-OSS-PLAN.md](DRIFT-AND-OSS-PLAN.md).

### Support posture

Stated plainly so it does not have to be inferred:

- **Maintained on a best-effort basis, by one person.** There is no SLA, no support contract,
  and no guaranteed response time. Issues are read; not all of them get fixed.
- **Provider coverage is intentionally narrow and will stay that way.** Requests for a new
  provider are welcome, but the bar is the coverage invariant in
  [CONTRIBUTING.md](CONTRIBUTING.md): a module that cannot be kept correct will not be added,
  because a wrong "this token is harmless" is worse than no answer.
- **Correctness reports get priority over everything else.** If BlastRadius told you a
  credential was safe and it was not, that is the bug that matters most — say so and it goes
  to the front.
- **No warranty.** This is a diagnostic aid, not a security audit. It reports what each
  provider's own API says about a credential and, where it cannot determine something, says
  so. Do not treat a clean report as a clean bill of health; it is not one, and the tool will
  tell you as much.

## Agent hooks

The exit code is the contract, so it composes with whatever hook mechanism your agent
already has:

```bash
blastradius --resolve --fail-on catastrophic || echo "refusing to continue"
```

Exit 1 at or above the threshold, 0 below it, 2 on error.

### Telling an agent what it can reach

In the reference incident, nothing in the loop knew what the credential it picked up could
do. That is a knowledge gap, and it is one a session-start hook can close. For Claude Code,
in `.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "blastradius --resolve --fail-on catastrophic || true",
            "timeout": 120
          }
        ]
      }
    ]
  }
}
```

The output becomes context, so the agent begins every session already knowing that the
token in `scripts/deploy.sh` can delete your volumes *and* the backups inside them. Drop
`--resolve` if you do not want a session start authenticating against live accounts; you
lose the severities and keep the inventory.

`|| true` is deliberate. Without it a catastrophic finding aborts the session before you can
read why.

This project runs that hook on itself. `.claude/settings.json` and `tools/session-hook.mjs`
are the working example — worth reading before you wire up your own, because both narrowings
in it are deliberate:

- **Discovery only, never `--resolve`.** This repository's contract-test credentials are real.
  Resolving at session start would authenticate against six live provider accounts every time
  anyone opened an editor.
- **The repo tree only** — not the environment, not `~/.claude`. That file is committed, so it
  runs for anyone who clones. Inventorying a contributor's whole machine because they opened
  an editor is overreach whatever the tool is for; someone who wants that runs `blastradius`
  themselves and chooses it.

It stays silent when there is nothing to report. A hook that says "no credentials found" every
session is noise, and noise is what gets a warning ignored.

**Be clear about what this does and does not do.** It informs; it does not enforce. An agent
that knows a token is dangerous is less likely to reach for it, and that is worth having —
but a hook cannot make a reachable credential unreachable. Only the remediation each finding
prints does that.

**A skill would be weaker still.** A skill is instructions a model may or may not follow, and
the failure this tool describes is an agent doing something nobody told it to. Asking the
failure mode to police itself is not a control. A hook at least runs whether the model
cooperates or not.

Resolution is sequential and each provider gets a 10-second timeout, so budget roughly ten
seconds per unreachable credential — hence the generous hook timeout above. A runtime guard
that intercepted individual tool calls would be a different tool, with a per-agent
integration surface this project has decided against carrying.

## Development

```bash
npm test              # unit suite, offline, no credentials needed
npm run test:contract # live provider APIs — needs test credentials, see CONTRIBUTING.md
npm run changelog:scan # check provider changelogs for auth-relevant changes
```
