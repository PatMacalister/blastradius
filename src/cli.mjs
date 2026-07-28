#!/usr/bin/env node
/**
 * BlastRadius CLI.
 *
 *   blastradius                    discover only — offline, nothing leaves the machine
 *   blastradius --resolve          also ask each provider what its credential can do
 *   blastradius --resolve --json   machine-readable, for CI
 *
 * Discovery and resolution are separate commands on purpose. Discovery is inert. Resolution
 * authenticates with every credential it found, which is a materially different act — it
 * touches third-party accounts and can trip fraud detection. Making that the default would
 * be the same class of surprise this tool exists to report on.
 */

import { discover } from './core/discover.mjs';
import { resolveAll } from './core/resolve.mjs';
import { renderText, renderJson, exitCodeFor } from './core/report.mjs';
import { staleProviders, providers } from './providers/index.mjs';

const USAGE = `
blastradius — what can the credentials on this machine actually destroy?

Usage:
  blastradius [path] [options]

Options:
  --resolve            Ask each provider's API what the credential can actually do.
                       Without this, BlastRadius only reports what it found, not what it means.
  --json               Machine-readable output.
  --no-env             Skip the process environment.
  --no-agent-config    Skip ~/.claude, ~/.cursor, MCP config, ~/.aws/credentials.
  --fail-on <level>    CI gate threshold: low|moderate|high|severe|catastrophic (default: severe)
  --allow-unknown      Do not fail CI on credentials whose privileges could not be determined.
  --no-heuristic       Skip the search for credentials in formats BlastRadius does not know.
  --fail-on-unrecognised
                       Also fail CI when an unrecognised high-entropy credential is found.
  --providers          List supported providers and when each was last verified.
  -h, --help           This.

Exit codes: 0 clean, 1 at or above threshold, 2 error.

BlastRadius is a diagnostic aid, not a security audit, and is provided without warranty.
It reports what each provider's own API discloses about a credential, and says so plainly
where it cannot determine something. Risk may remain in setups, environments and
infrastructure it cannot inspect. Every report ends with what it does not cover.
`.trim();

function parseArgs(argv) {
  const opts = {
    root: process.cwd(),
    resolve: false,
    json: false,
    includeEnv: true,
    includeAgentConfig: true,
    threshold: 'severe',
    allowUnknown: false,
    heuristic: true,
    failOnUnrecognised: false,
    help: false,
    listProviders: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--resolve') opts.resolve = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--no-env') opts.includeEnv = false;
    else if (arg === '--no-agent-config') opts.includeAgentConfig = false;
    else if (arg === '--allow-unknown') opts.allowUnknown = true;
    else if (arg === '--no-heuristic') opts.heuristic = false;
    else if (arg === '--fail-on-unrecognised' || arg === '--fail-on-unrecognized') opts.failOnUnrecognised = true;
    else if (arg === '--providers') opts.listProviders = true;
    else if (arg === '--fail-on') opts.threshold = argv[++i];
    else if (arg === '-h' || arg === '--help') opts.help = true;
    else if (!arg.startsWith('--')) opts.root = arg;
  }
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }

  if (opts.listProviders) {
    for (const p of providers) {
      process.stdout.write(`${p.id.padEnd(12)} ${p.label.padEnd(16)} last verified ${p.lastVerified}\n`);
    }
    return 0;
  }

  const { candidates, unrecognised } = await discover({
    root: opts.root,
    includeEnv: opts.includeEnv,
    includeAgentConfig: opts.includeAgentConfig,
    heuristic: opts.heuristic,
  });

  const findings = opts.resolve ? await resolveAll(candidates) : candidates;

  process.stdout.write(
    opts.json
      ? `${renderJson(findings, { resolved: opts.resolve, unrecognised })}\n`
      : `${renderText(findings, { resolved: opts.resolve, unrecognised })}\n`,
  );

  if (!opts.json) {
    const stale = staleProviders();
    if (stale.length > 0) {
      process.stderr.write(
        `\nwarning: ${stale.length} provider module(s) not verified against the live API recently.\n` +
        `Results for those providers may be wrong in either direction.\n`,
      );
    }
    if (!opts.resolve && candidates.length > 0) {
      process.stderr.write('\nRun again with --resolve to find out what these credentials can actually do.\n');
    }
  }

  return opts.resolve
    ? exitCodeFor(findings, {
      threshold: opts.threshold,
      allowUnknown: opts.allowUnknown,
      unrecognised,
      failOnUnrecognised: opts.failOnUnrecognised,
    })
    : 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`blastradius: ${err?.message ?? err}\n`);
    process.exit(2);
  });
