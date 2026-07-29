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

import { access, constants, readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { discover } from './core/discover.mjs';
import { resolveAll } from './core/resolve.mjs';
import { renderText, renderJson, exitCodeFor } from './core/report.mjs';
import { staleProviders, providers } from './providers/index.mjs';
import { SEVERITY_ORDER } from './core/capabilities.mjs';

const USAGE = `
blastradius — what can the credentials on this machine actually destroy?

Usage:
  blastradius [path] [options]        path defaults to the current directory
  blastradius help | version

Two passes, and the second is opt-in:

  blastradius .                       discover only. Offline, inert, nothing leaves
                                      the machine. Reports what was found, not what
                                      it means.
  blastradius . --resolve             ask each provider what its credential can
                                      actually do. Authenticates with every
                                      credential found, so it touches real accounts.

Options:
  --resolve            Ask each provider's API what the credential can actually do.
                       Sequential by design: parallel auth bursts across your accounts
                       look like credential stuffing to provider fraud detection, so
                       budget roughly ten seconds per unreachable credential.
  --json               Machine-readable output (schema version 2).
  --no-env             Skip the process environment.
  --no-agent-config    Skip ~/.claude, ~/.cursor, MCP config, ~/.aws/credentials.
  --no-heuristic       Skip the search for credentials in formats BlastRadius does not know.
  --providers          List supported providers and when each was last verified.
  -h, --help           This.
  -v, --version        Print the version.

CI gate (all of these require --resolve — without it nothing is assessed):
  --fail-on <level>    low | moderate | high | severe | catastrophic  (default: severe)
  --allow-unknown      Do not fail on credentials whose privileges could not be determined.
                       Silences every unknown, not only the one you had in mind.
  --fail-on-unrecognised
                       Also fail when an unrecognised high-entropy credential is found.

Exit codes: 0 clean, 1 at or above threshold, 2 error.

BlastRadius is a diagnostic aid, not a security audit, and is provided without warranty.
It reports what each provider's own API discloses about a credential, and says so plainly
where it cannot determine something. Risk may remain in setups, environments and
infrastructure it cannot inspect. Every report ends with what it does not cover.
`.trim();

/** Read from package.json rather than duplicated here, where it would drift on the next release. */
async function version() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(await readFile(join(here, '..', 'package.json'), 'utf8'));
    return `${pkg.name} ${pkg.version}`;
  } catch {
    return 'blastradius (version unknown — package.json not readable)';
  }
}

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
    version: false,
    listProviders: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--resolve') opts.resolve = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--no-env') opts.includeEnv = false;
    else if (arg === '--no-agent-config') opts.includeAgentConfig = false;
    else if (arg === '--allow-unknown') { opts.allowUnknown = true; opts.gateFlagUsed = true; }
    else if (arg === '--no-heuristic') opts.heuristic = false;
    else if (arg === '--fail-on-unrecognised' || arg === '--fail-on-unrecognized') { opts.failOnUnrecognised = true; opts.gateFlagUsed = true; }
    else if (arg === '--providers') opts.listProviders = true;
    else if (arg === '--fail-on') { opts.threshold = argv[++i]; opts.gateFlagUsed = true; }
    else if (arg === '-h' || arg === '--help' || arg === 'help') opts.help = true;
    else if (arg === '-v' || arg === '--version' || arg === 'version') opts.version = true;
    // An unrecognised flag was silently ignored, so a typo'd --fail-on became no gate at all
    // and a mistyped --no-resolve became a resolving run. Both fail quietly in the direction
    // that matters, so unknown flags are now an error rather than a shrug.
    else if (arg.startsWith('-')) throw new Error(`unknown option ${arg} — run --help for the list`);
    else opts.root = arg;
  }

  // A threshold outside the ladder ranked 0, which made the gate fire on everything —
  // including a scan with no findings — with nothing said about why. Fail-closed but silent
  // is the combination that teaches people to distrust the exit code.
  if (!SEVERITY_ORDER.includes(opts.threshold)) {
    throw new Error(
      `--fail-on must be one of ${SEVERITY_ORDER.filter((s) => s !== 'none').join(', ')} (got ${JSON.stringify(opts.threshold)})`,
    );
  }

  // The gate flags only do anything under --resolve: without it nothing is assessed, so
  // exitCodeFor is never consulted and the run exits 0 no matter what was found. A CI job
  // built on `--fail-on severe` without `--resolve` is a gate that cannot fail, which is
  // worse than no gate — it reports success over a check that never ran.
  if (opts.gateFlagUsed && !opts.resolve) {
    throw new Error(
      'gate flags (--fail-on, --allow-unknown, --fail-on-unrecognised) require --resolve. ' +
      'Without it nothing is assessed and the run always exits 0.',
    );
  }

  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }

  if (opts.version) {
    process.stdout.write(`${await version()}\n`);
    return 0;
  }

  if (opts.listProviders) {
    for (const p of providers) {
      process.stdout.write(`${p.id.padEnd(12)} ${p.label.padEnd(16)} last verified ${p.lastVerified}\n`);
    }
    return 0;
  }

  // A path that cannot be scanned must not report "nothing found".
  //
  // discover.mjs walks with `try { readdir } catch { return }`, so an unreachable directory
  // is indistinguishable from an empty one and the run exits 0 — a green CI gate over a scan
  // that never happened. A mistyped path, a checkout that did not land, or a moved directory
  // all produced a clean bill of health. That is the precise failure this tool tells other
  // people not to accept, so it fails loudly instead.
  try {
    const info = await stat(opts.root);
    if (!info.isDirectory()) {
      throw new Error(`not a directory: ${opts.root}`);
    }
    // stat() succeeds on a directory the caller cannot open — it only needs the parent to be
    // traversable. Without this check a mode-000 directory still scanned to "nothing found".
    await access(opts.root, constants.R_OK | constants.X_OK);
  } catch (err) {
    const reason = err?.code === 'ENOENT' ? 'no such directory'
      : err?.code === 'EACCES' ? 'permission denied'
      : err?.message ?? String(err);
    throw new Error(`cannot scan ${opts.root}: ${reason}`);
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
