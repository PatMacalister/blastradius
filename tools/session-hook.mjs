#!/usr/bin/env node
/**
 * SessionStart hook — tell the agent what this checkout has lying around.
 *
 * This is the recipe from the README, running against BlastRadius itself. The argument for it
 * is the reference incident: nothing in that loop knew what the credential it picked up could
 * do. A session that opens already knowing "ops/contract-tests.env holds live provider
 * credentials" is less likely to blunder into it than one that discovers the file mid-task.
 *
 * Two deliberate narrowings, both of which matter more here than they would elsewhere:
 *
 * 1. DISCOVERY ONLY. Never --resolve. This repository's contract-test credentials are real,
 *    and resolving would authenticate against six live provider accounts on every session
 *    start — slow, and exactly the "surprising act" the tool's own opt-in design exists to
 *    prevent. Discovery is offline and inert.
 *
 * 2. THE REPO TREE ONLY, not the environment or ~/.claude. This file is committed, so it runs
 *    for anyone who clones the project. Inventorying a contributor's whole machine because
 *    they opened an editor is overreach, whatever the tool is for. Someone who wants that runs
 *    `blastradius` themselves and chooses it.
 *
 * Silent when there is nothing to say. A hook that reports "no credentials found" on every
 * session is noise, and noise is what gets a warning ignored.
 */

import { discover } from '../src/core/discover.mjs';
import { fingerprint } from '../src/core/redact.mjs';
import { dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

function emit(context) {
  process.stdout.write(`${JSON.stringify({
    hookSpecificOutput: { hookEventName: 'SessionStart', additionalContext: context },
  })}\n`);
}

try {
  const { candidates, unrecognised } = await discover({
    root: ROOT,
    includeEnv: false,
    includeAgentConfig: false,
    heuristic: true,
  });

  if (candidates.length === 0 && unrecognised.length === 0) process.exit(0);

  const lines = [
    'BlastRadius scanned this checkout at session start (discovery only — offline, no',
    'credential was transmitted). Treat everything below as live unless you have checked:',
    '',
  ];

  for (const c of candidates) {
    const where = c.sources.map((s) => `${relative(ROOT, s.path) || s.path}:${s.line}`).join(', ');
    lines.push(`  ${c.providerId} ${fingerprint(c.secret)} — ${where}`);
  }
  for (const u of unrecognised) {
    const where = u.sources.map((s) => `${relative(ROOT, s.path) || s.path}${s.line ? `:${s.line}` : ''}`).join(', ');
    lines.push(`  unrecognised ${u.key} — ${where}`);
  }

  lines.push(
    '',
    'Privileges were NOT resolved, so nothing here is graded — an unlabelled credential is',
    'not a harmless one. Do not run `--resolve` against this repository casually: it',
    'authenticates with every credential found, and these are real.',
  );

  emit(lines.join('\n'));
} catch (err) {
  // A hook that breaks the session is worse than one that says nothing. Report and stand down.
  emit(`BlastRadius session-start scan did not complete: ${err?.message ?? err}`);
}
