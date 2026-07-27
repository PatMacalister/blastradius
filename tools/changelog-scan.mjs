#!/usr/bin/env node
/**
 * CHANGELOG SCANNER — Mechanism B from DRIFT-AND-OSS-PLAN.md.
 *
 * Contract tests catch drift that has already happened. This catches drift that has been
 * *announced*, which is the only way to get lead time on a deprecation rather than
 * discovering it on the cutover date. It also covers providers where holding a live test
 * credential is impractical.
 *
 * Design constraint that matters more than completeness: an unfiltered changelog watcher
 * produces noise, gets ignored, and is then worse than nothing because it manufactures the
 * appearance of coverage. Everything here is filtered to auth/permission vocabulary, and
 * only *new* entries are ever reported.
 *
 *   node tools/changelog-scan.mjs           report new relevant entries
 *   node tools/changelog-scan.mjs --json    machine-readable, for CI
 *
 * Exit 0 = nothing relevant. Exit 1 = something relevant changed, go look.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { providers } from '../src/providers/index.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const STATE_DIR = join(HERE, '.changelog-state');

/**
 * The filter. Terms chosen because they precede the changes that actually break scope
 * resolution — anything about how permissions are named, granted, or read.
 */
const RELEVANT = /\b(scope|permission|token|api key|credential|auth|oauth|deprecat|breaking|sunset|retire|removed|least privilege|iam|role|introspect)/i;

const MAX_ENTRIES = 40;

/** Below this, assume the parse failed rather than that the provider had a quiet week. */
const MIN_PLAUSIBLE_ENTRIES = 3;

function stripTags(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Deliberately small RSS/Atom reader — a dependency-free parse of title+link is enough. */
function parseFeed(xml) {
  const entries = [];
  const blocks = xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) ?? [];
  for (const block of blocks.slice(0, MAX_ENTRIES)) {
    const title = stripTags(block.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? '');
    const link =
      block.match(/<link[^>]*href=["']([^"']+)["']/i)?.[1] ??
      stripTags(block.match(/<link[^>]*>([\s\S]*?)<\/link>/i)?.[1] ?? '');
    const body = stripTags(
      block.match(/<(description|summary|content)[^>]*>([\s\S]*?)<\/\1>/i)?.[2] ?? '',
    );
    if (title) entries.push({ title, link, body: body.slice(0, 400) });
  }
  return entries;
}

/**
 * HTML changelogs have no stable structure across providers, so rather than pretending to
 * parse them, take headings as entries. Cruder, and honest about being crude.
 */
function parseHtml(html) {
  const headings = html.match(/<h[1-4][^>]*>[\s\S]*?<\/h[1-4]>/gi) ?? [];
  return headings
    .slice(0, MAX_ENTRIES)
    .map((h) => ({ title: stripTags(h), link: '', body: '' }))
    .filter((e) => e.title.length > 3);
}

async function loadState(id) {
  try {
    return JSON.parse(await readFile(join(STATE_DIR, `${id}.json`), 'utf8'));
  } catch {
    return { seen: [] };
  }
}

async function saveState(id, state) {
  await mkdir(STATE_DIR, { recursive: true });
  await writeFile(join(STATE_DIR, `${id}.json`), JSON.stringify(state, null, 2));
}

async function scanProvider(provider, { fetchImpl = fetch } = {}) {
  const result = { id: provider.id, label: provider.label, url: provider.changelog.url, new: [], error: null, unwatchable: false };

  // Some providers publish no machine-readable changelog at all. Retrying weekly and failing
  // weekly would train the operator to ignore the warnings — so a known-unwatchable provider
  // is declared once, reported as a standing blind spot, and not counted as an error.
  if (provider.changelog.unwatchable) {
    result.unwatchable = true;
    result.error = provider.changelog.note ?? 'no machine-readable changelog';
    return result;
  }

  let text;
  try {
    const res = await fetchImpl(provider.changelog.url, {
      headers: {
        'user-agent': 'blastradius-changelog-scan',
        // Without this, docs.stripe.com serves German and every entry silently fails the
        // English-vocabulary RELEVANT filter — a watcher that runs, reports nothing, and
        // covers nothing. Verified 2026-07-27.
        'accept-language': 'en-US,en;q=0.9',
      },
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      result.error = `HTTP ${res.status}`;
      return result;
    }
    text = await res.text();
  } catch (err) {
    result.error = err?.message ?? String(err);
    return result;
  }

  const entries = provider.changelog.type === 'rss' ? parseFeed(text) : parseHtml(text);

  // A source that fetches cleanly but yields (almost) nothing is the dangerous case: it
  // reports no news, which reads identically to "nothing changed".
  //
  // The threshold is 3 rather than 0 because 0 was not enough. railway.com/changelog returns
  // 200 and parses to exactly one heading — "Weekly product updates since 2021", the page
  // tagline — so a zero-check passed it as healthy while it watched nothing at all. Any real
  // changelog has more entries than that; a handful means the parse failed, not that the
  // provider went quiet.
  if (entries.length < MIN_PLAUSIBLE_ENTRIES) {
    result.error =
      `fetched OK but produced only ${entries.length} parseable entr${entries.length === 1 ? 'y' : 'ies'} — ` +
      'the page is probably JavaScript-rendered or has changed shape. This provider is NOT being watched.';
    return result;
  }

  const state = await loadState(provider.id);
  const seen = new Set(state.seen);

  for (const entry of entries) {
    const key = entry.title;
    if (seen.has(key)) continue;
    seen.add(key);
    if (RELEVANT.test(`${entry.title} ${entry.body}`)) result.new.push(entry);
  }

  // Bound the state file — old entries falling off the feed will never come back.
  await saveState(provider.id, { seen: [...seen].slice(-500), lastRun: new Date().toISOString() });
  return result;
}

async function main() {
  const json = process.argv.includes('--json');
  const results = [];
  for (const provider of providers) {
    results.push(await scanProvider(provider));
  }

  const relevant = results.filter((r) => r.new.length > 0);
  const errored = results.filter((r) => r.error && !r.unwatchable);
  const blindSpots = results.filter((r) => r.unwatchable);

  if (json) {
    process.stdout.write(`${JSON.stringify({ results }, null, 2)}\n`);
  } else {
    for (const r of relevant) {
      process.stdout.write(`\n=== ${r.label} — ${r.new.length} relevant change(s)\n${r.url}\n`);
      for (const e of r.new) {
        process.stdout.write(`  • ${e.title}\n`);
        if (e.link) process.stdout.write(`    ${e.link}\n`);
      }
    }
    for (const r of errored) {
      // A changelog we cannot reach is itself worth knowing about — a moved feed means
      // this provider has been silently unmonitored since it moved.
      process.stderr.write(`warning: ${r.label} changelog unreachable (${r.error}) — ${r.url}\n`);
    }
    if (blindSpots.length > 0) {
      // Printed every run, deliberately. These providers rely on contract tests alone, and
      // a standing gap that stops being mentioned stops being remembered.
      process.stderr.write(
        `\nNot watched by changelog (${blindSpots.length}) — these depend entirely on contract tests:\n`,
      );
      for (const r of blindSpots) process.stderr.write(`  ${r.label}: ${r.error}\n`);
    }
    if (relevant.length === 0 && errored.length === 0) {
      process.stdout.write('No auth-relevant changelog entries since last run.\n');
    }
  }

  return relevant.length > 0 ? 1 : 0;
}

// Only run when invoked directly — the parsers are imported by the unit tests.
const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (invokedDirectly) {
  main()
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`changelog-scan: ${err?.message ?? err}\n`);
      process.exit(2);
    });
}

export { parseFeed, parseHtml, stripTags, RELEVANT, scanProvider, main };
