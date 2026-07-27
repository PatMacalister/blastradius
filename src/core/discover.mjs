/**
 * Pass 1 — reachability.
 *
 * The question is not "what is committed to git" but "what could an agent running in this
 * directory find if it went looking". In the reference incident (see INCIDENTS.md) the token
 * was reachable precisely because the agent's search was not scoped to its task — it read a
 * file that had nothing to do with the work, found something that authenticated, and used
 * it. Note it did not sweep exhaustively; one carelessly-placed file was enough.
 *
 * So this pass deliberately mirrors an agent's own scavenging behaviour: working tree
 * including gitignored files, dotfiles, the process environment, and agent/MCP config.
 *
 * This pass is entirely offline. No credential leaves the machine here.
 *
 * Three things this does that a regex-over-files scanner does not:
 *
 *   1. **Context-aware patterns.** Several real providers (Railway, Vercel, Cloudflare)
 *      issue tokens with no distinctive prefix — a Railway token is a bare UUID. Matching
 *      those on shape alone would drown the report in false positives, so those providers
 *      declare a regex with a capture group that includes the surrounding variable name,
 *      and group 1 is the credential. See _contract.mjs.
 *   2. **Structural parsing** of the two formats that actually hold agent-reachable
 *      credentials: dotenv files and MCP/agent JSON config. A credential inside an
 *      MCP server's `env` block is the single most agent-reachable place a secret can sit,
 *      and it is invisible to a repo-only scanner.
 *   3. **Key/value pair extraction** to feed the unrecognised-credential heuristic, so a
 *      credential in a format BlastRadius has never seen becomes visible ignorance rather
 *      than silent absence. See entropy.mjs.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { join, relative, basename, extname } from 'node:path';
import { homedir } from 'node:os';
import { loadProviders } from '../providers/index.mjs';
import { findUnrecognised } from './entropy.mjs';

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', 'coverage',
  '.venv', 'venv', '__pycache__', 'vendor', '.cache', 'target',
]);

// Reading a 200MB binary looking for a token is a waste; secrets live in text.
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const BINARY_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.zip', '.gz', '.tar',
  '.woff', '.woff2', '.ttf', '.otf', '.mp4', '.mp3', '.wasm', '.so', '.dll', '.exe',
]);

/** File shapes whose key/value pairs are worth feeding to the entropy heuristic. */
const PAIR_BEARING_EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf']);

/**
 * Agent and MCP configuration is a first-class source. These files routinely hold server
 * credentials in plaintext and are outside the repo, so repo-only scanners never see them.
 */
export function agentConfigPaths(home = homedir()) {
  return [
    join(home, '.claude', 'settings.json'),
    join(home, '.claude', 'mcp.json'),
    join(home, '.claude.json'),
    join(home, '.cursor', 'mcp.json'),
    join(home, '.codeium', 'windsurf', 'mcp_config.json'),
    join(home, '.config', 'mcp', 'config.json'),
    join(home, '.aws', 'credentials'),
    join(home, '.netrc'),
  ];
}

async function* walk(dir, root, depth = 0) {
  if (depth > 12) return;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(full, root, depth + 1);
    } else if (entry.isFile()) {
      if (BINARY_EXT.has(extname(entry.name).toLowerCase())) continue;
      yield full;
    }
  }
}

function isDotenvName(name) {
  return /^\.env(\..+)?$/.test(name) || name.endsWith('.env');
}

/**
 * A dotenv parser rather than a line regex, so `export FOO="bar"` and quoted values
 * normalise to the same pair a context-aware provider pattern expects to see.
 */
export function parseDotenv(text) {
  const pairs = [];
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$/);
    if (!m) continue;
    let value = m[2].trim();
    // Strip a matched pair of surrounding quotes, and anything after an unquoted comment.
    if (/^"(.*)"$/.test(value) || /^'(.*)'$/.test(value)) {
      value = value.slice(1, -1);
    } else {
      value = value.split(/\s+#/)[0].trim();
    }
    pairs.push({ key: m[1], value, line: i + 1 });
  }
  return pairs;
}

/**
 * Pull credential-bearing pairs out of agent/MCP configuration.
 *
 * An MCP server definition puts credentials in three places, all of which an agent can
 * read: the `env` block, inline `--flag=value` arguments, and request `headers`. This is
 * the case the whole tool is named after, so it gets a real parser rather than a regex.
 */
export function parseAgentConfig(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  const pairs = [];
  const seen = new Set();

  const visit = (node, path) => {
    if (node === null || typeof node !== 'object') return;
    if (seen.has(node)) return;
    seen.add(node);

    if (Array.isArray(node)) {
      for (const item of node) {
        if (typeof item === 'string') {
          // `--token=abc` / `--api-key abc` style arguments.
          const flag = item.match(/^--?([A-Za-z0-9_-]*(?:key|token|secret|password|auth)[A-Za-z0-9_-]*)=(.+)$/i);
          if (flag) pairs.push({ key: flag[1], value: flag[2], path });
        } else {
          visit(item, path);
        }
      }
      return;
    }

    for (const [key, value] of Object.entries(node)) {
      const where = path ? `${path}.${key}` : key;
      if (typeof value === 'string') {
        pairs.push({ key, value, path: where });
      } else {
        visit(value, where);
      }
    }
  };

  visit(doc, '');
  return pairs;
}

/** Simple `key: value` / `key = value` extraction for YAML/TOML/INI — heuristic input only. */
export function parseLooseePairs(text) {
  const pairs = [];
  for (const [i, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith('//')) continue;
    const m = line.match(/^["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*(.+)$/);
    if (!m) continue;
    const value = m[2].trim().replace(/^["']|["'],?$/g, '');
    pairs.push({ key: m[1], value, line: i + 1 });
  }
  return pairs;
}

/**
 * Match provider patterns against a block of text.
 *
 * If a pattern declares a capture group, group 1 is the credential and the rest of the
 * match is context (a variable name) that earned the match its confidence.
 */
function matchCandidates(text, providers, source) {
  const found = [];
  const lines = text.split(/\r?\n/);
  for (const [lineNo, line] of lines.entries()) {
    if (line.length > 4096) continue;
    for (const provider of providers) {
      for (const pattern of provider.patterns) {
        const m = line.match(pattern.regex);
        if (!m) continue;
        found.push({
          secret: m[1] ?? m[0],
          providerId: provider.id,
          pattern: pattern.name,
          confidence: pattern.confidence,
          source: { ...source, line: source.line ?? lineNo + 1 },
        });
      }
    }
  }
  return found;
}

/** Deduplicate by secret value — the same key in five files is one credential, five locations. */
function collapse(candidates) {
  const bySecret = new Map();
  for (const c of candidates) {
    const existing = bySecret.get(c.secret);
    if (existing) {
      const already = existing.sources.some(
        (s) => s.kind === c.source.kind && s.path === c.source.path && s.line === c.source.line,
      );
      if (!already) existing.sources.push(c.source);
      // Keep the highest-confidence classification of the same string.
      if (c.confidence > existing.confidence) {
        existing.providerId = c.providerId;
        existing.pattern = c.pattern;
        existing.confidence = c.confidence;
      }
    } else {
      bySecret.set(c.secret, {
        secret: c.secret,
        providerId: c.providerId,
        pattern: c.pattern,
        confidence: c.confidence,
        sources: [c.source],
      });
    }
  }
  return [...bySecret.values()];
}

/** Collapse heuristic hits the same way, and never let one shadow a properly identified credential. */
function collapseUnrecognised(items, knownSecrets) {
  const bySecret = new Map();
  for (const item of items) {
    if (knownSecrets.has(item.secret)) continue;
    const existing = bySecret.get(item.secret);
    if (existing) {
      existing.sources.push(item.source);
    } else {
      bySecret.set(item.secret, {
        secret: item.secret,
        key: item.key,
        entropy: item.entropy,
        sources: [item.source],
      });
    }
  }
  return [...bySecret.values()];
}

export async function discover({
  root = process.cwd(),
  env = process.env,
  home = homedir(),
  includeEnv = true,
  includeAgentConfig = true,
  heuristic = true,
} = {}) {
  const providers = loadProviders();
  const candidates = [];
  const pairs = [];

  const addPairs = (list, source) => {
    for (const p of list) {
      pairs.push({ key: p.key, value: p.value, source: { ...source, line: p.line ?? source.line } });
    }
  };

  for await (const file of walk(root, root)) {
    let info;
    try {
      info = await stat(file);
    } catch { continue; }
    if (info.size > MAX_FILE_BYTES) continue;

    let text;
    try {
      text = await readFile(file, 'utf8');
    } catch { continue; }

    const name = basename(file);
    const rel = relative(root, file) || name;
    const source = { kind: 'file', path: rel };

    candidates.push(...matchCandidates(text, providers, source));

    // Structural passes. These feed the heuristic and let context-aware patterns see a
    // normalised `KEY=value` even when the file wrote `export KEY="value"`.
    if (isDotenvName(name)) {
      const parsed = parseDotenv(text);
      addPairs(parsed, source);
      for (const p of parsed) {
        candidates.push(...matchCandidates(`${p.key}=${p.value}`, providers, { ...source, line: p.line }));
      }
    } else if (PAIR_BEARING_EXT.has(extname(name).toLowerCase())) {
      const parsed = extname(name).toLowerCase() === '.json'
        ? parseAgentConfig(text)
        : parseLooseePairs(text);
      addPairs(parsed, source);
      for (const p of parsed) {
        candidates.push(...matchCandidates(`${p.key}=${p.value}`, providers, { ...source, line: p.line }));
      }
    }
  }

  if (includeEnv) {
    for (const [key, value] of Object.entries(env)) {
      if (typeof value !== 'string' || value.length < 8) continue;
      const source = { kind: 'env', path: key };
      // Match against `KEY=value` so context-aware provider patterns can see the name.
      candidates.push(...matchCandidates(`${key}=${value}`, providers, source));
      pairs.push({ key, value, source });
    }
  }

  if (includeAgentConfig) {
    for (const path of agentConfigPaths(home)) {
      let text;
      try {
        text = await readFile(path, 'utf8');
      } catch { continue; }
      const source = { kind: 'agent-config', path };
      candidates.push(...matchCandidates(text, providers, source));

      const parsed = path.endsWith('.json') ? parseAgentConfig(text) : parseLooseePairs(text);
      addPairs(parsed, source);
      for (const p of parsed) {
        candidates.push(...matchCandidates(`${p.key}=${p.value}`, providers, source));
      }
    }
  }

  const collapsed = collapse(candidates);
  const knownSecrets = new Set(collapsed.map((c) => c.secret));

  const unrecognised = heuristic
    ? collapseUnrecognised(findUnrecognised(pairs, { knownSecrets }), knownSecrets)
    : [];

  return { candidates: collapsed, unrecognised };
}

export const _internals = { matchCandidates, collapse, walk, isDotenvName };
