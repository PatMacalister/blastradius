import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discover, _internals, agentConfigPaths } from '../../src/core/discover.mjs';
import { loadProviders } from '../../src/providers/index.mjs';
import { FAKE } from '../fixtures.mjs';

const providers = loadProviders();

test('a known token shape is detected with its line number', () => {
  const text = `line one\nTOKEN=${FAKE.githubClassic}\nline three`;
  const found = _internals.matchCandidates(text, providers, { kind: 'file', path: '.env' });
  assert.equal(found.length, 1);
  assert.equal(found[0].providerId, 'github');
  assert.equal(found[0].source.line, 2);
});

test('ordinary prose produces nothing', () => {
  const found = _internals.matchCandidates('the quick brown fox', providers, { kind: 'file', path: 'a.txt' });
  assert.equal(found.length, 0);
});

// The same key pasted into five files is one credential with five locations, not five findings.
test('the same secret in several places collapses to one finding', () => {
  const collapsed = _internals.collapse([
    { secret: 'x', providerId: 'github', pattern: 'p', confidence: 1, source: { path: 'a' } },
    { secret: 'x', providerId: 'github', pattern: 'p', confidence: 1, source: { path: 'b' } },
    { secret: 'y', providerId: 'stripe', pattern: 'p', confidence: 1, source: { path: 'c' } },
  ]);
  assert.equal(collapsed.length, 2);
  assert.equal(collapsed[0].sources.length, 2);
});

test('agent and MCP config paths are part of the search surface', () => {
  const paths = agentConfigPaths('/home/test');
  const joined = paths.join('|');
  assert.ok(joined.includes('.claude'));
  assert.ok(joined.includes('mcp.json'));
  assert.ok(joined.includes('.aws'));
});

test('discover walks a tree, skips node_modules, and reads the environment', async () => {
  const root = await mkdtemp(join(tmpdir(), 'blastradius-'));
  await writeFile(join(root, '.env'), `STRIPE=${FAKE.stripeLive}\n`);
  await mkdir(join(root, 'src'), { recursive: true });
  await writeFile(join(root, 'src', 'config.js'), `const t = "${FAKE.githubClassic}";\n`);
  await mkdir(join(root, 'node_modules', 'pkg'), { recursive: true });
  await writeFile(join(root, 'node_modules', 'pkg', 'leak.js'), `const t = "${FAKE.stripeTest}";\n`);

  const { candidates: found } = await discover({
    root,
    env: { DEPLOY_TOKEN: FAKE.githubFineGrained },
    includeAgentConfig: false,
  });

  const ids = found.map((f) => f.providerId).sort();
  assert.deepEqual(ids, ['github', 'github', 'stripe']);

  const fromEnv = found.find((f) => f.sources.some((s) => s.kind === 'env'));
  assert.equal(fromEnv.sources[0].path, 'DEPLOY_TOKEN');

  const leaked = found.find((f) => f.secret === FAKE.stripeTest);
  assert.equal(leaked, undefined, 'node_modules must be skipped');
});
