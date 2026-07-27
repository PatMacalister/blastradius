/**
 * Structural discovery — dotenv, MCP/agent config, and context-gated provider patterns.
 *
 * The MCP case is the one the tool is named after: a credential in an MCP server's `env`
 * block is the most agent-reachable place a secret can sit, and it is invisible to every
 * repo-only scanner.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discover, parseDotenv, parseAgentConfig } from '../../src/core/discover.mjs';
import { FAKE } from '../fixtures.mjs';

const UUID = '3f2504e0-4f89-11d3-9a0c-0305e82c3301';

test('dotenv parsing handles export, quotes, and trailing comments', () => {
  const pairs = parseDotenv([
    '# a comment',
    'PLAIN=one',
    'export EXPORTED="two"',
    "SINGLE='three'",
    'WITH_COMMENT=four # trailing',
    'not a pair',
  ].join('\n'));

  assert.deepEqual(pairs.map((p) => [p.key, p.value]), [
    ['PLAIN', 'one'],
    ['EXPORTED', 'two'],
    ['SINGLE', 'three'],
    ['WITH_COMMENT', 'four'],
  ]);
});

test('MCP server env blocks and flag arguments are extracted', () => {
  const pairs = parseAgentConfig(JSON.stringify({
    mcpServers: {
      db: {
        command: 'npx',
        args: ['-y', 'some-server', '--api-key=abc123'],
        env: { RAILWAY_TOKEN: UUID },
      },
    },
  }));

  const byKey = Object.fromEntries(pairs.map((p) => [p.key, p.value]));
  assert.equal(byKey.RAILWAY_TOKEN, UUID);
  assert.equal(byKey['api-key'], 'abc123');
});

test('a Railway token is found in an MCP env block but not as a bare UUID', async () => {
  const root = await mkdtemp(join(tmpdir(), 'blastradius-mcp-'));

  await writeFile(join(root, 'mcp.json'), JSON.stringify({
    mcpServers: { deploy: { env: { RAILWAY_TOKEN: UUID } } },
  }));
  // The same UUID as ordinary data must NOT be reported — this is the false-positive guard.
  await writeFile(join(root, 'fixtures.json'), JSON.stringify({ orderId: UUID }));

  const { candidates } = await discover({ root, env: {}, includeAgentConfig: false });
  const railway = candidates.filter((c) => c.providerId === 'railway');

  assert.equal(railway.length, 1, 'exactly one Railway credential');
  assert.equal(railway[0].secret, UUID);
  assert.ok(railway[0].sources.every((s) => s.path === 'mcp.json'));
});

test('context-gated patterns read the variable name from the environment', async () => {
  const root = await mkdtemp(join(tmpdir(), 'blastradius-env-'));
  const { candidates } = await discover({
    root,
    env: { RAILWAY_TOKEN: UUID, ORDER_ID: '3f2504e0-4f89-11d3-9a0c-0305e82c3302' },
    includeAgentConfig: false,
  });

  const ids = candidates.map((c) => c.providerId);
  assert.deepEqual(ids, ['railway']);
  assert.equal(candidates[0].sources[0].path, 'RAILWAY_TOKEN');
});

test('an unrecognised high-entropy secret is surfaced separately, not as a provider finding', async () => {
  const root = await mkdtemp(join(tmpdir(), 'blastradius-heur-'));
  await writeFile(join(root, '.env'), [
    `GITHUB_TOKEN=${FAKE.githubClassic}`,
    'INTERNAL_API_SECRET=hX7pQ2mK9vLw4RtZ8nB3yD6fJ1sA5gU0',
    'NODE_ENV=production',
  ].join('\n'));

  const { candidates, unrecognised } = await discover({ root, env: {}, includeAgentConfig: false });

  assert.deepEqual(candidates.map((c) => c.providerId), ['github']);
  assert.equal(unrecognised.length, 1);
  assert.equal(unrecognised[0].key, 'INTERNAL_API_SECRET');
});

// AWS was cut from v1 (03-execution-plan.md, open decision 1), so ~/.aws/credentials is read
// but never classified. The heuristic is the only thing standing between "we don't support
// AWS" and "we silently said nothing about your AWS key" — this pins that it still fires.
test('an AWS secret key still surfaces as unrecognised even with no AWS provider', async () => {
  const home = await mkdtemp(join(tmpdir(), 'blastradius-home-'));
  const root = await mkdtemp(join(tmpdir(), 'blastradius-awsroot-'));
  await mkdir(join(home, '.aws'), { recursive: true });
  await writeFile(join(home, '.aws', 'credentials'), [
    '[default]',
    'aws_access_key_id = AKIAIOSFODNN7EXAMPLE',
    'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  ].join('\n'));

  const { candidates, unrecognised } = await discover({ root, env: {}, home });

  assert.equal(candidates.length, 0, 'no provider module claims AWS');
  assert.deepEqual(unrecognised.map((u) => u.key), ['aws_secret_access_key']);
});

test('the heuristic can be switched off', async () => {
  const root = await mkdtemp(join(tmpdir(), 'blastradius-noheur-'));
  await writeFile(join(root, '.env'), 'INTERNAL_API_SECRET=hX7pQ2mK9vLw4RtZ8nB3yD6fJ1sA5gU0\n');

  const { unrecognised } = await discover({ root, env: {}, includeAgentConfig: false, heuristic: false });
  assert.equal(unrecognised.length, 0);
});
