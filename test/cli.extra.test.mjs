import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { run } from '../src/cli.mjs';
import { finding } from '../src/finding.mjs';
import { nextStepHint } from '../src/report.mjs';

const CLI = fileURLToPath(new URL('../bin/secops.mjs', import.meta.url));
const spawn = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });

// Offline: checks are injected, output is captured.
const fakeChecks = (status = 'pass') => ({
  mail: async () => [finding('mail', status, 'stub')],
  tls: async () => [finding('tls', 'pass', 'stub')],
  headers: async () => [finding('headers', 'pass', 'stub')],
});
async function invoke(args, status) {
  const out = [];
  const err = [];
  const code = await run(args, { checks: fakeChecks(status), out: (s) => out.push(s), err: (s) => err.push(s) });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

// --- help ---

test('CLI: --help and -h print usage to stdout and exit 0', () => {
  for (const flag of ['--help', '-h']) {
    const r = spawn(flag);
    assert.equal(r.status, 0, flag);
    assert.match(r.stdout, /Usage: secops/);
    assert.match(r.stdout, /--no-hint/);
    assert.equal(r.stderr, '');
  }
});

test('CLI: help wins over other arguments and works without network', () => {
  assert.equal(spawn('all', 'example.com', '--help').status, 0);
});

test('CLI: invalid input still exits 1 and prints usage on stderr', () => {
  const none = spawn();
  assert.equal(none.status, 1);
  assert.match(none.stderr, /Usage: secops/);
  assert.equal(none.stdout, '');
  assert.equal(spawn('portscan', 'example.com').status, 1);
  assert.equal(spawn('mail').status, 1);
});

// --- next-step hint ---

test('hint: text report ends with exactly one Next: line pointing at Korantix', async () => {
  const { code, out } = await invoke(['all', 'example.com']);
  assert.equal(code, 0);
  const lines = out.trimEnd().split('\n');
  assert.equal(lines.at(-1), 'Next: continuous monitoring and change alerts for example.com → https://korantix.io/en?domain=example.com');
  assert.equal(lines.filter((l) => l.startsWith('Next:')).length, 1);
  assert.ok(lines.at(-3).startsWith('Summary:') || lines.at(-2) === '', 'hint follows the Summary line');
});

test('hint: --no-hint suppresses it, in any argument position', async () => {
  for (const args of [['all', 'example.com', '--no-hint'], ['--no-hint', 'all', 'example.com']]) {
    const { code, out } = await invoke(args);
    assert.equal(code, 0);
    assert.doesNotMatch(out, /Next:/);
    assert.match(out, /Summary:/);
  }
});

test('hint: never appears in --json output, which stays valid JSON', async () => {
  const { out } = await invoke(['mail', 'example.com', '--json']);
  assert.doesNotMatch(out, /Next:|korantix\.io/);
  assert.equal(JSON.parse(out).domain, 'example.com');
});

test('hint: exit codes are unchanged with and without it', async () => {
  assert.equal((await invoke(['mail', 'example.com'], 'fail')).code, 2);
  assert.equal((await invoke(['mail', 'example.com', '--no-hint'], 'fail')).code, 2);
  assert.equal((await invoke(['mail', 'example.com'], 'warn')).code, 0);
  assert.equal((await invoke(['mail', 'bad domain'])).code, 1);
});

test('hint: uses the normalized domain and is URL-encoded', () => {
  assert.match(nextStepHint('xn--bcher-kva.example'), /domain=xn--bcher-kva\.example$/);
});
