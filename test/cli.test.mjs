import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { formatText, exitCode, summarize } from '../src/report.mjs';
import { finding } from '../src/finding.mjs';

const CLI = fileURLToPath(new URL('../bin/secops.mjs', import.meta.url));
const run = (...args) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });

// These cases fail before any network access.
test('CLI: no arguments prints usage, exit 1', () => {
  const r = run();
  assert.equal(r.status, 1);
  assert.match(r.stderr, /Usage: secops/);
});

test('CLI: unknown check, exit 1', () => {
  assert.equal(run('portscan', 'example.com').status, 1);
});

test('CLI: URL instead of domain is rejected, exit 1', () => {
  const r = run('tls', 'https://example.com');
  assert.equal(r.status, 1);
  assert.match(r.stderr, /bare domain name/);
});

test('report: exit code 2 on fail or error, 0 otherwise', () => {
  assert.equal(exitCode([finding('x', 'pass', 'ok'), finding('x', 'warn', 'hmm')]), 0);
  assert.equal(exitCode([finding('x', 'fail', 'bad')]), 2);
  assert.equal(exitCode([finding('x', 'error', 'broken')]), 2);
});

test('report: text output groups by check and summarizes', () => {
  const fs = [finding('spf', 'pass', 'a'), finding('spf', 'warn', 'b', { remediation: 'fix b' }), finding('tls', 'fail', 'c')];
  const text = formatText('example.com', fs);
  assert.match(text, /\[SPF\]\n {2}PASS {2}a\n {2}WARN {2}b\n {8}→ fix b\n\[TLS\]/);
  assert.match(text, /Summary: 1 pass · 1 warn · 1 fail · 0 info · 0 error/);
  assert.deepEqual(summarize(fs), { pass: 1, warn: 1, fail: 1, info: 0, error: 0 });
});

test('finding: rejects unknown status', () => {
  assert.throws(() => finding('x', 'critical', 'nope'));
});
