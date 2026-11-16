import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { run } from '../src/cli.mjs';
import { finding } from '../src/finding.mjs';
import { parseDomainList, mapLimit } from '../src/batch.mjs';

// --- list parsing ---

test('parseDomainList: comments, blanks, CRLF, BOM, trailing comments and case are handled', () => {
  const text = '﻿# fleet\r\nExample.COM\r\n\r\n  github.com  # primary\n# done\nexample.org.\n';
  const { entries, invalid, duplicates } = parseDomainList(text);
  assert.deepEqual(entries, [
    { domain: 'example.com', line: 2 },
    { domain: 'github.com', line: 4 },
    { domain: 'example.org', line: 6 },
  ]);
  assert.deepEqual(invalid, []);
  assert.equal(duplicates, 0);
});

test('parseDomainList: a UTF-8 BOM before the first domain is dropped', () => {
  assert.deepEqual(parseDomainList(String.fromCharCode(0xfeff) + 'a.example\nb.example').entries.map((e) => e.domain), ['a.example', 'b.example']);
});

test('parseDomainList: duplicates collapse to the first line (after normalisation)', () => {
  const { entries, duplicates } = parseDomainList('a.example\nA.EXAMPLE.\nb.example\na.example');
  assert.deepEqual(entries.map((e) => [e.domain, e.line]), [['a.example', 1], ['b.example', 3]]);
  assert.equal(duplicates, 2);
});

test('parseDomainList: every invalid line is reported with its line number, using the single-domain validator', () => {
  const { entries, invalid } = parseDomainList('ok.example\nhttps://x.example\n10.0.0.1\nlocalhost\nuser@x.example\nexample.com:443\n-bad.example\nfine.example');
  assert.deepEqual(entries.map((e) => e.domain), ['ok.example', 'fine.example']);
  assert.deepEqual(invalid.map((i) => i.line), [2, 3, 4, 5, 6, 7]);
  assert.ok(invalid.every((i) => i.message));
});

test('parseDomainList: IDNs are converted to punycode', () => {
  assert.equal(parseDomainList('bücher.example').entries[0].domain, 'xn--bcher-kva.example');
});

// --- bounded concurrency ---

test('mapLimit: never exceeds the limit and keeps input order', async () => {
  let active = 0;
  let peak = 0;
  const out = await mapLimit(Array.from({ length: 12 }, (_, i) => i), 4, async (n) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, 5 + (n % 3) * 4));
    active -= 1;
    return n * 2;
  });
  assert.equal(peak, 4);
  assert.deepEqual(out, Array.from({ length: 12 }, (_, i) => i * 2));
});

test('mapLimit: empty input and limit larger than input are fine', async () => {
  assert.deepEqual(await mapLimit([], 4, async (x) => x), []);
  assert.deepEqual(await mapLimit([1, 2], 16, async (x) => x + 1), [2, 3]);
});

// --- CLI batch mode (offline: checks and file reads injected) ---

const FILE = '# fleet\nclean.example\nwarn.example\nbroken.example\nclean.example\n';
function checksFor(statusByDomain, tracker = {}) {
  const make = (name) => async (domain, options) => {
    tracker.options = options;
    tracker.active = (tracker.active || 0) + 1;
    tracker.peak = Math.max(tracker.peak || 0, tracker.active);
    await new Promise((r) => setTimeout(r, 3));
    tracker.active -= 1;
    tracker.seen = [...(tracker.seen || []), `${name}:${domain}`];
    const status = name === 'mail' ? statusByDomain[domain] || 'pass' : 'pass';
    return [finding(name, status, `${name} stub`, { id: `${name}/stub` })];
  };
  return { mail: make('mail'), tls: make('tls'), headers: make('headers') };
}
async function invoke(args, { files = { 'domains.txt': FILE }, status = { 'warn.example': 'warn', 'broken.example': 'fail' }, tracker } = {}) {
  const out = [];
  const err = [];
  const code = await run(args, {
    checks: checksFor(status, tracker),
    out: (s) => out.push(s),
    err: (s) => err.push(s),
    readFile: (f) => { if (!(f in files)) throw Object.assign(new Error('nope'), { code: 'ENOENT' }); return files[f]; },
  });
  return { code, out: out.join('\n'), err: err.join('\n') };
}

test('batch: checks every unique domain once, prints per-domain reports and a summary table', async () => {
  const tracker = {};
  const r = await invoke(['all', '--file', 'domains.txt'], { tracker });
  assert.equal(r.code, 2);
  for (const d of ['clean.example', 'warn.example', 'broken.example']) assert.match(r.out, new RegExp(`Target: ${d}`));
  assert.equal(r.out.match(/Target: clean\.example/g).length, 1);
  assert.match(r.out, /Batch summary: 3 domain\(s\)/);
  assert.match(r.out, /clean\.example\s+0\s+0\s+0\s+3\s+OK/);
  assert.match(r.out, /warn\.example\s+0\s+0\s+1\s+2\s+WARN/);
  assert.match(r.out, /broken\.example\s+1\s+0\s+0\s+2\s+FAIL/);
  assert.match(r.out, /TOTAL\s+1\s+0\s+1\s+7\s+FAIL/);
  assert.equal(tracker.seen.length, 9); // 3 domains x 3 checks
  assert.doesNotMatch(r.out, /Next:/); // the hint is per-domain advice; not printed for batches
});

test('batch: exit code is the worst across domains', async () => {
  assert.equal((await invoke(['all', '--file', 'domains.txt'], { status: {} })).code, 0);
  assert.equal((await invoke(['all', '--file', 'domains.txt'], { status: { 'warn.example': 'warn' } })).code, 0);
  assert.equal((await invoke(['all', '--file', 'domains.txt'], { status: { 'warn.example': 'error' } })).code, 2);
});

test('batch: --file works with a single check and with --file=path', async () => {
  const r = await invoke(['mail', '--file=domains.txt'], { status: {} });
  assert.equal(r.code, 0);
  assert.match(r.out, /Batch summary: 3 domain/);
});

test('batch: --concurrency bounds parallel domains', async () => {
  const tracker = {};
  await invoke(['mail', '--file', 'domains.txt', '--concurrency', '1'], { tracker, status: {} });
  assert.equal(tracker.peak, 1);
  const wide = {};
  await invoke(['mail', '--file', 'domains.txt', '--concurrency', '3'], { tracker: wide, status: {} });
  assert.equal(wide.peak, 3);
});

test('batch: invalid --concurrency is a usage error', async () => {
  for (const v of ['0', '17', 'abc', '1.5']) {
    const r = await invoke(['all', '--file', 'domains.txt', '--concurrency', v]);
    assert.equal(r.code, 1, v);
    assert.match(r.err, /--concurrency/);
  }
});

test('batch: invalid lines abort with exit 1 before any check runs, listing file:line', async () => {
  const tracker = {};
  const r = await invoke(['all', '--file', 'd.txt'], { files: { 'd.txt': 'ok.example\nhttp://bad.example\n10.0.0.1\n' }, tracker });
  assert.equal(r.code, 1);
  assert.match(r.err, /d\.txt:2: invalid domain "http:\/\/bad\.example"/);
  assert.match(r.err, /d\.txt:3: invalid domain "10\.0\.0\.1"/);
  assert.match(r.err, /2 invalid line\(s\)/);
  assert.equal(tracker.seen, undefined);
  assert.equal(r.out, '');
});

test('batch: --skip-invalid warns on stderr and continues', async () => {
  const r = await invoke(['mail', '--file', 'd.txt', '--skip-invalid'], { files: { 'd.txt': 'ok.example\nhttp://bad.example\n' }, status: {} });
  assert.equal(r.code, 0);
  assert.match(r.err, /d\.txt:2: invalid domain/);
  assert.match(r.out, /Batch summary: 1 domain/);
});

test('batch: unreadable or empty files are usage errors', async () => {
  const missing = await invoke(['all', '--file', 'nope.txt']);
  assert.equal(missing.code, 1);
  assert.match(missing.err, /cannot read nope\.txt: ENOENT/);
  const empty = await invoke(['all', '--file', 'e.txt'], { files: { 'e.txt': '# nothing\n\n' } });
  assert.equal(empty.code, 1);
  assert.match(empty.err, /no domains found/);
});

test('batch: --file cannot be combined with a domain argument', async () => {
  const r = await invoke(['all', 'example.com', '--file', 'domains.txt']);
  assert.equal(r.code, 1);
  assert.match(r.err, /cannot be combined/);
});

test('batch: --json emits one document with per-domain findings and totals', async () => {
  const r = await invoke(['all', '--file', 'domains.txt', '--json']);
  const j = JSON.parse(r.out);
  assert.deepEqual(j.domains.map((d) => d.domain), ['clean.example', 'warn.example', 'broken.example']);
  assert.equal(j.summary.fail, 1);
  assert.equal(j.domains[2].summary.fail, 1);
  assert.ok(j.checkedAt);
  assert.equal(r.code, 2);
});

test('batch: results keep file order regardless of completion order', async () => {
  const slow = {
    mail: async (d) => { await new Promise((r) => setTimeout(r, d === 'a.example' ? 40 : 1)); return [finding('mail', 'pass', 'x', { id: 'mail/x' })]; },
  };
  const out = [];
  await run(['mail', '--file', 'f', '--json'], { checks: slow, out: (s) => out.push(s), err: () => {}, readFile: () => 'a.example\nb.example\nc.example' });
  assert.deepEqual(JSON.parse(out[0]).domains.map((d) => d.domain), ['a.example', 'b.example', 'c.example']);
});

test('batch: a check that throws becomes an error finding instead of aborting the batch', async () => {
  const checks = { mail: async (d) => { if (d === 'b.example') throw new Error('kaboom'); return [finding('mail', 'pass', 'ok', { id: 'mail/x' })]; } };
  const out = [];
  const code = await run(['mail', '--file', 'f', '--json'], { checks, out: (s) => out.push(s), err: () => {}, readFile: () => 'a.example\nb.example' });
  assert.equal(code, 2);
  assert.equal(JSON.parse(out[0]).domains[1].findings[0].status, 'error');
});

// --- --dkim-selector, --format ---

test('--dkim-selector is passed to the checks as parsed selectors', async () => {
  const tracker = {};
  await invoke(['mail', 'example.com', '--dkim-selector', 'S1,s2'], { tracker, status: {} });
  assert.deepEqual(tracker.options.dkimSelectors, ['s1', 's2']);
});

test('--dkim-selector is rejected for tls/headers and for invalid selectors', async () => {
  assert.equal((await invoke(['tls', 'example.com', '--dkim-selector', 's1'])).code, 1);
  const r = await invoke(['mail', 'example.com', '--dkim-selector', 'bad selector']);
  assert.equal(r.code, 1);
  assert.match(r.err, /invalid DKIM selector/);
  assert.equal((await invoke(['mail', 'example.com', '--dkim-selector'])).code, 1);
});

test('--format: --json is an alias, conflicts are usage errors, unknown values are rejected', async () => {
  const a = await invoke(['mail', 'example.com', '--json'], { status: {} });
  const b = await invoke(['mail', 'example.com', '--format', 'json'], { status: {} });
  assert.deepEqual(Object.keys(JSON.parse(a.out)), Object.keys(JSON.parse(b.out)));
  assert.deepEqual(Object.keys(JSON.parse(a.out)), ['domain', 'checkedAt', 'summary', 'findings']);
  assert.equal((await invoke(['mail', 'example.com', '--json', '--format', 'sarif'])).code, 1);
  assert.equal((await invoke(['mail', 'example.com', '--json', '--format', 'json'])).code, 0);
  const bad = await invoke(['mail', 'example.com', '--format', 'xml']);
  assert.equal(bad.code, 1);
  assert.match(bad.err, /unknown format: xml/);
});

test('unknown options are usage errors', async () => {
  const r = await invoke(['mail', 'example.com', '--fast']);
  assert.equal(r.code, 1);
  assert.match(r.err, /unknown option: --fast/);
});

test('--format sarif and markdown work for a single domain (exit code unchanged)', async () => {
  const s = await invoke(['mail', 'broken.example', '--format', 'sarif']);
  assert.equal(s.code, 2);
  assert.equal(JSON.parse(s.out).version, '2.1.0');
  const m = await invoke(['mail', 'broken.example', '--format=markdown']);
  assert.equal(m.code, 2);
  assert.match(m.out, /^# Domain security posture report/);
});

// --- real process, still offline ---

test('CLI process: --help lists the new options; a bad --file exits 1 with a clear message', () => {
  const cli = fileURLToPath(new URL('../bin/secops.mjs', import.meta.url));
  const help = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  for (const flag of ['--format', '--file', '--concurrency', '--dkim-selector', '--skip-invalid']) assert.match(help.stdout, new RegExp(flag));
  const bad = spawnSync(process.execPath, [cli, 'all', '--file', 'definitely-missing-file.txt'], { encoding: 'utf8' });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /cannot read definitely-missing-file\.txt/);
});
