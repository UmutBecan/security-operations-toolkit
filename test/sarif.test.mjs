import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { finding } from '../src/finding.mjs';
import { toSarif, sarifLevel, artifactUriFor, validateSarifShape } from '../src/sarif.mjs';
import { RULES, ruleFor } from '../src/rules.mjs';
import { run } from '../src/cli.mjs';
import { VERSION } from '../src/meta.mjs';

const results = [
  {
    domain: 'a.example',
    line: 3,
    findings: [
      finding('dmarc', 'pass', 'Policy p=reject', { id: 'dmarc/policy-reject' }),
      finding('dmarc', 'info', 'DMARC record', { id: 'dmarc/record', detail: 'v=DMARC1; p=reject' }),
      finding('dmarc', 'warn', 'Legacy "pct=50" tag', { id: 'dmarc/legacy-pct', detail: 'sampling differs', remediation: 'Remove pct.' }),
      finding('mx', 'warn', 'No MX records', { id: 'mx/implicit', remediation: 'Publish MX.' }),
      finding('tls', 'fail', 'Certificate expired 3 day(s) ago', { id: 'tls/expired', detail: 'valid to X' }),
      finding('mta-sts', 'info', 'MTA-STS not published', { id: 'mta-sts/missing', remediation: 'Optional.' }),
      finding('dkim', 'warn', 'No DKIM key record at selector "s1"', { id: 'dkim/selector-not-found', key: 's1' }),
      finding('dkim', 'warn', 'No DKIM key record at selector "s2"', { id: 'dkim/selector-not-found', key: 's2' }),
    ],
  },
  { domain: 'b.example', line: 4, findings: [finding('tls', 'error', 'TLS connection failed', { id: 'tls/connect-error' })] },
];

test('level mapping: fail/error -> error, warn -> warning, actionable info -> note, pass and plain info omitted', () => {
  assert.equal(sarifLevel({ status: 'fail' }), 'error');
  assert.equal(sarifLevel({ status: 'error' }), 'error');
  assert.equal(sarifLevel({ status: 'warn' }), 'warning');
  assert.equal(sarifLevel({ status: 'info', remediation: 'x' }), 'note');
  assert.equal(sarifLevel({ status: 'info' }), null);
  assert.equal(sarifLevel({ status: 'pass' }), null);
});

test('SARIF: shape satisfies GitHub required fields', () => {
  const log = toSarif(results, { artifactUri: 'domains.txt' });
  assert.deepEqual(validateSarifShape(log), []);
  assert.equal(log.version, '2.1.0');
  assert.match(log.$schema, /sarif-2\.1\.0/);
  const driver = log.runs[0].tool.driver;
  assert.equal(driver.name, 'security-operations-toolkit');
  assert.equal(driver.version, VERSION);
  assert.equal(driver.semanticVersion, VERSION);
});

test('SARIF: only reportable findings become results, with the right levels and ids', () => {
  const r = toSarif(results).runs[0].results;
  assert.deepEqual(r.map((x) => [x.ruleId, x.level]), [
    ['dmarc/legacy-pct', 'warning'],
    ['mx/implicit', 'warning'],
    ['tls/expired', 'error'],
    ['mta-sts/missing', 'note'],
    ['dkim/selector-not-found', 'warning'],
    ['dkim/selector-not-found', 'warning'],
    ['tls/connect-error', 'error'],
  ]);
});

test('SARIF: message carries the domain, detail and remediation; location uses the line of the domain', () => {
  const [first] = toSarif(results, { artifactUri: 'infra/domains.txt' }).runs[0].results;
  assert.equal(first.message.text, 'a.example: Legacy "pct=50" tag. sampling differs. Remediation: Remove pct.');
  const loc = first.locations[0];
  assert.equal(loc.physicalLocation.artifactLocation.uri, 'infra/domains.txt');
  assert.deepEqual(loc.physicalLocation.region, { startLine: 3, startColumn: 1, endLine: 3, endColumn: 1 });
  assert.equal(loc.logicalLocations[0].name, 'a.example');
  assert.equal(first.properties.domain, 'a.example');
});

test('SARIF: only rules that have results are listed, ruleIndex points at them', () => {
  const run0 = toSarif(results).runs[0];
  const ids = run0.tool.driver.rules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual([...new Set(run0.results.map((r) => r.ruleId))].sort(), [...ids].sort());
  for (const res of run0.results) assert.equal(ids[res.ruleIndex], res.ruleId);
  for (const rule of run0.tool.driver.rules) {
    assert.ok(rule.shortDescription.text && rule.fullDescription.text && rule.help.text, rule.id);
    assert.ok(['error', 'warning', 'note'].includes(rule.defaultConfiguration.level));
  }
});

test('SARIF: fingerprints are stable across runs, differ per domain and per key, and are unique', () => {
  const a = toSarif(results).runs[0].results.map((r) => r.partialFingerprints.primaryLocationLineHash);
  const b = toSarif(results).runs[0].results.map((r) => r.partialFingerprints.primaryLocationLineHash);
  assert.deepEqual(a, b);
  assert.equal(new Set(a).size, a.length);
});

test('SARIF: a fingerprint does not depend on the line, so reordering the file does not reopen alerts', () => {
  const moved = results.map((r) => ({ ...r, line: r.line + 10 }));
  const f = (x) => toSarif(x).runs[0].results.map((r) => r.partialFingerprints.primaryLocationLineHash);
  assert.deepEqual(f(results), f(moved));
});

test('SARIF: identical findings for one domain get distinct fingerprints via a counter', () => {
  const dup = [{ domain: 'a.example', line: 1, findings: [
    finding('tls', 'warn', 'x', { id: 'tls/expiring' }), finding('tls', 'warn', 'x', { id: 'tls/expiring' })] }];
  const h = toSarif(dup).runs[0].results.map((r) => r.partialFingerprints.primaryLocationLineHash);
  assert.equal(new Set(h).size, 2);
  assert.match(h[0], /:1$/);
  assert.match(h[1], /:2$/);
});

test('SARIF: a clean run is still a valid log with zero results', () => {
  const log = toSarif([{ domain: 'a.example', line: 1, findings: [finding('spf', 'pass', 'ok', { id: 'spf/hardfail' })] }]);
  assert.deepEqual(validateSarifShape(log), []);
  assert.deepEqual(log.runs[0].results, []);
  assert.equal(log.runs[0].properties.domainsChecked, 1);
});

test('SARIF: a finding without a catalogued id still serialises under <check>/unclassified', () => {
  const log = toSarif([{ domain: 'a.example', line: 1, findings: [finding('spf', 'warn', 'legacy', {})] }]);
  assert.deepEqual(validateSarifShape(log), []);
  assert.equal(log.runs[0].results[0].ruleId, 'spf/unclassified');
});

test('artifactUriFor: relative forward-slash path, absolute and parent paths reduce to the file name', () => {
  assert.equal(artifactUriFor('domains.txt'), 'domains.txt');
  assert.equal(artifactUriFor('./ops/domains.txt'), 'ops/domains.txt');
  assert.equal(artifactUriFor('ops\\domains.txt'), 'ops/domains.txt');
  assert.equal(artifactUriFor('/etc/domains.txt'), 'domains.txt');
  assert.equal(artifactUriFor('C:\\work\\domains.txt'), 'domains.txt');
  assert.equal(artifactUriFor('../x/domains.txt'), 'domains.txt');
  assert.equal(artifactUriFor(undefined), 'domains.txt');
  assert.equal(artifactUriFor('-'), 'domains.txt');
});

test('validateSarifShape rejects the mistakes GitHub rejects', () => {
  const good = () => toSarif(results);
  const bad = (mutate) => { const l = good(); mutate(l); return validateSarifShape(l); };
  assert.ok(bad((l) => { l.version = '2.0.0'; }).length);
  assert.ok(bad((l) => { delete l.runs[0].tool.driver.name; }).length);
  assert.ok(bad((l) => { l.runs[0].tool.driver.rules[0].help.text = ''; }).length);
  assert.ok(bad((l) => { l.runs[0].results[0].ruleId = 'nope/nope'; }).length);
  assert.ok(bad((l) => { l.runs[0].results[0].level = 'critical'; }).length);
  assert.ok(bad((l) => { l.runs[0].results[0].locations = []; }).length);
  assert.ok(bad((l) => { l.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = '/abs/path'; }).length);
  assert.ok(bad((l) => { l.runs[0].results[0].locations[0].physicalLocation.region.startLine = 0; }).length);
  assert.ok(bad((l) => { delete l.runs[0].results[0].partialFingerprints; }).length);
  assert.ok(bad((l) => { l.runs[0].results[1].partialFingerprints = l.runs[0].results[0].partialFingerprints; }).length);
});

// --- rule catalog stays in sync with the checks ---

const srcDir = fileURLToPath(new URL('../src/', import.meta.url));
const sources = ['checks/mail.mjs', 'checks/tls.mjs', 'checks/headers.mjs', 'checks/mta-sts.mjs', 'checks/dkim.mjs', 'cli.mjs']
  .map((f) => readFileSync(srcDir + f, 'utf8')).join('\n');

test('rule catalog: every id used in the checks is catalogued, every catalogued id is used', () => {
  const used = new Set([...sources.matchAll(/(?:id: |opts\()'([a-z-]+\/[a-z0-9-]+)'/g)].map((m) => m[1]));
  for (const check of ['mx', 'spf', 'dmarc', 'dkim', 'mta-sts', 'tls-rpt']) used.add(`${check}/lookup-error`); // built from `${check}/lookup-error`
  assert.ok(used.size > 50);
  const missing = [...used].filter((id) => !RULES[id]);
  assert.deepEqual(missing, []);
  const dead = Object.keys(RULES).filter((id) => !used.has(id));
  assert.deepEqual(dead, []);
});

test('rule catalog: ids are <check>/<slug>, unique, with usable help text', () => {
  for (const [id, r] of Object.entries(RULES)) {
    assert.match(id, /^[a-z-]+\/[a-z0-9-]+$/);
    assert.equal(r.id, id);
    assert.ok(r.title.length > 3 && r.help.length > 3, id);
    assert.ok(['error', 'warning', 'note'].includes(r.level), id);
  }
  assert.equal(ruleFor({ id: 'tls/expired', check: 'tls' }).level, 'error');
});

// --- the real SARIF captured from live domains (see README "For pipelines") ---

test('captured real-run SARIF fixture passes the shape check', () => {
  const fixtures = fileURLToPath(new URL('./fixtures/', import.meta.url));
  const files = readdirSync(fixtures).filter((f) => f.endsWith('.sarif.json'));
  assert.ok(files.length > 0, 'expected at least one captured SARIF fixture');
  for (const f of files) {
    const log = JSON.parse(readFileSync(fixtures + f, 'utf8'));
    assert.deepEqual(validateSarifShape(log), [], f);
    for (const res of log.runs[0].results) assert.ok(RULES[res.ruleId], `${f}: ${res.ruleId} not in catalog`);
  }
});

test('CLI --format sarif output is valid JSON with only SARIF on stdout', async () => {
  const out = [];
  const code = await run(['mail', '--file', 'ops/domains.txt', '--format', 'sarif'], {
    checks: { mail: async () => [finding('spf', 'fail', 'No SPF record found', { id: 'spf/missing', remediation: 'Publish SPF.' })] },
    out: (s) => out.push(s),
    err: () => {},
    readFile: () => '# x\none.example\n',
  });
  assert.equal(code, 2);
  assert.equal(out.length, 1);
  const log = JSON.parse(out[0]);
  assert.deepEqual(validateSarifShape(log), []);
  const loc = log.runs[0].results[0].locations[0].physicalLocation;
  assert.equal(loc.artifactLocation.uri, 'ops/domains.txt');
  assert.equal(loc.region.startLine, 2);
});
