import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateSpf, evaluateDmarc, evaluateMx, parseTags } from '../src/checks/mail.mjs';

const statuses = (fs) => fs.map((f) => f.status);
const has = (fs, status, re) => fs.some((f) => f.status === status && re.test(f.title));

test('SPF: missing record fails', () => {
  assert.deepEqual(statuses(evaluateSpf(['google-site-verification=abc'])), ['fail']);
});

test('SPF: multiple records fail', () => {
  const r = evaluateSpf(['v=spf1 -all', 'v=spf1 include:_spf.example.net ~all']);
  assert.ok(has(r, 'fail', /Multiple SPF/));
});

test('SPF: -all passes, ~all passes', () => {
  assert.ok(has(evaluateSpf(['v=spf1 mx -all']), 'pass', /-all/));
  assert.ok(has(evaluateSpf(['v=spf1 mx ~all']), 'pass', /~all/));
});

test('SPF: +all and bare all fail, ?all warns', () => {
  assert.ok(has(evaluateSpf(['v=spf1 +all']), 'fail', /allows any server/));
  assert.ok(has(evaluateSpf(['v=spf1 all']), 'fail', /allows any server/));
  assert.ok(has(evaluateSpf(['v=spf1 ?all']), 'warn', /neutral/));
});

test('SPF: missing all warns unless redirect is used', () => {
  assert.ok(has(evaluateSpf(['v=spf1 mx']), 'warn', /No "all"/));
  const r = evaluateSpf(['v=spf1 redirect=_spf.example.net']);
  assert.ok(!has(r, 'warn', /No "all"/));
});

test('SPF: more than 10 top-level DNS terms fails', () => {
  const includes = Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(' ');
  assert.ok(has(evaluateSpf([`v=spf1 ${includes} -all`]), 'fail', /11 DNS-querying terms/));
  assert.ok(has(evaluateSpf(['v=spf1 a mx include:x.example.net -all']), 'info', /^3 DNS-querying/));
});

test('SPF: ptr is flagged as deprecated', () => {
  assert.ok(has(evaluateSpf(['v=spf1 ptr -all']), 'warn', /ptr/));
});

test('SPF: non-SPF TXT beginning with v=spf10 is not treated as SPF', () => {
  assert.deepEqual(statuses(evaluateSpf(['v=spf10 -all'])), ['fail']);
});

test('DMARC: parseTags', () => {
  assert.deepEqual(parseTags('v=DMARC1; p=reject; rua=mailto:a@example.com'),
    { v: 'DMARC1', p: 'reject', rua: 'mailto:a@example.com' });
});

test('DMARC: missing and multiple records fail', () => {
  assert.deepEqual(statuses(evaluateDmarc([])), ['fail']);
  assert.ok(has(evaluateDmarc(['v=DMARC1; p=none', 'v=DMARC1; p=reject']), 'fail', /Multiple/));
});

test('DMARC: policy levels', () => {
  assert.ok(has(evaluateDmarc(['v=DMARC1; p=reject; rua=mailto:a@example.com']), 'pass', /reject/));
  assert.ok(has(evaluateDmarc(['v=DMARC1; p=quarantine; rua=mailto:a@example.com']), 'pass', /quarantine/));
  assert.ok(has(evaluateDmarc(['v=DMARC1; p=none; rua=mailto:a@example.com']), 'warn', /monitoring only/));
  assert.ok(has(evaluateDmarc(['v=DMARC1; rua=mailto:a@example.com']), 'fail', /invalid policy/));
});

test('DMARC: pct < 100 and missing rua warn', () => {
  const r = evaluateDmarc(['v=DMARC1; p=reject; pct=50']);
  assert.ok(has(r, 'warn', /50%/));
  assert.ok(has(r, 'warn', /rua/));
});

test('MX: none, null MX and sorted list', () => {
  assert.ok(has(evaluateMx([]), 'info', /No MX/));
  assert.ok(has(evaluateMx([{ priority: 0, exchange: '' }]), 'info', /Null MX/));
  const r = evaluateMx([{ priority: 20, exchange: 'b.example.net' }, { priority: 10, exchange: 'a.example.net' }]);
  assert.equal(r[0].detail, '10 a.example.net, 20 b.example.net');
});
