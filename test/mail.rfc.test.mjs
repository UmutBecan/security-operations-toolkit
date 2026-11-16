import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateDmarc, evaluateMx, discoverDmarc, treeWalkTargets } from '../src/checks/mail.mjs';

const find = (fs, status, re) => fs.find((f) => f.status === status && re.test(f.title));

// --- DMARC pct (RFC 9989 Appendix A.6) and t tag (section 4.7) ---

test('DMARC pct<100 is a legacy tag ignored by RFC 9989 receivers, with remediation', () => {
  const f = find(evaluateDmarc(['v=DMARC1; p=reject; rua=mailto:a@example.com; pct=25']), 'warn', /Legacy "pct=25"/);
  assert.ok(f);
  assert.match(f.title, /RFC 9989/);
  assert.match(f.detail, /not 25%/);
  assert.match(f.detail, /RFC 7489/);
  assert.match(f.remediation, /Remove pct/);
  assert.match(f.remediation, /t=y/);
});

test('DMARC pct=100 is only informational; pct=0 still warns', () => {
  const rec = (pct) => evaluateDmarc([`v=DMARC1; p=reject; rua=mailto:a@example.com; pct=${pct}`]);
  assert.ok(find(rec(100), 'info', /Legacy "pct=100"/));
  assert.equal(find(rec(100), 'warn', /pct/), undefined);
  assert.ok(find(rec(0), 'warn', /Legacy "pct=0"/));
});

test('DMARC without pct produces no pct finding', () => {
  const r = evaluateDmarc(['v=DMARC1; p=reject; rua=mailto:a@example.com']);
  assert.equal(r.some((f) => /pct/.test(f.title)), false);
});

test('DMARC t=y warns for enforcing policies, is informational for p=none', () => {
  const q = evaluateDmarc(['v=DMARC1; p=quarantine; t=y; rua=mailto:a@example.com']);
  assert.ok(find(q, 'warn', /Test mode t=y.*p=quarantine/));
  const n = evaluateDmarc(['v=DMARC1; p=none; t=y; rua=mailto:a@example.com']);
  assert.ok(find(n, 'info', /no effect/));
});

test('DMARC t=n and absent t are silent; invalid t warns', () => {
  const base = 'v=DMARC1; p=reject; rua=mailto:a@example.com';
  assert.equal(evaluateDmarc([`${base}; t=n`]).some((f) => /\bt=|Invalid t/.test(f.title)), false);
  assert.ok(find(evaluateDmarc([`${base}; t=maybe`]), 'warn', /Invalid t value "maybe"/));
});

// --- DMARC discovery (RFC 9989 section 4.10) ---

test('treeWalkTargets: parent chain up to the TLD', () => {
  assert.deepEqual(treeWalkTargets('example.com'), ['com']);
  assert.deepEqual(treeWalkTargets('a.b.example.com'), ['b.example.com', 'example.com', 'com']);
});

test('treeWalkTargets: more than 8 labels is shortened to 7 (RFC 9989 section 4.10 example), max 8 queries total', () => {
  const t = treeWalkTargets('a.b.c.d.e.f.g.h.i.j.mail.example.com');
  assert.deepEqual(t, ['g.h.i.j.mail.example.com', 'h.i.j.mail.example.com', 'i.j.mail.example.com',
    'j.mail.example.com', 'mail.example.com', 'example.com', 'com']);
  assert.equal(1 + t.length, 8);
  // exactly 8 labels is not shortened: starts at the immediate parent
  assert.equal(treeWalkTargets('a.b.c.d.e.f.example.com')[0], 'b.c.d.e.f.example.com');
});

const fakeLookup = (zone, log = []) => async (name) => { log.push(name); return zone[name] ?? []; };

test('discoverDmarc: own record wins and no parent is queried', async () => {
  const log = [];
  const r = await discoverDmarc('mail.example.com', fakeLookup({
    '_dmarc.mail.example.com': ['v=DMARC1; p=reject'],
    '_dmarc.example.com': ['v=DMARC1; p=none'],
  }, log));
  assert.equal(r.inherited, false);
  assert.deepEqual(log, ['_dmarc.mail.example.com']);
});

test('discoverDmarc: subdomain inherits the parent record', async () => {
  const log = [];
  const r = await discoverDmarc('mail.example.com', fakeLookup({ '_dmarc.example.com': ['v=DMARC1; p=reject; sp=quarantine'] }, log));
  assert.equal(r.inherited, true);
  assert.equal(r.name, 'example.com');
  assert.deepEqual(log, ['_dmarc.mail.example.com', '_dmarc.example.com']);
});

test('discoverDmarc: non-DMARC TXT and multiple records at one level are discarded, walk continues', async () => {
  const r = await discoverDmarc('a.b.example.com', fakeLookup({
    '_dmarc.b.example.com': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'],
    '_dmarc.example.com': ['something else', 'v=DMARC1; p=quarantine'],
  }));
  assert.equal(r.name, 'example.com');
  assert.equal(r.records.length, 1);
});

test('discoverDmarc: nothing found lists every queried name', async () => {
  const r = await discoverDmarc('a.example.com', fakeLookup({}));
  assert.deepEqual(r.records, []);
  assert.deepEqual(r.queried, ['_dmarc.a.example.com', '_dmarc.example.com', '_dmarc.com']);
});

test('discoverDmarc: a DNS error propagates (reported as an error finding, not as "no record")', async () => {
  await assert.rejects(discoverDmarc('example.com', async () => { throw Object.assign(new Error('x'), { code: 'ESERVFAIL' }); }));
});

test('DMARC evaluate: inherited record uses sp, falls back to p, and says where it came from', () => {
  const sp = evaluateDmarc(['v=DMARC1; p=none; sp=reject; rua=mailto:a@example.com'], { inheritedFrom: 'example.com' });
  assert.ok(find(sp, 'info', /inherited from _dmarc\.example\.com/));
  assert.ok(find(sp, 'pass', /Policy sp=reject/));
  const p = evaluateDmarc(['v=DMARC1; p=quarantine; rua=mailto:a@example.com'], { inheritedFrom: 'example.com' });
  assert.ok(find(p, 'pass', /Policy p=quarantine/));
});

test('DMARC "No record" finding states exactly what was queried', () => {
  const r = evaluateDmarc([], { queried: ['_dmarc.a.example.com', '_dmarc.example.com', '_dmarc.com'] });
  assert.equal(r[0].status, 'fail');
  assert.match(r[0].detail, /_dmarc\.a\.example\.com, _dmarc\.example\.com, _dmarc\.com/);
  assert.match(r[0].detail, /RFC 9989/);
  // without discovery info the finding must say parents were not checked
  assert.match(evaluateDmarc([])[0].detail, /parent-domain policy was not checked/);
});

// --- MX (RFC 5321 section 5.1 implicit MX, RFC 7505 Null MX) ---

test('MX: no MX but A/AAAA present reports implicit MX (warn), not "no mail"', () => {
  const r = evaluateMx([], { a: ['192.0.2.1'], aaaa: ['2001:db8::1'] });
  assert.equal(r[0].status, 'warn');
  assert.match(r[0].title, /implicit MX/);
  assert.match(r[0].detail, /192\.0\.2\.1/);
  assert.match(r[0].detail, /5321/);
  assert.match(r[0].remediation, /Null MX/);
  assert.doesNotMatch(r[0].title, /does not receive mail/);
});

test('MX: no MX and no addresses is informational and does not claim an explicit no-mail declaration', () => {
  const r = evaluateMx([], { a: [], aaaa: [] });
  assert.equal(r[0].status, 'info');
  assert.match(r[0].detail, /Only a Null MX/);
});

test('MX: Null MX (0 .) is the only "accepts no mail" statement, even if addresses exist', () => {
  const r = evaluateMx([{ priority: 0, exchange: '' }], { a: ['192.0.2.1'], aaaa: [] });
  assert.equal(r[0].status, 'info');
  assert.match(r[0].title, /Null MX/);
  assert.match(r[0].title, /accepts no mail/);
});
