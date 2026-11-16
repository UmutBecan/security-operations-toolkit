import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { evaluateDkim, parseSelectors, dkimNotEvaluated } from '../src/checks/dkim.mjs';

const rsaRecord = (bits, extra = '') => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  return `v=DKIM1; k=rsa; ${extra}p=${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`;
};
const one = (rec, sel = 's1') => evaluateDkim(sel, 'example.com', rec === null ? [] : [rec]);

test('parseSelectors: splits, lower-cases, dedupes and validates', () => {
  assert.deepEqual(parseSelectors('S1, selector2,s1'), ['s1', 'selector2']);
  assert.deepEqual(parseSelectors('a.b'), ['a.b']);
  for (const bad of ['', ',', 'bad selector', '-x', 'x_', 'a..b', '../x', 'a;b', 'x'.repeat(64)]) {
    assert.throws(() => parseSelectors(bad), /selector/, bad);
  }
  assert.throws(() => parseSelectors(Array.from({ length: 11 }, (_, i) => `s${i}`).join(',')), /at most 10/);
});

test('no selector: DKIM is "not evaluated" (info) and never reported as missing', () => {
  const f = dkimNotEvaluated();
  assert.equal(f.status, 'info');
  assert.equal(f.id, 'dkim/not-evaluated');
  assert.match(f.detail, /cannot be enumerated from DNS/);
  assert.doesNotMatch(f.title, /missing/i);
});

test('selector with no record: warn, scoped to that selector, says other selectors may exist', () => {
  const [f] = one(null, 'k1');
  assert.equal(f.status, 'warn');
  assert.equal(f.id, 'dkim/selector-not-found');
  assert.equal(f.key, 'k1');
  assert.match(f.detail, /k1\._domainkey\.example\.com/);
  assert.match(f.detail, /other selectors may exist/);
});

test('non-DKIM TXT at the selector name is ignored', () => {
  assert.equal(one('v=spf1 -all')[0].id, 'dkim/selector-not-found');
});

test('empty p= is a revoked key (RFC 6376 section 3.6.1)', () => {
  const fs = one('v=DKIM1; k=rsa; p=');
  assert.deepEqual(fs.map((f) => f.id), ['dkim/revoked']);
  assert.equal(fs[0].status, 'warn');
  assert.match(fs[0].detail, /3\.6\.1/);
});

test('missing p= tag is invalid (fail)', () => {
  const [f] = one('v=DKIM1; k=rsa');
  assert.equal(f.id, 'dkim/invalid-key');
  assert.equal(f.status, 'fail');
});

test('2048-bit RSA passes', () => {
  const [f] = one(rsaRecord(2048));
  assert.equal(f.id, 'dkim/key-ok');
  assert.equal(f.status, 'pass');
  assert.match(f.title, /2048 bits/);
});

test('1024-bit RSA warns (RFC 8301 section 3.2 SHOULD 2048)', () => {
  const [f] = one(rsaRecord(1024));
  assert.equal(f.id, 'dkim/key-below-2048');
  assert.equal(f.status, 'warn');
});

test('512-bit RSA fails (RFC 8301 section 3.2 MUST NOT below 1024)', () => {
  const [f] = one(rsaRecord(512));
  assert.equal(f.id, 'dkim/key-too-short');
  assert.equal(f.status, 'fail');
});

test('default key type is rsa when k= is absent; whitespace inside p= is tolerated', () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const b64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const spaced = `${b64.slice(0, 40)} ${b64.slice(40)}`;
  assert.equal(one(`v=DKIM1; p=${spaced}`)[0].id, 'dkim/key-ok');
});

test('garbage p= is invalid, not a crash', () => {
  assert.equal(one('v=DKIM1; k=rsa; p=%%%not-base64%%%')[0].id, 'dkim/invalid-key');
  assert.equal(one('v=DKIM1; k=rsa; p=AAAA')[0].id, 'dkim/invalid-key');
});

test('Ed25519 key (RFC 8463): 32 raw bytes pass, anything else fails', () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  assert.equal(one(`v=DKIM1; k=ed25519; p=${raw}`)[0].id, 'dkim/key-ok');
  assert.equal(one('v=DKIM1; k=ed25519; p=AAAA')[0].id, 'dkim/invalid-key');
});

test('unknown key type is informational, not a failure', () => {
  const [f] = one('v=DKIM1; k=future; p=AAAA');
  assert.equal(f.id, 'dkim/key-type-unknown');
  assert.equal(f.status, 'info');
});

test('t=y adds a testing note without hiding the key result', () => {
  const fs = one(rsaRecord(2048, 't=y; '));
  assert.deepEqual(fs.map((f) => f.id), ['dkim/key-ok', 'dkim/testing']);
});

test('findings for different selectors carry distinct keys', () => {
  const a = evaluateDkim('s1', 'example.com', [])[0];
  const b = evaluateDkim('s2', 'example.com', [])[0];
  assert.notEqual(a.key, b.key);
});
