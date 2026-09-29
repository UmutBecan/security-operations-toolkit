import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateTls } from '../src/checks/tls.mjs';

const NOW = new Date('2026-01-01T00:00:00Z');
const base = { authorized: true, protocol: 'TLSv1.3', issuer: 'Example CA', validTo: 'Jun  1 00:00:00 2026 GMT' };
const has = (fs, status, re) => fs.some((f) => f.status === status && re.test(f.title));

test('trusted, long-lived, TLS 1.3 passes', () => {
  const r = evaluateTls(base, NOW);
  assert.ok(r.every((f) => f.status === 'pass'));
  assert.ok(has(r, 'pass', /151 more day/));
});

test('untrusted certificate fails with reason', () => {
  assert.ok(has(evaluateTls({ ...base, authorized: false, authorizationError: 'ERR_TLS_CERT_ALTNAME_INVALID' }, NOW),
    'fail', /ALTNAME_INVALID/));
});

test('expiry thresholds', () => {
  const at = (validTo) => evaluateTls({ ...base, validTo }, NOW);
  assert.ok(has(at('Dec 25 00:00:00 2025 GMT'), 'fail', /expired 7 day/));
  assert.ok(has(at('Jan 10 00:00:00 2026 GMT'), 'fail', /expires in 9 day/));
  assert.ok(has(at('Jan 20 00:00:00 2026 GMT'), 'warn', /expires in 19 day/));
});

test('unreadable expiry is an error, not a pass', () => {
  assert.ok(has(evaluateTls({ ...base, validTo: undefined }, NOW), 'error', /expiry/));
});

test('legacy protocol fails, TLS 1.2 passes', () => {
  assert.ok(has(evaluateTls({ ...base, protocol: 'TLSv1.1' }, NOW), 'fail', /legacy/));
  assert.ok(has(evaluateTls({ ...base, protocol: 'TLSv1.2' }, NOW), 'pass', /TLSv1\.2/));
});
