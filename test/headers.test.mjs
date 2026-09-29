import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateHeaders } from '../src/checks/headers.mjs';

const has = (fs, status, re) => fs.some((f) => f.status === status && re.test(f.title));
const run = (headers, url = 'https://example.com/') => evaluateHeaders({ url, status: 200, headers });

const strong = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
};

test('strong header set has no warn/fail', () => {
  const r = run(strong);
  assert.ok(!r.some((f) => f.status === 'warn' || f.status === 'fail'));
});

test('empty header set warns on each control', () => {
  const r = run({});
  for (const re of [/Strict-Transport-Security missing/, /Content-Security-Policy missing/, /nosniff missing/, /clickjacking/i]) {
    assert.ok(has(r, 'warn', re), re.toString());
  }
  assert.ok(has(r, 'info', /Referrer-Policy not set/));
});

test('short or malformed HSTS max-age warns', () => {
  assert.ok(has(run({ 'strict-transport-security': 'max-age=300' }), 'warn', /300s/));
  assert.ok(has(run({ 'strict-transport-security': 'includeSubDomains' }), 'warn', /missing/));
});

test('X-Frame-Options alone satisfies clickjacking protection', () => {
  assert.ok(has(run({ 'x-frame-options': 'SAMEORIGIN' }), 'pass', /Clickjacking/));
  assert.ok(has(run({ 'x-frame-options': 'ALLOW-FROM https://x.example' }), 'warn', /clickjacking/i));
});

test('non-HTTPS final URL fails', () => {
  assert.ok(has(run(strong, 'http://example.com/'), 'fail', /not served over HTTPS/));
});

test('version disclosure is reported as info only when a version is present', () => {
  assert.ok(has(run({ server: 'nginx/1.25.3' }), 'info', /version disclosed/));
  assert.ok(!has(run({ server: 'nginx' }), 'info', /version disclosed/));
});
