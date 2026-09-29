import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeDomain } from '../src/domain.mjs';

test('normalizes case, whitespace and trailing dot', () => {
  assert.equal(normalizeDomain('  Example.COM. '), 'example.com');
});

test('converts internationalized names to punycode', () => {
  assert.equal(normalizeDomain('bücher.example'), 'xn--bcher-kva.example');
});

for (const bad of ['', 'localhost', 'https://example.com', 'example.com/path', 'example.com:443',
  '192.0.2.1', '2001:db8::1', 'user@example.com', '-bad.example', 'bad-.example', 'a..example',
  `${'a'.repeat(64)}.example`, 'exa mple.com']) {
  test(`rejects ${JSON.stringify(bad)}`, () => {
    assert.throws(() => normalizeDomain(bad));
  });
}

test('rejects non-string input', () => {
  assert.throws(() => normalizeDomain(undefined));
});
