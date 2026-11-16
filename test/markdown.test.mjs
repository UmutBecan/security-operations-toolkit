import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finding } from '../src/finding.mjs';
import { formatMarkdown, mdEscape, domainStatus } from '../src/markdown.mjs';
import { formatBatchText } from '../src/report.mjs';

const results = [
  { domain: 'ok.example', findings: [finding('spf', 'pass', 'hardfail', { id: 'spf/hardfail' })] },
  { domain: 'meh.example', findings: [
    finding('dmarc', 'warn', 'No aggregate reporting address (rua)', { id: 'dmarc/no-rua', remediation: 'Add rua=mailto:<address>.' }),
    finding('spf', 'pass', 'hardfail', { id: 'spf/hardfail' }),
  ] },
  { domain: 'bad.example', findings: [
    finding('tls', 'fail', 'Certificate expired 3 day(s) ago', { id: 'tls/expired', detail: 'valid to X', remediation: 'Renew.' }),
    finding('mta-sts', 'info', 'MTA-STS not published', { id: 'mta-sts/missing', remediation: 'Optional hardening.' }),
    finding('mx', 'info', '1 MX record(s)', { id: 'mx/list', detail: '10 mail.bad.example' }),
  ] },
];

test('markdown: summary table lists every domain with status and counts', () => {
  const md = formatMarkdown(results, { generatedAt: '2026-01-01T00:00:00.000Z' });
  assert.match(md, /^# Domain security posture report/);
  assert.match(md, /domains: 3 · overall: \*\*action required\*\*/);
  assert.match(md, /\| ok\.example \| OK \| 0 \| 0 \| 0 \| 1 \|/);
  assert.match(md, /\| meh\.example \| REVIEW \| 0 \| 0 \| 1 \| 1 \|/);
  assert.match(md, /\| bad\.example \| ACTION REQUIRED \| 1 \| 0 \| 0 \| 0 \|/);
});

test('markdown: findings table carries severity, finding and remediation; clean domains and plain info are left out', () => {
  const md = formatMarkdown(results);
  assert.match(md, /### bad\.example/);
  assert.match(md, /\| Fail \| tls \| Certificate expired 3 day\(s\) ago\. valid to X \| Renew\. \|/);
  assert.match(md, /\| Note \| mta-sts \| MTA-STS not published \| Optional hardening\. \|/);
  assert.doesNotMatch(md, /### ok\.example/);
  assert.doesNotMatch(md, /1 MX record/);
  assert.ok(md.indexOf('| Fail |') < md.indexOf('| Note |'), 'most severe first');
});

test('markdown: nothing to report says so', () => {
  const md = formatMarkdown([results[0]]);
  assert.match(md, /No findings need attention\./);
  assert.match(md, /overall: \*\*no issues\*\*/);
});

test('markdown: attacker-controlled text from DNS or headers cannot inject markup', () => {
  const evil = '<img src=x onerror=alert(1)> [click](https://evil.example) | `code` **bold**\n# heading';
  const md = formatMarkdown([{ domain: 'a.example', findings: [finding('headers', 'warn', 'Software version disclosed', { id: 'headers/version-disclosed', detail: evil })] }]);
  assert.doesNotMatch(md, /<img/);
  assert.doesNotMatch(md, /\[click\]\(/);
  assert.doesNotMatch(md, /\n# heading/);
  const row = md.split('\n').find((l) => l.startsWith('| Warn'));
  assert.equal(row.split(/(?<!\\)\|/).length, 6, 'a pipe in the data must not add table columns');
});

test('mdEscape + domainStatus basics', () => {
  assert.equal(mdEscape('a|b\nc'), 'a\\|b c');
  assert.equal(domainStatus([{ status: 'error' }]), 'ACTION REQUIRED');
  assert.equal(domainStatus([{ status: 'warn' }]), 'REVIEW');
  assert.equal(domainStatus([{ status: 'info' }, { status: 'pass' }]), 'OK');
});

test('finding(): control characters from untrusted text are neutralised (terminal/log injection)', () => {
  const f = finding('headers', 'info', 'x\u001b[31mred', { detail: 'line1\nFAKE  PASS  forged\r\u0007', id: 'headers/response' });
  assert.doesNotMatch(f.title, /\u001b/);
  assert.doesNotMatch(f.detail, /[\n\r\u0007]/);
});

test('batch text: summary table has one row per domain plus a total', () => {
  const t = formatBatchText(results);
  assert.match(t, /Batch summary: 3 domain\(s\)/);
  assert.match(t, /DOMAIN\s+FAIL\s+ERROR\s+WARN\s+PASS\s+RESULT/);
  assert.match(t, /bad\.example\s+1\s+0\s+0\s+0\s+FAIL/);
  assert.match(t, /TOTAL\s+1\s+0\s+1\s+2\s+FAIL/);
});
