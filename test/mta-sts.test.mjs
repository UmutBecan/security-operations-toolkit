import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateMtaStsTxt, evaluateMtaStsPolicy, parsePolicy, mxMatches, evaluateTlsRpt, checkMtaSts,
  MAX_AGE_RECOMMENDED,
} from '../src/checks/mta-sts.mjs';

const ids = (fs) => fs.map((f) => f.id);
const byId = (fs, id) => fs.find((f) => f.id === id);
const policy = (extra = {}) => ({
  status: 200,
  contentType: 'text/plain; charset=utf-8',
  body: ['version: STSv1', 'mode: enforce', 'mx: mail.example.com', 'max_age: 604800'].join('\r\n'),
  ...extra,
});

// --- TXT record (RFC 8461 section 3.1) ---

test('mta-sts txt: absent is info with remediation, not a failure', () => {
  const r = evaluateMtaStsTxt(['v=spf1 -all']);
  assert.equal(r.valid, false);
  assert.deepEqual(ids(r.findings), ['mta-sts/missing']);
  assert.equal(r.findings[0].status, 'info');
  assert.ok(r.findings[0].remediation);
});

test('mta-sts txt: valid record', () => {
  const r = evaluateMtaStsTxt(['v=STSv1; id=20160831085700Z;']);
  assert.equal(r.valid, true);
  assert.deepEqual(ids(r.findings), ['mta-sts/record']);
});

test('mta-sts txt: several records means no policy (section 3.1)', () => {
  const r = evaluateMtaStsTxt(['v=STSv1; id=a', 'v=STSv1; id=b', 'unrelated']);
  assert.equal(r.valid, false);
  assert.equal(r.findings[0].status, 'warn');
  assert.equal(r.findings[0].id, 'mta-sts/invalid-record');
});

test('mta-sts txt: missing or over-long id is invalid', () => {
  for (const rec of ['v=STSv1;', 'v=STSv1; id=', `v=STSv1; id=${'a'.repeat(33)}`, 'v=STSv1; id=bad-id']) {
    const r = evaluateMtaStsTxt([rec]);
    assert.equal(r.valid, false, rec);
    assert.equal(r.findings[0].id, 'mta-sts/invalid-record', rec);
  }
});

test('mta-sts txt: version token is case-sensitive per the ABNF', () => {
  assert.equal(evaluateMtaStsTxt(['v=stsv1; id=1']).findings[0].id, 'mta-sts/missing');
});

// --- policy parsing (section 3.2) ---

test('parsePolicy: accepts CRLF and LF, ignores unknown keys, collects every mx line', () => {
  const { policy: p, errors } = parsePolicy('version: STSv1\nmode: testing\nmx: a.example.com\nmx: *.example.net\nmax_age: 86400\nfuture: x\n');
  assert.deepEqual(errors, []);
  assert.equal(p.mode, 'testing');
  assert.deepEqual(p.mx, ['a.example.com', '*.example.net']);
  assert.equal(p.maxAge, 86400);
});

test('parsePolicy: reports bad version, mode, max_age and mx', () => {
  const { errors } = parsePolicy('version: STSv2\nmode: strict\nmax_age: -1\nmx: not_a_host\n');
  assert.equal(errors.length, 4);
  assert.match(errors.join(' '), /version/);
  assert.match(errors.join(' '), /mode/);
  assert.match(errors.join(' '), /max_age/);
  assert.match(errors.join(' '), /mx pattern/);
});

test('parsePolicy: max_age above 31557600 is rejected (section 3.2)', () => {
  const { errors } = parsePolicy('version: STSv1\nmode: enforce\nmx: a.example.com\nmax_age: 31557601');
  assert.match(errors.join(' '), /exceeds the maximum of 31557600/);
});

test('parsePolicy: mx is required unless mode is none', () => {
  assert.match(parsePolicy('version: STSv1\nmode: enforce\nmax_age: 1000').errors.join(' '), /no mx/);
  assert.deepEqual(parsePolicy('version: STSv1\nmode: none\nmax_age: 86400').errors, []);
});

// --- MX pattern matching (section 4.1) ---

test('mxMatches: wildcard matches exactly one left-most label', () => {
  assert.equal(mxMatches('*.example.com', 'mail.example.com'), true);
  assert.equal(mxMatches('*.example.com', 'example.com'), false);
  assert.equal(mxMatches('*.example.com', 'foo.bar.example.com'), false);
  assert.equal(mxMatches('mail.example.com', 'MAIL.example.com.'), true);
  assert.equal(mxMatches('mail.example.com', 'mail2.example.com'), false);
  assert.equal(mxMatches('*.example.com', 'evilexample.com'), false);
});

// --- policy evaluation ---

test('policy: enforce, covered MX, one-week max_age is clean', () => {
  const fs = evaluateMtaStsPolicy(policy(), ['mail.example.com.']);
  assert.deepEqual(fs.filter((f) => f.status === 'warn' || f.status === 'fail' || f.status === 'error'), []);
  assert.ok(byId(fs, 'mta-sts/mode-enforce'));
  assert.ok(byId(fs, 'mta-sts/mx-covered'));
  assert.ok(byId(fs, 'mta-sts/max-age-ok'));
});

test('policy: testing mode warns', () => {
  const fs = evaluateMtaStsPolicy(policy({ body: 'version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800' }), ['mail.example.com']);
  assert.equal(byId(fs, 'mta-sts/mode-testing').status, 'warn');
});

test('policy: mode none is informational and skips mx and max_age checks', () => {
  const fs = evaluateMtaStsPolicy(policy({ body: 'version: STSv1\nmode: none\nmax_age: 86400' }), ['mail.example.com']);
  assert.equal(byId(fs, 'mta-sts/mode-none').status, 'info');
  assert.equal(byId(fs, 'mta-sts/max-age-low'), undefined);
  assert.equal(byId(fs, 'mta-sts/mx-mismatch'), undefined);
});

test('policy: MX host outside the mx patterns warns and names the host', () => {
  const fs = evaluateMtaStsPolicy(policy(), ['mail.example.com', 'backup.other.net']);
  const f = byId(fs, 'mta-sts/mx-mismatch');
  assert.equal(f.status, 'warn');
  assert.match(f.title, /1 of 2/);
  assert.match(f.detail, /backup\.other\.net/);
  assert.match(f.detail, /enforce mode/);
});

test('policy: max_age under one week warns, exactly one week passes', () => {
  const low = evaluateMtaStsPolicy(policy({ body: 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400' }), ['mail.example.com']);
  assert.equal(byId(low, 'mta-sts/max-age-low').status, 'warn');
  assert.match(byId(low, 'mta-sts/max-age-low').detail, /section 3\.2/);
  assert.equal(MAX_AGE_RECOMMENDED, 604800);
  assert.ok(byId(evaluateMtaStsPolicy(policy(), ['mail.example.com']), 'mta-sts/max-age-ok'));
});

test('policy: non text/plain media type warns (section 3.2)', () => {
  const fs = evaluateMtaStsPolicy(policy({ contentType: 'text/html' }), ['mail.example.com']);
  assert.equal(byId(fs, 'mta-sts/content-type').status, 'warn');
});

test('policy: invalid file yields a single policy-invalid warning', () => {
  const fs = evaluateMtaStsPolicy(policy({ body: '<html>not a policy</html>' }), []);
  assert.deepEqual(ids(fs), ['mta-sts/policy-invalid']);
});

test('policy: redirect and other non-200 are "unavailable", never followed', () => {
  const r301 = evaluateMtaStsPolicy({ status: 301, contentType: '', body: '' }, []);
  assert.equal(r301[0].id, 'mta-sts/policy-unavailable');
  assert.match(r301[0].detail, /301/);
  assert.match(r301[0].detail, /MUST NOT be followed/);
  assert.match(evaluateMtaStsPolicy({ status: 404, contentType: '', body: '' }, [])[0].detail, /404/);
});

test('policy: fetch error is unavailable with the error code', () => {
  const f = evaluateMtaStsPolicy({ error: { code: 'ETIMEDOUT', message: 'timed out' } }, [])[0];
  assert.equal(f.status, 'warn');
  assert.match(f.detail, /ETIMEDOUT/);
});

// --- orchestration with injected lookups/fetch (no network) ---

test('checkMtaSts: no TXT record means the policy is never fetched', async () => {
  let fetched = false;
  const fs = await checkMtaSts('example.com', {
    lookupTxt: async () => [],
    fetchPolicy: async () => { fetched = true; return policy(); },
  });
  assert.equal(fetched, false);
  assert.deepEqual(ids(fs), ['mta-sts/missing']);
});

test('checkMtaSts: queries _mta-sts.<domain> and passes the domain to the fetcher', async () => {
  const seen = {};
  const fs = await checkMtaSts('example.com', {
    lookupTxt: async (n) => { seen.name = n; return ['v=STSv1; id=1']; },
    fetchPolicy: async (d) => { seen.domain = d; return policy(); },
    mxHosts: ['mail.example.com'],
  });
  assert.equal(seen.name, '_mta-sts.example.com');
  assert.equal(seen.domain, 'example.com');
  assert.ok(byId(fs, 'mta-sts/mode-enforce'));
});

test('checkMtaSts: a throwing fetcher becomes a warning, not a crash', async () => {
  const fs = await checkMtaSts('example.com', {
    lookupTxt: async () => ['v=STSv1; id=1'],
    fetchPolicy: async () => { const e = new Error('boom'); e.code = 'ECONNREFUSED'; throw e; },
  });
  assert.equal(byId(fs, 'mta-sts/policy-unavailable').status, 'warn');
});

// --- TLS-RPT (RFC 8460 section 3) ---

test('tls-rpt: missing is info with remediation', () => {
  const [f] = evaluateTlsRpt(['v=spf1 -all']);
  assert.equal(f.id, 'tls-rpt/missing');
  assert.equal(f.status, 'info');
  assert.ok(f.remediation);
});

test('tls-rpt: valid mailto and https rua pass', () => {
  assert.equal(evaluateTlsRpt(['v=TLSRPTv1; rua=mailto:tlsrpt@example.com'])[0].status, 'pass');
  assert.equal(evaluateTlsRpt(['v=TLSRPTv1;rua=https://report.example.com/v1, mailto:a@example.com'])[0].id, 'tls-rpt/present');
});

test('tls-rpt: missing or unsupported rua warns', () => {
  for (const rec of ['v=TLSRPTv1;', 'v=TLSRPTv1; rua=ftp://x.example.com', 'v=TLSRPTv1; rua=']) {
    assert.equal(evaluateTlsRpt([rec])[0].id, 'tls-rpt/invalid-record', rec);
  }
});

test('tls-rpt: multiple records means not implemented (warn)', () => {
  const fs = evaluateTlsRpt(['v=TLSRPTv1; rua=mailto:a@example.com', 'v=TLSRPTv1; rua=mailto:b@example.com']);
  assert.equal(fs[0].status, 'warn');
});
