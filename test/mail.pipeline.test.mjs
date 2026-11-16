import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { checkMail } from '../src/checks/mail.mjs';
import { RULES } from '../src/rules.mjs';

// checkMail with every lookup injected: no network.
function fakeDns(txt = {}, { mx = [{ priority: 10, exchange: 'mail.example.com' }], policy } = {}) {
  const calls = { txt: [], policy: [] };
  return {
    calls,
    deps: {
      lookupTxt: async (name) => { calls.txt.push(name); return txt[name] || []; },
      lookupMx: async () => mx,
      lookupAddresses: async () => ({ a: [], aaaa: [] }),
      fetchPolicy: async (d) => { calls.policy.push(d); if (policy instanceof Error) throw policy; return policy; },
    },
  };
}
const ids = (fs) => fs.map((f) => f.id);

const GOOD = {
  'example.com': ['v=spf1 -all'],
  '_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:r@example.com'],
  '_mta-sts.example.com': ['v=STSv1; id=1'],
  '_smtp._tls.example.com': ['v=TLSRPTv1; rua=mailto:t@example.com'],
};
const POLICY = { status: 200, contentType: 'text/plain', body: 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 2592000' };

test('checkMail: MTA-STS and TLS-RPT are evaluated against the real MX hosts', async () => {
  const { deps, calls } = fakeDns(GOOD, { policy: POLICY });
  const fs = await checkMail('example.com', { deps });
  assert.ok(ids(fs).includes('mta-sts/mode-enforce'));
  assert.ok(ids(fs).includes('mta-sts/mx-covered'));
  assert.ok(ids(fs).includes('tls-rpt/present'));
  assert.deepEqual(calls.policy, ['example.com']);
  assert.ok(calls.txt.includes('_mta-sts.example.com'));
  assert.ok(calls.txt.includes('_smtp._tls.example.com'));
  assert.equal(fs.some((f) => f.status === 'fail' || f.status === 'error'), false);
});

test('checkMail: without --dkim-selector DKIM is "not evaluated" and no DKIM name is queried', async () => {
  const { deps, calls } = fakeDns(GOOD, { policy: POLICY });
  const fs = await checkMail('example.com', { deps });
  assert.ok(ids(fs).includes('dkim/not-evaluated'));
  assert.equal(calls.txt.some((n) => n.includes('_domainkey')), false);
  assert.equal(fs.some((f) => f.check === 'dkim' && f.status !== 'info'), false);
});

test('checkMail: named selectors are queried at <selector>._domainkey.<domain>', async () => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const rec = `v=DKIM1; k=rsa; p=${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`;
  const { deps, calls } = fakeDns({ ...GOOD, 'good._domainkey.example.com': [rec] }, { policy: POLICY });
  const fs = await checkMail('example.com', { dkimSelectors: ['good', 'gone'], deps });
  assert.ok(calls.txt.includes('good._domainkey.example.com'));
  assert.ok(calls.txt.includes('gone._domainkey.example.com'));
  assert.equal(fs.find((f) => f.id === 'dkim/key-ok').key, 'good');
  assert.equal(fs.find((f) => f.id === 'dkim/selector-not-found').key, 'gone');
  assert.equal(ids(fs).includes('dkim/not-evaluated'), false);
});

test('checkMail: no MTA-STS TXT record means the policy host is never contacted', async () => {
  const { deps, calls } = fakeDns({ ...GOOD, '_mta-sts.example.com': [] }, { policy: POLICY });
  const fs = await checkMail('example.com', { deps });
  assert.deepEqual(calls.policy, []);
  assert.ok(ids(fs).includes('mta-sts/missing'));
});

test('checkMail: Null MX / no MX leaves nothing to compare the policy against (no mismatch finding)', async () => {
  const { deps } = fakeDns(GOOD, { mx: [{ priority: 0, exchange: '' }], policy: POLICY });
  const fs = await checkMail('example.com', { deps });
  assert.equal(ids(fs).includes('mta-sts/mx-mismatch'), false);
});

test('checkMail: policy fetch failure and DNS failure are findings, not exceptions', async () => {
  const boom = Object.assign(new Error('refused'), { code: 'ECONNREFUSED' });
  const { deps } = fakeDns(GOOD, { policy: boom });
  deps.lookupTxt = async (n) => { if (n === '_smtp._tls.example.com') throw Object.assign(new Error('x'), { code: 'ESERVFAIL' }); return GOOD[n] || []; };
  const fs = await checkMail('example.com', { deps });
  assert.equal(fs.find((f) => f.id === 'mta-sts/policy-unavailable').status, 'warn');
  const err = fs.find((f) => f.id === 'tls-rpt/lookup-error');
  assert.equal(err.status, 'error');
});

test('checkMail: output order is stable (mx, spf, dmarc, mta-sts, tls-rpt, dkim)', async () => {
  const { deps } = fakeDns(GOOD, { policy: POLICY });
  const fs = await checkMail('example.com', { deps });
  const order = [];
  for (const f of fs) if (order[order.length - 1] !== f.check) order.push(f.check);
  assert.deepEqual(order, ['mx', 'spf', 'dmarc', 'mta-sts', 'tls-rpt', 'dkim']);
});

test('every finding the mail check can emit carries a catalogued rule id', async () => {
  const scenarios = [
    fakeDns(GOOD, { policy: POLICY }),
    fakeDns({}, { mx: [], policy: undefined }),
    fakeDns({ ...GOOD, '_mta-sts.example.com': ['v=STSv1; id=1'] }, { policy: { status: 301, contentType: '', body: '' } }),
  ];
  for (const { deps } of scenarios) {
    for (const f of await checkMail('example.com', { dkimSelectors: ['s1'], deps })) {
      assert.ok(f.id, `${f.check}: ${f.title} has no id`);
      assert.ok(RULES[f.id], `${f.id} missing from the rule catalog`);
    }
  }
});
