import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fetchPolicy } from '../src/checks/mta-sts.mjs';
import { isPublicAddress, policyHostFor, safeLookup, BlockedTargetError } from '../src/netsafe.mjs';

// A local plain-HTTP server stands in for the policy host; the lookup seam points the derived name at it.
// Everything is offline and loopback-only.
async function withServer(handler, fn) {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const opts = { transport: http, port, lookup: (h, o, cb) => (o.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4)) };
  try { await fn(opts, server); } finally { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); }
}

test('fetchPolicy: 200 returns status, content type and body; request path and host are fixed', async () => {
  let seen;
  await withServer((req, res) => {
    seen = { url: req.url, host: req.headers.host.split(':')[0], accept: req.headers.accept, method: req.method };
    res.setHeader('content-type', 'text/plain');
    res.end('version: STSv1\r\nmode: enforce\r\n');
  }, async (opts) => {
    const r = await fetchPolicy('example.com', opts);
    assert.equal(r.status, 200);
    assert.equal(r.contentType, 'text/plain');
    assert.match(r.body, /mode: enforce/);
    assert.deepEqual(seen, { url: '/.well-known/mta-sts.txt', host: 'mta-sts.example.com', accept: 'text/plain', method: 'GET' });
  });
});

test('fetchPolicy: a redirect is returned as-is and never followed, even to another host', async () => {
  let secondHit = false;
  await withServer((req, res) => {
    if (req.url !== '/.well-known/mta-sts.txt') secondHit = true;
    res.writeHead(302, { location: 'http://127.0.0.1/steal' });
    res.end();
  }, async (opts) => {
    const r = await fetchPolicy('example.com', opts);
    assert.equal(r.status, 302);
    assert.equal(r.body, '');
    assert.equal(secondHit, false);
  });
});

test('fetchPolicy: body over the cap is aborted (POLICY_TOO_LARGE)', async () => {
  await withServer((req, res) => { res.end('x'.repeat(5000)); }, async (opts) => {
    await assert.rejects(fetchPolicy('example.com', { ...opts, maxBytes: 1024 }), { code: 'POLICY_TOO_LARGE' });
  });
});

test('fetchPolicy: declared Content-Length over the cap is refused before reading', async () => {
  await withServer((req, res) => { res.setHeader('content-length', '999999'); res.write('x'); }, async (opts) => {
    await assert.rejects(fetchPolicy('example.com', { ...opts, maxBytes: 1024 }), { code: 'POLICY_TOO_LARGE' });
  });
});

test('fetchPolicy: a server that never answers times out', async () => {
  await withServer(() => { /* never respond */ }, async (opts) => {
    await assert.rejects(fetchPolicy('example.com', { ...opts, timeoutMs: 150 }), { code: 'ETIMEDOUT' });
  });
});

test('fetchPolicy: refuses internal names and IP literals before any connection', async () => {
  for (const d of ['localhost', '127.0.0.1', 'printer.local', 'host.internal', 'x.home.arpa', 'a.lan']) {
    await assert.rejects(fetchPolicy(d), BlockedTargetError, d);
  }
});

test('policyHostFor derives mta-sts.<domain> only', () => {
  assert.equal(policyHostFor('Example.COM'), 'mta-sts.example.com');
  assert.equal(policyHostFor('bücher.example'), 'mta-sts.xn--bcher-kva.example');
  for (const bad of ['http://example.com', 'example.com/path', 'example.com:8080', '10.0.0.1', '[::1]', 'example']) {
    assert.throws(() => policyHostFor(bad), BlockedTargetError, bad);
  }
});

test('isPublicAddress: private, loopback, link-local, metadata and mapped addresses are refused', () => {
  const refused = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1',
    '0.0.0.0', '224.0.0.1', '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:10.0.0.1', 'not-an-ip'];
  for (const a of refused) assert.equal(isPublicAddress(a), false, a);
  for (const a of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '140.82.112.3', '2606:4700:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isPublicAddress(a), true, a);
  }
});

test('safeLookup refuses a name that resolves to loopback (no DNS rebinding window)', async () => {
  await assert.rejects(
    new Promise((resolve, reject) => safeLookup('localhost', {}, (err, a) => (err ? reject(err) : resolve(a)))),
    { code: 'BLOCKED_TARGET' },
  );
});
