import https from 'node:https';
import { finding } from '../finding.mjs';
import { parseTags } from '../txt.mjs';
import { policyHostFor, safeLookup } from '../netsafe.mjs';

// MTA-STS (RFC 8461) and SMTP TLS Reporting (RFC 8460). Section numbers below refer to those RFCs.

export const POLICY_MAX_BYTES = 64 * 1024;          // RFC 8461 section 3.3: suggested maximum policy size, 64 KB
export const POLICY_TIMEOUT_MS = 10_000;            // RFC 8461 section 3.3 suggests one minute; a CLI check uses less
export const MAX_AGE_CEILING = 31_557_600;          // RFC 8461 section 3.2: maximum value of max_age
export const MAX_AGE_RECOMMENDED = 604_800;         // one week; section 3.2: "typically ... weeks or greater"

const DOMAIN_LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;

// ---------- TXT record, RFC 8461 section 3.1 ----------

// "records that do not begin with v=STSv1; are discarded. If the number of resulting records is not one,
// or if the resulting record is syntactically invalid, senders MUST assume the recipient domain does not
// have an available MTA-STS Policy". The version token is case-sensitive in the ABNF (%s).
const isStsRecord = (r) => /^v=STSv1\s*;/.test(r.trim());

export function evaluateMtaStsTxt(txtRecords) {
  const recs = txtRecords.filter(isStsRecord);
  if (recs.length === 0) {
    return { valid: false, findings: [finding('mta-sts', 'info', 'MTA-STS not published', {
      id: 'mta-sts/missing',
      detail: 'No "v=STSv1" TXT record at _mta-sts.<domain> (RFC 8461 section 3.1).',
      remediation: 'Optional hardening: publish an MTA-STS policy (start with mode=testing and a TLS-RPT record) so sending servers require TLS to your MX hosts.',
    })] };
  }
  if (recs.length > 1) {
    return { valid: false, findings: [finding('mta-sts', 'warn', `Multiple MTA-STS TXT records (${recs.length})`, {
      id: 'mta-sts/invalid-record',
      detail: 'RFC 8461 section 3.1: if the number of v=STSv1 records is not one, senders assume there is no MTA-STS policy.',
      remediation: 'Keep exactly one "_mta-sts" TXT record.',
    })] };
  }
  const record = recs[0].trim();
  const tags = parseTags(record);
  if (!/^[A-Za-z0-9]{1,32}$/.test(tags.id || '')) {
    return { valid: false, findings: [finding('mta-sts', 'warn', 'MTA-STS TXT record has no valid id', {
      id: 'mta-sts/invalid-record',
      detail: `${record} — "id" is required and must be 1-32 letters/digits (RFC 8461 section 3.1); senders then assume there is no policy.`,
      remediation: 'Set id=<up to 32 alphanumerics> and change it whenever the policy changes.',
    })] };
  }
  return { valid: true, findings: [finding('mta-sts', 'info', 'MTA-STS TXT record', { id: 'mta-sts/record', detail: record })] };
}

// ---------- Policy file, RFC 8461 section 3.2 ----------

function validMxPattern(v) {
  const body = v.startsWith('*.') ? v.slice(2) : v;
  const labels = body.split('.');
  return labels.length >= 2 && labels.every((l) => DOMAIN_LABEL.test(l));
}

// Pattern matching, section 4.1: RFC 6125 matching where "*" may only match the entire left-most label,
// so "*.example.com" matches "mail.example.com" but not "example.com" or "foo.bar.example.com".
export function mxMatches(pattern, host) {
  const p = pattern.toLowerCase();
  const h = host.toLowerCase().replace(/\.$/, '');
  if (!p.startsWith('*.')) return p === h;
  const suffix = p.slice(1); // ".example.com"
  return h.endsWith(suffix) && !h.slice(0, -suffix.length).includes('.') && h.length > suffix.length;
}

// Parses the CRLF/LF separated "key: value" body. Unknown keys are ignored (the ABNF allows extensions).
export function parsePolicy(body) {
  const errors = [];
  const policy = { version: undefined, mode: undefined, maxAge: undefined, mx: [] };
  for (const raw of body.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const i = line.indexOf(':');
    if (i < 1) continue;
    const key = line.slice(0, i).trim();
    const value = line.slice(i + 1).trim();
    if (key === 'version') policy.version = value;
    else if (key === 'mode') policy.mode = value;
    else if (key === 'max_age') policy.maxAge = value;
    else if (key === 'mx') policy.mx.push(value);
  }
  if (policy.version !== 'STSv1') errors.push(`version must be "STSv1" (got ${JSON.stringify(policy.version ?? null)})`);
  if (!['enforce', 'testing', 'none'].includes(policy.mode)) {
    errors.push(`mode must be enforce, testing or none (got ${JSON.stringify(policy.mode ?? null)})`);
  }
  if (policy.maxAge === undefined || !/^\d{1,10}$/.test(policy.maxAge)) {
    errors.push(`max_age must be a non-negative integer (got ${JSON.stringify(policy.maxAge ?? null)})`);
  } else if (Number(policy.maxAge) > MAX_AGE_CEILING) {
    errors.push(`max_age ${policy.maxAge} exceeds the maximum of ${MAX_AGE_CEILING} (RFC 8461 section 3.2)`);
  } else {
    policy.maxAge = Number(policy.maxAge);
  }
  const badMx = policy.mx.filter((m) => !validMxPattern(m));
  if (badMx.length) errors.push(`invalid mx pattern(s): ${badMx.join(', ')}`);
  if (policy.mx.length === 0 && policy.mode !== 'none') errors.push('no mx patterns');
  return { policy, errors };
}

const secs = (n) => {
  const d = n / 86_400;
  const days = Number.isInteger(d) ? String(d) : d.toFixed(1);
  return `${n} s (${days} day${days === '1' ? '' : 's'})`;
};

// fetched: { status, contentType, body } | { error: { code, message } }; mxHosts: actual MX exchange names.
export function evaluateMtaStsPolicy(fetched, mxHosts = []) {
  const unavailable = (detail) => [finding('mta-sts', 'warn', 'MTA-STS TXT record is published but the policy could not be fetched', {
    id: 'mta-sts/policy-unavailable',
    detail,
    remediation: 'Serve https://mta-sts.<domain>/.well-known/mta-sts.txt with HTTP 200 (no redirect), a valid certificate for mta-sts.<domain>, and text/plain content. Until then senders behave as if MTA-STS were not deployed (RFC 8461 section 3.3).',
  })];
  if (fetched.error) return unavailable(`${fetched.error.code || 'ERROR'}: ${fetched.error.message}`);
  if (fetched.status !== 200) {
    const redirect = fetched.status >= 300 && fetched.status < 400;
    return unavailable(`HTTP ${fetched.status}${redirect ? ' — redirects MUST NOT be followed (RFC 8461 section 3.3), so this policy is unusable' : ''}`);
  }

  const out = [];
  const ct = (fetched.contentType || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'text/plain') {
    out.push(finding('mta-sts', 'warn', `Policy media type is "${ct || 'missing'}", expected text/plain`, {
      id: 'mta-sts/content-type',
      detail: 'RFC 8461 section 3.2: senders SHOULD validate that the media type is text/plain.',
      remediation: 'Serve the policy file with Content-Type: text/plain.',
    }));
  }

  const { policy, errors } = parsePolicy(fetched.body);
  if (errors.length) {
    out.push(finding('mta-sts', 'warn', 'MTA-STS policy file is invalid', {
      id: 'mta-sts/policy-invalid',
      detail: errors.join('; '),
      remediation: 'Fix the policy file: version: STSv1, mode, mx and max_age are all required (RFC 8461 section 3.2).',
    }));
    return out;
  }

  out.push(finding('mta-sts', 'info', 'MTA-STS policy', {
    id: 'mta-sts/policy',
    detail: `mode ${policy.mode}; max_age ${secs(policy.maxAge)}; mx ${policy.mx.join(', ') || '(none)'}`,
  }));

  if (policy.mode === 'enforce') {
    out.push(finding('mta-sts', 'pass', 'MTA-STS mode=enforce', { id: 'mta-sts/mode-enforce' }));
  } else if (policy.mode === 'testing') {
    out.push(finding('mta-sts', 'warn', 'MTA-STS mode=testing — delivery is not blocked on TLS failures', {
      id: 'mta-sts/mode-testing',
      detail: 'RFC 8461 section 5: in testing mode sending MTAs may deliver as though there were no MTA-STS validation failure.',
      remediation: 'Review TLS-RPT reports, then switch to mode: enforce and publish a new id.',
    }));
  } else {
    out.push(finding('mta-sts', 'info', 'MTA-STS mode=none — policy is treated as inactive', {
      id: 'mta-sts/mode-none',
      detail: 'RFC 8461 sections 5 and 8.3: "none" is the documented way to withdraw MTA-STS before removing it.',
      remediation: 'If MTA-STS should be active, set mode: testing (then enforce).',
    }));
    return out;
  }

  const hosts = mxHosts.map((h) => h.toLowerCase().replace(/\.$/, '')).filter(Boolean);
  if (hosts.length > 0) {
    const uncovered = hosts.filter((h) => !policy.mx.some((p) => mxMatches(p, h)));
    if (uncovered.length > 0) {
      out.push(finding('mta-sts', 'warn', `${uncovered.length} of ${hosts.length} MX host(s) not covered by the policy's mx patterns`, {
        id: 'mta-sts/mx-mismatch',
        detail: `Not matched: ${uncovered.join(', ')}. Patterns: ${policy.mx.join(', ')}. RFC 8461 section 4.1: a "*." pattern matches exactly one left-most label.${policy.mode === 'enforce' ? ' In enforce mode compliant senders will not deliver to uncovered hosts.' : ''}`,
        remediation: 'Add an mx: line for every MX host (or a "*.example.net" suffix pattern), then publish a new id.',
      }));
    } else {
      out.push(finding('mta-sts', 'pass', 'Every MX host is covered by the policy', { id: 'mta-sts/mx-covered' }));
    }
  }

  if (policy.maxAge < MAX_AGE_RECOMMENDED) {
    out.push(finding('mta-sts', 'warn', `max_age is short (${secs(policy.maxAge)})`, {
      id: 'mta-sts/max-age-low',
      detail: 'RFC 8461 section 3.2: the value is typically in the range of weeks or greater, to limit attacks at policy refresh time; section 10: prefer values as long as is practical.',
      remediation: 'Use at least max_age: 604800 (one week); 31557600 (one year, the maximum) once the policy is stable.',
    }));
  } else {
    out.push(finding('mta-sts', 'pass', `max_age ${secs(policy.maxAge)}`, { id: 'mta-sts/max-age-ok' }));
  }
  return out;
}

// ---------- policy fetch (HTTPS only, SSRF-guarded) ----------

// Fetches https://mta-sts.<domain>/.well-known/mta-sts.txt. Hardening, see SECURITY.md:
//  - host is derived from the validated domain only (policyHostFor), port 443, https only;
//  - no redirect is ever followed (RFC 8461 section 3.3 forbids it, which also rules out off-host redirects);
//  - connect-time DNS result must be a public address (safeLookup), so no internal service can be reached;
//  - certificate verification is on; body is capped at maxBytes and the whole request at timeoutMs.
// `transport`, `port` and `lookup` are test seams (a local HTTP server); the CLI never sets them.
export function fetchPolicy(domain, {
  timeoutMs = POLICY_TIMEOUT_MS, maxBytes = POLICY_MAX_BYTES, transport = https, port = 443, lookup = safeLookup,
} = {}) {
  return new Promise((resolve, reject) => {
    let host;
    try { host = policyHostFor(domain); } catch (e) { reject(e); return; }
    const req = transport.request({
      host, port, method: 'GET', path: '/.well-known/mta-sts.txt', servername: host, agent: false,
      lookup, rejectUnauthorized: true, minVersion: 'TLSv1.2',
      headers: { accept: 'text/plain', 'user-agent': 'security-operations-toolkit (+defensive posture check)' },
    });
    const fail = (err) => { clearTimeout(timer); req.destroy(); reject(err); };
    const timer = setTimeout(() => fail(Object.assign(new Error(`timed out after ${timeoutMs} ms`), { code: 'ETIMEDOUT' })), timeoutMs);
    req.on('error', (err) => { clearTimeout(timer); reject(err); });
    req.on('response', (res) => {
      const status = res.statusCode;
      const contentType = String(res.headers['content-type'] || '');
      if (status !== 200) { // never read a non-200 body; 3xx is deliberately not followed
        clearTimeout(timer); res.destroy(); req.destroy(); resolve({ status, contentType, body: '' }); return;
      }
      if (Number(res.headers['content-length']) > maxBytes) {
        fail(Object.assign(new Error(`policy larger than ${maxBytes} bytes`), { code: 'POLICY_TOO_LARGE' })); return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > maxBytes) fail(Object.assign(new Error(`policy larger than ${maxBytes} bytes`), { code: 'POLICY_TOO_LARGE' }));
        else chunks.push(c);
      });
      res.on('end', () => { clearTimeout(timer); resolve({ status, contentType, body: Buffer.concat(chunks).toString('utf8') }); });
      res.on('error', (err) => { clearTimeout(timer); reject(err); });
    });
    req.end();
  });
}

// Orchestrates TXT lookup then (only when a valid TXT record exists) the policy fetch.
export async function checkMtaSts(domain, { lookupTxt, fetchPolicy: fetcher = fetchPolicy, mxHosts = [] }) {
  const txt = await lookupTxt(`_mta-sts.${domain}`);
  const record = evaluateMtaStsTxt(txt);
  if (!record.valid) return record.findings;
  let fetched;
  try {
    fetched = await fetcher(domain);
  } catch (err) {
    fetched = { error: { code: err.code || err.name, message: err.message } };
  }
  return [...record.findings, ...evaluateMtaStsPolicy(fetched, mxHosts)];
}

// ---------- TLS-RPT, RFC 8460 section 3 ----------

// "records that do not begin with v=TLSRPTv1; are discarded. If the number of resulting records is not one,
// senders MUST assume the recipient domain does not implement TLSRPT." rua is required; schemes mailto and https.
const isTlsRptRecord = (r) => /^v=TLSRPTv1\s*;/.test(r.trim());

export function evaluateTlsRpt(txtRecords) {
  const recs = txtRecords.filter(isTlsRptRecord);
  if (recs.length === 0) {
    return [finding('tls-rpt', 'info', 'TLS-RPT not published', {
      id: 'tls-rpt/missing',
      detail: 'No "v=TLSRPTv1" TXT record at _smtp._tls.<domain> (RFC 8460 section 3).',
      remediation: 'Optional: publish "v=TLSRPTv1; rua=mailto:<address>" to receive daily reports about TLS failures when other servers deliver to you.',
    })];
  }
  if (recs.length > 1) {
    return [finding('tls-rpt', 'warn', `Multiple TLS-RPT records (${recs.length})`, {
      id: 'tls-rpt/invalid-record',
      detail: 'RFC 8460 section 3: if the number of v=TLSRPTv1 records is not one, senders assume the domain does not implement TLS-RPT.',
      remediation: 'Keep exactly one "_smtp._tls" TXT record.',
    })];
  }
  const record = recs[0].trim();
  const rua = (parseTags(record).rua || '').split(',').map((s) => s.trim()).filter(Boolean);
  const ok = rua.length > 0 && rua.every((u) => /^(mailto:[^\s]+@[^\s]+|https:\/\/[^\s]+)$/i.test(u));
  if (!ok) {
    return [finding('tls-rpt', 'warn', 'TLS-RPT record has no valid rua', {
      id: 'tls-rpt/invalid-record',
      detail: `${record} — rua is required and supports mailto: and https: URIs (RFC 8460 section 3).`,
      remediation: 'Set rua=mailto:<address> or rua=https://<endpoint>.',
    })];
  }
  return [finding('tls-rpt', 'pass', 'TLS-RPT reporting is published', { id: 'tls-rpt/present', detail: record })];
}
