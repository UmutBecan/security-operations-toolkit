import { finding } from '../finding.mjs';

const HSTS_MIN_SECONDS = 15_552_000; // 180 days

export async function fetchHeaders(domain, { timeoutMs = 10_000 } = {}) {
  const res = await fetch(`https://${domain}/`, {
    method: 'GET',
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: { 'user-agent': 'security-operations-toolkit/0.1 (+defensive posture check)' },
  });
  await res.body?.cancel();
  return { url: res.url, status: res.status, headers: Object.fromEntries(res.headers) };
}

// headers: object with lower-case header names (as produced by fetchHeaders).
export function evaluateHeaders({ url, status, headers }) {
  const h = (name) => headers[name];
  const out = [finding('headers', 'info', `Final response ${status} from ${url}`)];

  if (!url.startsWith('https://')) {
    out.push(finding('headers', 'fail', 'Final page is not served over HTTPS', {
      remediation: 'Redirect all HTTP traffic to HTTPS.',
    }));
  }

  const hsts = h('strict-transport-security');
  if (!hsts) {
    out.push(finding('headers', 'warn', 'Strict-Transport-Security missing', {
      remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".',
    }));
  } else {
    const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? NaN);
    if (!(maxAge >= HSTS_MIN_SECONDS)) {
      out.push(finding('headers', 'warn', `HSTS max-age too short (${Number.isNaN(maxAge) ? 'missing' : maxAge}s)`, {
        remediation: 'Use at least max-age=15552000 (180 days); one year is common.',
      }));
    } else {
      out.push(finding('headers', 'pass', 'Strict-Transport-Security present', { detail: hsts }));
    }
  }

  const csp = h('content-security-policy');
  if (csp) {
    out.push(finding('headers', 'pass', 'Content-Security-Policy present (policy strength not evaluated)'));
  } else {
    out.push(finding('headers', 'warn', 'Content-Security-Policy missing', {
      remediation: 'Define a CSP; start in Content-Security-Policy-Report-Only mode.',
    }));
  }

  if ((h('x-content-type-options') || '').toLowerCase() === 'nosniff') {
    out.push(finding('headers', 'pass', 'X-Content-Type-Options: nosniff'));
  } else {
    out.push(finding('headers', 'warn', 'X-Content-Type-Options: nosniff missing'));
  }

  const xfo = (h('x-frame-options') || '').toLowerCase();
  if (/frame-ancestors/i.test(csp || '') || xfo === 'deny' || xfo === 'sameorigin') {
    out.push(finding('headers', 'pass', 'Clickjacking protection (frame-ancestors or X-Frame-Options)'));
  } else {
    out.push(finding('headers', 'warn', 'No clickjacking protection', {
      remediation: 'Add CSP "frame-ancestors \'self\'" or "X-Frame-Options: DENY".',
    }));
  }

  if (h('referrer-policy')) out.push(finding('headers', 'pass', `Referrer-Policy: ${h('referrer-policy')}`));
  else out.push(finding('headers', 'info', 'Referrer-Policy not set (browser default applies)'));

  const disclosed = ['server', 'x-powered-by'].filter((n) => /\d/.test(h(n) || ''))
    .map((n) => `${n}: ${h(n)}`);
  if (disclosed.length) {
    out.push(finding('headers', 'info', 'Software version disclosed in headers', { detail: disclosed.join('; ') }));
  }
  return out;
}

export async function checkHeaders(domain) {
  try {
    return evaluateHeaders(await fetchHeaders(domain));
  } catch (err) {
    const reason = err.cause?.code || err.name || err.message;
    return [finding('headers', 'error', `HTTPS request to ${domain} failed (${reason})`)];
  }
}
