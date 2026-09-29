import tls from 'node:tls';
import { finding } from '../finding.mjs';

const DAY_MS = 86_400_000;

// Connects once and records what the server presented. Trust is evaluated from
// Node's own chain and hostname verification (authorized / authorizationError).
export function inspectTls(host, { port = 443, timeoutMs = 10_000 } = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false });
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error('timeout')));
    socket.once('error', reject);
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();
      resolve({
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
        protocol: socket.getProtocol(),
        subject: cert.subject?.CN,
        issuer: cert.issuer?.O || cert.issuer?.CN,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
      });
      socket.end();
    });
  });
}

export function evaluateTls(info, now = new Date()) {
  const out = [];

  if (info.authorized) out.push(finding('tls', 'pass', 'Certificate chain and hostname are trusted'));
  else {
    out.push(finding('tls', 'fail', `Certificate not trusted (${info.authorizationError || 'unknown reason'})`, {
      remediation: 'Serve a certificate from a public CA that covers this hostname, with the full intermediate chain.',
    }));
  }

  const days = Math.floor((Date.parse(info.validTo) - now.getTime()) / DAY_MS);
  const detail = `valid to ${info.validTo}; issuer ${info.issuer ?? 'unknown'}`;
  if (Number.isNaN(days)) out.push(finding('tls', 'error', 'Could not read certificate expiry'));
  else if (days < 0) out.push(finding('tls', 'fail', `Certificate expired ${-days} day(s) ago`, { detail }));
  else if (days < 14) out.push(finding('tls', 'fail', `Certificate expires in ${days} day(s)`, { detail, remediation: 'Renew now and check that automatic renewal works.' }));
  else if (days < 30) out.push(finding('tls', 'warn', `Certificate expires in ${days} day(s)`, { detail, remediation: 'Confirm automatic renewal is scheduled.' }));
  else out.push(finding('tls', 'pass', `Certificate valid for ${days} more day(s)`, { detail }));

  // Only the negotiated version is known; this is not a full protocol enumeration.
  if (info.protocol === 'TLSv1.3' || info.protocol === 'TLSv1.2') {
    out.push(finding('tls', 'pass', `Negotiated ${info.protocol}`));
  } else {
    out.push(finding('tls', 'fail', `Negotiated legacy protocol ${info.protocol}`, {
      remediation: 'Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only.',
    }));
  }
  return out;
}

export async function checkTls(domain) {
  try {
    return evaluateTls(await inspectTls(domain));
  } catch (err) {
    return [finding('tls', 'error', `TLS connection to ${domain}:443 failed (${err.code || err.message})`)];
  }
}
