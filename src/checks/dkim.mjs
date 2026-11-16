import { createPublicKey } from 'node:crypto';
import { finding } from '../finding.mjs';
import { parseTags } from '../txt.mjs';

// DKIM key records live at <selector>._domainkey.<domain> (RFC 6376 section 3.6.2). A selector cannot be
// discovered from DNS, so this check only ever runs for selectors the operator names with --dkim-selector.
// Without one the toolkit reports that DKIM was not evaluated and never reports it as missing.

export const MAX_SELECTORS = 10;
const SELECTOR_LABEL = /^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$/;

// RFC 6376 section 3.1.1: a selector is one or more dot-separated sub-domain labels.
export function parseSelectors(value) {
  const list = String(value).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  if (list.length === 0) throw new Error('--dkim-selector needs at least one selector');
  if (list.length > MAX_SELECTORS) throw new Error(`at most ${MAX_SELECTORS} DKIM selectors are accepted`);
  for (const s of list) {
    if (s.length > 126 || !s.split('.').every((l) => SELECTOR_LABEL.test(l))) {
      throw new Error(`invalid DKIM selector: ${s}`);
    }
  }
  return [...new Set(list)];
}

export function dkimNotEvaluated() {
  return finding('dkim', 'info', 'DKIM not evaluated (no selector given)', {
    id: 'dkim/not-evaluated',
    detail: 'DKIM selectors cannot be enumerated from DNS, so a missing DKIM record cannot be proven. Pass --dkim-selector <s1,s2> to check known selectors.',
  });
}

function rsaBits(der) {
  // RFC 6376 section 3.6.1 specifies an RSAPublicKey (PKCS#1); in practice most records carry SubjectPublicKeyInfo.
  for (const type of ['spki', 'pkcs1']) {
    try {
      return createPublicKey({ key: der, format: 'der', type }).asymmetricKeyDetails?.modulusLength;
    } catch { /* try next encoding */ }
  }
  return undefined;
}

export function evaluateDkim(selector, domain, txtRecords) {
  const name = `${selector}._domainkey.${domain}`;
  const opts = (id, extra = {}) => ({ id, key: selector, ...extra });
  const records = txtRecords.filter((r) => {
    const t = parseTags(r);
    return (t.v === undefined || t.v.toUpperCase() === 'DKIM1') && ('p' in t || 'k' in t);
  });
  if (records.length === 0) {
    return [finding('dkim', 'warn', `No DKIM key record at selector "${selector}"`, opts('dkim/selector-not-found', {
      detail: `No DKIM TXT record at ${name}. This only shows that this selector is not published; DKIM cannot be enumerated from DNS, so other selectors may exist.`,
      remediation: 'Check the selector name against a DKIM-Signature header (s=) of a real message, or publish the key at this name.',
    }))];
  }
  const out = [];
  if (records.length > 1) {
    out.push(finding('dkim', 'info', `Selector "${selector}" has ${records.length} key records; evaluating the first`, opts('dkim/multiple-records')));
  }
  const tags = parseTags(records[0]);

  if (tags.p === undefined) {
    out.push(finding('dkim', 'fail', `DKIM record for "${selector}" has no p= tag`, opts('dkim/invalid-key', {
      detail: 'RFC 6376 section 3.6.1: p= (public key) is required.',
      remediation: 'Publish the full record, e.g. "v=DKIM1; k=rsa; p=<base64 key>".',
    })));
    return out;
  }
  const p = tags.p.replace(/\s+/g, '');
  if (p === '') {
    out.push(finding('dkim', 'warn', `DKIM key for selector "${selector}" is revoked (empty p=)`, opts('dkim/revoked', {
      detail: 'RFC 6376 section 3.6.1: an empty p= means the key has been revoked; messages signed with this selector fail verification.',
      remediation: 'If revocation is intentional, remove the record when no longer needed. Otherwise publish a new key under a new selector and sign with it.',
    })));
    return out;
  }

  const k = (tags.k || 'rsa').toLowerCase();
  const raw = /^[A-Za-z0-9+/]+={0,2}$/.test(p) ? Buffer.from(p, 'base64') : null;
  if (k === 'rsa') {
    const bits = raw ? rsaBits(raw) : undefined;
    if (!bits) {
      out.push(finding('dkim', 'fail', `DKIM key for "${selector}" is not a parseable RSA public key`, opts('dkim/invalid-key', {
        detail: 'The p= value is not valid base64 of an RSA public key (RFC 6376 section 3.6.1).',
        remediation: 'Re-publish the key exactly as generated; check that the TXT value was not truncated.',
      })));
    } else if (bits < 1024) {
      out.push(finding('dkim', 'fail', `DKIM RSA key for "${selector}" is ${bits} bits`, opts('dkim/key-too-short', {
        detail: 'RFC 8301 section 3.2: signers MUST use RSA keys of at least 1024 bits and verifiers MUST NOT accept signatures made with keys shorter than that.',
        remediation: 'Generate a 2048-bit RSA key and publish it under a new selector.',
      })));
    } else if (bits < 2048) {
      out.push(finding('dkim', 'warn', `DKIM RSA key for "${selector}" is ${bits} bits`, opts('dkim/key-below-2048', {
        detail: 'RFC 8301 section 3.2: signers SHOULD use RSA keys of at least 2048 bits.',
        remediation: 'Rotate to a 2048-bit key under a new selector.',
      })));
    } else {
      out.push(finding('dkim', 'pass', `DKIM RSA key for "${selector}" is ${bits} bits`, opts('dkim/key-ok')));
    }
  } else if (k === 'ed25519') {
    if (raw && raw.length === 32) {
      out.push(finding('dkim', 'pass', `DKIM Ed25519 key for "${selector}" (RFC 8463)`, opts('dkim/key-ok')));
    } else {
      out.push(finding('dkim', 'fail', `DKIM Ed25519 key for "${selector}" is not 32 bytes of base64`, opts('dkim/invalid-key', {
        detail: 'RFC 8463 defines k=ed25519 with a raw 256-bit public key in p=.',
        remediation: 'Re-publish the key exactly as generated.',
      })));
    }
  } else {
    out.push(finding('dkim', 'info', `DKIM key type "${tags.k}" for "${selector}" is not evaluated`, opts('dkim/key-type-unknown', {
      detail: 'RFC 6376 section 3.6.1: verifiers ignore unrecognized key types.',
    })));
  }

  if ((tags.t || '').split(':').map((f) => f.trim().toLowerCase()).includes('y')) {
    out.push(finding('dkim', 'info', `Selector "${selector}" is flagged as testing (t=y)`, opts('dkim/testing', {
      detail: 'RFC 6376 section 3.6.1: verifiers must not treat mail from testing-mode signers differently from unsigned mail, so DKIM adds no protection until t=y is removed.',
      remediation: 'Remove t=y once signing is verified.',
    })));
  }
  return out;
}
