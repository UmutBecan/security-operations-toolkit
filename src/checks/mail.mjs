import { promises as dns } from 'node:dns';
import { finding } from '../finding.mjs';

const NO_DATA = new Set(['ENODATA', 'ENOTFOUND']);
const SPF_LOOKUP_LIMIT = 10;

// TXT records arrive as arrays of <=255 byte chunks; join them per RFC 7208 §3.3.
export async function lookupTxt(name) {
  try {
    return (await dns.resolveTxt(name)).map((chunks) => chunks.join(''));
  } catch (err) {
    if (NO_DATA.has(err.code)) return [];
    throw err;
  }
}

export async function lookupMx(name) {
  try {
    return await dns.resolveMx(name);
  } catch (err) {
    if (NO_DATA.has(err.code)) return [];
    throw err;
  }
}

export function evaluateSpf(txtRecords) {
  const spf = txtRecords.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (spf.length === 0) {
    return [finding('spf', 'fail', 'No SPF record found', {
      remediation: 'Publish one TXT record starting with "v=spf1" that lists your sending services and ends with "-all" or "~all".',
    })];
  }
  if (spf.length > 1) {
    return [finding('spf', 'fail', `Multiple SPF records (${spf.length})`, {
      detail: 'RFC 7208 treats more than one SPF record as a permanent error.',
      remediation: 'Merge them into a single v=spf1 record.',
    })];
  }

  const record = spf[0].trim();
  const terms = record.split(/\s+/).slice(1);
  const out = [finding('spf', 'info', 'SPF record', { detail: record })];

  const all = terms.find((t) => /^[+\-~?]?all$/i.test(t));
  const hasRedirect = terms.some((t) => /^redirect=/i.test(t));
  if (!all) {
    out.push(hasRedirect
      ? finding('spf', 'info', 'Policy delegated with redirect=')
      : finding('spf', 'warn', 'No "all" mechanism — unlisted senders are not rejected', {
        remediation: 'End the record with "-all" (or "~all" while rolling out).',
      }));
  } else {
    const q = /^[+\-~?]/.test(all) ? all[0] : '+';
    if (q === '+') {
      out.push(finding('spf', 'fail', `"${all}" allows any server to send as this domain`, {
        remediation: 'Replace with "-all" or "~all".',
      }));
    } else if (q === '?') {
      out.push(finding('spf', 'warn', '"?all" (neutral) gives receivers no guidance', {
        remediation: 'Use "-all" or "~all".',
      }));
    } else if (q === '~') {
      out.push(finding('spf', 'pass', '"~all" softfail policy'));
    } else {
      out.push(finding('spf', 'pass', '"-all" hardfail policy'));
    }
  }

  // Top-level count only: nested includes are not resolved, so the real total can be higher.
  const lookups = terms.filter((t) => /^[+\-~?]?(include:|a(:|\/|$)|mx(:|\/|$)|ptr(:|$)|exists:)/i.test(t)
    || /^redirect=/i.test(t)).length;
  if (lookups > SPF_LOOKUP_LIMIT) {
    out.push(finding('spf', 'fail', `${lookups} DNS-querying terms at top level (limit ${SPF_LOOKUP_LIMIT})`, {
      remediation: 'Remove unused includes or flatten the record.',
    }));
  } else {
    out.push(finding('spf', 'info', `${lookups} DNS-querying terms at top level (limit ${SPF_LOOKUP_LIMIT}; nested includes not counted)`));
  }

  if (terms.some((t) => /^[+\-~?]?ptr(:|$)/i.test(t))) {
    out.push(finding('spf', 'warn', '"ptr" mechanism is deprecated (RFC 7208 §5.5)', {
      remediation: 'Replace "ptr" with explicit ip4/ip6 or include terms.',
    }));
  }
  return out;
}

export function parseTags(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return tags;
}

export function evaluateDmarc(txtRecords) {
  const dmarc = txtRecords.filter((r) => /^v=DMARC1\s*(;|$)/i.test(r.trim()));
  if (dmarc.length === 0) {
    return [finding('dmarc', 'fail', 'No DMARC record found', {
      remediation: 'Publish a TXT record at _dmarc.<domain>, starting with "v=DMARC1; p=none; rua=mailto:..." and tighten to quarantine/reject after reviewing reports.',
    })];
  }
  if (dmarc.length > 1) {
    return [finding('dmarc', 'fail', `Multiple DMARC records (${dmarc.length})`, {
      detail: 'Receivers ignore DMARC when more than one record is published.',
      remediation: 'Keep exactly one record.',
    })];
  }

  const record = dmarc[0].trim();
  const tags = parseTags(record);
  const out = [finding('dmarc', 'info', 'DMARC record', { detail: record })];
  const p = (tags.p || '').toLowerCase();

  if (p === 'reject') out.push(finding('dmarc', 'pass', 'Policy p=reject'));
  else if (p === 'quarantine') out.push(finding('dmarc', 'pass', 'Policy p=quarantine'));
  else if (p === 'none') {
    out.push(finding('dmarc', 'warn', 'Policy p=none — monitoring only, spoofed mail is not blocked', {
      remediation: 'Move to p=quarantine, then p=reject, once reports show legitimate senders pass.',
    }));
  } else {
    out.push(finding('dmarc', 'fail', `Missing or invalid policy (p=${tags.p ?? ''})`, {
      remediation: 'Set p=none, p=quarantine or p=reject.',
    }));
  }

  if (tags.pct !== undefined && Number(tags.pct) < 100) {
    out.push(finding('dmarc', 'warn', `Policy applied to ${tags.pct}% of mail (pct)`));
  }
  if (!tags.rua) {
    out.push(finding('dmarc', 'warn', 'No aggregate reporting address (rua)', {
      remediation: 'Add rua=mailto:<address> to receive aggregate reports.',
    }));
  }
  return out;
}

export function evaluateMx(mxRecords) {
  if (mxRecords.length === 0) {
    return [finding('mx', 'info', 'No MX records — domain does not receive mail')];
  }
  if (mxRecords.length === 1 && mxRecords[0].exchange === '') {
    return [finding('mx', 'info', 'Null MX (RFC 7505) — domain explicitly accepts no mail')];
  }
  const hosts = [...mxRecords].sort((a, b) => a.priority - b.priority)
    .map((r) => `${r.priority} ${r.exchange}`).join(', ');
  return [finding('mx', 'info', `${mxRecords.length} MX record(s)`, { detail: hosts })];
}

// DKIM is intentionally not checked: without a known selector its absence cannot be proven.
export async function checkMail(domain) {
  const out = [];
  const run = async (check, fn) => {
    try { out.push(...(await fn())); } catch (err) {
      out.push(finding(check, 'error', `DNS lookup failed (${err.code || err.message})`));
    }
  };
  await run('mx', async () => evaluateMx(await lookupMx(domain)));
  await run('spf', async () => evaluateSpf(await lookupTxt(domain)));
  await run('dmarc', async () => evaluateDmarc(await lookupTxt(`_dmarc.${domain}`)));
  return out;
}
