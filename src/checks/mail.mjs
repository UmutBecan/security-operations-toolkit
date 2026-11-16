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

// A/AAAA lookup, used only to evaluate RFC 5321 section 5.1 "implicit MX" when a domain has no MX records.
export async function lookupAddresses(name) {
  const one = async (fn) => {
    try { return await fn(name); } catch (err) {
      if (NO_DATA.has(err.code)) return [];
      throw err;
    }
  };
  const [a, aaaa] = await Promise.all([one((n) => dns.resolve4(n)), one((n) => dns.resolve6(n))]);
  return { a, aaaa };
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

const isDmarcRecord = (r) => /^v=DMARC1\s*(;|$)/i.test(r.trim());

// Names (after "_dmarc.") visited by the RFC 9989 section 4.10 DNS Tree Walk when the Author Domain itself
// publishes no policy: the immediate parent (or, above 8 labels, the name shortened to 7 labels), then each
// further parent up to the TLD. At most 7 names, so with the initial query never more than 8 lookups.
export function treeWalkTargets(domain) {
  const labels = domain.split('.');
  const n = labels.length;
  const start = n <= 8 ? 1 : n - 7;
  const out = [];
  for (let i = start; i < n; i += 1) out.push(labels.slice(i).join('.'));
  return out;
}

// RFC 9989 section 4.10.1 policy discovery. `lookup` is injectable so the walk is testable offline.
// Nearest valid record wins; a target with several DMARC records yields none (discarded, steps 2 and 6).
export async function discoverDmarc(domain, lookup = lookupTxt) {
  const queried = [`_dmarc.${domain}`];
  const own = (await lookup(queried[0])).filter(isDmarcRecord);
  if (own.length > 0) return { records: own, name: domain, inherited: false, queried };
  for (const target of treeWalkTargets(domain)) {
    const name = `_dmarc.${target}`;
    queried.push(name);
    const found = (await lookup(name)).filter(isDmarcRecord);
    if (found.length === 1) return { records: found, name: target, inherited: true, queried };
  }
  return { records: [], name: null, inherited: false, queried };
}

export function evaluateDmarc(txtRecords, { inheritedFrom, queried } = {}) {
  const dmarc = txtRecords.filter(isDmarcRecord);
  if (dmarc.length === 0) {
    const scope = queried && queried.length > 0
      ? `Queried ${queried.join(', ')}; none held a DMARC record (RFC 9989 section 4.10 DNS tree walk).`
      : 'Only _dmarc.<domain> was queried; parent-domain policy was not checked.';
    return [finding('dmarc', 'fail', 'No DMARC record found', {
      detail: scope,
      remediation: 'Publish a TXT record at _dmarc.<domain>, starting with "v=DMARC1; p=none; rua=mailto:..." and tighten to quarantine/reject after reviewing reports.',
    })];
  }
  if (dmarc.length > 1) {
    return [finding('dmarc', 'fail', `Multiple DMARC records (${dmarc.length})`, {
      detail: 'Receivers discard all DMARC records when more than one is published (RFC 9989 section 4.10).',
      remediation: 'Keep exactly one record.',
    })];
  }

  const record = dmarc[0].trim();
  const tags = parseTags(record);
  const inherited = Boolean(inheritedFrom);
  const out = [finding('dmarc', 'info',
    inherited ? `DMARC record inherited from _dmarc.${inheritedFrom}` : 'DMARC record',
    { detail: record })];
  // A record found on a parent applies to this subdomain through "sp", falling back to "p" (RFC 9989 section 4.10.1).
  const polTag = inherited && tags.sp !== undefined ? 'sp' : 'p';
  const polValue = tags[polTag];
  const p = (polValue || '').toLowerCase();

  if (p === 'reject') out.push(finding('dmarc', 'pass', `Policy ${polTag}=reject`));
  else if (p === 'quarantine') out.push(finding('dmarc', 'pass', `Policy ${polTag}=quarantine`));
  else if (p === 'none') {
    out.push(finding('dmarc', 'warn', `Policy ${polTag}=none — monitoring only, spoofed mail is not blocked`, {
      remediation: 'Move to quarantine, then reject, once reports show legitimate senders pass.',
    }));
  } else {
    out.push(finding('dmarc', 'fail', `Missing or invalid policy (${polTag}=${polValue ?? ''})`, {
      remediation: 'Set p=none, p=quarantine or p=reject.',
    }));
  }

  // "pct" was removed by RFC 9989 (Appendix A.6; registered as historic). Under section 4.7 unknown tags
  // MUST be ignored, so RFC 9989 receivers apply the policy to all failing mail. RFC 7489 receivers may still sample.
  if (tags.pct !== undefined) {
    const n = Number(tags.pct);
    const harmless = Number.isFinite(n) && n >= 100;
    out.push(finding('dmarc', harmless ? 'info' : 'warn',
      `Legacy "pct=${tags.pct}" tag — removed in RFC 9989 and ignored by receivers that follow it`, {
        detail: harmless
          ? 'pct=100 equals the default, so behaviour is unchanged.'
          : `Receivers following RFC 9989 apply the policy to all failing mail, not ${tags.pct}%. Receivers still on RFC 7489 may sample by pct, so behaviour differs by receiver.`,
        remediation: 'Remove pct. To keep a policy in test mode use t=y (RFC 9989 section 4.7: failing mail is handled one level below the published policy); omit t or use t=n to enforce fully.',
      }));
  }
  if (tags.t !== undefined) {
    const t = tags.t.toLowerCase();
    if (t === 'y') {
      if (p === 'none') {
        out.push(finding('dmarc', 'info', 't=y has no effect with a "none" policy (RFC 9989 section 4.7)'));
      } else {
        out.push(finding('dmarc', 'warn', `Test mode t=y — failing mail is handled one level below ${polTag}=${p}`, {
          detail: 'RFC 9989 section 4.7: reject is applied as quarantine and quarantine as none while t=y.',
          remediation: 'Remove t=y (or set t=n) once reports show legitimate senders pass.',
        }));
      }
    } else if (t !== 'n') {
      out.push(finding('dmarc', 'warn', `Invalid t value "${tags.t}" (expected y or n)`, {
        remediation: 'Use t=y while testing, or t=n / omit it to enforce.',
      }));
    }
  }
  if (!tags.rua) {
    out.push(finding('dmarc', 'warn', 'No aggregate reporting address (rua)', {
      remediation: 'Add rua=mailto:<address> to receive aggregate reports.',
    }));
  }
  return out;
}

// RFC 5321 section 5.1: with no MX records the domain's own A/AAAA acts as an implicit MX (preference 0),
// so an empty MX answer does not mean "no mail". Only a Null MX (RFC 7505, "0 .") declares that.
export function evaluateMx(mxRecords, addresses = { a: [], aaaa: [] }) {
  if (mxRecords.length === 0) {
    const addrs = [...(addresses.a || []), ...(addresses.aaaa || [])];
    if (addrs.length > 0) {
      return [finding('mx', 'warn', "No MX records — mail falls back to the domain's own A/AAAA address (implicit MX)", {
        detail: `RFC 5321 section 5.1 treats the host itself as the mail exchanger (${addrs.join(', ')}).`,
        remediation: 'If this domain should receive mail, publish explicit MX records. If it should not, publish a Null MX ("0 .", RFC 7505).',
      })];
    }
    return [finding('mx', 'info', 'No MX records and no A/AAAA records — nothing to deliver mail to', {
      detail: 'Only a Null MX ("0 .", RFC 7505) explicitly states that a domain accepts no mail.',
    })];
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
  await run('mx', async () => {
    const mx = await lookupMx(domain);
    return evaluateMx(mx, mx.length === 0 ? await lookupAddresses(domain) : undefined);
  });
  await run('spf', async () => evaluateSpf(await lookupTxt(domain)));
  await run('dmarc', async () => {
    const found = await discoverDmarc(domain);
    return evaluateDmarc(found.records, { inheritedFrom: found.inherited ? found.name : undefined, queried: found.queried });
  });
  return out;
}
