#!/usr/bin/env node
import { normalizeDomain } from '../src/domain.mjs';
import { checkMail } from '../src/checks/mail.mjs';
import { checkTls } from '../src/checks/tls.mjs';
import { checkHeaders } from '../src/checks/headers.mjs';
import { formatText, exitCode, summarize } from '../src/report.mjs';

const CHECKS = { mail: checkMail, tls: checkTls, headers: checkHeaders };

const USAGE = `Usage: secops <mail|tls|headers|all> <domain> [--json]

  mail     MX, SPF and DMARC records (public DNS)
  tls      certificate trust, expiry and negotiated protocol on port 443
  headers  HTTP security headers of https://<domain>/
  all      run every check

Exit codes: 0 no failures · 1 usage error · 2 at least one fail/error finding`;

async function main(argv) {
  const json = argv.includes('--json');
  const [check, target] = argv.filter((a) => a !== '--json');
  if (!check || !target || !(check === 'all' || check in CHECKS)) {
    console.error(USAGE);
    return 1;
  }

  let domain;
  try {
    domain = normalizeDomain(target);
  } catch (err) {
    console.error(`error: ${err.message}`);
    return 1;
  }

  const selected = check === 'all' ? Object.values(CHECKS) : [CHECKS[check]];
  const findings = (await Promise.all(selected.map((fn) => fn(domain)))).flat();

  if (json) {
    console.log(JSON.stringify({ domain, checkedAt: new Date().toISOString(), summary: summarize(findings), findings }, null, 2));
  } else {
    console.log(formatText(domain, findings));
  }
  return exitCode(findings);
}

process.exitCode = await main(process.argv.slice(2));
