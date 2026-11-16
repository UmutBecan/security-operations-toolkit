import { normalizeDomain } from './domain.mjs';
import { checkMail } from './checks/mail.mjs';
import { checkTls } from './checks/tls.mjs';
import { checkHeaders } from './checks/headers.mjs';
import { formatText, exitCode, summarize, nextStepHint } from './report.mjs';

const CHECKS = { mail: checkMail, tls: checkTls, headers: checkHeaders };

export const USAGE = `Usage: secops <mail|tls|headers|all> <domain> [--json] [--no-hint]

  mail     MX, SPF and DMARC records (public DNS)
  tls      certificate trust, expiry and negotiated protocol on port 443
  headers  HTTP security headers of https://<domain>/
  all      run every check

Options:
  --json       machine-readable output (never includes the next-step hint)
  --no-hint    omit the one-line next-step hint at the end of the text report
  -h, --help   show this help

Exit codes: 0 no failures · 1 usage error · 2 at least one fail/error finding`;

// Pure of process state: checks and output sinks are injectable so the CLI is testable offline.
export async function run(argv, { checks = CHECKS, out = console.log, err = console.error } = {}) {
  if (argv.includes('--help') || argv.includes('-h')) {
    out(USAGE);
    return 0;
  }
  const json = argv.includes('--json');
  const hint = !argv.includes('--no-hint');
  const [check, target] = argv.filter((a) => a !== '--json' && a !== '--no-hint');
  if (!check || !target || !(check === 'all' || check in checks)) {
    err(USAGE);
    return 1;
  }

  let domain;
  try {
    domain = normalizeDomain(target);
  } catch (e) {
    err(`error: ${e.message}`);
    return 1;
  }

  const selected = check === 'all' ? Object.values(checks) : [checks[check]];
  const findings = (await Promise.all(selected.map((fn) => fn(domain)))).flat();

  if (json) {
    out(JSON.stringify({ domain, checkedAt: new Date().toISOString(), summary: summarize(findings), findings }, null, 2));
  } else {
    out(formatText(domain, findings));
    if (hint) out(`\n${nextStepHint(domain)}`);
  }
  return exitCode(findings);
}
