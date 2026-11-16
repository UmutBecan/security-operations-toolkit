import { readFileSync, statSync } from 'node:fs';
import { normalizeDomain } from './domain.mjs';
import { checkMail } from './checks/mail.mjs';
import { checkTls } from './checks/tls.mjs';
import { checkHeaders } from './checks/headers.mjs';
import { parseSelectors } from './checks/dkim.mjs';
import { finding } from './finding.mjs';
import { formatText, formatBatchText, exitCode, summarize, nextStepHint } from './report.mjs';
import { parseDomainList, mapLimit, MAX_FILE_BYTES, DEFAULT_CONCURRENCY, MAX_CONCURRENCY } from './batch.mjs';
import { toSarif, artifactUriFor } from './sarif.mjs';
import { formatMarkdown } from './markdown.mjs';

const CHECKS = { mail: checkMail, tls: checkTls, headers: checkHeaders };
const FORMATS = ['text', 'json', 'sarif', 'markdown'];

export const USAGE = `Usage: secops <mail|tls|headers|all> <domain> [options]
       secops <mail|tls|headers|all> --file <domains.txt> [options]

  mail     MX, SPF, DMARC, MTA-STS, TLS-RPT (public DNS + the MTA-STS policy file); DKIM for named selectors
  tls      certificate trust, expiry and negotiated protocol on port 443
  headers  HTTP security headers of https://<domain>/
  all      run every check

Options:
  --format <f>           text (default) | json | sarif | markdown
  --json                 same as --format json (never includes the next-step hint)
  --file <path>          check every domain in a file (one per line, "#" comments, "-" reads stdin)
  --concurrency <n>      domains checked in parallel with --file (default ${DEFAULT_CONCURRENCY}, max ${MAX_CONCURRENCY})
  --skip-invalid         with --file: warn about invalid lines and continue (default: exit 1 before checking)
  --dkim-selector <s,..> also check DKIM keys at <selector>._domainkey.<domain> (mail, all)
  --no-hint              omit the one-line next-step hint at the end of a single-domain text report
  -h, --help             show this help

Exit codes: 0 no failures · 1 usage error · 2 at least one fail/error finding (worst across all domains)`;

const VALUE_FLAGS = new Set(['--format', '--file', '--concurrency', '--dkim-selector']);
const BOOL_FLAGS = new Set(['--json', '--no-hint', '--skip-invalid']);

// Returns { positionals, flags } or { error }.
function parseArgs(argv) {
  const positionals = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '-') { positionals.push(a); continue; }
    if (!a.startsWith('-')) { positionals.push(a); continue; }
    const eq = a.indexOf('=');
    const name = eq > 0 ? a.slice(0, eq) : a;
    if (BOOL_FLAGS.has(name) && eq < 0) flags[name] = true;
    else if (VALUE_FLAGS.has(name)) {
      const value = eq > 0 ? a.slice(eq + 1) : argv[(i += 1)];
      if (value === undefined || (eq < 0 && value.startsWith('--'))) return { error: `${name} needs a value` };
      flags[name] = value;
    } else return { error: `unknown option: ${a}` };
  }
  return { positionals, flags };
}

const defaultReadFile = (file) => {
  if (file === '-') return readFileSync(0, 'utf8');
  if (statSync(file).size > MAX_FILE_BYTES) throw new Error(`file is larger than ${MAX_FILE_BYTES} bytes`);
  return readFileSync(file, 'utf8');
};

// Pure of process state: checks, file reading and output sinks are injectable so the CLI is testable offline.
export async function run(argv, { checks = CHECKS, out = console.log, err = console.error, readFile = defaultReadFile } = {}) {
  if (argv.includes('--help') || argv.includes('-h')) {
    out(USAGE);
    return 0;
  }
  const usage = (msg) => { if (msg) err(`error: ${msg}`); err(USAGE); return 1; };

  const parsed = parseArgs(argv);
  if (parsed.error) return usage(parsed.error);
  const { positionals, flags } = parsed;

  let format = flags['--format'] ?? 'text';
  if (!FORMATS.includes(format)) return usage(`unknown format: ${format} (expected ${FORMATS.join(', ')})`);
  if (flags['--json']) {
    if (flags['--format'] && flags['--format'] !== 'json') return usage('--json conflicts with --format ' + flags['--format']);
    format = 'json';
  }
  const hint = !flags['--no-hint'];
  const fileMode = flags['--file'] !== undefined;

  const [check, target, extra] = positionals;
  if (!check || !(check === 'all' || check in checks) || extra !== undefined) return usage();
  if (fileMode ? target !== undefined : !target) return usage(fileMode ? '--file cannot be combined with a domain argument' : undefined);

  let dkimSelectors = [];
  if (flags['--dkim-selector'] !== undefined) {
    if (!(check === 'all' || check === 'mail')) return usage('--dkim-selector applies to the mail and all checks');
    try { dkimSelectors = parseSelectors(flags['--dkim-selector']); } catch (e) { return usage(e.message); }
  }
  let concurrency = DEFAULT_CONCURRENCY;
  if (flags['--concurrency'] !== undefined) {
    concurrency = Number(flags['--concurrency']);
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > MAX_CONCURRENCY) {
      return usage(`--concurrency must be an integer from 1 to ${MAX_CONCURRENCY}`);
    }
  }

  let targets;
  if (fileMode) {
    let text;
    try { text = readFile(flags['--file']); } catch (e) {
      err(`error: cannot read ${flags['--file']}: ${e.code || e.message}`);
      return 1;
    }
    const list = parseDomainList(text);
    if (list.invalid.length > 0) {
      for (const bad of list.invalid) err(`${flags['--file']}:${bad.line}: invalid domain "${bad.input}" (${bad.message})`);
      if (!flags['--skip-invalid']) {
        err(`error: ${list.invalid.length} invalid line(s); fix them or pass --skip-invalid`);
        return 1;
      }
    }
    if (list.entries.length === 0) {
      err(`error: no domains found in ${flags['--file']}`);
      return 1;
    }
    targets = list.entries;
  } else {
    try {
      targets = [{ domain: normalizeDomain(target), line: 1 }];
    } catch (e) {
      err(`error: ${e.message}`);
      return 1;
    }
  }

  const names = check === 'all' ? Object.keys(checks) : [check];
  const options = { dkimSelectors };
  const results = await mapLimit(targets, concurrency, async ({ domain, line }) => {
    const parts = await Promise.all(names.map(async (name) => {
      try { return await checks[name](domain, options); } catch (e) {
        return [finding(name, 'error', `check failed (${e.code || e.message})`, { id: `${name}/lookup-error` })];
      }
    }));
    return { domain, line, findings: parts.flat() };
  });
  const allFindings = results.flatMap((r) => r.findings);
  const checkedAt = new Date().toISOString();
  const single = !fileMode;

  if (format === 'json') {
    const body = single
      ? { domain: results[0].domain, checkedAt, summary: summarize(allFindings), findings: allFindings }
      : {
        checkedAt,
        summary: summarize(allFindings),
        domains: results.map((r) => ({ domain: r.domain, summary: summarize(r.findings), findings: r.findings })),
      };
    out(JSON.stringify(body, null, 2));
  } else if (format === 'sarif') {
    out(JSON.stringify(toSarif(results, { artifactUri: artifactUriFor(fileMode ? flags['--file'] : undefined) }), null, 2));
  } else if (format === 'markdown') {
    out(formatMarkdown(results, { generatedAt: checkedAt, check }));
  } else if (single) {
    out(formatText(results[0].domain, results[0].findings));
    if (hint) out(`\n${nextStepHint(results[0].domain)}`);
  } else {
    out(formatBatchText(results));
  }
  return exitCode(allFindings);
}
