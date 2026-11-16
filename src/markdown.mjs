import { summarize, exitCode } from './report.mjs';

// Findings can embed DNS TXT or HTTP header text from the target, which is attacker-controlled. Everything
// that came from a check is escaped so it cannot inject markdown, links, images or HTML into the report.
export function mdEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[\\`*[\]|]|(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])/g, (c) => `\\${c}`)
    .replace(/\s+/g, ' ')
    .trim();
}

const SEVERITY = { fail: 'Fail', error: 'Error', warn: 'Warn', info: 'Note' };
const ORDER = { fail: 0, error: 1, warn: 2, info: 3 };

export function domainStatus(findings) {
  if (findings.some((f) => f.status === 'fail' || f.status === 'error')) return 'ACTION REQUIRED';
  if (findings.some((f) => f.status === 'warn')) return 'REVIEW';
  return 'OK';
}

// results: [{ domain, findings }]. Short, management-readable: a status table first, then only what needs
// a decision (fail/error/warn, plus info findings that carry a remediation) with the remediation next to it.
export function formatMarkdown(results, { generatedAt = new Date().toISOString(), check = 'all' } = {}) {
  const all = results.flatMap((r) => r.findings);
  const total = summarize(all);
  const lines = [
    '# Domain security posture report',
    '',
    `Generated ${generatedAt} · checks: ${mdEscape(check)} · domains: ${results.length} · overall: **${exitCode(all) === 2 ? 'action required' : (total.warn > 0 ? 'review recommended' : 'no issues')}**`,
    '',
    '## Summary',
    '',
    '| Domain | Status | Fail | Error | Warn | Pass |',
    '|---|---|---:|---:|---:|---:|',
  ];
  for (const { domain, findings } of results) {
    const c = summarize(findings);
    lines.push(`| ${mdEscape(domain)} | ${domainStatus(findings)} | ${c.fail} | ${c.error} | ${c.warn} | ${c.pass} |`);
  }

  lines.push('', '## Findings');
  let any = false;
  for (const { domain, findings } of results) {
    const items = findings
      .filter((f) => f.status === 'fail' || f.status === 'error' || f.status === 'warn' || (f.status === 'info' && f.remediation))
      .sort((a, b) => ORDER[a.status] - ORDER[b.status]);
    if (items.length === 0) continue;
    any = true;
    lines.push('', `### ${mdEscape(domain)}`, '', '| Severity | Area | Finding | Remediation |', '|---|---|---|---|');
    for (const f of items) {
      const finding = f.detail ? `${mdEscape(f.title)}. ${mdEscape(f.detail)}` : mdEscape(f.title);
      lines.push(`| ${SEVERITY[f.status]} | ${mdEscape(f.check)} | ${finding} | ${f.remediation ? mdEscape(f.remediation) : ''} |`);
    }
  }
  if (!any) lines.push('', 'No findings need attention.');
  lines.push('', '_Read-only checks of public DNS, TLS and HTTP data. Findings with severity Note are optional hardening._', '');
  return lines.join('\n');
}
