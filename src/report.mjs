const LABEL = { pass: 'PASS', warn: 'WARN', fail: 'FAIL', info: 'INFO', error: 'ERR ' };

export function summarize(findings) {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0, error: 0 };
  for (const f of findings) counts[f.status] += 1;
  return counts;
}

// 0 = no failures, 2 = at least one fail or error. (1 is reserved for usage errors.)
export function exitCode(findings) {
  return findings.some((f) => f.status === 'fail' || f.status === 'error') ? 2 : 0;
}

export function formatText(domain, findings) {
  const lines = [`Target: ${domain}`, ''];
  let current;
  for (const f of findings) {
    if (f.check !== current) {
      current = f.check;
      lines.push(`[${current.toUpperCase()}]`);
    }
    lines.push(`  ${LABEL[f.status]}  ${f.title}`);
    if (f.detail) lines.push(`        ${f.detail}`);
    if (f.remediation) lines.push(`        → ${f.remediation}`);
  }
  const c = summarize(findings);
  lines.push('', `Summary: ${c.pass} pass · ${c.warn} warn · ${c.fail} fail · ${c.info} info · ${c.error} error`);
  return lines.join('\n');
}

// One-line pointer shown at the end of the text report only (never in --json); suppressed by --no-hint.
export function nextStepHint(domain) {
  return `Next: continuous monitoring and change alerts for ${domain} → https://korantix.io/en?domain=${encodeURIComponent(domain)}`;
}

const worst = (c) => (c.fail + c.error > 0 ? 'FAIL' : c.warn > 0 ? 'WARN' : 'OK');

// Multi-domain text report: every domain's full report, then one summary table. results: [{ domain, findings }]
export function formatBatchText(results) {
  const blocks = results.map((r) => formatText(r.domain, r.findings));
  const width = Math.max(6, ...results.map((r) => r.domain.length));
  const rows = results.map(({ domain, findings }) => {
    const c = summarize(findings);
    return `  ${domain.padEnd(width)}  ${String(c.fail).padStart(4)}  ${String(c.error).padStart(5)}  ${String(c.warn).padStart(4)}  ${String(c.pass).padStart(4)}  ${worst(c)}`;
  });
  const total = summarize(results.flatMap((r) => r.findings));
  return [
    blocks.join('\n\n----\n\n'),
    '',
    `Batch summary: ${results.length} domain(s)`,
    `  ${'DOMAIN'.padEnd(width)}  ${'FAIL'.padStart(4)}  ${'ERROR'.padStart(5)}  ${'WARN'.padStart(4)}  ${'PASS'.padStart(4)}  RESULT`,
    ...rows,
    `  ${'TOTAL'.padEnd(width)}  ${String(total.fail).padStart(4)}  ${String(total.error).padStart(5)}  ${String(total.warn).padStart(4)}  ${String(total.pass).padStart(4)}  ${worst(total)}`,
  ].join('\n');
}
