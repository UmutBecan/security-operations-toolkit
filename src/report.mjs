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
