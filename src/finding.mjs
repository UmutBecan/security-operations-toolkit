// A finding is the single output unit of every check.
// status: pass | warn | fail | info | error
// id: stable rule id "<check>/<slug>" (see src/rules.mjs); used by SARIF and for suppression/tracking.
// key: optional discriminator when one rule can fire several times for one domain (e.g. one DKIM selector each).
export const STATUSES = ['pass', 'warn', 'fail', 'info', 'error'];

// Text that originates from DNS or HTTP responses is attacker-influenced. Replace control characters
// (terminal escape sequences, newlines that could forge extra report lines) and Unicode line/paragraph
// separators before it reaches any output.
const CONTROL = /[\p{Cc}\p{Zl}\p{Zp}]/gu;
export const clean = (s) => String(s).replace(CONTROL, ' ');

export function finding(check, status, title, { detail, remediation, id, key } = {}) {
  if (!STATUSES.includes(status)) throw new Error(`unknown status: ${status}`);
  const f = { check, status, title: clean(title) };
  if (id) f.id = id;
  if (key !== undefined) f.key = clean(key);
  if (detail) f.detail = clean(detail);
  if (remediation) f.remediation = clean(remediation);
  return f;
}
