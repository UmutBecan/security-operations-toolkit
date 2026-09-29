// A finding is the single output unit of every check.
// status: pass | warn | fail | info | error
export const STATUSES = ['pass', 'warn', 'fail', 'info', 'error'];

export function finding(check, status, title, { detail, remediation } = {}) {
  if (!STATUSES.includes(status)) throw new Error(`unknown status: ${status}`);
  const f = { check, status, title };
  if (detail) f.detail = detail;
  if (remediation) f.remediation = remediation;
  return f;
}
