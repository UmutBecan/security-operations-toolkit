// Rule catalog: one entry per stable finding id. Used by SARIF (tool.driver.rules) and by tests that keep
// the ids emitted by the checks and this list in sync. Ids never change meaning; retire an id rather than reuse it.
// Entry: id -> [defaultLevel (error|warning|note), short title, help text].
// Status mapping used throughout: fail/error -> error, warn -> warning, info -> note, pass -> (not reported).

const R = {
  // mx
  'mx/list': ['note', 'MX records published', 'Lists the mail exchangers. No action needed.'],
  'mx/null': ['note', 'Null MX: domain accepts no mail (RFC 7505)', 'The domain explicitly declares that it accepts no mail.'],
  'mx/implicit': ['warning', 'No MX records: implicit MX in effect (RFC 5321 section 5.1)', 'Publish explicit MX records if the domain should receive mail, or a Null MX ("0 .", RFC 7505) if it should not.'],
  'mx/none': ['note', 'No MX and no A/AAAA records', 'Nothing can deliver mail to this name. Publish a Null MX (RFC 7505) to state that explicitly.'],
  'mx/lookup-error': ['error', 'MX lookup failed', 'The DNS query failed (timeout, SERVFAIL). Re-run; if it persists, check the domain\'s name servers.'],
  // spf
  'spf/missing': ['error', 'No SPF record', 'Publish one TXT record starting with "v=spf1" that lists your sending services and ends with "-all" or "~all".'],
  'spf/multiple': ['error', 'Multiple SPF records (RFC 7208 permerror)', 'Merge all SPF records into a single v=spf1 record.'],
  'spf/record': ['note', 'SPF record published', 'The record text is in the finding detail.'],
  'spf/delegated': ['note', 'SPF policy delegated with redirect=', 'The policy is defined by the redirect target.'],
  'spf/no-all': ['warning', 'SPF has no "all" mechanism', 'End the record with "-all" (or "~all" while rolling out).'],
  'spf/plus-all': ['error', 'SPF allows any server to send (+all)', 'Replace "+all" with "-all" or "~all".'],
  'spf/neutral-all': ['warning', 'SPF "?all" gives receivers no guidance', 'Use "-all" or "~all".'],
  'spf/softfail': ['note', 'SPF "~all" softfail policy', 'No action needed.'],
  'spf/hardfail': ['note', 'SPF "-all" hardfail policy', 'No action needed.'],
  'spf/lookup-limit': ['error', 'SPF exceeds the DNS lookup limit (RFC 7208 section 4.6.4)', 'Remove unused includes or flatten the record.'],
  'spf/lookup-count': ['note', 'SPF top-level DNS lookup count', 'Nested includes are not counted.'],
  'spf/ptr': ['warning', 'SPF "ptr" mechanism is deprecated (RFC 7208 section 5.5)', 'Replace "ptr" with explicit ip4/ip6 or include terms.'],
  'spf/lookup-error': ['error', 'SPF lookup failed', 'The DNS query failed. Re-run; if it persists, check the domain\'s name servers.'],
  // dmarc
  'dmarc/missing': ['error', 'No DMARC record', 'Publish a TXT record at _dmarc.<domain>: "v=DMARC1; p=none; rua=mailto:..." and tighten to quarantine/reject after reviewing reports.'],
  'dmarc/multiple': ['error', 'Multiple DMARC records', 'Keep exactly one DMARC record; receivers discard all of them otherwise.'],
  'dmarc/record': ['note', 'DMARC record published', 'The record text is in the finding detail.'],
  'dmarc/policy-reject': ['note', 'DMARC policy reject', 'No action needed.'],
  'dmarc/policy-quarantine': ['note', 'DMARC policy quarantine', 'No action needed.'],
  'dmarc/policy-none': ['warning', 'DMARC policy none: monitoring only', 'Move to quarantine, then reject, once reports show legitimate senders pass.'],
  'dmarc/policy-invalid': ['error', 'DMARC policy missing or invalid', 'Set p=none, p=quarantine or p=reject.'],
  'dmarc/legacy-pct': ['warning', 'DMARC "pct" tag is legacy (removed in RFC 9989)', 'Remove pct. Use t=y for test mode (RFC 9989 section 4.7); omit t or use t=n to enforce fully.'],
  'dmarc/test-mode': ['warning', 'DMARC test mode t=y lowers the effective policy', 'Remove t=y (or set t=n) once reports show legitimate senders pass.'],
  'dmarc/test-mode-noop': ['note', 'DMARC t=y has no effect with p=none', 'No action needed.'],
  'dmarc/invalid-t': ['warning', 'DMARC "t" tag has an invalid value', 'Use t=y while testing, or t=n / omit it to enforce.'],
  'dmarc/no-rua': ['warning', 'DMARC has no aggregate reporting address', 'Add rua=mailto:<address> to receive aggregate reports.'],
  'dmarc/lookup-error': ['error', 'DMARC lookup failed', 'The DNS query failed. Re-run; if it persists, check the domain\'s name servers.'],
  // dkim
  'dkim/not-evaluated': ['note', 'DKIM not evaluated: no selector given', 'DKIM selectors cannot be enumerated from DNS. Pass --dkim-selector to check selectors you know.'],
  'dkim/selector-not-found': ['warning', 'No DKIM key record at the given selector', 'Check the selector against the s= tag of a real DKIM-Signature header, or publish the key at that name.'],
  'dkim/multiple-records': ['note', 'Several DKIM key records at one selector', 'Only the first record is evaluated.'],
  'dkim/invalid-key': ['error', 'DKIM key record is invalid', 'Re-publish the key exactly as generated and check that the TXT value was not truncated.'],
  'dkim/revoked': ['warning', 'DKIM key is revoked (empty p=, RFC 6376 section 3.6.1)', 'Remove the record if the revocation is final, or publish a new key under a new selector.'],
  'dkim/key-too-short': ['error', 'DKIM RSA key shorter than 1024 bits (RFC 8301 section 3.2)', 'Generate a 2048-bit RSA key and publish it under a new selector.'],
  'dkim/key-below-2048': ['warning', 'DKIM RSA key below 2048 bits (RFC 8301 section 3.2)', 'Rotate to a 2048-bit key under a new selector.'],
  'dkim/key-ok': ['note', 'DKIM key is strong', 'No action needed.'],
  'dkim/key-type-unknown': ['note', 'DKIM key type not evaluated', 'Verifiers ignore unrecognized key types (RFC 6376 section 3.6.1).'],
  'dkim/testing': ['note', 'DKIM selector is in testing mode (t=y)', 'Remove t=y once signing is verified; verifiers treat testing-mode mail like unsigned mail.'],
  'dkim/lookup-error': ['error', 'DKIM lookup failed', 'The DNS query failed. Re-run; if it persists, check the domain\'s name servers.'],
  // mta-sts
  'mta-sts/missing': ['note', 'MTA-STS not published (RFC 8461)', 'Optional hardening: publish an MTA-STS policy, starting with mode=testing and a TLS-RPT record.'],
  'mta-sts/invalid-record': ['warning', 'MTA-STS TXT record is invalid (RFC 8461 section 3.1)', 'Keep exactly one "_mta-sts" TXT record of the form "v=STSv1; id=<up to 32 alphanumerics>".'],
  'mta-sts/record': ['note', 'MTA-STS TXT record published', 'The record text is in the finding detail.'],
  'mta-sts/policy-unavailable': ['warning', 'MTA-STS policy cannot be fetched (RFC 8461 section 3.3)', 'Serve https://mta-sts.<domain>/.well-known/mta-sts.txt with HTTP 200 (no redirect) and a valid certificate; until then senders ignore MTA-STS.'],
  'mta-sts/content-type': ['warning', 'MTA-STS policy is not served as text/plain (RFC 8461 section 3.2)', 'Serve the policy file with Content-Type: text/plain.'],
  'mta-sts/policy-invalid': ['warning', 'MTA-STS policy file is invalid (RFC 8461 section 3.2)', 'version, mode, mx and max_age are required; fix the policy file and publish a new id.'],
  'mta-sts/policy': ['note', 'MTA-STS policy fetched', 'Mode, max_age and mx patterns are in the finding detail.'],
  'mta-sts/mode-enforce': ['note', 'MTA-STS mode enforce', 'No action needed.'],
  'mta-sts/mode-testing': ['warning', 'MTA-STS mode testing does not block delivery (RFC 8461 section 5)', 'Review TLS-RPT reports, then switch to mode: enforce and publish a new id.'],
  'mta-sts/mode-none': ['note', 'MTA-STS mode none: policy inactive (RFC 8461 section 8.3)', 'Set mode: testing, then enforce, if MTA-STS should be active.'],
  'mta-sts/mx-mismatch': ['warning', 'MX hosts not covered by the MTA-STS mx patterns (RFC 8461 section 4.1)', 'Add an mx: line for every MX host, then publish a new id. In enforce mode uncovered hosts stop receiving mail from compliant senders.'],
  'mta-sts/mx-covered': ['note', 'MTA-STS mx patterns cover every MX host', 'No action needed.'],
  'mta-sts/max-age-low': ['warning', 'MTA-STS max_age below one week (RFC 8461 sections 3.2 and 10)', 'Use at least max_age: 604800; 31557600 (the maximum) once the policy is stable.'],
  'mta-sts/max-age-ok': ['note', 'MTA-STS max_age is adequate', 'No action needed.'],
  'mta-sts/lookup-error': ['error', 'MTA-STS lookup failed', 'The DNS query failed. Re-run; if it persists, check the domain\'s name servers.'],
  // tls-rpt
  'tls-rpt/missing': ['note', 'TLS-RPT not published (RFC 8460)', 'Optional: publish "v=TLSRPTv1; rua=mailto:<address>" at _smtp._tls.<domain> to receive TLS failure reports.'],
  'tls-rpt/invalid-record': ['warning', 'TLS-RPT record is invalid (RFC 8460 section 3)', 'Keep exactly one "_smtp._tls" TXT record with a valid rua (mailto: or https:).'],
  'tls-rpt/present': ['note', 'TLS-RPT reporting published', 'No action needed.'],
  'tls-rpt/lookup-error': ['error', 'TLS-RPT lookup failed', 'The DNS query failed. Re-run; if it persists, check the domain\'s name servers.'],
  // tls
  'tls/trusted': ['note', 'Certificate chain and hostname are trusted', 'No action needed.'],
  'tls/untrusted': ['error', 'Certificate is not trusted', 'Serve a certificate from a public CA that covers this hostname, with the full intermediate chain.'],
  'tls/expiry-unknown': ['error', 'Certificate expiry could not be read', 'Inspect the certificate manually.'],
  'tls/expired': ['error', 'Certificate has expired', 'Renew the certificate and check that automatic renewal works.'],
  'tls/expiring-soon': ['error', 'Certificate expires in under 14 days', 'Renew now and check that automatic renewal works.'],
  'tls/expiring': ['warning', 'Certificate expires in under 30 days', 'Confirm automatic renewal is scheduled.'],
  'tls/valid': ['note', 'Certificate validity is comfortable', 'No action needed.'],
  'tls/protocol-ok': ['note', 'TLS 1.2 or 1.3 negotiated', 'No action needed.'],
  'tls/legacy-protocol': ['error', 'Legacy TLS protocol negotiated', 'Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only.'],
  'tls/connect-error': ['error', 'TLS connection failed', 'The TLS handshake on port 443 failed. Check that the service is reachable.'],
  // headers
  'headers/response': ['note', 'HTTPS response received', 'The final URL and status are in the finding.'],
  'headers/not-https': ['error', 'Final page is not served over HTTPS', 'Redirect all HTTP traffic to HTTPS.'],
  'headers/hsts-missing': ['warning', 'Strict-Transport-Security header missing', 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".'],
  'headers/hsts-short': ['warning', 'HSTS max-age is shorter than 180 days', 'Use at least max-age=15552000 (180 days); one year is common.'],
  'headers/hsts-ok': ['note', 'Strict-Transport-Security present', 'No action needed.'],
  'headers/csp-missing': ['warning', 'Content-Security-Policy header missing', 'Define a CSP; start in Content-Security-Policy-Report-Only mode.'],
  'headers/csp-ok': ['note', 'Content-Security-Policy present', 'Policy strength is not evaluated.'],
  'headers/nosniff-missing': ['warning', 'X-Content-Type-Options: nosniff missing', 'Add "X-Content-Type-Options: nosniff".'],
  'headers/nosniff-ok': ['note', 'X-Content-Type-Options: nosniff present', 'No action needed.'],
  'headers/framing-missing': ['warning', 'No clickjacking protection', 'Add CSP "frame-ancestors \'self\'" or "X-Frame-Options: DENY".'],
  'headers/framing-ok': ['note', 'Clickjacking protection present', 'No action needed.'],
  'headers/referrer-missing': ['note', 'Referrer-Policy not set', 'Set a Referrer-Policy such as strict-origin-when-cross-origin.'],
  'headers/referrer-ok': ['note', 'Referrer-Policy set', 'No action needed.'],
  'headers/version-disclosed': ['note', 'Software version disclosed in headers', 'Remove version numbers from Server / X-Powered-By.'],
  'headers/request-error': ['error', 'HTTPS request failed', 'The HTTPS GET failed. Check that the site is reachable and its certificate is valid.'],
};

export const RULES = Object.fromEntries(Object.entries(R).map(([id, [level, title, help]]) => [id, { id, level, title, help }]));

const GENERIC = { level: 'note', title: 'Finding', help: 'See the finding detail and docs/checks.md.' };

// Never throws: a finding without a catalogued id still serialises (falls back to "<check>/unclassified").
export function ruleFor(f) {
  const id = f.id && RULES[f.id] ? f.id : `${f.check}/unclassified`;
  return RULES[id] || { id, ...GENERIC, title: `Unclassified ${f.check} finding` };
}
