# Checks

## mail

| Rule | Status |
|---|---|
| No MX / null MX (RFC 7505) / MX list | info |
| No SPF record | fail |
| More than one SPF record (RFC 7208 permerror) | fail |
| `+all` or bare `all` | fail |
| `?all` | warn |
| No `all` and no `redirect=` | warn |
| `~all` / `-all` | pass |
| More than 10 DNS-querying terms at top level | fail |
| `ptr` mechanism (deprecated) | warn |
| No DMARC record at `_dmarc.<domain>` | fail |
| More than one DMARC record | fail |
| `p=reject` / `p=quarantine` | pass |
| `p=none` | warn |
| Missing or invalid `p=` | fail |
| `pct` below 100 | warn |
| No `rua` | warn |

**Not checked:** DKIM. A DKIM record lives at `<selector>._domainkey.<domain>` and the
selector is not discoverable from DNS, so a missing record cannot be proven. Reporting
"DKIM missing" without a known selector would be a false finding.

**Limitation:** SPF lookup counting does not follow nested `include:` chains.

## tls

| Rule | Status |
|---|---|
| Chain and hostname trusted by Node's CA store | pass |
| Not trusted (reason reported, e.g. expired, wrong host, self-signed) | fail |
| Expired, or expires in < 14 days | fail |
| Expires in < 30 days | warn |
| Negotiated TLS 1.2 / 1.3 | pass |
| Negotiated anything older | fail |

**Limitation:** only port 443, only the negotiated protocol version.

## headers

Fetches `https://<domain>/` (following redirects) and evaluates the final response.

| Rule | Status |
|---|---|
| Final URL not HTTPS | fail |
| `Strict-Transport-Security` missing or `max-age` < 180 days | warn |
| `Content-Security-Policy` missing | warn |
| `X-Content-Type-Options: nosniff` missing | warn |
| No CSP `frame-ancestors` and no `X-Frame-Options: DENY/SAMEORIGIN` | warn |
| `Referrer-Policy` not set | info |
| Version number in `Server` / `X-Powered-By` | info |

**Limitation:** CSP is checked for presence only; its policy strength is not graded.
