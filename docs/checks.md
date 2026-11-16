# Checks

## mail

| Rule | Status |
|---|---|
| MX list | info |
| Null MX (RFC 7505, `0 .`): explicitly accepts no mail | info |
| No MX but A/AAAA present: implicit MX (RFC 5321 §5.1) | warn |
| No MX and no A/AAAA | info |
| No SPF record | fail |
| More than one SPF record (RFC 7208 permerror) | fail |
| `+all` or bare `all` | fail |
| `?all` | warn |
| No `all` and no `redirect=` | warn |
| `~all` / `-all` | pass |
| More than 10 DNS-querying terms at top level | fail |
| `ptr` mechanism (deprecated) | warn |
| No DMARC record at `_dmarc.<domain>` or, via the RFC 9989 §4.10 tree walk, at a parent | fail |
| Record inherited from a parent (judged by `sp`, else `p`) | info |
| More than one DMARC record | fail |
| `p=reject` / `p=quarantine` | pass |
| `p=none` | warn |
| Missing or invalid `p=` | fail |
| Legacy `pct` below 100 (removed in RFC 9989, ignored by its receivers) | warn |
| Legacy `pct=100` | info |
| `t=y` with `quarantine`/`reject` (RFC 9989 test mode) | warn |
| `t=y` with `p=none`, or an invalid `t` value | info / warn |
| No `rua` | warn |

**Not checked:** DKIM. A DKIM record lives at `<selector>._domainkey.<domain>` and the
selector is not discoverable from DNS, so a missing record cannot be proven. Reporting
"DKIM missing" without a known selector would be a false finding.

**DMARC discovery:** `_dmarc.<domain>` first, then the parent names of the RFC 9989 section 4.10 DNS tree walk
(at most 8 lookups; names with more than 8 labels are shortened to 7). The nearest valid record wins; a name with
several DMARC records contributes none. The `np` tag (non-existent subdomains) is not evaluated.

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
