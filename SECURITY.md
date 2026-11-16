# Security

## Scope

This toolkit is **defensive and read-only**. It performs public DNS queries, a single
TLS handshake and a single HTTPS `GET` per target. It does not scan ports, fuzz,
authenticate, or attempt exploitation, and it will not accept contributions that do.

Only run it against domains you own or are authorized to assess.

## What the tool connects to

For every domain it checks, the toolkit makes only these outbound requests, all derived from the validated
domain name and never from user-supplied URLs or from content found in a response:

- public DNS queries for the domain and the fixed names `_dmarc.`, `_mta-sts.`, `_smtp._tls.` and any
  `<selector>._domainkey.` you named;
- one TLS handshake to `<domain>:443`;
- one HTTPS `GET https://<domain>/`;
- when (and only when) a valid `_mta-sts.<domain>` TXT record exists, one HTTPS `GET`
  `https://mta-sts.<domain>/.well-known/mta-sts.txt`.

### MTA-STS policy fetch: SSRF controls

The policy URL is the only place the toolkit fetches a host it constructed itself, so it is locked down
(`src/netsafe.mjs`, `src/checks/mta-sts.mjs`; covered by `test/mta-sts.fetch.test.mjs`):

- **Derived host only.** The host is `mta-sts.` + the domain after `normalizeDomain`. URLs, ports, paths, userinfo
  and IP literals are rejected before any lookup; names ending in `localhost`, `local`, `localdomain`, `internal`,
  `intranet`, `lan`, `home`, `corp`, `private` or `arpa` are refused as internal.
- **Public addresses only.** The connection's DNS result is checked at connect time and refused if any address is
  loopback, private (RFC 1918), link-local (including the 169.254.169.254 cloud metadata address), CGNAT,
  multicast, reserved, documentation, unique-local IPv6, or an IPv4-mapped IPv6 address of one of those. The
  address that was checked is the address that is connected to, so DNS rebinding cannot swap it afterwards.
- **No redirects, ever.** Any 3xx is treated as "policy unavailable" and is not followed (RFC 8461 section 3.3
  forbids following them), so a policy host cannot bounce the tool to another host or scheme.
- **HTTPS only, port 443**, certificate verification on, TLS 1.2 or newer.
- **Bounded.** 10 second total timeout, 64 KB body cap (also enforced against a declared `Content-Length`), a
  non-200 response body is never read.
- **Untrusted output.** Text taken from DNS and HTTP responses has control characters removed before it is
  printed, and is escaped in `--format markdown`, so a hostile TXT record cannot forge report lines or inject
  markup. SARIF output is JSON-encoded.

The `--file` input is read as a plain list of domain names (1 MiB maximum) and is never executed or interpreted.

## Reporting a vulnerability

If you find a security issue in the toolkit itself, please open a GitHub issue with a
minimal description, or use GitHub's private vulnerability reporting on this
repository if the details should not be public.
