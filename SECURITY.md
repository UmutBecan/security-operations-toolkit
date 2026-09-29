# Security

## Scope

This toolkit is **defensive and read-only**. It performs public DNS queries, a single
TLS handshake and a single HTTPS `GET` per target. It does not scan ports, fuzz,
authenticate, or attempt exploitation, and it will not accept contributions that do.

Only run it against domains you own or are authorized to assess.

## Reporting a vulnerability

If you find a security issue in the toolkit itself, please open a GitHub issue with a
minimal description, or use GitHub's private vulnerability reporting on this
repository if the details should not be public.
