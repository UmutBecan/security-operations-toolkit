// Parses "k=v; k=v" tag lists used by DMARC (RFC 9989), DKIM (RFC 6376 section 3.2), MTA-STS TXT (RFC 8461
// section 3.1) and TLS-RPT (RFC 8460 section 3). Tag names are lower-cased; a repeated name overwrites the earlier one.
export function parseTags(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return tags;
}
