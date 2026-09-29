import { domainToASCII } from 'node:url';

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

// Accepts a bare domain name only. URLs, IP literals, ports and paths are rejected
// so every check targets exactly the name the operator intended.
export function normalizeDomain(input) {
  if (typeof input !== 'string') throw new Error('domain must be a string');
  let d = input.trim().toLowerCase();
  if (d.endsWith('.')) d = d.slice(0, -1);
  if (!d) throw new Error('domain is empty');
  if (/[/:@?#\s]/.test(d)) throw new Error('provide a bare domain name, not a URL, port or path');
  if (/^[0-9.]+$/.test(d)) throw new Error('IP addresses are not accepted; provide a domain name');

  const ascii = domainToASCII(d);
  if (!ascii || ascii.length > 253) throw new Error(`invalid domain: ${input}`);
  const labels = ascii.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) {
    throw new Error(`invalid domain: ${input}`);
  }
  return ascii;
}
