// SSRF guard for the one place the toolkit fetches a URL it derived itself (the MTA-STS policy, RFC 8461
// section 3.2). The target host is always "mta-sts.<validated domain>"; this module additionally refuses
// internal-looking names and, at connect time, any address that is not publicly routable.
import dns from 'node:dns';
import net from 'node:net';
import { normalizeDomain } from './domain.mjs';

// Name suffixes that are never public DNS. (The resolved-address check below is the real control;
// this only fails early and gives a clearer message.)
const INTERNAL_SUFFIXES = ['localhost', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp', 'private', 'home.arpa', 'arpa'];

export class BlockedTargetError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BlockedTargetError';
    this.code = 'BLOCKED_TARGET';
  }
}

const blocked = new net.BlockList();
for (const [net4, prefix] of [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
]) blocked.addSubnet(net4, prefix, 'ipv4');
for (const [net6, prefix] of [
  ['::', 128], ['::1', 128], ['64:ff9b::', 96], ['100::', 64], ['2001::', 32], ['2001:db8::', 32], ['2002::', 16],
  ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8],
]) blocked.addSubnet(net6, prefix, 'ipv6');

// true only for a publicly routable unicast address. IPv4-mapped IPv6 (::ffff:a.b.c.d) is judged as the IPv4 address.
export function isPublicAddress(address) {
  let addr = String(address);
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (mapped) addr = mapped[1];
  const family = net.isIP(addr);
  if (family === 0) return false;
  return !blocked.check(addr, family === 4 ? 'ipv4' : 'ipv6');
}

// Returns the policy host "mta-sts.<domain>" or throws BlockedTargetError. Re-validates the domain so the
// function is safe on its own, refuses IP literals, single-label and internal names.
export function policyHostFor(domain) {
  let d;
  try {
    d = normalizeDomain(domain);
  } catch (e) {
    throw new BlockedTargetError(`refusing policy fetch: ${e.message}`);
  }
  if (net.isIP(d)) throw new BlockedTargetError('refusing policy fetch: IP literal');
  const labels = d.split('.');
  const tld = labels[labels.length - 1];
  const tail2 = labels.slice(-2).join('.');
  if (INTERNAL_SUFFIXES.includes(tld) || INTERNAL_SUFFIXES.includes(tail2)) {
    throw new BlockedTargetError(`refusing policy fetch: ${d} looks like an internal name`);
  }
  return `mta-sts.${d}`;
}

// A `lookup` for net/tls/https that resolves normally but refuses non-public addresses. Because connect uses
// the address returned here, there is no gap between "check" and "use" (no DNS rebinding window).
export function safeLookup(hostname, options, callback) {
  const opts = typeof options === 'function' ? {} : { ...options };
  const cb = typeof options === 'function' ? options : callback;
  dns.lookup(hostname, { ...opts, all: true }, (err, addresses) => {
    if (err) return cb(err);
    const bad = addresses.find((a) => !isPublicAddress(a.address));
    if (bad || addresses.length === 0) {
      return cb(new BlockedTargetError(`refusing to connect: ${hostname} resolves to a non-public address`));
    }
    if (opts.all) return cb(null, addresses);
    return cb(null, addresses[0].address, addresses[0].family);
  });
}
