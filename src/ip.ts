/**
 * Canonical IPv4 address and CIDR parsing.
 *
 * Addresses are represented as unsigned 32-bit integers (0..2^32-1).
 * Bit operations use `>>> 0` so every value stays a non-negative Uint32.
 */

export type IP = number;
export type Prefix = number; // 0..32

/** A closed integer interval of addresses: all IPs in [lo, hi]. */
export interface AddrRange {
  lo: IP;
  hi: IP;
}

export interface Cidr {
  base: IP; // network address, canonical
  prefix: Prefix;
  lo: IP; // inclusive
  hi: IP; // inclusive
}

const IPV4_OCTET =
  /^(0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;

/** Parse a canonical dotted-quad IPv4 address (no leading zeros). Throws on bad input. */
export function parseIp(text: unknown): IP {
  if (typeof text !== "string") {
    throw new Error("IP address must be a string");
  }
  const parts = text.split(".");
  if (parts.length !== 4) {
    throw new Error(`invalid IPv4 address: ${text}`);
  }
  let value = 0;
  for (const part of parts) {
    if (!IPV4_OCTET.test(part)) {
      throw new Error(`invalid IPv4 address (bad octet): ${text}`);
    }
    value = (value << 8) | Number(part);
  }
  return value >>> 0;
}

/** Format an unsigned 32-bit IP as dotted quad. */
export function formatIp(ip: IP): string {
  return [(ip >>> 24) & 255, (ip >>> 16) & 255, (ip >>> 8) & 255, ip & 255].join(
    ".",
  );
}

/**
 * Parse a canonical IPv4 CIDR: base address must already be the network
 * address (all host bits zero), e.g. `10.0.0.0/24` is accepted while
 * `10.0.0.1/24` and `010.0.0.0/8` are rejected.
 */
export function parseCidr(text: unknown): Cidr {
  if (typeof text !== "string") {
    throw new Error("CIDR must be a string");
  }
  const slash = text.indexOf("/");
  if (slash < 0) {
    throw new Error(`CIDR missing prefix length: ${text}`);
  }
  const addrText = text.slice(0, slash);
  const prefixText = text.slice(slash + 1);
  if (!/^(?:[0-9]|[12][0-9]|3[0-2])$/.test(prefixText)) {
    throw new Error(`CIDR prefix length out of range: ${text}`);
  }
  const prefix = Number(prefixText);
  const base = parseIp(addrText);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if ((base & mask) >>> 0 !== base) {
    throw new Error(`non-canonical CIDR (host bits set): ${text}`);
  }
  const lo = base;
  const hi = prefix === 0 ? 0xffffffff : (base | (~mask >>> 0)) >>> 0;
  return { base, prefix, lo, hi };
}

export function formatCidr(c: Cidr): string {
  return `${formatIp(c.base)}/${c.prefix}`;
}

/** Full address span of a CIDR as a closed interval. */
export function cidrRange(c: Cidr): AddrRange {
  return { lo: c.lo, hi: c.hi };
}

/** Number of addresses covered by a prefix length: 2^(32-prefix). */
export function cidrSize(prefix: Prefix): number {
  // Safe up to 2^32; every result fits in a double without rounding loss.
  return 2 ** (32 - prefix);
}
