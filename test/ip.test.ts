import { describe, expect, it } from "vitest";
import { parseCidr, parseIp, formatIp, cidrSize } from "../src/ip.js";

describe("parseIp", () => {
  it("parses canonical dotted quads", () => {
    expect(parseIp("0.0.0.0")).toBe(0);
    expect(parseIp("255.255.255.255")).toBe(0xffffffff);
    expect(parseIp("10.0.0.1")).toBe(0x0a000001);
    expect(formatIp(0x0a000001)).toBe("10.0.0.1");
  });

  it("rejects leading zeros, out-of-range octets and malformed strings", () => {
    for (const bad of ["01.2.3.4", "1.02.3.4", "256.0.0.1", "1.2.3", "1.2.3.4.5", "a.b.c.d", "1..3.4", " 1.2.3.4", "1.2.3.4 "]) {
      expect(() => parseIp(bad), bad).toThrow();
    }
  });
});

describe("parseCidr", () => {
  it("computes ranges for boundary prefixes", () => {
    const zero = parseCidr("0.0.0.0/0");
    expect([zero.lo, zero.hi]).toEqual([0, 0xffffffff]);
    expect(cidrSize(0)).toBe(2 ** 32);

    const host = parseCidr("10.0.0.1/32");
    expect([host.lo, host.hi]).toEqual([0x0a000001, 0x0a000001]);
    expect(cidrSize(32)).toBe(1);
  });

  it("rejects non-canonical network addresses and bad prefixes", () => {
    for (const bad of [
      "10.0.0.1/24", // host bits set
      "10.0.0.128/25", // fine, actually — replaced below
      "0.0.0.0/33",
      "10.0.0.0/-1",
      "10.0.0.0",
      "10.0.0.0/",
      "256.0.0.0/8",
      "010.0.0.0/8",
      "192.168.1.5/30",
    ]) {
      if (bad === "10.0.0.128/25") {
        expect(() => parseCidr(bad)).not.toThrow();
        continue;
      }
      expect(() => parseCidr(bad), bad).toThrow();
    }
  });
});
