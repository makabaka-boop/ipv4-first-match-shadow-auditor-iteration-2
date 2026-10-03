import { describe, expect, it } from "vitest";
import { audit, type Action } from "../src/audit.js";
import { formatIp, parseIp, type Cidr } from "../src/ip.js";
import { normalize, subtract, union } from "../src/intervals.js";

/**
 * Differential testing inside a small subnet.
 *
 * All generated CIDRs are subnets of BASE/PREFIX, and ground truth is found
 * by walking every one of the SUBNET_SIZE addresses linearly — an actual
 * first-match simulation rather than any set algebra. The sparse interval
 * implementation and the simulator must agree exactly.
 */

const BASE = parseIp("10.13.0.0");
const PREFIX = 24;
const SUBNET_SIZE = 2 ** (32 - PREFIX);

interface GenRule {
  id: string;
  action: Action;
  cidr: Cidr;
}

// Deterministic PRNG so the suite is reproducible.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomRules(rand: () => number, count: number): GenRule[] {
  const rules: GenRule[] = [];
  const used = new Set<string>();
  let guard = 0;
  while (rules.length < count && guard < count * 50) {
    guard++;
    // /32, /31, ..., down to the subnet prefix so blocks stay aligned.
    const hostBits = Math.floor(rand() * (32 - PREFIX + 1));
    const block = 2 ** hostBits;
    const offset = Math.floor(rand() * (SUBNET_SIZE / block)) * block;
    const p = 32 - hostBits;
    const lo = (BASE + offset) >>> 0;
    const cidr: Cidr = {
      base: lo,
      prefix: p,
      lo,
      hi: (lo + block - 1) >>> 0,
    };
    const id = `r${rules.length}`;
    if (used.has(`${lo}/${p}`)) continue;
    used.add(`${lo}/${p}`);
    rules.push({ id, action: rand() < 0.5 ? "allow" : "deny", cidr });
  }
  return rules;
}

/** Index of the first rule matching address offset, or -1. */
function firstMatchIndex(rules: GenRule[], offset: number): number {
  const ip = BASE + offset;
  for (let i = 0; i < rules.length; i++) {
    const c = rules[i]!.cidr;
    if (ip >= c.lo && ip <= c.hi) return i;
  }
  return -1;
}

function checkCoverageCertificate(
  rules: GenRule[],
  ruleIndex: number,
  report: ReturnType<typeof audit>,
  label: string,
): void {
  const target = rules[ruleIndex]!.cidr;
  const targetLo = Math.max(target.lo, BASE);
  const targetHi = Math.min(target.hi, BASE + SUBNET_SIZE - 1);
  const targetSize = targetHi - targetLo + 1;
  const targetMask = (1n << BigInt(targetSize)) - 1n;
  const certificate = report.rules[ruleIndex]!.coverageCertificate;

  expect(certificate, `${label} rule ${ruleIndex} certificate`).not.toBeNull();

  const offsetMask = (ruleIndexInPolicy: number): bigint => {
    const range = rules[ruleIndexInPolicy]!.cidr;
    const lo = Math.max(range.lo, targetLo);
    const hi = Math.min(range.hi, targetHi);
    if (lo > hi) return 0n;
    const width = BigInt(hi - lo + 1);
    const shift = BigInt(lo - targetLo);
    return (((1n << width) - 1n) << shift) & targetMask;
  };

  const priorMasks = rules.slice(0, ruleIndex).map((_, j) => offsetMask(j));
  let minimumRules = ruleIndex + 1;
  const subsetCount = 2 ** ruleIndex;
  for (let subset = 1; subset < subsetCount; subset++) {
    let covered = 0n;
    let selected = 0;
    for (let bit = 0; bit < ruleIndex; bit++) {
      if ((subset & (1 << bit)) !== 0) {
        covered |= priorMasks[bit]!;
        selected++;
      }
    }
    if (covered === targetMask) minimumRules = Math.min(minimumRules, selected);
  }

  expect(certificate!.ruleIds, `${label} rule ${ruleIndex} certificate size`).toHaveLength(
    minimumRules,
  );
  expect(new Set(certificate!.ruleIds).size, `${label} certificate has no duplicate rule`).toBe(
    certificate!.ruleIds.length,
  );

  let certificateMask = 0n;
  let expectedStart = targetLo;
  for (const step of certificate!.steps) {
    const priorIndex = rules.findIndex((rule, j) => j < ruleIndex && rule.id === step.ruleId);
    expect(priorIndex, `${label} certificate rule id must be earlier`).toBeGreaterThanOrEqual(0);

    const start = parseIp(step.startAddress);
    const end = parseIp(step.endAddress);
    const prior = rules[priorIndex]!.cidr;
    expect(start, `${label} certificate step start`).toBe(expectedStart);
    expect(start, `${label} certificate starts inside target`).toBeGreaterThanOrEqual(targetLo);
    expect(end, `${label} certificate ends inside target`).toBeLessThanOrEqual(targetHi);
    expect(start, `${label} step is covered by its selected rule`).toBeGreaterThanOrEqual(prior.lo);
    expect(end, `${label} step is covered by its selected rule`).toBeLessThanOrEqual(prior.hi);

    const width = BigInt(end - start + 1);
    certificateMask |= ((1n << width) - 1n) << BigInt(start - targetLo);
    expectedStart = end + 1;
  }

  expect(expectedStart, `${label} certificate reaches target end`).toBe(targetHi + 1);
  expect(certificateMask, `${label} certificate exactly covers target`).toBe(targetMask);
}

function checkPolicy(rules: GenRule[], label: string, outsideExposed?: number[]): void {
  const input = {
    rules: rules.map((r) => ({ id: r.id, action: r.action, cidr: `${formatIp(r.cidr.base)}/${r.cidr.prefix}` })),
    queries: [formatIp(BASE), formatIp(BASE + SUBNET_SIZE - 1), formatIp(BASE + Math.floor(SUBNET_SIZE / 2))],
  };
  const report = audit(input);

  // --- per-rule residuals: enumerate every address ---
  const expectedExposed = rules.map(() => 0);
  const expectedWitness = rules.map<number | null>(() => null);
  for (let off = 0; off < SUBNET_SIZE; off++) {
    const idx = firstMatchIndex(rules, off);
    if (idx >= 0) {
      expectedExposed[idx]!++;
      if (expectedWitness[idx] === null) expectedWitness[idx] = off;
    }
  }

  report.rules.forEach((r, i) => {
    // Generated CIDRs are contained in the subnet, so subnet enumeration is
    // exhaustive for them. A rule extending beyond it (e.g. /0) declares the
    // addresses it exposes outside the subnet explicitly.
    const outside = outsideExposed?.[i] ?? 0;
    const exposedTotal = expectedExposed[i]! + outside;
    expect(r.exposedAddresses, `${label} rule ${i} exposed`).toBe(exposedTotal);
    const total = 2 ** (32 - rules[i]!.cidr.prefix);
    const expectedStatus =
      exposedTotal === 0 ? "shadowed" : exposedTotal === total ? "active" : "partial";
    expect(r.status, `${label} rule ${i} status`).toBe(expectedStatus);
    expect(r.totalAddresses).toBe(total);
    if (outside > 0 && rules[i]!.cidr.lo < BASE) {
      expect(r.witness, `${label} rule ${i} witness`).toBe(formatIp(rules[i]!.cidr.lo));
    } else {
      expect(r.witness, `${label} rule ${i} witness`).toBe(
        expectedWitness[i] === null ? null : formatIp(BASE + expectedWitness[i]!),
      );
    }
    if (r.status === "shadowed" && rules[i]!.cidr.lo >= BASE && rules[i]!.cidr.hi < BASE + SUBNET_SIZE) {
      checkCoverageCertificate(rules, i, report, label);
    } else {
      expect(r.coverageCertificate, `${label} rule ${i} has no certificate`).toBeUndefined();
    }
  });

  // --- adjacent swaps: compare decisions on every maximal constant run ---
  // A rule membership flips exactly at lo and hi+1, so those are the run
  // boundaries; sampling one address per run is equivalent to walking all
  // 2^32 addresses.
  const boundaries = new Set<number>([0, 0xffffffff]);
  for (const r of rules) {
    boundaries.add(r.cidr.lo);
    boundaries.add(r.cidr.hi < 0xffffffff ? r.cidr.hi + 1 : r.cidr.hi);
  }
  const points = [...boundaries].sort((x, y) => x - y);
  // Build runs [p, nextPoint-1] from consecutive boundary points.
  const runs: Array<[number, number]> = [];
  for (let p = 0; p < points.length; p++) {
    const lo = points[p]!;
    const hi = p + 1 < points.length ? points[p + 1]! - 1 : 0xffffffff;
    runs.push([lo, Math.max(lo, hi)]);
  }

  const decide = (ord: number[], ip: number): Action => {
    for (const ri of ord) {
      const c = rules[ri]!.cidr;
      if (ip >= c.lo && ip <= c.hi) return rules[ri]!.action;
    }
    return "deny";
  };

  for (let i = 0; i + 1 < rules.length; i++) {
    const order = rules.map((_, k) => k);
    const swapped = order.slice();
    [swapped[i], swapped[i + 1]] = [swapped[i + 1]!, swapped[i]!];

    let changed = 0;
    let witnessIp: number | null = null;
    for (const [lo, hi] of runs) {
      if (decide(order, lo) !== decide(swapped, lo)) {
        changed += hi - lo + 1;
        if (witnessIp === null) witnessIp = lo;
      }
    }
    const got = report.swaps[i]!;
    expect(got.changedAddresses, `${label} swap ${i} changed`).toBe(changed);
    expect(got.witness, `${label} swap ${i} witness`).toBe(
      witnessIp === null ? null : formatIp(witnessIp),
    );
  }

  // Re-running the same ordered request must produce identical certificates.
  const rerun = audit(input);
  expect(rerun, `${label} repeated audit report`).toEqual(report);

  // --- queries: first matching rule ---
  report.queries.forEach((q, qi) => {
    const off = [0, SUBNET_SIZE - 1, Math.floor(SUBNET_SIZE / 2)][qi]!;
    const idx = firstMatchIndex(rules, off);
    expect(q.ruleId).toBe(idx === -1 ? null : rules[idx]!.id);
    expect(q.action).toBe(idx === -1 ? "deny" : rules[idx]!.action);
    expect(q.index).toBe(idx === -1 ? null : idx);
  });
}

describe("exhaustive differential audit inside 10.13.0.0/24", () => {
  it("empty intersection: disjoint rules leave everyone active", () => {
    const rules = [0, 64, 128, 192].map((off, i) => ({
      id: `r${i}`,
      action: (i % 2 === 0 ? "allow" : "deny") as Action,
      cidr: { base: BASE + off, prefix: 26, lo: BASE + off, hi: BASE + off + 63 } as Cidr,
    }));
    checkPolicy(rules, "disjoint");
  });

  it("complete shadowing: broad deny /24 hides all later rules", () => {
    const rules: GenRule[] = [
      { id: "cover", action: "deny", cidr: { base: BASE, prefix: 24, lo: BASE, hi: BASE + 255 } },
      { id: "a", action: "allow", cidr: { base: BASE, prefix: 26, lo: BASE, hi: BASE + 63 } },
      { id: "b", action: "allow", cidr: { base: BASE + 100, prefix: 32, lo: BASE + 100, hi: BASE + 100 } },
      { id: "c", action: "deny", cidr: { base: BASE + 128, prefix: 25, lo: BASE + 128, hi: BASE + 255 } },
    ];
    checkPolicy(rules, "fully-shadowed");
  });

  it("partial intersection with fragmented residuals and differing actions", () => {
    const mk = (id: string, action: Action, off: number, prefix: number): GenRule => {
      const size = 2 ** (32 - prefix);
      return { id, action, cidr: { base: BASE + off, prefix, lo: BASE + off, hi: BASE + off + size - 1 } };
    };
    const rules = [
      mk("m1", "deny", 64, 26), // .64..127
      mk("full", "allow", 0, 24), // keeps .0..63 and .128..255
      mk("tail", "deny", 128, 25), // .128..255 shadowed by full
      mk("hole", "allow", 200, 30), // shadowed
      mk("edge", "deny", 0, 30), // .0..3 shadowed by full? no — full is earlier, so shadowed
    ];
    checkPolicy(rules, "fragmented");
  });

  it("same-action swaps never change any decision", () => {
    const mk = (id: string, off: number, prefix: number): GenRule => {
      const size = 2 ** (32 - prefix);
      return { id, action: "allow", cidr: { base: BASE + off, prefix, lo: BASE + off, hi: BASE + off + size - 1 } };
    };
    checkPolicy([mk("a", 0, 25), mk("b", 64, 26), mk("c", 0, 26), mk("d", 200, 30)], "same-action");
  });

  it("includes the /0 rule and matches full-space brute force over the subnet", () => {
    // A /0 rule inside a generated policy: enumeration of the subnet still
    // covers every address that can change inside it; addresses outside the
    // subnet are all decided by /0 and validated separately in semantics.
    const any0: Cidr = { base: 0, prefix: 0, lo: 0, hi: 0xffffffff };
    const rules: GenRule[] = [
      { id: "local", action: "allow", cidr: { base: BASE, prefix: 26, lo: BASE, hi: BASE + 63 } },
      { id: "any", action: "deny", cidr: any0 },
      { id: "late", action: "allow", cidr: { base: BASE + 128, prefix: 25, lo: BASE + 128, hi: BASE + 255 } },
    ];
    checkPolicy(
      rules,
      "with-/0",
      // "local" exposes 64 inside the subnet; "any" (/0, second) wins the
      // other 192 subnet addresses plus every address outside the subnet:
      // outside = 2^32 - 256. "late" is fully shadowed.
      [0, 2 ** 32 - SUBNET_SIZE, 0],
    );
  });

  for (let seed = 1; seed <= 300; seed++) {
    it(`random policy #${seed} agrees with address-by-address simulation`, () => {
      const rand = mulberry32(seed * 7919 + 13);
      const count = 1 + Math.floor(rand() * 10);
      checkPolicy(randomRules(rand, count), `random-${seed}`);
    });
  }
});

describe("interval set algebra vs brute-force bitset", () => {
  it("union and subtract over a 256-address universe match a Set oracle", () => {
    const rand = mulberry32(4242);
    const randomIntervals = () => {
      const n = 1 + Math.floor(rand() * 6);
      return normalize(
        Array.from({ length: n }, () => {
          const lo = Math.floor(rand() * 256);
          const hi = lo + Math.floor(rand() * (256 - lo));
          return { lo: BASE + lo, hi: BASE + hi };
        }),
      );
    };
    const asSet = (set: ReturnType<typeof randomIntervals>) => {
      const s = new Set<number>();
      for (const { lo, hi } of set) for (let ip = lo; ip <= hi; ip++) s.add(ip);
      return s;
    };

    for (let trial = 0; trial < 200; trial++) {
      const a = randomIntervals();
      const b = randomIntervals();
      const sa = asSet(a);
      const sb = asSet(b);

      const u = asSet(union(a, b));
      for (const ip of sa) expect(u.has(ip)).toBe(true);
      for (const ip of sb) expect(u.has(ip)).toBe(true);
      expect(u.size).toBe(new Set([...sa, ...sb]).size);

      const d = asSet(subtract(a, b));
      for (const ip of sa) expect(d.has(ip)).toBe(!sb.has(ip));
      for (const ip of sb) expect(d.has(ip)).toBe(false);
    }
  });
});
