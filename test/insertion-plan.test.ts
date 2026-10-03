import { describe, expect, it } from "vitest";
import { audit, planInsertion, ValidationError, type Action } from "../src/audit.js";
import { formatIp, parseIp, type Cidr } from "../src/ip.js";
import { runAudit } from "../src/runtime.js";

const rule = (id: string, action: Action, cidr: string) => ({ id, action, cidr });
const BASE = parseIp("10.13.0.0");
const PREFIX = 24;
const SIZE = 2 ** (32 - PREFIX);

interface GenRule {
  id: string;
  action: Action;
  cidr: Cidr;
}

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

function randomCidr(rand: () => number, prefix: number = PREFIX): Cidr {
  const hostBits = Math.floor(rand() * (32 - prefix + 1));
  const block = 2 ** hostBits;
  const offset = Math.floor(rand() * (SIZE / block)) * block;
  const lo = BASE + offset;
  return {
    base: lo,
    prefix: 32 - hostBits,
    lo,
    hi: lo + block - 1,
  };
}

function randomRules(rand: () => number): GenRule[] {
  const count = 1 + Math.floor(rand() * 8);
  return Array.from({ length: count }, (_, i) => ({
    id: `r${i}`,
    action: rand() < 0.5 ? "allow" : "deny",
    cidr: randomCidr(rand),
  }));
}

const ruleInput = (r: GenRule) => ({
  id: r.id,
  action: r.action,
  cidr: `${formatIp(r.cidr.base)}/${r.cidr.prefix}`,
});

function firstMatch(rules: GenRule[], ip: number): { rule: GenRule; index: number } | null {
  for (let i = 0; i < rules.length; i++) {
    const r = rules[i]!;
    if (ip >= r.cidr.lo && ip <= r.cidr.hi) return { rule: r, index: i };
  }
  return null;
}

function decision(rules: GenRule[], ip: number): Action {
  return firstMatch(rules, ip)?.rule.action ?? "deny";
}

function evidence(rules: GenRule[], ip: number) {
  const match = firstMatch(rules, ip);
  return match === null
    ? { ruleId: null, action: "deny" as Action, index: null }
    : { ruleId: match.rule.id, action: match.rule.action, index: match.index };
}

describe("read-only insertion planning", () => {
  it("chooses the earliest minimum-change position and ignores same-action hit changes", () => {
    const input = {
      rules: [rule("lower", "allow", "10.13.0.0/25")],
      newRule: rule("temp-allow", "allow", "10.13.0.0/24"),
      probes: [{ address: "10.13.0.200", action: "allow" as const }],
    };
    const plan = audit(input).insertionPlan!;

    expect(plan).toMatchObject({
      feasible: true,
      candidatePositions: 2,
      position: 0,
      changedAddresses: 128,
    });
    expect(plan.changedIntervals).toEqual([
      { startAddress: "10.13.0.128", endAddress: "10.13.0.255" },
    ]);
    expect(plan.probes[0]).toEqual({
      address: "10.13.0.200",
      requiredAction: "allow",
      before: { ruleId: null, action: "deny", index: null },
      after: { ruleId: "temp-allow", action: "allow", index: 0 },
    });
  });

  it("handles a deny /0 by only flipping addresses previously allowed", () => {
    const input = {
      rules: [rule("local", "allow", "10.13.0.0/26")],
      newRule: rule("block-all", "deny", "0.0.0.0/0"),
      probes: [
        { address: "10.13.0.1", action: "deny" as const },
        { address: "8.8.8.8", action: "deny" as const },
      ],
    };
    const plan = audit(input).insertionPlan!;

    expect(plan.feasible).toBe(true);
    expect(plan.position).toBe(0);
    expect(plan.changedAddresses).toBe(64);
    expect(plan.changedIntervals).toEqual([
      { startAddress: "10.13.0.0", endAddress: "10.13.0.63" },
    ]);
    expect(plan.probes[0]!.before).toMatchObject({ action: "allow", ruleId: "local" });
    expect(plan.probes[0]!.after).toMatchObject({ action: "deny", ruleId: "block-all", index: 0 });
    expect(plan.probes[1]!.after).toMatchObject({ action: "deny", ruleId: "block-all", index: 0 });
  });

  it("handles an allow /0 while protecting a local deny across full IPv4 space", () => {
    const input = {
      rules: [rule("local-deny", "deny", "10.13.0.0/24")],
      newRule: rule("allow-all", "allow", "0.0.0.0/0"),
      probes: [{ address: "8.8.8.8", action: "allow" as const }],
      protectedAddresses: ["10.13.0.1"],
    };
    const plan = audit(input).insertionPlan!;

    expect(plan.feasible).toBe(true);
    expect(plan.position).toBe(1);
    expect(plan.changedAddresses).toBe(2 ** 32 - 256);
    expect(plan.changedIntervals).toEqual([
      { startAddress: "0.0.0.0", endAddress: "10.12.255.255" },
      { startAddress: "10.13.1.0", endAddress: "255.255.255.255" },
    ]);
  });

  it("finds fragmented sorted disjoint change intervals for overlapping CIDRs", () => {
    const input = {
      rules: [
        rule("a", "allow", "10.13.0.0/26"),
        rule("d", "deny", "10.13.0.64/26"),
        rule("b", "allow", "10.13.0.128/26"),
      ],
      newRule: rule("block", "deny", "10.13.0.0/24"),
      probes: [
        { address: "10.13.0.5", action: "deny" as const },
        { address: "10.13.0.130", action: "deny" as const },
      ],
      protectedAddresses: ["10.13.0.100"],
    };
    const plan = audit(input).insertionPlan!;

    expect(plan.position).toBe(0);
    expect(plan.changedAddresses).toBe(128);
    expect(plan.changedIntervals).toEqual([
      { startAddress: "10.13.0.0", endAddress: "10.13.0.63" },
      { startAddress: "10.13.0.128", endAddress: "10.13.0.191" },
    ]);
  });

  it("reports no applicable plan when probe and protected-address requirements conflict", () => {
    const plan = audit({
      rules: [rule("allow-subnet", "allow", "10.13.0.0/24")],
      newRule: rule("block-subnet", "deny", "10.13.0.0/24"),
      probes: [{ address: "10.13.0.1", action: "deny" as const }],
      protectedAddresses: ["10.13.0.1"],
    }).insertionPlan!;

    expect(plan.feasible).toBe(false);
    expect(plan.position).toBeNull();
    expect(plan.changedAddresses).toBeNull();
    expect(plan.changedIntervals).toBeNull();
    expect(plan.reason).toMatch(/no insertion position/);
    expect(plan.probes[0]!.before).toMatchObject({
      ruleId: "allow-subnet",
      action: "allow",
      index: 0,
    });
    expect(plan.probes[0]!.after).toBeNull();
  });

  for (let seed = 1; seed <= 300; seed++) {
    it(`agrees with an address-by-address oracle (random ${seed})`, () => {
      const rand = mulberry32(seed * 104729 + 17);
      const oldRules = randomRules(rand);
      const newGenRule: GenRule = { id: "new-rule", action: rand() < 0.5 ? "allow" : "deny", cidr: randomCidr(rand) };
      const probeOffsets = Array.from({ length: 1 + Math.floor(rand() * 4) }, () =>
        Math.floor(rand() * SIZE),
      );
      const protectedOffsets = Array.from({ length: Math.floor(rand() * 4) }, () =>
        Math.floor(rand() * SIZE),
      );
      const probes = probeOffsets.map((off) => ({
        address: formatIp(BASE + off),
        action: (rand() < 0.5 ? "allow" : "deny") as Action,
      }));

      const input = {
        rules: oldRules.map(ruleInput),
        newRule: ruleInput(newGenRule),
        probes,
        protectedAddresses: protectedOffsets.map((off) => formatIp(BASE + off)),
      };
      const plan = audit(input).insertionPlan!;

      let expectedPosition: number | null = null;
      let expectedChanged: number[] = [];
      let expectedCount = Infinity;

      for (let position = 0; position <= oldRules.length; position++) {
        const inserted = [
          ...oldRules.slice(0, position),
          newGenRule,
          ...oldRules.slice(position),
        ];
        const probesOk = probes.every(
          (probe, i) => decision(inserted, BASE + probeOffsets[i]!) === probe.action,
        );
        const protectedOk = protectedOffsets.every(
          (off) => decision(inserted, BASE + off) === decision(oldRules, BASE + off),
        );
        if (!probesOk || !protectedOk) continue;

        const changed: number[] = [];
        for (let off = 0; off < SIZE; off++) {
          const ip = BASE + off;
          if (decision(oldRules, ip) !== decision(inserted, ip)) changed.push(ip);
        }
        if (changed.length < expectedCount) {
          expectedCount = changed.length;
          expectedPosition = position;
          expectedChanged = changed;
        }
      }

      expect(plan.candidatePositions).toBe(oldRules.length + 1);
      if (expectedPosition === null) {
        expect(plan.feasible).toBe(false);
        expect(plan.position).toBeNull();
        expect(plan.changedAddresses).toBeNull();
        expect(plan.changedIntervals).toBeNull();
        expect(plan.probes.every((probe) => probe.after === null)).toBe(true);
        return;
      }

      const inserted = [
        ...oldRules.slice(0, expectedPosition),
        newGenRule,
        ...oldRules.slice(expectedPosition),
      ];
      const expectedIntervals: Array<{ startAddress: string; endAddress: string }> = [];
      for (const ip of expectedChanged) {
        const last = expectedIntervals.at(-1);
        if (last && parseIp(last.endAddress) === ip - 1) {
          last.endAddress = formatIp(ip);
        } else {
          expectedIntervals.push({ startAddress: formatIp(ip), endAddress: formatIp(ip) });
        }
      }

      expect(plan.feasible).toBe(true);
      expect(plan.position).toBe(expectedPosition);
      expect(plan.changedAddresses).toBe(expectedCount);
      expect(plan.changedIntervals).toEqual(expectedIntervals);
      expect(plan.protectedAddresses).toEqual(protectedOffsets.map((off) => formatIp(BASE + off)));
      expect(plan.probes).toEqual(
        probes.map((probe, i) => ({
          address: probe.address,
          requiredAction: probe.action,
          before: evidence(oldRules, BASE + probeOffsets[i]!),
          after: evidence(inserted, BASE + probeOffsets[i]!),
        })),
      );
    });
  }

  it("accepts expectedAction as the probe conclusion field", () => {
    const plan = audit({
      rules: [rule("a", "deny", "10.13.0.0/24")],
      newRule: rule("b", "allow", "10.13.0.0/32"),
      probes: [{ address: "10.13.0.0", expectedAction: "allow" }],
    }).insertionPlan!;

    expect(plan.feasible).toBe(true);
    expect(plan.position).toBe(0);
    expect(plan.probes[0]).toMatchObject({ requiredAction: "allow" });
  });

  it("validates insertion-specific input and rejects the whole request on errors", () => {
    expect(() =>
      audit({
        rules: [rule("a", "allow", "10.13.0.0/24")],
        newRule: rule("a", "deny", "10.13.0.0/32"),
      }),
    ).toThrow(/duplicate rule id/);
    expect(() =>
      audit({
        rules: [rule("a", "allow", "10.13.0.0/24")],
        newRule: rule("bad", "deny", "10.13.0.1/24"),
      }),
    ).toThrow(/non-canonical/);
    expect(() =>
      audit({
        rules: [rule("a", "allow", "10.13.0.0/24")],
        newRule: rule("b", "deny", "10.13.0.0/32"),
        probes: [{ address: "10.13.0.1", action: "maybe" }],
      }),
    ).toThrow(ValidationError);
    expect(() =>
      audit({
        rules: [rule("a", "allow", "10.13.0.0/24")],
        newRule: rule("b", "deny", "10.13.0.0/32"),
        protectedAddresses: ["10.13.0.999"],
      }),
    ).toThrow(ValidationError);
    expect(() =>
      audit({
        rules: [rule("a", "allow", "10.13.0.0/24")],
        probes: [{ address: "10.13.0.1", action: "allow" }],
      }),
    ).toThrow(/probes and protectedAddresses require newRule/);
    expect(() => planInsertion({ rules: [rule("a", "allow", "10.13.0.0/24")] })).toThrow(
      /missing required field newRule/,
    );
    expect(() =>
      audit({
        rules: Array.from({ length: 300 }, (_, i) =>
          rule(`r${i}`, "allow", `${formatIp(i)}/32`),
        ),
        newRule: rule("extra", "allow", "10.13.0.0/32"),
      }),
    ).toThrow(/insertion would exceed 300 rules/);
  });

  it("keeps CLI and HTTP on the same JSON runtime result", () => {
    const input = {
      rules: [rule("a", "deny", "10.13.0.0/25"), rule("b", "allow", "10.13.0.0/24")],
      newRule: rule("c", "allow", "10.13.0.64/26"),
      probes: [{ address: "10.13.0.65", action: "allow" }],
      protectedAddresses: ["10.13.0.1"],
    };
    const text = JSON.stringify(input);
    expect(runAudit(text)).toEqual(audit(input));
  });
});
