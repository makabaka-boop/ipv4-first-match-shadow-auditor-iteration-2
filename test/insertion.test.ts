import { describe, expect, it } from "vitest";
import {
  audit,
  ValidationError,
  type Action,
  type FirstMatchEvidence,
} from "../src/audit.js";
import { formatIp, parseIp } from "../src/ip.js";
import { runAudit } from "../src/runtime.js";
import { createPolicyServer } from "../src/server.js";
import type { AddressInfo } from "node:net";

/**
 * Differential testing of the read-only insertion planner.
 *
 * The oracle inserts the rule at every position 0..n and walks every address
 * of a small /24 domain linearly — an actual first-match simulation. All
 * generated CIDRs live inside the domain, so enumerating it is exhaustive for
 * any address whose decision can change. The interval-based planner must
 * agree exactly: position, changed count, changed intervals and evidence.
 */

const BASE = parseIp("10.13.0.0");
const SIZE = 256;

interface SimRule {
  id: string;
  action: Action;
  lo: number;
  hi: number;
  prefix: number;
}

const mkRule = (
  id: string,
  action: Action,
  offset: number,
  prefix: number,
): SimRule => {
  const size = 2 ** (32 - prefix);
  return { id, action, lo: BASE + offset, hi: BASE + offset + size - 1, prefix };
};

const toInput = (r: SimRule) => ({
  id: r.id,
  action: r.action,
  cidr: `${formatIp(r.lo)}/${r.prefix}`,
});

const decide = (list: SimRule[], ip: number): Action => {
  for (const r of list) if (ip >= r.lo && ip <= r.hi) return r.action;
  return "deny";
};

const firstEvidence = (list: SimRule[], ip: number): FirstMatchEvidence => {
  for (let i = 0; i < list.length; i++) {
    const r = list[i]!;
    if (ip >= r.lo && ip <= r.hi) {
      return { ruleId: r.id, index: i, action: r.action };
    }
  }
  return { ruleId: null, index: null, action: "deny" };
};

interface Probe {
  ip: number;
  expect: Action;
}

interface OraclePlan {
  position: number;
  count: number;
  changed: Set<number>;
}

/** Brute-force optimum over all insertion positions, address by address. */
function oraclePlan(
  rules: SimRule[],
  newRule: SimRule,
  probes: Probe[],
  protectedIps: number[],
): OraclePlan | null {
  const n = rules.length;
  let best: OraclePlan | null = null;
  for (let p = 0; p <= n; p++) {
    const inserted = [...rules.slice(0, p), newRule, ...rules.slice(p)];
    const feasible =
      probes.every((pr) => decide(inserted, pr.ip) === pr.expect) &&
      protectedIps.every((ip) => decide(inserted, ip) === decide(rules, ip));
    if (!feasible) continue;
    const changed = new Set<number>();
    for (let off = 0; off < SIZE; off++) {
      const ip = BASE + off;
      if (decide(rules, ip) !== decide(inserted, ip)) changed.add(ip);
    }
    // Strict < keeps the earliest position among ties, like the planner.
    if (best === null || changed.size < best.count) {
      best = { position: p, count: changed.size, changed };
    }
  }
  return best;
}

/** Compare the planner against the oracle; returns whether a plan exists. */
function checkInsertion(
  rules: SimRule[],
  newRule: SimRule,
  probes: Probe[],
  protectedIps: number[],
  label: string,
): boolean {
  const report = audit({
    rules: rules.map(toInput),
    insertion: {
      rule: toInput(newRule),
      probes: probes.map((p) => ({ address: formatIp(p.ip), expect: p.expect })),
      protected: protectedIps.map(formatIp),
    },
  });
  const ins = report.insertion!;
  const oracle = oraclePlan(rules, newRule, probes, protectedIps);

  if (oracle === null) {
    expect(ins.feasible, `${label}: must be infeasible`).toBe(false);
    if (ins.feasible) return true;
    expect(ins.reason.length, `${label}: infeasible reason`).toBeGreaterThan(0);
    // No applicable plan may leak into an infeasible report.
    expect("position" in ins).toBe(false);
    expect("changedAddresses" in ins).toBe(false);
    expect("changedIntervals" in ins).toBe(false);
    return false;
  }

  expect(ins.feasible, `${label}: must be feasible`).toBe(true);
  if (!ins.feasible) return false;

  expect(ins.position, `${label}: position`).toBe(oracle.position);
  expect(ins.changedAddresses, `${label}: changed count`).toBe(oracle.count);

  // Changed intervals: sorted, non-overlapping, covering the oracle set.
  const covered = new Set<number>();
  let prevHi = -1;
  let total = 0;
  for (const iv of ins.changedIntervals) {
    const lo = parseIp(iv.startAddress);
    const hi = parseIp(iv.endAddress);
    expect(lo, `${label}: interval well-formed`).toBeLessThanOrEqual(hi);
    expect(lo, `${label}: intervals sorted and disjoint`).toBeGreaterThan(prevHi);
    prevHi = hi;
    total += hi - lo + 1;
    for (let ip = lo; ip <= hi; ip++) covered.add(ip);
  }
  expect(total, `${label}: interval sizes sum to changed count`).toBe(oracle.count);
  expect(covered, `${label}: intervals cover exactly the changed set`).toEqual(
    oracle.changed,
  );

  // Evidence is checked against the truly inserted list at the plan position.
  const inserted = [
    ...rules.slice(0, ins.position),
    newRule,
    ...rules.slice(ins.position),
  ];
  ins.probes.forEach((pr, i) => {
    const ip = probes[i]!.ip;
    expect(pr.address).toBe(formatIp(ip));
    expect(pr.expect).toBe(probes[i]!.expect);
    expect(pr.before, `${label}: probe ${i} before`).toEqual(firstEvidence(rules, ip));
    expect(pr.after, `${label}: probe ${i} after`).toEqual(firstEvidence(inserted, ip));
    expect(pr.satisfied, `${label}: probe ${i} satisfied`).toBe(true);
  });
  ins.protected.forEach((pr, i) => {
    const ip = protectedIps[i]!;
    expect(pr.address).toBe(formatIp(ip));
    expect(pr.before, `${label}: protected ${i} before`).toEqual(firstEvidence(rules, ip));
    expect(pr.after, `${label}: protected ${i} after`).toEqual(firstEvidence(inserted, ip));
    expect(pr.preserved, `${label}: protected ${i} preserved`).toBe(true);
  });
  return true;
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

function randomCase(rand: () => number): {
  rules: SimRule[];
  newRule: SimRule;
  probes: Probe[];
  protectedIps: number[];
} {
  const randomBlock = () => {
    const hostBits = Math.floor(rand() * 9); // /24 .. /32 inside the domain
    const block = 2 ** hostBits;
    const offset = Math.floor(rand() * (SIZE / block)) * block;
    return { offset, prefix: 32 - hostBits };
  };

  const rules: SimRule[] = [];
  const used = new Set<string>();
  const ruleCount = 1 + Math.floor(rand() * 6);
  let guard = 0;
  while (rules.length < ruleCount && guard < 200) {
    guard++;
    const { offset, prefix } = randomBlock();
    const key = `${offset}/${prefix}`;
    if (used.has(key)) continue;
    used.add(key);
    rules.push(
      mkRule(`r${rules.length}`, rand() < 0.5 ? "allow" : "deny", offset, prefix),
    );
  }

  const nb = randomBlock();
  const newRule = mkRule("new", rand() < 0.5 ? "allow" : "deny", nb.offset, nb.prefix);
  const probes: Probe[] = Array.from({ length: Math.floor(rand() * 4) }, () => ({
    ip: BASE + Math.floor(rand() * SIZE),
    expect: (rand() < 0.5 ? "allow" : "deny") as Action,
  }));
  const protectedIps: number[] = Array.from(
    { length: Math.floor(rand() * 4) },
    () => BASE + Math.floor(rand() * SIZE),
  );
  return { rules, newRule, probes, protectedIps };
}

describe("insertion planning vs per-address oracle in 10.13.0.0/24", () => {
  it("200 random policies agree on position, count, intervals and evidence", () => {
    let feasibleCount = 0;
    let infeasibleCount = 0;
    for (let seed = 1; seed <= 200; seed++) {
      const rand = mulberry32(seed * 31337 + 7);
      const { rules, newRule, probes, protectedIps } = randomCase(rand);
      const feasible = checkInsertion(
        rules,
        newRule,
        probes,
        protectedIps,
        `random-${seed}`,
      );
      if (feasible) feasibleCount++;
      else infeasibleCount++;
    }
    // Both outcomes must be exercised by the differential run.
    expect(feasibleCount).toBeGreaterThan(0);
    expect(infeasibleCount).toBeGreaterThan(0);
  });
});

describe("insertion planning: hand-computed cases", () => {
  const plan = (input: unknown) => {
    const ins = audit(input).insertion!;
    expect(ins).toBeDefined();
    return ins;
  };

  it("picks the only feasible position and reports shifted first-match evidence", () => {
    const ins = plan({
      rules: [
        { id: "r0", action: "allow", cidr: "10.0.0.0/24" },
        { id: "r1", action: "deny", cidr: "10.0.0.128/25" },
      ],
      insertion: {
        rule: { id: "temp", action: "deny", cidr: "10.0.0.64/26" },
        probes: [
          { address: "10.0.0.100", expect: "deny" },
          { address: "10.0.0.200", expect: "allow" },
        ],
      },
    });
    // Only position 0 lets the probe at .100 flip to deny; there the new rule
    // decides .64..127, which used to be allowed by r0 -> 64 changed addresses.
    expect(ins).toMatchObject({
      feasible: true,
      position: 0,
      changedAddresses: 64,
      changedIntervals: [{ startAddress: "10.0.0.64", endAddress: "10.0.0.127" }],
    });
    if (!ins.feasible) return;
    expect(ins.probes[0]).toEqual({
      address: "10.0.0.100",
      expect: "deny",
      before: { ruleId: "r0", index: 0, action: "allow" },
      after: { ruleId: "temp", index: 0, action: "deny" },
      satisfied: true,
    });
    // r0 keeps deciding .200 but shifts one index down behind the new rule.
    expect(ins.probes[1]).toEqual({
      address: "10.0.0.200",
      expect: "allow",
      before: { ruleId: "r0", index: 0, action: "allow" },
      after: { ruleId: "r0", index: 1, action: "allow" },
      satisfied: true,
    });
  });

  it("appending a deny /0 after an allow rule changes nothing", () => {
    const ins = plan({
      rules: [{ id: "r0", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: { rule: { id: "temp", action: "deny", cidr: "0.0.0.0/0" } },
    });
    expect(ins).toMatchObject({
      feasible: true,
      position: 1,
      changedAddresses: 0,
      changedIntervals: [],
    });
  });

  it("a deny /0 forced to the front flips exactly the previously allowed /24", () => {
    const ins = plan({
      rules: [{ id: "r0", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: {
        rule: { id: "temp", action: "deny", cidr: "0.0.0.0/0" },
        probes: [{ address: "10.0.0.5", expect: "deny" }],
      },
    });
    expect(ins).toMatchObject({
      feasible: true,
      position: 0,
      changedAddresses: 256,
      changedIntervals: [{ startAddress: "10.0.0.0", endAddress: "10.0.0.255" }],
    });
  });

  it("a deny /0 can never satisfy an allow probe on default-deny space", () => {
    const ins = plan({
      rules: [{ id: "r0", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: {
        rule: { id: "temp", action: "deny", cidr: "0.0.0.0/0" },
        probes: [{ address: "8.8.8.8", expect: "allow" }],
      },
    });
    expect(ins.feasible).toBe(false);
    if (ins.feasible) return;
    expect(ins.reason).toMatch(/no insertion position/);
    expect("position" in ins).toBe(false);
    expect("changedIntervals" in ins).toBe(false);
  });

  it("allow /0 behind a deny rule: protected address forces the later position", () => {
    const ins = plan({
      rules: [{ id: "r0", action: "deny", cidr: "10.0.0.0/24" }],
      insertion: {
        rule: { id: "temp", action: "allow", cidr: "0.0.0.0/0" },
        probes: [{ address: "8.8.8.8", expect: "allow" }],
        protected: ["10.0.0.5"],
      },
    });
    // Position 0 would flip the protected 10.0.0.5 to allow; position 1 keeps
    // it denied and still lets the new rule allow everything else.
    expect(ins).toMatchObject({
      feasible: true,
      position: 1,
      changedAddresses: 2 ** 32 - 256,
      changedIntervals: [
        { startAddress: "0.0.0.0", endAddress: "9.255.255.255" },
        { startAddress: "10.0.1.0", endAddress: "255.255.255.255" },
      ],
    });
    if (!ins.feasible) return;
    expect(ins.probes[0]).toEqual({
      address: "8.8.8.8",
      expect: "allow",
      before: { ruleId: null, index: null, action: "deny" },
      after: { ruleId: "temp", index: 1, action: "allow" },
      satisfied: true,
    });
    expect(ins.protected[0]).toEqual({
      address: "10.0.0.5",
      before: { ruleId: "r0", index: 0, action: "deny" },
      after: { ruleId: "r0", index: 0, action: "deny" },
      preserved: true,
    });
  });

  it("declares a protected-address conflict infeasible without emitting a plan", () => {
    // 10.1.0.7 is default-deny today; the new allow rule would flip it anywhere.
    const ins = plan({
      rules: [{ id: "r0", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: {
        rule: { id: "temp", action: "allow", cidr: "10.1.0.0/24" },
        protected: ["10.1.0.7"],
      },
    });
    expect(ins.feasible).toBe(false);
    if (ins.feasible) return;
    expect(ins.reason).toMatch(/no insertion position/);
    expect("position" in ins).toBe(false);
    expect("changedAddresses" in ins).toBe(false);
    expect("changedIntervals" in ins).toBe(false);
  });

  it("a probe contradicting a protected address is infeasible", () => {
    const ins = plan({
      rules: [{ id: "r0", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: {
        rule: { id: "temp", action: "deny", cidr: "10.0.0.0/25" },
        probes: [{ address: "10.0.0.5", expect: "deny" }],
        protected: ["10.0.0.5"],
      },
    });
    expect(ins.feasible).toBe(false);
  });

  it("default-deny probes stay satisfied and ties resolve to the earliest position", () => {
    const ins = plan({
      rules: [{ id: "r0", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: {
        rule: { id: "temp", action: "allow", cidr: "10.0.1.0/24" },
        probes: [
          { address: "8.8.8.8", expect: "deny" }, // default deny, never touched
          { address: "10.0.1.5", expect: "allow" },
        ],
      },
    });
    // Both positions change exactly the 256 default-deny addresses of the new
    // /24; the tie must resolve to the earliest position.
    expect(ins).toMatchObject({
      feasible: true,
      position: 0,
      changedAddresses: 256,
      changedIntervals: [{ startAddress: "10.0.1.0", endAddress: "10.0.1.255" }],
    });
    if (!ins.feasible) return;
    expect(ins.probes[0]!.before).toEqual({ ruleId: null, index: null, action: "deny" });
    expect(ins.probes[0]!.after).toEqual({ ruleId: null, index: null, action: "deny" });
    expect(ins.probes[1]!.after).toEqual({ ruleId: "temp", index: 0, action: "allow" });
  });

  it("a same-action first-match change is not a decision change", () => {
    // Inserting allow 10.0.0.128/25 in front of allow 10.0.0.0/24 moves the
    // first match of .128..255 from r0 to temp but keeps them allowed.
    const ins = plan({
      rules: [{ id: "r0", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: { rule: { id: "temp", action: "allow", cidr: "10.0.0.128/25" } },
    });
    expect(ins).toMatchObject({ feasible: true, changedAddresses: 0, changedIntervals: [] });
  });

  it("overlapping CIDRs: the optimum can be a non-trivial later position", () => {
    const ins = plan({
      rules: [{ id: "r0", action: "deny", cidr: "10.0.0.0/25" }],
      insertion: { rule: { id: "temp", action: "allow", cidr: "10.0.0.0/24" } },
    });
    // In front, the new /24 flips 256 deny addresses; behind r0 only the
    // default-deny upper half .128..255 flips -> 128.
    expect(ins).toMatchObject({
      feasible: true,
      position: 1,
      changedAddresses: 128,
      changedIntervals: [{ startAddress: "10.0.0.128", endAddress: "10.0.0.255" }],
    });
  });

  it("keeps the original audit sections identical with and without insertion", () => {
    const base = {
      rules: [
        { id: "web", action: "allow", cidr: "10.0.0.0/24" },
        { id: "api", action: "allow", cidr: "10.0.0.128/25" },
        { id: "deny-all", action: "deny", cidr: "0.0.0.0/0" },
      ],
      queries: ["10.0.0.5", "192.168.0.1"],
    };
    const plain = audit(base);
    const enriched = audit({
      ...base,
      insertion: {
        rule: { id: "temp", action: "allow", cidr: "192.168.0.0/24" },
        probes: [{ address: "192.168.0.10", expect: "allow" }],
        protected: ["10.0.0.5"],
      },
    });
    expect(plain.insertion).toBeUndefined();
    expect(enriched.insertion).toBeDefined();
    // Rules, shadowing certificates, swaps, queries and summary are untouched.
    expect({
      rules: enriched.rules,
      swaps: enriched.swaps,
      queries: enriched.queries,
      summary: enriched.summary,
    }).toEqual({
      rules: plain.rules,
      swaps: plain.swaps,
      queries: plain.queries,
      summary: plain.summary,
    });
  });
});

describe("insertion request validation", () => {
  const rules = [{ id: "web", action: "allow", cidr: "10.0.0.0/24" }];
  const rule = { id: "temp", action: "allow", cidr: "10.0.1.0/24" };
  const run = (insertion: unknown) => () => audit({ rules, insertion });

  it("rejects non-object insertion bodies and missing rule", () => {
    expect(run(null)).toThrow(ValidationError);
    expect(run(null)).toThrow(/insertion must be an object/);
    expect(run(5)).toThrow(/insertion must be an object/);
    expect(run({})).toThrow(/\$\.insertion\.rule: missing required field rule/);
  });

  it("rejects unknown fields at insertion and probe level", () => {
    expect(run({ rule, ttl: 30 })).toThrow(/unknown field "ttl"/);
    expect(run({ rule, probes: [{ address: "10.0.0.1", expect: "allow", ttl: 1 }] })).toThrow(
      /unknown field "ttl"/,
    );
  });

  it("validates the new rule with the regular rule contract", () => {
    expect(run({ rule: { id: "temp", action: "allow", cidr: "10.0.0.1/24" } })).toThrow(
      /\$\.insertion\.rule\.cidr: non-canonical CIDR/,
    );
    expect(run({ rule: { id: "temp", action: "permit", cidr: "10.0.1.0/24" } })).toThrow(
      /\$\.insertion\.rule\.action/,
    );
    expect(run({ rule: { id: "", action: "allow", cidr: "10.0.1.0/24" } })).toThrow(
      /\$\.insertion\.rule\.id/,
    );
    expect(run({ rule: { id: "web", action: "allow", cidr: "10.0.1.0/24" } })).toThrow(
      /duplicate rule id "web"/,
    );
  });

  it("validates probes and protected addresses", () => {
    expect(run({ rule, probes: "10.0.0.1" })).toThrow(/probes must be an array/);
    expect(run({ rule, probes: ["10.0.0.1"] })).toThrow(/probe must be an object/);
    expect(run({ rule, probes: [{ address: "10.0.0.256", expect: "allow" }] })).toThrow(
      /\$\.insertion\.probes\[0\]\.address/,
    );
    expect(run({ rule, probes: [{ address: "10.0.0.1", expect: "permit" }] })).toThrow(
      /expect must be "allow" or "deny"/,
    );
    expect(
      run({ rule, probes: Array.from({ length: 101 }, () => ({ address: "10.0.0.1", expect: "allow" })) }),
    ).toThrow(/too many probes/);
    expect(run({ rule, protected: "10.0.0.1" })).toThrow(/protected must be an array/);
    expect(run({ rule, protected: ["010.0.0.1"] })).toThrow(/\$\.insertion\.protected\[0\]/);
    expect(run({ rule, protected: Array(101).fill("10.0.0.1") })).toThrow(/too many protected/);
  });

  it("rejects the whole request on any invalid insertion input", () => {
    for (const insertion of [
      null,
      {},
      { rule: { id: "web", action: "allow", cidr: "10.0.1.0/24" } },
      { rule, probes: [{ address: "bad", expect: "allow" }] },
    ]) {
      expect(() => audit({ rules, queries: ["10.0.0.1"], insertion })).toThrow(ValidationError);
    }
  });
});

describe("CLI and HTTP consistency", () => {
  const bodies = [
    // Feasible plan with probes and protected addresses.
    JSON.stringify({
      rules: [
        { id: "web", action: "allow", cidr: "10.0.0.0/24" },
        { id: "deny-all", action: "deny", cidr: "0.0.0.0/0" },
      ],
      queries: ["10.0.0.5"],
      insertion: {
        rule: { id: "temp", action: "allow", cidr: "192.168.0.0/24" },
        probes: [{ address: "192.168.0.10", expect: "allow" }],
        protected: ["10.0.0.5"],
      },
    }),
    // Infeasible plan.
    JSON.stringify({
      rules: [{ id: "web", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: {
        rule: { id: "temp", action: "allow", cidr: "10.1.0.0/24" },
        protected: ["10.1.0.7"],
      },
    }),
  ];

  const postAudit = async (body: string) => {
    const server = createPolicyServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const res = await fetch(`http://127.0.0.1:${port}/audit`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      return { status: res.status, json: await res.json() };
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  };

  it("returns byte-identical reports from the CLI runtime and POST /audit", async () => {
    for (const body of bodies) {
      // cli.ts prints exactly runAudit(text); the HTTP path must agree.
      const cliReport = runAudit(body);
      const http = await postAudit(body);
      expect(http.status).toBe(200);
      expect(http.json).toEqual(cliReport);
    }
  });

  it("rejects the same invalid insertion with the same message on both paths", async () => {
    const bad = JSON.stringify({
      rules: [{ id: "web", action: "allow", cidr: "10.0.0.0/24" }],
      insertion: { rule: { id: "temp", action: "allow", cidr: "10.0.0.1/24" } },
    });
    let cliMessage = "";
    try {
      runAudit(bad);
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      cliMessage = (err as Error).message;
    }
    expect(cliMessage).toContain("$.insertion.rule.cidr");

    const http = await postAudit(bad);
    expect(http.status).toBe(400);
    expect(http.json).toEqual({ error: "validation_error", message: cliMessage });
  });
});
