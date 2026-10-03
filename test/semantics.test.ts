import { describe, expect, it } from "vitest";
import { audit, type Action } from "../src/audit.js";

const rule = (id: string, action: Action, cidr: string) => ({ id, action, cidr });
type R = ReturnType<typeof rule>;

const run = (rules: R[], queries: string[] = []) => audit({ rules, queries });

describe("per-rule residual coverage and status", () => {
  it("marks a single rule active over its whole CIDR", () => {
    const r = run([rule("a", "allow", "10.0.0.0/24")]).rules[0]!;
    expect(r).toMatchObject({
      exposedAddresses: 256,
      totalAddresses: 256,
      witness: "10.0.0.0",
      status: "active",
    });
  });

  it("reports /0 as 2^32 exposed addresses", () => {
    const r = run([rule("any", "allow", "0.0.0.0/0")]).rules[0]!;
    expect(r.exposedAddresses).toBe(2 ** 32);
    expect(r.witness).toBe("0.0.0.0");
    expect(r.status).toBe("active");
  });

  it("reports a rule fully covered by earlier rules as shadowed", () => {
    // A takes the whole /24, B repeats its lower half, C a sub-block of that.
    const rep = run([
      rule("a", "allow", "10.0.0.0/24"),
      rule("b", "deny", "10.0.0.0/25"),
      rule("c", "allow", "10.0.0.64/26"),
    ]);
    const [a, b, c] = rep.rules;
    expect(a).toMatchObject({ status: "active", exposedAddresses: 256, witness: "10.0.0.0" });
    expect(b).toMatchObject({ status: "shadowed", exposedAddresses: 0, witness: null });
    expect(c).toMatchObject({ status: "shadowed", exposedAddresses: 0, witness: null });
    expect(b.coverageCertificate).toEqual({
      ruleIds: ["a"],
      steps: [{ ruleId: "a", startAddress: "10.0.0.0", endAddress: "10.0.0.127" }],
    });
    expect(c.coverageCertificate).toEqual({
      ruleIds: ["a"],
      steps: [{ ruleId: "a", startAddress: "10.0.0.64", endAddress: "10.0.0.127" }],
    });
  });

  it("splits a rule into two exposed fragments around an earlier block", () => {
    // A covers whole /24; B only claims .64/26 later -> B is shadowed.
    // Reverse the order to expose fragments:
    const rep = run([
      rule("mid", "deny", "10.0.0.64/26"), // .64..127
      rule("whole", "allow", "10.0.0.0/24"), // keeps .0..63 and .128..255
    ]);
    const [mid, whole] = rep.rules;
    expect(mid).toMatchObject({ status: "active", exposedAddresses: 64, witness: "10.0.0.64" });
    expect(whole).toMatchObject({ status: "partial", exposedAddresses: 192, witness: "10.0.0.0" });
  });

  it("flags everything after an allow /0 as shadowed", () => {
    const rep = run([
      rule("any", "allow", "0.0.0.0/0"),
      rule("late", "deny", "10.0.0.0/8"),
      rule("late2", "deny", "8.8.8.8/32"),
    ]);
    expect(rep.summary.shadowedCount).toBe(2);
    expect(rep.rules[1]).toMatchObject({ status: "shadowed", exposedAddresses: 0, witness: null });
    expect(rep.rules[2]).toMatchObject({ status: "shadowed", exposedAddresses: 0, witness: null });
  });

  it("treats equal-action overlap as shadowing for decision purposes too", () => {
    const rep = run([rule("a", "deny", "10.0.0.0/24"), rule("b", "deny", "10.0.0.0/25")]);
    expect(rep.rules[1]).toMatchObject({ status: "shadowed", exposedAddresses: 0 });
  });

  it("does not attach coverage certificates to active or partial rules", () => {
    const rep = run([
      rule("first", "deny", "10.0.0.0/26"),
      rule("partial", "allow", "10.0.0.0/24"),
      rule("active", "deny", "10.0.1.0/24"),
    ]);
    expect(rep.rules[0]!.coverageCertificate).toBeUndefined();
    expect(rep.rules[1]!.coverageCertificate).toBeUndefined();
    expect(rep.rules[2]!.coverageCertificate).toBeUndefined();
  });
});

describe("shadowing coverage certificates", () => {
  it("returns exact closed intervals for a multi-step minimum cover", () => {
    const rep = run([
      rule("q0", "deny", "10.0.0.0/26"),
      rule("q1", "allow", "10.0.0.64/26"),
      rule("q2", "deny", "10.0.0.128/26"),
      rule("skip", "allow", "10.0.0.200/30"),
      rule("q3", "deny", "10.0.0.192/26"),
      rule("target", "allow", "10.0.0.0/24"),
    ]);

    expect(rep.rules[5]!.coverageCertificate).toEqual({
      ruleIds: ["q0", "q1", "q2", "q3"],
      steps: [
        { ruleId: "q0", startAddress: "10.0.0.0", endAddress: "10.0.0.63" },
        { ruleId: "q1", startAddress: "10.0.0.64", endAddress: "10.0.0.127" },
        { ruleId: "q2", startAddress: "10.0.0.128", endAddress: "10.0.0.191" },
        { ruleId: "q3", startAddress: "10.0.0.192", endAddress: "10.0.0.255" },
      ],
    });
  });

  it("breaks equal right-end choices using the earlier rule index", () => {
    const rep = run([
      rule("wide", "allow", "10.0.0.0/25"),
      rule("same-reach", "deny", "10.0.0.64/26"),
      rule("later", "deny", "10.0.0.128/25"),
      rule("target", "allow", "10.0.0.0/24"),
    ]);

    expect(rep.rules[3]!.coverageCertificate).toEqual({
      ruleIds: ["wide", "later"],
      steps: [
        { ruleId: "wide", startAddress: "10.0.0.0", endAddress: "10.0.0.127" },
        { ruleId: "later", startAddress: "10.0.0.128", endAddress: "10.0.0.255" },
      ],
    });
  });

  it("supports /0 boundaries with address-form endpoints and unsigned counts", () => {
    const rep = run([
      rule("any", "deny", "0.0.0.0/0"),
      rule("target", "allow", "0.0.0.0/0"),
      rule("host", "allow", "8.8.8.8/32"),
    ]);

    expect(rep.rules[1]!.coverageCertificate).toEqual({
      ruleIds: ["any"],
      steps: [{ ruleId: "any", startAddress: "0.0.0.0", endAddress: "255.255.255.255" }],
    });
    expect(rep.rules[2]!.coverageCertificate).toEqual({
      ruleIds: ["any"],
      steps: [{ ruleId: "any", startAddress: "8.8.8.8", endAddress: "8.8.8.8" }],
    });
  });
});

describe("adjacent swap impact", () => {
  it("counts the intersection not covered earlier and its smallest witness", () => {
    const rep = run([
      rule("a", "allow", "10.0.0.0/24"),
      rule("b", "deny", "10.0.0.128/25"),
    ]);
    const swap = rep.swaps[0]!;
    expect(swap.changedAddresses).toBe(128); // intersection .128..255
    expect(swap.witness).toBe("10.0.0.128");
    expect(swap.ids).toEqual(["a", "b"]);
  });

  it("excludes addresses already decided by earlier rules", () => {
    const rep = run([
      rule("early", "deny", "10.0.0.0/25"), // .0..127 decided first
      rule("a", "allow", "10.0.0.0/24"),
      rule("b", "deny", "10.0.0.0/25"), // intersection with a: .0..127, all shadowed by early
    ]);
    expect(rep.swaps[1]!.changedAddresses).toBe(0);
    expect(rep.swaps[1]!.witness).toBeNull();
  });

  it("reports zero change when adjacent rules share an action", () => {
    const rep = run([rule("a", "allow", "10.0.0.0/24"), rule("b", "allow", "10.0.0.128/25")]);
    expect(rep.swaps[0]).toMatchObject({ changedAddresses: 0, witness: null });
  });

  it("covers the /0 extreme: swapping changes the whole other CIDR", () => {
    const rep = run([rule("big", "allow", "0.0.0.0/0"), rule("small", "deny", "8.8.8.8/32")]);
    expect(rep.swaps[0]!.changedAddresses).toBe(1);
    expect(rep.swaps[0]!.witness).toBe("8.8.8.8");
  });

  it("handles /31 and /32 CIDRs with exact single-address witnesses", () => {
    const rep = run([
      rule("p2p", "allow", "10.0.0.0/31"), // .0, .1
      rule("one", "deny", "10.0.0.1/32"), // shadowed by p2p
      rule("other", "allow", "10.0.0.5/32"),
    ]);
    expect(rep.rules[0]).toMatchObject({ totalAddresses: 2, exposedAddresses: 2, status: "active" });
    expect(rep.rules[1]).toMatchObject({ totalAddresses: 1, exposedAddresses: 0, status: "shadowed" });
    expect(rep.rules[2]).toMatchObject({
      totalAddresses: 1,
      exposedAddresses: 1,
      witness: "10.0.0.5",
      status: "active",
    });
  });

  it("counts non-/0 residuals close to 2^32 exactly", () => {
    // 0.0.0.0/1 covers 2^31 addresses; a following /0 keeps the other half.
    const rep = run([rule("half", "deny", "0.0.0.0/1"), rule("rest", "allow", "0.0.0.0/0")]);
    expect(rep.rules[0]!.exposedAddresses).toBe(2 ** 31);
    expect(rep.rules[1]!.exposedAddresses).toBe(2 ** 31);
    expect(rep.rules[1]!.witness).toBe("128.0.0.0");
    expect(rep.swaps[0]!.changedAddresses).toBe(2 ** 31);
  });
});

describe("query resolution", () => {
  const rules = [
    rule("web", "allow", "10.0.0.0/24"),
    rule("api", "deny", "10.0.0.128/25"),
    rule("corp", "deny", "192.168.0.0/16"),
    rule("dead", "allow", "192.168.1.0/24"),
  ];

  it("returns the first matching rule and default deny otherwise", () => {
    const q = run(rules, ["10.0.0.5", "10.0.0.200", "192.168.1.1", "8.8.8.8", "10.0.0.128"]).queries;
    expect(q[0]).toMatchObject({ ruleId: "web", action: "allow", index: 0 });
    expect(q[1]).toMatchObject({ ruleId: "web", action: "allow", index: 0 }); // web precedes api
    expect(q[2]).toMatchObject({ ruleId: "corp", action: "deny", index: 2 }); // dead shadowed
    expect(q[3]).toMatchObject({ ruleId: null, action: "deny", index: null }); // default deny
    expect(q[4]).toMatchObject({ ruleId: "web", action: "allow" });
  });

  it("matches the default deny /0 explicitly too", () => {
    const q = run(
      [rule("all", "deny", "0.0.0.0/0")],
      ["8.8.8.8"],
    ).queries;
    expect(q[0]).toMatchObject({ ruleId: "all", action: "deny", index: 0 });
  });
});
