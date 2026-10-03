import { describe, expect, it } from "vitest";
import { audit, ValidationError } from "../src/audit.js";

const allow = (id: string, cidr: string) => ({ id, action: "allow" as const, cidr });

describe("request validation", () => {
  it("accepts a minimal valid policy", () => {
    const report = audit({ rules: [allow("r1", "10.0.0.0/24")] });
    expect(report.rules).toHaveLength(1);
    expect(report.queries).toEqual([]);
  });

  it("requires a rules array of 1..300", () => {
    expect(() => audit({})).toThrow(ValidationError);
    expect(() => audit({ rules: [] })).toThrow(ValidationError);
    expect(() => audit({ rules: "nope" })).toThrow(ValidationError);
    expect(() => audit({ rules: Array.from({ length: 301 }, (_, i) => allow(`r${i}`, "0.0.0.0/32")) })).toThrow(
      /too many rules/,
    );
    expect(audit({ rules: Array.from({ length: 300 }, (_, i) => allow(`r${i}`, "0.0.0.0/32")) }).rules).toHaveLength(300);
  });

  it("rejects unknown fields at root and rule level", () => {
    expect(() => audit({ rules: [allow("r1", "10.0.0.0/24")], extra: 1 })).toThrow(/unknown field "extra"/);
    expect(() => audit({ rules: [{ ...allow("r1", "10.0.0.0/24"), priority: 5 }] })).toThrow(/unknown field "priority"/);
  });

  it("rejects duplicate, missing or non-string ids", () => {
    expect(() => audit({ rules: [allow("r1", "10.0.0.0/24"), allow("r1", "10.0.0.1/32")] })).toThrow(
      /duplicate rule id "r1"/,
    );
    expect(() => audit({ rules: [{ action: "allow", cidr: "10.0.0.0/24" }] })).toThrow(/id/);
    expect(() => audit({ rules: [{ id: "", action: "allow", cidr: "10.0.0.0/24" }] })).toThrow(/id/);
  });

  it("rejects unknown actions", () => {
    expect(() => audit({ rules: [{ id: "r1", action: "permit", cidr: "10.0.0.0/24" }] })).toThrow(/action/);
  });

  it("rejects non-canonical CIDRs and out-of-range octets", () => {
    expect(() => audit({ rules: [allow("r1", "10.0.0.1/24")] })).toThrow(/non-canonical/);
    expect(() => audit({ rules: [allow("r1", "999.0.0.0/8")] })).toThrow();
    expect(() => audit({ rules: [allow("r1", "10.0.0.0/40")] })).toThrow();
    expect(() => audit({ rules: [allow("r1", "10.0.0.0")] })).toThrow();
  });

  it("accepts up to 100 canonical queries and rejects bad ones", () => {
    const ok = Array.from({ length: 100 }, () => "0.0.0.0");
    expect(audit({ rules: [allow("r1", "0.0.0.0/0")], queries: ok }).queries).toHaveLength(100);
    expect(() => audit({ rules: [allow("r1", "0.0.0.0/0")], queries: Array(101).fill("0.0.0.0") })).toThrow(
      /too many queries/,
    );
    expect(() => audit({ rules: [allow("r1", "0.0.0.0/0")], queries: ["10.0.0.0/24"] })).toThrow();
    expect(() => audit({ rules: [allow("r1", "0.0.0.0/0")], queries: ["010.0.0.1"] })).toThrow();
  });

  it("rejects non-object bodies and non-object rule entries", () => {
    expect(() => audit(null)).toThrow(ValidationError);
    expect(() => audit([])).toThrow(ValidationError);
    expect(() => audit({ rules: [null] })).toThrow(ValidationError);
    expect(() => audit({ rules: ["allow 10.0.0.0/24"] })).toThrow(ValidationError);
  });
});
