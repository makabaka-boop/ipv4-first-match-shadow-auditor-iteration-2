/**
 * First-match firewall policy auditor.
 *
 * For an ordered rule list [r0, r1, ...] the decision for an address is
 * determined by the first rule whose CIDR contains it; with no match the
 * default decision is "deny".
 *
 * Rather than enumerate the IPv4 space, address sets are tracked as sorted
 * disjoint interval lists (see intervals.ts). This makes per-rule residual
 * coverage and adjacent-swap impact cheap and exact.
 */

import {
  cidrRange,
  cidrSize,
  formatIp,
  parseCidr,
  parseIp,
  type Cidr,
  type IP,
} from "./ip.js";
import {
  addRange,
  countAddresses,
  minimumAddress,
  subtract,
  union,
  EMPTY,
  type IntervalSet,
} from "./intervals.js";

export type Action = "allow" | "deny";

export type RuleStatus = "active" | "partial" | "shadowed";

export interface RuleInput {
  id: string;
  action: Action;
  cidr: string;
}

export interface CoverageCertificateStep {
  ruleId: string;
  /** First address this rule adds to the certificate, as an IPv4 address. */
  startAddress: string;
  /** Last address this rule adds to the certificate, as an IPv4 address. */
  endAddress: string;
}

export interface CoverageCertificate {
  /** Rule ids selected by the left-to-right greedy proof. */
  ruleIds: string[];
  /**
   * Closed intervals newly contributed at each greedy step. Their union is
   * exactly the shadowed rule's CIDR, and each interval is covered by its
   * corresponding earlier rule.
   */
  steps: CoverageCertificateStep[];
}

export interface RuleAudit {
  id: string;
  action: Action;
  cidr: string;
  index: number;
  /** Addresses of this CIDR matched by no earlier rule. */
  exposedAddresses: number;
  /** Total addresses in this CIDR. */
  totalAddresses: number;
  /** Smallest address the rule still decides (null when fully shadowed). */
  witness: string | null;
  status: RuleStatus;
  /** Minimal proof from earlier rules; present only for shadowed rules. */
  coverageCertificate?: CoverageCertificate;
}

export interface SwapAudit {
  /** Rule indices whose order is swapped (adjacent pair). */
  indices: [number, number];
  ids: [string, string];
  actions: [Action, Action];
  /**
   * Addresses whose allow/deny decision changes after swapping the two
   * adjacent rules. Rules before/after the pair keep their priority, so only
   * addresses both rules cover and no earlier rule covers can be affected.
   */
  changedAddresses: number;
  /** Smallest affected address (null when nothing changes). */
  witness: string | null;
}

export interface QueryResult {
  query: string;
  /** First matching rule, or null when nothing matches (default deny). */
  ruleId: string | null;
  action: Action; // "deny" when ruleId is null
  index: number | null;
}

/** First-match evidence for one address under a given rule list. */
export interface FirstMatchEvidence {
  /** Matching rule id, or null when the default action decides. */
  ruleId: string | null;
  /** Index of the matching rule in the evaluated list, or null for the default. */
  index: number | null;
  action: Action; // "deny" when ruleId is null
}

/** One closed interval of addresses whose decision flips after insertion. */
export interface ChangedInterval {
  startAddress: string;
  endAddress: string;
}

export interface InsertionProbeReport {
  address: string;
  expect: Action;
  /** First match under the original rule list. */
  before: FirstMatchEvidence;
  /** First match with the new rule inserted at the selected position. */
  after: FirstMatchEvidence;
  /** Whether the post-insertion decision equals the expected one. */
  satisfied: boolean;
}

export interface InsertionProtectedReport {
  address: string;
  before: FirstMatchEvidence;
  after: FirstMatchEvidence;
  /** Whether the insertion kept this address's original decision. */
  preserved: boolean;
}

/** The selected insertion plan; computed with interval algebra only. */
export interface InsertionPlan {
  /** Index the new rule would occupy (0 = before all, ruleCount = after all). */
  position: number;
  /** Addresses in the whole IPv4 space whose allow/deny decision flips. */
  changedAddresses: number;
  /** Sorted, non-overlapping closed intervals covering exactly those addresses. */
  changedIntervals: ChangedInterval[];
  probes: InsertionProbeReport[];
  protected: InsertionProtectedReport[];
}

export type InsertionReport =
  | ({ rule: RuleInput; feasible: true } & InsertionPlan)
  | { rule: RuleInput; feasible: false; reason: string };

export interface AuditReport {
  rules: RuleAudit[];
  swaps: SwapAudit[];
  queries: QueryResult[];
  summary: {
    ruleCount: number;
    queryCount: number;
    shadowedCount: number;
    defaultAction: Action;
  };
  /** Read-only insertion plan; present only when the request carries one. */
  insertion?: InsertionReport;
}

/** Validation failure carrying a JSON-pointer-ish path for the CLI/server. */
export class ValidationError extends Error {
  readonly path: string;
  constructor(message: string, path = "$") {
    super(`${path}: ${message}`);
    this.name = "ValidationError";
    this.path = path;
  }
}

const ROOT_FIELDS = new Set(["rules", "queries", "insertion"]);
const RULE_FIELDS = new Set(["id", "action", "cidr"]);
const INSERTION_FIELDS = new Set(["rule", "probes", "protected"]);
const PROBE_FIELDS = new Set(["address", "expect"]);
const MAX_RULES = 300;
const MAX_QUERIES = 100;
const MAX_PROBES = 100;
const MAX_PROTECTED = 100;

const knownObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function rejectUnknownFields(
  obj: Record<string, unknown>,
  known: Set<string>,
  path: string,
): void {
  for (const key of Object.keys(obj)) {
    if (!known.has(key)) {
      throw new ValidationError(`unknown field "${key}"`, path);
    }
  }
}

interface ParsedRule {
  input: RuleInput;
  cidr: Cidr;
}

/** Validate one rule object (shared by the rules array and insertion.rule). */
function parseRuleObject(raw: unknown, path: string): ParsedRule {
  if (!knownObject(raw)) {
    throw new ValidationError("rule must be an object", path);
  }
  rejectUnknownFields(raw, RULE_FIELDS, path);

  const { id, action, cidr } = raw;
  if (typeof id !== "string" || id.length === 0) {
    throw new ValidationError("id must be a non-empty string", `${path}.id`);
  }
  if (action !== "allow" && action !== "deny") {
    throw new ValidationError(
      'action must be "allow" or "deny"',
      `${path}.action`,
    );
  }
  if (typeof cidr !== "string") {
    throw new ValidationError("cidr must be a string", `${path}.cidr`);
  }

  let parsedCidr: Cidr;
  try {
    parsedCidr = parseCidr(cidr);
  } catch (err) {
    throw new ValidationError((err as Error).message, `${path}.cidr`);
  }

  return { input: { id, action, cidr }, cidr: parsedCidr };
}

function parseRules(value: unknown): ParsedRule[] {
  if (!Array.isArray(value)) {
    throw new ValidationError("rules must be an array", "$.rules");
  }
  if (value.length < 1) {
    throw new ValidationError("at least one rule is required", "$.rules");
  }
  if (value.length > MAX_RULES) {
    throw new ValidationError(
      `too many rules: ${value.length} > ${MAX_RULES}`,
      "$.rules",
    );
  }

  const rules: ParsedRule[] = [];
  const seenIds = new Set<string>();
  value.forEach((raw, i) => {
    const path = `$.rules[${i}]`;
    const rule = parseRuleObject(raw, path);
    if (seenIds.has(rule.input.id)) {
      throw new ValidationError(
        `duplicate rule id "${rule.input.id}"`,
        `${path}.id`,
      );
    }
    seenIds.add(rule.input.id);
    rules.push(rule);
  });
  return rules;
}

function parseQueries(value: unknown): number[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ValidationError("queries must be an array", "$.queries");
  }
  if (value.length > MAX_QUERIES) {
    throw new ValidationError(
      `too many queries: ${value.length} > ${MAX_QUERIES}`,
      "$.queries",
    );
  }
  return value.map((raw, i) => {
    const path = `$.queries[${i}]`;
    try {
      return parseIp(raw);
    } catch (err) {
      throw new ValidationError((err as Error).message, path);
    }
  });
}

interface ParsedProbe {
  address: string;
  expect: Action;
  ip: IP;
}

interface ParsedProtected {
  address: string;
  ip: IP;
}

interface ParsedInsertion {
  rule: ParsedRule;
  probes: ParsedProbe[];
  protectedAddresses: ParsedProtected[];
}

function parseProbes(value: unknown): ParsedProbe[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ValidationError("probes must be an array", "$.insertion.probes");
  }
  if (value.length > MAX_PROBES) {
    throw new ValidationError(
      `too many probes: ${value.length} > ${MAX_PROBES}`,
      "$.insertion.probes",
    );
  }
  return value.map((raw, i) => {
    const path = `$.insertion.probes[${i}]`;
    if (!knownObject(raw)) {
      throw new ValidationError("probe must be an object", path);
    }
    rejectUnknownFields(raw, PROBE_FIELDS, path);
    const { address, expect } = raw;
    let ip: IP;
    try {
      ip = parseIp(address);
    } catch (err) {
      throw new ValidationError((err as Error).message, `${path}.address`);
    }
    if (expect !== "allow" && expect !== "deny") {
      throw new ValidationError(
        'expect must be "allow" or "deny"',
        `${path}.expect`,
      );
    }
    return { address: address as string, expect, ip };
  });
}

function parseProtected(value: unknown): ParsedProtected[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ValidationError(
      "protected must be an array",
      "$.insertion.protected",
    );
  }
  if (value.length > MAX_PROTECTED) {
    throw new ValidationError(
      `too many protected addresses: ${value.length} > ${MAX_PROTECTED}`,
      "$.insertion.protected",
    );
  }
  return value.map((raw, i) => {
    const path = `$.insertion.protected[${i}]`;
    try {
      return { address: raw as string, ip: parseIp(raw) };
    } catch (err) {
      throw new ValidationError((err as Error).message, path);
    }
  });
}

function parseInsertion(value: unknown, existingIds: Set<string>): ParsedInsertion {
  if (!knownObject(value)) {
    throw new ValidationError("insertion must be an object", "$.insertion");
  }
  rejectUnknownFields(value, INSERTION_FIELDS, "$.insertion");
  if (!("rule" in value)) {
    throw new ValidationError("missing required field rule", "$.insertion.rule");
  }
  const rule = parseRuleObject(value.rule, "$.insertion.rule");
  if (existingIds.has(rule.input.id)) {
    throw new ValidationError(
      `duplicate rule id "${rule.input.id}"`,
      "$.insertion.rule.id",
    );
  }
  return {
    rule,
    probes: parseProbes(value.probes),
    protectedAddresses: parseProtected(value.protected),
  };
}

/** Parse and validate the raw JSON request body. */
export function parseRequest(raw: unknown): {
  rules: ParsedRule[];
  queries: number[];
  rawQueries: unknown[];
  insertion: ParsedInsertion | null;
} {
  if (!knownObject(raw)) {
    throw new ValidationError("request body must be a JSON object");
  }
  rejectUnknownFields(raw, ROOT_FIELDS, "$");
  if (!("rules" in raw)) {
    throw new ValidationError("missing required field rules", "$.rules");
  }
  const rules = parseRules(raw.rules);
  const queryIps = parseQueries(raw.queries);
  const insertion =
    raw.insertion === undefined
      ? null
      : parseInsertion(
          raw.insertion,
          new Set(rules.map((r) => r.input.id)),
        );
  return {
    rules,
    queries: queryIps,
    rawQueries: raw.queries === undefined ? [] : (raw.queries as unknown[]),
    insertion,
  };
}

const statusFor = (
  exposed: IntervalSet,
  totalAddresses: number,
): RuleStatus => {
  if (exposed.length === 0) return "shadowed";
  if (countAddresses(exposed) === totalAddresses) return "active";
  return "partial";
};

/** First matching rule for an address, or the default deny when none matches. */
function firstMatch(rules: ParsedRule[], ip: IP): FirstMatchEvidence {
  for (let i = 0; i < rules.length; i++) {
    const { cidr, input } = rules[i]!;
    if (ip >= cidr.lo && ip <= cidr.hi) {
      return { ruleId: input.id, index: i, action: input.action };
    }
  }
  return { ruleId: null, index: null, action: "deny" };
}

/**
 * Build a minimum-size certificate that a target CIDR is covered by earlier
 * rules. Since the target is one contiguous integer interval, choose at each
 * uncovered cursor an earlier interval containing it whose right end reaches
 * farthest; ties keep the earlier rule index. This is the standard interval
 * stabbing greedy proof, so the number of selected rules is minimum.
 */
function coverageCertificate(
  previousRules: ParsedRule[],
  target: Cidr,
): CoverageCertificate {
  const ruleIds: string[] = [];
  const steps: CoverageCertificateStep[] = [];
  let cursor = target.lo;

  while (cursor <= target.hi) {
    let bestIndex: number | null = null;
    let bestHi = cursor;

    for (let j = 0; j < previousRules.length; j++) {
      const range = previousRules[j]!.cidr;
      if (range.lo > cursor || range.hi < cursor) continue;
      const candidateHi = Math.min(range.hi, target.hi);
      if (bestIndex === null || candidateHi > bestHi) {
        bestIndex = j;
        bestHi = candidateHi;
      }
    }

    // audit() only calls this after proving the target is fully shadowed.
    if (bestIndex === null) {
      throw new Error("internal error: incomplete shadowing certificate");
    }

    const selected = previousRules[bestIndex]!;
    ruleIds.push(selected.input.id);
    steps.push({
      ruleId: selected.input.id,
      startAddress: formatIp(cursor),
      endAddress: formatIp(bestHi),
    });

    // Deliberately no unsigned wrap: after 255.255.255.255 this is 2^32 and
    // the loop exits, avoiding 255.255.255.255 + 1 wrapping back to zero.
    cursor = bestHi + 1;
  }

  return { ruleIds, steps };
}

/**
 * Plan where to insert one new rule without touching the audited policy.
 *
 * Inserting at position p keeps rules 0..p-1 ahead of the new rule, so the
 * only addresses whose decision can flip are those the new rule covers and no
 * earlier rule decides: residual(p) = newRange − covered(0..p-1). On residual
 * the new rule decides everything with its own action, hence
 *
 *   changed(p) = residual(p) ∩ { addresses whose original decision ≠ newAction }
 *
 * The original-decision sets come from the same first-match exposed intervals
 * as the audit (the deny set is the complement of the allow set, which also
 * captures the default-deny region), so no address is ever enumerated and a
 * first-match change that keeps the same action is not counted.
 *
 * A position is feasible when every probe reaches its expected decision and
 * every protected address keeps its original one. Among feasible positions
 * the plan minimizes |changed(p)|; ties keep the earliest position.
 */
function planInsertion(
  rules: ParsedRule[],
  insertion: ParsedInsertion,
): InsertionReport {
  const n = rules.length;
  const newRule = insertion.rule;
  const newRange = cidrRange(newRule.cidr);
  const newAction = newRule.input.action;

  // coveredPrefix[p] = addresses decided by original rules 0..p-1.
  const coveredPrefix: IntervalSet[] = [EMPTY];
  for (let i = 0; i < n; i++) {
    coveredPrefix.push(addRange(coveredPrefix[i]!, cidrRange(rules[i]!.cidr)));
  }

  // Addresses whose original decision is "allow": the union of what each
  // allow rule actually decides. Everything else is deny (rules or default).
  let allowSet: IntervalSet = EMPTY;
  for (let i = 0; i < n; i++) {
    if (rules[i]!.input.action === "allow") {
      const exposed = subtract([cidrRange(rules[i]!.cidr)], coveredPrefix[i]!);
      allowSet = union(allowSet, exposed);
    }
  }
  // Addresses that already have the new rule's action never flip.
  const keepSet = newAction === "allow"
    ? allowSet
    : subtract([{ lo: 0, hi: 0xffffffff }], allowSet);

  // First-match facts for every constrained address, computed once.
  interface AddressFacts {
    before: FirstMatchEvidence;
    /** Index of the first matching original rule; n when the default decides. */
    firstIndex: number;
    coveredByNew: boolean;
  }
  const factsFor = (ip: IP): AddressFacts => {
    const before = firstMatch(rules, ip);
    return {
      before,
      firstIndex: before.index ?? n,
      coveredByNew: ip >= newRange.lo && ip <= newRange.hi,
    };
  };
  const probeFacts = insertion.probes.map((probe) => ({
    ...probe,
    ...factsFor(probe.ip),
  }));
  const protectedFacts = insertion.protectedAddresses.map((entry) => ({
    ...entry,
    ...factsFor(entry.ip),
  }));

  // Decision for an address after inserting at p: the new rule decides iff it
  // covers the address and no original rule before p does.
  const decisionAfter = (f: AddressFacts, p: number): Action =>
    f.coveredByNew && f.firstIndex >= p ? newAction : f.before.action;

  const evidenceAfter = (f: AddressFacts, p: number): FirstMatchEvidence => {
    if (f.coveredByNew && f.firstIndex >= p) {
      return { ruleId: newRule.input.id, index: p, action: newAction };
    }
    // Rules at or after the insertion point shift one index down.
    return f.firstIndex < n && f.firstIndex >= p
      ? { ...f.before, index: f.firstIndex + 1 }
      : f.before;
  };

  let best: {
    position: number;
    changedAddresses: number;
    changed: IntervalSet;
  } | null = null;

  for (let p = 0; p <= n; p++) {
    const feasible =
      probeFacts.every((f) => decisionAfter(f, p) === f.expect) &&
      protectedFacts.every((f) => decisionAfter(f, p) === f.before.action);
    if (!feasible) continue;

    const residual = subtract([newRange], coveredPrefix[p]!);
    const changed = subtract(residual, keepSet);
    const changedAddresses = countAddresses(changed);
    if (best === null || changedAddresses < best.changedAddresses) {
      best = { position: p, changedAddresses, changed };
    }
  }

  if (best === null) {
    return {
      rule: newRule.input,
      feasible: false,
      reason:
        "no insertion position satisfies every probe expectation and every protected address",
    };
  }

  const p = best.position;
  return {
    rule: newRule.input,
    feasible: true,
    position: p,
    changedAddresses: best.changedAddresses,
    changedIntervals: best.changed.map((r) => ({
      startAddress: formatIp(r.lo),
      endAddress: formatIp(r.hi),
    })),
    probes: probeFacts.map((f) => {
      const after = evidenceAfter(f, p);
      return {
        address: f.address,
        expect: f.expect,
        before: f.before,
        after,
        satisfied: after.action === f.expect,
      };
    }),
    protected: protectedFacts.map((f) => {
      const after = evidenceAfter(f, p);
      return {
        address: f.address,
        before: f.before,
        after,
        preserved: after.action === f.before.action,
      };
    }),
  };
}

/** Run the full audit over parsed input. */
export function audit(raw: unknown): AuditReport {
  const { rules, queries, rawQueries, insertion } = parseRequest(raw);

  // Per-rule residual analysis. `covered` = addresses decided by rules 0..i-1.
  const coveredBefore: IntervalSet[] = [];
  const exposedSets: IntervalSet[] = [];
  let covered: IntervalSet = EMPTY;

  const ruleReports: RuleAudit[] = rules.map(({ input, cidr }, i) => {
    coveredBefore.push(covered);
    const total = cidrSize(cidr.prefix);
    const exposed = subtract([cidrRange(cidr)], covered);
    exposedSets.push(exposed);
    const exposedCount = countAddresses(exposed);
    const witnessIp = minimumAddress(exposed);
    const status = statusFor(exposed, total);
    covered = addRange(covered, cidrRange(cidr));

    return {
      id: input.id,
      action: input.action,
      cidr: input.cidr,
      index: i,
      exposedAddresses: exposedCount,
      totalAddresses: total,
      witness: witnessIp === null ? null : formatIp(witnessIp),
      status,
      ...(status === "shadowed"
        ? { coverageCertificate: coverageCertificate(rules.slice(0, i), cidr) }
        : {}),
    };
  });

  // Adjacent swap analysis.
  const swapReports: SwapAudit[] = [];
  for (let i = 0; i + 1 < rules.length; i++) {
    const a = rules[i]!;
    const b = rules[i + 1]!;
    const beforeSet = coveredBefore[i]!;

    // After a swap, addresses covered by exactly one of the pair are still
    // decided by that same rule — only the mutual intersection can flip, and
    // only when the actions differ. Earlier rules shadow the pair there too.
    let changed: IntervalSet = EMPTY;
    if (a.input.action !== b.input.action) {
      const lo = Math.max(a.cidr.lo, b.cidr.lo);
      const hi = Math.min(a.cidr.hi, b.cidr.hi);
      const intersection: IntervalSet = lo <= hi ? [{ lo, hi }] : EMPTY;
      changed = subtract(intersection, beforeSet);
    }

    const witnessIp = minimumAddress(changed);
    swapReports.push({
      indices: [i, i + 1],
      ids: [a.input.id, b.input.id],
      actions: [a.input.action, b.input.action],
      changedAddresses: countAddresses(changed),
      witness: witnessIp === null ? null : formatIp(witnessIp),
    });
  }

  // Query resolution: first matching rule wins, otherwise default deny.
  const queryReports: QueryResult[] = queries.map((ip, i) => ({
    query: String(rawQueries[i]),
    ...firstMatch(rules, ip),
  }));

  return {
    rules: ruleReports,
    swaps: swapReports,
    queries: queryReports,
    summary: {
      ruleCount: rules.length,
      queryCount: queries.length,
      shadowedCount: ruleReports.filter((r) => r.status === "shadowed").length,
      defaultAction: "deny",
    },
    ...(insertion === null ? {} : { insertion: planInsertion(rules, insertion) }),
  };
}
