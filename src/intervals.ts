/**
 * Sparse sets of IPv4 addresses, represented as sorted arrays of disjoint
 * closed intervals [lo, hi]. This keeps every operation linear in the number
 * of distinct intervals instead of enumerating up to 2^32 addresses.
 */

import type { AddrRange, IP } from "./ip.js";

export type IntervalSet = readonly AddrRange[];

export const EMPTY: IntervalSet = [];

/** Merge a list of arbitrary intervals into sorted, disjoint, coalesced form. */
export function normalize(ranges: AddrRange[]): IntervalSet {
  return unionAll(
    ranges
      .filter((r) => r.lo <= r.hi)
      .map((r) => [r] as IntervalSet),
  );
}

/** Union of two sorted disjoint interval sets (adjacent intervals coalesce). */
export function union(a: IntervalSet, b: IntervalSet): IntervalSet {
  if (a.length === 0) return b;
  if (b.length === 0) return a;

  // Sorted merge of both streams, coalescing as we go.
  const merged: AddrRange[] = [];
  let i = 0;
  let j = 0;

  const push = (next: AddrRange) => {
    const last = merged.at(-1);
    if (last !== undefined && next.lo <= last.hi + 1) {
      if (next.hi > last.hi) last.hi = next.hi;
    } else {
      merged.push({ lo: next.lo, hi: next.hi });
    }
  };

  while (i < a.length || j < b.length) {
    const ai = a[i];
    const bj = b[j];
    if (bj === undefined || (ai !== undefined && ai.lo < bj.lo)) {
      push(ai!);
      i++;
    } else {
      push(bj);
      j++;
    }
  }
  return merged;
}

/** Intersection `a ∩ b` of two sorted disjoint interval sets. */
export function intersection(a: IntervalSet, b: IntervalSet): IntervalSet {
  if (a.length === 0 || b.length === 0) return EMPTY;
  const out: AddrRange[] = [];
  let i = 0;
  let j = 0;

  while (i < a.length && j < b.length) {
    const ai = a[i]!;
    const bj = b[j]!;
    const lo = Math.max(ai.lo, bj.lo);
    const hi = Math.min(ai.hi, bj.hi);
    if (lo <= hi) out.push({ lo, hi });
    if (ai.hi < bj.hi) i++;
    else j++;
  }
  return out;
}

/**
 * Set difference `a - b` for two sorted disjoint interval sets.
 * Returns a fresh sorted disjoint interval set.
 */
export function subtract(a: IntervalSet, b: IntervalSet): IntervalSet {
  if (a.length === 0 || b.length === 0) return a;
  const out: AddrRange[] = [];
  let j = 0;
  for (const interval of a) {
    // Skip cuts that lie entirely before this interval.
    while (j < b.length && b[j]!.hi < interval.lo) j++;
    let cursor = interval.lo;
    let k = j;
    while (k < b.length && b[k]!.lo <= interval.hi) {
      const cut = b[k]!;
      if (cut.lo > cursor) out.push({ lo: cursor, hi: cut.lo - 1 });
      if (cut.hi + 1 > cursor) cursor = cut.hi + 1;
      k++;
    }
    if (cursor <= interval.hi) out.push({ lo: cursor, hi: interval.hi });
  }
  return out;
}

/** Fold a new CIDR interval into the running covered set. */
export function addRange(set: IntervalSet, range: AddrRange): IntervalSet {
  return union(set, [range]);
}

/** Total address count of an interval set (safe: at most 2^32). */
export function countAddresses(set: IntervalSet): number {
  let total = 0;
  for (const { lo, hi } of set) {
    total += hi - lo + 1;
  }
  return total;
}

/** Smallest address in the set, or null when empty (used as the witness IP). */
export function minimumAddress(set: IntervalSet): IP | null {
  return set.length === 0 ? null : set[0]!.lo;
}

function unionAll(sets: IntervalSet[]): IntervalSet {
  let acc: IntervalSet = EMPTY;
  for (const set of sets) acc = union(acc, set);
  return acc;
}
