// Registrable-domain (eTLD+1) resolution against the vendored PSL snapshot — TS mirror of
// core/.../client/autofill/Psl.kt (design docs/design/2026-07-10-etld1-psl-matching.md,
// spec 02 §3.1 amendment). All three impls run the SAME spec/test-vectors/urimatch-etld1.json.
//
// BUNDLE PLACEMENT (A8): this module is the ONLY importer of pslData (~144 KB). urimatch.ts
// takes the resolver as a parameter precisely so content-script bundles never pull the blob —
// keep it that way.

import { PSL_RULES_JOINED, PSL_SNAPSHOT_HASH } from "./pslData.ts"; // explicit .ts: node --test type-stripping needs it (web mirror stays extensionless)
import type { PslResolve, PslResult } from "./urimatch.ts";

export { PSL_SNAPSHOT_HASH };

let parsed: { exact: Set<string>; wildcards: Set<string>; exceptions: Set<string> } | null = null;

/** Rule sets parsed once per process. Wildcards stored as their base ("*.kawasaki.jp" →
 *  "kawasaki.jp"), exceptions minus the "!". */
function sets(): NonNullable<typeof parsed> {
  if (!parsed) {
    const exact = new Set<string>();
    const wildcards = new Set<string>();
    const exceptions = new Set<string>();
    for (const rule of PSL_RULES_JOINED.split("\n")) {
      if (!rule) continue;
      if (rule.startsWith("!")) exceptions.add(rule.slice(1));
      else if (rule.startsWith("*.")) wildcards.add(rule.slice(2));
      else exact.add(rule);
    }
    parsed = { exact, wildcards, exceptions };
  }
  return parsed;
}

/**
 * Resolve a NORMALIZED host (the caller runs normalizeHost first; this only self-guards).
 *
 * Three-state result (A1): "registrable" (positively known), "public-suffix" (the host IS a
 * public suffix — exact, wildcard-derived, or exception-derived alike), "unknown" (no
 * EXPLICIT rule matched — the PSL's implicit `*` fallback is deliberately NOT applied — or
 * non-ASCII / IP / unparseable input; matching degrades to the pre-eTLD+1 rules).
 *
 * Walk (A2, normative): candidate suffixes longest-first; per candidate test exception →
 * exact → wildcard; an exception sets suffixLen = candidateLabels − 1 and STOPS (never
 * overridden by its sibling wildcard); exact/wildcard set suffixLen = candidateLabels and
 * stop. Longest-first + stop-on-first makes the longest rule win by construction.
 */
export const pslResolve: PslResolve = (host: string): PslResult => {
  // eslint-disable-next-line no-control-regex
  // Self-guard (security review 2026-10): no DNS name exceeds 253 octets (normalizeHost already
  // refuses one); without it a planted many-label host made this walk O(labels²).
  if (!host || host.length > 253 || /[^\x00-\x7f]/.test(host) || host.includes(":")) return { kind: "unknown" };
  const labels = host.split(".");
  if (labels.some((l) => !l)) return { kind: "unknown" };
  if (labels.length === 4 && labels.every((l) => /^\d+$/.test(l))) return { kind: "unknown" }; // IPv4
  // Each candidate suffix is a slice of `host` from a label's start offset — no per-step join.
  const starts: number[] = [];
  for (let i = 0, off = 0; i < labels.length; off += labels[i]!.length + 1, i++) starts.push(off);
  const suffixFrom = (i: number): string => host.slice(starts[i]);
  const { exact, wildcards, exceptions } = sets();
  let suffixLen = 0;
  for (let i = 0; i < labels.length; i++) {
    const cand = suffixFrom(i);
    if (exceptions.has(cand)) {
      suffixLen = labels.length - i - 1;
      break;
    }
    if (exact.has(cand)) {
      suffixLen = labels.length - i;
      break;
    }
    if (labels.length - i >= 2 && wildcards.has(suffixFrom(i + 1))) {
      suffixLen = labels.length - i;
      break;
    }
  }
  if (suffixLen === 0) return { kind: "unknown" };
  if (suffixLen >= labels.length) return { kind: "public-suffix" };
  return { kind: "registrable", domain: suffixFrom(labels.length - suffixLen - 1) };
};
