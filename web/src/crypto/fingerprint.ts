/**
 * The HUMAN short form of a fingerprint — shared by the recovery fingerprint (spec 04 §1) and the
 * identity fingerprint (spec 01 §5). Twin of core `Fingerprint.kt`.
 *
 * Security review 2026-10 (root cause A, §7): the short form a human READS or TYPES is the first
 * **32 lowercase hex = 128 bits**, not 16. A 64-bit (16-hex) prefix is a grindable truncated
 * second preimage; 128 bits is out of reach. The construction (`SHA-256(pub)`) is unchanged — only
 * the human-visible truncation length and the compare helper.
 *
 * A prefix (short) match is accepted ONLY from a human-typed entry ({@link matchesShort}). Machine
 * values (an in-person QR, a file, `Account.resealEscrowFor`) are compared at full 64-hex length by
 * their own callers, never through this helper.
 */

/** Human short-form length in hex chars (128 bits). */
export const SHORT_HEX_LEN = 32;

/** The short form: the first {@link SHORT_HEX_LEN} lowercase hex chars of a full fingerprint. */
export function shortForm(fullFingerprintHex: string): string {
  return fullFingerprintHex.toLowerCase().slice(0, SHORT_HEX_LEN);
}

/**
 * True iff a HUMAN-TYPED `entry` is the 32-hex short form of `fullFingerprintHex`. Spaces, dashes
 * and case are normalised away; after normalising it must be EXACTLY 32 hex digits and equal the
 * short form. The UI must not display the fingerprint before a correct entry.
 */
export function matchesShort(entry: string, fullFingerprintHex: string): boolean {
  const norm = entry.toLowerCase().replace(/[^0-9a-f]/g, "");
  return norm.length === SHORT_HEX_LEN && shortForm(fullFingerprintHex) === norm;
}

/**
 * Display grouping for the 32-hex short form: 8 groups of 4, split across two lines (4 groups per
 * line, joined by '\n'). Render with `white-space: pre-line` (or split on '\n').
 */
export function groupedShort(fullOrShortHex: string): string {
  const groups = (shortForm(fullOrShortHex).match(/.{1,4}/g) ?? []);
  return `${groups.slice(0, 4).join(" ")}\n${groups.slice(4).join(" ")}`;
}
