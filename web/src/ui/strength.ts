/** Rough entropy proxy — length + class diversity (not a substitute for a real estimator). */
export function estimateStrength(pw: string): number {
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^a-zA-Z0-9]/.test(pw)) classes++;
  const bits = pw.length * (classes <= 1 ? 2 : classes === 2 ? 3.5 : classes === 3 ? 5 : 6);
  if (bits < 40) return 0;
  if (bits < 60) return 1;
  if (bits < 80) return 2;
  if (bits < 110) return 3;
  return 4;
}

export const STRENGTH_LABELS = ["very weak", "weak", "fair", "good", "strong"] as const;

/**
 * F60 (spec 05 T8 / spec 01 §1): the master-password floor, enforced identically at
 * enrollment and every change (Welcome + Settings, incl. the forced-change path). The old
 * length≥8 gate let a weak all-lowercase password wrap the whole vault while backup exports
 * already demanded score≥3 — this makes the master password itself meet that bar BEFORE real
 * secrets migrate. A "good" score (≥3, ≥80 bits by estimateStrength) is the floor; the label
 * hint drives the UI. Non-ASCII is a SHOULD-warn only (§1): some platforms normalize/enter it
 * inconsistently, risking a password that won't round-trip — warn, never block.
 */
export const MASTER_PW_MIN_SCORE = 3;

export function meetsMasterPasswordFloor(pw: string): boolean {
  return estimateStrength(pw) >= MASTER_PW_MIN_SCORE;
}

/** True if the password contains any character outside printable 7-bit ASCII (§1 warn). */
export function masterPasswordHasNonAscii(pw: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /[^\x20-\x7e]/.test(pw);
}
