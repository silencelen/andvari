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
