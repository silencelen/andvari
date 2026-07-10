/**
 * Semver-ish comparison for the extension's self-update check. Versions are the three-part
 * strings the ×3 drift-guard (package.mjs) keeps in lockstep across manifest.json /
 * manifest.firefox.json / package.json, e.g. "0.8.0".
 *
 * Deliberately conservative: ANY malformed input returns false, so a garbled, truncated, or
 * hostile /downloads/manifest.json can never nag the user to "update" to nonsense. Missing
 * trailing parts count as zero ("0.8" === "0.8.0"). This is the ONLY place the extension
 * decides "newer" — the SW records an update signal only when this returns true, and the
 * popup shows the banner only for a signal the SW re-validated through this same function.
 */
export function isNewerVersion(latest: string, current: string): boolean {
  const parse = (v: string): number[] | null => {
    if (typeof v !== "string") return null;
    const parts = v.trim().split(".");
    if (parts.length === 0 || parts.length > 4) return null; // guard pathological input
    const nums = parts.map((p) => (/^\d+$/.test(p) ? Number.parseInt(p, 10) : Number.NaN));
    return nums.some(Number.isNaN) ? null : nums;
  };
  const a = parse(latest);
  const b = parse(current);
  if (!a || !b) return false;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] ?? 0;
    const y = b[i] ?? 0;
    if (x !== y) return x > y;
  }
  return false;
}
