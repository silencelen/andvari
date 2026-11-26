import { PUBLIC_INSTANCE } from "./publicinstance.ts";

/**
 * A release fact the code depends on (design 2026-11-15-onboarding-trust §0.3, `spec/public-instance.json`): a store
 * build bakes the public instance's `instanceId` and `card0Hash`, which exist only once card 0 is signed at the
 * cut-over. While any baked value is still a `PLACEHOLDER:`, the "andvari" choice cannot pin anything (bakedRoot is
 * null) and a store build MUST refuse to ship.
 *
 * package.mjs (the release packaging step) refuses to package then. The check is not in verify.sh or `--check` on
 * purpose: until the cut-over the tree carries the placeholders, and that is only wrong once it is packaged for release.
 *
 * Returns why this tree cannot be released, or null.
 */
export function publicInstanceReleaseProblem(): string | null {
  const placeholders = Object.entries(PUBLIC_INSTANCE).filter(([, v]) => typeof v === "string" && v.startsWith("PLACEHOLDER:")).map(([k]) => k);
  if (placeholders.length === 0) return null;
  return (
    `the public instance's ${placeholders.join(" and ")} ${placeholders.length === 1 ? "is" : "are"} still a placeholder ` +
    "(src/publicinstance.ts, from spec/public-instance.json): a store build must not ship until card 0 is signed and recorded."
  );
}
