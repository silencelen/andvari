import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { AUTO_LOCK_MAX_SECONDS, CLIPBOARD_CLEAR_MAX_SECONDS } from "./api/types";

/**
 * Three-way byte-pin for the policy-timer clamp ceilings (design 2026-07-15-multi-tenant-endpoints
 * §2.3, breaker B1-1): core `ClientPolicyClamps` (Kotlin, the single source) ≡ web `api/types.ts`
 * ≡ extension `api.ts`. Same discipline as updateverify.test.ts (which regex-extracts the pinned
 * update keys from the Kotlin source) and extension-pins.test.ts (web vitest as the cross-suite pin
 * home): editing any one copy must break this file first, deliberately — bump all three together.
 * The core + extension copies are pinned by SOURCE TEXT (not imported) so this test adds no foreign
 * files to web's type program — extension/src compiles under a different lib/strictness set.
 *
 * The ceilings are CLIENT-FLOOR-ONLY security constants: a hostile server's 0/absent/oversized
 * timer clamps into range, so a server cannot disable auto-lock or pin the clipboard for hours.
 * A raise ships as a client build constant, never a server value (design §11.5).
 */

const read = (rel: string): string => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf-8");
const clampsKt = read("../../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/ClientPolicyClamps.kt");
const extApiTs = read("../../extension/src/api.ts");

const extract = (src: string, decl: RegExp, label: string): number => {
  const m = decl.exec(src);
  const lit = m?.[1];
  if (lit === undefined) throw new Error(`${label}: constant literal not found`);
  return Number(lit.replace(/_/g, ""));
};
const ktConst = (name: string): number => extract(clampsKt, new RegExp(`const val ${name}\\s*=\\s*([0-9_]+)`), `core ClientPolicyClamps.${name}`);
const extConst = (name: string): number => extract(extApiTs, new RegExp(`export const ${name}\\s*=\\s*([0-9_]+)`), `extension api.ts ${name}`);

describe("ClientPolicyClamps — core/web/ext byte-parity (§2.3)", () => {
  it("AUTO_LOCK_MAX_SECONDS is 900 in all three implementations", () => {
    expect(ktConst("AUTO_LOCK_MAX_SECONDS")).toBe(900);
    expect(AUTO_LOCK_MAX_SECONDS).toBe(900);
    expect(extConst("AUTO_LOCK_MAX_SECONDS")).toBe(900);
  });

  it("CLIPBOARD_CLEAR_MAX_SECONDS is 300 in all three implementations", () => {
    expect(ktConst("CLIPBOARD_CLEAR_MAX_SECONDS")).toBe(300);
    expect(CLIPBOARD_CLEAR_MAX_SECONDS).toBe(300);
    expect(extConst("CLIPBOARD_CLEAR_MAX_SECONDS")).toBe(300);
  });

  it("ceilings admit the shipped wire defaults (a default policy is never clamped down)", () => {
    // Wire defaults: autoLockSeconds=300, clipboardClearSeconds=30 (core Wire.kt ClientPolicy).
    expect(AUTO_LOCK_MAX_SECONDS).toBeGreaterThanOrEqual(300);
    expect(CLIPBOARD_CLEAR_MAX_SECONDS).toBeGreaterThanOrEqual(30);
  });
});
