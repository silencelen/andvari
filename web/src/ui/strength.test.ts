import { describe, expect, it } from "vitest";
import {
  MASTER_PW_MIN_SCORE,
  estimateStrength,
  masterPasswordHasNonAscii,
  meetsMasterPasswordFloor,
} from "./strength";

/**
 * F60 (spec 05 T8 / spec 01 §1): the master-password floor that gates enrollment + every
 * password change (Welcome + Settings). Pinned so a future estimateStrength tweak can't
 * silently drop the vault-wrapping password below what a backup export already demands.
 */
describe("master-password floor (F60)", () => {
  it("the floor is score ≥ 3 (\"good\")", () => {
    expect(MASTER_PW_MIN_SCORE).toBe(3);
  });

  it("rejects the passwords the OLD length≥8 gate let through", () => {
    // 8+ chars but a single character class → weak; the whole point of F60.
    expect(meetsMasterPasswordFloor("password")).toBe(false);
    expect(meetsMasterPasswordFloor("aaaaaaaaaa")).toBe(false);
    expect(meetsMasterPasswordFloor("12345678")).toBe(false);
    // Short-but-mixed is still below the bit floor.
    expect(meetsMasterPasswordFloor("Ab3$")).toBe(false);
  });

  it("accepts genuinely strong passwords", () => {
    expect(meetsMasterPasswordFloor("correct-horse-battery-staple")).toBe(true);
    expect(meetsMasterPasswordFloor("Tr0ub4dor&3xtra-Length!!")).toBe(true);
    expect(meetsMasterPasswordFloor("a-fairly-long-diceware-style-phrase")).toBe(true);
  });

  it("agrees with estimateStrength at the boundary", () => {
    for (const pw of ["password", "Ab3$", "correct-horse-battery-staple", ""]) {
      expect(meetsMasterPasswordFloor(pw)).toBe(estimateStrength(pw) >= 3);
    }
  });

  it("empty never clears the floor (submit guards must still block it)", () => {
    expect(meetsMasterPasswordFloor("")).toBe(false);
  });

  it("flags non-ASCII (a SHOULD-warn, not a block)", () => {
    expect(masterPasswordHasNonAscii("plain-ascii-123")).toBe(false);
    expect(masterPasswordHasNonAscii("café-passphrase")).toBe(true); // é
    expect(masterPasswordHasNonAscii("naïve-☺-secret")).toBe(true);
    // The warn is independent of the floor — a strong non-ASCII password still passes.
    expect(meetsMasterPasswordFloor("café-très-long-passphrase-2024")).toBe(true);
  });
});
