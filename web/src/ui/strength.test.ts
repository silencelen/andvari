import { describe, expect, it } from "vitest";
import {
  MASTER_PW_MIN_SCORE,
  PATTERN_WARNING,
  entropyProxyScore,
  estimateStrength,
  hasPatternWeakness,
  masterPasswordHasNonAscii,
  meetsMasterPasswordFloor,
  patternWarning,
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

  it("gates on entropyProxyScore — F31's pattern penalty warns, it never refuses", () => {
    for (const pw of ["password", "Ab3$", "correct-horse-battery-staple", ""]) {
      expect(meetsMasterPasswordFloor(pw)).toBe(entropyProxyScore(pw) >= 3);
    }
    // The audit's two examples: both now SCORE lower, and both still clear the floor, because
    // no household member may be locked out of changing their password by a stricter estimator.
    for (const pw of ["Password1!Password1!", "a".repeat(40), "aA1!aA1!aA1!aA1!aA1!"]) {
      expect(estimateStrength(pw), pw).toBeLessThan(entropyProxyScore(pw));
      expect(meetsMasterPasswordFloor(pw), pw).toBe(true);
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

/**
 * F31: `length × classes` scored a doubled password as twice the entropy —
 * `Password1!Password1!` rendered as "strong" and a 40-character run of one letter cleared
 * both floors. Repeated blocks and ±1 runs now collapse before the length term. Kept in
 * lockstep with core Strength.kt (StrengthTest) and spec/test-vectors/strength.json.
 */
describe("pattern collapse (F31)", () => {
  it("charges a repeated block as the token plus one, not the whole span", () => {
    expect(estimateStrength("Password1!Password1!")).toBe(2);
    expect(entropyProxyScore("Password1!Password1!")).toBe(4); // what it used to score
    expect(estimateStrength("aA1!aA1!aA1!aA1!aA1!")).toBe(0);
    expect(estimateStrength("a".repeat(40))).toBe(0);
    // The smallest period wins: "abab…" collapses as "ab", never as "abab".
    expect(estimateStrength("ababababababababab")).toBe(estimateStrength("abababababab"));
  });

  it("charges an ascending/descending run as 2", () => {
    expect(estimateStrength("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm")).toBe(0);
    expect(estimateStrength("abcdefgh")).toBe(0);
  });

  it("leaves real passphrases and generated passwords alone", () => {
    for (const pw of [
      "correct horse battery staple",
      "correct-horse-battery-staple",
      "the quick brown fox jumps over the lazy dog 42 TIMES!",
      "Xk7#mQ2$vL9!pR4&",
      "Tr0ub4dor&3xtra-Length!!",
    ]) {
      expect(estimateStrength(pw), pw).toBe(entropyProxyScore(pw));
      expect(patternWarning(pw), pw).toBeNull();
    }
  });

  it("warns only when the pattern is what makes it weak", () => {
    expect(patternWarning("Password1!Password1!")).toBe(PATTERN_WARNING);
    expect(hasPatternWeakness("a".repeat(40))).toBe(true);
    expect(patternWarning("")).toBeNull();
    expect(hasPatternWeakness("")).toBe(false);
  });
});
