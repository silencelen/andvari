import { beforeAll, describe, expect, it } from "vitest";
import { fingerprint, shortFingerprint, shortFormMatches } from "./escrow";
import { initSodium } from "./sodium";

/** spec 04 §2(3) — the enroll-time short-form fingerprint entry (INFO-2). */
describe("escrow fingerprint short-form entry", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const full = "e3c0418f1118705a" + "0".repeat(48); // 64 lowercase hex chars

  it("accepts grouped / spaced / uppercase sheet transcriptions", () => {
    expect(shortFormMatches("e3c0418f1118705a", full)).toBe(true);
    expect(shortFormMatches("e3c0 418f 1118 705a", full)).toBe(true);
    expect(shortFormMatches("E3C0-418F-1118-705A", full)).toBe(true);
    expect(shortFormMatches("  e3c0 418f 1118 705a  ", full)).toBe(true);
  });

  it("rejects wrong, short, long, and empty entries", () => {
    expect(shortFormMatches("e3c0418f1118705b", full)).toBe(false); // wrong last char
    expect(shortFormMatches("e3c0418f1118705", full)).toBe(false); // 15 chars
    expect(shortFormMatches("e3c0418f1118705a0", full)).toBe(false); // 17 chars
    expect(shortFormMatches("", full)).toBe(false);
    expect(shortFormMatches("zzzz zzzz zzzz zzzz", full)).toBe(false); // non-hex
  });

  it("shortFingerprint() is the first 16 chars of fingerprint() and passes the check", async () => {
    const pub = new Uint8Array(32).fill(7);
    const fp = await fingerprint(pub);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    expect(await shortFingerprint(pub)).toBe(fp.slice(0, 16));
    expect(shortFormMatches(await shortFingerprint(pub), fp)).toBe(true);
  });
});
