import { beforeAll, describe, expect, it } from "vitest";
import { fingerprint, shortFingerprint, shortFormMatches } from "./escrow";
import { initSodium } from "./sodium";

/** spec 04 §2(3) — the enroll-time short-form fingerprint entry (INFO-2). */
describe("escrow fingerprint short-form entry", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const full = "e3c0418f1118705a" + "0".repeat(48); // 64 lowercase hex chars
  const short32 = "e3c0418f1118705a" + "0".repeat(16); // the 128-bit short form (first 32)

  it("accepts grouped / spaced / uppercase sheet transcriptions (32 hex)", () => {
    expect(shortFormMatches(short32, full)).toBe(true);
    expect(shortFormMatches("e3c0 418f 1118 705a 0000 0000 0000 0000", full)).toBe(true);
    expect(shortFormMatches("E3C0-418F-1118-705A-0000-0000-0000-0000", full)).toBe(true);
    expect(shortFormMatches(`  ${short32}  `, full)).toBe(true);
  });

  it("rejects the old 16-hex (64-bit) prefix, plus wrong, short, long, and empty entries", () => {
    // The security review 2026-10 change: a 16-hex prefix that used to match is now REJECTED.
    expect(shortFormMatches("e3c0418f1118705a", full)).toBe(false); // 16-hex prefix no longer enough
    expect(shortFormMatches(short32.slice(0, 31) + "1", full)).toBe(false); // wrong last char
    expect(shortFormMatches(short32.slice(0, 31), full)).toBe(false); // 31 chars
    expect(shortFormMatches(short32 + "0", full)).toBe(false); // 33 chars
    expect(shortFormMatches("", full)).toBe(false);
    expect(shortFormMatches("z".repeat(32), full)).toBe(false); // non-hex
  });

  it("shortFingerprint() stays the machine 16-hex recovery id; the human short form is 32 hex", async () => {
    // Recovery short id (recovery-cli + the in-person-QR rfp machine path) stays 16 hex; the
    // HUMAN typed/read short form moved to 32 (`shortFormMatches`). They are now distinct lengths.
    const pub = new Uint8Array(32).fill(7);
    const fp = await fingerprint(pub);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    expect(await shortFingerprint(pub)).toBe(fp.slice(0, 16));
    expect(shortFormMatches(fp.slice(0, 32), fp)).toBe(true); // 32-hex human short form matches
    expect(shortFormMatches(await shortFingerprint(pub), fp)).toBe(false); // the 16-hex id is not the human short form
  });
});
