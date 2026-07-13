import { describe, expect, it } from "vitest";
import { enrollPosture, escrowGate, normalizeShortFp } from "./enrollposture";

// design §F.1 — the fingerprint-provenance gate, pinned so a refactor can never let a server-sourced
// fingerprint become the escrow-seal anchor (reopening spec 05 T10) or seal escrow on a waived invite.

const SERVER_FULL_FP = "b26efdd3eafc9dad0011223344556677889900aabbccddeeff00112233445566"; // 64 hex
const RFP = "b26efdd3eafc9dad"; // the org SHORT fingerprint (first 16 hex of SERVER_FULL_FP)

describe("enrollPosture — posture from (link rfp, member-has-sheet)", () => {
  it("an rfp on the link ⇒ required-affirm (in-person QR)", () => {
    expect(enrollPosture(RFP, false)).toBe("required-affirm");
    expect(enrollPosture(RFP, true)).toBe("required-affirm");
  });
  it("no rfp, no sheet ⇒ WAIVED (frictionless default, no fingerprint UI)", () => {
    expect(enrollPosture(undefined, false)).toBe("waived");
  });
  it("no rfp but the member has a printed sheet ⇒ required-typed (pre-rfp ceremony)", () => {
    expect(enrollPosture(undefined, true)).toBe("required-typed");
  });
});

describe("escrowGate — NEVER auto-trust a server-sourced fingerprint", () => {
  it("waived seals NOTHING (no org pubkey to substitute)", () => {
    expect(escrowGate({ posture: "waived", typedSheet: "", serverFullFp: SERVER_FULL_FP, pubShortFp: RFP })).toEqual({
      seal: false,
      anchor: "none",
    });
  });

  it("required-affirm seals ONLY when the scanned rfp matches the fetched pubkey's short fingerprint", () => {
    // Match: the QR value the admin showed == the key the server actually serves.
    expect(escrowGate({ posture: "required-affirm", linkRfp: RFP, typedSheet: "", serverFullFp: SERVER_FULL_FP, pubShortFp: RFP })).toEqual({
      seal: true,
      anchor: "in-person-qr",
    });
    // Mismatch (server served a DIFFERENT key than the admin showed) → fail closed.
    expect(escrowGate({ posture: "required-affirm", linkRfp: RFP, typedSheet: "", serverFullFp: SERVER_FULL_FP, pubShortFp: "0000000000000000" })).toEqual({
      seal: false,
      anchor: "none",
    });
    // A grouped/spaced rfp normalizes; a short/garbage rfp never seals.
    expect(escrowGate({ posture: "required-affirm", linkRfp: "b26e fdd3 eafc 9dad", typedSheet: "", serverFullFp: SERVER_FULL_FP, pubShortFp: RFP }).seal).toBe(true);
    expect(escrowGate({ posture: "required-affirm", linkRfp: "b26e", typedSheet: "", serverFullFp: SERVER_FULL_FP, pubShortFp: RFP }).seal).toBe(false);
  });

  it("required-typed seals ONLY when the TYPED sheet value matches the server's advertised fingerprint", () => {
    // The human typed the correct first-16 from the printed sheet → the anchor validates the server key.
    expect(escrowGate({ posture: "required-typed", typedSheet: RFP, serverFullFp: SERVER_FULL_FP, pubShortFp: RFP })).toEqual({
      seal: true,
      anchor: "typed-sheet",
    });
    // Wrong typed value → fail closed (never trust the server value on its own).
    expect(escrowGate({ posture: "required-typed", typedSheet: "ffffffffffffffff", serverFullFp: SERVER_FULL_FP, pubShortFp: RFP }).seal).toBe(false);
  });

  it("the anchor is never the raw server value on any seal path (no auto-trust)", () => {
    for (const g of [
      escrowGate({ posture: "waived", typedSheet: "", serverFullFp: SERVER_FULL_FP, pubShortFp: RFP }),
      escrowGate({ posture: "required-affirm", linkRfp: RFP, typedSheet: "", serverFullFp: SERVER_FULL_FP, pubShortFp: RFP }),
      escrowGate({ posture: "required-typed", typedSheet: RFP, serverFullFp: SERVER_FULL_FP, pubShortFp: RFP }),
    ]) {
      expect(["none", "in-person-qr", "typed-sheet"]).toContain(g.anchor);
    }
  });
});

describe("normalizeShortFp", () => {
  it("lowercases and drops non-hex separators", () => {
    expect(normalizeShortFp("B26E-FDD3 EAFC:9DAD")).toBe("b26efdd3eafc9dad");
  });
});
