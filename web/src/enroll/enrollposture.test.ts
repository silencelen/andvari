import { describe, expect, it } from "vitest";
import { enrollPosture, escrowGate, normalizeShortFp } from "./enrollposture";

// design §F.1 — the fingerprint-provenance gate, pinned so a refactor can never let a server-sourced
// fingerprint become the escrow-seal anchor (reopening spec 05 T10) or seal escrow on a waived invite.
// Security review 2026-10, root cause A, A5: the in-person QR `rfp` is a FULL 64-hex machine value,
// compared at full length, and honoured only after the human typed the in-person code.

const SERVER_FULL_FP = "b26efdd3eafc9dad0011223344556677889900aabbccddeeff00112233445566"; // 64 hex
const RFP = SERVER_FULL_FP; // the in-person-QR rfp: the full fingerprint the admin's client stamped
const RFP16 = SERVER_FULL_FP.slice(0, 16); // the pre-A5 16-hex short id
const SHEET32 = SERVER_FULL_FP.slice(0, 32); // the 128-bit TYPED-sheet short form
const OTHER_FULL_FP = "f".repeat(64);

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
    expect(escrowGate({ posture: "waived", inPersonVerified: true, typedSheet: "", serverFullFp: SERVER_FULL_FP, pubFullFp: SERVER_FULL_FP })).toEqual({
      seal: false,
      anchor: "none",
    });
  });

  it("required-affirm seals ONLY on a FULL 64-hex match, after the in-person code, and anchors on the link rfp", () => {
    expect(escrowGate({ posture: "required-affirm", linkRfp: RFP, inPersonVerified: true, typedSheet: "", serverFullFp: SERVER_FULL_FP, pubFullFp: SERVER_FULL_FP })).toEqual({
      seal: true,
      anchor: "in-person-qr",
      verifiedFp: RFP,
    });
    // The server served a DIFFERENT key than the admin's link names → fail closed.
    expect(escrowGate({ posture: "required-affirm", linkRfp: RFP, inPersonVerified: true, typedSheet: "", serverFullFp: SERVER_FULL_FP, pubFullFp: OTHER_FULL_FP }).seal).toBe(false);
    // No in-person code typed (an emailed or forwarded link): never seal, whatever the link says.
    expect(escrowGate({ posture: "required-affirm", linkRfp: RFP, inPersonVerified: false, typedSheet: "", serverFullFp: SERVER_FULL_FP, pubFullFp: SERVER_FULL_FP }).seal).toBe(false);
    // Grouped or upper-cased: a machine value has no excuse to be reformatted.
    expect(escrowGate({ posture: "required-affirm", linkRfp: RFP.toUpperCase(), inPersonVerified: true, typedSheet: "", serverFullFp: SERVER_FULL_FP, pubFullFp: SERVER_FULL_FP }).seal).toBe(false);
  });

  // THE CARRY-FORWARD: the 16-hex (64-bit) prefix the pre-A5 gate accepted. The parameters below carry
  // BOTH the old (`pubShortFp`) and new (`pubFullFp`) shapes so this row runs unchanged against either
  // gate: the old gate sealed here, the new one must not.
  it("a 16-hex or 32-hex PREFIX rfp never seals (machine values compare at full length)", () => {
    for (const prefix of [RFP16, SERVER_FULL_FP.slice(0, 32)]) {
      const params = {
        posture: "required-affirm" as const,
        linkRfp: prefix,
        inPersonVerified: true,
        typedSheet: "",
        serverFullFp: SERVER_FULL_FP,
        pubFullFp: SERVER_FULL_FP,
        pubShortFp: RFP16,
      };
      expect(escrowGate(params).seal, `prefix ${prefix.length}`).toBe(false);
    }
  });

  it("required-typed seals ONLY when the TYPED sheet value matches, and anchors on the advertised fingerprint", () => {
    expect(escrowGate({ posture: "required-typed", inPersonVerified: false, typedSheet: SHEET32, serverFullFp: SERVER_FULL_FP, pubFullFp: SERVER_FULL_FP })).toEqual({
      seal: true,
      anchor: "typed-sheet",
      verifiedFp: SERVER_FULL_FP,
    });
    expect(escrowGate({ posture: "required-typed", inPersonVerified: false, typedSheet: RFP16, serverFullFp: SERVER_FULL_FP, pubFullFp: SERVER_FULL_FP }).seal).toBe(false);
    expect(escrowGate({ posture: "required-typed", inPersonVerified: false, typedSheet: "f".repeat(32), serverFullFp: SERVER_FULL_FP, pubFullFp: SERVER_FULL_FP }).seal).toBe(false);
    // The served key must hash to the advertised fingerprint in full.
    expect(escrowGate({ posture: "required-typed", inPersonVerified: false, typedSheet: SHEET32, serverFullFp: SERVER_FULL_FP, pubFullFp: OTHER_FULL_FP }).seal).toBe(false);
  });

  it("the seal anchor is never the served key's own fingerprint on the affirm path", () => {
    const g = escrowGate({ posture: "required-affirm", linkRfp: RFP, inPersonVerified: true, typedSheet: "", serverFullFp: OTHER_FULL_FP, pubFullFp: RFP });
    expect(g.verifiedFp).toBe(RFP); // the link value, which the served key had to equal
  });
});

describe("normalizeShortFp", () => {
  it("lowercases and drops non-hex separators", () => {
    expect(normalizeShortFp("B26E-FDD3 EAFC:9DAD")).toBe("b26efdd3eafc9dad");
  });
});
