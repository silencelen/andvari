import { describe, expect, it } from "vitest";
import { enrollPrefillFor, type EnrollPayload } from "./enrolllink";
import {
  INVITE_TTL_DEFAULT,
  escrowPostureLabel,
  inviteResultView,
  inviteTtlMinutes,
  normalizeOrgFp,
  shouldOfferQr,
  stampedRfp,
  tryQrModules,
} from "../ui/Admin";

// The two client-side security gates of the S4 web slice, pinned as pure functions so a
// refactor that drops or inverts either trips a test instead of silently exposing it.

const payload: EnrollPayload = { v: 1, o: "https://vault.taila2dff2.ts.net", t: "invite-token-value", e: "a@x.com" };

describe("enrollPrefillFor — a link applies only to its exact minting origin", () => {
  it("returns the payload on an exact origin match", () => {
    expect(enrollPrefillFor(payload, "https://vault.taila2dff2.ts.net")).toBe(payload);
  });
  it("refuses a different host (origin substitution)", () => {
    expect(enrollPrefillFor(payload, "https://evil.example")).toBeNull();
  });
  it("refuses a scheme change (http vs https is a different origin)", () => {
    expect(enrollPrefillFor(payload, "http://vault.taila2dff2.ts.net")).toBeNull();
  });
  it("refuses a port change", () => {
    expect(enrollPrefillFor(payload, "https://vault.taila2dff2.ts.net:8443")).toBeNull();
  });
  it("is null when there is no captured link", () => {
    expect(enrollPrefillFor(null, "https://vault.taila2dff2.ts.net")).toBeNull();
  });
});

describe("shouldOfferQr — the public-origin containment", () => {
  it("offers the QR on tailnet and LAN origins", () => {
    expect(shouldOfferQr("https://vault.taila2dff2.ts.net")).toBe(true);
    expect(shouldOfferQr("http://192.168.2.122")).toBe(true);
    expect(shouldOfferQr("http://localhost:5173")).toBe(true);
  });
  it("refuses the public break-glass origin (a QR there dies at register)", () => {
    expect(shouldOfferQr("https://andvari.monahanhosting.com")).toBe(false);
  });
});

describe("tryQrModules — the encoder-overflow guard", () => {
  it("returns a non-empty module matrix for a realistic enroll link", () => {
    const m = tryQrModules("https://vault.taila2dff2.ts.net/enroll#a1.eyJ2IjoxLCJvIjoiaHR0cHMifQ");
    expect(Array.isArray(m)).toBe(true);
    expect((m as boolean[][]).length).toBeGreaterThan(0);
  });
  it("returns null instead of throwing when the payload overflows QR capacity", () => {
    // Far past byte-mode capacity at any version → the vendored encoder throws a bare string.
    expect(tryQrModules("x".repeat(4000))).toBeNull();
  });
});

describe("inviteTtlMinutes — the invite lifetime is admin-chosen, secure-by-default-SHORT", () => {
  it("maps each choice to minutes inside the server's [5, 4320] clamp", () => {
    for (const c of ["1h", "1d", "3d"] as const) {
      const m = inviteTtlMinutes(c);
      expect(m).toBeGreaterThanOrEqual(5);
      expect(m).toBeLessThanOrEqual(72 * 60);
    }
    expect(inviteTtlMinutes("1h")).toBe(60);
    expect(inviteTtlMinutes("1d")).toBe(1440);
    expect(inviteTtlMinutes("3d")).toBe(4320);
  });
  it("defaults to the SHORT 1-hour window (the token is a bearer credential; the TTL is the sole containment)", () => {
    expect(INVITE_TTL_DEFAULT).toBe("1h");
    expect(inviteTtlMinutes(INVITE_TTL_DEFAULT)).toBe(60);
  });
  it("fails SAFE to 60 min for an unknown option — a future <option> without a case must never mint at the server's 72h default", () => {
    expect(inviteTtlMinutes("1w" as never)).toBe(60);
  });
});

describe("inviteResultView — the public break-glass origin is ALWAYS token-only (BLOCKER 2)", () => {
  it("never shows a QR/link/compose-note affordance when qrAvailable is false", () => {
    // resultLink is null on the public origin too, so a bare !resultLink gate would paint a
    // false "couldn't encode a QR" here — the helper must key on qrAvailable first.
    expect(inviteResultView(false, false, false)).toBe("token-only");
    expect(inviteResultView(false, true, true)).toBe("token-only");
    expect(inviteResultView(false, true, false)).toBe("token-only");
  });
  it("on a private origin, picks qr / overflow-link / compose-note by what actually encoded", () => {
    expect(inviteResultView(true, true, true)).toBe("qr");
    expect(inviteResultView(true, true, false)).toBe("overflow-link");
    expect(inviteResultView(true, false, false)).toBe("compose-note");
    expect(inviteResultView(true, false, true)).toBe("compose-note"); // a null link dominates
  });
});

describe("stampedRfp — a QR stamps rfp ONLY from an admin-confirmed sheet, never a server fetch (§F.2)", () => {
  it("stamps the confirmed org fingerprint on a required invite", () => {
    expect(stampedRfp("required", "b26efdd3eafc9dad")).toBe("b26efdd3eafc9dad");
  });
  it("stamps NOTHING when the admin hasn't confirmed their sheet (invitee falls back to typing)", () => {
    expect(stampedRfp("required", null)).toBeUndefined();
  });
  it("never stamps rfp on a waived invite (no fingerprint anywhere)", () => {
    expect(stampedRfp("waived", "b26efdd3eafc9dad")).toBeUndefined();
    expect(stampedRfp("waived", null)).toBeUndefined();
  });
});

describe("normalizeOrgFp — a typed sheet fingerprint is 16 hex after normalization", () => {
  it("lowercases and drops separators", () => {
    expect(normalizeOrgFp("B26E-FDD3 EAFC:9DAD")).toBe("b26efdd3eafc9dad");
    expect(normalizeOrgFp("B26E FDD3 EAFC 9DAD").length).toBe(16);
  });
});

describe("escrowPostureLabel — a null fingerprint is not just '—' (§F.9 reconciliation, keyed on recoveryEnrolled)", () => {
  it("a present escrow fingerprint is an admin backstop — regardless of the member piece", () => {
    expect(escrowPostureLabel("b26efdd3eafc9dad00", true)).toEqual({ label: "admin backstop", tone: "good" });
    expect(escrowPostureLabel("b26efdd3eafc9dad00", false)).toEqual({ label: "admin backstop", tone: "good" });
  });
  it("no escrow but a member piece reads as waived-by-intent (the member holds their own recovery)", () => {
    expect(escrowPostureLabel(null, true)).toEqual({ label: "waived (intended)", tone: "muted" });
  });
  it("no escrow AND no member piece reads as no-recovery / needs-setup (genuinely at risk)", () => {
    expect(escrowPostureLabel(null, false)).toEqual({ label: "no recovery / needs setup", tone: "bad" });
    expect(escrowPostureLabel(null, undefined)).toEqual({ label: "no recovery / needs setup", tone: "bad" });
  });
  // §F.4 (2026-07-13): with the persisted escrowPolicy, a *required* member whose escrow blob is
  // missing is a hostile-flip / deletion anomaly, NOT a waiver — this is the silent-loss signal the
  // reconciliation exists to surface, so pin every arm (the branch previously claimed coverage it lacked).
  it("a required member with no backstop key on file is a flagged anomaly, not a waiver", () => {
    expect(escrowPostureLabel(null, true, "required")).toEqual({
      label: "backstop missing (was required)",
      tone: "bad",
      detail: "This member signed up with a required admin backstop, but no backstop key is on file — it may have been deleted. Only their own recovery phrase can rescue them now; investigate.",
    });
    expect(escrowPostureLabel(null, false, "required")).toEqual({
      label: "no recovery — backstop missing",
      tone: "bad",
      detail: "This member signed up with a required admin backstop, but no backstop key or recovery phrase is on file — investigate before they're locked out for good.",
    });
    expect(escrowPostureLabel(null, undefined, "required")).toEqual({
      label: "no recovery — backstop missing",
      tone: "bad",
      detail: "This member signed up with a required admin backstop, but no backstop key or recovery phrase is on file — investigate before they're locked out for good.",
    });
    // a present fingerprint still wins (backstop is there) even for a required member.
    expect(escrowPostureLabel("b26efdd3eafc9dad00", false, "required")).toEqual({ label: "admin backstop", tone: "good" });
  });
  it("escrowPolicy 'waived' or null (old server) degrades byte-identically to the legacy heuristic", () => {
    expect(escrowPostureLabel(null, true, "waived")).toEqual({ label: "waived (intended)", tone: "muted" });
    expect(escrowPostureLabel(null, true, null)).toEqual({ label: "waived (intended)", tone: "muted" });
    expect(escrowPostureLabel(null, false, "waived")).toEqual({ label: "no recovery / needs setup", tone: "bad" });
  });
});
