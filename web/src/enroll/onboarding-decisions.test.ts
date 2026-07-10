import { describe, expect, it } from "vitest";
import { enrollPrefillFor, type EnrollPayload } from "./enrolllink";
import { shouldOfferQr, tryQrModules } from "../ui/Admin";

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
