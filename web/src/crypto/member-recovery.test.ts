import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { adRecovery } from "./ad";
import { fromB64, fromUtf8, toB64 } from "./bytes";
import { sealWithNonce } from "./envelope";
import {
  confirmMatches,
  deriveAuthKey,
  displayForm,
  generate,
  openUvk,
  parseSecret,
  recoveryAuthKey,
  recoveryWrapKey,
} from "./member-recovery";
import { initSodium } from "./sodium";

/**
 * Consumes spec/test-vectors/member-recovery.json (design 2026-07-12 §F.6) — the SAME file the
 * Kotlin MemberRecoveryVectorTest checks. Deterministic inputs (fixed recoverySecret 00..1f + fixed
 * userId) pin the two HKDF outputs and — with a FIXED nonce, exactly as wrap.json/envelope.json do —
 * the exact `recoveryWrappedUvk` ciphertext. Keep the two implementations in lockstep off this file.
 */
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "member-recovery.json", "utf-8"));

beforeAll(async () => {
  await initSodium();
});

describe("member-recovery.json — HKDF derivations (byte-parity with core)", () => {
  it("splits the secret into the pinned wrap/auth keys", async () => {
    const secret = fromB64(v.recoverySecretB64);
    expect(toB64(await recoveryWrapKey(secret)), "recoveryWrapKey").toBe(v.recoveryWrapKeyB64);
    expect(toB64(await recoveryAuthKey(secret)), "recoveryAuthKey").toBe(v.recoveryAuthKeyB64);
    // deriveAuthKey emits the same value as base64url (the wire form the server verifies).
    expect(await deriveAuthKey(secret), "deriveAuthKey b64").toBe(v.recoveryAuthKeyB64);
    // The AD string is pinned so a twin can't drift the domain separation.
    expect(fromUtf8(adRecovery(v.userId)), "adRecovery").toBe(v.adUtf8);
  });
});

describe("member-recovery.json — wrappedUvk ciphertext + round trip", () => {
  it("reproduces the exact ciphertext under the pinned nonce and opens the SAME UVK", async () => {
    const secret = fromB64(v.recoverySecretB64);
    const wrapKey = await recoveryWrapKey(secret);
    // Exact ciphertext under the pinned nonce (fixed-nonce vector, same posture as wrap.json).
    expect(
      toB64(sealWithNonce(wrapKey, fromB64(v.nonceB64), fromB64(v.uvkB64), adRecovery(v.userId))),
      "recoveryWrappedUvk",
    ).toBe(v.recoveryWrappedUvkB64);
    // openUvk recovers the SAME UVK (covers the random-nonce production path too).
    expect(toB64(await openUvk(secret, v.recoveryWrappedUvkB64, v.userId)), "openUvk round-trip").toBe(v.uvkB64);
  });

  it("generate() produces a piece whose blob opens back to the UVK (nondeterministic nonce)", async () => {
    const uvk = fromB64(v.uvkB64);
    const piece = await generate(v.userId, uvk);
    expect(piece.recoverySecret.length).toBe(32);
    expect(piece.recoveryAuthKey).toBe(await deriveAuthKey(piece.recoverySecret));
    expect(toB64(await openUvk(piece.recoverySecret, piece.recoveryWrappedUvk, v.userId))).toBe(v.uvkB64);
  });
});

describe("member-recovery.json — fails closed + confirm-only", () => {
  it("a wrong secret fails the AEAD tag (availability denial, T1)", async () => {
    const wrong = new Uint8Array(32).map((_, i) => (i + 1) & 0xff); // 01 02 … not the pinned secret
    await expect(openUvk(wrong, v.recoveryWrappedUvkB64, v.userId)).rejects.toThrow();
  });

  it("confirmMatches is a byte-equal confirmation that tolerates display whitespace", () => {
    const secret = fromB64(v.recoverySecretB64);
    const shown = displayForm(secret);
    expect(shown).toBe(v.recoverySecretB64);
    // Verbatim and space-grouped both confirm; a single wrong char does not.
    expect(confirmMatches(secret, shown)).toBe(true);
    expect(confirmMatches(secret, shown.replace(/(.{4})/g, "$1 ").trim())).toBe(true);
    expect(confirmMatches(secret, shown.slice(0, -1) + (shown.endsWith("A") ? "B" : "A"))).toBe(false);
    // parseSecret is total: garbage → null, never a throw.
    expect(parseSecret("!!! not base64 !!!")).toBeNull();
  });
});
