import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { fromB64 } from "./bytes";
import { EscrowOpenError, fingerprint, openEscrow, sealUvkV2, UNANCHORED_ACK } from "./escrow";
import { boxKeypairFromSeed, sealOpen, signKeypairFromSeed } from "./provider";
import { CryptoError, initSodium } from "./sodium";

/**
 * Escrow v2 (security review 2026-10, root cause A §2; spec 04 §3–§4), graded off the SAME
 * spec/test-vectors/escrow-v2.json the Kotlin engine consumes (core EscrowV2VectorTest). The blobs come
 * from an independent oracle; every REJECTION row must fail closed with its exact verdict.
 */
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "escrow-v2.json", "utf-8"));

interface Row {
  name: string;
  sealedB64: string;
  expectedUserId: string;
  expectedIdentityFpPrefix: string | null;
  unanchoredAck?: string;
  identityCheck: { encryptedIdentitySeedB64: string; identityPubB64: string } | null;
  verdict?: string;
  expect?: { format: string; userId: string; uvkB64: string; identityKeyB64: string; anchored: boolean };
}

describe("escrow-v2.json", () => {
  beforeAll(async () => {
    await initSodium();
  });
  const org = () => boxKeypairFromSeed(fromB64(v.org.seedB64));
  const open = (c: Row) =>
    openEscrow({
      recoveryKeypair: org(),
      sealed: fromB64(c.sealedB64),
      expectedUserId: c.expectedUserId,
      expectedIdentityFpPrefix: c.expectedIdentityFpPrefix,
      identityCheck: c.identityCheck,
      unanchoredAcknowledgment: c.unanchoredAck ?? null,
    });

  it("fixed material matches the existing vectors", async () => {
    expect(UNANCHORED_ACK).toBe(v.unanchoredAck);
    expect(await fingerprint(org().publicKey)).toBe(v.org.fingerprint);
    expect(boxKeypairFromSeed(fromB64(v.member.identitySeedB64)).publicKey).toEqual(fromB64(v.member.identityPubB64));
    expect(await fingerprint(fromB64(v.member.identityPubB64))).toBe(v.member.identityFingerprint);
  });

  it("v2 layout: sealUvkV2 produces the pinned frame", async () => {
    const seed = fromB64(v.member.identitySeedB64);
    const sealed = await sealUvkV2({
      recoveryPub: org().publicKey, verifiedRecoveryFp: v.org.fingerprint, userId: v.member.userId,
      identityPub: fromB64(v.member.identityPubB64), signer: signKeypairFromSeed(seed), uvk: fromB64(v.member.uvkB64), issuedAt: Number(v.v2.issuedAt),
    });
    expect(sealed.length).toBe(v.v2.sealedLength);
    expect(sealOpen(org().publicKey, org().privateKey, sealed)).toEqual(fromB64(v.v2.frameB64));
    expect(sealOpen(org().publicKey, org().privateKey, fromB64(v.v2.sealedB64))).toEqual(fromB64(v.v2.frameB64));
  });

  it("seal refuses a fingerprint that is not a FULL match", async () => {
    const seed = fromB64(v.member.identitySeedB64);
    for (const c of v.sealRefuse) {
      await expect(
        sealUvkV2({
          recoveryPub: org().publicKey, verifiedRecoveryFp: c.verifiedRecoveryFp, userId: v.member.userId,
          identityPub: fromB64(v.member.identityPubB64), signer: signKeypairFromSeed(seed), uvk: fromB64(v.member.uvkB64), issuedAt: 1791590400000,
        }),
        c.name,
      ).rejects.toThrow(CryptoError);
    }
  });

  it("open: every row yields its exact result or verdict", async () => {
    const rows = v.open as Row[];
    expect(rows.filter((r) => r.verdict).length).toBeGreaterThanOrEqual(30);
    for (const c of rows) {
      if (c.verdict) {
        let verdict: string | null = null;
        try {
          await open(c);
        } catch (e) {
          if (!(e instanceof EscrowOpenError)) throw e;
          verdict = e.verdict;
        }
        expect(verdict, c.name).toBe(c.verdict);
      } else {
        const got = await open(c);
        expect(got.format, c.name).toBe(c.expect!.format);
        expect(got.userId, c.name).toBe(c.expect!.userId);
        expect(got.uvk, c.name).toEqual(fromB64(c.expect!.uvkB64));
        expect(got.identityKey, c.name).toEqual(fromB64(c.expect!.identityKeyB64));
        expect(got.anchored, c.name).toBe(c.expect!.anchored);
      }
    }
  });
});
