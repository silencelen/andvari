import { beforeAll, describe, expect, it } from "vitest";
import type { AccountKeys } from "../api/types";
import { adIdkey, adUvk } from "../crypto/ad";
import { fromB64, toB64 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { EscrowOpenError, fingerprint, openEscrow, sealUvkV1 } from "../crypto/escrow";
import { masterKey, wrapKey, type KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { identityFingerprint } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account, IdentityMismatchError } from "./account";
import { loadSelfIdentityPub, recordSelfIdentityPub } from "./selfidentity";

/**
 * Escrow v1 → v2 migration (security review 2026-10, root cause A §8.4) and the recovered-member
 * backstop (§2.4) — web twin of core EscrowMigrationTest.
 */
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const PASSWORD = "correct horse battery staple";

async function legacyMember(orgPub: Uint8Array) {
  const r = await Account.enroll({ inviteToken: "inv", email: "m@x.com", displayName: "m", password: PASSWORD, kdfParams: KDF });
  const keys: AccountKeys = {
    kdfSalt: r.request.kdfSalt, kdfParams: r.request.kdfParams, wrappedUvk: r.request.wrappedUvk,
    encryptedIdentitySeed: r.request.encryptedIdentitySeed, identityPub: r.request.identityPub, escrowFingerprint: "",
  };
  return { r, keys };
}

describe("escrow v2 migration + backstop", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a new enrolment seals escrow v2", async () => {
    const org = boxKeypairFromSeed(randomBytes(32));
    const fp = await fingerprint(org.publicKey);
    const r = await Account.enroll({ inviteToken: "inv", email: "a@x.com", displayName: "a", password: PASSWORD, kdfParams: KDF, recoveryPublicKey: org.publicKey, recoveryFingerprint: fp });
    const opened = await openEscrow({
      recoveryKeypair: org, sealed: fromB64(r.request.escrow!.sealed), expectedUserId: r.request.userId,
      expectedIdentityFpPrefix: (await identityFingerprint(r.account.identityPub)).slice(0, 32),
      identityCheck: { encryptedIdentitySeedB64: r.request.encryptedIdentitySeed, identityPubB64: r.request.identityPub },
    });
    expect(opened.format).toBe("v2");
    expect(opened.anchored).toBe(true);
  });

  it("a v1 member re-seals to v2 and stays recoverable, and the retained v1 blob still recovers", async () => {
    const org = boxKeypairFromSeed(randomBytes(32));
    const fp = await fingerprint(org.publicKey);
    const { r } = await legacyMember(org.publicKey);
    const userId = r.request.userId;
    const anchor = (await identityFingerprint(r.account.identityPub)).slice(0, 32);
    const identityCheck = { encryptedIdentitySeedB64: r.request.encryptedIdentitySeed, identityPubB64: r.request.identityPub };

    // A v1 blob is recoverable ONLY through the identity check (Q3): one naming this account but holding
    // some other key is refused.
    const wrongKeyV1 = await openEscrow({
      recoveryKeypair: org, sealed: (await sealUvkV1(org.publicKey, userId, new Uint8Array(32))), expectedUserId: userId,
      expectedIdentityFpPrefix: anchor, identityCheck,
    }).catch((e) => e);
    // (a v1 blob carrying the WRONG key cannot pass the identity check)
    expect(wrongKeyV1).toBeInstanceOf(EscrowOpenError);
    expect((wrongKeyV1 as EscrowOpenError).verdict).toBe("identity_check_failed");

    // The member migrates: resealEscrowFor seals v2 under the confirmed fingerprint.
    const { sealed } = await r.account.resealEscrowFor(toB64(org.publicKey), fp);
    const v2 = await openEscrow({ recoveryKeypair: org, sealed: fromB64(sealed), expectedUserId: userId, expectedIdentityFpPrefix: anchor, identityCheck });
    expect(v2.format).toBe("v2");
    expect(v2.identityKey).toEqual(r.account.identityPub);

    // The legacy v1 blob for the SAME uvk (what the server retains) recovers as v1_legacy.
    const v1 = await sealUvkV1(org.publicKey, userId, v2.uvk);
    const legacy = await openEscrow({ recoveryKeypair: org, sealed: v1, expectedUserId: userId, expectedIdentityFpPrefix: anchor, identityCheck });
    expect(legacy.format).toBe("v1_legacy");
    expect(legacy.uvk).toEqual(v2.uvk);

    // Round trip: recover (temp-password re-wrap) and unlock — same identity, accepted by the pinned device.
    const salt = randomBytes(16);
    const mk = masterKey("temp password", salt, KDF);
    const wrappedUvk = toB64(seal(await wrapKey(mk), v2.uvk, adUvk(userId)));
    const keys: AccountKeys = {
      kdfSalt: toB64(salt), kdfParams: KDF, wrappedUvk, encryptedIdentitySeed: r.request.encryptedIdentitySeed,
      identityPub: r.request.identityPub, escrowFingerprint: fp,
    };
    const recovered = await Account.unlock(userId, "temp password", keys, r.account.identityPub);
    expect(recovered.identityPub).toEqual(r.account.identityPub);
  });

  it("backstop: a device that knew the real identity refuses a forged recovery", async () => {
    const { r } = await legacyMember(boxKeypairFromSeed(randomBytes(32)).publicKey);
    const userId = r.request.userId;
    const forgedUvk = randomBytes(32);
    const forgedSeed = randomBytes(32);
    const salt = randomBytes(16);
    const mk = masterKey("temp password", salt, KDF);
    const forgedKeys: AccountKeys = {
      kdfSalt: toB64(salt), kdfParams: KDF, wrappedUvk: toB64(seal(await wrapKey(mk), forgedUvk, adUvk(userId))),
      encryptedIdentitySeed: toB64(seal(forgedUvk, forgedSeed, adIdkey(userId))),
      identityPub: toB64(boxKeypairFromSeed(forgedSeed).publicKey), escrowFingerprint: "",
    };
    // No record (a fresh device): cannot tell — the documented Q2 residual.
    await Account.unlock(userId, "temp password", forgedKeys, null);
    // The member's device holds the real identity and hard-fails.
    await expect(Account.unlock(userId, "temp password", forgedKeys, r.account.identityPub)).rejects.toBeInstanceOf(IdentityMismatchError);
  });

  it("the browser record is written once and survives (never overwritten by a later value)", async () => {
    const a = (await legacyMember(new Uint8Array(32))).r.account;
    const b = (await legacyMember(new Uint8Array(32))).r.account;
    const mem = new Map<string, string>();
    const shim = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, val: string) => void mem.set(k, val), removeItem: (k: string) => void mem.delete(k), clear: () => mem.clear() };
    const had = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
    Object.defineProperty(globalThis, "localStorage", { value: shim, configurable: true });
    try {
      expect(loadSelfIdentityPub("u1")).toBeNull();
      recordSelfIdentityPub("u1", a);
      recordSelfIdentityPub("u1", b);
      expect(loadSelfIdentityPub("u1")).toEqual(a.identityPub);
      mem.set("andvari.selfIdentityPub.u2", "garbage!!");
      expect(loadSelfIdentityPub("u2")).toBeNull(); // a corrupt local record is treated as absent
    } finally {
      if (had) Object.defineProperty(globalThis, "localStorage", had);
      else delete (globalThis as { localStorage?: unknown }).localStorage;
    }
  });
});
