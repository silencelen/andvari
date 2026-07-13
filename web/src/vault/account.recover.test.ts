import { beforeAll, describe, expect, it } from "vitest";
import type { AccountKeys, RecoveryVerifyResponse } from "../api/types";
import { toB64 } from "../crypto/bytes";
import type { KdfParams } from "../crypto/keys";
import { deriveAuthKey } from "../crypto/member-recovery";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { CryptoError, initSodium } from "../crypto/sodium";
import { Account, IdentityMismatchError } from "./account";

/**
 * design §F.3 — Account.recover (client half of POST /recovery/self/commit). Drives the crypto the
 * Recover.tsx screen wraps around a mocked api: open the SAME UVK from the member-recovery piece, run
 * the spec 01 §5 identity-pubkey HARD-FAIL, and re-wrap the invariant UVK under the new password.
 */
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 }; // minimum-cost — this tests the flow, not the KDF
const OLD_PW = "the old master password";
const NEW_PW = "a brand new master password";

/** Enroll a real (waived) account, then reshape it into what the verify endpoint would return. */
async function enrolled(): Promise<{ verify: RecoveryVerifyResponse; recoverySecret: Uint8Array; request: Awaited<ReturnType<typeof Account.enroll>>["request"] }> {
  const { request, recoverySecret } = await Account.enroll({
    inviteToken: "t",
    email: "u@example.com",
    displayName: "u",
    password: OLD_PW,
    kdfParams: KDF, // waived: no recoveryPublicKey
  });
  const verify: RecoveryVerifyResponse = {
    userId: request.userId,
    recoveryTicket: "ticket-abc",
    recoveryWrappedUvk: request.memberRecovery.recoveryWrappedUvk,
    encryptedIdentitySeed: request.encryptedIdentitySeed,
    identityPub: request.identityPub,
  };
  return { verify, recoverySecret, request };
}

describe("Account.recover", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the wire recoveryAuthKey is what deriveAuthKey computes from the shown secret", async () => {
    const { request, recoverySecret } = await enrolled();
    expect(request.memberRecovery.recoveryAuthKey).toBe(await deriveAuthKey(recoverySecret));
  });

  it("happy path: re-wraps the SAME UVK so the account unlocks under the NEW password", async () => {
    const { verify, recoverySecret, request } = await enrolled();
    const commit = await Account.recover({ recoverySecret, verify, newPassword: NEW_PW, newKdfParams: KDF });
    expect(commit.recoveryTicket).toBe("ticket-abc");

    // The commit's re-wrapped UVK + fresh salt/params must unlock the account under NEW_PW, and the
    // seed-derived identity must still equal identityPub — proof the UVK is invariant across recovery.
    const keys: AccountKeys = {
      kdfSalt: commit.newKdfSalt,
      kdfParams: commit.newKdfParams,
      wrappedUvk: commit.newWrappedUvk,
      encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub,
      escrowFingerprint: "",
    };
    const account = await Account.unlock(request.userId, NEW_PW, keys);
    expect(toB64(account.identityPub)).toBe(request.identityPub);
  });

  it("the identity-pubkey HARD-FAIL fires on a substituted identityPub (BEFORE commit)", async () => {
    const { verify, recoverySecret } = await enrolled();
    // A compromised server swaps in a valid 32-byte curve25519 key IT controls.
    const tampered: RecoveryVerifyResponse = { ...verify, identityPub: toB64(boxKeypairFromSeed(randomBytes(32)).publicKey) };
    const err = await Account.recover({ recoverySecret, verify: tampered, newPassword: NEW_PW, newKdfParams: KDF }).catch((e) => e);
    expect(err).toBeInstanceOf(IdentityMismatchError);
    // Never softened into a bad-secret / wrong-password error (the Recover screen branches on the type).
    expect(err).not.toBeInstanceOf(CryptoError);
    expect((err as Error).message).not.toMatch(/password|phrase/i);
  });

  it("a wrong recovery secret fails CLOSED (AEAD tag) before any identity check", async () => {
    const { verify } = await enrolled();
    const wrong = randomBytes(32);
    const err = await Account.recover({ recoverySecret: wrong, verify, newPassword: NEW_PW, newKdfParams: KDF }).catch((e) => e);
    expect(err).toBeInstanceOf(CryptoError);
    expect(err).not.toBeInstanceOf(IdentityMismatchError);
  });
});
