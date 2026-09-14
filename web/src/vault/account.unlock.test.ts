import { beforeAll, describe, expect, it } from "vitest";
import type { AccountKeys } from "../api/types";
import { fromB64, toB64 } from "../crypto/bytes";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { CryptoError, initSodium } from "../crypto/sodium";
import { Account, IdentityMismatchError, VAULT_KEYS_DAMAGED, VaultKeyDamagedError } from "./account";

/**
 * F31 (spec 01 §5 MUST, core Account.unlock parity): after deriving the identity
 * keypair from the UVK-sealed seed — which the server cannot forge — the server-sent
 * `identityPub` must EQUAL the derived public key. A substituted key is a tampering
 * signal thrown as a DISTINCT type, so the auth surfaces can never soften it into
 * "wrong master password".
 */

// Minimum-cost argon2id — these tests exercise the cross-check, not the KDF.
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const PASSWORD = "correct horse battery";

/** Enroll for real and reshape the register request into the server's AccountKeys. */
async function enrolledKeys(): Promise<{ userId: string; keys: AccountKeys }> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { request } = await Account.enroll({
    inviteToken: "test-invite",
    email: "u@example.com",
    displayName: "u",
    password: PASSWORD,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return {
    userId: request.userId,
    keys: {
      kdfSalt: request.kdfSalt,
      kdfParams: request.kdfParams,
      wrappedUvk: request.wrappedUvk,
      encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub,
      escrowFingerprint: request.escrow!.fingerprint, // required-path enroll always seals escrow
    },
  };
}

describe("Account.unlock identityPub cross-check (F31 / spec 01 §5)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("unlocks when the server-sent identityPub matches the seed-derived key", async () => {
    const { userId, keys } = await enrolledKeys();
    const account = await Account.unlock(userId, PASSWORD, keys);
    expect(toB64(account.identityPub)).toBe(keys.identityPub);
  });

  it("throws the distinct IdentityMismatchError on a substituted identityPub", async () => {
    const { userId, keys } = await enrolledKeys();
    // A malicious/compromised server swaps in a key IT controls — a valid 32-byte
    // curve25519 public key, so only the cross-check can catch it.
    const tampered: AccountKeys = { ...keys, identityPub: toB64(boxKeypairFromSeed(randomBytes(32)).publicKey) };
    const err = await Account.unlock(userId, PASSWORD, tampered).catch((e) => e);
    expect(err).toBeInstanceOf(IdentityMismatchError);
    expect((err as Error).message).toMatch(/identity key mismatch — possible tampering/i);
    // NEVER presentable as a wrong password (Welcome branches on the type).
    expect(err).not.toBeInstanceOf(CryptoError);
    expect((err as Error).message).not.toMatch(/password/i);
  });

  it("an empty/garbled identityPub also fails the cross-check (no silent skip)", async () => {
    const { userId, keys } = await enrolledKeys();
    const err = await Account.unlock(userId, PASSWORD, { ...keys, identityPub: "" }).catch((e) => e);
    expect(err).toBeInstanceOf(IdentityMismatchError);
  });

  it('a MALFORMED identityPub ("AAAA=") is tampering — never "wrong master password"', async () => {
    // fromB64 throws CryptoError on undecodable base64url; unguarded, that would ride
    // Welcome's fallback branch and blame the user's password for server tampering.
    const { userId, keys } = await enrolledKeys();
    const err = await Account.unlock(userId, PASSWORD, { ...keys, identityPub: "AAAA=" }).catch((e) => e);
    expect(err).toBeInstanceOf(IdentityMismatchError);
    expect(err).not.toBeInstanceOf(CryptoError);
    expect((err as Error).message).not.toMatch(/password/i);
  });

  /**
   * Audit H67 — the structural/secret split, the web half of the twin (core
   * AccountUnlockWithUvkTest.structurallyDamagedWrappedUvkIsNotAWrongPassword). A `wrappedUvk` the
   * server hands back that is not a well-formed envelope is refused from its PUBLIC header alone,
   * before the wrap key is applied: no password could have made it pass, so calling it "wrong
   * master password" (which this code did until H67) sends a member with a half-restored account
   * row to reset a working password and then spend their recovery secret.
   */
  describe("a structurally damaged wrappedUvk (H67)", () => {
    const damage = async (mutate: (good: Uint8Array) => Uint8Array | string) => {
      const { userId, keys } = await enrolledKeys();
      const mutated = mutate(fromB64(keys.wrappedUvk));
      const wrappedUvk = typeof mutated === "string" ? mutated : toB64(mutated);
      return Account.unlock(userId, PASSWORD, { ...keys, wrappedUvk }).catch((e) => e);
    };

    it("is a distinct terminal error — never a CryptoError, never the password", async () => {
      for (const mutate of [
        () => "!!! not base64 !!!", // a truncated/garbled DB column
        (good: Uint8Array) => good.slice(0, 8), // too short to be an envelope
        (good: Uint8Array) => { const b = good.slice(); b[0] = 0x02; return b; }, // a version this build doesn't know
        (good: Uint8Array) => { const b = good.slice(); b[1] = 0x02; return b; }, // an alg it doesn't know
      ]) {
        const err = await damage(mutate);
        expect(err).toBeInstanceOf(VaultKeyDamagedError);
        expect(err).not.toBeInstanceOf(CryptoError);
        // The canon sentence, byte-identical to core HouseholdCopy.ACCOUNT_KEYS_DAMAGED and the
        // extension's unlockErrorCopy("keys_damaged") — the ladders render `message` verbatim.
        expect((err as Error).message).toBe(
          "This account's stored keys are damaged or from a newer version, so sign-in cannot continue. Contact your admin or restore from a backup.",
        );
        expect((err as Error).message).toBe(VAULT_KEYS_DAMAGED);
        expect((err as Error).message).not.toMatch(/password/i);
        expect((err as Error).message).not.toMatch(/try again/i); // terminal: the same blob fails forever
      }
    });

    /**
     * R38 — the sibling blob. `encryptedIdentitySeed` lives in the same account row, is damaged
     * by the same partial restore or the same too-new envelope version, and its open in the
     * shared tail was left un-gated — so a structurally broken seed collapsed into "wrong master
     * password" one line after the block above stopped saying exactly that about the same row.
     */
    it("R38: the sibling encryptedIdentitySeed gets the SAME terminal, not the password", async () => {
      const damageSeed = async (mutate: (good: Uint8Array) => Uint8Array | string) => {
        const { userId, keys } = await enrolledKeys();
        const mutated = mutate(fromB64(keys.encryptedIdentitySeed));
        const encryptedIdentitySeed = typeof mutated === "string" ? mutated : toB64(mutated);
        return Account.unlock(userId, PASSWORD, { ...keys, encryptedIdentitySeed }).catch((e) => e);
      };
      for (const mutate of [
        () => "!!! not base64 !!!",
        (good: Uint8Array) => good.slice(0, 8),
        (good: Uint8Array) => { const b = good.slice(); b[0] = 0x02; return b; },
        (good: Uint8Array) => { const b = good.slice(); b[1] = 0x02; return b; },
      ]) {
        const err = await damageSeed(mutate);
        expect(err).toBeInstanceOf(VaultKeyDamagedError);
        expect(err).not.toBeInstanceOf(CryptoError);
        expect((err as Error).message).toBe(VAULT_KEYS_DAMAGED);
      }
    });
  });

  it("a plain wrong password still reads as CryptoError, not tampering", async () => {
    const { userId, keys } = await enrolledKeys();
    const err = await Account.unlock(userId, "not the password", keys).catch((e) => e);
    expect(err).toBeInstanceOf(CryptoError);
    expect(err).not.toBeInstanceOf(IdentityMismatchError);
    // H67's other half: an INTACT blob + a wrong password is the one genuinely ambiguous outcome
    // (an AEAD tag failure) and must keep saying so — the split is only a fix if both sides hold.
    expect(err).not.toBeInstanceOf(VaultKeyDamagedError);
    expect((err as Error).message).toMatch(/wrong master password/);
  });
});
