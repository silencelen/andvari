import { beforeAll, describe, expect, it } from "vitest";
import type { AccountKeys } from "../api/types";
import type { AccountKeysV2 } from "../api/wire";
import { adIdkey, adRecovery, adUvk, adVkPersonal } from "../crypto/ad";
import { concat, fromB64, toB64 } from "../crypto/bytes";
import { DamagedKeyError, ENVELOPE_ALG_XCHACHA20POLY1305_IETF, ENVELOPE_VERSION, NONCE_BYTES, openKey, seal } from "../crypto/envelope";
import { KeysGoneError } from "../crypto/keyfloor";
import { type KdfParams, masterKey, wrapKey } from "../crypto/keys";
import { openUvk, recoveryWrapKey } from "../crypto/member-recovery";
import { aeadEncrypt, boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { CryptoError, initSodium } from "../crypto/sodium";
import { personalWrapInForce, signGenesis, verifyGenesis } from "../crypto/trust/genesis";
import { vector } from "../crypto/trust/vectors";
import { Account, VaultKeyDamagedError } from "./account";
import { openAccount, SEED_UNOPENABLE, UVK_DAMAGED } from "./accountopen";

/**
 * The shared code's rule of 2026-11-17 (core AccountZeroKeyTakeOutTest, AccountOpenZeroPersonalWrapTest): a key taken
 * out of a sealed structure that turns out to be all zeros (the account key out of its wrap or a recovery copy, the
 * identity seed, the personal vault's wrap) is refused as damage, and is never read as a lock (KeysGoneError) or as a
 * wrong password. The browser's own code keeps the same rule.
 */

/** The hostile input, and the only place it is built: an envelope under [key] whose plaintext is [n] zero bytes. */
function sealedZeros(key: Uint8Array, ad: Uint8Array, n = 32): Uint8Array {
  const nonce = randomBytes(NONCE_BYTES);
  return concat(Uint8Array.of(ENVELOPE_VERSION, ENVELOPE_ALG_XCHACHA20POLY1305_IETF), nonce, aeadEncrypt(key, nonce, new Uint8Array(n), ad));
}

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const PASSWORD = "zero keys are damage";
const USER = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";

beforeAll(async () => {
  await initSodium();
});

/** The wrap key [PASSWORD] derives at [salt]. */
async function wrapKeyOf(salt: Uint8Array): Promise<Uint8Array> {
  return wrapKey(masterKey(PASSWORD, salt, KDF));
}

describe("a key of zeros taken out of a sealed structure is damage, never a lock", () => {
  it("openKey refuses a plaintext of zeros as DamagedKeyError, a CryptoError, and opens a key with one non-zero byte", () => {
    const key = randomBytes(32);
    const ad = adUvk(USER);
    const e = (() => {
      try {
        return openKey(key, sealedZeros(key, ad), ad, "the test's key");
      } catch (x) {
        return x;
      }
    })();
    expect(e).toBeInstanceOf(DamagedKeyError);
    expect(e).toBeInstanceOf(CryptoError);
    expect(e).not.toBeInstanceOf(KeysGoneError);
    const almost = new Uint8Array(32);
    almost[31] = 1;
    expect(openKey(key, seal(key, almost, ad), ad, "the test's key")).toEqual(almost);
  });

  it("a password that opens a wrap of zeros meets damaged keys (Account.unlock), never a lock or a wrong password", async () => {
    const salt = randomBytes(16);
    const wk = await wrapKeyOf(salt);
    const keys: AccountKeys = {
      kdfSalt: toB64(salt),
      kdfParams: KDF,
      wrappedUvk: toB64(sealedZeros(wk, adUvk(USER))),
      encryptedIdentitySeed: toB64(seal(randomBytes(32), randomBytes(32), adIdkey(USER))),
      identityPub: toB64(randomBytes(32)),
      escrowFingerprint: "",
    } as AccountKeys;
    const e = await Account.unlock(USER, PASSWORD, keys).then(() => "opened", (x: unknown) => x);
    expect(e).toBeInstanceOf(VaultKeyDamagedError);
    expect(e).not.toBeInstanceOf(KeysGoneError);
  });

  it("an identity seed of zeros under the account's key is damaged keys on every unlock (Account.unlock)", async () => {
    const salt = randomBytes(16);
    const uvk = randomBytes(32);
    const zeroSeedPub = boxKeypairFromSeed(new Uint8Array(32).fill(0)).publicKey; // what a server would serve beside it
    const keys = {
      kdfSalt: toB64(salt),
      kdfParams: KDF,
      wrappedUvk: toB64(seal(await wrapKeyOf(salt), uvk, adUvk(USER))),
      encryptedIdentitySeed: toB64(sealedZeros(uvk, adIdkey(USER))),
      identityPub: toB64(zeroSeedPub),
      escrowFingerprint: "",
    } as AccountKeys;
    const e = await Account.unlock(USER, PASSWORD, keys).then(() => "opened", (x: unknown) => x);
    expect(e).toBeInstanceOf(VaultKeyDamagedError);
  });

  it("the new line's opening (openAccount): an account key of zeros and a seed of zeros are each refused as damage", () => {
    const keys = (seed: Uint8Array, uvk: Uint8Array) =>
      ({ encryptedIdentitySeed: toB64(seed), identityPub: toB64(boxKeypairFromSeed(new Uint8Array(32)).publicKey), genesis: null, personalWrap: null }) as unknown as AccountKeysV2;
    const uvk = randomBytes(32);
    const zeroUvk = new Uint8Array(32);
    expect(openAccount(USER, zeroUvk, keys(seal(uvk, randomBytes(32), adIdkey(USER)), zeroUvk), "i", null)).toEqual({ kind: "identity_fault", reason: UVK_DAMAGED });
    const r = openAccount(USER, uvk, keys(sealedZeros(uvk, adIdkey(USER)), uvk), "i", null);
    expect(r).toEqual({ kind: "identity_fault", reason: SEED_UNOPENABLE });
    expect(uvk.every((b) => b === 0), "the account key is wiped on the refusal").toBe(true);
  });

  it("a recovery copy that opens to zeros recovers nothing", async () => {
    const secret = randomBytes(32);
    const copy = toB64(sealedZeros(await recoveryWrapKey(secret), adRecovery(USER)));
    await expect(openUvk(secret, copy, USER)).rejects.toBeInstanceOf(DamagedKeyError);
  });

  it("a personal wrap of a vault key of zeros does not open, so no personal vault is in force; one non-zero byte still opens", () => {
    const v = vector("accountgenesis.json");
    const seed = fromB64(v.account.seedB64);
    const signer = signKeypairFromSeed(seed);
    const fields = { userId: v.account.userId, identityKey: v.account.identityPubB64, instanceId: v.instanceId, personalVaultId: v.personalVaultId, createdAt: 1_763_164_800_000 };
    const g = verifyGenesis(signGenesis(signer, fields), { signPub: signer.publicKey, identityPub: boxKeypairFromSeed(seed).publicKey, userId: fields.userId, instanceId: fields.instanceId, personalVaultId: fields.personalVaultId });
    if (!g.ok) throw new Error(g.verdict);
    const uvk = fromB64(v.account.uvkB64);
    const ad = adVkPersonal(fields.personalVaultId, fields.userId);
    expect(personalWrapInForce(g.value, uvk, { vaultId: fields.personalVaultId, wrappedVk: sealedZeros(uvk, ad) })).toBeNull();
    const almost = new Uint8Array(32);
    almost[0] = 9;
    expect(personalWrapInForce(g.value, uvk, { vaultId: fields.personalVaultId, wrappedVk: seal(uvk, almost, ad) })).toEqual(almost);
  });
});
