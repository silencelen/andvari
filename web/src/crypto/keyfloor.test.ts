import { beforeAll, describe, expect, it, vi } from "vitest";
import { encryptAttachment, decryptAttachment } from "./attachments";
import { toB64 } from "./bytes";
import { open, seal } from "./envelope";
import { fingerprint, sealUvkV1, sealUvkV2 } from "./escrow";
import { hkdfSha256 } from "./hkdf";
import { allZero, KeysGoneError } from "./keyfloor";
import { confirmMatches, displayForm, parseSecret } from "./member-recovery";
import { boxKeypairFromSeed, randomBytes, signDetached, signKeypairFromSeed } from "./provider";
import { CryptoError, initSodium, sodium } from "./sodium";
import { openVaultGrant, signVaultGrant } from "./trust/grant";

/**
 * Spec 01 "Keys in memory and the lock", rule 4, at every operation the web has: an all-zero key is refused with
 * KeysGoneError (never a CryptoError, which reads as a wrong key or damaged data) before the platform's provider is
 * called. On the code before the rule, each of these sealed, opened, derived or signed under the zeros.
 */
const ZERO = () => new Uint8Array(32);
const ONE = () => {
  const k = new Uint8Array(32);
  k[31] = 1; // the lowest key the rule accepts (keyfloor.json's near-zero rows)
  return k;
};
const AD = new TextEncoder().encode("andvari/v1|test");

async function refusal(f: () => unknown): Promise<unknown> {
  try {
    await f();
    return null;
  } catch (e) {
    return e;
  }
}

async function expectKeysGone(f: () => unknown): Promise<void> {
  const e = await refusal(f);
  expect(e).toBeInstanceOf(KeysGoneError);
  expect(e).not.toBeInstanceOf(CryptoError);
}

beforeAll(async () => {
  await initSodium();
});

describe("the floor itself", () => {
  it("allZero is true only for a non-empty run of zero bytes", () => {
    expect(allZero(ZERO())).toBe(true);
    expect(allZero(new Uint8Array(1))).toBe(true);
    expect(allZero(new Uint8Array(0))).toBe(false);
    expect(allZero(ONE())).toBe(false);
  });
});

describe("spec 01 rule 4 at each operation", () => {
  it("an envelope is neither sealed nor opened under a key of zeros, and the AEAD is never called", async () => {
    const s = sodium();
    const enc = vi.spyOn(s, "crypto_aead_xchacha20poly1305_ietf_encrypt");
    const dec = vi.spyOn(s, "crypto_aead_xchacha20poly1305_ietf_decrypt");
    try {
      await expectKeysGone(() => seal(ZERO(), new Uint8Array([1, 2, 3]), AD));
      const sealed = seal(ONE(), new Uint8Array([1, 2, 3]), AD);
      expect(enc).toHaveBeenCalledTimes(1);
      await expectKeysGone(() => open(ZERO(), sealed, AD));
      expect(dec).not.toHaveBeenCalled();
      expect(open(ONE(), sealed, AD)).toEqual(new Uint8Array([1, 2, 3]));
      // A blob whose public header is wrong is refused as damaged first, whatever the key (core Envelope.open's order).
      expect(await refusal(() => open(ZERO(), new Uint8Array(10), AD))).toBeInstanceOf(CryptoError);
    } finally {
      enc.mockRestore();
      dec.mockRestore();
    }
  });

  it("no wiped key is wrapped: a plaintext of exactly 32 or 64 zero bytes is refused; any other plaintext seals", async () => {
    const key = randomBytes(32);
    await expectKeysGone(() => seal(key, new Uint8Array(32), AD));
    await expectKeysGone(() => seal(key, new Uint8Array(64), AD));
    for (const n of [0, 1, 31, 33, 63, 65]) expect(() => seal(key, new Uint8Array(n), AD)).not.toThrow();
    expect(() => seal(key, ONE(), AD)).not.toThrow();
  });

  it("nothing is derived from an HKDF input key of zeros, before WebCrypto is asked; an empty salt (zeros as the HMAC key) still derives", async () => {
    const importKey = vi.spyOn(crypto.subtle, "importKey");
    try {
      await expectKeysGone(() => hkdfSha256(ZERO(), new Uint8Array(0), AD, 32));
      await expectKeysGone(() => hkdfSha256(ZERO(), randomBytes(32), AD, 32));
      expect(importKey).not.toHaveBeenCalled();
      expect((await hkdfSha256(ONE(), new Uint8Array(0), AD, 32)).length).toBe(32);
    } finally {
      importKey.mockRestore();
    }
  });

  it("nothing is signed with a seed of zeros: a detached signature, a signed frame", async () => {
    const sign = vi.spyOn(sodium(), "crypto_sign_detached");
    try {
      const wiped = signKeypairFromSeed(ONE());
      wiped.privateKey.fill(0); // what a wipe leaves: the whole secret zeroed
      await expectKeysGone(() => signDetached(wiped.privateKey, AD));
      const seedHalfOnly = signKeypairFromSeed(ONE());
      seedHalfOnly.privateKey.fill(0, 0, 32); // the seed half zeroed, the public half left
      await expectKeysGone(() => signDetached(seedHalfOnly.privateKey, AD));
      const zeroSeed = signKeypairFromSeed(ZERO()); // a seed of zeros as the key's seed
      await expectKeysGone(() => signDetached(zeroSeed.privateKey, AD)); // a signed frame: trust/keyfloor.vectors.test.ts
      expect(sign).not.toHaveBeenCalled();
      expect(signDetached(signKeypairFromSeed(ONE()).privateKey, AD).length).toBe(64);
    } finally {
      sign.mockRestore();
    }
  });

  it("no escrow seal of a zero UVK, v1 or v2", async () => {
    const org = boxKeypairFromSeed(randomBytes(32));
    await expectKeysGone(() => sealUvkV1(org.publicKey, "11111111-1111-4111-8111-111111111111", ZERO()));
    const seed = randomBytes(32);
    await expectKeysGone(async () =>
      sealUvkV2({
        recoveryPub: org.publicKey,
        verifiedRecoveryFp: await fingerprint(org.publicKey),
        userId: "11111111-1111-4111-8111-111111111111",
        identityPub: boxKeypairFromSeed(seed).publicKey,
        signer: signKeypairFromSeed(seed),
        uvk: ZERO(),
        issuedAt: 1_700_000_000_000,
      }),
    );
  });

  it("no file is encrypted or decrypted under a key of zeros", async () => {
    const push = vi.spyOn(sodium(), "crypto_secretstream_xchacha20poly1305_init_push");
    const pull = vi.spyOn(sodium(), "crypto_secretstream_xchacha20poly1305_init_pull");
    try {
      await expectKeysGone(() => encryptAttachment(ZERO(), new Uint8Array([1])));
      expect(push).not.toHaveBeenCalled();
      const real = encryptAttachment(ONE(), new Uint8Array([1]));
      await expectKeysGone(() => decryptAttachment(ZERO(), real.header, real.ciphertext));
      expect(pull).not.toHaveBeenCalled();
      expect(decryptAttachment(ONE(), real.header, real.ciphertext)).toEqual(new Uint8Array([1]));
    } finally {
      push.mockRestore();
      pull.mockRestore();
    }
  });

  it("a wiped vault key is never granted, and a wiped identity key opens no grant (a lock, never an unopenable grant)", async () => {
    const seed = randomBytes(32);
    const signer = signKeypairFromSeed(seed);
    const toKey = boxKeypairFromSeed(randomBytes(32)).publicKey;
    const fields = {
      from: "11111111-1111-4111-8111-111111111111",
      to: "22222222-2222-4222-8222-222222222222",
      toKey: toB64(toKey),
      vaultId: "33333333-3333-4333-8333-333333333333",
      grantId: toB64(randomBytes(16)),
      issuedAt: 1_700_000_000_000,
    };
    await expectKeysGone(() => signVaultGrant(signer, { ...fields, vk: ZERO() }));
    expect(() => signVaultGrant(signer, { ...fields, vk: ONE() })).not.toThrow();
    const open = vi.spyOn(sodium(), "crypto_box_seal_open");
    try {
      const me = { userId: fields.to, identityPub: toKey, identityPriv: ZERO() };
      await expectKeysGone(() => openVaultGrant(me, fields.vaultId, randomBytes(200), null));
      expect(open).not.toHaveBeenCalled();
    } finally {
      open.mockRestore();
    }
  });

  it("a recovery secret of zeros is no kit's: it does not parse, and it never confirms", () => {
    expect(parseSecret(displayForm(ZERO()))).toBeNull();
    expect(confirmMatches(ZERO(), displayForm(ZERO()))).toBe(false);
    expect(parseSecret(displayForm(ONE()))).toEqual(ONE());
  });
});
