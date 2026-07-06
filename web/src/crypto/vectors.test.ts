import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { adIdkey, adItem, adUvk, adVaultMeta, adVk } from "./ad";
import { fromB64, fromUtf8, toB64, utf8 } from "./bytes";
import { open, sealWithNonce } from "./envelope";
import { CANARY_USER_ID, KEY_TYPE_UVK, fingerprint, openEscrow, shortFingerprint } from "./escrow";
import { generatePassword } from "./generator";
import { hibpCountInRange, hibpPrefix, hibpSha1UpperHex, hibpSuffix } from "./hibp";
import { hkdfSha256 } from "./hkdf";
import { authKey, masterKey, wrapKey, type KdfParams } from "./keys";
import {
  argon2id,
  boxKeypairFromSeed,
  sealOpen,
  secretstreamDecrypt,
  secretstreamEncrypt,
} from "./provider";
import { initSodium } from "./sodium";
import { base32Decode, base32Encode, parseOtpauthUri, totpCode, type TotpAlgorithm } from "./totp";

/**
 * Consumes spec/test-vectors — the SAME files the Kotlin VectorsTest verifies.
 * Keep the two suites in lockstep; scripts/verify.sh runs both.
 */

const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function load(name: string): any {
  return JSON.parse(readFileSync(vectorsDir + name, "utf-8"));
}

beforeAll(async () => {
  await initSodium();
});

describe("kdf.json", () => {
  const v = load("kdf.json");
  it("argon2id", () => {
    for (const c of v.argon2id) {
      const out = argon2id(utf8(c.passwordUtf8), fromB64(c.saltB64), c.outLen, c.ops, c.memBytes);
      expect(toB64(out), c.passwordUtf8).toBe(c.outB64);
    }
  });
  it("hkdf", async () => {
    for (const c of v.hkdf) {
      const okm = await hkdfSha256(fromB64(c.ikmB64), new Uint8Array(0), utf8(c.infoUtf8), c.len);
      expect(toB64(okm), c.infoUtf8).toBe(c.okmB64);
    }
  });
  it("chain", async () => {
    for (const c of v.chain) {
      const mk = masterKey(c.passwordUtf8, fromB64(c.saltB64), c.kdfParams as KdfParams);
      expect(toB64(mk)).toBe(c.mkB64);
      expect(toB64(await authKey(mk))).toBe(c.authKeyB64);
      expect(toB64(await wrapKey(mk))).toBe(c.wrapKeyB64);
    }
  });
});

describe("envelope.json", () => {
  const v = load("envelope.json");
  it("seal + open", () => {
    for (const c of v.seal) {
      const sealed = sealWithNonce(fromB64(c.keyB64), fromB64(c.nonceB64), fromB64(c.plaintextB64), utf8(c.adUtf8));
      expect(toB64(sealed), c.name).toBe(c.envelopeB64);
      expect(toB64(open(fromB64(c.keyB64), fromB64(c.envelopeB64), utf8(c.adUtf8)))).toBe(c.plaintextB64);
    }
  });
  it("rejects", () => {
    for (const c of v.reject) {
      expect(() => open(fromB64(c.keyB64), fromB64(c.envelopeB64), utf8(c.adUtf8)), c.reason).toThrow();
    }
  });
});

describe("wrap.json — full enrollment chain", () => {
  const v = load("wrap.json");
  it("reproduces every hop", async () => {
    const mk = masterKey(v.passwordUtf8, fromB64(v.kdfSaltB64), v.kdfParams as KdfParams);
    expect(toB64(await authKey(mk))).toBe(v.authKeyB64);
    const wk = await wrapKey(mk);

    expect(toB64(sealWithNonce(wk, fromB64(v.uvkNonceB64), fromB64(v.uvkB64), adUvk(v.userId)))).toBe(v.wrappedUvkB64);
    const uvk = open(wk, fromB64(v.wrappedUvkB64), adUvk(v.userId));
    expect(toB64(uvk)).toBe(v.uvkB64);

    const identity = boxKeypairFromSeed(fromB64(v.identitySeedB64));
    expect(toB64(identity.publicKey)).toBe(v.identityPubB64);
    expect(toB64(identity.privateKey)).toBe(v.identityPrivB64);
    expect(toB64(open(uvk, fromB64(v.encryptedIdentitySeedB64), adIdkey(v.userId)))).toBe(v.identitySeedB64);

    const vk = open(uvk, fromB64(v.wrappedVkB64), adVk(v.personalVaultId, v.userId));
    expect(toB64(vk)).toBe(v.vkB64);
    expect(fromUtf8(open(vk, fromB64(v.vaultMetaBlobB64), adVaultMeta(v.personalVaultId)))).toBe(v.vaultMetaPlaintextUtf8);
    expect(fromUtf8(open(vk, fromB64(v.itemEnvelopeB64), adItem(v.personalVaultId, v.itemId, v.itemFormatVersion)))).toBe(
      v.itemPlaintextUtf8,
    );
  });
});

describe("seal.json", () => {
  const v = load("seal.json");
  it("keypair, fingerprint, opens", async () => {
    const kp = boxKeypairFromSeed(fromB64(v.recoverySeedB64));
    expect(toB64(kp.publicKey)).toBe(v.recoveryPubB64);
    expect(toB64(kp.privateKey)).toBe(v.recoveryPrivB64);
    expect(await fingerprint(kp.publicKey)).toBe(v.fingerprint);
    expect(await shortFingerprint(kp.publicKey)).toBe(v.shortFingerprint);

    for (const c of v.open) {
      expect(toB64(sealOpen(kp.publicKey, kp.privateKey, fromB64(c.sealedB64)))).toBe(c.plaintextB64);
    }
    const escrow = await openEscrow(kp.publicKey, kp.privateKey, fromB64(v.escrowUvk.sealedB64));
    expect(escrow.userId).toBe(v.escrowUvk.userId);
    expect(escrow.keyType).toBe(KEY_TYPE_UVK);
    expect(toB64(fromB64(escrow.key))).toBe(v.escrowUvk.uvkB64);

    const canary = await openEscrow(kp.publicKey, kp.privateKey, fromB64(v.canary.sealedB64));
    expect(canary.userId).toBe(CANARY_USER_ID);
    expect(canary.userId).toBe(v.canary.expectedUserId);
    expect(escrowKeyB64(canary.key)).toBe(v.canary.expectedKeyB64);

    const wrong = boxKeypairFromSeed(fromB64(v.rejectWrongKey.wrongSeedB64));
    expect(() => sealOpen(wrong.publicKey, wrong.privateKey, fromB64(v.rejectWrongKey.sealedB64))).toThrow();
  });
});

function escrowKeyB64(key: string): string {
  return toB64(fromB64(key));
}

describe("secretstream.json", () => {
  const v = load("secretstream.json");
  it("decrypts streams", () => {
    const key = fromB64(v.keyB64);
    for (const stream of v.streams) {
      const plain = (stream.chunksPlainB64 as string[]).map(fromB64);
      const cipher = (stream.chunksCipherB64 as string[]).map(fromB64);
      const dec = secretstreamDecrypt(key, fromB64(stream.headerB64), cipher);
      expect(dec.length).toBe(plain.length);
      for (let i = 0; i < plain.length; i++) expect(toB64(dec[i]!)).toBe(toB64(plain[i]!));
    }
  });
  it("rejects tampered streams", () => {
    const key = fromB64(v.keyB64);
    for (const reject of v.reject) {
      const cipher = (reject.chunksCipherB64 as string[]).map(fromB64);
      expect(() => secretstreamDecrypt(key, fromB64(reject.headerB64), cipher), reject.reason).toThrow();
    }
  });
  it("round-trips its own encryption", () => {
    const key = fromB64(v.keyB64);
    const chunks = [Uint8Array.from([1, 2, 3]), Uint8Array.from([4, 5])];
    const enc = secretstreamEncrypt(key, chunks);
    const dec = secretstreamDecrypt(key, enc.header, enc.chunks);
    expect(dec.map(toB64)).toEqual(chunks.map(toB64));
  });
});

describe("totp.json", () => {
  const v = load("totp.json");
  it("codes", async () => {
    for (const c of v.cases) {
      const code = await totpCode(
        {
          secret: base32Decode(c.secretBase32),
          algorithm: c.algorithm as TotpAlgorithm,
          digits: c.digits,
          periodSeconds: c.period,
          label: "",
          issuer: "",
        },
        c.timeSec,
      );
      expect(code, `T=${c.timeSec} ${c.algorithm}`).toBe(c.expected);
    }
  });
  it("uris", () => {
    for (const c of v.uris) {
      const parsed = parseOtpauthUri(c.uri);
      expect(base32Encode(parsed.secret)).toBe(c.expect.secretBase32);
      expect(parsed.algorithm).toBe(c.expect.algorithm);
      expect(parsed.digits).toBe(c.expect.digits);
      expect(parsed.periodSeconds).toBe(c.expect.period);
      expect(parsed.label).toBe(c.expect.label);
      expect(parsed.issuer).toBe(c.expect.issuer);
    }
  });
});

describe("hibp.json", () => {
  const v = load("hibp.json");
  it("hashes and range matching", async () => {
    for (const c of v.cases) {
      const hash = await hibpSha1UpperHex(c.passwordUtf8);
      expect(hash).toBe(c.sha1UpperHex);
      expect(hibpPrefix(hash)).toBe(c.prefix);
      expect(hibpSuffix(hash)).toBe(c.suffix);
      expect(hibpCountInRange(c.rangeResponse, hash)).toBe(c.expectedCount);
    }
  });
});

describe("generator (round-trip only — no vectors possible)", () => {
  it("respects classes and length", () => {
    for (let i = 0; i < 10; i++) {
      const pw = generatePassword();
      expect(pw).toHaveLength(20);
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[0-9]/);
      expect(pw).toMatch(/[^a-zA-Z0-9]/);
      expect([...pw].some((c) => "lIO01".includes(c))).toBe(false);
    }
  });
});
