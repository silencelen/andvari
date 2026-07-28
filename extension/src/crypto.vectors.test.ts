// The extension's OWN shared-vector run for the CRYPTO engine (node --test, same harness as
// urimatch.vectors.test.ts). crypto.fence.test.ts pins the four KDF fence NUMBERS and
// quickunlock.test.ts round-trips @noble against itself — neither proves the shipped engine agrees
// with the fleet's libsodium. That proof used to live only in web/src/crypto/noble-extension-poc.test.ts,
// which is skipped in every default run and exercises web's provider + raw @noble rather than THIS file.
// So: run the same spec/test-vectors the Kotlin and web suites run, through extension/src/crypto.ts.
// A refactor of the offsets, AD strings or argon2 param mapping now fails the gate instead of
// shipping an extension that cannot decrypt real vault blobs.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  adIdkey,
  adItem,
  adUvk,
  adVk,
  authKey,
  boxKeypairFromSeed,
  deriveMasterKey,
  fromB64,
  hkdfSha256,
  open,
  seal,
  sealOpen,
  toB64,
  wrapKey,
  type KdfParams,
} from "./crypto.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const load = (name: string) => JSON.parse(readFileSync(vectorsDir + name, "utf-8"));
const utf8 = (s: string) => new TextEncoder().encode(s);
const fromUtf8 = (u: Uint8Array) => new TextDecoder().decode(u);
// kdf.json's argon2id cases carry only ops/memBytes; deriveMasterKey takes the full params record.
const kdfParams = (ops: number, memBytes: number): KdfParams => ({ v: 1, alg: "argon2id13", ops, memBytes });

// The 64 MiB production-default case costs ~6 s of the gate. It stays IN the gate anyway: those are
// the params every real account derives under, and a case parked behind an env var is exactly how
// the PoC test came to never run at all.
test("kdf.json argon2id — deriveMasterKey == libsodium crypto_pwhash ARGON2ID13", () => {
  for (const c of load("kdf.json").argon2id) {
    assert.equal(c.outLen, 32, "deriveMasterKey only emits KEY_BYTES");
    const out = deriveMasterKey(c.passwordUtf8, kdfParams(c.ops, c.memBytes), fromB64(c.saltB64));
    assert.equal(toB64(out), c.outB64, `argon2id ops=${c.ops} mem=${c.memBytes}`);
  }
});

test("kdf.json hkdf — RFC 5869 HKDF-SHA-256 with the empty salt", () => {
  for (const c of load("kdf.json").hkdf) {
    const okm = hkdfSha256(fromB64(c.ikmB64), new Uint8Array(0), utf8(c.infoUtf8), c.len);
    assert.equal(toB64(okm), c.okmB64, c.infoUtf8);
  }
});

test("kdf.json chain — password → mk → authKey/wrapKey", () => {
  for (const c of load("kdf.json").chain) {
    const mk = deriveMasterKey(c.passwordUtf8, c.kdfParams as KdfParams, fromB64(c.saltB64));
    assert.equal(toB64(mk), c.mkB64, c.passwordUtf8);
    assert.equal(toB64(authKey(mk)), c.authKeyB64);
    assert.equal(toB64(wrapKey(mk)), c.wrapKeyB64);
  }
});

test("envelope.json — open() reads the frozen version‖alg‖nonce‖ct bytes another engine sealed", () => {
  for (const c of load("envelope.json").seal) {
    const pt = open(fromB64(c.keyB64), fromB64(c.envelopeB64), utf8(c.adUtf8));
    assert.equal(toB64(pt), c.plaintextB64, c.name);
  }
});

test("envelope.json — seal() output opens back, and lands in the frozen layout", () => {
  // seal() mints its own nonce (no injectable-nonce variant in the extension), so byte-equality with
  // the vector isn't available; assert the layout bytes + round-trip instead.
  for (const c of load("envelope.json").seal) {
    const key = fromB64(c.keyB64);
    const ad = utf8(c.adUtf8);
    const env = seal(key, fromB64(c.plaintextB64), ad);
    const frozen = fromB64(c.envelopeB64);
    assert.deepEqual([env[0], env[1]], [frozen[0], frozen[1]], `${c.name}: version‖alg header`);
    assert.equal(env.length, frozen.length, `${c.name}: length`);
    assert.equal(toB64(open(key, env, ad)), c.plaintextB64, c.name);
  }
});

test("envelope.json rejects — bad version/alg/mac, truncation, wrong AD all throw", () => {
  for (const c of load("envelope.json").reject) {
    assert.throws(() => open(fromB64(c.keyB64), fromB64(c.envelopeB64), utf8(c.adUtf8)), Error, c.reason);
  }
});

test("envelope.json — the ad*() helpers build the frozen AD strings verbatim", () => {
  // The AD literals are baked into every vector; if ad() drifts, every open above fails with an
  // opaque MAC error, so pin the construction itself.
  const [vaultId, itemId] = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"];
  assert.equal(fromUtf8(adItem(vaultId, itemId, 1)), load("envelope.json").seal[0].adUtf8);
  assert.equal(fromUtf8(adUvk("33333333-3333-4333-8333-333333333333")), load("envelope.json").seal[1].adUtf8);
});

test("wrap.json — the whole enrollment chain reproduces through crypto.ts", () => {
  const v = load("wrap.json");
  const mk = deriveMasterKey(v.passwordUtf8, v.kdfParams as KdfParams, fromB64(v.kdfSaltB64));
  assert.equal(toB64(authKey(mk)), v.authKeyB64);
  const wk = wrapKey(mk);

  const uvk = open(wk, fromB64(v.wrappedUvkB64), adUvk(v.userId));
  assert.equal(toB64(uvk), v.uvkB64);

  const identity = boxKeypairFromSeed(fromB64(v.identitySeedB64));
  assert.equal(toB64(identity.publicKey), v.identityPubB64);
  assert.equal(toB64(identity.privateKey), v.identityPrivB64);
  assert.equal(toB64(open(uvk, fromB64(v.encryptedIdentitySeedB64), adIdkey(v.userId))), v.identitySeedB64);

  const vk = open(uvk, fromB64(v.wrappedVkB64), adVk(v.personalVaultId, v.userId));
  assert.equal(toB64(vk), v.vkB64);
  // The item hop is the one the autofill path actually walks on every unlock.
  assert.equal(
    fromUtf8(open(vk, fromB64(v.itemEnvelopeB64), adItem(v.personalVaultId, v.itemId, v.itemFormatVersion))),
    v.itemPlaintextUtf8,
  );
});

test("seal.json — sealOpen reads a libsodium crypto_box_seal (the shared-vault grant path)", () => {
  const v = load("seal.json");
  const kp = boxKeypairFromSeed(fromB64(v.recoverySeedB64));
  assert.equal(toB64(kp.publicKey), v.recoveryPubB64);
  assert.equal(toB64(kp.privateKey), v.recoveryPrivB64);

  for (const c of v.open) {
    assert.equal(toB64(sealOpen(kp.publicKey, kp.privateKey, fromB64(c.sealedB64))), c.plaintextB64);
  }
  // Escrow payloads are out of the extension's surface (no escrow module here), but the sealed-box
  // open under them is the same primitive — assert the payload it yields, not just that it decodes.
  const escrow = JSON.parse(fromUtf8(sealOpen(kp.publicKey, kp.privateKey, fromB64(v.escrowUvk.sealedB64))));
  assert.equal(escrow.userId, v.escrowUvk.userId);
  assert.equal(escrow.key, v.escrowUvk.uvkB64);

  const wrong = boxKeypairFromSeed(fromB64(v.rejectWrongKey.wrongSeedB64));
  assert.throws(() => sealOpen(wrong.publicKey, wrong.privateKey, fromB64(v.rejectWrongKey.sealedB64)));
});
