import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { initSodium } from "./sodium";
import { aeadEncrypt, aeadDecrypt } from "./provider";
import { sealWithNonce, ENVELOPE_VERSION, ENVELOPE_ALG_XCHACHA20POLY1305_IETF } from "./envelope";

/**
 * Browser-extension crypto PoC — spike doc §Unknown 1, path B (docs/design/2026-07-08-browser-
 * extension-spike.md). The one real go/no-go blocker is that libsodium's emscripten glue uses
 * `eval`/`new Function`, which an MV3 service-worker CSP forbids even with `wasm-unsafe-eval`. The
 * resolution is pure-JS `@noble` — no WASM, no eval — for the extension's REDUCED crypto surface
 * (unlock + item AEAD; escrow/attachments are out of v1). This test proves @noble is BYTE-IDENTICAL
 * to libsodium and to the shared spec vectors every client runs, so an extension built on it
 * interoperates with web/Android/desktop at zero wire cost. Green here == path B is GO.
 */
const b64 = (u: Uint8Array) => Buffer.from(u).toString("base64url");
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
const utf8 = (s: string) => new TextEncoder().encode(s);
// vitest runs from web/; the vectors are the SAME file the Kotlin + TS suites pin against.
const V = JSON.parse(readFileSync("../spec/test-vectors/kdf.json", "utf8"));

// Spike PoC / future-extension regression guard. Skipped in the normal gate (the 64 MiB Argon2id
// adds ~6 s and no extension consumes @noble yet); run on demand with `EXT_POC=1 npx vitest run`.
describe.skipIf(!process.env.EXT_POC)("extension crypto: @noble (pure-JS, MV3-clean) ≡ libsodium ≡ spec vectors", () => {
  it("Argon2id == kdf.json (libsodium crypto_pwhash ARGON2ID13)", { timeout: 60_000 }, () => {
    for (const v of V.argon2id) {
      // libsodium opslimit→t, memlimit(bytes)→m(KiB), p=1, ALG_ARGON2ID13 → version 0x13.
      const out = argon2id(utf8(v.passwordUtf8), unb64(v.saltB64), {
        t: v.ops,
        m: v.memBytes / 1024,
        p: 1,
        dkLen: v.outLen,
        version: 0x13,
      });
      expect(b64(out), `argon2id ops=${v.ops} mem=${v.memBytes}`).toBe(v.outB64);
    }
  });

  it("HKDF-SHA256 == kdf.json", () => {
    for (const v of V.hkdf) {
      const out = hkdf(sha256, unb64(v.ikmB64), new Uint8Array(0), utf8(v.infoUtf8), v.len);
      expect(b64(out)).toBe(v.okmB64);
    }
  });

  it("XChaCha20-Poly1305 is byte-identical to libsodium and interops both directions", async () => {
    await initSodium();
    for (let i = 0; i < 24; i++) {
      const key = Uint8Array.from({ length: 32 }, (_, j) => (i * 7 + j) & 0xff);
      const nonce = Uint8Array.from({ length: 24 }, (_, j) => (i * 3 + j) & 0xff);
      const ad = Uint8Array.from([i & 0xff, 0xaa, 0xbb]);
      const pt = Uint8Array.from({ length: 13 + i }, (_, j) => (j * 5) & 0xff);
      const nobleCt = xchacha20poly1305(key, nonce, ad).encrypt(pt);
      const sodiumCt = aeadEncrypt(key, nonce, pt, ad);
      expect(b64(nobleCt), `ct i=${i}`).toBe(b64(sodiumCt)); // identical ciphertext + tag
      expect(b64(aeadDecrypt(key, nonce, nobleCt, ad))).toBe(b64(pt)); // libsodium opens @noble's
      expect(b64(xchacha20poly1305(key, nonce, ad).decrypt(sodiumCt))).toBe(b64(pt)); // @noble opens libsodium's
    }
  });

  it("full item envelope (version‖alg‖nonce‖ct) is byte-identical to core Envelope", async () => {
    await initSodium();
    const key = new Uint8Array(32).fill(9);
    const nonce = new Uint8Array(24).fill(4);
    const ad = utf8("v1|vaultId|itemId"); // stand-in for the item associated data
    const pt = utf8('{"type":"login","name":"x"}');
    const sodiumEnv = sealWithNonce(key, nonce, pt, ad);
    const nobleCt = xchacha20poly1305(key, nonce, ad).encrypt(pt);
    const nobleEnv = new Uint8Array([ENVELOPE_VERSION, ENVELOPE_ALG_XCHACHA20POLY1305_IETF, ...nonce, ...nobleCt]);
    expect(b64(nobleEnv)).toBe(b64(sodiumEnv));
  });
});
