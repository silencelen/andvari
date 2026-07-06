import { CryptoError, sodium } from "./sodium";

/**
 * Primitive layer — mirrors core/crypto/CryptoProvider.kt 1:1 (libsodium-sumo for
 * sodium primitives, WebCrypto for HMAC/SHA which libsodium doesn't ship).
 * Hash/HMAC functions are async (WebCrypto); sodium calls are sync post-init.
 */

export function randomBytes(n: number): Uint8Array {
  return sodium().randombytes_buf(n);
}

export function argon2id(
  password: Uint8Array,
  salt: Uint8Array,
  outLen: number,
  ops: number,
  memBytes: number,
): Uint8Array {
  const s = sodium();
  if (salt.length !== s.crypto_pwhash_SALTBYTES) throw new CryptoError("argon2id salt must be 16 bytes");
  try {
    return s.crypto_pwhash(outLen, password, salt, ops, memBytes, s.crypto_pwhash_ALG_ARGON2ID13);
  } catch (e) {
    throw new CryptoError("crypto_pwhash (argon2id) failed", { cause: e });
  }
}

type HashName = "SHA-1" | "SHA-256" | "SHA-512";

async function hmac(hash: HashName, key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  if (key.length === 0) throw new CryptoError("empty HMAC key");
  const k = await crypto.subtle.importKey("raw", key as BufferSource, { name: "HMAC", hash }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data as BufferSource));
}

export const hmacSha1 = (key: Uint8Array, data: Uint8Array) => hmac("SHA-1", key, data);
export const hmacSha256 = (key: Uint8Array, data: Uint8Array) => hmac("SHA-256", key, data);
export const hmacSha512 = (key: Uint8Array, data: Uint8Array) => hmac("SHA-512", key, data);

export async function sha1(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-1", data as BufferSource));
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

export function aeadEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Uint8Array {
  const s = sodium();
  if (key.length !== s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) throw new CryptoError("AEAD key must be 32 bytes");
  if (nonce.length !== s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) throw new CryptoError("AEAD nonce must be 24 bytes");
  return s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, ad, null, nonce, key);
}

export function aeadDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Uint8Array {
  try {
    return sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, ad, nonce, key);
  } catch (e) {
    throw new CryptoError("xchacha20poly1305 decrypt failed (bad MAC or AD)", { cause: e });
  }
}

export interface KeyPairBytes {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function boxKeypairFromSeed(seed: Uint8Array): KeyPairBytes {
  const s = sodium();
  if (seed.length !== s.crypto_box_SEEDBYTES) throw new CryptoError("box seed must be 32 bytes");
  const kp = s.crypto_box_seed_keypair(seed);
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

export function sealTo(recipientPublicKey: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return sodium().crypto_box_seal(plaintext, recipientPublicKey);
}

export function sealOpen(publicKey: Uint8Array, privateKey: Uint8Array, sealed: Uint8Array): Uint8Array {
  try {
    return sodium().crypto_box_seal_open(sealed, publicKey, privateKey);
  } catch (e) {
    throw new CryptoError("crypto_box_seal_open failed (wrong key or corrupt box)", { cause: e });
  }
}

export interface SecretStreamResult {
  header: Uint8Array;
  chunks: Uint8Array[];
}

export function secretstreamEncrypt(key: Uint8Array, chunks: Uint8Array[]): SecretStreamResult {
  const s = sodium();
  if (key.length !== s.crypto_secretstream_xchacha20poly1305_KEYBYTES) throw new CryptoError("secretstream key must be 32 bytes");
  const { state, header } = s.crypto_secretstream_xchacha20poly1305_init_push(key);
  const out = chunks.map((chunk, i) => {
    const tag = i === chunks.length - 1
      ? s.crypto_secretstream_xchacha20poly1305_TAG_FINAL
      : s.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
    return s.crypto_secretstream_xchacha20poly1305_push(state, chunk, null, tag);
  });
  return { header, chunks: out };
}

export function secretstreamDecrypt(key: Uint8Array, header: Uint8Array, chunks: Uint8Array[]): Uint8Array[] {
  const s = sodium();
  let state;
  try {
    state = s.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  } catch (e) {
    throw new CryptoError("secretstream init_pull failed (bad header)", { cause: e });
  }
  return chunks.map((cipher, i) => {
    let result;
    try {
      result = s.crypto_secretstream_xchacha20poly1305_pull(state, cipher, null);
    } catch (e) {
      throw new CryptoError(`secretstream pull failed at chunk ${i} (corrupt or reordered)`, { cause: e });
    }
    if (!result) throw new CryptoError(`secretstream pull failed at chunk ${i} (corrupt or reordered)`);
    const isLast = i === chunks.length - 1;
    const isFinal = result.tag === s.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
    if (isLast !== isFinal) throw new CryptoError("secretstream truncated or trailing data (final-tag mismatch)");
    return result.message;
  });
}
