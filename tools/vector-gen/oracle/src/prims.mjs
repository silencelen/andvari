// Crypto primitives, from the four pinned @noble libraries only. No andvari code.
//
// Every SHA-256, SHA-512, HMAC, HKDF, Ed25519 and X25519 call is also written to a journal, which
// `webcheck.mjs` replays through Node's WebCrypto: a second implementation recomputes each value
// the vectors were built from.

import { sha256 as nobleSha256, sha512 as nobleSha512 } from '@noble/hashes/sha2.js';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { blake2b } from '@noble/hashes/blake2.js';
import * as ed from '@noble/ed25519';
import { ed25519 as curvesEd, x25519 } from '@noble/curves/ed25519.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { xsalsa20poly1305, hsalsa } from '@noble/ciphers/salsa.js';
import { concat, utf8, hex, bytesEqual } from './bytes.mjs';

ed.hashes.sha512 = nobleSha512;

export const journal = [];
function note(entry) {
  journal.push(entry);
}

const asBytes = (x) => (typeof x === 'string' ? utf8(x) : x);

export function sha256(data) {
  const input = asBytes(data);
  const out = nobleSha256(input);
  note({ op: 'sha256', input: hex(input), out: hex(out) });
  return out;
}

export function sha512(data) {
  const input = asBytes(data);
  const out = nobleSha512(input);
  note({ op: 'sha512', input: hex(input), out: hex(out) });
  return out;
}

export function hmacSha256(key, data) {
  const input = asBytes(data);
  const out = nobleHmac(nobleSha256, key, input);
  note({ op: 'hmac', key: hex(key), input: hex(input), out: hex(out) });
  return out;
}

/** HKDF-SHA-256 with an empty salt (RFC 5869 default: HashLen zero bytes). `info` is a string or bytes. */
export function hkdfSha256(ikm, info, length) {
  const infoBytes = asBytes(info);
  const out = nobleHkdf(nobleSha256, ikm, undefined, infoBytes, length);
  note({ op: 'hkdf', ikm: hex(ikm), info: hex(infoBytes), length, out: hex(out) });
  return out;
}

// ---- Ed25519 (the joint signing key: crypto_sign_seed_keypair(seed)) ----

export function signPubFromSeed(seed) {
  const pub = ed.getPublicKey(seed);
  note({ op: 'ed25519.pub', seed: hex(seed), out: hex(pub) });
  return pub;
}

/** RFC 8032 deterministic signature, so the bytes reproduce on every engine. */
export function edSign(seed, message) {
  const sig = ed.sign(message, seed);
  note({ op: 'ed25519.sign', seed: hex(seed), message: hex(message), out: hex(sig) });
  return sig;
}

export function edVerify(pub, message, signature) {
  if (pub.length !== 32 || signature.length !== 64) return false;
  let ok;
  try {
    ok = ed.verify(signature, message, pub, { zip215: false });
  } catch {
    ok = false;
  }
  note({ op: 'ed25519.verify', pub: hex(pub), message: hex(message), signature: hex(signature), out: ok });
  return ok;
}

// ---- X25519 (the identity key: crypto_box_seed_keypair(seed)) ----

/** libsodium crypto_box_seed_keypair: sk = SHA-512(seed)[0..32), pk = X25519 base multiple of sk. */
export function boxKeypairFromSeed(seed) {
  const sk = sha512(seed).slice(0, 32);
  const pk = x25519.scalarMultBase(sk);
  note({ op: 'x25519.base', scalar: hex(sk), out: hex(pk) });
  return { publicKey: pk, secretKey: sk };
}

export function x25519Base(scalar) {
  const pk = x25519.scalarMultBase(scalar);
  note({ op: 'x25519.base', scalar: hex(scalar), out: hex(pk) });
  return pk;
}

export function x25519Shared(scalar, peerPublic) {
  const out = x25519.scalarMult(scalar, peerPublic);
  note({ op: 'x25519.dh', scalar: hex(scalar), peer: hex(peerPublic), out: hex(out) });
  return out;
}

const P = (1n << 255n) - 19n;
function modpow(base, exp, mod) {
  let result = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/**
 * crypto_sign_ed25519_pk_to_curve25519: the Montgomery u of an Edwards point, u = (1 + y) / (1 - y).
 * Returns null where libsodium refuses: not a curve point, a small-order point, or a point outside
 * the prime-order subgroup. The arithmetic is done here in BigInt; @noble/curves only answers the
 * three membership questions.
 */
export function edPubToX25519(edPub) {
  if (!edPub || edPub.length !== 32) return null;
  let point;
  try {
    point = curvesEd.Point.fromBytes(edPub);
  } catch {
    return null;
  }
  if (point.isSmallOrder() || !point.isTorsionFree()) return null;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? edPub[i] & 0x7f : edPub[i]);
  if (y >= P) return null;
  const num = (1n + y) % P;
  const den = (1n - y + P) % P;
  const u = (num * modpow(den, P - 2n, P)) % P;
  const out = new Uint8Array(32);
  let v = u;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  const viaNoble = curvesEd.utils.toMontgomery(edPub);
  if (!bytesEqual(out, viaNoble)) throw new Error('edPubToX25519: BigInt and @noble/curves disagree');
  return out;
}

/**
 * The encoding of -A for an Ed25519 public key A. An encoded point is y with the sign of x in the
 * top bit of the last byte (RFC 8032 §5.1.2), and -A = (-x, y), so -A is A with that one bit
 * flipped. It is computed here on the curve, by @noble/curves, and the bit flip must agree. -A is a
 * valid point with the same X25519 image as A (u depends on y alone).
 */
export function edNegate(edPub) {
  const negated = curvesEd.Point.fromBytes(edPub).negate().toBytes();
  const flipped = edPub.slice();
  flipped[31] ^= 0x80;
  if (!bytesEqual(negated, flipped) || bytesEqual(negated, edPub)) throw new Error('edNegate: the curve and the bit flip disagree');
  const image = edPubToX25519(negated);
  if (image === null || !bytesEqual(image, edPubToX25519(edPub))) throw new Error('edNegate: -A must have the X25519 image of A');
  return negated;
}

/** The order of the Ed25519 base point (RFC 8032 §5.1). */
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const leToBigInt = (bytes) => {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
};
const bigIntToLe32 = (n) => {
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};

/**
 * What the holder of `seed` can do that nobody else can: sign validly under -A, the negation of the
 * seed's Ed25519 key A. RFC 8032 §5.1.6 with the secret scalar s (the clamped first half of
 * SHA-512(seed)) replaced by L - s, and the same prefix (the second half): r = SHA-512(prefix || M)
 * mod L, R = rB, k = SHA-512(R || -A || M) mod L, S = (r + k(L - s)) mod L. (L - s)B is -A: checked
 * against edNegate, and the signature is then checked under -A with the strict verifier, whose call
 * the WebCrypto replay recomputes. Returns { signerPub: -A, signature }.
 */
export function edSignNegated(seed, message) {
  const h = sha512(seed);
  const head = h.slice(0, 32);
  head[0] &= 248;
  head[31] &= 127;
  head[31] |= 64;
  const s = leToBigInt(head) % ED_L;
  const negS = (ED_L - s) % ED_L;
  const negA = curvesEd.Point.BASE.multiply(negS).toBytes();
  if (!bytesEqual(negA, edNegate(signPubFromSeed(seed)))) throw new Error('edSignNegated: (L - s)B is not -A');
  const r = leToBigInt(sha512(concat(h.slice(32), message))) % ED_L;
  const R = curvesEd.Point.BASE.multiply(r).toBytes();
  const k = leToBigInt(sha512(concat(R, negA, message))) % ED_L;
  const signature = concat(R, bigIntToLe32((r + k * negS) % ED_L));
  if (!edVerify(negA, message, signature)) throw new Error('edSignNegated: the signature does not verify under -A');
  return { signerPub: negA, signature };
}

/**
 * Whether a 32-byte string is a low-order X25519 point (RFC 7748 §6.1): one whose product with any
 * clamped scalar is the all-zero value. Decided by @noble/curves' x25519, which refuses exactly these
 * points (its blocklist of u = 0, 1, p - 1 and the two points of order 8, after masking the top bit
 * and reducing mod p, as RFC 7748 §5 decodes u) and throws for them. Any other 32 bytes give a
 * product, so they are not low-order. Not journaled: WebCrypto has no X25519 call that answers this.
 */
export function isLowOrderX25519(u) {
  if (!u || u.length !== 32) throw new Error('isLowOrderX25519: 32 bytes');
  const scalar = new Uint8Array(32).fill(0x5a);
  try {
    x25519.scalarMult(scalar, u);
    return false;
  } catch {
    return true;
  }
}

/**
 * The published list of low-order X25519 encodings (D. J. Bernstein, cr.yp.to/ecdh.html#validate;
 * the list libsodium refuses): 0, 1, the two points of order 8, p - 1, p and p + 1, little endian.
 */
export const LOW_ORDER_X25519_HEX = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

// ---- AEAD envelope (spec 02 §2, unchanged): 0x01 0x01 || nonce(24) || XChaCha20-Poly1305 ct||tag ----

export function envelopeSeal(key, nonce, ad, plaintext) {
  if (key.length !== 32 || nonce.length !== 24) throw new Error('envelopeSeal: key or nonce length');
  const ct = xchacha20poly1305(key, nonce, asBytes(ad)).encrypt(plaintext);
  return concat(Uint8Array.of(0x01, 0x01), nonce, ct);
}

/** Returns the plaintext, or null (unknown version or alg, shorter than 42 bytes, or a bad tag). */
export function envelopeOpen(key, ad, envelope) {
  if (!envelope || envelope.length < 42) return null;
  if (envelope[0] !== 0x01 || envelope[1] !== 0x01) return null;
  const nonce = envelope.slice(2, 26);
  try {
    return xchacha20poly1305(key, nonce, asBytes(ad)).decrypt(envelope.slice(26));
  } catch {
    return null;
  }
}

// ---- crypto_box_seal (libsodium sealed box), with a caller-supplied ephemeral key so it reproduces ----

function hsalsa20(key32, in16) {
  const le = (bytes) => {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const words = new Uint32Array(bytes.length / 4);
    for (let i = 0; i < words.length; i++) words[i] = view.getUint32(4 * i, true);
    return words;
  };
  const sigma = le(utf8('expand 32-byte k'));
  const out = new Uint32Array(8);
  hsalsa(sigma, le(key32), le(in16), out);
  const bytes = new Uint8Array(32);
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < 8; i++) view.setUint32(4 * i, out[i], true);
  return bytes;
}

function boxKey(secretScalar, peerPublic) {
  // crypto_box_beforenm: HSalsa20(X25519(sk, pk), 16 zero bytes).
  return hsalsa20(x25519Shared(secretScalar, peerPublic), new Uint8Array(16));
}

/**
 * sealed = ephemeralPub || crypto_box(m, nonce = BLAKE2b-24(ephemeralPub || recipientPub), ephemeralSk, recipientPub).
 * `ephemeralScalar` is the 32-byte X25519 secret libsodium would draw at random.
 */
export function boxSeal(recipientPub, message, ephemeralScalar) {
  const epk = x25519Base(ephemeralScalar);
  const nonce = blake2b(concat(epk, recipientPub), { dkLen: 24 });
  const ct = xsalsa20poly1305(boxKey(ephemeralScalar, recipientPub), nonce).encrypt(message);
  return concat(epk, ct);
}

/** Returns the plaintext, or null. */
export function boxSealOpen(recipientPub, recipientSecret, sealed) {
  if (!sealed || sealed.length < 48) return null;
  const epk = sealed.slice(0, 32);
  const nonce = blake2b(concat(epk, recipientPub), { dkLen: 24 });
  try {
    return xsalsa20poly1305(boxKey(recipientSecret, epk), nonce).decrypt(sealed.slice(32));
  } catch {
    return null;
  }
}
