import { concat, fromB64 } from "./bytes";
import { allZero, requireKey } from "./keyfloor";
import { secretstreamDecrypt, secretstreamEncrypt } from "./provider";
import { CryptoError } from "./sodium";

/**
 * Attachment content crypto (spec 02 §6) — mirrors core Attachments.kt.
 * crypto_secretstream_xchacha20poly1305 over 64 KiB plaintext chunks. The
 * wire/storage shape is `header (24B)` followed by the ordered ciphertext chunks
 * concatenated; chunk boundaries are implicit because every ciphertext chunk
 * except the last is exactly CIPHER_CHUNK bytes.
 */
export const CHUNK = 64 * 1024;
export const STREAM_ABYTES = 17; // secretstream per-chunk overhead
export const CIPHER_CHUNK = CHUNK + STREAM_ABYTES;
export const HEADER_BYTES = 24;

/**
 * The exact stored/wire length (header ‖ chunks) of a `plainSize`-byte attachment (spec 02 §6) —
 * what the server must serve for a ref that declares that size. Strictly increasing, so a body of
 * exactly this length decrypts to exactly `plainSize` bytes or not at all. Null for a size no
 * attachment can have. Core `Attachments.wireLength` twin (security review 2026-10).
 */
export function wireLength(plainSize: number): number | null {
  if (!Number.isSafeInteger(plainSize) || plainSize <= 0) return null;
  return HEADER_BYTES + plainSize + Math.ceil(plainSize / CHUNK) * STREAM_ABYTES;
}

export interface EncryptedAttachment {
  header: Uint8Array;
  ciphertext: Uint8Array;
}

/** Chunk + encrypt. Empty plaintext is rejected (spec: last chunk is 1..65536 bytes). */
export function encryptAttachment(fileKey: Uint8Array, plaintext: Uint8Array): EncryptedAttachment {
  if (plaintext.length === 0) throw new CryptoError("attachment plaintext must not be empty");
  // Spec 01 rule 4: no file is sealed under a key of zeros (KeysGoneError).
  requireKey(fileKey);
  const chunks: Uint8Array[] = [];
  for (let off = 0; off < plaintext.length; off += CHUNK) {
    chunks.push(plaintext.subarray(off, Math.min(off + CHUNK, plaintext.length)));
  }
  const result = secretstreamEncrypt(fileKey, chunks);
  return { header: result.header, ciphertext: concat(...result.chunks) };
}

/** Split the concatenated ciphertext back into chunks by the fixed chunk size. */
export function splitChunks(ciphertext: Uint8Array): Uint8Array[] {
  if (ciphertext.length <= STREAM_ABYTES) throw new CryptoError("attachment ciphertext truncated");
  const n = Math.ceil(ciphertext.length / CIPHER_CHUNK);
  const last = ciphertext.length - (n - 1) * CIPHER_CHUNK;
  if (last <= STREAM_ABYTES) throw new CryptoError("attachment ciphertext has a malformed final chunk");
  const out: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const start = i * CIPHER_CHUNK;
    out.push(ciphertext.subarray(start, i === n - 1 ? start + last : start + CIPHER_CHUNK));
  }
  return out;
}

/** A file key is 32 random bytes (spec 02 §6). */
export const FILE_KEY_BYTES = 32;

/**
 * The file key an item document (or a backup's manifest) names, or null when it is no file key: not unpadded
 * base64url, not {@link FILE_KEY_BYTES} long, or all zeros. Core `ItemCodec.fileKeyOf` twin. A key taken out of data
 * that is all zeros is damage, never a lock: the caller refuses it as damaged content before anything is downloaded
 * or decrypted, and {@link decryptAttachment}'s floor (KeysGoneError) is never what answers for it.
 */
export function fileKeyOf(b64: string): Uint8Array | null {
  let k: Uint8Array;
  try {
    k = fromB64(b64);
  } catch {
    return null;
  }
  return k.length === FILE_KEY_BYTES && !allZero(k) ? k : null;
}

/** Decrypt; throws [CryptoError] on any corrupt, reordered, or truncated chunk (spec 02 §6). */
export function decryptAttachment(fileKey: Uint8Array, header: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  if (header.length !== HEADER_BYTES) throw new CryptoError(`attachment header must be ${HEADER_BYTES} bytes`);
  // Rule 4, as the envelope's open: a key of zeros opens nothing, as KeysGoneError, never as a damaged file.
  requireKey(fileKey);
  return concat(...secretstreamDecrypt(fileKey, header, splitChunks(ciphertext)));
}
