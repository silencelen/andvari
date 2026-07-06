import { beforeAll, describe, expect, it } from "vitest";
import { CHUNK, CIPHER_CHUNK, HEADER_BYTES, STREAM_ABYTES, decryptAttachment, encryptAttachment, splitChunks } from "./attachments";
import { randomBytes } from "./provider";
import { initSodium } from "./sodium";

/** Round-trip + malformed-shape cases for the spec 02 §6 attachment format. */

beforeAll(async () => {
  await initSodium();
});

describe("attachments", () => {
  it("round-trips across chunk boundaries", () => {
    const key = randomBytes(32);
    for (const size of [1, 5, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 2 * CHUNK + 7]) {
      const plain = randomBytes(size);
      const enc = encryptAttachment(key, plain);
      expect(enc.header.length, `size ${size}`).toBe(HEADER_BYTES);
      const expectedChunks = Math.ceil(size / CHUNK);
      expect(enc.ciphertext.length, `size ${size}`).toBe(size + expectedChunks * STREAM_ABYTES);
      const dec = decryptAttachment(key, enc.header, enc.ciphertext);
      expect(Buffer.from(dec).equals(Buffer.from(plain)), `size ${size}`).toBe(true);
    }
  });

  it("rejects empty plaintext", () => {
    expect(() => encryptAttachment(randomBytes(32), new Uint8Array(0))).toThrow();
  });

  it("splitChunks: every chunk except the last is exactly CIPHER_CHUNK; last ≥ ABYTES+1", () => {
    const key = randomBytes(32);
    const enc = encryptAttachment(key, randomBytes(2 * CHUNK + 3));
    const chunks = splitChunks(enc.ciphertext);
    expect(chunks.length).toBe(3);
    expect(chunks[0]!.length).toBe(CIPHER_CHUNK);
    expect(chunks[1]!.length).toBe(CIPHER_CHUNK);
    expect(chunks[2]!.length).toBe(3 + STREAM_ABYTES);
  });

  it("splitChunks rejects malformed shapes", () => {
    expect(() => splitChunks(new Uint8Array(0))).toThrow(); // empty
    expect(() => splitChunks(new Uint8Array(STREAM_ABYTES))).toThrow(); // ≤ overhead
    expect(() => splitChunks(new Uint8Array(CIPHER_CHUNK + STREAM_ABYTES))).toThrow(); // final chunk = bare overhead
    expect(() => splitChunks(new Uint8Array(CIPHER_CHUNK + 5))).toThrow(); // final chunk < overhead
    // Minimal valid shapes do split:
    expect(splitChunks(new Uint8Array(STREAM_ABYTES + 1)).length).toBe(1);
    expect(splitChunks(new Uint8Array(CIPHER_CHUNK)).length).toBe(1);
    expect(splitChunks(new Uint8Array(CIPHER_CHUNK + STREAM_ABYTES + 1)).length).toBe(2);
  });

  it("fails hard on tampering, truncation, and wrong key", () => {
    const key = randomBytes(32);
    const plain = randomBytes(CHUNK + 100);
    const enc = encryptAttachment(key, plain);

    const flipped = Uint8Array.from(enc.ciphertext);
    flipped[10]! ^= 0x01;
    expect(() => decryptAttachment(key, enc.header, flipped)).toThrow();

    // Dropping the final chunk entirely = missing FINAL tag.
    const truncated = enc.ciphertext.subarray(0, CIPHER_CHUNK);
    expect(() => decryptAttachment(key, enc.header, truncated)).toThrow();

    expect(() => decryptAttachment(randomBytes(32), enc.header, enc.ciphertext)).toThrow();
    expect(() => decryptAttachment(key, enc.header.subarray(0, 23), enc.ciphertext)).toThrow(); // bad header length
  });
});
