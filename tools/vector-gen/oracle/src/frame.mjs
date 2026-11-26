// The signed statement frame (design §2.1; layout unchanged from spec 01 §5.1).
//
//   offset 0   4   magic        61 76 73 02
//          4   1   purposeCode
//          5   32  signerPub    Ed25519
//          37  64  signature    Ed25519 over M
//          101 N   statement    2 <= N <= 1024
//   M = "andvari/v2|signed-statement" || 0x00 || frame[0..5) || signerPub || statement

import { concat, utf8, hex, bytesEqual } from './bytes.mjs';
import { sha256, signPubFromSeed, edSign, edVerify, edPubToX25519 } from './prims.mjs';
import { PURPOSE_BY_CODE, PURPOSE_CODES, parseStatement } from './statement.mjs';

export const MAGIC = Uint8Array.of(0x61, 0x76, 0x73, 0x02);
export const DOMAIN = 'andvari/v2|signed-statement';
export const MIN_FRAME = 103;
export const MAX_FRAME = 1125;

export function signedMessage(purposeCode, signerPub, statementBytes) {
  return concat(utf8(DOMAIN), Uint8Array.of(0x00), MAGIC, Uint8Array.of(purposeCode), signerPub, statementBytes);
}

/** Assemble a frame from parts, with no checks: malformed fixtures are built with this too. */
export function assembleFrame(purposeCode, signerPub, signature, statementBytes) {
  return concat(MAGIC, Uint8Array.of(purposeCode), signerPub, signature, statementBytes);
}

/** Sign `statement` (a string or bytes) with the joint key of `seed` and frame it. */
export function signFrame(purposeCode, seed, statement) {
  const statementBytes = typeof statement === 'string' ? utf8(statement) : statement;
  const signerPub = signPubFromSeed(seed);
  const message = signedMessage(purposeCode, signerPub, statementBytes);
  const signature = edSign(seed, message);
  return { frame: assembleFrame(purposeCode, signerPub, signature, statementBytes), signerPub, signature, message };
}

/** H(frame): lowercase hex SHA-256 of the full frame bytes. */
export function frameHash(frame) {
  return hex(sha256(frame));
}

/**
 * The frame checks of spec 01 §5.1 step 1, then the expected purpose.
 * Returns { verdict: 'ok', purposeCode, signerPub, signature, statementBytes } or
 * { verdict: 'bad_frame' | 'unknown_format' }.
 */
export function splitFrame(frame, expectedPurposeCode) {
  if (frame.length < 4) return { verdict: 'bad_frame' };
  if (!bytesEqual(frame.slice(0, 4), MAGIC)) return { verdict: 'unknown_format' };
  if (frame.length < MIN_FRAME || frame.length > MAX_FRAME) return { verdict: 'bad_frame' };
  const purposeCode = frame[4];
  if (!Object.hasOwn(PURPOSE_BY_CODE, purposeCode)) return { verdict: 'bad_frame' };
  if (expectedPurposeCode !== undefined && purposeCode !== expectedPurposeCode) return { verdict: 'bad_frame' };
  return {
    verdict: 'ok',
    purposeCode,
    signerPub: frame.slice(5, 37),
    signature: frame.slice(37, 101),
    statementBytes: frame.slice(101),
  };
}

/**
 * The whole §2 parse: frame checks, expected purpose, strict statement parse.
 * Returns { verdict: 'ok', purposeCode, signerPub, signature, statementBytes, values } or one of
 * bad_frame, unknown_format, non_canonical, bad_statement.
 */
export function parseFrame(frame, expectedPurposeCode) {
  const parts = splitFrame(frame, expectedPurposeCode);
  if (parts.verdict !== 'ok') return parts;
  const parsed = parseStatement(PURPOSE_BY_CODE[parts.purposeCode], parts.statementBytes);
  if (parsed.verdict !== 'ok') return { verdict: parsed.verdict };
  return { ...parts, values: parsed.values };
}

/** Signer binding, X25519 form (§2.1): ed25519_pk_to_curve25519(signerPub) == the expected key. */
export function signerMapsTo(signerPub, expectedX25519) {
  const image = edPubToX25519(signerPub);
  return image !== null && expectedX25519 !== null && expectedX25519.length === 32 && bytesEqual(image, expectedX25519);
}

/** Signer binding, Ed25519 form (§2.1): signerPub == the expected key, byte for byte. */
export function signerEquals(signerPub, expectedEd25519) {
  return expectedEd25519 !== null && expectedEd25519.length === 32 && bytesEqual(signerPub, expectedEd25519);
}

/** crypto_sign_verify_detached over M for a frame already split. */
export function signatureValid(parts) {
  return edVerify(parts.signerPub, signedMessage(parts.purposeCode, parts.signerPub, parts.statementBytes), parts.signature);
}

export { PURPOSE_CODES, PURPOSE_BY_CODE };
