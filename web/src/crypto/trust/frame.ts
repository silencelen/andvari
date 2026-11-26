import { concat, ctEquals, toHexLower } from "../bytes";
import { ed25519PkToCurve25519, type KeyPairBytes, sha256Sync, signDetached, signVerifyDetached } from "../provider";
import { CryptoError } from "../sodium";
import { type Checked, ok, refused } from "./checked";

/**
 * The signed-statement frame for every purpose 0x01–0x0A (design 2026-11-15 §2.1; layout unchanged
 * from spec 01 §5.1). Twin of core `SignedFrame`, graded off `statement-v2.json`.
 *
 * ```
 * 0    4   magic        61 76 73 02
 * 4    1   purposeCode
 * 5    32  signerPub    Ed25519 public key
 * 37   64  signature    Ed25519 over M
 * 101  N   statement    canonical JSON, printable ASCII, 2 <= N <= 1024
 * M = "andvari/v2|signed-statement" || 0x00 || frame[0..5) || signerPub || statement
 * ```
 *
 * Nothing here verifies a statement by itself. Each purpose has its own verifier, which cannot be called
 * without the key its context says must have signed.
 */

export const PURPOSE_CODES = {
  "vault-grant": 0x01,
  "escrow-uvk": 0x02,
  "vault-log": 0x03,
  "instance-card": 0x04,
  "account-genesis": 0x05,
  "link-offer": 0x06,
  "link-answer": 0x07,
  "recovery-rotation": 0x08,
  "assisted-recovery": 0x09,
  "recovery-veto": 0x0a,
} as const;

export type Purpose = keyof typeof PURPOSE_CODES;
export const PURPOSES = Object.keys(PURPOSE_CODES) as readonly Purpose[];

/** The purpose for a frame's byte 4, or null for a reserved code. */
export function purposeOfCode(code: number): Purpose | null {
  return PURPOSES.find((p) => PURPOSE_CODES[p] === code) ?? null;
}

/**
 * The verdicts of the §2 parse, in §2.4's order: `bad_frame` if shorter than 4 bytes; `unknown_format`
 * for a wrong magic (the magic is read before the length); `bad_frame` for a length outside 103..1125, a
 * reserved purpose code or a purpose other than the expected one; then `non_canonical` and
 * `bad_statement` for the statement.
 */
export type FrameVerdict = "bad_frame" | "unknown_format" | "non_canonical" | "bad_statement";

/** The four parts of a frame, split and NOT verified. */
export interface FrameParts {
  readonly purpose: Purpose;
  readonly signerPub: Uint8Array;
  readonly signature: Uint8Array;
  readonly statement: Uint8Array;
}

export const MAGIC = Uint8Array.of(0x61, 0x76, 0x73, 0x02);
export const DOMAIN = "andvari/v2|signed-statement";
export const STATEMENT_OFFSET = 101;
export const MIN_STATEMENT_BYTES = 2;
export const MAX_STATEMENT_BYTES = 1024;
export const MAX_FRAME_BYTES = STATEMENT_OFFSET + MAX_STATEMENT_BYTES;

/** True when `bytes` start with the frame magic (§6.4). */
export function hasMagic(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0x61 && bytes[1] === 0x76 && bytes[2] === 0x73 && bytes[3] === 0x02;
}

/** Split a frame (§2.1). Verdicts in §2.4's order; the statement is not looked at. */
export function splitFrame(frame: Uint8Array): Checked<FrameParts, FrameVerdict> {
  if (frame.length < 4) return refused("bad_frame");
  if (!hasMagic(frame)) return refused("unknown_format");
  if (frame.length < STATEMENT_OFFSET + MIN_STATEMENT_BYTES || frame.length > MAX_FRAME_BYTES) return refused("bad_frame");
  const purpose = purposeOfCode(frame[4]!);
  if (purpose === null) return refused("bad_frame");
  return ok({
    purpose,
    signerPub: frame.slice(5, 37),
    signature: frame.slice(37, STATEMENT_OFFSET),
    statement: frame.slice(STATEMENT_OFFSET),
  });
}

/** `H(frame)`: lowercase hex SHA-256 of the full frame bytes, no prefix (§2.1). */
export function frameHash(frame: Uint8Array): string {
  return toHexLower(sha256Sync(frame));
}

/** The signed message `M` (§2.1). */
export function signedMessage(purposeCode: number, signerPub: Uint8Array, statement: Uint8Array): Uint8Array {
  return concat(new TextEncoder().encode(DOMAIN), Uint8Array.of(0), MAGIC, Uint8Array.of(purposeCode), signerPub, statement);
}

/**
 * Frame `statement` under `purpose`, signed by `signer`. FOR THE BUILDERS OF THIS DIRECTORY ONLY: each
 * purpose has its own builder, and there is no "sign any statement" on an account. A source-scan test
 * (`trust-surface.test.ts`) pins that nothing outside `crypto/trust/` imports this.
 */
export function signFrame(signer: KeyPairBytes, purpose: Purpose, statement: Uint8Array): Uint8Array {
  if (signer.publicKey.length !== 32) throw new CryptoError("signed frame: signer public key must be 32 bytes");
  if (statement.length < MIN_STATEMENT_BYTES || statement.length > MAX_STATEMENT_BYTES) {
    throw new CryptoError("signed frame: statement length out of range");
  }
  const code = PURPOSE_CODES[purpose];
  const message = signedMessage(code, signer.publicKey, statement);
  try {
    const signature = signDetached(signer.privateKey, message);
    return concat(MAGIC, Uint8Array.of(code), signer.publicKey, signature, statement);
  } finally {
    message.fill(0); // M repeats the statement, which for a grant holds the vault key
  }
}

/**
 * Zero the parts of a split frame: the statement of a grant or of an assisted recovery holds a key in
 * the clear. Called by the opener of such a frame when it is done, whatever the outcome. What cannot be
 * reached from here is libsodium's own copy inside its WebAssembly memory, which it frees without wiping.
 */
export function wipeFrameParts(parts: FrameParts): void {
  parts.statement.fill(0);
  parts.signature.fill(0);
  parts.signerPub.fill(0);
}

/** The X25519 image of the frame's signer key, or null when it has none. */
export function signerImage(parts: FrameParts): Uint8Array | null {
  try {
    return ed25519PkToCurve25519(parts.signerPub);
  } catch {
    return null;
  }
}

/**
 * Signer binding, the X25519 form (§2.1): `ed25519_pk_to_curve25519(signerPub) == key`. `A` and `-A`
 * share an image, so {@link signatureValid} always follows.
 */
export function signerMapsTo(parts: FrameParts, x25519Key: Uint8Array): boolean {
  if (x25519Key.length !== 32) return false;
  const image = signerImage(parts);
  return image !== null && ctEquals(image, x25519Key);
}

/** Signer binding, the Ed25519 form (§2.1): `signerPub == key`, byte for byte (the card's `operatorSignKey`). */
export function signerIs(parts: FrameParts, ed25519Key: Uint8Array): boolean {
  return ed25519Key.length === 32 && ctEquals(parts.signerPub, ed25519Key);
}

/** `crypto_sign_verify_detached` over `M` under the frame's own `signerPub`. `M` repeats the statement, so it is wiped here. */
export function signatureValid(parts: FrameParts): boolean {
  const message = signedMessage(PURPOSE_CODES[parts.purpose], parts.signerPub, parts.statement);
  try {
    return signVerifyDetached(parts.signerPub, parts.signature, message);
  } finally {
    message.fill(0);
  }
}
