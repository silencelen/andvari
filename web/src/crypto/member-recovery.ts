import { adRecovery } from "./ad";
import { ctEquals, fromB64, toB64, utf8 } from "./bytes";
import { open, seal } from "./envelope";
import { hkdfSha256 } from "./hkdf";
import { randomBytes } from "./provider";

/**
 * spec 04 §per-member / design 2026-07-12 §F.6 — the per-member SELF-SERVICE recovery piece.
 * One of four byte-parity twins (core MemberRecovery.kt, this, MV3 ext, server), pinned to
 * spec/test-vectors/member-recovery.json.
 *
 * The symmetric counterpart to org escrow: the member holds ONE high-entropy secret at both
 * seal-time (enroll) and open-time (recovery), so there is no org PUBLIC key a hostile server
 * could substitute — spec 05 T10 does not apply and the enrollment fingerprint ceremony has
 * nothing to defend on this path. The worst a hostile server can do is serve a wrong/tampered
 * blob → the AEAD tag fails → recovery FAILS CLOSED (pure availability denial, accepted under T1).
 *
 *  - `recoverySecret` = 32 CSPRNG bytes ({@link randomBytes}) — 256-bit, matching the org seed. It
 *    is GENERATED, shown ONCE, then dropped; it is NEVER `Math.random` and NEVER derived from user
 *    input (the invariant the whole T8 posture rests on — §F.6).
 *  - HKDF-SHA-256 (empty-salt, the same construction as {@link authKey}/{@link wrapKey} in keys.ts)
 *    SPLITS the secret into a wrap key and an auth key. The split severs them: the value the server
 *    verifies (`recoveryAuthKey`) can never open the wrapped UVK, exactly like `authKey` vs `wrapKey`.
 *  - The UVK is sealed under the wrap key in an AEAD Envelope bound to {@link adRecovery} (userId).
 *  - base64url of a CSPRNG is unbiased, so the printed/QR sheet needs NO rejection sampling and NO
 *    Argon2id on this path (128-bit generated entropy is already computationally unreachable).
 */
export const SECRET_BYTES = 32;
export const KEY_BYTES = 32;
const INFO_WRAP = utf8("andvari/v1/recovery-wrap");
const INFO_AUTH = utf8("andvari/v1/recovery-auth");
const EMPTY_SALT = new Uint8Array(0);

/** Whitespace the printed sheet may hard-wrap the phrase with. base64url's alphabet includes `-`
 *  and `_`, so only whitespace is a safe separator to drop (mirrors the core twin's " \t\n\r"). */
const WHITESPACE_RE = /[ \t\n\r]/g;

/** HKDF-SHA-256(recoverySecret, "andvari/v1/recovery-wrap", 32) — the KEK that wraps the UVK. */
export const recoveryWrapKey = (recoverySecret: Uint8Array): Promise<Uint8Array> =>
  hkdfSha256(recoverySecret, EMPTY_SALT, INFO_WRAP, KEY_BYTES);

/** HKDF-SHA-256(recoverySecret, "andvari/v1/recovery-auth", 32) — the server-verified proof. The
 *  server stores `crypto_pwhash_str(recoveryAuthKey)`; severed from {@link recoveryWrapKey} it opens
 *  nothing. */
export const recoveryAuthKey = (recoverySecret: Uint8Array): Promise<Uint8Array> =>
  hkdfSha256(recoverySecret, EMPTY_SALT, INFO_AUTH, KEY_BYTES);

/** Recompute the base64url `recoveryAuthKey` the server verifies for a secret (recovery path). */
export const deriveAuthKey = async (recoverySecret: Uint8Array): Promise<string> =>
  toB64(await recoveryAuthKey(recoverySecret));

/** The generated piece: the raw [recoverySecret] to display ONCE, plus the two wire fields
 *  (recoveryWrappedUvk + recoveryAuthKey, both base64url) that go into the register / self-setup
 *  request. Mirrors org escrow's split of "secret stays with the holder, ciphertext + one-way
 *  verifier go to the server." */
export interface MemberRecoveryPiece {
  recoverySecret: Uint8Array;
  recoveryWrappedUvk: string;
  recoveryAuthKey: string;
}

/**
 * Generate a fresh recovery piece over [uvk]. The 256-bit [recoverySecret] is CSPRNG and NEVER user
 * input (§F.6); the caller shows it once (via {@link displayForm}) and drops it.
 */
export async function generate(userId: string, uvk: Uint8Array): Promise<MemberRecoveryPiece> {
  const recoverySecret = randomBytes(SECRET_BYTES);
  const wrapKey = await recoveryWrapKey(recoverySecret);
  const recoveryWrappedUvk = toB64(seal(wrapKey, uvk, adRecovery(userId)));
  const recoveryAuthKeyB64 = toB64(await recoveryAuthKey(recoverySecret));
  return { recoverySecret, recoveryWrappedUvk, recoveryAuthKey: recoveryAuthKeyB64 };
}

/**
 * Open the UVK from a `recoveryWrappedUvk` (recovery path). A wrong secret or a wrong/tampered blob
 * fails the AEAD tag → throws (fail-closed; availability denial only, T1). Returns the SAME UVK that
 * was sealed at enroll — never a regenerated one (the UVK is invariant, so both the org-escrow and
 * member-recovery blobs stay valid across a password reset).
 */
export async function openUvk(
  recoverySecret: Uint8Array,
  recoveryWrappedUvkB64: string,
  userId: string,
): Promise<Uint8Array> {
  const wrapKey = await recoveryWrapKey(recoverySecret);
  return open(wrapKey, fromB64(recoveryWrappedUvkB64), adRecovery(userId));
}

/**
 * The printed/display encoding of [recoverySecret]: base64url of the raw random bytes — the exact
 * form the org recovery sheet renders, so the two sheets read identically. UI layers may visually
 * group it with SPACES for readability (base64url's `-`/`_` rule out any other separator);
 * {@link confirmMatches} and {@link parseSecret} tolerate that whitespace.
 */
export const displayForm = (recoverySecret: Uint8Array): string => toB64(recoverySecret);

/**
 * Decode a typed/scanned-back recovery phrase to its raw secret bytes, or null if malformed. TOTAL
 * (never throws) — it runs in UI layers. Strips hard-wrap whitespace, then base64url-decodes.
 */
export function parseSecret(typed: string): Uint8Array | null {
  try {
    return fromB64(typed.replace(WHITESPACE_RE, ""));
  } catch {
    return null;
  }
}

/**
 * CONFIRMATION ONLY (§F.6): does what the user typed back re-decode to the SAME secret we generated?
 * Constant-time compare over the raw bytes. This gates the un-skippable "I saved my phrase" step; it
 * is NEVER a KDF source — a mistype must fail the confirm, never silently mis-key the wrap/auth
 * derivation.
 */
export function confirmMatches(recoverySecret: Uint8Array, typedBackEncoded: string): boolean {
  const typed = parseSecret(typedBackEncoded);
  if (typed === null) return false;
  return ctEquals(recoverySecret, typed);
}
