import { adIdkey } from "./ad";
import { ctEquals, fromB64, fromUtf8, toB64, toHexLower, utf8 } from "./bytes";
import { requireJsonSafe } from "./canonicaljson";
import { open as openEnvelope } from "./envelope";
import { matchesShort } from "./fingerprint";
import { boxKeypairFromSeed, ed25519PkToCurve25519, type KeyPairBytes, sealOpen, sealTo, sha256 } from "./provider";
import { buildSignedStatement, claimEscrowVerifier, type EscrowUvkStatement, formatOf, SignedStatementError } from "./signedstatement";

// The anchored escrow verifier is module-private to signedstatement.ts; this escrow open path claims it
// once, here, so nothing else can (security review 2026-10, root cause A; core twin: `internal`).
const verifyEscrowStatement = claimEscrowVerifier();
import { CryptoError } from "./sodium";

/** spec 04 §3 — sealed escrow payloads; mirrors core Escrow.kt. */
export const KEY_TYPE_UVK = "uvk";
export const KEY_TYPE_CANARY = "canary";
export const CANARY_USER_ID = "00000000-0000-0000-0000-000000000000";
export const CANARY_KEY: Uint8Array = new Uint8Array(32).fill(0x5a);

export interface EscrowPayload {
  v: number;
  userId: string;
  keyType: string;
  key: string;
  sha256: string;
}

/**
 * Canonical bytes — string template guarantees key order and no whitespace.
 *
 * Audit F33: [userId] is SERVER-SUPPLIED (it arrives on the session response), so the template is
 * composed under the same precondition core's twin applies — see {@link requireJsonSafe} for what
 * a value that escapes its JSON string would buy an attacker here. `keyType` is ours, but it is
 * interpolated into the same template, so it is held to the same rule rather than trusted by
 * position.
 */
export async function canonicalPayload(userId: string, keyType: string, keyBytes: Uint8Array): Promise<Uint8Array> {
  requireJsonSafe(userId, "escrow userId");
  requireJsonSafe(keyType, "escrow keyType");
  const keyB64 = toB64(keyBytes);
  const shaB64 = toB64(await sha256(keyBytes));
  return utf8(`{"v":1,"userId":"${userId}","keyType":"${keyType}","key":"${keyB64}","sha256":"${shaB64}"}`);
}

/**
 * The v1 (legacy) escrow seal. No client seals this since the escrow v2 branch (security review
 * 2026-10, root cause A); it stays so tests can build a legacy blob, because v1 blobs remain
 * recoverable indefinitely (owner decision Q3) through {@link openEscrow}'s mandatory identity check.
 */
export async function sealUvkV1(recoveryPub: Uint8Array, userId: string, uvk: Uint8Array): Promise<Uint8Array> {
  return sealTo(recoveryPub, await canonicalPayload(userId, KEY_TYPE_UVK, uvk));
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const ANCHOR_RE = /^[0-9a-f]{32,64}$/;
const FULL_FP_RE = /^[0-9a-f]{64}$/;

/**
 * Escrow v2 seal (security review 2026-10, root cause A §2.1; spec 04 §3). Twin of core
 * `Escrow.sealUvkV2`: an `escrow-uvk` SignedStatement binding `userId`, the member's seed-derived
 * identity key, the FULL org fingerprint and the UVK, signed with the joint key `signer` and sealed to
 * `recoveryPub`. REFUSES unless `hex(SHA-256(recoveryPub)) === verifiedRecoveryFp` IN FULL (64
 * lowercase hex), and unless `signer` maps to `identityPub`. The canary stays v1.
 *
 * `verifiedRecoveryFp` is always a value a HUMAN anchored, never one taken from a server response on its
 * own (security review 2026-10, root cause A, branch A5). Two anchors exist: the typed sheet (the member
 * typed 32 hex that matched the server-advertised full fingerprint, which is then passed here), and the
 * in-person QR, whose FULL 64-hex `rfp` the admin client minted from the admin's own sheet check and the
 * invitee accepts only after typing the in-person code from the admin's screen (`enrollCheckCode`). The
 * link's `rfp` itself is passed here, so the served key must hash to it in full — never
 * `fingerprint(servedKey)` anchored by a short prefix.
 */
export async function sealUvkV2(params: {
  recoveryPub: Uint8Array;
  verifiedRecoveryFp: string;
  userId: string;
  identityPub: Uint8Array;
  signer: KeyPairBytes;
  uvk: Uint8Array;
  issuedAt: number;
}): Promise<Uint8Array> {
  const { recoveryPub, verifiedRecoveryFp, userId, identityPub, signer, uvk, issuedAt } = params;
  if (recoveryPub.length !== 32) throw new CryptoError("recovery public key must be 32 bytes");
  if (!FULL_FP_RE.test(verifiedRecoveryFp) || (await fingerprint(recoveryPub)) !== verifiedRecoveryFp) {
    throw new CryptoError("recovery public key does not match the verified fingerprint (full compare) — refusing to seal escrow");
  }
  if (uvk.length !== 32) throw new CryptoError("escrow uvk must be 32 bytes");
  let mapped: Uint8Array;
  try {
    mapped = ed25519PkToCurve25519(signer.publicKey);
  } catch (e) {
    throw new CryptoError("escrow signer is not a usable Ed25519 key", { cause: e });
  }
  if (!ctEquals(mapped, identityPub)) throw new CryptoError("escrow signer does not map to the identity key it would name");
  const st: EscrowUvkStatement = { purpose: "escrow-uvk", userId, identityKey: identityPub, recoveryFp: verifiedRecoveryFp, issuedAt, key: uvk };
  const frame = buildSignedStatement(signer, st);
  try {
    return sealTo(recoveryPub, frame);
  } finally {
    frame.fill(0);
  }
}

/** The typed acknowledgment an admin gives for an UNANCHORED recovery (owner decision Q2). */
export const UNANCHORED_ACK = "I understand this recovery is UNANCHORED";

export type EscrowVerdict =
  | "bad_user_id"
  | "bad_anchor"
  | "unanchored_not_acknowledged"
  | "identity_check_required"
  | "identity_fp_mismatch"
  | "unopenable"
  | "unknown_format"
  | "bad_frame"
  | "non_canonical"
  | "bad_statement"
  | "user_mismatch"
  | "recovery_fp_mismatch"
  | "signer_not_pinned_key"
  | "bad_signature"
  | "identity_mismatch"
  | "v1_malformed"
  | "v1_self_check_failed"
  | "identity_check_failed";

export class EscrowOpenError extends Error {
  constructor(readonly verdict: EscrowVerdict, detail: string) {
    super(`escrow refused: ${verdict} (${detail})`);
    this.name = "EscrowOpenError";
  }
}

/** The server-supplied identity file from the admin escrow download (design §2.5). */
export interface IdentityCheck {
  encryptedIdentitySeedB64: string;
  identityPubB64: string;
}

/** A successfully opened escrow blob (twin of core `EscrowOpened`). `userId` is the caller's `expectedUserId`. */
export interface EscrowOpened {
  readonly format: "v2" | "v1_legacy";
  readonly userId: string;
  readonly uvk: Uint8Array;
  readonly identityKey: Uint8Array;
  readonly anchored: boolean;
}

const refuse = (verdict: EscrowVerdict, detail: string): never => {
  throw new EscrowOpenError(verdict, detail);
};

/**
 * Open a member's escrow blob, FAIL CLOSED — twin of core `Escrow.open` (spec 04 §4, design §2.2), graded
 * off spec/test-vectors/escrow-v2.json. The bare `openEscrow(pub, priv, sealed)` that adopted whatever
 * account the payload named is gone. `expectedUserId` is REQUIRED; `expectedIdentityFpPrefix` is >= 32
 * lowercase hex from a human, or null ONLY with `unanchoredAcknowledgment === UNANCHORED_ACK` (Q2);
 * `identityCheck` is REQUIRED. Same step order and verdicts as core: inputs → anchor (the identity is
 * vouched for out of band before the blob is read) → seal → format → v2 anchored verify / v1 legacy
 * parse + userId → identity-seed check (both formats). A v1 blob yields `v1_legacy`.
 */
export async function openEscrow(params: {
  recoveryKeypair: KeyPairBytes;
  sealed: Uint8Array;
  expectedUserId: string;
  expectedIdentityFpPrefix: string | null;
  identityCheck: IdentityCheck | null;
  unanchoredAcknowledgment?: string | null;
}): Promise<EscrowOpened> {
  const { recoveryKeypair, sealed, expectedUserId, expectedIdentityFpPrefix, identityCheck } = params;
  if (!UUID_RE.test(expectedUserId)) refuse("bad_user_id", "expectedUserId is not a lowercase uuid");
  const anchored = expectedIdentityFpPrefix != null;
  if (expectedIdentityFpPrefix != null) {
    if (!ANCHOR_RE.test(expectedIdentityFpPrefix)) refuse("bad_anchor", "identity anchor must be 32..64 lowercase hex");
  } else if (params.unanchoredAcknowledgment !== UNANCHORED_ACK) {
    refuse("unanchored_not_acknowledged", "an unanchored recovery needs the typed acknowledgment");
  }
  if (identityCheck == null) return refuse("identity_check_required", "recovery needs the identity file");
  let identityPub: Uint8Array | null = null;
  try {
    identityPub = fromB64(identityCheck.identityPubB64);
  } catch {
    identityPub = null;
  }
  if (identityPub == null || identityPub.length !== 32) return refuse("identity_check_failed", "identity file identityPub is not a 32-byte key");

  if (expectedIdentityFpPrefix != null && !(await fingerprint(identityPub)).startsWith(expectedIdentityFpPrefix)) {
    refuse("identity_fp_mismatch", "identity does not match the fingerprint you were given");
  }

  let plaintext: Uint8Array;
  try {
    plaintext = sealOpen(recoveryKeypair.publicKey, recoveryKeypair.privateKey, sealed);
  } catch {
    return refuse("unopenable", "not sealed to this recovery key");
  }
  const orgFp = await fingerprint(recoveryKeypair.publicKey);
  try {
    let format: "v2" | "v1_legacy";
    let uvk: Uint8Array;
    const kind = formatOf(plaintext);
    if (kind === "v2-signed") {
      let st: EscrowUvkStatement;
      try {
        st = verifyEscrowStatement(plaintext, expectedUserId, identityPub, orgFp).statement as EscrowUvkStatement;
      } catch (e) {
        if (e instanceof SignedStatementError) return refuse(e.verdict, e.message);
        throw e;
      }
      format = "v2";
      uvk = st.key;
    } else if (kind === "v1-json") {
      const payload = await parseV1(plaintext);
      if (payload.userId !== expectedUserId) refuse("user_mismatch", "this backstop key belongs to another account");
      format = "v1_legacy";
      uvk = fromB64(payload.key);
    } else {
      return refuse("unknown_format", "unknown backstop key format");
    }

    try {
      let derived: Uint8Array;
      try {
        const seed = openEnvelope(uvk, fromB64(identityCheck.encryptedIdentitySeedB64), adIdkey(expectedUserId));
        try {
          const kp = boxKeypairFromSeed(seed);
          kp.privateKey.fill(0);
          derived = kp.publicKey;
        } finally {
          seed.fill(0);
        }
      } catch {
        return refuse("identity_check_failed", "the escrowed key does not open this account's identity");
      }
      if (!ctEquals(derived, identityPub)) refuse("identity_check_failed", "the escrowed key does not open this account's identity");
      return Object.freeze({ format, userId: expectedUserId, uvk: uvk.slice(), identityKey: identityPub.slice(), anchored });
    } finally {
      uvk.fill(0);
    }
  } finally {
    plaintext.fill(0);
  }
}

/** Legacy v1 payload parse (integrity only): `v == 1`, `keyType == "uvk"`, 32-byte key, sha256 self-check. */
async function parseV1(plaintext: Uint8Array): Promise<EscrowPayload> {
  let payload: EscrowPayload;
  try {
    payload = JSON.parse(fromUtf8(plaintext)) as EscrowPayload;
  } catch {
    return refuse("v1_malformed", "malformed v1 backstop key");
  }
  if (payload === null || typeof payload !== "object" || payload.v !== 1 || payload.keyType !== KEY_TYPE_UVK || typeof payload.key !== "string" || typeof payload.sha256 !== "string" || typeof payload.userId !== "string") {
    refuse("v1_malformed", "not a v1 uvk backstop key");
  }
  let keyBytes: Uint8Array;
  try {
    keyBytes = fromB64(payload.key);
  } catch {
    return refuse("v1_malformed", "v1 key is not base64url");
  }
  if (keyBytes.length !== 32) refuse("v1_malformed", "v1 key is not 32 bytes");
  const expected = toB64(await sha256(keyBytes));
  keyBytes.fill(0);
  if (!ctEquals(utf8(expected), utf8(payload.sha256))) refuse("v1_self_check_failed", "escrow payload self-check failed (sha256 mismatch)");
  return payload;
}

/** Open the fixed canary blob (spec 04 §4): a canary belongs to no member, so it has its own opener. */
export async function openCanary(recoveryKeypair: KeyPairBytes, sealed: Uint8Array): Promise<void> {
  const raw = fromUtf8(sealOpen(recoveryKeypair.publicKey, recoveryKeypair.privateKey, sealed));
  let payload: EscrowPayload;
  try {
    payload = JSON.parse(raw) as EscrowPayload;
  } catch (e) {
    throw new CryptoError("canary payload is not JSON", { cause: e });
  }
  if (payload.v !== 1 || payload.keyType !== KEY_TYPE_CANARY || payload.userId !== CANARY_USER_ID) throw new CryptoError("not the canary blob");
  const key = fromB64(payload.key);
  if (!ctEquals(key, CANARY_KEY) || toB64(await sha256(key)) !== payload.sha256) throw new CryptoError("canary payload mismatch");
}

/** spec 04 §1 — lowercase hex SHA-256 of the 32-byte public key. */
export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  return toHexLower(await sha256(publicKey));
}

/**
 * The legacy 16-hex (64-bit) short id of the org recovery key, kept ONLY because `seal.json` pins it.
 * Nothing compares or displays it any more (security review 2026-10, root cause A, branch A5): the admin
 * sheet-confirm and the in-person-QR `rfp` are full 64-hex compares (`matchesFull`). Do not add a caller.
 */
export async function shortFingerprint(publicKey: Uint8Array): Promise<string> {
  return (await fingerprint(publicKey)).slice(0, 16);
}

/**
 * spec 04 §2(3): at enrollment the user must TYPE the first 32 hex chars (128 bits) of the org
 * recovery fingerprint from the PRINTED sheet (the UI deliberately does not display them first).
 * Separators/whitespace/case tolerated; exactly 32 hex chars required. One shared helper
 * ({@link matchesShort}) backs both the recovery (here) and identity short forms.
 */
export function shortFormMatches(entry: string, fullFingerprintHex: string): boolean {
  return matchesShort(entry, fullFingerprintHex);
}
