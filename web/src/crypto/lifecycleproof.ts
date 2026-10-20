import { ctEquals, fromB64, toB64, toHexLower, utf8 } from "./bytes";
import { hkdfSha256 } from "./hkdf";
import { hmacSha256, randomBytes, sha256 } from "./provider";

/**
 * Lifecycle proofs (spec 03 §11) — the TS mirror of core LifecycleProof.kt, byte-identical
 * (pinned by spec/test-vectors/lifecycleproof.json). Destructive shared-vault ops carry an
 * HMAC-SHA-256 under a key derived from the vault key VK (which the server never holds); a
 * 0.5.0 client verifies before treating a server's destructive claim as an owner action.
 * MACs, not signatures — they remove only the server from the forgery set.
 *
 * Domain strings: `|`-joined UTF-8; integers decimal; the accept proof embeds lowercase-hex
 * SHA-256 of the posted wrappedVk string's UTF-8 bytes. Proof values are base64url, unpadded.
 */
const LIFECYCLE_INFO = "andvari/v1|lifecycle";

/** lifecycleKey = HKDF-SHA-256(ikm = VK, salt = "", info = "andvari/v1|lifecycle", 32). */
export function lifecycleKey(vk: Uint8Array): Promise<Uint8Array> {
  return hkdfSha256(vk, new Uint8Array(0), utf8(LIFECYCLE_INFO), 32);
}

async function mac(key: Uint8Array, domain: string): Promise<string> {
  return toB64(await hmacSha256(key, utf8(domain)));
}

/** Ad.join parity (F33: a check, not a comment) — mirror of core requireDomainSafe: several of
 *  these components arrive on server rows, and a `|` inside one would shift the tuple boundaries
 *  so two different tuples MAC identically. Conforming values (UUIDs, hex, base64url) can never
 *  contain `|`, so honest input — and the lifecycleproof.json vectors — never trips this. On the
 *  verify side every recompute site is try/catch-wrapped (store.verifyRemoval, the transfer
 *  verifies), so a throw degrades to "unverified" → retain-and-warn, exactly like a bad proof. */
function requireDomainSafe(...parts: string[]): void {
  for (const p of parts) {
    if (p.includes("|")) throw new Error("lifecycle proof component must not contain '|'");
  }
}

export const deleteProof = (key: Uint8Array, vaultId: string, deleteId: string): Promise<string> => {
  requireDomainSafe(vaultId, deleteId);
  return mac(key, `andvari/v1|lifecycle|delete|${vaultId}|${deleteId}`);
};

export const restoreProof = (key: Uint8Array, vaultId: string, deleteId: string): Promise<string> => {
  requireDomainSafe(vaultId, deleteId);
  return mac(key, `andvari/v1|lifecycle|restore|${vaultId}|${deleteId}`);
};

export const offerProof = (
  key: Uint8Array,
  vaultId: string,
  offerId: string,
  toUserId: string,
  expiresAt: number,
  seq: number,
): Promise<string> => {
  requireDomainSafe(vaultId, offerId, toUserId);
  return mac(key, `andvari/v1|lifecycle|transfer|${vaultId}|${offerId}|${toUserId}|${expiresAt}|${seq}`);
};

export async function acceptProof(
  key: Uint8Array,
  vaultId: string,
  offerId: string,
  newOwnerUserId: string,
  seq: number,
  wrappedVk: string,
): Promise<string> {
  return acceptProofFromHash(key, vaultId, offerId, newOwnerUserId, seq, toHexLower(await sha256(utf8(wrappedVk))));
}

/**
 * Accept proof from the wrap HASH directly (spec 03 §11): other members receive only
 * `lastTransfer.wrapHash` (= hexLower(sha256(utf8(wrappedVk)))), never the new owner's
 * wrappedVk blob, yet must re-verify the seq-chained acceptProof to trust the ownership
 * flip. Byte-identical domain to acceptProof — the accepter passes its own wrappedVk.
 */
export const acceptProofFromHash = (
  key: Uint8Array,
  vaultId: string,
  offerId: string,
  newOwnerUserId: string,
  seq: number,
  wrapHash: string,
): Promise<string> => {
  requireDomainSafe(vaultId, offerId, newOwnerUserId, wrapHash);
  return mac(key, `andvari/v1|lifecycle|transfer-accept|${vaultId}|${offerId}|${newOwnerUserId}|${seq}|${wrapHash}`);
};

export const removeProof = (key: Uint8Array, vaultId: string, targetUserId: string, nonce: string): Promise<string> => {
  requireDomainSafe(vaultId, targetUserId, nonce);
  return mac(key, `andvari/v1|lifecycle|remove|${vaultId}|${targetUserId}|${nonce}`);
};

/** Constant-time compare of a presented base64url proof against the expected value. */
export function verifyProof(expected: string, presented: string): boolean {
  try {
    return ctEquals(fromB64(expected), fromB64(presented));
  } catch {
    return false;
  }
}

// ---- removal proofs v2 (security review 2026-10, root cause A §6; branch A7; core LifecycleProof/RemovalProof twin) ----

/** `andvari/v1|lifecycle|remove-v2|{vaultId}|{targetUserId}|{nonce}|{issuedAt}`. */
export const removeV2Proof = (key: Uint8Array, vaultId: string, targetUserId: string, nonce: string, issuedAt: number): Promise<string> => {
  requireDomainSafe(vaultId, targetUserId, nonce);
  return mac(key, `andvari/v1|lifecycle|remove-v2|${vaultId}|${targetUserId}|${nonce}|${issuedAt}`);
};

/** `andvari/v1|lifecycle|leave|{vaultId}|{userId}|{nonce}|{issuedAt}`: minted by the LEAVING member's client. */
export const leaveProof = (key: Uint8Array, vaultId: string, userId: string, nonce: string, issuedAt: number): Promise<string> => {
  requireDomainSafe(vaultId, userId, nonce);
  return mac(key, `andvari/v1|lifecycle|leave|${vaultId}|${userId}|${nonce}|${issuedAt}`);
};

/** A fresh v2 nonce: 16 CSPRNG bytes, base64url unpadded. */
export function newRemovalNonce(): string {
  return toB64(randomBytes(16));
}

/**
 * The grammar a v1 (legacy) removal nonce must have to be VERIFIED at all (A10 review LOW-1): the token grammar the
 * consumed record stores (trustrecords.ts ConsumedNonceRow, `[A-Za-z0-9_-]{1,128}`). Pre-A7 clients minted a UUID,
 * the vectors carry base64url too; both fit. A nonce the consumed record could not represent would be verified but
 * never consumed, and so replay on that browser — it is refused before any MAC instead. Core `isLegacyNonce` twin.
 */
export const LEGACY_NONCE_RE = /^[A-Za-z0-9_-]{1,128}$/;

export function isLegacyNonce(nonce: string): boolean {
  return LEGACY_NONCE_RE.test(nonce);
}

/** True for a well-formed v2 nonce: base64url that decodes to exactly 16 bytes and re-encodes to itself. */
export function isV2Nonce(nonce: string): boolean {
  try {
    const raw = fromB64(nonce);
    return raw.length === 16 && toB64(raw) === nonce;
  } catch {
    return false;
  }
}

/** ±10 minutes of clock skew around liveSince and now (§6.3 step 6). */
export const REMOVAL_SKEW_MS = 10 * 60 * 1000;

export type RemovalVerdict = "valid" | "valid_legacy" | "left_unproven" | "anomaly" | "replay_denied" | "already_recorded";

export interface RemovalDecision {
  verdict: RemovalVerdict;
  /** The §6.3 step that decided it. */
  step: string;
  /** For a valid verdict: the record to consume, `[nonce, issuedAt]`. */
  consume?: [string, number];
}

/**
 * The removal-proof verifier (root cause A §6.3, §8.6; branch A7) — core `RemovalProof.decide` twin, graded by
 * spec/test-vectors/lifecycleproof.json `verdicts`, and THE function store.ts calls on every removed/left row. The
 * caller handles `deleted` and a self-initiated drop first. Steps in order, first failure wins: (3) a complete v2
 * proof, else the in-window legacy rows (a v1 remove proof whose MAC verifies and whose nonce is unconsumed is
 * "valid_legacy"; a proof-less `left` is "left_unproven"); (4) the MAC for the reason's domain, target = me;
 * (5) the nonce not in THIS device's consumed set, else "replay_denied"; (6) liveSince − 10 min ≤ issuedAt ≤
 * now + 10 min, liveSince being THIS device's own first sight (missing → fail closed); (6′, A7 review MEDIUM-2) a
 * nonce found only in the account-state set is "already_recorded" (another of my devices consumed it; calm).
 * (6″, A13 c10) a v1 proof has no issuedAt, so for a v1 nonce found only in account state the time that record was
 * consumed (`consumedAccountAt`) gets the same window: outside it, or with no time or no liveSince, "anomaly" at step
 * "window" (a replay after a re-add, as on v2); inside it "already_recorded", consumed at the RECORDED time.
 */
export async function decideRemoval(input: {
  lifecycleKey: Uint8Array;
  vaultId: string;
  myUserId: string;
  reason: string;
  proofV?: number | null;
  proof?: string | null;
  nonce?: string | null;
  issuedAt?: number | null;
  consumed: ReadonlySet<string>;
  consumedAccount: ReadonlySet<string>;
  /** A13 (c10): when each `consumedAccount` nonce was consumed (account-state `[nonce, at]`). Only the v1 path reads it. */
  consumedAccountAt?: ReadonlyMap<string, number>;
  liveSince: number | null | undefined;
  now: number;
}): Promise<RemovalDecision> {
  const { lifecycleKey: key, vaultId, myUserId, reason, proof, nonce, issuedAt, consumed, consumedAccount, liveSince, now } = input;
  const proofV = input.proofV ?? null;
  if (reason !== "removed" && reason !== "left") return { verdict: "anomaly", step: "reason" };
  if (proofV !== 2) {
    if (proofV !== null && proofV !== 1) return { verdict: "anomaly", step: "fields" };
    if (reason === "left") {
      return (proof ?? null) === null && (nonce ?? null) === null ? { verdict: "left_unproven", step: "legacy" } : { verdict: "anomaly", step: "fields" };
    }
    if (!proof || !nonce) return { verdict: "anomaly", step: "fields" };
    // A10 review LOW-1: a nonce the consumed record cannot hold is never verified (it could not be consumed).
    if (!isLegacyNonce(nonce)) return { verdict: "anomaly", step: "fields" };
    let expected: string;
    try {
      expected = await removeProof(key, vaultId, myUserId, nonce);
    } catch {
      return { verdict: "anomaly", step: "mac" };
    }
    if (!verifyProof(expected, proof)) return { verdict: "anomaly", step: "mac" };
    if (consumed.has(nonce)) return { verdict: "replay_denied", step: "nonce" };
    if (consumedAccount.has(nonce)) {
      // Step 6″ (A13, c10): the account-state record's time is the only time a v1 removal has.
      const at = input.consumedAccountAt?.get(nonce);
      if (liveSince == null || at === undefined || at < liveSince - REMOVAL_SKEW_MS || at > now + REMOVAL_SKEW_MS) return { verdict: "anomaly", step: "window" };
      return { verdict: "already_recorded", step: "recorded", consume: [nonce, at] };
    }
    return { verdict: "valid_legacy", step: "legacy", consume: [nonce, now] };
  }
  if (!proof || nonce == null || issuedAt == null || !Number.isSafeInteger(issuedAt) || !isV2Nonce(nonce)) return { verdict: "anomaly", step: "fields" };
  let expected: string;
  try {
    expected = reason === "removed" ? await removeV2Proof(key, vaultId, myUserId, nonce, issuedAt) : await leaveProof(key, vaultId, myUserId, nonce, issuedAt);
  } catch {
    return { verdict: "anomaly", step: "mac" };
  }
  if (!verifyProof(expected, proof)) return { verdict: "anomaly", step: "mac" };
  if (consumed.has(nonce)) return { verdict: "replay_denied", step: "nonce" };
  if (liveSince == null || issuedAt < liveSince - REMOVAL_SKEW_MS || issuedAt > now + REMOVAL_SKEW_MS) return { verdict: "anomaly", step: "window" };
  if (consumedAccount.has(nonce)) return { verdict: "already_recorded", step: "recorded", consume: [nonce, issuedAt] };
  return { verdict: "valid", step: "valid", consume: [nonce, issuedAt] };
}
