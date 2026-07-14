import { ApiError } from "../api/client";
import type { AccountKeys, RecoverySelfSetupResponse } from "../api/types";

/**
 * design 2026-07-12 §F.9 — the web vault-entry recovery-CAPTURE gate, as testable seams.
 *
 * `memberRecovery` is MANDATORY at register, so every account HAS a recovery piece — but a piece the
 * user never durably CONFIRMED saving (an interrupted reveal) is a silent-total-loss path for a waived
 * account, and the migration nudge for pre-flag accounts was consumed by no client. The durable,
 * cross-device signal is the server's per-user `recoveryConfirmed` flag. It flips two ways:
 *
 *   - ENROLL happy path (piece shown once + confirmed in-flow): POST /recovery/self/confirm — NO
 *     regenerate; the register-committed piece IS what the user saved.  → {@link settleRecoveryConfirm}
 *   - BLOCK path (Unlock / SignIn, flag still false): regenerate + PUT /recovery/self-setup to COMMIT the
 *     fresh piece (does NOT flip the flag — it runs on mount, before capture), SHOW it once, then — only
 *     after the type-back — POST /recovery/self/confirm. An interrupted reveal thus leaves recoveryConfirmed
 *     =false and the gate correctly re-fires.  → {@link setupAndCommitRecovery} + {@link settleRecoveryConfirm}
 *
 * design 2026-07-13 piece-binding: every confirm is BOUND (presents the `pieceId` minted for the piece
 * this surface revealed) and AWAITED — a `409 recovery_piece_stale` means a concurrent setup (another
 * device's gate) rotated the piece away, so the just-typed phrase is DEAD and must never be presented
 * as saved.
 *
 * Pinned as pure/async functions (house pattern: Admin's `escrowPostureLabel`, enroll's posture gate)
 * so the enroll-vs-block distinction — enroll never regenerates, block always does — can't silently
 * regress into re-clobbering the phrase the user already saved.
 */

/**
 * Should the vault-entry gate BLOCK on this account's server keys? fail-SAFE: `undefined` (an old
 * server that omits the field) ⇒ unconfirmed ⇒ gate. A re-nudge is harmless (the account keeps its
 * escrow backstop, if any, and simply re-runs setup-and-reveal); a false negative would be a silent
 * loss, so the polarity is deliberately "block unless we KNOW it's confirmed".
 */
export function needsRecoveryCapture(keys: Pick<AccountKeys, "recoveryConfirmed">): boolean {
  return keys.recoveryConfirmed !== true;
}

/** The two collaborators {@link setupAndCommitRecovery} needs — narrowed so a test can pass plain
 *  mocks (no full ApiClient / Account construction). */
interface SelfSetupClient {
  recoverySelfSetup(req: { currentAuthKey: string; memberRecovery: { recoveryWrappedUvk: string; recoveryAuthKey: string } }): Promise<RecoverySelfSetupResponse>;
}
interface RecoverableAccount {
  setupMemberRecovery(currentAuthKey: string): Promise<{
    request: { currentAuthKey: string; memberRecovery: { recoveryWrappedUvk: string; recoveryAuthKey: string } };
    recoverySecret: Uint8Array;
  }>;
}

/**
 * BLOCK-path capture (§F.9): regenerate a fresh recovery piece over the in-memory UVK and COMMIT it via
 * PUT /recovery/self-setup — which stores/rotates the piece but does NOT flip `recoveryConfirmed` (the
 * caller flips it via /recovery/self/confirm only after the type-back capture) — returning the raw secret
 * to SHOW ONCE through the un-skippable RecoveryReveal, plus the server-minted `pieceId` of the piece
 * just committed (design 2026-07-13: the confirm presents it, so it can never attest a piece a
 * concurrent setup rotated away; `null` from a pre-binding server ⇒ the legacy unbound confirm).
 * `currentAuthKey` is the login authKey the caller derived from the just-typed master password (the
 * server re-verifies it, like changePassword). On a failed commit the freshly-minted secret is ZEROED
 * and the error rethrown, so the caller keeps the gate closed (never proceeds to the vault) and
 * surfaces a retry — the raw secret is never left dangling.
 */
export async function setupAndCommitRecovery(
  client: SelfSetupClient,
  account: RecoverableAccount,
  currentAuthKey: string,
): Promise<{ recoverySecret: Uint8Array; pieceId: string | null }> {
  const { request, recoverySecret } = await account.setupMemberRecovery(currentAuthKey);
  try {
    const { pieceId } = await client.recoverySelfSetup(request);
    return { recoverySecret, pieceId: pieceId ?? null };
  } catch (e) {
    recoverySecret.fill(0);
    throw e;
  }
}

/** design 2026-07-13: true iff the server refused the confirm because the presented piece was rotated
 *  away (`409 recovery_piece_stale`) — the ONE outcome that must never proceed as if captured. */
function isStaleRecoveryPiece(e: unknown): boolean {
  return e instanceof ApiError && e.code === "recovery_piece_stale";
}

/**
 * Post-type-back confirm settlement (design 2026-07-13 piece-binding) — the ONE sequence both
 * surfaces (enroll reveal + vault-entry capture gate) follow, pinned here so neither can regress to
 * a fire-and-forget confirm. Zeroes the secret material FIRST (`zero` — the phrase's purpose is
 * over, captured or dead), then AWAITS the BOUND confirm and dispatches:
 *   - 200 → `onProceed`: captured; hand the account to the vault.
 *   - 409 `recovery_piece_stale` → `onStale`, NEVER `onProceed`: a concurrent setup rotated the
 *     piece away, so the typed phrase attests a DEAD piece — the gate shows the static notice and
 *     re-runs setup + reveal; enroll shows the notice and proceeds unconfirmed on acknowledgment.
 *   - anything else (network, 5xx) → `onProceed` unconfirmed (today's polarity): the flag stays 0,
 *     so the vault-entry gate re-fires at the next unlock and heals.
 */
export async function settleRecoveryConfirm(
  client: { recoverySelfConfirm(pieceId?: string | null): Promise<string> },
  pieceId: string | null,
  handlers: { zero: () => void; onStale: () => void; onProceed: () => void },
): Promise<void> {
  handlers.zero();
  try {
    await client.recoverySelfConfirm(pieceId);
  } catch (e) {
    if (isStaleRecoveryPiece(e)) return handlers.onStale();
    // Network/other refusal: never block the vault on a flap — unconfirmed, the re-gate heals.
  }
  handlers.onProceed();
}
