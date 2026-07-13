import type { AccountKeys } from "../api/types";

/**
 * design 2026-07-12 §F.9 — the web vault-entry recovery-CAPTURE gate, as testable seams.
 *
 * `memberRecovery` is MANDATORY at register, so every account HAS a recovery piece — but a piece the
 * user never durably CONFIRMED saving (an interrupted reveal) is a silent-total-loss path for a waived
 * account, and the migration nudge for pre-flag accounts was consumed by no client. The durable,
 * cross-device signal is the server's per-user `recoveryConfirmed` flag. It flips two ways:
 *
 *   - ENROLL happy path (piece shown once + confirmed in-flow): POST /recovery/self/confirm — NO
 *     regenerate; the register-committed piece IS what the user saved.  → {@link ApiClient.recoverySelfConfirm}
 *   - BLOCK path (Unlock / SignIn, flag still false): regenerate + PUT /recovery/self-setup to COMMIT the
 *     fresh piece (does NOT flip the flag — it runs on mount, before capture), SHOW it once, then — only
 *     after the type-back — POST /recovery/self/confirm. An interrupted reveal thus leaves recoveryConfirmed
 *     =false and the gate correctly re-fires.  → {@link setupAndCommitRecovery} + {@link confirmRegisteredRecovery}
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
  recoverySelfSetup(req: { currentAuthKey: string; memberRecovery: { recoveryWrappedUvk: string; recoveryAuthKey: string } }): Promise<string>;
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
 * to SHOW ONCE through the un-skippable RecoveryReveal. `currentAuthKey` is the login authKey the caller
 * derived from the just-typed master password (the server re-verifies it, like changePassword). On a
 * failed commit the freshly-minted secret is ZEROED and the error rethrown, so the caller keeps the
 * gate closed (never proceeds to the vault) and surfaces a retry — the raw secret is never left dangling.
 */
export async function setupAndCommitRecovery(
  client: SelfSetupClient,
  account: RecoverableAccount,
  currentAuthKey: string,
): Promise<Uint8Array> {
  const { request, recoverySecret } = await account.setupMemberRecovery(currentAuthKey);
  try {
    await client.recoverySelfSetup(request);
  } catch (e) {
    recoverySecret.fill(0);
    throw e;
  }
  return recoverySecret;
}

/**
 * ENROLL happy-path confirm (§F.9): flip the server flag AFTER the user saved + confirmed the
 * register-committed phrase. Distinct from the block path — it must NEVER regenerate (that would
 * clobber the very piece the user just wrote down). Best-effort at the call site: a failure only
 * re-nudges on the next unlock via the block path.
 */
export function confirmRegisteredRecovery(client: { recoverySelfConfirm(): Promise<string> }): Promise<string> {
  return client.recoverySelfConfirm();
}
