import { AUTO_LOCK_MAX_SECONDS, CLIPBOARD_CLEAR_MAX_SECONDS } from "../api/types";

/**
 * Policy-timer clamps (design 2026-07-15-multi-tenant-endpoints §2.3, breaker B1-1). The
 * `ClientPolicy` timers arrive from an UNAUTHENTICATED endpoint on an untrusted server, and both
 * are CLIENT-FLOOR-ONLY fields: a server may make this client safer, never laxer. Before these
 * clamps, a hostile server could send `autoLockSeconds: 0` ("never lock") or a huge
 * `clipboardClearSeconds` ("pin the clipboard for hours") and the client obeyed — the only guards
 * were `Math.max(0, …)` / `Math.max(1, …)`, floors with no ceiling.
 *
 * Each timer clamps toward its OWN safe direction:
 *  - auto-lock: 0 / absent / garbage / oversized ⇒ the CEILING ({@link AUTO_LOCK_MAX_SECONDS}) —
 *    a server cannot disable the idle lock, but a "never lock" lie degrades to the most generous
 *    window rather than a hair-trigger one. Small positive values pass through (locking sooner is
 *    strictly safer).
 *  - clipboard-clear: garbage ⇒ the FLOOR (1 s — wipe fast), oversized ⇒ the ceiling
 *    ({@link CLIPBOARD_CLEAR_MAX_SECONDS}) — a secret can never sit on the clipboard past the cap.
 *
 * The ceilings are the byte-pinned core/web/ext constants (policy-clamps.test.ts); a raise ships
 * as a client build constant, never a server value (design §11.5). Applied at the web resolution
 * points: resolveAutoLockSeconds (useAutoLock.ts) and the two clipboard-copy timers (Vault.useCopy,
 * Welcome.RecoveryReveal). The monotonicity suite (policy-monotonicity.test.ts) pins both.
 */

/** Effective auto-lock window: `(0, AUTO_LOCK_MAX_SECONDS]`, never 0/disabled from a server value. */
export function clampAutoLockSeconds(value: number | null | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return AUTO_LOCK_MAX_SECONDS;
  return Math.min(value, AUTO_LOCK_MAX_SECONDS);
}

/** Effective clipboard-clear window: `[1, CLIPBOARD_CLEAR_MAX_SECONDS]`. */
export function clampClipboardClearSeconds(value: number | null | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return 1;
  return Math.min(Math.max(1, value), CLIPBOARD_CLEAR_MAX_SECONDS);
}
