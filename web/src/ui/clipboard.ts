/**
 * ux-error--2 (polish audit 2026-07-27): `navigator.clipboard.writeText` REJECTS in real
 * conditions — "Document is not focused" (click-then-alt-tab), a permissions-policy denial in an
 * embedded context, some Firefox configs — and every copy button here used to fire it unawaited,
 * so the failure surfaced only as an unhandled rejection in the console while the user believed
 * their password was on the clipboard. One guarded write behind every copy surface in the web
 * client — Vault's useCopy (item password / TOTP / PAN / CVV / …), Settings' CopyButton (identity
 * code, TOTP setup material), Admin's invite token + enrollment link, and Welcome's recovery
 * phrase: it resolves false instead of ever rejecting; callers render {@link CLIPBOARD_FAILED}
 * (the extension toClipboard's twin behavior — popup.ts shows the same sentence on its catch).
 */
export async function writeClipboard(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

/** What became of a scheduled auto-clear: the clipboard really was blanked, or the platform
 *  refused the wipe and the secret is STILL on it (a retry is armed for the next focus). */
export type ClipboardClearOutcome = "cleared" | "stuck";

/**
 * The auto-clear half of a SECRET copy, as one module-scope slot (audit F05).
 *
 * Two defects this replaces, both on the same mechanism:
 *  - the wipe used to live in per-component refs. `useCopy` is instantiated per `Detail`, and
 *    Detail unmounts on every back-to-list, so the pending timer id was discarded while the
 *    timer kept running: copy A, go back, copy B, and A's orphan blanked B's password mid-window.
 *    ONE slot per document — the newest copy owns the clear (the extension popup's AM2 idiom,
 *    which the web docblocks already claimed parity with). Note the wipe itself is never
 *    cancelled on unmount: a wipe firing after the view is gone is exactly the hygiene we want.
 *  - the wipe was a bare unretried `writeText("")` whose rejection was discarded — and the
 *    dominant flow (copy → alt-tab → paste) is precisely when the document is unfocused and the
 *    write REJECTS, so the secret stayed on the clipboard while the UI said it had been cleared.
 *    A refused wipe now arms a one-shot focus/visibility retry and tells its owner "stuck", so
 *    the surface can stop asserting a clear that did not happen.
 */
let clearTimer: number | null = null;
let clearOwner: ((outcome: ClipboardClearOutcome) => void) | null = null;
let retryHandler: (() => void) | null = null;

function detachRetry(): void {
  if (!retryHandler) return;
  document.removeEventListener("visibilitychange", retryHandler);
  window.removeEventListener("focus", retryHandler);
  retryHandler = null;
}

async function attemptClear(): Promise<void> {
  const owner = clearOwner;
  if (await writeClipboard("")) {
    detachRetry();
    owner?.("cleared");
    return;
  }
  // Refused (almost always: the document isn't focused). Say so, then retry the moment this
  // document is looked at again — the one event that reliably makes the write permissible.
  owner?.("stuck");
  detachRetry();
  retryHandler = () => {
    if (document.visibilityState === "hidden") return; // still in the background — wait for the next event
    detachRetry();
    void attemptClear();
  };
  document.addEventListener("visibilitychange", retryHandler);
  window.addEventListener("focus", retryHandler);
}

/**
 * Arm the single auto-clear slot: blank the clipboard `seconds` from now, replacing whatever
 * earlier copy held it. `onOutcome` belongs to the copy that armed it and is dropped the moment
 * a newer copy takes the slot — a stale surface must never be told about someone else's wipe.
 * Callers clamp `seconds` (policyclamp) before arming; this only owns the timing slot.
 */
export function scheduleClipboardClear(seconds: number, onOutcome?: (outcome: ClipboardClearOutcome) => void): void {
  if (clearTimer !== null) window.clearTimeout(clearTimer);
  detachRetry();
  clearOwner = onOutcome ?? null;
  clearTimer = window.setTimeout(() => {
    clearTimer = null;
    void attemptClear();
  }, seconds * 1000);
}

/** Test seam only — drop the live slot so one spec's armed wipe can't fire inside the next. */
export function resetClipboardClearForTest(): void {
  if (clearTimer !== null) window.clearTimeout(clearTimer);
  clearTimer = null;
  clearOwner = null;
  detachRetry();
}
