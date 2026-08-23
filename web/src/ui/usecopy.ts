import { useRef, useState } from "react";
import { scheduleClipboardClear, writeClipboard } from "./clipboard";
import { clampClipboardClearSeconds } from "./policyclamp";

/**
 * The shared "copy a secret to the clipboard" hook — flash label, failure flag, and the
 * auto-clear timer, in one place.
 *
 * Extracted from Vault.tsx (2026-08-22) when the verification run became a second consumer.
 * It is deliberately ONE owner: the clamp, the single-live-timer rule and the
 * platform-refused-the-wipe flag below are each the fix for a specific shipped bug, and a
 * second hand-rolled copy path in another view would re-open all three.
 */
export function useCopy(clearSeconds: number) {
  const [flash, setFlash] = useState<string | null>(null);
  const [copyErr, setCopyErr] = useState(false);
  // Audit F05: the platform refused the auto-clear, so the value is STILL on the clipboard —
  // the surfaces below retract the "clears in Ns" promise instead of leaving it standing.
  const [wipeStuck, setWipeStuck] = useState(false);
  const flashTimer = useRef<number | null>(null);
  const copy = async (label: string, value: string) => {
    // ux-error--2: writeText rejects in real conditions ("Document is not focused",
    // permissions-policy) and every call site is fire-and-forget — surface the canon
    // sentence instead of an unhandled rejection over a clipboard that got nothing.
    if (!(await writeClipboard(value))) {
      setFlash(null);
      setCopyErr(true);
      return;
    }
    setCopyErr(false);
    setWipeStuck(false);
    setFlash(label);
    // Cut J (v2 #10, review fix): the flash-timer id was never STORED, so the dedupe guard
    // was dead code; and each copy stacked a fresh unconditional wipe — copying B after A
    // let A's stale timer blank the clipboard mid-way through B's window. One live timer each.
    if (flashTimer.current) window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash((f) => (f === label ? null : f)), 2600);
    // Audit F05: the wipe slot is MODULE scope (clipboard.ts), not a per-instance ref — this
    // hook is re-instantiated per Detail and Detail unmounts on every back-to-list, so the ref
    // dropped the pending id while the timer kept running and A's orphan blanked B's password.
    // Clamped into [1, CLIPBOARD_CLEAR_MAX_SECONDS] (design 2026-07-15 §2.3, B1-1) at the timer
    // itself — belt to the caller-side clamp; no useCopy consumer can pin the clipboard.
    scheduleClipboardClear(clampClipboardClearSeconds(clearSeconds), (outcome) => setWipeStuck(outcome === "stuck"));
  };
  return { flash, copyErr, wipeStuck, copy };
}
