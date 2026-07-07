import { useEffect, useRef } from "react";

/**
 * Inactivity auto-lock (spec 01 §8, policy `autoLockSeconds`): after `timeoutSeconds`
 * with NO user interaction the vault locks via the same path as the manual Lock
 * button. "Activity" is pointer/key/touch only — background sync does not extend the
 * window. 0 (or a missing policy) disables the timer entirely.
 *
 * Clock choice: wall clock (Date.now) — time asleep/suspended must count as idle, so a
 * laptop that wakes past the window locks on the first check. `performance.now()`
 * pauses during suspend in some browsers and would come back "fresh".
 */

const CHECK_INTERVAL_MS = 1_000;
/** Coarse activity throttle: sub-second repeat events don't rewrite the timestamp. */
const ACTIVITY_THROTTLE_MS = 1_000;

export interface AutoLockHandle {
  /** Record user interaction (throttled to >=1 s granularity). */
  activity(): void;
  /** Immediate expiry check — used on visibilitychange (background timers are throttled). */
  checkNow(): void;
  /** Tear down; guarantees onExpire never fires afterwards. */
  stop(): void;
}

/**
 * DOM-free timer core (unit-tested in useAutoLock.test.ts). Checks expiry on a 1 s
 * interval rather than one long setTimeout so a forward wall-clock jump (sleep, NTP)
 * is noticed at the next tick instead of stretching the deadline. Fires at most once.
 */
export function createAutoLock(timeoutSeconds: number, onExpire: () => void, now: () => number = Date.now): AutoLockHandle {
  const disabled = !Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0;
  let last = now();
  let stopped = false;
  let timer: ReturnType<typeof setInterval> | undefined;

  const check = () => {
    if (stopped || disabled) return;
    if (now() - last >= timeoutSeconds * 1_000) {
      stopped = true; // fire exactly once; consumer teardown calls stop() anyway
      if (timer !== undefined) clearInterval(timer);
      onExpire();
    }
  };
  if (!disabled) timer = setInterval(check, CHECK_INTERVAL_MS);

  return {
    activity() {
      if (stopped || disabled) return;
      const n = now();
      if (n - last >= ACTIVITY_THROTTLE_MS) last = n;
    },
    checkNow: check,
    stop() {
      stopped = true;
      if (timer !== undefined) clearInterval(timer);
    },
  };
}

// ---- policy fallback (spec 01 §8) ----

const AUTOLOCK_KEY_PREFIX = "andvari.autoLockSeconds.";

/**
 * spec 01 §8: the natives persist the last-known `autoLockSeconds` (Android
 * SessionStore / desktop equivalent) so a policy fetch that fails — a transient 5xx
 * right after login, an offline start — never silently disables the idle lock. This
 * is the web twin's pure resolution core (unit-tested): [fetched] is the CURRENT
 * fetch's value (`null` = the fetch failed and no policy object exists), [persisted]
 * the stored per-user fallback. A successful fetch is authoritative — INCLUDING a
 * genuine 0 ("disabled"), which must overwrite a stale non-zero fallback and never be
 * resurrected by it. Returns the seconds to arm the timer with, plus what to persist
 * (`null` = leave storage untouched — a failed fetch must not clobber the fallback).
 */
export function resolveAutoLockSeconds(
  fetched: number | null,
  persisted: number | null,
): { seconds: number; persist: number | null } {
  if (fetched !== null && Number.isFinite(fetched)) {
    const v = Math.max(0, fetched);
    return { seconds: v, persist: v };
  }
  const fallback = persisted !== null && Number.isFinite(persisted) ? Math.max(0, persisted) : 0;
  return { seconds: fallback, persist: null };
}

/** Last successfully fetched value for [userId], or null when none is stored (or
 *  storage is unavailable / holds garbage). Same guard pattern as plan.ts. */
export function readPersistedAutoLockSeconds(userId: string): number | null {
  if (typeof localStorage === "undefined") return null;
  const raw = localStorage.getItem(AUTOLOCK_KEY_PREFIX + userId);
  if (raw === null) return null;
  const n = Number(raw);
  return raw !== "" && Number.isFinite(n) && n >= 0 ? n : null;
}

export function writePersistedAutoLockSeconds(userId: string, seconds: number): void {
  if (typeof localStorage === "undefined") return;
  localStorage.setItem(AUTOLOCK_KEY_PREFIX + userId, String(seconds));
}

/**
 * React binding: listens for pointerdown/keydown/touchstart in the CAPTURE phase (a
 * stopPropagation inside the app can't starve the timer) and re-checks expiry the
 * moment the tab becomes visible again (background tabs throttle intervals, so the
 * lock for an expired hidden tab lands on return, before the user can read anything
 * beyond one frame). Pass 0 while locked/logged out to disable.
 */
export function useAutoLock(timeoutSeconds: number, onLock: () => void): void {
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;
  useEffect(() => {
    if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) return;
    const ctl = createAutoLock(timeoutSeconds, () => onLockRef.current());
    const activity = () => ctl.activity();
    const vis = () => {
      if (document.visibilityState === "visible") ctl.checkNow();
    };
    window.addEventListener("pointerdown", activity, true);
    window.addEventListener("keydown", activity, true);
    window.addEventListener("touchstart", activity, true);
    document.addEventListener("visibilitychange", vis);
    return () => {
      ctl.stop();
      window.removeEventListener("pointerdown", activity, true);
      window.removeEventListener("keydown", activity, true);
      window.removeEventListener("touchstart", activity, true);
      document.removeEventListener("visibilitychange", vis);
    };
  }, [timeoutSeconds]);
}
