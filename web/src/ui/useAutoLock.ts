import { useEffect, useRef, useState } from "react";
import { clampAutoLockSeconds } from "./policyclamp";

/**
 * Inactivity auto-lock (spec 01 §8, policy `autoLockSeconds`): after `timeoutSeconds`
 * with NO user interaction the vault locks via the same path as the manual Lock
 * button. "Activity" is pointer/key/touch only — background sync does not extend the
 * window.
 *
 * 0 disables the timer MECHANISM (createAutoLock/useAutoLock) — App passes 0 while no
 * vault is open. But POLICY resolution ({@link resolveAutoLockSeconds}) can no longer
 * produce 0: design 2026-07-15 §2.3 (B1-1) clamps the server-declared value into
 * `(0, AUTO_LOCK_MAX_SECONDS]`, so a hostile server's 0/absent/oversized window can
 * never disable the lock — only the client's own "nothing unlocked" state can.
 *
 * Clock choice: wall clock (Date.now) — time asleep/suspended must count as idle, so a
 * laptop that wakes past the window locks on the first check. `performance.now()`
 * pauses during suspend in some browsers and would come back "fresh".
 */

const CHECK_INTERVAL_MS = 1_000;
/** Coarse activity throttle: sub-second repeat events don't rewrite the timestamp. */
const ACTIVITY_THROTTLE_MS = 1_000;
/** Cut M (v2 #16): how far ahead of the lock the pre-warning surfaces. */
const WARNING_LEAD_MS = 30_000;
/** Cut M (v2 #16): windows this short (or shorter) get NO pre-warning — a 30 s lead on a
 *  60 s window would start nagging half-way through every idle pause. */
const WARNING_MIN_TIMEOUT_S = 60;

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
 *
 * Cut M (v2 #16): `onWarning` (optional) is edge-triggered — called with `true` when the
 * idle time crosses T-{@link WARNING_LEAD_MS} (only for windows > {@link WARNING_MIN_TIMEOUT_S})
 * and with `false` the moment activity resets the window or the lock itself fires. Never
 * re-fires per tick; the caller renders it, so it must be a clean boolean transition.
 */
export function createAutoLock(
  timeoutSeconds: number,
  onExpire: () => void,
  now: () => number = Date.now,
  onWarning?: (active: boolean) => void,
): AutoLockHandle {
  const disabled = !Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0;
  let last = now();
  let stopped = false;
  let timer: ReturnType<typeof setInterval> | undefined;

  // Idle threshold (ms) past which the pre-warning is up; Infinity = warning disabled
  // (short window or no listener), so the comparison below is always false.
  const warnAtMs = !disabled && timeoutSeconds > WARNING_MIN_TIMEOUT_S ? timeoutSeconds * 1_000 - WARNING_LEAD_MS : Infinity;
  let warned = false;
  const setWarned = (v: boolean) => {
    if (warned === v) return; // edge-triggered — quiet across the 1 s ticks in between
    warned = v;
    onWarning?.(v);
  };

  const check = () => {
    if (stopped || disabled) return;
    const idle = now() - last;
    if (idle >= timeoutSeconds * 1_000) {
      stopped = true; // fire exactly once; consumer teardown calls stop() anyway
      if (timer !== undefined) clearInterval(timer);
      setWarned(false); // the lock notice supersedes the warning banner
      onExpire();
      return;
    }
    setWarned(idle >= warnAtMs);
  };
  if (!disabled) timer = setInterval(check, CHECK_INTERVAL_MS);

  return {
    activity() {
      if (stopped || disabled) return;
      const n = now();
      if (n - last >= ACTIVITY_THROTTLE_MS) last = n;
      // Clear an active warning NOW, not at the next tick — the banner says "touch
      // anywhere to stay unlocked", so the touch must visibly land. (A throttled repeat
      // can't strand it: a live warning means >=30 s idle, far past the 1 s throttle.)
      setWarned(n - last >= warnAtMs);
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
 * the stored per-user fallback. Returns the seconds to arm the timer with, plus what
 * to persist (`null` = leave storage untouched — a failed fetch must not clobber the
 * fallback).
 *
 * design 2026-07-15 §2.3 (B1-1, supersedes the old "a fetched 0 is authoritative"
 * rule): every resolved value is CLAMPED into `(0, AUTO_LOCK_MAX_SECONDS]` — a
 * server-supplied 0/absent that would mean "never lock" clamps to the ceiling, an
 * oversized window clamps down, and the no-fetch-no-fallback cold case arms the
 * ceiling instead of disabling (a server that 404s the policy route must not win what
 * a declared 0 can't). Stale persisted values from the pre-clamp era (0, oversized)
 * are clamped on READ too, so they can't resurrect a disabled lock.
 */
export function resolveAutoLockSeconds(
  fetched: number | null,
  persisted: number | null,
): { seconds: number; persist: number | null } {
  if (fetched !== null && Number.isFinite(fetched)) {
    const v = clampAutoLockSeconds(fetched);
    return { seconds: v, persist: v };
  }
  return { seconds: clampAutoLockSeconds(persisted), persist: null };
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
 *
 * Cut M (v2 #16): returns the pre-warning flag — true while ~30 s remain before the lock
 * (windows > 60 s only). The same activity events that feed the timer clear it, so any
 * click/keypress/touch dismisses the caller's banner.
 */
export function useAutoLock(timeoutSeconds: number, onLock: () => void): boolean {
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;
  const [warning, setWarning] = useState(false);
  useEffect(() => {
    if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) return;
    const ctl = createAutoLock(timeoutSeconds, () => onLockRef.current(), Date.now, setWarning);
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
      setWarning(false); // a re-arm (policy change, lock, sign-out) must not strand a stale banner
      window.removeEventListener("pointerdown", activity, true);
      window.removeEventListener("keydown", activity, true);
      window.removeEventListener("touchstart", activity, true);
      document.removeEventListener("visibilitychange", vis);
    };
  }, [timeoutSeconds]);
  return warning;
}
