import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createAutoLock,
  readPersistedAutoLockSeconds,
  resolveAutoLockSeconds,
  writePersistedAutoLockSeconds,
} from "./useAutoLock";

/**
 * Pure timer core tests. Time is driven two ways in lockstep: an injected now() (what
 * expiry compares) and vitest fake timers (what schedules the 1 s checks) — so the
 * tests are deterministic regardless of whether the fake clock also patches Date.
 */
describe("createAutoLock", () => {
  let t: number;
  const now = () => t;

  beforeEach(() => {
    t = 100_000;
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const advance = (ms: number) => {
    t += ms;
    vi.advanceTimersByTime(ms);
  };

  it("fires once after the timeout with no activity", () => {
    const onExpire = vi.fn();
    const ctl = createAutoLock(30, onExpire, now);
    advance(29_000);
    expect(onExpire).not.toHaveBeenCalled();
    advance(2_000);
    expect(onExpire).toHaveBeenCalledTimes(1);
    advance(120_000); // never re-fires
    expect(onExpire).toHaveBeenCalledTimes(1);
    ctl.stop();
  });

  it("activity resets the window", () => {
    const onExpire = vi.fn();
    const ctl = createAutoLock(30, onExpire, now);
    advance(25_000);
    ctl.activity();
    advance(25_000);
    expect(onExpire).not.toHaveBeenCalled(); // only 25 s since last activity
    advance(6_000);
    expect(onExpire).toHaveBeenCalledTimes(1);
    ctl.stop();
  });

  it("throttles sub-second repeat activity (coarse >=1 s granularity)", () => {
    const onExpire = vi.fn();
    const ctl = createAutoLock(30, onExpire, now);
    advance(10_000);
    ctl.activity(); // resets the window to t=110s
    t += 400;
    ctl.activity(); // 400 ms later — sub-second repeat, must NOT move the timestamp
    t -= 400;
    advance(29_000); // 29 s since the FIRST of the pair
    expect(onExpire).not.toHaveBeenCalled();
    advance(1_000); // 30 s since the first — the ignored repeat didn't stretch it
    expect(onExpire).toHaveBeenCalledTimes(1);
    ctl.stop();
  });

  it("0 / negative / NaN timeout disables entirely", () => {
    for (const timeout of [0, -5, Number.NaN]) {
      const onExpire = vi.fn();
      const ctl = createAutoLock(timeout, onExpire, now);
      advance(3_600_000);
      ctl.checkNow();
      expect(onExpire).not.toHaveBeenCalled();
      ctl.stop();
    }
  });

  it("checkNow fires immediately when the window passed while ticks were throttled", () => {
    const onExpire = vi.fn();
    const ctl = createAutoLock(30, onExpire, now);
    // Simulate a hidden tab: wall clock jumps far ahead without interval ticks running.
    t += 3_600_000;
    ctl.checkNow();
    expect(onExpire).toHaveBeenCalledTimes(1);
    ctl.stop();
  });

  it("stop() prevents any later fire", () => {
    const onExpire = vi.fn();
    const ctl = createAutoLock(30, onExpire, now);
    ctl.stop();
    advance(120_000);
    ctl.checkNow();
    expect(onExpire).not.toHaveBeenCalled();
  });
});

/**
 * Cut M (v2 #16) pre-lock warning: edge-triggered onWarning(true) at T-30 s so the caller
 * can surface a "locking soon" banner before unsaved editor work is destroyed; any
 * activity (the same events that feed the timer) clears it, and windows <= 60 s never
 * warn at all — a 30 s lead there would nag half-way through every idle pause.
 */
describe("pre-lock warning (Cut M v2 #16)", () => {
  let t: number;
  const now = () => t;

  beforeEach(() => {
    t = 100_000;
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const advance = (ms: number) => {
    t += ms;
    vi.advanceTimersByTime(ms);
  };

  it("fires once at T-30 s and is withdrawn when the lock itself lands", () => {
    const onExpire = vi.fn();
    const onWarning = vi.fn();
    const ctl = createAutoLock(90, onExpire, now, onWarning);
    advance(59_000); // 31 s remain — still quiet
    expect(onWarning).not.toHaveBeenCalled();
    advance(1_000); // 60 s idle = T-30
    expect(onWarning).toHaveBeenCalledTimes(1);
    expect(onWarning).toHaveBeenLastCalledWith(true);
    advance(20_000); // edge-triggered: the ticks inside the window don't re-fire
    expect(onWarning).toHaveBeenCalledTimes(1);
    advance(10_000); // 90 s → lock; the lock notice supersedes the banner
    expect(onExpire).toHaveBeenCalledTimes(1);
    expect(onWarning).toHaveBeenCalledTimes(2);
    expect(onWarning).toHaveBeenLastCalledWith(false);
    ctl.stop();
  });

  it("activity clears an active warning immediately, then it re-arms for the next approach", () => {
    const onExpire = vi.fn();
    const onWarning = vi.fn();
    const ctl = createAutoLock(90, onExpire, now, onWarning);
    advance(61_000);
    expect(onWarning).toHaveBeenLastCalledWith(true);
    ctl.activity(); // the banner says "touch anywhere" — no waiting for the next tick
    expect(onWarning).toHaveBeenCalledTimes(2);
    expect(onWarning).toHaveBeenLastCalledWith(false);
    advance(59_000); // only 59 s since the touch — quiet
    expect(onWarning).toHaveBeenCalledTimes(2);
    advance(1_000); // T-30 of the NEW window
    expect(onWarning).toHaveBeenCalledTimes(3);
    expect(onWarning).toHaveBeenLastCalledWith(true);
    expect(onExpire).not.toHaveBeenCalled();
    ctl.stop();
  });

  it("never fires for windows of 60 s or less — the lock still lands normally", () => {
    for (const timeout of [60, 45, 30]) {
      const onExpire = vi.fn();
      const onWarning = vi.fn();
      const ctl = createAutoLock(timeout, onExpire, now, onWarning);
      advance(timeout * 1_000 + 5_000);
      expect(onExpire).toHaveBeenCalledTimes(1);
      expect(onWarning).not.toHaveBeenCalled();
      ctl.stop();
    }
  });

  it("checkNow raises the warning when a hidden tab returns inside the window", () => {
    const onExpire = vi.fn();
    const onWarning = vi.fn();
    const ctl = createAutoLock(90, onExpire, now, onWarning);
    // Wall clock jumps 65 s with no interval ticks (throttled background tab).
    t += 65_000;
    ctl.checkNow();
    expect(onWarning).toHaveBeenCalledTimes(1);
    expect(onWarning).toHaveBeenLastCalledWith(true);
    expect(onExpire).not.toHaveBeenCalled();
    ctl.stop();
  });
});

/**
 * spec 01 §8 policy fallback (native SessionStore parity): a transient policy-fetch
 * failure right after login must NOT silently disable the lock — the last
 * successfully fetched value takes over; a genuinely fetched 0 stays authoritative.
 */
describe("resolveAutoLockSeconds", () => {
  it("uses AND persists a successfully fetched value — including 0 (disabled)", () => {
    expect(resolveAutoLockSeconds(60, null)).toEqual({ seconds: 60, persist: 60 });
    expect(resolveAutoLockSeconds(60, 300)).toEqual({ seconds: 60, persist: 60 }); // fetch beats fallback
    // A genuine policy of 0 disables the lock and OVERWRITES a stale non-zero
    // fallback — the fallback must never resurrect the old 60.
    expect(resolveAutoLockSeconds(0, 60)).toEqual({ seconds: 0, persist: 0 });
  });

  it("falls back to the persisted value on a failed fetch, leaving storage untouched", () => {
    expect(resolveAutoLockSeconds(null, 60)).toEqual({ seconds: 60, persist: null });
    expect(resolveAutoLockSeconds(null, 0)).toEqual({ seconds: 0, persist: null });
    expect(resolveAutoLockSeconds(null, null)).toEqual({ seconds: 0, persist: null }); // nothing known → disabled
  });

  it("never arms a broken timer on garbage", () => {
    expect(resolveAutoLockSeconds(Number.NaN, 60)).toEqual({ seconds: 60, persist: null });
    expect(resolveAutoLockSeconds(-5, 60)).toEqual({ seconds: 0, persist: 0 }); // negative fetch = disabled
    expect(resolveAutoLockSeconds(null, Number.NaN)).toEqual({ seconds: 0, persist: null });
  });
});

describe("persisted auto-lock fallback storage", () => {
  it("round-trips per user (0 included) and rejects garbage", () => {
    const backing = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => backing.get(k) ?? null,
      setItem: (k: string, v: string) => void backing.set(k, v),
    });
    try {
      expect(readPersistedAutoLockSeconds("u1")).toBeNull();
      writePersistedAutoLockSeconds("u1", 300);
      expect(readPersistedAutoLockSeconds("u1")).toBe(300);
      writePersistedAutoLockSeconds("u1", 0); // fetched 0 overwrites the stale 300
      expect(readPersistedAutoLockSeconds("u1")).toBe(0);
      expect(readPersistedAutoLockSeconds("u2")).toBeNull(); // per-user keying
      backing.set("andvari.autoLockSeconds.u3", "garbage");
      expect(readPersistedAutoLockSeconds("u3")).toBeNull();
      backing.set("andvari.autoLockSeconds.u4", "-9");
      expect(readPersistedAutoLockSeconds("u4")).toBeNull();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
