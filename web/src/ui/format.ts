/** Tiny display helpers shared across views. */

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB"];

export function humanSize(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "?";
  let v = bytes;
  let u = 0;
  while (v >= 1024 && u < UNITS.length - 1) {
    v /= 1024;
    u++;
  }
  return `${u === 0 ? v : v >= 100 ? Math.round(v) : v.toFixed(1)} ${UNITS[u]}`;
}

export function fmtDate(epochMs: number | null | undefined): string {
  if (!epochMs) return "—";
  return new Date(epochMs).toLocaleString();
}

/** "July 14"-style day (spec 03 §11 copy). Falls back gracefully for a missing time.
 *  quality-deadcode--7: Vault.tsx and Sharing.tsx each carried a byte-identical private
 *  copy while this file — the designated formatting home — had neither. One now. */
export function fmtDay(ms?: number): string {
  if (!ms) return "soon";
  return new Date(ms).toLocaleDateString(undefined, { month: "long", day: "numeric" });
}

/**
 * "July 14" for a date in the CURRENT year, "July 14, 2025" otherwise (H131).
 *
 * [fmtDay] was written for the 7/30-day lifecycle windows of spec 03 §11, where the year is never
 * in doubt, and was then reused for version history — which is capped at ten SAVES, not at any
 * age, so an item edited twice a year renders a 2024 version as a bare "July 14" that reads as
 * this July. Use this wherever the thing being dated can be arbitrarily old; keep [fmtDay] for
 * the bounded windows, where the extra year is noise.
 */
export function fmtDayYear(ms?: number, now: number = Date.now()): string {
  if (!ms) return "soon";
  const d = new Date(ms);
  if (d.getFullYear() === new Date(now).getFullYear()) return fmtDay(ms);
  return d.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" });
}

/**
 * "3 months ago" at day resolution — enough for a staleness column, and it never implies a
 * precision the underlying client clock does not have.
 *
 * H131: lived privately in Staleness.tsx while the Duplicates tab beside it printed a raw
 * `toLocaleDateString()`, so two adjacent rows of the same Health view spoke different time
 * dialects ("updated 9/12/2026" next to "yesterday"). Moved to the designated formatting home
 * so the tabs share ONE vocabulary — and so the plural below is pinned by format.test.ts.
 *
 * The plural bug it also carried: the month branch runs up to 24 months and the year branch then
 * divided DAYS by 365, so days 720–729 produced "1 years ago". (The day and month branches cannot
 * hit 1 — `days < 60` catches them first — which is why only this one read wrong.)
 */
export function ago(ms: number | undefined, now: number): string {
  if (ms === undefined) return "—";
  const days = Math.max(0, Math.floor((now - ms) / 86_400_000));
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 60) return `${days} days ago`;
  const months = Math.floor(days / 30);
  if (months < 24) return `${months} months ago`;
  const years = Math.floor(days / 365);
  return `${years} year${years === 1 ? "" : "s"} ago`;
}

/** F26: the one-line reason shown on the Unlock card after an inactivity auto-lock. */
export function inactivityNotice(seconds: number): string {
  if (seconds >= 60) {
    const m = Math.round(seconds / 60);
    return `Locked after ${m} minute${m === 1 ? "" : "s"} of inactivity.`;
  }
  const s = Math.max(1, Math.round(seconds));
  return `Locked after ${s} second${s === 1 ? "" : "s"} of inactivity.`;
}
