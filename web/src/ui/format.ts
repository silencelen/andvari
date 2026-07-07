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

/** F26: the one-line reason shown on the Unlock card after an inactivity auto-lock. */
export function inactivityNotice(seconds: number): string {
  if (seconds >= 60) {
    const m = Math.round(seconds / 60);
    return `Locked after ${m} minute${m === 1 ? "" : "s"} of inactivity.`;
  }
  const s = Math.max(1, Math.round(seconds));
  return `Locked after ${s} second${s === 1 ? "" : "s"} of inactivity.`;
}
