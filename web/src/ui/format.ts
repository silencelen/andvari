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
