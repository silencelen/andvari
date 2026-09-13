import type { AdminDeviceSummary } from "../api/types";

/**
 * H25 (audit 2026-09-13): the admin device list used to treat every signed-out device as live
 * and revocable forever — `devices.revokedAt` is stamped only by the admin revoke path, logout
 * revokes SESSIONS and never the device row, and every login mints a fresh device row — so a
 * member who signed in from five phones over a year showed "5 devices" with five Revoke buttons,
 * none holding a session. The server now derives liveness through the sessions join
 * (AdminDeviceSummary.live, the Service.deviceHasLiveSession definition) and this maps the row to
 * the one thing the column has to say:
 *
 *  - "revoked":    the admin revoked it (revokedAt set) — the terminal state, shown red;
 *  - "signed_out": no live session (live === false) — nothing to revoke, shown muted;
 *  - "live":       holds a session — the only state that gets a Revoke button.
 *
 * `live` is optional so an older server (which omits it) keeps the pre-fix reading: every
 * non-revoked row is live. Pure so admindevices.test.ts pins the mapping.
 */
export type AdminDeviceState = "revoked" | "signed_out" | "live";

export function adminDeviceState(d: Pick<AdminDeviceSummary, "revokedAt" | "live">): AdminDeviceState {
  if (d.revokedAt) return "revoked";
  if (d.live === false) return "signed_out";
  return "live";
}
