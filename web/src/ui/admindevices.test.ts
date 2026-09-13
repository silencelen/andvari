import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { adminDeviceState } from "./admindevices";

/**
 * H25 (audit 2026-09-13): the admin device list treated every signed-out device as live and
 * revocable forever. The server now derives liveness (AdminDeviceSummary.live); the web side has
 * one job — never offer Revoke on a row that holds no session — and this pins that mapping plus
 * the render wiring (UserRows is a closure inside Admin.tsx with no render seam here).
 */
describe("adminDeviceState", () => {
  it("revoked wins over everything — the admin's own action is terminal", () => {
    expect(adminDeviceState({ revokedAt: 1, live: true })).toBe("revoked");
    expect(adminDeviceState({ revokedAt: 1, live: false })).toBe("revoked");
  });

  it("a device the server says holds no live session is 'signed out' — nothing to revoke", () => {
    expect(adminDeviceState({ revokedAt: null, live: false })).toBe("signed_out");
  });

  it("a live device gets the Revoke affordance", () => {
    expect(adminDeviceState({ revokedAt: null, live: true })).toBe("live");
  });

  it("an OLD server that omits `live` keeps the pre-fix reading (every non-revoked row is live) — additive field", () => {
    expect(adminDeviceState({ revokedAt: null })).toBe("live");
    expect(adminDeviceState({ revokedAt: null, live: undefined })).toBe("live");
  });
});

describe("Admin.tsx device rows render through adminDeviceState", () => {
  const adminTsx = readFileSync(fileURLToPath(new URL("./Admin.tsx", import.meta.url)), "utf8");

  it("shows 'signed out' (muted, no button) for a session-less device and Revoke only for a live one", () => {
    const start = adminTsx.indexOf("const state = adminDeviceState(d);");
    expect(start, "device row no longer maps through adminDeviceState — update the pin").toBeGreaterThan(-1);
    const cell = adminTsx.slice(start, adminTsx.indexOf("</td>", start));
    expect(cell).toContain('state === "signed_out" ? (');
    expect(cell).toContain('<span className="muted">signed out</span>');
    expect(cell).toContain(">Revoke</button>");
    // The bare `d.revokedAt ?` branch (the pre-fix shape) must not come back.
    expect(cell).not.toContain("d.revokedAt ? (");
  });
});
