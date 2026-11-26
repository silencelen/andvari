import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { deviceName } from "../vault/account";
import type { SettingsSession } from "../vault/settingsflow";
import { AccountDevicesCard, deviceLine, revokeOutcomeText } from "./AccountDevices";
import { DEVICES_HOW, DEVICES_LAST_SEEN, DEVICES_PLATFORM, DEVICES_REVOKE_KEEPS_COPY, DEVICES_TITLE, DEVICES_UNAVAILABLE, DEVICES_UNKNOWN, DEVICES_WRONG_PASSWORD } from "./copy";

/** The account's own devices on the Settings flow (design §8.6). */
describe("AccountDevicesCard", () => {
  it("renders its heading and a live region before the list arrives", () => {
    const settings = { wire: { devices: () => new Promise(() => {}) } } as unknown as SettingsSession;
    const html = renderToStaticMarkup(createElement(AccountDevicesCard, { settings }));
    expect(html).toContain(DEVICES_TITLE);
    expect(html).toContain('role="status"');
  });

  it("never reports an unclear revoke as done, and a wrong password as its own sentence", () => {
    expect(revokeOutcomeText({ kind: "done", value: undefined })).toBeNull();
    expect(revokeOutcomeText({ kind: "wrong_password" })).toBe(DEVICES_WRONG_PASSWORD);
    expect(revokeOutcomeText({ kind: "unknown", error: new Error("x") })).toBe(DEVICES_UNKNOWN);
    expect(revokeOutcomeText({ kind: "session_ended" })).toBe(DEVICES_UNAVAILABLE);
    expect(revokeOutcomeText({ kind: "refused", code: "bad_device_id" })).toBe(DEVICES_UNAVAILABLE);
  });

  // Browser walk, 2026-11-16: each row read "web Chrome/149.0.0.0 (web, registered, …)", in the narrow sign-in card.
  it("says how each device joined and what it is in words, never the wire's raw values", () => {
    expect(deviceLine({ how: "registered", platform: "web", lastSeenAt: null })).toBe(`${DEVICES_HOW.registered} · ${DEVICES_PLATFORM.web}`);
    for (const how of ["registered", "password", "linked", "recovered"]) {
      const parts = deviceLine({ how: how as "password", platform: "android", lastSeenAt: null }).split(" · ");
      expect(parts).toEqual([DEVICES_HOW[how], "Android"]);
      expect(parts).not.toContain(how);
    }
    expect(deviceLine({ how: "brand-new" as "password", platform: "toaster", lastSeenAt: null })).not.toMatch(/brand-new|toaster/);
    // The last part is DEVICES_LAST_SEEN filled with the time (its words up to the slot, whatever they are).
    const seen = deviceLine({ how: "password", platform: "web", lastSeenAt: Date.UTC(2026, 10, 16, 12) }).split(" · ");
    expect(seen.slice(0, 2)).toEqual([DEVICES_HOW.password, DEVICES_PLATFORM.web]);
    const last = seen[2] ?? "";
    expect(last.startsWith(DEVICES_LAST_SEEN.slice(0, DEVICES_LAST_SEEN.indexOf("{0}")))).toBe(true);
    expect(last.length).toBeGreaterThan(DEVICES_LAST_SEEN.length - 3);
  });

  it("is a settings sheet that states what removing a device does not do (§4.4)", () => {
    const settings = { wire: { devices: () => new Promise(() => {}) } } as unknown as SettingsSession;
    const html = renderToStaticMarkup(createElement(AccountDevicesCard, { settings }));
    expect(html).toContain('<section class="sheet">');
    expect(html).toContain(DEVICES_REVOKE_KEEPS_COPY.replace(/'/g, "&#x27;"));
    const css = readFileSync(fileURLToPath(new URL("./styles.css", import.meta.url)), "utf8");
    expect(css).toMatch(/\.device-list\s*\{[^}]*list-style:\s*none/);
  });

  it("a removed device stays listed and is marked as removed (the walk saw it listed like a live one)", () => {
    const src = readFileSync(fileURLToPath(new URL("./AccountDevices.tsx", import.meta.url)), "utf8");
    expect(src).toContain('{!d.current && !d.live && <span className="tag">{DEVICES_REMOVED_TAG}</span>}');
  });

  it("this browser is named as a person would name it", () => {
    expect(deviceName("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/149.0.0.0 Safari/537.36")).toBe("Chrome on Linux");
    expect(deviceName("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0")).toBe("Edge on Windows");
    expect(deviceName("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15")).toBe("Safari on Mac");
    expect(deviceName("Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0")).toBe("Firefox on Linux");
    expect(deviceName("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")).toBe("Safari on iPhone");
    expect(deviceName("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36")).toBe("Chrome on Android");
    expect(deviceName(null)).toBe("Web browser");
  });
});
