// node --test. What each manifest may ask the browser for. A new permission is a decision, not a side effect: Chrome
// disables an installed extension whose update asks for a permission with a warning until the person accepts it, and
// Firefox asks again too. So each manifest asks for nothing beyond what main ships (manifest.json,
// manifest.firefox.json) and what the Safari build already needed before its card-fill rework (manifest.safari.json:
// nativeMessaging, for the andvari app's handler). Adding one means adding it here, in the same change.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

type PermissionKey = "permissions" | "optional_permissions" | "host_permissions" | "optional_host_permissions";

const ALLOWED: Record<string, Record<PermissionKey, readonly string[]>> = {
  // As on main.
  "manifest.json": {
    permissions: ["storage", "activeTab", "scripting", "alarms", "offscreen", "contextMenus"],
    optional_permissions: [],
    host_permissions: ["https://andvari.monahanhosting.com/*"],
    optional_host_permissions: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
  },
  // As on main.
  "manifest.firefox.json": {
    permissions: ["storage", "activeTab", "scripting", "alarms", "clipboardWrite", "contextMenus"],
    optional_permissions: [],
    host_permissions: ["https://andvari.monahanhosting.com/*", "https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
    optional_host_permissions: [],
  },
  // Not on main: the Safari build as this branch had it before the card-fill rework (3e6e212e).
  "manifest.safari.json": {
    permissions: ["storage", "activeTab", "scripting", "alarms", "nativeMessaging"],
    optional_permissions: [],
    host_permissions: ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
    optional_host_permissions: [],
  },
};

const manifest = (file: string): Record<string, unknown> => JSON.parse(readFileSync(new URL(`../${file}`, import.meta.url), "utf8")) as Record<string, unknown>;

test("each manifest asks for no permission beyond the ones listed here", () => {
  for (const [file, allowed] of Object.entries(ALLOWED)) {
    const m = manifest(file);
    for (const key of Object.keys(allowed) as PermissionKey[]) {
      const asked = m[key] ?? [];
      assert.ok(Array.isArray(asked), `${file}: ${key} is a list`);
      for (const p of asked) assert.ok(allowed[key].includes(p as string), `${file} asks for ${key} "${String(p)}", which is not listed`);
    }
    // No other kind of ask either: a key this test does not know is a new kind of permission.
    for (const key of Object.keys(m)) {
      if (/permission/i.test(key)) assert.ok(key in allowed, `${file}: an unknown permission key "${key}"`);
    }
  }
});

test("the frame tree is not asked for: card fill reads each frame's ancestor origins instead", () => {
  for (const file of Object.keys(ALLOWED)) {
    const m = manifest(file);
    for (const key of ["permissions", "optional_permissions"]) {
      const asked = (m[key] ?? []) as string[];
      assert.ok(!asked.includes("webNavigation"), `${file} ${key}`);
      assert.ok(!asked.includes("tabs"), `${file} ${key}: tabs reads every tab's address`);
    }
  }
});
