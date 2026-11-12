// node --test. The App Store's Safari build has no default server: it uses the server chosen in the andvari app, and
// none until the app names one. These pins hold the manifest and build.mjs to it; build.mjs itself fails a Safari
// build that still names the reference origin anywhere in dist/.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = (f: string): string => readFileSync(new URL(f, import.meta.url), "utf8");

test("the Safari manifest names no server and has no options page", () => {
  const raw = read("../manifest.safari.json");
  assert.ok(!raw.includes("monahanhosting"), "no reference-server host permission");
  const m = JSON.parse(raw) as { host_permissions: string[]; options_ui?: unknown };
  assert.equal(m.options_ui, undefined, "the server is chosen in the app, so there is no Options page to send anyone to");
  assert.ok(m.host_permissions.includes("https://*/*"), "pages still get the content script (Safari asks per site)");
});

test("the Safari build replaces the reference origin, and fails if it is left in dist/", () => {
  const build = read("../build.mjs");
  assert.match(build, /plugins: target === "safari" \? \[noDefaultServer\] : \[\]/);
  assert.match(build, /const NO_SERVER_ORIGIN = "https:\/\/no-server\.invalid";/, "a name that can never resolve (RFC 6761)");
  assert.match(build, /if \(left\.length > 0\) throw new Error/);
  assert.match(build, /if \(target !== "safari"\) cpSync\("INSTALL\.txt"/, "the desktop install notes (which name the reference server) stay out");
  // The swap is of the exact declaration: a reworded one fails the build instead of silently keeping the default.
  assert.ok(read("./serverurl.ts").includes('export const DEFAULT_SERVER_URL = "https://andvari.monahanhosting.com";'));
});

test("in the Safari build, no server chosen means nothing is dialed and no autofill is registered", () => {
  const bg = read("./background.ts");
  assert.match(bg, /function noServerChosen\(\): boolean \{\s*return BUILD_TARGET === "safari" && serverUrl === DEFAULT_SERVER_URL;/);
  const apply = bg.slice(bg.indexOf("async function applyServerState("), bg.indexOf("const serverReady"));
  assert.match(apply, /if \(dialBlock === null && noServerChosen\(\)\) dialBlock = \{ kind: "unsettled" \};/);
  // The Safari lane answers a connection test without dialing.
  const lane = bg.slice(bg.indexOf("async function appVaultDispatch("), bg.indexOf('case "status":', bg.indexOf("async function appVaultDispatch(")));
  assert.match(lane, /case "ping":\s*\/\/[^\n]*\n\s*return \{ ok: false, error:/);
});

test("the Safari build ships no Options, connector or offscreen page, and its worker refuses a server change from one", () => {
  const build = read("../build.mjs");
  assert.match(build, /const DESKTOP_ONLY_PAGES = \["options", "connector", "offscreen"\];/);
  assert.match(build, /\.\.\.\(target === "safari"\s*\? \{\}\s*: \{\s*options: "src\/options\.ts"/, "not even bundled");
  assert.match(build, /if \(target !== "safari"\) cpSync\("options\.html"/);
  assert.match(build, /if \(pages\.length > 0\) throw new Error\(`the Safari build must not ship/);
  const bg = read("./background.ts");
  const lane = bg.slice(bg.indexOf("async function appVaultDispatch("), bg.indexOf('case "status":', bg.indexOf("async function appVaultDispatch(")));
  assert.match(lane, /case "setServerUrl":[\s\S]*?return \{ ok: false, code: "not_allowed" \} satisfies Res<"setServerUrl">;/);
  assert.match(lane, /case "forgetLegacyServer":\s*return \{ ok: false \} satisfies Res<"forgetLegacyServer">;/);
});
