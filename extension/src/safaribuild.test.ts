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

test("no build has a default server, and the Safari build fails if the old reference origin is left in dist/", () => {
  const build = read("../build.mjs");
  assert.ok(read("./serverurl.ts").includes('export const NO_SERVER_ORIGIN = "https://no-server.invalid";'), "a name that can never resolve (RFC 6761)");
  assert.ok(!read("./serverurl.ts").includes("DEFAULT_SERVER_URL"));
  assert.match(build, /if \(left\.length > 0\) throw new Error/);
  assert.match(build, /if \(target !== "safari"\) cpSync\("INSTALL\.txt"/, "the desktop install notes stay out");
});

test("in the Safari build, no server chosen means nothing is dialed and no autofill is registered", () => {
  const bg = read("./background.ts");
  assert.match(bg, /function noServerChosen\(\): boolean \{\s*return serverUrl === NO_SERVER_ORIGIN;/);
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
  assert.match(lane, /case "chooseServer":\s*case "confirmServer":[\s\S]*?return \{ ok: false, code: "not_allowed" \} satisfies Res<"chooseServer">;/);
  assert.match(lane, /case "forgetServer":\s*return \{ ok: false \} satisfies Res<"forgetServer">;/);
  assert.match(lane, /case "followServerChange":\s*return \{ ok: false, code: "not_allowed" \} satisfies Res<"followServerChange">;/);
});

test("the Safari popup copies no password, card number or security code (C4): they are filled, or copied in the app", () => {
  const popup = read("./popup.ts");
  assert.match(popup, /function copiesLongLivedSecrets\(\): boolean \{\s*return BUILD_TARGET !== "safari";/);
  // Every button that copies one of them is behind the rule.
  const guarded = popup.split("\n").filter((l) => /actBtn\(T\.BTN_(PASS|COPY|NUM|CVV), T\.COPY_(PASSWORD|CARD_NUMBER|CARD_CVV),/.test(l));
  assert.equal(guarded.length, 4, "the row's and the detail's password, the card number and the security code");
  for (const line of guarded) assert.ok(line.includes("copiesLongLivedSecrets()"), line.trim());
  assert.equal((popup.match(/T\.COPY_PASSWORD\b/g) ?? []).length, 2, "the row and the detail, both guarded");
});

