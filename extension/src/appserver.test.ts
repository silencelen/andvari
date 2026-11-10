import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { APP_SERVER_REQUEST, appServerToAdopt, askAppServer, parseAppServerReply } from "./appserver.ts";

const HOME = "https://home.example";

test("the handler's reply: an origin, an explicit null, or nothing usable", () => {
  assert.deepEqual(parseAppServerReply({ ok: true, type: "appServer", url: HOME }), { kind: "set", url: HOME });
  assert.deepEqual(parseAppServerReply({ ok: true, type: "appServer", url: "https://HOME.example:443/" }), { kind: "set", url: HOME }, "canonicalized");
  assert.deepEqual(parseAppServerReply({ ok: true, type: "appServer", url: null }), { kind: "none" });
  for (const bad of [
    undefined,
    null,
    "https://home.example",
    { ok: false, type: "appServer", url: HOME },
    { ok: true, type: "other", url: HOME },
    { ok: true, type: "appServer" }, // a missing key is not "no server"
    { ok: true, type: "appServer", url: 42 },
    { ok: true, type: "appServer", url: "" },
    { ok: true, type: "appServer", url: "javascript:alert(1)" },
    { ok: true, type: "appServer", url: "https://home.example/vault" },
    { ok: true, type: "appServer", url: "https://user@home.example" },
  ]) {
    assert.deepEqual(parseAppServerReply(bad), { kind: "unavailable" }, JSON.stringify(bad));
  }
});

test("asking the app sends the one message and never throws", async () => {
  const sent: unknown[] = [];
  const answer = await askAppServer(async (m) => {
    sent.push(m);
    return { ok: true, type: "appServer", url: HOME };
  });
  assert.deepEqual(answer, { kind: "set", url: HOME });
  assert.deepEqual(sent, [APP_SERVER_REQUEST]);
  assert.deepEqual(await askAppServer(async () => { throw new Error("no native host"); }), { kind: "unavailable" });
  assert.deepEqual(await askAppServer(() => new Promise(() => {}), 10), { kind: "unavailable" }, "silence is no answer");
});

test("only the Safari build adopts, only the app's origin, and only when it differs", () => {
  const set = { kind: "set", url: HOME } as const;
  assert.equal(appServerToAdopt(set, "https://andvari.monahanhosting.com", "safari"), HOME);
  assert.equal(appServerToAdopt(set, null, "safari"), HOME, "a pending or unsettled server yields to the app's confirmed one");
  assert.equal(appServerToAdopt(set, HOME, "safari"), null, "already in effect: no switch, no lock");
  assert.equal(appServerToAdopt(set, "https://other.example", "chrome"), null);
  assert.equal(appServerToAdopt(set, "https://other.example", "firefox"), null);
  assert.equal(appServerToAdopt({ kind: "none" }, "https://other.example", "safari"), null, "an app with no server moves nothing");
  assert.equal(appServerToAdopt({ kind: "unavailable" }, "https://other.example", "safari"), null);
});

// Wiring pins: the worker adopts through the one trusted commit, the message is extension-page-only, and the Safari
// manifest (only) may talk to the app.
test("the worker adopts the app's server through commitServerUrl, in the Safari build only", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const fn = bg.slice(bg.indexOf("function syncAppServer"), bg.indexOf("function syncAppServer") + 1500);
  assert.match(fn, /BUILD_TARGET !== "safari"/);
  assert.match(fn, /appServerToAdopt\(/);
  assert.match(fn, /await commitServerUrl\(adopt\)/);
  assert.match(bg, /case "appServer":\s*return syncAppServer\(\);/);
  const gate = readFileSync(new URL("./sendergate.ts", import.meta.url), "utf8");
  assert.match(gate, /appServer: "extension"/);
});

test("only the Safari manifest asks for nativeMessaging", () => {
  const perms = (f: string) => (JSON.parse(readFileSync(new URL(`../${f}`, import.meta.url), "utf8")) as { permissions: string[] }).permissions;
  assert.ok(perms("manifest.safari.json").includes("nativeMessaging"));
  assert.ok(!perms("manifest.json").includes("nativeMessaging"));
  assert.ok(!perms("manifest.firefox.json").includes("nativeMessaging"));
});
