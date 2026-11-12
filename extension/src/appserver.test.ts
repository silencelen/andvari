import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { APP_SERVER_REQUEST, appServerToAdopt, askAppServer, askAppServerDetailed, nativeSender, parseAppServerReply } from "./appserver.ts";

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

test("an ask says how the native call ended", async () => {
  assert.deepEqual(await askAppServerDetailed(async () => ({ ok: true, type: "appServer", url: null })), { answer: { kind: "none" }, call: "resolved", error: null, nativeSave: false });
  assert.deepEqual(await askAppServerDetailed(async () => undefined), { answer: { kind: "unavailable" }, call: "resolved", error: null, nativeSave: false }, "an empty reply is not a timeout");
  assert.deepEqual(await askAppServerDetailed(() => new Promise(() => {}), 10), { answer: { kind: "unavailable" }, call: "timeout", error: null, nativeSave: false });
  // The system's own save prompt (iOS 26.2): only an explicit true counts.
  assert.equal((await askAppServerDetailed(async () => ({ ok: true, type: "appServer", url: null, nativeSave: true }))).nativeSave, true);
  assert.equal((await askAppServerDetailed(async () => ({ ok: true, type: "appServer", url: null, nativeSave: "yes" }))).nativeSave, false);
  assert.equal((await askAppServerDetailed(async () => ({ ok: false, nativeSave: true }))).nativeSave, false);
  const rejected = await askAppServerDetailed(async () => { throw new Error("no host"); });
  assert.equal(rejected.call, "rejected");
  assert.equal(rejected.error, "Error: no host");
});

test("the native call prefers browser.runtime, then chrome's callback form, and rejects when there is neither", async () => {
  const calls: string[] = [];
  const browser = { runtime: { sendNativeMessage: (app: string, msg: unknown) => { calls.push(`browser:${app}:${JSON.stringify(msg)}`); return Promise.resolve("b"); } } };
  const chromeNs = {
    runtime: {
      lastError: null as { message?: string } | null,
      sendNativeMessage: (_app: string, _msg: unknown, cb?: (r: unknown) => void) => { calls.push("chrome"); cb?.("c"); },
    },
  };
  assert.equal(await nativeSender({ browser, chrome: chromeNs }, "app")(APP_SERVER_REQUEST), "b");
  assert.deepEqual(calls, ['browser:app:{"type":"appServer"}']);
  assert.equal(await nativeSender({ chrome: chromeNs }, "app")(APP_SERVER_REQUEST), "c");
  chromeNs.runtime.lastError = { message: "denied" };
  await assert.rejects(nativeSender({ chrome: chromeNs }, "app")(APP_SERVER_REQUEST), /denied/);
  await assert.rejects(nativeSender({}, "app")(APP_SERVER_REQUEST), /not available/);
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
  const fn = bg.slice(bg.indexOf("function syncAppServer"), bg.indexOf("function syncAppServer") + 2600);
  assert.match(fn, /BUILD_TARGET !== "safari"/);
  assert.match(fn, /return await adoptAppAnswer\(asked\.answer, ""\);/, "the worker's own answer is adopted through the one path");
  const adopt = bg.slice(bg.indexOf("function adoptAppAnswer("), bg.indexOf("async function adoptRelayedAppServer("));
  assert.match(adopt, /appServerToAdopt\(/);
  assert.match(adopt, /await commitServerUrl\(adopt\)/);
  // Without a store the app's origin is used for this worker life only, and only after the kept commit refused.
  assert.match(adopt, /r\.code === "storage" && \(await adoptAppServerUnkept\(adopt\)\)/);
  // One adoption at a time.
  assert.match(adopt, /const next = appAdoptChain\.then\(run, run\);/);
  // The popup's relayed answer: Safari only, read with the same parser, after worker start and the retirement, and
  // adopted through the same path.
  const relay = bg.slice(bg.indexOf("async function adoptRelayedAppServer("), bg.indexOf("// Safari: the earlier build's own session is retired first"));
  assert.match(relay, /if \(BUILD_TARGET !== "safari"\) return \{ app: "unavailable" \};/);
  assert.match(relay, /parseAppServerReply\(\{ ok: true, type: "appServer", url: msg\.url \}\)/);
  assert.ok(relay.indexOf("await Promise.race([ownSessionRetired") < relay.indexOf("return adoptAppAnswer(answer"));
  assert.match(bg, /case "appServerAnswer":\s*return adoptRelayedAppServer\(msg\);/);
  // The Details answer never waits on worker start.
  assert.match(bg, /type === "serverDiag"\) \{\s*sendResponse\(senderMaySend\("serverDiag", sender, EXTENSION_BASE\) \? serverDiag\(\) : null\);/);
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
