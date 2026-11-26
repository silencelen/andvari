import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { APP_SERVER_REQUEST, appServerToAdopt, appServerToForget, askAppServer, askAppServerDetailed, nativeSender, parseAppServerReply } from "./appserver.ts";

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

// Spec 03 §13 (decided on 2026-11-15): an account deleted in the app leaves the device as a fresh install, with nothing
// of the account's server. The app then has no server, and says so: the extension forgets the one it adopted.
test("the extension forgets its server only when the app itself says it has none, in the Safari build, with one in effect", () => {
  assert.equal(appServerToForget({ kind: "none" }, true, "safari"), true);
  assert.equal(appServerToForget({ kind: "none" }, false, "safari"), false, "a first install: nothing to forget");
  assert.equal(appServerToForget({ kind: "unavailable" }, true, "safari"), false, "no answer is not the app's word");
  assert.equal(appServerToForget({ kind: "set", url: HOME }, true, "safari"), false);
  assert.equal(appServerToForget({ kind: "none" }, true, "chrome"), false);
  assert.equal(appServerToForget({ kind: "none" }, true, "firefox"), false);
  // Only an explicit null is "none": a reply that is not the app's own never forgets anything.
  for (const reply of [undefined, null, {}, { ok: true, type: "appServer" }, { ok: true, type: "appServer", url: 7 }, { ok: false, type: "appServer", url: null }, { ok: true, type: "other", url: null }]) {
    assert.equal(appServerToForget(parseAppServerReply(reply), true, "safari"), false, JSON.stringify(reply));
  }
  assert.equal(appServerToForget(parseAppServerReply({ ok: true, type: "appServer", url: null }), true, "safari"), true);
});

test("forgetting removes the kept choice first, then the origin's records, and leaves the first-install block", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const adopt = bg.slice(bg.indexOf("function adoptAppAnswer("), bg.indexOf("async function adoptRelayedAppServer("));
  // Asked only where nothing is adopted, and after the stale-answer check: an older "none" forgets nothing.
  assert.match(adopt, /if \(adopt === null\) \{[\s\S]{0,260}?if \(appServerToForget\(answer, !noServerChosen\(\), BUILD_TARGET\)\) \{\s*const forgotten = await forgetAppServer\(\);/);
  assert.ok(adopt.indexOf("if (!(askedAt >= newestAppAnswerAt)) {") < adopt.indexOf("appServerToForget("));
  assert.equal(bg.split("forgetAppServer(").length - 1, 2, "one caller");
  const forget = bg.slice(bg.indexOf("async function forgetAppServer("), bg.indexOf("function syncAppServer("));
  const steps = [
    "redeemGen++;",
    "await trusted.remove([SERVER_URL_KEY, LAST_EMAIL_KEY]);",
    "if (trustedStoreOk) return false;",
    "APP_VAULT?.close();",
    "applyServerChange(NO_SERVER_ORIGIN)",
    "if (!noServerChosen()) return false;",
    "await purgeOriginNamespace(oldKey)",
    'dialBlock = { kind: "unsettled" };',
    "events = null;",
    "await registerAutofillScripts();",
  ];
  let at = -1;
  for (const step of steps) {
    const next = forget.indexOf(step, at + 1);
    assert.ok(next > at, `${step}, in this order`);
    at = next;
  }
  // The old origin's key is read before the switch moves the worker off it.
  assert.ok(forget.indexOf("const oldKey = currentOriginKey;") < forget.indexOf("applyServerChange("));
  // When the worker's own ask got no answer, the popup asks the app itself: it hands the app's "none" to the worker as
  // it does a server, through the one relay (read there with the one parser, where only an explicit null is "none").
  const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf8");
  assert.match(popup, /else if \(own\.answer\.kind === "none"\) \{[\s\S]{0,200}?await ask\(\{ type: "appServerAnswer", url: null, nativeSave: own\.nativeSave, askedAt \}\);/);
});

// Wiring pins: the worker adopts through the one trusted commit, the message is extension-page-only, and the Safari
// manifest (only) may talk to the app.
test("the worker adopts the app's server through commitServerUrl, in the Safari build only", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const fn = bg.slice(bg.indexOf("function syncAppServer"), bg.indexOf("function syncAppServer") + 2600);
  assert.match(fn, /BUILD_TARGET !== "safari"/);
  assert.match(fn, /return await adoptAppAnswer\(asked\.answer, "", askedAt\);/, "the worker's own answer is adopted through the one path");
  const adopt = bg.slice(bg.indexOf("function adoptAppAnswer("), bg.indexOf("async function adoptRelayedAppServer("));
  assert.match(adopt, /appServerToAdopt\(/);
  assert.match(adopt, /await commitServerUrl\(adopt\)/);
  // Without a store the app's origin is used for this worker life only, and only after the kept commit refused.
  assert.match(adopt, /r\.code === "storage" && \(await adoptAppServerUnkept\(adopt\)\)/);
  // One adoption at a time, and in order: an answer asked for before the newest one handled is dropped (round-5 L8).
  assert.match(adopt, /const next = appAdoptChain\.then\(run, run\);/);
  assert.ok(adopt.indexOf("if (!(askedAt >= newestAppAnswerAt)) {") < adopt.indexOf("appServerToAdopt("), "checked before anything is adopted");
  assert.match(adopt, /newestAppAnswerAt = askedAt;/);
  assert.match(fn, /const askedAt = Date\.now\(\);\s*const asked = await askAppServerDetailed/, "the worker stamps its ask before sending it");
  // The popup's relayed answer: Safari only, read with the same parser, after worker start and the retirement, and
  // adopted through the same path.
  const relay = bg.slice(bg.indexOf("async function adoptRelayedAppServer("), bg.indexOf("// Safari: the earlier build's own session is retired first"));
  assert.match(relay, /if \(BUILD_TARGET !== "safari"\) return \{ app: "unavailable" \};/);
  assert.match(relay, /parseAppServerReply\(\{ ok: true, type: "appServer", url: msg\.url \}\)/);
  assert.ok(relay.indexOf("await Promise.race([ownSessionRetired") < relay.indexOf("return adoptAppAnswer(answer"));
  assert.match(relay, /return adoptAppAnswer\(answer, " \(the popup's answer\)", askedAt\);/);
  assert.match(relay, /typeof msg\.askedAt === "number" && Number\.isFinite\(msg\.askedAt\) \? msg\.askedAt : 0/, "an unstamped answer counts as the oldest");
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
