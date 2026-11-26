// node --test. The Safari build adopts the andvari app's server and forgets it once the app has none (spec 03 §13: an
// account deleted in the app leaves the device as a fresh install, with nothing of the account's server). The real
// background.ts built for Safari, its native handler answered by the harness (testing/bgharness.ts).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { settle, World } from "./testing/bgharness.ts";

(globalThis as { __ANDVARI_TARGET__?: string }).__ANDVARI_TARGET__ = "safari"; // read by buildtarget.ts at the first start()

const HOME = "https://home.example";
// The trusted store's keys (serverurl.ts SERVER_URL_KEY, device.ts LAST_EMAIL_KEY).
const KEPT_SERVER = "serverUrl";
const KEPT_EMAIL = "lastEmail";

/** A Safari worker whose app first names [HOME]; `app.url` is what the app answers from then on. */
async function adopted() {
  const wd = new World();
  const app: { url: string | null | undefined } = { url: HOME };
  wd.native = async (msg: { type: string }) => {
    if (msg.type !== "appServer") return { ok: true, type: msg.type };
    // undefined: the handler gives no answer (a timeout, no handler)
    return app.url === undefined ? undefined : { ok: true, type: "appServer", url: app.url, nativeSave: false };
  };
  const w = await wd.start();
  assert.deepEqual(await w.popup({ type: "appServer" }), { app: "set" });
  const info = await w.popup({ type: "serverInfo" });
  assert.equal(info.url, HOME, "the app's server is adopted");
  assert.equal(info.block, null);
  assert.equal(wd.trusted().get(KEPT_SERVER), HOME, "and kept");
  return { wd, w, app };
}

test("Safari: once the app says it has no server, the worker forgets the one it adopted: the kept choice and the remembered email", async () => {
  const { wd, w, app } = await adopted();
  wd.trusted().set(KEPT_EMAIL, "alice@example.com");
  app.url = null; // an account deleted in the app: the device is a fresh install, with no server
  // On the code before: { app: "none" } too, but nothing was forgotten.
  assert.deepEqual(await w.popup({ type: "appServer" }), { app: "none" });
  await settle();
  const info = await w.popup({ type: "serverInfo" });
  assert.equal(info.url, "", "no server in effect: not the deleted account's");
  assert.deepEqual(info.block, { kind: "unsettled" }, "the block a first install starts with");
  assert.equal(wd.trusted().has(KEPT_SERVER), false, "the kept choice is gone");
  assert.equal(wd.trusted().has(KEPT_EMAIL), false, "nothing names the account");
  // A new worker life starts where a first install does.
  const again = await wd.start();
  assert.equal((await again.popup({ type: "serverInfo" })).url, "");
  // The app names a server again: it is adopted as on a first install.
  app.url = HOME;
  assert.deepEqual(await again.popup({ type: "appServer" }), { app: "set" });
  assert.equal((await again.popup({ type: "serverInfo" })).url, HOME);
});

test("Safari: an app that gives no answer forgets nothing; the popup's relay of the app's \"none\" forgets as the worker's own ask does", async () => {
  const { wd, w, app } = await adopted();
  app.url = undefined; // no answer from the handler
  assert.notDeepEqual(await w.popup({ type: "appServer" }), { app: "none" });
  assert.equal((await w.popup({ type: "serverInfo" })).url, HOME, "no answer is not the app's word");
  assert.equal(wd.trusted().get(KEPT_SERVER), HOME);
  // The popup asked the app itself and relays its "none".
  assert.deepEqual(await w.popup({ type: "appServerAnswer", url: null, nativeSave: false, askedAt: Date.now() }), { app: "none" });
  const info = await w.popup({ type: "serverInfo" });
  assert.equal(info.url, "");
  assert.deepEqual(info.block, { kind: "unsettled" });
  assert.equal(wd.trusted().has(KEPT_SERVER), false);
});
