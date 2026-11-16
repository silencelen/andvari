// node --test. The Safari build's popup fill and its other-site confirm, under the rule that a login is filled only into
// the page the popup showed (see popupfill.harness.test.ts). The real background.ts built for Safari (its vault is the
// andvari app's, reached by native messages the harness answers), driven through testing/bgharness.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { World } from "./testing/bgharness.ts";

(globalThis as { __ANDVARI_TARGET__?: string }).__ANDVARI_TARGET__ = "safari"; // read by buildtarget.ts at the first start()

const BANK = "https://bank.example";
const EVIL = "https://evil.example";
const TICKET = "a".repeat(64);
const LOGINS: Record<string, { name: string; username: string; password: string; uris: string[] }> = {
  "item-bank": { name: "bank", username: "alice", password: "bank-pw", uris: [BANK] },
  "item-forum": { name: "forum", username: "al", password: "forum-pw", uris: ["https://forum.example"] },
};

async function safariWorld() {
  const wd = new World();
  wd.native = (msg: { type: string; itemId?: string }) => {
    if (msg.type === "vaultOpen") {
      const items = Object.entries(LOGINS).map(([itemId, l]) => ({ itemId, name: l.name, username: l.username, uris: l.uris, hasTotp: false }));
      return { ok: true, type: "vaultOpen", state: "open", ticket: TICKET, email: "alice@example.com", items, cards: [] };
    }
    if (msg.type === "vaultSecret") {
      const l = LOGINS[msg.itemId ?? ""];
      return l ? { ok: true, type: "vaultSecret", state: "secret", username: l.username, password: l.password } : { ok: true, type: "vaultSecret", state: "refused" };
    }
    return { ok: true, type: msg.type };
  };
  const w = await wd.start();
  const opened = await w.popup({ type: "appUnlock" });
  assert.equal(opened.ok, true, `the app's vault opens: ${JSON.stringify(opened)}`);
  const redeemed: { origin: string; secret: unknown }[] = [];
  wd.tabAnswer = async (tabId: number, msg: { type: string; itemId: string }) => {
    if (msg.type !== "fillItem") return undefined;
    const origin = new URL(wd.tabs.get(tabId).url).origin;
    const r = await w.page({ type: "reveal", itemId: msg.itemId, host: new URL(origin).hostname }, tabId, origin);
    redeemed.push({ origin, secret: r?.secret });
    return r?.ok ? { filled: "both" } : { filled: "nothing", code: "no_fields" };
  };
  return { wd, w, redeemed };
}

test("Safari: this site's login fills on the page shown; a login saved for another site fills there after the confirm", async () => {
  const { wd, w, redeemed } = await safariWorld();
  wd.tabs.set(3, { id: 3, url: `${BANK}/login`, active: true });
  const ok = await w.popup({ type: "fillFromPopup", itemId: "item-bank", page: BANK });
  assert.equal(ok.ok, true, JSON.stringify(ok));
  const ask = await w.popup({ type: "fillFromPopup", itemId: "item-forum", page: BANK });
  assert.deepEqual(ask.needsConfirm, { savedFor: "forum.example", page: "bank.example" }, "the person is asked, with both hosts named");
  const confirmed = await w.popup({ type: "fillFromPopup", itemId: "item-forum", confirmedOtherSite: "bank.example", page: BANK });
  assert.equal(confirmed.ok, true, JSON.stringify(confirmed));
  assert.deepEqual(redeemed.map((r) => r.origin), [BANK, BANK]);
  assert.deepEqual(redeemed.map((r) => (r.secret as { password: string }).password), ["bank-pw", "forum-pw"]);
});

test("Safari: once the tab moved off the page shown, neither a pick nor a confirmation fills, and no confirm is offered for the new page", async () => {
  const { wd, w, redeemed } = await safariWorld();
  wd.tabs.set(3, { id: 3, url: `${BANK}/login`, active: true });
  wd.tabs.set(3, { id: 3, url: `${EVIL}/login`, active: true }); // the opener moved it before the tap
  const pick = await w.popup({ type: "fillFromPopup", itemId: "item-bank", page: BANK });
  assert.equal(pick.code, "not_allowed");
  assert.equal(pick.needsConfirm, undefined, "no confirm naming the page the popup did not show");
  const confirmedForShown = await w.popup({ type: "fillFromPopup", itemId: "item-forum", confirmedOtherSite: "bank.example", page: BANK });
  assert.equal(confirmedForShown.code, "not_allowed");
  // A confirmation that names the new host does not help either: the popup did not show that page.
  const confirmedForNew = await w.popup({ type: "fillFromPopup", itemId: "item-bank", confirmedOtherSite: "evil.example", page: BANK });
  assert.equal(confirmedForNew.code, "not_allowed");
  assert.deepEqual(wd.tabMessages, [], "no fill request reached the tab");
  assert.deepEqual(redeemed, []);
  assert.equal(wd.nativeLog.filter((m: { type: string }) => m.type === "vaultSecret").length, 0, "the app was asked for no secret");
});
