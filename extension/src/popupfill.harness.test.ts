// node --test. A page that changes its address between the popup's list and the fill (release 0.30.0 port of the
// overhaul's fix 1f903bc5). The popup lists "This site" for the active tab's page; the tab can move to another site
// while the popup is open (a page that opened the tab can navigate it at any moment). The person's pick was made for
// the page the popup showed, so the worker fills only while the tab is still on that page. The real background.ts,
// driven through testing/bgharness.ts; the fake content script redeems the grant the way content.ts does (a `reveal`
// from the tab's top frame, at the origin the browser reports for it, while the fill request is being answered).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { signedInWorld } from "./testing/bgharness.ts";

const BANK = "https://bank.example";
const EVIL = "https://evil.example";
const SHOP = "https://shop.example";

async function world() {
  const made = await signedInWorld({
    setup: ({ acct }) => {
      acct.addItem(acct.personalVaultId, { type: "login", name: "bank", login: { username: "alice", password: "bank-pw", uris: [BANK] } });
      acct.addItem(acct.personalVaultId, { type: "login", name: "forum", login: { username: "al", password: "forum-pw", uris: ["https://forum.example"] } });
    },
  });
  const { world: wd, w } = made;
  // The content script in the tab's top frame: on a fill request it asks for the secret at the origin the tab is on.
  const redeemed: { origin: string; secret: unknown }[] = [];
  wd.tabAnswer = async (tabId: number, msg: { type: string; itemId: string }) => {
    if (msg.type !== "fillItem") return undefined;
    const origin = new URL(wd.tabs.get(tabId).url).origin;
    const r = await w.page({ type: "reveal", itemId: msg.itemId, host: new URL(origin).hostname }, tabId, origin);
    redeemed.push({ origin, secret: r?.secret });
    return r?.ok ? { filled: "both" } : { filled: "nothing", code: "no_fields" };
  };
  return { ...made, redeemed };
}

test("a fill picked for the page the popup showed is refused once the tab is on another site, and nothing is granted", async () => {
  const { world: wd, w, redeemed } = await world();
  wd.tabs.set(7, { id: 7, url: `${BANK}/login`, active: true });
  const listed = await w.popup({ type: "matches", host: "bank.example" });
  assert.equal(listed.matches.length, 1, "the popup lists the bank login as this site's");
  const itemId = listed.matches[0].itemId;
  // The opener navigates the tab to its own page before the person's click lands.
  wd.tabs.set(7, { id: 7, url: `${EVIL}/login`, active: true });
  const r = await w.popup({ type: "fillFromPopup", itemId, page: BANK });
  assert.deepEqual(redeemed, [], `the page the tab moved to received no secret, got ${JSON.stringify(redeemed)}`);
  assert.equal(r.ok, false);
  assert.equal(r.code, "not_allowed");
  assert.deepEqual(wd.tabMessages, [], "no fill request reached the tab");
  // And no grant stands for the new page: its frame's reveal of the bank login is refused.
  const reveal = await w.page({ type: "reveal", itemId, host: "evil.example" }, 7, EVIL);
  assert.equal(reveal.ok, false);
  assert.equal(reveal.secret, undefined);
});

test("a fill with no page named is refused; a fill on the page the popup showed reaches that tab's top frame", async () => {
  const { world: wd, w, redeemed } = await world();
  wd.tabs.set(7, { id: 7, url: `${BANK}/login`, active: true });
  const itemId = (await w.popup({ type: "matches", host: "bank.example" })).matches[0].itemId;
  const none = await w.popup({ type: "fillFromPopup", itemId });
  assert.equal(none.code, "not_allowed", "the popup always names the page it showed");
  assert.deepEqual(wd.tabMessages, []);
  const ok = await w.popup({ type: "fillFromPopup", itemId, page: BANK });
  assert.equal(ok.ok, true);
  assert.deepEqual(wd.tabMessages.map((m: { tabId: number; msg: { type: string } }) => [m.tabId, m.msg.type]), [[7, "fillItem"]]);
  assert.deepEqual(redeemed, [{ origin: BANK, secret: { username: "alice", password: "bank-pw", totpCode: null } }]);
});

test("a login picked from the full list for a page it was not saved for still fills on the page the popup showed, and only there", async () => {
  const { world: wd, w, redeemed } = await world();
  wd.tabs.set(7, { id: 7, url: `${SHOP}/checkout`, active: true });
  const all = await w.popup({ type: "allItems" });
  const forum = all.items.find((i: { name: string }) => i.name === "forum");
  assert.ok(forum, "the full list holds the forum login");
  const ok = await w.popup({ type: "fillFromPopup", itemId: forum.itemId, page: SHOP });
  assert.equal(ok.ok, true, "the person's pick for the page shown fills there");
  assert.deepEqual(redeemed, [{ origin: SHOP, secret: { username: "al", password: "forum-pw", totpCode: null } }]);
  // The same pick after the tab moved away is refused.
  wd.tabs.set(7, { id: 7, url: `${EVIL}/`, active: true });
  const moved = await w.popup({ type: "fillFromPopup", itemId: forum.itemId, page: SHOP });
  assert.equal(moved.code, "not_allowed");
  assert.equal(redeemed.length, 1, "nothing more was handed out");
});

test("the popup names the page it showed: the origin of the active tab, read when the list is drawn", async () => {
  const { readFileSync } = await import("node:fs");
  const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf8");
  assert.ok(popup.includes("tabPage = page;"), "loadUnlocked keeps the origin of the page it lists for");
  assert.ok(popup.includes(`{ type: "fillFromPopup", itemId, page }`), "a pick names the page");
  assert.ok(popup.includes(`{ type: "fillFromPopup", itemId, confirmedOtherSite, page }`), "a confirmed pick names the page");
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  // Safari's other-site confirm runs after the page check, so a confirmation never fills a page the popup did not show.
  const check = bg.indexOf("if (shownPage === null || shownPage !== top)");
  const safari = bg.indexOf("const confirmed = confirmedOtherSite !== null");
  assert.ok(check > 0 && safari > check, "the page check comes before the Safari confirm");
});
