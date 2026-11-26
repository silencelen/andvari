// node --test. A page that changes its address between the popup's list and the fill, and the question asked before a
// login saved for another site is filled from the popup's full list.
// The popup lists "This site" for the tab's origin; the tab can move to another site while the popup is open (a page
// that opened the tab can navigate it at any moment). The person's pick was made for the site the popup named, so the
// worker fills only while the tab is still on that page. The real background.ts, driven through testing/bgharness.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { signedInWorld } from "./testing/bgharness.ts";
import { FILL_PAGE_NOT_SECURE } from "./copy.ts";
import { fillApproved } from "./errors.ts";

/** What the question before a fill names, and whether it carries the token the person's yes is sent with. */
function asked(r: { needsConfirm?: { savedFor: string; page: string; domain: string | null; confirm: string } }) {
  assert.ok(r.needsConfirm, `asked first: ${JSON.stringify(r)}`);
  const { savedFor, page, domain, confirm } = r.needsConfirm;
  return { savedFor, page, domain, token: typeof confirm === "string" && confirm !== "" };
}

const BANK = "https://bank.example";
const EVIL = "https://evil.example";

async function world() {
  return signedInWorld({
    setup: ({ acct }) => void acct.addItem(acct.personalVaultId, { type: "login", name: "bank", login: { username: "alice", password: "bank-pw", uris: [BANK] } }),
  });
}

test("a fill picked for the page the popup showed is refused once the tab is on another site, and nothing is granted", async () => {
  const { world: wd, w } = await world();
  wd.tabs.set(7, { id: 7, url: `${BANK}/login`, active: true });
  const listed = await w.popup({ type: "matches", host: BANK });
  assert.equal(listed.matches.length, 1, "the popup lists the bank login as this site's");
  const itemId = listed.matches[0].itemId;
  // The opener navigates the tab to its own page before the person's click lands.
  wd.tabs.set(7, { id: 7, url: `${EVIL}/login`, active: true });
  const r = await w.popup({ type: "fillFromPopup", itemId, page: BANK });
  assert.equal(r.ok, false);
  assert.equal(r.code, "not_allowed");
  assert.deepEqual(wd.tabMessages, [], "no fill request reached the tab");
  // And no grant stands for the new page: its frame's reveal of the bank login is refused.
  const reveal = await w.page({ type: "reveal", itemId, host: "bank.example" }, 7, EVIL);
  assert.equal(reveal.ok, false);
  assert.equal(reveal.secret, undefined);
});

test("a fill with no page named is refused; a fill on the page the popup showed goes to that tab's top frame", async () => {
  const { world: wd, w } = await world();
  wd.tabs.set(7, { id: 7, url: `${BANK}/login`, active: true });
  const itemId = (await w.popup({ type: "matches", host: BANK })).matches[0].itemId;
  const none = await w.popup({ type: "fillFromPopup", itemId });
  assert.equal(none.code, "not_allowed", "the popup always names the page it showed");
  assert.deepEqual(wd.tabMessages, []);
  await w.popup({ type: "fillFromPopup", itemId, page: BANK });
  assert.deepEqual(wd.tabMessages.map((m: { tabId: number; msg: { type: string } }) => [m.tabId, m.msg.type]), [[7, "fillItem"]], "the fill request went to the tab");
});

const SHOP = "https://shop.example";

/** Two logins, and the content script in the tab's top frame: on a fill request it asks for the secret at the origin the tab is on. */
async function worldWithPage() {
  const made = await signedInWorld({
    setup: ({ acct }) => {
      acct.addItem(acct.personalVaultId, { type: "login", name: "bank", login: { username: "alice", password: "bank-pw", uris: [BANK] } });
      acct.addItem(acct.personalVaultId, { type: "login", name: "forum", login: { username: "al", password: "forum-pw", uris: ["https://forum.example"] } });
    },
  });
  const { world: wd, w } = made;
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

test("a login picked from the full list for a page it was not saved for asks first, naming both hosts; after the person's yes it fills on the page the popup showed, and only there", async () => {
  const { world: wd, w, redeemed } = await worldWithPage();
  wd.tabs.set(7, { id: 7, url: `${SHOP}/checkout`, active: true });
  const all = await w.popup({ type: "allItems" });
  const forum = all.items.find((i: { name: string }) => i.name === "forum");
  assert.ok(forum, "the full list holds the forum login");
  // On the code before: filled at once (ok true), with no question.
  const pick = await w.popup({ type: "fillFromPopup", itemId: forum.itemId, page: SHOP });
  assert.equal(pick.ok, false, "one click does not fill a login saved for another site");
  assert.deepEqual(asked(pick), { savedFor: "forum.example", page: "shop.example", domain: null, token: true }, "the person is asked, with both hosts named");
  assert.deepEqual(wd.tabMessages, [], "nothing reached the tab before the person's yes");
  assert.equal(redeemed.length, 0);
  const ok = await w.popup({ type: "fillFromPopup", itemId: forum.itemId, confirmedOtherSite: pick.needsConfirm.confirm, page: SHOP });
  assert.equal(ok.ok, true, "the person's confirmed pick for the page shown fills there");
  assert.equal(redeemed.length, 1);
  assert.equal(redeemed[0]!.origin, SHOP);
  const secret = redeemed[0]!.secret as { username?: string; password?: string };
  assert.deepEqual([secret.username, secret.password], ["al", "forum-pw"]);
  // The same pick after the tab moved away is refused, with the confirmation too.
  wd.tabs.set(7, { id: 7, url: `${EVIL}/`, active: true });
  const moved = await w.popup({ type: "fillFromPopup", itemId: forum.itemId, page: SHOP });
  assert.equal(moved.code, "not_allowed");
  const movedConfirmed = await w.popup({ type: "fillFromPopup", itemId: forum.itemId, confirmedOtherSite: pick.needsConfirm.confirm, page: SHOP });
  assert.equal(movedConfirmed.code, "not_allowed");
  assert.equal(redeemed.length, 1, "nothing more was handed out");
});

/** A pick of the bank login from the full list on [url] (the tab's top page): what the worker answers. */
async function pickBankOn(url: string) {
  const made = await worldWithPage();
  const { world: wd, w } = made;
  wd.tabs.set(7, { id: 7, url, active: true });
  const page = new URL(url).origin;
  const bank = (await w.popup({ type: "allItems" })).items.find((i: { name: string }) => i.name === "bank");
  assert.ok(bank, "the full list holds the bank login");
  const r = await w.popup({ type: "fillFromPopup", itemId: bank.itemId, page });
  return { ...made, r, page, itemId: bank.itemId as string };
}

test("a login picked from the full list on its own site fills with one click, no question", async () => {
  const { r, redeemed } = await pickBankOn(`${BANK}/login`);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.needsConfirm, undefined);
  assert.deepEqual(redeemed.map((x) => x.origin), [BANK]);
});

test("a login picked from the full list on a subdomain of its site fills with one click, no question", async () => {
  const { r, redeemed } = await pickBankOn("https://login.bank.example/start");
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.needsConfirm, undefined);
  assert.deepEqual(redeemed.map((x) => x.origin), ["https://login.bank.example"]);
});

for (const lookAlike of ["https://bank.example.evil.example/login", "https://bank-example.example/login", "https://xn--bnk-sna.example/login"]) {
  test(`a login picked from the full list on a look-alike host (${new URL(lookAlike).hostname}) asks first, naming both hosts; nothing is filled before the yes`, async () => {
    const { world: wd, r, redeemed } = await pickBankOn(lookAlike);
    assert.equal(r.ok, false);
    assert.deepEqual(asked(r), { savedFor: "bank.example", page: new URL(lookAlike).hostname, domain: null, token: true });
    assert.deepEqual(wd.tabMessages, []);
    assert.equal(redeemed.length, 0);
  });
}

test("a page that holds the login's site in a frame: the question is asked for the tab's top page, and after the yes only the top frame can take the login", async () => {
  // The tab's top page is evil.example; bank.example is a frame inside it. The pick is judged by the top page.
  const { world: wd, w, r, itemId, redeemed } = await pickBankOn(`${EVIL}/embeds-the-bank`);
  assert.equal(r.ok, false);
  assert.deepEqual(asked(r), { savedFor: "bank.example", page: "evil.example", domain: null, token: true });
  assert.deepEqual(wd.tabMessages, []);
  // After the yes, the fill goes to the top frame only; another frame of the page (of a third site) cannot take the grant.
  const ADS = "https://ads.example";
  wd.tabAnswer = async (tabId: number, msg: { type: string; itemId: string }) => {
    if (msg.type !== "fillItem") return undefined;
    const fromFrame = await w.page({ type: "reveal", itemId: msg.itemId, host: "ads.example" }, tabId, ADS, 3);
    assert.equal(fromFrame.ok, false, "a frame cannot take the top page's grant");
    assert.equal(fromFrame.secret, undefined);
    const top = await w.page({ type: "reveal", itemId: msg.itemId, host: "evil.example" }, tabId, EVIL);
    redeemed.push({ origin: EVIL, secret: top?.secret });
    return top?.ok ? { filled: "both" } : { filled: "nothing", code: "no_fields" };
  };
  const ok = await w.popup({ type: "fillFromPopup", itemId, confirmedOtherSite: r.needsConfirm.confirm, page: EVIL });
  assert.equal(ok.ok, true, JSON.stringify(ok));
  assert.deepEqual(redeemed.map((x) => x.origin), [EVIL]);
});

test("the popup names the page it showed: the origin of the active tab, read when the list is drawn", async () => {
  const { readFileSync } = await import("node:fs");
  const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf8");
  assert.ok(popup.includes("tabPage = tab?.page ?? null;"), "the list keeps the origin of the page it lists for");
  assert.ok(popup.includes(`{ type: "fillFromPopup", itemId, page }`), "a pick names the page");
  assert.ok(popup.includes(`{ type: "fillFromPopup", itemId, confirmedOtherSite, page }`), "a confirmed pick names the page");
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  // Safari's other-site confirm runs after the page check, so a confirmation never fills a page the popup did not show.
  const check = bg.indexOf("if (shownPage === null || shownPage !== top)");
  const safari = bg.indexOf("const confirmed = confirmedOtherSite !== null");
  assert.ok(check > 0 && safari > check, "the page check comes before the Safari confirm");
});

/** One login "x" saved for [saved] and a second one, "other"; the tab's top page at [url]; a pick of "x" from the full list. */
async function pickOn(saved: string[], url: string) {
  const made = await signedInWorld({
    setup: ({ acct }) => {
      acct.addItem(acct.personalVaultId, { type: "login", name: "x", login: { username: "u", password: "pw", uris: saved } });
      acct.addItem(acct.personalVaultId, { type: "login", name: "other", login: { username: "o", password: "other-pw", uris: ["https://other.example"] } });
    },
  });
  const { world: wd, w } = made;
  const redeemed: { origin: string; secret: unknown }[] = [];
  wd.tabAnswer = async (tabId: number, msg: { type: string; itemId: string }) => {
    if (msg.type !== "fillItem") return undefined;
    const origin = new URL(wd.tabs.get(tabId).url).origin;
    const r = await w.page({ type: "reveal", itemId: msg.itemId, host: new URL(origin).hostname }, tabId, origin);
    redeemed.push({ origin, secret: r?.secret });
    return r?.ok ? { filled: "both" } : { filled: "nothing", code: "no_fields" };
  };
  wd.tabs.set(7, { id: 7, url, active: true });
  const page = new URL(url).origin;
  const items = (await w.popup({ type: "allItems" })).items as { name: string; itemId: string }[];
  const itemId = items.find((i) => i.name === "x")!.itemId;
  const otherId = items.find((i) => i.name === "other")!.itemId;
  const r = await w.popup({ type: "fillFromPopup", itemId, page });
  return { ...made, redeemed, r, page, itemId, otherId };
}

test("a plain-http page and a login saved for https on the same host: the question names both schemes and the page as not secure, never the same name twice", async () => {
  const { r, redeemed } = await pickOn(["https://bank.example"], "http://bank.example/login");
  // On the code before: "saved for bank.example. You are on bank.example."
  assert.deepEqual(asked(r), { savedFor: "https://bank.example", page: fillApproved(FILL_PAGE_NOT_SECURE, "http://bank.example"), domain: null, token: true });
  assert.notEqual(r.needsConfirm.savedFor, r.needsConfirm.page);
  assert.deepEqual(redeemed, []);
});

test("a plain-http page of another host: the page is named with its scheme, as not secure; the saved site by its host", async () => {
  const { r } = await pickOn(["https://bank.example"], "http://evil.example/");
  assert.deepEqual(asked(r), { savedFor: "bank.example", page: fillApproved(FILL_PAGE_NOT_SECURE, "http://evil.example"), domain: null, token: true });
});

test("a long host under a known suffix: the question also names the page's registrable domain, the part a long host can push out of view", async () => {
  const long = "bank.com.secure.login.verify.account.update.session.evil.co.uk";
  const { r } = await pickOn(["https://bank.com"], `https://${long}/login`);
  // On the code before: only the whole host, whose end ran past the popup's edge.
  assert.deepEqual(asked(r), { savedFor: "bank.com", page: long, domain: "evil.co.uk", token: true });
  // A page whose host is its registrable domain names nothing more; under an unknown suffix nothing can be named.
  assert.equal((await pickOn(["https://bank.com"], "https://evil.co.uk/")).r.needsConfirm.domain, null);
  assert.equal((await pickOn(["https://bank.example"], "https://bank.example.secure.login.evil.example/")).r.needsConfirm.domain, null);
});

test("the person's yes is bound to the item it was asked for: a yes for one login never fills another, nor does a yes that names only the page", async () => {
  const { w, world: wd, r, itemId, otherId, redeemed } = await pickOn(["https://bank.example"], "https://evil.example/");
  asked(r);
  const yes: string = r.needsConfirm.confirm;
  // The yes given for "x", sent with the other login: refused, nothing reaches the page.
  const swapped = await w.popup({ type: "fillFromPopup", itemId: otherId, confirmedOtherSite: yes, page: "https://evil.example" });
  assert.equal(swapped.ok, false);
  assert.ok(swapped.needsConfirm, "the other login is asked about in its own right");
  // On the code before: the page's host was the whole confirmation, for any login.
  const hostOnly = await w.popup({ type: "fillFromPopup", itemId: otherId, confirmedOtherSite: "evil.example", page: "https://evil.example" });
  assert.equal(hostOnly.ok, false);
  assert.deepEqual(wd.tabMessages, []);
  assert.deepEqual(redeemed, []);
  // The yes for "x" fills "x", on the page it was asked on.
  const filled = await w.popup({ type: "fillFromPopup", itemId, confirmedOtherSite: yes, page: "https://evil.example" });
  assert.equal(filled.ok, true, JSON.stringify(filled));
  assert.deepEqual(redeemed.map((x) => [x.origin, (x.secret as { password: string }).password]), [["https://evil.example", "pw"]]);
});

test("the question's box lets a long host wrap inside the popup, and names the registrable domain on a line of its own", async () => {
  // What a test here can show is the rule and the line being there; the wrap itself needs a real popup to be seen.
  const { readFileSync } = await import("node:fs");
  const css = readFileSync(new URL("../popup.css", import.meta.url), "utf8");
  const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf8");
  assert.ok(css.includes("#other-site-confirm, #other-site-confirm button { overflow-wrap: anywhere; }"));
  const box = popup.slice(popup.indexOf("function confirmOtherSite("), popup.indexOf("async function copyUsername("));
  assert.ok(box.includes('box.id = "other-site-confirm";'));
  assert.ok(box.includes("fillApproved(T.FILL_OTHER_SITE_DOMAIN, q.domain)"), "the registrable domain is named");
  assert.ok(box.includes("void fillItem(itemId, q.confirm);"), "the yes is sent with the question's own token");
});
