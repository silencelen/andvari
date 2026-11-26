// node --test. Spec 05 autofill (e): matching respects the page's scheme. A login saved for
// an https address is not offered on the same host over plain http — not in the page, not in the popup, not at a
// reveal, not as the target of a save — and on an http page only an address saved as http matches. The real
// background.ts, driven through testing/bgharness.ts; each test fails on the code the review read.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { signedInWorld } from "./testing/bgharness.ts";
import { isPlainHttp, matchLoginsAt, offeredUris, RESOLVE_UNKNOWN } from "./urimatch.ts";
import { requestPage, tabPageOf } from "./senderorigin.ts";

const BANK_S = "https://bank.example";
const BANK_P = "http://bank.example";
const ROUTER_P = "http://router.example";
const ROUTER_S = "https://router.example";

const item = (name: string, uris: string[]) => ({ type: "login", name, login: { username: "alice", password: `${name}-pw`, uris } });

async function world() {
  return signedInWorld({
    setup: ({ acct }) => {
      acct.addItem(acct.personalVaultId, item("bank", [BANK_S]));
      acct.addItem(acct.personalVaultId, item("router", [ROUTER_P]));
      acct.addItem(acct.personalVaultId, item("bare", ["bare.example"]));
    },
  });
}

const names = (r: { matches: { name: string }[] }) => r.matches.map((m) => m.name).sort();

test("F4: a page over plain http is not offered the login saved for https on the same host", async () => {
  const { w } = await world();
  assert.deepEqual(names(await w.page({ type: "matches", host: "bank.example" }, 3, BANK_P)), [], "http page: nothing");
  assert.deepEqual(names(await w.page({ type: "matches", host: "bank.example" }, 3, BANK_S)), ["bank"], "https page: the login");
  // A scheme-less saved address opens as https: not an http address either.
  assert.deepEqual(names(await w.page({ type: "matches", host: "bare.example" }, 3, "http://bare.example")), []);
  assert.deepEqual(names(await w.page({ type: "matches", host: "bare.example" }, 3, "https://bare.example")), ["bare"]);
  // The page's claimed host has no say: an http frame claiming nothing still gets nothing.
  assert.deepEqual(names(await w.page({ type: "matches", host: "https://bank.example" }, 3, BANK_P)), []);
});

test("F4: an address saved as http matches its http page, and an https page of the same host as before", async () => {
  const { w } = await world();
  assert.deepEqual(names(await w.page({ type: "matches", host: "router.example" }, 3, ROUTER_P)), ["router"]);
  assert.deepEqual(names(await w.page({ type: "matches", host: "router.example" }, 3, "http://router.example:8080")), ["router"], "a port is no other page");
  assert.deepEqual(names(await w.page({ type: "matches", host: "router.example" }, 3, ROUTER_S)), ["router"], "an https page matches every address, as core does");
});

test("F4: the page's reveal of the https login is refused over http and allowed over https", async () => {
  const { w } = await world();
  const bank = (await w.page({ type: "matches", host: "bank.example" }, 3, BANK_S)).matches[0];
  const overHttp = await w.page({ type: "reveal", itemId: bank.itemId, host: "bank.example" }, 3, BANK_P);
  assert.equal(overHttp.ok, false, "no password goes to the http page");
  assert.equal(overHttp.secret, undefined);
  const overHttps = await w.page({ type: "reveal", itemId: bank.itemId, host: "bank.example" }, 3, BANK_S);
  assert.equal(overHttps.secret?.password, "bank-pw");
});

test("F4: the popup on an http page lists no https login as this site's, and its reveal names no host match", async () => {
  const { w } = await world();
  // The popup names the active tab's origin (popup.ts activeTabPage), scheme included.
  assert.deepEqual(names(await w.popup({ type: "matches", host: BANK_P })), []);
  assert.deepEqual(names(await w.popup({ type: "matches", host: BANK_S })), ["bank"]);
  assert.deepEqual(names(await w.popup({ type: "matches", host: ROUTER_P })), ["router"]);
  // Without `explicit` the popup's reveal rests on the host match alone: refused over http.
  const bank = (await w.popup({ type: "matches", host: BANK_S })).matches[0];
  assert.equal((await w.popup({ type: "reveal", itemId: bank.itemId, host: BANK_P })).ok, false);
  assert.equal((await w.popup({ type: "reveal", itemId: bank.itemId, host: BANK_S })).ok, true);
});

test("F4: a password typed on the http page is a new login, never an update of the one saved for https", async () => {
  const { w } = await world();
  const http = await w.page({ type: "capturedCredential", username: "alice", password: "typed-over-http" }, 4, BANK_P);
  assert.equal(http.ok, true);
  assert.equal(http.pending?.updatesItemId, null, "not offered as an update of the https login");
  const https = await w.page({ type: "capturedCredential", username: "alice", password: "typed-over-https" }, 5, BANK_S);
  assert.notEqual(https.pending?.updatesItemId, null, "over https the same capture updates the saved login");
});

test("F4: the Safari build (the app's vault) applies the same rule at its list, its reveal and its other-site confirm", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf-8");
  const span = (from: string, to: string) => bg.slice(bg.indexOf(from), bg.indexOf(to, bg.indexOf(from)));
  const lane = span("async function appVaultDispatch(", "async function appVaultCode(");
  assert.match(lane, /filter\(\(i\) => matchLoginsAt\(i\.uris, page, pslResolve\)\)/, "the popup's list, by the tab's origin");
  assert.match(lane, /matchLoginsOnPage\(it\.uris, webHost, isPlainHttp\(msg\.host\), pslResolve\)/, "the popup's reveal");
  assert.match(bg, /return top === null \|\| normalizeHost\(top\) === null \? null : top;/, "activePageHost answers the origin");
  const fill = span("async function fillFromPopup(", "// ---- S3 in-page card fill");
  assert.match(fill, /const uris = offeredUris\(saved, isPlainHttp\(top\)\);/, "the confirm is asked for an https login on an http page");
  const badge = span("function refreshTabBadge(", "/** Popup ONLY:");
  assert.match(badge, /host = new URL\(top\)\.origin;/, "the badge counts by the top origin, scheme included");
  assert.doesNotMatch(badge, /\.hostname/);
});

test("F4: linking a login to an http page from the popup adds the http address, so it then matches there", async () => {
  const { w, server } = await world();
  const bank = (await w.popup({ type: "matches", host: BANK_S })).matches[0];
  const pushes = server.pushes.length;
  assert.equal((await w.popup({ type: "linkUri", itemId: bank.itemId, host: BANK_P })).ok, true);
  assert.equal(server.pushes.length, pushes + 1, "an https address is not taken as the http page's link");
  assert.deepEqual(names(await w.popup({ type: "matches", host: BANK_P })), ["bank"]);
  // Linked again: nothing more to push.
  assert.equal((await w.popup({ type: "linkUri", itemId: bank.itemId, host: BANK_P })).ok, true);
  assert.equal(server.pushes.length, pushes + 1);
});

// ---- the pure parts ----

test("F4: the page rule mirrors core FillRules: an http identifier is offered only addresses saved as http", () => {
  assert.equal(isPlainHttp("http://bank.example"), true);
  assert.equal(isPlainHttp(" HTTP://bank.example"), true);
  assert.equal(isPlainHttp("https://bank.example"), false);
  assert.equal(isPlainHttp("bank.example"), false);
  assert.equal(isPlainHttp(undefined), false);
  assert.deepEqual(offeredUris(["https://a.example", "http://a.example", "a.example", "androidapp://x"], true), ["http://a.example"]);
  assert.equal(matchLoginsAt(["https://bank.example"], "http://bank.example", RESOLVE_UNKNOWN), false);
  assert.equal(matchLoginsAt(["https://bank.example"], "https://bank.example", RESOLVE_UNKNOWN), true);
  assert.equal(matchLoginsAt(["http://bank.example"], "http://www.bank.example:81", RESOLVE_UNKNOWN), true);
});

test("F4: a tab sender's page is its browser-set origin, scheme kept; the popup's tab is named by its origin", () => {
  assert.equal(requestPage(true, "http://bank.example", "https://bank.example"), "http://bank.example");
  assert.equal(requestPage(true, "null", "bank.example"), null);
  assert.equal(requestPage(false, undefined, "http://bank.example"), "http://bank.example");
  assert.deepEqual(tabPageOf("http://bank.example:8080/login?x=1"), { host: "bank.example", page: "http://bank.example:8080" });
  assert.deepEqual(tabPageOf("https://www.bank.example/"), { host: "www.bank.example", page: "https://www.bank.example" });
  assert.equal(tabPageOf("chrome://newtab/"), null);
});
