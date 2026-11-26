// node --test. The save offer, against the Android twin (a login typed on a page shown inside
// another app was filed under the wrong site and replaced a stored password by itself). Two properties, pinned through
// the real background.ts (testing/bgharness.ts): every write waits for the person's Save, and a capture is filed under
// the capturing frame's own origin, a sub-frame from another site included.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { signedInWorld } from "./testing/bgharness.ts";

const SHOP = "https://shop.example";
const WIDGET = "https://widget.example";

async function world() {
  return signedInWorld({
    setup: ({ acct }) => void acct.addItem(acct.personalVaultId, { type: "login", name: "shop", login: { username: "alice", password: "shop-old", uris: [SHOP] } }),
  });
}

async function shopPassword(w: Awaited<ReturnType<typeof world>>["w"]): Promise<string | undefined> {
  const shop = (await w.popup({ type: "matches", host: SHOP })).matches[0];
  return (await w.popup({ type: "reveal", itemId: shop.itemId, host: SHOP, explicit: true })).secret?.password;
}

test("a changed password typed on the site's own page is only offered: nothing is written until Save", async () => {
  const { server, w } = await world();
  const before = server.pushes.length;
  const cap = await w.page({ type: "capturedCredential", username: "alice", password: "shop-new" }, 4, SHOP);
  assert.equal(cap.ok, true);
  assert.notEqual(cap.pending?.updatesItemId, null, "offered as an update of the shop login");
  assert.equal(server.pushes.length, before, "the capture wrote nothing");
  assert.equal(await shopPassword(w), "shop-old", "the stored password is unchanged");
  // Dismiss: still nothing.
  await w.page({ type: "resolvePendingSave", action: "dismiss" }, 4, SHOP);
  assert.equal(server.pushes.length, before);
  // Captured again and saved: one write, the person's.
  await w.page({ type: "capturedCredential", username: "alice", password: "shop-new" }, 4, SHOP);
  assert.equal((await w.page({ type: "resolvePendingSave", action: "save" }, 4, SHOP)).ok, true);
  assert.equal(server.pushes.length, before + 1);
  assert.equal(await shopPassword(w), "shop-new");
});

test("a sub-frame from another site captures under its own origin, never the top page's login, and writes only on Save", async () => {
  const { server, w } = await world();
  const before = server.pushes.length;
  // The shop's page shows a frame from widget.example; the person types the shop's username there.
  await w.page({ type: "pageInfo", host: "shop.example" }, 4, SHOP, 0);
  const cap = await w.page({ type: "capturedCredential", username: "alice", password: "typed-in-widget" }, 4, WIDGET, 3);
  assert.equal(cap.ok, true);
  assert.equal(cap.pending?.host, "widget.example", "filed under the frame's own site");
  assert.equal(cap.pending?.updatesItemId, null, "never as an update of the top page's login");
  assert.equal(server.pushes.length, before, "nothing written by the capture");
  assert.equal(await shopPassword(w), "shop-old");
  // The person's Save, on the offer the widget's frame shows.
  assert.equal((await w.page({ type: "resolvePendingSave", action: "save" }, 4, WIDGET, 3)).ok, true);
  assert.equal(server.pushes.length, before + 1, "the Save writes once");
  const names = (await w.popup({ type: "allItems" })).items.map((i: { name: string }) => i.name).sort();
  assert.deepEqual(names, ["shop", "widget.example"], "a new login for the widget's site");
  assert.equal(await shopPassword(w), "shop-old", "the shop's stored password was never replaced");
  const widget = (await w.popup({ type: "matches", host: WIDGET })).matches;
  assert.deepEqual(widget.map((m: { uris: string[] }) => m.uris), [[WIDGET]], "stored under the frame's origin");
});
