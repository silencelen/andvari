import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { APP_VAULT_LIFETIME_MS, AppVault, describeDiag, parseOpenReply, parseSecretReply, vaultFromApp } from "./appvault.ts";

const TICKET = "ab".repeat(32);
const item = { itemId: "i1", name: "Example", username: "fam", uris: ["https://login.example.com/x"], hasTotp: true };
const opened = { ok: true, type: "vaultOpen", state: "open", ticket: TICKET, email: "u@example.com", items: [item, { ...item, itemId: "i0", name: "alpha" }] };

test("the open reply: a list with no secrets, an open-the-app state, a cancel, or nothing usable", () => {
  const r = parseOpenReply(opened);
  assert.equal(r.state, "open");
  assert.deepEqual(r.state === "open" ? Object.keys(r.items[0]!).sort() : [], ["hasTotp", "itemId", "name", "uris", "username"], "an item carries no secret field, whatever the handler sent");
  assert.deepEqual(parseOpenReply({ ...opened, items: [{ ...item, password: "hunter2", totp: "otpauth://x" }] }), { state: "open", ticket: TICKET, email: "u@example.com", items: [item] }, "a secret the handler should never send is dropped");
  assert.deepEqual(parseOpenReply({ ok: true, type: "vaultOpen", state: "openApp", message: "Turn on Face ID" }), { state: "openApp", message: "Turn on Face ID" });
  assert.deepEqual(parseOpenReply({ ok: true, type: "vaultOpen", state: "cancelled" }), { state: "cancelled" });
  for (const bad of [
    undefined,
    { ...opened, ok: false },
    { ...opened, type: "vaultSecret" },
    { ...opened, ticket: "short" },
    { ...opened, items: "x" },
    { ...opened, items: [{ ...item, itemId: "" }] },
    { ...opened, items: [{ ...item, uris: "https://x" }] },
  ]) {
    assert.deepEqual(parseOpenReply(bad), { state: "unavailable" }, JSON.stringify(bad));
  }
});

test("the secret reply is the one thing asked for, or a reason", () => {
  const both = { ok: true, type: "vaultSecret", state: "secret", username: "fam", password: "hunter2", totpCode: "123456" };
  assert.deepEqual(parseSecretReply(both, "login"), { state: "login", username: "fam", password: "hunter2" }, "a code that came along is dropped");
  assert.deepEqual(parseSecretReply(both, "code"), { state: "code", code: "123456" }, "a password that came along is dropped");
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "secret", totpCode: "123456" }, "login"), { state: "unavailable" });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "secret", username: "a", password: "b" }, "code"), { state: "unavailable" });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "refused" }, "login"), { state: "refused" });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "cancelled" }, "code"), { state: "cancelled" });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultOpen", state: "secret", username: "a", password: "b" }, "login"), { state: "unavailable" });
});

test("the worker's vault: locked until opened, one secret per ask, gone on close and after its lifetime", async () => {
  const sent: { type: string; ticket?: string; itemId?: string; want?: string; name?: string }[] = [];
  let now = 1000;
  const vault = new AppVault(async (m) => {
    sent.push(m);
    if (m.type === "vaultOpen") return opened;
    if (m.type === "vaultSecret") return { ok: true, type: "vaultSecret", state: "secret", username: "fam", password: "hunter2" };
    return { ok: true, type: "vaultClose" };
  }, () => now);

  assert.equal(vault.unlocked, false);
  assert.deepEqual(vault.items(), []);
  assert.deepEqual(await vault.secret("i1", "login"), { state: "cancelled" }, "nothing is asked of the handler while locked");
  assert.equal(sent.length, 0);

  assert.equal((await vault.open()).state, "open");
  assert.equal(vault.unlocked, true);
  assert.equal(vault.email, "u@example.com");
  assert.deepEqual(vault.items().map((i) => i.name), ["alpha", "Example"]);
  assert.ok(!JSON.stringify(vault.items()).includes("hunter2"));

  assert.deepEqual(await vault.secret("not-in-the-list", "login"), { state: "refused" }, "only an item of the open list can be asked for");
  assert.equal((await vault.secret("i1", "login")).state, "login");
  assert.deepEqual(sent.at(-1), { type: "vaultSecret", ticket: TICKET, itemId: "i1", want: "login", name: "Example" }, "one thing, and the name a second prompt would show");

  vault.close();
  assert.equal(vault.unlocked, false);
  assert.deepEqual(sent.at(-1), { type: "vaultClose", ticket: TICKET }, "the handler is told to wipe its keys");
  vault.close(); // idempotent
  assert.equal(sent.filter((m) => m.type === "vaultClose").length, 1);

  await vault.open();
  now += APP_VAULT_LIFETIME_MS;
  assert.equal(vault.unlocked, false, "the list does not outlive its lifetime");
  assert.deepEqual(vault.items(), []);
});

test("the handler's account of its process is kept as numbers and booleans only", async () => {
  assert.equal(describeDiag({ diag: { pid: 71, processAgeSeconds: 3, hadVault: true, ticketFound: false, note: "text is dropped", nested: {} } }), "pid=71 processAgeSeconds=3 hadVault=true ticketFound=false");
  assert.equal(describeDiag({ ok: true }), null);
  assert.equal(describeDiag("x"), null);
  const vault = new AppVault(async (m) =>
    m.type === "vaultOpen" ? { ...opened, diag: { pid: 71, hadVault: false } } : { ok: true, type: "vaultSecret", state: "secret", username: "a", password: "b", diag: { pid: 72, ticketFound: false } },
  );
  await vault.open();
  await vault.secret("i1", "login");
  assert.deepEqual(vault.diag, { open: "pid=71 hadVault=false", secret: "pid=72 ticketFound=false" }, "two pids: the process did not survive between the messages");
});

test("a handler that throws, stays silent or answers nonsense opens nothing", async () => {
  assert.deepEqual(await new AppVault(async () => { throw new Error("no host"); }).open(), { state: "unavailable" });
  assert.deepEqual(await new AppVault(async () => "nonsense").open(), { state: "unavailable" });
  const cancelled = new AppVault(async () => ({ ok: true, type: "vaultOpen", state: "cancelled" }));
  assert.deepEqual(await cancelled.open(), { state: "cancelled" });
  assert.equal(cancelled.unlocked, false);
});

// Wiring pins: where the Safari worker's vault comes from, and that nothing of it is stored.
test("the Safari worker has no session of its own: its handlers read the app's vault, and its sign-in lanes refuse", () => {
  assert.equal(vaultFromApp("safari"), true);
  assert.equal(vaultFromApp("chrome"), false);
  assert.equal(vaultFromApp("firefox"), false);
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  // One gate before the dispatch: every message of the own-session lanes is refused in the Safari build.
  assert.match(bg, /if \(APP_VAULT !== null\) \{\s*const viaApp = await appVaultDispatch\(msg, sender\);\s*if \(viaApp !== undefined\) return viaApp;\s*\}/);
  const fn = bg.slice(bg.indexOf("async function appVaultDispatch("), bg.indexOf("// ---- end of the Safari app-vault lane ----"));
  for (const type of ["unlock", "unlockTotp", "unlockWithPin", "unlockWithBio", "enrollQuickUnlock", "enrollQuickUnlockBio", "setTotp", "linkUri", "signOut"]) {
    assert.ok(fn.includes(`case "${type}":`), `${type} never reaches the own-session code`);
  }
  // The lane touches no storage: the list and the ticket are memory.
  assert.ok(!/chrome\.storage|trusted\.|sessionSeal|plainSession|indexedDB/.test(fn), "nothing of the app's vault is stored");
  // A page frame gets nothing from the list and no secret without the popup's grant.
  assert.match(fn, /case "allItems":\s*if \(sender\.tab !== undefined\) return/);
  assert.match(fn, /case "totp":\s*if \(sender\.tab !== undefined\) return/);
});

test("a page frame gets a secret only through the popup's grant, never a code, and the popup must confirm another site", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const reveal = bg.slice(bg.indexOf("async function appVaultReveal("), bg.indexOf("async function appVaultCode("));
  assert.match(reveal, /allowed = isTopFrame && loginGrantRedeemable\(grants\.get\(tabId\), msg\.itemId, sender\.origin, Date\.now\(\)\);/);
  assert.ok(!/senderHost\(/.test(reveal), "a host match alone releases nothing to a page frame in this build");
  assert.match(reveal, /vault\.secret\(msg\.itemId, "login"\)/);
  assert.match(reveal, /totpCode: null/);
  assert.match(bg, /APP_VAULT!\.secret\(itemId, "code"\)/);
  // The popup's "This site" list is computed from the active tab's own URL, and a page frame gets none.
  const lane = bg.slice(bg.indexOf("async function appVaultDispatch("), bg.indexOf("function appVaultList("));
  assert.match(lane, /if \(sender\.tab !== undefined \|\| !vault\.unlocked\) return \{ locked: !vault\.unlocked, matches: \[\] \}/);
  assert.match(lane, /const page = await activePageHost\(\);/);
  // A login saved for another site is not granted to the active page until the person confirmed it.
  const fill = bg.slice(bg.indexOf("async function fillFromPopup("), bg.indexOf("async function topOrigin("));
  const confirm = fill.indexOf("if (APP_VAULT !== null && !confirmedOtherSite) {");
  assert.ok(confirm > 0 && confirm < fill.indexOf("grants.set(tab.id"), "asked before any grant is minted");
  assert.match(fill, /needsConfirm: \{ savedFor, page: page \?\? top \}/);
});

test("each capture is queued under its own id, and the old session is retired before the app's server is adopted", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  assert.match(bg, /pending\.appSaveId \?\?= `c-\$\{/);
  assert.ok(!bg.includes("id: `t${tabId}-${pending.frameId}`"));
  const retire = bg.slice(bg.indexOf("async function retireOwnSession("), bg.indexOf("const ownSessionRetired"));
  const erase = retire.indexOf('await doLock("signout", seen);');
  const purge = retire.indexOf("for (const k of keys) await purgeOriginNamespace(k);");
  const revoke = retire.indexOf("revoker.logout()");
  const done = retire.indexOf("await trusted.set({ [DONE]: true });");
  assert.ok(erase > 0 && erase < purge && purge < revoke && revoke < done, "erase, purge every namespace, revoke, and only then the marker");
  assert.match(retire, /if \(!revoked\) return;/);
  assert.match(retire, /\^ns\\\.\(\[0-9a-f\]\{16\}\)\\\./);
  const sync = bg.slice(bg.indexOf("function syncAppServer("), bg.indexOf("function syncAppServer(") + 1500);
  assert.match(sync, /await Promise\.race\(\[ownSessionRetired, delay\(APP_SERVER_START_WAIT_MS\)\]\);/);
});
