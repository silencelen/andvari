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

// Build 14 on a device: after Face ID the popup flipped between the unlock screen and the list without end. The popup
// goes back to its unlock screen whenever a list answers "locked"; the status and the login lists came from the app's
// vault, but the card list fell through to the worker's own session, which this build never has, and said "locked".
// Every render therefore read unlocked, then locked, then asked again.
test("one unlock is one view change: every list agrees with the status on every tick, and rendering asks the handler nothing", async () => {
  const sent: string[] = [];
  let handlerRestarted = false;
  const vault = new AppVault(async (m) => {
    sent.push(m.type);
    if (m.type === "vaultOpen") return opened;
    // After a restart the handler knows no ticket: it prompts again itself (naming the login) and still answers.
    if (m.type === "vaultSecret") return { ok: true, type: "vaultSecret", state: "secret", username: "fam", password: "hunter2", diag: { ticketFound: !handlerRestarted } };
    return { ok: true, type: "vaultClose" };
  });
  /** What the popup shows after one render: the unlock screen if the status or ANY list says locked. */
  const view = (): "locked" | "unlocked" => {
    const lists = [vault.listAnswer(vault.items()), vault.listAnswer(vault.items()), vault.listAnswer<never>([])]; // this site, all logins, cards
    return vault.unlocked && lists.every((l) => !l.locked) ? "unlocked" : "locked";
  };
  const seen: string[] = [view()];
  const render = (): void => {
    const v = view();
    if (v !== seen.at(-1)) seen.push(v);
  };

  await vault.open();
  for (let tick = 0; tick < 10; tick++) render(); // the popup's status poll, once a second
  assert.deepEqual(seen, ["locked", "unlocked"], "locked to unlocked exactly once");
  assert.deepEqual(sent, ["vaultOpen"], "no handler call on render");

  handlerRestarted = true; // iOS ended the handler's process; the worker cannot know and does not need to
  for (let tick = 0; tick < 5; tick++) render();
  assert.equal((await vault.secret("i1", "login")).state, "login");
  for (let tick = 0; tick < 5; tick++) render();
  assert.deepEqual(seen, ["locked", "unlocked"], "a dead handler process does not change the view");
  assert.deepEqual(sent, ["vaultOpen", "vaultSecret"], "one unlock, one secret, nothing closed");
  assert.equal(vault.diag.secret, "ticketFound=false");

  vault.close(); // Lock, or the popup went away
  render();
  assert.deepEqual(seen, ["locked", "unlocked", "locked"]);
  assert.deepEqual(sent, ["vaultOpen", "vaultSecret", "vaultClose"]);
});

test("a secret the app's gates refuse ends the vault; a cancelled prompt does not", async () => {
  let answer: unknown = { ok: true, type: "vaultSecret", state: "cancelled" };
  const vault = new AppVault(async (m) => (m.type === "vaultOpen" ? opened : m.type === "vaultSecret" ? answer : { ok: true, type: "vaultClose" }));
  await vault.open();
  assert.deepEqual(await vault.secret("i1", "login"), { state: "cancelled" });
  assert.equal(vault.unlocked, true);
  answer = { ok: true, type: "vaultSecret", state: "openApp", message: "Open andvari" };
  assert.equal((await vault.secret("i1", "login")).state, "openApp");
  assert.equal(vault.unlocked, false);
});

test("every list the Safari popup renders from is answered by the app's vault, none by the worker's own session", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  const lane = bg.slice(bg.indexOf("async function appVaultDispatch("), bg.indexOf("function appVaultList("));
  for (const type of ["status", "matches", "allItems", "cardItems"]) assert.ok(lane.includes(`case "${type}":`), `${type} is answered in the lane`);
  assert.match(lane, /return vault\.listAnswer<CardItem>\(\[\]\)/);
  // The popup's lists, as it asks for them once unlocked: each one's "locked" sends it back to the unlock screen.
  const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf8");
  const asked = [...popup.matchAll(/if \(!(\w+) \|\| \1\.locked\) return relocked\(\);/g)].length;
  assert.equal(asked, 4, "a new list in the popup needs its answer in the Safari lane too");
});

// Build 15 on a device: Face ID came up and then there was no popup. iOS dismisses the popup when the system's Face ID
// sheet appears, and the popup's going away (a port disconnect) closed the vault the same unlock was opening, so every
// reopening asked again. The unlock now belongs to the worker for its lifetime, whatever the popup's page does.
test("an unlock survives the popup going away while Face ID is up, and a reopened popup finds the list", async () => {
  const sent: string[] = [];
  let answerOpen: (v: unknown) => void = () => {};
  const vault = new AppVault(async (m) => {
    sent.push(m.type);
    if (m.type === "vaultOpen") return new Promise((resolve) => (answerOpen = resolve));
    return { ok: true, type: "vaultClose" };
  });
  const pending = vault.open();
  // The page is hidden, shown, and gone while the prompt is up. None of that reaches the vault: there is no call for
  // it. Even an explicit close that lands mid-prompt has nothing to close, and the answer is still honoured.
  vault.close();
  assert.equal(vault.unlocked, false);
  answerOpen(opened);
  assert.equal((await pending).state, "open");
  assert.equal(vault.unlocked, true, "the answer that arrives after the popup went away is kept");
  // The popup is opened again: it renders from the worker, with no second prompt.
  assert.deepEqual(vault.listAnswer(vault.items()).items.map((i) => i.itemId).sort(), ["i0", "i1"]);
  assert.deepEqual(sent, ["vaultOpen"], "one unlock, nothing closed");
  // An empty or odd card list is a list, never "locked".
  assert.deepEqual(vault.listAnswer([]), { locked: false, items: [] });
  assert.deepEqual(vault.listAnswer([undefined, null]), { locked: false, items: [undefined, null] });
});

test("the Safari worker ties the vault to nothing in the popup's page", () => {
  const bg = readFileSync(new URL("./background.ts", import.meta.url), "utf8");
  assert.ok(!/onConnect\.addListener/.test(bg), "no port: its disconnect closed the vault during Face ID");
  const popup = readFileSync(new URL("./popup.ts", import.meta.url), "utf8");
  assert.ok(!/addEventListener\("(pagehide|unload|beforeunload)"/.test(popup), "the popup's unload locks nothing");
  assert.ok(!popup.includes("runtime.connect("));
  // The prompt is asked for only after the unlock view has been painted and the sheet has settled.
  const onOpen = popup.slice(popup.indexOf("async function appUnlockOnOpen("), popup.indexOf("async function appUnlockOnOpen(") + 1400);
  assert.ok(onOpen.indexOf("requestAnimationFrame(() => requestAnimationFrame(") > 0 && onOpen.indexOf("requestAnimationFrame(") < onOpen.indexOf("await appUnlock();"));
});
