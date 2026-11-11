import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { APP_VAULT_LIFETIME_MS, AppVault, parseOpenReply, parseSecretReply, vaultFromApp } from "./appvault.ts";

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

test("the secret reply is one login's secret or a reason", () => {
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "secret", username: "fam", password: "hunter2", totpCode: "123456" }), { state: "secret", username: "fam", password: "hunter2", totpCode: "123456" });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "secret", username: "fam", password: "hunter2" }), { state: "secret", username: "fam", password: "hunter2", totpCode: null });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "refused" }), { state: "refused" });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "cancelled" }), { state: "cancelled" });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultSecret", state: "secret", username: "fam" }), { state: "unavailable" });
  assert.deepEqual(parseSecretReply({ ok: true, type: "vaultOpen", state: "secret", username: "a", password: "b" }), { state: "unavailable" });
});

test("the worker's vault: locked until opened, one secret per ask, gone on close and after its lifetime", async () => {
  const sent: { type: string; ticket?: string; itemId?: string }[] = [];
  let now = 1000;
  const vault = new AppVault(async (m) => {
    sent.push(m);
    if (m.type === "vaultOpen") return opened;
    if (m.type === "vaultSecret") return { ok: true, type: "vaultSecret", state: "secret", username: "fam", password: "hunter2" };
    return { ok: true, type: "vaultClose" };
  }, () => now);

  assert.equal(vault.unlocked, false);
  assert.deepEqual(vault.items(), []);
  assert.deepEqual(await vault.secret("i1"), { state: "cancelled" }, "nothing is asked of the handler while locked");
  assert.equal(sent.length, 0);

  assert.equal((await vault.open()).state, "open");
  assert.equal(vault.unlocked, true);
  assert.equal(vault.email, "u@example.com");
  assert.deepEqual(vault.items().map((i) => i.name), ["alpha", "Example"]);
  assert.ok(!JSON.stringify(vault.items()).includes("hunter2"));

  assert.deepEqual(await vault.secret("not-in-the-list"), { state: "refused" }, "only an item of the open list can be asked for");
  assert.equal((await vault.secret("i1")).state, "secret");
  assert.deepEqual(sent.at(-1), { type: "vaultSecret", ticket: TICKET, itemId: "i1" });

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
