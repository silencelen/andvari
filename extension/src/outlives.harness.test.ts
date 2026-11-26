// node --test. Work that outlives a lock. The shared Kotlin code was found to have work
// that went on after a lock with what the lock had dropped. The twin here: a save or a sync on the wire when the
// person signs out and another account signs in. The write lands under its own account at the server; nothing of it
// is added to, or decrypted with, the session that holds the worker by the time the answer comes back. The real
// background.ts, driven through testing/bgharness.ts.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { signedInWorld } from "./testing/bgharness.ts";

const SITE = "https://shop.example";
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
const tick = (ms = 5) => new Promise((r) => setTimeout(r, ms));

/** The FIRST request matching [match] is answered by [answer] only once `release()` is called; every other passes. */
function holdOnce(server: { override: unknown }, match: (method: string, path: string) => boolean, answer: (body: unknown) => Response) {
  let open: (() => void) | null = null;
  let hit = false;
  server.override = (method: string, path: string, body: unknown) => {
    if (hit || !match(method, path)) return null;
    hit = true;
    return new Promise<void>((r) => (open = r)).then(() => answer(body));
  };
  return {
    get hit() {
      return hit;
    },
    release() {
      open?.();
    },
  };
}

test("a new login saved by one account, answered after another account signed in, never lands in the second account's list", async () => {
  const { world, server, w } = await signedInWorld();
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
  const cap = await w.page({ type: "capturedCredential", username: "alice", password: "alice-shop-pw" }, 4, SITE);
  assert.equal(cap.ok, true);
  const hold = holdOnce(
    server,
    (m, p) => m === "POST" && p === "/api/v1/sync/push",
    (body) => json({ rev: 9, results: (body as { mutations: { mutationId: string }[] }).mutations.map((m) => ({ mutationId: m.mutationId, status: "applied", newItemRev: 9 })) }),
  );
  const saving = w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE);
  for (let i = 0; i < 400 && !hold.hit; i++) await tick();
  assert.ok(hold.hit, "the save is on the wire");
  // Meanwhile: sign out, and the other account signs in on this browser.
  await w.popup({ type: "signOut" });
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  hold.release();
  const saved = await saving;
  assert.equal(saved.ok, true, "the write landed under the first account");
  const names = (await w.popup({ type: "allItems" })).items.map((i: { name: string }) => i.name);
  assert.deepEqual(names, [], "the first account's new login is not in the second account's list");
  assert.deepEqual((await w.page({ type: "matches", host: "shop.example" }, 4, SITE)).matches, [], "nor offered on the page to the second account");
});

test("a sync answered after another account signed in is dropped, not decrypted into that account's session", async () => {
  let alice: { rev: number; vaultKeys: Map<string, unknown>; personalVaultId: string; userId: string; grants: unknown[]; items: unknown[] } | null = null;
  const { server, w } = await signedInWorld({
    setup: ({ acct }) => {
      acct.addItem(acct.personalVaultId, { type: "login", name: "alice-only", login: { username: "a", password: "p", uris: [SITE] } });
      alice = acct;
    },
  });
  const bob = server.addAccount({ email: "bob@example.com", password: "bob horse" });
  bob.addItem(bob.personalVaultId, { type: "login", name: "bob-only", login: { username: "b", password: "q", uris: [SITE] } });
  const a = alice!;
  // A resync starts as the first account; its feed is held on the wire.
  const hold = holdOnce(
    server,
    (m, p) => m === "GET" && p.startsWith("/api/v1/sync?"),
    () => json({ rev: a.rev, vaults: [...a.vaultKeys.keys()].map((vaultId) => ({ vaultId, type: "x" })), grants: [{ vaultId: a.personalVaultId, userId: a.userId, role: "owner", wrappedVk: "" }, ...a.grants], items: a.items }),
  );
  const syncing = w.alarm("resync");
  for (let i = 0; i < 400 && !hold.hit; i++) await tick();
  assert.ok(hold.hit, "the feed was asked for");
  await w.popup({ type: "signOut" });
  assert.equal((await w.popup({ type: "unlock", email: bob.email, password: bob.password })).ok, true);
  const names = async () => (await w.popup({ type: "allItems" })).items.map((i: { name: string }) => i.name);
  assert.deepEqual(await names(), ["bob-only"]);
  hold.release();
  await syncing;
  await tick(50);
  assert.deepEqual(await names(), ["bob-only"], "the second account's list is untouched by the first account's feed");
});
