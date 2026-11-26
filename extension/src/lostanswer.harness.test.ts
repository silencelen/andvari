// node --test. A save from the extension whose answer was lost (the reader's finding of 2026-11-18): it may be stored,
// so it is "cannot tell", never "could not save"; the second try sends the same item under the same item id and the
// same mutation id, so that the server, which answers a replayed mutation id from its journal (spec 03 §5), takes it
// once. The real background.ts, driven through testing/bgharness.ts, with the push played by a server that keeps a
// journal by mutation id.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { SAVE_CANNOT_TELL, SAVE_FAILED, SAVE_REJECTED_FULL, saveErrorCopy } from "./errors.ts";
import { signedInWorld } from "./testing/bgharness.ts";

const SITE = "https://shop.example";
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

type Mutation = { mutationId: string; itemId: string };

/** A push route that stores each new mutation once, keeps its result by mutation id, and loses the first answer as [lose] says. */
function journalled(server: { override: unknown }, lose: "no_answer" | "bad_gateway") {
  const journal = new Map<string, unknown>();
  const stored = new Map<string, number>();
  const seen: Mutation[] = [];
  let pushes = 0;
  server.override = (method: string, path: string, body: unknown) => {
    if (method !== "POST" || path !== "/api/v1/sync/push") return null;
    pushes++;
    const m = (body as { mutations: Mutation[] }).mutations[0]!;
    seen.push({ mutationId: m.mutationId, itemId: m.itemId });
    const done = journal.get(m.mutationId);
    if (done !== undefined) return Promise.resolve(json(200, { rev: 9, results: [done] }));
    const r = { mutationId: m.mutationId, status: "applied", newItemRev: 1 };
    journal.set(m.mutationId, r);
    stored.set(m.itemId, (stored.get(m.itemId) ?? 0) + 1);
    if (pushes === 1) return lose === "no_answer" ? Promise.reject(new TypeError("Failed to fetch")) : Promise.resolve(new Response("<html>Bad gateway</html>", { status: 502, headers: { "content-type": "text/html" } }));
    return Promise.resolve(json(200, { rev: 9, results: [r] }));
  };
  return {
    stored,
    seen,
    get pushes() {
      return pushes;
    },
  };
}

for (const lose of ["no_answer", "bad_gateway"] as const) {
  test(`a new login whose save answer was lost (${lose}) is 'cannot tell'; the second try sends the same item, and the server holds it once`, async () => {
    const { world, server, w } = await signedInWorld();
    world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
    assert.equal((await w.page({ type: "capturedCredential", username: "alice", password: "alice-shop-pw" }, 4, SITE)).ok, true);
    const push = journalled(server, lose);
    const first = await w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE);
    // On the code before: { ok: false } with no code, read as "Could not save — try again".
    assert.equal(first.ok, false);
    assert.equal(first.code, "cannot_tell");
    assert.equal(saveErrorCopy(first.code), SAVE_CANNOT_TELL);
    assert.notEqual(saveErrorCopy(first.code), SAVE_FAILED);
    assert.equal(first.lost, undefined, "the ids stay in the worker");
    const second = await w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE);
    assert.equal(second.ok, true);
    assert.equal(push.pushes, 2);
    // On the code before: a fresh item id and mutation id, and two logins at the server.
    assert.deepEqual(push.seen[1], push.seen[0], "the same item id and the same mutation id");
    assert.deepEqual([...push.stored.values()], [1], "one item at the server");
    const names = (await w.popup({ type: "allItems" })).items.map((i: { name: string }) => i.name);
    assert.deepEqual(names, ["shop.example"], "listed once here");
  });
}

for (const changed of [true, false]) {
  test(`what was caught ${changed ? "changed" : "is the same"} between the two tries of a login whose answer was lost: ${changed ? "the second try is a new item under new ids" : "the same item under the same ids"}`, async () => {
    const { world, server, w } = await signedInWorld();
    world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
    assert.equal((await w.page({ type: "capturedCredential", username: "alice", password: "alice-shop-pw" }, 4, SITE)).ok, true);
    const push = journalled(server, "no_answer");
    assert.equal((await w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE)).code, "cannot_tell");
    // The person types into the same form again: another password, or the same one.
    assert.equal((await w.page({ type: "capturedCredential", username: "alice", password: changed ? "another-pw" : "alice-shop-pw" }, 4, SITE)).ok, true);
    const second = await w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE);
    assert.equal(second.ok, true);
    assert.equal(push.pushes, 2);
    if (changed) {
      // Never the first request's ids with other content: the server would answer from its record of the first.
      assert.notEqual(push.seen[1]!.mutationId, push.seen[0]!.mutationId);
      assert.notEqual(push.seen[1]!.itemId, push.seen[0]!.itemId);
      assert.equal(push.stored.size, 2, "the first try's item, stored with its answer lost, and the new one");
    } else {
      // On the code before: a fresh capture dropped the ids, and the same login could be stored twice.
      assert.deepEqual(push.seen[1], push.seen[0]);
      assert.deepEqual([...push.stored.values()], [1]);
    }
  });
}

test("what was caught changed between the two tries of a card whose answer was lost: the second try is a new item under new ids", async () => {
  const { world, server, w } = await signedInWorld();
  world.tabs.set(5, { id: 5, url: `${SITE}/pay`, active: true });
  const PAN = "4242424242424242";
  await w.page({ type: "captureCard", fields: { number: PAN, expMonth: "12", expYear: "2031", cardholderName: "ALICE A" } }, 5, SITE);
  const push = journalled(server, "no_answer");
  assert.equal((await w.page({ type: "resolvePendingCardSave", action: "save" }, 5, SITE)).code, "cannot_tell");
  // The expiry is corrected and the form submitted again (past the double-fire window of one capture).
  await new Promise((r) => setTimeout(r, 1600));
  await w.page({ type: "captureCard", fields: { number: PAN, expMonth: "11", expYear: "2031", cardholderName: "ALICE A" } }, 5, SITE);
  const second = await w.page({ type: "resolvePendingCardSave", action: "save" }, 5, SITE);
  assert.equal(second.ok, true);
  assert.equal(push.pushes, 2);
  assert.notEqual(push.seen[1]!.mutationId, push.seen[0]!.mutationId);
  assert.notEqual(push.seen[1]!.itemId, push.seen[0]!.itemId);
});

test("a save the server refuses because the account is full is said as a full account: the server's reason reaches the sentence", async () => {
  const { world, server, w } = await signedInWorld();
  world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
  assert.equal((await w.page({ type: "capturedCredential", username: "alice", password: "alice-shop-pw" }, 4, SITE)).ok, true);
  server.override = (method: string, path: string, body: unknown) => {
    if (method !== "POST" || path !== "/api/v1/sync/push") return null;
    const m = (body as { mutations: Mutation[] }).mutations[0]!;
    return Promise.resolve(json(200, { rev: 9, results: [{ mutationId: m.mutationId, status: "rejected", reason: "quota_exceeded" }] }));
  };
  const r = await w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE);
  assert.equal(r.code, "rejected");
  // On the code before: no reason, and the line "an attachment it references is no longer there".
  assert.equal(r.reason, "quota_exceeded");
  assert.equal(saveErrorCopy(r.code, r.reason), SAVE_REJECTED_FULL);
});

test("a refusal by the server itself (a 4xx) is not 'cannot tell': nothing was stored", async () => {
  const { world, server, w } = await signedInWorld();
  world.tabs.set(4, { id: 4, url: `${SITE}/login`, active: true });
  assert.equal((await w.page({ type: "capturedCredential", username: "alice", password: "alice-shop-pw" }, 4, SITE)).ok, true);
  server.override = (method: string, path: string) => (method === "POST" && path === "/api/v1/sync/push" ? Promise.resolve(json(400, { error: "bad_request", message: "x" })) : null);
  const r = await w.page({ type: "resolvePendingSave", action: "save" }, 4, SITE);
  assert.equal(r.ok, false);
  assert.notEqual(r.code, "cannot_tell");
});
