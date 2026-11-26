// node --test. The real background.ts (testing/bgharness.ts) for the two approved-wording entries that needed the worker
// to carry more: entry 8 names the address the verified card names, and entry 10's "Not now" closes the kind change
// notice until the next unlock with the old kind kept.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { Chain, signedInWorld, World } from "./testing/bgharness.ts";
import { nsKey, originKeyFor } from "./serverurl.ts";
import { PIN_KEY } from "./pinstore.ts";

const pinKey = (origin: string) => nsKey(originKeyFor(origin), PIN_KEY);

test("entry 8: a first pin whose newest verified card names another address answers both addresses, and keeps nothing", async () => {
  const world = new World();
  const dialed = "https://vault.smith.example";
  const named = "https://elsewhere.smith.example";
  const chain = new Chain({ origin: dialed });
  chain.add({ origin: named }); // the newest card, validly signed, names another address
  world.serve(dialed, chain);
  const w = await world.start();
  const r = await w.popup({ type: "chooseServer", choice: "own", origin: dialed });
  assert.deepEqual(r, { ok: false, code: "origin_mismatch", mismatch: { dialed, named } });
  assert.equal(world.trusted().get(pinKey(dialed)), undefined, "nothing is pinned");
  assert.deepEqual(world.dialed(dialed), ["GET /api/v1/instance"], "only the card chain was asked for");
});

test("entry 8: a chain that does not verify carries no address (card_invalid, no mismatch)", async () => {
  const world = new World();
  const dialed = "https://vault.smith.example";
  const chain = new Chain({ origin: dialed });
  chain.add({ origin: "https://elsewhere.smith.example" });
  chain.frames[1] = chain.frames[1]!.slice(); // the newest card's frame, with one signature byte changed
  chain.frames[1]![chain.frames[1]!.length - 1] ^= 1;
  world.serve(dialed, chain);
  const w = await world.start();
  const r = await w.popup({ type: "chooseServer", choice: "own", origin: dialed });
  assert.equal(r.ok, false);
  assert.notEqual(r.code, "origin_mismatch");
  assert.equal(r.mismatch, undefined, "an address from an unverified card is never answered");
});

test("entry 10: Not now closes the kind change notice until the next unlock, and the old kind stays in force", async () => {
  const { chain, server, acct, w, world } = await signedInWorld();
  const A = server.origin;
  const c = chain.add({ kind: "public" });
  await w.alarm("resync");
  const st1 = await w.popup({ type: "status" });
  assert.equal(st1.cardNotice?.kind, "kind");
  // A hash that is not the pending card's changes nothing.
  assert.deepEqual(await w.popup({ type: "deferServerChange", hash: "x".repeat(64) }), { ok: false });
  assert.equal((await w.popup({ type: "status" })).cardNotice?.kind, "kind");
  assert.deepEqual(await w.popup({ type: "deferServerChange", hash: c.hash }), { ok: true });
  assert.equal((await w.popup({ type: "status" })).cardNotice, null, "the notice is closed");
  const stored = world.trusted().get(pinKey(A)) as { pin: { kind: string }; pending: { card: { hash: string } } | null };
  assert.equal(stored.pin.kind, "private", "the old kind stays in force");
  assert.equal(stored.pending?.card.hash, c.hash, "the change still waits for the person");
  // A refresh does not bring it back before an unlock.
  await w.alarm("resync");
  assert.equal((await w.popup({ type: "status" })).cardNotice, null);
  // The next unlock asks again.
  await w.popup({ type: "lock" });
  assert.equal((await w.popup({ type: "unlock", email: acct.email, password: acct.password })).ok, true);
  const st2 = await w.popup({ type: "status" });
  assert.equal(st2.cardNotice?.kind, "kind", "the next unlock shows the gate again");
  assert.equal(st2.cardNotice?.hash, c.hash);
});

test("rendered run: with no server chosen the connection test answers confirm_server, and dials nothing", async () => {
  const world = new World();
  const w = await world.start();
  assert.deepEqual(await w.popup({ type: "ping" }), { ok: false, code: "confirm_server" });
  assert.deepEqual(world.dialed(), []);
});

test("entry 10: a page cannot close the kind change notice", async () => {
  const { chain, w } = await signedInWorld();
  const c = chain.add({ kind: "public" });
  await w.alarm("resync");
  assert.deepEqual(await w.page({ type: "deferServerChange", hash: c.hash }, 7, "https://site.example"), { ok: false });
  assert.equal((await w.popup({ type: "status" })).cardNotice?.kind, "kind");
});
