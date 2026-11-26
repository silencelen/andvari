// A person removed from a shared vault keeps a sealed copy of its items on this browser (the holding area). Added again
// and accepted, the vault comes back: the server serves its items again, deletions included, and the store puts back
// as live any held item that this answer did not bring. What happened to an item of the vault while the person was out
// must still hold once they are back: an item deleted in the vault is not listed again, an item moved to another vault
// shows once, in that vault, and a change of theirs that waited with the held copy ends as a waiting change ends on the
// ordinary road when a pull brings its item's deletion. Driven through the real VaultStore, SharedLogSession and
// VaultLogStore against a fake server.
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { Mutation, PushResponse, WireItem } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { BOB, browser, type Browser, family, type FakeSyncServer, freshDb, heldOf, listed, namesIn, noticesOf } from "./fakesyncserver.testkit";
import { type HeldVaultRecord, openVaultCache, type PullBatch, type VaultCache } from "./idbcache";

type Wire = { pushMutations: (ms: Mutation[]) => Promise<PushResponse> };
const wireOf = (who: Browser): Wire => (who.store as unknown as { wire: Wire }).wire;

/**
 * [who]'s pushes are answered as an honest server answers a put over a deleted item (spec 03 §5): the item is stored
 * again, and the answer is `conflict` with the deletion's mark as `serverItem`. The fake server alone answers `applied`.
 */
function answersPutOverDeletion(server: FakeSyncServer, who: Browser): void {
  const wire = wireOf(who);
  const push = wire.pushMutations;
  wire.pushMutations = async (ms: Mutation[]): Promise<PushResponse> => {
    const before = new Map(ms.map((m) => [m.mutationId, server.items.get(m.itemId)]));
    const resp = await push(ms);
    return {
      ...resp,
      results: resp.results.map((r) => {
        const m = ms.find((x) => x.mutationId === r.mutationId);
        const was = before.get(r.mutationId);
        if (m?.op !== "put" || r.status !== "applied" || was?.deleted !== true) return r;
        return { ...r, status: "conflict" as const, serverItem: { ...was, blob: null } as WireItem };
      }),
    };
  };
}

/** [run] with [who]'s pushes failing as if offline, and the offline copy kept for good (so a change is queued, not refused). */
async function offline(who: Browser, run: () => Promise<void>): Promise<void> {
  const wire = wireOf(who);
  const push = wire.pushMutations;
  wire.pushMutations = () => Promise.reject(new TypeError("offline"));
  try {
    await run();
  } finally {
    wire.pushMutations = push;
  }
}

/** Alice removes bob from [vaultId]; his browser learns it and holds the vault's copy. */
async function removeBob(alice: Browser, bob: Browser, vaultId: string): Promise<void> {
  await alice.store.removeVaultMember(vaultId, BOB);
  await bob.store.sync();
  expect(heldOf(bob)).toEqual([vaultId]);
  expect(listed(bob.store, vaultId)).toBe(false);
}

/** Alice adds bob to [vaultId] again; his browser is asked, he accepts, and syncs. */
async function addBobAgainAndAccept(alice: Browser, bob: Browser, vaultId: string): Promise<void> {
  await alice.store.addVaultMember(vaultId, BOB, "writer");
  await bob.store.sync();
  const ask = bob.shared.pendingAsks().find((a) => a.vaultId === vaultId);
  expect(ask).toBeDefined();
  expect((await bob.shared.answer(ask!, true)).kind).toBe("adopted");
  await bob.store.sync();
  expect(listed(bob.store, vaultId)).toBe(true);
  expect(heldOf(bob)).toEqual([]);
}

/** Every item [who] lists, as `<vault id>:<name>`. */
const everywhere = (who: Browser): string[] => who.store.list().map((i) => `${i.vaultId}:${i.doc.name}`).sort();

/** The ids of the items [who]'s held copy of [vaultId] holds, in memory. */
const heldIdsOf = (who: Browser, vaultId: string): string[] =>
  ((who.store as unknown as { holding: Map<string, { items: WireItem[] }> }).holding.get(vaultId)?.items ?? []).map((w) => w.itemId).sort();

/** The held copy of [vaultId] at rest. */
async function heldAtRest(vaultId: string): Promise<HeldVaultRecord | undefined> {
  return (await (await openVaultCache(BOB)).heldVaults()).find((r) => r.vault.vaultId === vaultId && r.setAside !== true);
}

/** The ids of the items the held copy of [vaultId] holds at rest. */
async function heldIdsAtRest(vaultId: string): Promise<string[]> {
  return ((await heldAtRest(vaultId))?.items ?? []).map((w) => w.itemId).sort();
}

/** The live rows of [itemId] the offline copy holds at rest, as their revision and format version. */
async function rowsAtRest(itemId: string): Promise<{ rev: number; formatVersion: number }[]> {
  const cache = await openVaultCache(BOB);
  return (await cache.envelopes()).filter((e) => e.itemId === itemId && !e.deleted).map((e) => ({ rev: e.rev, formatVersion: e.formatVersion }));
}

/**
 * Alice adds bob to [vaultId] again and his browser pulls the answer that brings the grant back (which serves what
 * happened to the vault's items meanwhile, deletions included); he is asked and has not answered yet. From then on the
 * server serves nothing more of the vault's items: a delta past those rows, as a real server answers.
 */
async function grantBackServedOnce(server: FakeSyncServer, alice: Browser, bob: Browser, vaultId: string): Promise<void> {
  await alice.store.addVaultMember(vaultId, BOB, "writer");
  await bob.store.sync();
  expect(bob.shared.pendingAsks().some((a) => a.vaultId === vaultId)).toBe(true);
  server.tamper = (r) => ({ ...r, items: r.items.filter((i) => i.vaultId !== vaultId) });
}

/**
 * A new store over the same offline copy: a reload of the page, and equally a lock and unlock (an unlock builds a new
 * VaultStore over the same cache and hydrates it, ui/opensession.ts `enterVault`), followed by its first sync.
 */
const reloaded = async (server: FakeSyncServer, bob: Browser): Promise<Browser> =>
  browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });

/** [who] accepts the ask to [vaultId] and pulls; the vault is back and nothing of it is held. */
async function acceptAndPull(who: Browser, vaultId: string): Promise<void> {
  const ask = who.shared.pendingAsks().find((a) => a.vaultId === vaultId);
  expect(ask).toBeDefined();
  expect((await who.shared.answer(ask!, true)).kind).toBe("adopted");
  await who.store.sync();
  expect(listed(who.store, vaultId)).toBe(true);
  expect(heldOf(who)).toEqual([]);
}

/**
 * [base] with every held record each commit of a pull writes counted, by vault: what `putHeld` is called with inside
 * `applyPull`, the one transaction of a pull.
 */
function countingHeldWrites(base: VaultCache): { cache: VaultCache; writes: Map<string, number> } {
  const writes = new Map<string, number>();
  const applyPull = base.applyPull.bind(base);
  const cache: VaultCache = Object.assign(Object.create(Object.getPrototypeOf(base) as object) as VaultCache, base, {
    applyPull: (fn: (b: PullBatch) => void) =>
      applyPull((b) => {
        const putHeld = b.putHeld.bind(b);
        fn({
          ...b,
          putHeld: (h: HeldVaultRecord) => {
            writes.set(h.vault.vaultId, (writes.get(h.vault.vaultId) ?? 0) + 1);
            putHeld(h);
          },
        });
      }),
  });
  return { cache, writes };
}

/** What the offline copy at rest holds of [itemId]: its live rows and the queued changes of it. */
async function atRest(itemId: string): Promise<{ live: number; queued: number }> {
  const cache = await openVaultCache(BOB);
  return {
    live: (await cache.envelopes()).filter((e) => e.itemId === itemId && !e.deleted).length,
    queued: (await cache.pending()).filter((m) => m.itemId === itemId).length,
  };
}

describe("added again to a shared vault: what was deleted or moved while the person was out stays so", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("(a) an item deleted in the vault while the person was out, whose deletion the answer carries, is not listed again, in memory or at rest, and nothing is queued for it", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeBob(alice, bob, old);
    await alice.store.remove(bankId);
    expect(server.items.get(bankId)?.deleted).toBe(true);
    await addBobAgainAndAccept(alice, bob, old);
    expect(namesIn(bob, old)).toEqual([]);
    expect(bob.store.get(bankId)).toBeUndefined();
    expect(await atRest(bankId)).toEqual({ live: 0, queued: 0 });
    expect(await bob.store.queuedMutationCount()).toBe(0);
    // A reload of the offline copy lists it no more either.
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    expect(namesIn(again, old)).toEqual([]);
    expect(server.items.get(bankId)?.deleted).toBe(true);
  });

  it("(a, served earlier) the deletion is served once, at the answer that brings the grant back, before the person accepts; the answer after the acceptance serves nothing of the vault: the item is not listed again", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeBob(alice, bob, old);
    await alice.store.remove(bankId);
    await alice.store.addVaultMember(old, BOB, "writer");
    await bob.store.sync(); // serves the vault's items, its deletion among them; the person is asked
    const ask = bob.shared.pendingAsks().find((a) => a.vaultId === old);
    expect(ask).toBeDefined();
    // From here on the server serves nothing more of the vault's items: a delta past the deletion's revision.
    server.tamper = (r) => ({ ...r, items: r.items.filter((i) => i.vaultId !== old) });
    expect((await bob.shared.answer(ask!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(heldOf(bob)).toEqual([]);
    expect(namesIn(bob, old)).toEqual([]);
    expect(await atRest(bankId)).toEqual({ live: 0, queued: 0 });
  });

  it("(b) an unsent edit of the deleted item, parked with the held copy, ends as a waiting edit ends on the ordinary road: sent, it brings the item back and the person is told once", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    answersPutOverDeletion(server, bob);
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
    try {
      await offline(bob, () => bob.store.save(bank.itemId, { ...bank.doc, name: "bank (edited)" }, [], undefined, old));
      expect(await bob.store.queuedMutationCount()).toBe(1);
      // The removal is learned before the edit is sent: the edit is parked with the held copy, never sent.
      await alice.store.removeVaultMember(old, BOB);
      await bob.shared.logs.refresh(old, null, null, true);
      await bob.store.sync();
      expect(heldOf(bob)).toEqual([old]);
      expect(server.items.get(bank.itemId)?.deleted).toBe(false);
      expect(await bob.store.queuedMutationCount()).toBe(0);
      expect(await bob.store.unsentChangeCount()).toBe(1);
      // The removal's notice carries no count; the held copy's waiting count (Sharing) is its one parked change.
      expect(noticesOf(bob, old)).toEqual(["removed"]);
      expect(bob.shared.logs.status(old).kind).toBe("removed");
      // While he is out, alice deletes the item; then she adds him again and he accepts.
      await alice.store.remove(bank.itemId);
      await addBobAgainAndAccept(alice, bob, old);
      await bob.store.sync(); // the answer that follows the replay
      // The ordinary road (sync: flushQueue sends a queued put; the answer `conflict` with the deletion's mark is
      // noteBroughtBack): the edit brought the item back, and the person is told so, once, with the count 1.
      expect(server.items.get(bank.itemId)).toMatchObject({ deleted: false });
      expect(namesIn(bob, old)).toEqual(["bank (edited)"]);
      expect(noticesOf(bob, old)).toEqual(["removed", "restored", "item-brought-back"]);
      expect(bob.store.notices().find((n) => n.vaultId === old && n.kind === "item-brought-back")?.parkedCount).toBe(1);
      expect(await bob.store.unsentChangeCount()).toBe(0);
      expect(await atRest(bank.itemId)).toEqual({ live: 1, queued: 0 });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("(b, the ordinary road) an unsent edit whose item a pull deletes: sent at the next sync, it brings the item back and the person is told once", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    answersPutOverDeletion(server, bob);
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
    try {
      await alice.store.remove(bank.itemId);
      await offline(bob, async () => {
        await bob.store.save(bank.itemId, { ...bank.doc, name: "bank (edited)" }, [], undefined, old);
        await bob.store.sync().catch(() => {});
      });
      await bob.store.sync();
      await bob.store.sync();
      expect(server.items.get(bank.itemId)).toMatchObject({ deleted: false });
      expect(namesIn(bob, old)).toEqual(["bank (edited)"]);
      expect(noticesOf(bob, old)).toEqual(["item-brought-back"]);
      expect(bob.store.notices().find((n) => n.vaultId === old)?.parkedCount).toBe(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("(c) an item moved to another shared vault the person reads, while they were out of its first vault, shows once, in the vault it was moved to", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const work = await alice.store.createSharedVault("Work");
    await alice.store.addVaultMember(work, BOB, "reader");
    await bob.store.sync();
    expect((await bob.shared.answer(bob.shared.pendingAsks().find((a) => a.vaultId === work)!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(listed(bob.store, work)).toBe(true);
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeBob(alice, bob, old);
    await alice.store.runGesture(alice.store.newMoveGesture(bankId, work, true));
    expect(server.items.get(bankId)?.deleted).toBe(true);
    await addBobAgainAndAccept(alice, bob, old);
    expect(everywhere(bob).filter((e) => e.endsWith(":bank"))).toEqual([`${work}:bank`]);
    expect(namesIn(bob, old)).toEqual([]);
    expect(await atRest(bankId)).toEqual({ live: 0, queued: 0 });
  });

  it("(e) the deletion is served at the answer that brings the grant back, and the page is reloaded (or locked and unlocked) before the person accepts: the item is not listed again, in memory or at rest, and nothing waits to be sent", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeBob(alice, bob, old);
    await alice.store.remove(bankId);
    await grantBackServedOnce(server, alice, bob, old);
    const again = await reloaded(server, bob);
    await acceptAndPull(again, old);
    expect(namesIn(again, old)).toEqual([]);
    expect(again.store.get(bankId)).toBeUndefined();
    expect(await atRest(bankId)).toEqual({ live: 0, queued: 0 });
    expect(await again.store.queuedMutationCount()).toBe(0);
    expect(await again.store.unsentChangeCount()).toBe(0);
    expect(server.items.get(bankId)?.deleted).toBe(true);
  });

  it("(f) on the same road, until the person accepts, the held copy keeps every item it held, the deleted one among them, in memory and at rest", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeBob(alice, bob, old);
    const heldBefore = heldIdsOf(bob, old);
    expect(heldBefore).toContain(bankId);
    await alice.store.remove(bankId);
    await grantBackServedOnce(server, alice, bob, old);
    expect(heldIdsOf(bob, old)).toEqual(heldBefore);
    const again = await reloaded(server, bob);
    expect(heldOf(again)).toEqual([old]);
    expect(listed(again.store, old)).toBe(false);
    expect(heldIdsOf(again, old)).toEqual(heldBefore);
    expect(await heldIdsAtRest(old)).toEqual(heldBefore);
  });

  it("(g) an item rewritten while the person was out at a format version this build cannot read: back, it is not live at its old held revision, the row at rest is the served one, and it is kept as a row this browser cannot read", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    await removeBob(alice, bob, old);
    const row = server.items.get(bank.itemId)!;
    const newRev = ++server.rev;
    server.items.set(bank.itemId, { ...row, rev: newRev, updatedAt: newRev, formatVersion: 99 });
    await addBobAgainAndAccept(alice, bob, old);
    expect(bob.store.get(bank.itemId)).toBeUndefined();
    expect(namesIn(bob, old)).toEqual([]);
    expect(await rowsAtRest(bank.itemId)).toEqual([{ rev: newRev, formatVersion: 99 }]);
    expect(bob.store.undecryptable().filter((u) => u.itemId === bank.itemId)).toEqual([{ itemId: bank.itemId, vaultId: old, formatVersion: 99 }]);
  });

  it("(h) an item moved to another shared vault the person reads, the move served at the answer that brings the grant back, and a new store built before the person accepts: it shows once, in the vault it was moved to", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const work = await alice.store.createSharedVault("Work");
    await alice.store.addVaultMember(work, BOB, "reader");
    await bob.store.sync();
    expect((await bob.shared.answer(bob.shared.pendingAsks().find((a) => a.vaultId === work)!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(listed(bob.store, work)).toBe(true);
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeBob(alice, bob, old);
    await alice.store.runGesture(alice.store.newMoveGesture(bankId, work, true));
    expect(server.items.get(bankId)?.deleted).toBe(true);
    await grantBackServedOnce(server, alice, bob, old);
    const again = await reloaded(server, bob);
    await acceptAndPull(again, old);
    expect(everywhere(again).filter((e) => e.endsWith(":bank"))).toEqual([`${work}:bank`]);
    expect(namesIn(again, old)).toEqual([]);
    expect(await atRest(bankId)).toEqual({ live: 0, queued: 0 });
  });

  it("(i) a deletion served while the copy is held is recorded with it at rest; a live row of the item served later takes the record out, and back the item shows once, at the served revision", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bank = alice.store.list().find((i) => i.vaultId === old)!;
    await removeBob(alice, bob, old);
    expect((await heldAtRest(old))?.deletedServed).toBeUndefined();
    await alice.store.remove(bank.itemId);
    await alice.store.addVaultMember(old, BOB, "writer");
    await bob.store.sync(); // serves the deletion; the person is asked
    expect((await heldAtRest(old))?.deletedServed).toEqual([bank.itemId]);
    expect(await heldIdsAtRest(old)).toEqual([bank.itemId]);
    await alice.store.restoreDeleted(bank.itemId, old, bank.doc);
    await bob.store.sync(); // serves the item live again, before the person accepts
    expect((await heldAtRest(old))?.deletedServed).toBeUndefined();
    expect(await heldIdsAtRest(old)).toEqual([bank.itemId]);
    const again = await reloaded(server, bob);
    await acceptAndPull(again, old);
    expect(namesIn(again, old)).toEqual(["bank"]);
    expect(again.store.get(bank.itemId)?.rev).toBe(server.items.get(bank.itemId)?.rev);
    expect(await atRest(bank.itemId)).toEqual({ live: 1, queued: 0 });
  });

  it("(j) many deletions served in one answer while the copy is held: the commit of that pull writes the held record once, the record at rest names every one, and the copy keeps every item", async () => {
    freshDb();
    const { cache, writes } = countingHeldWrites(await openVaultCache(BOB));
    const { alice, bob, old } = await family(cache);
    for (let k = 1; k < 60; k++) await alice.store.save(null, { type: "login", name: `item ${k}`, login: { username: "u", password: `p${k}` } }, [], undefined, old);
    await bob.store.sync();
    const ids = bob.store.list().filter((i) => i.vaultId === old).map((i) => i.itemId).sort();
    expect(ids).toHaveLength(60);
    await removeBob(alice, bob, old);
    expect(heldIdsOf(bob, old)).toEqual(ids);
    for (const id of ids) await alice.store.remove(id);
    await alice.store.addVaultMember(old, BOB, "writer");
    writes.clear();
    await bob.store.sync(); // brings the grant back and serves all 60 deletions; the person is asked
    expect(bob.shared.pendingAsks().some((a) => a.vaultId === old)).toBe(true);
    expect(writes.get(old)).toBe(1);
    expect([...((await heldAtRest(old))?.deletedServed ?? [])].sort()).toEqual(ids);
    expect(heldIdsOf(bob, old)).toEqual(ids);
    expect(await heldIdsAtRest(old)).toEqual(ids);
  }, 300000);

  it("(k, a number) a held record at rest whose served deletions are a number, not a list: the next sync completes and the held copy is as it was; a deletion served later is recorded as a list", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeBob(alice, bob, old);
    const before = (await heldAtRest(old))!;
    const heldBefore = before.items.map((w) => w.itemId).sort();
    await (await openVaultCache(BOB)).putHeld({ ...before, deletedServed: 5 as unknown as string[] });
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    await alice.store.addVaultMember(old, BOB, "writer");
    await again.store.sync(); // serves the vault's items live again; the person is asked
    expect(again.shared.pendingAsks().some((a) => a.vaultId === old)).toBe(true);
    expect(heldOf(again)).toEqual([old]);
    expect(listed(again.store, old)).toBe(false);
    expect(heldIdsOf(again, old)).toEqual(heldBefore);
    expect(await heldIdsAtRest(old)).toEqual(heldBefore);
    await alice.store.remove(bankId);
    await again.store.sync(); // serves the deletion, still before the person accepts
    expect((await heldAtRest(old))?.deletedServed).toEqual([bankId]);
    expect(await heldIdsAtRest(old)).toEqual(heldBefore);
  });

  it("(k, a string) a held record at rest whose served deletions are a string, not a list: no item is left out because its id stands inside the string", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeBob(alice, bob, old);
    const before = (await heldAtRest(old))!;
    await (await openVaultCache(BOB)).putHeld({ ...before, deletedServed: `xx${bankId}xx` as unknown as string[] });
    // The server serves nothing of the vault's items from here on: the item comes back from the held copy alone.
    server.tamper = (r) => ({ ...r, items: r.items.filter((i) => i.vaultId !== old) });
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    await alice.store.addVaultMember(old, BOB, "writer");
    await again.store.sync(); // the person is asked
    await acceptAndPull(again, old);
    expect(server.items.get(bankId)?.deleted).toBe(false);
    expect(namesIn(again, old)).toEqual(["bank"]);
    expect(await atRest(bankId)).toEqual({ live: 1, queued: 0 });
  });

  it("(l) a deletion first served in the very pull that puts the copy back: no held record is left at rest, nothing is held after a reload, a further sync restores nothing a second time, and only the deleted item stays out", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bank = alice.store.list().find((i) => i.vaultId === old)!;
    await alice.store.save(null, { type: "login", name: "mail", login: { username: "m", password: "pw2" } }, [], undefined, old);
    const mailId = alice.store.list().find((i) => i.vaultId === old && i.doc.name === "mail")!.itemId;
    await bob.store.sync();
    await removeBob(alice, bob, old);
    expect(heldIdsOf(bob, old)).toEqual([bank.itemId, mailId].sort());
    await alice.store.addVaultMember(old, BOB, "writer");
    await bob.store.sync(); // brings the grant back; the person is asked
    const ask = bob.shared.pendingAsks().find((a) => a.vaultId === old);
    expect(ask).toBeDefined();
    await alice.store.remove(bank.itemId); // after the answer that asked him: no pull of his has served it yet
    expect((await heldAtRest(old))?.deletedServed).toBeUndefined();
    expect((await bob.shared.answer(ask!, true)).kind).toBe("adopted");
    expect(heldOf(bob)).toEqual([old]);
    await bob.store.sync(); // the one pull that serves the deletion for the first time and puts the vault back
    expect(listed(bob.store, old)).toBe(true);
    expect(heldOf(bob)).toEqual([]);
    expect(noticesOf(bob, old)).toEqual(["removed", "restored"]);
    // 1. After that pull, no held record of the vault is at rest.
    expect(await heldAtRest(old)).toBeUndefined();
    // 2. A new store over the same offline copy (a reload) holds nothing of the vault.
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    expect(heldOf(again)).toEqual([]);
    // 3. A further sync puts the vault back no second time: it stays listed, nothing is held, and the person was told once.
    await again.store.sync();
    expect({
      held: heldOf(again),
      listed: listed(again.store, old),
      restored: [...noticesOf(bob, old), ...noticesOf(again, old)].filter((k) => k === "restored").length,
    }).toEqual({ held: [], listed: true, restored: 1 });
    // 4. The deleted item is not among the vault's live items; its other item is.
    expect(again.store.list().filter((i) => i.vaultId === old).map((i) => i.itemId)).toEqual([mailId]);
  });

  // (d) An item absent from the answer, with no deletion of it served (deleted for good, or left out by the server):
  // the held copy puts it back, as store.cards.test.ts pins. That road is not changed here; what it shows and sends is
  // recorded below, so that a later change of it is a decision, not an accident.
  it("(d, today) an item deleted for good while the person was out is listed again from the held copy; an edit of it stores it again on the server", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    await removeBob(alice, bob, old);
    server.items.delete(bank.itemId); // purged: the server serves neither the item nor its deletion
    await addBobAgainAndAccept(alice, bob, old);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(bob.store.get(bank.itemId)?.rev).toBe(bank.rev);
    expect(await atRest(bank.itemId)).toEqual({ live: 1, queued: 0 });
    await bob.store.save(bank.itemId, { ...bank.doc, name: "bank (edited)" }, [], undefined, old);
    expect(server.items.get(bank.itemId)).toMatchObject({ vaultId: old, deleted: false });
    expect(noticesOf(bob, old)).toEqual(["removed", "restored"]);
  });
});
