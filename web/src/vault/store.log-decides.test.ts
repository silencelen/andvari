// A shared vault's log of who is in it is signed by its members and checked by this browser; what the server serves
// beside it is not. So on every sync, a 410 resync and an ordinary delta alike, a vault this browser holds whose verified
// log no longer names the account (removed, purged, or the vault deleted) takes the removal's road BEFORE anything the
// server serves for it is applied: the held copy, made from what this browser held before the answer, and the notice;
// it is not listed as the person's any more, whatever rows the server sends. Driven through the real VaultStore,
// SharedLogSession and VaultLogStore against a fake server that serves what it likes.
import { beforeAll, describe, expect, it } from "vitest";
import type { SyncResponse, WireItem, WireVault } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { BOB, browser, type Browser, commitsFail, family, type FakeSyncServer, freezeByRecord, freshDb, heldOf, listed, namesIn, noticesOf } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

/**
 * After the owner removed bob from [vaultId]: every answer the server gives (full ones, or deltas, or both) serves bob's
 * grant row as it was before the removal and the vault's own row, names no removal, and serves [items] of the vault:
 * "none", "as held" (unchanged), or "deleted" (each one marked deleted). [logHead] false serves the vault row without one.
 */
function servedOnAfterRemoval(server: FakeSyncServer, vaultId: string, opts: { on: "full" | "delta" | "both"; items: "none" | "as held" | "deleted"; logHead?: boolean }): void {
  const row = server.grantRowOf(vaultId, BOB);
  const held: WireItem[] = [...server.items.values()].filter((i) => i.vaultId === vaultId);
  return void (server.tamper = (r: SyncResponse, _since: number, userId: string) => {
    if (userId !== BOB || (opts.on === "full" && !r.full) || (opts.on === "delta" && r.full)) return r;
    const vaultRow: WireVault = opts.logHead === false ? ({ vaultId, type: "shared", rev: server.rev, metaBlob: server.metas.get(vaultId) ?? "", createdAt: 0 } as WireVault) : server.vaultRowOf(vaultId);
    const its = opts.items === "none" ? [] : opts.items === "as held" ? held : held.map((i) => ({ ...i, deleted: true, rev: server.rev, blob: "" }));
    return {
      ...r,
      grants: [...r.grants.filter((g) => g.vaultId !== vaultId), row],
      vaults: [...r.vaults.filter((v) => v.vaultId !== vaultId), vaultRow],
      items: [...r.items.filter((i) => i.vaultId !== vaultId), ...its],
      removedGrants: r.removedGrants.filter((id) => id !== vaultId),
    } as SyncResponse;
  });
}

/** What [who] shows of [vaultId]: not listed, no item of it, the notice [kind], and one held copy of its one item. */
function heldWithNotice(who: Browser, vaultId: string, kind: string): void {
  expect(listed(who.store, vaultId)).toBe(false);
  expect(namesIn(who, vaultId)).toEqual([]);
  expect(noticesOf(who, vaultId)).toEqual([kind]);
  expect(heldOf(who)).toEqual([vaultId]);
  expect(who.store.heldVaults()[0]).toMatchObject({ name: "Family", itemCount: 1 });
}

describe("a shared vault whose verified log no longer names the account takes the removal's road, whatever the server serves of it", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a 410 whose fresh list serves both of the vault's rows, with no log head and no item, after the owner's removal: the notice and the held copy, also after a reload", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    servedOnAfterRemoval(server, old, { on: "full", items: "none", logHead: false });
    await alice.store.removeVaultMember(old, BOB);
    server.forgetHistory();
    await bob.store.sync();
    heldWithNotice(bob, old, "removed");
    // At rest: a reload with the offline copy holds the copy and lists the vault no more.
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(heldOf(again)).toEqual([old]);
    expect(listed(again.store, old)).toBe(false);
  });

  for (const items of ["none", "as held"] as const) {
    it(`a 410 whose fresh list serves both rows with the true log head and ${items === "none" ? "no item" : "the vault's items"}, naming no removal: the notice and the held copy`, async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      servedOnAfterRemoval(server, old, { on: "full", items });
      await alice.store.removeVaultMember(old, BOB);
      server.forgetHistory();
      await bob.store.sync();
      heldWithNotice(bob, old, "removed");
      expect(bob.store.vaults().some((v) => v.vaultId === old)).toBe(false);
    });
  }

  for (const items of ["deleted", "as held"] as const) {
    it(`a delta that serves both rows and ${items === "deleted" ? "marks the vault's item deleted" : "its items unchanged"}, naming no removal: the notice and the held copy, made from what this browser held`, async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      servedOnAfterRemoval(server, old, { on: "delta", items });
      await alice.store.removeVaultMember(old, BOB);
      server.rev++;
      await bob.store.sync();
      heldWithNotice(bob, old, "removed");
      const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
      expect(heldOf(again)).toEqual([old]);
      expect(again.store.heldVaults()[0]!.itemCount).toBe(1);
      expect(listed(again.store, old)).toBe(false);
    });
  }
});

describe("one step further: what the server can still serve, and what this browser then shows", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the owner deletes the vault and the server goes on serving both rows with no item: the deletion's notice and the held copy; the owner's restore lists it again", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    servedOnAfterRemoval(server, old, { on: "both", items: "none" });
    await alice.store.deleteSharedVault(old);
    server.forgetHistory();
    await bob.store.sync();
    heldWithNotice(bob, old, "deleted");
    server.tamper = null;
    await alice.store.restoreSharedVault(old, alice.shared.logs.verifiedState(old)!.deleteId!);
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(heldOf(bob)).toEqual([]);
    expect(noticesOf(bob, old)).toEqual(["deleted", "restored"]);
  });

  it("the person added again after the removal: listed again once they accept, the held copy goes, and the notice says it is back", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    servedOnAfterRemoval(server, old, { on: "full", items: "none" });
    await alice.store.removeVaultMember(old, BOB);
    server.forgetHistory();
    await bob.store.sync();
    heldWithNotice(bob, old, "removed");
    server.tamper = null;
    await alice.store.addVaultMember(old, BOB, "writer");
    await bob.store.sync();
    const ask = bob.shared.pendingAsks().find((a) => a.vaultId === old);
    expect(ask).toBeDefined();
    expect((await bob.shared.answer(ask!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(heldOf(bob)).toEqual([]);
    expect(noticesOf(bob, old)).toEqual(["removed", "restored"]);
  });

  it("a server that withholds the log's newest entries (the removal among them): the log still names the account, so the vault stays listed with what is served", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const before = server.logs.get(old)!.length;
    servedOnAfterRemoval(server, old, { on: "full", items: "as held" });
    await alice.store.removeVaultMember(old, BOB);
    server.logCut.set(old, before);
    server.forgetHistory();
    await bob.store.sync();
    expect(bob.shared.logs.status(old).kind).toBe("verified");
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    // Once the server serves the whole log, the removal is read there, whatever rows it goes on serving.
    server.logCut.delete(old);
    servedOnAfterRemoval(server, old, { on: "delta", items: "as held" });
    server.rev++;
    await bob.store.sync();
    heldWithNotice(bob, old, "removed");
  });

  it("a vault frozen here decides nothing by its log: served on with its rows and items it stays listed as served; an item a delta marks deleted is dropped as on the ordinary road", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await freezeByRecord(bob, old);
    servedOnAfterRemoval(server, old, { on: "full", items: "as held" });
    await alice.store.removeVaultMember(old, BOB);
    server.forgetHistory();
    await bob.store.sync();
    expect(bob.shared.logs.status(old).kind).toBe("frozen");
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(bob.store.notices()).toEqual([]);
    servedOnAfterRemoval(server, old, { on: "delta", items: "deleted" });
    server.rev++;
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual([]);
    expect(heldOf(bob)).toEqual([]);
  });

  it("several shared vaults, one of them decided by its log: only that one is held and told; the other stays listed with its items", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const work = await alice.store.createSharedVault("Work");
    await alice.store.addVaultMember(work, BOB, "reader");
    await alice.store.save(null, { type: "login", name: "mail", login: { username: "w", password: "pw2" } }, [], undefined, work);
    await bob.store.sync();
    expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    servedOnAfterRemoval(server, old, { on: "both", items: "deleted" });
    await alice.store.removeVaultMember(old, BOB);
    server.forgetHistory();
    await bob.store.sync();
    heldWithNotice(bob, old, "removed");
    expect(listed(bob.store, work)).toBe(true);
    expect(namesIn(bob, work)).toEqual(["mail"]);
    expect(noticesOf(bob, work)).toEqual([]);
  });

  it("two tabs, each answered with both rows after the removal: each says it, and one held copy is kept at rest", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const tab2 = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    servedOnAfterRemoval(server, old, { on: "delta", items: "deleted" });
    await alice.store.removeVaultMember(old, BOB);
    server.rev++;
    await bob.store.sync();
    await tab2.store.sync();
    heldWithNotice(bob, old, "removed");
    heldWithNotice(tab2, old, "removed");
    const disk = await openVaultCache(BOB);
    expect((await disk.heldVaults()).map((h) => [h.vault.vaultId, h.items.length])).toEqual([[old, 1]]);
    expect((await disk.envelopes()).filter((e) => e.vaultId === old)).toEqual([]);
  });

  it("the page closes between the decision and the write: nothing at rest changed, and the next start gives the notice and the held copy", async () => {
    freshDb();
    const state = { fail: false };
    const { server, alice, bob, old } = await family(commitsFail(await openVaultCache(BOB), state));
    servedOnAfterRemoval(server, old, { on: "both", items: "none" });
    await alice.store.removeVaultMember(old, BOB);
    server.forgetHistory();
    state.fail = true;
    await bob.store.sync().catch(() => {});
    const disk = await openVaultCache(BOB);
    expect((await disk.heldVaults()).length).toBe(0);
    expect((await disk.envelopes()).filter((e) => e.vaultId === old).length).toBe(1);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    heldWithNotice(again, old, "removed");
    expect((await (await openVaultCache(BOB)).heldVaults()).map((h) => h.items.length)).toEqual([1]);
  });
});
