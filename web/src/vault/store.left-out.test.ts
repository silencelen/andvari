// What a browser holds does not vanish without a trace where it cannot tell why: when the server answers a sync with
// "start again from nothing" (410), an item this browser held of the personal vault, or of a shared vault still listed
// (frozen or not), that the fresh list neither carries nor marks as deleted is set aside, sealed, for 30 days, with a
// notice. One the list marks as deleted is dropped as on the ordinary road. One that a later answer serves again goes
// back to its vault and leaves the set: it never exists twice. Driven through the real VaultStore, SharedLogSession and
// VaultLogStore against a fake server that serves what it likes.
import { beforeAll, describe, expect, it } from "vitest";
import type { SyncResponse } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { fill, ITEMS_SET_ASIDE_FROZEN_NOTICE, ITEMS_SET_ASIDE_PERSONAL_NOTICE, ITEMS_SET_ASIDE_SHARED_NOTICE } from "../ui/copy";
import { noticeBody } from "../ui/Vault";
import { BOB, browser, family, freezeByRecord, freshDb, heldOf, listed, namesIn, noticesOf } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

/** Bob's answers, full ones or deltas, with [vaultId]'s items left out (or, [deleted], each one marked deleted). */
function leaveOut(vaultId: string, on: "full" | "delta" | "both", deleted = false) {
  return (r: SyncResponse, _since: number, userId: string): SyncResponse => {
    if (userId !== BOB || (on === "full" && !r.full) || (on === "delta" && r.full)) return r;
    return { ...r, items: deleted ? r.items.map((i) => (i.vaultId === vaultId ? { ...i, deleted: true, blob: "" } : i)) : r.items.filter((i) => i.vaultId !== vaultId) } as SyncResponse;
  };
}

describe("an item a fresh list neither carries nor marks as deleted is set aside with a notice", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the personal vault: its item left out of the fresh list (with the vault's rows) is set aside, kept at rest, and goes back once when served again", async () => {
    freshDb();
    const { server, bob } = await family(await openVaultCache(BOB));
    const pv = bob.profile.personalVaultId;
    await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "mine" } }, [], undefined, pv);
    await bob.store.sync();
    server.tamper = (r, since, userId) => {
      const out = leaveOut(pv, "full")(r, since, userId);
      return userId === BOB && r.full ? ({ ...out, grants: out.grants.filter((g) => g.vaultId !== pv), vaults: out.vaults.filter((v) => v.vaultId !== pv) } as SyncResponse) : out;
    };
    server.forgetHistory();
    await bob.store.sync();
    expect(namesIn(bob, pv)).toEqual([]);
    expect(noticesOf(bob, pv)).toEqual(["items-set-aside"]);
    const n = bob.store.notices().find((x) => x.vaultId === pv)!;
    expect(n).toMatchObject({ parkedCount: 1, personal: true });
    expect(noticeBody(n)).toEqual({ warn: true, body: fill(ITEMS_SET_ASIDE_PERSONAL_NOTICE, "1 item") });
    expect(bob.store.itemsSetAside()).toMatchObject([{ vaultId: pv, personal: true, itemCount: 1, canCopyOut: true }]);
    // At rest: a reload, the server still leaving it out, finds it set aside.
    server.tamper = leaveOut(pv, "delta");
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(again.store.itemsSetAside()).toMatchObject([{ vaultId: pv, itemCount: 1 }]);
    expect(namesIn(again, pv)).toEqual([]);
    // Served again: back in its vault, once, and no longer set aside, at rest too.
    server.tamper = null;
    server.rev++;
    await again.store.sync();
    expect(namesIn(again, pv)).toEqual(["my-own"]);
    expect(again.store.itemsSetAside()).toEqual([]);
    const third = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(namesIn(third, pv)).toEqual(["my-own"]);
    expect(third.store.itemsSetAside()).toEqual([]);
    expect((await (await openVaultCache(BOB)).heldVaults()).length).toBe(0);
  });

  it("the personal vault: an item the fresh list marks as deleted is dropped, with no notice and nothing set aside (as on the ordinary road)", async () => {
    freshDb();
    const { server, bob } = await family(await openVaultCache(BOB));
    const pv = bob.profile.personalVaultId;
    await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "mine" } }, [], undefined, pv);
    await bob.store.sync();
    server.tamper = leaveOut(pv, "full", true);
    server.forgetHistory();
    await bob.store.sync();
    expect(namesIn(bob, pv)).toEqual([]);
    expect(bob.store.notices()).toEqual([]);
    expect(bob.store.itemsSetAside()).toEqual([]);
  });

  it("the personal vault named as removed by a delta: nothing changes, and the notice says the removal was refused (the comparison)", async () => {
    freshDb();
    const { server, bob } = await family(await openVaultCache(BOB));
    const pv = bob.profile.personalVaultId;
    await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "mine" } }, [], undefined, pv);
    await bob.store.sync();
    server.tamper = (r, _s, userId) => (userId === BOB && !r.full ? ({ ...r, removedGrants: [...r.removedGrants, pv] } as SyncResponse) : r);
    server.rev++;
    await bob.store.sync();
    expect(namesIn(bob, pv)).toEqual(["my-own"]);
    expect(noticesOf(bob, pv)).toEqual(["personal-kept"]);
    expect(bob.store.itemsSetAside()).toEqual([]);
  });

  it("a frozen vault the owner removed, answered 410 with both of its rows and no item: it stays listed, and its item is set aside with the frozen vault's notice", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await freezeByRecord(bob, old);
    const row = server.grantRowOf(old, BOB);
    await alice.store.removeVaultMember(old, BOB);
    server.tamper = (r, _s, userId) =>
      userId === BOB && r.full ? ({ ...r, grants: [...r.grants, row], vaults: [...r.vaults, server.vaultRowOf(old)], items: r.items.filter((i) => i.vaultId !== old), removedGrants: r.removedGrants.filter((id) => id !== old) } as SyncResponse) : r;
    server.forgetHistory();
    await bob.store.sync();
    expect(bob.shared.logs.status(old).kind).toBe("frozen");
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual([]);
    expect(heldOf(bob)).toEqual([]);
    expect(noticesOf(bob, old)).toEqual(["items-set-aside"]);
    const n = bob.store.notices().find((x) => x.vaultId === old)!;
    expect(n).toMatchObject({ parkedCount: 1, frozen: true, vaultName: "Family" });
    expect(noticeBody(n)).toEqual({ warn: true, body: fill(ITEMS_SET_ASIDE_FROZEN_NOTICE, "1 item", "Family") });
    expect(bob.store.itemsSetAside()).toMatchObject([{ vaultId: old, name: "Family", personal: false, itemCount: 1 }]);
  });

  it("a vault the person is still a member of, answered 410 with its rows and none of its items: they are set aside with a notice, the vault stays listed", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    server.tamper = leaveOut(old, "full");
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual([]);
    const n = bob.store.notices().find((x) => x.vaultId === old)!;
    expect(n.kind).toBe("items-set-aside");
    expect(noticeBody(n)).toEqual({ warn: true, body: fill(ITEMS_SET_ASIDE_SHARED_NOTICE, "1 item", "Family") });
    // Copied out into the personal vault, each as a new item; then removed from this device, at rest too.
    expect(await bob.store.copySetAsideToPersonal(old)).toEqual({ copied: 1, attachmentsLeftOut: 0, unreadable: 0 });
    expect(namesIn(bob, bob.profile.personalVaultId)).toEqual(["bank"]);
    await bob.store.removeSetAside(old);
    expect(bob.store.itemsSetAside()).toEqual([]);
    expect((await (await openVaultCache(BOB)).heldVaults()).length).toBe(0);
  });

  it("a shared vault's item the fresh list marks as deleted is dropped as today, with no notice and nothing set aside", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    server.tamper = leaveOut(old, "full", true);
    server.forgetHistory();
    await bob.store.sync();
    expect(listed(bob.store, old)).toBe(true);
    expect(namesIn(bob, old)).toEqual([]);
    expect(bob.store.notices()).toEqual([]);
    expect(bob.store.itemsSetAside()).toEqual([]);
  });

  it("the personal vault's item served by the fresh list under another vault only: refused for its vault, and set aside", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    const pv = bob.profile.personalVaultId;
    await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "mine" } }, [], undefined, pv);
    await bob.store.sync();
    server.tamper = (r, _s, userId) => (userId === BOB && r.full ? ({ ...r, items: r.items.map((i) => (i.vaultId === pv ? { ...i, vaultId: old } : i)) } as SyncResponse) : r);
    server.forgetHistory();
    await bob.store.sync();
    expect(namesIn(bob, pv)).toEqual([]);
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(bob.store.notices().map((n) => n.kind).sort()).toEqual(["items-set-aside", "wrong-vault"]);
    expect(bob.store.itemsSetAside()).toMatchObject([{ vaultId: pv, itemCount: 1 }]);
  });

  it("a resync that leaves nothing out sets nothing aside and says nothing", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    const pv = bob.profile.personalVaultId;
    await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "mine" } }, [], undefined, pv);
    await bob.store.sync();
    server.forgetHistory();
    await bob.store.sync();
    expect(namesIn(bob, old)).toEqual(["bank"]);
    expect(namesIn(bob, pv)).toEqual(["my-own"]);
    expect(bob.store.notices()).toEqual([]);
    expect(bob.store.itemsSetAside()).toEqual([]);
  });

  it("left out at two resyncs in a row: one set of the item, not two, and its days run from the first", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    server.tamper = leaveOut(old, "full");
    server.forgetHistory();
    await bob.store.sync();
    const first = bob.store.itemsSetAside()[0]!.expungeAt;
    server.forgetHistory();
    await bob.store.sync();
    expect(bob.store.itemsSetAside()).toMatchObject([{ vaultId: old, itemCount: 1 }]);
    expect(bob.store.itemsSetAside()[0]!.expungeAt).toBeGreaterThanOrEqual(first);
  });
});
