// A removal read from a shared vault's verified log is carried out the same whether or not the page closes part-way:
// stopped at any one of its writes, the next start and one honest answer end where the uncut run ends (what is listed,
// which vaults have a working key, the held copies, the notices told and the questions asked), also when the owner added
// the person again in between. A key opened through the account's own wrap to seal a held copy is never a working key:
// it lists no vault, shows no item, and allows no write. And the verified log is read before anything an answer serves
// for a vault this browser holds is applied, whatever that answer serves: a vault row, a grant row (the key), an item,
// or a marker that an item is deleted. Driven through the real VaultStore, SharedLogSession and VaultLogStore against a
// fake server that serves what it likes.
import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import type { SyncResponse, WireItem } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { BOB, browser, type Browser, type Closing, closingAt, commitsFail, family, freshDb, listed, namesIn, noticesOf } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

/** What [who] shows of [vaultId]: listed, a working key, the items shown, its held copies (items in each), the questions asked. */
const seen = (who: Browser, vaultId: string) => ({
  listed: listed(who.store, vaultId),
  key: who.account.hasVault(vaultId),
  items: namesIn(who, vaultId),
  held: who.store.heldVaults().filter((h) => h.vaultId === vaultId).map((h) => h.itemCount),
  asks: who.shared.pendingAsks().filter((a) => a.vaultId === vaultId).length,
});

/** The held copies of [vaultId] in the offline copy at rest (items in each), items set aside not counted. */
const heldAtRest = async (vaultId: string): Promise<number[]> =>
  (await (await openVaultCache(BOB)).heldVaults()).filter((h) => h.vault.vaultId === vaultId && h.setAside !== true).map((h) => h.items.length);

/**
 * The removal's road, closed at its write [at] (Infinity: never): bob's tab reads the owner's removal of "Family" in a
 * sync whose writes stop at [at]; then, where [readd], the owner adds bob again; then bob starts again and gets one
 * honest answer. [writes]: how many writes that sync made. [told]: the notices about the vault told by a session whose
 * pull commit landed (a notice told by a page that closed before its commit is not the browser's record).
 */
async function removalRun(at: number, readd: boolean) {
  freshDb();
  const { server, alice, bob, old } = await family(await openVaultCache(BOB));
  const c: Closing = { at: Infinity, n: 0, committed: false };
  const io = closingAt(bob.profile.storage, await openVaultCache(BOB), c);
  const tab = await browser(server, bob.person, bob.contacts, { cache: io.cache, again: { ...bob.profile, storage: io.storage } });
  await alice.store.removeVaultMember(old, BOB);
  Object.assign(c, { at, n: 0, committed: false });
  await tab.store.sync().catch(() => {});
  const writes = c.n;
  const toldByTab = c.committed ? noticesOf(tab, old) : [];
  if (readd) {
    await alice.store.sync();
    await alice.store.addVaultMember(old, BOB, "writer");
  }
  const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
  const told = [...new Set([...toldByTab, ...noticesOf(again, old)])].sort();
  return { writes, end: { ...seen(again, old), atRest: await heldAtRest(old), told } };
}

describe("a removal read from the verified log, the page closed part-way", () => {
  beforeAll(async () => {
    await initSodium();
  });

  for (const readd of [false, true]) {
    it(`stopped at each write of the removal's road${readd ? ", the person added again before the next start" : ""}: the next start and one honest answer end where the uncut run ends`, async () => {
      const uncut = await removalRun(Infinity, readd);
      expect(uncut.end).toEqual({ listed: false, key: false, items: [], held: [1], asks: readd ? 1 : 0, atRest: [1], told: ["removed"] });
      expect(uncut.writes).toBeGreaterThan(1);
      const differs: string[] = [];
      for (let at = 0; at < uncut.writes; at++) {
        const cut = await removalRun(at, readd);
        if (JSON.stringify(cut.end) !== JSON.stringify(uncut.end)) differs.push(`closed at write ${at} of ${uncut.writes}: ${JSON.stringify(cut.end)}`);
      }
      expect(differs).toEqual([]);
    }, 600_000);
  }

  it("the removal read, the page closed before its commit, the owner adds the person again, and the next start's answer leaves out the vault's row: held and told, not listed and no key; the question comes with the vault's row, before anything is shown", async () => {
    freshDb();
    const state = { fail: false };
    const { server, alice, bob, old } = await family(commitsFail(await openVaultCache(BOB), state));
    await alice.store.removeVaultMember(old, BOB);
    state.fail = true;
    await bob.store.sync().catch(() => {});
    state.fail = false;
    await alice.store.sync();
    await alice.store.addVaultMember(old, BOB, "writer");
    server.tamper = (r, _s, userId) => (userId !== BOB || r.full ? r : ({ ...r, vaults: r.vaults.filter((v) => v.vaultId !== old) } as SyncResponse));
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
    expect(noticesOf(again, old)).toEqual(["removed"]);
    server.tamper = null;
    await again.store.sync();
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
  });

  it("the same, the next start's answer serving the vault's row: held and told, not listed and no key, and the question to join again is asked", async () => {
    freshDb();
    const state = { fail: false };
    const { server, alice, bob, old } = await family(commitsFail(await openVaultCache(BOB), state));
    await alice.store.removeVaultMember(old, BOB);
    state.fail = true;
    await bob.store.sync().catch(() => {});
    state.fail = false;
    await alice.store.sync();
    await alice.store.addVaultMember(old, BOB, "writer");
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(noticesOf(again, old)).toEqual(["removed"]);
    expect(await heldAtRest(old)).toEqual([1]);
  });

  it("another device of the account reads the removal first, so the account's record no longer lets the key be adopted: this browser's next start still keeps the held copy and tells it", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await alice.store.removeVaultMember(old, BOB);
    const phone = await browser(server, bob.person, bob.contacts, { again: { storage: memoryStorage(), personalVaultId: bob.profile.personalVaultId, personalVk: bob.profile.personalVk } });
    expect(phone.shared.accountState.local().accepted.get(old)?.decision).toBe("decline");
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
    expect(noticesOf(again, old)).toEqual(["removed"]);
    expect(await heldAtRest(old)).toEqual([1]);
  });

  it("the key opened through the account's own wrap to seal the held copy is never a working key: at every fetch of the vault's log during that sync the vault is not listed, no item of it is shown, and a save into it is refused", async () => {
    freshDb();
    const state = { fail: false };
    const { server, alice, bob, old } = await family(commitsFail(await openVaultCache(BOB), state));
    await alice.store.removeVaultMember(old, BOB);
    state.fail = true;
    await bob.store.sync().catch(() => {});
    state.fail = false;
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const during: unknown[] = [];
    const saves: Promise<string>[] = [];
    server.onLogPage = (vaultId) => {
      if (vaultId !== old) return;
      during.push({ listed: listed(again.store, old), key: again.account.hasVault(old), items: namesIn(again, old) });
      saves.push(again.store.save(null, { type: "login", name: "late", login: { username: "x", password: "y" } }, [], undefined, old).then(() => "saved", () => "refused"));
    };
    await again.store.sync();
    server.onLogPage = null;
    expect(during.length).toBeGreaterThan(0);
    expect(during).toEqual(during.map(() => ({ listed: false, key: false, items: [] })));
    expect(await Promise.all(saves)).toEqual(saves.map(() => "refused"));
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
    expect(noticesOf(again, old)).toEqual(["removed"]);
  });
});

describe("the verified log is read before anything an answer serves for a held vault is applied, whatever it serves", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** After the owner removed bob: bob's next delta names no removal, serves no vault row, and serves [extra] alone. */
  async function afterRemovalServing(extra: (old: string, its: WireItem[], bump: number, mine: WireItem[]) => Partial<SyncResponse>) {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const row = server.grantRowOf(old, BOB);
    const pv = bob.profile.personalVaultId;
    await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "mine" } }, [], undefined, pv);
    await bob.store.sync();
    await alice.store.removeVaultMember(old, BOB);
    const its = [...server.items.values()].filter((i) => i.vaultId === old);
    const mine = [...server.items.values()].filter((i) => i.vaultId === pv);
    const bump = ++server.rev;
    const add = extra(old, its, bump, mine);
    server.tamper = (r, _s, userId) =>
      userId !== BOB || r.full
        ? r
        : ({
            ...r,
            removedGrants: r.removedGrants.filter((id) => id !== old),
            grants: [...r.grants, ...(add.grants === undefined ? [] : add.grants.map((g) => (g.vaultId === old ? row : g)))],
            items: [...r.items.filter((i) => i.vaultId !== old), ...(add.items ?? [])],
          } as SyncResponse);
    return { server, bob, old, pv };
  }

  it("a delta that serves only markers that the vault's items are deleted: held from what this browser held, and told", async () => {
    const { server, bob, old } = await afterRemovalServing((_old, its, bump) => ({ items: its.map((i) => ({ ...i, deleted: true, rev: bump, blob: "" })) }));
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
    expect(noticesOf(bob, old)).toEqual(["removed"]);
    server.tamper = null;
    server.rev++;
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
  });

  it("a delta that serves only this account's grant row of the vault (its key): held and told", async () => {
    const { bob, old } = await afterRemovalServing((vaultId) => ({ grants: [{ vaultId } as never] }));
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
    expect(noticesOf(bob, old)).toEqual(["removed"]);
  });

  it("a delta that serves only the vault's items unchanged: held and told", async () => {
    const { bob, old } = await afterRemovalServing((_old, its) => ({ items: its }));
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
    expect(noticesOf(bob, old)).toEqual(["removed"]);
  });

  it("a delta that serves only a marker that an item of the personal vault is deleted, under the shared vault's id: the shared vault is held and told, the personal item stays", async () => {
    const { bob, old, pv } = await afterRemovalServing((vaultId, _its, bump, mine) => ({ items: [{ ...mine[0]!, vaultId, deleted: true, rev: bump, blob: "" }] }));
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
    expect(noticesOf(bob, old)).toEqual(["removed"]);
    expect(namesIn(bob, pv)).toEqual(["my-own"]);
  });
});
