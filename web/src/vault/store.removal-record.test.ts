// What decides whether a removal from a shared vault is still owed is one record, written together with what it
// describes: with each shared vault's offline copy, the `add` of the vault's log under which this browser adopted the
// vault or last carried a removal out; and, beside each key in the session's ring, the `add` under which this session
// adopted it. Wherever the verified log names the account through another `add`, or not at all, the removal is carried
// out (the held copy, the notice), and where it names the account again the question to join again is asked before
// anything is shown or can be written. And a key works only while its `add` is the one the verified log names now: a
// road that moves the log without the rule running (another tab, a chase of an item's head, a read outside a pull, a new
// start) shows nothing and writes nothing of that vault. Driven through the real VaultStore, SharedLogSession and
// VaultLogStore against a fake server that serves what it likes.
import { beforeAll, describe, expect, it } from "vitest";
import type { SyncResponse } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { BOB, browser, type Browser, type Closing, closingAt, commitsFail, family, freshDb, listed, namesIn, noticesOf } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

/** What [who] shows of [vaultId]: listed, a key in the ring, the items shown, its held copies (items in each), the questions asked. */
const seen = (who: Browser, vaultId: string) => ({
  listed: listed(who.store, vaultId),
  key: who.account.hasVault(vaultId),
  items: namesIn(who, vaultId),
  held: who.store.heldVaults().filter((h) => h.vaultId === vaultId).map((h) => h.itemCount),
  asks: who.shared.pendingAsks().filter((a) => a.vaultId === vaultId).length,
});
const heldAtRest = async (vaultId: string): Promise<number[]> =>
  (await (await openVaultCache(BOB)).heldVaults()).filter((h) => h.vault.vaultId === vaultId && h.setAside !== true).map((h) => h.items.length);
/** Whether a save into [vaultId] is sealed and queued ("saved") or refused here. */
const trySave = (who: Browser, vaultId: string, name: string): Promise<string> =>
  who.store.save(null, { type: "login", name, login: { username: "x", password: "y" } }, [], undefined, vaultId).then(
    () => "saved",
    () => "refused",
  );
/** The owner removes bob from the vault and adds him again (bob's next `add` in its log). */
const removeAndAddAgain = async (alice: Browser, vaultId: string, rounds = 1): Promise<void> => {
  for (let i = 0; i < rounds; i++) {
    await alice.store.removeVaultMember(vaultId, BOB);
    await alice.store.sync();
    await alice.store.addVaultMember(vaultId, BOB, "writer");
    await alice.store.sync();
  }
};

/**
 * A chain of starts after the owner's removal: the tab that reads the removal (its writes stop at cuts[0]), then one more
 * start per later entry of [cuts] (its writes, from its hydrate on, stop at that number), then one honest start.
 * [addAgainBefore]: the index of the start before which the owner adds bob again (cuts.length: before the honest start).
 * [told]: every notice about the vault told by a session whose pull commit landed, counted, and the honest start's.
 */
async function chain(cuts: number[], addAgainBefore?: number) {
  freshDb();
  const { server, alice, bob, old } = await family(await openVaultCache(BOB));
  const told: string[] = [];
  const writes: number[] = [];
  const c0: Closing = { at: Infinity, n: 0, committed: false };
  const io0 = closingAt(bob.profile.storage, await openVaultCache(BOB), c0);
  const tab = await browser(server, bob.person, bob.contacts, { cache: io0.cache, again: { ...bob.profile, storage: io0.storage } });
  await alice.store.removeVaultMember(old, BOB);
  Object.assign(c0, { at: cuts[0], n: 0, committed: false });
  await tab.store.sync().catch(() => {});
  writes.push(c0.n);
  if (c0.committed) told.push(...noticesOf(tab, old));
  const addAgain = async (): Promise<void> => {
    await alice.store.sync();
    await alice.store.addVaultMember(old, BOB, "writer");
  };
  for (let i = 1; i < cuts.length; i++) {
    if (addAgainBefore === i) await addAgain();
    const c: Closing = { at: cuts[i]!, n: 0, committed: false };
    const io = closingAt(bob.profile.storage, await openVaultCache(BOB), c);
    let s: Browser | null = null;
    try {
      s = await browser(server, bob.person, bob.contacts, { cache: io.cache, again: { ...bob.profile, storage: io.storage }, sync: false });
      await s.store.sync().catch(() => {});
    } catch {
      /* the page closed during its start */
    }
    writes.push(c.n);
    if (s !== null && c.committed) told.push(...noticesOf(s, old));
  }
  if (addAgainBefore === cuts.length) await addAgain();
  const last = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
  told.push(...noticesOf(last, old));
  return { writes, end: { ...seen(last, old), atRest: await heldAtRest(old), told: told.sort() } };
}

describe("the record decides whether a removal is still owed", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("removed and added again while bob was away; his next start closed at each of its writes, then one honest start: ends where the uncut run ends", async () => {
    const run = async (m: number) => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      await alice.store.removeVaultMember(old, BOB);
      await alice.store.sync();
      await alice.store.addVaultMember(old, BOB, "writer");
      const c: Closing = { at: m, n: 0, committed: false };
      const io = closingAt(bob.profile.storage, await openVaultCache(BOB), c);
      let told: string[] = [];
      try {
        const s = await browser(server, bob.person, bob.contacts, { cache: io.cache, again: { ...bob.profile, storage: io.storage }, sync: false });
        await s.store.sync().catch(() => {});
        if (c.committed) told = noticesOf(s, old);
      } catch {
        /* closed */
      }
      const last = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
      return { writes: c.n, end: { ...seen(last, old), atRest: await heldAtRest(old), told: [...told, ...noticesOf(last, old)].sort() } };
    };
    const uncut = await run(Infinity);
    expect(uncut.end).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1, atRest: [1], told: ["removed"] });
    const differs: string[] = [];
    for (let m = 0; m < uncut.writes; m++) {
      const cut = await run(m);
      if (JSON.stringify(cut.end) !== JSON.stringify(uncut.end)) differs.push(`closed at write ${m} of ${uncut.writes}: ${JSON.stringify(cut.end)}`);
    }
    expect(differs).toEqual([]);
  }, 600_000);

  for (const addAgainBefore of [1, 2] as const) {
    it(`the removal's tab closed at write n, the owner adds bob again before the ${addAgainBefore === 1 ? "second" : "honest"} start, the second start closed at write m: every pair ends where the uncut run ends`, async () => {
      const uncut = await chain([Infinity, Infinity], addAgainBefore);
      expect(uncut.end).toMatchObject({ listed: false, key: false, items: [], held: [1], asks: 1, atRest: [1] });
      const differs: string[] = [];
      for (let n = 0; n < uncut.writes[0]!; n++) {
        const first = await chain([n, Infinity], addAgainBefore);
        for (let m = 0; m < Math.max(first.writes[1]!, 1); m++) {
          const cut = await chain([n, m], addAgainBefore);
          if (JSON.stringify(cut.end) !== JSON.stringify(uncut.end)) differs.push(`n ${n} m ${m}: ${JSON.stringify(cut.end)}`);
        }
      }
      expect(differs.slice(0, 5)).toEqual([]);
      expect(differs.length).toBe(0);
    }, 1_200_000);
  }

  it("removed and added again BEFORE the removal's tab syncs; that sync closed at each of its writes; then one honest start: ends where the uncut run ends", async () => {
    const run = async (at: number) => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      const c: Closing = { at: Infinity, n: 0, committed: false };
      const io = closingAt(bob.profile.storage, await openVaultCache(BOB), c);
      const tab = await browser(server, bob.person, bob.contacts, { cache: io.cache, again: { ...bob.profile, storage: io.storage } });
      await removeAndAddAgain(alice, old);
      Object.assign(c, { at, n: 0, committed: false });
      await tab.store.sync().catch(() => {});
      const told = c.committed ? noticesOf(tab, old) : [];
      const last = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
      return { writes: c.n, end: { ...seen(last, old), atRest: await heldAtRest(old), told: [...told, ...noticesOf(last, old)].sort() } };
    };
    const uncut = await run(Infinity);
    expect(uncut.end).toMatchObject({ listed: false, key: false, items: [], held: [1], asks: 1, atRest: [1] });
    const differs: string[] = [];
    for (let at = 0; at < uncut.writes; at++) {
      const cut = await run(at);
      if (JSON.stringify(cut.end) !== JSON.stringify(uncut.end)) differs.push(`closed at write ${at} of ${uncut.writes}: ${JSON.stringify(cut.end)}`);
    }
    expect(differs).toEqual([]);
  }, 600_000);

  it("the removal's sync closed at each write; the owner adds bob again DURING the next start (after its hydrate, before its sync): ends where the uncut run ends, and nothing is shown after the hydrate", async () => {
    const run = async (at: number) => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      const c: Closing = { at: Infinity, n: 0, committed: false };
      const io = closingAt(bob.profile.storage, await openVaultCache(BOB), c);
      const tab = await browser(server, bob.person, bob.contacts, { cache: io.cache, again: { ...bob.profile, storage: io.storage } });
      await alice.store.removeVaultMember(old, BOB);
      Object.assign(c, { at, n: 0, committed: false });
      await tab.store.sync().catch(() => {});
      const toldTab = c.committed ? noticesOf(tab, old) : [];
      const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
      const afterHydrate = seen(again, old);
      await alice.store.sync();
      await alice.store.addVaultMember(old, BOB, "writer");
      await again.store.sync();
      return { writes: c.n, afterHydrate: { listed: afterHydrate.listed, items: afterHydrate.items }, end: { ...seen(again, old), atRest: await heldAtRest(old), told: [...toldTab, ...noticesOf(again, old)].sort() } };
    };
    const uncut = await run(Infinity);
    expect(uncut.end).toMatchObject({ listed: false, key: false, items: [], held: [1], asks: 1, atRest: [1] });
    const differs: string[] = [];
    for (let at = 0; at < uncut.writes; at++) {
      const cut = await run(at);
      if (JSON.stringify(cut.end) !== JSON.stringify(uncut.end) || cut.afterHydrate.listed || cut.afterHydrate.items.length > 0) differs.push(`closed at write ${at}: ${JSON.stringify(cut)}`);
    }
    expect(differs).toEqual([]);
  }, 600_000);

  it("a second tab open: the removal's tab closed at each write, the owner adds bob again, the second tab syncs, then a new start: ends where the uncut run ends", async () => {
    const run = async (at: number) => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      const c: Closing = { at: Infinity, n: 0, committed: false };
      const io = closingAt(bob.profile.storage, await openVaultCache(BOB), c);
      const tabA = await browser(server, bob.person, bob.contacts, { cache: io.cache, again: { ...bob.profile, storage: io.storage } });
      const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
      await alice.store.removeVaultMember(old, BOB);
      Object.assign(c, { at, n: 0, committed: false });
      await tabA.store.sync().catch(() => {});
      await alice.store.sync();
      await alice.store.addVaultMember(old, BOB, "writer");
      await tabB.store.sync().catch(() => {});
      const b = seen(tabB, old);
      const last = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
      return { writes: c.n, b, end: { ...seen(last, old), atRest: await heldAtRest(old) } };
    };
    const uncut = await run(Infinity);
    expect(uncut.b).toMatchObject({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(uncut.end).toMatchObject({ listed: false, key: false, items: [], held: [1], asks: 1, atRest: [1] });
    const differs: string[] = [];
    for (let at = 0; at < uncut.writes; at++) {
      const cut = await run(at);
      if (JSON.stringify({ b: cut.b, end: cut.end }) !== JSON.stringify({ b: uncut.b, end: uncut.end })) differs.push(`closed at write ${at}: ${JSON.stringify(cut)}`);
    }
    expect(differs).toEqual([]);
  }, 600_000);

  it("the record at rest is written in the same commit as what it describes: at every write of the removal's road (the person added again before it), the offline copy holds the vault's rows with the record of its adoption, or the held copy with the record of the removal carried out, never one with the other's record", async () => {
    const atRestAfter = async (at: number) => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      const c: Closing = { at: Infinity, n: 0, committed: false };
      const io = closingAt(bob.profile.storage, await openVaultCache(BOB), c);
      const tab = await browser(server, bob.person, bob.contacts, { cache: io.cache, again: { ...bob.profile, storage: io.storage } });
      const addBefore = (await (await openVaultCache(BOB)).logRecords()).find((r) => r.vaultId === old);
      await removeAndAddAgain(alice, old);
      Object.assign(c, { at, n: 0, committed: false });
      await tab.store.sync().catch(() => {});
      const cache = await openVaultCache(BOB);
      const rows = (await cache.vaults()).some((v) => v.vaultId === old);
      const heldCopy = (await cache.heldVaults()).some((h) => h.vault.vaultId === old && h.setAside !== true);
      const rec = (await cache.logRecords()).find((r) => r.vaultId === old);
      return { writes: c.n, addBefore, state: { rows, heldCopy, carried: rec?.carried, addSeq: rec?.addSeq } };
    };
    const uncut = await atRestAfter(Infinity);
    expect(uncut.addBefore).toMatchObject({ carried: false });
    const adopted = uncut.addBefore!.addSeq;
    expect(uncut.state).toEqual({ rows: true, heldCopy: true, carried: true, addSeq: adopted });
    const states = new Set<string>();
    for (let at = 0; at <= uncut.writes; at++) {
      const s = (await atRestAfter(at)).state;
      states.add(JSON.stringify(s));
      // Before the commit: the vault's rows, adopted under the old add, no held copy. After it: the held copy, and the
      // record says the removal of that same add is carried out (the vault's row is back beside it for the question).
      const before = { rows: true, heldCopy: false, carried: false, addSeq: adopted };
      expect([JSON.stringify(before), JSON.stringify(uncut.state)]).toContain(JSON.stringify(s));
    }
    expect(states.size).toBe(2);
  }, 600_000);

  it("two tabs, an honest server, no stop: removed and added again; tab B syncs first, then tab A: tab A holds the copy, tells it, lists nothing and writes nothing", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    await removeAndAddAgain(alice, old);
    await alice.store.save(null, { type: "login", name: "late", login: { username: "a", password: "pw2" } }, [], undefined, old);
    await tabB.store.sync();
    expect(seen(tabB, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(noticesOf(bob, old)).toEqual(["removed"]);
    expect(await trySave(bob, old, "from-a")).toBe("refused");
    await bob.store.sync().catch(() => {});
    expect([...server.items.values()].filter((i) => i.vaultId === old).length).toBe(2);
  });

  it("one tab, no stop: removed and added again; the server serves the vault row with the head bob already holds, and an item written after the re-add whose head the chase follows: held, told and asked, as with an honest server", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const st0 = bob.shared.logs.status(old);
    const held = st0.kind === "verified" ? st0.state.head : null;
    expect(held).not.toBeNull();
    await removeAndAddAgain(alice, old);
    await alice.store.save(null, { type: "login", name: "late", login: { username: "a", password: "pw2" } }, [], undefined, old);
    server.tamper = (r, _s, userId) => (userId !== BOB ? r : ({ ...r, vaults: r.vaults.map((v) => (v.vaultId === old ? { ...v, logHead: { seq: held!.seq, hash: held!.hash } } : v)) } as SyncResponse));
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(noticesOf(bob, old)).toEqual(["removed"]);
    server.tamper = null;
    server.rev++;
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(await heldAtRest(old)).toEqual([1]);
    const reload = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(seen(reload, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
  });

  it("the key opened to seal the held copy leaves the ring when the seal itself throws: nothing is listed, shown or written", async () => {
    freshDb();
    const state = { fail: false };
    const { server, alice, bob, old } = await family(commitsFail(await openVaultCache(BOB), state));
    await alice.store.removeVaultMember(old, BOB);
    state.fail = true;
    await bob.store.sync().catch(() => {});
    state.fail = false;
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const acct = again.account as unknown as { resealForHolding: (...a: unknown[]) => unknown };
    const real = acct.resealForHolding.bind(again.account);
    acct.resealForHolding = (vaultId: unknown, ...rest: unknown[]) => {
      if (vaultId === old) throw new Error("the seal failed");
      return real(vaultId, ...rest);
    };
    await again.store.sync().catch(() => {});
    expect({ listed: listed(again.store, old), key: again.account.hasVault(old), items: namesIn(again, old) }).toEqual({ listed: false, key: false, items: [] });
    expect(await trySave(again, old, "late")).toBe("refused");
  });
});

describe("a key works only while its add is the one the verified log names now", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** Bob holds "Family" with "bank"; the owner removes him and adds him again; bob's tab has not synced since. */
  async function movedUnderBob() {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeAndAddAgain(alice, old);
    return { server, alice, bob, old, bankId };
  }
  const nothingOf = async (who: Browser, vaultId: string, itemId: string) => ({
    listed: listed(who.store, vaultId),
    items: namesIn(who, vaultId),
    get: who.store.get(itemId) !== undefined,
    save: await trySave(who, vaultId, "w"),
  });
  const NOTHING = { listed: false, items: [], get: false, save: "refused" };

  it("a read of the log outside a pull (an own log action's read, a look at a held change, a decline carried out again): nothing shown or written before the rule runs", async () => {
    const { bob, old, bankId } = await movedUnderBob();
    expect(listed(bob.store, old)).toBe(true);
    await bob.shared.logs.refresh(old, null, null, true);
    expect(await nothingOf(bob, old, bankId)).toEqual(NOTHING);
  });

  it("a chase of an item's head that reads the log on: nothing shown or written before the rule runs", async () => {
    const { server, bob, old, bankId } = await movedUnderBob();
    const h = server.head(old);
    await bob.shared.logs.noteItemHead(old, h.seq, h.hash);
    expect(await nothingOf(bob, old, bankId)).toEqual(NOTHING);
  });

  it("another tab's stored log taken over: tab A shows and writes nothing of the vault before its own next sync", async () => {
    const { server, bob, old, bankId } = await movedUnderBob();
    const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(seen(tabB, old)).toMatchObject({ listed: false, held: [1], asks: 1 });
    expect(await nothingOf(bob, old, bankId)).toEqual(NOTHING);
  });

  it("a new start whose log at rest moved past its record (a page closed after the log was read): nothing shown, no key, before any answer", async () => {
    const { server, bob, old, bankId } = await movedUnderBob();
    await bob.shared.logs.refresh(old, null, null, true);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    expect(again.account.hasVault(old)).toBe(false);
    expect(await nothingOf(again, old, bankId)).toEqual(NOTHING);
  });
});

describe("a third tab, two rounds in one answer, a record without its copy and a copy without its record, an older head", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a third tab that starts in the middle (after tab B carried the removal out, before tab A syncs): all three end held, told and asked, nothing listed", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    await removeAndAddAgain(alice, old);
    await tabB.store.sync();
    const tabC = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    await bob.store.sync();
    for (const t of [bob, tabB, tabC]) expect(seen(t, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(await heldAtRest(old)).toEqual([1]);
  });

  it("a third tab that starts before anyone read the removal, beside an open tab: both carry it out", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeAndAddAgain(alice, old);
    const tabC = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    await tabC.store.sync();
    await bob.store.sync();
    for (const t of [bob, tabC]) expect(seen(t, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(noticesOf(tabC, old)).toEqual(["removed"]);
  });

  it("removed, added, removed and added again while away (two rounds in one answer): one held copy, one notice, asked", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeAndAddAgain(alice, old, 2);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(noticesOf(again, old)).toEqual(["removed"]);
    expect(await heldAtRest(old)).toEqual([1]);
  });

  it("the held copy gone (the person removed it) while its record stays: a later re-add asks, tells nothing again, and lists nothing", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await alice.store.removeVaultMember(old, BOB);
    await bob.store.sync();
    await bob.store.removeHeldCopy(old);
    bob.store.clearNotices();
    await alice.store.sync();
    await alice.store.addVaultMember(old, BOB, "writer");
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [], asks: 1 });
    expect(noticesOf(again, old)).toEqual([]);
  });

  it("an offline copy from before records were kept (the vault's rows, no record): removed and added again while away, the next start still holds, tells and asks; and the record is written with that start's commit", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeAndAddAgain(alice, old);
    const withoutRecords = (cache: Awaited<ReturnType<typeof openVaultCache>>) =>
      new Proxy(cache, {
        get(target, prop) {
          if (prop === "logRecords") return async () => [];
          const v = Reflect.get(target, prop, target) as unknown;
          return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
        },
      });
    const again = await browser(server, bob.person, bob.contacts, { cache: withoutRecords(await openVaultCache(BOB)), again: bob.profile });
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 1 });
    expect(noticesOf(again, old)).toEqual(["removed"]);
    expect((await (await openVaultCache(BOB)).logRecords()).find((r) => r.vaultId === old)).toMatchObject({ carried: true });
  });

  it("an offline copy from before records were kept, its log at rest already showing the removal (a page closed after reading it): the next start holds and tells", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await alice.store.removeVaultMember(old, BOB);
    await bob.shared.logs.refresh(old, null, null, true);
    const withoutRecords = (cache: Awaited<ReturnType<typeof openVaultCache>>) =>
      new Proxy(cache, {
        get(target, prop) {
          if (prop === "logRecords") return async () => [];
          const v = Reflect.get(target, prop, target) as unknown;
          return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
        },
      });
    const again = await browser(server, bob.person, bob.contacts, { cache: withoutRecords(await openVaultCache(BOB)), again: bob.profile });
    expect(seen(again, old)).toEqual({ listed: false, key: false, items: [], held: [1], asks: 0 });
    expect(noticesOf(again, old)).toEqual(["removed"]);
  });

  it("a server that serves a head hint OLDER than what this browser holds: nothing is fetched back, the vault stays as it is", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    server.tamper = (r, _s, userId) => (userId !== BOB ? r : ({ ...r, vaults: r.vaults.map((v) => (v.vaultId === old ? { ...v, logHead: { seq: 0, hash: "00".repeat(32) } } : v)) } as SyncResponse));
    server.rev++;
    await bob.store.sync();
    expect(seen(bob, old)).toEqual({ listed: true, key: true, items: ["bank"], held: [], asks: 0 });
  });
});
