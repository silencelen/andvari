// Where the decision about a removal is enforced: at the places where something leaves this browser. A change of a
// shared vault (a delete, a move, a copy out of it) is sent only while the vault's key works, whatever screen or tab
// asks; and a log the server does not serve in full at this moment (it withholds the newest entries, serves an entry
// that does not verify, or the vault is frozen) is decided against its last verified state: a removal that state shows
// is carried out with the held copy and its notice, never dropped in silence. Driven through the real VaultStore,
// SharedLogSession and VaultLogStore against a fake server that serves what it likes.
import { beforeAll, describe, expect, it, vi } from "vitest";
import { toB64 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { memoryStorage } from "../api/devicesecret";
import { BOB, browser, type Browser, family, freshDb, listed, namesIn, noticesOf, type FakeSyncServer } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

const removeAndAddAgain = async (alice: Browser, vaultId: string): Promise<void> => {
  await alice.store.removeVaultMember(vaultId, BOB);
  await alice.store.sync();
  await alice.store.addVaultMember(vaultId, BOB, "writer");
  await alice.store.sync();
};
const heldAtRest = async (vaultId: string): Promise<number[]> =>
  (await (await openVaultCache(BOB)).heldVaults()).filter((h) => h.vault.vaultId === vaultId && h.setAside !== true).map((h) => h.items.length);
const held = (who: Browser, vaultId: string): number[] => who.store.heldVaults().filter((h) => h.vaultId === vaultId).map((h) => h.itemCount);
const asks = (who: Browser, vaultId: string): number => who.shared.pendingAsks().filter((a) => a.vaultId === vaultId).length;
const inVault = (server: FakeSyncServer, vaultId: string): number => [...server.items.values()].filter((i) => i.vaultId === vaultId && !i.deleted).length;

/** Removed and added again; tab B of the same profile syncs (it carries the removal out and asks); tab A (bob) has not synced since. */
async function movedByAnotherTab() {
  freshDb();
  const { server, alice, bob, old } = await family(await openVaultCache(BOB));
  const bank = bob.store.list().find((i) => i.vaultId === old)!;
  await removeAndAddAgain(alice, old);
  const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
  expect(asks(tabB, old)).toBe(1);
  expect(listed(bob.store, old)).toBe(false);
  expect(namesIn(bob, old)).toEqual([]);
  return { server, alice, bob, old, bank, tabB };
}

describe("a change of a vault whose key does not work is never sent", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a delete from a tab whose item view was opened before another tab moved the log is refused, and nothing reaches the server", async () => {
    const { server, bob, bank } = await movedByAnotherTab();
    let outcome = "done";
    await bob.store.remove(bank.itemId).catch((e: unknown) => {
      outcome = `refused: ${String(e)}`;
    });
    await bob.store.sync().catch(() => {});
    expect({ outcome, deletedOnServer: server.items.get(bank.itemId)?.deleted }).toEqual({ outcome: expect.stringMatching(/^refused/), deletedOnServer: false });
  });

  it("a delete after a read of the log outside a pull in the same tab is refused, and nothing reaches the server", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    await removeAndAddAgain(alice, old);
    await bob.shared.logs.refresh(old, null, null, true);
    expect(listed(bob.store, old)).toBe(false);
    await bob.store.remove(bankId).catch(() => {});
    expect(server.items.get(bankId)?.deleted).toBe(false);
  });

  it("a move out of the vault (copy to Personal, then delete the source), minted before or after the log moved, does not run", async () => {
    const { server, bob, old, bank } = await movedByAnotherTab();
    const personal = bob.account.personalVaultId!;
    const before = inVault(server, personal);
    await (async () => {
      await bob.store.runGesture(bob.store.newMoveGesture(bank.itemId, personal, true));
    })().catch(() => {});
    expect({ sourceDeleted: server.items.get(bank.itemId)?.deleted, copiedToPersonal: inVault(server, personal) - before, listedOld: listed(bob.store, old) }).toEqual({
      sourceDeleted: false,
      copiedToPersonal: 0,
      listedOld: false,
    });
  });

  it("a move gesture kept by a screen from before the log moved does not run", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    const personal = bob.account.personalVaultId!;
    const kept = bob.store.newMoveGesture(bankId, personal, true);
    await removeAndAddAgain(alice, old);
    await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    const before = inVault(server, personal);
    await bob.store.runGesture(kept).catch(() => {});
    expect({ sourceDeleted: server.items.get(bankId)?.deleted, copied: inVault(server, personal) - before }).toEqual({ sourceDeleted: false, copied: 0 });
  });

  it("'copy everything to Personal' of a vault whose key does not work copies nothing", async () => {
    const { server, bob, old } = await movedByAnotherTab();
    const personal = bob.account.personalVaultId!;
    const before = inVault(server, personal);
    await bob.store.copyAllToPersonal(old).catch(() => {});
    expect(inVault(server, personal) - before).toBe(0);
  });

  it("a delete queued while offline before the log moved is not sent after it moved; the rule then holds it with the vault", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bankId = bob.store.list().find((i) => i.vaultId === old)!.itemId;
    // Offline, with the offline copy kept for good: the delete is queued, not sent.
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
    try {
      const wire = (bob.store as unknown as { wire: { pushMutations: (...a: unknown[]) => Promise<unknown> } }).wire;
      const push = wire.pushMutations;
      wire.pushMutations = () => Promise.reject(new TypeError("offline"));
      await bob.store.remove(bankId);
      wire.pushMutations = push;
      expect({ queued: await bob.store.queuedMutationCount(), deleted: server.items.get(bankId)?.deleted }).toEqual({ queued: 1, deleted: false });
      await removeAndAddAgain(alice, old);
      await bob.shared.logs.refresh(old, null, null, true);
      await bob.store.sync().catch(() => {});
      await bob.store.sync().catch(() => {});
      // The held copy holds what the person held (the item they deleted is not in it), and their unsent delete is parked
      // with it, out of the queue.
      expect({ deletedOnServer: server.items.get(bankId)?.deleted, held: held(bob, old), asks: asks(bob, old), queued: await bob.store.queuedMutationCount() }).toEqual({
        deletedOnServer: false,
        held: [0],
        asks: 1,
        queued: 0,
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("a screen that kept an opened item asks for its attachment, its history, a rename and a restore: nothing is fetched for show, nothing is sent", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const bank = bob.store.list().find((i) => i.vaultId === old)!;
    await removeAndAddAgain(alice, old);
    await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    const writesBefore = server.writes.length;
    const outcomes: string[] = [];
    const tryIt = (name: string, p: () => Promise<unknown>) =>
      p().then(
        () => outcomes.push(`${name}: done`),
        () => outcomes.push(`${name}: refused`),
      );
    await tryIt("attachment", () => bob.store.downloadAttachment(bank, { id: "a", name: "f", size: 1, fileKey: toB64(randomBytes(32)) }));
    await tryIt("rename", () => bob.store.renameVault(old, "Other"));
    await tryIt("restore", () => bob.store.restoreDeleted(bank.itemId, old, bank.doc));
    await tryIt("purge", () => bob.store.purgeDeleted(bank.itemId, old));
    const history = await bob.store.itemVersions(bank.itemId, old).catch(() => []);
    expect({ outcomes, history, writes: server.writes.slice(writesBefore) }).toEqual({
      outcomes: ["attachment: refused", "rename: refused", "restore: refused", "purge: refused"],
      history: [],
      writes: [],
    });
  });
});

type Unserved = "withheld" | "failed" | "frozen";

/** The server does not serve [vaultId]'s log in full for [who]'s next reads, in the way [how] names. Returns the honest server again. */
async function unserve(server: FakeSyncServer, vaultId: string, how: Unserved, cut: number, who: Browser): Promise<() => void> {
  if (how === "withheld") {
    server.logCut.set(vaultId, server.logs.get(vaultId)!.length - cut);
    return () => server.logCut.delete(vaultId);
  }
  if (how === "failed") {
    const all = server.logs.get(vaultId)!;
    server.logs.set(vaultId, [...all, toB64(randomBytes(48))]);
    return () => server.logs.set(vaultId, all);
  }
  // Frozen: the account's own record of the vault names another genesis (two stories about the vault's start).
  await who.shared.accountState.update((doc) => {
    const rec = doc.vaults.get(vaultId)!;
    return { ...doc, vaults: new Map([...doc.vaults, [vaultId, { ...rec, genesisHash: "ab".repeat(32) }]]) };
  });
  return () => {};
}

describe("a log not served in full decides against its last verified state", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** Bob holds "Family"; the owner removes him; bob's log is read on outside a pull (no rule ran, nothing committed). */
  async function removedReadOutsidePull() {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await alice.store.removeVaultMember(old, BOB);
    await alice.store.sync();
    await bob.shared.logs.refresh(old, null, null, true);
    expect(bob.shared.logs.status(old).kind).toBe("removed");
    return { server, alice, bob, old };
  }

  it("control: the next start with an honest server holds the copy and tells it", async () => {
    const { server, bob, old } = await removedReadOutsidePull();
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect({ held: held(again, old), told: noticesOf(again, old), atRest: await heldAtRest(old) }).toEqual({ held: [1], told: ["removed"], atRest: [1] });
  });

  for (const how of ["withheld", "failed", "frozen"] as const) {
    it(`removed; the next start's log is ${how}: the copy is held and the person told at once, and the same after the server serves honestly`, async () => {
      const { server, bob, old } = await removedReadOutsidePull();
      const honest = await unserve(server, old, how, 1, bob);
      const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
      const first = { status: again.shared.logs.status(old).kind, listed: listed(again.store, old), held: held(again, old), told: noticesOf(again, old), atRest: await heldAtRest(old) };
      honest();
      server.rev++;
      await again.store.sync().catch(() => {});
      const later = { listed: listed(again.store, old), held: held(again, old), told: noticesOf(again, old), atRest: await heldAtRest(old) };
      expect({ first, later }).toEqual({
        first: { status: how, listed: false, held: [1], told: ["removed"], atRest: [1] },
        later: { listed: false, held: [1], told: ["removed"], atRest: [1] },
      });
    });
  }

  for (const how of ["honest", "withheld", "failed", "frozen"] as const) {
    it(`removed and added again, the log read outside a pull, a new start whose log is ${how}: held and told at once, asked once the log is read in full`, async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      await removeAndAddAgain(alice, old);
      await bob.shared.logs.refresh(old, null, null, true);
      const honest = how === "honest" ? () => {} : await unserve(server, old, how, 2, bob);
      const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
      const first = { listed: listed(again.store, old), key: again.account.hasVault(old), items: namesIn(again, old), held: held(again, old), told: noticesOf(again, old) };
      honest();
      server.rev++;
      await again.store.sync().catch(() => {});
      server.rev++;
      await again.store.sync().catch(() => {});
      const end = { listed: listed(again.store, old), items: namesIn(again, old), held: held(again, old), asks: asks(again, old), told: noticesOf(again, old), atRest: await heldAtRest(old) };
      expect({ first, end }).toEqual({
        first: { listed: false, key: false, items: [], held: [1], told: ["removed"] },
        // A frozen log is frozen for good: it adopts nothing new, so the question to join again is not asked on it.
        end: { listed: false, items: [], held: [1], asks: how === "frozen" ? 0 : 1, told: ["removed"], atRest: [1] },
      });
    });
  }

  it("a server that withholds for three answers in a row and then serves: held and told from the first, asked at the end", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeAndAddAgain(alice, old);
    await bob.shared.logs.refresh(old, null, null, true);
    server.logCut.set(old, server.logs.get(old)!.length - 2);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    const looks: unknown[] = [];
    for (let i = 0; i < 2; i++) {
      server.rev++;
      await again.store.sync().catch(() => {});
      looks.push({ held: held(again, old), asks: asks(again, old), listed: listed(again.store, old) });
    }
    server.logCut.delete(old);
    server.rev++;
    await again.store.sync().catch(() => {});
    expect({ looks, end: { held: held(again, old), asks: asks(again, old), told: noticesOf(again, old), atRest: await heldAtRest(old) } }).toEqual({
      looks: [
        { held: [1], asks: 0, listed: false },
        { held: [1], asks: 0, listed: false },
      ],
      end: { held: [1], asks: 1, told: ["removed"], atRest: [1] },
    });
  });

  it("a server that repeats an older answer after a newer one: the removal carried out stays carried out, nothing is listed or told again", async () => {
    const { server, bob, old } = await removedReadOutsidePull();
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(held(again, old)).toEqual([1]);
    server.logCut.set(old, server.logs.get(old)!.length - 1);
    server.rev++;
    await again.store.sync().catch(() => {});
    const reload = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect({ listed: listed(reload.store, old), held: held(reload, old), told: noticesOf(reload, old), atRest: await heldAtRest(old), key: reload.account.hasVault(old) }).toEqual({
      listed: false,
      held: [1],
      told: [],
      atRest: [1],
      key: false,
    });
  });

  it("a log withheld at rest when a new start begins (the flag a read outside a pull left): the start holds nothing open, its first pull holds and tells", async () => {
    const { server, bob, old } = await removedReadOutsidePull();
    server.logCut.set(old, server.logs.get(old)!.length - 1);
    await bob.shared.logs.refresh(old, null, null, true);
    expect(bob.shared.logs.status(old).kind).toBe("withheld");
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const atStart = { listed: listed(again.store, old), key: again.account.hasVault(old), items: namesIn(again, old) };
    await again.store.sync().catch(() => {});
    expect({ atStart, held: held(again, old), told: noticesOf(again, old), atRest: await heldAtRest(old) }).toEqual({
      atStart: { listed: false, key: false, items: [] },
      held: [1],
      told: ["removed"],
      atRest: [1],
    });
  });

  it("a withheld answer while a second tab is open: both tabs end held and unlisted, and one held copy is at rest", async () => {
    const { server, bob, old } = await removedReadOutsidePull();
    const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    server.logCut.set(old, server.logs.get(old)!.length - 1);
    server.rev++;
    await tabB.store.sync().catch(() => {});
    await bob.store.sync().catch(() => {});
    expect({ a: { listed: listed(bob.store, old), held: held(bob, old) }, b: { listed: listed(tabB.store, old), held: held(tabB, old) }, atRest: await heldAtRest(old) }).toEqual({
      a: { listed: false, held: [1] },
      b: { listed: false, held: [1] },
      atRest: [1],
    });
  });

  it("a withheld flag does not outlive the next full read, also where the served head equals the held one", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    server.logCut.set(old, server.logs.get(old)!.length - 1);
    await bob.shared.logs.refresh(old, null, null, true);
    expect(bob.shared.logs.status(old).kind).toBe("withheld");
    server.logCut.delete(old);
    const h = server.head(old);
    await bob.shared.logs.refresh(old, h.seq, h.hash);
    expect(bob.shared.logs.status(old).kind).toBe("verified");
  });
});

describe("what this very answer brought, and a second tab", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a vault adopted in this answer whose items name a later head: its heads are chased before anything is listed, and nothing this answer brought goes into a held copy", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    // A second browser of bob's account that has synced once and holds nothing of the vault (bob accepted elsewhere).
    const other = { ...bob.profile, storage: memoryStorage() };
    const second = await browser(server, bob.person, bob.contacts, { again: other, sync: false });
    const firstSync = server.tamper;
    server.tamper = (r, since, userId) => (userId === BOB && since === 0 ? { ...r, vaults: [], grants: r.grants.filter((g) => g.vaultId !== old), items: r.items.filter((i) => i.vaultId !== old) } : r);
    await second.store.sync();
    server.tamper = firstSync;
    const atAdd = server.logs.get(old)!.length;
    const rowAtAdd = server.grantRowOf(old, BOB);
    await removeAndAddAgain(alice, old);
    await alice.store.save(null, { type: "login", name: "late", login: { username: "a", password: "pw2" } }, [], undefined, old);
    // The answer serves the grant row as it was at bob's first add, and the first read of the vault's log is cut there;
    // every later read is whole, so the head the item "late" names is chased to the log as it is.
    let pages = 0;
    server.logCut.set(old, atAdd);
    server.tamper = (r, _since, userId) => (userId !== BOB ? r : { ...r, grants: r.grants.map((g) => (g.vaultId === old ? rowAtAdd : g)) });
    const shownDuring: string[][] = [];
    server.onLogPage = (v) => {
      if (v !== old) return;
      pages++;
      if (pages > 1) server.logCut.delete(old);
      shownDuring.push(namesIn(second, old));
    };
    await second.store.sync().catch(() => {});
    server.onLogPage = null;
    server.tamper = null;
    server.logCut.delete(old);
    server.rev++;
    await second.store.sync().catch(() => {});
    const heldItems = second.store.heldVaults().filter((h) => h.vaultId === old).map((h) => h.itemCount);
    expect({ shownDuring: shownDuring.flat(), listed: listed(second.store, old), items: namesIn(second, old), held: heldItems, asks: asks(second, old) }).toEqual({
      shownDuring: [],
      listed: false,
      items: [],
      held: [],
      asks: 1,
    });
  });

  it("two tabs: removed and added again, the person answers yes in the second tab, then the first tab syncs: it ends where the second is", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeAndAddAgain(alice, old);
    const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect((await tabB.shared.answer(tabB.shared.pendingAsks().find((a) => a.vaultId === old)!, true)).kind).toBe("adopted");
    await tabB.store.sync();
    const b = { listed: listed(tabB.store, old), items: namesIn(tabB, old), held: held(tabB, old), asks: asks(tabB, old) };
    const atRestAfterB = await heldAtRest(old);
    await bob.store.sync().catch(() => {});
    await bob.store.sync().catch(() => {});
    const a = { listed: listed(bob.store, old), items: namesIn(bob, old), held: held(bob, old), asks: asks(bob, old) };
    expect({ a, atRest: await heldAtRest(old) }).toEqual({ a: b, atRest: atRestAfterB });
    expect(b).toMatchObject({ listed: true, items: ["bank"] });
  });

  it("an offline copy from before records were kept, its log at rest already naming the person again: the record comes from the account's own accepted entry, so the removal is carried out and the person asked", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeAndAddAgain(alice, old);
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
    expect({ listed: listed(again.store, old), held: held(again, old), asks: asks(again, old), told: noticesOf(again, old) }).toEqual({ listed: false, held: [1], asks: 1, told: ["removed"] });
  });
});
