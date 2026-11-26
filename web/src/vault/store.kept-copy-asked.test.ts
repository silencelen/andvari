// A person removed from a shared vault keeps a sealed copy of its items on this browser (shown under "Recently
// removed"). Added again, the browser shows an invitation to answer. While it shows one that its person can answer, the
// kept copy is closed: its items are not copied out, and nothing is written or sent for it. In every other state it
// opens as before, until its day (decided on 22 and 23 November 2026). Driven through the real VaultStore,
// SharedLogSession and VaultLogStore against a fake server; every attack below is the honest app's answer to what a
// server serves, never a claim about a server that serves another page.
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { type ApiClient, ApiError, TrafficStoppedError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { SyncResponse } from "../api/types";
import { initSodium } from "../crypto/sodium";
import { ALICE, BOB, browser, type Browser, family, type FakeSyncServer, freshDb, heldOf, listed, namesIn } from "./fakesyncserver.testkit";
import { type HeldVaultRecord, openVaultCache } from "./idbcache";
import { type ItemWire, VaultStore } from "./store";

const DAY = 24 * 60 * 60 * 1000;

type Wire = Record<string, (...a: unknown[]) => Promise<unknown>>;
const wireOf = (who: Browser): Wire => (who.store as unknown as { wire: Wire }).wire;

/** The requests that would send or fetch something for a vault: every write, and the attachment downloads. */
const SENDS = ["pushMutations", "uploadAttachment", "downloadAttachment", "appendLog", "putSelfWrap", "putAccountState", "updateVaultMeta", "restoreItem"];

/** Every such request [who] makes from now on, by name, in the order made. */
function sendsOf(who: Browser): string[] {
  const seen: string[] = [];
  const wire = wireOf(who);
  for (const name of SENDS) {
    const f = wire[name]!;
    wire[name] = (...a: unknown[]) => {
      seen.push(name);
      return f.apply(wire, a);
    };
  }
  return seen;
}

/** [who]'s row of [vaultId] under "Recently removed". */
const rowOf = (who: Browser, vaultId: string) => who.store.heldVaults().find((h) => h.vaultId === vaultId);

/** What decides the copy-out of [who]'s kept copy of [vaultId]: whether it is closed for an invitation, and whether a copy-out is offered. */
const gateOf = (who: Browser, vaultId: string) => {
  const r = rowOf(who, vaultId);
  return { addedAgain: r?.addedAgain, canCopyOut: r?.canCopyOut };
};
const CLOSED = { addedAgain: true, canCopyOut: false };
const OPEN = { addedAgain: false, canCopyOut: true };

/** Whether [who] lists [vaultId] and holds its key: a vault the account may use. */
const liveOf = (who: Browser, vaultId: string) => ({ listed: listed(who.store, vaultId), key: who.account.hasVault(vaultId) });
const NOT_LIVE = { listed: false, key: false };

/** The invitations [who] shows for [vaultId]. */
const asksOf = (who: Browser, vaultId: string) => who.shared.pendingAsks().filter((a) => a.vaultId === vaultId);

/** The names of the items in [who]'s personal vault. */
const personalNames = (who: Browser): string[] => namesIn(who, who.account.personalVaultId).sort();

/** The kept copy of [vaultId] at rest. */
async function heldAtRest(vaultId: string): Promise<HeldVaultRecord | undefined> {
  return (await (await openVaultCache(BOB)).heldVaults()).find((r) => r.vault.vaultId === vaultId && r.setAside !== true);
}

/** Alice removes bob from [vaultId]; his browser learns it and keeps the vault's copy, open. */
async function removeBob(alice: Browser, bob: Browser, vaultId: string): Promise<void> {
  await alice.store.removeVaultMember(vaultId, BOB);
  await bob.store.sync();
  expect(heldOf(bob)).toEqual([vaultId]);
  expect(liveOf(bob, vaultId)).toEqual(NOT_LIVE);
  expect(rowOf(bob, vaultId)?.canCopyOut).toBe(true);
}

/** Alice adds bob to [vaultId] again and his browser pulls the answer that brings the grant back. */
async function addBobAgain(alice: Browser, bob: Browser, vaultId: string): Promise<void> {
  await alice.store.addVaultMember(vaultId, BOB, "writer");
  await bob.store.sync();
}

/** Removed, added again and asked: the invitation shows, and the kept copy is closed. */
async function askedAgain(alice: Browser, bob: Browser, vaultId: string): Promise<void> {
  await removeBob(alice, bob, vaultId);
  await addBobAgain(alice, bob, vaultId);
  expect(asksOf(bob, vaultId)).toHaveLength(1);
  expect(heldOf(bob)).toEqual([vaultId]);
}

/** [who]'s copy-out of [vaultId] goes: the held item lands in the personal vault and a push carries it. */
async function copiesOut(who: Browser, vaultId: string): Promise<void> {
  const sent = sendsOf(who);
  const r = await who.store.copyHeldToPersonal(vaultId);
  expect(r.copied).toBe(1);
  expect(personalNames(who)).toEqual(["bank"]);
  expect(sent).toContain("pushMutations");
}

/** The grant row of bob's for [vaultId] in each answer the server gives his browser, rewritten by [g]. */
function grantServedAs(server: FakeSyncServer, vaultId: string, g: (signedGrant: string | null) => string | null): void {
  server.tamper = (r: SyncResponse, _since: number, userId: string) =>
    userId !== BOB ? r : { ...r, grants: r.grants.map((x) => (x.vaultId === vaultId && x.userId === BOB ? { ...x, signedGrant: g(x.signedGrant ?? null) } : x)) };
}

/** A sealed grant that does not open for bob: canonical base64url of three zero bytes. */
const NOT_A_GRANT = "AAAA";

describe("a kept copy while this browser shows an invitation to its vault that its person can answer", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("asked: the kept copy is closed, its copy-out refused, nothing copied, written or sent, and the vault no vault the account may use; a decline then opens it and the same copy-out goes", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const atRest = await heldAtRest(old);
    // The reader of the copy at rest finds it: "nothing written at rest" below compares a record, not two absences.
    expect(atRest).toMatchObject({ vault: { vaultId: old } });
    const sent = sendsOf(bob);
    const out = await bob.store.copyHeldToPersonal(old).catch((e: unknown) => e);
    expect({ sent, personal: personalNames(bob) }).toEqual({ sent: [], personal: [] });
    expect(out).toMatchObject({ name: "HeldClosedWhileAskedError" });
    expect(gateOf(bob, old)).toEqual(CLOSED);
    expect(liveOf(bob, old)).toEqual(NOT_LIVE);
    expect(await heldAtRest(old)).toEqual(atRest);
    expect(heldOf(bob)).toEqual([old]);
    // The invitation still stands, and a decline opens the copy: the copy-out refused above now goes. The record of
    // requests sees the session's own writes, the decline's record and its leave, as it sees the store's push.
    const answered = sendsOf(bob);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, false)).kind).toBe("declined");
    expect(answered).toEqual(expect.arrayContaining(["putAccountState", "appendLog"]));
    expect(gateOf(bob, old)).toEqual(OPEN);
    await copiesOut(bob, old);
    expect(liveOf(bob, old)).toEqual(NOT_LIVE);
  });

  it("the refusal is the store's own: called directly while closed, whatever the screen offers, the copy-out sends nothing and leaves the personal vault as it was", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const sent = sendsOf(bob);
    const err = await bob.store.copyHeldToPersonal(old).catch((e: unknown) => e);
    expect({ sent, personal: personalNames(bob), live: liveOf(bob, old) }).toEqual({ sent: [], personal: [], live: NOT_LIVE });
    expect(err).toMatchObject({ name: "HeldClosedWhileAskedError", vaultId: old });
    expect(err).not.toMatchObject({ name: "HeldKeyGoneError" });
  });

  describe("the five open states: the copy opens as before, and the vault is no vault the account may use", () => {
    it("a grant that does not open", async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      await removeBob(alice, bob, old);
      grantServedAs(server, old, () => NOT_A_GRANT);
      await addBobAgain(alice, bob, old);
      expect(bob.shared.outcome(old)).toMatchObject({ kind: "refused", reason: "grant_refused" });
      expect({ asks: asksOf(bob, old), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: [], gate: OPEN, live: NOT_LIVE });
      await copiesOut(bob, old);
      expect(liveOf(bob, old)).toEqual(NOT_LIVE);
    });

    it("an owner who is not a current contact on this browser", async () => {
      freshDb();
      const { alice, bob, old } = await family(await openVaultCache(BOB));
      await removeBob(alice, bob, old);
      bob.shared.currency.drop(ALICE);
      await addBobAgain(alice, bob, old);
      expect(bob.shared.outcome(old)).toMatchObject({ kind: "connect_first" });
      expect({ asks: asksOf(bob, old), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: [], gate: OPEN, live: NOT_LIVE });
      await copiesOut(bob, old);
      expect(liveOf(bob, old)).toEqual(NOT_LIVE);
    });

    it("a decline whose leave the server did not store", async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      await askedAgain(alice, bob, old);
      const wire = wireOf(bob);
      wire.appendLog = () => Promise.reject(new ApiError(403, "forbidden", "refused"));
      const logBefore = server.logs.get(old)!.length;
      expect(await bob.shared.answer(asksOf(bob, old)[0]!, false)).toMatchObject({ kind: "declined" });
      expect(server.logs.get(old)!.length).toBe(logBefore);
      expect({ asks: asksOf(bob, old), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: [], gate: OPEN, live: NOT_LIVE });
      await copiesOut(bob, old);
      expect(liveOf(bob, old)).toEqual(NOT_LIVE);
    });

    it("accepted in a second tab of the same browser, this tab not yet synced: open here at once; its next sync adopts and the vault is back", async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      await askedAgain(alice, bob, old);
      expect(gateOf(bob, old)).toEqual(CLOSED);
      const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
      expect((await tabB.shared.answer(asksOf(tabB, old)[0]!, true)).kind).toBe("adopted");
      // This tab still shows the invitation from its own last pull, but the account's record of answers, which both tabs
      // read from this browser's storage, answers that add: the copy here is open, and no vault the account may use yet.
      expect(asksOf(bob, old)).toHaveLength(1);
      expect({ gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ gate: OPEN, live: NOT_LIVE });
      await bob.store.sync();
      expect({ listed: listed(bob.store, old), held: heldOf(bob), items: namesIn(bob, old) }).toEqual({ listed: true, held: [], items: ["bank"] });
    });

    it("a grant row with no signed grant", async () => {
      freshDb();
      const { server, alice, bob, old } = await family(await openVaultCache(BOB));
      await removeBob(alice, bob, old);
      grantServedAs(server, old, () => null);
      await addBobAgain(alice, bob, old);
      expect(bob.shared.outcome(old)).toMatchObject({ kind: "refused" });
      expect({ asks: asksOf(bob, old), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: [], gate: OPEN, live: NOT_LIVE });
      await copiesOut(bob, old);
      expect(liveOf(bob, old)).toEqual(NOT_LIVE);
    });
  });

  it("an invitation shown for an earlier add closes nothing for a later one: withdrawn, bob added once more with a grant that does not verify, the log moved on outside a pull: open, and no vault the account may use", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const earlier = asksOf(bob, old)[0]!.addSeq;
    expect(gateOf(bob, old)).toEqual(CLOSED);
    await alice.store.removeVaultMember(old, BOB);
    await alice.store.addVaultMember(old, BOB, "writer");
    grantServedAs(server, old, () => NOT_A_GRANT);
    // The log is read outside a pull of this tab (a log action, another tab): the invitation in memory names the earlier
    // add. The account state refuses the record this browser writes of the removal it verifies, so the account's record of
    // answers holds no answer to the earlier add: only the add the invitation names keeps the copy open.
    const wire = wireOf(bob);
    const put = wire.putAccountState!;
    wire.putAccountState = () => Promise.reject(new ApiError(403, "forbidden", "refused"));
    await bob.shared.logs.refresh(old, null, null, true);
    wire.putAccountState = put;
    expect(bob.shared.outcome(old)).toMatchObject({ kind: "ask", addSeq: earlier });
    expect(bob.shared.logs.verifiedState(old)!.latestAdds[BOB]!.seq).toBeGreaterThan(earlier);
    expect(Object.keys(bob.shared.logs.verifiedState(old)!.members)).toContain(BOB);
    expect(bob.shared.accountState.local().accepted.get(old)?.addSeq).not.toBe(earlier);
    expect({ gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ gate: OPEN, live: NOT_LIVE });
    // Its next pull decides the later add: the grant does not open, nothing asks, and the copy stays open.
    await bob.store.sync();
    expect({ asks: asksOf(bob, old), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: [], gate: OPEN, live: NOT_LIVE });
    await copiesOut(bob, old);
  });

  it("an answer whose outcome is not known (cut off after it went out, or never sent): open, and no vault the account may use, until the next pull asks again; then closed", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const wire = wireOf(bob);
    const put = wire.putAccountState!;
    const read = wire.accountState!;
    wire.putAccountState = () => Promise.reject(new Error("the answer was cut off"));
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, true)).toMatchObject({ kind: "not_recorded", reason: "unknown" });
    expect({ gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ gate: OPEN, live: NOT_LIVE });
    wire.putAccountState = put;
    await bob.store.sync();
    expect(asksOf(bob, old)).toHaveLength(1);
    expect({ gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ gate: CLOSED, live: NOT_LIVE });
    // Never sent: the account state could not be read before the write.
    wire.accountState = () => Promise.reject(new TypeError("offline"));
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, true)).toMatchObject({ kind: "not_recorded", reason: "unreachable" });
    expect({ gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ gate: OPEN, live: NOT_LIVE });
    wire.accountState = read;
    await bob.store.sync();
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
  });

  it("withdrawn while asked: open as soon as the removal is verified, before any pull; the copy keeps its first day", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    vi.setSystemTime(t0);
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await removeBob(alice, bob, old);
    const firstDay = rowOf(bob, old)!.expungeAt;
    vi.setSystemTime(t0 + 5 * DAY);
    await addBobAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    await alice.store.removeVaultMember(old, BOB);
    // The removal is verified outside a pull (the log read afresh): the invitation in memory names the same add.
    await bob.shared.logs.refresh(old, null, null, true);
    expect(bob.shared.outcome(old)).toMatchObject({ kind: "ask" });
    expect({ gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ gate: OPEN, live: NOT_LIVE });
    await bob.store.sync();
    expect({ asks: asksOf(bob, old), gate: gateOf(bob, old), live: liveOf(bob, old), held: heldOf(bob) }).toEqual({ asks: [], gate: OPEN, live: NOT_LIVE, held: [old] });
    expect(rowOf(bob, old)!.expungeAt).toBe(firstDay);
    await copiesOut(bob, old);
  });

  it("withdrawn while asked, and the account state refuses the record of the removal: the verified log alone opens the copy", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const add = asksOf(bob, old)[0]!.addSeq;
    expect(gateOf(bob, old)).toEqual(CLOSED);
    await alice.store.removeVaultMember(old, BOB);
    const wire = wireOf(bob);
    const put = wire.putAccountState!;
    wire.putAccountState = () => Promise.reject(new ApiError(403, "forbidden", "refused"));
    await bob.shared.logs.refresh(old, null, null, true);
    wire.putAccountState = put;
    const s = bob.shared.logs.verifiedState(old)!;
    expect({ outcome: bob.shared.outcome(old)?.kind, latestAdd: s.latestAdds[BOB]?.seq, member: BOB in s.members, answered: bob.shared.accountState.local().accepted.get(old)?.addSeq === add }).toEqual({
      outcome: "ask",
      latestAdd: add,
      member: false,
      answered: false,
    });
    expect({ gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ gate: OPEN, live: NOT_LIVE });
    await copiesOut(bob, old);
  });

  it("accepted while closed: the vault is back, its item live, and nothing of it is kept", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect({ listed: listed(bob.store, old), held: heldOf(bob), items: namesIn(bob, old), atRest: await heldAtRest(old) }).toEqual({ listed: true, held: [], items: ["bank"], atRest: undefined });
    // The reader of a vault the account may use sees one: every "not live" in this file compares against a reader that can say yes.
    expect(liveOf(bob, old)).toEqual({ listed: true, key: true });
  });

  it("on its day the copy goes while closed, in memory and at rest, and the vault is no vault the account may use", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const t0 = Date.now();
    vi.setSystemTime(t0);
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const day = rowOf(bob, old)!.expungeAt;
    vi.setSystemTime(day - 1);
    await bob.store.sync();
    expect(gateOf(bob, old)).toEqual(CLOSED);
    vi.setSystemTime(day);
    await bob.store.sync();
    expect({ held: heldOf(bob), atRest: await heldAtRest(old), live: liveOf(bob, old) }).toEqual({ held: [], atRest: undefined, live: NOT_LIVE });
  });

  it("\"Remove from this device\" while closed: the copy goes, the invitation still stands, and accepting it brings the vault back", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    await bob.store.removeHeldCopy(old);
    expect({ held: heldOf(bob), atRest: await heldAtRest(old), asks: asksOf(bob, old).length, live: liveOf(bob, old) }).toEqual({ held: [], atRest: undefined, asks: 1, live: NOT_LIVE });
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect({ listed: listed(bob.store, old), held: heldOf(bob), items: namesIn(bob, old) }).toEqual({ listed: true, held: [], items: ["bank"] });
  });

  it("a reload over the offline copy before any pull, online and offline: what the browser shows from its copy alone, and closed after its first pull", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    const online = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const beforeAnyPull = { asks: asksOf(online, old).length, gate: gateOf(online, old), live: liveOf(online, old) };
    server.tamper = () => {
      throw new TypeError("offline");
    };
    const offline = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    await offline.store.sync().catch(() => {});
    const whileOffline = { asks: asksOf(offline, old).length, gate: gateOf(offline, old), live: liveOf(offline, old) };
    server.tamper = null;
    await online.store.sync();
    const afterFirstPull = { asks: asksOf(online, old).length, gate: gateOf(online, old), live: liveOf(online, old) };
    expect({ beforeAnyPull, whileOffline, afterFirstPull }).toEqual({
      beforeAnyPull: { asks: 1, gate: CLOSED, live: NOT_LIVE },
      whileOffline: { asks: 1, gate: CLOSED, live: NOT_LIVE },
      afterFirstPull: { asks: 1, gate: CLOSED, live: NOT_LIVE },
    });
  });

  it("a lock and an unlock (a new store over the same offline copy, then its first sync): closed again while asked, and a decline there opens it", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const unlocked = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect({ asks: asksOf(unlocked, old).length, gate: gateOf(unlocked, old), live: liveOf(unlocked, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
    expect((await unlocked.shared.answer(asksOf(unlocked, old)[0]!, false)).kind).toBe("declined");
    expect(gateOf(unlocked, old)).toEqual(OPEN);
    await copiesOut(unlocked, old);
  });

  it("a browser whose storage refuses every write: the gate reads only, closed as before, and its refusal writes nothing at rest", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const atRest = await heldAtRest(old);
    const storage = bob.profile.storage;
    const set = storage.set;
    const remove = storage.remove;
    const tried: string[] = [];
    storage.set = (k: string) => {
      tried.push(k);
      throw new Error("storage refuses the write");
    };
    storage.remove = (k: string) => {
      tried.push(k);
      throw new Error("storage refuses the write");
    };
    try {
      expect(gateOf(bob, old)).toEqual(CLOSED);
      await expect(bob.store.copyHeldToPersonal(old)).rejects.toMatchObject({ name: "HeldClosedWhileAskedError" });
      expect(gateOf(bob, old)).toEqual(CLOSED);
      expect(tried).toEqual([]);
    } finally {
      storage.set = set;
      storage.remove = remove;
    }
    expect(await heldAtRest(old)).toEqual(atRest);
    expect(personalNames(bob)).toEqual([]);
  });

  it("a copy-out started before the invitation arrives runs to its end: the gate is asked once, at its head; once asked, the copy is closed", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeBob(alice, bob, old);
    await alice.store.addVaultMember(old, BOB, "writer");
    const wire = wireOf(bob);
    const push = wire.pushMutations!;
    let arrived = false;
    wire.pushMutations = async (...a: unknown[]) => {
      if (!arrived) {
        arrived = true;
        // The answer that brings the grant back is decided while the copy-out is under way.
        const row = server.grantRowOf(old, BOB);
        bob.shared.noteGrantRow(old, { wrappedVk: row.wrappedVk, signedGrant: row.signedGrant ?? null, rev: row.rev });
        await bob.shared.onSharedVault(old, null);
        expect(gateOf(bob, old)).toEqual(CLOSED);
      }
      return push.apply(wire, a);
    };
    const r = await bob.store.copyHeldToPersonal(old);
    expect({ arrived, copied: r.copied, personal: personalNames(bob) }).toEqual({ arrived: true, copied: 1, personal: ["bank"] });
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
    await expect(bob.store.copyHeldToPersonal(old)).rejects.toMatchObject({ name: "HeldClosedWhileAskedError" });
  });

  it("a log served behind what this browser verified, or with an entry that does not verify: nothing asks, the copy is open and no vault the account may use; served honestly again, it asks and closes", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    const entries = server.logs.get(old)!.length;
    server.logCut.set(old, entries - 1);
    await bob.store.sync().catch(() => {});
    expect({ log: bob.shared.logs.status(old).kind, asks: asksOf(bob, old), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ log: "withheld", asks: [], gate: OPEN, live: NOT_LIVE });
    server.logCut.delete(old);
    await bob.store.sync();
    expect(gateOf(bob, old)).toEqual(CLOSED);
    server.logs.set(old, [...server.logs.get(old)!, "AAAA"]);
    await bob.store.sync().catch(() => {});
    expect({ log: bob.shared.logs.status(old).kind, asks: asksOf(bob, old), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ log: "failed", asks: [], gate: OPEN, live: NOT_LIVE });
    server.logs.set(old, server.logs.get(old)!.slice(0, entries));
    await bob.store.sync();
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
  });

  it("a grant row the server leaves out of a pull while asked: what is so (the session keeps the row its last pull noted, so the invitation stands and the copy stays closed)", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    server.tamper = (r: SyncResponse, _since: number, userId: string) => (userId !== BOB ? r : { ...r, grants: r.grants.filter((g) => g.vaultId !== old) });
    await bob.store.sync();
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
    await expect(bob.store.copyHeldToPersonal(old)).rejects.toMatchObject({ name: "HeldClosedWhileAskedError" });
  });

  it("accepted on another device of the account, and the account's record of answers served behind to this browser: still asked here and closed until answered here; answered, the vault is back", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const behind = { ...server.states.get(BOB)! };
    const phone = await browser(server, bob.person, bob.contacts, { again: { storage: memoryStorage(), personalVaultId: bob.profile.personalVaultId, personalVk: bob.profile.personalVk } });
    expect((await phone.shared.answer(asksOf(phone, old)[0]!, true)).kind).toBe("adopted");
    const wire = wireOf(bob);
    const read = wire.accountState!;
    wire.accountState = async () => ({ sealedState: behind.sealed, seq: behind.seq });
    await bob.store.sync();
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
    wire.accountState = read;
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect({ listed: listed(bob.store, old), held: heldOf(bob), items: namesIn(bob, old) }).toEqual({ listed: true, held: [], items: ["bank"] });
  });
});

/** [who]'s account state refuses every write from now on, with [error]; returns a way to take the refusal back. */
function writesRefused(who: Browser, error: () => unknown): () => void {
  const wire = wireOf(who);
  const put = wire.putAccountState!;
  wire.putAccountState = () => Promise.reject(error());
  return () => {
    wire.putAccountState = put;
  };
}
const FULL = (): unknown => new ApiError(413, "account_state_full", "full");

describe("an answer whose write the server refused opens the kept copy for that add (decided on 23 and 24 November 2026)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("refused: open; then a pull that leaves the grant row out, a pull whose grant does not verify and a pull that asks the same add again: open after each, never a vault the account may use, and the invitation still stands", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    const add = asksOf(bob, old)[0]!.addSeq;
    writesRefused(bob, FULL);
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, true)).toMatchObject({ kind: "not_recorded", reason: "account_state_full" });
    expect({ gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ gate: OPEN, live: NOT_LIVE });
    const rounds: Record<string, unknown> = {};
    server.tamper = (r: SyncResponse, _since: number, userId: string) => (userId !== BOB ? r : { ...r, grants: r.grants.filter((g) => g.vaultId !== old) });
    await bob.store.sync();
    rounds.grantLeftOut = { gate: gateOf(bob, old), live: liveOf(bob, old) };
    grantServedAs(server, old, () => NOT_A_GRANT);
    await bob.store.sync();
    rounds.grantNotVerifying = { outcome: bob.shared.outcome(old)?.kind, gate: gateOf(bob, old), live: liveOf(bob, old) };
    server.tamper = null;
    await bob.store.sync();
    rounds.askedAgain = { asks: asksOf(bob, old).map((a) => a.addSeq), gate: gateOf(bob, old), live: liveOf(bob, old) };
    expect(rounds).toEqual({
      grantLeftOut: { gate: OPEN, live: NOT_LIVE },
      grantNotVerifying: { outcome: "refused", gate: OPEN, live: NOT_LIVE },
      askedAgain: { asks: [add], gate: OPEN, live: NOT_LIVE },
    });
    await copiesOut(bob, old);
    expect(liveOf(bob, old)).toEqual(NOT_LIVE);
  });

  it("a server that keeps meeting the write with newer ones (contended): open for that add, and the invitation stands", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    writesRefused(bob, () => new ApiError(409, "stale_state", "stale"));
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, true)).toMatchObject({ kind: "not_recorded", reason: "contended" });
    await bob.store.sync();
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: 1, gate: OPEN, live: NOT_LIVE });
  });

  it("this browser's own traffic stop: a write it refused before sending is a refusal (open for that add); one it sent and whose answer it dropped is not known (closed again once asked)", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const back = writesRefused(bob, () => new TrafficStoppedError("the origin's pin is forked", true));
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, true)).toMatchObject({ kind: "not_recorded", reason: "unknown" });
    await bob.store.sync();
    const sent = { asks: asksOf(bob, old).length, gate: gateOf(bob, old) };
    back();
    writesRefused(bob, () => new TrafficStoppedError("the origin's pin is forked", false));
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, true)).toMatchObject({ kind: "not_recorded", reason: "traffic_stopped" });
    await bob.store.sync();
    const notSent = { asks: asksOf(bob, old).length, gate: gateOf(bob, old) };
    expect({ sent, notSent }).toEqual({ sent: { asks: 1, gate: CLOSED }, notSent: { asks: 1, gate: OPEN } });
  });

  it("refused for one add, then bob removed and added again with an invitation he can answer: closed afresh", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const first = asksOf(bob, old)[0]!.addSeq;
    const back = writesRefused(bob, FULL);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("not_recorded");
    back();
    expect(gateOf(bob, old)).toEqual(OPEN);
    await alice.store.removeVaultMember(old, BOB);
    await bob.store.sync();
    expect(gateOf(bob, old)).toEqual(OPEN);
    await addBobAgain(alice, bob, old);
    expect(asksOf(bob, old).map((a) => a.addSeq)).not.toContain(first);
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
  });

  it("refused, then answered again and taken: adopted, and the vault is back", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const back = writesRefused(bob, FULL);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("not_recorded");
    back();
    await bob.store.sync();
    expect(gateOf(bob, old)).toEqual(OPEN);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect({ listed: listed(bob.store, old), held: heldOf(bob), items: namesIn(bob, old) }).toEqual({ listed: true, held: [], items: ["bank"] });
  });

  it("after an adoption no refusal is remembered: the acceptance served away and the adoption asked again directly, the copy is as a session that never saw the refusal decides it", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const add = asksOf(bob, old)[0]!.addSeq;
    const back = writesRefused(bob, FULL);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("not_recorded");
    back();
    await bob.store.sync();
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("adopted");
    // The acceptance is taken out of the account's record (served away), before the pull that puts the copy back.
    await bob.shared.accountState.update((doc) => ({ ...doc, accepted: new Map([...doc.accepted].filter(([v]) => v !== old)) }));
    expect(await bob.shared.onSharedVault(old, null)).toMatchObject({ kind: "ask", addSeq: add });
    const fresh = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const row = server.grantRowOf(old, BOB);
    fresh.shared.noteGrantRow(old, { wrappedVk: "", signedGrant: row.signedGrant ?? null, rev: row.rev });
    expect(await fresh.shared.onSharedVault(old, null)).toMatchObject({ kind: "ask", addSeq: add });
    expect({ here: bob.shared.heldClosedByAsk(old), fresh: fresh.shared.heldClosedByAsk(old) }).toEqual({ here: true, fresh: true });
    expect(gateOf(bob, old)).toEqual(CLOSED);
  });

  it("refused, then a reload: what is so (nothing of the refusal is kept, so the copy is closed again once the reloaded page is asked)", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const back = writesRefused(bob, FULL);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("not_recorded");
    back();
    expect(gateOf(bob, old)).toEqual(OPEN);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect({ asks: asksOf(again, old).length, gate: gateOf(again, old), live: liveOf(again, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
  });

  it("a decline whose record and leave the server both refuse: the copy stays open after the next pull, which asks the same add again; declining again keeps it open, and \"Remove from this device\" ends it", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    writesRefused(bob, FULL);
    wireOf(bob).appendLog = () => Promise.reject(new ApiError(403, "forbidden", "refused"));
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, false)).toMatchObject({ kind: "declined", leave: "not_stored" });
    const afterDecline = gateOf(bob, old);
    await bob.store.sync();
    const afterPull = { asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) };
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, false)).kind).toBe("declined");
    const afterSecondDecline = gateOf(bob, old);
    expect({ afterDecline, afterPull, afterSecondDecline }).toEqual({ afterDecline: OPEN, afterPull: { asks: 1, gate: OPEN, live: NOT_LIVE }, afterSecondDecline: OPEN });
    await bob.store.sync();
    expect(gateOf(bob, old)).toEqual(OPEN);
    await bob.store.removeHeldCopy(old);
    expect({ held: heldOf(bob), atRest: await heldAtRest(old) }).toEqual({ held: [], atRest: undefined });
  });

  it("refused in one tab: what is so (the other tab does not learn it and stays closed until its own answer; refused there too, it opens)", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(gateOf(tabB, old)).toEqual(CLOSED);
    const back = writesRefused(tabB, FULL);
    expect((await tabB.shared.answer(asksOf(tabB, old)[0]!, true)).kind).toBe("not_recorded");
    back();
    await tabB.store.sync();
    await bob.store.sync();
    expect({ tabB: gateOf(tabB, old), tabA: gateOf(bob, old), asksA: asksOf(bob, old).length, asksB: asksOf(tabB, old).length }).toEqual({ tabB: OPEN, tabA: CLOSED, asksA: 1, asksB: 1 });
    writesRefused(bob, FULL);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("not_recorded");
    expect(gateOf(bob, old)).toEqual(OPEN);
  });
});

/** [who]'s server answers every request [name] with [error] from now on. */
function wireRefuses(who: Browser, name: string, error: () => unknown): void {
  wireOf(who)[name] = () => Promise.reject(error());
}

/** Neither the decline's record nor its leave is stored: the account state refuses every write and the log every append. Returns a way to take both back. */
function recordAndLeaveRefused(who: Browser): () => void {
  const back = writesRefused(who, FULL);
  const wire = wireOf(who);
  const append = wire.appendLog!;
  wire.appendLog = () => Promise.reject(new ApiError(403, "forbidden", "refused"));
  return () => {
    back();
    wire.appendLog = append;
  };
}

/**
 * [who] answers the invitation to [vaultId] as the screen does it: the answer, then the sync the screen runs at once
 * after it. What the answer gave (its kind, with the reason of an answer not recorded, or "threw"), and the copy before
 * and after that sync.
 */
async function answeredAsTheScreenDoes(who: Browser, vaultId: string, accept: boolean) {
  let kind: string;
  try {
    const a = await who.shared.answer(asksOf(who, vaultId)[0]!, accept);
    kind = a.kind === "not_recorded" ? `${a.kind}:${a.reason}` : a.kind;
  } catch {
    kind = "threw";
  }
  const beforeSync = gateOf(who, vaultId);
  await who.store.sync().catch(() => {});
  return { kind, beforeSync, afterSync: gateOf(who, vaultId), asks: asksOf(who, vaultId).length, live: liveOf(who, vaultId) };
}

/** [who]'s copy-out of [vaultId], tried: how many items it copied, or the name of its refusal. */
async function copyOutTried(who: Browser, vaultId: string): Promise<string> {
  return who.store.copyHeldToPersonal(vaultId).then(
    (r) => `copied:${r.copied}`,
    (e: unknown) => (e as Error).name,
  );
}

describe("a decline opens the kept copy for its add, whatever the server and this browser made of it", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  for (const [label, error] of [
    ["a 500 on every account-state write and every log append", () => new ApiError(500, "http_500", "Internal Server Error")],
    ["a 500 with an error body", () => new ApiError(500, "internal", "boom")],
    ["no answer to any write", () => new Error("no answer in time")],
  ] as const) {
    it(`${label}: an accept whose outcome is not known is closed again at its sync; a decline opens the copy and it stays open at that sync and the pulls after it, and on its day its item is in the personal vault`, async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      const t0 = Date.now();
      vi.setSystemTime(t0);
      freshDb();
      const { alice, bob, old } = await family(await openVaultCache(BOB));
      await askedAgain(alice, bob, old);
      const day = rowOf(bob, old)!.expungeAt;
      wireRefuses(bob, "putAccountState", error);
      wireRefuses(bob, "appendLog", error);
      const accept = { ...(await answeredAsTheScreenDoes(bob, old, true)), copyOut: await copyOutTried(bob, old) };
      const decline = { ...(await answeredAsTheScreenDoes(bob, old, false)), copyOut: await copyOutTried(bob, old) };
      const personal = personalNames(bob);
      const pulls: unknown[] = [];
      for (let i = 0; i < 2; i++) {
        await bob.store.sync().catch(() => {});
        pulls.push({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) });
      }
      vi.setSystemTime(day);
      await bob.store.sync().catch(() => {});
      expect({ accept, decline, personal, pulls, atDay: { held: heldOf(bob), personal: personalNames(bob), live: liveOf(bob, old) } }).toEqual({
        accept: { kind: "not_recorded:unknown", beforeSync: OPEN, afterSync: CLOSED, asks: 1, live: NOT_LIVE, copyOut: "HeldClosedWhileAskedError" },
        decline: { kind: "declined", beforeSync: OPEN, afterSync: OPEN, asks: 1, live: NOT_LIVE, copyOut: "copied:1" },
        personal: ["bank"],
        pulls: [
          { asks: 1, gate: OPEN, live: NOT_LIVE },
          { asks: 1, gate: OPEN, live: NOT_LIVE },
        ],
        atDay: { held: [], personal: ["bank"], live: NOT_LIVE },
      });
    });
  }

  it("storage that throws on every write, an honest server: the accept throws and the copy stays closed; the decline throws too and opens it, and the copy-out goes while storage still throws; with storage writing again, the invitation still stands and an accept adopts", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const storage = bob.profile.storage;
    const set = storage.set;
    storage.set = () => {
      throw new Error("QuotaExceededError");
    };
    let accept: unknown;
    let decline: unknown;
    let copyOut: string;
    let personal: string[];
    try {
      accept = await answeredAsTheScreenDoes(bob, old, true);
      decline = await answeredAsTheScreenDoes(bob, old, false);
      copyOut = await copyOutTried(bob, old);
      personal = personalNames(bob);
    } finally {
      storage.set = set;
    }
    const shown = asksOf(bob, old).length;
    const again = (await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind;
    await bob.store.sync();
    expect({ accept, decline, copyOut, personal, shown, again, after: { listed: listed(bob.store, old), items: namesIn(bob, old), held: heldOf(bob) } }).toEqual({
      accept: { kind: "threw", beforeSync: CLOSED, afterSync: CLOSED, asks: 1, live: NOT_LIVE },
      decline: { kind: "threw", beforeSync: OPEN, afterSync: OPEN, asks: 1, live: NOT_LIVE },
      copyOut: "copied:1",
      personal: ["bank"],
      shown: 1,
      again: "adopted",
      after: { listed: true, items: ["bank"], held: [] },
    });
  });

  it("the server says \"stored\" to the decline's leave and never serves it, and answers the record's write with a 500: open after the decline's sync, which asks the same add again", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    wireRefuses(bob, "putAccountState", () => new ApiError(500, "http_500", "x"));
    wireOf(bob).appendLog = async () => ({ rev: server.rev, head: server.head(old), deleted: null });
    const logBefore = server.logs.get(old)!.length;
    expect(await answeredAsTheScreenDoes(bob, old, false)).toEqual({ kind: "declined", beforeSync: OPEN, afterSync: OPEN, asks: 1, live: NOT_LIVE });
    expect(server.logs.get(old)!.length).toBe(logBefore);
    await copiesOut(bob, old);
  });

  it("a decline whose record and leave are both refused, then bob removed and added again with an invitation that can be answered: closed afresh for the new add", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const first = asksOf(bob, old)[0]!.addSeq;
    const back = recordAndLeaveRefused(bob);
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, false)).toMatchObject({ kind: "declined", leave: "not_stored" });
    back();
    await bob.store.sync();
    expect({ asks: asksOf(bob, old).map((a) => a.addSeq), gate: gateOf(bob, old) }).toEqual({ asks: [first], gate: OPEN });
    await alice.store.removeVaultMember(old, BOB);
    await bob.store.sync();
    expect(gateOf(bob, old)).toEqual(OPEN);
    await addBobAgain(alice, bob, old);
    expect(asksOf(bob, old).map((a) => a.addSeq)).not.toContain(first);
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
  });

  it("a decline whose record and leave are both refused, then a reload: what is so (nothing of the decline is kept, so the copy is closed again once the reloaded page is asked)", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const back = recordAndLeaveRefused(bob);
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, false)).toMatchObject({ kind: "declined", leave: "not_stored" });
    back();
    expect(gateOf(bob, old)).toEqual(OPEN);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect({ asks: asksOf(again, old).length, gate: gateOf(again, old), live: liveOf(again, old) }).toEqual({ asks: 1, gate: CLOSED, live: NOT_LIVE });
  });

  it("a decline whose record and leave are both refused in one tab: what is so (the other tab does not learn it and stays closed until its own answer; declined there too, it opens)", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const tabB = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(gateOf(tabB, old)).toEqual(CLOSED);
    const back = recordAndLeaveRefused(tabB);
    expect(await tabB.shared.answer(asksOf(tabB, old)[0]!, false)).toMatchObject({ kind: "declined", leave: "not_stored" });
    back();
    await tabB.store.sync();
    await bob.store.sync();
    expect({ tabB: gateOf(tabB, old), tabA: gateOf(bob, old), asksA: asksOf(bob, old).length, asksB: asksOf(tabB, old).length }).toEqual({ tabB: OPEN, tabA: CLOSED, asksA: 1, asksB: 1 });
    recordAndLeaveRefused(bob);
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, false)).toMatchObject({ kind: "declined", leave: "not_stored" });
    await bob.store.sync();
    expect(gateOf(bob, old)).toEqual(OPEN);
  });

  it("after an adoption no decline is remembered: a decline whose record and leave are refused, then accepted and taken, then the acceptance served away and the adoption asked again directly: the copy is as a session that never saw the decline decides it", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const add = asksOf(bob, old)[0]!.addSeq;
    const back = recordAndLeaveRefused(bob);
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, false)).toMatchObject({ kind: "declined", leave: "not_stored" });
    back();
    await bob.store.sync();
    expect({ asks: asksOf(bob, old).length, gate: gateOf(bob, old) }).toEqual({ asks: 1, gate: OPEN });
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("adopted");
    // The acceptance is taken out of the account's record (served away), before the pull that puts the copy back.
    await bob.shared.accountState.update((doc) => ({ ...doc, accepted: new Map([...doc.accepted].filter(([v]) => v !== old)) }));
    expect(await bob.shared.onSharedVault(old, null)).toMatchObject({ kind: "ask", addSeq: add });
    const fresh = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const row = server.grantRowOf(old, BOB);
    fresh.shared.noteGrantRow(old, { wrappedVk: "", signedGrant: row.signedGrant ?? null, rev: row.rev });
    expect(await fresh.shared.onSharedVault(old, null)).toMatchObject({ kind: "ask", addSeq: add });
    expect({ here: bob.shared.heldClosedByAsk(old), fresh: fresh.shared.heldClosedByAsk(old) }).toEqual({ here: true, fresh: true });
    expect(gateOf(bob, old)).toEqual(CLOSED);
  });

  it("the decline keeps the add it answered, not the add of the session's last outcome: the owner no longer a current contact at a pull (connect first), current again, then a decline from the invitation still shown, its record and leave refused: the next pull asks the same add again, and the copy is open", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    const shown = asksOf(bob, old)[0]!;
    const key = `andvari.current.${BOB}`;
    const saved = bob.profile.storage.get(key);
    bob.shared.currency.drop(ALICE);
    await bob.store.sync();
    const moved = bob.shared.outcome(old)?.kind;
    if (saved !== null) bob.profile.storage.set(key, saved);
    const back = recordAndLeaveRefused(bob);
    const a = await bob.shared.answer(shown, false);
    back();
    await bob.store.sync();
    expect({ moved, answered: a.kind, asks: asksOf(bob, old).map((x) => x.addSeq), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ moved: "connect_first", answered: "declined", asks: [shown.addSeq], gate: OPEN, live: NOT_LIVE });
  });
});

describe("a refusal by the server is told from an outcome not known by where it came from, never by its word", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  for (const code of ["unknown", "unreachable"] as const) {
    it(`a 400 whose code is literally ${code}, on every account-state write and every log append: the accept is a refusal and opens the copy, the decline after it keeps it open, and on its day its item is in the personal vault`, async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      const t0 = Date.now();
      vi.setSystemTime(t0);
      freshDb();
      const { alice, bob, old } = await family(await openVaultCache(BOB));
      await askedAgain(alice, bob, old);
      expect(gateOf(bob, old)).toEqual(CLOSED);
      const day = rowOf(bob, old)!.expungeAt;
      wireRefuses(bob, "putAccountState", () => new ApiError(400, code, "no"));
      wireRefuses(bob, "appendLog", () => new ApiError(400, code, "no"));
      const accept = { ...(await answeredAsTheScreenDoes(bob, old, true)), copyOut: await copyOutTried(bob, old) };
      const personal = personalNames(bob);
      const decline = await answeredAsTheScreenDoes(bob, old, false);
      vi.setSystemTime(day);
      await bob.store.sync().catch(() => {});
      expect({ accept, personal, decline, atDay: { held: heldOf(bob), personal: personalNames(bob), live: liveOf(bob, old) } }).toEqual({
        accept: { kind: `not_recorded:${code}`, beforeSync: OPEN, afterSync: OPEN, asks: 1, live: NOT_LIVE, copyOut: "copied:1" },
        personal: ["bank"],
        decline: { kind: "declined", beforeSync: OPEN, afterSync: OPEN, asks: 1, live: NOT_LIVE },
        atDay: { held: [], personal: ["bank"], live: NOT_LIVE },
      });
    });
  }
});

describe("the store asks the session's reader itself, with no road around it", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a session whose reader is missing while asked: \"Recently removed\" cannot be read and the copy-out is refused, so nothing opens the copy by itself; with the reader back, a decline opens it and the copy-out goes", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    const session = bob.shared as unknown as { heldClosedByAsk?: unknown };
    const reader = session.heldClosedByAsk;
    session.heldClosedByAsk = undefined;
    const sent = sendsOf(bob);
    let rows: unknown;
    let copyOut: unknown;
    try {
      rows = (() => {
        try {
          return bob.store.heldVaults();
        } catch (e) {
          return e;
        }
      })();
      copyOut = await bob.store.copyHeldToPersonal(old).catch((e: unknown) => e);
    } finally {
      session.heldClosedByAsk = reader;
    }
    expect({ rows: rows instanceof TypeError, copyOut: copyOut instanceof TypeError, sent, personal: personalNames(bob), live: liveOf(bob, old) }).toEqual({ rows: true, copyOut: true, sent: [], personal: [], live: NOT_LIVE });
    expect(gateOf(bob, old)).toEqual(CLOSED);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, false)).kind).toBe("declined");
    await copiesOut(bob, old);
  });

  it("a store with no session layer attached closes nothing: over the same offline copy, while the session's store shows it closed, its kept copy is not closed for an invitation", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    const wire = wireOf(bob);
    const bare = new VaultStore(wire as unknown as ApiClient, bob.account, await openVaultCache(BOB), undefined, wire as unknown as ItemWire);
    await bare.hydrate();
    expect(bare.heldVaults().map((h) => ({ vaultId: h.vaultId, addedAgain: h.addedAgain }))).toEqual([{ vaultId: old, addedAgain: false }]);
  });
});

describe("the gate's order and what it remembers, each case showing first what could have been otherwise", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a decline whose record is written and whose leave the server refused: declined, nothing asked and open after each of the next two pulls, and after a reload too, where only the account's record keeps it open", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    wireRefuses(bob, "appendLog", () => new ApiError(403, "forbidden", "refused"));
    expect(await bob.shared.answer(asksOf(bob, old)[0]!, false)).toMatchObject({ kind: "declined", leave: "not_stored" });
    const pulls: unknown[] = [];
    for (let i = 0; i < 2; i++) {
      await bob.store.sync();
      pulls.push({ outcome: bob.shared.outcome(old)?.kind, asks: asksOf(bob, old).length, gate: gateOf(bob, old), live: liveOf(bob, old) });
    }
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    const reloaded = { outcome: again.shared.outcome(old)?.kind, asks: asksOf(again, old).length, gate: gateOf(again, old), live: liveOf(again, old) };
    const declined = { outcome: "declined", asks: 0, gate: OPEN, live: NOT_LIVE };
    expect({ pulls, reloaded }).toEqual({ pulls: [declined, declined], reloaded: declined });
  });

  it("an adoption that arrives by a pull ends what the session remembers of a refused answer: the acceptance then served away and the same add asked again, the copy is as a session that never saw the refusal decides it", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    const add = asksOf(bob, old)[0]!.addSeq;
    const back = writesRefused(bob, FULL);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("not_recorded");
    back();
    await bob.store.sync();
    // The memory holds the copy open while the same add is asked again.
    expect({ asks: asksOf(bob, old).map((a) => a.addSeq), reader: bob.shared.heldClosedByAsk(old), gate: gateOf(bob, old) }).toEqual({ asks: [add], reader: false, gate: OPEN });
    const phone = await browser(server, bob.person, bob.contacts, { again: { storage: memoryStorage(), personalVaultId: bob.profile.personalVaultId, personalVk: bob.profile.personalVk } });
    expect((await phone.shared.answer(asksOf(phone, old)[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect(bob.shared.outcome(old)?.kind).toBe("adopted");
    await bob.shared.accountState.update((doc) => ({ ...doc, accepted: new Map([...doc.accepted].filter(([v]) => v !== old)) }));
    expect(await bob.shared.onSharedVault(old, null)).toMatchObject({ kind: "ask", addSeq: add });
    const fresh = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    const row = server.grantRowOf(old, BOB);
    fresh.shared.noteGrantRow(old, { wrappedVk: "", signedGrant: row.signedGrant ?? null, rev: row.rev });
    expect(await fresh.shared.onSharedVault(old, null)).toMatchObject({ kind: "ask", addSeq: add });
    expect({ here: bob.shared.heldClosedByAsk(old), fresh: fresh.shared.heldClosedByAsk(old) }).toEqual({ here: true, fresh: true });
  });

  it("while closed, the copy-out is refused before the vault's key is opened: no opening of this account's wrap while closed, and one once a decline opens the copy", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    const logs = bob.shared.logs as unknown as { openOwnWrap: (...a: unknown[]) => Promise<unknown> };
    const real = logs.openOwnWrap;
    let opened = 0;
    logs.openOwnWrap = (...a: unknown[]) => {
      opened++;
      return real.apply(bob.shared.logs, a);
    };
    await expect(bob.store.copyHeldToPersonal(old)).rejects.toMatchObject({ name: "HeldClosedWhileAskedError" });
    const whileClosed = opened;
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, false)).kind).toBe("declined");
    await copiesOut(bob, old);
    expect({ whileClosed, afterDecline: opened }).toEqual({ whileClosed: 0, afterDecline: 1 });
  });

  it("while closed, a read-only copy is refused as read-only: the closed refusal comes after the write gate", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    await expect(bob.store.copyHeldToPersonal(old)).rejects.toMatchObject({ name: "HeldClosedWhileAskedError" });
    bob.store.freezeAsReadOnlyCopy("forked");
    await expect(bob.store.copyHeldToPersonal(old)).rejects.toMatchObject({ name: "ReadOnlyCopyError" });
    expect(personalNames(bob)).toEqual([]);
  });

  it("while closed, a browser with no personal vault is refused for that: the closed refusal comes after the personal vault is asked for", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    await expect(bob.store.copyHeldToPersonal(old)).rejects.toMatchObject({ name: "HeldClosedWhileAskedError" });
    (bob.account as unknown as { personalVaultIdValue: string }).personalVaultIdValue = "";
    await expect(bob.store.copyHeldToPersonal(old)).rejects.toMatchObject({ name: "NoPersonalVaultError" });
  });

  it("a refused accept keeps the add it answered, not the add of the session's last outcome: the owner no longer a current contact at a pull (connect first), current again, then an accept from the invitation still shown, refused: the next pull asks the same add again, and the copy is open", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await askedAgain(alice, bob, old);
    expect(gateOf(bob, old)).toEqual(CLOSED);
    const shown = asksOf(bob, old)[0]!;
    const key = `andvari.current.${BOB}`;
    const saved = bob.profile.storage.get(key);
    bob.shared.currency.drop(ALICE);
    await bob.store.sync();
    const moved = bob.shared.outcome(old)?.kind;
    if (saved !== null) bob.profile.storage.set(key, saved);
    const back = writesRefused(bob, FULL);
    const a = await bob.shared.answer(shown, true);
    back();
    await bob.store.sync();
    expect({ moved, answered: a.kind, asks: asksOf(bob, old).map((x) => x.addSeq), gate: gateOf(bob, old), live: liveOf(bob, old) }).toEqual({ moved: "connect_first", answered: "not_recorded", asks: [shown.addSeq], gate: OPEN, live: NOT_LIVE });
  });
});
