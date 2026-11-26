// A shared vault whose account record names an entry above the log this browser verified: nothing is written into it,
// and it is not shown as writable, whatever the vault's stored flag says and whichever tab of the profile set or cleared
// that flag (decided on 23 November 2026: after a server is put back from a backup such a vault is read-only on every
// device). The record and the flag live in the profile's storage, which every tab of a browser shares; the write gate
// reads the record at the moment it is asked. Driven through the real VaultStore, SharedLogSession, VaultLogStore and
// offline copy against the shared fake server; a second tab is a second session over the same storage.
import "fake-indexeddb/auto";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { AttachmentRef } from "../api/types";
import { memoryStorage } from "../api/devicesecret";
import { toB64, utf8 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { VAULT_KEY_NOT_VERIFIED } from "../ui/copy";
import { VaultKeyNotVerifiedError } from "./account";
import { type AccountDocument, withVaultHead } from "./accountdoc";
import { ALICE, BOB, browser, type Browser, contact, FakeSyncServer, freshDb, listed, namesIn, person, type Profile } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";
import { LogActionError } from "./store";

const CAROL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
/** The hash another device of the account recorded at a place the served log does not hold. */
const OTHER_HASH = "ab".repeat(32);

/** A read of a vault's log, held until the test lets it go on. */
interface Hold {
  reached: () => void;
  released: Promise<void>;
}

/**
 * The shared fake server, which can also be out of reach for item changes ([pushDown]), and which can hold one read of a
 * vault's log by one session: the session made right after [holdNextSession] is set waits, at its next read of a log
 * page while [hold] is set, until the hold is released; the page is then served as the server holds the log at that
 * moment.
 */
class Server extends FakeSyncServer {
  pushDown = false;
  holdNextSession = false;
  hold: Hold | null = null;

  override wireFor(userId: string) {
    const w = super.wireFor(userId);
    const s = this;
    const holds = this.holdNextSession;
    this.holdNextSession = false;
    return {
      ...w,
      async pushMutations(mutations: Parameters<typeof w.pushMutations>[0]) {
        if (s.pushDown) throw new TypeError("offline");
        return w.pushMutations(mutations);
      },
      async logPage(vaultId: string, after: number | null) {
        const h = holds ? s.hold : null;
        if (h !== null) {
          s.hold = null;
          h.reached();
          await h.released;
        }
        return w.logPage(vaultId, after);
      },
      async downloadAttachment(id: string): Promise<Uint8Array> {
        const a = s.attachments.get(id);
        if (a !== undefined && s.personals.get(a.vaultId) === userId) return a.body.slice();
        return w.downloadAttachment(id);
      },
    };
  }
}

const itemOf = (who: Browser, name: string) => who.store.list().find((i) => i.doc.name === name)!;
const flagKey = (who: Browser, vaultId: string): string => `andvari.log2.${who.person.userId}.${vaultId}.flag`;
const sealedKey = (who: Browser): string => `andvari.as2.${who.person.userId}.sealed`;

/**
 * Alice owns "Family" with one login, "bank"; bob is a writer who accepted, carol a reader who accepted and then left.
 * Bob keeps "deeds" in the vault. Bob's and alice's browsers verified carol's leave (at seq [at]), and bob's account
 * records the vault up to that leave. [cache]: bob's browser keeps the offline copy.
 */
async function scene(opts: { cache?: boolean } = {}) {
  freshDb();
  const server = new Server();
  const a = person(ALICE);
  const b = person(BOB);
  const c = person(CAROL);
  const alice = await browser(server, a, [contact(b, "Bob"), contact(c, "Carol")]);
  const bob = await browser(server, b, [contact(a, "Alice")], { cache: opts.cache === true ? await openVaultCache(BOB) : undefined });
  const old = await alice.store.createSharedVault("Family");
  await alice.store.addVaultMember(old, BOB, "writer");
  await alice.store.addVaultMember(old, CAROL, "reader");
  await alice.store.save(null, { type: "login", name: "bank", login: { username: "a", password: "pw1" } }, [], undefined, old);
  await bob.store.sync();
  expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  await bob.store.sync();
  const carol = await browser(server, c, [contact(a, "Alice")]);
  expect((await carol.shared.answer(carol.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  await bob.store.save(null, { type: "note", name: "deeds", notes: "d" }, [], undefined, old);
  await bob.store.sync();
  const at = server.logs.get(old)!.length;
  await carol.store.leaveSharedVault(old);
  await bob.store.sync();
  await alice.store.sync();
  const verified = bob.shared.logs.verifiedState(old)!;
  expect(verified.head.seq).toBe(at);
  expect(alice.shared.logs.verifiedState(old)!.head.seq).toBe(at);
  const hashAt = bob.shared.logs.hashes(old).get(at)!;
  await bob.shared.accountState.update((doc) => withVaultHead(doc, old, verified.genesisHash, at, hashAt));
  expect(bob.shared.accountState.local().vaults.get(old)).toMatchObject({ seq: at, hash: hashAt });
  expect(bob.store.mayWrite(old)).toBe(true);
  const bankId = itemOf(bob, "bank").itemId;
  return { server, alice, bob, old, at, hashAt, genesis: verified.genesisHash, bankId };
}
type Scene = Awaited<ReturnType<typeof scene>>;

/** A browser of bob's with a profile of its own (another device of the account). */
async function otherDevice(s: Scene, opts: { cache?: boolean } = {}): Promise<Browser> {
  const profile: Profile = { storage: memoryStorage(), personalVaultId: s.bob.profile.personalVaultId, personalVk: s.bob.profile.personalVk.slice() };
  return browser(s.server, s.bob.person, s.bob.contacts, { again: profile, cache: opts.cache === true ? await openVaultCache(BOB) : undefined });
}

/** What [fn] answers, and every write the server was sent by it and by one more sync of [who]'s (all, and [s]'s vault's). */
async function tryRoad(s: Scene, who: Browser, fn: () => Promise<unknown>): Promise<{ answer: unknown; sent: string[]; all: string[] }> {
  const before = s.server.writes.length;
  const answer = await fn().then(
    (v) => ({ ok: v }),
    (e: unknown) => e,
  );
  await who.store.sync();
  const all = s.server.writes.slice(before);
  return { answer, sent: all.filter((w) => w.endsWith(`:${s.old}`)), all };
}

/** A change of "bank" (found by its id, whatever its name is now) in [s]'s vault, made in [who]'s session. */
const saveBank = (s: Scene, who: Browser, name: string): Promise<void> => {
  const bank = who.store.get(s.bankId)!;
  return who.store.save(bank.itemId, { ...bank.doc, name }, [], undefined, s.old);
};

const refusedAsReadOnly = (answer: unknown, vaultId: string): void => {
  expect(answer).toBeInstanceOf(VaultKeyNotVerifiedError);
  expect((answer as VaultKeyNotVerifiedError).vaultId).toBe(vaultId);
  expect((answer as Error).message).toBe(VAULT_KEY_NOT_VERIFIED);
};

/** [who]'s session shows [s]'s vault [standing] and read-only: listed with its items, nothing writable. */
function readOnlyIn(s: Scene, who: Browser, standing: "withheld" | "frozen"): void {
  expect(who.shared.logs.status(s.old).kind).toBe(standing);
  expect(who.store.mayWrite(s.old)).toBe(false);
  expect(who.shared.logs.writeAllowed(s.old)).toBe(false);
  expect(who.account.logKeyRing().has(s.old)).toBe(true);
  expect(listed(who.store, s.old)).toBe(true);
  expect(namesIn(who, s.old).sort()).toEqual(["bank", "deeds"]);
}

/** [who]'s session shows [s]'s vault verified and writable, with its items. */
function writableIn(s: Scene, who: Browser): void {
  expect(who.shared.logs.status(s.old).kind).toBe("verified");
  expect(who.store.mayWrite(s.old)).toBe(true);
  expect(who.shared.logs.writeAllowed(s.old)).toBe(true);
  expect(listed(who.store, s.old)).toBe(true);
}

/** [who]'s account records [s]'s vault at [seq] with [hash] (written as a device that verified it writes it). */
async function recordAt(s: Scene, who: Browser, seq: number, hash: string): Promise<void> {
  await who.shared.accountState.update((doc) => withVaultHead(doc, s.old, s.genesis, seq, hash));
  expect(who.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq, hash });
}

/** [doc] with [vaultId]'s record replaced by [rec] (null: no record), which withVaultHead never does (it only raises). */
function withRecordReplaced(doc: AccountDocument, vaultId: string, rec: { genesisHash: string; seq: number; hash: string } | null): AccountDocument {
  const vaults = new Map(doc.vaults);
  if (rec === null) vaults.delete(vaultId);
  else vaults.set(vaultId, { vaultId, ...rec, extra: new Map() });
  return { ...doc, vaults };
}

/**
 * Honest use: alice adds carol again (the server stores it at [at]+1), and another device of bob's reads the log, verifies
 * that entry and records it. Bob's browser has read none of it.
 */
async function recordedElsewhere(s: Scene): Promise<string> {
  await s.alice.store.addVaultMember(s.old, CAROL, "reader");
  const other = await otherDevice(s);
  expect(other.shared.logs.verifiedState(s.old)!.head.seq).toBe(s.at + 1);
  const hash = other.shared.logs.hashes(s.old).get(s.at + 1)!;
  await recordAt(s, other, s.at + 1, hash);
  expect(s.bob.shared.logs.verifiedState(s.old)!.head.seq).toBe(s.at);
  return hash;
}

/** Every read of [s]'s vault's log fails from now on (until onLogPage is cleared). */
function logReadsFail(s: Scene): void {
  s.server.onLogPage = (v) => {
    if (v === s.old) throw new Error("the log cannot be read now");
  };
}

type Mode = "two sessions" | "a hook";

/** Bob's first tab (his scene browser), a second tab of his on the same profile, and another device of his. */
interface Tabs {
  mode: Mode;
  tabA: Browser;
  tabB: Browser;
  other: Browser;
}

async function twoTabs(s: Scene, mode: Mode): Promise<Tabs> {
  const other = await otherDevice(s);
  s.server.holdNextSession = mode === "two sessions";
  const tabB = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile });
  expect(s.server.holdNextSession).toBe(false);
  writableIn(s, tabB);
  return { mode, tabA: s.bob, tabB, other };
}

/**
 * The second tab begins a read of the log (one that is not skipped: a forced read, as an item's head hint starts one)
 * before the account's higher record ([seq], [hash]) and the first tab's flag land, and ends it after them.
 * "two sessions": while the second tab's read waits, another device writes the record to the server, the first tab
 * reads the account state and then reads the log (its read sets [flag]). "a hook": the record and [flag] are written
 * into the shared storage at the moment the second tab's page is asked for, standing for the first tab's two steps.
 */
async function secondTabReadsAcross(s: Scene, t: Tabs, seq: number, hash: string, flag: string): Promise<void> {
  const st = t.tabA.profile.storage;
  if (t.mode === "two sessions") {
    let reached!: () => void;
    let release!: () => void;
    const atGate = new Promise<void>((r) => (reached = r));
    s.server.hold = { reached, released: new Promise<void>((r) => (release = r)) };
    const readB = t.tabB.shared.logs.refresh(s.old, null, null, true);
    await atGate;
    await recordAt(s, t.other, seq, hash);
    await t.tabA.shared.refreshState();
    expect(t.tabA.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq, hash });
    await t.tabA.shared.logs.refresh(s.old, null, null, true);
    expect(st.get(flagKey(t.tabA, s.old))).toBe(flag);
    release();
    await readB;
    return;
  }
  const before = st.get(sealedKey(t.tabA))!;
  await recordAt(s, t.tabA, seq, hash);
  const after = st.get(sealedKey(t.tabA))!;
  st.set(sealedKey(t.tabA), before);
  expect(t.tabB.shared.accountState.local().vaults.get(s.old)!.seq).toBe(s.at);
  let armed = true;
  s.server.onLogPage = (v) => {
    if (!armed || v !== s.old) return;
    armed = false;
    st.set(sealedKey(t.tabA), after);
    st.set(flagKey(t.tabA, s.old), flag);
  };
  await t.tabB.shared.logs.refresh(s.old, null, null, true);
  s.server.onLogPage = null;
  expect(armed).toBe(false);
}

describe("a shared vault whose account record is above the log this browser verified: nothing is written into it, whatever its flag says", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  for (const mode of ["two sessions", "a hook"] as const) {
    it(`(a) ${mode}: a second tab's read of the log that began before the higher record and the first tab's flag, and ends below the record, leaves the vault withheld and not writable in both tabs, and a save in either sends nothing`, async () => {
      const s = await scene();
      const t = await twoTabs(s, mode);
      await secondTabReadsAcross(s, t, s.at + 1, OTHER_HASH, `withheld:${s.at}`);
      for (const tab of [t.tabA, t.tabB]) {
        expect(tab.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.at + 1, hash: OTHER_HASH });
        readOnlyIn(s, tab, "withheld");
      }
      for (const tab of [t.tabA, t.tabB]) {
        const r = await tryRoad(s, tab, () => saveBank(s, tab, "bank-new"));
        expect(r.sent).toEqual([]);
        refusedAsReadOnly(r.answer, s.old);
        readOnlyIn(s, tab, "withheld");
      }
    });

    it(`(b) ${mode}: the same timing, the served log holding another entry at the record's place and going on beyond it: frozen in both tabs, the account's record unchanged, and nothing sent`, async () => {
      const s = await scene();
      const t = await twoTabs(s, mode);
      // Alice's two changes land where another device of bob's recorded an entry the server no longer holds.
      await s.alice.store.addVaultMember(s.old, CAROL, "reader");
      await s.alice.store.setMemberRole(s.old, CAROL, "writer");
      expect(s.server.head(s.old).seq).toBe(s.at + 2);
      // This browser last wrote the account's record of the vault long ago: its batching does not hold a write back.
      t.tabA.profile.storage.set(`andvari.log2.${BOB}.${s.old}.recordAt`, "0");
      const before = s.server.writes.length;
      await secondTabReadsAcross(s, t, s.at + 1, OTHER_HASH, `frozen:${s.at + 1}`);
      expect(s.server.writes.slice(before).filter((w) => w.endsWith(`:${s.old}`))).toEqual([]);
      for (const tab of [t.tabA, t.tabB]) {
        expect(tab.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.at + 1, hash: OTHER_HASH });
        readOnlyIn(s, tab, "frozen");
      }
      for (const tab of [t.tabA, t.tabB]) {
        const r = await tryRoad(s, tab, () => saveBank(s, tab, "bank-new"));
        expect(r.sent).toEqual([]);
        refusedAsReadOnly(r.answer, s.old);
        readOnlyIn(s, tab, "frozen");
        expect(tab.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.at + 1, hash: OTHER_HASH });
      }
    });
  }

  it("(c) the flag cleared while the record is above the verified head: a save, a deletion, a rename, a file's upload and a change of its members (the log's append) each send nothing and are refused", async () => {
    const s = await scene();
    const alice = s.alice;
    await recordAt(s, alice, s.at + 1, OTHER_HASH);
    await alice.store.sync();
    expect(alice.shared.logs.status(s.old).kind).toBe("withheld");
    const st = alice.profile.storage;
    const withFile = async (): Promise<void> => {
      const bank = alice.store.get(s.bankId)!;
      const data = utf8("a new file");
      const ref: AttachmentRef = { id: crypto.randomUUID(), name: "f", size: data.length, fileKey: toB64(randomBytes(32)) };
      return alice.store.save(bank.itemId, { ...bank.doc, attachments: [ref] }, [{ id: ref.id, data }], undefined, s.old);
    };
    const roads: [string, () => Promise<unknown>, "item" | "log"][] = [
      ["a save of an item", () => saveBank(s, alice, "bank2"), "item"],
      ["a deletion", () => alice.store.remove(s.bankId), "item"],
      ["a rename", () => alice.store.renameVault(s.old, "Renamed"), "item"],
      ["an upload of an attached file", withFile, "item"],
      ["a change of its members", () => alice.store.setMemberRole(s.old, BOB, "reader"), "log"],
    ];
    for (const [what, fn, kind] of roads) {
      // Whatever cleared it (another tab's read that began before the record landed, or anything else).
      st.remove(flagKey(alice, s.old));
      const files = s.server.attachments.size;
      const r = await tryRoad(s, alice, fn);
      expect(r.sent, what).toEqual([]);
      expect(s.server.attachments.size, what).toBe(files);
      if (kind === "item") refusedAsReadOnly(r.answer, s.old);
      else {
        expect(r.answer, what).toBeInstanceOf(LogActionError);
        expect((r.answer as LogActionError).outcome, what).toEqual({ kind: "read_only", vaultId: s.old });
      }
      st.remove(flagKey(alice, s.old));
      expect(alice.shared.logs.status(s.old).kind, what).toBe("withheld");
      expect(alice.store.mayWrite(s.old), what).toBe(false);
      expect(alice.shared.logs.writeAllowed(s.old), what).toBe(false);
    }
    expect(s.server.grants.get(s.old)!.get(BOB)!.role).toBe("writer");
    expect(alice.store.get(s.bankId)!.doc.name).toBe("bank");
  });

  it("(c) the flag cleared while the record is above the verified head: a change queued while the vault could be written is not drained, and still waits", async () => {
    const s = await scene({ cache: true });
    // The browser lets a change wait to be sent only where its storage is persistent.
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
    const bank = itemOf(s.bob, "bank");
    s.server.pushDown = true;
    await saveBank(s, s.bob, "bank-queued");
    s.server.pushDown = false;
    expect((await (await openVaultCache(BOB)).pending()).map((m) => m.itemId)).toEqual([bank.itemId]);
    await recordAt(s, s.bob, s.at + 1, OTHER_HASH);
    // No read of the log since: the flag is empty.
    expect(s.bob.profile.storage.get(flagKey(s.bob, s.old))).toBeNull();
    const r = await tryRoad(s, s.bob, () => s.bob.store.sync());
    expect(r.sent).toEqual([]);
    expect((await (await openVaultCache(BOB)).pending()).map((m) => m.itemId)).toEqual([bank.itemId]);
    readOnlyIn(s, s.bob, "withheld");
  });

  it("(d) a browser at the served head learns a higher record and its read of the log fails, once and then every time: not writable, nothing sent; a read that reaches the record's entry with its hash makes it writable again", async () => {
    const s = await scene();
    await recordedElsewhere(s);
    logReadsFail(s);
    await s.bob.store.sync();
    expect(s.bob.shared.accountState.local().vaults.get(s.old)!.seq).toBe(s.at + 1);
    readOnlyIn(s, s.bob, "withheld");
    for (const name of ["bank-1", "bank-2"]) {
      const r = await tryRoad(s, s.bob, () => saveBank(s, s.bob, name));
      expect(r.sent, name).toEqual([]);
      refusedAsReadOnly(r.answer, s.old);
      readOnlyIn(s, s.bob, "withheld");
    }
    s.server.onLogPage = null;
    await s.bob.store.sync();
    writableIn(s, s.bob);
    expect(s.bob.shared.logs.verifiedState(s.old)!.head.seq).toBe(s.at + 1);
    const r = await tryRoad(s, s.bob, () => saveBank(s, s.bob, "bank-3"));
    expect(r.answer).toEqual({ ok: undefined });
    expect(r.sent).toEqual([`push:${s.old}`]);
  });

  it("(d) the same, and the read that then succeeds ends below the record: withheld, as a read that ends below the record leaves it today", async () => {
    const s = await scene();
    await recordedElsewhere(s);
    logReadsFail(s);
    await s.bob.store.sync();
    readOnlyIn(s, s.bob, "withheld");
    s.server.onLogPage = null;
    // The server now serves the log only up to the entry before the record's.
    s.server.logCut.set(s.old, s.at + 1);
    const r = await tryRoad(s, s.bob, () => saveBank(s, s.bob, "bank-1"));
    expect(r.sent).toEqual([]);
    refusedAsReadOnly(r.answer, s.old);
    readOnlyIn(s, s.bob, "withheld");
    expect(s.bob.profile.storage.get(flagKey(s.bob, s.old))).toBe(`withheld:${s.at}`);
  });

  it("(e) a reload with the offline copy after a read that failed, before any read: the vault is listed and read-only; still so after a sync whose read fails; writable after a sync that reads the log", async () => {
    const s = await scene();
    const tab = await otherDevice(s, { cache: true });
    writableIn(s, tab);
    await recordedElsewhere(s);
    logReadsFail(s);
    await tab.store.sync();
    readOnlyIn(s, tab, "withheld");
    const reloaded = await browser(s.server, s.bob.person, s.bob.contacts, { again: tab.profile, cache: await openVaultCache(BOB), sync: false });
    readOnlyIn(s, reloaded, "withheld");
    await reloaded.store.sync();
    readOnlyIn(s, reloaded, "withheld");
    s.server.onLogPage = null;
    await reloaded.store.sync();
    writableIn(s, reloaded);
    expect(namesIn(reloaded, s.old).sort()).toEqual(["bank", "deeds"]);
  });

  it("(f) a record at the verified head, below it on the same chain, or none: the vault is writable as before, and a save is sent", async () => {
    const s = await scene();
    const below = s.bob.shared.logs.hashes(s.old).get(s.at - 1)!;
    const steps: [string, (doc: AccountDocument) => AccountDocument][] = [
      ["a record at the verified head", (doc) => doc],
      ["a record below the verified head on the same chain", (doc) => withRecordReplaced(doc, s.old, { genesisHash: s.genesis, seq: s.at - 1, hash: below })],
      ["no record", (doc) => withRecordReplaced(doc, s.old, null)],
    ];
    for (const [what, change] of steps) {
      await s.bob.shared.accountState.update(change);
      const rec = s.bob.shared.accountState.local().vaults.get(s.old);
      expect(rec?.seq ?? null, what).toBe(what === "no record" ? null : what === "a record at the verified head" ? s.at : s.at - 1);
      writableIn(s, s.bob);
      const r = await tryRoad(s, s.bob, () => saveBank(s, s.bob, `bank: ${what}`));
      expect(r.answer, what).toEqual({ ok: undefined });
      expect(r.sent, what).toEqual([`push:${s.old}`]);
      writableIn(s, s.bob);
    }
  });

  it("(f) a record that names another beginning, above the verified head, does not close the vault in this gate: verified until its log is read, which freezes it at the genesis as before", async () => {
    const s = await scene();
    await s.bob.shared.accountState.update((doc) => withRecordReplaced(doc, s.old, { genesisHash: OTHER_HASH, seq: s.at + 3, hash: OTHER_HASH }));
    writableIn(s, s.bob);
    await s.bob.shared.logs.refresh(s.old, null, null, true);
    expect(s.bob.shared.logs.status(s.old)).toMatchObject({ kind: "frozen", atSeq: 0 });
    expect(s.bob.store.mayWrite(s.old)).toBe(false);
  });

  it("(f) closed by the record alone, the flag empty: reading, copying an item out and leaving stay open", async () => {
    const s = await scene();
    await recordAt(s, s.bob, s.at + 1, OTHER_HASH);
    const st = s.bob.profile.storage;
    expect(st.get(flagKey(s.bob, s.old))).toBeNull();
    readOnlyIn(s, s.bob, "withheld");
    const personal = s.bob.account.personalVaultId;
    const deeds = itemOf(s.bob, "deeds").itemId;
    const copy = await tryRoad(s, s.bob, async () => s.bob.store.runGesture(s.bob.store.newMoveGesture(deeds, personal, false)));
    expect(copy.answer).toMatchObject({ ok: expect.any(Number) });
    expect(copy.sent).toEqual([]);
    expect(s.bob.store.list().filter((i) => i.vaultId === personal && i.doc.name === "deeds")).toHaveLength(1);
    st.remove(flagKey(s.bob, s.old));
    readOnlyIn(s, s.bob, "withheld");
    const leave = await tryRoad(s, s.bob, () => s.bob.store.leaveSharedVault(s.old));
    expect(leave.sent).toContain(`log-leave:${s.old}`);
    expect(leave.sent.filter((w) => w !== `log-leave:${s.old}`)).toEqual([]);
    expect(s.server.grants.get(s.old)!.get(BOB)!.revoked).toBe(true);
  });

  it("(g) honest use: another device made an entry and recorded it; this browser's sync reads the log: verified at the new head and writable at the end of that sync; between the account state's read and the log's read a save is refused with the read-only line", async () => {
    const s = await scene();
    await recordedElsewhere(s);
    const between: boolean[] = [];
    let inBetween: Promise<unknown> | null = null;
    s.server.onLogPage = (v) => {
      if (v !== s.old) return;
      between.push(s.bob.store.mayWrite(s.old));
      // A person's save at this moment of the sync.
      inBetween ??= saveBank(s, s.bob, "bank-in-between").then(
        (v) => ({ ok: v }),
        (e: unknown) => e,
      );
    };
    const before = s.server.writes.length;
    await s.bob.store.sync();
    s.server.onLogPage = null;
    writableIn(s, s.bob);
    expect(s.bob.shared.logs.verifiedState(s.old)!.head.seq).toBe(s.at + 1);
    expect(between.length).toBeGreaterThan(0);
    expect(between.every((w) => !w)).toBe(true);
    refusedAsReadOnly(await inBetween, s.old);
    expect(s.server.writes.slice(before).filter((w) => w === `push:${s.old}`)).toEqual([]);
    const r = await tryRoad(s, s.bob, () => saveBank(s, s.bob, "bank-after"));
    expect(r.answer).toEqual({ ok: undefined });
    expect(r.sent).toEqual([`push:${s.old}`]);
  });

  it("(g) honest use, the log's read failing: a save made in that stretch is refused with the read-only line and is not kept; after the next read that succeeds the vault is writable, the refused save is not sent, and a new save is", async () => {
    const s = await scene();
    await recordedElsewhere(s);
    logReadsFail(s);
    await s.bob.store.sync();
    const r = await tryRoad(s, s.bob, () => saveBank(s, s.bob, "bank-while-failing"));
    refusedAsReadOnly(r.answer, s.old);
    expect(r.sent).toEqual([]);
    s.server.onLogPage = null;
    const after = await tryRoad(s, s.bob, () => s.bob.store.sync());
    expect(after.sent).toEqual([]);
    writableIn(s, s.bob);
    expect(s.bob.store.get(s.bankId)!.doc.name).toBe("bank");
    const again = await tryRoad(s, s.bob, () => saveBank(s, s.bob, "bank-later"));
    expect(again.answer).toEqual({ ok: undefined });
    expect(again.sent).toEqual([`push:${s.old}`]);
  });
});
