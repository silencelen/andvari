// Two tabs of one browser profile and a shared vault's stored standing: the verified state, the hashes of the verified
// entries and the flag live in the profile's storage, which every tab writes. A tab whose read of the log began before
// another tab stored more never lowers what that tab stored: it joins what it verified with what is stored at the
// moment it writes (decided on 24 November 2026). Driven through the real VaultStore, SharedLogSession and
// VaultLogStore against the shared fake server; a second tab is a second session over the same storage.
import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import { initSodium } from "../crypto/sodium";
import { VaultKeyNotVerifiedError } from "./account";
import { withVaultHead } from "./accountdoc";
import { ALICE, BOB, browser, type Browser, contact, FakeSyncServer, freshDb, listed, person, type Profile } from "./fakesyncserver.testkit";

const CAROL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

/** A read of a vault's log, held until the test lets it go on. */
interface Hold {
  reached: () => void;
  released: Promise<void>;
}

/**
 * The shared fake server, which can hold one read of a vault's log by the session made right after [holdNextSession]
 * is set: that session waits, at its next read of a log page while [hold] is set, until the hold is released; the page
 * is then served as the server holds the log at that moment, with its last entry spoiled where [spoilHeld] is set.
 */
class Server extends FakeSyncServer {
  holdNextSession = false;
  hold: Hold | null = null;
  spoilHeld = false;

  override wireFor(userId: string) {
    const w = super.wireFor(userId);
    const s = this;
    const holds = this.holdNextSession;
    this.holdNextSession = false;
    return {
      ...w,
      async logPage(vaultId: string, after: number | null) {
        const h = holds ? s.hold : null;
        if (h === null) return w.logPage(vaultId, after);
        s.hold = null;
        h.reached();
        await h.released;
        const page = await w.logPage(vaultId, after);
        if (!s.spoilHeld || page.entries.length === 0) return page;
        const last = page.entries[page.entries.length - 1]!;
        const mid = Math.floor(last.length / 2);
        const spoiled = last.slice(0, mid) + (last[mid] === "A" ? "B" : "A") + last.slice(mid + 1);
        return { ...page, entries: [...page.entries.slice(0, -1), spoiled] };
      },
    };
  }
}

const key = (vaultId: string, part: string): string => `andvari.log2.${BOB}.${vaultId}.${part}`;
const PARTS = ["state", "hashes", "flag"] as const;

/** As store.record-above-head.test.ts: alice owns "Family" ("bank"), bob a writer ("deeds"), carol left at seq [at]; bob's record at [at]. */
async function scene() {
  freshDb();
  const server = new Server();
  const a = person(ALICE);
  const b = person(BOB);
  const c = person(CAROL);
  const alice = await browser(server, a, [contact(b, "Bob"), contact(c, "Carol")]);
  const bob = await browser(server, b, [contact(a, "Alice")]);
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
  const hashAt = bob.shared.logs.hashes(old).get(at)!;
  await bob.shared.accountState.update((doc) => withVaultHead(doc, old, verified.genesisHash, at, hashAt));
  expect(bob.store.mayWrite(old)).toBe(true);
  const bankId = bob.store.list().find((i) => i.doc.name === "bank")!.itemId;
  return { server, alice, bob, old, at, hashAt, genesis: verified.genesisHash, bankId };
}
type Scene = Awaited<ReturnType<typeof scene>>;

/** Another browser of alice's, with a profile of its own: it verified the log as it stands when this is called. */
function aliceElsewhere(s: Scene): Promise<Browser> {
  const profile: Profile = { storage: memoryStorage(), personalVaultId: s.alice.profile.personalVaultId, personalVk: s.alice.profile.personalVk.slice() };
  return browser(s.server, s.alice.person, s.alice.contacts, { again: profile });
}

/** An offer of the vault to bob, signed by [who] over the log as [who]'s browser verified it (nothing is read first). */
async function offerToBob(s: Scene, who: Browser): Promise<void> {
  expect((await who.shared.logs.append(s.old, { kind: "offer", to: BOB, expiresInMs: 60 * 60 * 1000 })).kind).toBe("appended");
}

/** A save of "bank" in [who]'s session: what it answered, and every write to [s]'s vault it and one more sync sent. */
async function saveBank(s: Scene, who: Browser, name: string): Promise<{ answer: string; sent: string[] }> {
  const before = s.server.writes.length;
  const bank = who.store.get(s.bankId)!;
  const answer = await who.store.save(bank.itemId, { ...bank.doc, name }, [], undefined, s.old).then(
    () => "ok",
    (e: unknown) => (e instanceof VaultKeyNotVerifiedError ? "refused:read_only" : `threw:${(e as Error)?.message}`),
  );
  await who.store.sync().catch(() => undefined);
  return { answer, sent: s.server.writes.slice(before).filter((w) => w.endsWith(`:${s.old}`)) };
}

const standing = (s: Scene, who: Browser) => {
  const st = who.shared.logs.status(s.old);
  return {
    status: st.kind,
    head: who.shared.logs.verifiedState(s.old)?.head.seq ?? null,
    mayWrite: who.store.mayWrite(s.old),
    writeAllowed: who.shared.logs.writeAllowed(s.old),
    listed: listed(who.store, s.old),
  };
};

/** The three keys of [s]'s vault's standing, as stored now. */
const storedStanding = (s: Scene): (string | null)[] => PARTS.map((p) => s.bob.profile.storage.get(key(s.old, p)));

/** Puts [texts] (as {@link storedStanding} took them) back into the profile's storage. */
function putStanding(s: Scene, texts: readonly (string | null)[]): void {
  PARTS.forEach((p, i) => {
    const t = texts[i]!;
    if (t === null) s.bob.profile.storage.remove(key(s.old, p));
    else s.bob.profile.storage.set(key(s.old, p), t);
  });
}

/**
 * A second tab of bob's over the same storage, which runs [onOfferSeen] once, as a task of its own, while its read of
 * the log waits on the step that follows a verified offer (the step forgets an earlier refusal of an offer).
 */
async function tabWithHook(s: Scene): Promise<{ tab: Browser; arm: (f: () => void) => void; fired: () => boolean }> {
  const st = s.bob.profile.storage;
  let hook: (() => void) | null = null;
  let fired = false;
  const storage: Profile["storage"] = {
    map: st.map,
    get: (k) => st.get(k),
    set: (k, v) => st.set(k, v),
    remove: (k) => {
      st.remove(k);
      const f = hook;
      if (f !== null && k === key(s.old, "offerRefused")) {
        hook = null;
        fired = true;
        queueMicrotask(f);
      }
    },
  };
  const tab = await browser(s.server, s.bob.person, s.bob.contacts, { again: { ...s.bob.profile, storage } });
  return { tab, arm: (f) => (hook = f), fired: () => fired };
}

describe("two tabs of one profile: a tab's read of a shared vault's log never lowers the standing another tab stored", () => {
  beforeAll(async () => {
    await initSodium();
  });

  for (const ending of ["verified to the head it was served", "ending in an entry that does not verify"] as const) {
    it(`a second tab whose read began before the first tab verified two entries and then found the log served one short, ${ending}: the first tab stays read-only at the head it verified, with that entry's hash, and a save sends nothing`, async () => {
      const s = await scene();
      const st = s.bob.profile.storage;
      // The account's record of the vault was written a moment ago: the next write of it is batched.
      st.set(key(s.old, "recordAt"), String(Date.now()));
      s.server.holdNextSession = true;
      const tabB = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile });
      expect(s.server.holdNextSession).toBe(false);
      await s.alice.store.addVaultMember(s.old, CAROL, "reader");
      await s.alice.store.setMemberRole(s.old, CAROL, "writer");
      expect(s.server.head(s.old).seq).toBe(s.at + 2);
      let reached!: () => void;
      let release!: () => void;
      const atGate = new Promise<void>((r) => (reached = r));
      s.server.hold = { reached, released: new Promise<void>((r) => (release = r)) };
      s.server.spoilHeld = ending !== "verified to the head it was served";
      const readB = tabB.shared.logs.refresh(s.old, null, null, true);
      await atGate;
      await s.bob.shared.logs.refresh(s.old, null, null, true);
      expect(standing(s, s.bob)).toMatchObject({ status: "verified", head: s.at + 2, mayWrite: true, writeAllowed: true });
      const hashTop = s.bob.shared.logs.hashes(s.old).get(s.at + 2)!;
      // From now on the server serves one entry less (it withholds the newest, or was put back from a backup).
      s.server.logCut.set(s.old, s.at + 2);
      await s.bob.shared.logs.refresh(s.old, null, null, true);
      expect(standing(s, s.bob)).toMatchObject({ status: "withheld", head: s.at + 2, mayWrite: false });
      release();
      await readB;
      for (const tab of [s.bob, tabB]) {
        const x = standing(s, tab);
        expect(x.status).toBe(ending === "verified to the head it was served" ? "withheld" : "failed");
        expect(x).toMatchObject({ head: s.at + 2, mayWrite: false, writeAllowed: false, listed: true });
        expect(tab.shared.logs.hashes(s.old).get(s.at + 2)).toBe(hashTop);
      }
      const r = await saveBank(s, s.bob, "bank-after-the-short-read");
      expect(r).toEqual({ answer: "refused:read_only", sent: [] });
      expect(standing(s, s.bob)).toMatchObject({ status: "withheld", head: s.at + 2, mayWrite: false });
      expect(s.bob.shared.logs.hashes(s.old).get(s.at + 2)).toBe(hashTop);
    });
  }

  it("the first tab stores its higher standing while the second tab's read waits on a step after the fetch (the step after a verified entry): the second tab's read leaves it withheld at the higher head, and a save sends nothing", async () => {
    const s = await scene();
    const st = s.bob.profile.storage;
    st.set(key(s.old, "recordAt"), String(Date.now()));
    const { tab: tabB, arm, fired } = await tabWithHook(s);
    const before = storedStanding(s);
    // Alice offers the vault to bob, takes the offer back, and adds carol again: three entries.
    await offerToBob(s, s.alice);
    expect((await s.alice.shared.logs.append(s.old, { kind: "cancel" })).kind).toBe("appended");
    await s.alice.store.addVaultMember(s.old, CAROL, "reader");
    expect(s.server.head(s.old).seq).toBe(s.at + 3);
    // The first tab reads all three, and then finds the log served one short.
    await s.bob.shared.logs.refresh(s.old, null, null, true);
    expect(standing(s, s.bob)).toMatchObject({ status: "verified", head: s.at + 3, mayWrite: true, writeAllowed: true });
    const hashTop = s.bob.shared.logs.hashes(s.old).get(s.at + 3)!;
    s.server.logCut.set(s.old, s.at + 3);
    await s.bob.shared.logs.refresh(s.old, null, null, true);
    expect(standing(s, s.bob)).toMatchObject({ status: "withheld", head: s.at + 3 });
    // The second tab's read is made from what was stored before the first tab's two reads; the first tab's standing
    // lands while it waits on the step after the offer, before it verifies the cancel.
    const first = storedStanding(s);
    putStanding(s, before);
    arm(() => putStanding(s, first));
    await tabB.shared.logs.refresh(s.old, null, null, true);
    expect(fired()).toBe(true);
    for (const tab of [s.bob, tabB]) {
      expect(standing(s, tab)).toMatchObject({ status: "withheld", head: s.at + 3, mayWrite: false, writeAllowed: false, listed: true });
      expect(tab.shared.logs.hashes(s.old).get(s.at + 3)).toBe(hashTop);
    }
    expect(await saveBank(s, s.bob, "bank-after-the-short-read")).toEqual({ answer: "refused:read_only", sent: [] });
    expect(standing(s, s.bob)).toMatchObject({ status: "withheld", head: s.at + 3 });
  });

  it("two tabs verified two different entries at one place, the second tab's read finding the first tab's entry stored before it reaches that place: frozen there in both tabs, and a save sends nothing", async () => {
    const s = await scene();
    const elsewhere = await aliceElsewhere(s);
    s.server.holdNextSession = true;
    const tabB = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile });
    // Alice adds carol again at at+1, and the first tab verifies that entry while the second tab's read waits.
    await s.alice.store.addVaultMember(s.old, CAROL, "reader");
    let reached!: () => void;
    let release!: () => void;
    const atGate = new Promise<void>((r) => (reached = r));
    s.server.hold = { reached, released: new Promise<void>((r) => (release = r)) };
    const readB = tabB.shared.logs.refresh(s.old, null, null, true);
    await atGate;
    await s.bob.shared.logs.refresh(s.old, null, null, true);
    expect(standing(s, s.bob)).toMatchObject({ status: "verified", head: s.at + 1, mayWrite: true, writeAllowed: true });
    const first = s.bob.shared.logs.hashes(s.old).get(s.at + 1)!;
    // The server forgets that entry, and alice's other browser signs another one at at+1 (an offer to bob).
    s.server.logs.get(s.old)!.pop();
    await offerToBob(s, elsewhere);
    expect(s.server.head(s.old).seq).toBe(s.at + 1);
    expect(s.server.head(s.old).hash).not.toBe(first);
    release();
    await readB;
    for (const tab of [s.bob, tabB]) {
      expect(tab.shared.logs.status(s.old)).toMatchObject({ kind: "frozen", atSeq: s.at + 1 });
      // Found as a fork while the entry was verified: the state is left at the entry before it, with the frozen flag.
      expect(standing(s, tab)).toMatchObject({ head: s.at, mayWrite: false, writeAllowed: false, listed: true });
      expect(tab.shared.logs.hashes(s.old).get(s.at + 1)).toBe(first);
    }
    expect(await saveBank(s, s.bob, "bank-after-the-fork")).toEqual({ answer: "refused:read_only", sent: [] });
    expect(s.bob.shared.logs.status(s.old)).toMatchObject({ kind: "frozen", atSeq: s.at + 1 });
  });

  it("two tabs verified two different entries at one place, the first tab's entry stored only after the second tab verified its own there: frozen there in both tabs, what the first tab stored is kept, and a save sends nothing", async () => {
    const s = await scene();
    const elsewhere = await aliceElsewhere(s);
    const { tab: tabB, arm, fired } = await tabWithHook(s);
    const before = storedStanding(s);
    await s.alice.store.addVaultMember(s.old, CAROL, "reader");
    await s.bob.shared.logs.refresh(s.old, null, null, true);
    expect(standing(s, s.bob)).toMatchObject({ status: "verified", head: s.at + 1, mayWrite: true, writeAllowed: true });
    const first = s.bob.shared.logs.hashes(s.old).get(s.at + 1)!;
    const stored = storedStanding(s);
    putStanding(s, before);
    // The server forgets that entry, and alice's other browser signs an offer to bob at at+1.
    s.server.logs.get(s.old)!.pop();
    await offerToBob(s, elsewhere);
    // The second tab verifies the offer; the first tab's standing lands while it waits on the step after it.
    arm(() => putStanding(s, stored));
    // The account's record of the vault is due for a write: a read that froze writes none.
    s.bob.profile.storage.set(key(s.old, "recordAt"), "0");
    await tabB.shared.logs.refresh(s.old, null, null, true);
    expect(fired()).toBe(true);
    for (const tab of [s.bob, tabB]) {
      expect(tab.shared.logs.status(s.old)).toMatchObject({ kind: "frozen", atSeq: s.at + 1 });
      expect(standing(s, tab)).toMatchObject({ head: s.at + 1, mayWrite: false, writeAllowed: false, listed: true });
      expect(tab.shared.logs.hashes(s.old).get(s.at + 1)).toBe(first);
      expect(tab.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.at, hash: s.hashAt });
    }
    expect(await saveBank(s, s.bob, "bank-after-the-fork")).toEqual({ answer: "refused:read_only", sent: [] });
    expect(s.bob.shared.logs.status(s.old)).toMatchObject({ kind: "frozen", atSeq: s.at + 1 });
  });

  it("honest use: two tabs and one honest server, entries arriving while both read: both end verified at the newest head and writable, and nothing is frozen or withheld on the way", async () => {
    const s = await scene();
    const st = s.bob.profile.storage;
    const flags: (string | null)[] = [];
    s.server.holdNextSession = true;
    const tabB = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile });
    let reached!: () => void;
    let release!: () => void;
    const atGate = new Promise<void>((r) => (reached = r));
    s.server.hold = { reached, released: new Promise<void>((r) => (release = r)) };
    const readB = tabB.shared.logs.refresh(s.old, null, null, true);
    await atGate;
    await s.alice.store.addVaultMember(s.old, CAROL, "reader");
    await s.bob.shared.logs.refresh(s.old, null, null, true);
    flags.push(st.get(key(s.old, "flag")));
    expect(standing(s, s.bob)).toMatchObject({ status: "verified", head: s.at + 1, mayWrite: true });
    await s.alice.store.setMemberRole(s.old, CAROL, "writer");
    release();
    await readB;
    flags.push(st.get(key(s.old, "flag")));
    for (const tab of [s.bob, tabB]) expect(standing(s, tab)).toMatchObject({ status: "verified", head: s.at + 2, mayWrite: true, writeAllowed: true });
    // Both tabs' syncs, and one more entry read by the first tab while the second tab syncs.
    await s.bob.store.sync();
    flags.push(st.get(key(s.old, "flag")));
    await s.alice.store.setMemberRole(s.old, CAROL, "reader");
    await Promise.all([s.bob.store.sync(), tabB.store.sync()]);
    flags.push(st.get(key(s.old, "flag")));
    for (const tab of [s.bob, tabB]) expect(standing(s, tab)).toMatchObject({ status: "verified", head: s.at + 3, mayWrite: true, writeAllowed: true });
    expect(flags).toEqual([null, null, null, null]);
    const a = await saveBank(s, s.bob, "bank-from-tab-a");
    expect(a.answer).toBe("ok");
    expect(a.sent).toContain(`push:${s.old}`);
    const b = await saveBank(s, tabB, "bank-from-tab-b");
    expect(b.answer).toBe("ok");
    expect(b.sent).toContain(`push:${s.old}`);
    for (const tab of [s.bob, tabB]) expect(standing(s, tab)).toMatchObject({ status: "verified", head: s.at + 3, mayWrite: true });
  });
});
