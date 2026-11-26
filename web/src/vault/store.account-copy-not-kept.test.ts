// A browser whose storage cannot keep the account's sealed copy (a full storage drops a large write without a word,
// while small writes still land): the account's document this session read is what it goes on with, never the older copy
// the storage still holds. Driven through the real VaultStore, SharedLogSession and AccountStateStore against the shared
// fake server.
import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import { initSodium } from "../crypto/sodium";
import { VaultKeyNotVerifiedError } from "./account";
import { withVaultHead } from "./accountdoc";
import { ALICE, BOB, browser, type Browser, contact, FakeSyncServer, freshDb, listed, person, type Profile } from "./fakesyncserver.testkit";

const CAROL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
/** The hash another device of the account recorded at a place the served log does not hold. */
const OTHER_HASH = "ab".repeat(32);
const SEALED = `andvari.as2.${BOB}.sealed`;

/** As store.record-above-head.test.ts: alice owns "Family" ("bank"), bob a writer ("deeds"), carol left at seq [at]; bob's record at [at]. */
async function scene() {
  freshDb();
  const server = new FakeSyncServer();
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
  return { server, alice, bob, old, at, genesis: verified.genesisHash, bankId };
}
type Scene = Awaited<ReturnType<typeof scene>>;

/** A browser of bob's with a profile of its own (another device of the account). */
function otherDevice(s: Scene): Promise<Browser> {
  const profile: Profile = { storage: memoryStorage(), personalVaultId: s.bob.profile.personalVaultId, personalVk: s.bob.profile.personalVk.slice() };
  return browser(s.server, s.bob.person, s.bob.contacts, { again: profile });
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

describe("a browser whose storage cannot keep the account's sealed copy", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the account's record above the served head, learned by a session whose storage drops the account's copy: the vault is read-only there, a save sends nothing, and the session's next write of the account state keeps the record on the server", async () => {
    const s = await scene();
    // Before the record rises, a save of this browser's goes out.
    const first = await saveBank(s, s.bob, "bank-before");
    expect(first.answer).toBe("ok");
    expect(first.sent).toContain(`push:${s.old}`);
    const o = await otherDevice(s);
    // Another device recorded an entry the server no longer serves (a restore): the record is above the served head.
    await o.shared.accountState.update((doc) => withVaultHead(doc, s.old, s.genesis, s.at + 1, OTHER_HASH));
    const st = s.bob.profile.storage;
    const keptBefore = st.get(SEALED);
    const dropping: Profile["storage"] = {
      map: st.map,
      get: (k) => st.get(k),
      remove: (k) => st.remove(k),
      set: (k, v) => {
        if (k === SEALED) return; // the larger write fails, and the storage says nothing
        st.set(k, v);
      },
    };
    const tab = await browser(s.server, s.bob.person, s.bob.contacts, { again: { ...s.bob.profile, storage: dropping } });
    expect(st.get(SEALED)).toBe(keptBefore);
    // What the session reads of the account is the document it read, not the older copy at rest.
    expect(tab.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.at + 1, hash: OTHER_HASH });
    expect(tab.shared.logs.status(s.old).kind).toBe("withheld");
    expect(tab.store.mayWrite(s.old)).toBe(false);
    expect(listed(tab.store, s.old)).toBe(true);
    expect(await saveBank(s, tab, "bank-full-storage")).toEqual({ answer: "refused:read_only", sent: [] });
    // A write of the account's state in this session (a new vault records the person's own answer to it).
    await tab.store.createSharedVault("Another");
    const fresh = await otherDevice(s);
    expect(fresh.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.at + 1, hash: OTHER_HASH });
    expect(fresh.shared.logs.status(s.old).kind).toBe("withheld");
    expect(fresh.store.mayWrite(s.old)).toBe(false);
    // The copy at rest is still the older one; the session goes on with what it wrote.
    expect(st.get(SEALED)).toBe(keptBefore);
    expect(tab.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.at + 1, hash: OTHER_HASH });
  });
});
