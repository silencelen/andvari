// What the web app does today with a shared vault after its server is put back from a backup, on two courses. These
// cases describe the client as it is now, not a rule of the product: they pin today's behaviour so that a change of it
// is seen, and they say nothing about whether that behaviour is wanted.
//
// The scene: alice owns "Family" with "bank"; bob is a writer who accepted and keeps "deeds" there. The server is backed
// up; alice then adds carol and makes her a writer, bob's browser verifies both entries and his account records the
// vault at the second. The server is put back from the backup, which loses those two entries and that record. A browser
// of alice's that never saw them (another device of hers) writes on. Driven through the real VaultStore,
// SharedLogSession, VaultLogStore and offline copy against the shared fake server.
import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import { initSodium } from "../crypto/sodium";
import { withRecovery, withVaultHead } from "./accountdoc";
import { ALICE, BOB, browser, type Browser, contact, FakeSyncServer, freshDb, listed, namesIn, person, type Profile } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

const CAROL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

const newProfile = (who: Browser): Profile => ({ storage: memoryStorage(), personalVaultId: who.profile.personalVaultId, personalVk: who.profile.personalVk.slice() });

/** Everything the fake server stores, copied: what a backup of it holds. */
function backup(server: FakeSyncServer) {
  return structuredClone({
    rev: server.rev,
    logs: server.logs,
    metas: server.metas,
    grants: server.grants,
    items: server.items,
    attachments: server.attachments,
    states: server.states,
    pushed: server.pushed,
    versions: server.versions,
  });
}

/** The server put back from [b]: everything it stores is as the backup holds it. */
function restore(server: FakeSyncServer, b: ReturnType<typeof backup>): void {
  const c = structuredClone(b);
  server.rev = c.rev;
  server.logs = c.logs;
  server.metas = c.metas;
  server.grants = c.grants;
  server.items = c.items;
  server.attachments = c.attachments;
  server.states = c.states;
  server.pushed = c.pushed;
  server.versions = c.versions;
}

/**
 * The scene above, up to the restore and alice's other device. [lostAt]: the restored log's head; [verifiedAt]: bob's
 * verified head, which the restore lost ([lostAt] + 2); [lostHash]: bob's hash at it, which his account recorded.
 */
async function restored(opts: { cache: boolean }) {
  freshDb();
  const server = new FakeSyncServer();
  const a = person(ALICE);
  const b = person(BOB);
  const c = person(CAROL);
  const alice = await browser(server, a, [contact(b, "Bob"), contact(c, "Carol")]);
  const bob = await browser(server, b, [contact(a, "Alice")], { cache: opts.cache ? await openVaultCache(BOB) : undefined });
  const old = await alice.store.createSharedVault("Family");
  await alice.store.addVaultMember(old, BOB, "writer");
  await alice.store.save(null, { type: "login", name: "bank", login: { username: "a", password: "pw1" } }, [], undefined, old);
  await bob.store.sync();
  expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  await bob.store.sync();
  await bob.store.save(null, { type: "note", name: "deeds", notes: "d" }, [], undefined, old);
  await bob.store.sync();
  const lostAt = server.head(old).seq;
  expect(bob.shared.logs.verifiedState(old)!.head.seq).toBe(lostAt);
  const saved = backup(server);
  // The entries the restore loses: bob's browser verifies them, and his account records the vault at the second.
  await alice.store.addVaultMember(old, CAROL, "reader");
  await alice.store.setMemberRole(old, CAROL, "writer");
  await bob.store.sync();
  const verifiedAt = lostAt + 2;
  expect(bob.shared.logs.verifiedState(old)!.head.seq).toBe(verifiedAt);
  const genesis = bob.shared.logs.verifiedState(old)!.genesisHash;
  const lostHash = bob.shared.logs.hashes(old).get(verifiedAt)!;
  await bob.shared.accountState.update((doc) => withVaultHead(doc, old, genesis, verifiedAt, lostHash));
  expect(bob.shared.accountState.local().vaults.get(old)).toMatchObject({ seq: verifiedAt, hash: lostHash });
  expect(bob.store.mayWrite(old)).toBe(true);
  restore(server, saved);
  expect(server.head(old).seq).toBe(lostAt);
  // Another device of alice's, which never saw the lost entries: it opens the restored log as the owner.
  const alice2 = await browser(server, a, alice.contacts, { again: newProfile(alice) });
  expect(alice2.shared.logs.status(old).kind).toBe("verified");
  expect(alice2.shared.logs.verifiedState(old)!.head.seq).toBe(lostAt);
  return { server, alice2, bob, old, lostAt, verifiedAt, lostHash, genesis };
}

describe("a shared vault after its server is put back from a backup, as the web app does it today", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the restored log grows past the lost entries before this browser syncs again: the sync's read fails, and at a reload from the offline copy the vault is not opened", async () => {
    const s = await restored({ cache: true });
    // Three entries on the restored log: its head passes bob's verified head before his browser reads it.
    await s.alice2.store.addVaultMember(s.old, CAROL, "reader");
    await s.alice2.store.setMemberRole(s.old, CAROL, "writer");
    await s.alice2.store.setMemberRole(s.old, CAROL, "reader");
    expect(s.server.head(s.old).seq).toBe(s.verifiedAt + 1);
    await s.bob.store.sync();
    expect(s.bob.shared.logs.status(s.old)).toMatchObject({ kind: "failed", verdict: "bad_prev" });
    expect(s.bob.store.mayWrite(s.old)).toBe(false);
    expect(listed(s.bob.store, s.old)).toBe(true);
    expect(namesIn(s.bob, s.old).sort()).toEqual(["bank", "deeds"]);
    // A reload from the offline copy, before its first sync and after it.
    const reloaded = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile, cache: await openVaultCache(BOB), sync: false });
    expect(reloaded.shared.logs.status(s.old)).toMatchObject({ kind: "failed", verdict: "bad_prev" });
    expect(listed(reloaded.store, s.old)).toBe(false);
    expect(namesIn(reloaded, s.old)).toEqual([]);
    await reloaded.store.sync();
    expect(reloaded.shared.logs.status(s.old)).toMatchObject({ kind: "failed", verdict: "bad_prev" });
    expect(listed(reloaded.store, s.old)).toBe(false);
    expect(namesIn(reloaded, s.old)).toEqual([]);
  });

  it("a browser whose verified log on the restored chain has passed the place of the account's record when that record reaches it: the record is replaced by this browser's head, the vault stays writable, and a save is sent", async () => {
    const s = await restored({ cache: false });
    // A new sign-in of bob's after the restore: it reads the backup's account state and verifies the restored log.
    const fresh = await browser(s.server, s.bob.person, s.bob.contacts, { again: newProfile(s.bob) });
    expect(fresh.shared.logs.status(s.old).kind).toBe("verified");
    expect(fresh.store.mayWrite(s.old)).toBe(true);
    // Alice writes on; the new sign-in verifies past the record's place, its own record of the vault lagging behind:
    // it wrote one at the first entry, and its record writes are batched (at most one every ten minutes).
    await s.alice2.store.addVaultMember(s.old, CAROL, "reader");
    await fresh.store.sync();
    expect(fresh.shared.accountState.local().vaults.get(s.old)!.seq).toBe(s.lostAt + 1);
    await s.alice2.store.setMemberRole(s.old, CAROL, "writer");
    await s.alice2.store.setMemberRole(s.old, CAROL, "reader");
    await fresh.store.sync();
    const head = fresh.shared.logs.verifiedState(s.old)!.head.seq;
    expect(head).toBe(s.verifiedAt + 1);
    expect(fresh.shared.logs.hashes(s.old).get(s.verifiedAt)).not.toBe(s.lostHash);
    expect(fresh.shared.accountState.local().vaults.get(s.old)!.seq).toBeLessThan(s.verifiedAt);
    // The older browser, which holds the higher record, writes the account state (any change of it): the merge keeps
    // its higher record, and the server stores it.
    expect((await s.bob.shared.accountState.update((doc) => withRecovery(doc, { posture: "private", fp: "none", at: Date.now() }))).kind).toBe("written");
    await fresh.store.sync();
    // Before: the account's record as it reached the new sign-in.
    expect(fresh.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.verifiedAt, hash: s.lostHash });
    expect(fresh.shared.logs.status(s.old).kind).toBe("verified");
    expect(fresh.store.mayWrite(s.old)).toBe(true);
    const bank = fresh.store.list().find((i) => i.vaultId === s.old && i.doc.name === "bank")!;
    const writes = s.server.writes.length;
    await fresh.store.save(bank.itemId, { ...bank.doc, name: "bank-after" }, [], undefined, s.old);
    await fresh.store.sync();
    expect(s.server.writes.slice(writes)).toEqual([`push:${s.old}`]);
    // The next read of the log that moves on, once the batched record write is due (it last wrote long ago).
    fresh.profile.storage.set(`andvari.log2.${BOB}.${s.old}.recordAt`, "0");
    await s.alice2.store.setMemberRole(s.old, CAROL, "writer");
    await fresh.store.sync();
    const after = fresh.shared.logs.verifiedState(s.old)!.head;
    expect(after.seq).toBe(s.verifiedAt + 2);
    // After: the record is this browser's head, here and on the server, and the vault is writable.
    expect(fresh.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: after.seq, hash: after.hash });
    const third = await browser(s.server, s.bob.person, s.bob.contacts, { again: newProfile(s.bob), sync: false });
    expect(third.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: after.seq, hash: after.hash });
    expect(fresh.shared.logs.status(s.old).kind).toBe("verified");
    expect(fresh.store.mayWrite(s.old)).toBe(true);
  });
});
