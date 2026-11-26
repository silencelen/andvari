// The roads into the read-only adoption of a shared vault whose log is not verified on this browser (decided on
// 23 November 2026), pinned as built: only a withheld or frozen log is let in (a purged or failed one takes no key there), and the
// offline road of a reload from the offline copy tries only this account's own wrap and writes nothing. Driven through
// the real VaultStore, SharedLogSession, VaultLogStore and offline copy against the shared fake server.
import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import { initSodium } from "../crypto/sodium";
import { withVaultHead } from "./accountdoc";
import { BOB, browser, type Browser, family, freshDb, listed, type Profile } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

const flagKey = (vaultId: string): string => `andvari.log2.${BOB}.${vaultId}.flag`;
const recordAtKey = (vaultId: string): string => `andvari.log2.${BOB}.${vaultId}.recordAt`;
const newProfile = (bob: Browser): Profile => ({ storage: memoryStorage(), personalVaultId: bob.profile.personalVaultId, personalVk: bob.profile.personalVk.slice() });
/** Whether [who]'s session holds this account's grant row of [vaultId] (from a pull, or from the offline copy). */
const grantRowKnown = (who: Browser, vaultId: string): boolean => (who.shared as unknown as { rows: ReadonlyMap<string, unknown> }).rows.get(vaultId) !== undefined;

describe("the roads into a shared vault's read-only adoption", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a purged log takes no key on the shared vault's road: the session that does not hold the key gets none, and the vault is not listed", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    // The same road takes the key read-only for a withheld log: a reload from the offline copy, before its first sync,
    // which knows this account's grant row (and its own wrap on it) from the copy.
    bob.profile.storage.set(flagKey(old), `withheld:${bob.shared.logs.verifiedState(old)!.head.seq}`);
    const withheld = await browser(server, bob.person, bob.contacts, { again: bob.profile, cache: await openVaultCache(BOB), sync: false });
    expect(withheld.shared.logs.status(old).kind).toBe("withheld");
    expect(withheld.account.logKeyRing().has(old)).toBe(true);
    // The fake server never serves `purged`: the flag a read of a purged log sets, in the real storage.
    bob.profile.storage.set(flagKey(old), "purged:5");
    // A reload from the offline copy and before its first sync: the grant row is known, and the key ring is empty.
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile, cache: await openVaultCache(BOB), sync: false });
    expect(grantRowKnown(again, old)).toBe(true);
    expect(again.account.logKeyRing().has(old)).toBe(false);
    expect(again.shared.logs.status(old).kind).toBe("purged");
    const writes = server.writes.length;
    expect(await again.shared.onSharedVault(old, null, true)).toBeNull();
    expect(again.account.logKeyRing().has(old)).toBe(false);
    expect(listed(again.store, old)).toBe(false);
    expect(server.writes.slice(writes)).toEqual([]);
  });

  it("a failed log takes no key at a reload from the offline copy, nor on the shared vault's road: the vault is not listed and nothing is sent", async () => {
    freshDb();
    const { server, bob, old } = await family(await openVaultCache(BOB));
    // A reload from the offline copy of a verified log takes the key: the copy's grant row is known.
    const verified = await browser(server, bob.person, bob.contacts, { again: bob.profile, cache: await openVaultCache(BOB), sync: false });
    expect(verified.shared.logs.status(old).kind).toBe("verified");
    expect(verified.account.logKeyRing().has(old)).toBe(true);
    expect(listed(verified.store, old)).toBe(true);
    // The flag a read sets where an entry does not verify, in the real storage.
    bob.profile.storage.set(flagKey(old), "failed:bad_signature");
    const writes = server.writes.length;
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile, cache: await openVaultCache(BOB), sync: false });
    expect(grantRowKnown(again, old)).toBe(true);
    expect(again.shared.logs.status(old).kind).toBe("failed");
    expect(again.account.logKeyRing().has(old)).toBe(false);
    expect(listed(again.store, old)).toBe(false);
    expect(await again.shared.onSharedVault(old, null, true)).toBeNull();
    expect(again.account.logKeyRing().has(old)).toBe(false);
    expect(listed(again.store, old)).toBe(false);
    expect(server.writes.slice(writes)).toEqual([]);
  });

  it("the offline road of a withheld vault writes nothing: the account's record stays where it was although a higher one is due", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    const rec0 = bob.shared.accountState.local().vaults.get(old)!;
    await alice.store.setMemberRole(old, BOB, "reader");
    await bob.store.sync();
    const head = bob.shared.logs.verifiedState(old)!.head.seq;
    expect(head).toBeGreaterThan(rec0.seq);
    // The record behind the verified head (as before its batched write), and the server withholding the newest entry.
    await bob.shared.accountState.update((doc) => ({ ...doc, vaults: new Map([...doc.vaults, [old, rec0]]) }));
    server.logCut.set(old, head);
    await bob.shared.logs.refresh(old, null, null, true);
    expect(bob.shared.logs.status(old).kind).toBe("withheld");
    expect(bob.shared.accountState.local().vaults.get(old)!.seq).toBe(rec0.seq);
    // Due: this browser holds no time of its last write of the record.
    bob.profile.storage.remove(recordAtKey(old));
    const serverState = server.states.get(BOB)!.seq;
    const writes = server.writes.length;
    const again = await browser(server, bob.person, bob.contacts, { again: bob.profile, cache: await openVaultCache(BOB), sync: false });
    expect(again.shared.logs.status(old).kind).toBe("withheld");
    expect(again.account.logKeyRing().has(old)).toBe(true);
    expect(listed(again.store, old)).toBe(true);
    expect(again.store.mayWrite(old)).toBe(false);
    expect(again.shared.accountState.local().vaults.get(old)!.seq).toBe(rec0.seq);
    expect(server.states.get(BOB)!.seq).toBe(serverState);
    expect(server.writes.slice(writes)).toEqual([]);
  });

  it("a key taken read-only through a grant is not tried on the offline road: at a reload from the offline copy the vault is listed after the sync and not before it", async () => {
    freshDb();
    const f = await family();
    await f.alice.store.setMemberRole(f.old, BOB, "reader");
    await f.bob.store.sync();
    const v = f.bob.shared.logs.verifiedState(f.old)!;
    const at = v.head.seq;
    await f.bob.shared.accountState.update((doc) => withVaultHead(doc, f.old, v.genesisHash, at, f.bob.shared.logs.hashes(f.old).get(at)!));
    // The server put back below the record, and with no wrap of bob's own on his row: only the grant gives the key.
    f.server.logCut.set(f.old, at);
    Object.assign(f.server.grants.get(f.old)!.get(BOB)!, { wrappedVk: "", rev: ++f.server.rev });
    const p = newProfile(f.bob);
    const cached = await browser(f.server, f.bob.person, f.bob.contacts, { again: p, cache: await openVaultCache(BOB) });
    expect(cached.shared.logs.status(f.old).kind).toBe("withheld");
    expect(listed(cached.store, f.old)).toBe(true);
    const reopened = await browser(f.server, f.bob.person, f.bob.contacts, { again: p, cache: await openVaultCache(BOB), sync: false });
    expect(reopened.account.logKeyRing().has(f.old)).toBe(false);
    expect(listed(reopened.store, f.old)).toBe(false);
    await reopened.store.sync();
    expect(listed(reopened.store, f.old)).toBe(true);
    expect(reopened.store.mayWrite(f.old)).toBe(false);
  });
});
