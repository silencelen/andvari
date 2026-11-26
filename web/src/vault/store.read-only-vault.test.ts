// A shared vault that the account recorded further than the server now serves, opened in a browser that never held its
// key: the server was put back from a backup, so its log ends below the account's record (withheld), or went on beside
// it (frozen). Decided on 23 November 2026, for every device of the account: such a vault opens read-only where it was
// refused before, no device writes to it, and the account's record is never lowered. A record of another beginning
// gives no key. Driven through the real VaultStore, SharedLogSession, VaultLogStore and offline copy against the shared
// fake server.
import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import type { AttachmentRef, ItemDoc } from "../api/types";
import { memoryStorage } from "../api/devicesecret";
import { toB64, utf8 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { VaultKeyNotVerifiedError } from "./account";
import { withVaultHead } from "./accountdoc";
import { ALICE, BOB, browser, type Browser, contact, FakeSyncServer, freshDb, listed, namesIn, person, type Profile } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

const CAROL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

/** The shared fake server, serving a person the files of their own personal vault, as the real server does. */
class Server extends FakeSyncServer {
  override wireFor(userId: string) {
    const w = super.wireFor(userId);
    const s = this;
    return {
      ...w,
      async downloadAttachment(id: string): Promise<Uint8Array> {
        const a = s.attachments.get(id);
        if (a !== undefined && s.personals.get(a.vaultId) === userId) return a.body.slice();
        return w.downloadAttachment(id);
      },
    };
  }
}

type Standing = "withheld" | "frozen";

const idOf = (who: Browser, name: string): string => who.store.list().find((i) => i.doc.name === name)!.itemId;
const itemOf = (who: Browser, name: string) => who.store.list().find((i) => i.doc.name === name)!;

async function saveWithFile(who: Browser, name: string, vaultId: string): Promise<void> {
  const data = utf8(`the file of ${name}`);
  const ref: AttachmentRef = { id: crypto.randomUUID(), name: "f", size: data.length, fileKey: toB64(randomBytes(32)) };
  await who.store.save(null, { type: "note", name, attachments: [ref] }, [{ id: ref.id, data }], undefined, vaultId);
}

/**
 * Alice owns "Family" with one login, "bank"; bob is a writer who accepted, carol a reader who accepted and then left.
 * Bob keeps "deeds" (with a file) in the vault, "scrap" in its trash and "photo" (with a file) in his personal vault.
 * Bob's browser verified carol's leave (at seq [at]), and the account's record of the vault names that leave.
 */
async function scene() {
  freshDb();
  const server = new Server();
  server.keepsTrash = true;
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
  const personal = bob.account.personalVaultId;
  await saveWithFile(bob, "deeds", old);
  await bob.store.save(null, { type: "note", name: "scrap", notes: "x" }, [], undefined, old);
  const scrapId = idOf(bob, "scrap");
  await bob.store.remove(scrapId);
  await saveWithFile(bob, "photo", personal);
  await bob.store.sync();
  const scrap = (await bob.store.deletedItems()).find((t) => t.itemId === scrapId);
  expect(scrap?.doc).toBeTruthy();
  const at = server.logs.get(old)!.length;
  await carol.store.leaveSharedVault(old);
  await bob.store.sync();
  const verified = bob.shared.logs.verifiedState(old)!;
  expect(verified.head.seq).toBe(at);
  // The account's record follows the verified head (batched): here it is written up to carol's leave.
  await bob.shared.accountState.update((doc) => withVaultHead(doc, old, verified.genesisHash, at, bob.shared.logs.hashes(old).get(at)!));
  expect(bob.shared.accountState.local().vaults.get(old)).toMatchObject({ seq: at });
  return { server, alice, bob, old, personal, at, scrapId, scrapDoc: scrap!.doc as ItemDoc };
}
type Scene = Awaited<ReturnType<typeof scene>>;

/** The server put back from a backup: its log ends below the record (withheld), or went on beside it at the record's place (frozen). */
async function restoreServer(s: Scene, standing: Standing): Promise<void> {
  if (standing === "withheld") {
    s.server.logCut.set(s.old, s.at);
  } else {
    s.server.logs.set(s.old, s.server.logs.get(s.old)!.slice(0, s.at));
    await s.alice.store.setMemberRole(s.old, CAROL, "writer");
    expect(s.server.logs.get(s.old)!.length).toBe(s.at + 1);
  }
}

/** A browser of bob's that never held the vault's key: a new profile, the same account (its state on the server). */
async function freshBob(s: Scene, opts: { cache?: boolean; sync?: boolean } = {}): Promise<Browser> {
  const profile: Profile = { storage: memoryStorage(), personalVaultId: s.bob.profile.personalVaultId, personalVk: s.bob.profile.personalVk.slice() };
  return browser(s.server, s.bob.person, s.bob.contacts, { again: profile, cache: opts.cache === true ? await openVaultCache(BOB) : undefined, sync: opts.sync });
}

/** What [fn] answers, and every write the server was sent by it and by one more sync of [who]'s. */
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

const onServer = (s: Scene, itemId: string): string => JSON.stringify(s.server.items.get(itemId) ?? null);

const refused = (answer: unknown, vaultId: string): void => {
  expect(answer).toBeInstanceOf(VaultKeyNotVerifiedError);
  expect((answer as VaultKeyNotVerifiedError).vaultId).toBe(vaultId);
};

/** [who] opened [s]'s vault read-only: listed with its items, the key held, the log [standing], no write allowed. */
function openReadOnly(s: Scene, who: Browser, standing: Standing): void {
  expect(who.shared.logs.status(s.old).kind).toBe(standing);
  expect(who.account.logKeyRing().has(s.old)).toBe(true);
  expect(listed(who.store, s.old)).toBe(true);
  expect(namesIn(who, s.old).sort()).toEqual(["bank", "deeds"]);
  expect(who.store.mayWrite(s.old)).toBe(false);
  expect(who.shared.logs.writeAllowed(s.old)).toBe(false);
}

describe("a shared vault the account recorded further than the server serves, on a browser that never held its key", () => {
  beforeAll(async () => {
    await initSodium();
  });

  for (const standing of ["withheld", "frozen"] as const) {
    describe(standing === "withheld" ? "the record ahead of the served log (withheld)" : "the record beside the served log (frozen)", () => {
      it("opens read-only: listed with its items, nothing sent for it, the account's record not lowered", async () => {
        const s = await scene();
        await restoreServer(s, standing);
        const writes = s.server.writes.length;
        const fresh = await freshBob(s);
        openReadOnly(s, fresh, standing);
        expect(s.server.writes.slice(writes).filter((w) => w.endsWith(`:${s.old}`))).toEqual([]);
        expect(fresh.shared.accountState.local().vaults.get(s.old)!.seq).toBe(s.at);
      });

      it("after a reload (with and without the offline copy) it is still listed and still read-only, and the record is unchanged", async () => {
        const s = await scene();
        await restoreServer(s, standing);
        const fresh = await freshBob(s);
        openReadOnly(s, fresh, standing);
        const again = await browser(s.server, s.bob.person, s.bob.contacts, { again: fresh.profile });
        openReadOnly(s, again, standing);
        expect(again.shared.accountState.local().vaults.get(s.old)!.seq).toBeGreaterThanOrEqual(s.at);

        // The offline copy: the vault is opened from what this browser holds, before anything is fetched.
        const cached = await freshBob(s, { cache: true });
        openReadOnly(s, cached, standing);
        const reopened = await browser(s.server, s.bob.person, s.bob.contacts, { again: cached.profile, cache: await openVaultCache(BOB), sync: false });
        openReadOnly(s, reopened, standing);
        await reopened.store.sync();
        openReadOnly(s, reopened, standing);
        expect(reopened.shared.accountState.local().vaults.get(s.old)!.seq).toBeGreaterThanOrEqual(s.at);
      });

      it("every item write into it sends nothing and is refused", async () => {
        const s = await scene();
        await restoreServer(s, standing);
        const fresh = await freshBob(s);
        openReadOnly(s, fresh, standing);
        const bank = itemOf(fresh, "bank");
        const photo = idOf(fresh, "photo");
        const roads: [string, () => Promise<unknown>][] = [
          ["delete an item", () => fresh.store.remove(bank.itemId)],
          ['"Delete forever" from its trash', () => fresh.store.purgeDeleted(s.scrapId, s.old)],
          [
            "a change with a new file",
            async () => {
              const data = utf8("a new file");
              const ref: AttachmentRef = { id: crypto.randomUUID(), name: "f", size: data.length, fileKey: toB64(randomBytes(32)) };
              return fresh.store.save(bank.itemId, { ...bank.doc, attachments: [ref] }, [{ id: ref.id, data }], undefined, s.old);
            },
          ],
          ["a change without a file", () => fresh.store.save(bank.itemId, { ...bank.doc, name: "bank2" }, [], undefined, s.old)],
          ["a new item", () => fresh.store.save(null, { type: "note", name: "new" }, [], undefined, s.old)],
          ["a move with a file into it from the personal vault", async () => fresh.store.runGesture(fresh.store.newMoveGesture(photo, s.old, true))],
          ["a move out of it to the personal vault", async () => fresh.store.runGesture(fresh.store.newMoveGesture(bank.itemId, s.personal, true))],
          ["bringing an item back from its trash", () => fresh.store.restoreDeleted(s.scrapId, s.old, s.scrapDoc)],
          ["renaming it", () => fresh.store.renameVault(s.old, "Renamed")],
          ["an import into it", () => fresh.store.importDocs([{ itemId: crypto.randomUUID(), doc: { type: "note", name: "imported" } }], undefined, s.old)],
        ];
        for (const [what, fn] of roads) {
          const items = [...s.server.items.values()].filter((i) => i.vaultId === s.old || i.vaultId === s.personal).map((i) => JSON.stringify(i));
          const files = s.server.attachments.size;
          const r = await tryRoad(s, fresh, fn);
          expect(r.sent, what).toEqual([]);
          expect(r.all, what).toEqual([]);
          expect(s.server.attachments.size, what).toBe(files);
          expect([...s.server.items.values()].filter((i) => i.vaultId === s.old || i.vaultId === s.personal).map((i) => JSON.stringify(i)), what).toEqual(items);
          refused(r.answer, s.old);
        }
        expect(onServer(s, bank.itemId)).toContain(bank.itemId);
        openReadOnly(s, fresh, standing);
      });

      it("leaving it and copying its items out stay open", async () => {
        const s = await scene();
        await restoreServer(s, standing);
        const fresh = await freshBob(s);
        openReadOnly(s, fresh, standing);
        const deeds = idOf(fresh, "deeds");
        const was = onServer(s, deeds);
        const copy = await tryRoad(s, fresh, async () => fresh.store.runGesture(fresh.store.newMoveGesture(deeds, s.personal, false)));
        expect(copy.answer).toMatchObject({ ok: expect.any(Number) });
        expect(copy.sent).toEqual([]);
        expect(copy.all).toEqual([`upload:${s.personal}`, `push:${s.personal}`]);
        expect(onServer(s, deeds)).toBe(was);
        const all = await tryRoad(s, fresh, () => fresh.store.copyAllToPersonal(s.old, () => {}));
        expect(all.answer).toEqual({ ok: { copied: 2 } });
        expect(all.sent).toEqual([]);
        const leave = await tryRoad(s, fresh, () => fresh.store.leaveSharedVault(s.old));
        expect(leave.sent).toContain(`log-leave:${s.old}`);
        expect(leave.sent.filter((w) => w !== `log-leave:${s.old}`)).toEqual([]);
        expect(s.server.grants.get(s.old)!.get(BOB)!.revoked).toBe(true);
      });
    });
  }

  it("withheld: writable again once the log is read through the record's entry with its hash", async () => {
    const s = await scene();
    await restoreServer(s, "withheld");
    const fresh = await freshBob(s);
    openReadOnly(s, fresh, "withheld");
    s.server.logCut.delete(s.old);
    await fresh.store.sync();
    expect(fresh.shared.logs.status(s.old).kind).toBe("verified");
    expect(fresh.store.mayWrite(s.old)).toBe(true);
    const bank = idOf(fresh, "bank");
    const r = await tryRoad(s, fresh, () => fresh.store.remove(bank));
    expect(r.answer).toEqual({ ok: undefined });
    expect(r.sent).toEqual([`push:${s.old}`]);
  });

  it("withheld, then served on with another entry at the record's place: frozen, and never writable again", async () => {
    const s = await scene();
    await restoreServer(s, "withheld");
    const fresh = await freshBob(s);
    openReadOnly(s, fresh, "withheld");
    // The restored log goes on beside the record: alice's change stored where the account recorded carol's leave.
    s.server.logCut.delete(s.old);
    s.server.logs.set(s.old, s.server.logs.get(s.old)!.slice(0, s.at));
    await s.alice.store.setMemberRole(s.old, CAROL, "writer");
    await fresh.store.sync();
    openReadOnly(s, fresh, "frozen");
    await fresh.store.sync();
    openReadOnly(s, fresh, "frozen");
  });

  it("a browser that stands at the served head and learns a record above it reads the log again: withheld, and no longer writable", async () => {
    const s = await scene();
    const verified = s.bob.shared.logs.verifiedState(s.old)!;
    expect(s.bob.store.mayWrite(s.old)).toBe(true);
    // Another device of the account verified one more entry and recorded it; the server was put back to before it.
    await s.bob.shared.accountState.update((doc) => withVaultHead(doc, s.old, verified.genesisHash, s.at + 1, "ab".repeat(32)));
    await s.bob.store.sync();
    expect(s.bob.shared.logs.status(s.old).kind).toBe("withheld");
    expect(s.bob.store.mayWrite(s.old)).toBe(false);
    expect(listed(s.bob.store, s.old)).toBe(true);
    const bank = idOf(s.bob, "bank");
    const r = await tryRoad(s, s.bob, () => s.bob.store.remove(bank));
    expect(r.sent).toEqual([]);
    refused(r.answer, s.old);
    expect(s.bob.shared.accountState.local().vaults.get(s.old)).toMatchObject({ seq: s.at + 1, hash: "ab".repeat(32) });
  });

  it("a record of another beginning gives no key: on a fresh browser, and at a reload of the browser that held the key", async () => {
    const s = await scene();
    await s.bob.shared.accountState.update((doc) => {
      const rec = doc.vaults.get(s.old)!;
      return withVaultHead({ ...doc, vaults: new Map([...doc.vaults].filter(([id]) => id !== s.old)) }, s.old, "ab".repeat(32), rec.seq, rec.hash);
    });
    const fresh = await freshBob(s);
    expect(fresh.account.logKeyRing().has(s.old)).toBe(false);
    expect(listed(fresh.store, s.old)).toBe(false);

    // The browser that held the key reads the record and freezes at the genesis; its session keeps the key it held.
    await s.bob.shared.logs.refresh(s.old, null, null, true);
    expect(s.bob.shared.logs.status(s.old)).toMatchObject({ kind: "frozen", atSeq: 0 });
    expect(s.bob.store.mayWrite(s.old)).toBe(false);
    const again = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile });
    expect(again.shared.logs.status(s.old).kind).toBe("frozen");
    expect(again.account.logKeyRing().has(s.old)).toBe(false);
    expect(listed(again.store, s.old)).toBe(false);
    expect(again.shared.accountState.local().vaults.get(s.old)).toMatchObject({ genesisHash: "ab".repeat(32) });
  });
});
