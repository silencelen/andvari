// A shared vault that this browser can open but whose history does not let anyone write to it: frozen here (the history
// contradicts itself: closed to changes for good) or withheld (the server serves less of it than this browser verified
// and the account recorded: closed until the history has been read through). Decided for the whole product on
// 23 November 2026: such a vault can be read, and no device writes to it. Driven through the real VaultStore,
// SharedLogSession, VaultLogStore and offline copy against the shared fake server, with the person a member who may
// write, the vault's key held in this browser, and each standing reached as a browser reaches it:
//  - frozen: a member's leave this browser verified is taken out of the server's log and the owner's change is stored
//    at its position (two entries at one position);
//  - withheld: the server serves the log only up to the entry before the one this browser verified.
// Every road that writes an item into the vault, or deletes one of it, sends nothing for the vault (an attachment's
// upload included), a further sync leaves the item on the server as it was, and the call says so. Leaving the vault and
// copying an item out of it stay open.
import "fake-indexeddb/auto";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { AttachmentRef, ItemDoc } from "../api/types";
import { toB64, utf8 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { VaultKeyNotVerifiedError } from "./account";
import { ALICE, BOB, browser, type Browser, contact, FakeSyncServer, freezeByRecord, freshDb, listed, person } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";
import { LogActionError } from "./store";

const CAROL = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

/**
 * The shared fake server, which can also be out of reach for item changes ([pushDown]: a request that never gets an
 * answer), and which serves a person the files of their own personal vault, as the real server does.
 */
class Server extends FakeSyncServer {
  pushDown = false;
  /** A post of a log entry that gets no answer (it may or may not have arrived): the change is held. */
  appendDown = false;
  /** Run once inside the next file download, before its bytes are handed back (a closure while a file is copied). */
  onDownload: (() => Promise<void>) | null = null;
  /** Run once after the server took the next file upload, before its answer is handed back (a closure while it is in the air). */
  onUpload: (() => Promise<void>) | null = null;

  override wireFor(userId: string) {
    const w = super.wireFor(userId);
    const s = this;
    return {
      ...w,
      async pushMutations(mutations: Parameters<typeof w.pushMutations>[0]) {
        if (s.pushDown) throw new TypeError("offline");
        return w.pushMutations(mutations);
      },
      async appendLog(vaultId: string, req: Parameters<typeof w.appendLog>[1]) {
        if (s.appendDown) throw new TypeError("offline");
        return w.appendLog(vaultId, req);
      },
      async uploadAttachment(...args: Parameters<typeof w.uploadAttachment>) {
        const r = await w.uploadAttachment(...args);
        if (s.onUpload !== null) {
          const f = s.onUpload;
          s.onUpload = null;
          await f();
        }
        return r;
      },
      async downloadAttachment(id: string): Promise<Uint8Array> {
        if (s.onDownload !== null) {
          const f = s.onDownload;
          s.onDownload = null;
          await f();
        }
        const a = s.attachments.get(id);
        if (a !== undefined && s.personals.get(a.vaultId) === userId) return a.body.slice();
        return w.downloadAttachment(id);
      },
    };
  }
}

type Standing = "frozen" | "withheld";

const idOf = (who: Browser, name: string): string => who.store.list().find((i) => i.doc.name === name)!.itemId;
const itemOf = (who: Browser, name: string) => who.store.list().find((i) => i.doc.name === name)!;

async function saveWithFile(who: Browser, name: string, vaultId: string): Promise<void> {
  const data = utf8(`the file of ${name}`);
  const ref: AttachmentRef = { id: crypto.randomUUID(), name: "f", size: data.length, fileKey: toB64(randomBytes(32)) };
  await who.store.save(null, { type: "note", name, attachments: [ref] }, [{ id: ref.id, data }], undefined, vaultId);
}

/**
 * Alice owns "Family" with one login, "bank"; bob is a writer who accepted, carol a reader who accepted and then left
 * (bob's browser verified her leave). Bob keeps "deeds" (with a file) in the vault, "scrap" in its trash, and "photo"
 * (with a file) in his personal vault. [cache]: bob's browser keeps the offline copy.
 */
async function scene(opts: { cache?: boolean } = {}) {
  freshDb();
  const server = new Server();
  server.keepsTrash = true;
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
  expect(bob.shared.logs.verifiedState(old)?.head.seq).toBe(at);
  return { server, alice, bob, old, personal, at, scrapId, scrapDoc: scrap!.doc as ItemDoc };
}
type Scene = Awaited<ReturnType<typeof scene>>;

/** The server's side of [s]'s vault turning [standing] for bob (nothing of bob's has read it yet). */
async function closeServer(s: Scene, standing: Standing): Promise<void> {
  if (standing === "frozen") {
    // Carol's leave, which bob verified, is taken out of the log, and alice's change is stored at its position.
    s.server.logs.set(s.old, s.server.logs.get(s.old)!.slice(0, s.at));
    await s.alice.store.setMemberRole(s.old, CAROL, "writer");
  } else {
    // The server serves the log only up to the entry before the one bob's account recorded (it recorded the vault at
    // his adoption, and his browser verified carol's leave after that).
    s.server.logCut.set(s.old, s.at - 1);
  }
}

/** [s]'s vault turned [standing] on bob's browser, read by [reader] (bob's own tab, or another tab of his profile). */
async function close(s: Scene, standing: Standing, reader: Browser = s.bob): Promise<void> {
  await closeServer(s, standing);
  await reader.store.sync();
  expect(s.bob.shared.logs.status(s.old).kind).toBe(standing);
  if (standing === "withheld") expect(s.bob.shared.accountState.local().vaults.get(s.old)!.seq).toBeGreaterThan(s.server.head(s.old).seq);
  // Bob's browser holds the vault's key and shows the vault with its items.
  expect(s.bob.account.logKeyRing().has(s.old)).toBe(true);
  expect(listed(s.bob.store, s.old)).toBe(true);
  expect(s.bob.store.list().filter((i) => i.vaultId === s.old)).toHaveLength(2);
}

/** What [fn] answers, and every write the server was sent by it and by one more sync of bob's (all, and [s]'s vault's). */
async function tryRoad(s: Scene, fn: () => Promise<unknown>): Promise<{ answer: unknown; sent: string[]; all: string[] }> {
  const before = s.server.writes.length;
  const answer = await fn().then(
    (v) => ({ ok: v }),
    (e: unknown) => e,
  );
  await s.bob.store.sync();
  const all = s.server.writes.slice(before);
  return { answer, sent: all.filter((w) => w.endsWith(`:${s.old}`)), all };
}

/** [itemId] as the server holds it (its row, and whether it is deleted), for a comparison before and after. */
const onServer = (s: Scene, itemId: string): string => JSON.stringify(s.server.items.get(itemId) ?? null);

const refused = (answer: unknown, vaultId: string): void => {
  expect(answer).toBeInstanceOf(VaultKeyNotVerifiedError);
  expect((answer as VaultKeyNotVerifiedError).vaultId).toBe(vaultId);
};

describe("a shared vault this browser can read but whose history lets nobody write: no item write leaves the browser", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  for (const standing of ["frozen", "withheld"] as const) {
    describe(`${standing}, its key held here`, () => {
      it(`(a) deleting an item of it sends nothing and is refused`, async () => {
        const s = await scene();
        await close(s, standing);
        const bank = idOf(s.bob, "bank");
        const was = onServer(s, bank);
        const r = await tryRoad(s, () => s.bob.store.remove(bank));
        expect(r.sent).toEqual([]);
        expect(onServer(s, bank)).toBe(was);
        refused(r.answer, s.old);
      });

      it(`(b) "Delete forever" of an item in its trash sends nothing and is refused`, async () => {
        const s = await scene();
        await close(s, standing);
        const was = onServer(s, s.scrapId);
        const r = await tryRoad(s, () => s.bob.store.purgeDeleted(s.scrapId, s.old));
        expect(r.sent).toEqual([]);
        expect(onServer(s, s.scrapId)).toBe(was);
        refused(r.answer, s.old);
      });

      it(`(c) a change of an item with a new file attached uploads nothing and is refused`, async () => {
        const s = await scene();
        await close(s, standing);
        const bank = itemOf(s.bob, "bank");
        const was = onServer(s, bank.itemId);
        const files = s.server.attachments.size;
        const data = utf8("a new file");
        const ref: AttachmentRef = { id: crypto.randomUUID(), name: "f", size: data.length, fileKey: toB64(randomBytes(32)) };
        const r = await tryRoad(s, () => s.bob.store.save(bank.itemId, { ...bank.doc, attachments: [ref] }, [{ id: ref.id, data }], undefined, s.old));
        expect(r.sent).toEqual([]);
        expect(s.server.attachments.size).toBe(files);
        expect(onServer(s, bank.itemId)).toBe(was);
        refused(r.answer, s.old);
      });

      it(`(d) moving an item with a file into it from the personal vault uploads nothing and is refused`, async () => {
        const s = await scene();
        const photo = idOf(s.bob, "photo");
        // The move was asked for while the vault could be written (a screen kept the gesture).
        const g = s.bob.store.newMoveGesture(photo, s.old, true);
        await close(s, standing);
        const was = onServer(s, photo);
        const files = s.server.attachments.size;
        const r = await tryRoad(s, () => s.bob.store.runGesture(g));
        expect(r.sent).toEqual([]);
        expect(s.server.attachments.size).toBe(files);
        expect(onServer(s, photo)).toBe(was);
        expect(s.server.items.has(g.newItemId)).toBe(false);
        refused(r.answer, s.old);
      });

      it(`(e) moving an item out of it to the personal vault is refused before its copy is sent`, async () => {
        const s = await scene();
        const bank = idOf(s.bob, "bank");
        const g = s.bob.store.newMoveGesture(bank, s.personal, true);
        await close(s, standing);
        const was = onServer(s, bank);
        const r = await tryRoad(s, () => s.bob.store.runGesture(g));
        expect(r.sent).toEqual([]);
        // Nothing at all: a copy without its source's deletion would leave the item twice.
        expect(r.all).toEqual([]);
        expect(s.server.items.has(g.newItemId)).toBe(false);
        expect(onServer(s, bank)).toBe(was);
        refused(r.answer, s.old);
      });

      it(`(e2) moving an item with a file out of it, the vault turning ${standing} while the file is copied: nothing is sent after the closure, no copy is made, and the move is refused`, async () => {
        const s = await scene();
        const deeds = itemOf(s.bob, "deeds");
        const was = onServer(s, deeds.itemId);
        const g = s.bob.store.newMoveGesture(deeds.itemId, s.personal, true);
        // Another tab of bob's profile reads the log and finds it closed while this tab downloads the source's file.
        const tab = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile, sync: false });
        const closing: string[] = [];
        let closed = false;
        s.server.onDownload = async () => {
          const at = s.server.writes.length;
          await closeServer(s, standing);
          await tab.store.sync();
          closing.push(...s.server.writes.slice(at));
          closed = true;
        };
        const r = await tryRoad(s, () => s.bob.store.runGesture(g));
        expect(closed).toBe(true);
        expect(s.bob.shared.logs.status(s.old).kind).toBe(standing);
        // What the closure itself wrote: in the frozen standing, the other member's contradicting entry; else nothing.
        expect(closing).toEqual(standing === "frozen" ? [`log-role:${s.old}`] : []);
        // Nothing else reached the server, for either vault: no file uploaded, no copy pushed, no deletion.
        expect(r.all.filter((w) => !closing.includes(w))).toEqual([]);
        expect(s.server.items.has(g.newItemId)).toBe(false);
        expect(s.bob.store.list().filter((i) => i.vaultId === s.personal && i.doc.name === "deeds")).toHaveLength(0);
        expect(onServer(s, deeds.itemId)).toBe(was);
        expect(s.bob.store.list().filter((i) => i.vaultId === s.old && i.doc.name === "deeds")).toHaveLength(1);
        refused(r.answer, s.old);
      });

      it(`(e3) moving an item with a file out of it, the vault turning ${standing} while the file's upload into the personal vault is in the air: the copy is not pushed, and the move is refused`, async () => {
        const s = await scene();
        const deeds = itemOf(s.bob, "deeds");
        const was = onServer(s, deeds.itemId);
        const g = s.bob.store.newMoveGesture(deeds.itemId, s.personal, true);
        // Another tab of bob's profile reads the log and finds it closed after the server took the file's upload, before
        // its answer reaches this tab: the download's question has already been answered yes, and the one question left
        // before the copy is pushed is the one that must refuse it.
        const tab = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile, sync: false });
        const closing: string[] = [];
        let closed = false;
        s.server.onUpload = async () => {
          const at = s.server.writes.length;
          await closeServer(s, standing);
          await tab.store.sync();
          closing.push(...s.server.writes.slice(at));
          closed = true;
        };
        const r = await tryRoad(s, () => s.bob.store.runGesture(g));
        expect(closed).toBe(true);
        expect(s.bob.shared.logs.status(s.old).kind).toBe(standing);
        // What the closure itself wrote: in the frozen standing, the other member's contradicting entry; else nothing.
        expect(closing).toEqual(standing === "frozen" ? [`log-role:${s.old}`] : []);
        // The one write besides it is the file's upload the server took before the closure: no copy pushed into the
        // personal vault, nothing sent to the closed vault.
        expect(r.all.filter((w) => !closing.includes(w))).toEqual([`upload:${s.personal}`]);
        expect(s.server.items.has(g.newItemId)).toBe(false);
        expect(s.bob.store.list().filter((i) => i.vaultId === s.personal && i.doc.name === "deeds")).toHaveLength(0);
        expect(onServer(s, deeds.itemId)).toBe(was);
        expect(s.bob.store.list().filter((i) => i.vaultId === s.old && i.doc.name === "deeds")).toHaveLength(1);
        refused(r.answer, s.old);
      });

      it(`(f) a change queued while the vault could be written is not sent while it is ${standing}${standing === "withheld" ? ", and is sent once its history has been read through" : ""}`, async () => {
        const s = await scene({ cache: true });
        // The browser lets a change wait to be sent only where its storage is persistent.
        vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
        const bank = itemOf(s.bob, "bank");
        s.server.pushDown = true;
        await s.bob.store.save(bank.itemId, { ...bank.doc, name: "bank-queued" }, [], undefined, s.old);
        s.server.pushDown = false;
        expect((await (await openVaultCache(BOB)).pending()).map((m) => m.itemId)).toEqual([bank.itemId]);
        // Another tab of bob's reads the log and finds it closed; bob's tab then drains its queue at its next sync.
        const tab = await browser(s.server, s.bob.person, s.bob.contacts, { again: s.bob.profile, sync: false });
        await close(s, standing, tab);
        const was = onServer(s, bank.itemId);
        const r = await tryRoad(s, () => s.bob.store.sync());
        expect(r.sent).toEqual([]);
        expect(onServer(s, bank.itemId)).toBe(was);
        expect(r.answer).toEqual({ ok: undefined });
        // Not dropped: the change still waits in the offline copy.
        expect((await (await openVaultCache(BOB)).pending()).map((m) => m.itemId)).toEqual([bank.itemId]);
        if (standing === "withheld") {
          s.server.logCut.delete(s.old);
          await s.bob.store.sync();
          expect(s.bob.shared.logs.status(s.old).kind).toBe("verified");
          await s.bob.store.sync();
          expect(s.server.writes.filter((w) => w === `push:${s.old}`).length).toBeGreaterThan(0);
          expect(onServer(s, bank.itemId)).not.toBe(was);
          expect((await (await openVaultCache(BOB)).pending())).toEqual([]);
        }
      });

      it(`(g) leaving it stays open: the leave is sent and the server takes it`, async () => {
        const s = await scene();
        await close(s, standing);
        const r = await tryRoad(s, () => s.bob.store.leaveSharedVault(s.old));
        expect(r.sent).toContain(`log-leave:${s.old}`);
        expect(r.sent.filter((w) => w !== `log-leave:${s.old}`)).toEqual([]);
        expect(s.server.grants.get(s.old)!.get(BOB)!.revoked).toBe(true);
      });

      it(`(h) copying an item with a file out of it to the personal vault stays open, the source untouched`, async () => {
        const s = await scene();
        await close(s, standing);
        const deeds = idOf(s.bob, "deeds");
        const was = onServer(s, deeds);
        const g = s.bob.store.newMoveGesture(deeds, s.personal, false);
        const r = await tryRoad(s, () => s.bob.store.runGesture(g));
        expect(r.answer).toMatchObject({ ok: expect.any(Number) });
        expect(r.sent).toEqual([]);
        expect(r.all).toEqual([`upload:${s.personal}`, `push:${s.personal}`]);
        expect(onServer(s, deeds)).toBe(was);
        expect(s.bob.store.list().filter((i) => i.vaultId === s.personal && i.doc.name === "deeds")).toHaveLength(1);
      });

      it(`(h2) "Copy all to Personal" stays open: every item reaches the personal vault, and the vault is sent nothing`, async () => {
        const s = await scene();
        await close(s, standing);
        const was = [...s.server.items.values()].filter((i) => i.vaultId === s.old).map((i) => JSON.stringify(i));
        const r = await tryRoad(s, () => s.bob.store.copyAllToPersonal(s.old, () => {}));
        expect(r.answer).toEqual({ ok: { copied: 2 } });
        expect(r.sent).toEqual([]);
        expect(r.all.filter((w) => !w.endsWith(`:${s.personal}`))).toEqual([]);
        expect([...s.server.items.values()].filter((i) => i.vaultId === s.old).map((i) => JSON.stringify(i))).toEqual(was);
        expect(s.bob.store.list().filter((i) => i.vaultId === s.personal).map((i) => i.doc.name).sort()).toEqual(["bank", "deeds", "photo"]);
        expect(s.bob.store.list().filter((i) => i.vaultId === s.old).map((i) => i.doc.name).sort()).toEqual(["bank", "deeds"]);
      });

      it(`the store's write question, which the screens ask before they offer a write, says no for it and yes for the personal vault; the member's role is still one that may write`, async () => {
        const s = await scene();
        await close(s, standing);
        expect(s.bob.store.mayWrite(s.old)).toBe(false);
        expect(s.bob.store.mayWrite(s.personal)).toBe(true);
        // What the screen's copy-out condition reads: the key works here and the role is not a reader's.
        expect(s.bob.account.mayWrite(s.old)).toBe(true);
        expect(s.bob.account.roleFor(s.old)).toBe("writer");
      });
    });
  }

  it("a verified shared vault and the personal vault are written as before: a delete, a file's upload and a change are sent", async () => {
    const s = await scene();
    expect(s.bob.shared.logs.status(s.old).kind).toBe("verified");
    expect(s.bob.store.mayWrite(s.old)).toBe(true);
    const bank = idOf(s.bob, "bank");
    const del = await tryRoad(s, () => s.bob.store.remove(bank));
    expect(del.sent).toEqual([`push:${s.old}`]);
    expect(s.server.items.get(bank)!.deleted).toBe(true);
    const photo = itemOf(s.bob, "photo");
    const data = utf8("another file");
    const ref: AttachmentRef = { id: crypto.randomUUID(), name: "g", size: data.length, fileKey: toB64(randomBytes(32)) };
    const save = await tryRoad(s, () => s.bob.store.save(photo.itemId, { ...photo.doc, attachments: [...(photo.doc.attachments ?? []), ref] }, [{ id: ref.id, data }], undefined, s.personal));
    expect(save.answer).toEqual({ ok: undefined });
    expect(save.all).toEqual([`upload:${s.personal}`, `push:${s.personal}`]);
  });

  it("withheld, then its log read through: the vault takes item writes again", async () => {
    const s = await scene();
    await close(s, "withheld");
    const bank = idOf(s.bob, "bank");
    await expect(s.bob.store.remove(bank)).rejects.toBeInstanceOf(VaultKeyNotVerifiedError);
    s.server.logCut.delete(s.old);
    await s.bob.store.sync();
    expect(s.bob.shared.logs.status(s.old).kind).toBe("verified");
    expect(s.bob.store.mayWrite(s.old)).toBe(true);
    const r = await tryRoad(s, () => s.bob.store.remove(bank));
    expect(r.answer).toEqual({ ok: undefined });
    expect(r.sent).toEqual([`push:${s.old}`]);
    expect(s.server.items.get(bank)!.deleted).toBe(true);
  });

  // A change of the vault's history (its log) that was signed while the vault could be written and whose answer was
  // lost waits in the browser and is sent again later. A withheld vault takes no change of its history either, a leave
  // excepted (decided on 24 November 2026); a frozen one never takes one.
  describe("a held change of its history", () => {
    /** Alice's change of bob's role, signed while the vault is verified, whose answer was lost: held in her browser. */
    async function heldRoleChange(s: Scene): Promise<void> {
      await s.alice.store.sync();
      s.server.appendDown = true;
      await s.alice.store.setMemberRole(s.old, BOB, "reader").then(
        () => {},
        () => {},
      );
      s.server.appendDown = false;
      expect(s.alice.store.heldChangeFor(s.old)).not.toBeNull();
      expect(s.server.grants.get(s.old)!.get(BOB)!.role).toBe("writer");
    }
    const logWrites = (s: Scene, from: number): string[] => s.server.writes.slice(from).filter((w) => w.startsWith("log-") && w.endsWith(`:${s.old}`));

    it("withheld in a session that holds its key: a held change of its members is not sent again and stays held; once its history has been read through it is sent", async () => {
      const s = await scene();
      await heldRoleChange(s);
      s.server.logCut.set(s.old, s.at - 1);
      await s.alice.store.sync();
      expect(s.alice.shared.logs.status(s.old).kind).toBe("withheld");
      expect(s.alice.account.logKeyRing().has(s.old)).toBe(true);
      const before = s.server.writes.length;
      await s.alice.store.resendHeldChanges();
      expect(s.server.writes.slice(before)).toEqual([]);
      expect(s.alice.store.heldChangeFor(s.old)).not.toBeNull();
      expect(s.server.grants.get(s.old)!.get(BOB)!.role).toBe("writer");
      // The history read through: the vault is verified again, and the pull's re-send of what the gate held sends it.
      s.server.logCut.delete(s.old);
      const through = s.server.writes.length;
      await s.alice.store.sync();
      expect(s.alice.shared.logs.status(s.old).kind).toBe("verified");
      expect(logWrites(s, through)).toEqual([`log-role:${s.old}`]);
      expect(s.server.grants.get(s.old)!.get(BOB)!.role).toBe("reader");
      await s.alice.store.sync();
      expect(s.alice.store.heldChangeFor(s.old)).toBeNull();
      expect(logWrites(s, through)).toEqual([`log-role:${s.old}`]);
    });

    it("verified: a held change of its members is sent again, as before", async () => {
      const s = await scene();
      await heldRoleChange(s);
      const before = s.server.writes.length;
      await s.alice.store.resendHeldChanges();
      expect(logWrites(s, before)).toEqual([`log-role:${s.old}`]);
      expect(s.server.grants.get(s.old)!.get(BOB)!.role).toBe("reader");
      await s.alice.store.sync();
      expect(s.alice.store.heldChangeFor(s.old)).toBeNull();
      expect(logWrites(s, before)).toEqual([`log-role:${s.old}`]);
    });

    it("frozen: a held change of its members is not sent again, as before", async () => {
      const s = await scene();
      await heldRoleChange(s);
      await freezeByRecord(s.alice, s.old);
      const before = s.server.writes.length;
      await s.alice.store.resendHeldChanges();
      await s.alice.store.sync().catch(() => {});
      expect(logWrites(s, before)).toEqual([]);
      expect(s.server.grants.get(s.old)!.get(BOB)!.role).toBe("writer");
    });

    it("withheld: a held leave is sent again, as before", async () => {
      const s = await scene();
      await close(s, "withheld");
      s.server.appendDown = true;
      await s.bob.store.leaveSharedVault(s.old).then(
        () => {},
        () => {},
      );
      s.server.appendDown = false;
      expect(s.bob.store.heldChangeFor(s.old)).toMatchObject({ kind: "leave" });
      const before = s.server.writes.length;
      await s.bob.store.resendHeldChanges();
      expect(logWrites(s, before)).toEqual([`log-leave:${s.old}`]);
      expect(s.server.grants.get(s.old)!.get(BOB)!.revoked).toBe(true);
    });
  });

  describe("frozen: the roads that already stop before anything is sent", () => {
    for (const [what, road, answer] of [
      ["a new item", (s: Scene) => s.bob.store.save(null, { type: "note", name: "new" }, [], undefined, s.old), "key"],
      ["a change of an item without a file", (s: Scene) => s.bob.store.save(idOf(s.bob, "bank"), { ...itemOf(s.bob, "bank").doc, name: "bank2" }, [], undefined, s.old), "key"],
      ["bringing an item back from the trash", (s: Scene) => s.bob.store.restoreDeleted(s.scrapId, s.old, s.scrapDoc), "key"],
      ["renaming the vault", (s: Scene) => s.bob.store.renameVault(s.old, "Renamed"), "key"],
      ["an import into it", (s: Scene) => s.bob.store.importDocs([{ itemId: crypto.randomUUID(), doc: { type: "note", name: "imported" } }], undefined, s.old), "key"],
      ["a change of its members", (s: Scene) => s.bob.store.setMemberRole(s.old, CAROL, "writer"), "log"],
    ] as const) {
      it(`${what}: nothing sent, refused`, async () => {
        const s = await scene();
        await close(s, "frozen");
        const items = [...s.server.items.keys()].map((id) => onServer(s, id));
        const r = await tryRoad(s, () => road(s));
        expect(r.sent).toEqual([]);
        expect([...s.server.items.keys()].map((id) => onServer(s, id))).toEqual(items);
        if (answer === "key") refused(r.answer, s.old);
        else expect((r.answer as LogActionError).outcome).toMatchObject({ kind: "read_only", frozen: "unsent" });
      });
    }
  });
});
