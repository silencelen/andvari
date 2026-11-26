// The places where something leaves this browser, each held to a list that is closed in the code: the functions of the
// store that read the set of opened items directly (every other read goes through the guarded read); every public
// function of the store, each a read, a change shown here to send nothing while the vault's key does not work, or exempt
// with its reason; the one function that drops a vault's rows without a held copy, with its closed list of reasons; and
// the one place of the log's appends, which asks the same question with a leave as its exception. A function, a direct
// read or a drop that is in no list fails these tests until its line says why it is allowed.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { ALICE, BOB, browser, family, freshDb, listed, namesIn } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";
import { DROP_REASONS, type UnfinishedMove, type VaultItem } from "./store";

const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "store.ts"), "utf8");

/** The class body of VaultStore, line by line, each with the member (method, getter) it belongs to. */
function membersOfStore(): { name: string; isPublic: boolean; lines: string[] }[] {
  const lines = source.split("\n");
  const start = lines.findIndex((l) => l.startsWith("export class VaultStore"));
  const out: { name: string; isPublic: boolean; lines: string[] }[] = [];
  for (let i = start + 1; i < lines.length && !lines[i]!.startsWith("}"); i++) {
    const l = lines[i]!;
    // A member starts at two spaces: `name(`, `async name(`, `get name(`, `name<`, with or without `private`/`static`.
    const m = /^ {2}(?:(private|protected|static)\s+)*(?:readonly\s+)?(?:async\s+)?(?:get\s+)?([A-Za-z_]\w*)\s*[(<]/.exec(l);
    if (m !== null && m[2] !== "constructor") out.push({ name: m[2]!, isPublic: !/^ {2}(private|protected|static)\b/.test(l), lines: [] });
    else if (/^ {2}constructor\(/.test(l)) out.push({ name: "constructor", isPublic: false, lines: [] });
    out.at(-1)?.lines.push(l);
  }
  return out;
}

const count = (lines: readonly string[], needle: string): number => lines.reduce((n, l) => n + l.split(needle).length - 1, 0);

/**
 * Every function of the store that reads the set of opened items (`itemsById`) directly, how many times, and why. All
 * others read it through the guarded read (`openedItems`, `openedItem`), which shows nothing of a vault whose key does
 * not work. Found by reading store.ts: each `this.itemsById` is counted in the member it stands in.
 */
const DIRECT_READS: Record<string, readonly [number, string]> = {
  openedItems: [1, "the guarded read itself"],
  openedItem: [1, "the guarded read itself, for one item"],
  applyWireItem: [3, "the one writer of served and cached rows into the set"],
  pullOnce: [7, "the removal's rule: the resync's clear, the reinstate's items, what was opened before this answer and putting it back before a held copy is made"],
  chaseItemHeads: [1, "the removal's rule: the heads of the rows this answer applied, read before the rule runs again"],
  openForHeldCopy: [1, "the removal's rule: an item opened with the key taken only to seal the held copy"],
  nothingOpenedSinceRecord: [1, "the removal's rule: whether anything of the vault is opened here at all, whatever its key"],
  itemsHeldBeforeResync: [1, "the removal's rule: everything held before a resync replaces the set, to be set aside"],
  setAsideLeftOut: [1, "the removal's rule: an item still held is not set aside"],
  takeSharedVaults: [1, "the removal's rule: everything held of each shared vault, taken before a resync"],
  putBackTaken: [1, "the removal's rule: a taken vault put back for its removal"],
  moveToHolding: [1, "the removal's rule: the held copy holds everything the person held, whatever the key"],
  hardDropLocal: [2, "the drop of a vault's rows, called only by dropWithoutHeldCopy"],
  moveStoredOutside: [1, "the removal's notice: the items a move's deletion left behind"],
  materializeConflict: [2, "a conflict copy of a row this pull served; sealed under the seal's gate and sent through the one sender"],
  materializeConflictFromServerItem: [1, "a conflict copy the server's answer to this browser's own change displaced; sent through the one sender"],
  noteBroughtBack: [1, "the name of an item a change of this browser brought back, for its notice"],
  coalesceQueuedPuts: [1, "the queue's own: the pre-edit value of a change already made here"],
  revertDeniedMutation: [1, "the queue's own: a change the server denied is reverted"],
  revertOptimisticSave: [2, "the queue's own: a save that did not happen is reverted"],
  restoreRemoved: [1, "the queue's own: a delete that did not happen is reverted"],
  save: [2, "the item an edit names, refused by mayWrite before anything is queued, and the save's own optimistic apply"],
  remove: [2, "an item a screen kept is refused (never ignored), and the delete's own optimistic drop"],
  runGesture: [2, "the copy's optimistic apply and the source's drop, after both legs were sent"],
  foreignInHalfMade: [1, "counts all a half-made vault holds, so one holding anything else is never deleted; the deletion asks mayWrite at the log"],
};

/** Every public function of the store that only reads, or changes only this browser's own state. */
const READS: Record<string, string> = Object.fromEntries(
  (
    [
      ["freezeAsReadOnlyCopy", "local"],
      ["isReadOnlyCopy", "read"],
      ["pulledInThisSession", "read"],
      ["attachFence", "setup"],
      ["close", "local"],
      ["isClosed", "read"],
      ["onInterrupted", "setup"],
      ["readOnlyCopyReason", "read"],
      ["attachPinRefresh", "setup"],
      ["noteRev", "local"],
      ["lastSyncAt", "read"],
      ["cacheDurable", "read"],
      ["cacheDemoted", "read"],
      ["hasPendingSync", "read"],
      ["queuedMutationCount", "read"],
      ["unsentChangeCount", "read"],
      ["ownsVault", "read"],
      ["demoteCache", "local"],
      ["list", "the guarded read"],
      ["get", "the guarded read"],
      ["undecryptable", "read"],
      ["needsUpdateCount", "read"],
      ["vaults", "read; hides a vault whose key does not work"],
      ["shownVaultIds", "read; the listed vaults and the account's own, whose key works"],
      ["quota", "read"],
      ["mayWrite", "the question itself"],
      ["attachSharedLogs", "setup"],
      ["sharedLogs", "read"],
      ["quarantinedItems", "read"],
      ["deleteMutation", "builds a change, sends nothing"],
      ["itemVersions", "read; each version opens only under a key that works"],
      ["deletedItems", "read; each opens only under a key that works"],
      ["importProjections", "read; refused for a vault whose key does not work"],
      ["downloadAttachment", "read; refused for a vault whose key does not work (store.removal-enforced.test.ts)"],
      ["notices", "read"],
      ["dismissNotice", "local"],
      ["clearNotices", "local"],
      ["undecryptableGrantVaults", "read"],
      ["heldVaults", "read"],
      ["removeHeldCopy", "local: the held copy at rest"],
      ["itemsSetAside", "read"],
      ["removeSetAside", "local: the copies set aside at rest"],
      ["incomingTransfers", "read"],
      ["pendingTransferFor", "read"],
      ["isLogGoverned", "read"],
      ["listDeleted", "read; reads logs, posts nothing"],
      ["memberRoster", "read"],
      ["unfinishedMoves", "read"],
      ["dismissFrozenMove", "local"],
      ["heldChangeFor", "read"],
      ["withdrawHeldChange", "local: a held change is no longer sent"],
      ["withdrawHeldChangeAs", "local: a held change is no longer sent"],
      ["moveDeleteWaiting", "read"],
      ["moveLate", "read"],
      ["movePlan", "read; counts through the guarded read"],
      ["moveSize", "read; counts through the guarded read"],
    ] as const
  ).map(([k, v]) => [k, v]),
);

/** Public functions that send changes but are not decided by this vault's key, each with why. */
const EXEMPT: Record<string, string> = {
  createSharedVault: "a new vault: its genesis starts a new log that no key can disagree with yet",
  leaveSharedVault: "a leave: a person may always leave (the one exception at the log's appends)",
  copyHeldToPersonal: "reads a held copy under its own wrap and writes only the personal vault, which no log decides (the sender asks mayWrite all the same)",
  copySetAsideToPersonal: "reads copies set aside under their own wrap and writes only the personal vault (the sender asks mayWrite all the same)",
  hydrate: "a new start sends only the self-wrap of a key it adopts under the add the verified log names now, which works by definition",
};

/** Bob's tab A, whose key of "Family" does not work: the owner removed and added him again, and tab B carried it out. */
async function keyNotWorking() {
  freshDb();
  const { server, alice, bob, old } = await family(await openVaultCache(BOB));
  const bank = bob.store.list().find((i) => i.vaultId === old)! as VaultItem;
  const personal = bob.account.personalVaultId!;
  const kept = bob.store.newMoveGesture(bank.itemId, personal, true);
  await alice.store.removeVaultMember(old, BOB);
  await alice.store.sync();
  await alice.store.addVaultMember(old, BOB, "writer");
  await alice.store.sync();
  await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
  expect(listed(bob.store, old)).toBe(false);
  expect(namesIn(bob, old)).toEqual([]);
  return { server, bob, old, bank, personal, kept };
}
type Ctx = Awaited<ReturnType<typeof keyNotWorking>>;

/** Every public function of the store that sends a change of a vault, called on that vault while its key does not work. */
const CHANGES: Record<string, (c: Ctx) => Promise<unknown>> = {
  save: (c) => c.bob.store.save(c.bank.itemId, { ...c.bank.doc, name: "edited" }, [], undefined, c.old),
  remove: (c) => c.bob.store.remove(c.bank.itemId),
  restoreDeleted: (c) => c.bob.store.restoreDeleted(c.bank.itemId, c.old, c.bank.doc),
  purgeDeleted: (c) => c.bob.store.purgeDeleted(c.bank.itemId, c.old),
  importDocs: (c) => c.bob.store.importDocs([{ itemId: crypto.randomUUID(), doc: { type: "note", name: "n", notes: "x" } }], undefined, c.old),
  renameVault: (c) => c.bob.store.renameVault(c.old, "Other"),
  newMoveGesture: async (c) => c.bob.store.runGesture(c.bob.store.newMoveGesture(c.bank.itemId, c.personal, true)),
  runGesture: (c) => c.bob.store.runGesture(c.kept),
  copyAllToPersonal: (c) => c.bob.store.copyAllToPersonal(c.old),
  moveEverything: (c) => c.bob.store.moveEverything(c.old, { name: "Mine", add: [] }),
  finishMove: (c) => c.bob.store.finishMove({ vaultId: c.old, name: "Family", newVaultId: null, newName: "Mine", added: [] } as unknown as UnfinishedMove),
  copyLateIntoMove: (c) => c.bob.store.copyLateIntoMove(c.old),
  addVaultMember: (c) => c.bob.store.addVaultMember(c.old, ALICE, "writer"),
  removeVaultMember: (c) => c.bob.store.removeVaultMember(c.old, ALICE),
  setMemberRole: (c) => c.bob.store.setMemberRole(c.old, ALICE, "reader"),
  deleteSharedVault: (c) => c.bob.store.deleteSharedVault(c.old),
  restoreSharedVault: (c) => c.bob.store.restoreSharedVault(c.old, "none"),
  offerTransfer: (c) => c.bob.store.offerTransfer(c.old, ALICE),
  cancelTransfer: (c) => c.bob.store.cancelTransfer(c.old),
  acceptTransfer: (c) => c.bob.store.acceptTransfer(c.old, "none"),
  sendHeldDeletion: (c) => c.bob.store.sendHeldDeletion(c.old),
  resendHeldChanges: (c) => c.bob.store.resendHeldChanges(),
  sendBeforeDelete: (c) => c.bob.store.sendBeforeDelete(),
  sync: (c) => c.bob.store.sync(),
};

describe("the places where something leaves this browser, each a closed list", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the functions that read the set of opened items directly are exactly the listed ones, each with its reason", () => {
    const found: Record<string, number> = {};
    for (const m of membersOfStore()) {
      const n = count(m.lines, "this.itemsById");
      if (n > 0) found[m.name] = (found[m.name] ?? 0) + n;
    }
    expect(found).toEqual(Object.fromEntries(Object.entries(DIRECT_READS).map(([k, [n]]) => [k, n])));
  });

  it("every public function of the store is a read, a change shown to send nothing while the key does not work, or exempt with its reason", () => {
    const publicNames = [...new Set(membersOfStore().filter((m) => m.isPublic).map((m) => m.name))].sort();
    const listedNames = [...Object.keys(READS), ...Object.keys(CHANGES), ...Object.keys(EXEMPT)];
    expect(new Set(listedNames).size).toBe(listedNames.length);
    expect(publicNames).toEqual([...listedNames].sort());
  });

  for (const [name, call] of Object.entries(CHANGES)) {
    it(`${name}: on a vault whose key does not work, nothing is sent`, async () => {
      const c = await keyNotWorking();
      const before = c.server.writes.length;
      await call(c).catch(() => {});
      expect(c.server.writes.slice(before)).toEqual([]);
    });
  }

  it("the items' changes leave through one sender, and each other change asks mayWrite before its request", () => {
    const sendsIn = (needle: string): string[] => membersOfStore().filter((m) => count(m.lines, needle) > 0).map((m) => m.name);
    expect({
      push: sendsIn("this.wire.pushMutations("),
      upload: sendsIn("this.wire.uploadAttachment("),
      restore: sendsIn("this.wire.restoreItem("),
      purge: sendsIn("this.wire.purgeItem("),
      meta: sendsIn("this.api.updateVaultMeta("),
      appendOutsideTheLog: sendsIn("appendLog("),
    }).toEqual({ push: ["sendItemChanges"], upload: ["uploadInto"], restore: ["restoreDeleted"], purge: ["purgeDeleted"], meta: ["renameVault"], appendOutsideTheLog: [] });
    for (const name of ["restoreDeleted", "purgeDeleted", "renameVault", "sendItemChanges", "uploadInto"]) {
      const body = membersOfStore().find((m) => m.name === name)!.lines.join("\n");
      expect(body.includes("this.refuseUnlessMayWrite(")).toBe(true);
    }
  });

  it("rows of a shared vault leave without a held copy only through dropWithoutHeldCopy, for a reason of its closed list", () => {
    expect([...DROP_REASONS]).toEqual(["held-copy-made", "held-copy-removed-by-person", "own-leave", "nothing-opened", "not-log-governed"]);
    const members = membersOfStore();
    const drops = members.filter((m) => count(m.lines, "this.hardDropLocal(") > 0).map((m) => m.name);
    expect(drops).toEqual(["dropWithoutHeldCopy"]);
    const reasons = [...source.matchAll(/this\.dropWithoutHeldCopy\(vaultId, "([a-z-]+)"\)/g)].map((m) => m[1]);
    expect(count(source.split("\n"), "this.dropWithoutHeldCopy(")).toBe(reasons.length);
    expect(new Set(reasons)).toEqual(new Set(DROP_REASONS));
    // Every other removal of rows at rest, by the member it stands in: the purge of rows that do not parse at all, the
    // drop's own disk twin, and the held and set-aside copies' own lifetimes (not live rows).
    const atRest = (needle: string): string[] => members.filter((m) => count(m.lines, needle) > 0).map((m) => m.name);
    expect({ dropVault: atRest("dropVault("), clear: atRest("itemsById.clear()") }).toEqual({ dropVault: ["purgeMalformedCachedRows", "hardDropLocal"], clear: ["pullOnce"] });
  });

  it("the one place of the log's appends asks the same question: with the gate closed nothing is posted but a leave", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    alice.shared.logs.attachWriteGate(() => false);
    const before = server.writes.length;
    for (const change of [
      () => alice.store.removeVaultMember(old, BOB),
      () => alice.store.setMemberRole(old, BOB, "reader"),
      () => alice.store.offerTransfer(old, BOB),
      () => alice.store.deleteSharedVault(old),
    ])
      await change().catch(() => {});
    expect(server.writes.slice(before)).toEqual([]);
    bob.shared.logs.attachWriteGate(() => false);
    await bob.store.leaveSharedVault(old).catch(() => {});
    expect(server.writes.slice(before)).toEqual([`log-leave:${old}`]);
  });
});
