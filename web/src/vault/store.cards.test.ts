import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type {
  DeletedItem,
  DeletedItemsResponse,
  ItemDoc,
  ItemRestoreResponse,
  ItemUpload,
  ItemVersion,
  ItemVersionsResponse,
  Mutation,
  PushResponse,
  SyncResponse,
  WireGrant,
  WireItem,
  WireVault,
} from "../api/types";
import { adItem } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { sealSharedGrant } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account, ITEM_FORMAT_VERSION, docFloor } from "./account";
import { VaultStore } from "./store";

/**
 * Cards / formatVersion 2 (design 2026-07-09, "the degradation gate") — the web twin of
 * core MixedFleetFormatVersionTest: card docs seal at the fv2 per-doc floor, everything
 * else stays bit-compatible fv1 for the fielded fleet, reseals are monotonic (never below
 * the fv an item was decrypted at — the downgrade the server refuses), and the store's
 * wire formatVersion always equals the fv the blob was AD-bound at. Same real-Account +
 * FakeApi drive pattern as store.test.ts.
 */

// Minimum-cost argon2id — these tests exercise fv mechanics, not the KDF.
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

const CARD_DOC: ItemDoc = {
  type: "card",
  name: "Blue Visa",
  card: { cardholderName: "Jacob Cardholder", number: "4242424242424242", expMonth: "12", expYear: "2027", securityCode: "123", brand: "visa" },
};
const LOGIN_DOC: ItemDoc = { type: "login", name: "GitHub", login: { username: "jacob", password: "hunter2" } };

const emptySync = (rev: number): SyncResponse => ({ rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] });

class FakeApi {
  queue: SyncResponse[] = [];
  pushes: Mutation[][] = [];
  sinceLog: number[] = [];
  rev = 1;
  /** Item history: archived versions the server would hold, keyed by itemId. */
  itemVersionsById = new Map<string, ItemVersion[]>();
  /** Item undelete: tombstoned items the server would list + a capture of restore POSTs. */
  deletedList: DeletedItem[] = [];
  restored: { itemId: string; upload: ItemUpload }[] = [];

  async itemVersions(itemId: string): Promise<ItemVersionsResponse> {
    return { itemId, versions: this.itemVersionsById.get(itemId) ?? [] };
  }
  async deletedItems(): Promise<DeletedItemsResponse> {
    return { items: this.deletedList };
  }
  async restoreItem(itemId: string, upload: ItemUpload): Promise<ItemRestoreResponse> {
    this.restored.push({ itemId, upload });
    this.deletedList = this.deletedList.filter((d) => d.itemId !== itemId);
    return { rev: 999 };
  }
  async sync(since: number): Promise<SyncResponse> {
    this.sinceLog.push(since);
    const resp = this.queue.shift() ?? emptySync(this.rev);
    this.rev = Math.max(this.rev, resp.rev);
    return resp;
  }
  async push(mutations: Mutation[]): Promise<PushResponse> {
    this.pushes.push(mutations);
    return { rev: ++this.rev, results: mutations.map((m) => ({ mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 })) };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

async function enroll(email: string): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "cards-test",
    email,
    displayName: email,
    password: `pw ${email}`,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return account;
}

function wire(vaultId: string, itemId: string, blob: string | null, formatVersion: number, rev = 1): WireItem {
  return { itemId, vaultId, rev, createdAt: 0, updatedAt: 0, deleted: false, conflict: false, formatVersion, attachmentIds: [], blob };
}

/** A raw test-held VK delivered through the real sealed-grant path (core twin's fixture) —
 *  lets a test mint envelopes at an ARBITRARY AD fv, simulating other-generation writers. */
function grantRawVk(member: Account, vaultId: string): Uint8Array {
  const vk = randomBytes(32);
  member.addGrant({ vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 1, sealedVk: toB64(sealSharedGrant(member.identityPub, vaultId, vk)) });
  return vk;
}

const sealAt = (vk: Uint8Array, vaultId: string, itemId: string, doc: ItemDoc, fv: number): string =>
  toB64(seal(vk, utf8(JSON.stringify(doc)), adItem(vaultId, itemId, fv)));

describe("Account formatVersion mechanics (cards, fv2)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  /** The ceiling is 2 for the 0.7.0 generation — a further bump is a design event
   *  (per-doc floors + the server monotonic guard must be revisited), not a refactor. */
  it("pins ITEM_FORMAT_VERSION at 2; docFloor floors card-bearing docs at 2, logins/notes at 1", () => {
    expect(ITEM_FORMAT_VERSION).toBe(2);
    expect(docFloor(CARD_DOC)).toBe(2);
    // Type alone floors: a card whose fields were stripped must still never seal below 2.
    expect(docFloor({ type: "card", name: "husk" })).toBe(2);
    // Card data floors regardless of declared type (the legacy-restore edge re-floor).
    expect(docFloor({ type: "login", name: "l", card: { number: "4242424242424242" } })).toBe(2);
    expect(docFloor(LOGIN_DOC)).toBe(1);
    expect(docFloor({ type: "note", name: "n" })).toBe(1);
  });

  it("encryptItem seals cards at 2 / logins at 1 and binds the fv into the AD", async () => {
    const account = await enroll("fv@example.com");
    const cardId = account.newItemId();
    const up = account.encryptItem(account.personalVaultId, cardId, CARD_DOC);
    expect(up.formatVersion).toBe(2);

    const back = account.decryptItem(wire(account.personalVaultId, cardId, up.blob, 2));
    expect(back.card?.number).toBe("4242424242424242");
    expect(back.card?.brand).toBe("visa");
    // Same blob re-declared fv1: the ceiling gate passes but the AD no longer matches —
    // the server cannot re-declare an envelope's version without the open failing.
    expect(() => account.decryptItem(wire(account.personalVaultId, cardId, up.blob, 1))).toThrow();

    expect(account.encryptItem(account.personalVaultId, account.newItemId(), LOGIN_DOC).formatVersion).toBe(1);
  });

  it("reseal is monotonic: never below the fv the item was decrypted at, even when the floor drops", async () => {
    const member = await enroll("monotonic@example.com");
    const vaultId = "44444444-4444-4444-8444-444444444444";
    const vk = grantRawVk(member, vaultId);

    // A note that CARRIED a card object arrives sealed at fv2 (a 0.7.0-generation writer).
    const noteWithCard: ItemDoc = { type: "note", name: "carried a card", card: { number: "4242424242424242" } };
    const itemId = member.newItemId();
    const decrypted = member.decryptItem(wire(vaultId, itemId, sealAt(vk, vaultId, itemId, noteWithCard, 2), 2, 5));

    // Spread-edit the card AWAY: the doc's floor would now be 1, but the item arrived at
    // 2 → the reseal stays 2 (re-emitting a lower fv is the downgrade the server refuses).
    expect(member.encryptItem(vaultId, itemId, { ...decrypted, card: undefined }).formatVersion).toBe(2);

    // Viewing an OLDER archived fv1 version (item history) must not lower the memory —
    // decryptItemVersion funnels through decryptItem's monotonic max.
    member.decryptItemVersion(vaultId, itemId, { rev: 4, blob: sealAt(vk, vaultId, itemId, LOGIN_DOC, 1), formatVersion: 1, archivedAt: 0 });
    expect(member.encryptItem(vaultId, itemId, { ...decrypted, card: undefined }).formatVersion).toBe(2);

    // No cross-item bleed: a fresh login in the same vault still seals at its floor.
    expect(member.encryptItem(vaultId, member.newItemId(), LOGIN_DOC).formatVersion).toBe(1);
  });
});

describe("VaultStore card formatVersion wiring (fv2)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a card save pushes formatVersion 2 and round-trips through sync + decryptItem (AD consistency)", async () => {
    const account = await enroll("save@example.com");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), account);

    await store.save(null, CARD_DOC);
    const cardMut = api.pushes.at(-1)![0]!;
    expect(cardMut.vaultId).toBe(account.personalVaultId);
    expect(cardMut.item!.formatVersion).toBe(2);

    // A server echo of exactly the pushed row decrypts back to the same card — the wire
    // fv IS the AD fv, or this open would throw and the card would vanish undecryptable.
    const echoed = wire(cardMut.vaultId, cardMut.itemId, cardMut.item!.blob, cardMut.item!.formatVersion, 5);
    const rejoined = new VaultStore(api.asClient(), account); // fresh working set, same keys
    api.queue.push({ rev: 9, full: true, vaults: [], grants: [], items: [echoed], removedGrants: [] });
    await rejoined.sync();
    expect(rejoined.get(cardMut.itemId)?.doc).toEqual(CARD_DOC);
  });

  it("login/note saves still carry formatVersion 1 (bit-compat with the fielded fleet)", async () => {
    const account = await enroll("bitcompat@example.com");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), account);

    await store.save(null, LOGIN_DOC);
    expect(api.pushes.at(-1)![0]!.item!.formatVersion).toBe(1);
    await store.save(null, { type: "note", name: "plain note" });
    expect(api.pushes.at(-1)![0]!.item!.formatVersion).toBe(1);
  });

  it("a live fv2 item reseals at 2 after an fv1 archived version is viewed via itemVersions()", async () => {
    const member = await enroll("history@example.com");
    const vaultId = "55555555-5555-4555-8555-555555555555";
    const vk = grantRawVk(member, vaultId);
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), member);

    // A NOTE carrying a card object (the shape the legacy-restore edge mints): its floor
    // is 2 only while the card key is present — so the per-item fv MEMORY, not the floor,
    // is what the decisive assertion below exercises.
    const noteWithCard: ItemDoc = { type: "note", name: "carried a card", card: { number: "4242424242424242" } };
    const itemId = member.newItemId();
    api.queue.push({ rev: 5, full: true, vaults: [], grants: [], items: [wire(vaultId, itemId, sealAt(vk, vaultId, itemId, noteWithCard, 2), 2, 4)], removedGrants: [] });
    await store.sync();
    expect(store.get(itemId)?.doc).toEqual(noteWithCard);

    // The archive holds an fv1 original (the legacy-restore edge mints exactly these).
    api.itemVersionsById.set(itemId, [
      { rev: 3, blob: sealAt(vk, vaultId, itemId, noteWithCard, 1), formatVersion: 1, archivedAt: 1 },
    ]);
    const versions = await store.itemVersions(itemId, vaultId);
    expect(versions).toHaveLength(1);

    // Restoring that version is a plain put — it must go out at 2, not mint a refused
    // fv downgrade because an older archive was merely LOOKED at.
    await store.save(itemId, versions[0]!.doc);
    expect(api.pushes.at(-1)![0]!.item!.formatVersion).toBe(2);

    // The decisive monotonic leg: strip the card so docFloor drops to 1 — the per-item
    // memory ALONE must keep the reseal at 2 (else this very save would be the refused
    // fv_downgrade the server guard exists for).
    await store.save(itemId, { ...store.get(itemId)!.doc, card: undefined });
    expect(docFloor(store.get(itemId)!.doc)).toBe(1);
    expect(api.pushes.at(-1)![0]!.item!.formatVersion).toBe(2);
  });

  it("holding-area round-trip: a held card re-seals at fv2 and rehydrates on reinstate", async () => {
    const owner = await enroll("owner@example.com");
    const member = await enroll("member@example.com");
    const { request, vaultId } = owner.buildCreateSharedVault("Family");
    const sealedVk = owner.wrapVkForMember(member.identityPub, vaultId);
    const itemId = owner.newItemId();
    const up = owner.encryptItem(vaultId, itemId, CARD_DOC);
    const vault: WireVault = { vaultId, type: "shared", rev: 2, metaBlob: request.metaBlob, createdAt: 0 };
    const grant: WireGrant = { vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 3, sealedVk };

    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), member);
    api.queue.push({ rev: 5, full: true, vaults: [vault], grants: [grant], items: [wire(vaultId, itemId, up.blob, up.formatVersion, 4)], removedGrants: [] });
    await store.sync();
    expect(store.get(itemId)?.doc).toEqual(CARD_DOC);

    // Revocation: the card is re-sealed into the ciphertext-only holding snapshot.
    api.queue.push({ rev: 6, full: false, vaults: [], grants: [], items: [], removedGrants: [vaultId], removedGrantsInfo: [{ vaultId, reason: "left" }] });
    await store.sync();
    expect(store.get(itemId)).toBeUndefined();
    expect(store.heldVaults().map((h) => h.vaultId)).toContain(vaultId);

    // Reinstate via a re-delivered live grant WITHOUT the item in the backfill: the belt
    // rehydrate decrypts the held snapshot — a held wire fv diverging from the fv the
    // snapshot blob was sealed (AD-bound) at would throw here and silently drop the card.
    api.queue.push({ rev: 7, full: false, vaults: [{ ...vault, rev: 7 }], grants: [{ ...grant, rev: 7 }], items: [], removedGrants: [] });
    await store.sync();
    expect(store.heldVaults()).toHaveLength(0);
    expect(store.get(itemId)?.doc).toEqual(CARD_DOC);
  });

  it("needsUpdateCount counts newer-fv items only — a corrupt blob at a supported fv is excluded", async () => {
    const account = await enroll("banner@example.com");
    const pv = account.personalVaultId;
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), account);

    const newerId = account.newItemId();
    const corruptId = account.newItemId();
    // fv3: the fail-closed gate fires on the wire field before any crypto.
    const newer = wire(pv, newerId, account.encryptItem(pv, newerId, LOGIN_DOC).blob, 3, 4);
    // AD mismatch at a SUPPORTED fv: a blob sealed for a different itemId.
    const corrupt = wire(pv, corruptId, account.encryptItem(pv, account.newItemId(), LOGIN_DOC).blob, 1, 5);
    api.queue.push({ rev: 9, full: true, vaults: [], grants: [], items: [newer, corrupt], removedGrants: [] });
    await store.sync();

    expect(store.undecryptable()).toHaveLength(2); // both retained for backup enumeration
    expect(store.needsUpdateCount()).toBe(1); // …but only the newer-fv one is an app-update problem
  });

  it("Trash × newer fv: a tombstone whose newest archived version is fv3 surfaces doc:null (restore stays disabled)", async () => {
    const account = await enroll("trash@example.com");
    const pv = account.personalVaultId;
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), account);

    const deadId = account.newItemId();
    api.deletedList = [{ itemId: deadId, vaultId: pv, deletedAt: 1_690_000_000_000 }];
    api.itemVersionsById.set(deadId, [
      { rev: 9, blob: account.encryptItem(pv, deadId, CARD_DOC).blob, formatVersion: 3, archivedAt: 2 },
    ]);

    const trash = await store.deletedItems();
    expect(trash).toHaveLength(1); // still listed by identity —
    expect(trash[0]!.doc).toBeNull(); // — but fail-closed unnamed: nothing decrypted, nothing to restore
  });

  it("restoreDeleted of a card POSTs formatVersion 2 to the restore route", async () => {
    const account = await enroll("undelete@example.com");
    const pv = account.personalVaultId;
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), account);

    const deadId = account.newItemId();
    api.deletedList = [{ itemId: deadId, vaultId: pv, deletedAt: 1_690_000_000_000 }];
    api.itemVersionsById.set(deadId, [
      { rev: 9, blob: account.encryptItem(pv, deadId, CARD_DOC).blob, formatVersion: 2, archivedAt: 2 },
    ]);

    const trash = await store.deletedItems();
    expect(trash[0]!.doc?.card?.number).toBe("4242424242424242"); // an fv2 archive decrypts on this build

    await store.restoreDeleted(deadId, pv, trash[0]!.doc!);
    expect(api.restored).toHaveLength(1);
    expect(api.restored[0]!.upload.formatVersion).toBe(2); // the tombstone kept fv2 — a lower fv would be refused
  });

  it("importDocs of plain logins/notes still pushes formatVersion 1", async () => {
    const account = await enroll("import@example.com");
    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), account);

    await store.importDocs([
      { itemId: account.newItemId(), doc: LOGIN_DOC },
      { itemId: account.newItemId(), doc: { type: "note", name: "imported note" } },
    ]);
    const puts = api.pushes.flat().filter((m) => m.op === "put");
    expect(puts).toHaveLength(2);
    for (const m of puts) expect(m.item!.formatVersion).toBe(1); // fielded-fleet bit-compat
  });
});
