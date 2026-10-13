import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AccountKeys, ItemDoc, Mutation, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import { adItem, adUvk, adVaultMeta, adVk } from "../crypto/ad";
import { fromB64, toB64 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import { masterKey, wrapKey, type KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { sealSharedGrant } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account, VaultKeyNotVerifiedError } from "./account";
import { memoryClientState } from "./accountstatesync";
import { openVaultCache, type VaultCache } from "./idbcache";
import { ItemChangedVaultsError, VaultStore } from "./store";

/**
 * Item home (security review 2026-10, root cause A §5; branch A1b) on the path a real client takes — web twin of core
 * `ItemHomeAcceptanceTest`. The campaign HIGH A-4: a hostile server serves a conflict-flagged row for an item this
 * browser holds in vault P under ANOTHER vault S, next to the genuine row; before A1b `materializeConflict` re-sealed
 * the locally held twin (P's plaintext) under S's key and pushed it. The §5.3 acceptance, both row orders, warm and
 * cold (hydrated from IndexedDB):
 *  1. no push carries an S envelope whose plaintext is P's doc for X (every pushed S envelope is decrypted);
 *  2. `get(X).vaultId == P` and P's doc is unchanged;
 *  3. exactly one "the server sent an item under the wrong vault" anomaly;
 *  4. in-window, a v1-only S is legacy-read-only and INV-WRITE-KEY blocks any seal under it on its own.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const g = globalThis as unknown as { indexedDB: IDBFactory };
const utf8 = (s: string) => new TextEncoder().encode(s);

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  password: string;
  personalVaultId: string;
  personalWrappedVk: string;
  personalMeta: string;
}

async function enroll(tag: string): Promise<Enrolled> {
  const email = `${tag}-${Math.random().toString(16).slice(2)}@example.com`;
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
  return {
    account,
    keys: {
      kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap,
    },
    userId: request.userId,
    password,
    personalVaultId: request.personalVault.vaultId,
    personalWrappedVk: request.personalVault.wrappedVk,
    personalMeta: request.personalVault.metaBlob,
  };
}

const unlock = (e: Enrolled) => Account.unlock(e.userId, e.password, e.keys);

async function uvkOf(e: Enrolled): Promise<Uint8Array> {
  const mk = masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams);
  return open(await wrapKey(mk), fromB64(e.keys.wrappedUvk), adUvk(e.userId));
}

/** A scripted hostile server: a queue of /sync answers, and every mutation the client pushes. */
class Server {
  queue: SyncResponse[] = [];
  pushed: Mutation[] = [];
  rev = 100;
  resyncOnce = false;
  /** When set, a put for this itemId is answered `conflict` with this row as the displaced (losing) value. */
  conflictFor: { itemId: string; row: WireItem } | null = null;
  async restoreItem() {
    return { rev: ++this.rev };
  }
  async sync(since: number): Promise<SyncResponse> {
    if (this.resyncOnce && since > 0) {
      this.resyncOnce = false;
      throw new ApiError(410, "resync_required", "gone");
    }
    return this.queue.shift() ?? { rev: this.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
  }
  async push(mutations: Mutation[]): Promise<PushResponse> {
    this.pushed.push(...mutations);
    return {
      rev: this.rev,
      results: mutations.map((m) =>
        this.conflictFor && m.itemId === this.conflictFor.itemId && m.op === "put"
          ? { mutationId: m.mutationId, status: "conflict" as const, newItemRev: ++this.rev, serverItem: this.conflictFor.row }
          : { mutationId: m.mutationId, status: "applied" as const, newItemRev: ++this.rev },
      ),
    };
  }
  async accountState() {
    return { sealedState: null, seq: 0 };
  }
  async vaultMembers() {
    return [];
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

/** The §5.3 fixture (see the core twin): `writable` false = the review's v1-sealed S; true = S a vault the victim
 *  owns that a colluding co-member can read (INV-HOME must hold with no INV-WRITE-KEY behind it). */
interface World {
  victim: Enrolled;
  writable: boolean;
  p: string;
  s: string;
  x: string;
  vkS: Uint8Array;
  docP: ItemDoc;
  personalRow: WireVault;
  personalGrant: WireGrant;
  sRow: WireVault;
  sGrant: WireGrant;
  genuine: WireItem;
  flagged: WireItem;
}

async function world(writable: boolean): Promise<World> {
  const victim = await enroll("a1b-victim");
  const p = victim.personalVaultId;
  const x = victim.account.newItemId();
  const docP: ItemDoc = { type: "login", name: "Bank", login: { username: "me", password: "P-SECRET-0001", uris: [] } };
  const bait: ItemDoc = { type: "login", name: "Bank", login: { username: "me", password: "server-chosen", uris: [] } };
  let s: string;
  let vkS: Uint8Array;
  let sRow: WireVault;
  let sGrant: WireGrant;
  if (writable) {
    const shared = victim.account.buildCreateSharedVault("Household");
    s = shared.vaultId;
    vkS = open(await uvkOf(victim), fromB64(shared.request.wrappedVk), adVk(s, victim.userId));
    sRow = { vaultId: s, type: "shared", rev: 7, metaBlob: shared.request.metaBlob, createdAt: 0 };
    sGrant = { vaultId: s, userId: victim.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 7, sealedVk: null };
  } else {
    s = victim.account.newItemId();
    vkS = randomBytes(32);
    sRow = { vaultId: s, type: "shared", rev: 7, metaBlob: toB64(seal(vkS, utf8(JSON.stringify({ name: "Server" })), adVaultMeta(s))), createdAt: 0 };
    sGrant = { vaultId: s, userId: victim.userId, role: "writer", wrappedVk: "", rev: 7, sealedVk: toB64(sealSharedGrant(fromB64(victim.keys.identityPub), s, vkS)) };
  }
  const up = victim.account.encryptItem(p, x, docP);
  const genuine: WireItem = { itemId: x, vaultId: p, rev: 3, createdAt: 1, updatedAt: 1, deleted: false, conflict: false, formatVersion: up.formatVersion, attachmentIds: [], blob: up.blob };
  const flagged: WireItem = { itemId: x, vaultId: s, rev: 8, createdAt: 1, updatedAt: 2, deleted: false, conflict: true, formatVersion: 1, attachmentIds: [], blob: toB64(seal(vkS, utf8(JSON.stringify(bait)), adItem(s, x, 1))) };
  return {
    victim, writable, p, s, x, vkS, docP,
    personalRow: { vaultId: p, type: "personal", rev: 2, metaBlob: victim.personalMeta, createdAt: 0 },
    personalGrant: { vaultId: p, userId: victim.userId, role: "owner", wrappedVk: victim.personalWrappedVk, rev: 2, sealedVk: null },
    sRow, sGrant, genuine, flagged,
  };
}

const seedFeed = (w: World): SyncResponse => ({ rev: 5, full: true, vaults: [w.personalRow], grants: [w.personalGrant], items: [w.genuine], removedGrants: [] });
const fixture = (w: World, flaggedFirst: boolean): SyncResponse => ({
  rev: 9, full: false, vaults: [w.sRow], grants: [w.sGrant],
  items: flaggedFirst ? [w.flagged, { ...w.genuine, rev: 6 }] : [{ ...w.genuine, rev: 6 }, w.flagged],
  removedGrants: [],
});

/** Decrypt an S envelope the client pushed; null when it does not open under S's key. */
function openS(w: World, m: Mutation): ItemDoc | null {
  if (!m.item) return null;
  try {
    return JSON.parse(new TextDecoder().decode(open(w.vkS, fromB64(m.item.blob), adItem(w.s, m.itemId, m.item.formatVersion)))) as ItemDoc;
  } catch {
    return null;
  }
}

/** A warm client (one store all along) or a cold one (a fresh Account + store hydrated from the same IndexedDB). */
async function client(w: World, server: Server, cold: boolean): Promise<{ device: Account; store: VaultStore }> {
  const local = memoryClientState();
  const first = await unlock(w.victim);
  const cache: VaultCache = await openVaultCache(w.victim.userId);
  const s1 = new VaultStore(server.asClient(), first, cache, local);
  server.queue.push(seedFeed(w));
  await s1.sync();
  expect(s1.get(w.x)?.vaultId).toBe(w.p);
  if (!cold) return { device: first, store: s1 };
  cache.close();
  const second = await unlock(w.victim);
  const s2 = new VaultStore(server.asClient(), second, await openVaultCache(w.victim.userId), local);
  await s2.hydrate();
  return { device: second, store: s2 };
}

function assertAcceptance(w: World, server: Server, device: Account, store: VaultStore): void {
  for (const m of server.pushed.filter((x) => x.vaultId === w.s)) {
    expect(openS(w, m)?.login?.password, "P's plaintext was sealed under S and pushed").not.toBe(w.docP.login!.password);
  }
  expect(store.get(w.x)?.vaultId).toBe(w.p);
  expect(store.get(w.x)?.doc).toEqual(w.docP);
  expect(store.list().filter((i) => i.itemId === w.x)).toHaveLength(1);
  expect(store.notices().filter((n) => n.kind === "wrong-vault")).toHaveLength(1);
  if (!w.writable) {
    expect(device.isLegacyReadOnly(w.s)).toBe(true);
    expect(() => device.encryptItem(w.s, device.newItemId(), w.docP)).toThrow(VaultKeyNotVerifiedError);
  }
}

describe("A1b — item home (VaultStore)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  for (const writable of [false, true]) {
    for (const flaggedFirst of [true, false]) {
      for (const cold of [false, true]) {
        it(`§5.3 acceptance: ${writable ? "writable" : "v1-sealed"} S, ${flaggedFirst ? "flagged row first" : "genuine row first"}, ${cold ? "cold" : "warm"}`, async () => {
          const w = await world(writable);
          const server = new Server();
          const { device, store } = await client(w, server, cold);
          server.queue.push(fixture(w, flaggedFirst));
          await store.sync();
          assertAcceptance(w, server, device, store);
        });
      }
    }
  }

  it("the editor's save after the fixture seals under P (the core MEDIUM's web twin)", async () => {
    const w = await world(true);
    const server = new Server();
    const { store } = await client(w, server, false);
    server.queue.push(fixture(w, false));
    await store.sync();
    server.pushed = [];
    const edited: ItemDoc = { ...w.docP, login: { ...w.docP.login!, password: "P-SECRET-0002" } };
    await store.save(w.x, edited, [], undefined, w.p); // the editor opened X in P
    expect(server.pushed.filter((m) => m.itemId === w.x && m.op === "put").map((m) => m.vaultId)).toEqual([w.p]);
    for (const m of server.pushed.filter((x) => x.vaultId === w.s)) expect(openS(w, m)?.login?.password ?? "").not.toMatch(/^P-SECRET/);
  });

  it("INV-EDIT: a save from an editor bound to another vault is refused, never re-targeted", async () => {
    const w = await world(true);
    const server = new Server();
    const { store } = await client(w, server, false);
    server.queue.push({ rev: 9, full: false, vaults: [w.sRow], grants: [w.sGrant], items: [], removedGrants: [] });
    await store.sync();
    server.pushed = [];
    await expect(store.save(w.x, { ...w.docP, name: "Bank 2" }, [], undefined, w.s)).rejects.toThrow(/changed vaults/i);
    expect(server.pushed.filter((m) => m.itemId === w.x)).toEqual([]);
  });

  it("INV-HOME covers tombstones: a served delete of X under S leaves X in P", async () => {
    const w = await world(true);
    const server = new Server();
    const { store } = await client(w, server, false);
    const tomb: WireItem = { itemId: w.x, vaultId: w.s, rev: 8, createdAt: 1, updatedAt: 3, deleted: true, conflict: false, formatVersion: 1, attachmentIds: [], blob: null };
    server.queue.push({ rev: 9, full: false, vaults: [w.sRow], grants: [w.sGrant], items: [tomb], removedGrants: [] });
    await store.sync();
    expect(store.get(w.x)?.vaultId).toBe(w.p);
    expect(store.notices().filter((n) => n.kind === "wrong-vault")).toHaveLength(1);
  });

  it("the home survives a 410 resync-from-0: a snapshot serving X only under S does not re-home it", async () => {
    const w = await world(true);
    const server = new Server();
    const { store } = await client(w, server, true);
    server.resyncOnce = true;
    server.queue.push({ rev: 9, full: true, vaults: [w.personalRow, w.sRow], grants: [w.personalGrant, w.sGrant], items: [{ ...w.flagged, conflict: false }], removedGrants: [] });
    await store.sync();
    expect(store.list().filter((i) => i.itemId === w.x && i.vaultId === w.s)).toEqual([]);
    expect(store.notices().filter((n) => n.kind === "wrong-vault")).toHaveLength(1);
  });

  it("INV-CONFLICT, push side: a displaced value under another vault than the pushed one is not copied", async () => {
    const w = await world(true);
    const server = new Server();
    const { store } = await client(w, server, false);
    server.queue.push({ rev: 9, full: false, vaults: [w.sRow], grants: [w.sGrant], items: [], removedGrants: [] });
    await store.sync();
    server.pushed = [];
    server.conflictFor = { itemId: w.x, row: { ...w.flagged, conflict: false } };
    await store.save(w.x, { ...w.docP, name: "Bank (edited)" }, [], undefined, w.p);
    expect(server.pushed.filter((m) => m.vaultId === w.s)).toEqual([]);
    expect(store.notices().filter((n) => n.kind === "wrong-vault")).toHaveLength(1);
    expect(store.get(w.x)?.vaultId).toBe(w.p);
  });

  it("INV-WRITE-KEY on every web path (save, copy-into, import, restore): a v1-only S is never written under", async () => {
    const w = await world(false);
    const server = new Server();
    const { device, store } = await client(w, server, false);
    server.queue.push({ rev: 9, full: false, vaults: [w.sRow], grants: [w.sGrant], items: [], removedGrants: [] });
    await store.sync();
    expect(device.isLegacyReadOnly(w.s)).toBe(true);
    server.pushed = [];
    await expect(store.save(null, { ...w.docP, name: "new in S" }, [], undefined, w.s)).rejects.toThrow(VaultKeyNotVerifiedError);
    await expect(store.runGesture(store.newMoveGesture(w.x, w.s, false))).rejects.toThrow(VaultKeyNotVerifiedError);
    await expect(store.importDocs([{ itemId: device.newItemId(), doc: w.docP }], undefined, w.s)).rejects.toThrow(VaultKeyNotVerifiedError);
    await expect(store.restoreDeleted(device.newItemId(), w.s, w.docP)).rejects.toThrow(VaultKeyNotVerifiedError);
    expect(server.pushed.filter((m) => m.vaultId === w.s)).toEqual([]);
  });

  it("INV-SEAL: a restore or a move can never seal an item under another vault than its home", async () => {
    const w = await world(true);
    const server = new Server();
    const { store } = await client(w, server, false);
    server.queue.push({ rev: 9, full: false, vaults: [w.sRow], grants: [w.sGrant], items: [], removedGrants: [] });
    await store.sync();
    await expect(store.restoreDeleted(w.x, w.s, w.docP)).rejects.toThrow(ItemChangedVaultsError);
    const g = store.newMoveGesture(w.x, w.s, true);
    expect(g.newItemId).not.toBe(w.x);
    await expect(store.runGesture({ ...g, sourceVaultId: w.s })).rejects.toThrow(ItemChangedVaultsError);
  });
});
