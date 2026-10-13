import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AccountKeys, PersonalWrap, PushResponse, RemovedGrantInfo, SyncResponse, UserLookupResponse, VaultMemberAdd, VaultMemberSummary, WireGrant, WireItem, WireVault } from "../api/types";
import { adIdkey, adUvk, adVk } from "../crypto/ad";
import { fromB64, toB64 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import { masterKey, wrapKey, type KdfParams } from "../crypto/keys";
import { newRemovalNonce, removeV2Proof } from "../crypto/lifecycleproof";
import { boxKeypairFromSeed, randomBytes, sealTo, signKeypairFromSeed } from "../crypto/provider";
import { openSharedGrant, sealSharedGrant } from "../crypto/sharedgrant";
import { buildGrantFrame, openSignedGrant } from "../crypto/signedgrant";
import { initSodium } from "../crypto/sodium";
import { Account, legacyTagOf, VaultKeyNotVerifiedError } from "./account";
import { memoryClientState } from "./accountstatesync";
import type { Contact } from "./accountstate";
import { IdbVaultCache, openVaultCache } from "./idbcache";
import { HELD_KEYS_KEY, MemberNotVerifiedError, OwnershipNotConfirmedError, VaultStore } from "./store";
import { withOwned } from "./accountstate";

/**
 * Signed vault grants on the path a real client takes (security review 2026-10, root cause A §1.4–§1.6, §3.2,
 * §8.2, branch A6) — web twin of core `SignedGrantEngineTest`. The invariant: a member never adopts a VK, and
 * never mints a self-wrap, for a key the server or an unpinned party chose.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const g = globalThis as unknown as { indexedDB: IDBFactory };

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  password: string;
  identityPub: string;
  personalVaultId: string;
  personalWrappedVk: string;
  personalMeta: string;
  personalWrap: PersonalWrap;
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
    identityPub: request.identityPub,
    personalVaultId: request.personalVault.vaultId,
    personalWrappedVk: request.personalVault.wrappedVk,
    personalMeta: request.personalVault.metaBlob,
    personalWrap: request.personalWrap!,
  };
}

const unlock = (e: Enrolled) => Account.unlock(e.userId, e.password, e.keys);

async function uvkOf(e: Enrolled): Promise<Uint8Array> {
  const mk = masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams);
  return open(await wrapKey(mk), fromB64(e.keys.wrappedUvk), adUvk(e.userId));
}
async function seedOf(e: Enrolled): Promise<Uint8Array> {
  return open(await uvkOf(e), fromB64(e.keys.encryptedIdentitySeed), adIdkey(e.userId));
}

class FakeServer {
  feed: SyncResponse;
  selfWraps: { vaultId: string; wrappedVk: string }[] = [];
  adds: { vaultId: string; body: VaultMemberAdd }[] = [];
  reissues: { vaultId: string; userId: string; signedGrant: string }[] = [];
  identities: Record<string, UserLookupResponse> = {};
  members: Record<string, VaultMemberSummary[]> = {};
  accountStateBlob: string | null = null;
  accountSeq = 0;
  /** A7 review: answer the next delta pull with 410, forcing a since=0 resync. */
  resyncOnce = false;
  leaves: string[] = [];
  constructor(feed: SyncResponse) {
    this.feed = feed;
  }
  async leaveVault(vaultId: string) {
    this.leaves.push(vaultId);
    return { rev: this.feed.rev + 1 };
  }
  async sync(since: number): Promise<SyncResponse> {
    if (this.resyncOnce && since > 0) {
      this.resyncOnce = false;
      throw new ApiError(410, "resync_required", "gone");
    }
    if (since === 0) return this.feed;
    if (since < this.feed.rev) return { ...this.feed, full: false };
    return { rev: this.feed.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
  }
  async push(): Promise<PushResponse> {
    return { rev: this.feed.rev, results: [] };
  }
  async accountState() {
    return { sealedState: this.accountStateBlob, seq: this.accountSeq };
  }
  async putAccountState(sealedState: string, baseSeq: number) {
    if (baseSeq !== this.accountSeq) throw new ApiError(409, "stale_state", "stale");
    this.accountStateBlob = sealedState;
    this.accountSeq += 1;
    return { sealedState, seq: this.accountSeq };
  }
  async userIdentity(userId: string) {
    const u = this.identities[userId];
    if (!u) throw new ApiError(404, "not_found", "no");
    return u;
  }
  async vaultMembers(vaultId: string) {
    return this.members[vaultId] ?? [];
  }
  async addVaultMember(vaultId: string, body: VaultMemberAdd) {
    this.adds.push({ vaultId, body });
    return { rev: this.feed.rev + 1 };
  }
  async reissueGrant(vaultId: string, userId: string, body: { signedGrant: string }) {
    this.reissues.push({ vaultId, userId, signedGrant: body.signedGrant });
    return { rev: this.feed.rev + 1 };
  }
  async putGrantSelfWrap(vaultId: string, body: { wrappedVk: string }) {
    this.selfWraps.push({ vaultId, wrappedVk: body.wrappedVk });
    return { rev: this.feed.rev + 1 };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

interface World {
  owner: Enrolled;
  member: Enrolled;
  vaultId: string;
  metaBlob: string;
  ownerWrap: string;
  vk: Uint8Array;
}

async function world(): Promise<World> {
  const owner = await enroll("a6-owner");
  const member = await enroll("a6-member");
  const shared = owner.account.buildCreateSharedVault("Household");
  const vk = open(await uvkOf(owner), fromB64(shared.request.wrappedVk), adVk(shared.vaultId, owner.userId));
  return { owner, member, vaultId: shared.vaultId, metaBlob: shared.request.metaBlob, ownerWrap: shared.request.wrappedVk, vk };
}

const served = (e: Enrolled, name: string): UserLookupResponse => ({ userId: e.userId, displayName: name, identityPub: e.identityPub });
const pinOf = (e: Enrolled, label: string): Contact => ({ userId: e.userId, identityPub: e.identityPub, label, verifiedAt: 1000, method: "typed" });
const personalRow = (e: Enrolled): WireVault => ({ vaultId: e.personalVaultId, type: "personal", rev: 2, metaBlob: e.personalMeta, createdAt: 0 });
const personalGrant = (e: Enrolled): WireGrant => ({ vaultId: e.personalVaultId, userId: e.userId, role: "owner", wrappedVk: e.personalWrappedVk, rev: 2, sealedVk: null });
const sharedRow = (w: World, rev = 3): WireVault => ({ vaultId: w.vaultId, type: "shared", rev, metaBlob: w.metaBlob, createdAt: 0 });

function feed(w: World, rev: number, grant: WireGrant | null, items: WireItem[] = []): SyncResponse {
  return {
    rev, full: true,
    vaults: grant ? [personalRow(w.member), sharedRow(w)] : [personalRow(w.member)],
    grants: grant ? [personalGrant(w.member), grant] : [personalGrant(w.member)],
    items, removedGrants: [],
  };
}

const v1Seal = (w: World) => toB64(sealSharedGrant(fromB64(w.member.identityPub), w.vaultId, w.vk));
const ownerSigned = (w: World) => w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"));
const memberRow = (w: World, rev: number, sealedVk: string | null, signedGrant: string | null): WireGrant => ({ vaultId: w.vaultId, userId: w.member.userId, role: "writer", wrappedVk: "", rev, sealedVk, signedGrant });

async function opensTo(e: Enrolled, wrap: string, vaultId: string): Promise<Uint8Array> {
  return open(await uvkOf(e), fromB64(wrap), adVk(vaultId, e.userId));
}

describe("A6 — signed grants (VaultStore)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  it("a verified grant from a pinned owner is adopted, named, and self-wrapped once", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 5, null));
    const device = await unlock(w.member);
    const store = new VaultStore(server.asClient(), device, undefined, memoryClientState());
    await store.sync();
    expect(await store.verifyMemberTyped(served(w.owner, "Owner"), await w.owner.account.identityFingerprintShort())).not.toBeNull();

    server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSigned(w)));
    await store.sync();
    expect(device.hasVault(w.vaultId)).toBe(true);
    expect(device.keySource(w.vaultId)).toBe("signed-grant");
    expect(device.isLegacyReadOnly(w.vaultId)).toBe(false);
    const added = store.notices().filter((n) => n.vaultId === w.vaultId);
    expect(added.map((n) => n.kind)).toEqual(["added"]);
    expect(added[0]!.vaultName).toBe("Household");
    expect(added[0]!.byLabel).toBe("Owner");
    expect(server.selfWraps).toHaveLength(1);
    expect(toB64(await opensTo(w.member, server.selfWraps[0]!.wrappedVk, w.vaultId))).toBe(toB64(w.vk));
    await store.sync();
    expect(server.selfWraps).toHaveLength(1);
  });

  it("a grant naming the owner but signed by another pinned member is refused, with no v1 fallback", async () => {
    const w = await world();
    const mallorySeed = randomBytes(32);
    const malloryBox = boxKeypairFromSeed(mallorySeed);
    const mallorySign = signKeypairFromSeed(mallorySeed);
    const malloryId = "33333333-3333-4333-8333-333333333333";
    const server = new FakeServer(feed(w, 5, null));
    const device = await unlock(w.member);
    const store = new VaultStore(server.asClient(), device, undefined, memoryClientState());
    await store.sync();
    await store.accountState.pin(pinOf(w.owner, "Owner"));
    await store.accountState.pin({ userId: malloryId, identityPub: toB64(malloryBox.publicKey), label: "Mallory", verifiedAt: 1000, method: "typed" });

    const serverVk = randomBytes(32);
    const forged = buildGrantFrame(mallorySign, {
      purpose: "vault-grant", from: w.owner.userId, to: w.member.userId, toKey: fromB64(w.member.identityPub), vaultId: w.vaultId,
      grantId: randomBytes(16), issuedAt: 1_791_590_400_000, vk: serverVk,
    });
    const sealed = toB64(sealTo(fromB64(w.member.identityPub), forged));
    const v1Forged = toB64(sealSharedGrant(fromB64(w.member.identityPub), w.vaultId, serverVk));
    server.feed = feed(w, 9, memberRow(w, 9, v1Forged, sealed));
    await store.sync();
    expect(device.hasVault(w.vaultId)).toBe(false);
    const n = store.notices().filter((x) => x.vaultId === w.vaultId && x.kind === "grant-anomaly");
    expect(n.map((x) => x.reason)).toEqual(["signer_not_pinned_key"]);
    expect(store.pendingInvitations()).toEqual([]);
    expect(server.selfWraps).toEqual([]);
  });

  it("a grant whose signer is not the pinned key of the named sender is refused", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 5, null));
    const device = await unlock(w.member);
    const store = new VaultStore(server.asClient(), device, undefined, memoryClientState());
    await store.sync();
    const other = boxKeypairFromSeed(randomBytes(32));
    await store.accountState.pin({ userId: w.owner.userId, identityPub: toB64(other.publicKey), label: "Owner", verifiedAt: 1000, method: "typed" });
    server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSigned(w)));
    await store.sync();
    expect(device.hasVault(w.vaultId)).toBe(false);
    expect(store.notices().filter((x) => x.kind === "grant-anomaly").map((x) => x.reason)).toEqual(["signer_not_pinned_key"]);
    expect(server.selfWraps).toEqual([]);
  });

  it("an unpinned sender is a pending invitation; accepting runs the ceremony then §1.4", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSigned(w))));
    server.identities[w.owner.userId] = served(w.owner, "Owner (server)");
    const device = await unlock(w.member);
    const store = new VaultStore(server.asClient(), device, undefined, memoryClientState());
    await store.sync();
    expect(device.hasVault(w.vaultId)).toBe(false); // the dual-sent v1 seal is not used instead
    expect(store.vaults().some((v) => v.vaultId === w.vaultId)).toBe(false);
    const inv = store.pendingInvitations();
    expect(inv).toHaveLength(1);
    expect(inv[0]!.vaultId).toBe(w.vaultId);
    expect(inv[0]!.fromUserId).toBe(w.owner.userId);
    expect(server.selfWraps).toEqual([]);

    expect(await store.acceptInvitation(inv[0]!, "0000 0000 0000 0000 0000 0000 0000 0000")).toBe(false);
    expect(device.hasVault(w.vaultId)).toBe(false);
    expect(await store.acceptInvitation(inv[0]!, await w.owner.account.identityFingerprintShort())).toBe(true);
    expect(device.hasVault(w.vaultId)).toBe(true);
    expect(device.keySource(w.vaultId)).toBe("signed-grant");
    expect(store.pendingInvitations()).toEqual([]);
    await store.sync();
    expect(server.selfWraps).toHaveLength(1);
  });

  it("a declined invitation stays hidden across a restart", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, null, ownerSigned(w))));
    const local = memoryClientState();
    const cache = (await openVaultCache(w.member.userId)) as IdbVaultCache;
    const store = new VaultStore(server.asClient(), await unlock(w.member), cache, local);
    await store.sync();
    store.declineInvitation(store.pendingInvitations()[0]!);
    expect(store.pendingInvitations()).toEqual([]);
    const again = new VaultStore(server.asClient(), await unlock(w.member), (await openVaultCache(w.member.userId)) as IdbVaultCache, local);
    await again.hydrate();
    await again.sync();
    expect(again.pendingInvitations()).toEqual([]);
  });

  it("a v1-only key is read-only and self-wrapped only after the human confirms", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)));
    const device = await unlock(w.member);
    const store = new VaultStore(server.asClient(), device, undefined, memoryClientState());
    await store.hydrate();
    await store.sync();
    await store.sync();
    expect(device.hasVault(w.vaultId)).toBe(true);
    expect(device.keySource(w.vaultId)).toBe("legacy-seal");
    expect(device.isLegacyReadOnly(w.vaultId)).toBe(true);
    expect(device.roleFor(w.vaultId)).toBe("reader");
    expect(() => device.encryptItem(w.vaultId, device.newItemId(), { type: "login", name: "x" })).toThrow(VaultKeyNotVerifiedError);
    expect(server.selfWraps).toEqual([]);
    const review = store.legacyReviewVaults();
    expect(review.map((r) => r.vaultId)).toEqual([w.vaultId]);
    expect(review[0]!.name).toBe("Household");

    await store.acceptLegacyVault(w.vaultId);
    expect(server.selfWraps).toHaveLength(1);
    expect(device.isLegacyReadOnly(w.vaultId)).toBe(false);
    expect(store.legacyReviewVaults()).toEqual([]);
  });

  it("pre-upgrade evidence in the durable cache freezes the key, but a later v1 grant does not", async () => {
    const w = await world();
    const itemId = w.owner.account.newItemId();
    const up = w.owner.account.encryptItem(w.vaultId, itemId, { type: "login", name: "wifi" });
    const item: WireItem = { itemId, vaultId: w.vaultId, rev: 4, createdAt: 1, updatedAt: 1, deleted: false, conflict: false, formatVersion: up.formatVersion, attachmentIds: [], blob: up.blob };
    // What a pre-A6 browser left on disk: the v1 row and an item that decrypted under it, and NO freeze marker
    // (an A6 store writes the marker into this cache before its first pull, so the rows are written directly).
    const oldCache = (await openVaultCache(w.member.userId)) as IdbVaultCache;
    await oldCache.applyPull((b) => {
      b.upsertGrant(personalGrant(w.member));
      b.upsertVault(personalRow(w.member));
      b.upsertGrant(memberRow(w, 4, v1Seal(w), null));
      b.upsertVault(sharedRow(w));
      b.upsertItem(item);
      b.setCursor(4);
    });

    // A second shared vault that a v1 grant delivers only AFTER the upgrade.
    const later = w.owner.account.buildCreateSharedVault("Later");
    const laterVk = open(await uvkOf(w.owner), fromB64(later.request.wrappedVk), adVk(later.vaultId, w.owner.userId));
    const laterRow: WireGrant = { vaultId: later.vaultId, userId: w.member.userId, role: "writer", wrappedVk: "", rev: 8, sealedVk: toB64(sealSharedGrant(fromB64(w.member.identityPub), later.vaultId, laterVk)) };
    const server = new FakeServer({ rev: 8, full: false, vaults: [{ vaultId: later.vaultId, type: "shared", rev: 8, metaBlob: later.request.metaBlob, createdAt: 0 }], grants: [laterRow], items: [], removedGrants: [] });
    const device = await unlock(w.member);
    // Fresh client state (no freeze marker yet) over the cache the old client wrote: this release's first run.
    const store = new VaultStore(server.asClient(), device, (await openVaultCache(w.member.userId)) as IdbVaultCache, memoryClientState());
    await store.hydrate();
    await store.sync();
    expect(server.selfWraps.map((s) => s.vaultId)).toEqual([w.vaultId]);
    expect(device.isLegacyReadOnly(w.vaultId)).toBe(false);
    expect(device.isLegacyReadOnly(later.vaultId)).toBe(true);
    expect(store.legacyReviewVaults().map((r) => r.vaultId)).toEqual([later.vaultId]);
  });

  it("a pin a fresh device learned from an older blob cannot skip verification (A5 review L-3)", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 5, null));
    const a = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await a.sync();
    await a.accountState.pin(pinOf(w.owner, "Owner"));
    const olderBlob = server.accountStateBlob;
    const olderSeq = server.accountSeq;
    await a.accountState.unpin(w.owner.userId);
    server.accountStateBlob = olderBlob;
    server.accountSeq = olderSeq;

    server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSigned(w)));
    const bAccount = await unlock(w.member);
    const b = new VaultStore(server.asClient(), bAccount, undefined, memoryClientState());
    await b.sync();
    expect(b.accountState.doc.contacts.some((c) => c.userId === w.owner.userId)).toBe(true);
    expect(b.accountState.currentPin(w.owner.userId)).toBeNull();
    expect(bAccount.hasVault(w.vaultId)).toBe(false);
    expect(b.pendingInvitations().map((i) => i.fromUserId)).toEqual([w.owner.userId]);
    expect(b.memberPinState(w.owner.userId, w.owner.identityPub)).toBe("needs-verification");
    await b.sync();
    expect(bAccount.hasVault(w.vaultId)).toBe(false);

    expect(await b.verifyMemberTyped(served(w.owner, "Owner"), await w.owner.account.identityFingerprintShort())).not.toBeNull();
    await b.sync();
    expect(bAccount.hasVault(w.vaultId)).toBe(true);
  });

  it("MED-1 (d): a pin added on another device is NOT current here until verified here", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 5, null));
    const b = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await b.sync();
    await b.accountState.pin({ userId: "44444444-4444-4444-8444-444444444444", identityPub: toB64(randomBytes(32)), label: "Someone", verifiedAt: 1, method: "typed" });
    const a = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await a.sync();
    await a.accountState.pin(pinOf(w.owner, "Owner"));
    await b.sync();
    expect(b.accountState.doc.contacts.some((c) => c.userId === w.owner.userId)).toBe(true);
    expect(b.accountState.currentPin(w.owner.userId)).toBeNull();
    expect(await b.verifyMemberTyped(served(w.owner, "Owner"), await w.owner.account.identityFingerprintShort())).not.toBeNull();
    expect(b.accountState.currentPin(w.owner.userId)).not.toBeNull();
  });

  it("the owner grants only to a pinned member, sealed to the pin key", async () => {
    const w = await world();
    const server = new FakeServer({
      rev: 5, full: true, vaults: [personalRow(w.owner), sharedRow(w)],
      grants: [personalGrant(w.owner), { vaultId: w.vaultId, userId: w.owner.userId, role: "owner", wrappedVk: w.ownerWrap, rev: 3, sealedVk: null }], items: [], removedGrants: [],
    });
    const store = new VaultStore(server.asClient(), await unlock(w.owner), undefined, memoryClientState());
    await store.sync();
    // A6b: the owner's own evidence of ownership (seeded directly here; in the app: the creation record, a transfer
    // accept, or the password-reauthed "You own <vault>?").
    await expect(store.addVaultMember(w.vaultId, w.member.userId, "writer")).rejects.toBeInstanceOf(OwnershipNotConfirmedError);
    await store.accountState.update((d) => withOwned(d, w.vaultId, 1));
    await expect(store.addVaultMember(w.vaultId, w.member.userId, "writer")).rejects.toBeInstanceOf(MemberNotVerifiedError);
    expect(server.adds).toEqual([]);

    await store.accountState.pin(pinOf(w.member, "Member"));
    expect(store.memberPinState(w.member.userId, w.member.identityPub)).toBe("pinned");
    expect(store.memberPinState(w.member.userId, toB64(randomBytes(32)))).toBe("key-changed");

    await store.addVaultMember(w.vaultId, w.member.userId, "writer");
    expect(server.adds).toHaveLength(1);
    const add = server.adds[0]!.body;
    const me = boxKeypairFromSeed(await seedOf(w.member));
    const opened = openSignedGrant({
      myUserId: w.member.userId, myIdentityPub: me.publicKey, myIdentityPriv: me.privateKey, rowVaultId: w.vaultId, sealed: fromB64(add.signedGrant!),
      pinFor: (uid) => (uid === w.owner.userId ? { identityPub: fromB64(w.owner.identityPub), current: true } : null), heldVk: null,
    });
    if (opened.verdict !== "adopt") throw new Error(opened.verdict);
    expect(toB64(opened.vk)).toBe(toB64(w.vk));
    expect(toB64(openSharedGrant(me.publicKey, me.privateKey, w.vaultId, fromB64(add.sealedVk)))).toBe(toB64(w.vk));
  });

  it("the owner re-issues legacy grants only on confirmation and lists the rest", async () => {
    const w = await world();
    const unpinned = await enroll("a6-unpinned");
    const server = new FakeServer({
      rev: 5, full: true, vaults: [personalRow(w.owner), sharedRow(w)],
      grants: [personalGrant(w.owner), { vaultId: w.vaultId, userId: w.owner.userId, role: "owner", wrappedVk: w.ownerWrap, rev: 3, sealedVk: null }], items: [], removedGrants: [],
    });
    server.members[w.vaultId] = [
      { userId: w.owner.userId, email: "o@example.com", displayName: "Owner", role: "owner", identityPub: w.owner.identityPub, addedAt: 0 },
      { userId: w.member.userId, email: "m@example.com", displayName: "Member", role: "writer", identityPub: w.member.identityPub, addedAt: 0, legacyGrant: true },
      { userId: unpinned.userId, email: "u@example.com", displayName: "Unpinned", role: "reader", identityPub: unpinned.identityPub, addedAt: 0, legacyGrant: true },
    ];
    const store = new VaultStore(server.asClient(), await unlock(w.owner), undefined, memoryClientState());
    await store.sync();
    await store.accountState.update((d) => withOwned(d, w.vaultId, 1)); // A6b: ownership evidence (see above)
    await store.accountState.pin(pinOf(w.member, "Member"));
    await store.sync();
    expect(server.reissues, "A6b: sync() never re-issues").toEqual([]);
    const rows = await store.loadLegacyGrants(w.vaultId);
    expect(rows.map((r) => r.userId).sort()).toEqual([w.member.userId, unpinned.userId].sort());
    expect(server.reissues, "listing signs nothing for an unrecorded pair").toEqual([]);
    await expect(store.confirmReissue(rows.find((r) => r.userId === unpinned.userId)!)).rejects.toBeInstanceOf(MemberNotVerifiedError);
    await store.confirmReissue(rows.find((r) => r.userId === w.member.userId)!);
    expect(server.reissues.map((r) => [r.vaultId, r.userId])).toEqual([[w.vaultId, w.member.userId]]);
    const me = boxKeypairFromSeed(await seedOf(w.member));
    const opened = openSignedGrant({
      myUserId: w.member.userId, myIdentityPub: me.publicKey, myIdentityPriv: me.privateKey, rowVaultId: w.vaultId, sealed: fromB64(server.reissues[0]!.signedGrant),
      pinFor: (uid) => (uid === w.owner.userId ? { identityPub: fromB64(w.owner.identityPub), current: true } : null), heldVk: w.vk,
    });
    expect(opened.verdict).toBe("adopt");
    expect(store.legacyGrantRows(w.vaultId).map((m) => m.userId)).toEqual([unpinned.userId]);
    expect(store.legacyGrantRows(w.vaultId)[0]!.pinState).toBe("needs-verification");
    await store.sync();
    expect(server.reissues).toHaveLength(1);
  });
});

describe("A5b review LOW-1 (carried into A6): Use new only after the co-holders loaded", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("acceptPersonalChange is refused until describePersonalChange succeeded", async () => {
    const victim = await enroll("low1");
    const mate = await enroll("low1-mate");
    const shared = victim.account.buildCreateSharedVault("Household");
    const rows: SyncResponse = {
      rev: 9, full: true,
      vaults: [personalRow(victim), { vaultId: shared.vaultId, type: "shared", rev: 3, metaBlob: shared.request.metaBlob, createdAt: 0 }],
      grants: [personalGrant(victim), { vaultId: shared.vaultId, userId: victim.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 3, sealedVk: null }],
      items: [], removedGrants: [],
    };
    const sharedWrap = victim.account.buildPersonalWrap(shared.vaultId);
    const local = memoryClientState();
    const s1 = new VaultStore(new FakeServer(rows).asClient(), await Account.unlock(victim.userId, victim.password, victim.keys), undefined, local);
    await s1.sync();
    await s1.describePersonalChange();
    s1.acceptPersonalChange(); // A9 (M-2): confirmed once on a device with no designation on record

    const again = await Account.unlock(victim.userId, victim.password, { ...victim.keys, personalWrap: sharedWrap });
    const failing = new FakeServer(rows);
    failing.vaultMembers = async () => {
      throw new ApiError(503, "unavailable", "no");
    };
    const store = new VaultStore(failing.asClient(), again, undefined, local);
    await store.sync();
    expect(again.personalStatus).toBe("changed");
    await expect(store.describePersonalChange()).rejects.toBeTruthy();
    expect(() => store.acceptPersonalChange()).toThrow();
    expect(again.personalVaultId).toBe(victim.personalVaultId);

    const ok = new FakeServer(rows);
    ok.members[shared.vaultId] = [{ userId: mate.userId, email: "mate@example.com", displayName: "Mate", role: "writer", identityPub: mate.identityPub, addedAt: 0 }];
    const store2 = new VaultStore(ok.asClient(), again, undefined, local);
    const d = await store2.describePersonalChange();
    expect(d.servedVaultId).toBe(shared.vaultId);
    expect(d.currentVaultId).toBe(victim.personalVaultId);
    expect(d.servedCoHolders.map((c) => c.displayName)).toEqual(["Mate"]);
    store2.acceptPersonalChange();
    expect(again.personalVaultId).toBe(shared.vaultId);
  });
});

// ---- A6 fix round (adversarial review): the vouch is bound to the key; pin currency is a per-device human
// confirmation; a v2 grant never silently replaces a legacy-held key; a present-but-bad v2 field is an anomaly;
// the freeze marker lives with the durable cache. ----

async function signedFor(w: World, vk: Uint8Array): Promise<string> {
  const signer = signKeypairFromSeed(await seedOf(w.owner));
  const frame = buildGrantFrame(signer, {
    purpose: "vault-grant", from: w.owner.userId, to: w.member.userId, toKey: fromB64(w.member.identityPub), vaultId: w.vaultId,
    grantId: randomBytes(16), issuedAt: 1_791_590_400_000, vk,
  });
  return toB64(sealTo(fromB64(w.member.identityPub), frame));
}
const v1SealOf = (w: World, vk: Uint8Array) => toB64(sealSharedGrant(fromB64(w.member.identityPub), w.vaultId, vk));

describe("A6 fix round", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  it("HIGH-1: a vouch covers only the key it was given for", async () => {
    const w = await world();
    const local = memoryClientState();
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)));
    const s1 = new VaultStore(server.asClient(), await unlock(w.member), undefined, local);
    await s1.sync();
    await s1.acceptLegacyVault(w.vaultId);
    expect(server.selfWraps).toHaveLength(1);
    const lines = (local.get("grant.legacy.authorized") ?? "").split("\n");
    expect(lines).toHaveLength(1);
    expect(lines[0]!.split("|")).toEqual([w.vaultId, expect.stringMatching(/^[0-9a-f]{64}$/), "confirmed"]);

    // A fresh store sharing the client state; the server now serves ANOTHER v1 key for the same vault.
    const forgedVk = randomBytes(32);
    const server2 = new FakeServer(feed(w, 9, memberRow(w, 9, v1SealOf(w, forgedVk), null)));
    const d2 = await unlock(w.member);
    const s2 = new VaultStore(server2.asClient(), d2, undefined, local);
    await s2.sync();
    // Round 3 (the vouch gate): the swapped-in key is not even held read-only; it is refused as vk_mismatch.
    expect(d2.hasVault(w.vaultId)).toBe(false);
    expect(d2.grantAnomalies().get(w.vaultId)).toBe("vk_mismatch");
    expect(server2.selfWraps).toEqual([]);
  });

  it("HIGH-1: the vouch restores from persisted state on reload; a line with no tag is ignored", async () => {
    const w = await world();
    const local = memoryClientState();
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)));
    const s1 = new VaultStore(server.asClient(), await unlock(w.member), undefined, local);
    await s1.sync();
    await s1.acceptLegacyVault(w.vaultId);
    const d2 = await unlock(w.member);
    await new VaultStore(new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null))).asClient(), d2, undefined, local).sync();
    expect(d2.isLegacyReadOnly(w.vaultId)).toBe(false);
    expect(() => d2.encryptItem(w.vaultId, d2.newItemId(), { type: "login", name: "x" })).not.toThrow();

    const bare = memoryClientState();
    bare.set("grant.legacy.authorized", w.vaultId);
    const d3 = await unlock(w.member);
    await new VaultStore(new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null))).asClient(), d3, undefined, bare).sync();
    expect(d3.isLegacyReadOnly(w.vaultId)).toBe(true);
  });

  it("LOW-3: the freeze vouches with kind frozen", async () => {
    const w = await world();
    const itemId = w.owner.account.newItemId();
    const up = w.owner.account.encryptItem(w.vaultId, itemId, { type: "login", name: "wifi" });
    const item: WireItem = { itemId, vaultId: w.vaultId, rev: 4, createdAt: 1, updatedAt: 1, deleted: false, conflict: false, formatVersion: up.formatVersion, attachmentIds: [], blob: up.blob };
    // A pre-A6 browser's cache: written WITHOUT any freeze marker (simulated by the old rows alone).
    const cache = (await openVaultCache(w.member.userId)) as IdbVaultCache;
    await cache.applyPull((b) => {
      b.upsertGrant(memberRow(w, 4, v1Seal(w), null));
      b.upsertVault(sharedRow(w));
      b.upsertItem(item);
      b.setCursor(4);
    });
    const local = memoryClientState();
    const server = new FakeServer({ rev: 4, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
    const store = new VaultStore(server.asClient(), await unlock(w.member), (await openVaultCache(w.member.userId)) as IdbVaultCache, local);
    await store.hydrate();
    await store.sync();
    expect(server.selfWraps.map((x) => x.vaultId)).toEqual([w.vaultId]);
    expect((local.get("grant.legacy.authorized") ?? "").split("|")[2]).toBe("frozen");
  });

  it("LOW-1: with the durable cache present and localStorage cleared, freeze evidence is not recomputed", async () => {
    const w = await world();
    const itemId = w.owner.account.newItemId();
    const up = w.owner.account.encryptItem(w.vaultId, itemId, { type: "login", name: "wifi" });
    const item: WireItem = { itemId, vaultId: w.vaultId, rev: 4, createdAt: 1, updatedAt: 1, deleted: false, conflict: false, formatVersion: up.formatVersion, attachmentIds: [], blob: up.blob };
    // THIS release pulls the v1 grant (post-upgrade rows): never evidence.
    const s1 = new VaultStore(new FakeServer(feed(w, 4, memberRow(w, 4, v1Seal(w), null), [item])).asClient(), await unlock(w.member), (await openVaultCache(w.member.userId)) as IdbVaultCache, memoryClientState());
    await s1.hydrate();
    await s1.sync();
    // localStorage cleared (fresh client state); the IndexedDB cache survives.
    const server = new FakeServer({ rev: 4, full: false, vaults: [], grants: [], items: [], removedGrants: [] });
    const d = await unlock(w.member);
    const s2 = new VaultStore(server.asClient(), d, (await openVaultCache(w.member.userId)) as IdbVaultCache, memoryClientState());
    await s2.hydrate();
    await s2.sync();
    expect(server.selfWraps).toEqual([]);
    expect(d.isLegacyReadOnly(w.vaultId)).toBe(true);
  });

  it("MED-1 (a): an ascending replay of two older blobs that carry a later-tombstoned pin leaves it NOT current", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 5, null));
    const a = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await a.sync();
    await a.accountState.pin(pinOf(w.owner, "Owner"));
    const blob1 = { s: server.accountStateBlob, q: server.accountSeq };
    await a.accountState.pin({ userId: "55555555-5555-4555-8555-555555555555", identityPub: toB64(randomBytes(32)), label: "X", verifiedAt: 2, method: "typed" });
    const blob2 = { s: server.accountStateBlob, q: server.accountSeq };
    await a.accountState.unpin(w.owner.userId);

    const b = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    server.accountStateBlob = blob1.s;
    server.accountSeq = blob1.q;
    await b.sync();
    server.accountStateBlob = blob2.s;
    server.accountSeq = blob2.q;
    await b.sync();
    expect(b.accountState.doc.contacts.some((c) => c.userId === w.owner.userId)).toBe(true);
    expect(b.accountState.currentPin(w.owner.userId)).toBeNull();
  });

  it("MED-1 (b)/(c): a pin confirmed here is current; a confirmation of a DIFFERENT key for the same user is not", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 5, null));
    const b = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await b.sync();
    await b.accountState.pin(pinOf(w.owner, "Owner"));
    expect(b.accountState.currentPin(w.owner.userId)).not.toBeNull();
    // Another device re-pins the owner with ANOTHER key (newer); this device only confirmed the first one.
    const a = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await a.sync();
    await a.accountState.pin({ userId: w.owner.userId, identityPub: toB64(randomBytes(32)), label: "Owner?", verifiedAt: 5000, method: "typed" });
    await b.sync();
    expect(b.accountState.doc.contacts.find((c) => c.userId === w.owner.userId)!.identityPub).not.toBe(w.owner.identityPub);
    expect(b.accountState.currentPin(w.owner.userId)).toBeNull();
  });

  it("MED-2: a vouched legacy key + a v2 grant with a DIFFERENT key → anomaly, held key kept, still writable", async () => {
    const w = await world();
    const local = memoryClientState();
    const server = new FakeServer(feed(w, 5, null));
    const d = await unlock(w.member);
    const store = new VaultStore(server.asClient(), d, undefined, local);
    await store.sync();
    await store.accountState.pin(pinOf(w.owner, "Owner"));
    server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), null));
    await store.sync();
    await store.acceptLegacyVault(w.vaultId);
    server.feed = feed(w, 12, memberRow(w, 12, v1Seal(w), await signedFor(w, randomBytes(32))));
    await store.sync();
    expect(store.notices().filter((n) => n.kind === "grant-anomaly").map((n) => n.reason)).toEqual(["vk_mismatch"]);
    expect(d.keySource(w.vaultId)).toBe("legacy-seal");
    expect(d.decryptVaultName(w.vaultId, w.metaBlob)).toBe("Household");
    expect(d.isLegacyReadOnly(w.vaultId)).toBe(false);
  });

  it("MED-2: an UNVOUCHED legacy key + a different-key v2 → anomaly, still read-only, key unchanged", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 5, null));
    const d = await unlock(w.member);
    const store = new VaultStore(server.asClient(), d, undefined, memoryClientState());
    await store.sync();
    await store.accountState.pin(pinOf(w.owner, "Owner"));
    server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), null));
    await store.sync();
    server.feed = feed(w, 12, memberRow(w, 12, v1Seal(w), await signedFor(w, randomBytes(32))));
    await store.sync();
    expect(store.notices().filter((n) => n.kind === "grant-anomaly").map((n) => n.reason)).toEqual(["vk_mismatch"]);
    expect(d.keySource(w.vaultId)).toBe("legacy-seal");
    expect(d.isLegacyReadOnly(w.vaultId)).toBe(true);
    expect(d.decryptVaultName(w.vaultId, w.metaBlob)).toBe("Household");
  });

  it("MED-2: cold start with a vouch — the vouched v1 key wins over a different-key v2, flagged", async () => {
    const w = await world();
    const local = memoryClientState();
    const s1 = new VaultStore(new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null))).asClient(), await unlock(w.member), undefined, local);
    await s1.sync();
    await s1.acceptLegacyVault(w.vaultId);
    await s1.accountState.pin(pinOf(w.owner, "Owner"));
    // Persist the pin server-side for the next device-state-sharing store: same client state, so it is confirmed.
    const server = new FakeServer(feed(w, 12, memberRow(w, 12, v1Seal(w), await signedFor(w, randomBytes(32)))));
    server.accountStateBlob = (s1 as unknown as { api: FakeServer }).api.accountStateBlob;
    server.accountSeq = (s1 as unknown as { api: FakeServer }).api.accountSeq;
    const d = await unlock(w.member);
    const s2 = new VaultStore(server.asClient(), d, undefined, local);
    await s2.sync();
    expect(d.keySource(w.vaultId)).toBe("legacy-seal");
    expect(d.decryptVaultName(w.vaultId, w.metaBlob)).toBe("Household");
    expect(d.isLegacyReadOnly(w.vaultId)).toBe(false);
    expect(s2.notices().filter((n) => n.kind === "grant-anomaly").map((n) => n.reason)).toEqual(["vk_mismatch"]);
  });

  it("round 2 MEDIUM-A: a vouch + STRIPPED seal + a v2 grant with a DIFFERENT key → refused, never adopted", async () => {
    const w = await world();
    const local = memoryClientState();
    const s1 = new VaultStore(new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null))).asClient(), await unlock(w.member), undefined, local);
    await s1.sync();
    await s1.acceptLegacyVault(w.vaultId);
    await s1.accountState.pin(pinOf(w.owner, "Owner"));
    const server = new FakeServer(feed(w, 12, memberRow(w, 12, null, await signedFor(w, randomBytes(32)))));
    server.accountStateBlob = (s1 as unknown as { api: FakeServer }).api.accountStateBlob;
    server.accountSeq = (s1 as unknown as { api: FakeServer }).api.accountSeq;
    const d = await unlock(w.member);
    const s2 = new VaultStore(server.asClient(), d, undefined, local);
    await s2.sync();
    expect(d.hasVault(w.vaultId)).toBe(false);
    expect(s2.notices().filter((n) => n.kind === "grant-anomaly").map((n) => n.reason)).toEqual(["vk_mismatch"]);
    expect(server.selfWraps).toEqual([]);
  });

  it("round 2 MEDIUM-A: a vouch + STRIPPED seal + a v2 grant with the SAME key → adopted normally", async () => {
    const w = await world();
    const local = memoryClientState();
    const s1 = new VaultStore(new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null))).asClient(), await unlock(w.member), undefined, local);
    await s1.sync();
    await s1.acceptLegacyVault(w.vaultId);
    await s1.accountState.pin(pinOf(w.owner, "Owner"));
    const server = new FakeServer(feed(w, 12, memberRow(w, 12, null, await signedFor(w, w.vk))));
    server.accountStateBlob = (s1 as unknown as { api: FakeServer }).api.accountStateBlob;
    server.accountSeq = (s1 as unknown as { api: FakeServer }).api.accountSeq;
    const d = await unlock(w.member);
    const s2 = new VaultStore(server.asClient(), d, undefined, local);
    await s2.sync();
    expect(d.keySource(w.vaultId)).toBe("signed-grant");
    expect(s2.notices().filter((n) => n.kind === "grant-anomaly")).toEqual([]);
  });

  it("round 2 LOW-A: re-confirming a user replaces this device's earlier confirmation (core recordConfirmed parity)", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 5, null));
    const b = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await b.sync();
    const oldKey = toB64(randomBytes(32));
    await b.accountState.pin({ userId: w.owner.userId, identityPub: oldKey, label: "Owner", verifiedAt: 1000, method: "typed" });
    await b.accountState.pin({ ...pinOf(w.owner, "Owner"), verifiedAt: 2000 });
    // Another device later re-pins the OLD key: this device's confirmation of it was replaced, so it does not count.
    const a = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await a.sync();
    await a.accountState.pin({ userId: w.owner.userId, identityPub: oldKey, label: "Owner", verifiedAt: 3000, method: "typed" });
    await b.sync();
    expect(b.accountState.doc.contacts.find((c) => c.userId === w.owner.userId)!.identityPub).toBe(oldKey);
    expect(b.accountState.currentPin(w.owner.userId)).toBeNull();
  });

  it("LOW-2: a PRESENT but garbage v2 field is an anomaly with no v1 fallback and no review card", async () => {
    const w = await world();
    const garbage = toB64(randomBytes(200));
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), garbage)));
    const d = await unlock(w.member);
    const store = new VaultStore(server.asClient(), d, undefined, memoryClientState());
    await store.sync();
    expect(d.hasVault(w.vaultId)).toBe(false);
    expect(store.notices().filter((n) => n.kind === "grant-anomaly").map((n) => n.reason)).toEqual(["unopenable"]);
    expect(store.legacyReviewVaults()).toEqual([]);
    await expect(store.acceptLegacyVault(w.vaultId)).rejects.toBeTruthy();
    // An ABSENT field keeps the trust-on-first-use path.
    const w2 = await world();
    const s2 = new VaultStore(new FakeServer(feed(w2, 9, memberRow(w2, 9, v1Seal(w2), null))).asClient(), await unlock(w2.member), undefined, memoryClientState());
    await s2.sync();
    expect(s2.legacyReviewVaults().map((r) => r.vaultId)).toEqual([w2.vaultId]);
  });

  it("LOW-2: a garbage v2 arriving for a held legacy key is an anomaly and takes the vault off the review card", async () => {
    const w = await world();
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)));
    const d = await unlock(w.member);
    const store = new VaultStore(server.asClient(), d, undefined, memoryClientState());
    await store.sync();
    expect(store.legacyReviewVaults()).toHaveLength(1);
    server.feed = feed(w, 12, memberRow(w, 12, v1Seal(w), toB64(randomBytes(200))));
    await store.sync();
    expect(store.notices().filter((n) => n.kind === "grant-anomaly").map((n) => n.reason)).toEqual(["unopenable"]);
    expect(store.legacyReviewVaults()).toEqual([]);
    await expect(store.acceptLegacyVault(w.vaultId)).rejects.toBeTruthy();
  });
});

// ---- A6 re-review round 3: ONE vouch gate on every key-source path (core SignedGrantEngineTest twins) ----

async function signedBy(w: World, signer: Enrolled, vk: Uint8Array): Promise<string> {
  const frame = buildGrantFrame(signKeypairFromSeed(await seedOf(signer)), {
    purpose: "vault-grant", from: signer.userId, to: w.member.userId, toKey: fromB64(w.member.identityPub), vaultId: w.vaultId,
    grantId: randomBytes(16), issuedAt: 1_791_590_400_000, vk,
  });
  return toB64(sealTo(fromB64(w.member.identityPub), frame));
}
const sealFor = (w: World, vk: Uint8Array) => toB64(sealSharedGrant(fromB64(w.member.identityPub), w.vaultId, vk));
async function wrapFor(w: World, vk: Uint8Array): Promise<string> {
  return toB64(seal(await uvkOf(w.member), vk, adVk(w.vaultId, w.member.userId)));
}

/** A device that vouched for the real key K (Accept) and pinned the owner, restarted, then served [rows] in order. */
async function vouchedThenServe(w: World, rows: (WireGrant | null)[]): Promise<{ d: Account; store: VaultStore; server: FakeServer }> {
  const local = memoryClientState();
  const first = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)));
  const s1 = new VaultStore(first.asClient(), await unlock(w.member), undefined, local);
  await s1.sync();
  await s1.acceptLegacyVault(w.vaultId);
  await s1.accountState.pin(pinOf(w.owner, "Owner"));
  const server = new FakeServer(feed(w, 10, null));
  server.accountStateBlob = first.accountStateBlob;
  server.accountSeq = first.accountSeq;
  const d = await unlock(w.member);
  const store = new VaultStore(server.asClient(), d, undefined, local);
  let rev = 12;
  for (const row of rows) {
    server.feed = feed(w, rev, row ? { ...row, rev } : null);
    await store.sync();
    rev += 3;
  }
  return { d, store, server };
}

async function assertVouchHolds(w: World, kPrime: Uint8Array, d: Account, store: VaultStore, server: FakeServer, ruleTwo: boolean, label: string) {
  const heldIsKPrime = d.hasVault(w.vaultId) && d.legacyKeyTag(w.vaultId) === legacyTagOf(kPrime);
  if (ruleTwo) {
    expect(heldIsKPrime, `${label}: the UVK wrap is used (A1)`).toBe(true);
    expect(d.grantAnomalies().get(w.vaultId), `${label}: flagged`).toBe("vk_mismatch");
  } else {
    expect(heldIsKPrime, `${label}: K' never held`).toBe(false);
  }
  if (heldIsKPrime) {
    expect(d.selfWrapAuthorized(w.vaultId), `${label}: never self-wrapped`).toBe(false);
    expect(() => d.buildOwnerWrap(w.vaultId), `${label}: never owner-wrapped`).toThrow();
    // A6 final review LOW-G: nor signed onward to anyone.
    expect(() => d.buildSignedGrant(w.vaultId, pinOf(w.owner, "Owner")), `${label}: never signed onward`).toThrow();
  }
  for (const sw of server.selfWraps) {
    expect(toB64(await opensTo(w.member, sw.wrappedVk, w.vaultId)), `${label}: no self-wrap of K'`).not.toBe(toB64(kPrime));
  }
  expect(store.legacyReviewVaults().some((r) => r.vaultId === w.vaultId), `${label}: no Accept offer`).toBe(false);
  await expect(store.acceptLegacyVault(w.vaultId), `${label}: Accept refuses`).rejects.toBeTruthy();
}

describe("A6 re-review round 3 — the vouch gate", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  it("holds for every row shape, single-pull and two-pull", async () => {
    const third = await enroll("a6-unpinned-sender");
    const shapes: [string, (w: World, k: Uint8Array) => Promise<WireGrant | null>][] = [
      ["wrap", async (w, k) => ({ ...memberRow(w, 0, null, null), wrappedVk: await wrapFor(w, k) })],
      ["v2", async (w, k) => memberRow(w, 0, null, await signedBy(w, w.owner, k))],
      ["v2+seal", async (w, k) => memberRow(w, 0, sealFor(w, k), await signedBy(w, w.owner, k))],
      ["seal", async (w, k) => memberRow(w, 0, sealFor(w, k), null)],
      ["pending+seal", async (w, k) => memberRow(w, 0, sealFor(w, k), await signedBy(w, third, k))],
      ["broken+seal", async (w, k) => memberRow(w, 0, sealFor(w, k), toB64(randomBytes(200)))],
      ["absent", async () => null],
      // A6 final review LOW-G: the seal IS the vouched key K and the v2 grant carries K'.
      ["seal(K)+v2(K')", async (w, k) => memberRow(w, 0, sealFor(w, w.vk), await signedBy(w, w.owner, k))],
    ];
    for (const [name, shape] of shapes) {
      for (const twoPull of [false, true]) {
        const w = await world();
        const kPrime = randomBytes(32);
        const rows = twoPull ? [memberRow(w, 0, sealFor(w, kPrime), null), await shape(w, kPrime)] : [await shape(w, kPrime)];
        const { d, store, server } = await vouchedThenServe(w, rows);
        await assertVouchHolds(w, kPrime, d, store, server, name === "wrap", `${name}/${twoPull ? "two-pull" : "single"}`);
      }
    }
  }, 120_000);

  it("MEDIUM-B: seal for K_s then a verified v2 for K_s never promotes K_s against the vouch", async () => {
    const w = await world();
    const ks = randomBytes(32);
    const { d, store, server } = await vouchedThenServe(w, [memberRow(w, 0, sealFor(w, ks), null), memberRow(w, 0, sealFor(w, ks), await signedBy(w, w.owner, ks))]);
    expect(d.keySource(w.vaultId)).not.toBe("signed-grant");
    expect(store.notices().some((n) => n.kind === "grant-anomaly" && n.reason === "vk_mismatch")).toBe(true);
    await assertVouchHolds(w, ks, d, store, server, false, "MEDIUM-B");
  });

  it("LOW-E: a v1 seal for another key than the vouch is vk_mismatch, not an Accept offer", async () => {
    const w = await world();
    const k = randomBytes(32);
    const { d, store, server } = await vouchedThenServe(w, [memberRow(w, 0, sealFor(w, k), null)]);
    expect(store.notices().some((n) => n.kind === "grant-anomaly" && n.reason === "vk_mismatch")).toBe(true);
    await assertVouchHolds(w, k, d, store, server, false, "LOW-E");
  });

  it("LOW-F: another device's UVK wrap for another key is used but flagged", async () => {
    const w = await world();
    const k = randomBytes(32);
    const { d, store, server } = await vouchedThenServe(w, [{ ...memberRow(w, 0, null, null), wrappedVk: await wrapFor(w, k) }]);
    expect(d.keySource(w.vaultId)).toBe("uvk-wrap");
    expect(store.notices().some((n) => n.kind === "grant-anomaly" && n.reason === "vk_mismatch")).toBe(true);
    await assertVouchHolds(w, k, d, store, server, true, "LOW-F");
  });
});

describe("A6 final review LOW-G / LOW-H (closed in A7)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  it("LOW-G: the vouch table holds on a WARM session too (rows served to the engine that vouched, no restart)", async () => {
    const third = await enroll("a7-unpinned-sender");
    const shapes: [string, (w: World, k: Uint8Array) => Promise<WireGrant | null>][] = [
      ["wrap", async (w, k) => ({ ...memberRow(w, 0, null, null), wrappedVk: await wrapFor(w, k) })],
      ["v2", async (w, k) => memberRow(w, 0, null, await signedBy(w, w.owner, k))],
      ["v2+seal", async (w, k) => memberRow(w, 0, sealFor(w, k), await signedBy(w, w.owner, k))],
      ["seal", async (w, k) => memberRow(w, 0, sealFor(w, k), null)],
      ["pending+seal", async (w, k) => memberRow(w, 0, sealFor(w, k), await signedBy(w, third, k))],
      ["broken+seal", async (w, k) => memberRow(w, 0, sealFor(w, k), toB64(randomBytes(200)))],
      ["seal(K)+v2(K')", async (w, k) => memberRow(w, 0, sealFor(w, w.vk), await signedBy(w, w.owner, k))],
    ];
    for (const [name, shape] of shapes) {
      const w = await world();
      const kPrime = randomBytes(32);
      const server = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)));
      const d = await unlock(w.member);
      const store = new VaultStore(server.asClient(), d, undefined, memoryClientState());
      await store.sync();
      await store.acceptLegacyVault(w.vaultId);
      await store.accountState.pin(pinOf(w.owner, "Owner"));
      server.selfWraps = [];
      let rev = 12;
      for (const row of [memberRow(w, 0, sealFor(w, kPrime), null), await shape(w, kPrime)]) {
        server.feed = feed(w, rev, row ? { ...row, rev } : null);
        await store.sync();
        rev += 3;
      }
      expect(d.legacyKeyTag(w.vaultId), `warm/${name}: K stays held`).toBe(legacyTagOf(w.vk));
      await assertVouchHolds(w, kPrime, d, store, server, false, `warm/${name}`);
    }
  }, 120_000);

  it("LOW-G: a held legacy key whose vouch (seeded directly) names another key is never promoted", async () => {
    const w = await world();
    const d = await unlock(w.member);
    d.grantPins = (uid) => (uid === w.owner.userId ? { identityPub: fromB64(w.owner.identityPub), current: true } : null);
    const ks = randomBytes(32);
    d.addGrant(memberRow(w, 9, sealFor(w, ks), null));
    expect(d.keySource(w.vaultId)).toBe("legacy-seal");
    d.authorizeLegacyKey(w.vaultId, legacyTagOf(w.vk), "confirmed"); // the vouch is for K, the held key is K_s
    d.addGrant(memberRow(w, 12, sealFor(w, ks), await signedBy(w, w.owner, ks)));
    expect(d.keySource(w.vaultId), "never promoted to signed-grant").toBe("legacy-seal");
    expect(d.grantAnomalies().get(w.vaultId)).toBe("vk_mismatch");
    expect(d.selfWrapAuthorized(w.vaultId)).toBe(false);
    expect(() => d.buildSignedGrant(w.vaultId, pinOf(w.owner, "Owner"))).toThrow();
  });

  it("LOW-H: rule 2 meeting a mismatching vouch also raises the vault-key-mismatch flag", async () => {
    const w = await world();
    const k = randomBytes(32);
    const { d, store } = await vouchedThenServe(w, [{ ...memberRow(w, 0, null, null), wrappedVk: await wrapFor(w, k) }]);
    expect(d.vkMismatch(w.vaultId)).toBe(true);
    expect(store.notices().some((n) => n.kind === "vk-mismatch" && n.vaultId === w.vaultId)).toBe(true);
  });
});

describe("A7 — per-vault held-key memory (closes R15(g) on a device that held the vault)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  it("a v2-adopted vault later served with K' is flagged on a warm session and refused after a restart", async () => {
    const w = await world();
    const local = memoryClientState();
    const server = new FakeServer(feed(w, 5, null));
    const d = await unlock(w.member);
    const store = new VaultStore(server.asClient(), d, undefined, local);
    await store.sync();
    await store.accountState.pin(pinOf(w.owner, "Owner"));
    server.feed = feed(w, 9, memberRow(w, 9, null, await signedBy(w, w.owner, w.vk)));
    await store.sync();
    expect(d.keySource(w.vaultId)).toBe("signed-grant");
    expect(server.selfWraps).toHaveLength(1);
    const kPrime = randomBytes(32);
    server.feed = feed(w, 12, memberRow(w, 12, null, await signedBy(w, w.owner, kPrime)));
    await store.sync();
    expect(d.legacyKeyTag(w.vaultId), "warm: K stays").toBe(legacyTagOf(w.vk));
    expect(d.vkMismatch(w.vaultId), "warm: flagged").toBe(true);
    // Reload: the server now serves only the grant for K'.
    const again = await unlock(w.member);
    const reloaded = new VaultStore(server.asClient(), again, undefined, local);
    await reloaded.sync();
    expect(again.hasVault(w.vaultId), "K' is refused, never adopted").toBe(false);
    expect(again.grantAnomalies().get(w.vaultId)).toBe("vk_mismatch");
    expect(server.selfWraps, "nothing wrapped for K'").toHaveLength(1);
  });

  for (const shape of ["seal", "v2"] as const) {
    it(`a wrap-adopted vault later served a ${shape} for K' is refused after a restart`, async () => {
      const w = await world();
      const local = memoryClientState();
      const server = new FakeServer(feed(w, 5, null));
      const d = await unlock(w.member);
      const store = new VaultStore(server.asClient(), d, undefined, local);
      await store.sync();
      await store.accountState.pin(pinOf(w.owner, "Owner"));
      server.feed = feed(w, 9, { ...memberRow(w, 9, null, null), wrappedVk: await wrapFor(w, w.vk) });
      await store.sync();
      expect(d.keySource(w.vaultId)).toBe("uvk-wrap");
      const kPrime = randomBytes(32);
      server.feed = feed(w, 12, shape === "seal" ? memberRow(w, 12, sealFor(w, kPrime), null) : memberRow(w, 12, null, await signedBy(w, w.owner, kPrime)));
      await store.sync();
      expect(d.legacyKeyTag(w.vaultId), "warm: K stays").toBe(legacyTagOf(w.vk));
      expect(d.vkMismatch(w.vaultId), "warm: flagged").toBe(true);
      const again = await unlock(w.member);
      const reloaded = new VaultStore(server.asClient(), again, undefined, local);
      await reloaded.sync();
      expect(again.hasVault(w.vaultId), "K' refused after a restart").toBe(false);
      expect(reloaded.legacyReviewVaults().some((r) => r.vaultId === w.vaultId), "never offered for Accept").toBe(false);
    });
  }

  it("the memory survives a server-driven removal (A7 review MEDIUM-1)", async () => {
    const w = await world();
    const local = memoryClientState();
    const server = new FakeServer(feed(w, 5, null));
    const d = await unlock(w.member);
    const store = new VaultStore(server.asClient(), d, undefined, local);
    await store.sync();
    server.feed = feed(w, 9, { ...memberRow(w, 9, null, null), wrappedVk: await wrapFor(w, w.vk) });
    await store.sync();
    expect(local.get(HELD_KEYS_KEY) ?? "").toContain(w.vaultId);
    server.feed = { ...feed(w, 12, null), full: false, removedGrants: [w.vaultId] };
    await store.sync();
    expect(d.hasVault(w.vaultId)).toBe(false);
    expect(local.get(HELD_KEYS_KEY) ?? "").toContain(w.vaultId);
    expect(d.heldKeyTagsSnapshot().has(w.vaultId)).toBe(true);
  });
});

describe("A7 review MEDIUM-1 / LOW-1: the held-key memory and the vouch survive every server-driven drop", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  async function adoptedV2(w: World): Promise<{ d: Account; store: VaultStore; server: FakeServer; local: ReturnType<typeof memoryClientState> }> {
    const local = memoryClientState();
    const server = new FakeServer(feed(w, 5, null));
    const d = await unlock(w.member);
    const store = new VaultStore(server.asClient(), d, undefined, local);
    await store.sync();
    await store.accountState.pin(pinOf(w.owner, "Owner"));
    server.feed = feed(w, 9, memberRow(w, 9, null, await signedBy(w, w.owner, w.vk)));
    await store.sync();
    expect(d.keySource(w.vaultId)).toBe("signed-grant");
    return { d, store, server, local };
  }
  const removalFeed = (w: World, rev: number, info: RemovedGrantInfo | null): SyncResponse => ({
    ...feed(w, rev, null), full: false, removedGrants: [w.vaultId], removedGrantsInfo: info ? [info] : [],
  });
  async function validRemoval(w: World): Promise<RemovedGrantInfo> {
    const nonce = newRemovalNonce();
    const at = Date.now();
    const key = await w.owner.account.lifecycleKeyFor(w.vaultId);
    return { vaultId: w.vaultId, reason: "removed", removeProof: await removeV2Proof(key, w.vaultId, w.member.userId, nonce, at), removeNonce: nonce, proofV: 2, issuedAt: at };
  }
  async function assertReAddWithKPrimeRefused(w: World, d: Account, store: VaultStore, server: FakeServer, rev: number, label: string) {
    const kPrime = randomBytes(32);
    server.selfWraps = [];
    server.feed = feed(w, rev, memberRow(w, rev, sealFor(w, kPrime), await signedBy(w, w.owner, kPrime)));
    await store.sync();
    expect(d.hasVault(w.vaultId) && d.legacyKeyTag(w.vaultId) === legacyTagOf(kPrime), `${label}: K' never adopted`).toBe(false);
    expect(d.grantAnomalies().get(w.vaultId), `${label}: vk_mismatch`).toBe("vk_mismatch");
    expect(server.selfWraps, `${label}: never self-wrapped`).toHaveLength(0);
    expect(() => d.buildOwnerWrap(w.vaultId), `${label}: never owner-wrapped`).toThrow();
  }

  it("an anomaly removal, then a re-add with K': refused", async () => {
    const w = await world();
    const { d, store, server } = await adoptedV2(w);
    server.feed = removalFeed(w, 12, null);
    await store.sync();
    expect(store.notices().filter((n) => n.vaultId === w.vaultId).at(-1)!.kind).toBe("anomaly");
    await assertReAddWithKPrimeRefused(w, d, store, server, 15, "anomaly");
  });

  it("a replay-denied removal, then a re-add with K': refused", async () => {
    const w = await world();
    const { d, store, server } = await adoptedV2(w);
    const info = await validRemoval(w);
    server.feed = removalFeed(w, 12, info);
    await store.sync();
    server.feed = feed(w, 15, memberRow(w, 15, null, await signedBy(w, w.owner, w.vk)));
    await store.sync();
    expect(d.hasVault(w.vaultId)).toBe(true);
    server.feed = removalFeed(w, 18, info);
    await store.sync();
    expect(store.notices().filter((n) => n.vaultId === w.vaultId).at(-1)!.kind).toBe("replay-denied");
    await assertReAddWithKPrimeRefused(w, d, store, server, 21, "replay-denied");
  });

  it("a resync drop, then a re-add with K': refused", async () => {
    const w = await world();
    const { d, store, server } = await adoptedV2(w);
    server.feed = { ...feed(w, 12, null), removedGrants: [w.vaultId] };
    server.resyncOnce = true;
    await store.sync();
    expect(d.hasVault(w.vaultId), "the silent resync drop ran").toBe(false);
    await assertReAddWithKPrimeRefused(w, d, store, server, 15, "resync");
  });

  it("a valid removal, then a re-add with the same K: works normally", async () => {
    const w = await world();
    const { d, store, server } = await adoptedV2(w);
    server.feed = removalFeed(w, 12, await validRemoval(w));
    await store.sync();
    server.selfWraps = [];
    server.feed = feed(w, 15, memberRow(w, 15, null, await signedBy(w, w.owner, w.vk)));
    await store.sync();
    expect(d.keySource(w.vaultId)).toBe("signed-grant");
    expect(d.selfWrapAuthorized(w.vaultId), "self-wrap allowed again").toBe(true);
    expect(d.grantAnomalies().has(w.vaultId)).toBe(false);
  });

  it("the user's own leave clears the memory: a re-add with a new key is adopted", async () => {
    const w = await world();
    const { d, store, server } = await adoptedV2(w);
    server.feed = removalFeed(w, 12, { vaultId: w.vaultId, reason: "left" });
    await store.leaveSharedVault(w.vaultId);
    expect(server.leaves).toEqual([w.vaultId]);
    expect(d.hasVault(w.vaultId)).toBe(false);
    const k2 = randomBytes(32);
    server.feed = feed(w, 15, memberRow(w, 15, null, await signedBy(w, w.owner, k2)));
    await store.sync();
    expect(d.legacyKeyTag(w.vaultId)).toBe(legacyTagOf(k2));
    expect(d.keySource(w.vaultId)).toBe("signed-grant");
  });

  it("LOW-1: a server-chosen first seal does not block the genuine key", async () => {
    const w = await world();
    const ks = randomBytes(32);
    const local = memoryClientState();
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, sealFor(w, ks), null)));
    const first = new VaultStore(server.asClient(), await unlock(w.member), undefined, local);
    await first.sync();
    await first.accountState.pin(pinOf(w.owner, "Owner"));
    expect(local.get(HELD_KEYS_KEY) ?? "", "an unvouched seal records no tag").not.toContain(w.vaultId);
    server.feed = feed(w, 12, memberRow(w, 12, null, await signedBy(w, w.owner, w.vk)));
    const again = await unlock(w.member);
    const reloaded = new VaultStore(server.asClient(), again, undefined, local);
    await reloaded.sync();
    expect(again.legacyKeyTag(w.vaultId), "K is adopted").toBe(legacyTagOf(w.vk));
    expect(again.keySource(w.vaultId)).toBe("signed-grant");
  });

  it("LOW-1: a vouch records the held-key tag", async () => {
    const w = await world();
    const local = memoryClientState();
    const server = new FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)));
    const store = new VaultStore(server.asClient(), await unlock(w.member), undefined, local);
    await store.sync();
    expect(local.get(HELD_KEYS_KEY) ?? "").not.toContain(w.vaultId);
    await store.acceptLegacyVault(w.vaultId);
    await store.sync();
    expect(local.get(HELD_KEYS_KEY) ?? "").toContain(`${w.vaultId}|${legacyTagOf(w.vk)}`);
  });
});

// keep imports used even where only types matter
void seal;
