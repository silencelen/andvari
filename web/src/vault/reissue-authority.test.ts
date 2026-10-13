import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AccountKeys, PushResponse, SyncResponse, VaultMemberAdd, VaultMemberSummary, WireGrant, WireVault } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import type { Contact } from "./accountstate";
import { OwnershipNotConfirmedError, OwnershipTransferAckRequiredError, ReauthFailedError, VaultStore } from "./store";
import { VaultKeyNotVerifiedError } from "./account";
import { issuedFor, ownsVault } from "./accountstate";
import { adIdkey, adUvk, adVk } from "../crypto/ad";
import { fromB64, toB64, toHexLower, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { type KdfParams, masterKey, wrapKey } from "../crypto/keys";
import { acceptProofFromHash } from "../crypto/lifecycleproof";
import { sha256Sync } from "../crypto/provider";
import { openSignedGrant } from "../crypto/signedgrant";

/**
 * Grant re-issue authority (security review 2026-10, root cause A, branch A6b) — web twin of core
 * `ReissueAuthorityTest`. The invariant: this account's client never signs or seals a vault key to a user unless
 * (a) a human on this device confirmed that (vault, user) pair now, or (b) the pair is in this account's
 * UVK-authenticated issued-grants record for the same identity key; and it never takes an owner-only signing
 * action on a vault on the strength of the server's `role=owner` label alone.
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
}

const FLOOR: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };

async function enroll(tag: string, kdfParams: KdfParams = KDF): Promise<Enrolled> {
  const email = `${tag}-${Math.random().toString(16).slice(2)}@example.com`;
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
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
  };
}

const unlock = (e: Enrolled) => Account.unlock(e.userId, e.password, e.keys);

class FakeServer {
  feed: SyncResponse;
  adds: { vaultId: string; body: VaultMemberAdd }[] = [];
  reissues: { vaultId: string; userId: string; signedGrant: string }[] = [];
  offers: { vaultId: string; toUserId: string }[] = [];
  removals: { vaultId: string; userId: string }[] = [];
  created: string[] = [];
  members: Record<string, VaultMemberSummary[]> = {};
  accountStateBlob: string | null = null;
  accountSeq = 0;
  keys: AccountKeys | null = null;
  selfUserId: string | null = null;
  constructor(feed: SyncResponse) {
    this.feed = feed;
  }
  async sync(since: number): Promise<SyncResponse> {
    if (since === 0) return this.feed;
    if (since < this.feed.rev) return { ...this.feed, full: false };
    return { rev: this.feed.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
  }
  async push(): Promise<PushResponse> {
    return { rev: this.feed.rev, results: [] };
  }
  async accountKeys(): Promise<AccountKeys> {
    if (!this.keys) throw new ApiError(404, "not_found", "no");
    return this.keys;
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
  async vaultMembers(vaultId: string) {
    return this.members[vaultId] ?? [];
  }
  async createVault(req: { vaultId: string; metaBlob: string; wrappedVk: string }) {
    // The created vault joins the creator's feed, with the creator's own UVK-wrapped owner row.
    this.created.push(req.vaultId);
    const rev = this.feed.rev + 1;
    this.feed = {
      ...this.feed, rev,
      vaults: [...this.feed.vaults, { vaultId: req.vaultId, type: "shared", rev, metaBlob: req.metaBlob, createdAt: 0 }],
      grants: [...this.feed.grants, { vaultId: req.vaultId, userId: this.selfUserId!, role: "owner", wrappedVk: req.wrappedVk, rev, sealedVk: null }],
    };
    return { rev };
  }
  async addVaultMember(vaultId: string, body: VaultMemberAdd) {
    this.adds.push({ vaultId, body });
    return { rev: this.feed.rev + 1 };
  }
  async removeVaultMember(vaultId: string, userId: string) {
    this.removals.push({ vaultId, userId });
    return { rev: this.feed.rev + 1 };
  }
  async reissueGrant(vaultId: string, userId: string, body: { signedGrant: string }) {
    this.reissues.push({ vaultId, userId, signedGrant: body.signedGrant });
    return { rev: this.feed.rev + 1 };
  }
  async offerTransfer(vaultId: string, body: { toUserId: string }) {
    this.offers.push({ vaultId, toUserId: body.toUserId });
    return { rev: this.feed.rev + 1, expiresAt: 0 };
  }
  async putGrantSelfWrap() {
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
}

/** An owner, a member, and a shared vault "Household" the owner created ON ANOTHER DEVICE before this branch. */
async function world(ownerKdf: KdfParams = KDF, memberKdf: KdfParams = KDF): Promise<World> {
  const owner = await enroll("a6b-owner", ownerKdf);
  const member = await enroll("a6b-member", memberKdf);
  const shared = owner.account.buildCreateSharedVault("Household");
  return { owner, member, vaultId: shared.vaultId, metaBlob: shared.request.metaBlob, ownerWrap: shared.request.wrappedVk };
}

const pinOf = (e: Enrolled, label: string): Contact => ({ userId: e.userId, identityPub: e.identityPub, label, verifiedAt: 1000, method: "typed" });
const personalRow = (e: Enrolled): WireVault => ({ vaultId: e.personalVaultId, type: "personal", rev: 2, metaBlob: e.personalMeta, createdAt: 0 });
const personalGrant = (e: Enrolled): WireGrant => ({ vaultId: e.personalVaultId, userId: e.userId, role: "owner", wrappedVk: e.personalWrappedVk, rev: 2, sealedVk: null });
const sharedRow = (w: World, rev = 3): WireVault => ({ vaultId: w.vaultId, type: "shared", rev, metaBlob: w.metaBlob, createdAt: 0 });
const summary = (e: Enrolled, name: string, role: string, legacy = false): VaultMemberSummary => ({
  userId: e.userId, email: `${name}@example.com`, displayName: name, role, identityPub: e.identityPub, addedAt: 0, ...(legacy ? { legacyGrant: true } : {}),
});

function ownerFeed(w: World, rev = 5): SyncResponse {
  return {
    rev, full: true, vaults: [personalRow(w.owner), sharedRow(w)],
    grants: [personalGrant(w.owner), { vaultId: w.vaultId, userId: w.owner.userId, role: "owner", wrappedVk: w.ownerWrap, rev: 3, sealedVk: null }],
    items: [], removedGrants: [],
  };
}

describe("A6b — re-issue authority (VaultStore)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  it("a server-listed pinned member on a held vault is NOT re-issued without confirmation", async () => {
    const w = await world();
    const server = new FakeServer(ownerFeed(w));
    server.members[w.vaultId] = [summary(w.owner, "Owner", "owner"), summary(w.member, "Member", "writer", true)];
    const store = new VaultStore(server.asClient(), await unlock(w.owner), undefined, memoryClientState());
    await store.sync();
    await store.accountState.pin(pinOf(w.member, "Member"));
    await store.sync();
    await store.sync();
    expect(server.reissues, "sync() never signs a grant: the member list and the role are the server's").toEqual([]);
  });

  it("a server role=owner relabel on a vault this account never created or accepted unlocks no signing action", async () => {
    const w = await world();
    const colluder = await enroll("a6b-colluder");
    const server = new FakeServer({ rev: 5, full: true, vaults: [personalRow(w.member)], grants: [personalGrant(w.member)], items: [], removedGrants: [] });
    const device = await unlock(w.member);
    const store = new VaultStore(server.asClient(), device, undefined, memoryClientState());
    await store.sync();
    await store.accountState.pin(pinOf(w.owner, "Owner"));
    await store.accountState.pin(pinOf(colluder, "Colluder"));
    const signed = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"));
    server.feed = {
      rev: 9, full: true, vaults: [personalRow(w.member), sharedRow(w, 9)],
      grants: [personalGrant(w.member), { vaultId: w.vaultId, userId: w.member.userId, role: "owner", wrappedVk: "", rev: 9, sealedVk: null, signedGrant: signed }],
      items: [], removedGrants: [],
    };
    server.members[w.vaultId] = [summary(w.member, "Member", "owner"), summary(colluder, "Colluder", "writer", true)];
    await store.sync();
    expect(device.hasVault(w.vaultId)).toBe(true);
    expect(device.serverRoleFor(w.vaultId), "the label is still shown as the server reports it").toBe("owner");
    await store.sync();
    expect(server.reissues, "no automatic re-issue on a relabelled vault").toEqual([]);
    expect(store.ownsVault(w.vaultId), "the label is not evidence").toBe(false);
    expect(store.ownershipNeedsConfirmation(w.vaultId), "the owner UI asks 'You own <vault>?' first").toBe(true);
    await expect(store.addVaultMember(w.vaultId, colluder.userId, "writer")).rejects.toBeInstanceOf(OwnershipNotConfirmedError);
    await expect(store.offerTransfer(w.vaultId, colluder.userId)).rejects.toBeInstanceOf(OwnershipNotConfirmedError);
    // The list may SHOW the row (the server listed it), but its confirmation refuses without ownership evidence.
    const rows = await store.loadLegacyGrants(w.vaultId);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.ownershipConfirmed).toBe(false);
    await expect(store.confirmReissue(rows[0]!)).rejects.toBeInstanceOf(OwnershipNotConfirmedError);
    // Nor can the member claim it: its key came from a grant, not from its own UVK wrap.
    await expect(store.describeOwnership(w.vaultId)).rejects.toBeInstanceOf(VaultKeyNotVerifiedError);
    expect(server.adds).toEqual([]);
    expect(server.offers).toEqual([]);
    expect(server.reissues).toEqual([]);
  });

  /** The owner's browser, with a vault it CREATED through the store (its own evidence of ownership). */
  async function ownerWithCreatedVault(owner: Enrolled, local = memoryClientState()) {
    const server = new FakeServer({ rev: 5, full: true, vaults: [personalRow(owner)], grants: [personalGrant(owner)], items: [], removedGrants: [] });
    server.selfUserId = owner.userId;
    const store = new VaultStore(server.asClient(), await unlock(owner), undefined, local);
    await store.sync();
    const vaultId = await store.createSharedVault("Family");
    expect(store.ownsVault(vaultId), "creating the vault records ownership").toBe(true);
    return { store, server, vaultId, local };
  }

  async function opensForMember(member: Enrolled, owner: Enrolled, vaultId: string, signed: string): Promise<Uint8Array> {
    const uvk = open(await wrapKey(masterKey(member.password, fromB64(member.keys.kdfSalt), member.keys.kdfParams)), fromB64(member.keys.wrappedUvk), adUvk(member.userId));
    const me = boxKeypairFromSeed(open(uvk, fromB64(member.keys.encryptedIdentitySeed), adIdkey(member.userId)));
    const opened = openSignedGrant({
      myUserId: member.userId, myIdentityPub: me.publicKey, myIdentityPriv: me.privateKey, rowVaultId: vaultId, sealed: fromB64(signed),
      pinFor: (uid) => (uid === owner.userId ? { identityPub: fromB64(owner.identityPub), current: true } : null), heldVk: null,
    });
    if (opened.verdict !== "adopt") throw new Error(opened.verdict);
    return opened.vk;
  }

  it("a confirmed re-issue works (and only for the row this store offered)", async () => {
    const owner = await enroll("a6b-owner");
    const member = await enroll("a6b-member");
    const { store, server, vaultId } = await ownerWithCreatedVault(owner);
    server.members[vaultId] = [summary(owner, "Owner", "owner"), summary(member, "Member (server)", "writer", true)];
    await store.accountState.pin(pinOf(member, "Member"));
    await store.sync();
    expect(server.reissues).toEqual([]);

    const rows = await store.loadLegacyGrants(vaultId);
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.vaultName, "the row names the vault").toBe("Family");
    expect(row.verifiedLabel, "and the member by the label this device verified").toBe("Member");
    expect(row.displayName).toBe("Member (server)");
    expect(row.ownershipConfirmed).toBe(true);
    expect(server.reissues, "loading the list signs nothing for an unrecorded pair").toEqual([]);
    await expect(store.confirmReissue({ ...row })).rejects.toThrow(/not offered/);
    expect(server.reissues).toEqual([]);

    await store.confirmReissue(row);
    expect(server.reissues.map((r) => [r.vaultId, r.userId])).toEqual([[vaultId, member.userId]]);
    expect((await opensForMember(member, owner, vaultId, server.reissues[0]!.signedGrant)).length).toBe(32);
    expect(store.accountState.issued(vaultId, member.userId), "the confirmed pair is now recorded").not.toBeNull();
    expect(store.legacyGrantRows(vaultId)).toEqual([]);
    await expect(store.confirmReissue(row), "a row is confirmed once").rejects.toThrow(/not offered/);
    await store.sync();
    expect(server.reissues, "sync() adds nothing").toHaveLength(1);
  });

  it("a recorded pair only annotates the row; every re-issue is the owner's tap (A9, M-3)", async () => {
    const owner = await enroll("a6b-owner");
    const member = await enroll("a6b-member");
    const { store, server, vaultId } = await ownerWithCreatedVault(owner);
    await store.accountState.pin(pinOf(member, "Member"));
    await store.addVaultMember(vaultId, member.userId, "writer");
    const rec = store.accountState.issued(vaultId, member.userId);
    expect(rec?.keyHash).toBe(toHexLower(sha256Sync(fromB64(member.identityPub))));

    // The server now lists the member as legacy (a key-format migration). Before A9 the recorded pair was re-issued
    // without a prompt (rule b); the record is relayed by the server, which can withhold a removal tombstone from a
    // device that never saw it, so the record is now a hint on the row and the owner taps.
    server.members[vaultId] = [summary(owner, "Owner", "owner"), summary(member, "Member", "writer", true)];
    const first = await store.loadLegacyGrants(vaultId);
    expect(server.reissues, "a recorded pair is never re-issued without the owner's confirmation").toEqual([]);
    expect(first).toHaveLength(1);
    expect(first[0]!.previouslySharedAt, "the record annotates: 'you shared this vault with them on …'").toBe(rec!.at);
    await store.confirmReissue(first[0]!);
    expect(server.reissues.map((r) => [r.vaultId, r.userId])).toEqual([[vaultId, member.userId]]);
    expect((await opensForMember(member, owner, vaultId, server.reissues[0]!.signedGrant)).length).toBe(32);

    // The member's identity key changes and the owner re-verifies the NEW key: same pair, another key.
    const newKey = boxKeypairFromSeed(randomBytes(32)).publicKey;
    await store.accountState.pin({ userId: member.userId, identityPub: toB64(newKey), label: "Member", verifiedAt: 2000, method: "typed" });
    server.members[vaultId] = [summary(owner, "Owner", "owner"), { ...summary(member, "Member", "writer", true), identityPub: toB64(newKey) }];
    const rows = await store.loadLegacyGrants(vaultId);
    expect(rows.map((r) => r.userId)).toEqual([member.userId]);
    expect(server.reissues, "a different identity key is never re-issued silently").toHaveLength(1);
    await store.confirmReissue(rows[0]!);
    expect(server.reissues, "only the owner's confirmation re-issues to the new key").toHaveLength(2);
    expect(store.accountState.issued(vaultId, member.userId)!.keyHash).toBe(toHexLower(sha256Sync(newKey)));
  });

  it("the issued-grants record survives a restart and is never shrunk by served account state", async () => {
    const owner = await enroll("a6b-owner");
    const member = await enroll("a6b-member");
    const { store, server, vaultId, local } = await ownerWithCreatedVault(owner);
    const beforeAdd = server.accountStateBlob;
    await store.accountState.pin(pinOf(member, "Member"));
    await store.addVaultMember(vaultId, member.userId, "writer");
    expect(store.accountState.issued(vaultId, member.userId)).not.toBeNull();

    // Reload (the same browser storage), and the server replays the OLDER blob that lacks the record.
    server.accountStateBlob = beforeAdd;
    server.accountSeq += 1;
    const reloaded = new VaultStore(server.asClient(), await unlock(owner), undefined, local);
    await reloaded.sync();
    expect(reloaded.accountState.issued(vaultId, member.userId), "the record survived the reload and the replay").not.toBeNull();
    expect(reloaded.ownsVault(vaultId)).toBe(true);
    const written = (await unlock(owner)).openAccountState(server.accountStateBlob!);
    expect(issuedFor(written, vaultId, member.userId), "the local copy won and was written back").not.toBeNull();

    // Withheld entirely: still there.
    server.accountStateBlob = null;
    await reloaded.sync();
    expect(reloaded.accountState.issued(vaultId, member.userId)).not.toBeNull();

    // Another device of the owner learns it from the (authentic) served blob.
    const other = new VaultStore(server.asClient(), await unlock(owner), undefined, memoryClientState());
    await other.sync();
    expect(other.accountState.issued(vaultId, member.userId), "every device of the owner shares the record").not.toBeNull();

    // A removal tombstones it, and the tombstone too survives a replay of the older blob.
    const withRecord = server.accountStateBlob;
    await store.sync();
    await store.removeVaultMember(vaultId, member.userId);
    expect(store.accountState.issued(vaultId, member.userId), "removing the member drops the pair").toBeNull();
    server.accountStateBlob = withRecord;
    server.accountSeq += 1;
    await store.sync();
    expect(store.accountState.issued(vaultId, member.userId), "an older blob cannot bring it back").toBeNull();
  });

  it("the 'You own <vault>?' confirmation requires a reauth", async () => {
    const w = await world(FLOOR); // the reauth applies the unlock KDF fence
    const server = new FakeServer(ownerFeed(w));
    server.keys = w.owner.keys;
    const store = new VaultStore(server.asClient(), await unlock(w.owner), undefined, memoryClientState());
    await store.sync();
    await store.accountState.pin(pinOf(w.member, "Member"));
    expect(store.ownershipNeedsConfirmation(w.vaultId), "a vault created before A6b has no ownership record").toBe(true);
    await expect(store.addVaultMember(w.vaultId, w.member.userId, "writer")).rejects.toBeInstanceOf(OwnershipNotConfirmedError);

    const claim = await store.describeOwnership(w.vaultId);
    expect(claim.receivedAsMember, "a vault this account created needs only the single confirm").toBe(false);
    expect(claim.origin).toBe("created");
    expect(claim.vaultName).toBe("Household");
    await expect(store.confirmOwnership(claim, "not the password")).rejects.toBeInstanceOf(ReauthFailedError);
    expect(store.ownsVault(w.vaultId), "a wrong password records nothing").toBe(false);
    expect(server.adds).toEqual([]);
    await expect(store.confirmOwnership({ ...claim }, w.owner.password)).rejects.toThrow(/not described/);

    await store.confirmOwnership(claim, w.owner.password);
    expect(store.ownsVault(w.vaultId)).toBe(true);
    expect(store.ownershipNeedsConfirmation(w.vaultId), "asked once").toBe(false);
    await store.addVaultMember(w.vaultId, w.member.userId, "writer");
    expect(server.adds).toHaveLength(1);
    expect(ownsVault((await unlock(w.owner)).openAccountState(server.accountStateBlob!), w.vaultId), "sealed in account state for every device").toBe(true);
  });

  it("a verified transfer away ends the ownership record", async () => {
    const owner = await enroll("a6b-owner");
    const member = await enroll("a6b-member");
    const { store, server, vaultId } = await ownerWithCreatedVault(owner);
    const wrapHash = toHexLower(sha256Sync(utf8("member-wrap")));
    const offerId = "11111111-1111-4111-8111-111111111111";
    const key = await (store as unknown as { account: Account }).account.lifecycleKeyFor(vaultId);
    const proof = await acceptProofFromHash(key, vaultId, offerId, member.userId, 1, wrapHash);
    const rev = server.feed.rev + 1;
    server.feed = {
      ...server.feed, rev, full: true,
      vaults: server.feed.vaults.map((v) => (v.vaultId === vaultId ? { ...v, rev, lastTransfer: { offerId, newOwnerUserId: member.userId, acceptProof: proof, seq: 1, wrapHash } } : v)),
    };
    await store.sync();
    expect(store.ownsVault(vaultId), "a verified transfer to someone else ends this account's ownership evidence").toBe(false);
    await expect(store.offerTransfer(vaultId, member.userId)).rejects.toBeInstanceOf(OwnershipNotConfirmedError);
  });

  // ---- A6b review MEDIUM-1 / LOW-3 ----

  async function uvkOfE(e: Enrolled): Promise<Uint8Array> {
    return open(await wrapKey(masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams)), fromB64(e.keys.wrappedUvk), adUvk(e.userId));
  }

  /** The member's browser holding the vault through a verified grant AND its own self-wrap, the row relabelled owner. */
  async function memberHoldingRelabelled(w: World) {
    const vk = open(await uvkOfE(w.owner), fromB64(w.ownerWrap), adVk(w.vaultId, w.owner.userId));
    const selfWrap = toB64(seal(await uvkOfE(w.member), vk, adVk(w.vaultId, w.member.userId)));
    const signed = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"));
    const server = new FakeServer({
      rev: 9, full: true, vaults: [personalRow(w.member), sharedRow(w, 9)],
      grants: [personalGrant(w.member), { vaultId: w.vaultId, userId: w.member.userId, role: "owner", wrappedVk: selfWrap, rev: 9, sealedVk: null, signedGrant: signed }],
      items: [], removedGrants: [],
    });
    server.keys = w.member.keys;
    server.members[w.vaultId] = [summary(w.member, "Member", "owner"), summary(w.owner, "Owner", "writer")];
    const store = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    // A9 (L-2): the member-granted bit comes from authenticated provenance, here the owner's VERIFIED v2 grant beside the
    // self-wrap, which needs the owner pinned on this device (as it was when the member accepted the grant).
    await store.accountState.pin(pinOf(w.owner, "Owner"));
    await store.sync();
    return { store, server };
  }

  it("MEDIUM-1: a member-granted vault is not claimed by a single confirm", async () => {
    const w = await world(KDF, FLOOR);
    const { store } = await memberHoldingRelabelled(w);
    expect(store.ownershipNeedsConfirmation(w.vaultId)).toBe(true);
    const claim = await store.describeOwnership(w.vaultId);
    expect(claim.receivedAsMember).toBe(true);
    expect(claim.reportedOwner?.userId, "the server's owner label, shown as reported").toBe(w.member.userId);
    expect(claim.coHolders.map((c) => c.userId), "the co-holders are named").toEqual([w.owner.userId]);
    expect(claim.origin).toBe("created");
    expect(claim.lastTransferTo).toBeNull();
    await expect(store.confirmOwnership(claim, w.member.password), "one confirm does not claim a vault received as a member").rejects.toBeInstanceOf(OwnershipTransferAckRequiredError);
    expect(store.ownsVault(w.vaultId)).toBe(false);
    await store.confirmOwnership(claim, w.member.password, true);
    expect(store.ownsVault(w.vaultId), "the explicit transfer acknowledgement is accepted").toBe(true);
  });

  it("LOW-3: the reauth refuses a replayed older salt and a weakened KDF", async () => {
    const owner = await enroll("a6b-owner", FLOOR);
    const device = await unlock(owner);
    const uvk = await uvkOfE(owner);
    const oldSalt = randomBytes(16);
    const oldWrap = toB64(seal(await wrapKey(masterKey("the old password", oldSalt, FLOOR)), uvk, adUvk(owner.userId)));
    const replayed = { ...owner.keys, kdfSalt: toB64(oldSalt), wrappedUvk: oldWrap };
    expect(await device.verifyPassword("the old password", replayed).catch(() => false), "a replayed older salt never passes").toBe(false);
    const weakWrap = toB64(seal(await wrapKey(masterKey(owner.password, fromB64(owner.keys.kdfSalt), KDF)), uvk, adUvk(owner.userId)));
    const weakened = { ...owner.keys, kdfParams: KDF, wrappedUvk: weakWrap };
    expect(await device.verifyPassword(owner.password, weakened).catch(() => false), "a weakened KDF never passes").toBe(false);
    expect(await device.verifyPassword(owner.password, owner.keys), "the real keys still pass").toBe(true);
  });

  it("MEDIUM-1: the member provenance survives a reload whose served row looks like an owner row", async () => {
    const w = await world(KDF, FLOOR);
    const vk = open(await uvkOfE(w.owner), fromB64(w.ownerWrap), adVk(w.vaultId, w.owner.userId));
    const selfWrap = toB64(seal(await uvkOfE(w.member), vk, adVk(w.vaultId, w.member.userId)));
    const signed = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"));
    const server = new FakeServer({
      rev: 9, full: true, vaults: [personalRow(w.member), sharedRow(w, 9)],
      grants: [personalGrant(w.member), { vaultId: w.vaultId, userId: w.member.userId, role: "writer", wrappedVk: selfWrap, rev: 9, sealedVk: null, signedGrant: signed }],
      items: [], removedGrants: [],
    });
    server.keys = w.member.keys;
    server.members[w.vaultId] = [summary(w.member, "Member", "owner")];
    const local = memoryClientState();
    const s1 = new VaultStore(server.asClient(), await unlock(w.member), undefined, local);
    await s1.accountState.pin(pinOf(w.owner, "Owner")); // A9 (L-2): the grant verifies
    await s1.sync();
    server.feed = {
      rev: 12, full: true, vaults: [personalRow(w.member), sharedRow(w, 12)],
      grants: [personalGrant(w.member), { vaultId: w.vaultId, userId: w.member.userId, role: "owner", wrappedVk: selfWrap, rev: 12, sealedVk: null }],
      items: [], removedGrants: [],
    };
    const reloaded = new VaultStore(server.asClient(), await unlock(w.member), undefined, local);
    await reloaded.sync();
    const claim = await reloaded.describeOwnership(w.vaultId);
    expect(claim.receivedAsMember, "the durable provenance outlives the served row").toBe(true);
    await expect(reloaded.confirmOwnership(claim, w.member.password)).rejects.toBeInstanceOf(OwnershipTransferAckRequiredError);
  });

  it("LOW-R (A1b): a fresh device still needs the transfer ack when another device recorded member provenance", async () => {
    const w = await world(KDF, FLOOR);
    const vk = open(await uvkOfE(w.owner), fromB64(w.ownerWrap), adVk(w.vaultId, w.owner.userId));
    const selfWrap = toB64(seal(await uvkOfE(w.member), vk, adVk(w.vaultId, w.member.userId)));
    const signed = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"));
    const server = new FakeServer({
      rev: 9, full: true, vaults: [personalRow(w.member), sharedRow(w, 9)],
      grants: [personalGrant(w.member), { vaultId: w.vaultId, userId: w.member.userId, role: "writer", wrappedVk: selfWrap, rev: 9, sealedVk: null, signedGrant: signed }],
      items: [], removedGrants: [],
    });
    server.keys = w.member.keys;
    server.members[w.vaultId] = [summary(w.member, "Member", "owner")];
    const s1 = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await s1.accountState.pin(pinOf(w.owner, "Owner")); // A9 (L-2): the grant verifies
    await s1.sync();
    server.feed = {
      rev: 12, full: true, vaults: [personalRow(w.member), sharedRow(w, 12)],
      grants: [personalGrant(w.member), { vaultId: w.vaultId, userId: w.member.userId, role: "owner", wrappedVk: selfWrap, rev: 12, sealedVk: null }],
      items: [], removedGrants: [],
    };
    // Another browser of the same member: nothing local, and its FIRST served row is owner-shaped.
    const fresh = new VaultStore(server.asClient(), await unlock(w.member), undefined, memoryClientState());
    await fresh.sync();
    const claim = await fresh.describeOwnership(w.vaultId);
    expect(claim.receivedAsMember, "the account-state record reaches a device that never saw the member row").toBe(true);
    await expect(fresh.confirmOwnership(claim, w.member.password)).rejects.toBeInstanceOf(OwnershipTransferAckRequiredError);
  });

  it("copy (A1b): a reauth against a stale session salt says to lock and unlock, byte-identical with core", async () => {
    const w = await world(FLOOR);
    const uvk = await uvkOfE(w.owner);
    const newSalt = randomBytes(16);
    const newWrap = toB64(seal(await wrapKey(masterKey("the new password", newSalt, FLOOR)), uvk, adUvk(w.owner.userId)));
    const server = new FakeServer(ownerFeed(w));
    server.keys = { ...w.owner.keys, kdfSalt: toB64(newSalt), wrappedUvk: newWrap };
    const store = new VaultStore(server.asClient(), await unlock(w.owner), undefined, memoryClientState());
    await store.sync();
    const claim = await store.describeOwnership(w.vaultId);
    await expect(store.confirmOwnership(claim, "the new password")).rejects.toThrow(/^Lock and unlock andvari, then try again\.$/);
    expect(store.ownsVault(w.vaultId)).toBe(false);
  });
});
