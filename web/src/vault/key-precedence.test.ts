import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { AccountKeys, PushResponse, SyncResponse, WireGrant, WireVault } from "../api/types";
import { adItem, adVaultMeta } from "../crypto/ad";
import { fromB64, toB64, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { sealSharedGrant } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account, VaultGrantKeyUnreadableError } from "./account";
import { IdbVaultCache, openVaultCache } from "./idbcache";
import { VaultStore } from "./store";

/**
 * Canonical-key precedence (security review 2026-10, root cause A §3.1–§3.2), web twin of core's
 * VaultKeyPrecedenceTest + SyncEngineVaultKeyPrecedenceTest. The server is hostile and can attach
 * a `sealedVk` (crypto_box_seal to our PUBLIC identity key, so mintable by the server) to any grant
 * row, the owner's own included. Our `wrappedVk` opens only under our UVK, so it wins: a seal that
 * disagrees is a "vault key mismatch" anomaly, and a damaged wrap is "key unreadable", never a
 * reason to open the seal instead.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const g = globalThis as unknown as { indexedDB: IDBFactory };

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  password: string;
}

async function enroll(email: string): Promise<Enrolled> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({
    inviteToken: "t",
    email,
    displayName: email,
    password,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return {
    account,
    keys: {
      kdfSalt: request.kdfSalt,
      kdfParams: request.kdfParams,
      wrappedUvk: request.wrappedUvk,
      encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub,
      escrowFingerprint: request.escrow!.fingerprint,
    },
    userId: request.userId,
    password,
  };
}

const device = (e: Enrolled) => Account.unlock(e.userId, e.password, e.keys);

/** The hostile server's move: a well-formed v1 seal to the victim's public key around a VK it chose. */
const forgedSeal = (e: Enrolled, vaultId: string, serverVk: Uint8Array) =>
  toB64(sealSharedGrant(e.account.identityPub, vaultId, serverVk));

/** One flipped ciphertext byte: a well-formed envelope whose AEAD tag no longer verifies. */
function tamper(b64: string): string {
  const raw = fromB64(b64);
  raw[raw.length - 1] = raw[raw.length - 1]! ^ 0x01;
  return toB64(raw);
}

class FakeApi {
  queue: SyncResponse[] = [];
  selfWraps: { vaultId: string; wrappedVk: string }[] = [];
  rev = 1;
  async sync(): Promise<SyncResponse> {
    const resp = this.queue.shift() ?? { rev: this.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
    this.rev = Math.max(this.rev, resp.rev);
    return resp;
  }
  async push(): Promise<PushResponse> {
    return { rev: ++this.rev, results: [] };
  }
  async putGrantSelfWrap(vaultId: string, body: { wrappedVk: string }) {
    this.selfWraps.push({ vaultId, wrappedVk: body.wrappedVk });
    return { rev: ++this.rev };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

describe("canonical-key precedence — Account", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a forged seal on the owner's own row never displaces the UVK-wrapped key, and is flagged", async () => {
    const owner = await enroll("owner@example.com");
    const { request, vaultId } = owner.account.buildCreateSharedVault("Household");
    const serverVk = randomBytes(32);
    const row: WireGrant = {
      vaultId, userId: owner.userId, role: "owner", wrappedVk: request.wrappedVk, rev: 2,
      sealedVk: forgedSeal(owner, vaultId, serverVk),
    };
    const d = await device(owner);
    d.addGrant(row);
    expect(d.decryptVaultName(vaultId, request.metaBlob)).toBe("Household");
    const itemId = d.newItemId();
    const up = d.encryptItem(vaultId, itemId, { type: "login", name: "x" });
    expect(() => open(serverVk, fromB64(up.blob), adItem(vaultId, itemId, up.formatVersion))).toThrow();
    expect(d.vkMismatch(vaultId)).toBe(true);
    expect(d.keyArrivedByMemberGrant(vaultId)).toBe(true); // a row with any seal is never a personal candidate (H64)
  });

  it("a matching seal is silent; an unopenable seal is ignored", async () => {
    const owner = await enroll("quiet@example.com");
    const { request, vaultId } = owner.account.buildCreateSharedVault("Household");
    const same = await device(owner);
    same.addGrant({ vaultId, userId: owner.userId, role: "owner", wrappedVk: request.wrappedVk, rev: 2, sealedVk: owner.account.wrapVkForMember(owner.account.identityPub, vaultId) });
    expect(same.vkMismatch(vaultId)).toBe(false);
    const stranger = boxKeypairFromSeed(randomBytes(32));
    const foreign = await device(owner);
    foreign.addGrant({ vaultId, userId: owner.userId, role: "owner", wrappedVk: request.wrappedVk, rev: 2, sealedVk: toB64(sealSharedGrant(stranger.publicKey, vaultId, randomBytes(32))) });
    expect(foreign.decryptVaultName(vaultId, request.metaBlob)).toBe("Household");
    expect(foreign.vkMismatch(vaultId)).toBe(false);
  });

  it("a damaged wrap never falls back to a seal", async () => {
    const owner = await enroll("damaged@example.com");
    const { request, vaultId } = owner.account.buildCreateSharedVault("Household");
    const row: WireGrant = {
      vaultId, userId: owner.userId, role: "owner", wrappedVk: tamper(request.wrappedVk), rev: 2,
      sealedVk: forgedSeal(owner, vaultId, randomBytes(32)),
    };
    const d = await device(owner);
    expect(() => d.addGrant(row)).toThrow(VaultGrantKeyUnreadableError);
    expect(d.hasVault(vaultId)).toBe(false);
    expect(d.keyUnreadable(vaultId)).toBe(true);
    const d2 = await device(owner);
    expect(() => d2.addGrant({ ...row, wrappedVk: "!!not-base64!!" })).toThrow(VaultGrantKeyUnreadableError);
    expect(d2.hasVault(vaultId)).toBe(false);
  });

  it("member self-wrap round-trips; a second device reads the VK from the wrap with the seal absent", async () => {
    const owner = await enroll("sw-owner@example.com");
    const member = await enroll("sw-member@example.com");
    const { request, vaultId } = owner.account.buildCreateSharedVault("Household");
    const row: WireGrant = { vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 4, sealedVk: owner.account.wrapVkForMember(member.account.identityPub, vaultId) };
    const first = await device(member);
    first.addGrant(row);
    expect(first.needsSelfWrap(row)).toBe(true);
    const wrap = first.buildSelfWrap(vaultId);
    expect(first.needsSelfWrap({ ...row, wrappedVk: wrap })).toBe(false);

    const second = await device(member);
    second.addGrant({ ...row, wrappedVk: wrap, sealedVk: null, rev: 5 });
    expect(second.decryptVaultName(vaultId, request.metaBlob)).toBe("Household");
    expect(second.keyArrivedByMemberGrant(vaultId)).toBe(true); // H64 holds without the seal
    second.setPersonalVault(vaultId);
    expect(second.personalVaultId).toBe("");

    const third = await device(member);
    third.addGrant({ ...row, wrappedVk: wrap, sealedVk: forgedSeal(member, vaultId, randomBytes(32)) });
    expect(third.decryptVaultName(vaultId, request.metaBlob)).toBe("Household");
    expect(third.vkMismatch(vaultId)).toBe(true);
  });
});

describe("canonical-key precedence — VaultStore", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  it("a swapped seal raises vk-mismatch on sync AND on cold-start hydrate, keeping our key", async () => {
    const owner = await enroll("store-owner@example.com");
    const { request, vaultId } = owner.account.buildCreateSharedVault("Household");
    const vault: WireVault = { vaultId, type: "shared", rev: 3, metaBlob: request.metaBlob, createdAt: 0 };
    const grant: WireGrant = { vaultId, userId: owner.userId, role: "owner", wrappedVk: request.wrappedVk, rev: 3, sealedVk: forgedSeal(owner, vaultId, randomBytes(32)) };
    const api = new FakeApi();
    api.queue.push({ rev: 7, full: true, vaults: [vault], grants: [grant], items: [], removedGrants: [] });

    const live = await device(owner);
    const cache = (await openVaultCache(owner.userId)) as IdbVaultCache;
    const store = new VaultStore(api.asClient(), live, cache);
    await store.sync();
    expect(live.decryptVaultName(vaultId, request.metaBlob)).toBe("Household");
    const n = store.notices().filter((x) => x.vaultId === vaultId);
    expect(n.map((x) => x.kind)).toEqual(["vk-mismatch"]);
    expect(n[0]!.vaultName).toBe("Household");
    expect(api.selfWraps).toEqual([]);

    const cold = await device(owner);
    const store2 = new VaultStore(api.asClient(), cold, (await openVaultCache(owner.userId)) as IdbVaultCache);
    await store2.hydrate();
    expect(cold.decryptVaultName(vaultId, request.metaBlob)).toBe("Household");
    expect(store2.notices().map((x) => x.kind)).toEqual(["vk-mismatch"]);
  });

  it("a damaged wrap raises key-unreadable and is not counted as an F20 'other device' grant", async () => {
    const owner = await enroll("store-damaged@example.com");
    const { request, vaultId } = owner.account.buildCreateSharedVault("Household");
    const vault: WireVault = { vaultId, type: "shared", rev: 3, metaBlob: request.metaBlob, createdAt: 0 };
    const grant: WireGrant = { vaultId, userId: owner.userId, role: "owner", wrappedVk: tamper(request.wrappedVk), rev: 3, sealedVk: forgedSeal(owner, vaultId, randomBytes(32)) };
    const api = new FakeApi();
    api.queue.push({ rev: 7, full: true, vaults: [vault], grants: [grant], items: [], removedGrants: [] });
    const d = await device(owner);
    const store = new VaultStore(api.asClient(), d);
    await store.sync();
    expect(d.hasVault(vaultId)).toBe(false);
    expect(store.notices().filter((x) => x.vaultId === vaultId).map((x) => x.kind)).toEqual(["key-unreadable"]);
    expect(store.undecryptableGrantVaults()).not.toContain(vaultId);
  });

  it("a v1-seal key is NOT auto-self-wrapped (no laundering); a wrap on the row is still read first", async () => {
    const owner = await enroll("store-sw-owner@example.com");
    const member = await enroll("store-sw-member@example.com");
    const { request, vaultId } = owner.account.buildCreateSharedVault("Household");
    const vault: WireVault = { vaultId, type: "shared", rev: 3, metaBlob: request.metaBlob, createdAt: 0 };
    const sealed: WireGrant = { vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 4, sealedVk: owner.account.wrapVkForMember(member.account.identityPub, vaultId) };
    const api = new FakeApi();
    api.queue.push({ rev: 7, full: true, vaults: [vault], grants: [sealed], items: [], removedGrants: [] });
    const first = await device(member);
    const store = new VaultStore(api.asClient(), first);
    await store.sync();
    await store.sync();
    expect(first.hasVault(vaultId)).toBe(true);
    // A seal is server-mintable: wrapping its key under the UVK would make a server-chosen key canonical.
    expect(api.selfWraps).toEqual([]);

    const wrap = first.buildSelfWrap(vaultId);
    const api2 = new FakeApi();
    api2.queue.push({ rev: 8, full: true, vaults: [vault], grants: [{ ...sealed, wrappedVk: wrap, sealedVk: null, rev: 8 }], items: [], removedGrants: [] });
    const second = await device(member);
    const store2 = new VaultStore(api2.asClient(), second);
    await store2.sync();
    expect(second.decryptVaultName(vaultId, request.metaBlob)).toBe("Household");
    expect(api2.selfWraps).toEqual([]);
    // Sanity: a server-chosen meta blob does not open under the held key.
    const bogus = toB64(seal(randomBytes(32), utf8('{"name":"x"}'), adVaultMeta(vaultId)));
    expect(second.decryptVaultName(vaultId, bogus)).toBe("(vault)");
  });
});
