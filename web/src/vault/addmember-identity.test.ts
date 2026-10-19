import "fake-indexeddb/auto";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AccountKeys, PushResponse, SyncResponse, VaultMemberAdd, WireGrant, WireVault } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import { groupedShort } from "../crypto/fingerprint";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { identityFingerprint } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { type Contact, AccountStateError, decodeAccountState, emptyAccountState, encodeAccountState, mergeAccountState } from "./accountstate";
import { memoryClientState } from "./accountstatesync";
import { addIdentityCheck, normalizeEmail, pinFromQr, pinFromTyped, composeIdentityQr } from "./contacts";
import { LegacyPinConfirmRequiredError, MemberIdentityMismatchError, MemberNotVerifiedError, VaultStore } from "./store";

/**
 * Security review 2026-10, branch A11 (q00, HIGH): the add-member confirm trusted the SERVER's display name for the
 * recipient. `lookup(email)` returns `{userId, displayName, identityPub}`; the pin gate was keyed by the RETURNED
 * userId and the confirm said "You've verified {displayName}". A server plus one pinned colluder C answers a lookup
 * for B's email with C's userId under B's name: the gate passes, the screen says B, C gets the vault key.
 *
 * Now a pin records the email the human typed when they ran the ceremony, the add is REFUSED when the typed email
 * does not match it, and a pin from before this change (no email) can only be used after the human confirms the
 * pin's OWN label and fingerprint ("this is who you verified") — never the lookup's name.
 */

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const g = globalThis as unknown as { indexedDB: IDBFactory };

interface Enrolled {
  account: Account;
  keys: AccountKeys;
  userId: string;
  email: string;
  password: string;
  identityPub: string;
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
    userId: request.userId, email, password, identityPub: request.identityPub,
    personalVaultId: request.personalVault.vaultId, personalWrappedVk: request.personalVault.wrappedVk, personalMeta: request.personalVault.metaBlob,
  };
}

class FakeServer {
  feed: SyncResponse;
  adds: { vaultId: string; body: VaultMemberAdd }[] = [];
  accountStateBlob: string | null = null;
  accountSeq = 0;
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
    throw new ApiError(404, "not_found", "no");
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
  async vaultMembers() {
    return [];
  }
  async createVault(req: { vaultId: string; metaBlob: string; wrappedVk: string }) {
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
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

const personalRow = (e: Enrolled): WireVault => ({ vaultId: e.personalVaultId, type: "personal", rev: 2, metaBlob: e.personalMeta, createdAt: 0 });
const personalGrant = (e: Enrolled): WireGrant => ({ vaultId: e.personalVaultId, userId: e.userId, role: "owner", wrappedVk: e.personalWrappedVk, rev: 2, sealedVk: null });

async function ownerWithVault(owner: Enrolled) {
  const server = new FakeServer({ rev: 5, full: true, vaults: [personalRow(owner)], grants: [personalGrant(owner)], items: [], removedGrants: [] });
  server.selfUserId = owner.userId;
  const store = new VaultStore(server.asClient(), await Account.unlock(owner.userId, owner.password, owner.keys), undefined, memoryClientState());
  await store.sync();
  const vaultId = await store.createSharedVault("Family");
  return { store, server, vaultId };
}

/** A pin made by the ceremony itself: the human typed `who`'s 32-hex code, read from their screen. */
async function verifyTyped(store: VaultStore, who: Enrolled, label: string, typedEmail: string | null): Promise<Contact> {
  const fp = await identityFingerprint((await import("../crypto/bytes")).fromB64(who.identityPub));
  const c = await pinFromTyped(groupedShort(fp), { userId: who.userId, identityPub: who.identityPub }, label, Date.now(), typedEmail);
  expect(c).not.toBeNull();
  await store.accountState.pin(c!);
  return c!;
}

describe("A11 q00 — add-member confirms the identity the human verified, never the server's name", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  });

  it("the ceremony records the email the human typed (normalised); the enrol / member-list paths record none", async () => {
    const bea = boxKeypairFromSeed(new Uint8Array(32).fill(5));
    const served = { userId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", identityPub: (await import("../crypto/bytes")).toB64(bea.publicKey) };
    const fp = await identityFingerprint(bea.publicKey);
    expect((await pinFromTyped(groupedShort(fp), served, "Bea", 1, "  Bea@Example.COM "))?.email).toBe("bea@example.com");
    expect((await pinFromTyped(groupedShort(fp), served, "Bea", 1))?.email, "no typed email → none recorded").toBeUndefined();
    const qr = await composeIdentityQr(served.userId, bea.publicKey);
    expect((await pinFromQr(qr, served, "Bea", 1, "bea@example.com"))?.email).toBe("bea@example.com");
    expect(normalizeEmail(" A@B.C ")).toBe("a@b.c");
  });

  it("the pure check: match, mismatch, legacy, and another pin claiming the typed email", () => {
    const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const pinB: Contact = { userId: B, identityPub: "x", label: "Bea", verifiedAt: 1, method: "typed", email: "bea@example.com" };
    const pinC: Contact = { userId: C, identityPub: "y", label: "Carl", verifiedAt: 1, method: "typed", email: "carl@example.com" };
    const legacyC: Contact = { userId: C, identityPub: "y", label: "Carl", verifiedAt: 1, method: "typed" };
    expect(addIdentityCheck(B, "Bea@example.com ", [pinB, pinC]).kind).toBe("match");
    expect(addIdentityCheck(C, "bea@example.com", [pinB, pinC]).kind, "server answered B's email with C's account").toBe("mismatch");
    expect(addIdentityCheck(C, "bea@example.com", [pinB, legacyC]).kind, "B's pin claims the email: C's legacy pin cannot stand in").toBe("mismatch");
    const legacy = addIdentityCheck(C, "bea@example.com", [legacyC]);
    expect(legacy.kind).toBe("legacy");
    expect(legacy.kind === "legacy" && legacy.pin.label, "the legacy confirm shows C's VERIFIED label").toBe("Carl");
    expect(addIdentityCheck(B, "bea@example.com", []).kind).toBe("unpinned");
  });

  it("lookup(B's email) → C's userId under B's name, C pinned with C's email → REFUSED, nothing sealed", async () => {
    const owner = await enroll("q00-owner");
    const bea = await enroll("q00-bea");
    const carl = await enroll("q00-carl");
    const { store, server, vaultId } = await ownerWithVault(owner);
    await verifyTyped(store, carl, "Carl", carl.email);
    // The hostile server's lookup answer for B's email: C's id and key under B's display name.
    const found = { userId: carl.userId, displayName: "Bea", identityPub: carl.identityPub };
    expect(store.memberPinState(found.userId, found.identityPub), "the old gate passes: C is pinned").toBe("pinned");
    expect(store.addMemberIdentity(bea.email, found.userId).kind).toBe("mismatch");
    await expect(store.addVaultMember(vaultId, found.userId, "writer", { typedEmail: bea.email })).rejects.toBeInstanceOf(MemberIdentityMismatchError);
    await expect(store.addVaultMember(vaultId, found.userId, "writer", { typedEmail: bea.email, legacyPinConfirmed: true }), "a confirmation cannot override a recorded mismatch").rejects.toBeInstanceOf(MemberIdentityMismatchError);
    expect(server.adds).toEqual([]);
  });

  it("legacy pin (no recorded email): the confirm shows C's verified label; without the human's confirmation it is refused", async () => {
    const owner = await enroll("q00-owner");
    const bea = await enroll("q00-bea");
    const carl = await enroll("q00-carl");
    const { store, server, vaultId } = await ownerWithVault(owner);
    await verifyTyped(store, carl, "Carl", null); // a pre-A11 pin
    const found = { userId: carl.userId, displayName: "Bea", identityPub: carl.identityPub };
    const check = store.addMemberIdentity(bea.email, found.userId);
    expect(check.kind).toBe("legacy");
    expect(check.kind === "legacy" && check.pin.label, "the screen names who the human verified, not the server's 'Bea'").toBe("Carl");
    await expect(store.addVaultMember(vaultId, found.userId, "writer", { typedEmail: bea.email })).rejects.toBeInstanceOf(LegacyPinConfirmRequiredError);
    expect(server.adds).toEqual([]);
    // The human read "Carl" and confirmed anyway: that is the human's verified choice, and it is honoured.
    await store.addVaultMember(vaultId, found.userId, "writer", { typedEmail: bea.email, legacyPinConfirmed: true });
    expect(server.adds.map((a) => a.body.userId)).toEqual([carl.userId]);
  });

  it("genuine B (pinned with B's email): works; unpinned still refused", async () => {
    const owner = await enroll("q00-owner");
    const bea = await enroll("q00-bea");
    const carl = await enroll("q00-carl");
    const { store, server, vaultId } = await ownerWithVault(owner);
    await expect(store.addVaultMember(vaultId, bea.userId, "writer", { typedEmail: bea.email })).rejects.toBeInstanceOf(MemberNotVerifiedError);
    await verifyTyped(store, bea, "Bea", bea.email);
    await verifyTyped(store, carl, "Carl", carl.email);
    expect(store.addMemberIdentity(bea.email.toUpperCase(), bea.userId).kind).toBe("match");
    await store.addVaultMember(vaultId, bea.userId, "writer", { typedEmail: ` ${bea.email.toUpperCase()}` });
    expect(server.adds.map((a) => a.body.userId)).toEqual([bea.userId]);
  });

  it("the account-state codec carries the email, strictly, and omits it while absent", () => {
    const U = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const key = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU";
    const base = emptyAccountState(U);
    const legacy = { ...base, contacts: [{ userId: B, identityPub: key, label: "Bea", verifiedAt: 1, method: "typed" as const }] };
    const enc = encodeAccountState(legacy);
    expect(enc, "a pre-A11 contact encodes without an email key").not.toContain("email");
    expect(decodeAccountState(U, enc).contacts[0]!.email).toBeUndefined();
    const withEmail = { ...base, contacts: [{ ...legacy.contacts[0]!, email: "bea@example.com" }] };
    const enc2 = encodeAccountState(withEmail);
    expect(decodeAccountState(U, enc2).contacts[0]!.email).toBe("bea@example.com");
    for (const bad of ["Bea@example.com", " bea@example.com", "bea", "", "a b@example.com", 7]) {
      const raw = JSON.parse(enc2);
      raw.contacts[0].email = bad;
      expect(() => decodeAccountState(U, JSON.stringify(raw)), `email ${JSON.stringify(bad)}`).toThrow(AccountStateError);
    }
    // The merge keeps the newer pin whole (its email included).
    const newer = { ...base, seq: 2, contacts: [{ ...legacy.contacts[0]!, verifiedAt: 5, email: "bea@example.com" }] };
    expect(mergeAccountState(U, legacy, newer, 0).doc.contacts[0]!.email).toBe("bea@example.com");
  });
});

describe("A11 q00 — the web add-member screen (source pins)", () => {
  const src = readFileSync(fileURLToPath(new URL("../ui/Sharing.tsx", import.meta.url)), "utf8");
  const start = src.indexOf("function AddMember(");
  const body = src.slice(start, src.indexOf("\n}\n", start));
  it("never names the recipient by the lookup's displayName on the confirm", () => {
    expect(start).toBeGreaterThan(0);
    expect(body).not.toMatch(/You've verified \{found\.displayName\}/);
    expect(body, "the pinned branch shows the pin's own label").toMatch(/identity\.pin\.label/);
  });
  it("passes the typed email to the store and to the ceremony", () => {
    expect(body).toMatch(/addVaultMember\(vaultId, found\.userId, role, \{ typedEmail/);
    expect(body).toMatch(/verifiedEmail=\{/);
  });
});
