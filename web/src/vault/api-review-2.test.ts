import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AccountKeys, ItemDoc, PersonalWrap, PushResponse, RecoveryVerifyResponse, SyncResponse, VaultMemberAdd, VaultMemberSummary, WireGrant, WireItem, WireVault } from "../api/types";
import { adItem, adUvk, adVaultMeta } from "../crypto/ad";
import { fromB64, toB64, toHexLower, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import { authKey, KdfPolicyError, type KdfParams, masterKey, wrapKey } from "../crypto/keys";
import { acceptProofFromHash } from "../crypto/lifecycleproof";
import { boxKeypairFromSeed, randomBytes, sha256Sync } from "../crypto/provider";
import { sealSharedGrant } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account, ReauthFailedError, VaultKeyNotVerifiedError } from "./account";
import { AccountStateSync, memoryClientState } from "./accountstatesync";
import { decodeAccountState, emptyAccountState, isBlankAccountState, ownsVault, withPersonal } from "./accountstate";
import type { Contact } from "./accountstate";
import { NoPersonalVaultError, ReauthStaleSessionError, VaultStore } from "./store";

/**
 * Security review 2026-10, branch A9 (web twin of core `ApiReview2Test`): the second API-review round over
 * A6b/A1b/A5c. M-1 (one fenced reauth derivation), M-2 (the personal designation in account state; a served wrap is
 * never adopted silently on a fresh device; a second apply never switches), M-3 (no silent rule-(b) re-issue; the
 * record only annotates; a device-local tombstone), L-1 (a home only from an applied row), L-2 (the member-granted bit
 * only from an actual adoption), and the LOW items (ownership release retried, rename through INV-WRITE-KEY, recover()
 * wipes the probe's secrets).
 */

// The recover() wipe is invisible from outside: capture the LIVE secret-key arrays each keypair derivation hands out.
const rec = vi.hoisted(() => ({ privates: [] as { live: Uint8Array; at: Uint8Array }[] }));
vi.mock("../crypto/provider", async (importOriginal) => {
  const real = await importOriginal<typeof import("../crypto/provider")>();
  const keep = (k: { privateKey: Uint8Array }) => rec.privates.push({ live: k.privateKey, at: k.privateKey.slice() });
  return {
    ...real,
    boxKeypairFromSeed: (seed: Uint8Array) => {
      const k = real.boxKeypairFromSeed(seed);
      keep(k);
      return k;
    },
    signKeypairFromSeed: (seed: Uint8Array) => {
      const k = real.signKeypairFromSeed(seed);
      keep(k);
      return k;
    },
  };
});

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const FLOOR: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const WEAK: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

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
  recoverySecret: Uint8Array;
  encryptedIdentitySeed: string;
  recoveryWrappedUvk: string;
}

async function enroll(tag: string, kdfParams: KdfParams = KDF): Promise<Enrolled> {
  const email = `${tag}-${Math.random().toString(16).slice(2)}@example.com`;
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account, recoverySecret } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
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
    recoverySecret,
    encryptedIdentitySeed: request.encryptedIdentitySeed,
    recoveryWrappedUvk: request.memberRecovery.recoveryWrappedUvk,
  };
}

/** A fresh device of `e`; the wrap the server serves it is `wrap` (default: the one enrolment minted). */
const unlock = (e: Enrolled, wrap: PersonalWrap | null = e.personalWrap) => Account.unlock(e.userId, e.password, { ...e.keys, personalWrap: wrap });

async function uvkOfE(e: Enrolled): Promise<Uint8Array> {
  return open(await wrapKey(masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams)), fromB64(e.keys.wrappedUvk), adUvk(e.userId));
}

async function expectedAuthKey(e: Enrolled): Promise<string> {
  return toB64(await authKey(masterKey(e.password, fromB64(e.keys.kdfSalt), e.keys.kdfParams)));
}

class FakeServer {
  feed: SyncResponse;
  adds: { vaultId: string; body: VaultMemberAdd }[] = [];
  reissues: { vaultId: string; userId: string; signedGrant: string }[] = [];
  removals: { vaultId: string; userId: string }[] = [];
  puts: { wrap: PersonalWrap; currentAuthKey?: string }[] = [];
  members: Record<string, VaultMemberSummary[]> = {};
  accountStateBlob: string | null = null;
  accountSeq = 0;
  keys: AccountKeys | null = null;
  selfUserId: string | null = null;
  withholdState = false;
  failStatePut = false;
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
  async putPersonalWrap(wrap: PersonalWrap, currentAuthKey?: string) {
    this.puts.push({ wrap, currentAuthKey });
  }
  async accountState() {
    return this.withholdState ? { sealedState: null, seq: 0 } : { sealedState: this.accountStateBlob, seq: this.accountSeq };
  }
  async putAccountState(sealedState: string, baseSeq: number) {
    if (this.failStatePut) throw new ApiError(500, "internal", "no");
    if (baseSeq !== this.accountSeq) throw new ApiError(409, "stale_state", "stale");
    this.accountStateBlob = sealedState;
    this.accountSeq += 1;
    return { sealedState, seq: this.accountSeq };
  }
  async vaultMembers(vaultId: string) {
    return this.members[vaultId] ?? [];
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
  async removeVaultMember(vaultId: string, userId: string) {
    this.removals.push({ vaultId, userId });
    return { rev: this.feed.rev + 1 };
  }
  async reissueGrant(vaultId: string, userId: string, body: { signedGrant: string }) {
    this.reissues.push({ vaultId, userId, signedGrant: body.signedGrant });
    return { rev: this.feed.rev + 1 };
  }
  async putSelfWrap() {
    return { rev: this.feed.rev + 1 };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

const pinOf = (e: Enrolled, label: string): Contact => ({ userId: e.userId, identityPub: e.identityPub, label, verifiedAt: 1000, method: "typed" });
const personalRow = (e: Enrolled): WireVault => ({ vaultId: e.personalVaultId, type: "personal", rev: 2, metaBlob: e.personalMeta, createdAt: 0 });
const personalGrant = (e: Enrolled): WireGrant => ({ vaultId: e.personalVaultId, userId: e.userId, role: "owner", wrappedVk: e.personalWrappedVk, rev: 2, sealedVk: null });
const summary = (e: Enrolled, name: string, role: string, legacy = false): VaultMemberSummary =>
  ({ userId: e.userId, email: `${name}@example.com`, displayName: name, role, identityPub: e.identityPub, addedAt: 0, ...(legacy ? { legacyGrant: true } : {}) });

interface World {
  owner: Enrolled;
  sharedId: string;
  metaBlob: string;
  ownerWrap: string;
  feed: SyncResponse;
}

async function world(params: KdfParams = KDF): Promise<World> {
  const owner = await enroll("a9", params);
  const shared = owner.account.buildCreateSharedVault("Household");
  const feed: SyncResponse = {
    rev: 5, full: true,
    vaults: [personalRow(owner), { vaultId: shared.vaultId, type: "shared", rev: 3, metaBlob: shared.request.metaBlob, createdAt: 0 }],
    grants: [personalGrant(owner), { vaultId: shared.vaultId, userId: owner.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 3, sealedVk: null }],
    items: [], removedGrants: [],
  };
  return { owner, sharedId: shared.vaultId, metaBlob: shared.request.metaBlob, ownerWrap: shared.request.wrappedVk, feed };
}

function serverOf(w: World, keys: AccountKeys | null = w.owner.keys): FakeServer {
  const s = new FakeServer(w.feed);
  s.keys = keys;
  s.selfUserId = w.owner.userId;
  s.members[w.sharedId] = [summary(w.owner, "Owner", "owner")];
  s.members[w.owner.personalVaultId] = [summary(w.owner, "Owner", "owner")];
  return s;
}

async function designationOn(server: FakeServer, e: Enrolled): Promise<string | null> {
  if (!server.accountStateBlob) return null;
  return (await unlock(e)).openAccountState(server.accountStateBlob).personal?.vaultId ?? null;
}

const store = (server: FakeServer, account: Account, local = memoryClientState()) => new VaultStore(server.asClient(), account, undefined, local);

describe("A9 — second API-review round (VaultStore / Account)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  // ---- M-1 ----

  it("M-1: the re-designation reauth refuses weakened params and a replayed salt, and uploads the session's proof", async () => {
    const w = await world(FLOOR);
    const server = serverOf(w);
    const s = store(server, await unlock(w.owner));
    await s.sync();
    const proposal = await s.proposePersonalVault(w.sharedId);

    server.keys = { ...w.owner.keys, kdfParams: WEAK };
    await expect(s.redesignatePersonalVault(proposal, w.owner.password)).rejects.toBeInstanceOf(KdfPolicyError);
    expect(server.puts).toHaveLength(0);

    server.keys = { ...w.owner.keys, kdfSalt: toB64(randomBytes(16)) };
    await expect(s.redesignatePersonalVault(proposal, w.owner.password)).rejects.toBeInstanceOf(ReauthStaleSessionError);
    expect(server.puts).toHaveLength(0);

    server.keys = w.owner.keys;
    await s.redesignatePersonalVault(proposal, w.owner.password);
    expect(server.puts).toHaveLength(1);
    expect(server.puts[0]!.currentAuthKey).toBe(await expectedAuthKey(w.owner));
    expect(server.puts[0]!.wrap.vaultId).toBe(w.sharedId);
  }, 60_000);

  it("M-1: reauthAuthKey is the one fenced derivation; the pre-session deriveAuthKey is fenced on the params", async () => {
    const owner = await enroll("a9-fence", FLOOR);
    const device = await unlock(owner);
    await expect(device.reauthAuthKey(owner.password, { ...owner.keys, kdfParams: WEAK })).rejects.toBeInstanceOf(KdfPolicyError);
    await expect(device.reauthAuthKey(owner.password, { ...owner.keys, kdfSalt: toB64(randomBytes(16)) })).rejects.toBeInstanceOf(ReauthStaleSessionError);
    expect(await device.reauthAuthKey(owner.password, owner.keys)).toBe(await expectedAuthKey(owner));
    await expect(Account.deriveAuthKey(owner.password, owner.keys.kdfSalt, WEAK)).rejects.toBeInstanceOf(KdfPolicyError);
  }, 60_000);

  it("M-1 tripwire: product code derives password credentials only through the fence", () => {
    const src = fileURLToPath(new URL("../", import.meta.url));
    const files: string[] = [];
    const walk = (d: string) => {
      for (const n of readdirSync(d)) {
        const p = join(d, n);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n) && !p.includes(`${"/"}vendor${"/"}`)) files.push(p);
      }
    };
    walk(src);
    expect(files.length).toBeGreaterThan(50);
    const rel = (f: string) => f.slice(src.length);
    // The raw KDF: only inside Account (every caller fenced) and the backup KDF (its own window, spec 07 §2.3).
    const rawKdf = files.filter((f) => readFileSync(f, "utf8").split("\n").some((l) => /\bmasterKey\(/.test(l.split("//")[0]!)))
      .map(rel).filter((p) => !["vault/account.ts", "export/export.ts", "crypto/keys.ts"].includes(p));
    expect(rawKdf).toEqual([]);
    // The pre-session login derivation: only at the sign-in site, over the prelogin values.
    const logins = files.flatMap((f) =>
      readFileSync(f, "utf8").split("\n").flatMap((line, i) => (/Account\.deriveAuthKey\(/.test(line.split("//")[0]!) ? [{ path: rel(f), line: i + 1, code: line.trim() }] : [])),
    );
    // The one legitimate site: the sign-in over the prelogin values (the in-session proof derives through the raw KDF
    // inside Account, proving the password against the session UVK; A9 review LOW-1).
    const offenders = logins.filter((l) => !(l.path === "ui/Welcome.tsx" && l.code.includes("pre.kdfSalt") && l.code.includes("pre.kdfParams")));
    expect(offenders).toEqual([]);
    expect(logins).toHaveLength(1);
  });

  // ---- M-2 ----

  it("M-2: registration designates the personal vault on the first sync; a fresh device agreeing with it is confirmed", async () => {
    const w = await world();
    const server = serverOf(w);
    const local = memoryClientState();
    const s = store(server, w.owner.account, local); // the registering device: the enrolment just built
    await s.sync();
    expect(w.owner.account.personalStatus).toBe("confirmed");
    expect(await designationOn(server, w.owner)).toBe(w.owner.personalVaultId);
    expect(s.designatedPersonalVaultId()).toBe(w.owner.personalVaultId);
    expect(local.get("personal.wrap")).toContain(w.owner.personalVaultId);

    // A9 review LOW-4: a fresh device (no cached wrap, no high-water mark of its own) confirms the served wrap ONCE,
    // even when the designation names it: on a fresh device the designation is as replayable as the wrap.
    const fresh = await unlock(w.owner);
    const localFresh = memoryClientState();
    const s2 = store(server, fresh, localFresh);
    await s2.sync();
    expect(fresh.personalStatus).toBe("proposed");
    expect(s2.personalChange()).toEqual({ currentVaultId: w.owner.personalVaultId, servedVaultId: w.owner.personalVaultId });
    await s2.sync();
    expect(fresh.personalStatus).toBe("proposed");
    await s2.describePersonalChange();
    s2.acceptPersonalChange();
    expect(fresh.personalStatus).toBe("confirmed");
    expect(fresh.personalVaultId).toBe(w.owner.personalVaultId);
    expect(s2.personalChange()).toBeNull();
    const restarted = await unlock(w.owner);
    await store(server, restarted, localFresh).sync();
    expect(restarted.personalStatus, "exactly once").toBe("confirmed");
  });

  it("review LOW-4: a fresh device served a replayed older state/wrap pair stays proposed", async () => {
    const w = await world(FLOOR);
    const server = serverOf(w);
    const a = store(server, w.owner.account);
    await a.sync();
    const older = { blob: server.accountStateBlob, seq: server.accountSeq };
    await a.redesignatePersonalVault(await a.proposePersonalVault(w.sharedId), w.owner.password);
    expect(await designationOn(server, w.owner)).toBe(w.sharedId);
    server.accountStateBlob = older.blob;
    server.accountSeq = older.seq + 5;
    const b = await unlock(w.owner, w.owner.personalWrap);
    const sb = store(server, b);
    await sb.sync();
    expect(b.personalStatus).toBe("proposed");
    expect(b.personalVaultId).toBe("");
    expect(sb.vaults().every((v) => v.type !== "personal")).toBe(true);
  }, 60_000);

  it("review LOW-1: the reauth proves the password against the session UVK (web has no quick unlock; the proof still refuses a substituted wrap)", async () => {
    const owner = await enroll("a9-qu", FLOOR);
    const uvk = await uvkOfE(owner);
    const device = await unlock(owner);
    // The server answers GET /account/keys with the session's salt but a wrap that is NOT of our UVK: the salt pre-check
    // passes, the proof does not, and no key derived under its parameters is ever sent.
    const junkWrap = toB64(seal(randomBytes(32), uvk, adUvk(owner.userId)));
    await expect(device.reauthAuthKey(owner.password, { ...owner.keys, wrappedUvk: junkWrap })).rejects.toBeInstanceOf(ReauthFailedError);
    // A wrong password is proved wrong locally (never sent to the server to find out).
    await expect(device.reauthAuthKey("not the password", owner.keys)).rejects.toBeInstanceOf(ReauthFailedError);
    // The real keys pass.
    expect(await device.reauthAuthKey(owner.password, owner.keys)).toBe(await expectedAuthKey(owner));
  }, 60_000);

  it("review LOW-2: a default save while proposed is refused with 'Choose a vault for this item.'", async () => {
    const w = await world();
    const server = serverOf(w);
    server.withholdState = true;
    const b = await unlock(w.owner);
    const s = store(server, b);
    await s.sync();
    expect(b.personalStatus).toBe("proposed");
    const doc: ItemDoc = { type: "login", name: "Bank", login: { username: "me", password: "pw" } };
    await expect(s.save(null, doc)).rejects.toBeInstanceOf(NoPersonalVaultError);
    await expect(s.save(null, doc)).rejects.toThrow("Choose a vault for this item.");
    await expect(s.importDocs([])).rejects.toBeInstanceOf(NoPersonalVaultError);
    expect(s.list()).toEqual([]);
    await s.save(null, doc, [], undefined, w.sharedId);
    expect(s.list().map((i) => i.vaultId)).toEqual([w.sharedId]);
  });

  it("M-2: a fresh device served a superseded wrap against the designation asks instead of adopting", async () => {
    const w = await world(FLOOR);
    const server = serverOf(w);
    const a = store(server, w.owner.account);
    await a.sync();
    await a.redesignatePersonalVault(await a.proposePersonalVault(w.sharedId), w.owner.password);
    expect(await designationOn(server, w.owner)).toBe(w.sharedId);
    expect(server.puts).toHaveLength(1);
    await a.sync();
    expect(w.owner.account.personalStatus).toBe("confirmed"); // the established device is unchanged
    expect(w.owner.account.personalVaultId).toBe(w.sharedId);

    const b = await unlock(w.owner, w.owner.personalWrap); // the SUPERSEDED wrap, replayed to a fresh device
    const localB = memoryClientState();
    const sb = store(server, b, localB);
    await sb.sync();
    expect(b.personalStatus).toBe("proposed");
    expect(b.personalVaultId).toBe("");
    expect(sb.personalChange()).toEqual({ currentVaultId: w.sharedId, servedVaultId: w.owner.personalVaultId });
    expect(localB.get("personal.wrap")).toBeNull();
    expect(sb.vaults().every((v) => v.type !== "personal")).toBe(true);
    expect(server.puts).toHaveLength(1);
    expect(await designationOn(server, w.owner)).toBe(w.sharedId);

    await sb.describePersonalChange();
    sb.acceptPersonalChange();
    expect(b.personalStatus).toBe("confirmed");
    expect(b.personalVaultId).toBe(w.owner.personalVaultId);
    expect(localB.get("personal.wrap")).toContain(w.owner.personalVaultId);
    await sb.sync();
    expect(await designationOn(server, w.owner)).toBe(w.owner.personalVaultId);
    expect(server.puts).toHaveLength(1);
  }, 60_000);

  it("M-2: a fresh device with account state withheld treats the served wrap as a proposal, nothing seals under it", async () => {
    const w = await world();
    const server = serverOf(w);
    server.withholdState = true;
    const b = await unlock(w.owner);
    const sb = store(server, b);
    await sb.sync();
    expect(b.personalStatus).toBe("proposed");
    expect(b.personalVaultId).toBe("");
    expect(sb.personalChange()).toEqual({ currentVaultId: "", servedVaultId: w.owner.personalVaultId });
    expect(sb.personalVaultChoices).toBeNull();
    expect(sb.vaults().every((v) => v.type !== "personal")).toBe(true);
    expect(server.puts).toHaveLength(0);
    expect(() => sb.acceptPersonalChange()).toThrow();
    const d = await sb.describePersonalChange();
    expect(d.currentVaultId).toBe("");
    expect(d.servedVaultId).toBe(w.owner.personalVaultId);
    sb.acceptPersonalChange();
    expect(b.personalStatus).toBe("confirmed");
    expect(b.personalVaultId).toBe(w.owner.personalVaultId);
    server.withholdState = false;
    await sb.sync();
    expect(await designationOn(server, w.owner)).toBe(w.owner.personalVaultId);
  });

  it("M-2: a second apply while changed or withheld never switches (the rule lives in Account)", async () => {
    const w = await world();
    const sharedWrap = w.owner.account.buildPersonalWrap(w.sharedId);
    const device = await unlock(w.owner);
    device.applyPersonalWrap(sharedWrap);
    expect(device.personalStatus).toBe("changed");
    expect(device.personalVaultId).toBe(w.owner.personalVaultId);
    expect(device.pendingPersonalChange?.vaultId).toBe(w.sharedId);
    device.applyPersonalWrap(w.owner.personalWrap);
    expect(device.personalStatus).toBe("confirmed");
    expect(device.pendingPersonalChange).toBeNull();

    const withheld = await unlock(w.owner, null);
    withheld.applyCachedPersonalWrap(w.owner.personalWrap);
    expect(withheld.personalStatus).toBe("withheld");
    withheld.applyPersonalWrap(sharedWrap);
    expect(withheld.personalStatus).toBe("changed");
    expect(withheld.personalVaultId).toBe(w.owner.personalVaultId);

    const junked = await unlock(w.owner);
    junked.applyPersonalWrap({ vaultId: w.sharedId, wrappedVk: w.ownerWrap });
    expect(junked.personalStatus).toBe("unreadable-cached");
    expect(junked.personalVaultId).toBe(w.owner.personalVaultId);
  });

  it("M-2: withPersonal always outranks the designation it replaces; an absent key reads as null", () => {
    const u = "33333333-3333-4333-8333-333333333333";
    const doc = withPersonal(emptyAccountState(u), "11111111-1111-4111-8111-111111111111", 100);
    expect(doc.personal).toEqual({ vaultId: "11111111-1111-4111-8111-111111111111", at: 100 });
    const next = withPersonal(doc, "22222222-2222-4222-8222-222222222222", 5);
    expect(next.personal!.vaultId).toBe("22222222-2222-4222-8222-222222222222");
    expect(next.personal!.at).toBeGreaterThan(100);
    expect(isBlankAccountState(next)).toBe(false);
    expect(decodeAccountState(u, JSON.stringify({ v: 1, userId: u, seq: 0 })).personal).toBeNull();
  });

  // ---- M-3 ----

  async function ownerWithCreatedVault(owner: Enrolled, local = memoryClientState()) {
    const server = new FakeServer({ rev: 5, full: true, vaults: [personalRow(owner)], grants: [personalGrant(owner)], items: [], removedGrants: [] });
    server.keys = owner.keys;
    server.selfUserId = owner.userId;
    const s = store(server, owner.account, local);
    await s.sync();
    const vaultId = await s.createSharedVault("Family");
    expect(s.ownsVault(vaultId)).toBe(true);
    return { s, server, vaultId };
  }

  it("M-3: a recorded pair is not re-issued without a confirmation and only annotates the row", async () => {
    const owner = await enroll("a9-owner");
    const member = await enroll("a9-member");
    const { s, server, vaultId } = await ownerWithCreatedVault(owner);
    await s.accountState.pin(pinOf(member, "Member"));
    await s.addVaultMember(vaultId, member.userId, "writer");
    const rec = s.accountState.issued(vaultId, member.userId)!;
    expect(rec).not.toBeNull();
    server.members[vaultId] = [summary(owner, "Owner", "owner"), summary(member, "Member", "writer", true)];
    const rows = await s.loadLegacyGrants(vaultId);
    expect(rows).toHaveLength(1);
    expect(server.reissues).toHaveLength(0);
    expect(rows[0]!.previouslySharedAt).toBe(rec.at);
    expect(rows[0]!.ownershipConfirmed).toBe(true);
    await s.sync();
    expect(server.reissues).toHaveLength(0);
    expect((s as unknown as Record<string, unknown>).reissueGrant).toBeUndefined(); // the prompt-free path is gone
    await s.confirmReissue(rows[0]!);
    expect(server.reissues.map((r) => [r.vaultId, r.userId])).toEqual([[vaultId, member.userId]]);
  });

  it("M-3: a withheld tombstone with a stale blob never re-issues, and the removing device forgets the pair", async () => {
    const owner = await enroll("a9-owner");
    const member = await enroll("a9-member");
    const localA = memoryClientState();
    const { s: a, server, vaultId } = await ownerWithCreatedVault(owner, localA);
    await a.accountState.pin(pinOf(member, "Member"));
    await a.addVaultMember(vaultId, member.userId, "writer");
    const withRecord = server.accountStateBlob;
    await a.removeVaultMember(vaultId, member.userId);
    expect(server.removals).toHaveLength(1);
    expect(a.accountState.issued(vaultId, member.userId)).toBeNull();

    server.accountStateBlob = withRecord;
    server.accountSeq += 1;
    server.members[vaultId] = [summary(owner, "Owner", "owner"), summary(member, "Member", "writer", true)];

    const c = store(server, await unlock(owner));
    await c.sync();
    await c.accountState.pin(pinOf(member, "Member"));
    expect(c.accountState.issued(vaultId, member.userId)).not.toBeNull();
    const rowsC = await c.loadLegacyGrants(vaultId);
    expect(rowsC).toHaveLength(1);
    expect(server.reissues).toHaveLength(0);

    localA.set("acctstate.copy", null);
    localA.set("acctstate.hw", null);
    const a2 = store(server, await unlock(owner), localA);
    await a2.sync();
    expect(a2.accountState.issued(vaultId, member.userId)).not.toBeNull();
    await a2.accountState.pin(pinOf(member, "Member"));
    const rowsA = await a2.loadLegacyGrants(vaultId);
    expect(rowsA).toHaveLength(1);
    expect(rowsA[0]!.previouslySharedAt).toBeNull();
    expect(server.reissues).toHaveLength(0);
  });

  // ---- L-2 ----

  it("L-2: a junk seal beside the owner's own wrap does not mark the vault member-granted", async () => {
    const w = await world(FLOOR);
    const junk = toB64(sealSharedGrant(boxKeypairFromSeed(randomBytes(32)).publicKey, w.sharedId, randomBytes(32)));
    const server = serverOf(w);
    server.feed = { ...w.feed, grants: w.feed.grants.map((g) => (g.vaultId === w.sharedId ? { ...g, sealedVk: junk } : g)) };
    const local = memoryClientState();
    const s = store(server, await unlock(w.owner), local);
    await s.sync();
    expect(s.receivedAsMember(w.sharedId)).toBe(false);
    expect(local.get("grant.member.granted")).toBeNull();
    const claim = await s.describeOwnership(w.sharedId);
    expect(claim.receivedAsMember).toBe(false);
    await s.confirmOwnership(claim, w.owner.password); // no transfer acknowledgement demanded of the genuine creator
    expect(s.ownsVault(w.sharedId)).toBe(true);
    expect(Object.keys((await unlock(w.owner)).openAccountState(server.accountStateBlob!).memberReceived)).toEqual([]);

    const relabelled = serverOf(w);
    relabelled.feed = { ...w.feed, grants: w.feed.grants.map((g) => (g.vaultId === w.sharedId ? { ...g, role: "writer" } : g)) };
    const s2 = store(relabelled, await unlock(w.owner));
    await s2.sync();
    expect(s2.receivedAsMember(w.sharedId)).toBe(false);
  }, 60_000);

  // ---- L-1 ----

  it("L-1: a tombstone or an unheld row served first never homes the item", async () => {
    for (const tombstoneFirst of [true, false]) {
      const victim = await enroll("a9-victim");
      const p = victim.personalVaultId;
      const x = victim.account.newItemId();
      const doc: ItemDoc = { type: "login", name: "Bank", login: { username: "me", password: "P-SECRET-0001" } };
      const up = victim.account.encryptItem(p, x, doc);
      const genuine: WireItem = { itemId: x, vaultId: p, rev: 4, createdAt: 1, updatedAt: 1, deleted: false, conflict: false, formatVersion: up.formatVersion, attachmentIds: [], blob: up.blob };
      const sId = victim.account.newItemId();
      const vkS = randomBytes(32);
      const sRow: WireVault = { vaultId: sId, type: "shared", rev: 7, metaBlob: toB64(seal(vkS, utf8('{"name":"Server"}'), adVaultMeta(sId))), createdAt: 0 };
      const first: WireItem = tombstoneFirst
        ? { itemId: x, vaultId: sId, rev: 3, createdAt: 1, updatedAt: 1, deleted: true, conflict: false, formatVersion: 1, attachmentIds: [], blob: null }
        : { itemId: x, vaultId: sId, rev: 3, createdAt: 1, updatedAt: 1, deleted: false, conflict: false, formatVersion: 1, attachmentIds: [], blob: toB64(seal(vkS, utf8('{"type":"login","name":"bait"}'), adItem(sId, x, 1))) };
      const server = new FakeServer({ rev: 9, full: true, vaults: [personalRow(victim), sRow], grants: [personalGrant(victim)], items: [first, genuine], removedGrants: [] });
      server.keys = victim.keys;
      const s = store(server, await unlock(victim));
      await s.sync();
      const label = tombstoneFirst ? "tombstone first" : "unheld row first";
      expect(s.get(x)?.vaultId, label).toBe(p);
      expect(s.get(x)?.doc, label).toEqual(doc);
      expect(s.quarantinedItems(), label).toEqual([]);
      expect(s.notices().filter((n) => n.kind === "wrong-vault"), label).toHaveLength(0);
    }
  });

  // ---- LOW ----

  it("LOW: a verified transfer away is released even when the first account-state write fails", async () => {
    const owner = await enroll("a9-owner");
    const member = await enroll("a9-member");
    const { s, server, vaultId } = await ownerWithCreatedVault(owner);
    const wrapHash = toHexLower(sha256Sync(utf8("member-wrap")));
    const offerId = "11111111-1111-4111-8111-111111111111";
    const proof = await acceptProofFromHash(await owner.account.lifecycleKeyFor(vaultId), vaultId, offerId, member.userId, 1, wrapHash);
    const rev = server.feed.rev + 1;
    server.feed = {
      ...server.feed, rev, full: true,
      vaults: server.feed.vaults.map((v) => (v.vaultId === vaultId ? { ...v, rev, lastTransfer: { offerId, newOwnerUserId: member.userId, acceptProof: proof, seq: 1, wrapHash } } : v)),
    };
    server.failStatePut = true;
    await s.sync();
    expect(s.ownsVault(vaultId)).toBe(false);
    expect(ownsVault((await unlock(owner)).openAccountState(server.accountStateBlob!), vaultId)).toBe(true);
    server.failStatePut = false;
    await s.sync();
    expect(ownsVault((await unlock(owner)).openAccountState(server.accountStateBlob!), vaultId)).toBe(false);
  });

  it("LOW: a rename refuses a key that contradicts the vouch (INV-WRITE-KEY whatever the path)", async () => {
    const w = await world();
    const device = await unlock(w.owner);
    device.rememberHeldKey(w.sharedId, "ab".repeat(32));
    device.addGrant({ vaultId: w.sharedId, userId: w.owner.userId, role: "owner", wrappedVk: w.ownerWrap, rev: 3, sealedVk: null });
    expect(device.hasVault(w.sharedId) && device.heldKeyContradictsVouch(w.sharedId)).toBe(true);
    expect(() => device.buildRenameMeta(w.sharedId, w.metaBlob, "Renamed")).toThrow(VaultKeyNotVerifiedError);
  });

  it("LOW: recover() wipes the probe account's identity and signing secrets", async () => {
    const r = await enroll("a9-recover");
    const verify: RecoveryVerifyResponse = {
      userId: r.userId, recoveryTicket: "opaque-ticket", recoveryWrappedUvk: r.recoveryWrappedUvk,
      encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub,
    };
    rec.privates.length = 0;
    const commit = await Account.recover({ recoverySecret: r.recoverySecret, verify, newPassword: "a brand new master password", newKdfParams: KDF });
    expect(commit.newWrappedUvk.length).toBeGreaterThan(0);
    expect(rec.privates, "one identity keypair and one signing keypair for the probe").toHaveLength(2);
    for (const { live, at } of rec.privates) {
      expect(at.some((b) => b !== 0)).toBe(true);
      expect(live.every((b) => b === 0), "the probe account's secret key was not wiped").toBe(true);
    }
  });

  it("the account-state sync writes a locally recorded designation back on the next refresh", async () => {
    // updateLocal (non-async, used by acceptPersonalChange) adopts at once and the next refresh writes it.
    const w = await world();
    const server = serverOf(w);
    const sync = new AccountStateSync(server.asClient(), await unlock(w.owner), memoryClientState());
    sync.updateLocal((d) => withPersonal(d, w.sharedId, 7));
    expect(sync.doc.personal?.vaultId).toBe(w.sharedId);
    await sync.refresh();
    expect(await designationOn(server, w.owner)).toBe(w.sharedId);
  });
});
