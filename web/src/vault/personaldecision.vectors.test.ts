import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { AccountKeys, ItemDoc, PersonalWrap, PushResponse, SyncResponse, VaultMemberSummary } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { memoryClientState } from "./accountstatesync";
import { emptyAccountState, withPersonal } from "./accountstate";
import { NoPersonalVaultError, VaultStore } from "./store";

/**
 * Security review 2026-10, branch A11 (web runner of `personalwrap.json` `decision`; core `PersonalDecisionVectorTest`
 * twin). c00: a withheld or unopenable served wrap no longer puts the cached wrap in force against the account's
 * designation. c01: a designation that moves away from the cached vault is a "changed" notice, never a silent switch.
 * Also c19 (a second apply keeps a proposal a proposal) and c04/c08 (copy-all-to-Personal refuses with no personal
 * vault in force). Each row drives the REAL Account + VaultStore against a fake server.
 */

const vectors = JSON.parse(readFileSync(fileURLToPath(new URL("../../../spec/test-vectors/personalwrap.json", import.meta.url)), "utf-8"));

interface DecisionRow {
  name: string;
  served: "none" | "junk" | "A" | "C";
  cached: "none" | "junk" | "A" | "C";
  designation: "A" | "C" | null;
  mergedStateBefore: boolean;
  expected: { status: string; inForce: "" | "A" | "C"; pending: "A" | "C" | null };
}

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const STATE_SEQ = 3;

class FakeServer {
  keys: AccountKeys | null = null;
  accountStateBlob: string | null = null;
  accountSeq = 0;
  members: Record<string, VaultMemberSummary[]> = {};
  pushes = 0;
  constructor(public feed: SyncResponse) {}
  async sync(since: number): Promise<SyncResponse> {
    return since === 0 ? this.feed : { rev: this.feed.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
  }
  async push(m: { mutationId: string }[]): Promise<PushResponse> {
    this.pushes++;
    return { rev: this.feed.rev, results: m.map((x) => ({ mutationId: x.mutationId, status: "ok", newItemRev: this.feed.rev + 1 })) } as unknown as PushResponse;
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
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

async function world() {
  const email = `a11-${Math.random().toString(16).slice(2)}@example.com`;
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const password = `pw ${email}`;
  const { request, account } = await Account.enroll({ inviteToken: "t", email, displayName: email, password, kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
  const keys: AccountKeys = {
    kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed,
    identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap,
  };
  const shared = account.buildCreateSharedVault("Household");
  const A = request.personalVault.vaultId;
  const C = shared.vaultId;
  const feed: SyncResponse = {
    rev: 5, full: true,
    vaults: [
      { vaultId: A, type: "personal", rev: 2, metaBlob: request.personalVault.metaBlob, createdAt: 0 },
      { vaultId: C, type: "shared", rev: 3, metaBlob: shared.request.metaBlob, createdAt: 0 },
    ],
    grants: [
      { vaultId: A, userId: request.userId, role: "owner", wrappedVk: request.personalVault.wrappedVk, rev: 2, sealedVk: null },
      { vaultId: C, userId: request.userId, role: "owner", wrappedVk: shared.request.wrappedVk, rev: 3, sealedVk: null },
    ],
    items: [], removedGrants: [],
  };
  const wraps: Record<"A" | "C" | "junk", PersonalWrap> = {
    A: request.personalWrap!,
    C: account.buildPersonalWrap(C),
    junk: { vaultId: C, wrappedVk: shared.request.wrappedVk }, // an owner wrap (Ad.vk): never opens as a personal wrap
  };
  return { account, keys, userId: request.userId, password, A, C, wraps, feed };
}

type World = Awaited<ReturnType<typeof world>>;

async function runRow(w: World, row: DecisionRow) {
  const server = new FakeServer(w.feed);
  const served = row.served === "none" ? null : w.wraps[row.served];
  server.keys = { ...w.keys, personalWrap: served };
  const local = memoryClientState();
  if (row.cached !== "none") local.set("personal.wrap", JSON.stringify(w.wraps[row.cached]));
  if (row.designation !== null) {
    const doc = { ...withPersonal(emptyAccountState(w.userId), row.designation === "A" ? w.A : w.C, 1000), seq: STATE_SEQ };
    server.accountStateBlob = w.account.sealAccountState(doc);
    server.accountSeq = STATE_SEQ;
  }
  if (row.mergedStateBefore) local.set("acctstate.hw", String(STATE_SEQ));
  const device = await Account.unlock(w.userId, w.password, server.keys);
  const s = new VaultStore(server.asClient(), device, undefined, local);
  await s.sync();
  return { device, s, server, local };
}

describe("A11 — personal-vault decision vectors (c00, c01)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const rows = vectors.decision as DecisionRow[];
  it("the decision table is present", () => {
    expect(rows.length).toBeGreaterThanOrEqual(15);
  });

  for (const row of rows) {
    it(`decision: ${row.name}`, async () => {
      const w = await world();
      const sym = (id: string | null | undefined) => (id === w.A ? "A" : id === w.C ? "C" : id ? id : id === "" ? "" : null);
      const { device } = await runRow(w, row);
      expect(device.personalStatus, "status").toBe(row.expected.status);
      expect(sym(device.personalVaultId), "in force").toBe(row.expected.inForce);
      const pending = device.personalStatus === "changed" || device.personalStatus === "proposed" ? sym(device.pendingPersonalChange?.vaultId) : null;
      expect(pending, "pending").toBe(row.expected.pending);
    });
  }

  it("c00: the held cached wrap is resolved only by the human, and nothing seals by default meanwhile", async () => {
    const w = await world();
    const { device, s, local } = await runRow(w, { name: "", served: "none", cached: "A", designation: "C", mergedStateBefore: true, expected: { status: "proposed", inForce: "", pending: "A" } });
    expect(s.personalChange()).toEqual({ currentVaultId: w.C, servedVaultId: w.A });
    expect(s.personalVaultChoices).toBeNull();
    const doc: ItemDoc = { type: "login", name: "Bank", login: { username: "me", password: "pw" } };
    await expect(s.save(null, doc)).rejects.toBeInstanceOf(NoPersonalVaultError);
    await s.sync(); // a later sync never confirms it on the human's behalf
    expect(device.personalStatus).toBe("proposed");
    await s.describePersonalChange();
    s.acceptPersonalChange();
    expect(device.personalStatus).toBe("confirmed");
    expect(device.personalVaultId).toBe(w.A);
    expect(local.get("personal.wrap")).toContain(w.A);
    expect(s.designatedPersonalVaultId()).toBe(w.A);
  });

  it("c19: a second apply while proposed keeps the proposal (nothing in force)", async () => {
    const w = await world();
    const device = await Account.unlock(w.userId, w.password, { ...w.keys, personalWrap: w.wraps.A });
    expect(device.personalStatus).toBe("confirmed");
    expect(device.holdPersonalProposal(w.C)).toBe(true);
    device.applyPersonalWrap(w.wraps.A);
    expect(device.personalStatus).toBe("proposed");
    expect(device.personalVaultId).toBe("");
    expect(device.pendingPersonalChange?.vaultId).toBe(w.A);
    expect(device.proposedAgainstDesignation).toBe(w.C);
    device.applyPersonalWrap(w.wraps.C);
    expect(device.personalStatus).toBe("proposed");
    expect(device.personalVaultId).toBe("");
    expect(device.pendingPersonalChange?.vaultId).toBe(w.A);
  });

  it("c04/c08: copy-all-to-Personal with no personal vault in force refuses before sealing anything", async () => {
    const w = await world();
    const { device, s, server } = await runRow(w, { name: "", served: "A", cached: "none", designation: null, mergedStateBefore: false, expected: { status: "proposed", inForce: "", pending: "A" } });
    expect(device.personalVaultId).toBe("");
    await s.save(null, { type: "login", name: "Shared", login: { username: "u", password: "p" } }, [], undefined, w.C);
    const before = server.pushes;
    await expect(s.copyAllToPersonal(w.C)).rejects.toBeInstanceOf(NoPersonalVaultError);
    expect(server.pushes).toBe(before);
  });
});
