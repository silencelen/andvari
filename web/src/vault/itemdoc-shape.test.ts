import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { ItemDoc, Mutation, PushResponse, SyncResponse, WireGrant, WireItem, WireVault } from "../api/types";
import { adItem, adVaultMeta } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { sealSharedGrant } from "../crypto/sharedgrant";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { itemDocProblem, vaultMetaName } from "./itemdoc-shape";
import { VaultStore } from "./store";

/**
 * Security review 2026-10 (root cause D): a document that opens under a vault key was still
 * WRITTEN by whoever holds that key — any writer of a shared vault — so its JSON is untrusted.
 * One `{"name": 1}` item used to throw inside VaultStore.list()'s comparator during render and,
 * with no error boundary, blank every member's vault on every unlock. The shared vectors pin the
 * verdict all three engines reach (core ItemDocShapeVectorTest, extension itemdocshape.test.ts);
 * the store test pins the consequence: a failing item is quarantined like an undecryptable one.
 */
const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
const v = JSON.parse(readFileSync(vectorsDir + "itemdoc-validate.json", "utf-8"));

describe("itemdoc-validate.json — the shared shape verdict", () => {
  it("every item case reaches the vector's verdict", () => {
    for (const c of v.items) {
      const problem = itemDocProblem(JSON.parse(c.docJson));
      expect(problem === null, `${c.name}: ${problem}`).toBe(c.valid);
    }
  });

  it("a vault name is displayed only when it is a JSON string", () => {
    for (const c of v.vaultNames) {
      expect(vaultMetaName(JSON.parse(c.metaJson)), c.name).toBe(c.expected);
    }
  });
});

const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

class FakeApi {
  queue: SyncResponse[] = [];
  rev = 1;
  async sync(): Promise<SyncResponse> {
    const resp = this.queue.shift() ?? { rev: this.rev, full: false, vaults: [], grants: [], items: [], removedGrants: [] };
    this.rev = Math.max(this.rev, resp.rev);
    return resp;
  }
  async push(mutations: Mutation[]): Promise<PushResponse> {
    return { rev: ++this.rev, results: mutations.map((m) => ({ mutationId: m.mutationId, status: "applied" as const, newItemRev: 1 })) };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

async function enroll(email: string): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "shape-test",
    email,
    displayName: email,
    password: `pw ${email}`,
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return account;
}

const wire = (vaultId: string, itemId: string, blob: string, rev: number): WireItem => ({
  itemId, vaultId, rev, createdAt: 0, updatedAt: 0, deleted: false, conflict: false, formatVersion: 1, attachmentIds: [], blob,
});

describe("a hostile co-member's malformed item is quarantined, not rendered", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the vault still lists, sorts and names; the bad items land in the undecryptable set", async () => {
    const member = await enroll("member@example.com");
    // A shared vault whose VK the attacker also holds — they can seal any plaintext under it.
    const vaultId = member.newItemId();
    const vk = randomBytes(32);
    const grant: WireGrant = { vaultId, userId: member.userId, role: "writer", wrappedVk: "", rev: 2, sealedVk: toB64(sealSharedGrant(member.identityPub, vaultId, vk)) };
    const metaBlob = toB64(seal(vk, utf8(JSON.stringify({ name: { evil: true }, metaV: 1 })), adVaultMeta(vaultId)));
    const vault: WireVault = { vaultId, type: "shared", rev: 2, metaBlob, createdAt: 0 };
    const sealRaw = (itemId: string, plaintext: string) => toB64(seal(vk, utf8(plaintext), adItem(vaultId, itemId, 1)));

    const good = member.newItemId();
    const badName = member.newItemId();
    const badUris = member.newItemId();
    const nullDoc = member.newItemId();
    const badAttachment = member.newItemId();
    const items = [
      wire(vaultId, good, sealRaw(good, JSON.stringify({ type: "login", name: "Fine", login: { uris: ["https://a.test"] } } satisfies ItemDoc)), 3),
      wire(vaultId, badName, sealRaw(badName, '{"type":"login","name":1}'), 4),
      wire(vaultId, badUris, sealRaw(badUris, '{"type":"login","name":"Zed","login":{"uris":[1]}}'), 5),
      wire(vaultId, nullDoc, sealRaw(nullDoc, "null"), 6),
      wire(vaultId, badAttachment, sealRaw(badAttachment, '{"type":"note","name":"Aha","attachments":[{"id":"../admin/users/x/escrow","name":"e","size":1,"fileKey":"k"}]}'), 7),
    ];

    const api = new FakeApi();
    const store = new VaultStore(api.asClient(), member);
    api.queue.push({ rev: 8, full: true, vaults: [vault], grants: [grant], items, removedGrants: [] });
    await store.sync();

    expect(() => store.list()).not.toThrow();
    expect(store.list().map((i) => i.doc.name)).toEqual(["Fine"]);
    expect(store.undecryptable().map((u) => u.itemId).sort()).toEqual([badName, badUris, nullDoc, badAttachment].sort());
    // A non-string vault name never reaches a JSX child or a localeCompare.
    const names = store.vaults().map((x) => x.name);
    expect(names.every((n) => typeof n === "string")).toBe(true);
    expect(names).toContain("Shared");
  });
});

describe("the web app has an error boundary around everything it renders", () => {
  it("main.tsx mounts <App /> inside <ErrorBoundary>", () => {
    const main = readFileSync(fileURLToPath(new URL("../main.tsx", import.meta.url)), "utf8");
    expect(main).toMatch(/<ErrorBoundary>\s*<App \/>\s*<\/ErrorBoundary>/);
  });
});
