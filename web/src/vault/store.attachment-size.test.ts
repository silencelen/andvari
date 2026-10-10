import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { AttachmentRef, ItemDoc } from "../api/types";
import { encryptAttachment } from "../crypto/attachments";
import { fromB64, toB64 } from "../crypto/bytes";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { planAttachments } from "../export/plan";
import { Account } from "./account";
import { VaultStore, type VaultItem } from "./store";

/**
 * Security review 2026-10 (root cause D): `AttachmentRef.size` is the item author's claim — a
 * co-member's, in a shared vault — and the backup cap budgets with it. A download must therefore
 * be exactly the length that claim implies (core SyncEngine.downloadAttachment twin), and the
 * planner never lets a non-positive claim in.
 */
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

describe("a declared attachment size is checked against the bytes", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("store.downloadAttachment refuses a body that contradicts the declared size", async () => {
    const recovery = boxKeypairFromSeed(randomBytes(32));
    const { account } = await Account.enroll({
      inviteToken: "size-test",
      email: "size@example.com",
      displayName: "size",
      password: "pw size",
      kdfParams: KDF,
      recoveryPublicKey: recovery.publicKey,
      recoveryFingerprint: await fingerprint(recovery.publicKey),
    });
    const key = randomBytes(32);
    const data = randomBytes(100_000);
    const enc = encryptAttachment(key, data);
    const wire = new Uint8Array(enc.header.length + enc.ciphertext.length);
    wire.set(enc.header);
    wire.set(enc.ciphertext, enc.header.length);
    const api = { downloadAttachment: async () => wire } as unknown as ApiClient;
    const store = new VaultStore(api, account);
    const ref = (size: number): AttachmentRef => ({ id: "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b", name: "f", size, fileKey: toB64(key) });
    const item = (r: AttachmentRef): VaultItem => ({ itemId: "i", vaultId: "v", rev: 1, updatedAt: 0, formatVersion: 1, doc: { type: "note", name: "n", attachments: [r] } satisfies ItemDoc });

    expect(await store.downloadAttachment(item(ref(data.length)), ref(data.length))).toEqual(data);
    for (const lie of [10, 1e14, 0, -1]) {
      await expect(store.downloadAttachment(item(ref(lie)), ref(lie)), `claim ${lie}`).rejects.toThrow();
    }
    expect(fromB64(ref(1).fileKey)).toEqual(key);
  });

  it("planAttachments never plans a non-positive claim in", () => {
    const mk = (name: string, size: number): VaultItem => ({
      itemId: name, vaultId: "v", rev: 1, updatedAt: 0, formatVersion: 1,
      doc: { type: "note", name, attachments: [{ id: name, name, size, fileKey: "k" }] },
    });
    const plan = planAttachments([mk("liar", -50), mk("zero", 0), mk("a", 60), mk("b", 60)], 100);
    expect(plan.included.map((e) => e.ref.name)).toEqual(["a"]);
    expect(plan.overCap).toEqual(["liar", "zero", "b"]);
    expect(plan.totalBytes).toBe(60);
  });
});
