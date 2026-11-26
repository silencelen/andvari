import { beforeAll, describe, expect, it } from "vitest";
import type { ApiClient } from "../api/client";
import type { AttachmentRef, ItemDoc } from "../api/types";
import { encryptAttachment, fileKeyOf } from "../crypto/attachments";
import { concat, toB64 } from "../crypto/bytes";
import { fingerprint } from "../crypto/escrow";
import { KeysGoneError } from "../crypto/keyfloor";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { SessionClosedError } from "./sessionfence";
import { DamagedAttachmentError, type ItemWire, VaultStore, type VaultItem } from "./store";

/**
 * The shared code's rule of 2026-11-17 (core AttachmentFileKeyTest, ItemCodec.fileKeyOf): an attachment's file key, as
 * its item names it, that is no key (all zeros, the wrong length, not base64url) is damaged content, refused before
 * anything is downloaded, never a lock; and a lock during the download opens nothing.
 */
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const ATT = "0f8e2c1a-3b4d-4e5f-8a9b-0c1d2e3f4a5b";

/** The hostile input, and the only place it is built: a file key of 32 zero bytes. */
const zeroFileKey = (): string => toB64(new Uint8Array(32));

async function rig() {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "filekey-test",
    email: "filekey@example.com",
    displayName: "filekey",
    password: "pw filekey",
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  const key = randomBytes(32);
  const data = randomBytes(1000);
  const enc = encryptAttachment(key, data);
  const body = concat(enc.header, enc.ciphertext);
  const wire = { downloads: 0, onDownload: null as (() => void) | null };
  const items = {
    downloadAttachment: async () => {
      wire.downloads++;
      wire.onDownload?.();
      return body.slice();
    },
  } as unknown as ItemWire;
  const store = new VaultStore({} as ApiClient, account, undefined, undefined, items);
  const ref = (fileKey: string): AttachmentRef => ({ id: ATT, name: "f", size: data.length, fileKey });
  const item = (r: AttachmentRef): VaultItem => ({ itemId: "i", vaultId: "v", rev: 1, updatedAt: 0, formatVersion: 1, doc: { type: "note", name: "n", attachments: [r] } satisfies ItemDoc });
  return { store, wire, ref, item, key, data };
}

describe("an attachment's file key is checked before anything is downloaded", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("all zeros, too short, too long, empty or not base64url: damaged content, with no download; the real key still opens the file", async () => {
    const { store, wire, ref, item, key, data } = await rig();
    for (const bad of [zeroFileKey(), toB64(randomBytes(16)), toB64(randomBytes(33)), "", "not base64url!"]) {
      const e = await store.downloadAttachment(item(ref(bad)), ref(bad)).then(() => "opened", (x: unknown) => x);
      expect(e, bad).toBeInstanceOf(DamagedAttachmentError);
      expect(e, bad).not.toBeInstanceOf(KeysGoneError);
    }
    expect(wire.downloads, "nothing was downloaded").toBe(0);
    expect(await store.downloadAttachment(item(ref(toB64(key))), ref(toB64(key)))).toEqual(data);
    expect(wire.downloads).toBe(1);
  });

  it("a lock during the download opens nothing: the session's end, not the bytes", async () => {
    const { store, wire, ref, item, key } = await rig();
    wire.onDownload = () => store.close();
    const r = ref(toB64(key));
    await expect(store.downloadAttachment(item(r), r)).rejects.toBeInstanceOf(SessionClosedError);
  });

  it("fileKeyOf reads exactly 32 bytes of unpadded base64url that are not all zeros", () => {
    const k = randomBytes(32);
    expect(fileKeyOf(toB64(k))).toEqual(k);
    expect(fileKeyOf(zeroFileKey())).toBeNull();
    expect(fileKeyOf(toB64(randomBytes(31)))).toBeNull();
    expect(fileKeyOf(`${toB64(k)}=`)).toBeNull();
  });
});
