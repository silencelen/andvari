import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import type { ItemDoc } from "../api/types";
import { concat, fromB64, toB64, utf8 } from "../crypto/bytes";
import type { KdfParams } from "../crypto/keys";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import {
  type AttachmentSection,
  BackupError,
  type BackupPayload,
  buildBackup,
  buildBackupWithPayloadBytes,
  csvWarnings,
  decodeBackupPayload,
  openBackup,
  writeCsv,
} from "./export";

/**
 * Consumes spec/test-vectors/export.json — the SAME file the Kotlin ExportVectorsTest
 * checks — so both impls write byte-identical CSVs and produce/open byte-identical
 * backup containers (spec 07 §4). Payload serialization is deliberately NOT
 * byte-compared across impls (key order differs); the pinned payloadUtf8 is sealed
 * as-is via buildBackupWithPayloadBytes.
 */

const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function load(name: string): any {
  return JSON.parse(readFileSync(vectorsDir + name, "utf-8"));
}

beforeAll(async () => {
  await initSodium();
});

const v = load("export.json");

/** Vector kdfParams use the header key `opsLimit`; the core KdfParams key is `ops`. */
function kdfParamsOf(p: { v: number; alg: string; opsLimit: number; memBytes: number }): KdfParams {
  return { v: p.v, alg: p.alg, ops: p.opsLimit, memBytes: p.memBytes };
}

describe("export.json — csv writer (byte-exact)", () => {
  for (const c of v.csv) {
    it(c.name, () => {
      expect(writeCsv(c.docs as ItemDoc[])).toBe(c.csvUtf8);
    });
  }
});

describe("export.json — container produce (byte-exact)", () => {
  for (const c of v.container) {
    it(c.name, async () => {
      const parts = await buildBackupWithPayloadBytes(
        c.passphraseUtf8,
        c.fileId,
        fromB64(c.kdfSaltB64),
        kdfParamsOf(c.kdfParams),
        utf8(c.payloadUtf8),
        [],
        fromB64(c.envelopeNonceB64),
      );
      expect(toB64(concat(...parts))).toBe(c.containerB64);
    });
  }
});

describe("export.json — container open (pinned bytes)", () => {
  for (const c of v.container) {
    it(c.name, async () => {
      const opened = await openBackup(c.passphraseUtf8, fromB64(c.containerB64));
      expect(opened.header.format).toBe("andvari-backup");
      expect(opened.header.v).toBe(1);
      expect(opened.header.fileId).toBe(c.fileId);
      expect(opened.header.kdfSalt).toBe(c.kdfSaltB64);
      expect(opened.attachmentSectionCount).toBe(0);
      // The payload must decode exactly as the pinned plaintext does (unknown
      // payload-level keys tolerated; doc-level unknowns preserved verbatim).
      expect(opened.payload).toEqual(decodeBackupPayload(JSON.parse(c.payloadUtf8)));
    });
  }
});

describe("export.json — reject", () => {
  for (const r of v.reject) {
    it(r.name, async () => {
      let caught: unknown;
      try {
        await openBackup(r.passphraseUtf8, fromB64(r.containerB64));
      } catch (e) {
        caught = e;
      }
      expect(caught, r.name).toBeInstanceOf(BackupError);
      expect((caught as BackupError).code, r.name).toBe(r.reason);
    });
  }
});

describe("backup round-trip (own impl — random params + attachment sections)", () => {
  // Minimum-cost argon2id — these tests exercise framing/crypto plumbing, not the KDF.
  const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
  const PASS = "round-trip passphrase";

  function makePayload(attachments: BackupPayload["attachments"]): BackupPayload {
    const doc = {
      type: "login",
      name: "GitHub",
      login: { username: "jacob", password: "hunter2", uris: ["https://github.com/login"] },
      attachments: [{ id: "at-1", name: "scan.pdf", size: 5, fileKey: toB64(randomBytes(32)) }],
      "x-unknown": { keep: true }, // doc-level unknown fields must survive build→open
    } as unknown as ItemDoc;
    return {
      v: 1,
      exportedAt: 1751850000000,
      origin: "https://andvari.example.net",
      userId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      identityFingerprint: "0123456789abcdef",
      vaults: [{ vaultId: "v-1", type: "personal", name: "Personal", role: "owner" }],
      items: [{ itemId: "i-1", vaultId: "v-1", formatVersion: 1, updatedAt: 1751840000000, doc }],
      attachments,
      skipped: { undecryptable: [], attachmentsOverCap: ["tax-archive.zip"], attachmentFetchFailed: [] },
    };
  }

  it("builds, opens, and decrypts an attachment section; truncation and wrong keys reject", async () => {
    const fileKey = randomBytes(32);
    // > one 64 KiB chunk so the section spans multiple secretstream chunks.
    const attachmentPlain = new Uint8Array(70_000).map((_, i) => i & 0xff);
    const payload = makePayload([
      { section: 1, attachmentId: "at-1", itemId: "i-1", name: "scan.pdf", size: attachmentPlain.length, fileKey: toB64(fileKey) },
    ]);
    const sections: AttachmentSection[] = [
      // build() zeroes the supplied buffer after sealing — hand it a copy.
      { fileKey, plaintext: () => attachmentPlain.slice() },
    ];
    const parts = await buildBackup(PASS, crypto.randomUUID(), randomBytes(16), KDF, payload, sections);
    const bytes = concat(...parts);

    const opened = await openBackup(PASS, bytes);
    expect(opened.attachmentSectionCount).toBe(1);
    // Payload round-trips through our own serialize→seal→open→decode path.
    expect(opened.payload).toEqual(payload);
    // Doc-level unknown fields survive verbatim.
    expect((opened.payload.items[0]!.doc as unknown as Record<string, unknown>)["x-unknown"]).toEqual({ keep: true });
    // The attachment section decrypts to the exact plaintext under the manifest fileKey.
    expect(toB64(opened.readAttachment(opened.payload.attachments[0]!))).toBe(toB64(attachmentPlain));

    // Wrong per-attachment key → the combined AEAD failure code.
    let wrongKey: unknown;
    try {
      opened.readAttachmentSection(1, randomBytes(32));
    } catch (e) {
      wrongKey = e;
    }
    expect(wrongKey).toBeInstanceOf(BackupError);
    expect((wrongKey as BackupError).code).toBe("wrong_passphrase_or_corrupt");

    // A truncated file fails the framing scan (spec 07 §2.2 step 4) before any KDF.
    let truncated: unknown;
    try {
      await openBackup(PASS, bytes.subarray(0, bytes.length - 1));
    } catch (e) {
      truncated = e;
    }
    expect(truncated).toBeInstanceOf(BackupError);
    expect((truncated as BackupError).code).toBe("truncated");

    // Wrong passphrase on our own container → wrong_passphrase_or_corrupt.
    let wrongPass: unknown;
    try {
      await openBackup("not the passphrase", bytes);
    } catch (e) {
      wrongPass = e;
    }
    expect(wrongPass).toBeInstanceOf(BackupError);
    expect((wrongPass as BackupError).code).toBe("wrong_passphrase_or_corrupt");
  });

  it("rejects a manifest/section mismatch at build time", async () => {
    const payload = makePayload([
      { section: 1, attachmentId: "at-1", itemId: "i-1", name: "scan.pdf", size: 3, fileKey: toB64(randomBytes(32)) },
    ]);
    await expect(buildBackup(PASS, crypto.randomUUID(), randomBytes(16), KDF, payload, [])).rejects.toThrow(
      /manifest lists 1 attachments/,
    );
  });
});

describe("csvWarnings (spec 07 §1 — by NAME, independent categories)", () => {
  it("enumerates all five categories", () => {
    const docs = [
      { type: "note", name: "Wifi", notes: "router" },
      { type: "card", name: "Visa", card: { number: "4242424242424242", brand: "visa" } },
      {
        type: "login",
        name: "Extra",
        login: { username: "u", password: "p", uris: ["https://a.test", "https://b.test"] },
        attachments: [{ id: "1", name: "a.bin", size: 1, fileKey: "a2V5" }],
      },
      { type: "login", name: "EmptyBoth", login: { username: "", password: "", uris: ["https://w.test"] } },
      { type: "login", name: "NoLoginBlock" },
    ] as unknown as ItemDoc[];
    const w = csvWarnings(docs);
    expect(w.noteItems).toEqual(["Wifi"]);
    expect(w.cardItems).toEqual(["Visa"]);
    expect(w.withAttachments).toEqual(["Extra"]);
    expect(w.extraUris).toEqual(["Extra"]);
    expect(w.emptyUsernameAndPassword).toEqual(["EmptyBoth", "NoLoginBlock"]);
  });

  it("cards split out of noteItems; notes keep their list; the writer stays logins-only", () => {
    const docs = [
      { type: "card", name: "Visa", card: { number: "4242424242424242", brand: "visa" } },
      { type: "note", name: "Wifi", notes: "router" },
      { type: "login", name: "GitHub", login: { username: "u", password: "p" } },
    ] as unknown as ItemDoc[];
    const w = csvWarnings(docs);
    expect(w.cardItems).toEqual(["Visa"]);
    expect(w.noteItems).toEqual(["Wifi"]); // never the card — cards have their own list
    // CSV rows unchanged by the card type: only the login row is written (vector-pinned shape).
    expect(writeCsv(docs)).toBe("name,url,username,password,note,totp\r\nGitHub,,u,p,,\r\n");
  });

  it("cards mirror notes against the other lists: attachment-eligible, login-only lists never", () => {
    const docs = [
      {
        type: "card",
        name: "Amex",
        card: { number: "378282246310005" },
        attachments: [{ id: "1", name: "front.jpg", size: 1, fileKey: "a2V5" }],
        // A stray login block on a card must not drag it into the login-gated lists
        // (same containment notes have always had).
        login: { username: "", password: "", uris: ["https://a.test", "https://b.test"] },
      },
      {
        type: "note",
        name: "NoteScan",
        attachments: [{ id: "2", name: "b.bin", size: 1, fileKey: "a2V5" }],
      },
    ] as unknown as ItemDoc[];
    const w = csvWarnings(docs);
    expect(w.cardItems).toEqual(["Amex"]);
    expect(w.noteItems).toEqual(["NoteScan"]);
    expect(w.withAttachments).toEqual(["Amex", "NoteScan"]); // type-blind, exactly as notes today
    expect(w.extraUris).toEqual([]); // login-only lists stay login-only
    expect(w.emptyUsernameAndPassword).toEqual([]);
  });
});
