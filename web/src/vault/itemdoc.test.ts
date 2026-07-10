import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ItemDoc, WireItem } from "../api/types";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";

/**
 * Consumes spec/test-vectors/itemdoc.json — the SAME file the Kotlin twin
 * (core ItemDocVectorsTest) checks — so both impls preserve unknown item-doc fields
 * identically (spec 02 §3). Assertions are PER-PATH, never whole-object: Kotlin
 * re-encodes with encodeDefaults + explicit nulls, web omits absent keys, and both
 * shapes are spec-legal. Web preserves unknowns naturally (JSON.parse + spread edits);
 * these vectors pin that no future "helpful" field-by-field rebuild regresses it.
 */

const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));

interface PathExpect {
  path: string;
  valueJson: string;
}

interface ItemDocCase {
  name: string;
  docJson: string;
  edit: Record<string, unknown>;
  expectUnknownPaths: PathExpect[];
  expectTyped: PathExpect[];
}

const vectors = JSON.parse(readFileSync(vectorsDir + "itemdoc.json", "utf-8")) as { cases: ItemDocCase[] };

/** The scripted edit through the REAL web edit shape: object spread. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function applyEdit(doc: any, edit: Record<string, unknown>): any {
  if ("none" in edit) return { ...doc };
  if ("setName" in edit) return { ...doc, name: edit["setName"] };
  if ("setFavorite" in edit) return { ...doc, favorite: edit["setFavorite"] };
  if ("setPassword" in edit) return { ...doc, login: { ...doc.login, password: edit["setPassword"] } };
  throw new Error(`unknown edit op: ${Object.keys(edit).join(",")}`);
}

/** JSON-pointer-ish walk; found=false means the path is ABSENT (distinct from null). */
function resolve(root: unknown, pointer: string): { found: boolean; value?: unknown } {
  let cur: unknown = root;
  for (const seg of pointer.replace(/^\//, "").split("/")) {
    if (Array.isArray(cur)) {
      const i = Number(seg);
      if (!Number.isInteger(i) || i < 0 || i >= cur.length) return { found: false };
      cur = cur[i];
    } else if (cur !== null && typeof cur === "object") {
      if (!(seg in (cur as Record<string, unknown>))) return { found: false };
      cur = (cur as Record<string, unknown>)[seg];
    } else {
      return { found: false };
    }
  }
  return { found: true, value: cur };
}

function assertPaths(label: string, kind: string, reencoded: unknown, expectations: PathExpect[]) {
  for (const e of expectations) {
    const actual = resolve(reencoded, e.path);
    expect(actual.found, `${label}: ${kind} path ${e.path} missing after round-trip`).toBe(true);
    expect(actual.value, `${label}: ${kind} path ${e.path}`).toEqual(JSON.parse(e.valueJson));
  }
}

describe("itemdoc.json (spec 02 §3 unknown-field round-trip)", () => {
  it("preserves unknown fields through parse → spread-edit → stringify", () => {
    for (const c of vectors.cases) {
      const doc = JSON.parse(c.docJson);
      const edited = applyEdit(doc, c.edit);
      const reencoded = JSON.parse(JSON.stringify(edited));
      assertPaths(c.name, "unknown", reencoded, c.expectUnknownPaths);
      assertPaths(c.name, "typed", reencoded, c.expectTyped);
    }
  });

  it("preserves unknown fields through the REAL encryptItem/decryptItem path", async () => {
    await initSodium();
    const account = await enroll();
    const c = vectors.cases.find((x) => x.name === "all-levels-set-password")!;
    const itemId = account.newItemId();
    const vaultId = account.personalVaultId;

    const doc = JSON.parse(c.docJson) as ItemDoc;
    // The wire fv comes from the upload (encryptItem computes floor + monotonic reseal),
    // so this round-trip stays valid for any vector case regardless of its doc floor.
    const up = account.encryptItem(vaultId, itemId, doc);
    const decrypted = account.decryptItem(wireItem(itemId, vaultId, up.blob, up.formatVersion));
    const edited = applyEdit(decrypted, c.edit) as ItemDoc;
    const reUp = account.encryptItem(vaultId, itemId, edited);
    const redecrypted = account.decryptItem(wireItem(itemId, vaultId, reUp.blob, reUp.formatVersion));

    const reencoded = JSON.parse(JSON.stringify(redecrypted));
    assertPaths("aead-round-trip", "unknown", reencoded, c.expectUnknownPaths);
    assertPaths("aead-round-trip", "typed", reencoded, c.expectTyped);
  });
});

// Minimum-cost argon2id — these tests exercise the doc pipeline, not the KDF.
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

async function enroll(): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({
    inviteToken: "itemdoc-test",
    email: "itemdoc@example.com",
    displayName: "itemdoc",
    password: "itemdoc vectors password",
    kdfParams: KDF,
    recoveryPublicKey: recovery.publicKey,
    recoveryFingerprint: await fingerprint(recovery.publicKey),
  });
  return account;
}

function wireItem(itemId: string, vaultId: string, blob: string, formatVersion: number): WireItem {
  return { itemId, vaultId, rev: 1, createdAt: 0, updatedAt: 0, deleted: false, conflict: false, formatVersion, attachmentIds: [], blob };
}
