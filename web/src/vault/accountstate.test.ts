import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiError, type ApiClient } from "../api/client";
import type { AccountStateResponse } from "../api/types";
import { adAccountState } from "../crypto/ad";
import { fromB64, fromUtf8, utf8 } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import type { KdfParams } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Account } from "./account";
import { type AccountStateDoc, AccountStateError, type Contact, decodeAccountState, emptyAccountState, encodeAccountState, mergeAccountState, withConsumedNonces, withContact, withoutContact } from "./accountstate";

/**
 * Security review 2026-10, root cause A §4.2 (branch A5): the account-state blob — vector rows from
 * spec/test-vectors/accountstate.json (shared with core AccountStateTest), then the sync client against a
 * scripted hostile server: a rolled-back blob is REFUSED (local wins, written back), an injected blob does
 * not open and adds nothing.
 */

const vectorsDir = fileURLToPath(new URL("../../../spec/test-vectors/", import.meta.url));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const v: any = JSON.parse(readFileSync(vectorsDir + "accountstate.json", "utf-8"));
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const docOf = (o: any): AccountStateDoc | null => (o === null ? null : decodeAccountState(o.userId, JSON.stringify(o)));
const canon = (d: AccountStateDoc | null) => (d === null ? null : encodeAccountState(d));

describe("accountstate.json", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the sample blob opens; another user's slot and an injected key do not; malformed documents are refused", () => {
    expect(fromUtf8(adAccountState(v.userId))).toBe(v.adUtf8);
    const uvk = fromB64(v.uvkB64);
    const plain = fromUtf8(open(uvk, fromB64(v.sampleBlobB64), adAccountState(v.userId)));
    expect(canon(decodeAccountState(v.userId, plain))).toBe(canon(docOf(v.sample)));
    for (const r of v.rejectOpen) expect(() => open(uvk, fromB64(r.blobB64), adAccountState(v.userId)), r.name).toThrow();
    for (const r of v.rejectDecode) expect(() => decodeAccountState(v.userId, r.plaintext), r.name).toThrow(AccountStateError);
  });

  it("merge rows", () => {
    for (const r of v.merge) {
      const m = mergeAccountState(v.userId, docOf(r.local), docOf(r.served), r.highWater);
      expect(m.rollback, `rollback ${r.name}`).toBe(r.expected.rollback);
      expect(canon(m.doc), `doc ${r.name}`).toBe(canon(docOf(r.expected.doc)));
    }
  });
});

const contact = (userId: string, at: number): Contact => ({ userId, identityPub: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM", label: "Bea", verifiedAt: at, method: "typed" });

// The old AccountStateSync (this browser's copy of the old document, merged on every sync) is gone, and
// its tests with it; store.n2.test.ts pins that nothing imports it. The new account state is accountdocstore.ts's.

describe("A13 (security review 2026-10, q23): a human unpin / re-pin wins the merge under clock skew", () => {
  const u = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const me = "33333333-3333-4333-8333-333333333333";
  const merge = (a: AccountStateDoc, b: AccountStateDoc) => mergeAccountState(me, a, b, 0).doc;

  it("an unpin on a slow clock still removes the pin another device recorded later", () => {
    const pinned = withContact({ ...emptyAccountState(me), seq: 1 }, contact(u, 5_000));
    const unpinned = withoutContact(pinned, u, 1_000);
    expect(unpinned.contactTombstones[u]).toBeGreaterThanOrEqual(5_000);
    expect(merge(unpinned, pinned).contacts.some((c) => c.userId === u)).toBe(false);
    expect(merge(pinned, unpinned).contacts.some((c) => c.userId === u)).toBe(false);
  });

  it("a re-pin on a slow clock survives the tombstone it replaces", () => {
    const tomb = withoutContact(withContact({ ...emptyAccountState(me), seq: 1 }, contact(u, 100)), u, 5_000);
    const repinned = withContact(tomb, contact(u, 1_000));
    expect(merge(repinned, tomb).contacts.map((c) => c.userId)).toEqual([u]);
  });

  it("a re-verification with a changed key on a slow clock wins the merge", () => {
    const oldPin = withContact({ ...emptyAccountState(me), seq: 1 }, contact(u, 5_000));
    const newKey: Contact = { ...contact(u, 1_000), identityPub: "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk" };
    const merged = merge(withContact(oldPin, newKey), oldPin);
    expect(merged.contacts.find((c) => c.userId === u)?.identityPub).toBe(newKey.identityPub);
    expect(withContact(oldPin, contact(u, 1_000)).contacts.find((c) => c.userId === u)?.verifiedAt).toBe(5_000);
  });
});

describe("A13 review RF3: a consumed nonce keeps the EARLIEST time any device recorded for it", () => {
  const me = "33333333-3333-4333-8333-333333333333";
  const vault = "66666666-6666-4666-8666-666666666666";
  const doc = (seq: number, list: Array<[string, number]>): AccountStateDoc => ({ ...emptyAccountState(me), seq, consumedNonces: { [vault]: list } });
  beforeAll(async () => {
    await initSodium();
  });

  it("withConsumedNonces keeps the earlier time for a repeated nonce, whichever side holds it", () => {
    expect(withConsumedNonces(doc(1, [["v1-nonce-a", 100]]), { [vault]: [["v1-nonce-a", 5_000], ["v1-nonce-c", 200]] }).consumedNonces[vault]).toEqual([
      ["v1-nonce-c", 200],
      ["v1-nonce-a", 100],
    ]);
    expect(withConsumedNonces(doc(1, [["v1-nonce-a", 5_000]]), { [vault]: [["v1-nonce-a", 100]] }).consumedNonces[vault]).toEqual([["v1-nonce-a", 100]]);
  });

  it("a later re-recording on another device cannot move a consumed nonce's time forward, whichever side holds it", () => {
    // D consumed the nonce at t=1_000; another device later wrote it again at t=50_000_000. The merged record keeps
    // D's time. (The removal decision this fed went with the lifecycle proofs, design §15's web row.)
    const nonce = "v1-nonce-a";
    for (const [local, served] of [
      [doc(3, [[nonce, 1_000]]), doc(4, [[nonce, 50_000_000]])],
      [doc(4, [[nonce, 50_000_000]]), doc(3, [[nonce, 1_000]])],
    ] as const) {
      const merged = mergeAccountState(me, local, served, 0).doc;
      const at = new Map(merged.consumedNonces[vault]!.map(([n, t]) => [n, t] as const));
      expect(at.get(nonce)).toBe(1_000);
    }
  });
});
