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
import { decideRemoval, removeProof } from "../crypto/lifecycleproof";
import { Account } from "./account";
import { type AccountStateDoc, AccountStateError, type Contact, decodeAccountState, emptyAccountState, encodeAccountState, mergeAccountState, withConsumedNonces, withContact, withoutContact } from "./accountstate";
import { AccountStateSync, memoryClientState } from "./accountstatesync";

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

class FakeStateServer {
  sealed: string | null = null;
  seq = 0;
  async accountState(): Promise<AccountStateResponse> {
    return { sealedState: this.sealed, seq: this.seq };
  }
  async putAccountState(sealedState: string, baseSeq: number): Promise<AccountStateResponse> {
    if (baseSeq !== this.seq) throw new ApiError(409, "stale_state", "stale");
    this.sealed = sealedState;
    this.seq += 1;
    return { sealedState, seq: this.seq };
  }
  asClient(): ApiClient {
    return this as unknown as ApiClient;
  }
}

async function account(): Promise<Account> {
  const recovery = boxKeypairFromSeed(randomBytes(32));
  const { account } = await Account.enroll({ inviteToken: "t", email: "s@example.com", displayName: "s", password: "pw pw pw pw", kdfParams: KDF, recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey) });
  return account;
}

const contact = (userId: string, at: number): Contact => ({ userId, identityPub: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM", label: "Bea", verifiedAt: at, method: "typed" });

describe("AccountStateSync — rollback and injection", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a rolled-back state is refused: the local copy wins and is written back above the high-water mark", async () => {
    const a = await account();
    const server = new FakeStateServer();
    const local = memoryClientState();
    const sync = new AccountStateSync(server.asClient(), a, local, () => 1000);
    await sync.pin(contact("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 100));
    const oldBlob = server.sealed!;
    await sync.pin(contact("cccccccc-cccc-4ccc-8ccc-cccccccccccc", 200));
    expect(sync.contacts()).toHaveLength(2);

    server.sealed = oldBlob;
    server.seq = 1;
    const again = new AccountStateSync(server.asClient(), a, local);
    await again.refresh();
    expect(again.anomaly).toBe("rollback");
    expect(again.contacts()).toHaveLength(2);
    const back = a.openAccountState(server.sealed!);
    expect(back.contacts).toHaveLength(2);
    expect(back.seq).toBeGreaterThan(2);
  });

  it("a withheld state after one was seen is a rollback", async () => {
    const a = await account();
    const server = new FakeStateServer();
    const local = memoryClientState();
    await new AccountStateSync(server.asClient(), a, local).pin(contact("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 100));
    server.sealed = null;
    server.seq = 0;
    const again = new AccountStateSync(server.asClient(), a, local);
    await again.refresh();
    expect(again.anomaly).toBe("rollback");
    expect(again.contacts()).toHaveLength(1);
  });

  it("the server cannot ADD a pin: a blob sealed under a key it chose does not open and adds nothing", async () => {
    const a = await account();
    const forged = withContact({ ...emptyAccountState(a.userId), seq: 50 }, contact("dddddddd-dddd-4ddd-8ddd-dddddddddddd", 1));
    const server = new FakeStateServer();
    server.sealed = Buffer.from(seal(new Uint8Array(32).fill(9), utf8(encodeAccountState(forged)), adAccountState(a.userId))).toString("base64url");
    server.seq = 7;
    const sync = new AccountStateSync(server.asClient(), a, memoryClientState());
    await sync.refresh();
    expect(sync.anomaly).toBe("unreadable");
    expect(sync.contacts()).toHaveLength(0);
  });

  it("two devices of one account converge through a 409 and a merge", async () => {
    const a = await account();
    const server = new FakeStateServer();
    const first = new AccountStateSync(server.asClient(), a, memoryClientState());
    const second = new AccountStateSync(server.asClient(), a, memoryClientState());
    await first.pin(contact("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 100));
    await second.pin(contact("cccccccc-cccc-4ccc-8ccc-cccccccccccc", 200));
    expect(a.openAccountState(server.sealed!).contacts.map((c) => c.userId).sort()).toEqual(["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "cccccccc-cccc-4ccc-8ccc-cccccccccccc"]);
  });
});

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

  it("a later re-recording on another device cannot launder a replayed v1 removal into the window", async () => {
    // D consumed the v1 nonce at t=1_000; another device later wrote it again at t=50_000_000 (an N-1 build's
    // already_recorded, or its own valid_legacy). A device that saw the vault go live again at t=40_000_000 is shown
    // the proof replayed: the record's time is the only time a v1 proof has, so it must still be D's.
    const key = randomBytes(32);
    const nonce = "v1-nonce-a";
    for (const [local, served] of [
      [doc(3, [[nonce, 1_000]]), doc(4, [[nonce, 50_000_000]])],
      [doc(4, [[nonce, 50_000_000]]), doc(3, [[nonce, 1_000]])],
    ] as const) {
      const merged = mergeAccountState(me, local, served, 0).doc;
      const at = new Map(merged.consumedNonces[vault]!.map(([n, t]) => [n, t] as const));
      expect(at.get(nonce)).toBe(1_000);
      const d = await decideRemoval({
        lifecycleKey: key, vaultId: vault, myUserId: me, reason: "removed", proofV: 1,
        proof: await removeProof(key, vault, me, nonce), nonce,
        consumed: new Set(), consumedAccount: new Set(at.keys()), consumedAccountAt: at, liveSince: 40_000_000, now: 50_000_100,
      });
      expect(d.verdict).toBe("anomaly");
      expect(d.step).toBe("window");
    }
  });
});
