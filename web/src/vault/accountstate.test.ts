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
import { type AccountStateDoc, AccountStateError, type Contact, decodeAccountState, emptyAccountState, encodeAccountState, mergeAccountState, withContact } from "./accountstate";
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
