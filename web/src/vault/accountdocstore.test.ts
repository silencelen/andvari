import { beforeAll, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AccountStateResponseV2 } from "../api/wire";
import { adAccountState } from "../crypto/ad";
import { toB64, utf8 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { type AccountDocument, EMPTY_DOCUMENT, encodeDocument, withAccepted, withRecovery } from "./accountdoc";
import { AccountStateStore, openAccountBlob } from "./accountdocstore";

/** The compare-and-set loop, rollback and withholding detection of the account-state store (spec 03 §3, design §5.4). */

const USER = "11111111-1111-4111-8111-111111111111";
const VAULT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER = "22222222-2222-4222-8222-222222222222";

const memory = memoryStorage;

/** A fake server holding one blob with a CAS counter; `script` may override answers. */
class FakeServer {
  sealed: string | null = null;
  cas = 0;
  puts = 0;
  staleFor = 0;
  getError: unknown = null;
  async accountState(): Promise<AccountStateResponseV2> {
    if (this.getError) throw this.getError;
    return { sealedState: this.sealed, seq: this.cas };
  }
  async putAccountState(sealedState: string, baseSeq: number): Promise<AccountStateResponseV2> {
    this.puts++;
    if (this.staleFor > 0) {
      this.staleFor--;
      this.cas++;
      throw new ApiError(409, "stale_state", "stale");
    }
    if (baseSeq !== this.cas) throw new ApiError(409, "stale_state", "stale");
    this.sealed = sealedState;
    this.cas++;
    return { sealedState, seq: this.cas };
  }
}

const sealFor = (uvk: Uint8Array, doc: AccountDocument): string => toB64(seal(uvk, utf8(encodeDocument(USER, doc)), adAccountState(USER)));

describe("AccountStateStore", () => {
  let uvk: Uint8Array;
  beforeAll(async () => {
    await initSodium();
    uvk = randomBytes(32);
  });

  it("writes with the next in-blob seq and keys in byte order, under the account's AD", async () => {
    const server = new FakeServer();
    const store = new AccountStateStore(USER, uvk, server, memory());
    const w = await store.update((d) => withAccepted(d, { vaultId: VAULT, owner: OWNER, addSeq: 1, at: 5, decision: "accept" }));
    expect(w.kind).toBe("written");
    const text = openAccountBlob(uvk, USER, server.sealed!)!;
    expect(JSON.parse(text).seq).toBe(1);
    expect(JSON.parse(text).accepted[VAULT].decision).toBe("accept");
    expect(store.highWater()).toBe(1);
  });

  it("merges and retries on 409 stale_state", async () => {
    const server = new FakeServer();
    server.staleFor = 2;
    const store = new AccountStateStore(USER, uvk, server, memory());
    const w = await store.update((d) => withRecovery(d, { posture: "private", fp: "none", at: 10 }));
    expect(w.kind).toBe("written");
    expect(server.puts).toBe(3);
  });

  it("gives up as contended after the bounded retries", async () => {
    const server = new FakeServer();
    server.staleFor = 99;
    const store = new AccountStateStore(USER, uvk, server, memory(), undefined, 3);
    expect((await store.update((d) => withRecovery(d, { posture: "private", fp: "none", at: 10 }))).kind).toBe("contended");
  });

  it("reports a rollback and keeps what the local copy holds", async () => {
    const server = new FakeServer();
    const storage = memory();
    const store = new AccountStateStore(USER, uvk, server, storage);
    await store.update((d) => withAccepted(d, { vaultId: VAULT, owner: OWNER, addSeq: 1, at: 5, decision: "accept" }));
    await store.update((d) => withAccepted(d, { vaultId: VAULT, owner: OWNER, addSeq: 1, at: 6, decision: "decline" }));
    // The server serves an older document (seq 1, the accept) than this browser has seen (seq 2).
    server.sealed = sealFor(uvk, withAccepted({ ...EMPTY_DOCUMENT, seq: 1 }, { vaultId: VAULT, owner: OWNER, addSeq: 1, at: 5, decision: "accept" }));
    const r = await store.read();
    expect(r.kind).toBe("ok");
    if (r.kind !== "ok") return;
    expect(r.anomalies).toContainEqual({ kind: "rollback", servedSeq: 1, highWater: 2 });
    expect(r.document.accepted.get(VAULT)!.decision).toBe("decline");
  });

  it("reports a withheld blob after one was seen, and not before", async () => {
    const server = new FakeServer();
    const store = new AccountStateStore(USER, uvk, server, memory());
    const first = await store.read();
    expect(first.kind === "ok" && first.anomalies).toEqual([]);
    await store.update((d) => withRecovery(d, { posture: "private", fp: "none", at: 10 }));
    server.sealed = null;
    const r = await store.read();
    expect(r.kind === "ok" && r.anomalies).toEqual([{ kind: "withheld" }]);
    expect(r.kind === "ok" && r.document.recovery?.posture).toBe("private");
  });

  it("an unopenable served blob leaves the local copy in force and is reported", async () => {
    const server = new FakeServer();
    const store = new AccountStateStore(USER, uvk, server, memory());
    await store.update((d) => withRecovery(d, { posture: "private", fp: "none", at: 10 }));
    server.sealed = toB64(seal(randomBytes(32), utf8("{}"), adAccountState(USER)));
    const r = await store.read();
    expect(r.kind).toBe("unopenable");
    expect(r.document.recovery?.posture).toBe("private");
    expect((await store.update((d) => withRecovery(d, { posture: "operator", fp: "a".repeat(64), at: 11 }))).kind).toBe("refused");
  });

  it("an unreachable read carries its error", async () => {
    const server = new FakeServer();
    server.getError = new TypeError("network");
    const r = await new AccountStateStore(USER, uvk, server, memory()).read();
    expect(r.kind).toBe("unreachable");
    expect(r.kind === "unreachable" && r.error).toBeInstanceOf(TypeError);
  });

  it("refuses to write a document that does not fit, and one whose seq cannot advance", async () => {
    const server = new FakeServer();
    const tiny = new AccountStateStore(USER, uvk, server, memory(), { contacts: 1000, tombstones: 1000, sealedChars: 200 });
    expect(await tiny.update((d) => withRecovery(d, { posture: "private", fp: "none", at: 10 }))).toEqual({ kind: "refused", code: "account_state_full" });
    server.sealed = sealFor(uvk, { ...EMPTY_DOCUMENT, seq: 2 ** 53 - 1 });
    const store = new AccountStateStore(USER, uvk, server, memory());
    expect(await store.update((d) => withRecovery(d, { posture: "private", fp: "none", at: 10 }))).toEqual({ kind: "refused", code: "account_state_damaged" });
  });

  it("an explicit recovery choice wins even from a device whose clock is behind", async () => {
    const d1 = withRecovery(EMPTY_DOCUMENT, { posture: "operator", fp: "a".repeat(64), at: 1000 });
    const d2 = withRecovery(d1, { posture: "private", fp: "none", at: 10 });
    expect(d2.recovery).toMatchObject({ posture: "private", at: 1001 });
  });

  it("writes nothing when the change is already in the document", async () => {
    const server = new FakeServer();
    const store = new AccountStateStore(USER, uvk, server, memory());
    await store.update((d) => withAccepted(d, { vaultId: VAULT, owner: OWNER, addSeq: 1, at: 5, decision: "accept" }));
    const w = await store.update((d) => withAccepted(d, { vaultId: VAULT, owner: OWNER, addSeq: 1, at: 5, decision: "accept" }));
    expect(w.kind).toBe("unchanged");
    expect(server.puts).toBe(1);
  });
});
