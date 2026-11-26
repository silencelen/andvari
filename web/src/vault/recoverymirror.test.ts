import { beforeAll, describe, expect, it } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import type { AccountStateResponseV2 } from "../api/wire";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { NONE } from "../crypto/trust/grammar";
import { AccountStateStore } from "./accountdocstore";
import { mirrorAgrees, readMirror, recordRecoveryChoice } from "./recoverymirror";

const U = "11111111-1111-4111-8111-111111111111";

class Server {
  sealed: string | null = null;
  seq = 0;
  fail = false;
  async accountState(): Promise<AccountStateResponseV2> {
    return { sealedState: this.sealed, seq: this.seq };
  }
  async putAccountState(sealedState: string, baseSeq: number): Promise<AccountStateResponseV2> {
    if (this.fail) throw new Error("offline");
    if (baseSeq !== this.seq) throw new Error("stale");
    this.sealed = sealedState;
    this.seq++;
    return { sealedState, seq: this.seq };
  }
}

describe("the recovery record and this browser's mirror (design §4.5)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a choice made here lands in the account state and then in the mirror, stamped after the record it supersedes", async () => {
    const server = new Server();
    const storage = memoryStorage();
    const store = new AccountStateStore(U, randomBytes(32), server, storage);
    const w = await recordRecoveryChoice(store, storage, U, { posture: "private", fp: NONE }, 1000);
    expect(w.kind).toBe("written");
    const m = readMirror(storage, U);
    expect(m).toEqual({ posture: "private", fp: NONE, at: 1000 });
    expect(mirrorAgrees(m, store.local().recovery)).toBe(true);
    // A later choice with an earlier clock is still stamped after the one in force.
    const w2 = await recordRecoveryChoice(store, storage, U, { posture: "private", fp: NONE }, 500);
    expect(w2.kind).toBe("written");
    expect(store.local().recovery!.at).toBe(1001);
    expect(readMirror(storage, U)!.at).toBe(1001);
  });

  it("a write that did not land sets no mirror, and a mirror that does not decode is no mirror", async () => {
    const server = new Server();
    server.fail = true;
    const storage = memoryStorage();
    const store = new AccountStateStore(U, randomBytes(32), server, storage);
    const w = await recordRecoveryChoice(store, storage, U, { posture: "private", fp: NONE }, 1000);
    expect(w.kind).not.toBe("written");
    expect(readMirror(storage, U)).toBeNull();
    storage.set(`andvari.recmirror.${U}`, '{"posture":"operator","fp":"x","at":1}');
    expect(readMirror(storage, U)).toBeNull();
    expect(mirrorAgrees(null, store.local().recovery)).toBe(false);
  });
});
