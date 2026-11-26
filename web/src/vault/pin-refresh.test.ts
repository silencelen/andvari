import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { ApiClient } from "../api/client";
import type { SyncResponse } from "../api/types";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { memoryClientState } from "./accountstatesync";
import { Account } from "./account";
import { NullCache } from "./idbcache";
import { type ItemWire, VaultStore } from "./store";

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

function store() {
  const seed = randomBytes(32);
  const account = Account.fromOpened(
    { userId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", uvk: randomBytes(32), identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed), genesis: null as never, personalVaultId: null, personalVk: null },
    null,
  );
  let rev = 0;
  const pulls = { n: 0 };
  const next = (): SyncResponse => ({ rev: ++rev, full: rev === 1, vaults: [], grants: [], items: [], removedGrants: [] }) as unknown as SyncResponse;
  const s = new VaultStore({} as ApiClient, account, new NullCache(), memoryClientState(), { sync: async () => (pulls.n++, next()) } as unknown as ItemWire);
  return Object.assign(s, { pulls });
}

describe("design §4.4: the pin is refreshed during a session, on every sync and policy probe", () => {
  beforeAll(async () => {
    await initSodium();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("each sync waits for the refresh beside it before sending (at most 3 s), one refresh at a time, never on a read-only copy", async () => {
    const s = store();
    let calls = 0;
    let release: () => void = () => {};
    s.attachPinRefresh(() => {
      calls++;
      return new Promise<void>((r) => (release = r));
    });
    vi.useFakeTimers();
    let done = false;
    const first = s.sync().then(() => (done = true));
    await vi.advanceTimersByTimeAsync(2_900);
    expect(done).toBe(false); // nothing is sent while the refresh may still find a fork
    expect(s.pulls.n).toBe(0);
    await vi.advanceTimersByTimeAsync(200);
    await first; // a refresh slower than the wait never stalls the sync
    expect(s.pulls.n).toBe(1);
    const second = s.sync(); // the first refresh is still in flight: joined, not started again
    release();
    await second;
    expect(calls).toBe(1);
    const third = s.sync();
    expect(calls).toBe(2);
    release();
    await third;
    vi.useRealTimers();
    // A failed refresh never fails the sync.
    s.attachPinRefresh(() => Promise.reject(new Error("offline")));
    await expect(s.sync()).resolves.toBeUndefined();
    s.freezeAsReadOnlyCopy();
    s.attachPinRefresh(() => {
      calls++;
      return Promise.resolve();
    });
    await s.sync();
    expect(calls).toBe(2);
  });

  it("a refresh that freezes the store ends the sync before it sends anything", async () => {
    const s = store();
    s.attachPinRefresh(async () => s.freezeAsReadOnlyCopy());
    await s.sync();
    expect(s.pulls.n).toBe(0);
    expect(s.isReadOnlyCopy()).toBe(true);
  });

  it("the session attaches it, and the policy probe refreshes the pin too", () => {
    expect(readFileSync(here("../ui/opensession.ts"), "utf8")).toContain("store.attachPinRefresh(pinRefreshFor(ctx, store));");
    expect(readFileSync(here("../ui/App.tsx"), "utf8")).toContain("void ctx.pins.refresh(ctx.origin).catch(() => {});");
  });
});
