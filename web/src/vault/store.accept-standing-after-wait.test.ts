// A transfer's `accept` asks the log's standing again after the one wait inside its signing (the comparison that finds
// whether the account's new wrap of the vault key opens to the committed key): a vault whose standing changed during that
// wait takes nothing. Driven through the real VaultStore, SharedLogSession and VaultLogStore against the shared fake
// server; the wait is the real comparison, with a step of the test's own run inside it.
import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { withVaultHead } from "./accountdoc";
import { ALICE, BOB, browser, contact, FakeSyncServer, freshDb, person } from "./fakesyncserver.testkit";

/** The hash another device of the account recorded at a place the served log does not hold. */
const OTHER_HASH = "ab".repeat(32);

/** A step run once inside the next comparison of a vault key with its commitment, before that comparison answers. */
const inside = vi.hoisted(() => ({ wait: null as null | (() => Promise<void>) }));

vi.mock("../crypto/trust/vaultlog", async (importOriginal) => {
  const m = await importOriginal<typeof import("../crypto/trust/vaultlog")>();
  return {
    ...m,
    keyMatches: async (...args: Parameters<typeof m.keyMatches>): Promise<boolean> => {
      const f = inside.wait;
      inside.wait = null;
      if (f !== null) await f();
      return m.keyMatches(...args);
    },
  };
});

/** Alice owns "Family" with bob as a writer, and offers it to bob; bob's browser verified the offer. */
async function offered() {
  freshDb();
  const server = new FakeSyncServer();
  const a = person(ALICE);
  const b = person(BOB);
  const alice = await browser(server, a, [contact(b, "Bob")]);
  const bob = await browser(server, b, [contact(a, "Alice")]);
  const old = await alice.store.createSharedVault("Family");
  await alice.store.addVaultMember(old, BOB, "writer");
  await bob.store.sync();
  expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  expect((await alice.shared.logs.append(old, { kind: "offer", to: BOB, expiresInMs: 60 * 60 * 1000 })).kind).toBe("appended");
  await bob.shared.logs.refresh(old, null, null, true);
  const v = bob.shared.logs.verifiedState(old)!;
  expect(v.pending).not.toBeNull();
  expect(bob.shared.logs.status(old).kind).toBe("verified");
  return { server, bob, old, v };
}

describe("a transfer's accept, and the log's standing after the wait inside its signing", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("the account's record of the vault rises above the verified head while the accept waits on its key's comparison with its commitment: the accept is refused read-only and nothing is sent", async () => {
    const { server, bob, old, v } = await offered();
    let ran = false;
    inside.wait = async () => {
      ran = true;
      // Another device of the account recorded an entry this browser has not verified (the served log ends below it).
      await bob.shared.accountState.update((doc) => withVaultHead(doc, old, v.genesisHash, v.head.seq + 1, OTHER_HASH));
      expect(bob.shared.logs.status(old).kind).toBe("withheld");
    };
    const mark = server.writes.length;
    const out = await bob.shared.logs.append(old, { kind: "accept" });
    expect(ran).toBe(true);
    expect(out).toMatchObject({ kind: "read_only", vaultId: old });
    expect(server.writes.slice(mark).filter((w) => w.endsWith(`:${old}`))).toEqual([]);
    expect(bob.shared.logs.pendingVaults()).not.toContain(old);
    expect(bob.shared.logs.status(old).kind).toBe("withheld");
  });

  it("nothing changes during that wait: the accept is sent and appended", async () => {
    const { server, bob, old } = await offered();
    let ran = false;
    inside.wait = async () => {
      ran = true;
    };
    const mark = server.writes.length;
    const out = await bob.shared.logs.append(old, { kind: "accept" });
    expect(ran).toBe(true);
    expect(out.kind).toBe("appended");
    expect(server.writes.slice(mark).filter((w) => w.endsWith(`:${old}`))).toContain(`log-accept:${old}`);
  });
});
