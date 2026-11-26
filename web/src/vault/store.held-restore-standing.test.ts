// The owner's own held `restore` of a deleted shared vault is sent again only while the vault's log reads as verified
// here, as every other held change of a log is: a vault whose account record names an entry above the log this browser
// verified (withheld) takes no change of its log. Driven through the real VaultStore, SharedLogSession and
// VaultLogStore against the shared fake server.
import "fake-indexeddb/auto";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { initSodium } from "../crypto/sodium";
import { withVaultHead } from "./accountdoc";
import { ALICE, BOB, browser, contact, FakeSyncServer, freshDb, person } from "./fakesyncserver.testkit";

/** The hash another device of the account recorded at a place the served log does not hold. */
const OTHER_HASH = "ab".repeat(32);

/** The shared fake server, which answers the next append with a 503 where [failNextAppend] is set. */
class Server extends FakeSyncServer {
  failNextAppend = false;

  override wireFor(userId: string) {
    const w = super.wireFor(userId);
    const s = this;
    return {
      ...w,
      async appendLog(vaultId: string, req: Parameters<typeof w.appendLog>[1]) {
        if (s.failNextAppend) {
          s.failNextAppend = false;
          throw new ApiError(503, "unavailable", "the server is down for a moment");
        }
        return w.appendLog(vaultId, req);
      },
    };
  }
}

/** Alice owns "Family" with bob as a writer; she deletes it, and her restore of it is held (its answer was a 503). */
async function heldRestore() {
  freshDb();
  const server = new Server();
  const a = person(ALICE);
  const b = person(BOB);
  const alice = await browser(server, a, [contact(b, "Bob")]);
  const bob = await browser(server, b, [contact(a, "Alice")]);
  const old = await alice.store.createSharedVault("Family");
  await alice.store.addVaultMember(old, BOB, "writer");
  await bob.store.sync();
  expect((await bob.shared.answer(bob.shared.pendingAsks()[0]!, true)).kind).toBe("adopted");
  await alice.store.deleteSharedVault(old);
  const v = alice.shared.logs.verifiedState(old)!;
  expect(v.deleteId).not.toBeNull();
  server.failNextAppend = true;
  expect((await alice.shared.logs.append(old, { kind: "restore" })).kind).toBe("pending");
  expect(alice.shared.logs.pendingVaults()).toContain(old);
  return { server, alice, old, v };
}

describe("an owner's held restore of a deleted shared vault, sent again", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("while the account's record names an entry above the log this browser verified (withheld): nothing is sent, and the restore stays held", async () => {
    const { server, alice, old, v } = await heldRestore();
    await alice.shared.accountState.update((doc) => withVaultHead(doc, old, v.genesisHash, v.head.seq + 1, OTHER_HASH));
    expect(alice.shared.logs.status(old).kind).toBe("withheld");
    const mark = server.writes.length;
    await alice.shared.logs.retryPending();
    expect(server.writes.slice(mark).filter((w) => w.endsWith(`:${old}`))).toEqual([]);
    expect(alice.shared.logs.pendingVaults()).toContain(old);
    expect(alice.shared.logs.status(old).kind).toBe("withheld");
  });

  it("while the log reads as verified here: the restore is sent and read back, and the vault is restored", async () => {
    const { server, alice, old } = await heldRestore();
    expect(alice.shared.logs.status(old).kind).toBe("verified");
    const mark = server.writes.length;
    await alice.shared.logs.retryPending();
    expect(server.writes.slice(mark).filter((w) => w.endsWith(`:${old}`))).toEqual([`log-restore:${old}`]);
    expect(alice.shared.logs.pendingVaults()).not.toContain(old);
    expect(alice.shared.logs.verifiedState(old)!.deleteId).toBeNull();
  });
});
