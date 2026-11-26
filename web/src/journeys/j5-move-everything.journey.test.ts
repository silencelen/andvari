import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { toB64, utf8 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 5: "Move everything to a new vault" (design §3.13) between the web and a native account. Bob, on the web,
 * owns "Bob's" and shares it with alice (made and connected by the engine's own code, SharePeer.java), who accepts it
 * on her side. Bob then moves everything: a new vault with a new key, the items copied under fresh ids and attachment
 * keys, alice added again, the old vault deleted. Alice's engine is asked about the new vault, accepts it, and reads
 * every item; the old vault is deleted on her side too.
 *
 * Every web step runs the sync store over real HTTP against the real server in its test mode.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";
type PeerVault = { items: string[]; members: string[]; status: string; writable: boolean };

describe.skipIf(skip !== null)("journey 5: Move everything to a new vault, with a native member", () => {
  let inst: TestInstance;
  let peer: SharePeerProcess;

  beforeAll(async () => {
    await initSodium();
    inst = await TestInstance.start({ kind: "private", mode: "open" });
    peer = await inst.sharePeer(PASSWORD);
  }, HOOK.startWithPeer);

  afterAll(async () => {
    await peer?.stop();
    await inst?.stop();
  }, HOOK.stop);

  beforeEach(() => inst.advance(61_000));

  it("bob moves his shared vault; alice is asked about the new one, accepts, and reads everything", async () => {
    const { alice, bob } = peer.ids;
    const browser = new Browser(inst);
    const r = await browser.signIn("bob@example.org", PASSWORD);
    expect(r.kind).toBe("opened");
    if (r.kind !== "opened") return;
    const { store, shared } = await browser.openVault(r.opened, r.wrap, "password");
    // §8.5: the one-tap list makes alice, the contact bob's native device made, current on this browser.
    expect(shared.contacts.confirmOneTap(new Set([alice]))).toBe(true);
    await store.sync();

    // Bob's own vault with alice as a writer, and two items in it, one with an attachment.
    const old = await store.createSharedVault("Bob's");
    await store.addVaultMember(old, alice, "writer");
    await store.save(null, { type: "login", name: "router", login: { username: "admin", password: "pw" } }, [], undefined, old);
    const attId = crypto.randomUUID();
    await store.save(null, { type: "note", name: "lease", notes: "n", attachments: [{ id: attId, name: "lease.txt", size: 5, fileKey: toB64(randomBytes(32)) }] }, [{ id: attId, data: utf8("lease") }], undefined, old);
    expect(await peer.cmd(`accept ${old}`)).toMatchObject({ adopted: true, owner: bob, name: "Bob's" });
    expect((await peer.cmd<PeerVault>(`vault ${old}`)).items.sort()).toEqual(["lease", "router"]);

    // The plan: alice is a remaining member this browser can add; the vault is in good standing.
    const plan = store.movePlan(old)!;
    expect(plan.sourceStays).toBe(false);
    expect(plan.members.map((m) => [m.userId, m.role, m.canBeAdded])).toEqual([[alice, "writer", true]]);
    const oldIds = store.list().filter((i) => i.vaultId === old).map((i) => i.itemId);

    const moved = await store.moveEverything(old, { name: "Bob's 2", add: [alice] });
    expect(moved.copied).toBe(2);
    expect(moved.oldKept).toBeNull();
    expect(moved.oldDeleted?.purgeAt).toBeGreaterThan(inst.now());
    const fresh = store.list().filter((i) => i.vaultId === moved.newVaultId);
    expect(fresh.map((i) => i.doc.name).sort()).toEqual(["lease", "router"]);
    expect(fresh.some((i) => oldIds.includes(i.itemId))).toBe(false);
    const lease = fresh.find((i) => i.doc.name === "lease")!;
    expect(lease.doc.attachments![0]!.id).not.toBe(attId);
    expect(new TextDecoder().decode(await store.downloadAttachment(lease, lease.doc.attachments![0]!))).toBe("lease");
    expect(Object.keys(shared.logs.verifiedState(moved.newVaultId)!.members).sort()).toEqual([alice, bob].sort());
    expect(shared.logs.verifiedState(old)?.deleteId).not.toBeNull();
    expect(store.vaults().some((v) => v.vaultId === old)).toBe(false);
    // The deleted vault is in bob's trash, to restore during its grace.
    expect((await store.listDeleted()).map((d) => d.name)).toContain("Bob's");

    // Alice: the old vault no longer gives her anything, and the new one is asked, accepted and read.
    expect((await peer.cmd<PeerVault>(`vault ${old}`)).items).toEqual([]);
    expect(await peer.cmd(`accept ${moved.newVaultId}`)).toMatchObject({ adopted: true, owner: bob, name: "Bob's 2" });
    const seen = await peer.cmd<PeerVault>(`vault ${moved.newVaultId}`);
    expect(seen.items.sort()).toEqual(["lease", "router"]);
    expect(seen.members.sort()).toEqual([alice, bob].sort());
    expect(seen.writable).toBe(true);
  }, 400_000);
});
