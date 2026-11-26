import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { deleteThroughFlow } from "../ui/DeleteAccount";
import { itemLogHead } from "../vault/itemhead";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 3: a shared vault between two connected accounts (design §3, §6.9, §8.5). Alice and bob are made, and
 * connected, by the engine's own code (SharePeer.java): the web can make neither a contact nor a link (§13). Alice
 * creates "Family", adds bob and saves an item. Bob then signs in on the web with his password: the one-tap list
 * makes alice current on this browser, the share is asked and accepted, read and written, left, offered again and
 * accepted, and finally removed by alice.
 *
 * Every web step runs the flow modules and the sync store over real HTTP against the real server in its test mode.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";
type Synced = { sync: string; items: string[]; members: string[] };

describe.skipIf(skip !== null)("journey 3: a shared vault from native accounts, used on the web", () => {
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

  it("bob accepts, reads, writes, leaves, accepts again and is removed", async () => {
    const { alice, bob, vault } = peer.ids;
    const browser = new Browser(inst);
    const r = await browser.signIn("bob@example.org", PASSWORD);
    expect(r.kind).toBe("opened");
    if (r.kind !== "opened") return;
    expect(r.session.userId).toBe(bob);
    const { account, store, shared } = await browser.openVault(r.opened, r.wrap, "password");

    // Before alice is current on this browser the share decrypts nothing: "connect with them first".
    expect(account.hasVault(vault)).toBe(false);
    expect(shared.outcome(vault)).toMatchObject({ kind: "connect_first" });
    expect(shared.pendingAsks()).toEqual([]);

    // §8.5: a password sign-in gets the one-tap list once; it lists the contact bob's native device made.
    expect(shared.contacts.oneTapListDue()).toBe(true);
    const listed = shared.contacts.list();
    expect(listed.map((c) => [c.record.userId, c.labelText, c.current])).toEqual([[alice, "Alice", null]]);
    expect(shared.contacts.confirmOneTap(new Set([alice]))).toBe(true);
    expect(shared.contacts.oneTapListDue()).toBe(false);

    // The next pull asks: alice's label (she is current here) and the vault's name, decrypted only now.
    await store.sync();
    const asks = shared.pendingAsks();
    expect(asks).toMatchObject([{ kind: "ask", vaultId: vault, owner: alice, ownerLabel: "Alice", vaultName: "Family" }]);
    expect(account.hasVault(vault)).toBe(false);
    expect((await shared.answer(asks[0]!, true)).kind).toBe("adopted");
    expect(account.roleFor(vault)).toBe("writer");

    // Read alice's item, write one back, and alice reads it.
    await store.sync();
    expect(store.list().filter((i) => i.vaultId === vault).map((i) => i.doc.name)).toEqual(["from alice"]);
    // Alice's engine stamped her verified head into the item (spec 02 §3): a head bob's log has verified, so the pull
    // chased nothing and the member list is not marked incomplete.
    const aliceHead = itemLogHead(store.list().find((i) => i.vaultId === vault)!.doc);
    expect(aliceHead).not.toBeNull();
    expect(shared.logs.hashes(vault).get(aliceHead!.seq)).toBe(aliceHead!.hash);
    expect(store.memberRoster(vault)?.mayBeIncomplete).toBe(false);
    await store.save(null, { type: "login", name: "from bob", login: { username: "bob", password: "pw" } }, [], undefined, vault);
    expect(store.notices()).toEqual([]);
    const seen = await peer.cmd<Synced>("sync");
    expect(seen.items.sort()).toEqual(["from alice", "from bob"]);
    expect(seen.members.sort()).toEqual([alice, bob].sort());

    // The Sharing screen's actions as an owner, through the store onto signed log entries: bob creates a vault, adds
    // alice (a current, compared contact here) as a reader, makes her a writer, offers her the vault and cancels,
    // removes her, deletes the vault and restores it. Each one is read back from this browser's verified log.
    const own = await store.createSharedVault("Bob's");
    expect(store.isLogGoverned(own)).toBe(true);
    expect(store.ownsVault(own)).toBe(true);
    await store.addVaultMember(own, alice, "reader");
    expect(shared.logs.verifiedState(own)?.members[alice]?.role).toBe("reader");
    // The member list is the verified log's, labelled from bob's current contact for alice's key (design §3.9).
    const roster = store.memberRoster(own)!;
    expect(roster.rows.map((r) => [r.userId, r.role, r.self])).toEqual([[bob, "owner", true], [alice, "reader", false]]);
    expect(roster.rows[1]!.label).toBe(shared.contacts.current(alice)!.labelText);
    expect(roster.mayBeIncomplete || roster.stale).toBe(false);
    await store.setMemberRole(own, alice, "writer");
    expect(shared.logs.verifiedState(own)?.members[alice]?.role).toBe("writer");
    await store.offerTransfer(own, alice);
    expect(store.pendingTransferFor(own)?.toUserId).toBe(alice);
    await store.cancelTransfer(own);
    expect(store.pendingTransferFor(own)).toBeNull();
    await store.removeVaultMember(own, alice);
    expect(shared.logs.verifiedState(own)?.members[alice]).toBeUndefined();
    const { purgeAt } = await store.deleteSharedVault(own);
    expect(purgeAt).toBeGreaterThan(Date.now());
    const deleteId = shared.logs.verifiedState(own)?.deleteId;
    expect(typeof deleteId).toBe("string");
    // The trash lists it by name, read from the owner's own wrap under the log's genesis; the key stays out of use.
    const trashed = (await store.listDeleted()).find((d) => d.vaultId === own);
    expect(trashed?.name).toBe("Bob's");
    expect(trashed?.deleteId).toBe(deleteId);
    expect(account.hasVault(own)).toBe(false);
    await store.restoreSharedVault(own, deleteId!);
    expect(shared.logs.verifiedState(own)?.deleteId).toBeNull();
    expect(store.notices()).toEqual([]);

    // Bob leaves through the store: a signed `leave` from this browser's verified head; alice's log no longer lists him.
    await store.leaveSharedVault(vault);
    expect(store.notices()).toEqual([]);
    expect(store.list().some((i) => i.vaultId === vault)).toBe(false);
    expect(account.hasVault(vault)).toBe(false);
    expect((await peer.cmd<Synced>("sync")).members).toEqual([alice]);

    // Alice adds him again (as a reader): a new `add` is asked again, and accepting adopts the key.
    expect(await peer.cmd("add reader")).toEqual({ ok: true });
    await store.sync();
    const again = shared.pendingAsks();
    expect(again).toMatchObject([{ vaultId: vault, owner: alice }]);
    expect((await shared.answer(again[0]!, true)).kind).toBe("adopted");
    await store.sync();
    expect(account.roleFor(vault)).toBe("reader");
    expect(store.list().filter((i) => i.vaultId === vault).map((i) => i.doc.name).sort()).toEqual(["from alice", "from bob"]);
    // A reader seals nothing under the vault's key: the save is refused before anything is sent.
    expect(account.canSealUnder(vault)).toBe(false);
    await expect(store.save(null, { type: "note", name: "as a reader", notes: "x" }, [], undefined, vault)).rejects.toThrow();
    expect((await peer.cmd<Synced>("sync")).items.sort()).toEqual(["from alice", "from bob"]);

    // Alice removes him: the next pull reads the removal from the log, and the vault and its key leave this browser.
    expect(await peer.cmd("remove")).toEqual({ ok: true });
    await store.sync();
    expect(shared.logs.status(vault)).toMatchObject({ kind: "removed", byOwner: true });
    expect(account.hasVault(vault)).toBe(false);
    expect(store.list().some((i) => i.vaultId === vault)).toBe(false);
    expect(store.notices().map((n) => n.kind)).toContain("removed");

    // Added once more and accepted, bob deletes his account: the deletion carries his leave, placed after each
    // membership's log was brought up to the preview's head, and alice's log no longer lists him.
    expect(await peer.cmd("add writer")).toEqual({ ok: true });
    await store.sync();
    const last = shared.pendingAsks();
    expect(last).toMatchObject([{ vaultId: vault }]);
    expect((await shared.answer(last[0]!, true)).kind).toBe("adopted");
    const preview = await browser.wire.deletePreview();
    expect(preview.memberships.map((m) => m.vaultId)).toEqual([vault]);
    // A wrong typed address is refused before anything is derived or sent, through the card's own path.
    const settings = browser.settings(r.opened, "bob@example.org", account.sessionWrap);
    expect(await deleteThroughFlow(settings, shared, { typedEmail: "someone@example.org", password: PASSWORD, totp: "", totpRequired: false })).toMatchObject({ kind: "error", code: "confirm_email_mismatch" });
    const refreshed: string[] = [];
    const watching = Object.create(shared) as typeof shared;
    watching.refreshForDeletion = async (ms) => {
      refreshed.push(...ms.map((m) => m.vaultId));
      await shared.refreshForDeletion(ms);
    };
    let sent = false;
    const gone = await deleteThroughFlow(
      settings,
      watching,
      { typedEmail: "bob@example.org", password: PASSWORD, totp: "", totpRequired: false },
      () => {
        sent = true;
      },
      () => inst.now(),
    );
    expect(gone.kind).toBe("deleted");
    expect(sent).toBe(true);
    expect(refreshed).toEqual([vault]);
    expect((await peer.cmd<Synced>("sync")).members).toEqual([alice]);
  }, 400_000);
});
