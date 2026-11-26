import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { parseLogEntry } from "../crypto/trust/vaultlog";
import { fill, MOVE_CHANGED_AFTER_READ } from "../ui/copy";
import { moveResultText } from "../ui/Sharing";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 23: the move's deletion of the OLD vault names the point up to which the move read it (spec 03 §10.3), and
 * the real server refuses it when a member saved into the old vault between that read and the deletion. Bob, on the
 * web, owns "Bob's" with alice (the engine's own code, SharePeer.java) as a writer. He moves everything into "Bob's 2"
 * with alice added again; every check passes, and alice saves an item of her own into "Bob's" just before his deletion
 * of it reaches the server. The server refuses it (`409 vault_items_moved`), nothing is stored and nothing is held,
 * "Bob's" stays with alice's item, and the move says it changed meanwhile. Moving again carries her item over, and only
 * then is "Bob's" deleted.
 *
 * Every web step runs the sync store over real HTTP against the real server in its test mode; alice's save is made
 * while bob's deletion waits.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";
type PeerVault = { items: string[]; members: string[]; status: string; writable: boolean };

describe.skipIf(skip !== null)("journey 23: a member's save between the move's last read and its deletion of the old vault", () => {
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
  afterEach(() => vi.unstubAllGlobals());

  it("the server refuses the old vault's deletion that names the move's read; nothing is held, the old vault stays with alice's item, and moving again carries it", async () => {
    const { alice, bob } = peer.ids;
    const browser = new Browser(inst);
    const r = await browser.signIn("bob@example.org", PASSWORD);
    expect(r.kind).toBe("opened");
    if (r.kind !== "opened") return;
    const { store, shared } = await browser.openVault(r.opened, r.wrap, "password");
    expect(shared.contacts.confirmOneTap(new Set([alice]))).toBe(true);
    await store.sync();
    const old = await store.createSharedVault("Bob's");
    await store.addVaultMember(old, alice, "writer");
    await store.save(null, { type: "login", name: "router", login: { username: "admin", password: "pw" } }, [], undefined, old);
    expect(await peer.cmd(`accept ${old}`)).toMatchObject({ adopted: true, owner: bob, name: "Bob's" });

    // Alice saves into "Bob's" while bob's deletion of it is on its way: after his last read, before the server takes it.
    const real = globalThis.fetch;
    const deletions: { status: number; itemsAtMost: unknown; error?: string }[] = [];
    vi.stubGlobal("fetch", async (url: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (path === `/api/v1/vaults/${old}/log` && (init?.method ?? "GET") === "POST") {
        const body = JSON.parse(String(init?.body)) as { entry: string; itemsAtMost?: unknown };
        const parsed = parseLogEntry(fromB64Canonical(body.entry)!);
        if (parsed.ok && parsed.value.entry.kind === "delete") {
          if (deletions.length === 0) expect(await peer.cmd(`put ${old} alices-own`)).toEqual({ ok: true });
          const resp = await real(url, init);
          const answer = (await resp.clone().json().catch(() => ({}))) as { error?: string };
          deletions.push({ status: resp.status, itemsAtMost: body.itemsAtMost, ...(answer.error !== undefined ? { error: answer.error } : {}) });
          return resp;
        }
      }
      return real(url, init);
    });
    const moved = await store.moveEverything(old, { name: "Bob's 2", add: [alice] });
    vi.unstubAllGlobals();

    // One deletion of the old vault reached the server, naming the read point, and the server refused it. On the code
    // before, it named none, the server stored it, and alice's item went into the old vault's grace with it.
    expect(deletions).toHaveLength(1);
    expect(deletions[0]).toMatchObject({ status: 409, error: "vault_items_moved", itemsAtMost: expect.any(Number) });
    expect([moved.oldDeleted, moved.oldKept, moved.changed]).toEqual([null, "changed_meanwhile", 0]);
    expect(shared.logs.holds(old)).toBe(false);
    expect(store.unfinishedMoves()).toEqual([]);
    expect(moveResultText(moved, "Bob's")).toContain(fill(MOVE_CHANGED_AFTER_READ, "", "Bob's"));

    // At the server: nothing was stored; the old vault, alice in it, and her item are there.
    expect(shared.logs.verifiedState(old)?.deleteId).toBeNull();
    const seen = await peer.cmd<PeerVault>(`vault ${old}`);
    expect(seen.items.sort()).toEqual(["alices-own", "router"]);
    expect(seen.members.sort()).toEqual([alice, bob].sort());
    const page = await browser.wire.logPage(old, null);
    expect(page.entries.map((e) => parseLogEntry(fromB64Canonical(e)!)).map((p) => (p.ok ? p.value.entry.kind : "?"))).toEqual(["genesis", "add"]);

    // Moving again carries what is late: the newest vault holds alice's item, and only now is "Bob's" deleted.
    await store.sync();
    const again = await store.moveEverything(old, { name: "Bob's 3", add: [alice] });
    expect(again.oldDeleted).not.toBeNull();
    expect(
      store
        .list()
        .filter((i) => i.vaultId === again.newVaultId)
        .map((i) => i.doc.name)
        .sort(),
    ).toEqual(["alices-own", "router"]);
    expect(shared.logs.verifiedState(old)?.deleteId).not.toBeNull();
  }, 400_000);
});
