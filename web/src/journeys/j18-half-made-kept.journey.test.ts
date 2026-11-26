import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { parseLogEntry } from "../crypto/trust/vaultlog";
import { fill, MOVE_DISCARD_KEPT, MOVE_DISCARDED } from "../ui/copy";
import { moveResultText } from "../ui/Sharing";
import { MoveStoppedError } from "../vault/store";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 18: the half-made vault of a stopped move is deleted only while it holds nothing but the move's copies
 * (design §3.13 as ruled on 2026-11-18). Bob, on the web, owns "Bob's" with alice (made and connected by the engine's
 * own code, SharePeer.java) as a writer. His first "Move everything" makes "Bob's 2", copies the item and adds alice,
 * then stops before the old vault's deletion (the read before it fails). Alice accepts "Bob's 2" on her side and saves
 * an item of her own into it. Bob then removes alice and moves everything again: a fresh "Bob's 3" (alice holds the
 * half-made vault's key), the old vault deleted. The half-made "Bob's 2" is read from the server first: it holds alice's
 * item, which the move did not make, so it is NOT deleted, alice's item is still in it, and the line names it.
 *
 * Every web step runs the sync store over real HTTP against the real server in its test mode; only the reads of
 * `/sync` after the first run's addition are failed, to stop that run.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";
type PeerVault = { items: string[]; members: string[]; status: string; writable: boolean };

describe.skipIf(skip !== null)("journey 18: a half-made vault holding a member's own item is not deleted", () => {
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

  it("alice saves into the half-made vault; the next run finishes; the half-made vault is still there with her item, and the line names it", async () => {
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

    // The first run: once the new vault's addition of alice has been answered, every read of /sync fails, so the run
    // stops before the old vault's deletion (nothing of it is signed).
    const real = globalThis.fetch;
    let armed = false;
    vi.stubGlobal("fetch", async (url: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (armed && path === "/api/v1/sync") throw new TypeError("the connection broke");
      const resp = await real(url, init);
      const m = /^\/api\/v1\/vaults\/([^/]+)\/log$/.exec(path);
      if (m !== null && m[1] !== old && (init?.method ?? "GET") === "POST" && resp.ok) {
        const entry = (JSON.parse(String(init?.body)) as { entry: string }).entry;
        const parsed = parseLogEntry(fromB64Canonical(entry)!);
        if (parsed.ok && parsed.value.entry.kind === "add") armed = true;
      }
      return resp;
    });
    const stopped = await store.moveEverything(old, { name: "Bob's 2", add: [alice] }).then(
      () => null,
      (e: unknown) => e,
    );
    vi.unstubAllGlobals();
    expect(armed).toBe(true);
    expect(stopped).toBeInstanceOf(MoveStoppedError);
    const s = stopped as MoveStoppedError;
    expect([s.stage, s.deleteWaiting]).toEqual(["delete", false]);
    const half = s.newVaultId!;
    expect(shared.logs.verifiedState(old)?.deleteId).toBeNull();

    // Alice, whom the stopped run added, accepts "Bob's 2" and saves an item of her own into it.
    expect(await peer.cmd(`accept ${half}`)).toMatchObject({ adopted: true, owner: bob, name: "Bob's 2" });
    expect(await peer.cmd(`put ${half} alices-own`)).toEqual({ ok: true });
    expect((await peer.cmd<PeerVault>(`vault ${half}`)).items.sort()).toEqual(["alices-own", "router"]);

    // Bob removes alice and moves everything again: a fresh vault, the old one deleted, the half-made one read first.
    const moved = await store.moveEverything(old, { name: "Bob's 3", add: [], removing: alice });
    expect(moved.newVaultId).not.toBe(half);
    expect(moved.oldDeleted).not.toBeNull();
    // Read before anything was copied (design §3.13 as ruled on 2026-11-18), with alice, whom this move removes, named
    // as someone who can still open it, beside the one copy in it.
    expect(moved.discarded).toMatchObject({ vaultId: half, name: "Bob's 2", deleted: false, kept: true, foreign: 1, copies: 1 });
    expect(moved.discarded?.holders).toHaveLength(1);
    const line = moveResultText(moved, "Bob's");
    expect(line).toContain(fill(MOVE_DISCARD_KEPT, "Bob's 2"));
    expect(line).not.toContain(fill(MOVE_DISCARDED, "Bob's 2"));

    // At the server the half-made vault is still there, alice still in it, with her item.
    expect(store.vaults().some((v) => v.vaultId === half)).toBe(true);
    expect(shared.logs.verifiedState(half)?.deleteId).toBeNull();
    const seen = await peer.cmd<PeerVault>(`vault ${half}`);
    expect(seen.items.sort()).toEqual(["alices-own", "router"]);
    expect(seen.members.sort()).toEqual([alice, bob].sort());
    expect(seen.status).toBe("Verified");
    const page = await browser.wire.logPage(half, null);
    expect(page.entries.map((e) => parseLogEntry(fromB64Canonical(e)!)).map((p) => (p.ok ? p.value.entry.kind : "?"))).toEqual(["genesis", "add"]);
  }, 400_000);
});
