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
 * Journey 21: the deletion of a half-made vault names the point up to which its items were read (spec 03 §10.3), and
 * the real server refuses it when a member saved into the vault between that read and the deletion. Bob, on the web,
 * owns "Bob's" with alice (the engine's own code, SharePeer.java) as a writer. His first "Move everything" makes
 * "Bob's 2", copies the item and adds alice, then stops before the old vault's deletion. Alice accepts "Bob's 2". Bob
 * removes alice and moves everything again; the half-made vault is read first and holds nothing but the copy, so bob's
 * browser deletes it, and alice saves an item of her own into it just before that deletion reaches the server. The
 * server refuses it (`409 vault_items_moved`), nothing is stored, bob's browser reads the vault again, finds alice's
 * item, keeps the vault, and the line names it.
 *
 * Every web step runs the sync store over real HTTP against the real server in its test mode; the reads of `/sync`
 * after the first run's addition are failed to stop that run, and alice's save is made while bob's deletion waits.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";
type PeerVault = { items: string[]; members: string[]; status: string; writable: boolean };

describe.skipIf(skip !== null)("journey 21: a member's save between the read and the deletion of a half-made vault", () => {
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

  it("the server refuses the deletion that names its read; the vault is read again and kept with alice's item, and the line names it", async () => {
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

    // The first run stops after the new vault's addition of alice (every read of /sync fails from then on).
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
    const half = (stopped as MoveStoppedError).newVaultId!;
    expect(await peer.cmd(`accept ${half}`)).toMatchObject({ adopted: true, owner: bob, name: "Bob's 2" });
    expect((await peer.cmd<PeerVault>(`vault ${half}`)).items).toEqual(["router"]);

    // Alice saves into "Bob's 2" while bob's deletion of it is on its way: after his read, before the server takes it.
    const deletions: { status: number; itemsAtMost: unknown; error?: string }[] = [];
    vi.stubGlobal("fetch", async (url: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (path === `/api/v1/vaults/${half}/log` && (init?.method ?? "GET") === "POST") {
        const body = JSON.parse(String(init?.body)) as { entry: string; itemsAtMost?: unknown };
        const parsed = parseLogEntry(fromB64Canonical(body.entry)!);
        if (parsed.ok && parsed.value.entry.kind === "delete") {
          if (deletions.length === 0) expect(await peer.cmd(`put ${half} alices-own`)).toEqual({ ok: true });
          const resp = await real(url, init);
          const answer = (await resp.clone().json().catch(() => ({}))) as { error?: string };
          deletions.push({ status: resp.status, itemsAtMost: body.itemsAtMost, ...(answer.error !== undefined ? { error: answer.error } : {}) });
          return resp;
        }
      }
      return real(url, init);
    });
    const moved = await store.moveEverything(old, { name: "Bob's 3", add: [], removing: alice });
    vi.unstubAllGlobals();
    expect(moved.newVaultId).not.toBe(half);
    expect(moved.oldDeleted).not.toBeNull();

    // One deletion of the half-made vault reached the server, naming the read point, and the server refused it. On the
    // code before, it named none, the server stored it, and alice's item went with the vault.
    expect(deletions).toHaveLength(1);
    expect(deletions[0]).toMatchObject({ status: 409, error: "vault_items_moved", itemsAtMost: expect.any(Number) });
    expect(moved.discarded).toMatchObject({ vaultId: half, name: "Bob's 2", deleted: false, kept: true, foreign: 1, copies: 1 });
    expect(shared.logs.holds(half)).toBe(false);
    const line = moveResultText(moved, "Bob's");
    expect(line).toContain(fill(MOVE_DISCARD_KEPT, "Bob's 2"));
    expect(line).not.toContain(fill(MOVE_DISCARDED, "Bob's 2"));

    // At the server: nothing was stored; the vault, alice in it, and her item are there.
    expect(shared.logs.verifiedState(half)?.deleteId).toBeNull();
    const seen = await peer.cmd<PeerVault>(`vault ${half}`);
    expect(seen.items.sort()).toEqual(["alices-own", "router"]);
    expect(seen.members.sort()).toEqual([alice, bob].sort());
    const page = await browser.wire.logPage(half, null);
    expect(page.entries.map((e) => parseLogEntry(fromB64Canonical(e)!)).map((p) => (p.ok ? p.value.entry.kind : "?"))).toEqual(["genesis", "add"]);
  }, 400_000);
});
