import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { parseLogEntry } from "../crypto/trust/vaultlog";
import { fill, MOVE_DISCARD_KEPT } from "../ui/copy";
import { noticeBody } from "../ui/Vault";
import { MoveStoppedError } from "../vault/store";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 19: the unlock never sends a held deletion of a stopped move's half-made vault without reading the vault
 * first (design §3.13 as ruled on 2026-11-18). Bob, on the web, owns "Bob's" with alice (SharePeer.java) as a writer.
 * His first "Move everything" makes "Bob's 2", copies the item and adds alice, then stops before the old vault's
 * deletion. He removes alice and moves again: a fresh "Bob's 3", the old vault deleted; "Bob's 2" is read (nothing but
 * the copy), and its deletion is signed and sent, but the connection drops before it reaches the server: it is held.
 * Alice then saves an item of her own into "Bob's 2". Bob reloads and signs in again: the unlock reads "Bob's 2" before
 * anything of it is sent, finds alice's item, drops the held deletion and names the vault in a notice. At the server,
 * "Bob's 2" is still there with alice's item, and its log holds no deletion.
 *
 * Every web step runs the sync store over real HTTP against the real server in its test mode; only the reads of
 * `/sync` after the first run's addition, and the one post of "Bob's 2"'s deletion, are failed.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";
type PeerVault = { items: string[]; members: string[]; status: string; writable: boolean };

const entryKind = (body: BodyInit | null | undefined): string | null => {
  const parsed = parseLogEntry(fromB64Canonical((JSON.parse(String(body)) as { entry: string }).entry)!);
  return parsed.ok ? parsed.value.entry.kind : null;
};

describe.skipIf(skip !== null)("journey 19: the unlock reads a half-made vault before its held deletion is sent", () => {
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

  it("the half-made vault's deletion is held; alice saves into it; bob's next unlock drops the deletion, keeps the vault and names it", async () => {
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

    // The first run stops before the old vault's deletion: once the new vault's addition of alice is answered, every
    // read of /sync fails.
    const real = globalThis.fetch;
    let armed = false;
    vi.stubGlobal("fetch", async (url: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (armed && path === "/api/v1/sync") throw new TypeError("the connection broke");
      const resp = await real(url, init);
      const m = /^\/api\/v1\/vaults\/([^/]+)\/log$/.exec(path);
      if (m !== null && m[1] !== old && (init?.method ?? "GET") === "POST" && resp.ok && entryKind(init?.body) === "add") armed = true;
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

    // Bob removes alice and moves again. "Bob's 2" is read (only the copy) and its deletion signed; the post of that
    // deletion breaks before it reaches the server.
    let cut = 0;
    vi.stubGlobal("fetch", async (url: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (path === `/api/v1/vaults/${half}/log` && (init?.method ?? "GET") === "POST" && entryKind(init?.body) === "delete") {
        cut++;
        throw new TypeError("the connection broke");
      }
      return real(url, init);
    });
    const moved = await store.moveEverything(old, { name: "Bob's 3", add: [], removing: alice });
    vi.unstubAllGlobals();
    expect(cut).toBe(1);
    expect(moved.oldDeleted).not.toBeNull();
    // Dealt with before anything was copied (design §3.13 as ruled on 2026-11-18): alice, whom this move removes, is
    // named as someone who can still open it, beside the one copy in it.
    expect(moved.discarded).toMatchObject({ vaultId: half, name: "Bob's 2", deleted: false, waiting: true, copies: 1 });
    expect(moved.discarded?.holders).toHaveLength(1);
    expect(shared.logs.holds(half)).toBe(true);

    // Alice, still in "Bob's 2", accepts it and saves an item of her own into it.
    expect(await peer.cmd(`accept ${half}`)).toMatchObject({ adopted: true, owner: bob, name: "Bob's 2" });
    expect(await peer.cmd(`put ${half} alices-own`)).toEqual({ ok: true });

    // Bob reloads the page and signs in again: the unlock as the app runs it (the held changes, then the first sync).
    // Every post of a log entry for "Bob's 2" is counted from here.
    store.close();
    const later = browser.reload();
    const posts: string[] = [];
    vi.stubGlobal("fetch", async (url: string | URL | Request, init?: RequestInit) => {
      const path = new URL(String(url)).pathname;
      if (path === `/api/v1/vaults/${half}/log` && (init?.method ?? "GET") === "POST") posts.push(entryKind(init?.body) ?? "?");
      return real(url, init);
    });
    const again = await later.signIn("bob@example.org", PASSWORD);
    expect(again.kind).toBe("opened");
    if (again.kind !== "opened") return;
    const v = await later.openVault(again.opened, again.wrap, "password");
    vi.unstubAllGlobals();
    // On the code before: the unlock re-posted the held deletion unread, and alice's item went with the vault.
    expect(posts).toEqual([]);
    expect(v.shared.logs.holds(half), "the held deletion is dropped").toBe(false);
    const n = v.store.notices().filter((x) => x.kind === "half-made-kept");
    expect(n).toHaveLength(1);
    expect(n[0]).toMatchObject({ vaultId: half, vaultName: "Bob's 2" });
    expect(noticeBody(n[0]!).body).toBe(fill(MOVE_DISCARD_KEPT, "Bob's 2"));

    // At the server "Bob's 2" is still there, alice in it, with her item, and its log holds no deletion.
    expect(v.store.vaults().some((x) => x.vaultId === half)).toBe(true);
    const seen = await peer.cmd<PeerVault>(`vault ${half}`);
    expect(seen.items.sort()).toEqual(["alices-own", "router"]);
    expect(seen.members.sort()).toEqual([alice, bob].sort());
    expect(seen.status).toBe("Verified");
    const page = await later.wire.logPage(half, null);
    expect(page.entries.map((e) => parseLogEntry(fromB64Canonical(e)!)).map((p) => (p.ok ? p.value.entry.kind : "?"))).toEqual(["genesis", "add"]);
  }, 400_000);
});
