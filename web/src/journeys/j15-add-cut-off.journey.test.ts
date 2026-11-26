import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { logActionText } from "../ui/logactiontext";
import { ChangeNotStoredError } from "../vault/store";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 15: an added member whose answer is cut off (design §3.7). Bob, on the web, owns "Bob's" and adds alice (made
 * and connected by the engine's own code, SharePeer.java). The real server stores the signed `add` and answers; the
 * answer's body breaks off on its way. Its outcome cannot be told from the answer, so before anything is said the web
 * reads the vault's log from the server (the member list the person would be sent to): the read holds the add, so it
 * is shown as made, never "it isn't made"; the member list shows alice, nothing waits to be sent again, the server holds
 * the add once, and alice's engine can accept the vault: she holds its key.
 *
 * Every web step runs the flow modules and the sync store over real HTTP against the real server in its test mode;
 * only the add's answer is cut off, after the server answered it.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";

describe.skipIf(skip !== null)("journey 15: an added member whose answer was cut off", () => {
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

  it("bob adds alice, the answer breaks off: can't tell; the member list shows her; made once; she can accept", async () => {
    const { alice, bob } = peer.ids;
    const browser = new Browser(inst);
    const r = await browser.signIn("bob@example.org", PASSWORD);
    expect(r.kind).toBe("opened");
    if (r.kind !== "opened") return;
    const { store, shared } = await browser.openVault(r.opened, r.wrap, "password");
    expect(shared.contacts.confirmOneTap(new Set([alice]))).toBe(true);
    await store.sync();
    const old = await store.createSharedVault("Bob's");

    // The real server answers the add; its body breaks off after the first bytes.
    const real = globalThis.fetch;
    let cut = 0;
    vi.stubGlobal("fetch", async (url: string | URL | Request, init?: RequestInit) => {
      const resp = await real(url, init);
      const path = new URL(String(url)).pathname;
      if (cut > 0 || (init?.method ?? "GET") !== "POST" || path !== `/api/v1/vaults/${old}/log`) return resp;
      cut++;
      const text = await resp.text();
      let sent = false;
      const body = new ReadableStream<Uint8Array>({
        pull(c) {
          if (!sent) {
            sent = true;
            c.enqueue(new TextEncoder().encode(text.slice(0, Math.floor(text.length / 2))));
            return;
          }
          c.error(new TypeError("the connection broke"));
        },
      });
      return new Response(body, { status: resp.status, headers: resp.headers });
    });
    const e = await store.addVaultMember(old, alice, "writer").then(() => "made", (x: unknown) => x);
    vi.unstubAllGlobals();
    expect(cut).toBe(1);
    // "Cannot tell" sends the person to the member list, so the vault is read from the server before anything is said:
    // the read holds the add, so it is shown as made (never "it isn't made"), and nothing waits to be sent again.
    if (e !== "made") expect(e instanceof ChangeNotStoredError ? logActionText(e) : e).toBe("made");
    expect(store.memberRoster(old)?.rows.map((row) => [row.userId, row.role]).sort()).toEqual([[alice, "writer"], [bob, "owner"]].sort());
    expect(shared.logs.holds(old)).toBe(false);

    // The next pull and the next unlock's re-send change nothing: the server holds the add once.
    await store.sync();
    expect(store.memberRoster(old)?.rows.map((row) => [row.userId, row.role]).sort()).toEqual([[alice, "writer"], [bob, "owner"]].sort());
    expect(await shared.logs.retryPending()).toEqual([]);
    const page = await browser.wire.logPage(old, null);
    expect(page.entries).toHaveLength(2);

    // Alice holds the vault's key: her engine accepts the vault.
    expect(await peer.cmd(`accept ${old}`)).toMatchObject({ adopted: true, owner: bob, name: "Bob's" });
  }, 400_000);
});
