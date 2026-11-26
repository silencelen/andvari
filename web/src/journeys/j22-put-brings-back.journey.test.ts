import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { fill, ITEM_BROUGHT_BACK } from "../ui/copy";
import { noticeBody } from "../ui/Vault";
import { Browser } from "./browser";
import { journeysUnavailable, type SharePeerProcess, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 22: a put that brings a deleted item back (spec 03 §5). Bob is signed in on two browsers. On the first he
 * saves a login; the second reads it and deletes it. The first, which has not read the deletion, saves a change to the
 * login: the real server brings the item back with that change (an edit beats a deletion), answers `conflict` with the
 * deletion's mark, and stores the item without a conflict mark. The first browser makes no "(conflict)" copy and says
 * once that its change brought back an item deleted elsewhere; the second, after a sync, holds the one item, live.
 *
 * Bob's account is the one SharePeer.java registers; the share peer itself takes no part.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";

describe.skipIf(skip !== null)("journey 22: a change saved over an item deleted elsewhere brings it back", () => {
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

  it("no copy is made, the item is back with the change, and the first browser says so once", async () => {
    const first = new Browser(inst, "Bob's laptop");
    const r1 = await first.signIn("bob@example.org", PASSWORD);
    expect(r1.kind).toBe("opened");
    if (r1.kind !== "opened") return;
    const one = await first.openVault(r1.opened, r1.wrap, "password");
    await one.store.sync();
    await one.store.save(null, { type: "login", name: "router", login: { username: "admin", password: "pw" } });
    const { itemId, vaultId } = one.store.list().find((i) => i.doc.name === "router")!;

    inst.advance(61_000);
    const second = new Browser(inst, "Bob's desk");
    const r2 = await second.signIn("bob@example.org", PASSWORD);
    expect(r2.kind).toBe("opened");
    if (r2.kind !== "opened") return;
    const two = await second.openVault(r2.opened, r2.wrap, "password");
    await two.store.sync();
    expect(two.store.list().map((i) => i.doc.name)).toContain("router");
    await two.store.remove(itemId);
    expect(two.store.list().some((i) => i.itemId === itemId)).toBe(false);

    // The first browser has not read the deletion: its change is a put over the deleted item.
    await one.store.save(itemId, { type: "login", name: "router", login: { username: "admin", password: "changed" } }, [], undefined, vaultId);
    await one.store.sync();
    const named = (s: typeof one.store) => s.list().map((i) => i.doc.name).sort();
    // On the code before: no copy against this server either, but nothing was said.
    expect(named(one.store)).toEqual(["router"]);
    const n = one.store.notices().filter((x) => x.kind === "item-brought-back");
    expect(n).toHaveLength(1);
    expect(noticeBody(n[0]!).body).toBe(fill(ITEM_BROUGHT_BACK, "router", n[0]!.vaultName || "a vault"));
    await one.store.sync();
    expect(one.store.notices().filter((x) => x.kind === "item-brought-back")).toHaveLength(1);

    // The second browser reads the item back, live, with the change, and no copy of it.
    await two.store.sync();
    expect(named(two.store)).toEqual(["router"]);
    expect((two.store.get(itemId)?.doc as { login?: { password?: string } }).login?.password).toBe("changed");
  }, 400_000);
});
