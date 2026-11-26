// An item set aside (a fresh list left it out without saying it was deleted) is back only when an answer serves a row of
// its id, in its own vault, that opens to the same content as the copy kept here. The session and a reload ask the same
// question and get the same answer. A row that cannot be read is not "back"; a row that opens to other content leaves the
// kept copy where it is, and the person is told once that the server sent the item again with other content. Driven
// through the real VaultStore, SharedLogSession and VaultLogStore against a fake server that serves what it likes.
import { beforeAll, describe, expect, it } from "vitest";
import type { SyncResponse, WireItem } from "../api/types";
import { toB64 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { BOB, browser, type Browser, family, freshDb, noticesOf } from "./fakesyncserver.testkit";
import { openVaultCache } from "./idbcache";

const aside = (who: Browser): [string, number][] => who.store.itemsSetAside().map((s) => [s.personal ? "personal" : "shared", s.itemCount]);
const passwordsOf = (who: Browser, vaultId: string, name: string): string[] =>
  who.store
    .list()
    .filter((i) => i.vaultId === vaultId && i.doc.name === name)
    .map((i) => (i.doc as { login?: { password?: string } }).login?.password ?? "")
    .sort();
const asideAtRest = async (): Promise<number[]> => (await (await openVaultCache(BOB)).heldVaults()).filter((h) => h.setAside === true).map((h) => h.items.length);
const OTHER = "items-set-aside-other";

/**
 * Bob's personal item "my-own" saved with password "first", then changed to "second"; then a 410 whose fresh list leaves
 * it out, so it is set aside holding "second". [first] and [second]: the server's rows of the item at each content.
 */
async function setAsideAfterTwoContents() {
  freshDb();
  const { server, bob } = await family(await openVaultCache(BOB));
  const pv = bob.profile.personalVaultId;
  await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "first" } }, [], undefined, pv);
  await bob.store.sync();
  const id = bob.store.list().find((i) => i.doc.name === "my-own")!.itemId;
  const first: WireItem = { ...server.items.get(id)! };
  const it = bob.store.list().find((i) => i.itemId === id)!;
  await bob.store.save(id, { ...it.doc, login: { username: "b", password: "second" } }, [], undefined, pv);
  await bob.store.sync();
  const second: WireItem = { ...server.items.get(id)! };
  server.tamper = (r, _s, userId) => (userId !== BOB || !r.full ? r : ({ ...r, items: r.items.filter((i) => i.itemId !== id) } as SyncResponse));
  server.forgetHistory();
  await bob.store.sync();
  expect(passwordsOf(bob, pv, "my-own")).toEqual([]);
  expect(aside(bob)).toEqual([["personal", 1]]);
  expect(noticesOf(bob, pv)).toEqual(["items-set-aside"]);
  /** From now on every delta to bob serves [row] as the item's row, at a revision of its own. */
  const serveOnDeltas = (row: WireItem): void => {
    const bump = ++server.rev;
    server.tamper = (r, _s, userId) => (userId !== BOB || r.full ? r : ({ ...r, items: [...r.items.filter((i) => i.itemId !== id), { ...row, rev: bump }] } as SyncResponse));
  };
  return { server, bob, pv, id, first, second, serveOnDeltas };
}

describe("an item set aside is back only when served again with the same content", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("served again with older content: the served row shows as on any road, the copy set aside stays, and the person is told once; also after a reload", async () => {
    const { bob, pv, first, serveOnDeltas, server } = await setAsideAfterTwoContents();
    serveOnDeltas(first);
    await bob.store.sync();
    expect(passwordsOf(bob, pv, "my-own")).toEqual(["first"]);
    expect(aside(bob)).toEqual([["personal", 1]]);
    expect(noticesOf(bob, pv).filter((k) => k === OTHER)).toEqual([OTHER]);
    bob.store.dismissNotice(bob.store.notices().find((n) => n.kind === OTHER)!.id);
    server.rev++;
    await bob.store.sync();
    expect(noticesOf(bob, pv).filter((k) => k === OTHER)).toEqual([]);
    expect(await asideAtRest()).toEqual([1]);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(aside(again)).toEqual([["personal", 1]]);
    expect(noticesOf(again, pv).filter((k) => k === OTHER)).toEqual([]);
    await again.store.copySetAsideToPersonal(pv);
    expect(passwordsOf(again, pv, "my-own")).toEqual(["first", "second"]);
  });

  it("the comparison, on the ordinary road: older content served by a delta with nothing set aside shows as served, with no notice", async () => {
    freshDb();
    const { server, bob } = await family(await openVaultCache(BOB));
    const pv = bob.profile.personalVaultId;
    await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "first" } }, [], undefined, pv);
    await bob.store.sync();
    const id = bob.store.list().find((i) => i.doc.name === "my-own")!.itemId;
    const first: WireItem = { ...server.items.get(id)! };
    const it = bob.store.list().find((i) => i.itemId === id)!;
    await bob.store.save(id, { ...it.doc, login: { username: "b", password: "second" } }, [], undefined, pv);
    await bob.store.sync();
    const bump = ++server.rev;
    server.tamper = (r, _s, userId) => (userId !== BOB || r.full ? r : ({ ...r, items: [...r.items.filter((i) => i.itemId !== id), { ...first, rev: bump }] } as SyncResponse));
    await bob.store.sync();
    expect(passwordsOf(bob, pv, "my-own")).toEqual(["first"]);
    expect(noticesOf(bob, pv)).toEqual([]);
  });

  it("served again as a row that cannot be read: not back; the copy set aside stays in the session, after a reload, and at rest", async () => {
    const { bob, pv, second, serveOnDeltas, server } = await setAsideAfterTwoContents();
    serveOnDeltas({ ...second, blob: toB64(randomBytes(90)) });
    await bob.store.sync();
    expect(aside(bob)).toEqual([["personal", 1]]);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(aside(again)).toEqual([["personal", 1]]);
    expect(await asideAtRest()).toEqual([1]);
    expect(noticesOf(again, pv).filter((k) => k === OTHER)).toEqual([]);
  });

  it("served again with the same content under another revision: back, out of the set, no notice; also after a reload", async () => {
    const { bob, pv, second, serveOnDeltas, server } = await setAsideAfterTwoContents();
    serveOnDeltas(second);
    await bob.store.sync();
    expect(passwordsOf(bob, pv, "my-own")).toEqual(["second"]);
    expect(aside(bob)).toEqual([]);
    expect(noticesOf(bob, pv).filter((k) => k === OTHER)).toEqual([]);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(aside(again)).toEqual([]);
    expect(await asideAtRest()).toEqual([]);
  });

  it("served again to a second tab: with the same content it is back there and at rest; with other content the second tab tells it and the copy stays", async () => {
    for (const which of ["same", "other"] as const) {
      const { bob, pv, first, second, serveOnDeltas, server } = await setAsideAfterTwoContents();
      const tab2 = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
      expect(aside(tab2)).toEqual([["personal", 1]]);
      serveOnDeltas(which === "same" ? second : first);
      await tab2.store.sync();
      expect(aside(tab2)).toEqual(which === "same" ? [] : [["personal", 1]]);
      expect(await asideAtRest()).toEqual(which === "same" ? [] : [1]);
      expect(noticesOf(tab2, pv).filter((k) => k === OTHER)).toEqual(which === "same" ? [] : [OTHER]);
    }
  });

  it("the copy kept here can no longer be opened: a served row is not back, whatever it holds, and nothing is said about its content", async () => {
    const { bob, pv, second, serveOnDeltas, server } = await setAsideAfterTwoContents();
    const disk = await openVaultCache(BOB);
    const rec = (await disk.heldVaults()).find((h) => h.setAside === true)!;
    await disk.putHeld({ ...rec, items: rec.items.map((w) => ({ ...w, blob: toB64(randomBytes(90)) })) });
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    expect(aside(again)).toEqual([["personal", 1]]);
    serveOnDeltas(second);
    await again.store.sync();
    expect(passwordsOf(again, pv, "my-own")).toEqual(["second"]);
    expect(aside(again)).toEqual([["personal", 1]]);
    expect(noticesOf(again, pv).filter((k) => k === OTHER)).toEqual([]);
  });
});
