// A copy set aside is never replaced: an item left out again by a fresh list while a copy of it is kept, with other
// content, is kept BESIDE that copy, and what the person was told once stays told. Copying the items set aside out gives
// each copy its own new item. Driven through the real VaultStore, SharedLogSession and VaultLogStore against a fake
// server that serves what it likes.
import { beforeAll, describe, expect, it } from "vitest";
import type { ItemDoc, SyncResponse, WireItem } from "../api/types";
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
const OTHER = "items-set-aside-other";

/** Bob's personal item "my-own" holding "second", set aside by a fresh list that left it out. */
async function setAside() {
  freshDb();
  const { server, bob } = await family(await openVaultCache(BOB));
  const pv = bob.profile.personalVaultId;
  await bob.store.save(null, { type: "login", name: "my-own", login: { username: "b", password: "second" } }, [], undefined, pv);
  await bob.store.sync();
  const id = bob.store.list().find((i) => i.doc.name === "my-own")!.itemId;
  const base: WireItem = { ...server.items.get(id)! };
  const doc = bob.store.get(id)!.doc;
  const leaveOut = (r: SyncResponse): SyncResponse => ({ ...r, items: r.items.filter((i) => i.itemId !== id) }) as SyncResponse;
  server.tamper = (r, _s, userId) => (userId !== BOB || !r.full ? r : leaveOut(r));
  server.forgetHistory();
  await bob.store.sync();
  expect(aside(bob)).toEqual([["personal", 1]]);
  /** From now on every delta serves the item with [password] (sealed as any writer of the vault could), every full list leaves it out. */
  const serveOnDeltas = (password: string): void => {
    const sealed = bob.account.encryptItem(pv, id, { ...doc, login: { username: "b", password } } as ItemDoc);
    const bump = ++server.rev;
    const row: WireItem = { ...base, rev: bump, formatVersion: sealed.formatVersion, blob: sealed.blob };
    server.tamper = (r, _s, userId) => (userId !== BOB ? r : r.full ? leaveOut(r) : ({ ...leaveOut(r), items: [...leaveOut(r).items, row] } as SyncResponse));
  };
  /** From now on the item is left out of every answer, so what the list shows after a copy-out is the copies alone. */
  const leaveOutEverywhere = (): void => {
    server.tamper = (r, _s, userId) => (userId !== BOB ? r : leaveOut(r));
  };
  return { server, bob, pv, serveOnDeltas, leaveOutEverywhere };
}

describe("a copy set aside is never replaced", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("set aside holding 'second'; served again with 'first' (told, kept); then another fresh list leaves it out again: 'second' is still kept, beside 'first'", async () => {
    const { server, bob, pv, serveOnDeltas, leaveOutEverywhere } = await setAside();
    serveOnDeltas("first");
    await bob.store.sync();
    expect(passwordsOf(bob, pv, "my-own")).toEqual(["first"]);
    expect(noticesOf(bob, pv).filter((k) => k === OTHER)).toEqual([OTHER]);
    server.forgetHistory();
    await bob.store.sync();
    expect(passwordsOf(bob, pv, "my-own")).toEqual([]);
    expect(aside(bob)).toEqual([["personal", 2]]);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    expect(aside(again)).toEqual([["personal", 2]]);
    expect(passwordsOf(again, pv, "my-own")).toEqual([]);
    leaveOutEverywhere();
    await again.store.copySetAsideToPersonal(pv);
    expect(passwordsOf(again, pv, "my-own")).toEqual(["first", "second"]);
  });

  it("set aside three times with three contents: all three are kept, each told 'other' once, and copied out as three items", async () => {
    const { server, bob, pv, serveOnDeltas, leaveOutEverywhere } = await setAside();
    for (const password of ["first", "third"]) {
      serveOnDeltas(password);
      await bob.store.sync();
      expect(passwordsOf(bob, pv, "my-own")).toEqual([password]);
      server.forgetHistory();
      await bob.store.sync();
    }
    expect(aside(bob)).toEqual([["personal", 3]]);
    // Told once per item: the first "other" content was told, the later one is the same item.
    expect(noticesOf(bob, pv).filter((k) => k === OTHER).length).toBe(1);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile, sync: false });
    expect(aside(again)).toEqual([["personal", 3]]);
    leaveOutEverywhere();
    await again.store.copySetAsideToPersonal(pv);
    expect(passwordsOf(again, pv, "my-own")).toEqual(["first", "second", "third"]);
  });

  it("left out again with the SAME content as the copy kept: one copy, not two", async () => {
    const { server, bob, pv, serveOnDeltas } = await setAside();
    serveOnDeltas("second");
    await bob.store.sync();
    expect(aside(bob)).toEqual([]);
    server.forgetHistory();
    await bob.store.sync();
    expect(aside(bob)).toEqual([["personal", 1]]);
    expect(passwordsOf(bob, pv, "my-own")).toEqual([]);
  });
});
