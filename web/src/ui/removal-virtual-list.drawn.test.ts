// The virtual list (over 500 rows) renders by its own state (a scroll, a resize) without the vault screen rendering: it
// reads its rows through the store's guarded reader at its own render, so a removal another tab carried out draws no row of
// the vault, as the plain list does when the person types into the search.
import { act } from "react";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import type { ItemDoc } from "../api/types";
import { BOB } from "../vault/fakesyncserver.testkit";
import { closePage, settle, type } from "./dom.testkit";
import { byText } from "./vaultscreen.testkit";
import { GATE, leftIn, opened, type Opened, removeBob, tabBCarriesItOut, winOf } from "./removal.testkit";

beforeAll(async () => {
  await initSodium();
});
afterAll(async () => {
  await closePage();
});

async function servePersonalRow(f: Opened): Promise<void> {
  const personal = f.bob.account.personalVaultId!;
  f.server.tamper = (r, _since, userId) =>
    userId === BOB ? { ...r, vaults: [...r.vaults, { vaultId: personal, type: "personal", rev: r.rev, metaBlob: "", createdAt: 0 } as (typeof r.vaults)[number]] } : r;
  await f.screen.bell();
}

describe("a list drawn after another tab carried the removal out, with no event in this tab", () => {
  it("control: without the virtual list, the search draws nothing of the removed vault", async () => {
    const f = await opened();
    expect(byText(f.screen.page, GATE.name)).toBeDefined();
    await removeBob(f.alice, f.old);
    await tabBCarriesItOut(f);
    const search = [...f.screen.page.querySelectorAll("input")].find((i) => i.type === "search" || (i.getAttribute("placeholder") ?? "").toLowerCase().includes("search"));
    expect(search).toBeDefined();
    await type(search as HTMLInputElement, "Garden");
    expect(leftIn(f.screen).filter((x) => x !== "Garden")).toEqual([]);
    await f.screen.unmount();
  });

  it("the virtual list draws no row of the removed vault at its own render (another tab carried the removal out)", async () => {
    const f = await opened();
    await servePersonalRow(f);
    const docs: ItemDoc[] = Array.from({ length: 505 }, (_, i) => ({ type: "login", name: `a-${String(i).padStart(3, "0")}`, login: { username: "u", password: `p${i}` } }));
    await f.bob.store.importDocs(docs.map((doc) => ({ itemId: crypto.randomUUID(), doc })), () => {}, f.bob.account.personalVaultId);
    await f.screen.bell();
    expect(f.screen.page.querySelector(".vault-list--virtual"), "virtual list engaged").not.toBeNull();
    expect(leftIn(f.screen), "the gate row is outside the window at first").toEqual([]);
    await removeBob(f.alice, f.old);
    await tabBCarriesItOut(f);
    expect(f.bob.store.get(f.gate.itemId)).toBeUndefined();
    const win = winOf(f.screen);
    await act(async () => {
      Object.defineProperty(win, "innerHeight", { configurable: true, value: 100_000 });
      win.dispatchEvent(new win.Event("resize"));
    });
    await settle(10);
    expect(leftIn(f.screen)).toEqual([]);
    await f.screen.unmount();
  }, 180_000);
});
