// The import's report says which rows of the person's file were already in the destination vault, which is derived from
// that vault's items. Once the destination vault is gone (a removal carried out), the report is closed.
import { act } from "react";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { BOB, listed } from "../vault/fakesyncserver.testkit";
import { click, closePage } from "./dom.testkit";
import type { DrawnVault } from "./vaultscreen.testkit";
import { GATE, opened, type Opened, removeBob, winOf } from "./removal.testkit";

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

async function pick(screen: DrawnVault, input: HTMLInputElement, name: string, text: string): Promise<void> {
  const win = winOf(screen);
  const file = new win.File([text], name, { type: "text/csv" });
  await act(async () => {
    Object.defineProperty(input, "files", { configurable: true, value: [file] });
    input.dispatchEvent(new win.Event("change", { bubbles: true }));
  });
  await screen.bell().catch(() => {});
}

async function choose(screen: DrawnVault, select: HTMLSelectElement, value: string): Promise<void> {
  const win = winOf(screen);
  await act(async () => {
    select.value = value;
    select.dispatchEvent(new win.Event("change", { bubbles: true }));
  });
}

describe("the import's report across a removal", () => {
  it("the import's report closes once its destination vault is gone", async () => {
    const f = await opened();
    const { screen, old } = f;
    await servePersonalRow(f);
    await click([...screen.page.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Import")!);
    const fileInput = [...screen.page.querySelectorAll("input")].find((i) => i.type === "file" && i.getAttribute("aria-label") !== "Attach files")!;
    // One row is the gate as the vault holds it (the report says it is already there); one is new.
    const csv = `name,url,username,password\n${GATE.name},${GATE.login!.uris![0]},${GATE.login!.username},${GATE.login!.password}\nImported row,https://row.example.org,row-user,row-pw-61\n`;
    await pick(screen, fileInput as HTMLInputElement, "browser.csv", csv);
    const select = [...screen.page.querySelectorAll("select")].find((s) => [...s.options].some((o) => o.value === old)) as HTMLSelectElement | undefined;
    expect(select, screen.text()).toBeDefined();
    await choose(screen, select!, old);
    await click([...screen.page.querySelectorAll("button")].find((b) => b.textContent?.startsWith("Import "))!);
    await screen.bell();
    const report = () => ({ added: screen.text().includes("Added 1 item to"), gateNamed: screen.text().includes(GATE.name), family: screen.text().includes("“Family” (shared)") });
    expect(report(), screen.text().slice(0, 900)).toEqual({ added: true, gateNamed: true, family: true });
    await removeBob(f.alice, old);
    await screen.bell();
    expect(listed(f.bob.store, old)).toBe(false);
    expect(report()).toEqual({ added: false, gateNamed: false, family: false });
    await screen.unmount();
  });
});
