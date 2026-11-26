// Which vault is the person's own comes only from the opened account (Account.personalVaultId), never from a row a server
// serves: the own items are shown also where the server serves no row for the own vault, a shared vault the server serves
// no row for shows nothing, and no served label makes a shared vault the own one.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initSodium } from "../crypto/sodium";
import { BOB, browser, listed } from "../vault/fakesyncserver.testkit";
import { buttonNamed, click, closePage } from "./dom.testkit";
import { byText, drawVault, type DrawnVault } from "./vaultscreen.testkit";
import { GATE, leftIn, opened, removeBob } from "./removal.testkit";

beforeAll(async () => {
  await initSodium();
});
afterAll(async () => {
  await closePage();
});

const OWN = "Own bike lock";

/** Whether [name] is drawn in the list, and in Health's passwords and staleness tabs. */
async function shownIn(screen: DrawnVault, name: string): Promise<{ list: boolean; health: boolean; staleness: boolean }> {
  const list = [...screen.page.querySelectorAll("button.item .name")].some((n) => n.textContent === name);
  await click(buttonNamed(screen.page, "Health"));
  const health = screen.text().includes(name);
  const b = [...screen.page.querySelectorAll("button[aria-pressed]")].find((x) => x.textContent?.startsWith("Staleness"));
  expect(b, "Staleness").toBeDefined();
  await click(b!);
  const staleness = screen.text().includes(name);
  await click(buttonNamed(screen.page, "Vault"));
  return { list, health, staleness };
}

describe("the person's own vault when the server serves no row for it", () => {
  it("the own items are shown when the server serves no row for the own vault", async () => {
    const f = await opened();
    // The fake server serves rows of shared vaults only (none for the own vault), as a server that leaves it out does.
    await f.bob.store.save(null, { type: "login", name: OWN, login: { username: "bob", password: "pw" } }, [], undefined, f.bob.account.personalVaultId);
    await f.screen.bell();
    expect(listed(f.bob.store, f.bob.account.personalVaultId)).toBe(false);
    expect(await shownIn(f.screen, OWN)).toEqual({ list: true, health: true, staleness: true });
    await f.screen.unmount();
  });

  it("the Trash shows the person's own deleted items when the server serves no row for the own vault", async () => {
    const f = await opened();
    f.server.keepsTrash = true; // the server keeps deleted items and their last versions, as an honest server does
    await f.bob.store.save(null, { type: "login", name: OWN, login: { username: "bob", password: "pw" } }, [], undefined, f.bob.account.personalVaultId);
    await f.screen.bell();
    const own = f.bob.store.list().find((i) => i.doc.name === OWN)!;
    await f.bob.store.remove(own.itemId);
    await f.screen.bell();
    expect(listed(f.bob.store, f.bob.account.personalVaultId)).toBe(false);
    const trash = [...f.screen.page.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Trash");
    expect(trash).toBeDefined();
    await click(trash!);
    await f.screen.bell();
    expect({ named: f.screen.text().includes(OWN), restoreOffered: [...f.screen.page.querySelectorAll("button")].some((b) => b.textContent === "Restore") }).toEqual({ named: true, restoreOffered: true });
    await f.screen.unmount();
  });

  it("a shared vault the server serves no row for shows nothing", async () => {
    const f = await opened({ draw: false });
    f.server.tamper = (r, _since, userId) => (userId === BOB ? { ...r, vaults: r.vaults.filter((v) => v.vaultId !== f.old) } : r);
    // A new start of bob's browser profile with no offline copy: its first sync never sees the shared vault's row.
    const fresh = await browser(f.server, f.bob.person, f.bob.contacts, { again: f.bob.profile });
    expect(listed(fresh.store, f.old)).toBe(false);
    const screen = await drawVault(fresh);
    expect(await shownIn(screen, GATE.name)).toEqual({ list: false, health: false, staleness: false });
    expect(leftIn(screen)).toEqual([]);
    await screen.unmount();
  });

  it("no served row makes a shared vault count as the own", async () => {
    const f = await opened();
    // The server labels the shared vault "personal" and serves no row for the own vault.
    f.server.tamper = (r, _since, userId) => (userId === BOB ? { ...r, vaults: r.vaults.map((v) => (v.vaultId === f.old ? { ...v, type: "personal" } : v)) } : r);
    await f.screen.bell();
    expect(f.bob.store.vaults().find((v) => v.vaultId === f.old)?.type).toBe("shared");
    expect(byText(f.screen.page, GATE.name)).toBeDefined();
    // Removed from it: the label does not keep it on show.
    await removeBob(f.alice, f.old);
    await f.screen.bell();
    expect(listed(f.bob.store, f.old)).toBe(false);
    expect(await shownIn(f.screen, GATE.name)).toEqual({ list: false, health: false, staleness: false });
    expect(leftIn(f.screen)).toEqual([]);
    await f.screen.unmount();
  });
});
