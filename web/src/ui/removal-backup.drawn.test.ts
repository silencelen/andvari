// A backup holds only what the store's guarded reader still hands out when its file is written: what may be handed out is
// read again after the seal and its check, and a backup that lost a vault or an item is sealed again from the new read (at
// most three seals). A lock during the seal writes no file. The card shown after a backup names files of items still
// handed out only.
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import type { ItemDoc } from "../api/types";
import { BOB, type Browser, listed } from "../vault/fakesyncserver.testkit";
import { openBackup } from "../export/export";
import { BACKUP_NOT_MADE_CHANGED } from "./copy";
import { buttonNamed, click, closePage, settle, type } from "./dom.testkit";
import { backupPanel, filesWritten, opened, type Opened, removeBob } from "./removal.testkit";

/** What runs at the start of each of the next seals (the real seal runs right after it), one per seal, in order. */
const atSeal: { next: Array<() => Promise<void>>; seals: number } = { next: [], seals: 0 };
vi.mock("../export/export", async (importOriginal) => {
  const orig = await importOriginal<typeof import("../export/export")>();
  return {
    ...orig,
    buildBackup: async (...args: Parameters<typeof orig.buildBackup>) => {
      atSeal.seals++;
      const h = atSeal.next.shift();
      if (h) await h(); // a wrapper around the real seal, acting at its start
      return orig.buildBackup(...args);
    },
  };
});

beforeAll(async () => {
  await initSodium();
});
afterAll(async () => {
  await closePage();
});

const PW = "violet-harbour-quartz-1987-ledger-sunrise";

/** The server serves bob's own vault's row (as a real server does), so that the backup lists the own vault. */
async function servePersonalRow(f: Opened): Promise<void> {
  const personal = f.bob.account.personalVaultId!;
  f.server.tamper = (r, _since, userId) =>
    userId === BOB ? { ...r, vaults: [...r.vaults, { vaultId: personal, type: "personal", rev: r.rev, metaBlob: "", createdAt: 0 } as (typeof r.vaults)[number]] } : r;
  await f.screen.bell();
}

/** Another shared vault of alice's, with one item, that bob was added to and said yes to. */
async function anotherShared(f: Opened, name: string): Promise<string> {
  const v = await f.alice.store.createSharedVault(name);
  await f.alice.store.addVaultMember(v, BOB, "writer");
  await f.alice.store.save(null, { type: "login", name: `${name} item`, login: { username: "a", password: `pw-${name}` } }, [], undefined, v);
  await f.bob.store.sync();
  const ask = f.bob.shared.pendingAsks().find((a) => a.vaultId === v)!;
  expect((await f.bob.shared.answer(ask, true)).kind).toBe("adopted");
  await f.bob.store.sync();
  expect(listed(f.bob.store, v)).toBe(true);
  await f.screen.bell();
  return v;
}

/** The removal, carried out by bob's own real sync (what a bell during "Sealing backup…" does). */
const removalBySync = (f: Opened, alice: Browser, vaultId: string) => async () => {
  await removeBob(alice, vaultId);
  await f.bob.store.sync();
};

async function backUp(f: Opened): Promise<Blob[]> {
  return filesWritten(f.screen, async () => {
    await click(buttonNamed(f.screen.page, "Create encrypted backup"));
    for (let i = 0; i < 80 && !f.screen.text().includes("Done") && !f.screen.text().includes(BACKUP_NOT_MADE_CHANGED); i++) await settle(20);
  });
}

async function namesIn(file: Blob): Promise<{ names: string[]; vaults: string[] }> {
  const o = await openBackup(PW, new Uint8Array(await file.arrayBuffer()));
  return { names: o.payload.items.map((i: { doc: ItemDoc }) => i.doc.name).sort(), vaults: o.payload.vaults.map((v: { vaultId: string }) => v.vaultId) };
}

describe("a backup across a removal", () => {
  it("a lock during the backup's seal writes no file", async () => {
    const f = await opened();
    await servePersonalRow(f);
    await backupPanel(f.screen, PW);
    atSeal.next = [
      async () => {
        // A lock: the vault screen goes, then the store closes (ui/App.tsx).
        await f.screen.unmount();
        f.bob.store.close();
      },
    ];
    const written = await filesWritten(f.screen, async () => {
      await click(buttonNamed(f.screen.page, "Create encrypted backup"));
      await settle(80);
    });
    expect(written.length).toBe(0);
  }, 120_000);

  it("a backup sealed while a sync carries the removal out is sealed again without the vault", async () => {
    const f = await opened();
    await servePersonalRow(f);
    await f.bob.store.save(null, { type: "login", name: "Own bike lock", login: { username: "bob", password: "bike-pw-28" } });
    await f.screen.bell();
    await backupPanel(f.screen, PW);
    atSeal.seals = 0;
    atSeal.next = [removalBySync(f, f.alice, f.old)];
    const written = await backUp(f);
    expect({ listedAfter: listed(f.bob.store, f.old), handedOut: f.bob.store.get(f.gate.itemId) !== undefined }).toEqual({ listedAfter: false, handedOut: false });
    expect(written.length, f.screen.text().slice(0, 600)).toBe(1);
    const inFile = await namesIn(written[0]!);
    expect({ names: inFile.names, removedVaultInFile: inFile.vaults.includes(f.old), seals: atSeal.seals }).toEqual({ names: ["Own bike lock"], removedVaultInFile: false, seals: 2 });
    await f.screen.unmount();
  }, 120_000);

  it("nothing left to back up after the removal: no file, and the panel says so", async () => {
    const f = await opened();
    await backupPanel(f.screen, PW);
    atSeal.next = [removalBySync(f, f.alice, f.old)];
    const written = await backUp(f);
    expect({ files: written.length, said: f.screen.text().includes(BACKUP_NOT_MADE_CHANGED) }).toEqual({ files: 0, said: true });
    await f.screen.unmount();
  }, 120_000);

  it("a removal at each of three seals: no file, and the panel says so", async () => {
    const f = await opened();
    await servePersonalRow(f);
    await f.bob.store.save(null, { type: "login", name: "Own bike lock", login: { username: "bob", password: "bike-pw-28" } });
    const two = await anotherShared(f, "Two");
    const three = await anotherShared(f, "Three");
    await backupPanel(f.screen, PW);
    atSeal.seals = 0;
    atSeal.next = [removalBySync(f, f.alice, f.old), removalBySync(f, f.alice, two), removalBySync(f, f.alice, three)];
    const written = await backUp(f);
    expect({ files: written.length, said: f.screen.text().includes(BACKUP_NOT_MADE_CHANGED), seals: atSeal.seals }).toEqual({ files: 0, said: true, seals: 3 });
    await f.screen.unmount();
  }, 180_000);

  it("the names of files left out that the file itself holds come from the read after the check", async () => {
    // GATE names a file the server does not hold: its fetch fails, and before the removal its name is among those left out.
    const f = await opened({ attachment: true, fileMissing: true });
    await servePersonalRow(f);
    await f.bob.store.save(null, { type: "login", name: "Own bike lock", login: { username: "bob", password: "bike-pw-28" } });
    await f.screen.bell();
    await click([...f.screen.page.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Export")!);
    await click(buttonNamed(f.screen.page, "Back up vault…"));
    await f.screen.bell();
    const withFiles = [...f.screen.page.querySelectorAll('input[type="checkbox"]')].find((c) => (c.closest("label")?.textContent ?? "").toLowerCase().includes("attachment"));
    expect(withFiles, f.screen.text().slice(0, 800)).toBeDefined();
    await click(withFiles!);
    const inputs = [...f.screen.page.querySelectorAll('input[type="password"]')] as HTMLInputElement[];
    await type(inputs[0]!, PW);
    await type(inputs[1]!, PW);
    atSeal.seals = 0;
    atSeal.next = [removalBySync(f, f.alice, f.old)];
    const written = await backUp(f);
    expect(written.length, f.screen.text().slice(0, 600)).toBe(1);
    const o = await openBackup(PW, new Uint8Array(await written[0]!.arrayBuffer()));
    expect({ names: o.payload.items.map((i: { doc: ItemDoc }) => i.doc.name).sort(), fetchFailedInFile: o.payload.skipped.attachmentFetchFailed, seals: atSeal.seals }).toEqual({
      names: ["Own bike lock"],
      fetchFailedInFile: [],
      seals: 2,
    });
    await f.screen.unmount();
  }, 120_000);

  it("the card after a backup drops the names of a vault removed later", async () => {
    // GATE names a file the server does not hold: the backup's fetch fails, and the card names it.
    const f = await opened({ attachment: true, fileMissing: true });
    await servePersonalRow(f);
    await click([...f.screen.page.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Export")!);
    await click(buttonNamed(f.screen.page, "Back up vault…"));
    await f.screen.bell();
    const withFiles = [...f.screen.page.querySelectorAll('input[type="checkbox"]')].find((c) => (c.closest("label")?.textContent ?? "").toLowerCase().includes("attachment"));
    expect(withFiles, f.screen.text().slice(0, 800)).toBeDefined();
    await click(withFiles!);
    const inputs = [...f.screen.page.querySelectorAll('input[type="password"]')] as HTMLInputElement[];
    await type(inputs[0]!, PW);
    await type(inputs[1]!, PW);
    const written = await backUp(f);
    expect(written.length).toBe(1);
    expect(f.screen.text()).toContain("gate-plan.pdf");
    await removeBob(f.alice, f.old);
    await f.screen.bell();
    expect(listed(f.bob.store, f.old)).toBe(false);
    expect(f.screen.text()).not.toContain("gate-plan.pdf");
    await f.screen.unmount();
  }, 120_000);
});
