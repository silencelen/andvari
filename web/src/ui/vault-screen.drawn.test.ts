// The vault screen drawn over a real store whose shared vaults sit on the real log layer: what the screen keeps on show
// after the person was removed from a shared vault. A screen shows nothing that the store's guarded reader no longer hands
// out, whatever it opened before: the editor, the item, the list, Health and the Trash.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { toB64, utf8 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import type { ItemDoc } from "../api/types";
import { BOB, browser, type Browser, family, freshDb, listed } from "../vault/fakesyncserver.testkit";
import { openVaultCache } from "../vault/idbcache";
import { EDITOR_VAULT_GONE, ITEM_CLOSED, ITEM_CLOSED_EDITING, ITEM_CLOSED_EDITING_NOT_KEPT } from "./copy";
import { buttonNamed, click, closePage, settle, type } from "./dom.testkit";
import { byText, drawVault, type DrawnVault } from "./vaultscreen.testkit";

beforeAll(async () => {
  await initSodium();
});
afterAll(async () => {
  await closePage();
});

/** An item of the shared vault whose every field can be searched for in the page. */
const GATE: ItemDoc = {
  type: "login",
  name: "Garden gate",
  login: { username: "gate-keeper-41", password: "Tr0ub4dor-pw-93", uris: ["https://gate.example.org"] },
  notes: "spare key under the third stone",
};
const FIELDS = ["Garden gate", "gate-keeper-41", "Tr0ub4dor-pw-93", "gate.example.org", "spare key under the third stone"];
/** The fields of [GATE] still somewhere in the page: its text, its markup, or the value of a field. */
const leftIn = (screen: DrawnVault): string[] => FIELDS.filter((f) => screen.html().includes(f));

/** Alice owns "Family" with "bank" and [GATE]; bob, a writer of it, has the vault screen open. */
async function opened(opts: { cache?: boolean; attachment?: boolean } = {}) {
  freshDb();
  const { server, alice, bob, old } = await family(opts.cache ? await openVaultCache(BOB) : undefined);
  const files = opts.attachment ? [{ id: "9f0c5e3a-6c1b-4b7e-9a51-2d1e8f4c7a10", data: utf8("the gate's plan") }] : [];
  const doc: ItemDoc = opts.attachment ? { ...GATE, attachments: [{ id: files[0]!.id, name: "gate-plan.pdf", size: files[0]!.data.length, fileKey: toB64(randomBytes(32)) }] } : GATE;
  await alice.store.save(null, doc, files, undefined, old);
  await bob.store.sync();
  const gate = bob.store.list().find((i) => i.doc.name === GATE.name)!;
  expect(gate.vaultId).toBe(old);
  const screen = await drawVault(bob);
  expect(byText(screen.page, GATE.name), screen.text()).toBeDefined();
  return { server, alice, bob, old, gate, screen };
}

const removeBob = async (alice: Browser, vaultId: string): Promise<void> => {
  await alice.store.removeVaultMember(vaultId, BOB);
  await alice.store.sync();
};

async function openItem(screen: DrawnVault, name: string): Promise<void> {
  const row = [...screen.page.querySelectorAll("button.item")].find((b) => b.querySelector(".name")?.textContent === name);
  expect(row, name).toBeDefined();
  await click(row!);
}

async function openEditor(screen: DrawnVault, name: string): Promise<void> {
  await openItem(screen, name);
  await click(buttonNamed(screen.page, "Edit"));
  expect(screen.page.querySelector("form.sheet")).not.toBeNull();
}

/** The editor's field labelled [label] (its input follows the label inside the Field). */
function editorInput(screen: DrawnVault, label: string): HTMLInputElement {
  const lab = [...screen.page.querySelectorAll("form.sheet label")].find((l) => l.textContent?.startsWith(label));
  const input = lab?.parentElement?.querySelector("input, textarea");
  if (!input) throw new Error(`no field ${label}`);
  return input as HTMLInputElement;
}

/** What the page shows of the removal: the fields left, whether the editor and the item are open, and the lines. */
const shown = (screen: DrawnVault) => ({
  fieldsLeft: leftIn(screen),
  editorOpen: screen.page.querySelector("form.sheet") !== null,
  closedLine: [ITEM_CLOSED, ITEM_CLOSED_EDITING, ITEM_CLOSED_EDITING_NOT_KEPT].filter((l) => l !== undefined && screen.text().includes(l)),
});

/** Tab B of bob's browser profile (the same records at rest, its own key ring) syncs and carries the removal out. */
async function anotherTabSyncs(f: Awaited<ReturnType<typeof opened>>): Promise<Browser> {
  const tabB = await browser(f.server, f.bob.person, f.bob.contacts, { cache: await openVaultCache(BOB), again: f.bob.profile });
  expect(listed(tabB.store, f.old)).toBe(false);
  // This tab has not synced; its store's guarded reader no longer hands the vault's items out.
  expect(f.bob.store.get(f.gate.itemId)).toBeUndefined();
  return tabB;
}

/** The `storage` event a browser fires in this tab when another tab of the profile wrote a record of a vault's log. */
async function storageEventFromAnotherTab(screen: DrawnVault, vaultId: string): Promise<void> {
  const win = screen.page.ownerDocument.defaultView as unknown as Window & typeof globalThis;
  const { act } = await import("react");
  await act(async () => {
    win.dispatchEvent(new win.StorageEvent("storage", { key: `andvari.log2.${BOB}.${vaultId}.state` }));
  });
}

describe("the vault screen drawn over a real store", () => {
  it("lists an item of a shared vault by its name", async () => {
    const { screen } = await opened();
    expect(byText(screen.page, "bank")).toBeDefined();
    await screen.unmount();
  });
});

describe("after a removal, the screen shows nothing of the vault's items", () => {
  it("an open editor, then the owner removes the person, then a sync carries the removal out: the editor closes and says why", async () => {
    const { alice, bob, old, screen } = await opened();
    await openEditor(screen, GATE.name);
    expect(leftIn(screen)).toEqual(FIELDS);
    await removeBob(alice, old);
    await screen.bell();
    expect(listed(bob.store, old)).toBe(false);
    expect(shown(screen)).toEqual({ fieldsLeft: [], editorOpen: false, closedLine: [ITEM_CLOSED_EDITING] });
    await screen.unmount();
  });

  it("typing that was not saved is not kept, and the line says so", async () => {
    const { alice, bob, old, server, screen } = await opened();
    await openEditor(screen, GATE.name);
    await type(editorInput(screen, "Notes"), "typed after the removal, never saved");
    await removeBob(alice, old);
    const writesBefore = server.writes.length;
    await screen.bell();
    expect(listed(bob.store, old)).toBe(false);
    expect({ ...shown(screen), typedLeft: screen.html().includes("never saved"), sent: server.writes.slice(writesBefore) }).toEqual({
      fieldsLeft: [],
      editorOpen: false,
      closedLine: [ITEM_CLOSED_EDITING_NOT_KEPT],
      typedLeft: false,
      sent: [],
    });
    await screen.unmount();
  });

  it("a removal and a new add: the editor closes, and the vault is not listed until the person says yes", async () => {
    const { alice, bob, old, screen } = await opened();
    await openEditor(screen, GATE.name);
    await removeBob(alice, old);
    await alice.store.addVaultMember(old, BOB, "writer");
    await alice.store.sync();
    await screen.bell();
    expect(bob.shared.pendingAsks().filter((a) => a.vaultId === old)).toHaveLength(1);
    expect({ ...shown(screen), listed: listed(bob.store, old) }).toEqual({ fieldsLeft: [], editorOpen: false, closedLine: [ITEM_CLOSED_EDITING], listed: false });
    await screen.unmount();
  });

  it("the list after another tab of the same profile carried the removal out and this tab has not synced", async () => {
    const f = await opened({ cache: true });
    await removeBob(f.alice, f.old);
    await anotherTabSyncs(f);
    await storageEventFromAnotherTab(f.screen, f.old);
    expect({ fieldsLeft: leftIn(f.screen), bank: byText(f.screen.page, "bank") === undefined ? "gone" : "shown" }).toEqual({ fieldsLeft: [], bank: "gone" });
    await f.screen.unmount();
  });

  it("Health, its duplicates and its staleness after another tab of the same profile carried the removal out", async () => {
    const f = await opened({ cache: true });
    await click(buttonNamed(f.screen.page, "Health"));
    expect(leftIn(f.screen)).toContain(GATE.name);
    await removeBob(f.alice, f.old);
    await anotherTabSyncs(f);
    await storageEventFromAnotherTab(f.screen, f.old);
    const tabs: Record<string, string[]> = { passwords: leftIn(f.screen) };
    for (const [key, label] of [["duplicates", "Duplicates"], ["staleness", "Staleness"]] as const) {
      const b = [...f.screen.page.querySelectorAll("button[aria-pressed]")].find((x) => x.textContent?.startsWith(label));
      expect(b, label).toBeDefined();
      await click(b!);
      tabs[key] = leftIn(f.screen);
    }
    expect(tabs).toEqual({ passwords: [], duplicates: [], staleness: [] });
    await f.screen.unmount();
  });

  it("the Trash open on a deleted item of that vault", async () => {
    const f = await opened();
    // The server keeps a deleted item's last version (an honest server's Trash); the fake serves none, so it is given here.
    const kept = f.server.items.get(f.gate.itemId)!;
    await f.alice.store.remove(f.gate.itemId);
    await f.bob.store.sync();
    const wire = (f.bob.store as unknown as { wire: Record<string, unknown> }).wire;
    wire.deletedItems = async () => ({ items: [{ itemId: f.gate.itemId, vaultId: f.old, deletedAt: 1 }] });
    wire.itemVersions = async (itemId: string) => ({ itemId, versions: itemId === f.gate.itemId ? [{ rev: kept.rev, blob: kept.blob, formatVersion: kept.formatVersion, archivedAt: 1 }] : [] });
    const trash = [...f.screen.page.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Trash");
    expect(trash, [...f.screen.page.querySelectorAll("button")].map((b) => b.getAttribute("aria-label") ?? b.textContent).join("|")).toBeDefined();
    await click(trash!);
    await f.screen.bell();
    expect(leftIn(f.screen), f.screen.text()).toContain(GATE.name);
    await removeBob(f.alice, f.old);
    await f.screen.bell();
    expect(listed(f.bob.store, f.old)).toBe(false);
    expect({ fieldsLeft: leftIn(f.screen), restoreOffered: [...f.screen.page.querySelectorAll("button")].some((b) => b.textContent === "Restore") }).toEqual({ fieldsLeft: [], restoreOffered: false });
    await f.screen.unmount();
  });
});

describe("controls: the parts of the item view that read through the guarded reader at each render", () => {
  it("the item, its history and its attachments list are gone after the sync that carries the removal out", async () => {
    const f = await opened({ attachment: true });
    const wire = (f.bob.store as unknown as { wire: Record<string, unknown> }).wire;
    const sealed = f.server.items.get(f.gate.itemId)!;
    // One version in the item's history, as the server serves it (the fake serves none): the item's own sealed blob.
    wire.itemVersions = async (itemId: string) => ({ itemId, versions: [{ rev: 1, blob: sealed.blob, formatVersion: sealed.formatVersion, archivedAt: 1 }] });
    await openItem(f.screen, GATE.name);
    await click(buttonNamed(f.screen.page, "Version history"));
    const before = { fields: leftIn(f.screen), attachment: f.screen.html().includes("gate-plan.pdf"), history: f.screen.text().includes("Hide history") };
    expect(before).toEqual({ fields: FIELDS, attachment: true, history: true });
    await removeBob(f.alice, f.old);
    await f.screen.bell();
    expect({ fields: leftIn(f.screen), attachment: f.screen.html().includes("gate-plan.pdf"), history: f.screen.text().includes("Hide history") }).toEqual({ fields: [], attachment: false, history: false });
    await f.screen.unmount();
  });
});

/** The page's window, with its own constructors (File, Event). */
const winOf = (screen: DrawnVault) => screen.page.ownerDocument.defaultView as unknown as Window & typeof globalThis;

/** A file picked into [input], as the browser hands it to the page. */
async function pick(screen: DrawnVault, input: HTMLInputElement, name: string, text: string): Promise<void> {
  const win = winOf(screen);
  const file = new win.File([text], name, { type: "text/csv" });
  const { act } = await import("react");
  await act(async () => {
    Object.defineProperty(input, "files", { configurable: true, value: [file] });
    input.dispatchEvent(new win.Event("change", { bubbles: true }));
  });
  await screen.bell().catch(() => {});
}

async function choose(screen: DrawnVault, select: HTMLSelectElement, value: string): Promise<void> {
  const win = winOf(screen);
  const { act } = await import("react");
  await act(async () => {
    select.value = value;
    select.dispatchEvent(new win.Event("change", { bubbles: true }));
  });
}

/**
 * The fake server serves no row for a personal vault (the real one does, with its grant): bob's is served here, so that
 * the screens that offer the personal vault (a move's targets, an import's destination, an export) have it.
 */
async function servePersonalRow(f: Awaited<ReturnType<typeof opened>>): Promise<void> {
  const personal = f.bob.account.personalVaultId!;
  f.server.tamper = (r, _since, userId) =>
    userId === BOB ? { ...r, vaults: [...r.vaults, { vaultId: personal, type: "personal", rev: r.rev, metaBlob: "", createdAt: 0 } as (typeof r.vaults)[number]] } : r;
  await f.screen.bell();
  expect(f.bob.store.vaults().map((v) => v.vaultId)).toContain(personal);
}

const inputLabelled = (screen: DrawnVault, label: string): HTMLInputElement =>
  [...screen.page.querySelectorAll("input")].find((i) => i.getAttribute("aria-label") === label) as HTMLInputElement;

describe("what the next look will try: a removal while each part of the screen is open", () => {
  it("while the generator has filled the editor's password: closed, the new password is not kept, nothing is sent", async () => {
    const { alice, old, server, screen } = await opened();
    await openEditor(screen, GATE.name);
    await click(buttonNamed(screen.page, "Generate"));
    await click(buttonNamed(screen.page, "Replace?"));
    const generated = editorInput(screen, "Password").value;
    expect(generated).not.toBe(GATE.login!.password);
    await removeBob(alice, old);
    const before = server.writes.length;
    await screen.bell();
    expect({ ...shown(screen), generatedLeft: screen.html().includes(generated), sent: server.writes.slice(before) }).toEqual({
      fieldsLeft: [],
      editorOpen: false,
      closedLine: [ITEM_CLOSED_EDITING_NOT_KEPT],
      generatedLeft: false,
      sent: [],
    });
  });

  it("while the move and copy control is open: the item view closes, and the control with it", async () => {
    const f = await opened();
    const { alice, old, screen } = f;
    await servePersonalRow(f);
    await openItem(screen, GATE.name);
    await click(buttonNamed(screen.page, "Move to vault…"));
    expect(screen.text()).toContain("Move to another vault");
    await removeBob(alice, old);
    await screen.bell();
    expect({ ...shown(screen), control: screen.text().includes("Move to another vault") }).toEqual({ fieldsLeft: [], editorOpen: false, closedLine: [ITEM_CLOSED], control: false });
  });

  it("while a file is being attached in the editor: closed, the file is not kept and not uploaded", async () => {
    const { alice, old, server, screen } = await opened();
    await openEditor(screen, GATE.name);
    await pick(screen, inputLabelled(screen, "Attach files"), "secret-plan.txt", "the plan");
    expect(screen.text()).toContain("secret-plan.txt");
    await removeBob(alice, old);
    const before = server.writes.length;
    await screen.bell();
    expect({ ...shown(screen), fileLeft: screen.html().includes("secret-plan.txt"), sent: server.writes.slice(before) }).toEqual({
      fieldsLeft: [],
      editorOpen: false,
      closedLine: [ITEM_CLOSED_EDITING_NOT_KEPT],
      fileLeft: false,
      sent: [],
    });
  });

  it("while the import panel is planned into the removed vault: it is no destination, and nothing is imported", async () => {
    const f = await opened();
    const { alice, old, server, screen } = f;
    await servePersonalRow(f);
    await click([...screen.page.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Import")!);
    const fileInput = [...screen.page.querySelectorAll('input')].find((i) => i.type === "file" && i.getAttribute("aria-label") !== "Attach files")!;
    await pick(screen, fileInput as HTMLInputElement, "browser.csv", "name,url,username,password\nImported row,https://row.example.org,row-user,row-pw-61\n");
    const select = () => [...screen.page.querySelectorAll("select")].find((s) => [...s.options].some((o) => o.value === old)) as HTMLSelectElement | undefined;
    expect(select(), screen.text()).toBeDefined();
    await choose(screen, select()!, old);
    await removeBob(alice, old);
    await screen.bell();
    const importButton = [...screen.page.querySelectorAll("button")].find((b) => b.textContent?.startsWith("Import "));
    const before = server.writes.length;
    if (importButton && !importButton.disabled) await click(importButton);
    expect({ offered: select() !== undefined, importEnabled: importButton !== undefined && !importButton.disabled, sent: server.writes.slice(before) }).toEqual({ offered: false, importEnabled: false, sent: [] });
  });

  it("while the CSV export panel is open: the file written after the removal holds nothing of the vault", async () => {
    const f = await opened();
    await servePersonalRow(f);
    await f.bob.store.save(null, { type: "login", name: "Own bike lock", login: { username: "bob", password: "bike-pw-28" } });
    await f.screen.bell();
    await csvPanelAcked(f.screen);
    await removeBob(f.alice, f.old);
    await f.screen.bell();
    const written = await downloadCsv(f.screen, "Download 1 login as CSV");
    expect({ files: written.length, ownItem: written.join("").includes("Own bike lock"), fieldsLeft: FIELDS.filter((x) => written.join("").includes(x)), bank: written.join("").includes("bank") }).toEqual({
      files: 1,
      ownItem: true,
      fieldsLeft: [],
      bank: false,
    });
  });

  it("while the CSV export panel is open and another tab carries the removal out: a download pressed before this tab renders again writes nothing of the vault", async () => {
    const f = await opened({ cache: true });
    await csvPanelAcked(f.screen);
    await removeBob(f.alice, f.old);
    await anotherTabSyncs(f);
    // The button this tab drew before the other tab moved the log still counts the vault's two logins.
    const written = await downloadCsv(f.screen, "Download 2 logins as CSV");
    expect({ files: written.length, fieldsLeft: FIELDS.filter((x) => written.join("").includes(x)), bank: written.join("").includes("bank") }).toEqual({ files: 1, fieldsLeft: [], bank: false });
  });
});

/** Opens the CSV export panel, lets its own sync land, and ticks "I understand this file is unencrypted". */
async function csvPanelAcked(screen: DrawnVault): Promise<void> {
  await click([...screen.page.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Export")!);
  await click(buttonNamed(screen.page, "Export for another password manager…"));
  await screen.bell();
  expect(leftIn(screen)).toEqual([]); // the panel itself names no item's field
  const ack = [...screen.page.querySelectorAll('input[type="checkbox"]')].find((c) => c.parentElement?.textContent?.includes("unencrypted")) as HTMLInputElement;
  await click(ack);
}

/** Presses the CSV download button (whose text must be [label]) and returns the text of every file the page wrote. */
async function downloadCsv(screen: DrawnVault, label: string): Promise<string[]> {
  const written: Blob[] = [];
  const url = globalThis.URL as unknown as { createObjectURL: (b: Blob) => string };
  const real = url.createObjectURL;
  url.createObjectURL = (b: Blob) => {
    written.push(b);
    return "blob:written";
  };
  // The export dispatches an `Event` on the window (it keeps the auto-lock awake): the page's own Event, as in a browser,
  // not Node's, which the page's window refuses.
  const g = globalThis as { Event: typeof Event };
  const nodeEvent = g.Event;
  g.Event = winOf(screen).Event;
  try {
    const download = [...screen.page.querySelectorAll("button")].find((b) => b.textContent?.startsWith("Download "));
    expect(download?.textContent).toBe(label);
    expect((download as HTMLButtonElement).disabled, screen.text()).toBe(false);
    // The press as the browser delivers it: the click handler runs before this tab renders again.
    (download as HTMLButtonElement).click();
  } finally {
    url.createObjectURL = real;
    g.Event = nodeEvent;
  }
  await settle();
  expect(written.length, screen.text()).toBe(1);
  return Promise.all(written.map((b) => b.text()));
}

describe("what the next look will try: a new item's editor, and removals in a row", () => {
  it("while the editor holds a NEW item whose chosen vault is the removed one: that vault is no longer offered, and a save sends nothing", async () => {
    const { alice, old, server, screen } = await opened();
    await click(buttonNamed(screen.page, "+ Login"));
    const vaultSelect = () => [...screen.page.querySelectorAll("form.sheet select")][0] as HTMLSelectElement;
    await choose(screen, vaultSelect(), old);
    await type(editorInput(screen, "Name"), "new for the family");
    await removeBob(alice, old);
    await screen.bell();
    const save = [...screen.page.querySelectorAll("form.sheet button")].find((b) => b.textContent === "Save") as HTMLButtonElement;
    const before = server.writes.length;
    if (save && !save.disabled) await click(save);
    expect({
      editorOpen: screen.page.querySelector("form.sheet") !== null,
      line: screen.text().includes(EDITOR_VAULT_GONE),
      offered: [...vaultSelect().options].map((o) => o.value).includes(old),
      saveEnabled: save !== undefined && !save.disabled,
      sent: server.writes.slice(before),
    }).toEqual({ editorOpen: true, line: true, offered: false, saveEnabled: false, sent: [] });
  });

  it("two removals in a row, with a yes between them: the editor closes each time", async () => {
    const { alice, bob, old, screen } = await opened();
    await openEditor(screen, GATE.name);
    await removeBob(alice, old);
    await alice.store.addVaultMember(old, BOB, "writer");
    await alice.store.sync();
    await screen.bell();
    expect(shown(screen)).toEqual({ fieldsLeft: [], editorOpen: false, closedLine: [ITEM_CLOSED_EDITING] });
    expect((await bob.shared.answer(bob.shared.pendingAsks().find((a) => a.vaultId === old)!, true)).kind).toBe("adopted");
    await screen.bell();
    expect(listed(bob.store, old)).toBe(true);
    await openEditor(screen, GATE.name);
    await removeBob(alice, old);
    await screen.bell();
    expect(shown(screen)).toEqual({ fieldsLeft: [], editorOpen: false, closedLine: [ITEM_CLOSED_EDITING] });
  });

  it("a removal, then the person's yes to a new add, with the editor closed in between: nothing of the old editor comes back by itself", async () => {
    const { alice, bob, old, screen } = await opened();
    await openEditor(screen, GATE.name);
    await type(editorInput(screen, "Notes"), "typed before the removal, never saved");
    await removeBob(alice, old);
    await alice.store.addVaultMember(old, BOB, "writer");
    await alice.store.sync();
    await screen.bell();
    expect((await bob.shared.answer(bob.shared.pendingAsks().find((a) => a.vaultId === old)!, true)).kind).toBe("adopted");
    await screen.bell();
    // The vault is back after the yes, so its items are listed again; the editor is not, and the typing is not.
    expect({ listed: listed(bob.store, old), editorOpen: screen.page.querySelector("form.sheet") !== null, typedLeft: screen.html().includes("never saved"), notes: screen.html().includes(GATE.notes!) }).toEqual({
      listed: true,
      editorOpen: false,
      typedLeft: false,
      notes: false,
    });
  });
});

describe("a second tab carries the removal out while this tab only renders again (no event, no sync of its own)", () => {
  it("the list, when the person types into the search", async () => {
    const f = await opened({ cache: true });
    await removeBob(f.alice, f.old);
    await anotherTabSyncs(f);
    await type(inputLabelled(f.screen, "Search vault"), "Garden");
    expect(leftIn(f.screen)).toEqual([]);
  });

  it("the open item, when the person presses Show on its password", async () => {
    const f = await opened({ cache: true });
    await openItem(f.screen, GATE.name);
    await removeBob(f.alice, f.old);
    await anotherTabSyncs(f);
    await click(buttonNamed(f.screen.page, "Show"));
    expect(shown(f.screen)).toEqual({ fieldsLeft: [], editorOpen: false, closedLine: [ITEM_CLOSED] });
  });

  it("the open editor, when the person types into it", async () => {
    const f = await opened({ cache: true });
    await openEditor(f.screen, GATE.name);
    await removeBob(f.alice, f.old);
    await anotherTabSyncs(f);
    await type(editorInput(f.screen, "Notes"), "typed after the other tab moved the log");
    expect({ ...shown(f.screen), typedLeft: f.screen.html().includes("other tab moved") }).toEqual({ fieldsLeft: [], editorOpen: false, closedLine: [ITEM_CLOSED_EDITING_NOT_KEPT], typedLeft: false });
  });

  it("Health, when the person switches its tabs, and its breach scan asks for no range of the vault's passwords", async () => {
    const f = await opened({ cache: true });
    await click(buttonNamed(f.screen.page, "Health"));
    await removeBob(f.alice, f.old);
    await anotherTabSyncs(f);
    const tabs: Record<string, string[]> = {};
    for (const label of ["Duplicates", "Staleness", "Passwords"]) {
      const b = [...f.screen.page.querySelectorAll("button[aria-pressed]")].find((x) => x.textContent?.startsWith(label));
      await click(b!);
      tabs[label] = leftIn(f.screen);
    }
    const scan = [...f.screen.page.querySelectorAll("button")].find((b) => b.textContent?.includes("for breaches"));
    if (scan && !scan.disabled) await click(scan);
    await f.screen.bell().catch(() => {});
    const { hibpPrefix, hibpSha1UpperHex } = await import("../crypto/hibp");
    const removedPrefixes = [hibpPrefix(await hibpSha1UpperHex(GATE.login!.password!)), hibpPrefix(await hibpSha1UpperHex("pw1"))];
    expect({ tabs, asked: f.screen.ranges.filter((r) => removedPrefixes.includes(r)) }).toEqual({ tabs: { Duplicates: [], Staleness: [], Passwords: [] }, asked: [] });
  });
});
