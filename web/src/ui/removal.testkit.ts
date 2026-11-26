import { expect } from "vitest";
import { toB64, utf8 } from "../crypto/bytes";
import { randomBytes } from "../crypto/provider";
import type { ItemDoc } from "../api/types";
import { BOB, browser, type Browser, family, freshDb, listed } from "../vault/fakesyncserver.testkit";
import { openVaultCache } from "../vault/idbcache";
import { ITEM_CLOSED, ITEM_CLOSED_EDITING, ITEM_CLOSED_EDITING_NOT_KEPT } from "./copy";
import { buttonNamed, click, type } from "./dom.testkit";
import { drawVault, type DrawnVault } from "./vaultscreen.testkit";

/**
 * What a test of a removal from a shared vault needs around the vault screen drawn over a real store
 * (`vaultscreen.testkit.ts` over `fakesyncserver.testkit.ts`: the real store, the real log layer): the removal is always
 * a real one (the owner's real `removeVaultMember`), carried out by a real sync of this browser or by another tab's real
 * store. The only stand-ins these helpers offer are the timing of one call of the fake transport ([held]) and a record of
 * the files the page hands to the browser ([filesWritten]).
 */

/** An item of the shared vault whose every field can be searched for in the page. */
export const GATE: ItemDoc = {
  type: "login",
  name: "Garden gate",
  login: { username: "gate-keeper-41", password: "Tr0ub4dor-pw-93", uris: ["https://gate.example.org"] },
  notes: "spare key under the third stone",
};
export const GATE_FIELDS = ["Garden gate", "gate-keeper-41", "Tr0ub4dor-pw-93", "gate.example.org", "spare key under the third stone"];
/** The fields of [GATE] still somewhere in the page: its text, its markup, or the value of a field. */
export const leftIn = (screen: DrawnVault): string[] => GATE_FIELDS.filter((f) => screen.html().includes(f));
/** The attachment's id, as the item names it. */
export const PLAN_ID = "9f0c5e3a-6c1b-4b7e-9a51-2d1e8f4c7a10";

/**
 * Alice owns "Family" with "bank" and [GATE]; bob, a writer of it, has the vault screen open over an offline copy.
 * [attachment]: GATE carries one file, "gate-plan.pdf" (uploaded with it unless [fileMissing]: then the item names a file
 * the server does not hold).
 */
export async function opened(opts: { attachment?: boolean; fileMissing?: boolean; draw?: boolean } = {}) {
  freshDb();
  const { server, alice, bob, old } = await family(await openVaultCache(BOB));
  const data = utf8("the gate's plan, page 1");
  const files = opts.attachment && !opts.fileMissing ? [{ id: PLAN_ID, data }] : [];
  const doc: ItemDoc = opts.attachment ? { ...GATE, attachments: [{ id: PLAN_ID, name: "gate-plan.pdf", size: data.length, fileKey: toB64(randomBytes(32)) }] } : GATE;
  await alice.store.save(null, doc, files, undefined, old);
  await bob.store.sync();
  const gate = bob.store.list().find((i) => i.doc.name === GATE.name)!;
  expect(gate.vaultId).toBe(old);
  const screen = opts.draw === false ? (null as unknown as DrawnVault) : await drawVault(bob);
  return { server, alice, bob, old, gate, screen };
}
export type Opened = Awaited<ReturnType<typeof opened>>;

/** The owner removes bob from [vaultId] (a real entry of the vault's log). */
export const removeBob = async (alice: Browser, vaultId: string): Promise<void> => {
  await alice.store.removeVaultMember(vaultId, BOB);
  await alice.store.sync();
};

/** Tab B of bob's browser profile (the same records at rest, its own key ring) syncs and carries the removal out. */
export async function tabBCarriesItOut(f: Opened): Promise<Browser> {
  const tabB = await browser(f.server, f.bob.person, f.bob.contacts, { cache: await openVaultCache(BOB), again: f.bob.profile });
  expect(listed(tabB.store, f.old)).toBe(false);
  return tabB;
}

export const winOf = (screen: DrawnVault) => screen.page.ownerDocument.defaultView as unknown as Window & typeof globalThis;
/** The store's item wire (the fake server's routes for bob), so that a test can hold the timing of one call. */
export const wireOf = (b: Browser) => (b.store as unknown as { wire: Record<string, (...a: never[]) => Promise<unknown>> }).wire;

/** A gate a test holds a call behind and opens when it chooses: the timing of the call, nothing else. */
export function held(): { wait: Promise<void>; open: () => void } {
  let open = () => {};
  const wait = new Promise<void>((r) => (open = r));
  return { wait, open };
}

/** Opens the item named [name] from the list. */
export async function openItem(screen: DrawnVault, name: string): Promise<void> {
  const row = [...screen.page.querySelectorAll("button.item")].find((b) => b.querySelector(".name")?.textContent === name);
  expect(row, `${name} in ${screen.text().slice(0, 400)}`).toBeDefined();
  await click(row!);
}

/** The editor's field labelled [label] (its input follows the label inside the Field). */
export function editorInput(screen: DrawnVault, label: string): HTMLInputElement {
  const lab = [...screen.page.querySelectorAll("form.sheet label")].find((l) => l.textContent?.startsWith(label));
  const input = lab?.parentElement?.querySelector("input, textarea");
  if (!input) throw new Error(`no field ${label}`);
  return input as HTMLInputElement;
}

/** The lines the screen shows about an item it closed. */
export const closedLines = (screen: DrawnVault) => [ITEM_CLOSED, ITEM_CLOSED_EDITING, ITEM_CLOSED_EDITING_NOT_KEPT].filter((l) => screen.text().includes(l));

/** Opens the backup panel and types [pw] twice. */
export async function backupPanel(screen: DrawnVault, pw: string): Promise<void> {
  await click([...screen.page.querySelectorAll("button")].find((b) => b.getAttribute("aria-label") === "Export")!);
  await click(buttonNamed(screen.page, "Back up vault…"));
  await screen.bell();
  const inputs = [...screen.page.querySelectorAll('input[type="password"]')] as HTMLInputElement[];
  await type(inputs[0]!, pw);
  await type(inputs[1]!, pw);
}

/** Every Blob the page hands to URL.createObjectURL while [fn] runs (a file written by the page). */
export async function filesWritten(screen: DrawnVault, fn: () => Promise<void>): Promise<Blob[]> {
  const written: Blob[] = [];
  const url = globalThis.URL as unknown as { createObjectURL: (b: Blob) => string; revokeObjectURL: (u: string) => void };
  const real = url.createObjectURL;
  const realRevoke = url.revokeObjectURL;
  url.createObjectURL = (b: Blob) => {
    written.push(b);
    return "blob:written";
  };
  url.revokeObjectURL = () => {};
  const g = globalThis as { Event: typeof Event };
  const nodeEvent = g.Event;
  g.Event = winOf(screen).Event;
  try {
    await fn();
  } finally {
    url.createObjectURL = real;
    url.revokeObjectURL = realRevoke;
    g.Event = nodeEvent;
  }
  return written;
}
