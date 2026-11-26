// "Recently removed" while a kept copy is closed for an invitation (decided on 22 and 23 November 2026). A person
// removed from a shared vault keeps a sealed copy of it on this browser; added again, the browser shows an invitation,
// and while its person can answer it the copy is closed. Its row then says so, in the sentence the phone and the
// computer show, filled with the vault's name as the invitation names it and the day the copy leaves this browser; it
// offers no copy-out and does not say that the key is gone, and "Remove from this device" stays. In every other state
// the row is as before. Drawn over a stub of the store, and over the real store, session and log layer against a fake
// server.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { initSodium } from "../crypto/sodium";
import { BOB, browser, type Browser, family, freshDb, heldOf } from "../vault/fakesyncserver.testkit";
import { openVaultCache } from "../vault/idbcache";
import type { SharedLogSession } from "../vault/sharedlogs";
import type { VaultStore } from "../vault/store";
import * as C from "./copy";
import { fill, HELD_COPY, HELD_NO_KEY, REMOVE_FROM_THIS_DEVICE } from "./copy";
import { fmtDay } from "./format";
import { RecentlyRemoved } from "./Sharing";
import { SharedPrompts } from "./SharedPrompts";

const DAY = 86_400_000;
const V = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const W = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

/** The owner's sentence as the web holds it; read through the module so that a missing key reads as a failed case. */
const addedAgainText = (): string => (C as Record<string, unknown>).HELD_ADDED_AGAIN as string;

/** A part of the owner's sentence that no other line of the list holds. */
const UNTIL = "Until you accept";

/** [s] as the drawn markup holds a text node: the five characters React escapes. */
const asText = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");

/** The closed row's line, filled with [name] and the day [expungeAt], as the markup holds it. */
const closedLine = (name: string, expungeAt: number): string => asText(fill(addedAgainText(), name, fmtDay(expungeAt)));

type Row = { vaultId: string; name: string; reason: string; verified: boolean; byMe: boolean; expungeAt: number; itemCount: number; canCopyOut: boolean; addedAgain: boolean; invitationName?: string };

const expungeAt = Date.UTC(2026, 11, 13, 12);

/** A held row of an access removal, open, with one item and its copy-out offered; [r] changes it. */
const row = (r: Partial<Row> = {}): Row => ({ vaultId: V, name: "(vault)", reason: "removed", verified: true, byMe: false, expungeAt, itemCount: 1, canCopyOut: true, addedAgain: false, ...r });

/** A stub store whose "Recently removed" holds [rows]. */
const storeWith = (...rows: Row[]): VaultStore => ({ heldVaults: () => rows }) as unknown as VaultStore;

/** "Recently removed" drawn over [store]. */
const draw = (store: VaultStore): string => renderToStaticMarkup(createElement(RecentlyRemoved, { store, hide: [] }));

/** The drawn rows of [html], one string each, in order. */
const rowsIn = (html: string): string[] => html.split('<div class="field"').slice(1);

/** The ordinary line of an access removal, as drawn. */
const removedLine = (day: number): string => asText(`access removed · kept until ${fmtDay(day)}`);

/** How the invitation above the vault list draws [vaultName] inside its SHARE_ASK line. */
function askDraws(vaultName: string): string {
  const shared = {
    contacts: { oneTapListDue: () => false, list: () => [], prompts: () => [] },
    pendingAsks: () => [{ kind: "ask", vaultId: V, owner: A, ownerLabel: "Alice", vaultName, addSeq: 1, waiting: 0 }],
    undecided: () => [],
    outcome: () => null,
  } as unknown as SharedLogSession;
  const html = renderToStaticMarkup(createElement(SharedPrompts, { shared, onChanged: () => {} }));
  const lead = "Alice wants to share “";
  const start = html.indexOf(lead);
  expect(start, html).toBeGreaterThanOrEqual(0);
  const from = start + lead.length;
  return html.slice(from, html.indexOf("” with you.", from));
}

describe("the closed row of \"Recently removed\" says so, over a stub of the store", () => {
  it("closed for an invitation: the row holds the owner's sentence with the invitation's name and the copy's day, no copy-out, no line that the key is gone, and \"Remove from this device\"", () => {
    // The same rows open first: the copy-out and the line that the key is gone are drawn there.
    const openWithKey = draw(storeWith(row({ canCopyOut: true })));
    const openNoKey = draw(storeWith(row({ canCopyOut: false })));
    expect({ copy: openWithKey.includes(HELD_COPY), noKey: openNoKey.includes(asText(HELD_NO_KEY)) }).toEqual({ copy: true, noKey: true });
    for (const canCopyOut of [false, true]) {
      const html = draw(storeWith(row({ addedAgain: true, canCopyOut, invitationName: "Family" })));
      expect(html).toContain(`>${closedLine("Family", expungeAt)}</div>`);
      expect({ copy: html.includes(HELD_COPY), noKey: html.includes(asText(HELD_NO_KEY)), ordinary: html.includes(removedLine(expungeAt)), remove: html.includes(REMOVE_FROM_THIS_DEVICE) }).toEqual({ copy: false, noKey: false, ordinary: false, remove: true });
    }
  });

  it("every other row is as it was: its ordinary line, and the copy-out or the line that the key is gone by canCopyOut (green when written)", () => {
    for (const [r, line] of [
      [row({ reason: "removed", verified: true }), removedLine(expungeAt)],
      [row({ reason: "left", verified: true }), asText(`you left · kept until ${fmtDay(expungeAt)}`)],
      [row({ reason: "removed", verified: false }), asText(`unverified removal · kept until ${fmtDay(expungeAt)}`)],
      [row({ reason: "deleted", verified: true }), asText(`deleted by its owner · kept sealed until ${fmtDay(expungeAt)}`)],
    ] as const) {
      const withKey = draw(storeWith({ ...r, canCopyOut: true }));
      const noKey = draw(storeWith({ ...r, canCopyOut: false }));
      expect({ line: withKey.includes(line), copy: withKey.includes(HELD_COPY), noKey: withKey.includes(asText(HELD_NO_KEY)) }, r.reason).toEqual({ line: true, copy: true, noKey: false });
      expect({ line: noKey.includes(line), copy: noKey.includes(HELD_COPY), noKey: noKey.includes(asText(HELD_NO_KEY)) }, r.reason).toEqual({ line: true, copy: false, noKey: true });
      expect(withKey.includes(UNTIL), r.reason).toBe(false);
    }
  });

  it("two rows, one closed and one open: each draws its own state, and the closed one's sentence carries its own name and day", () => {
    const later = expungeAt + 3 * DAY;
    const html = draw(storeWith(row({ vaultId: V, name: "Family", expungeAt, canCopyOut: true }), row({ vaultId: W, name: "(vault)", expungeAt: later, addedAgain: true, canCopyOut: false, invitationName: "Garden" })));
    const [open, closed] = rowsIn(html);
    expect({ line: open!.includes(removedLine(expungeAt)), copy: open!.includes(HELD_COPY), sentence: open!.includes(UNTIL) }).toEqual({ line: true, copy: true, sentence: false });
    expect(closed).toContain(`>${closedLine("Garden", later)}</div>`);
    expect(fmtDay(expungeAt)).not.toBe(fmtDay(later));
    expect({ otherDay: closed!.includes(fmtDay(expungeAt)), otherName: closed!.includes("Family"), copy: closed!.includes(HELD_COPY), noKey: closed!.includes(asText(HELD_NO_KEY)), remove: closed!.includes(REMOVE_FROM_THIS_DEVICE) }).toEqual({ otherDay: false, otherName: false, copy: false, noKey: false, remove: true });
  });

  it("a name that tries to break the line is drawn as one line of text, as the invitation's SHARE_ASK draws it, never as markup", () => {
    for (const name of ["Fam\nily", "Fam\u200Fily", "Fam\u202Eily", "<b>x</b>", "N".repeat(300)]) {
      const html = draw(storeWith(row({ addedAgain: true, canCopyOut: false, invitationName: name })));
      // The invitation above the list draws the same name as this text node holds it.
      expect(askDraws(name), JSON.stringify(name)).toBe(asText(name));
      // One text node in one element: the whole sentence between the line's opening and closing tags.
      expect(html, JSON.stringify(name)).toContain(`>${closedLine(name, expungeAt)}</div>`);
      expect({ b: html.includes("<b>"), br: html.includes("<br") }).toEqual({ b: false, br: false });
    }
    expect(askDraws("<b>x</b>")).toBe("&lt;b&gt;x&lt;/b&gt;");
    // A name that reads like a placeholder or a replacement pattern is drawn as typed: the sentence is filled in one pass.
    const typed = draw(storeWith(row({ addedAgain: true, canCopyOut: false, invitationName: "$& {0} {1}" })));
    expect(typed).toContain(`>${closedLine("$& {0} {1}", expungeAt)}</div>`);
    expect(typed).toContain("“$&amp; {0} {1}”");
  });

  it("an invitation without a name: the sentence is filled as SHARE_ASK is filled for it", () => {
    expect(askDraws("")).toBe("");
    for (const invitationName of ["", undefined]) {
      const html = draw(storeWith(row({ addedAgain: true, canCopyOut: false, invitationName })));
      expect(html).toContain(`>${closedLine("", expungeAt)}</div>`);
      expect(html).not.toContain("(vault)” again");
    }
  });
});

describe("the owner's sentence is one sentence in both kinds of app", () => {
  it("the web's HELD_ADDED_AGAIN is the shared code's, letter for letter", () => {
    const core = readFileSync(fileURLToPath(new URL("../../../core/src/commonMain/kotlin/io/silencelen/andvari/core/app/AppCopy.kt", import.meta.url)), "utf8");
    const kotlin = /\bHELD_ADDED_AGAIN\("((?:[^"\\]|\\.)*)"\)/.exec(core)?.[1];
    expect(kotlin).toBe("You were added to “{0}” again. Until you accept, this device can't open the copy it kept. Accept before {1} to get it back. On that day it goes from this device.");
    expect(addedAgainText()).toBe(kotlin);
  });
});

/** Alice removes bob from [vaultId]; his browser learns it and keeps the vault's copy, open. */
async function removeBob(alice: Browser, bob: Browser, vaultId: string): Promise<void> {
  await alice.store.removeVaultMember(vaultId, BOB);
  await bob.store.sync();
  expect(heldOf(bob)).toEqual([vaultId]);
}

/** Alice adds bob to [vaultId] again and his browser pulls the answer that brings the grant back: asked. */
async function addBobAgain(alice: Browser, bob: Browser, vaultId: string): Promise<void> {
  await alice.store.addVaultMember(vaultId, BOB, "writer");
  await bob.store.sync();
  expect(asksOf(bob, vaultId)).toHaveLength(1);
}

const asksOf = (who: Browser, vaultId: string) => who.shared.pendingAsks().filter((a) => a.vaultId === vaultId);
const rowOf = (who: Browser, vaultId: string) => who.store.heldVaults().find((h) => h.vaultId === vaultId);

describe("the closed row through the real store", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("removed, then added again with an invitation the person can answer: the drawn row is the closed one; after a decline, the open one with its ordinary line and the copy-out", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await removeBob(alice, bob, old);
    const day = rowOf(bob, old)!.expungeAt;
    const removed = draw(bob.store);
    expect({ line: removed.includes(removedLine(day)), copy: removed.includes(HELD_COPY), sentence: removed.includes(UNTIL) }).toEqual({ line: true, copy: true, sentence: false });
    await addBobAgain(alice, bob, old);
    const closed = draw(bob.store);
    expect(closed).toContain(`>${closedLine("Family", day)}</div>`);
    expect({ copy: closed.includes(HELD_COPY), noKey: closed.includes(asText(HELD_NO_KEY)), ordinary: closed.includes(removedLine(day)), remove: closed.includes(REMOVE_FROM_THIS_DEVICE) }).toEqual({ copy: false, noKey: false, ordinary: false, remove: true });
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, false)).kind).toBe("declined");
    const declined = draw(bob.store);
    expect({ line: declined.includes(removedLine(day)), copy: declined.includes(HELD_COPY), noKey: declined.includes(asText(HELD_NO_KEY)), sentence: declined.includes(UNTIL) }).toEqual({ line: true, copy: true, noKey: false, sentence: false });
  });

  it("added again and accepted: the vault comes back and the list has no row", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await removeBob(alice, bob, old);
    await addBobAgain(alice, bob, old);
    expect(draw(bob.store)).toContain(UNTIL);
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, true)).kind).toBe("adopted");
    await bob.store.sync();
    expect({ held: heldOf(bob), html: draw(bob.store) }).toEqual({ held: [], html: "" });
  });

  it("the row carries the invitation's name, not its own: renamed while bob was out, the sentence names the vault as the invitation does; open, the row carries no such name", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await removeBob(alice, bob, old);
    const named = (who: Browser) => {
      const r = rowOf(who, old)!;
      return { name: r.name, addedAgain: r.addedAgain, invitationName: r.invitationName };
    };
    expect(named(bob)).toEqual({ name: "Family", addedAgain: false, invitationName: undefined });
    await alice.store.renameVault(old, "Garden");
    await addBobAgain(alice, bob, old);
    const day = rowOf(bob, old)!.expungeAt;
    expect({ ask: asksOf(bob, old)[0]!.vaultName, row: named(bob) }).toEqual({ ask: "Garden", row: { name: "Family", addedAgain: true, invitationName: "Garden" } });
    const html = draw(bob.store);
    expect(html).toContain(`>${closedLine("Garden", day)}</div>`);
    expect(html).not.toContain(closedLine("Family", day));
    expect((await bob.shared.answer(asksOf(bob, old)[0]!, false)).kind).toBe("declined");
    expect(named(bob)).toEqual({ name: "Family", addedAgain: false, invitationName: undefined });
  });

  it("open again after a decline that the server refused to record, and asked again at the next sync: the open row carries no invitation's name and is drawn as an open row", async () => {
    freshDb();
    const { alice, bob, old } = await family(await openVaultCache(BOB));
    await removeBob(alice, bob, old);
    await addBobAgain(alice, bob, old);
    const wire = (bob.store as unknown as { wire: Record<string, (...a: unknown[]) => Promise<unknown>> }).wire;
    wire.putAccountState = () => Promise.reject(new ApiError(413, "account_state_full", "full"));
    wire.appendLog = () => Promise.reject(new ApiError(403, "forbidden", "refused"));
    // A decline whose record the server refuses may throw on; the copy opens either way.
    await bob.shared.answer(asksOf(bob, old)[0]!, false).catch(() => undefined);
    await bob.store.sync();
    const r = rowOf(bob, old)!;
    expect({ asks: asksOf(bob, old).length, outcome: bob.shared.outcome(old)?.kind, addedAgain: r.addedAgain, invitationName: r.invitationName }).toEqual({
      asks: 1,
      outcome: "ask",
      addedAgain: false,
      invitationName: undefined,
    });
    const html = draw(bob.store);
    expect(html).toContain(removedLine(r.expungeAt));
    expect(html).toContain(HELD_COPY);
    expect(html).not.toContain(UNTIL);
  });

  it("after a reload the row's own name is \"(vault)\": the sentence still carries the invitation's name", async () => {
    freshDb();
    const { server, alice, bob, old } = await family(await openVaultCache(BOB));
    await removeBob(alice, bob, old);
    await addBobAgain(alice, bob, old);
    const again = await browser(server, bob.person, bob.contacts, { cache: await openVaultCache(BOB), again: bob.profile });
    expect(asksOf(again, old)).toHaveLength(1);
    const r = rowOf(again, old)!;
    expect({ name: r.name, addedAgain: r.addedAgain, invitationName: r.invitationName, ask: asksOf(again, old)[0]!.vaultName }).toEqual({ name: "(vault)", addedAgain: true, invitationName: "Family", ask: "Family" });
    const html = draw(again.store);
    expect(html).toContain(`>${closedLine("Family", r.expungeAt)}</div>`);
    expect(html).not.toContain(closedLine("(vault)", r.expungeAt));
  });
});
