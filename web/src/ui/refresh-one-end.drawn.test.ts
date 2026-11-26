import "fake-indexeddb/auto";
import { createElement } from "react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { SESSION_ENDED_HELD, SESSION_NOT_CONFIRMED } from "./copy";
import { closePage, draw, type Drawn, openPage } from "./dom.testkit";
import { browserStorages, ORIGIN, pinnedStore } from "./forget-earlier.testkit";
import { at, bootTab, fakeServer, keepSession, U } from "./refresh.testkit";
import { loadSession, SESSION_STORAGE_KEY, tokensKeptAcrossLock } from "./session";
import { endSessionByServer, heldEndNotice, keptChangesLine, sessionEndLine } from "./sessionend";
import { dropHeldPair, storageVerdict } from "./tabsession";
import type { WebContext } from "./opensession";
import { Welcome } from "./Welcome";

/**
 * Drawn: a refresh whose answer never came had no try left in tab A (the offline copy on, so tab B holds the same session).
 * Exactly one end is on the screen in each tab, the browser's own: in A, the card App lands on (endByServer: the record
 * kept without its pair, the notice heldEndNotice makes); in B, the unlock card it was on when the session every tab
 * shares went (App's `endedElsewhere`: the pair dropped from its memory, the card given the record). Neither says that
 * the server ended the session, that it expired, or that it was revoked.
 */
const occurrences = (text: string, line: string): number => text.split(line).length - 1;

describe("one end on the screen, the browser's own, drawn in two tabs", () => {
  let st: ReturnType<typeof browserStorages>;
  let drawn: Drawn[] = [];
  beforeAll(async () => {
    await initSodium();
    openPage();
  });
  afterAll(async () => {
    await closePage();
  });
  beforeEach(() => {
    st = browserStorages(); // real timers: tab A's own one more try was set and then cleared by its end
  });
  afterEach(async () => {
    for (const d of drawn) await d.unmount();
    drawn = [];
    st.restore();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("tab A, which met it, and tab B, on the unlock card", async () => {
    keepSession(true);
    const srv = fakeServer();
    srv.s.fates = ["lost"];
    at(srv, 1_000_000);
    const a = bootTab();
    const b = bootTab();
    await a.sync();
    const before = st.local.map.get(SESSION_STORAGE_KEY) ?? null;
    at(srv, 1_070_000);
    await a.sync();
    expect(a.ends).toEqual(["not_confirmed"]);

    // Tab A: App's endByServer for kind "unconfirmed".
    const endA = endSessionByServer(a.client, "unconfirmed");
    if (endA.kind !== "kept") throw new Error("the offline copy keeps the record");
    const noticeA = heldEndNotice("unconfirmed", undefined, sessionEndLine("unconfirmed"), keptChangesLine(0));
    // Tab B: App's storage listener.
    const v = storageVerdict(
      { key: SESSION_STORAGE_KEY, oldValue: before, newValue: st.local.map.get(SESSION_STORAGE_KEY) ?? null },
      { activeUserId: U, have: b.client.getTokens(), after: loadSession(), keptAcrossLock: tokensKeptAcrossLock },
    );
    if (v.kind !== "endedElsewhere") throw new Error(`expected endedElsewhere, got ${v.kind}`);
    dropHeldPair(b.client);

    const pins = await pinnedStore();
    const card = async (client: typeof a.client, session: typeof endA.session, notice: string | undefined) => {
      const ctx = { client, wire: new WireApi(client), pins, origin: ORIGIN, storage: memoryStorage() } as unknown as WebContext;
      const d = await draw(
        createElement(Welcome, { ctx, policy: null, policyError: false, onRetryPolicy: async () => {}, mode: { unlock: session }, notice: notice || undefined, onReady: () => {}, onForget: () => {} }),
      );
      drawn.push(d);
      await vi.waitFor(() => expect(d.page.textContent).toContain(SESSION_NOT_CONFIRMED), { timeout: 5_000, interval: 20 });
      return d.page.textContent ?? "";
    };
    for (const text of [await card(a.client, endA.session, noticeA), await card(b.client, v.meta, undefined)]) {
      expect(occurrences(text, SESSION_NOT_CONFIRMED), "the browser's own end, once").toBe(1);
      expect(text).not.toContain(SESSION_ENDED_HELD);
      expect(text).not.toContain(sessionEndLine("expired"));
      expect(text).not.toContain(sessionEndLine("revoked"));
    }
    expect(b.client.getTokens(), "tab B holds no pair").toBeNull();
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
  });
});
