import "fake-indexeddb/auto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { browserStorages } from "./forget-earlier.testkit";
import { at, bootTab, fakeServer, keepSession, U } from "./refresh.testkit";
import { loadSession, SESSION_STORAGE_KEY, tokensKeptAcrossLock } from "./session";
import { dropHeldPair, storageVerdict } from "./tabsession";

/**
 * With the offline copy on every tab holds the one pair the browser keeps. Where another tab's refresh had no try left and
 * the session ended there, a tab on that session's unlock card lets go of the pair it still held in memory (App applies
 * [storageVerdict]'s `endedElsewhere` with [dropHeldPair]): nothing of it can leave from that tab afterwards, a sign-out
 * on its card included.
 */
describe("a tab on the unlock card when another tab ended the session unconfirmed", () => {
  let st: ReturnType<typeof browserStorages>;
  beforeEach(() => {
    st = browserStorages();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  });
  afterEach(() => {
    vi.useRealTimers();
    st.restore();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("drops the pair from its memory; its sign-out then carries no token at all", async () => {
    keepSession(true);
    const srv = fakeServer();
    srv.s.fates = ["lost"];
    at(srv, 1_000_000);
    const a = bootTab();
    const card = bootTab(); // a tab on the unlock card: the pair is in its client's memory
    await a.sync();
    const before = st.local.map.get(SESSION_STORAGE_KEY) ?? null;
    at(srv, 1_070_000);
    await a.sync();
    expect(a.ends).toEqual(["not_confirmed"]);
    const v = storageVerdict(
      { key: SESSION_STORAGE_KEY, oldValue: before, newValue: st.local.map.get(SESSION_STORAGE_KEY) ?? null },
      { activeUserId: U, have: card.client.getTokens(), after: loadSession(), keptAcrossLock: tokensKeptAcrossLock },
    );
    expect(v.kind).toBe("endedElsewhere");
    dropHeldPair(card.client);
    expect(card.client.getTokens()).toBeNull();
    await card.client.logout();
    expect(srv.s.logouts, "no bearer").toEqual([""]);
    expect(srv.s.refreshes).toEqual(["r0"]);
    expect(srv.s.reuse).toBe(0);
  });
});
