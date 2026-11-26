import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AccountKeys, KdfParams, Mutation } from "../api/types";
import { openVaultCache, vaultDbName } from "../vault/idbcache";
import { fill, SIGN_IN_ENDED_KEPT, UNSENT_LOST_MANY, UNSENT_LOST_ONE, UNSENT_UNKNOWN } from "./copy";
import { loadSession, makeClient, saveSession, SESSION_STORAGE_KEY, setOfflineCopyEnabled, TAB_TOKENS_KEY, unsentChangeCount } from "./session";
import { clientEndLine, endByClientDecision, endedByServer } from "./sessionend";

/**
 * Design §4.4 (decided on 2026-11-17): a sign-in that this browser ends by itself (the recovery kit was not confirmed in
 * time; the account turned out to be the operator's, which the web does not take) says the number of unsent changes
 * BEFORE anything is deleted, with the same two steps as every other way out. It used to go straight through the
 * sign-out, which deleted the copy and its queue and only then said how many changes had gone.
 */

function fakeStorage(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, v),
  } as Storage;
}

const g = globalThis as { indexedDB?: IDBFactory };
const UID = "22222222-2222-4222-8222-222222222222";
const EMAIL = "bea@example.org";
const PAIR = { accessToken: "acc-2", refreshToken: "ref-2" };
const NOTICE = "The browser's own reason.";
const kdf = (): KdfParams => ({ v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 });
const keys = (): AccountKeys => ({ kdfSalt: "c2FsdA", kdfParams: kdf(), wrappedUvk: "wrap", encryptedIdentitySeed: "seed", identityPub: "pub", escrowFingerprint: "fp" });
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });

async function dbExists(userId: string): Promise<boolean> {
  const list = await (g.indexedDB as unknown as { databases: () => Promise<{ name?: string }[]> }).databases();
  return list.some((d) => d.name === vaultDbName(userId));
}

/** A browser holding the account: the session with its pair, the offline copy with [queued] changes not sent. */
async function held(queued: number) {
  await setOfflineCopyEnabled(UID, true);
  saveSession({ baseUrl: "", userId: UID, personalVaultId: "", email: EMAIL, tokens: PAIR });
  const cache = await openVaultCache(UID);
  await cache.setAccountKeys(keys());
  for (let i = 0; i < queued; i++) await cache.enqueue(mut(`m${i}`));
  cache.close();
  return makeClient(loadSession(), "");
}

beforeEach(() => {
  g.indexedDB = new FakeIDBFactory() as unknown as IDBFactory;
  vi.stubGlobal("localStorage", fakeStorage());
  vi.stubGlobal("sessionStorage", fakeStorage());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a sign-in this browser ends by itself, over a copy with changes not sent", () => {
  it("keeps the copy, its queue and the record; no pair stays; the line says the reason, the number and what stays", async () => {
    const client = await held(2);
    const c = await openVaultCache(UID);
    await c.putHeld({ vault: { vaultId: "v9" }, grant: null, items: [], reason: "deleted", verified: true, parked: [mut("p1")], expungeAt: 999 } as never);
    c.close();
    const unsent = await unsentChangeCount(UID);
    expect(unsent).toBe(3);

    const end = endByClientDecision(client, NOTICE, unsent);
    expect(end.kind).toBe("kept");
    if (end.kind !== "kept") return;
    // The number comes first, before anything is deleted: the person reads it on the card they land on.
    expect(end.line).toBe(`${NOTICE} ${fill(UNSENT_LOST_MANY, "3")} ${SIGN_IN_ENDED_KEPT}`);
    // No session stays: the pair is gone from the client, the persisted record and the tab's slot.
    expect(client.getTokens()).toBeNull();
    expect(JSON.parse(localStorage.getItem(SESSION_STORAGE_KEY)!).tokens).toBeNull();
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toBeNull();
    // What the browser keeps meanwhile: the record (so the unlock card and its own Sign out are there), the copy and
    // every change not sent.
    expect(loadSession()).toMatchObject({ userId: UID, email: EMAIL, tokens: null });
    expect(end.session).toEqual(loadSession());
    expect(endedByServer(end.session)).toBe(true); // the card that offers the sign-in, the read-only copy and Sign out
    expect(await dbExists(UID)).toBe(true);
    expect(await unsentChangeCount(UID)).toBe(3);
  });

  it("one change is said as one", async () => {
    const client = await held(1);
    const end = endByClientDecision(client, NOTICE, await unsentChangeCount(UID));
    expect(end.kind === "kept" && end.line).toBe(`${NOTICE} ${UNSENT_LOST_ONE} ${SIGN_IN_ENDED_KEPT}`);
  });

  it("when the browser cannot tell, it says so and keeps the copy: never said as none", async () => {
    const client = await held(0);
    const end = endByClientDecision(client, NOTICE, null);
    expect(end.kind).toBe("kept");
    expect(end.kind === "kept" && end.line).toBe(`${NOTICE} ${UNSENT_UNKNOWN} ${SIGN_IN_ENDED_KEPT}`);
    expect(client.getTokens()).toBeNull();
    expect(await dbExists(UID)).toBe(true);
  });

  it("with nothing unsent it is the sign-out it always was, and this step itself changes nothing", async () => {
    const client = await held(0);
    expect(await unsentChangeCount(UID)).toBe(0);
    expect(endByClientDecision(client, NOTICE, 0)).toEqual({ kind: "sign_out" });
    expect(client.getTokens()).toEqual(PAIR);
    expect(loadSession()).toMatchObject({ userId: UID, tokens: PAIR });
  });

  it("with no session record there is nothing of the account's to keep: the sign-out", () => {
    expect(endByClientDecision(null, NOTICE, 4)).toEqual({ kind: "sign_out" });
    expect(clientEndLine(NOTICE, 4)).toBe(`${NOTICE} ${fill(UNSENT_LOST_MANY, "4")} ${SIGN_IN_ENDED_KEPT}`);
  });
});

describe("the wiring: every sign-in or session the browser ends by itself goes through the count", () => {
  const read = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8");
  const app = read("./App.tsx");
  const welcome = read("./Welcome.tsx");

  it("App: a notice from the sign-in card goes to endByClient, never straight to the sign-out", () => {
    expect(app).toContain('onForget={(notice?: string) => void (notice ? endByClient(notice, "expired") : signOut(undefined, "user"))}');
    expect(app).not.toContain('signOut(notice, notice ? "expired" : "user")');
  });

  it("App: an open vault whose card turns out to name the operator goes the same way, revoked at the server as before", () => {
    expect(app).toContain('if (cardNamesOperator(pin, vaultUserId)) void endByClient(OPERATOR_NOT_ON_WEB, "user");');
    expect(app).not.toContain("void signOut(OPERATOR_NOT_ON_WEB");
  });

  it("App: endByClient counts first, signs out only over none, and otherwise lands on the unlock card with the line", () => {
    const body = app.slice(app.indexOf("const endByClient = useCallback("), app.indexOf("const liveUserId = "));
    const count = body.indexOf("await unsentChangeCount(uid)");
    expect(count).toBeGreaterThan(-1);
    expect(body.indexOf("p.store.freezeAsReadOnlyCopy(\"ended\");")).toBeLessThan(count);
    expect(body).toMatch(/if \(unsent === 0\) \{\s*await signOut\(notice, kind\);/);
    expect(body).toContain("const end = endByClientDecision(clientRef.current, notice, unsent);");
    expect(body).toContain('setPhase({ kind: "unlock", session: end.session, notice: line, endedHere: endedHereSeq.current });');
    expect(body).not.toContain("wipeVaultCache");
    expect(body).not.toContain("clearSession");
  });

  it("Welcome: each kit timeout and the operator refusal end the sign-in's own session, then hand the reason to App", () => {
    const timeouts = welcome.match(/onTimeout=\{\(\) => \{\n\s*wipeOpened\([^)]*\);\n\s*onForget\(KIT_TIMEOUT_NOTICE\);/g) ?? [];
    expect(timeouts).toHaveLength(4);
    expect(welcome).toContain("void abandonSignIn(ctx.client, flow);\n        onTimeout();");
    expect(welcome).toMatch(/wipeOpened\(c\.opened\);\n\s*void abandonSignIn\(ctx\.client, c\.flow\);\n\s*onForget\(OPERATOR_NOT_ON_WEB\);/);
  });

  it("the card it lands on does not say the server ended the session, and is drawn afresh", () => {
    expect(welcome).toContain("{!endedByBrowser && <Msg kind=\"info\">{session.endedUnconfirmed === true || endedUnconfirmed(session.userId) ? SESSION_NOT_CONFIRMED : SESSION_ENDED_HELD}</Msg>}");
    expect(app).toContain("endedByBrowser={phase.kind === \"unlock\" && phase.endedHere !== undefined}");
    expect(app).toContain("key={phase.kind === \"unlock\" && phase.endedHere !== undefined ? `ended-here-${phase.endedHere}` : \"welcome\"}");
  });
});
