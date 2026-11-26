import "fake-indexeddb/auto";
import { readFileSync } from "node:fs";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import type { AccountKeys, KdfParams, Mutation } from "../api/types";
import { openVaultCache, vaultDbName } from "../vault/idbcache";
import { READ_ONLY_ENDED_REFUSED, ReadOnlyCopyError } from "../vault/store";
import { ENDED_COPY_OPEN, ENDED_COPY_READ, KEPT_CHANGES_MANY, KEPT_CHANGES_ONE, SESSION_ENDED_COPY, SESSION_ENDED_HELD } from "./copy";
import { ENDED_COPY_STOP, endedCopyHold } from "./opensession";
import {
  applyOrgOfflineCachePolicy,
  loadSession,
  makeClient,
  pendingSyncCount,
  saveSession,
  SESSION_STORAGE_KEY,
  setOfflineCopyEnabled,
  TAB_TOKENS_KEY,
  unsentChangeCount,
  wipeLocalAccountState,
} from "./session";
import { fill, UNSENT_LOST_MANY, UNSENT_UNKNOWN } from "./copy";
import { SIGN_OUT_QUESTION, signOutQuestion } from "./SignOutLink";
import { forgetServerAsk } from "./Welcome";
import { endedByServer, endSessionByServer, keptChangesLine } from "./sessionend";
import { storageVerdict } from "./tabsession";

/**
 * Design §4.4 "A session the server ends does not delete the device's copy" (and its two exceptions: the person's
 * own acts, and a browser without the offline copy, where there is nothing to keep). What the web client holds for a
 * session: the token pair (the client's memory, the persisted session or the tab's slot), the session record, the
 * offline copy in IndexedDB (items and the account keys it unlocks with), its queue of changes not yet sent, the pin
 * and the self-identity records (account-scoped localStorage keys). The web has no quick-unlock material (spec 01 §8).
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
const UID = "11111111-1111-4111-8111-111111111111";
const EMAIL = "alice@example.org";
const PAIR = { accessToken: "acc-1", refreshToken: "ref-1" };
const kdf = (): KdfParams => ({ v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 });
const keys = (): AccountKeys => ({ kdfSalt: "c2FsdA", kdfParams: kdf(), wrappedUvk: "wrap", encryptedIdentitySeed: "seed", identityPub: "pub", escrowFingerprint: "fp" });
const mut = (id: string): Mutation => ({ mutationId: id, op: "put", itemId: `item-${id}`, vaultId: "v1", baseItemRev: 0 });
/** Account-scoped records that are not the copy: the pin's and the self-identity's stand-ins, and the per-account state. */
const OTHER_KEYS = { [`andvari.pin2.https://vault.example.org`]: "pin", [`andvari.selfId.${UID}`]: "self", [`andvari.cs.${UID}.hw`]: "7" };

async function dbExists(userId: string): Promise<boolean> {
  const list = await (g.indexedDB as unknown as { databases: () => Promise<{ name?: string }[]> }).databases();
  return list.some((d) => d.name === vaultDbName(userId));
}

/** A signed-in browser: the session and pair persisted, a copy with an item, the account keys and two queued changes. */
async function signedIn(offlineCopy: boolean): Promise<ApiClient> {
  if (offlineCopy) await setOfflineCopyEnabled(UID, true);
  saveSession({ baseUrl: "", userId: UID, personalVaultId: "", email: EMAIL, tokens: PAIR });
  for (const [k, v] of Object.entries(OTHER_KEYS)) localStorage.setItem(k, v);
  if (offlineCopy) {
    const cache = await openVaultCache(UID);
    await cache.setAccountKeys(keys());
    await cache.upsertItem({ itemId: "item-0", vaultId: "v1", rev: 1, blob: "b", deleted: false } as never);
    await cache.enqueue(mut("m1"));
    await cache.enqueue(mut("m2"));
    cache.close();
  }
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

describe("design §4.4: a session the server ends, with the offline copy on", () => {
  it("the session ends and its tokens go; the copy, its queue, the record, the pin and the identity stay", async () => {
    const client = await signedIn(true);
    expect(client.getTokens()).toEqual(PAIR);
    const end = endSessionByServer(client);
    expect(end.kind).toBe("kept");
    // Deleted: the pair, in the client, in the persisted session and in the tab's slot.
    expect(client.getTokens()).toBeNull();
    expect(JSON.parse(localStorage.getItem(SESSION_STORAGE_KEY)!).tokens).toBeNull();
    expect(sessionStorage.getItem(TAB_TOKENS_KEY)).toBeNull();
    // Kept: the session record (the account stands here as signed out by the server).
    const held = loadSession();
    expect(held).toMatchObject({ userId: UID, email: EMAIL, tokens: null });
    expect(end.kind === "kept" && end.session).toEqual(held);
    expect(endedByServer(held)).toBe(true);
    // Kept: the copy (items, the account keys it unlocks with) and the queue of changes not yet sent.
    expect(await dbExists(UID)).toBe(true);
    const cache = await openVaultCache(UID);
    expect((await cache.envelopes()).map((e) => e.itemId)).toEqual(["item-0"]);
    expect(await cache.accountKeys()).toEqual(keys());
    expect((await cache.pending()).map((m) => m.mutationId)).toEqual(["m1", "m2"]);
    cache.close();
    expect(await pendingSyncCount(UID)).toBe(2);
    // Kept: the pin, the self-identity records and the account's other state.
    for (const [k, v] of Object.entries(OTHER_KEYS)) expect(localStorage.getItem(k)).toBe(v);
  });

  it("before an act that deletes the copy, the changes not sent are counted while locked: the queue and the vaults held back", async () => {
    await signedIn(true);
    const cache = await openVaultCache(UID);
    await cache.putHeld({ vault: { vaultId: "v9" }, grant: null, items: [], reason: "deleted", verified: true, parked: [mut("p1")], expungeAt: 999 } as never);
    cache.close();
    // Nothing is unlocked: this is read from IndexedDB, as the unlock card's "Sign out" and "Forget this server" read it.
    expect(await unsentChangeCount(UID)).toBe(3);
    expect(await forgetServerAsk(UID)).toEqual({ text: fill(UNSENT_LOST_MANY, "3"), unsent: 3 });
    expect(await signOutQuestion(UID)).toBe(`${SIGN_OUT_QUESTION} ${fill(UNSENT_LOST_MANY, "3")}`);
    // "Forget this server" over a copy it cannot count is armed too, saying so; with nothing waiting it forgets at once.
    expect(await forgetServerAsk(UID, async () => { throw new Error("idb closed"); })).toEqual({ text: UNSENT_UNKNOWN, unsent: null });
    expect(await forgetServerAsk(UID, async () => 0)).toBeNull();
    expect(await forgetServerAsk(null)).toBeNull();
    // A browser without a copy of the account has nothing waiting.
    expect(await unsentChangeCount("someone-else")).toBe(0);
  });

  it("App's notice says the unsent changes stay and are sent at the next sign-in", () => {
    expect(keptChangesLine(0)).toBeUndefined();
    expect(keptChangesLine(1)).toBe(KEPT_CHANGES_ONE);
    expect(keptChangesLine(3)).toBe(KEPT_CHANGES_MANY.replace("{0}", "3"));
  });

  it("a refused refresh drops the pair and tells App at once; a server having a moment does not", async () => {
    const client = await signedIn(true);
    const fired: string[] = [];
    client.onRefreshRefused = () => fired.push("refused");
    // A 503 on refresh, in the server's own envelope, is transient: the pair stays, nothing ends, and the mark that the
    // refresh is out is cleared (the server took nothing).
    let refreshStatus = 503;
    const envelope = (status: number) => new Response(JSON.stringify({ error: status === 401 ? "session_revoked" : "unavailable", message: "m" }), { status });
    vi.stubGlobal("fetch", async (url: string) => envelope(url.endsWith("/auth/refresh") ? refreshStatus : 401));
    await client.sendRequest("GET", "/api/v2/account/devices").catch(() => null);
    expect(fired).toEqual([]);
    expect(client.getTokens()).toEqual(PAIR);
    // A 401 on refresh, in the server's own envelope, is the server ending the session.
    refreshStatus = 401;
    await client.sendRequest("GET", "/api/v2/account/devices").catch(() => null);
    expect(fired).toEqual(["refused"]);
    expect(client.getTokens()).toBeNull();
    // A refused refresh before a reload leaves the same held record App's end leaves: the copy stays.
    expect(endedByServer(loadSession())).toBe(true);
    expect(await pendingSyncCount(UID)).toBe(2);
  });

  it("another tab sees the shared pair go and ends its own session the same way", async () => {
    await signedIn(true);
    const before = localStorage.getItem(SESSION_STORAGE_KEY);
    endSessionByServer(null);
    const after = localStorage.getItem(SESSION_STORAGE_KEY);
    const v = storageVerdict(
      { key: SESSION_STORAGE_KEY, oldValue: before, newValue: after },
      { activeUserId: UID, have: PAIR, after: loadSession(), keptAcrossLock: () => true },
    );
    expect(v).toEqual({ kind: "endedElsewhere", meta: loadSession() });
    // Another account's tab, or a browser without the offline copy, is not told so.
    expect(storageVerdict({ key: SESSION_STORAGE_KEY, oldValue: before, newValue: after }, { activeUserId: "someone-else", have: PAIR, after: loadSession(), keptAcrossLock: () => true }).kind).not.toBe("endedElsewhere");
    expect(storageVerdict({ key: SESSION_STORAGE_KEY, oldValue: before, newValue: after }, { activeUserId: UID, have: PAIR, after: loadSession(), keptAcrossLock: () => false }).kind).not.toBe("endedElsewhere");
  });

  it("the copy opens read-only while it stands so: the store's writes say so, and traffic is held", () => {
    const store = { readOnlyCopyReason: () => "ended" as const };
    expect(endedCopyHold({ kind: "vault", store })).toBe(ENDED_COPY_STOP);
    expect(endedCopyHold({ kind: "vault", store: { readOnlyCopyReason: () => "forked" as const } })).toBeNull(); // the pin's own stop covers it
    expect(endedCopyHold({ kind: "vault", store: { readOnlyCopyReason: () => null } })).toBeNull();
    expect(endedCopyHold({ kind: "unlock" })).toBeNull(); // the sign-in that restores the session may dial
    expect(new ReadOnlyCopyError("ended").message).toBe(READ_ONLY_ENDED_REFUSED);
  });

  it("the next session of the same account adopts the copy: the store hydrates the kept queue to send it", async () => {
    await signedIn(true);
    endSessionByServer(null);
    // Signing in again opens the same per-account database (opensession.enterVault → openVaultCache(userId)); nothing
    // between the end and the sign-in removes it, and the sign-in's first sync sends the queue (j4-offline journey).
    const cache = await openVaultCache(UID);
    expect((await cache.pending()).map((m) => m.mutationId)).toEqual(["m1", "m2"]);
    cache.close();
    const opensession = readFileSync(new URL("./opensession.ts", import.meta.url), "utf8");
    expect(opensession).toContain("cache = await openCache(account.userId);");
    expect(opensession).toMatch(/await store\.hydrate\(\);[^]*await store\.sync\(\);/);
  });
});

describe("design §4.4: without the offline copy there is nothing to keep (today's rule)", () => {
  it("the end is the ordinary sign-out, which App runs; this step itself changes nothing", async () => {
    const client = await signedIn(false);
    const end = endSessionByServer(client);
    expect(end).toEqual({ kind: "sign_out" });
    expect(client.getTokens()).toEqual(PAIR); // App's signOut drops it, with the record
    expect(await dbExists(UID)).toBe(false);
    expect(endedByServer(loadSession())).toBe(false);
    // With no record at all there is nothing to keep either.
    localStorage.removeItem(SESSION_STORAGE_KEY);
    expect(endSessionByServer(null)).toEqual({ kind: "sign_out" });
  });
});

describe("design §4.4: only the person's own acts delete the copy", () => {
  it("turning the offline copy off, a policy that forbids it, and deleting the account each delete it", async () => {
    await signedIn(true);
    endSessionByServer(null);
    await setOfflineCopyEnabled(UID, false);
    expect(await dbExists(UID)).toBe(false);

    localStorage.clear();
    await signedIn(true);
    endSessionByServer(null);
    await applyOrgOfflineCachePolicy(false, UID);
    expect(await dbExists(UID)).toBe(false);

    localStorage.clear();
    await signedIn(true);
    endSessionByServer(null);
    await wipeLocalAccountState(UID, EMAIL);
    expect(await dbExists(UID)).toBe(false);
    expect(loadSession()).toBeNull();
  });

  const read = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8");

  it("the copy's wipe is called from those acts only: Sign out, Forget this server, Settings, deletion, policy", () => {
    const callers: string[] = [];
    for (const f of ["./App.tsx", "./Welcome.tsx", "./Settings.tsx", "./session.ts", "./Vault.tsx", "./sessionend.ts", "./opensession.ts"]) {
      read(f)
        .split("\n")
        .forEach((l) => {
          if (/wipeVaultCache\(/.test(l) && !/^\s*(\/\/|\*)/.test(l) && !/function wipeVaultCache/.test(l)) callers.push(`${f}: ${l.trim()}`);
        });
    }
    expect(callers).toEqual([
      "./App.tsx: if (uid) void wipeVaultCache(uid);", // signOut: the Sign-out link, or a server end without the offline copy
      "./Welcome.tsx: await wipeVaultCache(held.session.userId).catch(() => {});", // Forget this server (forgetHeldSession)
      "./Settings.tsx: await wipeVaultCache(userId);", // Settings: remove the offline copy
      // Only a wipe one of these acts already asked for, whose tab closed while it waited (the mark names the copy):
      "./session.ts: await Promise.all(owedWipes().map((u) => wipeVaultCache(u).catch(() => {})));", // finishOwedWipes, at a start
      "./session.ts: await wipeVaultCache(userId);", // wipeLocalAccountState: account deletion
      "./session.ts: await wipeVaultCache(userId);", // Forget the earlier account on this device: the second confirmation's click (decided on 2026-11-17)
      "./session.ts: await wipeVaultCache(userId);", // setOfflineCopyEnabled(false)
      "./session.ts: await wipeVaultCache(userId);", // applyOrgOfflineCachePolicy(false), after its one attempt to send
      "./opensession.ts: if (wipeIsOwed(userId)) await wipeVaultCache(userId);", // before the copy is opened again
    ]);
    const end = read("./sessionend.ts");
    expect(end).not.toMatch(/wipe|clearSession\(/);
  });

  it("App ends a server-ended session through endByServer: sign-out only without the offline copy", () => {
    const app = read("./App.tsx");
    const body = app.slice(app.indexOf("const endByServer = useCallback("), app.indexOf("const endSession = useCallback("));
    expect(body).toContain("p.store.freezeAsReadOnlyCopy(\"ended\");");
    expect(body).toContain("const end = endSessionByServer(clientRef.current, kind);");
    expect(body).toMatch(/if \(end\.kind === "sign_out"\) \{[^}]*await signOut\(line, kind\);/);
    // A session this browser could not confirm: the card says that end itself (Welcome), so the notice does not repeat it
    // (sessionend.ts heldEndNotice, drawn in refresh-one-end.drawn.test.ts).
    expect(body).toContain('setPhase({ kind: "unlock", session: end.session, notice: heldEndNotice(kind, notice, line, kept) });');
    expect(body).not.toContain("wipeVaultCache");
    expect(body).not.toContain("clearSession");
    expect(app).toContain("const endSession = useCallback((kind: SessionEndKind, notice?: string) => void endByServer(kind, notice), [endByServer]);");
    // Every server end reaches it: the socket's frames (Vault's onRevoked), a refused refresh, the unlock card's 401, another tab.
    // A refresh that had no try left ends here as not confirmed, never as the server's end (sessionend.ts sessionEndLine).
    expect(app).toContain("client.onRefreshRefused = (why) => onRefreshRefusedRef.current(why);");
    expect(app).toContain('onRefreshRefusedRef.current = (why) => onRevoked(why === "not_confirmed" ? "unconfirmed" : "expired");');
    expect(app).toContain('onSessionEnded={() => onRevoked("expired")}');
    expect(app).toContain('case "endedElsewhere":');
    // A held session (one the server ended included) boots to its unlock card, and a lock of its copy returns there.
    expect(app).toContain('setPhase(session !== null ? { kind: "unlock", session } : { kind: "welcome" });');
    expect(app).toContain('return session ? { kind: "unlock", session, notice } : { kind: "welcome", notice };');
  });

  it("the unlock card of an ended session offers the sign-in, the read-only copy and Sign out", () => {
    const welcome = read("./Welcome.tsx");
    const unlock = welcome.slice(welcome.indexOf("function Unlock("), welcome.indexOf("// ---- Sign up"));
    const ended = unlock.slice(unlock.indexOf("if (endedByServer(session)) {"), unlock.indexOf("if (!session.tokens) {"));
    // Said unless this browser ended it by itself (App endByClient), whose notice says why instead.
    // A session this browser could not confirm in time says that end instead (sessionend.ts endedUnconfirmed).
    expect(ended).toContain("{!endedByBrowser && <Msg kind=\"info\">{session.endedUnconfirmed === true || endedUnconfirmed(session.userId) ? SESSION_NOT_CONFIRMED : SESSION_ENDED_HELD}</Msg>}");
    expect(ended).toContain("<SignIn ctx={ctx} pin={pin} cardNotice={cardNotice} onReady={onReady} onForget={onForget} lockedEmail={session.email} />");
    expect(ended).toContain('<HeldCopyUnlock ctx={ctx} held={{ session, onReady, onForget }} mode="ended_copy" />');
    expect(ended).toContain("<SignOutLink userId={session.userId} onSignOut={() => onForget()} sendFirst={UNSENT_SEND_FIRST_SIGN_IN} />");
    expect(unlock).toContain('case "expired":\n          onSessionEnded();');
    const vault = read("./Vault.tsx");
    expect(vault).toContain('store.readOnlyCopyReason() === "ended"');
    expect(vault).toContain("{endedUnconfirmed(account.userId) ? SESSION_NOT_CONFIRMED_COPY : SESSION_ENDED_COPY}");
  });

  it("its sentences are defined under their mark, a placeholder or approved wording (the design gives the rule, not the wording)", () => {
    const copy = read("./copy.ts");
    for (const [name, value] of Object.entries({ SESSION_ENDED_HELD, ENDED_COPY_READ, ENDED_COPY_OPEN, SESSION_ENDED_COPY, KEPT_CHANGES_ONE, KEPT_CHANGES_MANY })) {
      expect(copy, name).toMatch(new RegExp(`/\\*\\* (?:PLACEHOLDER|Approved wording \\(decided on [0-9-]+\\))[^\\n]*\\*/\\nexport const ${name} = `));
      expect(value.length).toBeGreaterThan(0);
    }
    expect(read("../vault/store.ts")).toMatch(/\/\*\*\n \* (?:PLACEHOLDER |Approved wording \(decided on [0-9-]+\): )[^]*?\*\/\nexport const READ_ONLY_ENDED_REFUSED = /);
  });
});
