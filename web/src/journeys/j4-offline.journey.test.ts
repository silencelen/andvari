import "fake-indexeddb/auto"; // the browser profile's IndexedDB, where the offline copy lives
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { initSodium } from "../crypto/sodium";
import { cachedAccountKeys, enterVault, knownIdentity } from "../ui/opensession";
import { openVaultCache } from "../vault/idbcache";
import { openFromCopy, unlockSession } from "../vault/onboardflow";
import { cachedPendingWraps } from "../ui/session";
import { changePassword, type SettingsSession } from "../vault/settingsflow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * Journey 4: the plain offline unlock (spec 02 §8). A person signs in online on a browser that keeps the offline copy,
 * the server goes away, the page is reloaded, and the vault unlocks from this browser's copy with the password: an item
 * reads, nothing reaches the server, and a write made offline is queued and sent when the server is back.
 *
 * The screens' own functions run against the real server: the unlock (unlockSession, then openFromCopy when it gets
 * no answer, as Welcome's unlock card does) and enterVault, on the browser's real IndexedDB copy.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const EMAIL = "dana@example.org";
const PASSWORD = "correct horse Battery 9 staple";

/** A Map-backed Web Storage, for the session record and the identity record enterVault keeps in localStorage. */
function webStorage(): Storage {
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

describe.skipIf(skip !== null)("journey 4: the offline unlock", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    vi.stubGlobal("localStorage", webStorage());
    vi.stubGlobal("sessionStorage", webStorage());
    inst = await TestInstance.start({ kind: "public", mode: "open", env: { ANDVARI_SIGNUP_POW_BITS: "10" } });
  }, HOOK.start);

  afterAll(async () => {
    vi.unstubAllGlobals();
    await inst?.stop();
  }, HOOK.stop);

  beforeEach(() => inst.advance(61_000));

  it("signs in online, unlocks from the copy with the server gone, reads, sends nothing, and queues a write", async () => {
    const openCache = (userId: string) => openVaultCache(userId); // this browser keeps the offline copy
    const browser = new Browser(inst);
    const signed = await browser.signUp(EMAIL, PASSWORD, "Dana");
    const userId = signed.session.userId;
    const personal = signed.opened.personalVaultId!;

    // Online: the vault opens as the app opens it, caches the account keys with their genesis, and an item is saved.
    const online = await enterVault(browser.ctx, { opened: signed.opened, keys: signed.session.accountKeys, wrap: signed.wrap, email: EMAIL, pin: signed.pin, cardNotice: null, how: null }, openCache);
    await online.store.sync();
    await online.store.save(null, { type: "login", name: "Bank", login: { username: "dana", password: "s3cret" } });
    const bank = online.store.list().find((i) => i.doc.name === "Bank")!;
    expect(bank.rev).toBeGreaterThan(0);
    expect(await cachedAccountKeys(userId, openCache)).toMatchObject({ kdfSalt: signed.session.accountKeys.kdfSalt, genesis: signed.session.accountKeys.genesis });
    const tokens = browser.client.getTokens();

    // The server goes away; the page is reloaded (the profile's storage and IndexedDB stay, the session's pair is
    // restored from the kept session as makeClient does).
    await inst.halt();
    const reloaded = browser.reload();
    reloaded.client.setTokens(tokens);
    const known = knownIdentity(EMAIL)(userId);
    expect(known).not.toBeNull();
    const unlock = await unlockSession({ wire: reloaded.wire, pins: reloaded.pins, origin: reloaded.origin, userId, password: PASSWORD, knownIdentityPub: known });
    expect(unlock.kind).toBe("failed"); // no answer

    // The copy opens with the password, checked against the stored pin, and nothing is fetched to open it.
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const wrong = await openFromCopy({ keys: await cachedAccountKeys(userId, openCache), pins: reloaded.pins, origin: reloaded.origin, userId, password: PASSWORD + "x", knownIdentityPub: known });
    expect(wrong.kind).toBe("wrong_password");
    const copy = await openFromCopy({ keys: await cachedAccountKeys(userId, openCache), pins: reloaded.pins, origin: reloaded.origin, userId, password: PASSWORD, knownIdentityPub: known });
    if (copy.kind !== "opened") throw new Error(copy.kind);
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
    const offline = await enterVault(reloaded.ctx, { opened: copy.opened, keys: copy.keys, wrap: copy.wrap, email: EMAIL, pin: copy.pin, cardNotice: null, mode: "offline" }, openCache);
    expect(offline.store.isReadOnlyCopy()).toBe(false); // offline is not a fork: writes are allowed and queue

    // The item reads from the copy.
    expect(offline.store.get(bank.itemId)?.doc.login).toEqual({ username: "dana", password: "s3cret" });
    expect(offline.store.vaults().map((v) => v.vaultId)).toEqual([personal]);

    // A write made offline (design 2026-07-13-web-offline-cache §D.2a, §D.3): refused while the browser has not granted
    // persistent storage (refuse, never degrade: nothing is queued and the item does not stay)...
    // ...and the refusal names why, so the save screen can say it (saveerror.ts): the browser has not granted lasting storage.
    await expect(offline.store.save(null, { type: "note", name: "Refused", notes: "not kept" })).rejects.toMatchObject({ name: "OfflineNotSavedError", reason: "not_persistent" });
    expect(offline.store.list().map((i) => i.doc.name)).toEqual(["Bank"]);
    const none = await openCache(userId);
    expect(await none.pending()).toEqual([]);
    none.close();
    // ...and queued once it has: saved here, sent when the server is back.
    vi.stubGlobal("navigator", { storage: { persisted: async () => true } });
    await offline.store.save(null, { type: "note", name: "Written offline", notes: "queued" });
    expect(offline.store.list().map((i) => i.doc.name).sort()).toEqual(["Bank", "Written offline"]);
    const queue = await openCache(userId);
    expect((await queue.pending()).length).toBe(1);
    queue.close();

    // The server is back. It received nothing while it was away: another browser does not see the offline write yet.
    await inst.resume();
    const other = new Browser(inst, "Safari on a Mac");
    const seen = await other.signIn(EMAIL, PASSWORD);
    if (seen.kind !== "opened") throw new Error(seen.kind);
    const before = await other.openVault(seen.opened, seen.wrap);
    expect(before.store.list().map((i) => i.doc.name)).toEqual(["Bank"]);

    // The next sync sends the queue, and the other browser reads the note.
    await offline.store.sync();
    const drained = await openCache(userId);
    expect(await drained.pending()).toEqual([]);
    drained.close();
    await before.store.sync();
    expect(before.store.list().map((i) => i.doc.name).sort()).toEqual(["Bank", "Written offline"]);
  }, 600_000);

  it("a password change whose answer was lost: the copy opens with the new password after a reload; a second change after the lost answer never leaves the old one", async () => {
    const EMAIL2 = "erin@example.org";
    const P1 = "first Password 11 river";
    const P2 = "second Password 22 meadow";
    const P3 = "third Password 33 harbour";
    const openCache = (userId: string) => openVaultCache(userId);
    let browser = new Browser(inst);
    const signed = await browser.signUp(EMAIL2, P1, "Erin");
    const userId = signed.session.userId;
    const known = knownIdentity(EMAIL2)(userId);
    let tab = await enterVault(browser.ctx, { opened: signed.opened, keys: signed.session.accountKeys, wrap: signed.wrap, email: EMAIL2, pin: signed.pin, cardNotice: null, how: null }, openCache);
    await tab.store.sync();

    /** The tab's Settings session, with a wire whose answer to the password change is lost after the server took it. */
    const changesSent: string[] = [];
    const losing = (s: SettingsSession): SettingsSession => ({
      ...s,
      wire: new Proxy(s.wire, {
        get: (t, name) => {
          const f = (t as unknown as Record<string | symbol, unknown>)[name];
          if (name !== "changePassword" || typeof f !== "function") return typeof f === "function" ? f.bind(t) : f;
          return async (req: Parameters<SettingsSession["wire"]["changePassword"]>[0]) => {
            changesSent.push(req.newKdfSalt);
            await (f as SettingsSession["wire"]["changePassword"]).call(t, req);
            throw new TypeError("fetch failed"); // the server made it; its answer never arrived
          };
        },
      }),
    });
    /** A reload with the server away: the held session's unlock gets no answer, and the copy opens (or not) with [password]. */
    const offlineOpen = async (password: string) => {
      await inst.halt();
      const reloaded = browser.reload();
      try {
        expect((await unlockSession({ wire: reloaded.wire, pins: reloaded.pins, origin: reloaded.origin, userId, password, knownIdentityPub: known })).kind).toBe("failed");
        return await openFromCopy({ keys: await cachedAccountKeys(userId, openCache), pending: await cachedPendingWraps(userId, openCache), pins: reloaded.pins, origin: reloaded.origin, userId, password, knownIdentityPub: known });
      } finally {
        await inst.resume();
      }
    };

    // 1. P1 → P2, the answer lost. The server holds P2; the change's wrap is kept beside the copy before it went.
    expect((await changePassword(losing(tab.meta.settings), P1, P2, null)).kind).toBe("unknown");
    expect(await cachedPendingWraps(userId, openCache)).toHaveLength(1);
    const tokens = browser.client.getTokens();

    // 2. Reloaded with the server away: the copy opens with P2 (and, unsettled, still with P1); a third password nothing.
    expect((await offlineOpen(P2)).kind).toBe("opened");
    expect((await offlineOpen(P1)).kind).toBe("opened");
    expect((await offlineOpen(P3)).kind).toBe("wrong_password");

    // 3. The next online unlock settles it against the server's keys: P1 is refused there, P2 opens, and from then on the
    //    copy opens with P2 only.
    browser = browser.reload();
    browser.client.setTokens(tokens);
    expect((await unlockSession({ wire: browser.wire, pins: browser.pins, origin: browser.origin, userId, password: P1, knownIdentityPub: known })).kind).toBe("wrong_password");
    const online = await unlockSession({ wire: browser.wire, pins: browser.pins, origin: browser.origin, userId, password: P2, knownIdentityPub: known });
    if (online.kind !== "opened") throw new Error(online.kind);
    tab = await enterVault(browser.ctx, { opened: online.opened, keys: online.keys, wrap: online.wrap, email: EMAIL2, pin: online.pin, cardNotice: null }, openCache);
    expect(await cachedPendingWraps(userId, openCache)).toEqual([]);
    expect((await offlineOpen(P1)).kind).toBe("wrong_password");
    expect((await offlineOpen(P2)).kind).toBe("opened");

    // 4. On the web: P2 → P3 with the answer lost (the server holds P3), then the same form sent
    //    again. The first change is settled against the server before anything else is sent: the server holds its wrap,
    //    so P2 proves nothing now, and no second change goes.
    changesSent.length = 0;
    expect((await changePassword(losing(tab.meta.settings), P2, P3, null)).kind).toBe("unknown");
    expect((await changePassword(losing(tab.meta.settings), P2, P3, null)).kind).toBe("wrong_password");
    expect(changesSent).toHaveLength(1);
    expect(await cachedPendingWraps(userId, openCache)).toEqual([]);
    // This browser opens with the new password, offline and online, and the old one is refused in both.
    expect((await offlineOpen(P3)).kind).toBe("opened");
    expect((await offlineOpen(P2)).kind).toBe("wrong_password");
    const last = browser.reload();
    last.client.setTokens(browser.client.getTokens());
    expect((await unlockSession({ wire: last.wire, pins: last.pins, origin: last.origin, userId, password: P2, knownIdentityPub: known })).kind).toBe("wrong_password");
    expect((await unlockSession({ wire: last.wire, pins: last.pins, origin: last.origin, userId, password: P3, knownIdentityPub: known })).kind).toBe("opened");
  }, 600_000);
});
