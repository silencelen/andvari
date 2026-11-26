import "fake-indexeddb/auto"; // the browser profile's IndexedDB, where the offline copy lives
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { IDBFactory as FakeIDBFactory } from "fake-indexeddb";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiClient } from "../api/client";
import { DEVICE_KEY } from "../api/devicesecret";
import { initSodium } from "../crypto/sodium";
import { emailNorm } from "../crypto/trust/grammar";
import { writeLastExportAt } from "../export/plan";
import { cachedAccountKeys, enterVault, knownIdentity } from "../ui/opensession";
import {
  clearSession,
  clearTabTokens,
  declineCacheNudge,
  lockRevokeUnconfirmed,
  makeClient,
  migrateCacheConsentOnce,
  recordLockRevoke,
  resetTabClaim,
  SESSION_STORAGE_KEY,
  setOfflineCopyEnabled,
  wipeLocalAccountState,
  wipeVaultCache,
} from "../ui/session";
import { endSessionByServer } from "../ui/sessionend";
import { lockTabTokens, revokeForSignOut } from "../ui/tabsession";
import { writePersistedAutoLockSeconds } from "../ui/useAutoLock";
import { THEME_STORAGE_KEY } from "../ui/useTheme";
import { openFromCopy } from "../vault/onboardflow";
import { deleteAccount } from "../vault/settingsflow";
import { Browser } from "./browser";
import { journeysUnavailable, TestInstance } from "./harness";
import { HOOK } from "./wait";

/**
 * What the web client leaves in the browser after each way an account's session ends here (spec 05, "What a browser keeps
 * when an account ends"), the web twin of extension/src/leftbehind.harness.test.ts. Each profile is a real sign-up against
 * the test server, its vault opened as the app opens it (enterVault, with the browser's own IndexedDB copy where the offline
 * copy is on), an item saved and synced, and the conveniences the screens write; then one ending, run with the functions
 * App and Welcome call for it, in their order (the source pins at the end hold those call sequences to the screens' own).
 * Every key of every area (localStorage, sessionStorage, IndexedDB) is listed and the whole set pinned, so a key added
 * later fails here until someone decides whether it stays.
 *
 * A listed key reads `area:key [marks]`: the key with the origin, the user id, the normalised address, the personal vault
 * id and this browser's device id replaced by placeholders, any other uuid by `<id>`; the marks say what the VALUE names in
 * plain text: `u` the user id, `e` the address, `h` the address's SHA-256 (the device record's index), `d` the device id.
 * A whole IndexedDB database is listed as `idb:<name>`, then one line per row.
 *
 * Not produced by these profiles (no shared vault, no contact): the vault logs (`andvari.log2.<userId>.*`) and the contact
 * book (`andvari.current.<userId>`, `andvari.onetap.<userId>`); they are account-scoped keys, and the deletion's wipe of
 * them is pinned in ui/session.account-wipe.test.ts.
 */
const skip = journeysUnavailable();
if (skip) console.warn(skip);

const PASSWORD = "correct horse Battery 9 staple";
const g = globalThis as { indexedDB?: IDBFactory };

function storageOver(m: Map<string, string>): Storage {
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k: string) => m.get(k) ?? null,
    key: (i: number) => [...m.keys()][i] ?? null,
    removeItem: (k: string) => void m.delete(k),
    setItem: (k: string, v: string) => void m.set(k, String(v)),
  } as Storage;
}

/** One browser profile: its localStorage (also the device storage the screens' KeyValue reads, as in the app), its sessionStorage and IndexedDB. */
interface Profile {
  readonly local: Map<string, string>;
  readonly session: Map<string, string>;
  readonly idb: IDBFactory;
  readonly browser: Browser;
}

function newProfile(inst: TestInstance): Profile {
  const local = new Map<string, string>();
  const session = new Map<string, string>();
  vi.stubGlobal("localStorage", storageOver(local));
  vi.stubGlobal("sessionStorage", storageOver(session));
  const idb = new FakeIDBFactory() as unknown as IDBFactory;
  g.indexedDB = idb;
  resetTabClaim();
  const kv = { map: local, get: (k: string) => local.get(k) ?? null, set: (k: string, v: string) => void local.set(k, v), remove: (k: string) => void local.delete(k) };
  return { local, session, idb, browser: new Browser(inst, "Firefox on Linux", kv, makeClient(null, inst.origin)) };
}

interface Who {
  readonly email: string;
  readonly userId: string;
  readonly vaultId: string;
  readonly origin: string;
}

const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g;

function deviceIds(p: Profile): string[] {
  const raw = p.local.get(DEVICE_KEY);
  if (!raw) return [];
  try {
    return Object.values((JSON.parse(raw) as { devices?: Record<string, string> }).devices ?? {});
  } catch {
    return [];
  }
}

async function idbEntries(f: IDBFactory): Promise<[string, unknown][]> {
  const out: [string, unknown][] = [];
  for (const { name } of await f.databases()) {
    if (!name) continue;
    const db = await new Promise<IDBDatabase>((res, rej) => {
      const r = f.open(name);
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    try {
      out.push([`idb:${name}`, null]);
      for (const store of [...db.objectStoreNames]) {
        const rows = await new Promise<{ k: IDBValidKey[]; v: unknown[] }>((res, rej) => {
          const tx = db.transaction(store, "readonly");
          const s = tx.objectStore(store);
          const kr = s.getAllKeys();
          const vr = s.getAll();
          tx.oncomplete = () => res({ k: kr.result, v: vr.result });
          tx.onerror = () => rej(tx.error);
        });
        rows.k.forEach((k, i) => out.push([`idb:${name}/${store}:${String(k)}`, rows.v[i]]));
      }
    } finally {
      db.close();
    }
  }
  return out;
}

async function dump(p: Profile, who: Who, devices: string[]): Promise<string[]> {
  const addr = emailNorm(who.email)!;
  const addrHash = createHash("sha256").update(addr, "utf8").digest("hex");
  const norm = (k: string): string => {
    let s = k.replaceAll(who.origin, "<origin>").replaceAll(who.userId, "<userId>").replaceAll(addr, "<email>").replaceAll(who.vaultId, "<vault>");
    for (const d of devices) s = s.replaceAll(d, "<device>");
    return s.replace(UUID, "<id>");
  };
  const marks = (v: unknown): string => {
    let s: string;
    try {
      s = typeof v === "string" ? v : (JSON.stringify(v, (_k, x) => (x instanceof Uint8Array || x instanceof ArrayBuffer ? "" : x)) ?? "");
    } catch {
      s = String(v);
    }
    const m = [s.includes(who.userId) ? "u" : "", s.includes(addr) ? "e" : "", s.includes(addrHash) ? "h" : "", devices.some((d) => s.includes(d)) ? "d" : ""].join("");
    return m ? ` [${m}]` : "";
  };
  const out: string[] = [];
  for (const [k, v] of p.local) out.push(`local:${norm(k)}${marks(v)}`);
  for (const [k, v] of p.session) out.push(`session:${norm(k)}${marks(v)}`);
  for (const [k, v] of await idbEntries(p.idb)) out.push(`${norm(k)}${marks(v)}`);
  return out.sort();
}

const settle = (ms = 300) => new Promise((r) => setTimeout(r, ms));
const sorted = (...xs: string[][]) => xs.flat().sort();

/** The session record's pair: what a reload's makeClient would adopt. */
function heldPair(p: Profile): unknown {
  const raw = p.local.get(SESSION_STORAGE_KEY);
  return raw ? (JSON.parse(raw) as { tokens: unknown }).tokens : undefined;
}

/** A signed-in browser with its vault open, as a person leaves it after a while of use. */
async function signedIn(inst: TestInstance, name: string, offlineCopy: boolean) {
  inst.advance(3_601_000); // past the sign-up limit of one network (three an hour)
  const p = newProfile(inst);
  const email = `${name}@example.org`;
  const signed = await p.browser.signUp(email, PASSWORD, name);
  const userId = signed.session.userId;
  // The one-time question after the first unlock (B2-11): yes keeps the copy, no pins the browser's opt-out.
  if (offlineCopy) await setOfflineCopyEnabled(userId, true);
  else declineCacheNudge();
  const entered = await enterVault(p.browser.ctx, { opened: signed.opened, keys: signed.session.accountKeys, wrap: signed.wrap, email, pin: signed.pin, cardNotice: null, how: "registered" });
  await entered.store.sync();
  await entered.store.save(null, { type: "login", name: "Bank", login: { username: name, password: "s3cret" } });
  await entered.store.sync();
  // What App and Settings write along the way: the boot's consent reconciliation, the policy's auto-lock fallback, the
  // theme a person picked, and the last backup's date.
  await migrateCacheConsentOnce(userId);
  writePersistedAutoLockSeconds(userId, 300);
  p.local.set(THEME_STORAGE_KEY, "dark");
  writeLastExportAt(userId, inst.now());
  await settle();
  const who: Who = { email, userId, vaultId: signed.opened.personalVaultId!, origin: inst.origin };
  return { p, who, entered, devices: deviceIds(p) };
}

/** The server ends the session behind the browser's back (every refusal looks alike to it), and the browser's next request finds out. */
async function refusedByServer(inst: TestInstance, b: Browser, store: { sync(): Promise<void> }): Promise<void> {
  const elsewhere = new ApiClient(inst.origin, b.client.getTokens());
  expect((await elsewhere.logout()).ok).toBe(true);
  await store.sync().catch(() => {});
  expect(b.client.getTokens()).toBeNull(); // the refused refresh dropped the pair (App's hook wrote `tokens: null`)
}

// ---- the sets ----

/**
 * The account's records outside the session and the copy, and the browser's own settings, on every profile until a
 * deletion: the account-state high-water marks and sealed copy (`as2`), the self-identity records (the one whose KEY is the
 * address, and the pin by user id), the recovery mirror, the pin of the server, the device record (its secret, the
 * account's device id and the address's hash), how the session was made, and the settings: the auto-lock fallback, the
 * consent reconciliation stamp, the last backup's date, the theme.
 */
const ACCOUNT = [
  "local:andvari.as2.<userId>.cas",
  "local:andvari.as2.<userId>.hw",
  "local:andvari.as2.<userId>.sealed",
  "local:andvari.as2.<userId>.seen",
  "local:andvari.autoLockSeconds.<userId>",
  "local:andvari.cacheConsentMigrated.<userId>",
  "local:andvari.device.v2 [uhd]",
  "local:andvari.how.<userId>",
  "local:andvari.lastExportAt.<userId>",
  "local:andvari.pin2.<origin>",
  "local:andvari.recmirror.<userId>",
  "local:andvari.selfIdentityByEmail.<email> [u]",
  "local:andvari.selfIdentityPub.<userId>",
  "local:andvari.theme",
];
/** The offline copy's own settings: the account's opt-in, and the browser's once-asked request for lasting storage. */
const COPY_ON = ["local:andvari.cacheOptIn.<userId>", "local:andvari.persistRequested"];
/** No offline copy: the browser's opt-out. */
const COPY_OFF = ["local:andvari.cacheOptOut"];
/** The offline copy: one database for the account (the account keys it unlocks with, the vault, its grant, the item, the item's home). */
const COPY = [
  "idb:andvari-vault-<userId>",
  "idb:andvari-vault-<userId>/grants:<vault> [u]",
  "idb:andvari-vault-<userId>/items:<id>",
  "idb:andvari-vault-<userId>/kv:accountKeys.v2",
  "idb:andvari-vault-<userId>/kv:createdAt",
  "idb:andvari-vault-<userId>/kv:cursor",
  "idb:andvari-vault-<userId>/kv:itemHome:<id>",
  "idb:andvari-vault-<userId>/kv:lastSyncAt",
  "idb:andvari-vault-<userId>/kv:userId [u]",
  "idb:andvari-vault-<userId>/vaults:<vault>",
];
/** The session record: its value names the user id and the address (and holds the pair where the copy is on). */
const SESSION = ["local:andvari.session [ue]"];
/** This tab's pair, without the offline copy. */
const TAB_PAIR = ["session:andvari.tabTokens [u]"];

describe.skipIf(skip !== null)("journey 6: what the browser keeps after each ending", () => {
  let inst: TestInstance;

  beforeAll(async () => {
    await initSodium();
    vi.stubGlobal("navigator", { storage: { persist: async () => true, persisted: async () => true } });
    inst = await TestInstance.start({ kind: "public", mode: "open", env: { ANDVARI_SIGNUP_POW_BITS: "10" } });
  }, HOOK.start);

  afterAll(async () => {
    vi.unstubAllGlobals();
    await inst?.stop();
  }, HOOK.stop);

  it("a lock with the offline copy on keeps everything, the session's pair included", async () => {
    const { p, who, entered, devices } = await signedIn(inst, "lockon", true);
    const open = await dump(p, who, devices);
    expect(open).toEqual(sorted(ACCOUNT, COPY_ON, COPY, SESSION));
    entered.store.close(); // App.lockLocal with the copy on: the vault unmounts, nothing else changes
    await settle();
    expect(await dump(p, who, devices)).toEqual(open);
    expect(heldPair(p)).toMatchObject({ accessToken: expect.any(String), refreshToken: expect.any(String) });
  }, 300_000);

  it("a lock without it ends the tab's pair at the server and drops it; the session record stays without a pair", async () => {
    const { p, who, entered, devices } = await signedIn(inst, "lockoff", false);
    expect(await dump(p, who, devices)).toEqual(sorted(ACCOUNT, COPY_OFF, SESSION, TAB_PAIR));
    // App.lockPerTab: the pair is ended at the server and dropped; the revocation's record follows the server's answer.
    const { revoked } = await lockTabTokens(p.browser.client, { flush: null, flushWaitMs: 0, revoke: true });
    if (revoked) recordLockRevoke(who.userId, "pending");
    clearTabTokens();
    entered.store.close();
    expect(await dump(p, who, devices)).toEqual(sorted(ACCOUNT, COPY_OFF, SESSION, ["session:andvari.tabLockRevoke [u]"]));
    expect(await revoked).toBe(true);
    recordLockRevoke(who.userId, "confirmed");
    await settle();
    expect(await dump(p, who, devices)).toEqual(sorted(ACCOUNT, COPY_OFF, SESSION));
    expect(heldPair(p)).toBeNull();
  }, 300_000);

  it("a sign-out removes the session record, its pair and the offline copy, and nothing else", async () => {
    const { p, who, entered, devices } = await signedIn(inst, "signout", true);
    entered.store.close(); // the sign-out is offered on the unlock card: the vault is locked first
    // App.signOut, kind "user".
    expect(await revokeForSignOut(p.browser.client, null, lockRevokeUnconfirmed(who.userId))).toBe(true);
    clearSession();
    p.browser.client.setTokens(null);
    await wipeVaultCache(who.userId);
    await settle();
    expect(await dump(p, who, devices)).toEqual(sorted(ACCOUNT, COPY_ON));
  }, 300_000);

  it("\"Forget this server\" removes the held session's pair, the offline copy, the session record and the pin; the address stays only as the self-identity record's key", async () => {
    const { p, who, entered, devices } = await signedIn(inst, "forget", true);
    entered.store.close();
    // A reload (App's client from the kept session), then the pin is found damaged: PinStop offers "Forget this server".
    resetTabClaim();
    const b = new Browser(inst, p.browser.deviceName, p.browser.storage, makeClient(JSON.parse(p.local.get(SESSION_STORAGE_KEY)!), inst.origin));
    p.local.set(`andvari.pin2.${inst.origin}`, "{damaged");
    expect(b.pins.state(inst.origin).kind).not.toBe("pinned");
    // Welcome PinStop.forget with a held session: forgetHeldSession, then the pin, then the session record.
    b.client.setTokens(null);
    await wipeVaultCache(who.userId).catch(() => {});
    clearSession();
    b.pins.forget(inst.origin);
    clearSession();
    await settle();
    const left = await dump(p, who, devices);
    expect(left).toEqual(sorted(ACCOUNT.filter((k) => k !== "local:andvari.pin2.<origin>"), COPY_ON));
    expect(left.filter((k) => k.includes("<email>") || /\[[a-z]*e[a-z]*\]$/.test(k))).toEqual(["local:andvari.selfIdentityByEmail.<email> [u]"]);
  }, 300_000);

  it("a refusal by the server with the copy on ends the session and drops its pair; the copy and the session record stay, through the lock that follows", async () => {
    const { p, who, entered, devices } = await signedIn(inst, "refusedon", true);
    await refusedByServer(inst, p.browser, entered.store);
    // App.endByServer with the copy on: the vault stops and freezes, the session ends and its pair goes.
    p.browser.client.cutLiveTraffic();
    entered.store.freezeAsReadOnlyCopy("ended");
    expect(endSessionByServer(p.browser.client).kind).toBe("kept");
    entered.store.close();
    await settle();
    const ended = await dump(p, who, devices);
    expect(ended).toEqual(sorted(ACCOUNT, COPY_ON, COPY, SESSION));
    expect(heldPair(p)).toBeNull();
    // The unlock card opens the copy read-only with the password, and the person locks it.
    const copy = await openFromCopy({ keys: await cachedAccountKeys(who.userId), pins: p.browser.pins, origin: inst.origin, userId: who.userId, password: PASSWORD, knownIdentityPub: knownIdentity(who.email)(who.userId) });
    if (copy.kind !== "opened") throw new Error(copy.kind);
    const ro = await enterVault(p.browser.ctx, { opened: copy.opened, keys: copy.keys, wrap: copy.wrap, email: who.email, pin: copy.pin, cardNotice: null, mode: "ended_copy" });
    ro.store.close();
    await settle();
    expect(await dump(p, who, devices)).toEqual(ended);
  }, 300_000);

  it("a refusal by the server without the copy is the sign-out, with no request", async () => {
    const { p, who, entered, devices } = await signedIn(inst, "refusedoff", false);
    await refusedByServer(inst, p.browser, entered.store);
    p.browser.client.cutLiveTraffic();
    entered.store.freezeAsReadOnlyCopy("ended");
    expect(endSessionByServer(p.browser.client).kind).toBe("sign_out");
    entered.store.close();
    // App.signOut, kind "expired": nothing is sent; the same local wipe.
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    clearSession();
    p.browser.client.setTokens(null);
    await wipeVaultCache(who.userId);
    await settle();
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
    const left = await dump(p, who, devices);
    expect(left).toEqual(sorted(ACCOUNT, COPY_OFF));
    // No vault is open after it, so there is no lock to follow; nothing moves later either.
    await settle(1_000);
    expect(await dump(p, who, devices)).toEqual(left);
  }, 300_000);

  it("a deletion from this browser leaves nothing of the account: the pin, the device record's secret and the browser's settings stay", async () => {
    const { p, who, entered, devices } = await signedIn(inst, "deleted", true);
    const done = await deleteAccount(entered.meta.settings, { typedEmail: who.email, password: PASSWORD, verifiedState: () => null, nowMs: inst.now() });
    expect(done.kind).toBe("deleted");
    entered.store.close();
    // App.onAccountDeleted.
    await wipeLocalAccountState(who.userId, who.email);
    p.browser.client.setTokens(null);
    await settle();
    expect(await dump(p, who, devices)).toEqual(["local:andvari.device.v2", "local:andvari.persistRequested", "local:andvari.pin2.<origin>", "local:andvari.theme"]);
    expect(JSON.parse(p.local.get(DEVICE_KEY)!)).toMatchObject({ secret: expect.any(String), devices: {}, accounts: {} });
  }, 300_000);
});

/** The endings above run the screens' own calls in the screens' order; these pins fail when a screen's sequence changes. */
describe("journey 6: the endings' call sequences are the screens' own", () => {
  const src = (f: string) => readFileSync(fileURLToPath(new URL(`../ui/${f}`, import.meta.url)), "utf8");
  const inOrder = (text: string, parts: string[]) => {
    let at = 0;
    for (const part of parts) {
      const i = text.indexOf(part, at);
      expect(i, part).toBeGreaterThanOrEqual(0);
      at = i + part.length;
    }
  };
  const between = (text: string, from: string, to: string) => {
    const a = text.indexOf(from);
    expect(a, from).toBeGreaterThanOrEqual(0);
    return text.slice(a, text.indexOf(to, a));
  };

  it("App: the sign-out, the deletion, the per-tab lock and the server's end", () => {
    const app = src("App.tsx");
    inOrder(between(app, "const signOut = useCallback(", "const onAccountDeleted"), [
      'kind === "user" ? await revokeForSignOut(clientRef.current, lockRevokeRef.current, lockRevokeUnconfirmed(uid)) : true;',
      "clearSession();",
      "clientRef.current?.setTokens(null);",
      "if (uid) void wipeVaultCache(uid);",
    ]);
    inOrder(between(app, "const onAccountDeleted = useCallback(", "}, []);"), ['void wipeLocalAccountState(userId, email, end === "confirmed" ? "confirmed" : "unconfirmed");', "clientRef.current?.setTokens(null);"]);
    inOrder(between(app, "const lockPerTab = useCallback(", "}, []);"), [
      "await lockTabTokens(clientRef.current, { flush: usageFlushRef.current, flushWaitMs: LOCK_USAGE_FLUSH_WAIT_MS, revoke });",
      'recordLockRevoke(meta.userId, "pending");',
      'recordLockRevoke(meta.userId, ok ? "confirmed" : "unconfirmed");',
      "} finally {",
      "clearTabTokens();",
    ]);
    inOrder(between(app, "const lockLocal = useCallback(", "}, [lockPerTab]);"), ["if (meta && !tokensKeptAcrossLock(meta.userId)) {", "void lockPerTab(notice, meta, true);", "setPhase("]);
    inOrder(between(app, "const endByServer = useCallback(", "const endSession = useCallback("), [
      "clientRef.current?.cutLiveTraffic();",
      'p.store.freezeAsReadOnlyCopy("ended");',
      "const end = endSessionByServer(clientRef.current, kind);",
      'if (end.kind === "sign_out") {',
      "await signOut(line, kind);",
    ]);
  });

  it("Welcome: \"Forget this server\"", () => {
    const welcome = src("Welcome.tsx");
    inOrder(between(welcome, "async function forgetHeldSession(", "/** Design §4.4: a kept session"), [
      "ctx.client.setTokens(null);",
      "await wipeVaultCache(held.session.userId).catch(() => {});",
      "clearSession();",
    ]);
    inOrder(between(welcome, "export function PinStop(", "if (first.kind === \"blocked\")"), ["if (held) await forgetHeldSession(ctx, held);", "ctx.pins.forget(ctx.origin);", "clearSession();"]);
  });
});
