// Test support (not a test file, not bundled, not type-checked: tsconfig excludes src/testing). Loads the REAL
// background.ts under node and drives it through its one `runtime.onMessage` listener: a loader hook resolves its
// extensionless imports, and the harness stands in for everything the worker reaches outside itself: `chrome` (storage
// areas, permissions, tabs, alarms, ...), IndexedDB (transactional), the KDF worker (a fast stand-in), WebSocket (never
// opens) and `fetch`, routed to a fake andvari server that serves bytes sealed with the extension's own crypto leaves.
// Every request is logged, so a test can say what was sent. A server may hold an answer back (`hold`), so a test can
// act while a request is on the wire.
//
// Release 0.30.0 port of the overhaul's harness (the same shape), fitted to the released worker: no instance cards,
// the server is chosen with `setServerUrl` from an extension page, and the personal vault is confirmed once in the popup.
//
// A World holds what outlives a worker life (IndexedDB, storage.local and storage.session, the server); start()
// evaluates a fresh copy of background.ts against it.
import { register } from "node:module";
import { sha256 } from "@noble/hashes/sha2.js";
import { adIdkey, adItem, adUvk, adVk, adVkPersonal, authKey, boxKeypairFromSeed, seal, toB64, wrapKey } from "../crypto.ts";

// ---- the loader hook: background.ts imports "./api", node needs "./api.ts" ----
const HOOK = `export async function resolve(spec, ctx, next) {
  if ((spec.startsWith("./") || spec.startsWith("../")) && !/\\.[A-Za-z]+$/.test(spec) && ctx.parentURL && ctx.parentURL.includes("/extension/src/")) {
    try { return await next(spec + ".ts", ctx); } catch {}
  }
  return next(spec, ctx);
}`;
let hooked = false;
function hookOnce() {
  if (hooked) return;
  hooked = true;
  register("data:text/javascript," + encodeURIComponent(HOOK));
}

// ---- small helpers ----
const enc = new TextEncoder();
export const utf8 = (s) => enc.encode(s);
export const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
export const uuid = () => crypto.randomUUID();
const wait = (ms = 0) => new Promise((r) => setTimeout(r, ms));
export async function settle(rounds = 20) {
  for (let i = 0; i < rounds; i++) await wait(0);
}

/** The fast stand-in for Argon2id (the KDF worker's job): both the fake worker and the fake server use it. */
export function fastKdf(password, salt) {
  const p = utf8(password);
  const b = new Uint8Array(p.length + salt.length);
  b.set(p);
  b.set(salt, p.length);
  return sha256(b);
}

// ---- IndexedDB: transactional like the real thing ----
function fakeIdb(world) {
  const dbs = world.idb; // db name -> store name -> Map
  const later = (f) => setTimeout(f, 0);
  function makeDb(name) {
    const stores = dbs.get(name);
    return {
      objectStoreNames: { contains: (s) => stores.has(s) },
      createObjectStore(s) {
        stores.set(s, new Map());
      },
      close() {},
      transaction(storeName) {
        const data = stores.get(storeName);
        if (!data) throw new Error(`no store ${storeName}`);
        const work = new Map(data);
        let finished = false;
        let pending = 0;
        const complete = () => {
          if (finished) return;
          finished = true;
          data.clear();
          for (const [k, v] of work) data.set(k, v);
          tx.oncomplete?.();
        };
        const tx = {
          error: null,
          abort() {
            if (finished) throw new Error("InvalidStateError: the transaction has finished");
            finished = true;
            later(() => tx.onabort?.());
          },
          objectStore() {
            const req = (fn) => {
              const r = {};
              pending++;
              later(() => {
                if (finished) return;
                r.result = fn();
                r.onsuccess?.();
                if (--pending === 0) later(complete);
              });
              return r;
            };
            return {
              get: (k) => req(() => (work.has(k) ? structuredClone(work.get(k)) : undefined)),
              put: (v, k) => {
                const c = structuredClone(v);
                return req(() => void work.set(k, c));
              },
              delete: (k) => req(() => void work.delete(k)),
              clear: () => req(() => void work.clear()),
              getAllKeys: () => req(() => [...work.keys()].sort()),
              getAll: () => req(() => [...work.keys()].sort().map((k) => structuredClone(work.get(k)))),
            };
          },
        };
        later(() => {
          if (pending === 0) complete();
        });
        return tx;
      },
    };
  }
  return {
    open(name) {
      const r = {};
      later(() => {
        const fresh = !dbs.has(name);
        if (fresh) dbs.set(name, new Map());
        r.result = makeDb(name);
        if (fresh) r.onupgradeneeded?.();
        r.onsuccess?.();
      });
      return r;
    },
  };
}

// ---- chrome ----
function slot() {
  const ls = [];
  return { listeners: ls, addListener: (f) => ls.push(f), removeListener: () => {}, hasListener: () => false };
}
function area(map) {
  const pick = (keys) => {
    const out = {};
    if (keys === null || keys === undefined) for (const [k, v] of map) out[k] = structuredClone(v);
    else for (const k of typeof keys === "string" ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys)) if (map.has(k)) out[k] = structuredClone(map.get(k));
    return out;
  };
  return {
    get: async (keys) => pick(keys),
    set: async (items) => {
      for (const [k, v] of Object.entries(items)) map.set(k, structuredClone(v));
    },
    remove: async (keys) => {
      for (const k of typeof keys === "string" ? [keys] : keys) map.delete(k);
    },
    clear: async () => map.clear(),
    setAccessLevel: async () => {},
    onChanged: slot(),
  };
}
/** Anything the worker reaches that the harness did not spell out: callable, awaitable to undefined, never throws. */
function permissive() {
  return new Proxy(function () {}, {
    get: (_t, p) => (p === "then" ? undefined : p === "addListener" ? () => {} : permissive()),
    apply: () => Promise.resolve(undefined),
  });
}
function fakeChrome(world, life) {
  const base = "chrome-extension://harness/";
  const c = {
    runtime: {
      id: "harness",
      getURL: (p) => base + p,
      getManifest: () => ({ version: "0.30.0", manifest_version: 3 }),
      onMessage: life.onMessage,
      onStartup: slot(),
      onInstalled: life.onInstalled,
      sendMessage: async () => undefined,
      // Safari: the andvari app's handler (appvault.ts). A test answers it with `world.native(msg)`.
      sendNativeMessage: (_app, msg, cb) => {
        world.nativeLog.push(msg);
        void Promise.resolve(world.native?.(msg)).then(cb);
      },
      lastError: undefined,
    },
    storage: { local: area(world.local), session: area(world.session), sync: area(new Map()), onChanged: slot() },
    alarms: { create: async () => {}, clear: async () => true, get: async () => undefined, getAll: async () => [], onAlarm: life.onAlarm },
    tabs: {
      query: async () => [...world.tabs.values()].filter((t) => t.active),
      get: async (id) => {
        const t = world.tabs.get(id);
        if (!t) throw new Error(`no tab ${id}`);
        return t;
      },
      sendMessage: async (tabId, msg) => {
        world.tabMessages.push({ tabId, msg });
        return world.tabAnswer?.(tabId, msg);
      },
      create: async () => ({}),
      onUpdated: slot(),
      onRemoved: slot(),
      onActivated: slot(),
    },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {}, setBadgeTextColor: async () => {}, getBadgeText: async () => "", openPopup: async () => {} },
    permissions: { contains: async () => true, request: async () => true, onAdded: slot(), onRemoved: slot() },
    scripting: { registerContentScripts: async () => {}, unregisterContentScripts: async () => {}, updateContentScripts: async () => {}, getRegisteredContentScripts: async () => [] },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, onClicked: slot() },
    commands: { onCommand: slot() },
    windows: { onRemoved: slot(), create: async () => ({}) },
    offscreen: { hasDocument: async () => false, createDocument: async () => {}, closeDocument: async () => {}, Reason: { CLIPBOARD: "CLIPBOARD" } },
    idle: { onStateChanged: slot(), setDetectionInterval: () => {}, queryState: async () => "active" },
  };
  return new Proxy(c, { get: (t, p) => (p in t ? t[p] : permissive()) });
}

// ---- the server ----
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const err = (status, code) => json(status, { error: code, message: code });

/** An account as a full client would have registered it: keys, personal vault (owner wrap + personal wrap), items. */
export class Account {
  constructor({ email = "alice@example.com", password = "correct horse" } = {}) {
    this.email = email;
    this.password = password;
    this.userId = uuid();
    this.salt = rand(16);
    this.mk = fastKdf(password, this.salt);
    this.authKey = toB64(authKey(this.mk));
    this.uvk = rand(32);
    this.seed = rand(32);
    this.personalVaultId = uuid();
    this.vaultKeys = new Map([[this.personalVaultId, rand(32)]]);
    this.items = [];
    this.rev = 0;
  }
  accountKeys() {
    const vk = this.vaultKeys.get(this.personalVaultId);
    return {
      kdfSalt: toB64(this.salt),
      kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 },
      wrappedUvk: toB64(seal(wrapKey(this.mk), this.uvk, adUvk(this.userId))),
      encryptedIdentitySeed: toB64(seal(this.uvk, this.seed, adIdkey(this.userId))),
      identityPub: toB64(boxKeypairFromSeed(this.seed).publicKey),
      personalWrap: { vaultId: this.personalVaultId, wrappedVk: toB64(seal(this.uvk, vk, adVkPersonal(this.personalVaultId, this.userId))) },
    };
  }
  grants() {
    const vk = this.vaultKeys.get(this.personalVaultId);
    return [{ vaultId: this.personalVaultId, userId: this.userId, role: "owner", wrappedVk: toB64(seal(this.uvk, vk, adVk(this.personalVaultId, this.userId))) }];
  }
  addItem(vaultId, doc, fv = 1) {
    const itemId = uuid();
    this.items.push({ itemId, vaultId, rev: ++this.rev, deleted: false, formatVersion: fv, blob: toB64(seal(this.vaultKeys.get(vaultId), utf8(JSON.stringify(doc)), adItem(vaultId, itemId, fv))) });
    return itemId;
  }
}

/** A fake andvari server at one origin. `override(method, path, body)` may answer any request first; `hold(method,
 *  path)` may return a promise the answer waits for (the answer is computed after it settles). */
export class Server {
  constructor(origin) {
    this.origin = origin;
    this.accounts = [];
    this.pushes = [];
    this.override = null;
    this.hold = null;
  }
  addAccount(opts = {}) {
    const a = new Account(opts);
    this.accounts.push(a);
    return a;
  }
  account(token) {
    return this.accounts.find((a) => token === `Bearer at-${a.userId}`) ?? null;
  }
  async handle(method, path, body, headers) {
    const h = this.hold?.(method, path, body);
    if (h) await h;
    const o = this.override?.(method, path, body);
    if (o) return o;
    if (method === "GET" && path === "/api/v1/client-policy") return json(200, { serverTime: Date.now(), autoLockSeconds: 900, clipboardClearSeconds: 30 });
    if (method === "POST" && path === "/api/v1/auth/prelogin") {
      const a = this.accounts.find((x) => x.email === body.email);
      return a ? json(200, { kdfSalt: toB64(a.salt), kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 } }) : err(404, "not_found");
    }
    if (method === "POST" && path === "/api/v1/auth/login") {
      const a = this.accounts.find((x) => x.email === body.email);
      if (!a || body.authKey !== a.authKey) return err(401, "bad_credentials");
      return json(200, { userId: a.userId, deviceId: uuid(), accessToken: `at-${a.userId}`, refreshToken: `rt-${a.userId}`, accountKeys: a.accountKeys() });
    }
    if (method === "POST" && path === "/api/v1/auth/logout") return new Response("ok", { status: 200 });
    if (method === "POST" && path === "/api/v1/events/ticket") return err(403, "no_events_here");
    if (path.startsWith("/downloads")) return err(404, "not_found");
    const a = this.account(headers?.authorization ?? headers?.Authorization);
    if (!a) return err(401, "unauthorized");
    if (method === "GET" && path === "/api/v1/account/keys") return json(200, a.accountKeys());
    if (method === "GET" && /^\/api\/v1\/vaults\/[^/]+\/members$/.test(path)) return json(200, [{ userId: a.userId, email: a.email, displayName: "", role: "owner" }]);
    if (method === "GET" && path.startsWith("/api/v1/sync")) {
      return json(200, { rev: a.rev, vaults: [...a.vaultKeys.keys()].map((vaultId) => ({ vaultId, type: "personal" })), grants: a.grants(), items: a.items });
    }
    if (method === "POST" && path === "/api/v1/sync/push") {
      this.pushes.push({ userId: a.userId, body });
      for (const m of body.mutations) {
        if (m.op === "put") {
          const row = { itemId: m.itemId, vaultId: m.vaultId, rev: ++a.rev, deleted: false, formatVersion: m.item?.formatVersion ?? 1, blob: m.item?.blob };
          a.items = [...a.items.filter((i) => i.itemId !== m.itemId), row];
        }
      }
      return json(200, { rev: a.rev, results: body.mutations.map((m) => ({ mutationId: m.mutationId, status: "applied", newItemRev: a.rev })) });
    }
    if (path === "/api/v1/usage") return json(200, method === "GET" ? { sealedUsage: null, updatedAt: 0 } : {});
    return err(404, "not_found");
  }
}

// ---- the world ----
let lifeCounter = 0;

export class World {
  constructor() {
    this.idb = new Map();
    this.local = new Map();
    this.session = new Map();
    this.servers = new Map();
    this.log = [];
    this.tabs = new Map();
    this.tabMessages = [];
    this.tabAnswer = null; // (tabId, msg) => the content script's answer
    this.native = null; // (msg) => the Safari app handler's answer (a promise may hold it back)
    this.nativeLog = [];
  }
  serve(origin) {
    const s = new Server(origin);
    this.servers.set(origin, s);
    return s;
  }
  install(life) {
    const world = this;
    const g = globalThis;
    g.chrome = fakeChrome(world, life);
    g.indexedDB = fakeIdb(world);
    g.WebSocket = class {
      constructor(url) {
        this.url = url;
        this.readyState = 0;
      }
      send() {}
      close() {}
    };
    g.Worker = class {
      postMessage(data) {
        void (async () => {
          this.onmessage?.({ data: { ok: true, mk: fastKdf(data.password, data.salt) } });
        })();
      }
      terminate() {}
    };
    g.fetch = async (input, init = {}) => {
      const url = new URL(typeof input === "string" ? input : input.url);
      const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
      const headers = init.headers ?? {};
      world.log.push({ origin: url.origin, method: init.method ?? "GET", path: url.pathname, body, headers });
      const s = world.servers.get(url.origin);
      if (!s) throw new TypeError("fetch failed");
      return s.handle(init.method ?? "GET", url.pathname + url.search, body, headers);
    };
  }
  /** A new worker life: a fresh evaluation of background.ts against this world's storage. */
  async start() {
    hookOnce();
    const life = { onMessage: slot(), onAlarm: slot(), onInstalled: slot() };
    this.install(life);
    await import(`../background.ts?life=${++lifeCounter}`);
    // A fresh install: worker start waits for this event before it settles the server state.
    for (const l of life.onInstalled.listeners) l({ reason: "install" });
    const send = (msg, sender) =>
      new Promise((resolve) => {
        let answered = false;
        for (const l of life.onMessage.listeners) {
          const keep = l(msg, sender, (r) => {
            answered = true;
            resolve(r);
          });
          if (!keep && !answered) resolve(undefined);
        }
      });
    const popupSender = { url: "chrome-extension://harness/popup.html", id: "harness" };
    const optionsSender = { url: "chrome-extension://harness/options.html", id: "harness" };
    const w = {
      life,
      send,
      popup: (msg) => send(msg, popupSender),
      options: (msg) => send(msg, optionsSender),
      page: (msg, tabId, origin, frameId = 0) => send(msg, { tab: { id: tabId, url: origin + "/" }, frameId, origin, url: origin + "/", id: "harness" }),
      alarm: async (name) => {
        for (const l of life.onAlarm.listeners) await l({ name });
        await settle();
      },
    };
    await w.popup({ type: "serverInfo" });
    return w;
  }
}

/** Sign in from the popup; the first sign-in on a browser confirms the served personal vault once, as a person does. */
export async function signIn(w, acct) {
  const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
  if (!r?.ok) throw new Error(`unlock: ${JSON.stringify(r)}`);
  await w.popup({ type: "personalDescribeChange" }); // the popup names the vault (its co-holders) before the accept
  const acc = await w.popup({ type: "personalAcceptChange" });
  if (acc && acc.ok === false && acc.code !== "none") throw new Error(`personalAcceptChange: ${JSON.stringify(acc)}`);
}

/** A world with one server at `origin` (chosen through the options page), one account, and a signed-in worker life. */
export async function signedInWorld({ origin = "https://vault.smith.example", account = {}, signIn: doSignIn = true, setup = null } = {}) {
  const world = new World();
  const server = world.serve(origin);
  const acct = server.addAccount(account);
  setup?.({ world, server, acct });
  const w = await world.start();
  const set = await w.options({ type: "setServerUrl", url: origin });
  if (!set?.ok) throw new Error(`setServerUrl: ${JSON.stringify(set)}`);
  if (doSignIn) await signIn(w, acct);
  return { world, server, acct, w };
}
