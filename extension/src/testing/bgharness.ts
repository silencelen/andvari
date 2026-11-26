// Test support (not a test file, not bundled, not type-checked: tsconfig excludes src/testing). Loads the REAL
// background.ts under node and drives it through its one `runtime.onMessage` listener, as the 2026-11-15 security
// review did by hand: a loader hook resolves its extensionless imports, and the harness stands in for everything the
// worker reaches outside itself — `chrome` (storage areas, permissions, tabs, alarms, …), IndexedDB (transactional,
// with injectable failures), the KDF worker (a fast stand-in, with a hook that runs while it "derives"), WebSocket
// (never opens) and `fetch`, routed to fake andvari servers that serve bytes built with the extension's own crypto
// leaves and tweetnacl. Every request is logged, so a test can say what was dialed and what was sent.
//
// A World holds what outlives a worker life (IndexedDB, storage.local and storage.session, the servers); start()
// evaluates a fresh copy of background.ts against it (a new worker life: module state is new, storage is not).
import { register } from "node:module";
import { after, afterEach } from "node:test";
import nacl from "tweetnacl";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { adIdkey, adItem, adUvk, adVkPersonal, authKey, boxKeypairFromSeed, seal, toB64, wrapKey } from "../crypto.ts";
import { adVkShared } from "../wraps.ts";
import { adAccountState } from "../accountstate.ts";
import { b64Encode, frameHash, MAGIC, PURPOSE_CODES, signedMessage, ZERO_HASH } from "../statement.ts";

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
export const nameB64 = (text) => b64Encode(utf8(text));
const wait = (ms = 0) => new Promise((r) => setTimeout(r, ms));
export async function settle(rounds = 20) {
  for (let i = 0; i < rounds; i++) await wait(0);
}

// ---- the clock: a test moves the worker's wall clock forward (Date.now), never back; every test starts at real time ----
const realNow = Date.now.bind(Date);
let skewMs = 0;
Date.now = () => realNow() + skewMs;
/** Moves the wall clock [ms] forward, as a browser asleep or a person away would (a timer that never fired included). */
export function passTime(ms) {
  skewMs += ms;
}

// ---- No promise rejection goes unhandled anywhere in the worker's tests ----
// A rejection nobody handles is a failure the worker swallowed by accident (before this, a refused chrome.alarms.create
// was one, and the vault then never locked by itself). Every test that loads this harness fails on one, the test it
// happened in or, when it landed after the last test, the file's last hook.
const unhandled = [];
process.on("unhandledRejection", (e) => unhandled.push(e));
function failOnUnhandled() {
  if (unhandled.length === 0) return;
  const seen = unhandled.splice(0).map((e) => (e instanceof Error ? e.stack ?? e.message : String(e)));
  throw new Error(`unhandled promise rejection in the worker:\n${seen.join("\n")}`);
}
afterEach(async () => {
  await settle();
  skewMs = 0;
  failOnUnhandled();
});
after(async () => {
  await settle();
  failOnUnhandled();
});

/** The fast stand-in for Argon2id (the KDF worker's job): both the fake worker and the fake server use it. */
export function fastKdf(password, salt) {
  const p = utf8(password);
  const b = new Uint8Array(p.length + salt.length);
  b.set(p);
  b.set(salt, p.length);
  return sha256(b);
}

// ---- IndexedDB: transactional like the real thing (after trustedkv.test.ts), with injectable failures ----
function fakeIdb(world) {
  const dbs = world.idb; // db name → store name → Map
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
        const fail = (why) => {
          if (finished) return;
          finished = true;
          tx.error = new Error(why);
          later(() => tx.onerror?.());
        };
        const tx = {
          error: null,
          abort() {
            if (finished) throw new Error("InvalidStateError: the transaction has finished");
            finished = true;
            later(() => tx.onabort?.());
          },
          objectStore() {
            const req = (op, key, fn, value) => {
              const r = {};
              pending++;
              later(() => {
                if (finished) return;
                const run = () => {
                  if (finished) return;
                  if (world.idbFault?.(name, op, key)) return fail(`injected ${op} failure on ${String(key)}`);
                  r.result = fn();
                  r.onsuccess?.();
                  if (--pending === 0) later(complete);
                };
                // A test may hold a request (a slow disk, held by the test and not by a timer): it applies, and its
                // transaction completes, only once the promise the hook returned has settled.
                const hold = world.idbHold?.(name, op, key, value);
                if (hold) void hold.then(run, run);
                else run();
              });
              return r;
            };
            return {
              get: (k) => req("get", k, () => (work.has(k) ? structuredClone(work.get(k)) : undefined)),
              put: (v, k) => {
                const c = structuredClone(v);
                return req("put", k, () => void work.set(k, c), c);
              },
              delete: (k) => req("delete", k, () => void work.delete(k)),
              getAllKeys: () => req("getAllKeys", null, () => [...work.keys()].sort()),
              getAll: () => req("getAll", null, () => [...work.keys()].sort().map((k) => structuredClone(work.get(k)))),
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
      if (world.idbUnavailable) throw new Error("SecurityError: no IndexedDB here");
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
      getManifest: () => ({ version: "0.29.1", manifest_version: 3 }),
      onMessage: life.onMessage,
      onStartup: slot(),
      onInstalled: slot(),
      sendMessage: async () => undefined,
      // Safari: the andvari app's handler (appserver.ts, appvault.ts). A test answers it with `world.native(msg)`; a
      // world with no `native` answers nothing (the callback gets undefined, as a handler that is not there).
      sendNativeMessage: (_app, msg, cb) => {
        world.nativeLog.push(msg);
        void Promise.resolve(world.native?.(msg)).then(cb);
      },
      lastError: undefined,
    },
    storage: { local: area(world.local), session: area(world.session), sync: area(new Map()), onChanged: slot() },
    // Alarms are kept in the world (they outlive a worker life, as the browser's do). `world.alarmRefusal(name)` true
    // makes a create of that alarm reject, as a browser that refuses it does.
    alarms: {
      create: async (name, info) => {
        world.alarmAsks.push(name);
        if (world.alarmRefusal?.(name)) throw new Error(`alarms.create refused: ${name}`);
        world.alarms.set(name, structuredClone(info));
      },
      clear: async (name) => world.alarms.delete(name),
      get: async (name) => (world.alarms.has(name) ? { name, ...world.alarms.get(name) } : undefined),
      getAll: async () => [...world.alarms].map(([name, info]) => ({ name, ...info })),
      onAlarm: life.onAlarm,
    },
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
    permissions: { contains: async ({ origins }) => origins.every((o) => world.permits(o)), request: async () => true, onAdded: slot(), onRemoved: slot() },
    scripting: { registerContentScripts: async () => {}, unregisterContentScripts: async () => {}, updateContentScripts: async () => {}, getRegisteredContentScripts: async () => [] },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, onClicked: slot() },
    commands: { onCommand: slot() },
    windows: { onRemoved: slot(), create: async () => ({}) },
    offscreen: { hasDocument: async () => false, createDocument: async () => {}, closeDocument: async () => {}, Reason: { CLIPBOARD: "CLIPBOARD" } },
    idle: { onStateChanged: slot(), setDetectionInterval: () => {}, queryState: async () => "active" },
  };
  return new Proxy(c, { get: (t, p) => (p in t ? t[p] : permissive()) });
}

// ---- servers ----
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const err = (status, code) => json(status, { error: code, message: code });

/** One signed instance card (purpose 0x04). */
export function cardFrame(signer, f) {
  const st =
    `{"v":2,"purpose":"instance-card","instanceId":"${f.instanceId}","seq":${f.seq},"prev":"${f.prev}","origin":"${f.origin}",` +
    `"name":"${f.name}","kind":"${f.kind}","operator":"${f.operator}","operatorSignKey":"${f.operatorSignKey}","recoveryFp":"none","issuedAt":${f.issuedAt}}`;
  return signedFrame(PURPOSE_CODES["instance-card"], signer, utf8(st));
}
export function signedFrame(code, signer, statement) {
  const sig = nacl.sign.detached(signedMessage(code, signer.publicKey, statement), signer.secretKey);
  const frame = new Uint8Array(101 + statement.length);
  frame.set(MAGIC, 0);
  frame[4] = code;
  frame.set(signer.publicKey, 5);
  frame.set(sig, 37);
  frame.set(statement, 101);
  return frame;
}

/** An instance's card chain: card 0 at `origin`, then whatever a test appends. */
export class Chain {
  constructor({ origin, name = "Smith Vault", kind = "private" }) {
    this.instanceId = uuid();
    this.operator = uuid();
    this.key = nacl.sign.keyPair.fromSeed(rand(32));
    this.frames = [];
    this.add({ origin, name, kind });
  }
  get newest() {
    return this.cards[this.cards.length - 1];
  }
  /** A new card; `operator` hands the instance over to that account (it stays the operator on later cards). */
  add({ origin, name, kind, rotate = false, operator = undefined }) {
    if (operator !== undefined) this.operator = operator;
    const prev = this.cards?.length ? this.newest : null;
    const signer = this.key;
    if (rotate) this.key = nacl.sign.keyPair.fromSeed(rand(32));
    const fields = {
      instanceId: this.instanceId,
      seq: this.frames.length,
      prev: prev ? prev.hash : ZERO_HASH,
      origin: origin ?? prev.origin,
      name: nameB64(name ?? prev.nameText),
      kind: kind ?? prev.kind,
      operator: this.operator,
      operatorSignKey: b64Encode(this.key.publicKey),
      issuedAt: 1_700_000_000_000 + this.frames.length,
    };
    const frame = cardFrame(signer, fields);
    this.frames.push(frame);
    this.cards = [...(this.cards ?? []), { ...fields, nameText: name ?? prev.nameText, hash: frameHash(frame) }];
    return this.newest;
  }
  /** Another chain from the same card 0 onwards: a fork after card `atSeq`. */
  forkAfter(atSeq) {
    const f = Object.create(Chain.prototype);
    Object.assign(f, this, { frames: this.frames.slice(0, atSeq + 1), cards: this.cards.slice(0, atSeq + 1) });
    f.add({ name: "Forked" });
    return f;
  }
  body() {
    return { cards: this.frames.map(b64Encode) };
  }
}

/** An account as a full client would have registered it: keys, genesis, personal vault, account state, items. */
export class Account {
  constructor({ email = "alice@example.com", password = "correct horse", instanceId, operator = false }) {
    this.email = email;
    this.password = password;
    this.userId = uuid();
    this.salt = rand(16);
    this.mk = fastKdf(password, this.salt);
    this.authKey = toB64(authKey(this.mk));
    this.uvk = rand(32);
    this.seed = rand(32);
    this.role = operator ? "operator" : "member";
    this.personalVaultId = uuid();
    this.vaultKeys = new Map([[this.personalVaultId, rand(32)]]);
    this.grants = [];
    this.items = [];
    this.state = null;
    this.instanceId = instanceId;
    this.rev = 0;
  }
  genesisFrame() {
    const sign = nacl.sign.keyPair.fromSeed(this.seed);
    const st =
      `{"v":2,"purpose":"account-genesis","userId":"${this.userId}","identityKey":"${b64Encode(boxKeypairFromSeed(this.seed).publicKey)}",` +
      `"instanceId":"${this.instanceId}","personalVaultId":"${this.personalVaultId}","createdAt":1700000000000}`;
    return signedFrame(PURPOSE_CODES["account-genesis"], sign, utf8(st));
  }
  accountKeys() {
    return {
      kdfSalt: toB64(this.salt),
      kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 },
      wrappedUvk: toB64(seal(wrapKey(this.mk), this.uvk, adUvk(this.userId))),
      encryptedIdentitySeed: toB64(seal(this.uvk, this.seed, adIdkey(this.userId))),
      identityPub: toB64(boxKeypairFromSeed(this.seed).publicKey),
      personalWrap: { vaultId: this.personalVaultId, wrappedVk: toB64(seal(this.uvk, this.vaultKeys.get(this.personalVaultId), adVkPersonal(this.personalVaultId, this.userId))) },
      genesis: toB64(this.genesisFrame()),
    };
  }
  /** A shared vault this account holds a wrap for, recorded in the account state with `decision`. */
  addSharedVault({ decision = "accept", role = "writer" } = {}) {
    const vaultId = uuid();
    const vk = rand(32);
    const genesisHash = bytesToHex(rand(32));
    this.vaultKeys.set(vaultId, vk);
    this.grants.push({ vaultId, userId: this.userId, role, wrappedVk: toB64(seal(this.uvk, vk, adVkShared(vaultId, this.userId, genesisHash))) });
    const s = this.state ?? { v: 2, userId: this.userId, seq: 0, vaults: {}, accepted: {} };
    s.vaults[vaultId] = { genesisHash, seq: 0, hash: bytesToHex(rand(32)) };
    s.accepted[vaultId] = { owner: uuid(), addSeq: 1, at: 1, decision };
    this.state = s;
    return vaultId;
  }
  /** The account state document at in-blob `seq`, with the shared vault's decision as given (a copy). */
  stateAt(seq, decisions = {}) {
    const s = structuredClone(this.state ?? { v: 2, userId: this.userId, seq: 0, vaults: {}, accepted: {} });
    s.seq = seq;
    for (const [id, d] of Object.entries(decisions)) s.accepted[id].decision = d;
    return toB64(seal(this.uvk, utf8(JSON.stringify(s)), adAccountState(this.userId)));
  }
  addItem(vaultId, doc, fv = 1) {
    const itemId = uuid();
    this.items.push({ itemId, vaultId, rev: ++this.rev, deleted: false, formatVersion: fv, blob: toB64(seal(this.vaultKeys.get(vaultId), utf8(JSON.stringify(doc)), adItem(vaultId, itemId, fv))) });
    return itemId;
  }
}

/** A fake andvari server at one origin. `override(method, path, body)` may answer any request first. */
export class Server {
  constructor(origin, chain) {
    this.origin = origin;
    this.chain = chain;
    this.accounts = [];
    this.servedState = new Map(); // userId → sealedState override
    this.pushes = [];
    this.override = null;
  }
  addAccount(opts = {}) {
    const a = new Account({ ...opts, instanceId: this.chain.instanceId });
    this.accounts.push(a);
    return a;
  }
  account(token) {
    return this.accounts.find((a) => token === `Bearer at-${a.userId}`) ?? null;
  }
  async handle(method, path, body, headers) {
    const o = this.override?.(method, path, body, headers);
    if (o) return o;
    if (method === "GET" && path === "/api/v1/instance") return json(200, this.chain.body());
    if (method === "GET" && path === "/api/v1/client-policy") return json(200, { serverTime: Date.now(), autoLockSeconds: 900, clipboardClearSeconds: 30 });
    if (method === "POST" && path === "/api/v1/auth/prelogin") {
      const a = this.accounts.find((x) => x.email === body.email);
      return a ? json(200, { kdfSalt: toB64(a.salt), kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 } }) : err(404, "not_found");
    }
    if (method === "POST" && path === "/api/v1/auth/login") {
      const a = this.accounts.find((x) => x.email === body.email);
      if (!a || body.authKey !== a.authKey) return err(401, "bad_credentials");
      return json(200, { userId: a.userId, deviceId: uuid(), accessToken: `at-${a.userId}`, refreshToken: `rt-${a.userId}`, accountKeys: a.accountKeys(), role: a.role });
    }
    if (method === "POST" && path === "/api/v1/auth/logout") return new Response("ok", { status: 200 });
    if (method === "POST" && path === "/api/v1/events/ticket") return this.ticketsOn ? json(200, { ticket: uuid(), expiresInSeconds: 30 }) : err(403, "no_events_here");
    if (path.startsWith("/downloads")) return err(404, "not_found");
    const a = this.account(headers?.authorization);
    if (!a) return err(401, "unauthorized");
    if (method === "GET" && path === "/api/v1/account/keys") return json(200, a.accountKeys());
    if (method === "GET" && path === "/api/v1/account/state") {
      const s = this.servedState.has(a.userId) ? this.servedState.get(a.userId) : a.state ? a.stateAt(a.state.seq) : null;
      return json(200, { sealedState: s, seq: 1 });
    }
    if (method === "GET" && path.startsWith("/api/v1/sync")) {
      return json(200, { rev: a.rev, vaults: [...a.vaultKeys.keys()].map((vaultId) => ({ vaultId, type: "x" })), grants: [{ vaultId: a.personalVaultId, userId: a.userId, role: "owner", wrappedVk: "" }, ...a.grants], items: a.items });
    }
    if (method === "POST" && path === "/api/v1/sync/push") {
      this.pushes.push(body);
      return json(200, { rev: ++a.rev, results: body.mutations.map((m) => ({ mutationId: m.mutationId, status: "applied", newItemRev: a.rev })) });
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
    this.denied = new Set(); // origins whose host permission is not held
    this.asked = []; // every match pattern permissions.contains was asked about
    this.firefoxPatterns = false;
    this.idbFault = null; // (db, op, key) => boolean
    this.idbHold = null; // (db, op, key, value) => a promise the request waits on before it applies, or null
    this.idbUnavailable = false;
    this.kdfHook = null; // async () => void, runs while the KDF stand-in "derives"
    this.sockets = []; // every WebSocket the worker opened (a server answers tickets only with `ticketsOn`)
    this.alarms = new Map(); // name → create info, of every alarm set and not cleared
    this.alarmAsks = []; // every alarm name a create was asked for, refused or not
    this.alarmRefusal = null; // (name) => boolean: the browser refuses that alarm
    this.tabAnswer = null; // (tabId, msg) => the content script's answer
    // Safari mode: a test file sets `globalThis.__ANDVARI_TARGET__ = "safari"` before its first start() (buildtarget.ts
    // reads it once), and answers the andvari app's native handler here.
    this.native = null; // (msg) => the app handler's answer (a promise may hold it back)
    this.nativeLog = []; // every message sent to the app's handler
  }
  permits(pattern) {
    this.asked.push(pattern);
    // Firefox: a match pattern cannot carry a port, so one that does never matches a grant.
    if (this.firefoxPatterns && /^[a-z]+:\/\/[^/]*:\d+\//.test(pattern)) return false;
    for (const d of this.denied) if (pattern.startsWith(d)) return false;
    return true;
  }
  serve(origin, chain) {
    const s = new Server(origin, chain);
    this.servers.set(origin, s);
    return s;
  }
  /** Requests to [origin] (or every request), as `METHOD path`. */
  dialed(origin) {
    return this.log.filter((l) => origin === undefined || l.origin === origin).map((l) => `${l.method} ${l.path}`);
  }
  /** The trusted store's records (the andvari-trusted database). */
  trusted() {
    return this.idb.get("andvari-trusted")?.get("kv") ?? new Map();
  }
  install(life) {
    const world = this;
    const g = globalThis;
    g.chrome = fakeChrome(world, life);
    g.indexedDB = fakeIdb(world);
    g.__ANDVARI_CARDFILL__ = true;
    g.WebSocket = class {
      constructor(url) {
        this.url = url;
        this.readyState = 0;
        world.sockets.push(this); // a test drives it: onopen, then onmessage with the server's frames
      }
      send() {}
      close() {}
    };
    g.Worker = class {
      postMessage(data) {
        void (async () => {
          await world.kdfHook?.();
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
    const life = { onMessage: slot(), onAlarm: slot() };
    this.install(life);
    await import(`../background.ts?life=${++lifeCounter}`);
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
    const w = {
      life,
      send,
      popup: (msg) => send(msg, popupSender),
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

/** Typed address → Trust Gate → Connect. Returns the gate's answer. */
export async function connect(w, origin) {
  const gate = await w.popup({ type: "chooseServer", choice: "own", origin });
  if (!gate?.ok || !gate.gate) throw new Error(`chooseServer: ${JSON.stringify(gate)}`);
  const ok = await w.popup({ type: "confirmServer", origin, hash: gate.gate.hash });
  if (!ok?.ok) throw new Error(`confirmServer: ${JSON.stringify(ok)}`);
  return gate.gate;
}

/** A world with one server at `origin`, its chain, one account, and a worker life connected to it. */
export async function signedInWorld({ origin = "https://vault.smith.example", account = {}, signIn = true, setup = null } = {}) {
  const world = new World();
  const chain = new Chain({ origin });
  const server = world.serve(origin, chain);
  const acct = server.addAccount(account);
  setup?.({ world, chain, server, acct });
  const w = await world.start();
  await connect(w, origin);
  if (signIn) {
    const r = await w.popup({ type: "unlock", email: acct.email, password: acct.password });
    if (!r?.ok) throw new Error(`unlock: ${JSON.stringify(r)}`);
  }
  return { world, chain, server, acct, w };
}
