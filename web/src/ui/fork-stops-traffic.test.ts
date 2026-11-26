import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, carriesCredential, TrafficStoppedError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { Mutation, SyncResponse } from "../api/types";
import type { AccountKeysV2 } from "../api/wire";
import { WireApi } from "../api/wireclient";
import { initSodium } from "../crypto/sodium";
import { vector } from "../crypto/trust/vectors";
import { memoryClientState } from "../vault/accountstatesync";
import { Account } from "../vault/account";
import { NullCache } from "../vault/idbcache";
import { openFromCopy } from "../vault/onboardflow";
import { pinStopsTraffic } from "../vault/pinstore";
import { buildRegistration } from "../vault/registration";
import { type ItemWire, READ_ONLY_ENDED_REFUSED, ReadOnlyCopyError, VaultStore } from "../vault/store";
import { UsageTracker } from "../vault/usage";
import { CARD_FORK, SESSION_ENDED_COPY } from "./copy";
import { createWebContext, endedCopyHold, enterVault, heldWithoutPin, NO_PIN_STOP, noPinInForce, pinRefreshFor, stopSessionTraffic, type WebContext } from "./opensession";
import { Vault } from "./Vault";

/**
 * Design §4.4 "a fork stops traffic, not reading": under a forked (or damaged) pin nothing is sent to the origin,
 * nothing from it is accepted and nothing is written, while the person's copy stays readable. A server double counts
 * every connection the web client makes: requests (the one `fetch`) and event sockets.
 */
const cards = vector("instancecard.json");
const BASE: string[] = cards.chains.find((c: { name: string }) => c.name === "base").cards.map((c: { frameB64: string }) => c.frameB64);
const OTHER: string[] = cards.chains.find((c: { name: string }) => c.name === "public").cards.map((c: { frameB64: string }) => c.frameB64);
const ORIGIN = "https://vault.example.org";
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 } as const;
const PASSWORD = "correct horse battery";

/** The server double: what it was asked, and the sockets opened to it. */
class CountingServer {
  readonly requests: string[] = [];
  /** The requests that arrived carrying a credential: a bearer token, or a credential route's body (§4.4). */
  readonly credentialed: string[] = [];
  readonly sockets: { url: string; closed: boolean }[] = [];
  served = BASE.slice(0, 2);
  /** A request to a path containing this waits until [release] (an answer still on its way). */
  holdPath: string | null = null;
  private held: (() => void) | null = null;
  release(): void {
    this.held?.();
  }

  install(): void {
    const self = this;
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      self.requests.push(`${init?.method ?? "GET"} ${url}`);
      const headers = (init?.headers ?? {}) as Record<string, string>;
      if (headers["Authorization"] || /\/api\/v\d+\/(auth|recovery\/self)\//.test(new URL(url, ORIGIN).pathname)) self.credentialed.push(`${init?.method ?? "GET"} ${url}`);
      if (self.holdPath !== null && url.includes(self.holdPath)) await new Promise<void>((r) => (self.held = r));
      const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
      if (url.endsWith("/instance")) return json({ cards: self.served, rotations: [] });
      if (url.endsWith("/events/ticket")) return json({ ticket: "t" });
      return json({});
    });
    vi.stubGlobal(
      "WebSocket",
      class {
        onopen: (() => void) | null = null;
        onmessage: ((e: { data: string }) => void) | null = null;
        onclose: (() => void) | null = null;
        onerror: (() => void) | null = null;
        private readonly rec: { url: string; closed: boolean };
        constructor(url: string) {
          this.rec = { url, closed: false };
          self.sockets.push(this.rec);
        }
        send(): void {}
        close(): void {
          this.rec.closed = true;
        }
      },
    );
  }

  /** Everything sent that was not the pin refresh's own GET of the chain. */
  get traffic(): number {
    return this.requests.length + this.sockets.length;
  }
}

/** A context as App builds it, with the origin's pin settled on the base chain. */
async function pinnedContext(server: CountingServer): Promise<WebContext> {
  const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), null);
  const g = await ctx.pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
  ctx.pins.confirmTrustGate(g.ticket);
  expect(server.requests.length).toBe(1);
  return ctx;
}

/** Marks the pin forked the way a session finds it: a refresh that is served another chain. */
async function forkIt(ctx: WebContext, server: CountingServer): Promise<void> {
  server.served = OTHER;
  expect((await ctx.pins.refresh(ORIGIN)).kind).toBe("fork");
  server.requests.length = 0;
}

async function openedAccount(ctx: WebContext) {
  const pin = ctx.pins.pinFor(ORIGIN)!;
  const reg = await buildRegistration({
    email: "alice@example.org", displayName: "Alice", password: PASSWORD, kdfParams: KDF, signupTicket: "t", pin, ageConfirmed: true,
    device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: 1_763_164_800_000,
  });
  const r = reg.request;
  const keys: AccountKeysV2 = { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub, recoveryConfirmed: true, personalWrap: r.personalWrap, genesis: r.genesis };
  return { keys, userId: reg.userId, pin };
}

/** Calls every route of the transport and the wire client once (dummy arguments), as every screen could. */
async function sweepRoutes(ctx: WebContext): Promise<{ routes: number; stopped: number; reasons: Set<string> }> {
  const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const args = [id, id, id, id, id];
  const skip = new Set(["constructor", "setTokens", "useSessionTokens", "getTokens", "assertTrafficAllowed", "cutLiveTraffic"]);
  let stopped = 0;
  let routes = 0;
  const reasons = new Set<string>();
  for (const target of [ctx.client, ctx.wire] as object[]) {
    const proto = Object.getPrototypeOf(target) as object;
    for (const name of Object.getOwnPropertyNames(proto)) {
      const d = Object.getOwnPropertyDescriptor(proto, name)!;
      if (skip.has(name) || typeof d.value !== "function") continue;
      routes++;
      try {
        const r: unknown = (d.value as (...a: unknown[]) => unknown).apply(target, args);
        if (typeof r === "function") (r as () => void)(); // the events subscription's close
        else await Promise.race([Promise.resolve(r), new Promise((res) => setTimeout(res, 2_000))]);
      } catch (e) {
        if (e instanceof TrafficStoppedError) {
          stopped++;
          reasons.add(e.reason);
        }
      }
    }
  }
  await new Promise((r) => setTimeout(r, 0));
  return { routes, stopped, reasons };
}

const PROD_ROOT = fileURLToPath(new URL("..", import.meta.url));

function productionSources(dir = PROD_ROOT): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === "journeys" || name === "e2e" || name === "vendor") continue;
      out.push(...productionSources(p));
    } else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(p);
  }
  return out;
}

/** The code of a source file without its comments (a line comment, or a line inside a block comment). */
function codeLines(text: string): string[] {
  return text
    .split("\n")
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .map((l) => l.replace(/\s\/\/.*$/, ""));
}

describe("design §4.4: a fork stops traffic, not reading", () => {
  let server: CountingServer;

  beforeAll(async () => {
    await initSodium();
  });

  beforeEach(() => {
    server = new CountingServer();
    server.install();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("every connection the web client can make leaves through the one transport and its gate", () => {
    const hits: string[] = [];
    for (const file of productionSources()) {
      const rel = file.slice(PROD_ROOT.length);
      codeLines(readFileSync(file, "utf8")).forEach((line) => {
        if (/(?<![\w.])fetch\(/.test(line) && !/\basync fetch\(/.test(line)) hits.push(`${rel}: ${line.trim()}`);
        if (/new WebSocket\(|new EventSource\(|XMLHttpRequest|sendBeacon/.test(line)) hits.push(`${rel}: ${line.trim()}`);
      });
    }
    // The one fetch (ApiClient.send, gated before and after) and the one event socket (gated before it opens).
    // It follows no redirect (a redirect is an answer that is not the server's).
    expect(hits).toEqual(['api/client.ts: const resp = await fetch(url, { ...init, redirect: "manual" });', expect.stringMatching(/^api\/client\.ts: const sock = new WebSocket\(/)]);
    const client = readFileSync(join(PROD_ROOT, "api/client.ts"), "utf8");
    expect(client).toMatch(/const credentialed = carriesCredential\(url, init\);\n\s+this\.assertTrafficAllowed\(credentialed, false\);\n\s+const resp = await fetch\(url, \{ \.\.\.init, redirect: "manual" \}\);\n\s+this\.assertTrafficAllowed\(credentialed, true\);/);
    // The socket's place raises the gate's error as one after a send (its ticket request went out): never a default.
    expect(client).toMatch(/this\.assertTrafficAllowed\(true, true\); \/\/ §4\.4: the socket is traffic too[^\n]*\n\s+const sock = new WebSocket\(/);
    expect(client).toMatch(/assertTrafficAllowed\(credentialed: boolean, sent: boolean\): void/);
    expect(client).toMatch(/constructor\(public readonly reason: string, public readonly sent: boolean\)/);
    for (const call of client.match(/assertTrafficAllowed\([^)]*\)/g) ?? []) expect(call, "every place says whether anything was sent").toMatch(/,/);
    // App builds its context through createWebContext, which wires the gate to the pin of the origin it dials.
    // Its second stop holds traffic while the copy of a session the server ended is open (design §4.4).
    expect(readFileSync(join(PROD_ROOT, "ui/App.tsx"), "utf8")).toContain(
      "ctxRef.current = createWebContext(client, origin, browserStorage, bakedInstance(), undefined, () => endedCopyHold(phaseRef.current));",
    );
  });

  it("under a forked pin, no route of the transport or the wire client reaches the server", async () => {
    const ctx = await pinnedContext(server);
    await forkIt(ctx, server);
    ctx.client.setTokens({ accessToken: "a", refreshToken: "r" });
    const { routes, stopped } = await sweepRoutes(ctx);
    expect(server.requests).toEqual([]);
    expect(server.sockets).toEqual([]);
    expect(routes).toBeGreaterThan(100);
    expect(stopped).toBeGreaterThan(routes / 2); // the rest refused their dummy arguments before any request
    // The downloads manifest (Settings → Devices) and the sign-out POST go through the same gate.
    await expect(ctx.client.fetchStatic("/downloads/manifest.json")).rejects.toBeInstanceOf(TrafficStoppedError);
    await expect(ctx.client.logout()).rejects.toBeInstanceOf(TrafficStoppedError);
    expect(server.traffic).toBe(0);
  }, 120_000);

  it("a forked copy opened from this browser's cache reads, and nothing it can reach is sent", async () => {
    const ctx = await pinnedContext(server);
    const { keys, userId } = await openedAccount(ctx);
    await forkIt(ctx, server);
    const copy = await openFromCopy({ keys, pins: ctx.pins, origin: ORIGIN, userId, password: PASSWORD, knownIdentityPub: null });
    if (copy.kind !== "opened") throw new Error(copy.kind);
    const { account, store, shared } = await enterVault(ctx, { opened: copy.opened, keys: copy.keys, wrap: copy.wrap, email: "alice@example.org", pin: copy.pin, cardNotice: null, mode: "forked_copy" }, async () => new NullCache());
    expect(store.isReadOnlyCopy()).toBe(true);
    // The vault list, the trash, Sync now, a save, the sharing log's retry.
    expect(store.list()).toEqual([]);
    await store.sync();
    await expect(store.save(null, { type: "note", name: "n" })).rejects.toBeInstanceOf(ReadOnlyCopyError);
    await expect(store.listDeleted()).rejects.toBeInstanceOf(ReadOnlyCopyError);
    await shared.logs.retryPending().catch(() => []);
    // The policy probe and the pin refresh App runs at unlock.
    await expect(ctx.wire.clientPolicy()).rejects.toBeInstanceOf(TrafficStoppedError);
    expect((await ctx.pins.refresh(ORIGIN)).kind).toBe("fork");
    // The events socket Vault would open: refused before it mints a ticket, and never retried.
    const close = ctx.client.events(() => {}, () => {}, () => {}, () => {});
    await new Promise((r) => setTimeout(r, 10));
    close();
    // The usage ledger: the transport refuses its load and flush, and Vault halts it on a read-only copy.
    const usage = new UsageTracker(ctx.wire, account);
    await usage.load();
    usage.record("item");
    await usage.flush();
    usage.halt();
    usage.record("item");
    await usage.flush(new Set(["item"]));
    usage.dispose();
    // Settings → Devices, the health check's breach range, the account's devices.
    await expect(ctx.client.fetchStatic("/downloads/manifest.json")).rejects.toBeInstanceOf(TrafficStoppedError);
    await expect(ctx.client.hibpRange("ABCDE")).rejects.toBeInstanceOf(TrafficStoppedError);
    expect(server.traffic).toBe(0);
    // The vault screen keeps the fork warning in view.
    const html = renderVault(account, store, ctx, true);
    expect(html).toContain(CARD_FORK.replace(/'/g, "&#x27;"));
    expect(server.traffic).toBe(0);
  }, 240_000);

  it("the copy of a session the server ended opens read-only under its notice, and nothing it can reach is sent", async () => {
    // Design §4.4 "nothing is sent and nothing is written while it stands so". App's context: its second stop is the
    // screen showing that copy (App passes endedCopyHold(phaseRef.current)).
    let screen: { kind: string; store?: VaultStore } = { kind: "unlock" };
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), null, undefined, () => endedCopyHold(screen));
    const g = await ctx.pins.begin(ORIGIN);
    if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
    ctx.pins.confirmTrustGate(g.ticket);
    const { keys, userId } = await openedAccount(ctx);
    server.requests.length = 0;
    const copy = await openFromCopy({ keys, pins: ctx.pins, origin: ORIGIN, userId, password: PASSWORD, knownIdentityPub: null });
    if (copy.kind !== "opened") throw new Error(copy.kind);
    const { account, store, shared } = await enterVault(ctx, { opened: copy.opened, keys: copy.keys, wrap: copy.wrap, email: "alice@example.org", pin: copy.pin, cardNotice: null, mode: "ended_copy" }, async () => new NullCache());
    expect(store.isReadOnlyCopy()).toBe(true);
    expect(store.readOnlyCopyReason()).toBe("ended");
    expect(server.traffic, "opening it sent nothing").toBe(0);
    screen = { kind: "vault", store };
    await store.sync();
    const refused = await store.save(null, { type: "note", name: "n" }).catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(ReadOnlyCopyError);
    expect((refused as Error).message).toBe(READ_ONLY_ENDED_REFUSED);
    await expect(store.listDeleted()).rejects.toBeInstanceOf(ReadOnlyCopyError);
    await shared.logs.retryPending().catch(() => []);
    // What the vault's screens can reach, Settings' calls included: refused before they leave.
    await expect(ctx.wire.clientPolicy()).rejects.toBeInstanceOf(TrafficStoppedError);
    await expect(ctx.wire.devices()).rejects.toBeInstanceOf(TrafficStoppedError);
    await ctx.pins.refresh(ORIGIN).catch(() => null);
    const close = ctx.client.events(() => {}, () => {}, () => {}, () => {});
    await new Promise((r) => setTimeout(r, 10));
    close();
    await expect(ctx.client.fetchStatic("/downloads/manifest.json")).rejects.toBeInstanceOf(TrafficStoppedError);
    await expect(ctx.client.hibpRange("ABCDE")).rejects.toBeInstanceOf(TrafficStoppedError);
    await expect(ctx.client.logout()).rejects.toBeInstanceOf(TrafficStoppedError);
    expect(server.traffic).toBe(0);
    // The vault keeps the session-ended notice in view, not the fork warning.
    const html = renderVault(account, store, ctx, true);
    expect(html).toContain(SESSION_ENDED_COPY.replace(/'/g, "&#x27;"));
    expect(html).not.toContain(CARD_FORK.replace(/'/g, "&#x27;"));
    // Leaving the copy (the unlock card) lifts the hold: the sign-in that restores the session may dial.
    screen = { kind: "unlock" };
    expect(() => ctx.client.assertTrafficAllowed(true, false)).not.toThrow();
    // A fork found later says more than the session's end, and replaces it.
    store.freezeAsReadOnlyCopy("forked");
    expect(store.readOnlyCopyReason()).toBe("forked");
  }, 240_000);
});

describe("design §4.4: no credential goes to an origin without a pin in force", () => {
  let server: CountingServer;
  const PAIR = { accessToken: "a", refreshToken: "r" };

  beforeAll(async () => {
    await initSodium();
  });

  beforeEach(() => {
    server = new CountingServer();
    server.install();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** No route sends a credential: every request that left carried none, and the credential routes were refused. */
  async function noCredentialLeaves(ctx: WebContext): Promise<void> {
    ctx.client.setTokens(PAIR); // an in-memory pair, as a kept session whose pin record is gone still holds
    const { routes, reasons } = await sweepRoutes(ctx);
    expect(routes).toBeGreaterThan(100);
    expect(server.credentialed).toEqual([]);
    expect(reasons).toEqual(new Set([NO_PIN_STOP]));
    expect(server.sockets, "the events socket (its ticket is minted with the bearer token)").toEqual([]);
    await expect(ctx.client.logout()).rejects.toBeInstanceOf(TrafficStoppedError);
    await expect(ctx.wire.login("alice@example.org", "authKey", "x")).rejects.toBeInstanceOf(TrafficStoppedError);
    expect(server.credentialed).toEqual([]);
  }

  it("the transport tells the credential routes from a first pin's", () => {
    const yes = ["/api/v1/auth/refresh", "/api/v1/auth/logout", "/api/v2/auth/login", "/api/v2/auth/prelogin", "/api/v2/auth/register", "/api/v2/recovery/self/verify", "/api/v2/recovery/self/commit"];
    const no = ["/api/v2/instance", "/api/v2/client-policy", "/api/v2/signup/start", "/api/v2/signup/verify", "/api/v2/recovery-pubkey", "/downloads/manifest.json"];
    for (const p of yes) expect(carriesCredential(ORIGIN + p, { method: "POST" }), p).toBe(true);
    for (const p of no) expect(carriesCredential(ORIGIN + p, { method: "GET" }), p).toBe(false);
    expect(carriesCredential(ORIGIN + "/api/v2/instance", { headers: { Authorization: "Bearer a" } })).toBe(true);
    expect(carriesCredential(ORIGIN + "/api/v2/instance", { headers: new Headers({ Authorization: "Bearer a" }) })).toBe(true);
  });

  it("a first load: no route sends a credential; the first pin's requests go out without one; the pin then lets them", async () => {
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), null);
    expect(ctx.pins.state(ORIGIN).kind).toBe("none");
    await noCredentialLeaves(ctx);
    expect(server.requests.length, "the routes without a credential still go (the card chain, the policy)").toBeGreaterThan(0);
    // The first pin: its requests carry nothing.
    server.requests.length = 0;
    const g = await ctx.pins.begin(ORIGIN);
    if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
    expect(server.requests).toEqual([`GET ${ORIGIN}/api/v1/instance`]);
    expect(server.credentialed).toEqual([]);
    // With the pin in force a session's request carries its token (the control).
    ctx.pins.confirmTrustGate(g.ticket);
    await ctx.wire.devices().catch(() => null);
    expect(server.credentialed).toEqual([`GET ${ORIGIN}/api/v1/account/devices`]);
  }, 120_000);

  it("after \"Forget this server\": the same as a first load", async () => {
    const ctx = await pinnedContext(server);
    ctx.pins.forget(ORIGIN);
    server.requests.length = 0;
    await noCredentialLeaves(ctx);
  }, 120_000);

  it("a record that cannot be read: a failed read is no pin in force; a record that fails to decode stops everything", async () => {
    // browserStorage reads a storage failure as null (api/devicesecret.ts): this store keeps writes but never reads the pin.
    const m = memoryStorage();
    const unreadable = { get: (k: string) => (k.startsWith("andvari.pin2.") ? null : m.get(k)), set: m.set, remove: m.remove };
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, unreadable, null);
    const g = await ctx.pins.begin(ORIGIN);
    if (g.kind === "needs_trust_gate") ctx.pins.confirmTrustGate(g.ticket);
    expect(ctx.pins.state(ORIGIN).kind).toBe("none");
    server.requests.length = 0;
    await noCredentialLeaves(ctx);
    // A record that fails to decode is damaged: nothing goes at all (§4.4 "never read as no pin").
    const d = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), null);
    d.storage.set(`andvari.pin2.${ORIGIN}`, "not a pin");
    d.client.setTokens(PAIR);
    server.requests.length = 0;
    const r = await sweepRoutes(d);
    expect(server.requests).toEqual([]);
    expect(r.reasons).toEqual(new Set(["damaged"]));
  }, 120_000);

  it("a kept session whose origin holds no pin record is a blocked server: no unlock, nothing dialed, forgotten locally", () => {
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), null);
    expect(heldWithoutPin({ userId: "u" }, ctx)).toBe(true);
    expect(heldWithoutPin(null, ctx)).toBe(false);
    const welcome = readFileSync(join(PROD_ROOT, "ui/Welcome.tsx"), "utf8");
    const settled = welcome.slice(welcome.indexOf("function PinSettled("), welcome.indexOf("/** §12.3 in its typed-address wording"));
    // The check stops before settlePin (which would fetch the chain for a first pin).
    expect(settled.indexOf('if (holding && ctx.pins.state(ctx.origin).kind === "none") {')).toBeGreaterThan(-1);
    expect(settled.indexOf('setView({ kind: "held_no_pin" });')).toBeLessThan(settled.indexOf("await settlePin("));
    expect(settled).toContain('if (view.kind === "held_no_pin") return held ? <HeldWithoutPin ctx={ctx} held={held} />');
    // Forgetting it drops the pair first, unsent, then the copy and the record; App's sign-out then finds no pair to revoke.
    const forget = welcome.slice(welcome.indexOf("async function forgetHeldSession("), welcome.indexOf("/** Design §4.4: a kept session at an origin with no pin record"));
    expect(forget.indexOf("ctx.client.setTokens(null);")).toBeLessThan(forget.indexOf("wipeVaultCache("));
    expect(forget).not.toMatch(/logout|revoke/i);
    const stop = welcome.slice(welcome.indexOf("function PinStop("), welcome.indexOf("function HeldCopyUnlock("));
    expect(stop.indexOf("if (held) await forgetHeldSession(ctx, held);"), "Forget this server drops the held pair before the pin goes").toBeLessThan(stop.indexOf("ctx.pins.forget(ctx.origin);"));
    // App's boot dials nothing for it: no policy probe.
    const app = readFileSync(join(PROD_ROOT, "ui/App.tsx"), "utf8");
    expect(app).toContain("if (!heldWithoutPin(session, ctxRef.current)) await loadPolicy();");
    // The gate: forked/damaged stop everything, no pin in force stops the credentialed requests.
    const open = readFileSync(join(PROD_ROOT, "ui/opensession.ts"), "utf8");
    expect(open).toContain("return pinStopsTraffic(st) ?? (credentialed ? noPinInForce(st) : null) ?? hold?.() ?? null;");
    expect(noPinInForce({ kind: "none" })).toBe(NO_PIN_STOP);
  });
});

function renderVault(account: Account, store: VaultStore, ctx: WebContext, readOnlyCopy: boolean): string {
  return renderToStaticMarkup(
    createElement(Vault, {
      account, store, client: ctx.client, usageWire: ctx.wire, email: "alice@example.org", policy: null, readOnlyCopy, isAdmin: false,
      mustChangePassword: false, offlineRecoveryReminder: false, onLock: () => {}, onRevoked: () => {},
    }),
  );
}

/** A store on stub transports whose cache holds one queued write. */
function queuedStore() {
  const account = Account.fromOpened(
    { userId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", uvk: new Uint8Array(32).fill(1), identity: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(32) }, signing: { publicKey: new Uint8Array(32), privateKey: new Uint8Array(64) }, genesis: null as never, personalVaultId: null, personalVk: null } as never,
    null,
  );
  const sent = { pulls: 0, pushes: 0 };
  const wire = {
    sync: async (): Promise<SyncResponse> => (sent.pulls++, { rev: 1, full: true, vaults: [], grants: [], items: [], removedGrants: [] }) as unknown as SyncResponse,
    pushMutations: async () => {
      sent.pushes++;
      throw new TypeError("offline");
    },
  } as unknown as ItemWire;
  class QueuedCache extends NullCache {
    override async pending(): Promise<Mutation[]> {
      return [{ mutationId: "m1", op: "upsert", itemId: "i1", vaultId: "v1" } as unknown as Mutation];
    }
  }
  return { account, sent, store: new VaultStore({} as ApiClient, account, new QueuedCache(), memoryClientState(), wire) };
}

describe("design §4.4: a fork found while a vault is open", () => {
  let server: CountingServer;

  beforeAll(async () => {
    await initSodium();
  });

  beforeEach(() => {
    server = new CountingServer();
    server.install();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("the refresh beside a sync finds it: traffic stops at once, the store freezes, nothing queued is sent", async () => {
    const ctx = await pinnedContext(server);
    const { account, store, sent } = queuedStore();
    store.attachPinRefresh(pinRefreshFor(ctx, store));
    // A live events socket, as the open vault holds one.
    ctx.client.setTokens({ accessToken: "a", refreshToken: "r" });
    const close = ctx.client.events(() => {}, () => {}, () => {}, () => {});
    await vi.waitFor(() => expect(server.sockets.length).toBe(1));
    // An answer still on its way when the fork is found.
    server.holdPath = "/account/devices";
    const late = ctx.wire.devices().catch((e: unknown) => e);
    await vi.waitFor(() => expect(server.requests.some((r) => r.includes("/account/devices"))).toBe(true));
    server.requests.length = 0;

    server.served = OTHER;
    await store.sync();
    expect(server.requests).toEqual([`GET ${ORIGIN}/api/v1/instance`]); // the refresh that found the fork, and nothing after it
    expect(sent).toEqual({ pulls: 0, pushes: 0 });
    expect(store.isReadOnlyCopy()).toBe(true);
    expect(server.sockets[0]!.closed).toBe(true);
    server.release();
    expect(await late).toBeInstanceOf(TrafficStoppedError); // not accepted
    // From here on nothing is sent: another sync, a write, the policy probe.
    server.requests.length = 0;
    await store.sync();
    await expect(store.save(null, { type: "note", name: "n" })).rejects.toBeInstanceOf(ReadOnlyCopyError);
    await expect(ctx.wire.clientPolicy()).rejects.toBeInstanceOf(TrafficStoppedError);
    expect(server.requests).toEqual([]);
    expect(sent).toEqual({ pulls: 0, pushes: 0 });
    // The vault shows the fork warning (App passes readOnlyCopy when the pin store reports the stop).
    expect(renderVault(account, store, ctx, true)).toContain(CARD_FORK.replace(/'/g, "&#x27;"));
    close();
  }, 120_000);

  it("a fork the policy probe finds reaches App's listener; a damaged record stops traffic the same way", async () => {
    const ctx = await pinnedContext(server);
    const seen: string[] = [];
    const stop = ctx.pins.onStopped((o) => seen.push(o));
    // App's listener (App.tsx) runs stopSessionTraffic for the open store.
    const a = queuedStore();
    const off = ctx.pins.onStopped(() => stopSessionTraffic(ctx, a.store));
    server.served = OTHER;
    expect((await ctx.pins.refresh(ORIGIN)).kind).toBe("fork");
    expect(seen).toEqual([ORIGIN]);
    expect(a.store.isReadOnlyCopy()).toBe(true);
    off();

    // A damaged record: forget the server, pin again, then the record stops decoding.
    ctx.pins.forget(ORIGIN);
    server.served = BASE.slice(0, 2);
    const g = await ctx.pins.begin(ORIGIN);
    if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
    ctx.pins.confirmTrustGate(g.ticket);
    const b = queuedStore();
    b.store.attachPinRefresh(pinRefreshFor(ctx, b.store));
    expect(pinStopsTraffic(ctx.pins.state(ORIGIN))).toBeNull();
    ctx.storage.set(`andvari.pin2.${ORIGIN}`, "not a pin");
    expect(ctx.pins.state(ORIGIN).kind).toBe("damaged");
    server.requests.length = 0;
    await b.store.sync();
    expect(b.store.isReadOnlyCopy()).toBe(true);
    expect(b.sent).toEqual({ pulls: 0, pushes: 0 });
    expect(server.requests).toEqual([]);
    expect(seen).toEqual([ORIGIN, ORIGIN]);
    await expect(ctx.wire.clientPolicy()).rejects.toBeInstanceOf(TrafficStoppedError);
    // Forgetting the server lifts the stop: the next first pin may talk to it again (a credential waits for that pin).
    ctx.pins.forget(ORIGIN);
    expect(() => ctx.client.assertTrafficAllowed(false, false)).not.toThrow();
    expect(() => ctx.client.assertTrafficAllowed(true, false)).toThrow(TrafficStoppedError);
    stop();
  }, 120_000);

  it("a session's wire client is a WireApi over the gated transport", () => {
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), null);
    expect(ctx.wire).toBeInstanceOf(WireApi);
    expect(ctx.wire.transport).toBe(ctx.client);
    expect(typeof ctx.client.trafficGate).toBe("function");
  });
});
