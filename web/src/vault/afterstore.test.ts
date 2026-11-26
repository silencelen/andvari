import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { AnswerCutOffError, ApiClient, RedirectRefusedError, TrafficStoppedError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { ClientPolicyV2, NewDevice, RecoveryCommitRequestV2 } from "../api/wire";
import { AnsweredCostRefusedError, UnreadableAnswerError, WireApi } from "../api/wireclient";
import { KdfPolicyError } from "../crypto/keys";
import { initSodium } from "../crypto/sodium";
import { kitDisplayForm } from "../crypto/trust/recoverykit";
import { vector } from "../crypto/trust/vectors";
import { KIT_RECOVERY_NOT_SENT, KIT_RECOVERY_STORED_UNCHECKED, KIT_RECOVERY_UNKNOWN, KIT_RECOVERY_UNKNOWN_KIT_GONE,KIT_RECOVERY_UNKNOWN_SERVER_ERROR, KIT_RECOVERY_UNKNOWN_UNREADABLE, SIGNUP_NOT_SENT } from "../ui/copy";
import { createWebContext, type WebContext } from "../ui/opensession";
import { kitCommitScreen } from "../ui/Welcome";
import { outcomeOfThrow, type SendOutcome, unknownWhy } from "./afterstore";
import { commitKitRecovery, parseKitInput, verifyKit } from "./kitflow";
import { completeSignup } from "./onboardflow";
import { PinStore } from "./pinstore";
import { buildRegistration, type Registration } from "./registration";

/**
 * "The server stored it" is said only of what the server itself answered. With the REAL transport (ApiClient, its
 * traffic gate as App wires it, WireApi) and only `fetch` played: each case of the independent check's first probe, the
 * redirect the client no longer follows, and the check's sequence (the pin forgotten by another tab before the commit
 * left: nothing was sent, no kit is shown, and the old kit still works).
 */
const cards = vector("instancecard.json");
const BASE: string[] = cards.chains.find((c: { name: string }) => c.name === "base").cards.map((c: { frameB64: string }) => c.frameB64);
const ORIGIN = "https://vault.example.org";
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 } as const;
const EMAIL = "alice@example.com";
const COMMIT = "/api/v1/recovery/self/commit";

type Answer = () => Response | Promise<Response>;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

/** The server double behind `fetch`: the card chain, kit recovery's two routes and registration; it counts what arrives. */
class Server {
  readonly requests: string[] = [];
  readonly inits: RequestInit[] = [];
  /** The kit's piece the server holds (the registration's until a commit is stored). */
  piece: { recoveryWrappedUvk: string; recoveryAuthKey: string } | null = null;
  reg: Registration | null = null;
  /** How the commit (or the registration) is answered. */
  answer: Answer = () => json({}, 500);
  /** Run when a commit or a registration arrives, before it is answered (another tab acting meanwhile). */
  onArrive: () => void = () => {};
  /** The commit is stored when it arrives, whatever its answer then is. */
  storeCommit = false;

  install(): void {
    vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
      const path = new URL(url).pathname;
      this.requests.push(`${init.method ?? "GET"} ${path}`);
      this.inits.push(init);
      if (path.endsWith("/instance")) return json({ cards: BASE.slice(0, 2), rotations: [] });
      if (path.endsWith("/recovery/self/verify")) {
        const b = JSON.parse(String(init.body)) as { email: string; recoveryAuthKey: string };
        const r = this.reg!.request;
        if (b.email !== EMAIL || b.recoveryAuthKey !== this.piece!.recoveryAuthKey) return json({ error: "invalid_credentials", message: "x" }, 401);
        return json({ recoveryTicket: "dGlja2V0", userId: r.userId, recoveryWrappedUvk: this.piece!.recoveryWrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub });
      }
      if (path.endsWith("/recovery/self/commit") || path.endsWith("/auth/register")) {
        this.onArrive();
        if (this.storeCommit && path.endsWith("/commit")) this.piece = (JSON.parse(String(init.body)) as RecoveryCommitRequestV2).newMemberRecovery;
        return this.answer();
      }
      return json({ error: "not_found", message: "x" }, 404);
    });
  }

  count(path: string): number {
    return this.requests.filter((r) => r.endsWith(path)).length;
  }
}

/** A context as App builds it (ui/opensession.ts), its pin settled, over [storage] (shared by every tab of a browser). */
async function pinnedContext(storage = memoryStorage()): Promise<WebContext> {
  const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, storage, null);
  const g = await ctx.pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
  ctx.pins.confirmTrustGate(g.ticket);
  return ctx;
}

/** Another tab of the same browser: its own pin store over the same storage. Its "Forget this server" removes the record. */
function otherTab(storage: ReturnType<typeof memoryStorage>): PinStore {
  return new PinStore(storage, async () => {
    throw new Error("the other tab dials nothing here");
  }, null);
}

const COMMIT_REQ = {
  recoveryTicket: "dGlja2V0", newAuthKey: "QQ", newKdfSalt: "QQ", newKdfParams: KDF, newWrappedUvk: "QQ",
  newMemberRecovery: { recoveryWrappedUvk: "QQ", recoveryAuthKey: "QQ" }, device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) },
} as unknown as RecoveryCommitRequestV2;

/** One commit through the real transport, answered by [answer]: what it threw, how it is classed, and how many commits left the browser. */
async function probe(answer: Answer, arrange: (ctx: WebContext, storage: ReturnType<typeof memoryStorage>, server: Server) => void = () => {}) {
  const server = new Server();
  server.install();
  server.answer = answer;
  const storage = memoryStorage();
  const ctx = await pinnedContext(storage);
  arrange(ctx, storage, server);
  let thrown: unknown = null;
  try {
    await ctx.wire.recoverySelfCommit(EMAIL, COMMIT_REQ);
  } catch (e) {
    thrown = e;
  }
  return { thrown, outcome: thrown === null ? null : outcomeOfThrow(thrown, SENT_USER), why: thrown === null ? null : unknownWhy(thrown), commits: server.count(COMMIT), server, ctx };
}

/** The account the browser sent on the route (a kit's verified account, a registration's new id). */
const SENT_USER = "a1b2c3d4-0000-4000-8000-00000000000a";

/** A 200 under the JSON type whose body starts to arrive and then breaks off with [error] (the network failed mid-body). */
function cutOff(error: unknown): Response {
  let sent = false;
  const body = new ReadableStream<Uint8Array>({
    pull(c) {
      if (!sent) {
        sent = true;
        c.enqueue(new TextEncoder().encode('{"userId":"a1b2'));
        return;
      }
      c.error(error);
    },
  });
  return new Response(body, { status: 200, headers: { "Content-Type": "application/json" } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the outcome of a write the person cannot simply make again, over the real transport", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const lines: [string, Answer, SendOutcome][] = [
    ["a 200 HTML page (a captive portal's or a proxy's)", () => new Response("<html><body>Sign in to the Wi-Fi</body></html>", { status: 200, headers: { "Content-Type": "text/html" } }), "unknown"],
    ["a 200 with an empty body", () => new Response("", { status: 200 }), "unknown"],
    ["a 200 with an empty body under the JSON type", () => new Response("", { status: 200, headers: { "Content-Type": "application/json" } }), "unknown"],
    ["a 204 with no body", () => new Response(null, { status: 204 }), "unknown"],
    ["a 200 JSON object in another shape that names the account sent, under the JSON type: only this server could give it", () => json({ userId: SENT_USER }), "stored"],
    ["the same body under another type", () => new Response(JSON.stringify({ userId: SENT_USER }), { status: 200, headers: { "Content-Type": "text/plain" } }), "unknown"],
    ["a 200 JSON {} under the JSON type: names no account", () => json({}), "unknown"],
    ["a front's own {\"error\":…} at 200 under the JSON type", () => json({ error: "upstream_timeout", message: "x" }), "unknown"],
    ["the account sent, with an error in the same object", () => json({ userId: SENT_USER, error: "upstream_timeout" }), "unknown"],
    ["[] at 200 under the JSON type", () => json([]), "unknown"],
    ["null at 200 under the JSON type", () => json(null), "unknown"],
    ["{\"userId\":5} at 200 under the JSON type", () => json({ userId: 5 }), "unknown"],
    ["another account's id at 200 under the JSON type", () => json({ userId: "a1b2c3d4-0000-4000-8000-00000000000b" }), "unknown"],
    ["a 200 whose body is cut off by a network error", () => cutOff(new TypeError("terminated")), "unknown"],
    ["a 200 whose body read itself throws", () => ({ type: "basic", status: 200, ok: true, redirected: false, headers: new Headers({ "Content-Type": "application/json" }), text: async () => { throw new TypeError("network error"); }, json: async () => ({}) }) as unknown as Response, "unknown"],
    ["no answer (TypeError)", () => Promise.reject(new TypeError("Failed to fetch")), "unknown"],
    ["an abort", () => Promise.reject(Object.assign(new Error("aborted"), { name: "AbortError" })), "unknown"],
    ["a 502 from a proxy", () => new Response("<html>Bad Gateway</html>", { status: 502, headers: { "Content-Type": "text/html" } }), "unknown"],
    ["a 403 from a WAF", () => new Response("<html>Forbidden</html>", { status: 403, headers: { "Content-Type": "text/html" } }), "refused"],
    ["a 302 to another page", () => new Response(null, { status: 302, headers: { Location: "https://portal.example.net/login" } }), "unknown"],
    ["a 307 to the same route elsewhere", () => new Response(null, { status: 307, headers: { Location: "https://elsewhere.example.net/api/v1/recovery/self/commit" } }), "unknown"],
    ["a browser's opaque answer for a redirect not followed", () => ({ type: "opaqueredirect", status: 0, ok: false, redirected: false, headers: new Headers(), text: async () => "", json: async () => ({}) }) as unknown as Response, "unknown"],
  ];
  for (const [what, answer, expected] of lines) {
    it(`${what}: one request, ${expected}`, async () => {
      const r = await probe(answer);
      expect(r.commits).toBe(1);
      expect(r.thrown).not.toBeNull();
      expect(r.outcome).toBe(expected);
    });
  }

  it("the gate before the send: nothing leaves the browser, and that is a result of its own (nothing was sent)", async () => {
    const r = await probe(() => json({}), (_ctx, storage) => otherTab(storage).forget(ORIGIN));
    expect(r.commits).toBe(0);
    expect(r.thrown).toBeInstanceOf(TrafficStoppedError);
    expect((r.thrown as TrafficStoppedError).sent).toBe(false);
    expect(r.outcome).toBe("not_sent");
  });

  for (const [what, answer] of [
    ["a 409", () => json({ error: "email_taken", message: "x" }, 409)],
    ["a success answer", () => json({})],
  ] as [string, Answer][]) {
    it(`${what} dropped by the gate after it arrived (the pin forgotten by another tab while the request was on its way): cannot be told, never stored`, async () => {
      const r = await probe(answer, (_ctx, storage, server) => {
        server.onArrive = () => otherTab(storage).forget(ORIGIN);
      });
      expect(r.commits).toBe(1);
      expect(r.thrown).toBeInstanceOf(TrafficStoppedError);
      expect((r.thrown as TrafficStoppedError).sent).toBe(true);
      expect(r.outcome).toBe("unknown");
    });
  }

  it("the client follows no redirect on any route: every request goes out with redirect \"manual\", and a redirect is an answer that is not the server's", async () => {
    const r = await probe(() => new Response(null, { status: 301, headers: { Location: "https://elsewhere.example.net/" } }));
    expect(r.server.inits.length).toBeGreaterThanOrEqual(2); // the card chain, then the commit
    for (const init of r.server.inits) expect(init.redirect).toBe("manual");
    expect(r.thrown).toBeInstanceOf(RedirectRefusedError);
    // On a read as well: the client policy behind a redirect is a failed read, never a value.
    r.server.answer = () => new Response(null, { status: 302, headers: { Location: "/elsewhere" } });
    vi.stubGlobal("fetch", async () => new Response(null, { status: 302, headers: { Location: "/elsewhere" } }));
    await expect(r.ctx.wire.clientPolicy()).rejects.toBeInstanceOf(RedirectRefusedError);
  });

  it("an unreadable success answer is the server's own only under the JSON type, as a JSON object with no error that names the account sent", () => {
    expect(outcomeOfThrow(new UnreadableAnswerError("x", true, { userId: SENT_USER }), SENT_USER)).toBe("stored");
    expect(outcomeOfThrow(new UnreadableAnswerError("x", true, {}), SENT_USER)).toBe("unknown");
    expect(outcomeOfThrow(new UnreadableAnswerError("x", true), SENT_USER)).toBe("unknown");
    expect(outcomeOfThrow(new UnreadableAnswerError("x", false, { userId: SENT_USER }), SENT_USER)).toBe("unknown");
    // A cost refusal is "stored" only when it carries an answer that names the account; a bare one cannot be told.
    const refused = new KdfPolicyError("kdf_below_floor", { v: 1, alg: "argon2id13", ops: 1, memBytes: 1024 } as never);
    expect(outcomeOfThrow(new AnsweredCostRefusedError(refused, true, { userId: SENT_USER }), SENT_USER)).toBe("stored");
    expect(outcomeOfThrow(new AnsweredCostRefusedError(refused, true, { userId: "other" }), SENT_USER)).toBe("unknown");
    expect(outcomeOfThrow(new AnsweredCostRefusedError(refused, false, { userId: SENT_USER }), SENT_USER)).toBe("unknown");
    expect(outcomeOfThrow(refused, SENT_USER)).toBe("unknown");
  });

  it("an answer whose status arrived and whose body could not be read is an answer that could not be read, never \"no answer\"", async () => {
    for (const answer of [
      () => cutOff(new TypeError("terminated")),
      () => ({ type: "basic", status: 200, ok: true, redirected: false, headers: new Headers({ "Content-Type": "application/json" }), text: async () => { throw new TypeError("network error"); }, json: async () => ({}) }) as unknown as Response,
    ] as Answer[]) {
      const r = await probe(answer);
      expect(r.commits).toBe(1);
      expect(r.thrown).toBeInstanceOf(AnswerCutOffError);
      expect(r.outcome).toBe("unknown");
      expect(r.why).toBe("unreadable");
    }
    // No answer at all is still "no answer".
    const none = await probe(() => Promise.reject(new TypeError("Failed to fetch")));
    expect(none.why).toBe("no_answer");
  });
});

describe("the check's sequence: the pin forgotten by another tab while the new password's key is derived", () => {
  beforeAll(async () => {
    await initSodium();
  });

  async function registered(ctx: WebContext): Promise<Registration> {
    return buildRegistration({
      email: EMAIL, displayName: "Alice", password: "correct horse", kdfParams: KDF, signupTicket: "t", pin: ctx.pins.pinFor(ORIGIN)!, ageConfirmed: true,
      device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: 1_763_164_800_000,
    });
  }

  it("kit recovery: the commit is never sent, the screen says nothing was sent and shows no kit, and the old kit verifies afterwards", async () => {
    const server = new Server();
    server.install();
    const storage = memoryStorage();
    const ctx = await pinnedContext(storage);
    const reg = await registered(ctx);
    server.reg = reg;
    server.piece = reg.request.memberRecovery;
    server.answer = () => json({ userId: reg.userId }); // were it sent, an unreadable success that names the account: "stored"
    const input = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
    if (input.kind !== "typed") throw new Error("parse");
    const v = await verifyKit({ wire: ctx.wire, pins: ctx.pins, origin: ORIGIN, input, knownIdentityPub: () => null });
    if (v.kind !== "verified") throw new Error(v.kind);
    // The person types the new password; the browser derives its keys. Meanwhile another tab forgets this server: the
    // rule at the commit's start has passed already, and the wire's next step (the device object, after the keys) is
    // where the other tab's act lands, before the send.
    const tab2 = otherTab(storage);
    const wire = new (class extends WireApi {
      override newDevice(name: string): NewDevice {
        tab2.forget(ORIGIN);
        return super.newDevice(name);
      }
    })(ctx.client);
    const c = await commitKitRecovery({ wire, pins: ctx.pins, origin: ORIGIN, verified: v.verified, newPassword: "new horse battery", kdfParams: KDF, deviceName: "x" });
    expect(c.kind).toBe("not_sent");
    expect("kit" in c).toBe(false);
    expect(server.count(COMMIT)).toBe(0);
    expect([...v.verified.uvk].every((x) => x === 0)).toBe(true);
    if (c.kind === "recovered") throw new Error("recovered");
    const screen = kitCommitScreen(c);
    expect(screen).toEqual({ show: "form", err: KIT_RECOVERY_NOT_SENT, endSession: false });
    expect(screen.show).not.toBe("stored");
    expect(JSON.stringify(screen)).not.toContain(KIT_RECOVERY_STORED_UNCHECKED);
    // The old kit, afterwards (the server pinned again): it still opens the account.
    const g = await ctx.pins.begin(ORIGIN);
    if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
    ctx.pins.confirmTrustGate(g.ticket);
    const again = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
    if (again.kind !== "typed") throw new Error("parse");
    expect((await verifyKit({ wire: ctx.wire, pins: ctx.pins, origin: ORIGIN, input: again, knownIdentityPub: () => null })).kind).toBe("verified");
  }, 120_000);

  for (const [what, answer, stored, line] of [
    ["stored, and its answer lost on the way (no answer)", () => Promise.reject(new TypeError("Failed to fetch")), true, KIT_RECOVERY_UNKNOWN],
    ["stored, and answered by a proxy's 502", () => new Response("<html>Bad Gateway</html>", { status: 502, headers: { "Content-Type": "text/html" } }), true, KIT_RECOVERY_UNKNOWN_SERVER_ERROR],
    ["stored, and answered by a captive portal's page", () => new Response("<html>Wi-Fi</html>", { status: 200, headers: { "Content-Type": "text/html" } }), true, KIT_RECOVERY_UNKNOWN_UNREADABLE],
    ["stored, and its answer's body cut off by a network error (the server answered: never \"didn't answer\")", () => cutOff(new TypeError("terminated")), true, KIT_RECOVERY_UNKNOWN_UNREADABLE],
    ["not stored, and no answer", () => Promise.reject(new TypeError("Failed to fetch")), false, KIT_RECOVERY_UNKNOWN],
  ] as [string, Answer, boolean, string][]) {
    it(`kit recovery ${what}: the new kit is shown under the line that says why, and of the two kits kept exactly the right one works`, async () => {
      const server = new Server();
      server.install();
      const ctx = await pinnedContext();
      const reg = await registered(ctx);
      server.reg = reg;
      server.piece = reg.request.memberRecovery;
      server.storeCommit = stored;
      server.answer = answer;
      const verdict = async (secret: Uint8Array) => {
        const input = parseKitInput(kitDisplayForm(secret), EMAIL);
        if (input.kind !== "typed") throw new Error("parse");
        const r = await verifyKit({ wire: ctx.wire, pins: ctx.pins, origin: ORIGIN, input, knownIdentityPub: () => null });
        if (r.kind === "verified") r.verified.uvk.fill(0);
        return r.kind;
      };
      const input = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
      if (input.kind !== "typed") throw new Error("parse");
      const v = await verifyKit({ wire: ctx.wire, pins: ctx.pins, origin: ORIGIN, input, knownIdentityPub: () => null });
      if (v.kind !== "verified") throw new Error(v.kind);
      const c = await commitKitRecovery({ wire: ctx.wire, pins: ctx.pins, origin: ORIGIN, verified: v.verified, newPassword: "new horse battery", kdfParams: KDF, deviceName: "x" });
      expect(server.count(COMMIT)).toBe(1);
      expect(c.kind).toBe("unknown");
      if (c.kind !== "unknown") return;
      const screen = kitCommitScreen(c);
      expect(screen).toEqual({ show: "stored", kit: c.kit, accountId: c.accountId, line, gone: KIT_RECOVERY_UNKNOWN_KIT_GONE, endSession: true });
      expect(c.kit.secret.some((x) => x !== 0)).toBe(true);
      expect(await verdict(c.kit.secret.slice())).toBe(stored ? "verified" : "invalid_credentials");
      expect(await verdict(reg.recoverySecret)).toBe(stored ? "invalid_credentials" : "verified");
    }, 120_000);
  }

  it("registration: the pin forgotten before the send sends nothing, and no account was made", async () => {
    const server = new Server();
    server.install();
    server.answer = () => json({});
    const storage = memoryStorage();
    const ctx = await pinnedContext(storage);
    const tab2 = otherTab(storage);
    const wire = new (class extends WireApi {
      override newDevice(name: string): NewDevice {
        tab2.forget(ORIGIN);
        return super.newDevice(name);
      }
    })(ctx.client);
    const r = await completeSignup({
      wire, pins: ctx.pins, origin: ORIGIN, pin: ctx.pins.pinFor(ORIGIN)!, policy: { kdfParams: KDF } as unknown as ClientPolicyV2, email: EMAIL, displayName: "Alice",
      password: "correct horse battery", signupTicket: "t", ageConfirmed: true, deviceName: "x", nowMs: 1_763_164_800_000,
    });
    expect(r.kind).toBe("not_sent");
    expect("kit" in r).toBe(false);
    expect(server.count("/auth/register")).toBe(0);
    expect(SIGNUP_NOT_SENT.length).toBeGreaterThan(0);
  }, 120_000);
});
