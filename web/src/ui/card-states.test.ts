import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, carriesCredential, TrafficStoppedError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import { initSodium } from "../crypto/sodium";
import { vector } from "../crypto/trust/vectors";
import { settlePin, signIn } from "../vault/onboardflow";
import { PinStore, type WebPin } from "../vault/pinstore";
import * as C from "./copy";
import { fill } from "./copy";
import { createWebContext, type WebContext } from "./opensession";
import { cardNoticeText, KindChangeGate, PinStop } from "./Welcome";

/**
 * Every state of a server's identity card that design §4.4, §12.3 and §13 give the web, with the owner's approved words
 * (copy page 2026-11-15, entries 8, 10, 11 and 12). For each state, three pins: the words, what the person can choose,
 * and what may leave this browser while the state stands.
 *
 * The chains are spec/test-vectors/instancecard.json's: chain `base` (card 0 and the rename at https://vault.example.org,
 * card 2 moves it to https://vault2.example.org:8443, card 7 changes its kind to public), chain `public` (another
 * instance: a fork), and reject row `signed-by-another-key` (a card 1 signed by the wrong key).
 */
const cards = vector("instancecard.json");
const BASE: string[] = cards.chains.find((c: { name: string }) => c.name === "base").cards.map((c: { frameB64: string }) => c.frameB64);
const OTHER: string[] = cards.chains.find((c: { name: string }) => c.name === "public").cards.map((c: { frameB64: string }) => c.frameB64);
const BAD_CARD_1: string = cards.reject.find((r: { name: string }) => r.name === "signed-by-another-key").frameB64;
const BASE_CARD0_HASH: string = cards.chains.find((c: { name: string }) => c.name === "base").cards[0].record.hash;
const ORIGIN = "https://vault.example.org";
const ORIGIN2 = "https://vault2.example.org:8443";
const EXT = readFileSync(fileURLToPath(new URL("../../../extension/src/errors.ts", import.meta.url)), "utf8");
const WELCOME = readFileSync(fileURLToPath(new URL("./Welcome.tsx", import.meta.url)), "utf8");
const COPY = readFileSync(fileURLToPath(new URL("./copy.ts", import.meta.url)), "utf8");

/** What the server double was asked: every request, and those that carried a credential (a token or a credential route). */
class Server {
  readonly requests: string[] = [];
  readonly credentialed: string[] = [];
  served: string[] = BASE.slice(0, 2);
  /** The next request waits for this before it is answered (an answer still on its way). */
  holdNext: Promise<void> | null = null;
  install(): void {
    vi.stubGlobal("fetch", async (url: string, init?: RequestInit) => {
      const path = new URL(url, ORIGIN).pathname;
      this.requests.push(`${init?.method ?? "GET"} ${path}`);
      if (carriesCredential(url, init ?? {})) this.credentialed.push(path);
      const hold = this.holdNext;
      this.holdNext = null;
      if (hold !== null) await hold;
      const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
      if (path.endsWith("/instance")) return json({ cards: this.served, rotations: [] });
      if (path.endsWith("/prelogin")) return json({ kdfSalt: "AAAA", kdfParams: { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 } });
      return json({});
    });
  }
}

/** A context as App builds it for the page's origin, pinned through the Trust Gate on the first [n] cards of `base`. */
async function pinned(server: Server, origin: string, n: number): Promise<WebContext> {
  server.served = BASE.slice(0, n);
  const ctx = createWebContext(new ApiClient(origin), origin, memoryStorage(), null);
  const g = await ctx.pins.begin(origin);
  if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
  expect(ctx.pins.confirmTrustGate(g.ticket).kind).toBe("pinned");
  server.requests.length = 0;
  return ctx;
}

const signInOf = (ctx: WebContext) =>
  signIn({ wire: ctx.wire, pins: ctx.pins, origin: ctx.origin, email: "bea@example.org", password: "correct horse battery", deviceName: "test", session: null, knownIdentityPub: null });

const markup = (el: Parameters<typeof renderToStaticMarkup>[0]) => renderToStaticMarkup(el).replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");
const buttons = (html: string) => [...html.matchAll(/<button[^>]*>(.*?)<\/button>/g)].map((m) => m[1]!.replace(/<[^>]+>/g, ""));

describe("the identity card's states on the web (design §4.4, §12.3, §13; approved entries 8, 10, 11, 12)", () => {
  let server: Server;
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    server = new Server();
    server.install();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("the approved words, word for word and unmarked, the same as the extension shows them", () => {
    expect(C.CARD_OTHER_ADDRESS_TITLE).toBe("This address doesn't match the server's identity card");
    expect(fill(C.CARD_OTHER_ADDRESS, ORIGIN, ORIGIN2)).toBe(
      "The server at https://vault.example.org showed an identity card made for a different address, https://vault2.example.org:8443. andvari didn't connect, and nothing of yours was sent. The address may be wrong, the server may have moved, or someone may be imitating it. Check the address with the person who runs the server.",
    );
    expect(C.GATE_TITLE_KIND_CHANGE).toBe("This server says it changed");
    expect(C.GATE_KIND_CONTINUE).toBe("Continue");
    expect(C.GATE_KIND_NOT_NOW).toBe("Not now");
    expect(C.CARD_NOT_VERIFIED).toBe(
      "This server showed an update to its identity card that andvari can't verify. andvari ignored it and kept the card it had already checked. If this message stays, ask the operator what happened.",
    );
    expect(C.CARD_RECORD_DAMAGED_TITLE).toBe("andvari can't read its record of this server");
    expect(fill(C.CARD_RECORD_DAMAGED, ORIGIN).split("\n")).toEqual([
      "The record this device keeps of the identity of https://vault.example.org is damaged, or comes from a newer version of andvari. Without it andvari can't tell whether this is still the same server, so it has stopped using it on this device.",
      "If you went back to an older version of andvari, update it. Otherwise choose Forget this server and connect again. That removes this server's data from this device, including changes that hadn't synced. Your account on the server is not affected.",
    ]);
    expect(C.CARD_MOVED_UPDATE).toBe("This server says it moved. Update andvari.");
    for (const s of [C.CARD_OTHER_ADDRESS_TITLE, C.CARD_OTHER_ADDRESS, C.CARD_NOT_VERIFIED, C.CARD_RECORD_DAMAGED_TITLE, C.CARD_RECORD_DAMAGED]) expect(EXT).toContain(JSON.stringify(s));
    for (const k of ["CARD_OTHER_ADDRESS_TITLE", "CARD_NOT_VERIFIED", "CARD_RECORD_DAMAGED_TITLE", "GATE_TITLE_KIND_CHANGE", "CARD_MOVED_UPDATE"]) {
      const at = COPY.indexOf(`export const ${k} =`);
      const doc = COPY.slice(COPY.lastIndexOf("/**", at), at);
      expect(doc, k).not.toContain("PLACEHOLDER");
    }
    // The placeholder entry 12 replaces is gone.
    expect(COPY).not.toContain("HELD_NO_PIN");
  });

  it("a newer card that does not verify: entry 11 where CARD_WITHHELD shows; the pin stays, nothing stops, nothing is followed", async () => {
    const ctx = await pinned(server, ORIGIN, 2);
    const before = ctx.pins.pinFor(ORIGIN)!;
    server.served = [BASE[0]!, BAD_CARD_1];
    const s = await settlePin(ctx.pins, ORIGIN);
    expect(s.kind).toBe("pinned");
    if (s.kind !== "pinned") return;
    expect(s.notice?.kind).toBe("not_verified");
    expect(cardNoticeText(s.notice)).toBe(C.CARD_NOT_VERIFIED);
    // Choices: none of its own; the forms work on under the pin it had already checked.
    expect(s.pin).toEqual(before);
    expect(ctx.pins.pinFor(ORIGIN)).toEqual(before);
    expect(ctx.pins.state(ORIGIN).kind).toBe("pinned");
    // What left: the chain's own GET, no credential.
    expect(server.requests).toEqual(["GET /api/v1/instance"]);
    expect(server.credentialed).toEqual([]);
  });

  it("a card that does not verify at first contact: no pin, the stop's sentence and Try again, only the chain fetched", async () => {
    server.served = [BASE[0]!, BAD_CARD_1];
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), null);
    const r = await signInOf(ctx);
    expect(r.kind).toBe("pin");
    if (r.kind !== "pin") return;
    const html = markup(createElement(PinStop, { ctx, first: r.first.first, onRetry: () => {} }));
    expect(html).toContain(C.CARD_REFUSED);
    expect(buttons(html)).toEqual(["Try again"]);
    expect(ctx.pins.state(ORIGIN).kind).toBe("none");
    expect(server.requests).toEqual(["GET /api/v1/instance"]);
    expect(server.credentialed).toEqual([]);
  });

  it("an older card served (withheld): CARD_WITHHELD, the newer pin kept, nothing stops", async () => {
    const ctx = await pinned(server, ORIGIN, 2);
    const before = ctx.pins.pinFor(ORIGIN)!;
    server.served = [BASE[0]!];
    const s = await settlePin(ctx.pins, ORIGIN);
    expect(s.kind === "pinned" && s.notice?.kind).toBe("withheld");
    expect(cardNoticeText(s.kind === "pinned" ? s.notice : null)).toBe("This server is showing an older version of its identity card");
    expect(ctx.pins.pinFor(ORIGIN)).toEqual(before);
    expect(server.requests).toEqual(["GET /api/v1/instance"]);
    expect(server.credentialed).toEqual([]);
  });

  it("a fork: CARD_FORK, Forget this server (it says it deletes the copy), and nothing at all leaves afterwards", async () => {
    const ctx = await pinned(server, ORIGIN, 2);
    server.served = OTHER;
    const s = await settlePin(ctx.pins, ORIGIN);
    expect(s.kind).toBe("stop");
    if (s.kind !== "stop") return;
    const html = markup(createElement(PinStop, { ctx, first: s.first, onRetry: () => {} }));
    expect(html).toContain(C.CARD_FORK);
    expect(html).toContain(C.FORGET_DELETES_COPY);
    expect(buttons(html)).toEqual([C.FORGET_THIS_SERVER]);
    server.requests.length = 0;
    expect((await signInOf(ctx)).kind).toBe("pin");
    await expect(ctx.wire.accountKeys()).rejects.toBeInstanceOf(TrafficStoppedError);
    expect(server.requests).toEqual([]);
  });

  it("a fork marked by another refresh while this one's answer was on its way still stops (App's policy probe races the card)", async () => {
    const ctx = await pinned(server, ORIGIN, 2);
    server.served = OTHER;
    // Two refreshes at once, as App's policy probe and the Welcome card make them on a page load: the first one's
    // answer is held until the second has found the fork and marked it.
    let release: () => void = () => {};
    server.holdNext = new Promise<void>((r) => (release = r));
    const x = settlePin(ctx.pins, ORIGIN);
    await new Promise((r) => setTimeout(r, 0));
    const y = await settlePin(ctx.pins, ORIGIN);
    expect(ctx.pins.state(ORIGIN).kind).toBe("forked");
    release();
    expect([(await x).kind, y.kind]).toEqual(["stop", "stop"]);
  });

  it("a move: §13's line naming the new address, no way to follow it from the web, the pin kept at its card and origin", async () => {
    const ctx = await pinned(server, ORIGIN, 2);
    const before = ctx.pins.pinFor(ORIGIN)!;
    server.served = BASE.slice(0, 3);
    const s = await settlePin(ctx.pins, ORIGIN);
    expect(s.kind === "pinned" && s.notice?.kind).toBe("moved");
    expect(cardNoticeText(s.kind === "pinned" ? s.notice : null)).toBe("This server says it moved to https://vault2.example.org:8443");
    expect(ctx.pins.pinFor(ORIGIN)).toEqual(before);
    expect(ctx.pins.state(ORIGIN2).kind).toBe("none");
    // The web has no way to follow a move (another origin serves its own web client), so entry 13 (a followed move
    // refused) never arises here: the pin store has no follow call at all.
    expect(Object.getOwnPropertyNames(PinStore.prototype).filter((n) => /move|follow/i.test(n))).toEqual([]);
    expect(server.requests).toEqual(["GET /api/v1/instance"]);
    expect(server.credentialed).toEqual([]);
  });

  it("another address (origin_mismatch): entry 8 with both addresses, no buttons, no pin made, only the chain fetched", async () => {
    server.served = BASE.slice(0, 3);
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), null);
    const r = await signInOf(ctx);
    expect(r.kind).toBe("pin");
    if (r.kind !== "pin") return;
    expect(r.first.first).toEqual({ kind: "refused", verdict: "origin_mismatch", cardOrigin: ORIGIN2 });
    const html = markup(createElement(PinStop, { ctx, first: r.first.first, onRetry: () => {} }));
    expect(html).toContain(`<strong>${C.CARD_OTHER_ADDRESS_TITLE}</strong>`);
    expect(html).toContain(fill(C.CARD_OTHER_ADDRESS, ORIGIN, ORIGIN2));
    expect(html).toContain('role="alert"');
    expect(buttons(html)).toEqual([]);
    expect(ctx.pins.state(ORIGIN).kind).toBe("none");
    expect(server.requests).toEqual(["GET /api/v1/instance"]);
    expect(server.credentialed).toEqual([]);
  });

  it("another address on the baked public instance: core's CARD_MOVED_UPDATE instead, as entry 8 says", async () => {
    server.served = BASE.slice(0, 3);
    const baked = { origin: ORIGIN, instanceId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", card0Hash: BASE_CARD0_HASH, kind: "private" as const };
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, memoryStorage(), baked);
    const r = await signInOf(ctx);
    if (r.kind !== "pin") throw new Error(r.kind);
    expect(r.first.first).toEqual({ kind: "refused", verdict: "origin_mismatch", cardOrigin: ORIGIN2 });
    const html = markup(createElement(PinStop, { ctx, first: r.first.first, onRetry: () => {} }));
    expect(html).toContain(C.CARD_MOVED_UPDATE);
    expect(html).not.toContain(C.CARD_OTHER_ADDRESS_TITLE);
    expect(buttons(html)).toEqual([]);
  });

  it("a change of kind: entry 10's title over GATE_KIND_CHANGE, Continue and Not now; the old kind holds until Continue, which fetches only the chain", async () => {
    const ctx = await pinned(server, ORIGIN2, 7);
    expect(ctx.pins.pinFor(ORIGIN2)!.kind).toBe("private");
    server.served = BASE.slice(0, 8);
    const s = await settlePin(ctx.pins, ORIGIN2);
    if (s.kind !== "pinned" || s.notice?.kind !== "kind_changed") throw new Error(JSON.stringify(s));
    expect(s.notice.mustUpdate).toBe(false);
    expect(cardNoticeText(s.notice)).toBeNull(); // the gate, not a line
    const newest: WebPin = s.notice.newest;
    const html = markup(createElement(KindChangeGate, { newest, busy: false, onContinue: () => {}, onNotNow: () => {} }));
    expect(html).toContain(`<h2>${C.GATE_TITLE_KIND_CHANGE}</h2>`);
    expect(html).toContain("<p>Example Vault (https://vault2.example.org:8443) now says it is a public server. This changes who can be offered operator recovery. Continue only if you expected this.</p>");
    expect(buttons(html)).toEqual(["Continue", "Not now"]);
    // Until Continue the old kind stays in force.
    expect(ctx.pins.pinFor(ORIGIN2)!.kind).toBe("private");
    expect(server.credentialed).toEqual([]);
    server.requests.length = 0;
    const accepted = await ctx.pins.acceptKindChange(ORIGIN2, { newestHash: newest.hash });
    expect(accepted.kind).toBe("ok");
    expect(ctx.pins.pinFor(ORIGIN2)!.kind).toBe("public");
    expect(server.requests).toEqual(["GET /api/v1/instance"]);
    expect(server.credentialed).toEqual([]);
    // The screen: while the gate stands no form is rendered (so nothing derived from a password can be asked for);
    // Not now goes on under the PINNED card, the old kind, with no notice.
    const settled = WELCOME.slice(WELCOME.indexOf("function PinSettled("), WELCOME.indexOf("export function KindChangeGate("));
    expect(settled).toContain("return <KindChangeGate newest={newest} busy={busy} onContinue={() => void accept()} onNotNow={() => setView({ kind: \"ready\", pin: view.status.pinned, notice: null })} />;");
    expect(settled.indexOf('if (view.kind === "kind_gate")')).toBeGreaterThan(settled.indexOf('if (view.kind === "ready") return children(view.pin, view.notice);'));
  });

  it("a change of kind that also moves: accepted on this origin only (its card kept), then reported as a move", async () => {
    const ctx = await pinned(server, ORIGIN, 2);
    server.served = BASE.slice(0, 8);
    const s = await settlePin(ctx.pins, ORIGIN);
    if (s.kind !== "pinned" || s.notice?.kind !== "kind_changed") throw new Error(JSON.stringify(s));
    expect((await ctx.pins.acceptKindChange(ORIGIN, { newestHash: s.notice.newest.hash })).kind).toBe("ok");
    const pin = ctx.pins.pinFor(ORIGIN)!;
    expect([pin.origin, pin.seq, pin.kind]).toEqual([ORIGIN, 1, "public"]);
    const next = await settlePin(ctx.pins, ORIGIN);
    expect(cardNoticeText(next.kind === "pinned" ? next.notice : null)).toBe(`This server says it moved to ${ORIGIN2}`);
    expect(server.credentialed).toEqual([]);
  });

  it("a kind change of the baked instance is never gated: core's CARD_CHANGED_UPDATE line", () => {
    const pin = { root: "baked" } as WebPin;
    expect(cardNoticeText({ kind: "kind_changed", pinned: pin, newest: pin, mustUpdate: true })).toBe(C.CARD_CHANGED_UPDATE);
  });

  it("a damaged record: entry 12's title, the origin, two paragraphs and only Forget this server; no copy to open; nothing leaves", async () => {
    const storage = memoryStorage();
    storage.set(`andvari.pin2.${ORIGIN}`, "{not a record");
    const ctx = createWebContext(new ApiClient(ORIGIN), ORIGIN, storage, null);
    const s = await settlePin(ctx.pins, ORIGIN);
    expect(s).toEqual({ kind: "stop", first: { kind: "blocked", state: { kind: "damaged" } } });
    if (s.kind !== "stop") return;
    const held = { session: { userId: "u", email: "bea@example.org" } as never, onReady: () => {}, onForget: () => {} };
    const html = markup(createElement(PinStop, { ctx, first: s.first, held, onRetry: () => {} }));
    const [p1, p2] = fill(C.CARD_RECORD_DAMAGED, ORIGIN).split("\n");
    expect(html).toContain(`<h2>${C.CARD_RECORD_DAMAGED_TITLE}</h2>`);
    expect(html).toContain(`<strong class="mono">${ORIGIN}</strong>`);
    expect(html).toContain(`<p>${p1}</p><p>${p2}</p>`);
    expect(buttons(html)).toEqual([C.FORGET_THIS_SERVER]);
    expect(html).not.toContain("<input"); // no read-only copy: a record that checks nothing stays blocked (§4.4)
    expect(html).not.toContain(C.CARD_FORK);
    expect(html).not.toContain(C.FORGET_DELETES_COPY); // entry 12's own body says what forgetting removes
    expect((await signInOf(ctx)).kind).toBe("pin");
    await expect(ctx.wire.accountKeys()).rejects.toBeInstanceOf(TrafficStoppedError);
    await expect(ctx.wire.instance()).rejects.toBeInstanceOf(TrafficStoppedError);
    expect(server.requests).toEqual([]);
  });

  it("Forget this server on a stop fetches the server's settings again (the stop held them back too)", () => {
    const stop = WELCOME.slice(WELCOME.indexOf("export function PinStop("), WELCOME.indexOf("function HeldCopyUnlock("));
    expect(stop).toMatch(/else \{\s*onRetry\(\);[\s\S]*?onForgotten\?\.\(\);\s*\}/);
    expect(WELCOME).toContain("onForgotten={() => void p.onRetryPolicy()}");
    expect(WELCOME).toContain("<PinStop ctx={ctx} first={first} held={held} onRetry={() => void check()} onForgotten={onForgotten} />");
  });

  it("a kept session at an origin with no pin record shows entry 12 too, as core's engine shows its orphan", () => {
    const held = WELCOME.slice(WELCOME.indexOf("function HeldWithoutPin("), WELCOME.indexOf("export function PinStop("));
    expect(held).toContain("return <RecordDamaged origin={ctx.origin} onForget={() => void forget()} userId={held.session.userId} />;");
  });
});
