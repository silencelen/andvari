// The server choice and its card pin (design 2026-11-15-onboarding-trust §4.4, §12.2, §12.4, §15): the origin grammar
// at the input, no default server, the pin-store rules as pure transitions, worker start's server state and its blocks,
// the device object a sign-in sends, the `/instance` body parser, the operator key's display form, the first-launch
// wipe, and the baked public instance pinned to spec/public-instance.json with its release gate.
import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { canonicalizeServerUrl, getServerUrl, NO_SERVER_ORIGIN, nsKey, originKeyFor, originMatchPattern, setServerUrl, SERVER_URL_KEY } from "./serverurl.ts";
import { confirmKindChange, confirmMove, decodeStoredPin, newStoredPin, PIN_KEY, refreshPin } from "./pinstore.ts";
import { autofillExcludeMatches, dialRefusal, loadServerState } from "./serverstate.ts";
import { decodeDeviceRecord, deviceObject, emailNorm, newDeviceRecord } from "./device.ts";
import { displayX25519Image, fetchInstanceChain, INSTANCE_BODY_MAX_BYTES, operatorShortFp, parseInstanceBody } from "./cardfetch.ts";
import { FORMAT_KEY, STORE_FORMAT, wipeOldFormatOnce } from "./formatwipe.ts";
import { bakedRoot, isBakedInstance, PUBLIC_INSTANCE } from "./publicinstance.ts";
import { publicInstanceReleaseProblem } from "./releasegate.ts";
import { comparePinned, MAX_FIRST_PIN_CARDS, pinRecordOf, verifyChain, verifyForward } from "./instancecard.ts";
import { b64Encode, b64Strict, isDnsHost } from "./statement.ts";
import { chooseServerCopy, chooseServerMessage, fillApproved, SERVER_REDIRECTS, SERVER_REDIRECTS_TO } from "./errors.ts";
import { TrustedStoreUnavailable, type KvArea } from "./trustedkv.ts";

const vectorsDir = fileURLToPath(new URL("../../spec/test-vectors/", import.meta.url));
const ic = JSON.parse(readFileSync(vectorsDir + "instancecard.json", "utf-8"));
const enc = JSON.parse(readFileSync(vectorsDir + "encodings.json", "utf-8"));
const sv = JSON.parse(readFileSync(vectorsDir + "statement-v2.json", "utf-8"));
const publicJson = JSON.parse(readFileSync(new URL("../../spec/public-instance.json", import.meta.url), "utf-8"));
const frame = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const base = ic.chains[0].cards.map((c: { frameB64: string }) => frame(c.frameB64));
const cards = (n: number) => {
  const r = verifyChain(base.slice(0, n));
  assert.ok(r.ok);
  return r.cards;
};

function memKv(init: Record<string, unknown> = {}): KvArea & { data: Record<string, unknown> } {
  const data: Record<string, unknown> = { ...init };
  return {
    data,
    async get(keys) {
      if (keys === null) return { ...data };
      const ks = typeof keys === "string" ? [keys] : keys;
      return Object.fromEntries(ks.filter((k) => k in data).map((k) => [k, data[k]]));
    },
    async set(items) {
      Object.assign(data, items);
    },
    async remove(keys) {
      for (const k of typeof keys === "string" ? [keys] : keys) delete data[k];
    },
  };
}

test("§2.2: typed addresses are canonicalized, then the grammar decides (R4)", () => {
  assert.equal(canonicalizeServerUrl("https://Vault.Example.org/"), "https://vault.example.org");
  assert.equal(canonicalizeServerUrl("vault.example.org"), "https://vault.example.org");
  assert.equal(canonicalizeServerUrl("https://vault.example.org:443"), "https://vault.example.org");
  assert.equal(canonicalizeServerUrl("https://vault.example.org:8443"), "https://vault.example.org:8443");
  assert.equal(canonicalizeServerUrl("http://localhost:8080"), "http://localhost:8080");
  for (const bad of ["https://192.168.1.9", "http://192.168.1.9:8080", "https://[::1]", "https://intranet", "https://a.example/path", "https://a.example/?q", "https://u@a.example", "ftp://a.example", "http://a.example", "https://a.example."]) {
    assert.equal(canonicalizeServerUrl(bad), null, bad);
  }
  // Every grammar-valid origin of the vectors canonicalizes to itself.
  for (const r of enc.origin.filter((x: { valid: boolean }) => x.valid)) assert.equal(canonicalizeServerUrl(r.origin), r.origin, r.origin);
});

test("§0.2 O / §15: no default server — the placeholder origin until one is chosen, never stored", async () => {
  assert.equal(await getServerUrl(memKv()), NO_SERVER_ORIGIN);
  assert.equal(await getServerUrl(memKv({ [SERVER_URL_KEY]: "http://10.0.0.1" })), NO_SERVER_ORIGIN, "a value outside the grammar reads as none");
  const kv = memKv();
  assert.equal(await setServerUrl("https://vault.example.org", kv), "https://vault.example.org");
  await assert.rejects(setServerUrl(NO_SERVER_ORIGIN, kv));
  await assert.rejects(setServerUrl("http://10.0.0.1", kv));
  assert.equal(originMatchPattern("https://vault.example.org:8443"), "https://vault.example.org/*");
  assert.equal(originMatchPattern("https://10.0.0.1"), null);
});

test("§4.4: a pin record decodes exactly, and anything else is damaged (never 'no pin')", () => {
  const rec = newStoredPin("typed", pinRecordOf(cards(2)[1]!, cards(1)[0]!.hash));
  const at = rec.pin.origin;
  assert.deepEqual(decodeStoredPin(JSON.parse(JSON.stringify(rec)), at), { kind: "pin", stored: rec });
  assert.deepEqual(decodeStoredPin(undefined, at), { kind: "none" });
  for (const bad of [null, "x", { ...rec, v: 2 }, { ...rec, root: "kit" }, { ...rec, fork: "no" }, { ...rec, pin: { ...rec.pin, origin: "http://10.0.0.1" } }, { ...rec, pin: { ...rec.pin, extra: 1 } }, { ...rec, pending: { change: "rename", card: rec.pin } }]) {
    assert.deepEqual(decodeStoredPin(bad, at), { kind: "damaged" }, JSON.stringify(bad).slice(0, 80));
  }
});

test("A pin read under another origin's namespace is damaged, never in force", () => {
  const rec = newStoredPin("typed", pinRecordOf(cards(2)[1]!, cards(1)[0]!.hash));
  assert.equal(decodeStoredPin(rec, "https://elsewhere.example").kind, "damaged");
  // A pending move names another origin: that is the prompt, not damage.
  const moved = refreshPin(rec, cards(3)).stored;
  assert.equal(moved.pending?.change, "move");
  assert.equal(decodeStoredPin(moved, rec.pin.origin).kind, "pin");
});

test("§4.4: a card that changes both kind and origin is a kind change; accepting it keeps the pin at its card, and the move is its own prompt", () => {
  const c0 = cards(1)[0]!.hash;
  const pinAt1 = newStoredPin("typed", pinRecordOf(cards(2)[1]!, c0));
  // The vectors' card 2 moves; served as a card that also changes the kind, the change is a kind change.
  const card2 = cards(3)[2]!;
  const both = { ...card2, kind: card2.kind === "public" ? ("private" as const) : ("public" as const) };
  const kindFirst = refreshPin(pinAt1, [...cards(2), both]);
  assert.equal(kindFirst.verdict, "pending");
  assert.equal(kindFirst.stored.pending?.change, "kind");
  const accepted = confirmKindChange(kindFirst.stored)!;
  assert.equal(accepted.pin.origin, pinAt1.pin.origin, "the pin stays under its own origin");
  assert.equal(accepted.pin.seq, 1, "the pin stays at its card");
  assert.equal(accepted.pin.hash, pinAt1.pin.hash);
  assert.equal(accepted.pin.kind, both.kind, "the accepted kind is recorded");
  assert.equal(accepted.pending, null);
  assert.equal(decodeStoredPin(JSON.parse(JSON.stringify(accepted)), pinAt1.pin.origin).kind, "pin", "what is stored reads back under its namespace");
  // The next refresh offers the move on its own.
  const thenMove = refreshPin(accepted, [...cards(2), both]);
  assert.equal(thenMove.stored.pending?.change, "move");
  assert.equal(thenMove.stored.pending?.card.origin, both.origin);
  // A kind change without a move still advances the pin to the newest card.
  const pinAt2 = newStoredPin("typed", pinRecordOf(cards(7)[6]!, c0));
  const kindOnly = refreshPin(pinAt2, cards(8));
  assert.equal(kindOnly.stored.pending?.change, "kind");
  assert.equal(confirmKindChange(kindOnly.stored)?.pin.seq, 7);
});

test("§4.4: a refresh advances through renames, waits on a move or kind change, and a fork is durable", () => {
  const c0 = cards(1)[0]!.hash;
  const pinAt1 = newStoredPin("typed", pinRecordOf(cards(2)[1]!, c0));
  // card 1 → card 2 is a move: pending, the pin stays at card 1.
  const moved = refreshPin(pinAt1, cards(3));
  assert.equal(moved.verdict, "pending");
  assert.equal(moved.stored.pin.seq, 1);
  assert.equal(moved.stored.pending?.change, "move");
  const followed = confirmMove(moved.stored);
  assert.equal(followed?.origin, "https://vault2.example.org:8443");
  assert.equal(followed?.stored.pin.seq, 2);
  // a pin at card 2 advances silently through the recovery and handover cards (3..6), then card 7 changes the kind.
  const pinAt2 = newStoredPin("typed", pinRecordOf(cards(3)[2]!, c0));
  const advanced = refreshPin(pinAt2, cards(7));
  assert.equal(advanced.verdict, "ok");
  assert.equal(advanced.stored.pin.seq, 6);
  const kind = refreshPin(advanced.stored, cards(8));
  assert.equal(kind.verdict, "pending");
  assert.equal(kind.stored.pending?.change, "kind");
  assert.equal(confirmKindChange(kind.stored)?.pin.kind, "public");
  // withheld: the chain ends below the pin; nothing changes.
  assert.deepEqual(refreshPin(advanced.stored, cards(3)), { stored: advanced.stored, verdict: "withheld" });
  // a fork: card 0 of another chain; stored, and stays a fork whatever is served next.
  const other = verifyChain([frame(ic.chains[1].cards[0].frameB64)]);
  assert.ok(other.ok);
  const forked = refreshPin(pinAt1, other.cards);
  assert.equal(forked.verdict, "fork");
  assert.equal(forked.stored.fork, true);
  assert.equal(refreshPin(forked.stored, cards(8)).verdict, "fork");
  assert.equal(confirmMove(forked.stored), null);
});

test("§4.4 T-R7: the baked public instance never follows a move or a kind change", () => {
  // The vectors' base chain served under a pin keyed as the baked instance (its origin is the baked one): card 2 is a
  // move, and card 7 a kind change. Neither is followed; the pin stays where it was.
  const base0 = cards(1)[0]!;
  const baked = newStoredPin("baked", { ...pinRecordOf(cards(2)[1]!, base0.hash), origin: PUBLIC_INSTANCE.origin });
  assert.ok(isBakedInstance(baked.pin));
  for (const n of [3, 8]) {
    const r = refreshPin(baked, cards(n));
    assert.equal(r.verdict, "changed");
    assert.equal(r.stored.changed, true);
    assert.equal(r.stored.pending, null);
    assert.deepEqual(r.stored.pin, baked.pin);
  }
  // The same chain under an ordinary pin prompts instead.
  const own = newStoredPin("typed", pinRecordOf(cards(2)[1]!, base0.hash));
  assert.equal(refreshPin(own, cards(3)).verdict, "pending");
});

test("worker start: the server state and its blocks; every dialing message is refused while one stands", async () => {
  const origin = "https://vault.example.org";
  const pin = newStoredPin("typed", pinRecordOf(cards(2)[1]!, cards(1)[0]!.hash));
  const key = nsKey(originKeyFor(origin), PIN_KEY);
  assert.deepEqual((await loadServerState("ok", memKv())).block, { kind: "no_server" });
  assert.deepEqual((await loadServerState("ok", memKv({ [SERVER_URL_KEY]: origin }))).block, { kind: "no_server" }, "a server with no pin");
  assert.equal((await loadServerState("ok", memKv({ [SERVER_URL_KEY]: origin, [key]: pin }))).block, null);
  assert.deepEqual((await loadServerState("ok", memKv({ [SERVER_URL_KEY]: origin, [key]: { v: 9 } }))).block, { kind: "pin_damaged", origin });
  assert.deepEqual((await loadServerState("ok", memKv({ [SERVER_URL_KEY]: origin, [key]: { ...pin, fork: true } }))).block, { kind: "fork", origin });
  assert.deepEqual((await loadServerState("unavailable", memKv())).block, { kind: "no_store" });
  assert.deepEqual((await loadServerState("timedOut", memKv())).block, { kind: "unsettled" });
  // Safari holds no pin: a chosen server is in effect.
  assert.equal((await loadServerState("ok", memKv({ [SERVER_URL_KEY]: origin }), false)).block, null);
  for (const t of ["unlock", "unlockTotp", "unlockWithPin", "unlockWithBio", "ping"]) {
    assert.deepEqual(dialRefusal(t, { kind: "fork", origin }), { ok: false, code: "confirm_server" });
    assert.equal(dialRefusal(t, null), null);
  }
  assert.equal(dialRefusal("status", { kind: "no_server" }), null);
  assert.deepEqual(autofillExcludeMatches(origin, null, PUBLIC_INSTANCE.origin), ["https://vault.example.org/*", "https://vault.andvaripass.com/*"]);
  assert.equal(autofillExcludeMatches(origin, { kind: "unsettled" }, PUBLIC_INSTANCE.origin), null);
});

test("§8.7: the device object, with a secret this browser keeps and the device row it was given", () => {
  const rec = newDeviceRecord();
  assert.equal(b64Strict(rec.deviceSecret)?.length, 32);
  assert.deepEqual(deviceObject(rec), { platform: "extension", name: "Browser extension", deviceSecret: rec.deviceSecret });
  const known = { deviceSecret: rec.deviceSecret, deviceId: "11111111-1111-4111-8111-111111111111" };
  assert.deepEqual(decodeDeviceRecord(known), known);
  assert.equal(deviceObject(known).deviceId, known.deviceId);
  for (const bad of [null, { deviceSecret: "x", deviceId: null }, { deviceSecret: rec.deviceSecret, deviceId: "nope" }]) assert.equal(decodeDeviceRecord(bad), null);
  // emailNorm keys the record: the vectors' rows.
  for (const r of enc.emailNorm) assert.equal(emailNorm(r.input), r.expect.verdict === "ok" ? r.expect.emailNorm : null, r.why);
});

test("§2.3: every emailNorm row is graded, and the address's domain is the origin type's host grammar", () => {
  assert.equal(enc.emailNorm.length, 127, "all 127 rows of encodings.json");
  let graded = 0;
  for (const r of enc.emailNorm) {
    assert.deepEqual(Object.keys(r).sort(), ["expect", "input", "why"], r.why);
    const ok = r.expect.verdict === "ok";
    assert.deepEqual(Object.keys(r.expect).sort(), ok ? ["emailNorm", "verdict"] : ["verdict"], r.why);
    if (!ok) assert.equal(r.expect.verdict, "invalid_email", r.why);
    assert.equal(emailNorm(r.input), ok ? r.expect.emailNorm : null, r.why);
    graded++;
  }
  assert.equal(graded, 127);
  // One host grammar: an https origin's host and an address's domain agree, over the origin rows' hosts.
  let hosts = 0;
  for (const r of enc.origin) {
    const m = /^https:\/\/([^:/]*)$/.exec(r.origin);
    if (m === null) continue; // a port, a path, or not https: the origin type's own rows
    hosts++;
    assert.equal(isDnsHost(m[1]!), r.valid, r.why);
    // 254 octets in all; an address is stripped and lowercased before its domain is judged, an origin never is.
    if (m[1]!.length <= 252 && /^[\x21-\x7e]*$/.test(m[1]!) && !/[A-Z@]/.test(m[1]!)) assert.equal(emailNorm(`a@${m[1]}`) !== null, r.valid, r.why); // 254 octets in all
  }
  assert.ok(hosts > 10, "the origin rows hold plain https hosts to compare");
  for (const d of ["localhost", "127.0.0.1", "example", "1.2.3.4", "example.0x1f", "a-.example", "a..example"]) assert.equal(isDnsHost(d), false, d);
  assert.equal(emailNorm("a@b"), null, "row 5: a one-label domain");
  assert.equal(emailNorm("a@b.c"), "a@b.c");
  assert.equal(emailNorm(`${"x".repeat(65)}@example.com`), null, "a 65-character local part");
});

test("GET /instance: the body is parsed strictly; a fetch carries no credential", async () => {
  assert.deepEqual(parseInstanceBody('{"cards":[],"setup":{}}'), { ok: true, frames: [] });
  assert.deepEqual(parseInstanceBody('{"cards":["AA=="]}'), { ok: false, code: "card_invalid" });
  assert.deepEqual(parseInstanceBody("[]"), { ok: false, code: "card_invalid" });
  assert.deepEqual(parseInstanceBody("{}"), { ok: false, code: "card_invalid" });
  const seen: { url: string; headers: Record<string, string> }[] = [];
  const got = await fetchInstanceChain("https://vault.example.org", "extension/9.9.9", async (url, init) => {
    seen.push({ url, headers: init.headers });
    return new Response(JSON.stringify({ cards: ic.chains[0].cards.slice(0, 2).map((c: { frameB64: string }) => c.frameB64) }));
  });
  assert.ok(got.ok && got.frames.length === 2);
  assert.deepEqual(seen, [{ url: "https://vault.example.org/api/v1/instance", headers: { "X-Andvari-Client": "extension/9.9.9" } }]);
  assert.deepEqual(await fetchInstanceChain("https://x.example", "e", async () => new Response("", { status: 503 })), { ok: false, code: "unavailable" });
  assert.deepEqual(await fetchInstanceChain("https://x.example", "e", async () => { throw new TypeError("offline"); }), { ok: false, code: "unavailable" });
});

test("review of 2026-11-17: the first contact with a typed address follows no redirect, and says where one points when it can be read", async () => {
  const inits: (RequestRedirect | undefined)[] = [];
  const answer = (resp: Response) => async (_url: string, init: { redirect?: RequestRedirect }) => {
    inits.push(init.redirect);
    return resp;
  };
  // A redirect the browser lets the worker read: the address it points to, resolved against the one asked.
  assert.deepEqual(
    await fetchInstanceChain("https://vault.example.org", "e", answer(new Response(null, { status: 302, headers: { Location: "https://elsewhere.example/api/v1/instance" } }))),
    { ok: false, code: "redirected", to: "https://elsewhere.example/api/v1/instance" },
  );
  assert.deepEqual(await fetchInstanceChain("https://vault.example.org", "e", answer(new Response(null, { status: 307, headers: { Location: "/moved" } }))), { ok: false, code: "redirected", to: "https://vault.example.org/moved" });
  // What a browser gives under `redirect: "manual"`: an opaque answer, whose target it hides. Said as a redirect all the same.
  const opaque = new Response(null, { status: 200 });
  Object.defineProperty(opaque, "type", { value: "opaqueredirect" });
  assert.deepEqual(await fetchInstanceChain("https://vault.example.org", "e", answer(opaque)), { ok: false, code: "redirected", to: null });
  // A target that is not an http(s) address is not shown.
  assert.deepEqual(await fetchInstanceChain("https://vault.example.org", "e", answer(new Response(null, { status: 301, headers: { Location: "javascript:alert(1)" } }))), { ok: false, code: "redirected", to: null });
  assert.ok(inits.every((r) => r === "manual"), "every fetch asks the browser to follow nothing");
  // The popup and the options page say it, naming the address where it is known.
  assert.deepEqual(chooseServerMessage({ code: "redirected", redirectTo: "https://elsewhere.example/" }, PUBLIC_INSTANCE.origin), { title: null, body: fillApproved(SERVER_REDIRECTS_TO, "https://elsewhere.example/") });
  assert.deepEqual(chooseServerMessage({ code: "redirected" }, PUBLIC_INSTANCE.origin), { title: null, body: SERVER_REDIRECTS });
  assert.notEqual(chooseServerCopy("redirected"), chooseServerCopy(undefined));
});

test("a redirect at the first contact, over the real transport: an http address whose proxy sends it on to https is said with that address, and not followed", async () => {
  const { createServer } = await import("node:http");
  let followed = 0;
  const server = createServer((req, res) => {
    if (req.url === "/api/v1/instance") {
      res.writeHead(301, { location: "https://vault.example.org/api/v1/instance" });
      res.end();
    } else {
      followed++;
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  try {
    const port = (server.address() as { port: number }).port;
    const got = await fetchInstanceChain(`http://127.0.0.1:${port}`, "e"); // the real fetch
    assert.deepEqual(got, { ok: false, code: "redirected", to: "https://vault.example.org/api/v1/instance" });
    assert.equal(followed, 0);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("GET /instance is bounded in time, and its body is read through the cap", async () => {
  const within = <T>(p: Promise<T>, ms: number): Promise<T | "hung"> => Promise.race([p, new Promise<"hung">((r) => setTimeout(() => r("hung"), ms))]);
  // A server that never answers, and one that answers and then trickles its body forever.
  const never = async (): Promise<Response> => new Promise<Response>(() => {});
  assert.deepEqual(await within(fetchInstanceChain("https://x.example", "e", never, 50), 2000), { ok: false, code: "unavailable" });
  const trickle = async (): Promise<Response> =>
    new Response(new ReadableStream({ start: (c) => c.enqueue(new TextEncoder().encode('{"cards":[')) }), { status: 200 });
  assert.deepEqual(await within(fetchInstanceChain("https://x.example", "e", trickle, 50), 2000), { ok: false, code: "unavailable" });
  // A body over the cap is refused as it streams in: the reader stops pulling at the cap.
  let pulled = 0;
  const huge = async (): Promise<Response> =>
    new Response(
      new ReadableStream({
        pull: (c) => {
          pulled++;
          c.enqueue(new Uint8Array(64 * 1024));
        },
      }),
      { status: 200 },
    );
  assert.deepEqual(await within(fetchInstanceChain("https://x.example", "e", huge, 2000), 3000), { ok: false, code: "card_invalid" });
  assert.ok(pulled <= INSTANCE_BODY_MAX_BYTES / (64 * 1024) + 2, `stopped at the cap (${pulled} chunks)`);
  // A declared length over the cap is refused before reading.
  const declared = async (): Promise<Response> => new Response("{}", { status: 200, headers: { "content-length": String(INSTANCE_BODY_MAX_BYTES + 1) } });
  assert.deepEqual(await fetchInstanceChain("https://x.example", "e", declared), { ok: false, code: "card_invalid" });
});

test("verifyForward agrees with a whole-chain verify and comparePinned, from every pin of the vectors' chain", () => {
  const all = base as Uint8Array[];
  const whole = verifyChain(all);
  assert.ok(whole.ok);
  const c0 = whole.cards[0]!.hash;
  for (let at = 0; at < all.length; at++) {
    const pin = pinRecordOf(whole.cards[at]!, c0);
    for (let n = 0; n <= all.length; n++) {
      const served = all.slice(0, n);
      const fwd = verifyForward(served, pin);
      const full = verifyChain(served);
      assert.ok(full.ok && fwd.ok);
      const cmp = comparePinned(full.cards, pin);
      if (cmp.verdict !== "ok") assert.equal(fwd.verdict, cmp.verdict, `pin ${at}, ${n} cards`);
      else {
        assert.equal(fwd.verdict, "ok");
        assert.equal(fwd.verdict === "ok" ? (fwd.newest?.hash ?? pin.hash) : null, cmp.newest.hash, `pin ${at}, ${n} cards`);
      }
    }
  }
  // Only the cards after the pin are verified: a broken card after it is refused, one before it is not even read.
  const pinAt3 = pinRecordOf(whole.cards[3]!, c0);
  const broken = all.map((f) => f.slice());
  broken[5]![200] ^= 1;
  const v = verifyChain(broken);
  assert.ok(!v.ok && v.at === 5);
  assert.deepEqual(verifyForward(broken, pinAt3), { ok: false, verdict: v.verdict, at: 5 });
  const garbledPrefix = all.map((f, i) => (i === 2 ? new Uint8Array(5) : f));
  assert.equal(verifyForward(garbledPrefix, pinAt3).verdict, "ok", "the prefix is compared by hash, not parsed");
  assert.equal(MAX_FIRST_PIN_CARDS, 64);
});

test("the Trust Gate's operator key short form is the identity fingerprint over the key's X25519 image", () => {
  for (const k of Object.values(sv.keys as Record<string, { signPubB64?: string; identityPubB64?: string }>)) {
    if (!k.signPubB64 || !k.identityPubB64) continue;
    assert.equal(b64Encode(displayX25519Image(b64Strict(k.signPubB64)!)!), k.identityPubB64);
  }
  assert.match(operatorShortFp(ic.keys.operator.signPubB64), /^[0-9a-f]{32}$/);
});

test("§12.4: the first start of a new-format build deletes every old store once", async () => {
  const trusted = memKv({ serverUrl: "https://old.example", "ns.0123456789abcdef.quOfferDismissed": true });
  const local = memKv({ serverUrl: "https://old.example" });
  const session = memKv({ quickUnlock: "x" });
  assert.equal(await wipeOldFormatOnce(trusted, [local, session]), "ok");
  assert.deepEqual(trusted.data, { [FORMAT_KEY]: STORE_FORMAT });
  assert.deepEqual(local.data, {});
  assert.deepEqual(session.data, {});
  await trusted.set({ serverUrl: "https://new.example" });
  assert.equal(await wipeOldFormatOnce(trusted, [local, session]), "ok");
  assert.equal(trusted.data.serverUrl, "https://new.example", "once only");
  const refusing: KvArea = { get: async () => { throw new TrustedStoreUnavailable("no idb"); }, set: async () => {}, remove: async () => {} };
  assert.equal(await wipeOldFormatOnce(refusing, []), "unavailable");
  const hung: KvArea = { get: async () => { throw new TrustedStoreUnavailable("slow", true); }, set: async () => {}, remove: async () => {} };
  assert.equal(await wipeOldFormatOnce(hung, []), "timedOut");
});

test("The first-launch wipe clears the key databases, and storage.local and storage.session with no trusted store", async () => {
  const trusted = memKv({ serverUrl: "https://old.example" });
  const coKey = memKv({ "ns.0123456789abcdef.k_nonexp": "old co-key" });
  const sealKey = memKv({ sealKey: "old seal key" });
  assert.equal(await wipeOldFormatOnce(trusted, [memKv()], [coKey, sealKey]), "ok");
  assert.deepEqual(coKey.data, {}, "the quick-unlock co-key database");
  assert.deepEqual(sealKey.data, {}, "the session-seal key database");
  // No trusted store at all: storage.local and storage.session are cleared anyway.
  const refusing: KvArea = { get: async () => { throw new TrustedStoreUnavailable("no idb"); }, set: async () => {}, remove: async () => {} };
  const local = memKv({ serverUrl: "https://old.example" });
  const session = memKv({ session: "old snapshot" });
  assert.equal(await wipeOldFormatOnce(refusing, [local, session]), "unavailable");
  assert.deepEqual(local.data, {});
  assert.deepEqual(session.data, {});
  // A store that only timed out exists: it is left for the next start, and so are the others.
  const hung: KvArea = { get: async () => { throw new TrustedStoreUnavailable("slow", true); }, set: async () => {}, remove: async () => {} };
  const kept = memKv({ session: "live snapshot" });
  assert.equal(await wipeOldFormatOnce(hung, [kept]), "timedOut");
  assert.deepEqual(kept.data, { session: "live snapshot" });
});

test("§0.3: the baked public instance is spec/public-instance.json's, and a placeholder refuses a release", () => {
  for (const k of ["origin", "instanceId", "card0Hash", "kind", "name"] as const) assert.equal(PUBLIC_INSTANCE[k], publicJson.PUBLIC_INSTANCE[k], k);
  const placeholder = Object.values(PUBLIC_INSTANCE).some((v) => v.startsWith("PLACEHOLDER:"));
  assert.equal(bakedRoot() === null, placeholder, "no baked root while a placeholder stands");
  assert.equal(publicInstanceReleaseProblem() !== null, placeholder);
  const pkg = readFileSync(new URL("../package.mjs", import.meta.url), "utf-8");
  assert.match(pkg, /if \(!check\) \{\s*const baked = publicInstanceReleaseProblem\(\);\s*if \(baked !== null\) throw new Error\(baked\);/);
});
