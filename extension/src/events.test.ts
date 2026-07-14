// events.ts engine tests (node --test, chrome-free — sockets and tickets are injected fakes).
// Covers the design 2026-07-13-ext-live-sync.md §8 plan E1–E10: single-flight connect, fresh
// ticket per attempt, jittered backoff + cap + reset, the mint-null stop, revoked teardown,
// bell debounce, the 20 s keepalive, and close() idempotence. Mock timers make the delays
// deterministic (rand: () => 1 pins jitter at the top of the [base/2, base] window = base).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { startEvents, type EventsDeps, type WsLike } from "./events.ts";

class FakeSocket implements WsLike {
  readyState = 0; // CONNECTING
  url: string;
  sent: string[] = [];
  closeCalls = 0;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(): void {
    this.closeCalls++;
    this.readyState = 3; // CLOSED
  }
  // test drivers (what the browser would do):
  open(): void {
    this.readyState = 1; // OPEN
    this.onopen?.();
  }
  frame(data: unknown): void {
    this.onmessage?.({ data });
  }
  drop(): void {
    this.readyState = 3;
    this.onclose?.();
  }
}

/** Drain the microtask queue so async connect() progresses past its mint await. */
async function flush(): Promise<void> {
  for (let i = 0; i < 10; i++) await Promise.resolve();
}

function makeHarness(mint?: (n: number) => Promise<string | null>) {
  const sockets: FakeSocket[] = [];
  const counts = { bells: 0, revoked: 0, mints: 0 };
  const deps: EventsDeps = {
    wsUrl: "wss://x/api/v1/events",
    mintTicket: () => {
      counts.mints++;
      return mint ? mint(counts.mints) : Promise.resolve("t" + counts.mints);
    },
    makeSocket: (url: string) => {
      const s = new FakeSocket(url);
      sockets.push(s);
      return s;
    },
    onBell: () => void counts.bells++,
    onRevoked: () => void counts.revoked++,
    rand: () => 1,
  };
  return { deps, sockets, counts, start: () => startEvents(deps) };
}

const rev = (n: number): string => JSON.stringify({ type: "rev", rev: n });
const REVOKED = JSON.stringify({ type: "revoked" });

test("E1: connect mints exactly once and dials wsUrl + ?ticket= (URL-encoded)", async () => {
  const h = makeHarness(() => Promise.resolve("t 1+/="));
  h.start();
  await flush();
  assert.equal(h.counts.mints, 1);
  assert.equal(h.sockets.length, 1);
  assert.equal(h.sockets[0].url, "wss://x/api/v1/events?ticket=" + encodeURIComponent("t 1+/="));
});

test("E2: single-flight — two kick() while a mint is pending → one mint, one socket", async () => {
  let release: ((v: string | null) => void) | undefined;
  const h = makeHarness(
    () =>
      new Promise<string | null>((r) => {
        release = r;
      }),
  );
  const handle = h.start();
  await flush(); // the initial connect is now parked on the mint
  handle.kick();
  handle.kick();
  await flush();
  assert.equal(h.counts.mints, 1, "the kicks piggybacked on the in-flight connect");
  release!("tX");
  await flush();
  assert.equal(h.counts.mints, 1);
  assert.equal(h.sockets.length, 1);
});

test("E3: fresh ticket per attempt — open → drop → backoff → second mint, second socket", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const h = makeHarness();
  h.start();
  await flush();
  h.sockets[0].open(); // attempts reset to 0
  h.sockets[0].drop(); // → reconnect in base(0) = 1 s (rand = 1)
  t.mock.timers.tick(1_000);
  await flush();
  assert.equal(h.counts.mints, 2, "tickets are never reused — every attempt re-mints");
  assert.equal(h.sockets.length, 2);
  assert.ok(h.sockets[0].url.includes("t1") && h.sockets[1].url.includes("t2"));
});

test("E4: backoff 1,2,4…60 s cap; kick(false) respects a pending window, kick(true) resets; open restarts at 1 s", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  let fail = true;
  const h = makeHarness((n) => (fail ? Promise.reject(new Error("down")) : Promise.resolve("t" + n)));
  const handle = h.start();
  await flush(); // mint 1 failed → timer armed at 1 s
  assert.equal(h.counts.mints, 1);
  // With rand=1 the delay is exactly base: 1s, 2s, 4s, 8s, 16s, 32s, then capped 60s forever.
  for (const [delay, mintsAfter] of [
    [1_000, 2],
    [2_000, 3],
    [4_000, 4],
    [8_000, 5],
    [16_000, 6],
    [32_000, 7],
    [60_000, 8],
    [60_000, 9],
  ] as const) {
    t.mock.timers.tick(delay - 1);
    await flush();
    assert.equal(h.counts.mints, mintsAfter - 1, `no early fire inside the ${delay} ms window`);
    t.mock.timers.tick(1);
    await flush();
    assert.equal(h.counts.mints, mintsAfter, `retried at ${delay} ms`);
  }
  handle.kick(); // a pending 60 s window — kick(false) must NOT shortcut it
  await flush();
  assert.equal(h.counts.mints, 9);
  handle.kick(true); // cancel the window, reset attempts, reconnect NOW
  await flush();
  assert.equal(h.counts.mints, 10);
  t.mock.timers.tick(1_000); // …and the next failure backs off from 1 s again
  await flush();
  assert.equal(h.counts.mints, 11);
  fail = false;
  t.mock.timers.tick(2_000); // attempts=2 window
  await flush();
  assert.equal(h.counts.mints, 12);
  assert.equal(h.sockets.length, 1);
  h.sockets[0].open(); // success resets attempts…
  h.sockets[0].drop();
  t.mock.timers.tick(1_000); // …so the post-drop retry is back at 1 s
  await flush();
  assert.equal(h.counts.mints, 13);
  assert.equal(h.sockets.length, 2);
});

test("E5: mint → null stops the cycle (no socket, NO timer); a later kick() mints again", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  let dead = true;
  const h = makeHarness((n) => Promise.resolve(dead ? null : "t" + n));
  const handle = h.start();
  await flush();
  assert.equal(h.counts.mints, 1);
  assert.equal(h.sockets.length, 0);
  t.mock.timers.tick(600_000); // 10 min — a scheduled timer would have re-minted by now
  await flush();
  assert.equal(h.counts.mints, 1, "definitive refusal left no timer behind");
  dead = false;
  handle.kick(); // the T1/T3 re-probe path
  await flush();
  assert.equal(h.counts.mints, 2);
  assert.equal(h.sockets.length, 1);
});

test("E6: mint throw → a reconnect timer IS scheduled", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const h = makeHarness((n) => (n === 1 ? Promise.reject(new Error("offline")) : Promise.resolve("t" + n)));
  h.start();
  await flush();
  assert.equal(h.counts.mints, 1);
  assert.equal(h.sockets.length, 0);
  t.mock.timers.tick(1_000);
  await flush();
  assert.equal(h.counts.mints, 2, "the transient failure retried on the backoff timer");
  assert.equal(h.sockets.length, 1);
});

test("E7: revoked frame → onRevoked exactly once, socket closed, no timer, no reconnect ever", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const h = makeHarness();
  const handle = h.start();
  await flush();
  const s = h.sockets[0];
  s.open(); // schedules the catch-up bell — revoked must clear it
  s.frame(REVOKED);
  assert.equal(h.counts.revoked, 1);
  assert.equal(s.closeCalls, 1);
  assert.equal(handle.closed, true, "a revoked handle is dead — the glue recreates after unlock");
  s.frame(REVOKED); // late duplicate frame — no-op
  assert.equal(h.counts.revoked, 1, "onRevoked fires exactly once");
  s.drop(); // the onclose echo of the close — schedules nothing
  t.mock.timers.tick(600_000);
  await flush();
  assert.equal(h.counts.mints, 1, "no reconnect follows a revocation");
  assert.equal(h.counts.bells, 0, "the pending catch-up bell was cleared with the timers");
});

test("E8: bell debounce — open + a 3-frame burst → ONE onBell after 500 ms; later bells re-fire", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const h = makeHarness();
  h.start();
  await flush();
  const s = h.sockets[0];
  s.open(); // the open itself rings the (debounced) catch-up bell
  s.frame(rev(1));
  s.frame(rev(2));
  s.frame(rev(3));
  assert.equal(h.counts.bells, 0, "trailing debounce — nothing inside the window");
  t.mock.timers.tick(500);
  assert.equal(h.counts.bells, 1, "the open + burst collapsed into one sync nudge");
  s.frame(rev(4));
  t.mock.timers.tick(500);
  assert.equal(h.counts.bells, 2);
});

test("E9: keepalive pings every 20 s while open; a pong frame is ignored; pings stop on drop", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const h = makeHarness();
  h.start();
  await flush();
  const s = h.sockets[0];
  s.open();
  t.mock.timers.tick(500); // let the catch-up bell land so the count below is exact
  assert.equal(h.counts.bells, 1);
  t.mock.timers.tick(19_500); // t = 20 s since open
  assert.deepEqual(s.sent, ["ping"]);
  s.frame("pong"); // the server echo — not JSON, silently ignored
  assert.equal(h.counts.bells, 1);
  assert.equal(h.counts.revoked, 0);
  t.mock.timers.tick(20_000); // t = 40 s
  assert.deepEqual(s.sent, ["ping", "ping"]);
  s.drop(); // keepalive dies with the socket…
  t.mock.timers.tick(60_000); // (the 1 s backoff re-mints a new, never-opened socket)
  await flush();
  assert.deepEqual(s.sent, ["ping", "ping"], "no pings after onclose");
  assert.equal(h.sockets[1].sent.length, 0, "an unopened socket never pings");
});

test("E10: close() is idempotent, kills a pending bell, and late socket callbacks are no-ops", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] });
  const h = makeHarness();
  const handle = h.start();
  await flush();
  const s = h.sockets[0];
  s.open();
  assert.equal(handle.open, true);
  s.frame(rev(1)); // bell pending…
  handle.close(); // …and cleared here
  handle.close(); // idempotent
  assert.equal(handle.closed, true);
  assert.equal(handle.open, false);
  assert.equal(s.closeCalls, 1, "the second close() found no socket to re-close");
  t.mock.timers.tick(600_000);
  await flush();
  assert.equal(h.counts.bells, 0, "a pending bell never fires after close");
  assert.equal(h.counts.mints, 1, "no reconnect after close");
  s.open(); // late callbacks from the dying socket — all no-ops
  s.frame(rev(2));
  s.frame(REVOKED);
  s.drop();
  t.mock.timers.tick(600_000);
  await flush();
  assert.equal(h.counts.bells, 0);
  assert.equal(h.counts.revoked, 0);
  assert.equal(h.counts.mints, 1);
});
