# Extension live change-push (WebSocket dirty-bell) — BUILD CONTRACT

2026-07-13 · Status: SHIPPED 2026-07-14 (0.17.0, extension 0.14.0) — implemented, find→refute reviewed, gates green. (Was: BINDING.)
Base: HEAD `6e0d638`. Scope: `extension/` only + read-only references. **Zero server changes.**

## 0. Objective

A peer edit (web/Android/desktop write → server `Notifier.notifyRev`) reaches the MV3 extension in
~1–2 s instead of waiting for the 5-minute `"resync"` alarm. The extension joins the existing
dirty-bell channel (spec 03 §6): server→client frames only (`{"type":"rev","rev":N}`,
`{"type":"revoked"}`), no data plane — the bell triggers the EXISTING pull (`resync()` →
`api.sync(0)` → `decryptItems`). No new decrypt path, no new secret egress.

Server facts this contract relies on (verified at HEAD, cite-by-anchor):
- `App.kt` `post("/api/v1/events/ticket")` → `requirePrincipal` → `services.wsTickets.mint(p.userId, p.deviceId)`
  → `WsTicketResponse(ticket, 30)`. The deviceId binding is SERVER-side from the Bearer principal —
  the client never sends a deviceId.
- `App.kt` `webSocket("/api/v1/events")`: redeems `?ticket=` via `EventsTicketStore.redeem`
  (single-use, 30 s TTL, atomic remove), re-checks `service.deviceHasLiveSession(auth.deviceId)`
  (M8) and closes 1008 `VIOLATED_POLICY` if revoked; then `notifier.register`. The frame loop
  echoes app-level `Frame.Text("ping")` → `"pong"` — **the client keepalive needs no server work**.
- `install(WebSockets) { pingPeriodMillis = 30_000; timeoutMillis = 60_000 }` — protocol pings are
  auto-ponged by the BROWSER NETWORK PROCESS and are **not JS-visible**, so they CANNOT be assumed
  to reset Chrome's SW idle timer (attacked and rejected as the sole keepalive — see §1).
- `Notifier.notifyRevokedDevice/-User/-UserExcept`: sends `{"type":"revoked"}` then closes.
- `EventsTicketStore` ≠ `WsTicketStore` (recovery). Only the events one is touched — and only via
  the existing REST route. **Do not conflate; do not edit either.**

## 1. Socket lifecycle — pinned posture

**Hold the socket ONLY while a session exists in the SW (`session !== null` / restorable snapshot);
locked or logged-out = no socket.** This is forced, not chosen: `doLock()` calls
`api.setTokens(null, null)` and removes the snapshot, so no ticket can be minted while locked, and
there is nothing to sync (no vault keys). (The 5-min poll also only runs unlocked — `doLock` clears
the `"resync"` alarm — so "poll remains while locked" was never true and is not promised.)

**Pinned keepalive posture: client application-level keepalive, `"ping"` text frame every 20 s,
plus accept-SW-death as the tolerated degradation.** Rationale (attack log):
- Chrome 116+ extends SW lifetime on *JS-visible* WS send/receive activity within the 30 s idle
  window. The server's 30 s protocol pings are handled in the network process (never surface as
  `onmessage`) → NOT sufficient alone; relying on them risks SW death between pings.
- Client sends `"ping"` every 20 s (< 30 s idle window, < 60 s Ktor `timeoutMillis`); the server's
  existing echo answers `"pong"` — both directions JS-visible, timer reset guaranteed.
- `manifest.json` has `minimum_chrome_version: "109"`; on 109–115 (and Firefox event-page
  suspension) WS activity does NOT extend SW life → SW dies ~30 s idle, socket drops, and the
  design degrades to the 5-min alarm floor. **Do NOT bump minimum_chrome_version.**
- Offscreen-document socket host: REJECTED (no legitimate `chrome.offscreen.Reason`, extra
  message hop, absent on Firefox).
- SW death is never an error state: `chrome.alarms` persist, the session snapshot lives in
  `chrome.storage.session`, and §2's triggers reconnect on the next wake (≤5 min worst case).
- Keepalive does NOT touch the idle lock: no events-path code may call `armAutoLock()` (bells are
  not user activity — same law as `PASSIVE_MSGS`).

## 2. (Re)connect triggers — exact and exhaustive

MV3 discipline: no NEW `chrome.*` listeners are needed (WS handlers are plain object callbacks,
not extension events, and live only as long as the SW — exactly the keepalive design). The existing
synchronously-registered listeners are reused.

- **T1 — SW wake bootstrap**: one new top-level statement `void ensureSocket();` at module scope in
  `background.ts` (beside the existing update-alarm bootstrap IIFE). Runs on EVERY SW start —
  covers `onStartup`, `onInstalled`, popup-open wake, content-message wake, alarm wake. No-op when
  no session.
- **T2 — unlock success**: in `unlock()`, immediately after `void chrome.alarms.create("resync", …)`:
  `void ensureSocket(true)`.
- **T3 — resync alarm tick**: in the existing `chrome.alarms.onAlarm` listener, the `"resync"` arm
  becomes `{ void resync(); void ensureSocket(true); }`. This is the guaranteed ≤5-min revival
  after SW death and the periodic backoff reset while the SW stays alive.
- **T5 — internal**: `onclose`/transient-mint-failure → backoff reschedule inside `events.ts` (§6).
- **Deliberately NOT a trigger** (attacked and dropped): per-message `handle()` hook — `pageInfo`/
  `status` arrive constantly; resetting backoff there collapses it into a ~1 s mint hot-loop while
  the server is down. Popup freshness does not need it (popup reads local items; T3 bounds
  staleness). "post-sync" is subsumed by T3.

`ensureSocket` (new, in `background.ts`):
```ts
let events: EventsHandle | null = null;
async function ensureSocket(reset = false): Promise<void> {
  await ensureLoaded();                    // session may not be hydrated on a fresh wake
  if (!session) return;
  if (!events || events.closed) {
    events = startEvents({
      wsUrl: SERVER_URL.replace(/^http/, "ws") + "/api/v1/events",
      mintTicket,
      makeSocket: (u) => new WebSocket(u),
      onBell: () => void resync(),         // the EXISTING pull — the only refresh path
      onRevoked: () => void doLock("manual"),
    });
  } else {
    events.kick(reset);
  }
}
```
`doLock()` gains, as its FIRST statements: `events?.close(); events = null;` (covers
locked-while-connected for both manual and idle lock; late socket `onclose` after that is a no-op
because the handle is closed and `ensureSocket` guards on `session`).

## 3. Ticket flow

- **New `AndvariApi.eventsTicket()`** in `extension/src/api.ts`:
  ```ts
  export interface WsTicketResponse { ticket: string; expiresInSeconds: number }
  eventsTicket(): Promise<WsTicketResponse> { return this.json("POST", "/api/v1/events/ticket"); }
  ```
  Field names mirror core `Wire.kt` `WsTicketResponse(val ticket: String, val expiresInSeconds: Long)`.
  Rides `json()` → gets the Bearer header, the single-flight 401→refresh→retry, and ApiError parsing
  for free. Chrome-free (api.ts stays node-testable).
- **Single-use, minted per connect attempt, never persisted** (spec 03 §6; `EventsTicketStore.redeem`
  removes atomically). The ticket is a local variable inside one connect attempt — it MUST NOT enter
  `SessionSnapshot`, `chrome.storage.*`, or any log. The access token never rides a URL.
- **Glue mapping** (in `background.ts`): definitive auth refusal folds to `null`; everything else
  (offline, 5xx) stays a throw = transient:
  ```ts
  async function mintTicket(): Promise<string | null> {
    try { return (await api.eventsTicket()).ticket; }
    catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) return null;
      throw e;
    }
  }
  ```
  `null` ⇒ `events.ts` stops the current cycle (no timer, no socket) — the "existing revoked path"
  posture: the extension today tolerates dead tokens silently (`resync()` catch{}) and keeps serving
  offline fills until autolock; a ticket-mint 401 MUST NOT `doLock()` (laptop-asleep expiry would
  punish the user). The ≤5-min T3 kick is the bounded, self-limiting re-probe (each probe ≈ 1–2
  cheap 401s — the same order as today's failing alarm sync). No `authDead` latch (a mis-latch on a
  transient 401 would silently kill live sync for the whole session — attacked and rejected).

## 4. On dirty-bell

`{"type":"rev"}` → **trailing-debounced (500 ms) call of the EXISTING `resync()`** — never a new
decrypt/sync path. The debounce lives INSIDE `events.ts` (testable under node); `onBell` in glue is
exactly `() => void resync()`.
- `onopen` ALSO fires `onBell` (same debounce channel): catch-up for bells missed while down —
  parity with web `events()` `onOpen` → `syncNow()` (no server-side replay). The redundant
  post-unlock first-open sync is accepted: it closes the unlock-sync→socket-open missed-bell window.
- The frame's `rev` payload is IGNORED (no cursor state; `api.sync(0)` full pull stays). Self-echo
  after our own put = one extra debounced sync — harmless; `resync()` already yields to
  `writesInFlight` and re-checks it after the await.
- **Pin-keeping**: `decryptItems` (called only by `unlock` and `resync`) remains the sole open-path
  `adItem(` site; `putItem` the sole seal site. New code adds NO `adItem(`, no `formatVersion: <n>`
  literal, and all WS code lives in NEW `extension/src/events.ts`, which
  `web/src/extension-pins.test.ts` does not read (it reads `background.ts` only). The pin test
  requires **NO edit**; the two-`adItem(`-call-sites count stays exactly 2 in `background.ts`.

## 5. Backstop — final cadence

The `"resync"` alarm STAYS at `RESYNC_PERIOD_MIN = 5` (do not shorten; do not remove). Final cadence:
- Socket up (Chrome 116+, unlocked): peer edit → bell → ≤0.5 s debounce + sync RTT ≈ **1–2 s**.
- Socket down / SW dead / Chrome ≤115 / Firefox suspended: **≤5 min** (alarm tick syncs AND revives
  the socket via T3).
- Every socket (re)open: immediate catch-up sync (§4).
- Unlock: immediate full sync (existing) + socket up within ~1 s.

## 6. `extension/src/events.ts` — the new module (chrome-free, injectable)

Erasable-syntax TS only (no enums/parameter properties — must type-strip under `node --test`,
node 22). No imports from chrome-typed modules.

```ts
export interface WsLike {
  readyState: number; // 1 = OPEN
  send(data: string): void;
  close(): void;
  onopen: (() => void) | null;
  onmessage: ((ev: { data: unknown }) => void) | null;
  onclose: (() => void) | null;
  onerror: (() => void) | null;
}
export interface EventsDeps {
  wsUrl: string;                        // "wss://…/api/v1/events" — NO query string
  mintTicket(): Promise<string | null>; // null = definitive 401/403 → stop cycle (no timer)
  makeSocket(url: string): WsLike;      // background passes (u) => new WebSocket(u)
  onBell(): void;                       // debounced; open + rev frames
  onRevoked(): void;                    // explicit {"type":"revoked"} frame ONLY
  keepaliveMs?: number;                 // default 20_000
  bellDebounceMs?: number;              // default 500
  rand?: () => number;                  // default Math.random — jitter seam for tests
}
export interface EventsHandle {
  kick(resetBackoff?: boolean): void;
  close(): void;
  readonly open: boolean;    // socket readyState OPEN
  readonly closed: boolean;  // close() has been called — handle is dead, glue recreates
}
export function startEvents(deps: EventsDeps): EventsHandle; // connects immediately
```

Binding behavior (web `client.ts events()` parity except where stated):
1. `connect()`: single-flight — synchronous `connecting` flag; no-op if a socket exists, a connect
   is in flight, or the handle is closed. Re-check `closed` after EVERY await (a `doLock` mid-mint
   must abort — web `if (closed) return` parity).
2. Mint result: `null` → return (no timer, no socket; a later `kick()` starts a fresh cycle).
   Throw → `scheduleReconnect()`. Ticket → `makeSocket(wsUrl + "?ticket=" + encodeURIComponent(t))`.
3. `onopen`: `attempts = 0`; start keepalive `setInterval` — `send("ping")` iff `readyState === 1`;
   `scheduleBell()`.
4. `onmessage`: `JSON.parse` inside try/catch (the `"pong"` echo and any garbage are silently
   ignored — web parity). `type === "rev"` → `scheduleBell()`. `type === "revoked"` → set `closed`,
   clear ALL timers, close socket, fire `onRevoked()` exactly once. No reconnect ever follows a
   revoked frame (the server closes right after — `Notifier.notifyRevokedDevice`).
5. `onclose`: clear keepalive; drop the socket ref only if it is still the current one
   (`ws === sock` guard, web parity); if not `closed` → `scheduleReconnect()`. `onerror` = no-op
   (paired onclose recovers) — web parity.
6. `scheduleReconnect()`: no-op if `closed` or a timer is pending.
   `base = min(60_000, 1_000 · 2^min(attempts, 6))`; `delay = base/2 + rand() · base/2`;
   `attempts++`; `setTimeout(connect, delay)`. Cap 60 s; `attempts` resets ONLY on successful open
   and on `kick(true)`. No stop-after-N (a silent permanent stop is a stale-until-restart bug);
   SW death naturally rate-limits long outages to a few attempts per 5-min wake.
7. `kick(reset)`: no-op if `closed`. `reset === true` → cancel pending backoff timer, `attempts = 0`,
   then connect if no socket/in-flight. Else → connect only if no socket, no in-flight, AND no
   pending timer (must not shortcut backoff).
8. `scheduleBell()`: trailing debounce `bellDebounceMs`; a burst (bulk import) collapses to one
   `onBell`. Cleared by `close()`; never fires after close.
9. `close()`: idempotent; `closed = true`; clear backoff + keepalive + bell timers; `socket.close()`;
   null refs. Late socket callbacks after close are no-ops.

## 7. Failure-mode matrix (asserted behavior)

| Failure | Behavior |
|---|---|
| Server down / offline at mint | throw → backoff 1 s→60 s cap, jittered; SW dies ~30 s idle (no WS traffic) → next probe at T3 alarm |
| 1006 close loop (WS-stripping proxy; HTTP fine) | mint per attempt + backoff cap 60 s; bounded ≈1 mint+upgrade per minute worst case while SW awake; alarm-floor sync keeps data ≤5 min stale |
| Ticket race / double connect | impossible client-side (synchronous single-flight + one-socket guard); server ticket redeem is atomic single-use |
| Revoked inside 30 s ticket window | server M8 `deviceHasLiveSession` re-check closes 1008 → client retry mints → 401 → `null` → cycle stops |
| Revoked mid-socket | `{"type":"revoked"}` frame → `doLock("manual")` (web-parity sign-out; clears tokens+session so no re-mint is possible); no reconnect |
| Mint 401/403 (expiry, e.g. laptop slept past refresh lifetime) | cycle stops quietly; vault STAYS unlocked (offline-fill mission); T3 re-probes ≤5 min; NO doLock |
| Locked while connected (manual or idle-alarm) | `doLock` first statements tear down handle (socket + all timers); late onclose no-op |
| SW death while connected (Chrome ≤115, crash, FF suspend) | socket drops; server `finally` unregisters; T1/T3 reconnect on next wake; staleness ≤5 min |
| Token refresh during mint | inside `api.json()` — existing single-flight refresh + snapshot-before-POST discipline untouched |

## 8. Test plan

**New `extension/src/events.test.ts`** (`node --test`, auto-picked by the `src/**/*.test.ts` glob;
`t.mock.timers.enable({ apis: ["setTimeout", "setInterval"] })`, `rand: () => 1` for deterministic
delays, hand-rolled `WsLike` fake):
- E1 connect: one mint; socket URL = `wsUrl + "?ticket=" + encodeURIComponent(ticket)`.
- E2 single-flight: two `kick()` while mint pending → exactly one mint, one socket.
- E3 fresh ticket per attempt: open → drop (onclose) → advance past backoff → second mint, second
  socket (tickets never reused).
- E4 backoff: with rand=1, successive failed cycles delay 1 s, 2 s, 4 s … cap 60 s; after a
  successful open then drop, delay restarts at 1 s. `kick(true)` cancels a pending timer and
  reconnects immediately; `kick(false)` during a pending timer is a no-op.
- E5 mint→`null`: no socket, NO timer scheduled (advance 10 min → no further mint); a later
  `kick()` mints again.
- E6 mint throw: reconnect timer scheduled.
- E7 revoked frame: `onRevoked` fired exactly once; socket closed; no timer; subsequent onclose
  schedules nothing.
- E8 bell debounce: 3 rev frames inside the window → exactly 1 `onBell` after 500 ms; `onopen`
  also produces a (debounced) `onBell`.
- E9 keepalive: after open, advancing 20 s intervals sends `"ping"` each tick; a `"pong"` text
  frame is ignored (no onBell/onRevoked/throw); pings stop after close/onclose.
- E10 `close()`: idempotent; clears bell debounce (a pending bell never fires); late socket
  callbacks are no-ops.

**Extend `extension/src/api.test.ts`**: one test — `eventsTicket()` POSTs
`/api/v1/events/ticket` with the Bearer + `X-Andvari-Client` headers and returns the parsed body.

**Web pin suites (builder MUST run, from `web/`)**:
`npx vitest run src/extension-pins.test.ts src/ui/token-lockstep.test.ts` — both must pass with
ZERO edits (extension-pins reads `background.ts`: `adItem(` count stays exactly 2, no
digit-fv regressions; token-lockstep reads `popup.css`/`content-ui.ts`, untouched here).

**Gate commands** (never pipe to tail — pipe masks the exit code; confirm the events tests RAN):
```
cd extension && npm run typecheck > /tmp/ext-tc.log 2>&1; echo EXIT=$?
cd extension && npm test        > /tmp/ext-test.log 2>&1; echo EXIT=$?; grep -c "^ok" /tmp/ext-test.log
cd extension && npm run build   > /tmp/ext-build.log 2>&1; echo EXIT=$?
cd web && npx vitest run src/extension-pins.test.ts src/ui/token-lockstep.test.ts > /tmp/pins.log 2>&1; echo EXIT=$?
grep -c "adItem(" extension/src/background.ts   # MUST print 2
```

## 9. Scope fence — what NOT to build

- **No server changes** (routes, `Notifier`, `EventsTicketStore`, `WsTicketStore`, ping config).
- **No popup freshness hint** — decided NO: no `messages.ts` change, no new `Res` fields, no popup
  UI; the popup's existing per-second polls already surface fresh items. No status dot.
- **No `chrome.notifications`** (permission absent; notification spam is a non-goal).
- **No manifest edits**: no new permissions (WebSocket needs none; the MV3 extension-pages CSP
  `script-src 'self'; object-src 'self'` does not restrict connect), no `minimum_chrome_version`
  bump, no `manifest.firefox.json` change.
- **No sync-cursor/delta sync** (`sync(0)` stays), no offline mutation queue, no rev comparison.
- **No Bearer-in-URL fallback** and no Authorization-header WS path (browser WebSocket cannot set
  headers; the ticket path is the only one).
- **No pin-test edits**, no version bumps, no CHANGELOG/README edits (release cut owns those).
- **No `armAutoLock()` from any events/bell path.**
- Allowed comment-only touch: extend the `background.ts` header sentence about `"resync"` with one
  clause naming the live bell + `events.ts`.

Files touched, exhaustively: `extension/src/events.ts` (new), `extension/src/events.test.ts` (new),
`extension/src/background.ts` (glue: import, `events` handle, `ensureSocket`, `mintTicket`,
`doLock` teardown, `unlock` kick, alarm-listener kick, top-level `void ensureSocket();`, header
comment), `extension/src/api.ts` (`WsTicketResponse` + `eventsTicket()`), `extension/src/api.test.ts`
(one test). Nothing else.
