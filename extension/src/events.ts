/**
 * Live change-push engine (dirty-bell WebSocket, spec 03 §6) — design 2026-07-13-ext-live-sync.md
 * is the BINDING contract; web client.ts events() is the behavioral reference. Chrome-free and
 * socket-injected so it runs under plain `node --test`: background.ts passes the real
 * `(u) => new WebSocket(u)`, tests a hand-rolled fake.
 *
 * Frames are server→client only ({"type":"rev"} / {"type":"revoked"}); the bell triggers the
 * caller's EXISTING pull via onBell — this module never sees vault data. Auth = a single-use
 * ~30 s ticket minted per connect attempt (mintTicket); the ticket lives only inside one attempt
 * and is never stored. The 20 s app-level "ping" (server echoes "pong") keeps the WS traffic
 * JS-visible so Chrome 116+ extends the SW's life; on browsers that don't, the SW dies and the
 * caller's alarm-floor triggers reconnect on the next wake — never an error state.
 */

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
  /** "wss://…/api/v1/events" — NO query string; the per-attempt ticket is appended here. */
  wsUrl: string;
  /** null = definitive 401/403 → stop the current cycle quietly (no timer); a kick() re-probes.
   *  A throw = transient (offline / 5xx) → jittered backoff. */
  mintTicket(): Promise<string | null>;
  makeSocket(url: string): WsLike;
  /** Debounced dirty signal — fired on open (missed-bell catch-up) and on every rev frame. */
  onBell(): void;
  /** Explicit {"type":"revoked"} frame ONLY — never fired for mint failures or drops. */
  onRevoked(): void;
  keepaliveMs?: number; //    default 20_000 (< 30 s SW idle window, < 60 s server timeout)
  bellDebounceMs?: number; // default 500
  rand?: () => number; //     default Math.random — jitter seam for deterministic tests
}

export interface EventsHandle {
  /** Prod a dead cycle back to life. resetBackoff cancels a pending retry timer and reconnects
   *  immediately; without it a pending backoff window is respected (no hot-loop). */
  kick(resetBackoff?: boolean): void;
  close(): void;
  readonly open: boolean; //   socket readyState OPEN
  readonly closed: boolean; // close() ran (or a revoked frame) — handle is dead, glue recreates
}

/** Start the connect loop immediately and return the control handle. */
export function startEvents(deps: EventsDeps): EventsHandle {
  const keepaliveMs = deps.keepaliveMs ?? 20_000;
  const bellDebounceMs = deps.bellDebounceMs ?? 500;
  const rand = deps.rand ?? Math.random;

  let ws: WsLike | null = null;
  let closed = false;
  let connecting = false;
  let attempts = 0; // consecutive failed cycles since the last successful open
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  let bellTimer: ReturnType<typeof setTimeout> | null = null;

  const clearReconnect = (): void => {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };
  const clearBell = (): void => {
    if (bellTimer !== null) {
      clearTimeout(bellTimer);
      bellTimer = null;
    }
  };
  const stopKeepalive = (): void => {
    if (keepaliveTimer !== null) {
      clearInterval(keepaliveTimer);
      keepaliveTimer = null;
    }
  };

  /** Trailing debounce: a burst of bells (bulk import) collapses into ONE onBell. */
  const scheduleBell = (): void => {
    if (closed) return;
    if (bellTimer !== null) clearTimeout(bellTimer);
    bellTimer = setTimeout(() => {
      bellTimer = null;
      if (!closed) deps.onBell();
    }, bellDebounceMs);
  };

  /** Backoff base 1 s·2ⁿ capped at 60 s, jittered into [base/2, base] (web events() parity).
   *  No stop-after-N: a silent permanent stop would be a stale-until-restart bug — SW death
   *  naturally rate-limits long outages to a few attempts per alarm wake. */
  const scheduleReconnect = (): void => {
    if (closed || reconnectTimer !== null) return;
    const base = Math.min(60_000, 1_000 * 2 ** Math.min(attempts, 6));
    const delay = base / 2 + rand() * (base / 2);
    attempts++;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      void connect();
    }, delay);
  };

  const connect = async (): Promise<void> => {
    if (closed || connecting || ws) return; // synchronous single-flight + one-socket guard
    connecting = true;
    try {
      // Tickets are single-use — mint a fresh one per attempt; it exists only in this scope.
      const ticket = await deps.mintTicket();
      if (closed) return; // torn down mid-mint (doLock) — abort
      if (ticket === null) return; // definitive auth refusal — stop the cycle, no timer
      const sock = deps.makeSocket(deps.wsUrl + "?ticket=" + encodeURIComponent(ticket));
      ws = sock;
      sock.onopen = () => {
        if (closed || ws !== sock) return;
        attempts = 0; // healthy again — future drops restart the backoff from 1 s
        // App-level keepalive: JS-visible send/receive resets Chrome's SW idle timer (the
        // server's protocol pings never surface to JS, so they cannot). Server echoes "pong".
        keepaliveTimer = setInterval(() => {
          if (sock.readyState === 1) sock.send("ping");
        }, keepaliveMs);
        scheduleBell(); // catch-up: bells missed while down (web onOpen → syncNow parity)
      };
      sock.onmessage = (ev) => {
        if (closed) return;
        let type: unknown;
        try {
          type = (JSON.parse(String(ev.data)) as { type?: unknown }).type;
        } catch {
          return; // the "pong" echo and any garbage — silently ignored (web parity)
        }
        if (type === "rev") scheduleBell(); // payload rev is ignored — the pull is a full sync(0)
        else if (type === "revoked") {
          // Explicit server frame — a REAL revocation. The handle dies: every timer cleared,
          // no reconnect ever follows (the server closes right after sending it).
          closed = true;
          clearReconnect();
          clearBell();
          stopKeepalive();
          ws = null;
          sock.close();
          deps.onRevoked(); // exactly once — `closed` blocks any later frame from re-entering
        }
      };
      sock.onclose = () => {
        stopKeepalive();
        if (ws === sock) ws = null; // a stale socket's close must not drop the current one
        if (!closed) scheduleReconnect();
      };
      sock.onerror = () => {
        /* the paired onclose handles recovery (web parity) */
      };
    } catch {
      // Mint threw (offline / 5xx / proxy) — transient: keep trying quietly, jittered.
      if (!closed) scheduleReconnect();
    } finally {
      connecting = false;
    }
  };

  const kick = (resetBackoff = false): void => {
    if (closed) return;
    if (resetBackoff) {
      clearReconnect();
      attempts = 0;
      if (!ws && !connecting) void connect();
    } else if (!ws && !connecting && reconnectTimer === null) {
      void connect(); // a pending backoff window is respected — kick(false) never shortcuts it
    }
  };

  const close = (): void => {
    if (closed) return; // idempotent
    closed = true;
    clearReconnect();
    clearBell();
    stopKeepalive();
    const sock = ws;
    ws = null;
    sock?.close(); // its late onclose is a no-op: ws ref already dropped, `closed` set
  };

  void connect();

  return {
    kick,
    close,
    get open(): boolean {
      return ws !== null && ws.readyState === 1;
    },
    get closed(): boolean {
      return closed;
    },
  };
}
