import type {
  AdminDeviceSummary,
  AdminStatus,
  AdminUserSummary,
  AttachmentMeta,
  AuditEvent,
  ClientPolicy,
  CreateVaultRequest,
  CreateVaultResponse,
  DeletedItemsResponse,
  DeletedVaultSummary,
  InviteResponse,
  ItemRestoreResponse,
  ItemUpload,
  ItemVersionsResponse,
  PasswordChangeRequest,
  PreloginResponse,
  PushResponse,
  RegisterRequest,
  SessionResponse,
  SyncResponse,
  TotpSetupResponse,
  TotpStatus,
  TransferAcceptRequest,
  TransferOfferRequest,
  TransferOfferResponse,
  Mutation,
  AccountKeys,
  UserLookupResponse,
  VaultDeleteRequest,
  VaultDeleteResponse,
  VaultMemberAdd,
  VaultMemberRemoveRequest,
  VaultMemberSummary,
  VaultMetaUpdateRequest,
  VaultRestoreRequest,
  WsTicketResponse,
} from "./types";

export const CLIENT_VERSION = "0.11.1";
const CLIENT_HEADER = `web/${CLIENT_VERSION}`;

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

/** A request retries after at most this many refresh/adopt rounds (see raw()). */
const MAX_AUTH_ATTEMPTS = 2;

/** Abort a hung refresh POST after this long — other tabs queue behind our web lock. */
const REFRESH_FETCH_TIMEOUT_MS = 15_000;
/** Give up WAITING for another tab's refresh lock after this long (> the fetch timeout,
 *  so a healthy holder always finishes or times out first) and proceed without
 *  cross-tab exclusion rather than stall every tab behind one wedged fetch. */
const REFRESH_LOCK_WAIT_MS = 20_000;

/**
 * Why the session ended (events() → onRevoked): an explicit server `revoked` frame is
 * a real revocation; a 401/403 at ticket mint after a refused refresh is ordinary
 * EXPIRY (laptop asleep past the refresh lifetime) and must not be presented as
 * "your device was revoked".
 */
export type SessionEndKind = "revoked" | "expired";

/** AbortSignal.timeout where it exists (Chrome 103+/FF 100+/Safari 16+) — some
 *  browsers HAVE Web Locks but not this; a missing timeout must degrade to an
 *  unbounded wait, never crash the refresh path. */
function timeoutSignal(ms: number): AbortSignal | undefined {
  return typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
    ? AbortSignal.timeout(ms)
    : undefined;
}

/**
 * REST client for the andvari server. Holds the token pair, refreshes the access
 * token on 401 and retries, and surfaces 426 (upgrade) / 410 (resync) as typed
 * errors the store handles.
 *
 * `readPersistedTokens` (optional) reads the pair another TAB may have persisted
 * (ui/session.ts wires it to localStorage) — see tryRefresh: the refresh token is
 * single-use and rotating, and the server treats reuse as theft (it revokes the whole
 * device), so a rotation another tab already performed must be ADOPTED, never replayed.
 */
export class ApiClient {
  constructor(
    public baseUrl: string,
    private tokens: Tokens | null = null,
    private onTokens: (t: Tokens | null) => void = () => {},
    private readPersistedTokens: (() => Tokens | null) | null = null,
  ) {}

  setTokens(t: Tokens | null) {
    this.tokens = t;
    this.onTokens(t);
  }

  getTokens(): Tokens | null {
    return this.tokens;
  }

  private async raw(method: string, path: string, body?: unknown, auth = true, attempt = 0): Promise<Response> {
    const headers: Record<string, string> = { "X-Andvari-Client": CLIENT_HEADER };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const used = auth && this.tokens ? this.tokens.accessToken : null;
    if (used) headers["Authorization"] = `Bearer ${used}`;
    const resp = await fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (resp.status === 401 && auth && attempt < MAX_AUTH_ATTEMPTS && this.tokens) {
      // A refresh that completed while this request was in flight (another caller's
      // single-flight refresh, or a pair adopted from another tab) already replaced
      // the tokens — retry with the fresh access token instead of rotating again.
      if (this.tokens.accessToken !== used) return this.raw(method, path, body, auth, attempt + 1);
      if (await this.tryRefresh()) return this.raw(method, path, body, auth, attempt + 1);
    }
    return resp;
  }

  private refreshInFlight: Promise<boolean> | null = null;

  /**
   * F25 — the refresh token is SINGLE-USE and rotating; the server's reuse heuristic
   * revokes the whole device (`refresh_reuse`). Two concurrent 401s (a WS-bell sync
   * racing a user save at access expiry, or two tabs) must never both spend the same
   * refresh token:
   *  - in-tab: every concurrent caller awaits the ONE in-flight refresh promise;
   *  - cross-tab: the rotation runs inside the `andvari-refresh` Web Lock (where
   *    available, waited on for a BOUNDED time), and INSIDE the lock the persisted
   *    session is re-read first — if another tab already rotated, its pair is
   *    adopted and no POST happens.
   * A transport failure rejects every waiter without clearing tokens (transient);
   * only a definitive server refusal (401/403 from the refresh endpoint) kills the
   * pair — a 502/503/429 is the server having a moment, and destroying the pair on
   * it would cascade into a false fleet-wide "revoked" sign-out.
   */
  private tryRefresh(): Promise<boolean> {
    this.refreshInFlight ??= this.refreshExclusive().finally(() => {
      this.refreshInFlight = null;
    });
    return this.refreshInFlight;
  }

  private async refreshExclusive(): Promise<boolean> {
    // Web Locks API (Chrome 69+/FF 96+/Safari 15.4+) serializes tabs. Where missing
    // (older browsers, non-window contexts) proceed unlocked — the persisted-pair
    // re-read in refreshNow still catches most cross-tab races, and in-tab callers
    // are already deduped by the shared promise.
    const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
    if (!locks?.request) return this.refreshNow();
    // `granted` disambiguates a rejected lock WAIT from a failure of refreshNow
    // itself: post-grant errors must propagate untouched (re-running refreshNow after
    // its own fetch timed out could replay a rotation that DID land server-side).
    let granted = false;
    try {
      return await locks.request(
        "andvari-refresh",
        { signal: timeoutSignal(REFRESH_LOCK_WAIT_MS) },
        () => {
          granted = true;
          return this.refreshNow();
        },
      );
    } catch (e) {
      if (granted) throw e; // refreshNow's own failure — not a lock problem
      // The wait for another tab's (hung) refresh timed out, or Web Locks glitched:
      // proceed WITHOUT cross-tab exclusion. Per-tab single-flight still holds and
      // the persisted re-read still runs; the worst case is a rare double-rotation —
      // strictly better than every tab stalling behind one wedged fetch.
      return this.refreshNow();
    }
  }

  private async refreshNow(): Promise<boolean> {
    const spending = this.tokens;
    if (!spending) return false;
    // Re-read INSIDE the lock: if another tab already rotated (the persisted refresh
    // token differs from the one we were about to spend), adopt its pair — POSTing
    // ours now would replay a consumed token and revoke the device.
    const persisted = this.readPersistedTokens?.() ?? null;
    if (persisted && persisted.refreshToken !== spending.refreshToken) {
      this.setTokens(persisted);
      return true;
    }
    const resp = await fetch(this.baseUrl + "/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Andvari-Client": CLIENT_HEADER },
      body: JSON.stringify({ refreshToken: spending.refreshToken }),
      // A hung refresh must not wedge this tab's recovery — nor, via the web lock,
      // every OTHER tab's (they queue behind us for up to REFRESH_LOCK_WAIT_MS).
      signal: timeoutSignal(REFRESH_FETCH_TIMEOUT_MS),
    });
    if (!resp.ok) {
      // Only a definitive refusal means the pair is dead. Anything else (502/503/504/
      // 429, a proxy error page) is transient: keep the pair — clearing it here would
      // persist tokens:null, fail the next WS ticket mint with 401, and cascade a
      // FALSE "session ended" sign-out across every tab.
      if (resp.status === 401 || resp.status === 403) this.setTokens(null);
      return false;
    }
    const pair = (await resp.json()) as Tokens;
    this.setTokens(pair);
    return true;
  }

  /** Like raw() but with a binary request body (attachments). */
  private async rawBytes(method: string, path: string, body: Uint8Array | undefined, attempt = 0): Promise<Response> {
    const headers: Record<string, string> = { "X-Andvari-Client": CLIENT_HEADER };
    if (body !== undefined) headers["Content-Type"] = "application/octet-stream";
    const used = this.tokens ? this.tokens.accessToken : null;
    if (used) headers["Authorization"] = `Bearer ${used}`;
    const resp = await fetch(this.baseUrl + path, { method, headers, body: body as BodyInit | undefined });
    if (resp.status === 401 && attempt < MAX_AUTH_ATTEMPTS && this.tokens) {
      if (this.tokens.accessToken !== used) return this.rawBytes(method, path, body, attempt + 1);
      if (await this.tryRefresh()) return this.rawBytes(method, path, body, attempt + 1);
    }
    return resp;
  }

  private async throwApiError(resp: Response): Promise<never> {
    let code = `http_${resp.status}`;
    let message = resp.statusText;
    try {
      const err = await resp.json();
      code = err.error ?? code;
      message = err.message ?? message;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(resp.status, code, message);
  }

  private async json<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
    const resp = await this.raw(method, path, body, auth);
    if (!resp.ok) await this.throwApiError(resp);
    const text = await resp.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /** For endpoints that answer plain text ("ok") — errors still surface as ApiError. */
  private async text(method: string, path: string, body?: unknown): Promise<string> {
    const resp = await this.raw(method, path, body);
    if (!resp.ok) await this.throwApiError(resp);
    return resp.text();
  }

  prelogin(email: string) {
    return this.json<PreloginResponse>("POST", "/api/v1/auth/prelogin", { email }, false);
  }

  register(req: RegisterRequest) {
    return this.json<SessionResponse>("POST", "/api/v1/auth/register", req, false);
  }

  /**
   * F28 — `opts.installId` is a stable per-browser-install UUID (ui/session.ts) sent so
   * repeat sign-ins CAN be collapsed onto one device row. Today the fielded server
   * ignores it (Wire.kt DeviceInfo has only platform+name, Service.issueSession INSERTs
   * a fresh row per login, and its Json is ignoreUnknownKeys=true, so the extra field is
   * additive and safely dropped); once the server upserts devices on it, clients already
   * in the field start deduplicating with no further change here.
   */
  async login(
    email: string,
    authKey: string,
    deviceName: string,
    opts: { totp?: string; installId?: string } = {},
  ): Promise<SessionResponse> {
    const s = await this.json<SessionResponse>(
      "POST",
      "/api/v1/auth/login",
      {
        email,
        authKey,
        device: { platform: "web", name: deviceName, installId: opts.installId },
        ...(opts.totp ? { totp: opts.totp } : {}),
      },
      false,
    );
    this.setTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    return s;
  }

  logout() {
    return this.raw("POST", "/api/v1/auth/logout").finally(() => this.setTokens(null));
  }

  accountKeys() {
    return this.json<AccountKeys>("GET", "/api/v1/account/keys");
  }

  clientPolicy() {
    return this.json<ClientPolicy>("GET", "/api/v1/client-policy", undefined, false);
  }

  sync(since: number) {
    return this.json<SyncResponse>("GET", `/api/v1/sync?since=${since}`);
  }

  push(mutations: Mutation[]) {
    return this.json<PushResponse>("POST", "/api/v1/sync/push", { mutations });
  }

  /** Item history: the archived ciphertext versions of an item (server keeps the last 10),
   *  grant-checked. The caller decrypts each blob under the held VK (Account.decryptItemVersion). */
  itemVersions(itemId: string) {
    return this.json<ItemVersionsResponse>("GET", `/api/v1/items/${itemId}/versions`);
  }

  /** Item undelete: the caller's tombstoned items (grant-scoped server-side). */
  deletedItems() {
    return this.json<DeletedItemsResponse>("GET", "/api/v1/items/deleted");
  }

  /** Item undelete: restore a tombstoned item from a re-encrypted version; returns the new rev. */
  restoreItem(itemId: string, upload: ItemUpload) {
    return this.json<ItemRestoreResponse>("POST", `/api/v1/items/${itemId}/restore`, upload);
  }

  /** Item undelete (F49): "Delete forever" — hard-delete a tombstoned item + its versions. */
  purgeItem(itemId: string) {
    return this.json<ItemRestoreResponse>("POST", `/api/v1/items/${itemId}/purge`);
  }

  // ---- shared vaults (spec 03 §10) — refused on the public break-glass origin ----

  createVault(req: CreateVaultRequest) {
    return this.json<CreateVaultResponse>("POST", "/api/v1/vaults", req);
  }

  lookupUser(email: string) {
    return this.json<UserLookupResponse>("POST", "/api/v1/users/lookup", { email });
  }

  vaultMembers(vaultId: string) {
    return this.json<VaultMemberSummary[]>("GET", `/api/v1/vaults/${vaultId}/members`);
  }

  addVaultMember(vaultId: string, body: VaultMemberAdd) {
    return this.json<CreateVaultResponse>("POST", `/api/v1/vaults/${vaultId}/members`, body);
  }

  setVaultMemberRole(vaultId: string, userId: string, role: string) {
    return this.json<CreateVaultResponse>("PUT", `/api/v1/vaults/${vaultId}/members/${userId}`, { role });
  }

  /** DELETE member. `proof`/`nonce` (spec 03 §11 removal proof) are optional and additive:
   *  when supplied they ride the body so a 0.5.0 victim can verify the removal was a real
   *  owner action; omitted → the proofless 0.4.0 shape (no body). */
  removeVaultMember(vaultId: string, userId: string, body?: VaultMemberRemoveRequest) {
    return this.json<CreateVaultResponse>(
      "DELETE",
      `/api/v1/vaults/${vaultId}/members/${userId}`,
      body && (body.proof || body.nonce) ? body : undefined,
    );
  }

  // ---- vault lifecycle (spec 03 §11) — refused on the public break-glass origin ----

  deleteVault(vaultId: string, body: VaultDeleteRequest) {
    return this.json<VaultDeleteResponse>("POST", `/api/v1/vaults/${vaultId}/delete`, body);
  }

  restoreVault(vaultId: string, body: VaultRestoreRequest) {
    return this.json<CreateVaultResponse>("POST", `/api/v1/vaults/${vaultId}/restore`, body);
  }

  deletedVaults() {
    return this.json<DeletedVaultSummary[]>("GET", "/api/v1/vaults/deleted");
  }

  leaveVault(vaultId: string) {
    return this.json<CreateVaultResponse>("POST", `/api/v1/vaults/${vaultId}/leave`, {});
  }

  offerTransfer(vaultId: string, body: TransferOfferRequest) {
    return this.json<TransferOfferResponse>("POST", `/api/v1/vaults/${vaultId}/transfer`, body);
  }

  cancelTransfer(vaultId: string) {
    return this.json<CreateVaultResponse>("DELETE", `/api/v1/vaults/${vaultId}/transfer`);
  }

  acceptTransfer(vaultId: string, body: TransferAcceptRequest) {
    return this.json<CreateVaultResponse>("POST", `/api/v1/vaults/${vaultId}/transfer/accept`, body);
  }

  updateVaultMeta(vaultId: string, body: VaultMetaUpdateRequest) {
    return this.json<CreateVaultResponse>("PUT", `/api/v1/vaults/${vaultId}/meta`, body);
  }

  putEscrow(sealed: string, fingerprint: string) {
    return this.raw("PUT", "/api/v1/escrow/self", { sealed, fingerprint });
  }

  // F57: current org recovery PUBLIC key (base64url); the client verifies its fingerprint
  // against the user-confirmed sheet value before re-sealing escrow to it.
  recoveryPubkey() {
    return this.text("GET", "/api/v1/recovery-pubkey");
  }

  // ---- attachments (spec 02 §6: body = 24-byte header ‖ ciphertext chunks) ----

  async uploadAttachment(id: string, itemId: string, vaultId: string, body: Uint8Array): Promise<AttachmentMeta> {
    const q = `vaultId=${encodeURIComponent(vaultId)}&itemId=${encodeURIComponent(itemId)}`;
    const resp = await this.rawBytes("POST", `/api/v1/attachments/${id}?${q}`, body);
    if (!resp.ok) await this.throwApiError(resp);
    return (await resp.json()) as AttachmentMeta;
  }

  async downloadAttachment(id: string): Promise<Uint8Array> {
    const resp = await this.rawBytes("GET", `/api/v1/attachments/${id}`, undefined);
    if (!resp.ok) await this.throwApiError(resp);
    return new Uint8Array(await resp.arrayBuffer());
  }

  // ---- server TOTP + password change ----

  totpStatus() {
    return this.json<TotpStatus>("GET", "/api/v1/account/totp");
  }

  totpSetup() {
    return this.json<TotpSetupResponse>("POST", "/api/v1/account/totp/setup");
  }

  totpConfirm(code: string) {
    return this.json<TotpStatus>("POST", "/api/v1/account/totp/confirm", { code });
  }

  totpDisable(code: string) {
    return this.json<TotpStatus>("POST", "/api/v1/account/totp/disable", { code });
  }

  changePassword(req: PasswordChangeRequest) {
    return this.text("PUT", "/api/v1/account/password", req);
  }

  // ---- admin ----

  adminUsers() {
    return this.json<AdminUserSummary[]>("GET", "/api/v1/admin/users");
  }

  adminInvite(email: string, isAdmin: boolean, ttlMinutes?: number) {
    // ttlMinutes absent → the server keeps its 72h default; the QR flow passes ~60 min
    // (the server clamps to [5, 4320]). It is the only containment for a photographed QR.
    return this.json<InviteResponse>("POST", "/api/v1/admin/users", { email, isAdmin, ttlMinutes });
  }

  adminDisableUser(userId: string) {
    return this.text("POST", `/api/v1/admin/users/${userId}/disable`);
  }

  adminDevices(userId: string) {
    return this.json<AdminDeviceSummary[]>("GET", `/api/v1/admin/users/${userId}/devices`);
  }

  /** F59 recovery step 1 — the user's sealed escrow blob (base64url, text/plain) to carry to
   *  offline `recovery-cli recover`. Sealed to the org recovery PUBLIC key, so safe to hand
   *  out. Throws ApiError `no_escrow` (400) if the user never enrolled one. */
  adminUserEscrow(userId: string) {
    return this.text("GET", `/api/v1/admin/users/${userId}/escrow`);
  }

  adminRevokeDevice(deviceId: string) {
    return this.text("POST", `/api/v1/admin/devices/${deviceId}/revoke`);
  }

  adminAudit(params: { since?: number; type?: string; userId?: string; limit?: number }) {
    const q = new URLSearchParams();
    if (params.since !== undefined) q.set("since", String(params.since));
    if (params.type) q.set("type", params.type);
    if (params.userId) q.set("userId", params.userId);
    if (params.limit !== undefined) q.set("limit", String(params.limit));
    const qs = q.toString();
    return this.json<AuditEvent[]>("GET", `/api/v1/admin/audit${qs ? "?" + qs : ""}`);
  }

  adminPolicy() {
    return this.json<ClientPolicy>("GET", "/api/v1/admin/policy");
  }

  adminSetPolicy(policy: ClientPolicy) {
    return this.json<ClientPolicy>("PUT", "/api/v1/admin/policy", policy);
  }

  adminStatus() {
    return this.json<AdminStatus>("GET", "/api/v1/admin/status");
  }

  async hibpRange(prefix: string): Promise<string> {
    const resp = await this.raw("GET", `/api/v1/hibp/range/${prefix}`);
    if (!resp.ok) throw new ApiError(resp.status, "hibp_failed", "hibp range failed");
    return resp.text();
  }

  /**
   * WebSocket dirty-bell with automatic reconnection (spec 03 §6). Auth = a
   * single-use ~30 s ticket minted over the authenticated REST channel — tickets are
   * strictly one-shot, so every (re)connect attempt mints a fresh one; the long-lived
   * access token never appears in a URL.
   *
   * Liveness: any drop (server deploy, laptop sleep, proxy hiccup) reconnects with
   * exponential backoff (1 s → 60 s cap, jittered). `onOpen` fires on EVERY (re)open —
   * consumers use it to `/sync` and catch bells missed while the socket was down (the
   * notifier has no replay). A 401/403 at ticket mint means the session itself is dead
   * (the client already tried a token refresh): reconnection stops and `onRevoked`
   * fires so the consumer drops to the lock screen — with kind "expired", because a
   * dead session is usually plain expiry; only the server's explicit `revoked` frame
   * reports kind "revoked". On tab-visible, a dead socket reconnects immediately
   * instead of waiting out the backoff.
   *
   * Returns a close fn — tears down the socket, any pending retry timer, and the
   * visibility listener (callers MUST invoke it on lock/unmount or sockets leak).
   *
   * `onDown` (optional) reports live connectivity for the UI's status dot: it fires
   * ~2.5 s after the socket drops (debounced so a normal reconnect blip never flips
   * the dot) and `onOpen` is the paired "back up" signal. Start the UI as offline and
   * let the first `onOpen` turn it green.
   */
  events(onRev: (rev: number) => void, onRevoked: (kind: SessionEndKind) => void, onOpen?: () => void, onDown?: () => void): () => void {
    let ws: WebSocket | null = null;
    let closed = false;
    let connecting = false;
    let attempts = 0; // consecutive failed cycles since the last successful open
    let timer: ReturnType<typeof setTimeout> | null = null;
    let downTimer: ReturnType<typeof setTimeout> | null = null;

    // Debounce the "offline" signal: only report down if we stay down past the window,
    // so a 1 s server-deploy reconnect doesn't strobe the status dot.
    const signalDown = () => {
      if (closed || !onDown || downTimer !== null) return;
      downTimer = setTimeout(() => {
        downTimer = null;
        if (!closed) onDown();
      }, 2_500);
    };
    const clearDown = () => {
      if (downTimer !== null) {
        clearTimeout(downTimer);
        downTimer = null;
      }
    };

    const scheduleReconnect = () => {
      if (closed || timer !== null) return;
      // Backoff base 1s·2^n capped at 60s, jittered into [base/2, base] so a fleet of
      // tabs dropped by one server restart doesn't reconnect in lockstep.
      const base = Math.min(60_000, 1_000 * 2 ** Math.min(attempts, 6));
      const delay = base / 2 + Math.random() * (base / 2);
      attempts++;
      timer = setTimeout(() => {
        timer = null;
        void connect();
      }, delay);
    };

    const connect = async () => {
      if (closed || connecting || ws) return;
      connecting = true;
      try {
        // Tickets are single-use (spec 03 §6) — re-mint on every attempt.
        const t = await this.json<WsTicketResponse>("POST", "/api/v1/events/ticket");
        if (closed) return;
        const sock = new WebSocket(this.baseUrl.replace(/^http/, "ws") + `/api/v1/events?ticket=${encodeURIComponent(t.ticket)}`);
        ws = sock;
        sock.onopen = () => {
          attempts = 0; // healthy again — future drops restart the backoff from 1 s
          clearDown();
          onOpen?.();
        };
        sock.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === "rev") onRev(msg.rev);
            else if (msg.type === "revoked") {
              closed = true; // don't race a reconnect against the consumer's teardown
              onRevoked("revoked"); // explicit server frame — a REAL revocation
            }
          } catch {
            /* ignore */
          }
        };
        sock.onclose = () => {
          if (ws === sock) ws = null;
          signalDown();
          scheduleReconnect();
        };
        sock.onerror = () => {
          /* the paired onclose handles recovery */
        };
      } catch (e) {
        if (closed) return;
        if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
          // Session died (refresh already attempted inside json()) — surface it via the
          // consumer's existing session-expiry path and stop retrying. This is plain
          // EXPIRY as far as we can tell (laptop asleep past the refresh lifetime) —
          // never present it as a device revocation.
          closed = true;
          onRevoked("expired");
          return;
        }
        signalDown();
        scheduleReconnect(); // offline / server down — keep trying quietly
      } finally {
        connecting = false;
      }
    };

    // Tab became visible with a dead socket (e.g. laptop woke up): reconnect NOW —
    // don't leave the user staring at stale data for up to a full backoff window.
    const onVisible = () => {
      if (closed || typeof document === "undefined" || document.visibilityState !== "visible") return;
      if (!ws && !connecting) {
        if (timer !== null) {
          clearTimeout(timer);
          timer = null;
        }
        attempts = 0;
        void connect();
      }
    };
    if (typeof document !== "undefined") document.addEventListener("visibilitychange", onVisible);

    void connect();

    return () => {
      closed = true;
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      clearDown();
      if (typeof document !== "undefined") document.removeEventListener("visibilitychange", onVisible);
      ws?.close();
      ws = null;
    };
  }
}
