import type {
  AdminDeviceSummary,
  AdminStatus,
  AdminUserSummary,
  AttachmentMeta,
  AuditEvent,
  ClientPolicy,
  CreateVaultRequest,
  CreateVaultResponse,
  InviteResponse,
  PasswordChangeRequest,
  PreloginResponse,
  PushResponse,
  RegisterRequest,
  SessionResponse,
  SyncResponse,
  TotpSetupResponse,
  TotpStatus,
  Mutation,
  AccountKeys,
  UserLookupResponse,
  VaultMemberAdd,
  VaultMemberSummary,
  WsTicketResponse,
} from "./types";

export const CLIENT_VERSION = "0.3.0";
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

/**
 * REST client for the andvari server. Holds the token pair, refreshes the access
 * token once on 401 and retries, and surfaces 426 (upgrade) / 410 (resync) as typed
 * errors the store handles.
 */
export class ApiClient {
  constructor(
    public baseUrl: string,
    private tokens: Tokens | null = null,
    private onTokens: (t: Tokens | null) => void = () => {},
  ) {}

  setTokens(t: Tokens | null) {
    this.tokens = t;
    this.onTokens(t);
  }

  getTokens(): Tokens | null {
    return this.tokens;
  }

  private async raw(method: string, path: string, body?: unknown, auth = true, retry = true): Promise<Response> {
    const headers: Record<string, string> = { "X-Andvari-Client": CLIENT_HEADER };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (auth && this.tokens) headers["Authorization"] = `Bearer ${this.tokens.accessToken}`;
    const resp = await fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (resp.status === 401 && auth && retry && this.tokens) {
      if (await this.tryRefresh()) return this.raw(method, path, body, auth, false);
    }
    return resp;
  }

  private async tryRefresh(): Promise<boolean> {
    if (!this.tokens) return false;
    const resp = await fetch(this.baseUrl + "/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Andvari-Client": CLIENT_HEADER },
      body: JSON.stringify({ refreshToken: this.tokens.refreshToken }),
    });
    if (!resp.ok) {
      this.setTokens(null);
      return false;
    }
    const pair = (await resp.json()) as Tokens;
    this.setTokens(pair);
    return true;
  }

  /** Like raw() but with a binary request body (attachments). */
  private async rawBytes(method: string, path: string, body: Uint8Array | undefined, retry = true): Promise<Response> {
    const headers: Record<string, string> = { "X-Andvari-Client": CLIENT_HEADER };
    if (body !== undefined) headers["Content-Type"] = "application/octet-stream";
    if (this.tokens) headers["Authorization"] = `Bearer ${this.tokens.accessToken}`;
    const resp = await fetch(this.baseUrl + path, { method, headers, body: body as BodyInit | undefined });
    if (resp.status === 401 && retry && this.tokens) {
      if (await this.tryRefresh()) return this.rawBytes(method, path, body, false);
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

  async login(email: string, authKey: string, deviceName: string, totp?: string): Promise<SessionResponse> {
    const s = await this.json<SessionResponse>(
      "POST",
      "/api/v1/auth/login",
      { email, authKey, device: { platform: "web", name: deviceName }, ...(totp ? { totp } : {}) },
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

  removeVaultMember(vaultId: string, userId: string) {
    return this.json<CreateVaultResponse>("DELETE", `/api/v1/vaults/${vaultId}/members/${userId}`);
  }

  putEscrow(sealed: string, fingerprint: string) {
    return this.raw("PUT", "/api/v1/escrow/self", { sealed, fingerprint });
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

  adminInvite(email: string, isAdmin: boolean) {
    return this.json<InviteResponse>("POST", "/api/v1/admin/users", { email, isAdmin });
  }

  adminDisableUser(userId: string) {
    return this.text("POST", `/api/v1/admin/users/${userId}/disable`);
  }

  adminDevices(userId: string) {
    return this.json<AdminDeviceSummary[]>("GET", `/api/v1/admin/users/${userId}/devices`);
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
   * WebSocket dirty-bell. Auth = a single-use ~30 s ticket minted over the
   * authenticated REST channel (spec 03 §6) — the long-lived access token never
   * appears in a URL. Returns a close fn; `onOpen` fires once the socket is up
   * (the mint adds a round-trip, so callers racing a push should await it).
   */
  events(onRev: (rev: number) => void, onRevoked: () => void, onOpen?: () => void): () => void {
    let ws: WebSocket | null = null;
    let closed = false;
    void (async () => {
      try {
        const t = await this.json<WsTicketResponse>("POST", "/api/v1/events/ticket");
        if (closed) return;
        const sock = new WebSocket(this.baseUrl.replace(/^http/, "ws") + `/api/v1/events?ticket=${encodeURIComponent(t.ticket)}`);
        ws = sock;
        sock.onopen = () => onOpen?.();
        sock.onmessage = (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === "rev") onRev(msg.rev);
            else if (msg.type === "revoked") onRevoked();
          } catch {
            /* ignore */
          }
        };
      } catch {
        /* bell unavailable (offline / expired session) — sync still works on demand */
      }
    })();
    return () => {
      closed = true;
      ws?.close();
    };
  }
}
