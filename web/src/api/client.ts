import type {
  ClientPolicy,
  PreloginResponse,
  PushResponse,
  RegisterRequest,
  SessionResponse,
  SyncResponse,
  Mutation,
  AccountKeys,
} from "./types";

export const CLIENT_VERSION = "0.1.0";
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

  private async json<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
    const resp = await this.raw(method, path, body, auth);
    if (!resp.ok) {
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
    const text = await resp.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  prelogin(email: string) {
    return this.json<PreloginResponse>("POST", "/api/v1/auth/prelogin", { email }, false);
  }

  register(req: RegisterRequest) {
    return this.json<SessionResponse>("POST", "/api/v1/auth/register", req, false);
  }

  async login(email: string, authKey: string, deviceName: string): Promise<SessionResponse> {
    const s = await this.json<SessionResponse>(
      "POST",
      "/api/v1/auth/login",
      { email, authKey, device: { platform: "web", name: deviceName } },
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

  putEscrow(sealed: string, fingerprint: string) {
    return this.raw("PUT", "/api/v1/escrow/self", { sealed, fingerprint });
  }

  async hibpRange(prefix: string): Promise<string> {
    const resp = await this.raw("GET", `/api/v1/hibp/range/${prefix}`);
    if (!resp.ok) throw new ApiError(resp.status, "hibp_failed", "hibp range failed");
    return resp.text();
  }

  /** WebSocket dirty-bell. Returns a close fn. */
  events(onRev: (rev: number) => void, onRevoked: () => void): () => void {
    const wsUrl = this.baseUrl.replace(/^http/, "ws") + `/api/v1/events?access=${encodeURIComponent(this.tokens?.accessToken ?? "")}`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "rev") onRev(msg.rev);
        else if (msg.type === "revoked") onRevoked();
      } catch {
        /* ignore */
      }
    };
    return () => ws.close();
  }
}
