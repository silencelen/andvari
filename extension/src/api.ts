import type { KdfParams } from "./crypto";

/**
 * andvari API client for the extension. Same wire as web/src/api/client.ts (Bearer JSON). Cross-
 * origin fetch to the tailnet server works WITHOUT CORS via the manifest host_permissions (spike doc
 * Unknown 2). Surface: prelogin → login → sync → push (+ client-policy). A 401 rotates the token
 * pair once and retries transparently; `onTokensRotated` lets a session custodian re-persist it.
 */

export interface PreloginResponse {
  kdfSalt: string;
  kdfParams: KdfParams;
}
export interface AccountKeys {
  kdfSalt: string;
  kdfParams: KdfParams;
  wrappedUvk: string;
  encryptedIdentitySeed: string;
  identityPub: string;
}
export interface SessionResponse {
  userId: string;
  deviceId: string;
  accessToken: string;
  refreshToken: string;
  accountKeys: AccountKeys;
}
export interface WireGrant {
  vaultId: string;
  userId: string;
  role: string;
  wrappedVk: string;
  sealedVk?: string | null; // member grants (crypto_box_seal to identityPub) — TODO(extension)
}
export interface WireItem {
  itemId: string;
  vaultId: string;
  /** Server revision — the baseItemRev an update put must carry (conflict detection). */
  rev: number;
  deleted: boolean;
  formatVersion: number;
  blob: string | null;
}
export interface WireVault {
  vaultId: string;
  type: string; // "personal" | "shared"
}
export interface SyncResponse {
  rev: number;
  vaults: WireVault[];
  grants: WireGrant[];
  items: WireItem[];
}

export interface ItemUpload {
  formatVersion: number;
  attachmentIds: string[];
  blob: string;
}
export interface Mutation {
  mutationId: string;
  op: "put" | "delete";
  itemId: string;
  vaultId: string;
  baseItemRev: number;
  item?: ItemUpload;
}
/** Per-mutation outcome. HTTP 200 does NOT mean applied — callers must check `status`
 *  (a conflicted put answers 200 with status:"conflict" + the winning serverItem). */
export interface MutationResult {
  mutationId: string;
  status: "applied" | "conflict" | "duplicate" | "denied";
  newItemRev?: number;
  serverItem?: WireItem;
}
export interface PushResponse {
  rev: number;
  results: MutationResult[];
}

export interface ClientPolicyResponse {
  serverTime: number;
  /** Idle-lock window in seconds; 0 disables (spec 01 §8). Optional: older servers omit it. */
  autoLockSeconds?: number;
  clipboardClearSeconds?: number;
}

export class AndvariApi {
  constructor(
    private baseUrl: string,
    private accessToken: string | null = null,
    private refreshToken: string | null = null,
  ) {}

  /** Fires after a 401→refresh rotation. Refresh tokens are SINGLE-USE: a custodian that
   *  persists the session must re-persist on rotation — restoring a consumed pair reads as
   *  token reuse server-side and revokes the whole device. */
  onTokensRotated: ((access: string, refresh: string) => void) | null = null;

  setTokens(access: string | null, refresh: string | null): void {
    this.accessToken = access;
    this.refreshToken = refresh;
  }

  getTokens(): { access: string | null; refresh: string | null } {
    return { access: this.accessToken, refresh: this.refreshToken };
  }

  private async json<T>(method: string, path: string, body?: unknown, retrying = false): Promise<T> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.accessToken) headers["authorization"] = `Bearer ${this.accessToken}`;
    const resp = await fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    // On an expired access token, rotate once and retry (SW is single-threaded, so no cross-tab race).
    if (resp.status === 401 && !retrying && (await this.tryRefresh())) {
      return this.json<T>(method, path, body, true);
    }
    if (!resp.ok) throw new ApiError(resp.status, await resp.text().catch(() => ""));
    return (await resp.json()) as T;
  }

  /** Coalesce concurrent 401s onto ONE rotation. Two API calls can be in flight in the SW at once
   *  (e.g. the resync alarm's sync + a user save); if both 401, the first consumes the single-use
   *  refresh token and the second would read the now-null token and fail spuriously. Sharing the
   *  in-flight promise makes the second await the same rotation and retry with the fresh access. */
  private refreshInFlight: Promise<boolean> | null = null;
  private tryRefresh(): Promise<boolean> {
    this.refreshInFlight ??= this.doRefresh().finally(() => {
      this.refreshInFlight = null;
    });
    return this.refreshInFlight;
  }

  /** Rotate the token pair (single-use refresh — consume it before the request so a reuse can't
   *  leak; reuse would revoke the whole device). Returns whether a fresh access token is now held. */
  private async doRefresh(): Promise<boolean> {
    const rt = this.refreshToken;
    if (!rt) return false;
    this.refreshToken = null;
    try {
      const resp = await fetch(this.baseUrl + "/api/v1/auth/refresh", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ refreshToken: rt }),
      });
      if (!resp.ok) return false;
      const s = (await resp.json()) as { accessToken: string; refreshToken: string };
      this.accessToken = s.accessToken;
      this.refreshToken = s.refreshToken;
      this.onTokensRotated?.(s.accessToken, s.refreshToken);
      return true;
    } catch {
      return false;
    }
  }

  /** Unauthenticated: liveness smoke check (spike verification step 3) + the fleet lock policy. */
  clientPolicy(): Promise<ClientPolicyResponse> {
    return this.json("GET", "/api/v1/client-policy");
  }

  prelogin(email: string): Promise<PreloginResponse> {
    return this.json("POST", "/api/v1/auth/prelogin", { email });
  }

  /** Login with the derived authKey (base64). Returns tokens + the account's wrapped keys. */
  login(email: string, authKey: string, totp?: string): Promise<SessionResponse> {
    return this.json("POST", "/api/v1/auth/login", {
      email,
      authKey,
      device: { platform: "web", name: "Browser extension" },
      ...(totp ? { totp } : {}),
    });
  }

  /** Full snapshot when since=0: vaults/grants/items as deltas over the global rev. */
  sync(since = 0): Promise<SyncResponse> {
    return this.json("GET", `/api/v1/sync?since=${since}`);
  }

  /** Save/update flow: push put/delete mutations (the client-encrypted item rides in item.blob).
   *  Check results[] — see MutationResult. */
  push(mutations: Mutation[]): Promise<PushResponse> {
    return this.json("POST", "/api/v1/sync/push", { mutations });
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    body: string,
  ) {
    super(`andvari api ${status}: ${body.slice(0, 200)}`);
  }
}
