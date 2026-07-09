import type { KdfParams } from "./crypto";

/**
 * andvari API client for the extension. Same wire as web/src/api/client.ts (Bearer JSON). Cross-
 * origin fetch to the tailnet server works WITHOUT CORS via the manifest host_permissions (spike doc
 * Unknown 2). Only the fill surface is here: prelogin → login → sync. Token refresh, save/push,
 * lifecycle are TODO(extension) as the SW grows.
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
  deleted: boolean;
  formatVersion: number;
  blob: string | null;
}
export interface SyncResponse {
  rev: number;
  grants: WireGrant[];
  items: WireItem[];
}

export class AndvariApi {
  constructor(
    private baseUrl: string,
    private accessToken: string | null = null,
  ) {}

  setToken(token: string | null): void {
    this.accessToken = token;
  }

  private async json<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.accessToken) headers["authorization"] = `Bearer ${this.accessToken}`;
    const resp = await fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!resp.ok) throw new ApiError(resp.status, await resp.text().catch(() => ""));
    return (await resp.json()) as T;
  }

  /** Unauthenticated liveness/CSP/host_permissions smoke check (spike verification step 3). */
  clientPolicy(): Promise<{ serverTime: number }> {
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
}

export class ApiError extends Error {
  constructor(
    public status: number,
    body: string,
  ) {
    super(`andvari api ${status}: ${body.slice(0, 200)}`);
  }
}
