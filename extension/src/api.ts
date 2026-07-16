import type { KdfParams } from "./crypto";

/**
 * andvari API client for the extension. Same wire as web/src/api/client.ts (Bearer JSON). Cross-
 * origin fetch to the tailnet server works WITHOUT CORS via the manifest host_permissions (spike doc
 * Unknown 2). Surface: prelogin → login → sync → push (+ client-policy). Every request carries
 * `X-Andvari-Client: extension/<version>` (spec 03 §1) so a server min-version pin can reach it.
 * A 401 rotates the token pair once and retries transparently; `onTokensChanged` (awaited) lets a
 * session custodian re-persist the pair on EVERY mutation — including the pre-POST consume, so an
 * SW death mid-refresh can never resurrect a spent token (exttech-3). Chrome-free by design: the
 * manifest version is injected via the constructor, so the client is plain-node testable.
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
  /** Set by a rescue (admin-issued temporary password), cleared by a password change (Service.kt).
   *  The extension can't change the password itself, so it just nudges the user to the web vault. */
  mustChangePassword?: boolean;
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
  // ---- multi-tenant / endpoint-agnostic pivot (design 2026-07-15 §2.1/§2.2) ----
  // Additive/optional — old servers omit them; mirrors core Wire.kt ClientPolicy +
  // web/src/api/types.ts ClientPolicy, byte-consistent.
  /** §2.1 enum: "closed" | "invite-only" | "landing" | "open". Absent (old server) OR unknown value
   *  (newer server) ⇒ treat as "invite-only": plain invite-gated enroll, never open-register UI,
   *  no stranger nudge. Register success stays server-enforced (invite-ROW gate) either way. */
  signupMode?: string;
  /** §2.6 — per-instance login-factor stance. A UI pre-prompt HINT only; the reactive server errors
   *  (totp_required / public_login_requires_totp) stay authoritative. Never gates a client-side
   *  protection (§2.3 trust table). Absent ⇒ false. */
  totpRequired?: boolean;
  /** Decorative label — NEVER rendered as a verified identity, never in the trust gate (§2.3). */
  instanceName?: string | null;
  /** Server-claimed own origin — proxy-misconfig diagnostic only; never a trust anchor (§2.3). */
  canonicalOrigin?: string | null;
  /** Rendered as a raw https URL only (§2.3 R8 rule) — never as trusted branding. */
  selfHostDocsUrl?: string | null;
}

/** Client-side ceilings for the server-declared policy timers (design 2026-07-15 §2.3, breaker B1-1).
 *  Byte-pinned mirror of core `ClientPolicyClamps` (Kotlin) — locked three-way (core/web/ext) by
 *  `web/src/policy-clamps.test.ts`; bump all three together. The fields are CLIENT-FLOOR-ONLY: a
 *  hostile server may make the client safer, never laxer — a 0/absent/oversized `autoLockSeconds`
 *  clamps to the ceiling, so a server cannot disable auto-lock or pin the clipboard for hours.
 *  Wave 1 defines the constants only; call-site clamping (background.ts policy consumers) is wave-2 work. */
export const AUTO_LOCK_MAX_SECONDS = 900;
export const CLIPBOARD_CLEAR_MAX_SECONDS = 300;

/** Single-use /events WebSocket ticket (spec 03 §6). Field names mirror core Wire.kt
 *  WsTicketResponse — the deviceId binding is server-side from the Bearer principal. */
export interface WsTicketResponse {
  ticket: string;
  expiresInSeconds: number;
}

export class AndvariApi {
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  /** `extension/<version>` — the spec 03 §1 client id. Built from the manifest version passed in
   *  by background.ts, so api.ts itself stays chrome-free (and node-testable). */
  private readonly clientHeader: string;

  constructor(baseUrl: string, clientVersion?: string) {
    this.baseUrl = baseUrl;
    this.clientHeader = `extension/${clientVersion ?? "0.0.0"}`;
  }

  /** Fires on EVERY token-pair mutation (consume, restore, definitive clear, success). Awaited, so
   *  a session custodian can persist the snapshot BEFORE the refresh POST — a consumed single-use
   *  refresh token that resurrects from a stale snapshot reads as reuse server-side and revokes the
   *  whole device (exttech-3). Replaces the old success-only onTokensRotated. */
  onTokensChanged: (() => void | Promise<void>) | null = null;

  /** Fired when the server refuses a call with body code `upgrade_required` (HTTP 426 min-version
   *  pin, spec 03 §1). The refused call still throws its ApiError — this is a side-channel nudge,
   *  not a replacement error path (web client.ts:120 parity). */
  onUpgradeRequired: (() => void) | null = null;

  setTokens(access: string | null, refresh: string | null): void {
    this.accessToken = access;
    this.refreshToken = refresh;
  }

  getTokens(): { access: string | null; refresh: string | null } {
    return { access: this.accessToken, refresh: this.refreshToken };
  }

  private async json<T>(method: string, path: string, body?: unknown, retrying = false): Promise<T> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "X-Andvari-Client": this.clientHeader,
    };
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
    if (!resp.ok) await this.throwApiError(resp);
    return (await resp.json()) as T;
  }

  /** Parse the server's `{error, message}` body into a typed ApiError (web throwApiError parity):
   *  clients key on the BODY code, never the bare status. Non-JSON bodies fall back to
   *  `http_<status>` + statusText. A body code of `upgrade_required` additionally fires
   *  onUpgradeRequired before the throw. */
  private async throwApiError(resp: Response): Promise<never> {
    let code = `http_${resp.status}`;
    let message = resp.statusText;
    try {
      const err = (await resp.json()) as { error?: string; message?: string };
      code = err.error ?? code;
      message = err.message ?? message;
    } catch {
      /* non-JSON error body — keep the http_<status>/statusText fallback */
    }
    if (code === "upgrade_required") this.onUpgradeRequired?.();
    throw new ApiError(resp.status, code, message);
  }

  /** Coalesce concurrent 401s onto ONE rotation. Two API calls can be in flight in the SW at once
   *  (e.g. the resync alarm's sync + a user save); if both 401, the first consumes the single-use
   *  refresh token and the second would read the now-null token and fail spuriously. Sharing the
   *  in-flight promise makes the second await the same rotation and retry with the fresh access
   *  (AM6 — this single-flight is what prevents self-inflicted `refresh_reuse` device revocation). */
  private refreshInFlight: Promise<boolean> | null = null;
  private tryRefresh(): Promise<boolean> {
    this.refreshInFlight ??= this.doRefresh().finally(() => {
      this.refreshInFlight = null;
    });
    return this.refreshInFlight;
  }

  /**
   * Rotate the token pair, adapted to the SW snapshot reality (AM1). The single-use refresh token
   * is consumed and PERSISTED (refresh:null) BEFORE the POST — a woken SW that finds `{access,
   * refresh:null}` runs on the access token until a 401 and never replays a spent token. On a
   * transient failure (5xx / network) the pair is RESTORED so one blip doesn't dead-end the SW
   * life; only a definitive 401/403 kills it. Returns whether a fresh access token is now held.
   */
  private async doRefresh(): Promise<boolean> {
    const rt = this.refreshToken;
    if (!rt) return false;
    // 1. Consume + persist the consumed state before the POST (onTokensChanged is awaited).
    this.refreshToken = null;
    const atConsume = this.accessToken;
    await this.onTokensChanged?.();
    // 3. Outcome guard (AM1): apply the outcome ONLY if the pair is untouched since consume — a
    //    concurrent setTokens (doLock/unlock, spanning a lock→unlock) now owns it, so discard this
    //    refresh entirely (no set, no clear, no restore, no notify) rather than clobber the new pair.
    const owns = (): boolean => this.refreshToken === null && this.accessToken === atConsume;
    try {
      const resp = await fetch(this.baseUrl + "/api/v1/auth/refresh", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Andvari-Client": this.clientHeader },
        body: JSON.stringify({ refreshToken: rt }),
      });
      if (!resp.ok) {
        if (!owns()) return false;
        if (resp.status === 401 || resp.status === 403) {
          // Definitive refusal → the pair is dead (web client.ts:220 parity).
          this.accessToken = null;
          this.refreshToken = null;
          await this.onTokensChanged?.();
        } else {
          // 5xx / 429 / proxy error page — transient: restore so the session isn't dead-ended.
          this.refreshToken = rt;
          await this.onTokensChanged?.();
        }
        return false;
      }
      const s = (await resp.json()) as { accessToken: string; refreshToken: string };
      if (!owns()) return false;
      this.accessToken = s.accessToken;
      this.refreshToken = s.refreshToken;
      await this.onTokensChanged?.();
      return true;
    } catch {
      // Thrown fetch (transport failure) — same transient-keep as a 5xx.
      if (owns()) {
        this.refreshToken = rt;
        await this.onTokensChanged?.();
      }
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

  /** The account's wrapped keys (spec 03 — same bundle the login response carries). The extension's
   *  quick-unlock redeem (spec 01 §8.4) consumes this with the tokens it already holds instead of a
   *  fresh login: unwrap encryptedIdentitySeed under the recovered UVK + hard-compare identityPub.
   *  Rides json(), so the Bearer header, the 401→refresh→retry, and ApiError parsing all apply. */
  getAccountKeys(): Promise<AccountKeys> {
    return this.json("GET", "/api/v1/account/keys");
  }

  /**
   * Force a token rotation as an explicit first server contact (quick-unlock redeem, spec 01 §8.4 /
   * breaker A3⊕B2). Unlike the 401-driven tryRefresh this POSTs unconditionally, and it reports a
   * THREE-state outcome so the caller can route revocation to a full wipe: `revoked` = the refresh
   * token is definitively dead (revoked/rotated elsewhere → device revoked, password changed
   * elsewhere) ⇒ wipe the blob+tokens, full sign-in; `transient` = offline/5xx ⇒ keep the blob, try
   * the master password this time; `rotated` = a fresh pair is now held. AM1 parity: the consumed
   * refresh token is persisted (refresh:null) via onTokensChanged BEFORE the POST, so a mid-refresh
   * SW death never resurrects a spent token. A missing refresh token is treated as `revoked`.
   */
  async forceRefresh(): Promise<"rotated" | "revoked" | "transient"> {
    const rt = this.refreshToken;
    if (!rt) return "revoked";
    this.refreshToken = null; // consume + persist the consumed state before the POST (AM1)
    await this.onTokensChanged?.();
    try {
      const resp = await fetch(this.baseUrl + "/api/v1/auth/refresh", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Andvari-Client": this.clientHeader },
        body: JSON.stringify({ refreshToken: rt }),
      });
      if (!resp.ok) {
        if (resp.status === 401 || resp.status === 403) {
          this.accessToken = null;
          this.refreshToken = null;
          await this.onTokensChanged?.();
          return "revoked";
        }
        this.refreshToken = rt; // 5xx / 429 / proxy — transient: restore so the pair isn't dead-ended
        await this.onTokensChanged?.();
        return "transient";
      }
      const s = (await resp.json()) as { accessToken: string; refreshToken: string };
      this.accessToken = s.accessToken;
      this.refreshToken = s.refreshToken;
      await this.onTokensChanged?.();
      return "rotated";
    } catch {
      this.refreshToken = rt; // transport failure — transient-keep (same as a 5xx)
      await this.onTokensChanged?.();
      return "transient";
    }
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

  /** Mint a single-use ~30 s ticket for the /events dirty-bell WebSocket (spec 03 §6). Minted
   *  fresh per connect attempt and NEVER persisted — the access token never rides a URL. Rides
   *  json(), so the Bearer header, the single-flight 401→refresh→retry, and ApiError parsing
   *  all apply. */
  eventsTicket(): Promise<WsTicketResponse> {
    return this.json("POST", "/api/v1/events/ticket");
  }
}

/** A refused server response, carrying the parsed BODY code (spec 03 §8) — surfaces map the code
 *  to copy; `message` is human/debug detail only. `status` + `code` are explicit fields (not
 *  parameter properties) so this file type-strips under plain `node --test`. */
export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.name = "ApiError";
  }
}
