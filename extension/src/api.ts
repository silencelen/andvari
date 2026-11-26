import { grantedVaultIdsOf, refusedSession, sanitizeAccountKeys, sanitizeSync, type Refusal, type Sanitized } from "./wireids.ts";
import type { KdfParams } from "./crypto";
import type { DeviceObject } from "./device.ts";

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
  /** The personal vault's key under the UVK (spec 03 §3), set once by registration. In force only when it names the
   *  genesis's `personalVaultId` and opens (design 2026-11-15 §5.3); a withheld one leaves no personal vault. */
  personalWrap?: { vaultId: string; wrappedVk: string } | null;
  /** The account genesis record, a purpose-0x05 frame (design §5). Verified at every unlock (genesis.ts). */
  genesis?: string | null;
}
export interface SessionResponse {
  userId: string;
  deviceId: string;
  accessToken: string;
  refreshToken: string;
  accountKeys: AccountKeys;
  /** `operator` or `member` (spec 03 §2). The extension signs in only as `member` (design §12.2 rule 7): anything else,
   *  an absent field included, is revoked and refused (background hydrateSession). */
  role?: string;
}
export interface WireGrant {
  vaultId: string;
  userId: string;
  role: string;
  /** The owner wrap or member self-wrap under the UVK (genesis-bound AD for a shared vault); empty until a full client
   *  posts the self-wrap. The only key material the extension opens (§12.2 rule 1). */
  wrappedVk: string;
  /** A member grant's sealed 0x01 grant. Never opened or verified by the extension (§12.2 rule 1). */
  signedGrant?: string | null;
}
export interface WireItem {
  itemId: string;
  vaultId: string;
  /** Server revision — the baseItemRev an update put must carry (conflict detection). */
  rev: number;
  deleted: boolean;
  formatVersion: number;
  blob: string | null;
  /** Server write time (ms since epoch). Optional here because the extension never needed it
   *  before H20: it stamps the "(conflict YYYY-MM-DD)" copy name from the DISPLACED version's
   *  write day (web store.ts parity); absent ⇒ the materializer falls back to now. */
  updatedAt?: number;
}
export interface WireVault {
  vaultId: string;
  type: string; // "personal" | "shared" — a server label; the extension decides NOTHING from it (A5 review H-1)
  /** Vault meta ciphertext under the VK (spec 02 §4); read only to NAME vaults in the change notice (A6). */
  metaBlob?: string;
}
export interface SyncResponse {
  rev: number;
  vaults: WireVault[];
  grants: WireGrant[];
  items: WireItem[];
}

/** A sync answer as `sync()` returns it: sanitized, with the vaults it still grants (wireids.ts grantedVaultIdsOf). */
export interface SyncAnswer extends SyncResponse {
  grantedVaultIds: ReadonlySet<string> | null;
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
  /** `rejected` (spec 03 §5, audit 2026-09-13 H03 / recheck R37): a put the server can NEVER
   *  apply as sent — its attachment refs no longer resolve, or it is over the per-item quota.
   *  Permanent, not retryable: the same put fails identically forever (web/core twins). */
  status: "applied" | "conflict" | "duplicate" | "denied" | "rejected";
  newItemRev?: number;
  serverItem?: WireItem;
  /** `rejected` only: `unknown_attachment` | `attachment_mismatch` | `item_attachment_quota`. */
  reason?: string;
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
 *  Applied by the clamp helpers below at the background.ts policy consumers (wave 2). */
export const AUTO_LOCK_MAX_SECONDS = 900;
export const CLIPBOARD_CLEAR_MAX_SECONDS = 300;

/** §2.3/B1-1 idle-lock clamp. Absent/non-finite → the caller's default (itself ceiling-bounded);
 *  0/negative — the "never lock" attempt — clamps to the CEILING, never to "disabled": a server
 *  cannot switch the idle lock off. Anything above the ceiling clamps down; in-range passes as-is
 *  (a server may always tighten). Chrome-free + pure, so the node suite pins every branch. */
export function clampAutoLockSeconds(v: unknown, fallback: number): number {
  if (typeof v !== "number" || !Number.isFinite(v)) return Math.min(fallback, AUTO_LOCK_MAX_SECONDS);
  if (v <= 0) return AUTO_LOCK_MAX_SECONDS;
  return Math.min(v, AUTO_LOCK_MAX_SECONDS);
}

/** §2.3/B1-1 clipboard-clear clamp into [1, CLIPBOARD_CLEAR_MAX_SECONDS]: a 0 (never clear) or an
 *  hours-long window from a hostile server both clamp into range; absent/non-finite → the caller's
 *  default, same-bounded. */
export function clampClipboardClearSeconds(v: unknown, fallback: number): number {
  const pick = typeof v === "number" && Number.isFinite(v) ? v : fallback;
  return Math.min(Math.max(pick, 1), CLIPBOARD_CLEAR_MAX_SECONDS);
}

/** Single-use /events WebSocket ticket (spec 03 §6). Field names mirror core Wire.kt
 *  WsTicketResponse — the deviceId binding is server-side from the Bearer principal. */
export interface WsTicketResponse {
  ticket: string;
  expiresInSeconds: number;
}

export class AndvariApi {
  /**
   * Security review 2026-10 (plugin scan F1/F2, branch A10): every server-supplied id is checked against the UUID
   * grammar here, at the wire boundary (wireids.ts); a row with a malformed id is dropped before any caller sees it
   * and reported here as `(endpoint, refusals)`. A session with a malformed user or device id is refused outright
   * (`bad_wire_id`), before any token is held.
   */
  onRefusedIds: ((endpoint: string, refused: Refusal[]) => void) | null = null;

  private reported<T>(endpoint: string, s: Sanitized<T>): T {
    if (s.refused.length > 0) this.onRefusedIds?.(endpoint, s.refused);
    return s.value;
  }

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

  /** Design 2026-11-15 §4.4: called after the server definitively refused a refresh (401/403 in its own envelope) of the
   *  pair this client holds, once the dead pair is forgotten (`refused`); or after a refresh whose answer never came had
   *  no try left, so nothing was sent and the session ended here (`not_confirmed`, never said as the server's end). The
   *  background ends the session there; it never deletes what it holds. */
  onRefreshRefused: ((why: RefreshEnd) => void) | null = null;

  /** A refresh answered after this client's pair was cleared (a lock that stopped waiting for it), with the
   *  access token it consumed and the pair the answer leaves usable: the server's new pair, or, after a transient
   *  failure, the consumed one with its refresh token back. Awaited before the refresh settles. Not called when another
   *  pair was set meanwhile (that pair owns the client), nor after a definitive refusal. */
  onLateRefresh: ((consumed: string, pair: { access: string; refresh: string | null }) => Promise<void>) | null = null;

  /** The outcome of a refresh this client no longer owns: handed to onLateRefresh only when the pair was cleared. */
  private async lateRefresh(consumed: string | null, pair: { access: string; refresh: string | null }): Promise<void> {
    if (consumed === null || this.accessToken !== null || this.refreshToken !== null) return;
    await this.onLateRefresh?.(consumed, pair);
  }

  /** Security review 2026-10 (A16 review R4): asked before EVERY request this client would send — a call, a refresh, a
   *  logout. While it answers false nothing reaches the network: a call throws `confirm_server` (status 0), a refresh
   *  reports no fresh token and leaves the pair as it was, a logout reports false. Background: no server is dialed while
   *  one is pending or unknown (serverstate.ts). Null = always allowed. */
  mayDial: (() => boolean) | null = null;

  private dialAllowed(): boolean {
    return this.mayDial === null || this.mayDial();
  }

  private refuseDial(): ApiError {
    return new ApiError(0, "confirm_server", "no server is dialed while one awaits confirmation");
  }

  setTokens(access: string | null, refresh: string | null): void {
    this.accessToken = access;
    this.refreshToken = refresh;
    this.refreshMark = null;
  }

  /** The pair as it may be kept. A refresh token whose refresh got no answer of the server's ([refreshMark]) is never
   *  handed out: no snapshot or stash keeps it, so a worker that dies (or restarts) sends it nowhere again. */
  getTokens(): { access: string | null; refresh: string | null } {
    return { access: this.accessToken, refresh: this.refreshMark === null ? this.refreshToken : null };
  }

  /**
   * The mark that a refresh of [refreshToken] got no answer of the server's (spec 03 §2, the refresh's grace): the wall
   * time of its first sending, and whether its one more try was sent. Held in this worker's memory only (getTokens
   * hides the token): the one more try goes only within REFRESH_SECOND_TRY_MS of the first sending, by this worker, and
   * never a third; a worker that dies in the meantime has nothing to send.
   */
  private refreshMark: { outAt: number; triedAgain: boolean } | null = null;

  /** The refresh token of a session that ended here with no try left, kept for one use: the next sign-in's name for the
   *  session it replaces (`replacesRefreshToken`). Never sent as a refresh or to end a session. */
  keptUnconfirmed: string | null = null;

  /** The refresh token of the pair held here while a refresh of it got no answer of the server's and its mark stands
   *  (getTokens hides it), else null: a lock keeps it for the next sign-in's name, a sign-out drops it. */
  unansweredRefreshToken(): string | null {
    return this.refreshMark !== null ? this.refreshToken : null;
  }

  private async json<T>(method: string, path: string, body?: unknown, retrying = false): Promise<T> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "X-Andvari-Client": this.clientHeader,
    };
    if (this.accessToken) headers["authorization"] = `Bearer ${this.accessToken}`;
    if (!this.dialAllowed()) throw this.refuseDial();
    const resp = await fetch(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
    });
    // No redirect is followed on the server's routes: the server never answers with one, so it is an answer that is not
    // the server's (a proxy, a captive portal), and what the server did cannot be told from it.
    if (isRedirect(resp)) throw new ApiError(0, "redirect_refused", `the answer was a redirect (HTTP ${resp.status}), not the server's own`);
    // On an expired access token, rotate once and retry (SW is single-threaded, so no cross-tab race). A refresh that did
    // not renew the session although it lives, or that ended it here, is not handed back as this request's 401 (which
    // its callers read as the session's end): a renewal with no answer of the server's fails as a request with no answer.
    if (resp.status === 401 && !retrying) {
      const outcome = await this.tryRefresh();
      if (outcome === "renewed") return this.json<T>(method, path, body, true);
      if (outcome === "unanswered" || outcome === "unavailable") throw new RefreshUnansweredError(outcome);
      if (outcome === "not_confirmed") throw new SessionNotConfirmedError();
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
  private refreshInFlight: Promise<RefreshOutcome> | null = null;
  /** Settles when no refresh of this client's pair is on the wire (at once when none is). Never rejects.
   *  A lock waits on it, bounded, so it stashes the pair the server answered rather than the consumed one. */
  refreshSettled(): Promise<void> {
    return (this.refreshInFlight ?? Promise.resolve("dropped")).then(
      () => {},
      () => {},
    );
  }
  private tryRefresh(): Promise<RefreshOutcome> {
    this.refreshInFlight ??= this.doRefresh().finally(() => {
      this.refreshInFlight = null;
    });
    return this.refreshInFlight;
  }

  /**
   * Rotate the token pair, adapted to the SW snapshot reality (AM1). The single-use refresh token is consumed and
   * PERSISTED (refresh:null) BEFORE the POST — a woken SW that finds `{access, refresh:null}` runs on the access token
   * until a 401 and never replays a spent token. Spec 03 §2, the refresh's grace (the rule the shared code and the web
   * client keep): only an answer in the server's own envelope says what became of the token. Its refusal (401/403, or a
   * refresh code) ends the session as the server's; its answer for the moment (5xx, 429) to a first try restores the
   * token. Any other outcome (no answer, a gateway's page of any status, a redirect, a body that does not read) leaves
   * the token in memory, marked ([refreshMark]), for ONE more try within REFRESH_SECOND_TRY_MS of the first sending;
   * after that, or after the one more try, nothing is sent: the session ends here (`not_confirmed`), its token kept for
   * the next sign-in's name.
   */
  private async doRefresh(): Promise<RefreshOutcome> {
    const rt = this.refreshToken;
    if (!rt) {
      // A pair whose refresh token is missing while no renewal of it is on the wire: a renewal was out when the worker
      // stopped (the consume was persisted before the POST), and its answer never came to this worker. The token is not
      // known any more, so nothing can be sent or kept: the session ends here, not confirmed, and says so once.
      if (this.accessToken !== null && this.consumesOut === 0) {
        this.accessToken = null;
        await this.onTokensChanged?.();
        this.onRefreshRefused?.("not_confirmed");
        return "not_confirmed";
      }
      return "dropped";
    }
    if (!this.dialAllowed()) return "dropped"; // nothing consumed, nothing sent
    const mark = this.refreshMark;
    if (mark !== null) {
      const now = Date.now();
      if (mark.triedAgain || now < mark.outAt || now - mark.outAt > REFRESH_SECOND_TRY_MS) {
        await this.noTryLeft(rt);
        return "not_confirmed";
      }
    }
    const sent = await this.spend(rt, mark === null ? { outAt: Date.now(), triedAgain: false } : { outAt: mark.outAt, triedAgain: true });
    if (sent.outcome === "refused") this.onRefreshRefused?.("refused");
    return sent.outcome;
  }

  /** No try is left for a refresh whose answer never came: nothing is sent, the pair goes, and the token is kept. */
  private async noTryLeft(rt: string): Promise<void> {
    this.keptUnconfirmed = rt;
    this.accessToken = null;
    this.refreshToken = null;
    this.refreshMark = null;
    await this.onTokensChanged?.();
    this.onRefreshRefused?.("not_confirmed");
  }

  /**
   * One sending of [rt] ([mark]: this try's first sending, and whether it is the one more try), with the consume before
   * the POST and the outcome guard (AM1): the outcome is applied only while the pair is untouched since the consume; a
   * concurrent setTokens (doLock/unlock) owns it otherwise, and a late answer goes to onLateRefresh (a token whose
   * refresh got no answer of the server's never: it is not to be sent again).
   */
  private async spend(rt: string, mark: { outAt: number; triedAgain: boolean }): Promise<{ outcome: "renewed" | "refused" | "unavailable" | "unanswered" | "dropped" }> {
    this.consumesOut++;
    try {
      return await this.spendConsumed(rt, mark);
    } finally {
      this.consumesOut--;
    }
  }

  /** How many renewals of this client's pair have consumed its refresh token and not yet settled ([spend], [forceRefresh]). */
  private consumesOut = 0;

  private async spendConsumed(rt: string, mark: { outAt: number; triedAgain: boolean }): Promise<{ outcome: "renewed" | "refused" | "unavailable" | "unanswered" | "dropped" }> {
    this.refreshToken = null;
    this.refreshMark = null;
    const atConsume = this.accessToken;
    await this.onTokensChanged?.();
    const owns = (): boolean => this.refreshToken === null && this.accessToken === atConsume;
    let answer: RefreshAnswer = null;
    let status = 0;
    try {
      if (!this.dialAllowed()) throw this.refuseDial();
      const resp = await fetch(this.baseUrl + "/api/v1/auth/refresh", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Andvari-Client": this.clientHeader },
        body: JSON.stringify({ refreshToken: rt }),
        redirect: "manual", // a redirect is an answer that is not the server's
      });
      status = resp.status;
      answer = isRedirect(resp) ? null : await refreshAnswer(resp);
    } catch (e) {
      if (e instanceof ApiError && e.code === "confirm_server") {
        // A block since the consume: nothing left the browser, so the pair stands as it was before this try.
        if (owns()) {
          this.refreshToken = rt;
          this.refreshMark = mark.triedAgain ? { outAt: mark.outAt, triedAgain: false } : null;
          await this.onTokensChanged?.();
        }
        return { outcome: "dropped" };
      }
      answer = null; // no answer at all
    }
    if (answer !== null && "pair" in answer) {
      if (!owns()) {
        await this.lateRefresh(atConsume, { access: answer.pair.accessToken, refresh: answer.pair.refreshToken }).catch(() => {});
        return { outcome: "dropped" };
      }
      this.accessToken = answer.pair.accessToken;
      this.refreshToken = answer.pair.refreshToken;
      await this.onTokensChanged?.();
      return { outcome: "renewed" };
    }
    if (answer !== null && (status === 401 || status === 403 || REFRESH_ENDS.has(answer.refusal))) {
      if (!owns()) return { outcome: "dropped" };
      this.accessToken = null;
      this.refreshToken = null;
      await this.onTokensChanged?.();
      return { outcome: "refused" };
    }
    if (answer !== null && !mark.triedAgain) {
      // The server's own answer for the moment to a first try: it took nothing; the token is restored, unmarked.
      if (owns()) {
        this.refreshToken = rt;
        await this.onTokensChanged?.();
      } else await this.lateRefresh(atConsume, { access: atConsume ?? "", refresh: rt }).catch(() => {});
      return { outcome: "unavailable" };
    }
    // No answer of the server's (or its answer for the moment to the one more try, the first still unanswered): the
    // token stays in this worker's memory, marked; getTokens hides it, so nothing kept anywhere can send it again.
    if (owns()) {
      this.refreshToken = rt;
      this.refreshMark = mark;
    } else await this.lateRefresh(atConsume, { access: atConsume ?? "", refresh: null }).catch(() => {});
    return { outcome: answer === null ? "unanswered" : "unavailable" };
  }

  /** Unauthenticated: liveness smoke check (spike verification step 3) + the fleet lock policy. */
  clientPolicy(): Promise<ClientPolicyResponse> {
    return this.json("GET", "/api/v1/client-policy");
  }

  prelogin(email: string): Promise<PreloginResponse> {
    return this.json("POST", "/api/v1/auth/prelogin", { email });
  }

  /** Login with the derived authKey (base64) and this browser's device object (device.ts, spec 03 §2). Returns tokens +
   *  the account's wrapped keys. [replaces]: the refresh token of the session this sign-in replaces
   *  (`replacesRefreshToken`), sent only from a known device row (one with a deviceId). */
  async login(email: string, authKey: string, device: DeviceObject, totp?: string, replaces?: string | null): Promise<SessionResponse> {
    const s = await this.json<SessionResponse>("POST", "/api/v1/auth/login", {
      email,
      authKey,
      device,
      ...(totp ? { totp } : {}),
      ...(replaces && device.deviceId !== undefined ? { replacesRefreshToken: replaces } : {}),
    });
    // A10: the id grammar BEFORE the caller installs the session (the user id is the storage namespace key).
    const r = refusedSession(s);
    if (r) {
      this.onRefusedIds?.("login", [r]);
      throw new ApiError(0, "bad_wire_id", `the server sent a malformed ${r.field} on login`);
    }
    const accountKeys = this.reported("login", sanitizeAccountKeys(s.accountKeys));
    return accountKeys === s.accountKeys ? s : { ...s, accountKeys };
  }

  /** The account's wrapped keys (spec 03 — same bundle the login response carries). The extension's
   *  quick-unlock redeem (spec 01 §8.4) consumes this with the tokens it already holds instead of a
   *  fresh login: unwrap encryptedIdentitySeed under the recovered UVK + hard-compare identityPub.
   *  Rides json(), so the Bearer header, the 401→refresh→retry, and ApiError parsing all apply. */
  async getAccountKeys(): Promise<AccountKeys> {
    return this.reported("accountKeys", sanitizeAccountKeys(await this.json<AccountKeys>("GET", "/api/v1/account/keys")));
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
   *
   * The outcome guard of doRefresh applies here too: the answer is applied only while the pair is the one
   * this call consumed. Without it, a redeem whose refresh was answered late — after the person gave up on the PIN and
   * signed in with the master password, possibly as another account — wrote the redeem's pair over the new sign-in's
   * pair, and the new session then ran (and persisted) another session's tokens. Not owned: nothing is set, cleared,
   * restored or notified, and the answer is `transient` (the caller's own generation check has already moved on).
   */
  async forceRefresh(): Promise<"rotated" | "revoked" | "transient"> {
    this.consumesOut++;
    try {
      return await this.forceRefreshOnce();
    } finally {
      this.consumesOut--;
    }
  }

  private async forceRefreshOnce(): Promise<"rotated" | "revoked" | "transient"> {
    const rt = this.refreshToken;
    if (!rt) return "revoked";
    if (!this.dialAllowed()) return "transient"; // nothing consumed, nothing sent: keep the blob
    // A token whose refresh got no answer is sent again only by doRefresh's rule (once, inside the window).
    if (this.refreshMark !== null) return "transient";
    this.refreshToken = null; // consume + persist the consumed state before the POST (AM1)
    const sentAt = Date.now();
    const atConsume = this.accessToken;
    await this.onTokensChanged?.();
    const owns = (): boolean => this.refreshToken === null && this.accessToken === atConsume;
    try {
      if (!this.dialAllowed()) throw this.refuseDial(); // a block since the consume: restored below, like a transport failure
      const resp = await fetch(this.baseUrl + "/api/v1/auth/refresh", {
        method: "POST",
        headers: { "content-type": "application/json", "X-Andvari-Client": this.clientHeader },
        body: JSON.stringify({ refreshToken: rt }),
        redirect: "manual", // a redirect is not ok and neither 401 nor 403: transient
      });
      const answer = isRedirect(resp) ? null : await refreshAnswer(resp);
      if (!owns()) return "transient";
      if (answer !== null && "pair" in answer) {
        this.accessToken = answer.pair.accessToken;
        this.refreshToken = answer.pair.refreshToken;
        await this.onTokensChanged?.();
        return "rotated";
      }
      if (answer !== null && (resp.status === 401 || resp.status === 403 || REFRESH_ENDS.has(answer.refusal))) {
        this.accessToken = null;
        this.refreshToken = null;
        await this.onTokensChanged?.();
        return "revoked";
      }
      if (answer !== null) {
        this.refreshToken = rt; // the server's own answer for the moment: it took nothing; restored
        await this.onTokensChanged?.();
        return "transient";
      }
      // No answer of the server's (a gateway's page of any status among them): the token may be taken. It stays in this
      // worker's memory, marked, for the one more try within the window (doRefresh), and no record keeps it.
      this.refreshToken = rt;
      this.refreshMark = { outAt: sentAt, triedAgain: false };
      return "transient";
    } catch (e) {
      if (!owns()) return "transient";
      this.refreshToken = rt;
      if (e instanceof ApiError && e.code === "confirm_server") await this.onTokensChanged?.(); // nothing left: restored
      else this.refreshMark = { outAt: sentAt, triedAgain: false }; // no answer at all: as above
      return "transient";
    }
  }

  /** The UVK-sealed account state (spec 03 §3): `sealedState` null when the account never wrote one. The served `seq` is
   *  the server's compare-and-set token only; the extension reads the in-blob `seq` (accountstate.ts). */
  async accountState(): Promise<{ sealedState: string | null; seq: number }> {
    const r = await this.json<{ sealedState?: unknown; seq?: unknown }>("GET", "/api/v1/account/state");
    return { sealedState: typeof r.sealedState === "string" ? r.sealedState : null, seq: typeof r.seq === "number" ? r.seq : 0 };
  }

  /** Full snapshot when since=0: vaults/grants/items as deltas over the global rev. A10: rows whose ids are not
   *  UUIDs are dropped here, before the worker keys anything on them. `grantedVaultIds` is read from the answer as
   *  served (wireids.ts grantedVaultIdsOf): which vaults it still grants, or null when it cannot say. */
  async sync(since = 0): Promise<SyncAnswer> {
    const served = await this.json<SyncResponse>("GET", `/api/v1/sync?since=${since}`);
    const sync = this.reported("sync", sanitizeSync(served));
    return { ...sync, grantedVaultIds: grantedVaultIdsOf(served) };
  }

  /** Save/update flow: push put/delete mutations (the client-encrypted item rides in item.blob).
   *  Check results[] — see MutationResult. */
  push(mutations: Mutation[]): Promise<PushResponse> {
    return this.json("POST", "/api/v1/sync/push", { mutations });
  }

  /** The usage ledger (spec 02 §8.2) — one opaque blob per user. `sealedUsage: null` means no
   *  ledger has ever been written, which is NOT "nothing has been used". */
  getUsage(): Promise<{ sealedUsage: string | null; updatedAt: number }> {
    return this.json("GET", "/api/v1/usage");
  }

  /** Replace the stored ledger. Last-writer-wins, so callers merge against the server copy first;
   *  and callers MUST batch (spec 03 §3) — a PUT per fill would make updatedAt an activity trace. */
  putUsage(sealedUsage: string): Promise<unknown> {
    return this.json("PUT", "/api/v1/usage", { sealedUsage });
  }

  /** Mint a single-use ~30 s ticket for the /events dirty-bell WebSocket (spec 03 §6). Minted
   *  fresh per connect attempt and NEVER persisted — the access token never rides a URL. Rides
   *  json(), so the Bearer header, the single-flight 401→refresh→retry, and ApiError parsing
   *  all apply. */
  eventsTicket(): Promise<WsTicketResponse> {
    return this.json("POST", "/api/v1/events/ticket");
  }

  /** Revoke every server session for this device (POST /auth/logout, spec 03) — the sign-out
   *  half of the web client.ts logout / desktop-Android bounded-revoke parity. Deliberately NOT
   *  json(): the endpoint answers plain text ("ok"), and revocation is best-effort — this NEVER
   *  throws (the caller's local wipe must proceed on any failure). An expired access token still
   *  rotates once via the shared single-flight so the revoke lands. Token clearing stays with
   *  the caller (doLock), which owns the pair's lifecycle. Resolves whether the server accepted. */
  async logout(): Promise<boolean> {
    const post = (): Promise<Response> => {
      if (!this.dialAllowed()) return Promise.reject(this.refuseDial());
      const headers: Record<string, string> = { "X-Andvari-Client": this.clientHeader };
      if (this.accessToken) headers["authorization"] = `Bearer ${this.accessToken}`;
      return fetch(this.baseUrl + "/api/v1/auth/logout", { method: "POST", headers, redirect: "manual" }); // a redirect is not ok: unconfirmed
    };
    try {
      let resp = await post();
      if (resp.status === 401) {
        // A token whose refresh got no answer of the server's is never spent by a sign-out (the server would read it as
        // a stolen token's reuse): nothing is sent, the sign-out is not confirmed, and the token is kept for the next
        // sign-in's name. A kept token likewise.
        const rt = this.refreshToken;
        if (rt !== null && (this.refreshMark !== null || rt === this.keptUnconfirmed)) {
          this.keptUnconfirmed = rt;
          return false;
        }
        if ((await this.tryRefresh()) === "renewed") resp = await post();
      }
      return resp.ok;
    } catch {
      return false; // offline / unreachable — best-effort by contract
    }
  }
}

/**
 * A refresh whose answer never came is tried once more only within this long of its first sending (the edge included),
 * judged by the wall clock: the server answers a repeat of a token it replaced for sixty seconds from the replacement,
 * and the ten seconds are the margin for the road (the shared code's and the web client's REFRESH_SECOND_TRY_MS).
 */
export const REFRESH_SECOND_TRY_MS = 50_000;

/** How a refresh ended the session: refused by the server's own answer, or here, no try being left. */
export type RefreshEnd = "refused" | "not_confirmed";

/** What a refresh came to, for the request that set it off. */
type RefreshOutcome = "renewed" | "refused" | "unavailable" | "unanswered" | "not_confirmed" | "dropped";

/** The refusals by which the server ends a session at a refresh, in its own envelope, at any status. */
const REFRESH_ENDS = new Set(["invalid_refresh", "refresh_reuse", "refresh_expired"]);

type RefreshAnswer = { pair: { accessToken: string; refreshToken: string } } | { refusal: string } | null;

/** A refresh's answer, read whole: the new pair, or the server's own refusal ({error, message}), or null for anything
 *  else (a gateway's page, a body that does not read or does not decode, a 200 among them). */
async function refreshAnswer(resp: Response): Promise<RefreshAnswer> {
  let b: Record<string, unknown> | null;
  try {
    b = JSON.parse(await resp.text()) as Record<string, unknown> | null;
  } catch {
    return null;
  }
  if (typeof b !== "object" || b === null) return null;
  if (resp.ok) return typeof b.accessToken === "string" && typeof b.refreshToken === "string" ? { pair: { accessToken: b.accessToken, refreshToken: b.refreshToken } } : null;
  // The server's envelope names its `error` and a `message`, both, as the server sends them and as the web app requires:
  // a body with a code alone is not taken as the server's own answer (a page or a proxy can carry an `error` field).
  return typeof b.error === "string" && typeof b.message === "string" ? { refusal: b.error } : null;
}

/** A refused server response, carrying the parsed BODY code (spec 03 §8) — surfaces map the code
 *  to copy; `message` is human/debug detail only. `status` + `code` are explicit fields (not
 *  parameter properties) so this file type-strips under plain `node --test`. */
/** The statuses `fetch` follows, and the opaque answer a browser gives for one under `redirect: "manual"`. */
export function isRedirect(resp: Pick<Response, "status" | "type" | "redirected">): boolean {
  return resp.type === "opaqueredirect" || resp.redirected === true || [301, 302, 303, 307, 308].includes(resp.status);
}

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

/**
 * A request whose refresh did not renew the session although the session lives: no answer of the server's came (the
 * token stays marked for its one more try), or the server's answer for the moment. A TypeError, the way a request with
 * no answer fails, so every caller that reads "no answer" reads it so (never the request's own 401, which reads as the
 * session's end).
 */
export class RefreshUnansweredError extends TypeError {
  kind: "unanswered" | "unavailable";
  constructor(kind: "unanswered" | "unavailable") {
    super(`the session's renewal got no answer of the server's (${kind})`);
    this.kind = kind;
    this.name = "RefreshUnansweredError";
  }
}

/** A refresh whose answer never came had no try left: nothing was sent and the session ended here; its one end was raised
 *  already (onRefreshRefused `not_confirmed`). An ApiError with status 0, never 401. */
export class SessionNotConfirmedError extends ApiError {
  constructor() {
    super(0, "session_not_confirmed", "the session ended here: its renewal could not be confirmed, and nothing was sent");
    this.name = "SessionNotConfirmedError";
  }
}
