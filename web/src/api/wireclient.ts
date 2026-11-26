import { assertServerKdfParams, type KdfParams, KdfPolicyError } from "../crypto/keys";
import { AnswerCutOffError, type AnswerSize, type ApiClient, ApiError, isJsonContentType, pathSeg, readAnswerText, type Tokens } from "./client";
import { type Json, parseJson, Reader, WireShapeError } from "./decode";
import { DeviceIdentity } from "./devicesecret";
import { type Refusal, UUID_RE } from "./wireids";
import {
  type AccountDeletePreviewV2,
  type AccountDeleteRequestV2,
  type AccountKeysV2,
  type AccountRecoveryPut,
  type AccountStateResponseV2,
  type ClientPolicyV2,
  decodeAccountKeys,
  decodeAccountState,
  decodeAttachmentMeta,
  decodeClientPolicy,
  decodeDeletedAt,
  decodeDeletedItems,
  decodeDeletedVaults,
  decodeDeletePreview,
  decodeDevices,
  decodeInstance,
  decodeItemVersions,
  decodeLogAppend,
  decodeLogPage,
  decodeMembers,
  decodePrelogin,
  decodePush,
  decodeUsage,
  decodeRecoveryPieceId,
  decodeRecoveryRequests,
  decodeRecoveryVerify,
  decodeRev,
  decodeSession,
  decodeSignupVerify,
  decodeSync,
  type DeletedVaultSummaryV2,
  type DeviceRow,
  type EscrowSelfPut,
  type InstanceResponse,
  type LogAppendRequest,
  type LogAppendResponse,
  type LogPage,
  type NewDevice,
  type PasswordChangeRequestV2,
  type PreloginResponseV2,
  type RecoveryCommitRequestV2,
  type RecoveryRequestSummary,
  type RecoverySelfSetupRequestV2,
  type RecoveryVerifyResponseV2,
  type RegisterRequestV2,
  type SessionResponseV2,
  type SignupStartRequest,
  type SignupVerifyResponse,
  type SyncResponseV2,
  type UsageResponseV2,
  type VaultMemberSummaryV2,
} from "./wire";
import type { TotpSetupResponse } from "./types";
import type { AttachmentMeta, DeletedItemsResponse, ItemRestoreResponse, ItemUpload, ItemVersionsResponse, Mutation, PushResponse } from "./types";

const API = "/api/v1";

/** A served answer that is not the route's shape: a refusal of its own, never a value. */
export const BAD_RESPONSE = "bad_response";

/**
 * A success answer (2xx) this browser could not take as the route's shape: `ApiError(0, "bad_response")`, as before.
 * [serversJson] says whether it is the server's own answer, as far as the browser can tell: the JSON content type and
 * a body that parses as JSON (no redirect is ever followed: api/client.ts `send`). An empty body, a page from a proxy
 * or a captive portal, or a body under another type is not: what the server did with the request cannot be told from it.
 */
export class UnreadableAnswerError extends ApiError {
  constructor(
    message: string,
    public readonly serversJson: boolean,
    /** The parsed body when [serversJson] (vault/afterstore.ts reads whether it names the account sent); else undefined. */
    public readonly answer: unknown = undefined,
  ) {
    super(0, BAD_RESPONSE, message);
    this.name = "UnreadableAnswerError";
  }
}

/**
 * A registration's, a sign-in's or a kit recovery's success answer, decoded in full, whose served cost is outside the fence: the
 * [KdfPolicyError] it was, with what the answer was, so that whether the server stored the request is read from the
 * answer itself (vault/afterstore.ts): only a JSON object under the JSON type that names the account sent counts.
 */
export class AnsweredCostRefusedError extends KdfPolicyError {
  constructor(
    refused: KdfPolicyError,
    public readonly serversJson: boolean,
    public readonly answer: unknown,
  ) {
    super(refused.code, refused.params);
    this.name = "AnsweredCostRefusedError";
  }
}

/**
 * Told the pair a sign-in's own login, registration or kit recovery installed, at the moment it is installed: the flow
 * that made the call keeps it, so that its way out ends that session and no other (ui/tabsession.ts).
 */
export type SessionInstalled = (tokens: Tokens) => void;

/**
 * The session a sign-in replaces, named in its login (`replacesRefreshToken`, spec 03 §2): the refresh token this TAB
 * last held for it, and the account that pair is bound to. When the whole sign-in succeeded the server ends exactly
 * that session (its chain as it stands, also when the token is one it had already replaced, which it records as such),
 * if it is a session of the same account on the same device row; anything else is ignored. ui/tabsession.ts
 * [replacedSession] says when a tab names one.
 */
export interface ReplacedSession {
  readonly userId: string;
  readonly refreshToken: string;
}

/**
 * What a sign-in may name: the session this tab holds, or the tokens kept from sessions that ended in this browser
 * unconfirmed, one per account (ui/session.ts unconfirmedRefreshes), of which the login names only the email's account's.
 */
export type Replaces = ReplacedSession | readonly ReplacedSession[];

/** A paged list that did not end within its page limit: a failed read, never a shortened list. */
export const LIST_TOO_LONG = "list_too_long";

/** Spec 03 §16.7: a devices page holds at most 500 rows. The web reads at most 40 pages (20,000 devices). */
export const DEVICES_PAGE_ROWS = 500;
export const DEVICES_MAX_PAGES = 40;
/**
 * Spec 03 §5.1: a trash page holds at most 65,536 rows. The web reads at most 8 pages (524,288 deleted items), half the
 * app engine's 16: every page (up to 8 MiB of JSON) is parsed and held in one browser tab, whose memory is the tightest of
 * the clients', and 524,288 items is already far past any household's trash.
 */
export const TRASH_PAGE_ROWS = 65_536;
export const TRASH_MAX_PAGES = 8;

/** A trash row's position in the list's order: its `deletedAt`, and its `itemId` as the text served. */
interface TrashKey {
  readonly at: number;
  readonly id: string;
}

/** The row's position, or null when its `deletedAt` is not a non-negative integer or its `itemId` is not text. */
function trashKeyOf(row: unknown): TrashKey | null {
  if (row === null || typeof row !== "object" || Array.isArray(row)) return null;
  const o = row as { deletedAt?: unknown; itemId?: unknown };
  if (typeof o.deletedAt !== "number" || !Number.isSafeInteger(o.deletedAt) || o.deletedAt < 0 || typeof o.itemId !== "string") return null;
  return { at: o.deletedAt, id: o.itemId };
}

/** True when [k] comes strictly after [prev] in the trash's order, `(deletedAt, itemId)` descending. */
function trashBefore(k: TrashKey, prev: TrashKey): boolean {
  return k.at < prev.at || (k.at === prev.at && k.id < prev.id);
}

/**
 * The web client's calls on the routes of spec 03 after the cut-over, over the [ApiClient] transport (tokens,
 * refresh, the 401 retry and the upgrade nudge stay there). Each method sends exactly the body spec 03 §0.2
 * names and runs the response through its strict decoder (api/wire.ts); a malformed answer is
 * `ApiError(0, "bad_response")`, a refusal is the server's [ApiError] with its extras.
 *
 * Only routes the web may call exist here (design §13): sign-up, sign-in, the account, sync, the vault log,
 * kit recovery and its rotation, the account's own devices and the veto. There is no method for a link,
 * a device link, an instance card write or an operator route, so none can be called from this bundle.
 */
export class WireApi {
  constructor(
    readonly transport: ApiClient,
    readonly device: DeviceIdentity = new DeviceIdentity(),
    /** Rows a list answer dropped for a malformed id (wireids.ts's A10 rule); the store raises the anomaly. */
    private readonly onRefused: (endpoint: string, refused: Refusal[]) => void = () => {},
  ) {}

  /** [size]: whether the answer is small by its nature (a limit on its whole time) or grows with the vault (a limit on the time without progress). */
  private async call<T>(method: string, path: string, body: unknown, decode: (json: never) => T, auth = true, signal?: AbortSignal, size: AnswerSize = "small"): Promise<T> {
    return (await this.callKeeping(method, path, body, decode, auth, signal, size)).value;
  }

  /** [call], also handing back the parsed body and whether it came under the JSON type. */
  private async callKeeping<T>(method: string, path: string, body: unknown, decode: (json: never) => T, auth = true, signal?: AbortSignal, size: AnswerSize = "small"): Promise<{ value: T; json: Json; serversJson: boolean }> {
    const answer = await this.transport.sendRequest(method, API + path, body, { auth, size, ...(signal ? { signal } : {}) });
    let json: Json;
    try {
      json = parseJson(path, answer.text);
    } catch (e) {
      if (e instanceof WireShapeError) throw new UnreadableAnswerError(e.message, false);
      throw e;
    }
    const serversJson = isJsonContentType(answer.contentType);
    try {
      return { value: decode(json as never), json, serversJson };
    } catch (e) {
      // JSON in the route's wrong shape is the server's own answer only under the JSON type (a newer server's shape).
      if (e instanceof WireShapeError) throw new UnreadableAnswerError(e.message, serversJson, serversJson ? json : undefined);
      throw e;
    }
  }

  /** The served cost of a session answer that was decoded in full, checked; a refusal carries the answer ([AnsweredCostRefusedError]). */
  private assertAnsweredKdf(kdf: KdfParams, kept: { json: Json; serversJson: boolean }): void {
    try {
      assertServerKdfParams(kdf);
    } catch (e) {
      if (e instanceof KdfPolicyError) throw new AnsweredCostRefusedError(e, kept.serversJson, kept.json);
      throw e;
    }
  }

  /** A write that answers the plain-text `ok` (spec 03 §0.1). */
  private async ok(method: string, path: string, body?: unknown, auth = true): Promise<void> {
    await this.transport.sendRequest(method, API + path, body, { auth });
  }

  private reported<T>(endpoint: string, d: { refused: Refusal[] } & T): T {
    if (d.refused.length > 0) this.onRefused(endpoint, d.refused);
    return d;
  }

  /** This browser's device object for a device-creating request (design §8.7). */
  newDevice(name: string): NewDevice {
    return { platform: "web", name, deviceSecret: this.device.secret() };
  }

  // ---- Instance and policy ------------------------------------------------------------------------

  async clientPolicy(): Promise<ClientPolicyV2> {
    const p = await this.call("GET", "/client-policy", undefined, decodeClientPolicy, false);
    assertServerKdfParams(p.kdfParams);
    return p;
  }

  /** The card chain and rotations (spec 03 §17.1). Unverified: the pin store (vault/pinstore.ts) decides what they are. */
  instance(): Promise<InstanceResponse> {
    return this.call("GET", "/instance", undefined, decodeInstance, false);
  }

  // ---- Sign-up and registration ------------------------------------------------------------------

  /** Always `202 {status: "sent"}` on success, whether or not the address has an account (§14.1). */
  signupStart(req: SignupStartRequest): Promise<void> {
    return this.ok("POST", "/signup/start", req, false);
  }

  signupVerify(email: string, code: string): Promise<SignupVerifyResponse> {
    return this.call("POST", "/signup/verify", { email, code }, decodeSignupVerify, false);
  }

  /** Registers and installs the new session's tokens in memory; the caller persists the session. */
  async register(req: RegisterRequestV2, installed?: SessionInstalled): Promise<SessionResponseV2> {
    const kept = await this.callKeeping("POST", "/auth/register", req, (b) => decodeSession("register", b), false);
    const s = kept.value;
    // The account exists from here on: the answered session's pair is held first, so a caller that refuses the answer
    // (a cost outside the fence included) can end that session by its own token instead of leaving it open.
    this.transport.useSessionTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    installed?.({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    this.assertAnsweredKdf(s.accountKeys.kdfParams, kept);
    this.device.remember(req.email, s.userId, s.deviceId);
    return s;
  }

  // ---- Sessions ------------------------------------------------------------------------------------

  /** Sent only under the password rule (design §4.4, vault/passwordgate.ts): its answer is derived from the email's account. */
  async prelogin(email: string): Promise<PreloginResponseV2> {
    const p = await this.call("POST", "/auth/prelogin", { email }, decodePrelogin, false);
    assertServerKdfParams(p.kdfParams);
    return p;
  }

  /**
   * Password login (spec 03 §2) with this browser's device object: its secret always, and the deviceId it holds
   * for that account when it has one, so a known device stays known. `401 totp_required` is the cue for the
   * two-step field; a wrong code is the uniform `401 invalid_credentials`; `403 link_required` comes only
   * after the password and any code verified.
   */
  async login(email: string, authKey: string, deviceName: string, totp?: string, installed?: SessionInstalled, replaces?: Replaces | null): Promise<SessionResponseV2> {
    const deviceId = this.device.deviceIdFor(email);
    const device = { ...this.newDevice(deviceName), ...(deviceId ? { deviceId } : {}) };
    // The session this sign-in replaces is named only for the same account on the same row: this browser's row for the
    // email (its deviceId is sent) belongs to the account the replaced pair is bound to. Anything else names nothing.
    const rowAccount = deviceId !== null ? this.device.userIdFor(email) : null;
    const one = rowAccount === null || !replaces ? undefined : Array.isArray(replaces) ? (replaces as readonly ReplacedSession[]).find((r) => r.userId === rowAccount) : (replaces as ReplacedSession).userId === rowAccount ? (replaces as ReplacedSession) : undefined;
    const named = one ? { replacesRefreshToken: one.refreshToken } : {};
    const kept = await this.callKeeping("POST", "/auth/login", { email, authKey, device, ...(totp ? { totp } : {}), ...named }, (b) => decodeSession("login", b), false);
    const s = kept.value;
    // The server took the sign-in from here on: it issued this session and, for a device it did not know, made a row for
    // it. The pair is held and the row remembered BEFORE anything in the answer is judged, as the registration does, so
    // that a caller that refuses the answer (a cost outside the fence included) ends that session by its own token, and a
    // second try names the same row instead of making another.
    this.transport.useSessionTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    installed?.({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    this.device.remember(email, s.userId, s.deviceId);
    this.assertAnsweredKdf(s.accountKeys.kdfParams, kept);
    return s;
  }

  // ---- Account --------------------------------------------------------------------------------------

  async accountKeys(): Promise<AccountKeysV2> {
    const k = await this.call("GET", "/account/keys", undefined, decodeAccountKeys);
    assertServerKdfParams(k.kdfParams);
    return k;
  }

  accountState(): Promise<AccountStateResponseV2> {
    return this.call("GET", "/account/state", undefined, (b) => decodeAccountState("account/state", b));
  }

  putAccountState(sealedState: string, baseSeq: number): Promise<AccountStateResponseV2> {
    return this.call("PUT", "/account/state", { sealedState, baseSeq }, (b) => decodeAccountState("account/state", b));
  }

  changePassword(req: PasswordChangeRequestV2): Promise<void> {
    return this.ok("PUT", "/account/password", req);
  }

  putRecovery(req: AccountRecoveryPut): Promise<AccountStateResponseV2> {
    return this.call("PUT", "/account/recovery", req, (b) => decodeAccountState("account/recovery", b));
  }

  putEscrowSelf(req: EscrowSelfPut): Promise<void> {
    return this.ok("PUT", "/escrow/self", req);
  }

  /**
   * The instance's recovery public key as the server serves it (spec 03 §17.4), `b64` text. Unverified: the caller
   * uses it only after it hashed, at full length, to the `recoveryFp` of the card this browser pinned (§4.5).
   * `404 not_found` on a public instance and where there is no recovery key.
   */
  async recoveryPubkey(): Promise<string> {
    const answer = await this.transport.sendRequest("GET", `${API}/recovery-pubkey`, undefined, { auth: false });
    return answer.text.trim();
  }

  /**
   * A list that comes in pages (spec 03 §16.7 devices, §5.1 trash): while an answer holds a full page of [pageRows] rows
   * the next one is asked for after its last row; the list exists only once a shorter page (the last) has arrived. A
   * page the server refuses (a `400` for a cursor it does not know, any other refusal) fails the whole read, never a
   * shorter list; so does a list longer than [maxPages] pages ([LIST_TOO_LONG]). A page is counted by the rows the
   * server sent, before any row is dropped for a malformed id, and the cursor is taken from the last row it sent.
   */
  private async pagedList<R>(
    path: string,
    pageRows: number,
    maxPages: number,
    rowsOf: (json: Json) => unknown[],
    cursorOf: (last: Json) => string,
    decode: (json: never) => { rows: R[]; refused: Refusal[] },
  ): Promise<{ rows: R[]; refused: Refusal[] }> {
    const rows: R[] = [];
    const refused: Refusal[] = [];
    let after: string | null = null;
    for (let page = 0; page < maxPages; page++) {
      const q: string = after === null ? "" : `?after=${encodeURIComponent(after)}`;
      const got: { d: { rows: R[]; refused: Refusal[] }; next: string | null } = await this.call("GET", path + q, undefined, (json: Json) => {
        const d = decode(json as never);
        const raw = rowsOf(json);
        return { d, next: raw.length < pageRows ? null : cursorOf(raw[raw.length - 1] as Json) };
      });
      for (const row of got.d.rows) rows.push(row);
      for (const r of got.d.refused) refused.push(r);
      if (got.next === null) return { rows, refused };
      after = got.next;
    }
    throw new ApiError(0, LIST_TOO_LONG, `${path}: more than ${maxPages} pages`);
  }

  async devices(): Promise<DeviceRow[]> {
    const got = await this.pagedList(
      "/account/devices",
      DEVICES_PAGE_ROWS,
      DEVICES_MAX_PAGES,
      (json) => (Array.isArray(json) ? json : []),
      (last) => new Reader("account/devices").uuid((last as { deviceId?: unknown })?.deviceId, "deviceId of the page's last row"),
      decodeDevices,
    );
    // Spec 03 §16.7: a row seen twice (impossible from an honest server) is shown once, where it first came.
    const seenIds = new Set<string>();
    return this.reported("account/devices", got).rows.filter((r) => !seenIds.has(r.deviceId) && seenIds.add(r.deviceId) !== undefined);
  }

  async revokeDevice(deviceId: string, currentAuthKey: string): Promise<void> {
    return this.ok("POST", `/account/devices/${pathSeg(deviceId)}/revoke`, { currentAuthKey });
  }

  setRequireLink(enabled: boolean, currentAuthKey: string): Promise<void> {
    return this.ok("PUT", "/account/require-link", { enabled, currentAuthKey });
  }

  /**
   * `POST /account/totp/disable {code, currentAuthKey}` (spec 03 §0.1 row 16): turns two-step sign-in off. The server
   * checks the proof before it looks at the code, and sends the `two_step_off` mail. Answers the plain-text `ok`.
   */
  /**
   * `POST /account/totp/setup` with the password proof (server rule of 2026-11-17: asked at every setup, also on an
   * account that has none and right after a sign-in). Answers the new pending secret and its enrolment link.
   */
  totpSetup(currentAuthKey: string): Promise<TotpSetupResponse> {
    return this.call("POST", "/account/totp/setup", { currentAuthKey }, (body: Json): TotpSetupResponse => {
      const r = new Reader("totp_setup");
      const o = r.obj(body, "body");
      return { secretBase32: r.str(o.secretBase32, "secretBase32"), otpauthUri: r.str(o.otpauthUri, "otpauthUri") };
    });
  }

  totpDisable(code: string, currentAuthKey: string): Promise<void> {
    return this.ok("POST", "/account/totp/disable", { code, currentAuthKey });
  }

  recoveryRequests(): Promise<RecoveryRequestSummary[]> {
    return this.call("GET", "/account/recovery-requests", undefined, decodeRecoveryRequests);
  }

  /** The veto (design §9.3 step 2): a 0x0A frame signed by this account's identity key, with this account's session. */
  async vetoRecoveryRequest(requestId: string, statement: string): Promise<void> {
    return this.ok("POST", `/recovery/requests/${pathSeg(requestId)}/veto`, { statement });
  }

  deletePreview(): Promise<AccountDeletePreviewV2> {
    return this.call("GET", "/account/delete/preview", undefined, decodeDeletePreview);
  }

  /** The account's end, carrying one signed `leave` entry of each shared vault's log the account is in (req.leaves). */
  deleteAccountWithLeaves(req: AccountDeleteRequestV2): Promise<number> {
    return this.call("POST", "/account/delete", req, decodeDeletedAt);
  }

  // ---- Recovery with the kit ----------------------------------------------------------------------

  recoverySelfVerify(email: string, recoveryAuthKey: string): Promise<RecoveryVerifyResponseV2> {
    return this.call("POST", "/recovery/self/verify", { email, recoveryAuthKey }, decodeRecoveryVerify, false);
  }

  async recoverySelfCommit(email: string, req: RecoveryCommitRequestV2, installed?: SessionInstalled): Promise<SessionResponseV2> {
    const kept = await this.callKeeping("POST", "/recovery/self/commit", req, (b) => decodeSession("recovery/self/commit", b), false);
    const s = kept.value;
    // The recovery is stored from here on: as at a registration, the pair is held first so a refused answer's session ends.
    this.transport.useSessionTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    installed?.({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    this.assertAnsweredKdf(s.accountKeys.kdfParams, kept);
    this.device.remember(email, s.userId, s.deviceId);
    return s;
  }

  /** Rotating the kit (spec 03 §12): re-authenticated, answers the new piece id. */
  recoverySelfSetup(req: RecoverySelfSetupRequestV2): Promise<string> {
    return this.call("PUT", "/recovery/self-setup", req, decodeRecoveryPieceId);
  }

  recoverySelfConfirm(pieceId: string | null): Promise<void> {
    return this.ok("POST", "/recovery/self/confirm", pieceId ? { pieceId } : {});
  }

  // ---- Sync ---------------------------------------------------------------------------------------

  /** One answer that carries every item changed since [since] (all of them at 0): it grows with the vault, so its limit is the time without progress. */
  async sync(since: number): Promise<SyncResponseV2> {
    return this.reported("sync", await this.call("GET", `/sync?since=${encodeURIComponent(String(since))}`, undefined, decodeSync, true, undefined, "grows")).value;
  }

  /**
   * `POST /sync/push` (spec 03 §5): at most 200 mutations, applied in order in one transaction. The answer carries a
   * status per mutation; a thrown `400` or `413` is a definitive refusal of the whole batch, which the store's drain
   * bisects. The caller re-sends the SAME mutationIds after a lost answer (the server's dedup makes that idempotent).
   * Its body grows with the items it carries (an import's requests, a drain), so its limit is the time without progress,
   * unless the caller sets its own deadline (the send before a policy's wipe).
   */
  async pushMutations(mutations: Mutation[], opts: { signal?: AbortSignal } = {}): Promise<PushResponse> {
    return this.reported("sync/push", await this.call("POST", "/sync/push", { mutations }, decodePush, true, opts.signal, "grows")).value;
  }

  // ---- Items: history and trash (spec 03 §4, §5.1) ---------------------------------------------

  /** The archived ciphertext versions of an item, newest first; the caller opens each under the vault key it holds. */
  async itemVersions(itemId: string): Promise<ItemVersionsResponse> {
    const r = await this.call("GET", `/items/${pathSeg(itemId)}/versions`, undefined, decodeItemVersions);
    // The answer names the item it is for: one for another item is not this route's shape.
    if (r.itemId !== itemId) throw new ApiError(0, BAD_RESPONSE, "the server answered for another item");
    return r;
  }

  /**
   * Spec 03 §5.1: every page of the trash, newest first, one entry per item (the one with the newest `deletedAt`). What
   * the client refuses (NORMATIVE), each failing the whole read so that no row of it is shown, restored or purged: a page
   * of more than 65,536 rows; rows not strictly descending in `(deletedAt, itemId)` (`itemId`s compared as the text
   * served); a page after the first whose first row is not strictly after the cursor's row; a cursor that cannot be
   * built from the last row as a non-negative integer `deletedAt` and a `uuid` `itemId`; more than [TRASH_MAX_PAGES]
   * pages; a refused or unanswered page. A row with a malformed id is left out by the decoder but still counts for the
   * order checks.
   */
  async deletedItems(): Promise<DeletedItemsResponse> {
    const rows: DeletedItemsResponse["items"] = [];
    const refused: Refusal[] = [];
    let cursor: TrashKey | null = null;
    let done = false;
    for (let page = 0; page < TRASH_MAX_PAGES && !done; page++) {
      const after: TrashKey | null = cursor;
      const q: string = after === null ? "" : `?after=${encodeURIComponent(`${after.at}:${after.id}`)}`;
      const got: { d: ReturnType<typeof decodeDeletedItems>; next: TrashKey | null } = await this.call("GET", "/items/deleted" + q, undefined, (json: Json) => {
        const items = (json as { items?: unknown } | null)?.items;
        const raw = Array.isArray(items) ? items : [];
        if (raw.length > TRASH_PAGE_ROWS) throw new WireShapeError("items/deleted", `page of ${raw.length} rows (more than ${TRASH_PAGE_ROWS})`);
        let prev: TrashKey | null = after;
        raw.forEach((row, i) => {
          const k = trashKeyOf(row);
          if (k === null) throw new WireShapeError("items/deleted", `deletedAt or itemId of row ${i}`);
          // Strictly descending, and the first row of a later page strictly after the cursor's row.
          if (prev !== null && !trashBefore(k, prev)) throw new WireShapeError("items/deleted", i === 0 ? "first row (not after the cursor)" : `order at row ${i}`);
          prev = k;
        });
        const d = decodeDeletedItems(json);
        if (raw.length < TRASH_PAGE_ROWS) return { d, next: null };
        const last = trashKeyOf(raw[raw.length - 1]);
        if (last === null || !UUID_RE.test(last.id)) throw new WireShapeError("items/deleted", "the page's last row (no cursor can be built from it)");
        return { d, next: last };
      });
      for (const row of got.d.value.items) rows.push(row);
      for (const r of got.d.refused) refused.push(r);
      if (got.next === null) done = true;
      else cursor = got.next;
    }
    if (!done) throw new ApiError(0, LIST_TOO_LONG, `/items/deleted: more than ${TRASH_MAX_PAGES} pages`);
    const got = { rows, refused };
    const byItem = new Map<string, DeletedItemsResponse["items"][number]>();
    for (const row of got.rows) {
      const kept = byItem.get(row.itemId);
      if (!kept || row.deletedAt > kept.deletedAt) byItem.set(row.itemId, row);
    }
    return this.reported("items/deleted", { value: { items: [...byItem.values()] }, refused: got.refused }).value;
  }

  /** Un-tombstones an item with a version this browser re-encrypted (not a put: no conflict copy). Answers the new rev. */
  async restoreItem(itemId: string, upload: ItemUpload): Promise<ItemRestoreResponse> {
    return { rev: await this.call("POST", `/items/${pathSeg(itemId)}/restore`, upload, (b) => decodeRev("items/restore", b)) };
  }

  /** "Delete forever": hard-deletes a tombstoned item and its archived versions. */
  async purgeItem(itemId: string): Promise<ItemRestoreResponse> {
    return { rev: await this.call("POST", `/items/${pathSeg(itemId)}/purge`, undefined, (b) => decodeRev("items/purge", b)) };
  }

  // ---- Attachments (spec 03 §9) ---------------------------------------------------------------

  /**
   * Uploads one encrypted blob (`header ‖ ciphertext chunks`, spec 02 §6) under [id] for the item and vault named.
   * Idempotent per id: identical bytes answer the stored meta. The answer must name the same three ids.
   */
  async uploadAttachment(id: string, itemId: string, vaultId: string, body: Uint8Array): Promise<AttachmentMeta> {
    const path = `/attachments/${pathSeg(id)}?vaultId=${pathSeg(vaultId)}&itemId=${pathSeg(itemId)}`;
    const resp = await this.transport.requestBytes("POST", API + path, body);
    let meta: AttachmentMeta;
    try {
      meta = decodeAttachmentMeta(parseJson(path, await readAnswerText(resp)));
    } catch (e) {
      if (e instanceof WireShapeError) throw new ApiError(0, BAD_RESPONSE, e.message);
      throw e;
    }
    if (meta.attachmentId !== id || meta.itemId !== itemId || meta.vaultId !== vaultId) throw new ApiError(0, BAD_RESPONSE, "the server answered for another attachment");
    return meta;
  }

  /** The stored bytes of one attachment, exactly as uploaded; the caller verifies and opens them under the item's file key. */
  async downloadAttachment(id: string): Promise<Uint8Array> {
    const resp = await this.transport.requestBytes("GET", `${API}/attachments/${pathSeg(id)}`);
    try {
      return new Uint8Array(await resp.arrayBuffer());
    } catch (e) {
      throw new AnswerCutOffError(resp.status, e); // as readAnswerText: an answer that could not be read to its end
    }
  }

  // ---- The usage ledger (spec 03 §3) ----------------------------------------------------------

  /** One opaque blob per account. `sealedUsage: null`: no ledger was ever written (never "nothing is used"). */
  usage(): Promise<UsageResponseV2> {
    return this.call("GET", "/usage", undefined, decodeUsage);
  }

  /** Replaces the ledger. Rejects on any refusal, so a flush that did not land is never read as one that did. */
  putUsage(sealedUsage: string): Promise<void> {
    return this.ok("PUT", "/usage", { sealedUsage });
  }

  // ---- Shared vaults and the vault log -----------------------------------------------------------

  /**
   * Appends one signed entry (spec 03 §10.3). The caller keeps the frame in its pending-append record until
   * this answers, and re-posts the same bytes after a timeout (design §3.7); `409 log_head_moved` carries the
   * served head in `ApiError.extras`.
   */
  /**
   * A signed change to a vault's log. Its answer is handed on only when it is the server's own: decoded in full AND under
   * the JSON type; anything else is an {@link UnreadableAnswerError}, so the log store never reads "stored" from an answer
   * a front could have given (the store also checks that the head names the frame it sent).
   */
  async appendLog(vaultId: string, req: LogAppendRequest): Promise<LogAppendResponse> {
    const kept = await this.callKeeping("POST", `/vaults/${pathSeg(vaultId)}/log`, req, decodeLogAppend);
    if (!kept.serversJson) throw new UnreadableAnswerError("vaults/log: the answer was not under the JSON type", false);
    return kept.value;
  }

  /** One page of a vault's log, entries with `seq > after` (no `after`: from the genesis). */
  async logPage(vaultId: string, after: number | null): Promise<LogPage> {
    const q = after === null ? "" : `?after=${encodeURIComponent(String(after))}`;
    return this.call("GET", `/vaults/${pathSeg(vaultId)}/log${q}`, undefined, decodeLogPage);
  }

  /** Every entry through the served head, paging as spec 03 §10.6 says (FI-B3). */
  async fullLog(vaultId: string, after: number | null = null, maxPages = 64): Promise<{ entries: string[]; head: LogPage["head"]; purged: LogPage["purged"] }> {
    const entries: string[] = [];
    let cursor = after;
    for (let page = 0; page < maxPages; page++) {
      const p = await this.logPage(vaultId, cursor);
      entries.push(...p.entries);
      const last = (cursor ?? -1) + p.entries.length;
      if (p.entries.length === 0 || last >= p.head.seq) return { entries, head: p.head, purged: p.purged };
      cursor = last;
    }
    throw new ApiError(0, BAD_RESPONSE, "the log did not reach its served head");
  }

  async members(vaultId: string): Promise<VaultMemberSummaryV2[]> {
    return this.reported("vaults/members", await this.call("GET", `/vaults/${pathSeg(vaultId)}/members`, undefined, decodeMembers)).rows;
  }

  async deletedVaults(): Promise<DeletedVaultSummaryV2[]> {
    return this.reported("vaults/deleted", await this.call("GET", "/vaults/deleted", undefined, decodeDeletedVaults)).rows;
  }

  async putVaultMeta(vaultId: string, metaBlob: string, baseVaultRev?: number): Promise<number> {
    return this.call("PUT", `/vaults/${pathSeg(vaultId)}/meta`, { metaBlob, ...(baseVaultRev !== undefined ? { baseVaultRev } : {}) }, (b) => decodeRev("vaults/meta", b));
  }

  async putSelfWrap(vaultId: string, wrappedVk: string): Promise<number> {
    return this.call("PUT", `/vaults/${pathSeg(vaultId)}/grant/self-wrap`, { wrappedVk }, (b) => decodeRev("vaults/self-wrap", b));
  }
}
