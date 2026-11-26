import type {
  AccountDeleteBlocker,
  AccountDeletePreview,
  AccountDeleteRequest,
  AccountDeleteResponse,
  AdminDeviceSummary,
  AdminStatus,
  AdminUserSummary,
  AuditEvent,
  ClientPolicy,
  CreateVaultRequest,
  CreateVaultResponse,
  DeletedVaultSummary,
  InviteResponse,
  PasswordChangeRequest,
  PreloginResponse,
  RecoveryCommitRequest,
  RecoverySelfConfirmRequest,
  RecoverySelfSetupRequest,
  RecoverySelfSetupResponse,
  RecoveryVerifyRequest,
  RecoveryVerifyResponse,
  RegisterRequest,
  SessionResponse,
  TotpSetupResponse,
  TotpStatus,
  TransferAcceptRequest,
  TransferOfferRequest,
  TransferOfferResponse,
  AccountKeys,
  AccountStateResponse,
  PersonalWrap,
  VaultDeleteRequest,
  VaultDeleteResponse,
  VaultMemberAdd,
  VaultMemberRemoveRequest,
  VaultLeaveRequest,
  VaultMemberSummary,
  VaultMetaUpdateRequest,
  VaultRestoreRequest,
  WsTicketResponse,
} from "./types";
import { assertServerKdfParams } from "../crypto/keys";
import { decodeErrorExtras, type ErrorExtras } from "./wire";
import { SAFE_ID } from "../vault/itemdoc-shape";
import { refusedSession, sanitizeAccountKeys, sanitizeDeleteBlockers, sanitizeDeletedVaults, sanitizeDeletePreview, sanitizeMembers, type Refusal, type Sanitized } from "./wireids";

export const CLIENT_VERSION = "0.30.0";
const CLIENT_HEADER = `web/${CLIENT_VERSION}`;

/**
 * Every id interpolated into a request path goes through here (security review 2026-10, root
 * cause D). Item and attachment ids arrive from OTHER members — a tombstone's itemId via
 * /items/deleted, an attachment id from a decrypted doc — and every request carries this tab's
 * bearer token, so a planted `../admin/users/<id>/disable?` once turned "Delete forever" into an
 * admin action. A value that is not an id (SAFE_ID, spec 02 §3.2) is refused BEFORE any fetch; an
 * accepted one is percent-encoded on top. The refusal is what matters: WHATWG URL parsing treats
 * `%2e%2e` as `..` too. Core AndvariApi.pathSeg twin.
 */
export function pathSeg(id: string): string {
  if (!SAFE_ID.test(id)) throw new ApiError(0, "bad_path_segment", "not an id path segment");
  return encodeURIComponent(id);
}

export class ApiError extends Error {
  /** The fields a few refusals carry beside `error` (spec 03 §0.1), decoded for the code that defines them. */
  extras: ErrorExtras | null = null;
  /**
   * The wait a `429` names in its `Retry-After` (spec 03 §0.1), in whole seconds; null when the answer named none, or
   * named it in a form this client does not read (only plain seconds, at most a day). Said to the person, never waited
   * for by itself.
   */
  retryAfterS: number | null = null;
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

/** A `Retry-After` in plain seconds, 1 to 86 400 (a day); anything else (absent, a date, a fraction, out of range) is null. */
export function retryAfterSeconds(raw: string | null): number | null {
  if (raw === null) return null;
  const t = raw.trim();
  if (!/^\d{1,5}$/.test(t)) return null;
  const n = Number(t);
  return n >= 1 && n <= 86_400 ? n : null;
}

/**
 * Design §4.4 "a fork stops traffic, not reading": a request this client refused before anything left the browser, or
 * an answer it dropped unread, because its traffic gate ([ApiClient.trafficGate]) said the origin's pin is forked or
 * damaged. An ApiError with status 0, so a caller that only knows ApiError treats it as a refusal, never as a network
 * blip to retry.
 */
export class TrafficStoppedError extends ApiError {
  /**
   * [sent] tells the two apart: false when the gate refused the request before it left the browser (nothing was sent,
   * so nothing changed at the server), true when the request went out and the gate dropped its answer, whatever that
   * answer was (what the server did cannot be told). Every place that raises it says which: there is no default, so a
   * caller that forgets cannot make a request that went out read as one that never left.
   */
  constructor(public readonly reason: string, public readonly sent: boolean) {
    super(0, "traffic_stopped", `nothing is sent to this server: ${reason}`);
    this.name = "TrafficStoppedError";
  }
}

/**
 * An answer that was a redirect. The client follows no redirect on any request to the server's routes (`redirect:
 * "manual"`): the server never answers with one, so a redirect comes from something between the browser and the server
 * (a proxy, a captive portal), and it is an answer that is not the server's. What the server did with the request
 * cannot be told from it. An ApiError with status 0, so a caller that only knows ApiError reads it as a failure.
 */
export class RedirectRefusedError extends ApiError {
  constructor(public readonly answeredStatus: number) {
    super(0, "redirect_refused", `the answer was a redirect (HTTP ${answeredStatus}), not the server's own`);
    this.name = "RedirectRefusedError";
  }
}

/**
 * An answer whose status and headers arrived and whose body could not be read to its end (the connection broke while it
 * came, or the read itself failed). It is an answer, never "no answer": the server may have done what was asked, and
 * what it said cannot be read. `ApiError(0, "bad_response")`, as for any other answer this browser could not take.
 */
export class AnswerCutOffError extends ApiError {
  /** The limit that ended the answer while it came in, or null when the connection broke or the read failed by itself. */
  readonly limit: AnswerLimitKind | null;
  constructor(public readonly answeredStatus: number, cause: unknown) {
    super(0, "bad_response", `the answer (HTTP ${answeredStatus}) could not be read to its end: ${String(cause)}`);
    this.name = "AnswerCutOffError";
    this.limit = cause instanceof AnswerLimitError ? cause.kind : null;
  }
}

/**
 * Which of the two limits on an answer ended it. `too_long`: an answer that is small by its nature took longer than its
 * whole limit ({@link ANSWER_TIMEOUT_MS}). `stalled`: an answer whose size grows with the vault or a file (a sync, a push,
 * an attachment) went {@link PROGRESS_TIMEOUT_MS} without a byte.
 */
export type AnswerLimitKind = "too_long" | "stalled";

/** The reason a request was ended by one of this client's limits: what its signal is aborted with. */
export class AnswerLimitError extends Error {
  constructor(public readonly kind: AnswerLimitKind, public readonly ms: number) {
    super(kind === "too_long" ? `no whole answer within ${ms} ms` : `nothing came for ${ms} ms`);
    this.name = "AnswerLimitError";
  }
}

/**
 * A request one of this client's limits ended before any answer came. It is a TypeError, the way a fetch that got no
 * answer fails, so every caller that reads "no answer" (the request may or may not have reached the server) reads it so;
 * [kind] says which limit it was, for the sentence the person reads.
 */
export class NoAnswerInTimeError extends TypeError {
  constructor(public readonly kind: AnswerLimitKind, ms: number) {
    super(kind === "too_long" ? `no answer within ${ms} ms` : `nothing came for ${ms} ms`);
  }
}

/** The limit that ended [e]'s request (looked for in [e] and its causes), or null when no limit of this client did. */
export function answerLimitOf(e: unknown): AnswerLimitKind | null {
  let x: unknown = e;
  for (let depth = 0; depth < 4 && x !== null && x !== undefined; depth++) {
    if (x instanceof NoAnswerInTimeError || x instanceof AnswerLimitError) return x.kind;
    if (x instanceof AnswerCutOffError && x.limit !== null) return x.limit;
    x = typeof x === "object" ? (x as { cause?: unknown }).cause : undefined;
  }
  return null;
}

/** The body of an answer whose status arrived, as text; a failure while reading it is {@link AnswerCutOffError}. */
export async function readAnswerText(resp: Pick<Response, "status" | "text">): Promise<string> {
  try {
    return await resp.text();
  } catch (e) {
    throw new AnswerCutOffError(resp.status, e);
  }
}

/** The statuses `fetch` follows, and the opaque answer a browser gives for one under `redirect: "manual"`. */
export function isRedirect(resp: Pick<Response, "status" | "type" | "redirected">): boolean {
  return resp.type === "opaqueredirect" || resp.redirected === true || [301, 302, 303, 307, 308].includes(resp.status);
}

/** True when a `Content-Type` names JSON (`application/json`, any parameters after it), the type the server's API answers in. */
export function isJsonContentType(contentType: string | null | undefined): boolean {
  if (!contentType) return false;
  return (contentType.split(";")[0] ?? "").trim().toLowerCase() === "application/json";
}

/**
 * Design §4.4 "No credential goes to an origin without a pin in force": true for a request that carries a bearer
 * token, or goes to a route whose body is a credential: every `/auth/` route (prelogin, login with its `authKey` and
 * TOTP code, register's `authKey`, refresh's token, logout) and the kit recovery's `/recovery/self/` routes (the
 * `recoveryAuthKey`). The other routes without a session (the card chain, the client policy, the recovery public key,
 * the sign-up email and its code, static files) carry none.
 */
export function carriesCredential(url: string, init: RequestInit): boolean {
  const h = init.headers;
  const auth = h instanceof Headers ? h.get("Authorization") : h && !Array.isArray(h) ? (h as Record<string, string>)["Authorization"] : undefined;
  if (auth) return true;
  let path: string;
  try {
    path = new URL(url, "http://relative.invalid").pathname;
  } catch {
    return true; // a URL this client cannot read is asked as credentialed
  }
  return /^\/api\/v[0-9]+\/(auth|recovery\/self)\//.test(path);
}

/** A served answer as the v2 routes read it (api/wireclient.ts): the status and the body text, unparsed. */
export interface RawAnswer {
  status: number;
  text: string;
  /** The answer's `Content-Type`, or null without one: a body is the server's own JSON only under the JSON type. */
  contentType: string | null;
}

/**
 * Account deletion (spec 03 §13): the `409 account_delete_blocked` refusal, carrying WHAT blocks it — the vaults the
 * account owns that other accounts still use, or the last-admin role. An ApiError, so a caller that only knows the code
 * still reads it. `blockers` may be empty when the server sent none it could decode: still a refusal.
 */
export class AccountDeleteBlockedError extends ApiError {
  constructor(public blockers: AccountDeleteBlocker[]) {
    super(409, "account_delete_blocked", "account deletion is blocked");
    this.name = "AccountDeleteBlockedError";
  }
}

/**
 * Account deletion (spec 03 §13): a reply to `POST /account/delete` that says nothing reliable about whether the server
 * committed — any 5xx (a proxy's 502/504/524, or the server failing AFTER its commit) and any reply that is not the
 * server's JSON. The outcome is UNKNOWN: never reported as a failure ("not deleted" would be a guess, and a wrong one
 * sends the member back into a retry against an account that is gone), never as a success.
 */
export class AccountDeleteUnknownError extends Error {
  constructor(public status: number) {
    super(`the deletion's outcome is unknown (HTTP ${status})`);
    this.name = "AccountDeleteUnknownError";
  }
}

/** A served blocker row in the minimal shape (a kind and a count); anything else becomes a blocker of unknown kind, so a
 *  malformed row can never shrink a refusal into "nothing stands in the way". */
function blockerOf(raw: unknown): AccountDeleteBlocker {
  const r = (raw && typeof raw === "object" ? raw : {}) as { kind?: unknown; vaultId?: unknown; others?: unknown };
  return {
    kind: typeof r.kind === "string" ? r.kind : "unknown",
    vaultId: typeof r.vaultId === "string" ? r.vaultId : null,
    others: typeof r.others === "number" && Number.isFinite(r.others) ? r.others : 0,
  };
}

export interface Tokens {
  accessToken: string;
  refreshToken: string;
  /**
   * The mark that a refresh of [refreshToken] is out (spec 03 §2, the refresh's grace): the wall time in ms of its first
   * sending, written with the pair before the request goes and kept through whatever cuts it off (a lost answer, a tab
   * closed, reloaded or asleep). Only an answer in the server's own envelope clears it. Absent: no refresh is out.
   */
  refreshOutAt?: number;
  /** The one more try of that refresh was sent: no further try goes. */
  refreshTriedAgain?: boolean;
}

/**
 * A refresh whose answer never came is tried once more only within this long of its first try's sending (the edge
 * included), by any tab, judged by the wall clock so that a reload earns no extra try. The server answers a repeat of a
 * token it replaced for sixty seconds from the replacement; the second try has to arrive inside them, and the ten seconds
 * are the margin for the road. The shared code's session keeper has the same rule (REFRESH_SECOND_TRY_MS).
 */
export const REFRESH_SECOND_TRY_MS = 50_000;

/** How a refresh ended the session: `refused` by the server's own answer, or `not_confirmed` here, no try being left. */
export type RefreshEnd = "refused" | "not_confirmed";

/**
 * Where every tab shares one pair (the offline copy on), what this browser's record of that session holds now for a
 * refresh token this tab is about to send: `holds` (that same pair, or this tab's own slot holds it), `other` (another
 * pair of the same account), `ended` (the account's record with no pair), `gone` (no record of the account), `unsaved`
 * (no record, because this tab's own sign-in of that pair could not write it).
 */
export type SharedRecord = "holds" | "other" | "ended" | "gone" | "unsaved";

/**
 * The one more try of a refresh whose answer never came is made by the tab itself this long after the first try's
 * sending, where the tab is alive ([ApiClient.secondTryAfterMs]): after the first try's own limit
 * (REFRESH_FETCH_TIMEOUT_MS, fifteen seconds) has run out, with ten seconds more for the line to come back (a tunnel, a
 * change of network), and twenty-five seconds before the window ([REFRESH_SECOND_TRY_MS]) closes, for a road that is
 * slow and a timer the browser holds back in a tab that is not in view. A request that needs the session earlier makes
 * the try earlier; the try is made once either way.
 */
export const SECOND_TRY_AFTER_MS = 25_000;

/**
 * Why a refresh did not renew the session although the session lives (the request that set it off is not answered with
 * its own `401`, which its caller would read as the session's end):
 *  - `unanswered`: no answer of the server's came (no answer at all, a gateway's page, a body that does not read). The
 *    mark stands, and the one more try is left while its window lasts.
 *  - `unavailable`: the server's own answer for the moment (its 5xx, 429 or 426 in its envelope): it took nothing.
 *  - `not_kept`: the mark could not be written where the pair is kept, so nothing was sent; the next request tries again.
 * A TypeError, the way a request that got no answer fails: every caller that reads "no answer" reads it so (the change
 * waits in the queue, the events connection tries again later, the unlock card opens the copy).
 */
export type RenewalNotDone = "unanswered" | "unavailable" | "not_kept";

export class RefreshUnansweredError extends TypeError {
  constructor(public readonly kind: RenewalNotDone, cause?: unknown) {
    super(kind === "not_kept" ? "the mark of a refresh could not be kept: nothing was sent" : `the session's renewal got no answer of the server's (${kind})`);
    this.name = "RefreshUnansweredError";
    if (cause !== undefined) (this as { cause?: unknown }).cause = cause;
  }
}

/**
 * A refresh whose answer never came had no try left: nothing was sent, and the session ended here, not confirmed. Its end
 * was raised once already ([ApiClient.onRefreshRefused] `not_confirmed`); a caller raises none of its own and never says
 * it as expired, as ended by the server, or as revoked. An ApiError with status 0 (never 401), so a caller that only
 * knows ApiError reads it as a failure of the request and not as the session's end.
 */
export class SessionNotConfirmedError extends ApiError {
  constructor() {
    super(0, "session_not_confirmed", "the session ended in this browser: its renewal could not be confirmed, and nothing was sent");
    this.name = "SessionNotConfirmedError";
  }
}

/**
 * The session every tab shares is gone from this browser's record (another tab signed out or ended it) and this tab had
 * not heard of it yet: nothing was sent, and the end was raised once already ([ApiClient.onEndedElsewhere]). Status 0 (never 401), so a caller reads it as a failure of the request, not as the session's end.
 */
export class SessionEndedElsewhereError extends ApiError {
  constructor() {
    super(0, "session_ended_elsewhere", "the session every tab shares is no longer in this browser's record: nothing was sent");
    this.name = "SessionEndedElsewhereError";
  }
}

/** What a refresh came to, for the request that set it off ([ApiClient.rawSend]). */
type RefreshOutcome = "renewed" | RenewalNotDone | "not_confirmed" | "refused" | "dropped" | "elsewhere";

/** The refusals by which the server ends a session at a refresh, in its own envelope, at any status (with 401 and 403). */
const REFRESH_ENDS = new Set(["invalid_refresh", "refresh_reuse", "refresh_expired"]);

/** Whether the server's own refusal of a refresh ([refusal], answered at [status]) ends the session. */
const serverEnded = (refusal: string, status: number): boolean => status === 401 || status === 403 || REFRESH_ENDS.has(refusal);

/** The tab's own one more try is for this marked pair only ([ApiClient.scheduleSecondTry]). */
interface SecondTryOf {
  readonly token: string;
  readonly outAt: number;
}

const marked = (t: Tokens | null): boolean => typeof t?.refreshOutAt === "number";

/** The pair alone, without a mark. */
const bare = (t: Tokens): Tokens => ({ accessToken: t.accessToken, refreshToken: t.refreshToken });

/** [a] with the mark [b] carries for the same token: the earliest first sending, and a second try made by either. */
function withMark(a: Tokens, b: Tokens): Tokens {
  if (a.refreshToken !== b.refreshToken || !marked(b)) return a;
  const outAt = Math.min(a.refreshOutAt ?? Infinity, b.refreshOutAt!);
  return { ...a, refreshOutAt: outAt, ...(a.refreshTriedAgain || b.refreshTriedAgain ? { refreshTriedAgain: true } : {}) };
}

/**
 * A refresh's answer, read whole: the new pair, or the server's own refusal (its `{error, message}` envelope), or null
 * for anything else (a gateway's page, a body that does not read or does not decode, a `200` among them), which says
 * nothing of whether the server took the token.
 */
async function refreshAnswer(resp: Response): Promise<{ pair: Tokens } | { refusal: string } | null> {
  let b: Record<string, unknown> | null;
  try {
    b = JSON.parse(await resp.text()) as Record<string, unknown> | null;
  } catch {
    return null;
  }
  if (typeof b !== "object" || b === null) return null;
  if (resp.ok) return typeof b.accessToken === "string" && typeof b.refreshToken === "string" ? { pair: { accessToken: b.accessToken, refreshToken: b.refreshToken } } : null;
  return typeof b.error === "string" && typeof b.message === "string" ? { refusal: b.error } : null;
}

/** A request retries after at most this many refresh/adopt rounds (see raw()). */
const MAX_AUTH_ATTEMPTS = 2;

/** Abort a hung refresh POST after this long — other tabs queue behind our web lock. */
const REFRESH_FETCH_TIMEOUT_MS = 15_000;
/** Give up WAITING for another tab's refresh lock after this long (> the fetch timeout,
 *  so a healthy holder always finishes or times out first) and proceed without
 *  cross-tab exclusion rather than stall every tab behind one wedged fetch. */
const REFRESH_LOCK_WAIT_MS = 20_000;
/** Bound on the sign-out revocation POST — the natives' 5 s logout timeout, mirrored.
 *  Exported so ui/session.ts races the SAME clock the request is aborted on: abandoning a
 *  race does NOT cancel a fetch, and an uncancelled revocation outlives the sign-out (see
 *  logout()). One constant, one clock. */
export const LOGOUT_TIMEOUT_MS = 5_000;
/** The longest wait a refused `end-session` (429) is tried again after: a lock's answer stays prompt. */
export const END_SESSION_RETRY_MAX_S = 30;
/** Account deletion (spec 03 §13): how long `POST /account/delete` may take before its outcome is reported unknown —
 *  ample for the server's memory-hard verify and a wait on its writer lock. It also bounds App's hold on a session end
 *  that lands while the request is in flight (account-delete.ts stepDeletionWatch, DELETION_HOLD_LIMIT_MS). */
export const ACCOUNT_DELETE_TIMEOUT_MS = 60_000;
/** An answer that is small by its nature: how long its whole answer, the body included, may take (ApiClient.answerTimeoutMs). */
export const ANSWER_TIMEOUT_MS = 60_000;
/**
 * An answer whose size grows with the vault or a file (the sync, a push, an attachment's upload or download): how long it
 * may go without a byte (ApiClient.progressTimeoutMs). There is no limit on its total: a first sync of a large vault on a
 * slow line finishes.
 */
export const PROGRESS_TIMEOUT_MS = 30_000;
/**
 * A browser cannot see a request's body leave, so for a request with a body the wait for the answer's head is the time
 * without progress plus the time the body takes at this floor rate (2 KiB/s, 16 kbit/s: far below any line that still
 * carries a page). A 25 MiB attachment is then given about three and a half hours before its answer must begin.
 */
export const UPLOAD_FLOOR_BYTES_PER_S = 2_048;

/** The size of a request body as it leaves (a JSON text in UTF-8, or bytes); 0 for anything else. */
function bodyBytes(body: BodyInit | null | undefined): number {
  if (typeof body === "string") {
    let n = 0;
    for (let i = 0; i < body.length; i++) {
      const c = body.charCodeAt(i);
      n += c < 0x80 ? 1 : c < 0x800 ? 2 : c >= 0xd800 && c <= 0xdbff ? (i++, 4) : 3;
    }
    return n;
  }
  if (body instanceof Uint8Array || body instanceof ArrayBuffer) return body.byteLength;
  return 0;
}

/** What a request's answer is: small by its nature (a limit on its whole time), or growing with the vault or a file. */
export type AnswerSize = "small" | "grows";

/**
 * The limit of one request without a deadline of its caller. `small`: one deadline from the start for the whole answer.
 * `grows`: a window that each sign of progress renews (the request leaving, the answer's head, every piece of its body),
 * paused while the session is refreshed. When it strikes, the request's signal is aborted with an [AnswerLimitError].
 */
class AnswerWatch {
  readonly ctl = new AbortController();
  fired: AnswerLimitError | null = null;
  /** Called once when the limit strikes (the body's reader is cancelled through it). */
  onFire: (() => void) | null = null;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private over = false;

  constructor(
    private readonly size: AnswerSize,
    private readonly ms: number,
    private readonly floorBytesPerS: number,
  ) {
    if (size === "small") this.arm(ms);
  }

  private arm(ms: number): void {
    if (this.over) return;
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = setTimeout(() => this.fire(), ms);
  }

  private fire(): void {
    if (this.over) return;
    this.over = true;
    this.timer = undefined;
    this.fired = new AnswerLimitError(this.size === "small" ? "too_long" : "stalled", this.ms);
    this.ctl.abort(this.fired);
    this.onFire?.();
  }

  /** A request (or its re-send) leaves with a body of [bytes]. */
  sending(bytes: number): void {
    if (this.size === "grows") this.arm(this.ms + Math.ceil((bytes * 1000) / this.floorBytesPerS));
  }

  /** Something of the answer came: its head, or a piece of its body. */
  progressed(): void {
    if (this.size === "grows") this.arm(this.ms);
  }

  /** The session is being refreshed before a re-send (bounded by the refresh's own limits). */
  waiting(): void {
    if (this.size === "grows" && this.timer !== undefined && !this.over) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
  }

  /**
   * An answer is handed on to be read: a window paused for a refresh that led to no second send (the refresh failed, or
   * the tab is bound to another account now) runs again, so the body of the answer in hand is never read without a limit.
   */
  handedOn(): void {
    if (this.size === "grows" && this.timer === undefined) this.arm(this.ms);
  }

  /** The answer was read to its end, or failed: no limit is kept running. */
  done(): void {
    this.over = true;
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
  }
}

/**
 * Why the session ended (events() → onRevoked): an explicit server `revoked` frame is
 * a real revocation; a 401/403 at ticket mint after a refused refresh is ordinary
 * EXPIRY (laptop asleep past the refresh lifetime) and must not be presented as
 * "your device was revoked". `unconfirmed`: no server ended it; this browser could not confirm the session in time (a
 * refresh whose answer never came had no try left, [REFRESH_SECOND_TRY_MS]) and ended it itself, sending nothing.
 */
export type SessionEndKind = "revoked" | "expired" | "unconfirmed";

/** AbortSignal.timeout where it exists (Chrome 103+/FF 100+/Safari 16+) — some
 *  browsers HAVE Web Locks but not this; a missing timeout must degrade to an
 *  unbounded wait, never crash the refresh path. */
function timeoutSignal(ms: number): AbortSignal | undefined {
  return typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function"
    ? AbortSignal.timeout(ms)
    : undefined;
}

/** timeoutSignal, with an AbortController + timer where AbortSignal.timeout is missing: a deadline that must hold
 *  (account deletion — App holds a session end until the request ends) cannot degrade to an unbounded wait. */
function deadlineSignal(ms: number): AbortSignal | undefined {
  const native = timeoutSignal(ms);
  if (native || typeof AbortController === "undefined") return native;
  const c = new AbortController();
  setTimeout(() => c.abort(), ms);
  return c.signal;
}

/** A fetch rejected by its signal: the timeout's TimeoutError, or a plain abort. */
function isAbort(e: unknown): boolean {
  const name = typeof e === "object" && e !== null ? (e as { name?: unknown }).name : undefined;
  return name === "TimeoutError" || name === "AbortError";
}

/**
 * [resp] with its body read through [watch]: each piece renews a growing answer's window, the end (or a failure) stops
 * the limit, and a limit that strikes while the body comes ends the read with the limit's [AnswerLimitError] (read by
 * [readAnswerText] as an answer cut off, with the limit named). An answer without a readable body is handed back as it is.
 */
function watched(resp: Response, watch: AnswerWatch): Response {
  // A third review: after a 401 whose refresh failed, the paused window was never started again, and a body that never
  // came was then waited for without end (every later sync queued behind it). Every answer handed on is watched.
  watch.handedOn();
  const src = (resp as { body?: unknown }).body;
  if (!src || [101, 103, 204, 205, 304].includes(resp.status) || typeof (src as ReadableStream<Uint8Array>).getReader !== "function") {
    watch.done();
    return resp;
  }
  const reader = (src as ReadableStream<Uint8Array>).getReader();
  watch.onFire = () => void reader.cancel(watch.fired).catch(() => {});
  const body = new ReadableStream<Uint8Array>({
    async pull(c) {
      let r: ReadableStreamReadResult<Uint8Array>;
      try {
        r = await reader.read();
      } catch (e) {
        watch.done();
        c.error(watch.fired ?? e);
        return;
      }
      // A read the limit cancelled ends as "done": it is the limit's end, never the answer's.
      if (watch.fired) {
        c.error(watch.fired);
        return;
      }
      if (r.done) {
        watch.done();
        c.close();
        return;
      }
      watch.progressed();
      c.enqueue(r.value);
    },
    cancel(reason) {
      watch.done();
      return reader.cancel(reason);
    },
  });
  return new Response(body, { status: resp.status, statusText: resp.statusText, headers: resp.headers });
}

/** A refresh POST as a lock that overtakes it sees it (ApiClient.endSession): the token it spent, and what ended its answer. */
type RefreshTicket = { spent: string; owner: string | null; orphan: Promise<boolean> | null; settled: boolean };

/**
 * REST client for the andvari server. Holds the token pair, refreshes the access
 * token on 401 and retries. Every refused response throws a typed ApiError: the
 * store handles 410 (resync from 0), and a 426 `upgrade_required` (min-version pin,
 * spec 03 §1) additionally fires `onUpgradeRequired` so the app shell can show its
 * persistent "reload to update" bar — the server serves this very bundle, so only a
 * stale long-lived tab can sit behind the pin, and a plain reload IS the update.
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

  /**
   * A14 review W3: the account whose session this client's pair belongs to, for the persistence
   * hooks ui/session.ts wires (makeClient): a rotation is written, and another tab's pair adopted,
   * only while the persisted session is this account's. makeClient sets it from the session it was
   * built for; a sign-in or register rebinds it to the account the server just answered for, before
   * anything else can rotate the new pair.
   */
  boundUserId: string | null = null;

  /**
   * A14 review W2: bumped by every [setTokens] and [useSessionTokens]. A refresh records it before its
   * fetch and adopts the rotated pair only if nothing set the pair meanwhile — a lock that dropped it
   * (setTokens(null)) or a fresh sign-in must never be undone by a refresh that was already in flight.
   */
  private generation = 0;

  /**
   * Design §4.4 "a fork stops traffic, not reading": consulted before every request and socket this client makes, and
   * again when an answer lands. A non-null answer (why traffic stopped) refuses the request with
   * {@link TrafficStoppedError} before anything leaves the browser, and drops an answer that arrives after it. The app
   * wires it to the pin of the origin it dials (ui/opensession.ts createWebContext): forked or damaged stops traffic.
   */
  trafficGate?: (credentialed: boolean) => string | null;

  /** The live event sockets' closers, so a stop closes them at once ([cutLiveTraffic]). */
  private readonly liveSockets = new Set<() => void>();

  /**
   * Throws {@link TrafficStoppedError} while the gate says traffic is stopped. [credentialed] (design §4.4 "No
   * credential goes to an origin without a pin in force"): the request carries a bearer token, a refresh token, a
   * logout, or a value derived from the master password ({@link carriesCredential}); the gate refuses those to an
   * origin with no pin in force. A caller that cannot tell asks as credentialed. [sent]: whether anything of this act
   * has already left the browser (said at every call; never a default).
   */
  assertTrafficAllowed(credentialed: boolean, sent: boolean): void {
    const why = this.trafficGate?.(credentialed) ?? null;
    if (why !== null) throw new TrafficStoppedError(why, sent);
  }

  /** Closes every live event socket (and its reconnects) now: the app calls it when a session finds its pin forked. */
  cutLiveTraffic(): void {
    for (const close of [...this.liveSockets]) close();
  }

  /**
   * The one `fetch` of the web client: refused before it leaves, and its answer dropped, while traffic is stopped. It
   * follows no redirect: a redirect is an answer that is not the server's ({@link RedirectRefusedError}).
   */
  private async send(url: string, init: RequestInit): Promise<Response> {
    // The limit of this request (when the client set one) learns when it leaves and when its answer's head came.
    const watch = init.signal ? this.watches.get(init.signal) : undefined;
    watch?.sending(bodyBytes(init.body));
    const credentialed = carriesCredential(url, init);
    this.assertTrafficAllowed(credentialed, false);
    const resp = await fetch(url, { ...init, redirect: "manual" });
    this.assertTrafficAllowed(credentialed, true); // §4.4: nothing from a forked origin is accepted, an answer already on its way included
    watch?.progressed();
    if (isRedirect(resp)) throw new RedirectRefusedError(resp.status);
    return resp;
  }

  /** A same-origin static file (the downloads manifest), through the same gate as every API call. */
  fetchStatic(url: string, init: RequestInit = {}): Promise<Response> {
    return this.limited(init.signal ?? undefined, "small", (s) => this.send(url, s ? { ...init, signal: s } : init));
  }

  setTokens(t: Tokens | null) {
    this.generation++;
    this.clearSecondTry();
    this.tokens = t;
    this.onTokens(t);
  }

  private clearSecondTry(): void {
    if (this.secondTryTimer !== null) clearTimeout(this.secondTryTimer);
    this.secondTryTimer = null;
  }

  /**
   * After a first try whose answer never came, the tab makes the one more try itself at [secondTryAfterMs] from its
   * sending, if the pair is still that marked pair then (no request, and no other tab, made it meanwhile).
   */
  private scheduleSecondTry(asked: Tokens): void {
    if (this.secondTryAfterMs === null || asked.refreshTriedAgain || !marked(asked)) return;
    this.clearSecondTry();
    const of = { token: asked.refreshToken, outAt: asked.refreshOutAt! };
    const timer = setTimeout(() => {
      this.secondTryTimer = null;
      if (this.tokens?.refreshToken !== of.token) return;
      void this.tryRefresh(of).catch(() => {});
    }, Math.max(0, of.outAt + this.secondTryAfterMs - Date.now()));
    (timer as { unref?: () => void }).unref?.();
    this.secondTryTimer = timer;
  }

  /**
   * The request that set a refresh off, after it: re-sent once the session was renewed; its own answer handed back where
   * the refresh was refused by the server or the pair went meanwhile (as before); and otherwise an error its caller can
   * tell apart, never its `401`, which reads as the session's end: [RefreshUnansweredError] (the session lives) or
   * [SessionNotConfirmedError] (ended here; its end was raised once already).
   */
  private async afterRefresh(resp: Response): Promise<"resend" | Response> {
    let outcome: RefreshOutcome;
    try {
      outcome = await this.tryRefresh();
    } catch (e) {
      if (e instanceof TrafficStoppedError) throw e; // §4.4: a stop, said as a stop
      throw new RefreshUnansweredError("unanswered", e); // no answer at all (a lost answer, a time limit, a redirect)
    }
    switch (outcome) {
      case "renewed":
        return "resend";
      case "unanswered":
      case "unavailable":
      case "not_kept":
        throw new RefreshUnansweredError(outcome);
      case "not_confirmed":
        throw new SessionNotConfirmedError();
      case "elsewhere":
        throw new SessionEndedElsewhereError();
      case "refused":
      case "dropped":
        return resp;
    }
  }

  /**
   * A14 review W3: install a pair from a login or register response WITHOUT the persistence hook. The
   * caller's saveSession is the only writer of a fresh pair: the hook would place it under whatever
   * metadata is persisted now — on a tab that booted to Welcome for account X, X's — before the new
   * account's sign-in had even finished, and a sign-in that then failed would leave it there.
   */
  useSessionTokens(t: Tokens) {
    this.generation++;
    this.tokens = t;
  }

  getTokens(): Tokens | null {
    return this.tokens;
  }

  /**
   * Registered by the app shell (App.tsx), fired by throwApiError when the server
   * refuses a request with `upgrade_required` (HTTP 426: this bundle is older than
   * the org's min-version pin, spec 03 §1). Assigned post-construction because the
   * client is built by ui/session.ts's makeClient, which has no UI concerns. The
   * refused call still throws its ApiError unchanged — this is a side-channel nudge,
   * not a replacement error path.
   */
  onUpgradeRequired?: () => void;

  /**
   * Registered by the app shell (App.tsx): a refresh ended the session. `refused`: the server refused it outright in its
   * own envelope (401/403, or a refresh code). `not_confirmed`: a refresh whose answer never came had no try left, so
   * nothing was sent and the session ended here ([REFRESH_SECOND_TRY_MS]). The pair is already dropped when this fires;
   * App ends the session the design §4.4 way (the copy stays).
   */
  onRefreshRefused?: (why: RefreshEnd) => void;

  /**
   * Wired by ui/session.ts makeClient: keeps the refresh token of a session that ended here with no try left, or that a
   * lock or a sign-out dropped while a refresh of it had no answer, for ONE use: the next sign-in names it as the session
   * it replaces. It is never sent as a refresh or to end a session.
   */
  keepUnconfirmed?: (refreshToken: string, owner: string | null) => void;

  /**
   * Wired by ui/session.ts makeClient: whether [refreshToken] is one [keepUnconfirmed] kept, in any tab of this browser.
   * Such a token is never sent, whatever this tab still holds in its memory.
   */
  isKeptUnconfirmed?: (refreshToken: string) => boolean;

  /**
   * Wired by ui/session.ts makeClient: where every tab shares one pair (the offline copy on), what this browser's record
   * holds now for [refreshToken] ([SharedRecord]); undefined where the pair is this tab's own. A refresh token leaves this
   * tab only while the record holds that same pair ([mayLeave]); no record of a removed token is kept anywhere, the
   * record's absence is the guard.
   */
  sharedRecord?: (refreshToken: string) => SharedRecord | undefined;

  /**
   * Whether [refreshToken] may leave this tab now: where every tab shares the pair, only while this browser's record holds
   * that same pair. A record that cannot be read holds nothing.
   */
  private readonly mayLeave = (refreshToken: string): boolean => {
    const r = this.recordOf(refreshToken);
    return r === undefined || r === "holds";
  };

  /** [sharedRecord] for [refreshToken]; a record that cannot be read is gone. */
  private readonly recordOf = (refreshToken: string): SharedRecord | undefined => {
    try {
      return this.sharedRecord?.(refreshToken);
    } catch {
      return "gone";
    }
  };

  /**
   * The session every tab shares is no longer the one this browser's record holds: nothing is sent and nothing is kept
   * (the tab that removed it removed its token too); the pair goes and the tab ends as signed out elsewhere. A property,
   * not a method, as [noTryLeft]: nothing that walks the client's methods can drop the pair through it.
   */
  private readonly endElsewhere = (): RefreshOutcome => {
    this.setTokens(null);
    this.onEndedElsewhere?.();
    return "elsewhere";
  };

  /**
   * Registered by the app shell (App.tsx): the session every tab shares (the offline copy on) is no longer the one this
   * browser's record holds, because another tab signed out or ended it before this tab heard of it. Nothing was sent and
   * the pair is already dropped when this fires; App lands the tab as that tab's `storage` event would.
   */
  onEndedElsewhere?: () => void;

  /**
   * The tab makes the one more try of a refresh whose answer never came by itself, this long after the first try's
   * sending ([SECOND_TRY_AFTER_MS]); null: only a request that needs the session makes it. ui/session.ts makeClient sets
   * it for the app's client; a client built bare (a test, a helper) has no timer of its own.
   */
  secondTryAfterMs: number | null = null;
  private secondTryTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * [held] as this browser keeps it: with the mark another tab wrote on the same pair (the session every tab shares with
   * the offline copy on). Every place that sends a refresh token reads it through here, never its own memory alone.
   */
  private asKept(held: Tokens): Tokens {
    let persisted: Tokens | null = null;
    try {
      persisted = this.readPersistedTokens?.() ?? null;
    } catch {
      persisted = null;
    }
    return persisted ? withMark(held, persisted) : held;
  }

  /** Whether [t]'s refresh token may leave: no refresh of it is out unanswered, and it is not a kept token. */
  private spendable(t: Tokens): boolean {
    return !marked(t) && !this.isKeptUnconfirmed?.(t.refreshToken);
  }

  /** Keeps [refreshToken] for the next sign-in's name ([keepUnconfirmed]), as [owner]'s (the account the client was
   *  bound to when the call that keeps it began); a failure keeps nothing, and sends nothing. */
  private keepForNextSignIn(refreshToken: string, owner: string | null = this.boundUserId): void {
    try {
      this.keepUnconfirmed?.(refreshToken, owner);
    } catch {
      /* not kept: the next sign-in names nothing; nothing is sent either way */
    }
  }

  /**
   * Security review 2026-10 (plugin scan F1/F2, branch A10): every server-supplied id is checked against the UUID
   * grammar here, at the wire boundary (wireids.ts); a row with a malformed id is dropped before any caller sees it
   * and reported here as `(endpoint, refusals)`. The store surfaces it as a `bad-id` anomaly notice. A session or
   * identity row with a malformed id is refused outright (`bad_wire_id`).
   */
  get onRefusedIds(): ((endpoint: string, refused: Refusal[]) => void) | undefined {
    return this.refusedHandler;
  }

  /** Security review 2026-10, branch A11 (c21): the store installs its handler only once it exists, AFTER login or
   *  register; refusals reported before then are kept (a few, ids only) and handed to the first handler installed. */
  set onRefusedIds(fn: ((endpoint: string, refused: Refusal[]) => void) | undefined) {
    this.refusedHandler = fn;
    if (fn) for (const [endpoint, refused] of this.earlyRefusals.splice(0)) fn(endpoint, refused);
  }

  private refusedHandler?: (endpoint: string, refused: Refusal[]) => void;
  private readonly earlyRefusals: [string, Refusal[]][] = [];

  private emitRefused(endpoint: string, refused: Refusal[]): void {
    if (this.refusedHandler) this.refusedHandler(endpoint, refused);
    else if (this.earlyRefusals.length < 8) this.earlyRefusals.push([endpoint, refused]);
  }

  private reported<T>(endpoint: string, s: Sanitized<T>): T {
    if (s.refused.length > 0) this.emitRefused(endpoint, s.refused);
    return s.value;
  }

  private refuseWire(endpoint: string, r: Refusal): never {
    this.emitRefused(endpoint, [r]);
    throw new ApiError(0, "bad_wire_id", `the server sent a malformed ${r.field} on ${endpoint}`);
  }

  /** The two fences a served session passes BEFORE it is installed: the KDF floor (H1) and the id grammar (A10). */
  private session(endpoint: string, s: SessionResponse): SessionResponse {
    assertServerKdfParams(s.accountKeys.kdfParams); // H1: fence BEFORE installing the session
    const r = refusedSession(s);
    if (r) this.refuseWire(endpoint, r);
    const accountKeys = this.reported(endpoint, sanitizeAccountKeys(s.accountKeys));
    return accountKeys === s.accountKeys ? s : { ...s, accountKeys };
  }

  /**
   * Two kinds of limit on an answer, for a request whose caller sets no deadline of its own (review: an answer whose head
   * arrived and whose body never did left the screen waiting for ever; a second review: a limit on the whole time made the
   * first sync of a large vault on a slow line impossible). An answer that is small by its nature: [answerTimeoutMs] for
   * the whole answer, the body included, one limit for the request and its re-send after a refresh. An answer whose size
   * grows with the vault or a file: [progressTimeoutMs] without a byte, and no limit on its total. Past either before the
   * answer's head: a [NoAnswerInTimeError] (a TypeError, as for any request with no answer); past it while the body comes
   * in: the body read fails, an answer that could not be read ([AnswerCutOffError]). Both say which limit it was.
   */
  answerTimeoutMs = ANSWER_TIMEOUT_MS;
  /** The time without progress for an answer that grows with the vault or a file. */
  progressTimeoutMs = PROGRESS_TIMEOUT_MS;
  /** The floor rate a request's body is given to leave before its answer must begin (see UPLOAD_FLOOR_BYTES_PER_S). */
  uploadFloorBytesPerS = UPLOAD_FLOOR_BYTES_PER_S;

  /** The limit of each request in flight, by the signal it was sent with: [send] tells it when the request leaves and its head comes. */
  private readonly watches = new WeakMap<AbortSignal, AnswerWatch>();

  /** [run] under [signal], or under this client's own limit of the kind [size] names when the caller set none. */
  private async limited(signal: AbortSignal | undefined, size: AnswerSize, run: (s: AbortSignal | undefined) => Promise<Response>): Promise<Response> {
    if (signal !== undefined) return run(signal);
    const watch = new AnswerWatch(size, size === "small" ? this.answerTimeoutMs : this.progressTimeoutMs, this.uploadFloorBytesPerS);
    this.watches.set(watch.ctl.signal, watch);
    let resp: Response;
    try {
      resp = await run(watch.ctl.signal);
    } catch (e) {
      watch.done();
      // No answer came within the limit: said as no answer, the way a fetch that got none fails, with the limit named.
      if (watch.fired && (e === watch.fired || isAbort(e))) throw new NoAnswerInTimeError(watch.fired.kind, watch.fired.ms);
      throw e;
    }
    return watched(resp, watch);
  }

  private raw(method: string, path: string, body?: unknown, auth = true, attempt = 0, signal?: AbortSignal, size: AnswerSize = "small"): Promise<Response> {
    return this.limited(signal, size, (s) => this.rawSend(method, path, body, auth, attempt, s));
  }

  private async rawSend(method: string, path: string, body: unknown, auth: boolean, attempt: number, signal: AbortSignal | undefined): Promise<Response> {
    const headers: Record<string, string> = { "X-Andvari-Client": CLIENT_HEADER };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const used = auth && this.tokens ? this.tokens.accessToken : null;
    if (used) headers["Authorization"] = `Bearer ${used}`;
    // The account this request was made for. A 401 is retried, or the pair refreshed for it, only while
    // the tab is still bound to that account: after a sign-out and a sign-in as another, the old request ends with its
    // 401 instead of going out again under the new account's token.
    const bound = this.boundUserId;
    const resp = await this.send(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      // Optional deadline (account deletion): one signal for the request and its re-send, so the whole call is bounded.
      ...(signal ? { signal } : {}),
    });
    if (resp.status === 401 && auth && attempt < MAX_AUTH_ATTEMPTS && this.tokens && this.boundUserId === bound) {
      // A refresh that completed while this request was in flight (another caller's
      // single-flight refresh, or a pair adopted from another tab) already replaced
      // the tokens — retry with the fresh access token instead of rotating again.
      if (this.tokens.accessToken !== used) return this.rawSend(method, path, body, auth, attempt + 1, signal);
      // The refresh awaits: a sign-out and a sign-in as another account can happen meanwhile, and the re-send would then
      // carry that account's token. It goes out only while the tab is still bound to the account it was made for.
      // The window paused here runs again when the answer in hand is handed on without a re-send ([watched]).
      if (signal) this.watches.get(signal)?.waiting();
      if ((await this.afterRefresh(resp)) === "resend" && this.boundUserId === bound) return this.rawSend(method, path, body, auth, attempt + 1, signal);
    }
    return resp;
  }

  private refreshInFlight: Promise<RefreshOutcome> | null = null;

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
  private tryRefresh(secondTryOf?: SecondTryOf): Promise<RefreshOutcome> {
    this.refreshInFlight ??= this.refreshExclusive(secondTryOf).finally(() => {
      this.refreshInFlight = null;
    });
    return this.refreshInFlight;
  }

  private async refreshExclusive(secondTryOf?: SecondTryOf): Promise<RefreshOutcome> {
    // Web Locks API (Chrome 69+/FF 96+/Safari 15.4+) serializes tabs. Where missing
    // (older browsers, non-window contexts) proceed unlocked — the persisted-pair
    // re-read in refreshNow still catches most cross-tab races, and in-tab callers
    // are already deduped by the shared promise.
    const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
    if (!locks?.request) return this.refreshNow(secondTryOf);
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
          return this.refreshNow(secondTryOf);
        },
      );
    } catch (e) {
      if (granted) throw e; // refreshNow's own failure — not a lock problem
      // The wait for another tab's (hung) refresh timed out, or Web Locks glitched:
      // proceed WITHOUT cross-tab exclusion. Per-tab single-flight still holds and
      // the persisted re-read still runs; the worst case is a rare double-rotation —
      // strictly better than every tab stalling behind one wedged fetch.
      return this.refreshNow(secondTryOf);
    }
  }

  private async refreshNow(secondTryOf?: SecondTryOf): Promise<RefreshOutcome> {
    const held = this.tokens;
    if (!held) return "dropped";
    const generation = this.generation; // W2: the pair this refresh may replace
    // Re-read INSIDE the lock: if another tab already rotated (the persisted refresh
    // token differs from the one we were about to spend), adopt its pair — POSTing
    // ours now would replay a consumed token and revoke the device.
    const persisted = this.readPersistedTokens?.() ?? null;
    if (persisted && persisted.refreshToken !== held.refreshToken) {
      this.setTokens(persisted);
      return "renewed";
    }
    // Where every tab shares the pair, this tab's token leaves only while the record holds that same pair: a record gone
    // (another tab signed out) or holding no pair means this tab has not yet heard of that end, and its token, which that
    // tab may have spent, never goes.
    // This tab's own sign-in could not write the record (a full storage): nothing ended elsewhere, the session was never
    // saved where every tab shares it. Nothing is sent, and the request says so (RENEWAL_NOT_SAVED), as for a mark that
    // could not be written.
    if (this.recordOf(held.refreshToken) === "unsaved") return "not_kept";
    if (!this.mayLeave(held.refreshToken)) return this.endElsewhere();
    // A refresh whose answer never came (spec 03 §2, the grace): the server may have taken the token, and then answers it
    // again with the same pair for sixty seconds from the replacement only. So it is tried once more, by any tab (the mark
    // another tab wrote on this pair counts here), within [REFRESH_SECOND_TRY_MS] of its first sending, and never after:
    // a third try, or one after the window, would read as a stolen token's reuse and end every session of the device.
    const spending = persisted ? withMark(held, persisted) : held;
    const kept = this.isKeptUnconfirmed?.(spending.refreshToken) === true;
    const now = Date.now();
    const inWindow = marked(spending) && !spending.refreshTriedAgain && now >= spending.refreshOutAt! && now - spending.refreshOutAt! <= REFRESH_SECOND_TRY_MS;
    if (secondTryOf) {
      // The tab's own one more try: made only for the marked pair it was set for, inside the window; anything else (a
      // request or another tab made it, the answer came, the window is gone) leaves the end, if any, to the next request.
      if (kept || !inWindow || spending.refreshToken !== secondTryOf.token || spending.refreshOutAt !== secondTryOf.outAt) return "dropped";
    }
    let asked: Tokens;
    if (kept || (marked(spending) && !inWindow)) {
      this.noTryLeft(spending);
      return "not_confirmed";
    } else if (marked(spending)) {
      asked = { ...spending, refreshTriedAgain: true }; // counted before it goes: never a third
    } else {
      asked = { ...bare(spending), refreshOutAt: now };
    }
    // Written with the pair before the request goes: whatever cuts it off (a lost answer, the tab closed, reloaded or
    // asleep) leaves it. Not a new pair (no W2 generation): the same session, marked. The write is read back where the
    // pair is kept: a mark that could not be written is not a mark, and nothing is sent without one.
    this.tokens = asked;
    if (!this.markKept(asked)) {
      this.tokens = spending;
      return "not_kept";
    }
    const ticket: RefreshTicket = { spent: asked.refreshToken, owner: this.boundUserId, orphan: null, settled: false };
    this.refreshTicket = ticket;
    try {
      const outcome = await this.refreshSend(asked, generation, ticket);
      if (outcome === "unanswered" && this.tokens?.refreshToken === asked.refreshToken) this.scheduleSecondTry(asked);
      return outcome;
    } catch (e) {
      // The gate's stop (§4.4) refused it before it left: nothing reached the server, so the pair stands as it was before
      // this try. Every other failure (no answer, a timeout, a redirect) leaves the mark.
      if (e instanceof TrafficStoppedError && !e.sent && this.tokens === asked) {
        this.tokens = spending;
        this.onTokens(spending);
      } else if (this.tokens === asked) this.scheduleSecondTry(asked);
      throw e;
    } finally {
      ticket.settled = true;
    }
  }

  /**
   * Writes [asked] (the pair with its mark) through the persistence hook and reads it back where the pair is kept. False
   * when the browser keeps this pair (its token) and the write did not put the mark there: a reload, or another tab, would
   * then find the token unmarked and send it again at any later time. A pair the browser keeps nowhere (no reader wired,
   * or no record of it) lives only in this client's memory, which holds the mark.
   */
  private markKept(asked: Tokens): boolean {
    let threw = false;
    try {
      this.onTokens(asked);
    } catch {
      threw = true;
    }
    if (!this.readPersistedTokens) return !threw;
    let back: Tokens | null;
    try {
      back = this.readPersistedTokens();
    } catch {
      return false;
    }
    if (back === null || back.refreshToken !== asked.refreshToken) return !threw;
    return back.refreshOutAt === asked.refreshOutAt && (back.refreshTriedAgain === true) === (asked.refreshTriedAgain === true);
  }

  /**
   * No try is left for a refresh whose answer never came: nothing is sent, and the session ends here with an end of its
   * own (`not_confirmed`, never said as the server's). Its token is kept for one use only ([keepUnconfirmed]).
   */
  private readonly noTryLeft = (s: Tokens): void => {
    this.keepForNextSignIn(s.refreshToken);
    this.setTokens(null);
    this.onRefreshRefused?.("not_confirmed");
  };

  private async refreshSend(spending: Tokens, generation: number, ticket: RefreshTicket): Promise<RefreshOutcome> {
    const resp = await this.send(this.baseUrl + "/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Andvari-Client": CLIENT_HEADER },
      body: JSON.stringify({ refreshToken: spending.refreshToken }),
      // A hung refresh must not wedge this tab's recovery — nor, via the web lock,
      // every OTHER tab's (they queue behind us for up to REFRESH_LOCK_WAIT_MS).
      signal: timeoutSignal(REFRESH_FETCH_TIMEOUT_MS),
    });
    // W2: the pair was dropped or replaced while this refresh was in flight — adopt nothing. Spec 03 §2: a
    // rotated pair that nobody adopts is a live session nobody holds, so it is ended by its own refresh token (the lock
    // that dropped the pair reads the result through [ticket]).
    if (this.generation !== generation) {
      ticket.orphan = this.endOrphanedAnswer(resp, ticket);
      return "dropped";
    }
    const answer = await refreshAnswer(resp);
    if (this.generation !== generation) {
      // W2: …or while its body was read (and F2: a rotated pair nobody adopts is ended).
      ticket.orphan = this.endOrphaned(answer, resp.status, ticket);
      return "dropped";
    }
    // No answer of the server's (a gateway's page, a body that does not read, a 200 among them): the mark stays, for the
    // one more try. Never read as the server's end: a gateway's 401 page is not the server refusing the token.
    if (answer === null) return "unanswered";
    if ("refusal" in answer) {
      // Only a definitive refusal means the pair is dead. Anything else in the server's envelope (a 502/503/429 of its
      // own) is transient: keep the pair — clearing it here would persist tokens:null, fail the next WS ticket mint with
      // 401, and cascade a FALSE "session ended" sign-out across every tab.
      if (serverEnded(answer.refusal, resp.status)) {
        this.setTokens(null);
        this.onRefreshRefused?.("refused"); // design §4.4: the server ended the session
        return "refused";
      }
      // The server's answer to a first try clears the mark (it took nothing). To a second try, the first is still
      // unanswered: the mark stays, and no third try goes.
      const cur = this.tokens;
      if (!spending.refreshTriedAgain && cur && cur.refreshToken === spending.refreshToken) {
        this.tokens = bare(cur);
        this.onTokens(this.tokens);
      }
      return "unavailable";
    }
    this.ownRotations.set(spending.refreshToken, answer.pair.refreshToken);
    this.setTokens(answer.pair);
    return "renewed";
  }

  /**
   * What an answer nobody adopted comes to: a rotated pair is ended by its own refresh token; only the
   * server's own refusal of the token confirms that nothing it made is live. Anything else (a gateway's page of any
   * status, a body that does not read, the server's answer for the moment) is not a confirmation. Where the answer is
   * not the server's own at all (a page), the server may have taken the token and rotated the chain: the spent token is
   * kept for the next sign-in's name, as for a refresh that got no answer, as the account's the refresh began under.
   */
  private endOrphaned(answer: { pair: Tokens } | { refusal: string } | null, status: number, ticket: RefreshTicket): Promise<boolean> {
    if (answer === null) {
      this.keepForNextSignIn(ticket.spent, ticket.owner);
      return Promise.resolve(false);
    }
    if ("pair" in answer) return this.postEndSession(answer.pair.refreshToken);
    return Promise.resolve(serverEnded(answer.refusal, status));
  }

  /**
   * The refresh tokens this client's OWN refreshes replaced, each with the one the server answered in its place. A pair
   * adopted from another tab (the persisted pair, the `storage` listener) is never in it: it is not this client's line.
   */
  private readonly ownRotations = new Map<string, string>();

  /**
   * Whether the pair held now is the session whose refresh token was [refreshToken], as this client itself has kept it:
   * that token, or what this client's own refreshes turned it into. A sign-in's way out (ui/tabsession.ts) ends only
   * such a pair.
   */
  holdsSessionOf(refreshToken: string): boolean {
    const held = this.tokens?.refreshToken;
    if (held === undefined) return false;
    let t: string | undefined = refreshToken;
    for (let step = 0; t !== undefined && step <= 64; step++) {
      if (t === held) return true;
      t = this.ownRotations.get(t);
    }
    return false;
  }

  /**
   * The refresh POST last sent, for a lock that overtook it ([endSession]): [orphan] is set when its answer landed after
   * the pair was dropped or replaced, to whether the session that answer made is ended (true also when the refresh was
   * refused: nothing it made is live).
   */
  private refreshTicket: RefreshTicket | null = null;

  /** An answer to a refresh whose pair was dropped meanwhile, read as [endOrphaned] reads it. */
  private async endOrphanedAnswer(resp: Response, ticket: RefreshTicket): Promise<boolean> {
    return this.endOrphaned(await refreshAnswer(resp), resp.status, ticket);
  }

  /** `POST /auth/end-session` (spec 03 §2, index row 93), bounded and best effort: true only on the server's `200 ok`. */
  private async postEndSession(refreshToken: string, attempt = 0): Promise<boolean> {
    try {
      const resp = await this.send(this.baseUrl + "/api/v1/auth/end-session", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Andvari-Client": CLIENT_HEADER },
        body: JSON.stringify({ refreshToken }),
        signal: timeoutSignal(LOGOUT_TIMEOUT_MS),
      });
      // A refusal for the moment (429, the server naming its wait) is tried once more after that
      // wait, with the same token, which this call alone still holds (the tab dropped its pair at once). A wait the
      // server does not name, or one longer than END_SESSION_RETRY_MAX_S, is not waited for: the answer is "not
      // confirmed", which the unlock card says (LOCK_REVOKE_UNCONFIRMED).
      if (resp.status === 429 && attempt === 0) {
        const raw = resp.headers.get("Retry-After");
        const wait = raw !== null && /^\d{1,4}$/.test(raw.trim()) ? Number(raw.trim()) : null;
        if (wait === null || wait > END_SESSION_RETRY_MAX_S) return false;
        await new Promise((r) => setTimeout(r, Math.max(wait, 1) * 1000));
        return this.postEndSession(refreshToken, 1);
      }
      return resp.ok;
    } catch {
      return false;
    }
  }

  /**
   * Spec 03 §2 (index row 93): the lock of a tab that keeps no token (a browser without the offline copy)
   * ends exactly this tab's session at the server, by its own refresh token. The logout would end every session of the
   * browser's device row, so every other tab of this account in this browser; this call leaves them alone.
   *
   * Call it while the pair is still held and drop the pair right after, synchronously (as the logout's callers do): it
   * reads the pair and the refresh in flight now, closes this client's events sockets, and resolves later to whether the
   * server confirmed the end. Best effort: it never rejects, and the pair goes at once whatever it resolves to.
   *  - No refresh on its way: `end-session` with the pair's refresh token, the newest this tab holds.
   *  - A refresh on its way is spending that token, and sending a spent token reads as reuse at the server, which ends
   *    every tab of this browser for the account. So nothing is sent now: the drop makes that refresh adopt nothing (W2),
   *    and its answer, whenever it lands, is ended by its own new refresh token (refreshNow). This resolves to that.
   *    A refresh still waiting for another tab's refresh lock never sends (it finds no pair once it is let in), and one
   *    that has already adopted its answer left the pair read here as the newest: either way that token is unspent.
   */
  endSession(): Promise<boolean> {
    const held = this.tokens;
    const owner = this.boundUserId; // a token kept below is this account's, also after the caller rebinds the client
    const t = this.refreshTicket;
    const inflight = this.refreshInFlight;
    this.cutLiveTraffic();
    if (!held) return Promise.resolve(true);
    // The pair as this browser keeps it: a mark another tab wrote on it, or a token kept from a session that ended here.
    const pair = this.asKept(held);
    if (!inflight || !t || t.settled || t.spent !== pair.refreshToken) {
      // Where every tab shares the pair and the record no longer holds it, nothing is sent and nothing is kept.
      if (!this.mayLeave(pair.refreshToken)) return Promise.resolve(false);
      // A refresh of this token got no answer: the server may hold it as replaced, and `end-session` reads a replaced
      // token as a stolen one's reuse (every session of the row ends). Nothing is sent; the end is not confirmed, and the
      // token is kept for the next sign-in's name, so that the server ends that chain as replaced.
      if (!this.spendable(pair)) {
        this.keepForNextSignIn(pair.refreshToken, owner);
        return Promise.resolve(false);
      }
      return this.postEndSession(pair.refreshToken);
    }
    // It spent the pair's token: its answer is ended when it lands. A refresh that got no answer is unknown: its token is
    // kept for the next sign-in's name, as above.
    const outcome = () => {
      if (t.orphan) return t.orphan;
      this.keepForNextSignIn(t.spent, owner);
      return Promise.resolve(false);
    };
    return inflight.then(outcome, outcome);
  }

  /** Like raw() but with a binary request body (attachments): an answer that grows with a file. */
  private rawBytes(method: string, path: string, body: Uint8Array | undefined): Promise<Response> {
    return this.limited(undefined, "grows", (s) => this.rawBytesSend(method, path, body, 0, s));
  }

  private async rawBytesSend(method: string, path: string, body: Uint8Array | undefined, attempt: number, signal: AbortSignal | undefined): Promise<Response> {
    const headers: Record<string, string> = { "X-Andvari-Client": CLIENT_HEADER };
    if (body !== undefined) headers["Content-Type"] = "application/octet-stream";
    const used = this.tokens ? this.tokens.accessToken : null;
    if (used) headers["Authorization"] = `Bearer ${used}`;
    const bound = this.boundUserId; // as in rawSend: a re-send goes out only for the account the request was made for
    const resp = await this.send(this.baseUrl + path, { method, headers, body: body as BodyInit | undefined, ...(signal ? { signal } : {}) });
    if (resp.status === 401 && attempt < MAX_AUTH_ATTEMPTS && this.tokens && this.boundUserId === bound) {
      if (this.tokens.accessToken !== used) return this.rawBytesSend(method, path, body, attempt + 1, signal);
      if (signal) this.watches.get(signal)?.waiting();
      if ((await this.afterRefresh(resp)) === "resend" && this.boundUserId === bound) return this.rawBytesSend(method, path, body, attempt + 1, signal);
    }
    return resp;
  }

  private async throwApiError(resp: Response): Promise<never> {
    let code = `http_${resp.status}`;
    let message = resp.statusText;
    let body: unknown = null;
    try {
      body = await resp.json();
      const err = body as { error?: unknown; message?: unknown };
      if (typeof err.error === "string") code = err.error;
      if (typeof err.message === "string") message = err.message;
    } catch {
      /* non-JSON error body */
    }
    if (code === "upgrade_required") this.onUpgradeRequired?.();
    const e = new ApiError(resp.status, code, message);
    if (body !== null) e.extras = decodeErrorExtras(code, body as never);
    if (resp.status === 429) e.retryAfterS = retryAfterSeconds(resp.headers?.get("Retry-After") ?? null);
    throw e;
  }

  /**
   * The transport of the v2 routes (api/wireclient.ts): the same token, refresh and 401-retry handling as every
   * other call, a refusal thrown as an [ApiError] with its extras, and a success handed back as text for the
   * caller's own strict decoder. `auth = false` for the routes that run without a session.
   */
  async sendRequest(method: string, path: string, body?: unknown, opts: { auth?: boolean; signal?: AbortSignal; size?: AnswerSize } = {}): Promise<RawAnswer> {
    const resp = await this.raw(method, path, body, opts.auth ?? true, 0, opts.signal, opts.size ?? "small");
    if (!resp.ok) await this.throwApiError(resp);
    return { status: resp.status, text: await readAnswerText(resp), contentType: resp.headers?.get("Content-Type") ?? null };
  }

  /**
   * [sendRequest] for the two attachment routes (spec 03 §9): a raw byte body out (an upload) or raw bytes back (a
   * download), with the same token, refresh and 401-retry handling. A refusal is the same [ApiError].
   */
  async requestBytes(method: string, path: string, body?: Uint8Array): Promise<Response> {
    const resp = await this.rawBytes(method, path, body);
    if (!resp.ok) await this.throwApiError(resp);
    return resp;
  }

  private async json<T>(method: string, path: string, body?: unknown, auth = true): Promise<T> {
    const resp = await this.raw(method, path, body, auth);
    if (!resp.ok) await this.throwApiError(resp);
    const text = await readAnswerText(resp);
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /** For endpoints that answer plain text ("ok") — errors still surface as ApiError. `auth=false`
   *  for the pre-auth recovery endpoints (no session in hand; the recovery ticket is the credential). */
  private async text(method: string, path: string, body?: unknown, auth = true): Promise<string> {
    const resp = await this.raw(method, path, body, auth);
    if (!resp.ok) await this.throwApiError(resp);
    return readAnswerText(resp);
  }

  async prelogin(email: string) {
    // H1 fence (spec 05 T1): reject a weakened login KDF before any argon2id runs under it.
    const p = await this.json<PreloginResponse>("POST", "/api/v1/auth/prelogin", { email }, false);
    assertServerKdfParams(p.kdfParams);
    return p;
  }

  async register(req: RegisterRequest) {
    return this.session("register", await this.json<SessionResponse>("POST", "/api/v1/auth/register", req, false));
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
    const session = this.session("login", s);
    // A14 review W3: held in memory only; the caller's saveSession writes it, with this account's metadata.
    this.useSessionTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
    return session;
  }

  /**
   * bug-web--0: best-effort sign-out revocation. Deliberately NOT routed through raw(), and
   * deliberately NOT clearing or replacing the token pair:
   *  - ONE AbortSignal bounds every request it makes, so the caller's bound
   *    (revokeSessionBestEffort's race) actually CANCELS them. Abandoning a race leaves requests
   *    running, and a slow revocation that lands after the user signed back in on this same
   *    client would have nulled the NEW session's tokens from a `.finally` — a sign-out with a
   *    one-request lag;
   *  - a 401 does NOT mean the session is dead (security review 2026-10): the access token
   *    expires after 1 h, the refresh token lives 30 days, so a tab that sat locked past the hour
   *    got a 401 here while a copied refresh token stayed valid for a month. On a 401 this spends
   *    the CAPTURED refresh token once and revokes with the fresh access token. It never goes
   *    through tryRefresh: that adopts and persists the new pair (setTokens), which would
   *    resurrect the session the caller is tearing down. A refused refresh (a dead pair, or the
   *    break-glass origin, which refuses refresh) ends it there — the 401 is returned;
   * Dropping the pair is each call site's own job, done synchronously right after (App's
   * signOut, Welcome's two capture teardowns). The pair is read HERE, synchronously at call
   * time (before the first await), so a fire-and-forget `void` call from a sync path still
   * revokes the right session. Resolves with the final logout response: `ok` = revoked.
   */
  async logout(): Promise<Response> {
    const held = this.tokens;
    // Read at call time (the caller drops the pair right after), with what this browser keeps of it: the mark another
    // tab wrote on the same pair (the session every tab shares with the offline copy on), or a token kept as unconfirmed.
    const atCall = held ? this.asKept(held) : null;
    const signal = timeoutSignal(LOGOUT_TIMEOUT_MS);
    const post = (accessToken: string | null) => {
      const headers: Record<string, string> = { "X-Andvari-Client": CLIENT_HEADER };
      if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;
      return this.send(this.baseUrl + "/api/v1/auth/logout", { method: "POST", headers, signal });
    };
    const first = await post(atCall?.accessToken ?? null);
    if (first.status !== 401 || !atCall) return first;
    // Where every tab shares the pair and the record no longer holds it (another tab signed out, ended it, or renewed it),
    // this tab's token never goes, and nothing is kept: the sign-out is not confirmed.
    if (!this.mayLeave(atCall.refreshToken)) return first;
    // A refresh of the pair's token got no answer, in this tab or another, or its session ended here unconfirmed: it is
    // never sent as a refresh from here (the refresh's own rule), read again now, since another tab may have marked it
    // while the logout was on its way. It is kept for the next sign-in's name; the sign-out is not confirmed.
    const pair = this.asKept(atCall);
    if (!this.spendable(atCall) || !this.spendable(pair)) {
      this.keepForNextSignIn(pair.refreshToken);
      return first;
    }
    const refreshed = await this.send(this.baseUrl + "/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Andvari-Client": CLIENT_HEADER },
      body: JSON.stringify({ refreshToken: pair.refreshToken }),
      signal,
    });
    // Both the access and the refresh token refused: the session is already ended at the server (another tab of this
    // browser logged the device row out first). That is the confirmation a revoke wants, not
    // a failure to report; any other answer (5xx, 429, unreachable) stays unconfirmed.
    if (refreshed.status === 401) return new Response(null, { status: 204 });
    if (!refreshed.ok) return first;
    const fresh = (await refreshed.json()) as Tokens;
    return post(fresh.accessToken);
  }

  async accountKeys() {
    // H1: validate-if-present (re-unlock/change derive under these). Absence already fails closed in
    // masterKey; a mocked {} body (client.refresh.test.ts) legitimately carries no kdfParams.
    const k = await this.json<AccountKeys>("GET", "/api/v1/account/keys");
    if (k?.kdfParams) assertServerKdfParams(k.kdfParams);
    return k ? this.reported("accountKeys", sanitizeAccountKeys(k)) : k;
  }

  async clientPolicy() {
    // H1: fencing the enrollment/upgrade policy at parse also closes the export/backup (R1) and
    // password-change (R2) KDF-reuse paths, whose only param source is this response.
    const p = await this.json<ClientPolicy>("GET", "/api/v1/client-policy", undefined, false);
    if (p?.kdfParams) assertServerKdfParams(p.kdfParams);
    return p;
  }

  // The item routes (sync, push, history, trash, attachments) are the item layer's, in api/wireclient.ts (ItemWire).

  // ---- shared vaults (spec 03 §10) — refused on the public break-glass origin ----

  createVault(req: CreateVaultRequest) {
    return this.json<CreateVaultResponse>("POST", "/api/v1/vaults", req);
  }

  // ---- account state + identity (security review 2026-10, root cause A §4, A5) ----

  /** The UVK-sealed account-state blob and the server's CAS counter. */
  accountState() {
    return this.json<AccountStateResponse>("GET", "/api/v1/account/state");
  }

  /** Replace the blob; ApiError 409 `stale_state` when `baseSeq` is not the current counter. */
  putAccountState(sealedState: string, baseSeq: number) {
    return this.json<AccountStateResponse>("PUT", "/api/v1/account/state", { sealedState, baseSeq });
  }


  async vaultMembers(vaultId: string) {
    return this.reported("members", sanitizeMembers(await this.json<VaultMemberSummary[]>("GET", `/api/v1/vaults/${pathSeg(vaultId)}/members`)));
  }

  // The member, lifecycle and transfer routes below have no caller in the web app (its shared vaults change through the
  // vault's log, vault/logstore.ts); each is named so that it can be searched for apart from the store's gestures (see
  // api/sends.ts).
  async postVaultMember(vaultId: string, body: VaultMemberAdd) {
    return this.json<CreateVaultResponse>("POST", `/api/v1/vaults/${pathSeg(vaultId)}/members`, body);
  }

  async setVaultMemberRole(vaultId: string, userId: string, role: string) {
    return this.json<CreateVaultResponse>("PUT", `/api/v1/vaults/${pathSeg(vaultId)}/members/${pathSeg(userId)}`, { role });
  }

  /** DELETE member. `proof`/`nonce` (spec 03 §11 removal proof) are optional and additive:
   *  when supplied they ride the body so a 0.5.0 victim can verify the removal was a real
   *  owner action; omitted → the proofless 0.4.0 shape (no body). */
  async deleteVaultMember(vaultId: string, userId: string, body?: VaultMemberRemoveRequest) {
    return this.json<CreateVaultResponse>(
      "DELETE",
      `/api/v1/vaults/${pathSeg(vaultId)}/members/${pathSeg(userId)}`,
      body && (body.proof || body.nonce) ? body : undefined,
    );
  }

  // ---- vault lifecycle (spec 03 §11) — refused on the public break-glass origin ----

  async deleteVault(vaultId: string, body: VaultDeleteRequest) {
    return this.json<VaultDeleteResponse>("POST", `/api/v1/vaults/${pathSeg(vaultId)}/delete`, body);
  }

  async restoreVault(vaultId: string, body: VaultRestoreRequest) {
    return this.json<CreateVaultResponse>("POST", `/api/v1/vaults/${pathSeg(vaultId)}/restore`, body);
  }

  async deletedVaults() {
    return this.reported("deletedVaults", sanitizeDeletedVaults(await this.json<DeletedVaultSummary[]>("GET", "/api/v1/vaults/deleted")));
  }

  /** `body` is the v2 leave proof (root cause A §6.2, branch A7) minted by store.leaveSharedVault; `{}` is the
   *  pre-A7 shape the server still accepts in the compatibility window. */
  async leaveVault(vaultId: string, body?: VaultLeaveRequest) {
    return this.json<CreateVaultResponse>("POST", `/api/v1/vaults/${pathSeg(vaultId)}/leave`, body ?? {});
  }

  async postTransferOffer(vaultId: string, body: TransferOfferRequest) {
    return this.json<TransferOfferResponse>("POST", `/api/v1/vaults/${pathSeg(vaultId)}/transfer`, body);
  }

  async deleteTransferOffer(vaultId: string) {
    return this.json<CreateVaultResponse>("DELETE", `/api/v1/vaults/${pathSeg(vaultId)}/transfer`);
  }

  async postTransferAccept(vaultId: string, body: TransferAcceptRequest) {
    return this.json<CreateVaultResponse>("POST", `/api/v1/vaults/${pathSeg(vaultId)}/transfer/accept`, body);
  }

  async updateVaultMeta(vaultId: string, body: VaultMetaUpdateRequest) {
    return this.json<CreateVaultResponse>("PUT", `/api/v1/vaults/${pathSeg(vaultId)}/meta`, body);
  }




  // F57: current org recovery PUBLIC key (base64url); the client verifies its fingerprint
  // against the user-confirmed sheet value before re-sealing escrow to it.
  recoveryPubkey() {
    return this.text("GET", "/api/v1/recovery-pubkey");
  }

  // ---- per-member self-service recovery (design §F.3) — refused on the public break-glass origin ----

  /** Phase 1 (§F.3): prove possession of the recovery phrase. Unauthenticated (the user forgot their
   *  password). On success the server mints a single-use, short-TTL, userId-bound recoveryTicket and
   *  returns the material the client needs to open the UVK + run the identity-pubkey hard-fail. A bad
   *  phrase / unknown email / no-recovery-row all return a uniform 401 (`ApiError`, anti-enumeration). */
  recoverySelfVerify(email: string, recoveryAuthKey: string) {
    // quality-deadcode--3: the body literal carries its wire type instead of being an untyped
    // object beside an exported-but-uncalled RecoveryVerifyRequest (the "half-alive" state).
    const body: RecoveryVerifyRequest = { email, recoveryAuthKey };
    return this.json<RecoveryVerifyResponse>("POST", "/api/v1/recovery/self/verify", body, false);
  }

  /** Phase 2 (§F.3): commit the reset. Unauthenticated — the `recoveryTicket` from phase 1 is the
   *  credential. Overwrites verifier/wrappedUvk/kdf and revokes all sessions, so the user signs in
   *  fresh with the new password afterward. Answers plain text. */
  recoverySelfCommit(req: RecoveryCommitRequest) {
    return this.text("POST", "/api/v1/recovery/self/commit", req, false);
  }

  /** Migration/rotation (§F.3): add or rotate THIS account's recovery piece over the in-memory UVK.
   *  Authenticated; the server re-verifies `currentAuthKey` (fresh master-password reauth) before
   *  storing the block. Answers `{ pieceId }` (design 2026-07-13 piece-binding) — the opaque id the
   *  capture gate presents at confirm. A pre-binding server answered plain "ok": a non-JSON 2xx body
   *  yields `{ pieceId: null }` (legacy, unbound confirm) — never a throw on body shape alone. */
  async recoverySelfSetup(req: RecoverySelfSetupRequest): Promise<RecoverySelfSetupResponse> {
    const body = await this.text("PUT", "/api/v1/recovery/self-setup", req);
    try {
      return { pieceId: (JSON.parse(body) as RecoverySelfSetupResponse)?.pieceId ?? null };
    } catch {
      return { pieceId: null }; // pre-binding server rollback: plain "ok"
    }
  }

  /** design §F.9: flip this account's durable `recoveryConfirmed` flag after the revealed phrase was
   *  saved + confirmed in-flow — NO regenerate; the committed piece IS what the user saved. `pieceId`
   *  (design 2026-07-13 piece-binding: the register/self-setup-minted id of the piece the caller
   *  revealed) rides the body so the confirm can never attest a piece a concurrent setup rotated away
   *  — a mismatch is refused `409 recovery_piece_stale`; null/absent sends the legacy EMPTY body (the
   *  server's device-scoped rule applies). No key material rides this (unlike self-setup).
   *  Authenticated; server-refused on the public break-glass origin; rate-limited. Answers "ok". */
  recoverySelfConfirm(pieceId?: string | null) {
    // quality-deadcode--3: ditto — typed here, so the legacy empty-body branch stays visibly
    // deliberate rather than reading as a body the type just forgot to describe.
    const body: RecoverySelfConfirmRequest | undefined = pieceId != null ? { pieceId } : undefined;
    return this.text("POST", "/api/v1/recovery/self/confirm", body);
  }

  // ---- server TOTP + password change ----

  totpStatus() {
    return this.json<TotpStatus>("GET", "/api/v1/account/totp");
  }

  // Setting two-step sign-in up is WireApi.totpSetup, always with the password proof (vault/settingsflow.ts setUpTwoStep).

  /** Answers the plain-text `ok` (spec 03 §0.1 row 15), never a status: two-step sign-in is on once it resolves. */
  async totpConfirm(code: string): Promise<void> {
    await this.text("POST", "/api/v1/account/totp/confirm", { code });
  }

  // Turning two-step sign-in off carries the password proof beside the code (spec 03 §0.1 row 16): it goes through the
  // Settings flows (vault/settingsflow.ts turnOffTwoStep), which prove the password on this device first.

  changePassword(req: PasswordChangeRequest) {
    return this.text("PUT", "/api/v1/account/password", req);
  }

  // ---- account deletion (spec 03 §13) — refused on the public break-glass origin ----

  /** What a deletion would do now: its blockers, the vaults deleted with the account and those it leaves, and whether
   *  the request needs the TOTP code. Served vault ids pass the id grammar (A10) like every other. */
  async accountDeletePreview(): Promise<AccountDeletePreview> {
    return this.reported("accountDeletePreview", sanitizeDeletePreview(await this.json<AccountDeletePreview>("GET", "/api/v1/account/delete/preview")));
  }

  /** {@link ACCOUNT_DELETE_TIMEOUT_MS}; a field so a test can shorten it. */
  deleteTimeoutMs = ACCOUNT_DELETE_TIMEOUT_MS;

  /**
   * Delete this account. NOT idempotent and never retried here. What the reply proves decides how it surfaces:
   *  - the server's JSON `200 {deletedAt}` — deleted;
   *  - its JSON `409 account_delete_blocked` — {@link AccountDeleteBlockedError} with the blockers;
   *  - its JSON 4xx refusal — the usual ApiError (`reauth_failed`, `totp_code_required`, `bad_totp_code`,
   *    `confirm_email_mismatch`, `credential_changed`, `invalid_credentials`, …): refused before its transaction wrote
   *    anything;
   *  - any 5xx, and any reply that is not the server's JSON (a proxy's error page, a truncated body, a refusal without
   *    the server's `error` code) —
   *    {@link AccountDeleteUnknownError}: the server may have committed (spec 03 §13: unknown, never "not deleted").
   * A transport failure rejects with the fetch's TypeError, which the caller also treats as unknown. No answer within
   * {@link deleteTimeoutMs} aborts the request — {@link AccountDeleteUnknownError} with status 0: it may have reached the
   * server and committed. A 401 rides raw()'s one refresh-and-resend: a 401 means the request was not processed, so the
   * resend is a fresh attempt (under the same deadline).
   */
  async deleteAccount(req: AccountDeleteRequest): Promise<AccountDeleteResponse> {
    let resp: Response;
    try {
      resp = await this.raw("POST", "/api/v1/account/delete", req, true, 0, deadlineSignal(this.deleteTimeoutMs));
    } catch (e) {
      if (isAbort(e)) throw new AccountDeleteUnknownError(0);
      throw e;
    }
    if (resp.status >= 500) throw new AccountDeleteUnknownError(resp.status);
    type Reply = { error?: unknown; message?: unknown; blockers?: unknown; deletedAt?: unknown };
    let body: Reply | null = null;
    try {
      const parsed: unknown = JSON.parse(await resp.text());
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) body = parsed as Reply;
    } catch {
      /* not JSON — handled below */
    }
    if (body === null) throw new AccountDeleteUnknownError(resp.status);
    if (resp.ok) {
      if (typeof body.deletedAt === "number") return { deletedAt: body.deletedAt };
      throw new AccountDeleteUnknownError(resp.status); // a 2xx that is not the server's answer proves nothing
    }
    // The server's refusals always carry their code (§8); a JSON reply without one is some other hop's.
    if (typeof body.error !== "string") throw new AccountDeleteUnknownError(resp.status);
    if (resp.status === 409 && body.error === "account_delete_blocked") {
      const rows = Array.isArray(body.blockers) ? body.blockers.map(blockerOf) : [];
      throw new AccountDeleteBlockedError(this.reported("deleteAccount", sanitizeDeleteBlockers(rows)));
    }
    if (body.error === "upgrade_required") this.onUpgradeRequired?.();
    throw new ApiError(resp.status, body.error, typeof body.message === "string" ? body.message : resp.statusText);
  }

  // ---- admin ----

  adminUsers() {
    return this.json<AdminUserSummary[]>("GET", "/api/v1/admin/users");
  }

  adminInvite(email: string, isAdmin: boolean, ttlMinutes?: number, sendEmail?: boolean, escrowPolicy?: string) {
    // ttlMinutes absent → the server keeps its 72h default; the QR flow passes ~60 min
    // (the server clamps to [5, 4320]). It is the only containment for a photographed QR.
    // sendEmail (cut 4) → the server ALSO emails the enroll link and forces the ttl to ≤60 min;
    // it's a no-op unless the server is email-configured (AdminStatus.emailConfigured).
    // escrowPolicy (design §F.2) → the invite's recovery posture, "required" (default, admin backstop)
    // or "waived". Read SERVER-SIDE from the invite row at register; additive/defaulted so omitting it
    // keeps the safe "required" posture on rollback servers.
    return this.json<InviteResponse>("POST", "/api/v1/admin/users", { email, isAdmin, ttlMinutes, sendEmail, escrowPolicy });
  }

  async adminDisableUser(userId: string) {
    return this.text("POST", `/api/v1/admin/users/${pathSeg(userId)}/disable`);
  }

  async adminDevices(userId: string) {
    return this.json<AdminDeviceSummary[]>("GET", `/api/v1/admin/users/${pathSeg(userId)}/devices`);
  }

  /** F59 recovery step 1 — the member's escrow download (design §2.5, security review 2026-10):
   *  JSON `{userId, sealed, encryptedIdentitySeed, identityPub, legacySealed?}`, returned VERBATIM as
   *  text because it is written to disk as `recovery-cli recover --identity-file`. Everything in it is
   *  sealed or public, so safe to hand out. Throws ApiError `no_escrow` (404) if there is none. */
  async adminUserEscrow(userId: string) {
    return this.text("GET", `/api/v1/admin/users/${pathSeg(userId)}/escrow`);
  }

  /** §8.4 drill hook — POST the receipt `recovery-cli verify` printed (verbatim JSON text). */
  async adminEscrowDrill(receiptJson: string) {
    return this.json<{ dropped: string[]; kept: string[] }>("POST", "/api/v1/admin/escrow/drill", JSON.parse(receiptJson));
  }

  async adminRevokeDevice(deviceId: string) {
    return this.text("POST", `/api/v1/admin/devices/${pathSeg(deviceId)}/revoke`);
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
    const resp = await this.raw("GET", `/api/v1/hibp/range/${pathSeg(prefix)}`);
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
   * notifier has no replay).
   *
   * "Open" means REGISTERED, not merely upgraded (gate fix, audit 2026-09-13 wave 3): the
   * browser's `onopen` fires on the 101, but the server registers the socket with its
   * notifier only when the route handler body runs — a window of a few ms in which a bell
   * for a change that has just committed goes to nobody, and the notifier has no replay.
   * A consumer that pulled on the 101 and then relied on the bell (Vault.tsx) missed that
   * change until the next unrelated bell; the E2E gate reproduced it under load (push
   * 3 ms after the 101, no bell in 10 s). So the client sends the app-level "ping" the
   * server has always echoed as "pong" (spec 03 §6 — the extension's keepalive rides the
   * same echo), and reports `onOpen` on the FIRST pong: the echo loop starts after
   * register(), so a pong proves the registration. The catch-up pull therefore runs after
   * the socket can ring, which closes the window instead of narrowing it. The backoff reset
   * ALSO waits for the first pong (security review 2026-10, A17 item 3): a socket that
   * upgrades and dies before the server ever answered is a failed cycle, not a healthy one.
   * Resetting on the 101 let a tab whose sockets die within a second (a proxy with a short
   * idle timeout, a half-broken network) re-mint tickets at 1–2 per second — enough to hit
   * the server's per-account ticket bucket (60/min) and then be throttled for the whole tab,
   * a self-inflicted outage. Only the "back up" signal keys off the raw 101.
   * A 401/403 at ticket mint means the session itself is dead
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
        this.assertTrafficAllowed(true, true); // §4.4: the socket is traffic too (its ticket was minted with the bearer token, and that request went out)
        const sock = new WebSocket(this.baseUrl.replace(/^http/, "ws") + `/api/v1/events?ticket=${encodeURIComponent(t.ticket)}`);
        ws = sock;
        let registered = false; // per socket: a reconnect proves itself again
        sock.onopen = () => {
          clearDown();
          // Registration probe (see the doc comment): onOpen AND the backoff reset wait for the echo.
          try {
            sock.send("ping");
          } catch {
            /* a socket that cannot send is about to close; onclose reconnects */
          }
        };
        sock.onmessage = (ev) => {
          if (closed) return; // a frame after close()/revoked must not reset the ladder or fire onOpen (extension parity)
          if (this.trafficGate?.(true) != null) {
            close(); // §4.4: a frame from a forked origin is not accepted; the socket goes with it
            return;
          }
          if (ev.data === "pong") {
            // The echo loop runs after the server's notifier.register(): the first pong is
            // the proof the bell can reach this socket. Exactly once per socket.
            if (!registered) {
              registered = true;
              attempts = 0; // healthy again — a REGISTERED socket restarts the backoff from 1 s
              onOpen?.();
            }
            return;
          }
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
        if (e instanceof TrafficStoppedError) {
          close(); // §4.4: no reconnect to a forked origin
          return;
        }
        if (e instanceof SessionNotConfirmedError || e instanceof SessionEndedElsewhereError) {
          // The session ended here, not confirmed: its one end was raised already (onRefreshRefused). None of the socket's.
          close();
          return;
        }
        // A renewal that got no answer of the server's (RefreshUnansweredError, a TypeError) is not the session's end:
        // the socket tries again later, as for any request without an answer (below).
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

    const close = () => {
      closed = true;
      this.liveSockets.delete(close);
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
      }
      clearDown();
      if (typeof document !== "undefined") document.removeEventListener("visibilitychange", onVisible);
      ws?.close();
      ws = null;
    };
    this.liveSockets.add(close);

    void connect();

    return close;
  }
}
