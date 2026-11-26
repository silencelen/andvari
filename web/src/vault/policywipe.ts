import { ApiError, TrafficStoppedError } from "../api/client";
import type { Mutation, PushResponse } from "../api/types";
import { decodeName } from "../crypto/trust/grammar";
import { deleteCopy, readWaiting, type WaitingRead } from "./idbcache";

/**
 * A server's policy that forbids the offline copy (decided on 2026-11-17): before this browser wipes the copy it keeps of
 * an account, it tries ONCE to send the changes that wait in it, then wipes as specified, whatever the attempt brought,
 * and says afterwards how many changes could not be sent. A change is sent only where this browser may write to its
 * vault at that moment ({@link MayWrite}); where no account is open in this tab, that is the personal vault alone
 * (narrowed on 22 November 2026), and every other change counts as one that could not be sent.
 *
 * Once means one run through what waits, in the server's batches, no second try, no waiting for a connection, no
 * question to the person. Every request is sent only while this tab still holds the copy's own account's session,
 * checked at that request; each request has its own limit, and the whole attempt has one limit from its start, a refresh
 * of the session included: past it the wipe follows, whatever is in flight. One run per copy at a time across the
 * browser's tabs; from the moment the policy is read nothing new is queued into the copy (the store refuses the change,
 * {@link policyForbidsCopy}). The number is read from the copy at the moment it is wiped, by the run that wipes it, and
 * a change counts as sent only when the server's own answer says it took it; one whose request went out without an
 * answer in time may or may not have arrived, and is said as that. The notice is kept apart from the copy (the server's
 * name and the numbers, nothing of the content) and said once, and only when the copy is really gone.
 */

/** The server's batch limit for `POST /sync/push` (spec 03 §5), as the store's own drain sends. */
export const POLICY_WIPE_BATCH = 200;
/** Each request's own limit in the one attempt: past it the request is one whose answer did not come in time. */
export const POLICY_WIPE_REQUEST_LIMIT_MS = 30_000;
/** The whole attempt's one limit, from its start, whatever is in flight then: the wipe follows by this time. */
export const POLICY_WIPE_ATTEMPT_LIMIT_MS = 60_000;
/** How long the wipe itself is waited for before it is said as not made yet (a connection that does not close). */
export const POLICY_WIPE_DELETE_WAIT_MS = 10_000;

/** One push of the attempt, with the limit's signal. */
export type SendOnce = (mutations: Mutation[], signal: AbortSignal) => Promise<PushResponse>;

/** A sender's refusal: this tab no longer holds the copy's account's session, so nothing more is sent. */
export class NotThisAccountError extends Error {
  constructor() {
    super("this tab no longer holds the session of the copy's account");
    this.name = "NotThisAccountError";
  }
}

/** The clock the attempt's limits run on (a test drives its own). */
export interface PolicyWipeClock {
  now(): number;
  /** Calls [fn] after [ms]; the result cancels it. */
  after(ms: number, fn: () => void): () => void;
}

const realClock: PolicyWipeClock = {
  now: () => Date.now(),
  after: (ms, fn) => {
    const t = setTimeout(fn, ms);
    return () => clearTimeout(t);
  },
};

export interface PolicyWipeLimits {
  readonly requestMs?: number;
  readonly attemptMs?: number;
  readonly deleteWaitMs?: number;
  readonly clock?: PolicyWipeClock;
}

/** How the run of sends ended. */
export type AttemptEnd = "done" | "no_session" | "not_this_account" | "failed" | "limit";

export interface SentOnce {
  /** The changes the server's own answer says it took (applied, or a duplicate of one it had). */
  readonly taken: ReadonlySet<string>;
  /** The changes whose request went out and whose answer did not come in time, or could not be read: they may or may
   *  not have arrived. */
  readonly unsure: ReadonlySet<string>;
  /** Push requests made. */
  readonly requests: number;
  readonly end: AttemptEnd;
}

/** The statuses that mean the server took the change. */
const TAKEN = new Set(["applied", "duplicate"]);

/**
 * Whether the server's answer [status] to [m] means it took the change. A change answered with a conflict is judged by
 * what the server did with it: a put over a newer version IS stored (the server keeps the version it displaced in the
 * item's history), so it counts as sent; only a deletion over a newer edit is not made (the item stays as that edit
 * left it). No copy of a displaced version is made during the attempt: it would be a new change into a copy that is
 * being removed, and the displaced version is in the item's history at the server.
 */
function tookChange(m: Mutation, status: string): boolean {
  return TAKEN.has(status) || (status === "conflict" && m.op === "put");
}

/**
 * Whether a request that failed with [e] may have reached the server and been taken. Nothing went out for a sender's
 * own refusal or the gate's refusal before sending; the server answered and took nothing for its own refusal (a 4xx,
 * or a 500 of the one transaction). Anything else (no answer, an answer past the limit, cut off, unreadable, not the
 * server's own, a front's 502 or 504) leaves it unknown.
 */
function mayHaveArrived(e: unknown): boolean {
  if (e instanceof NotThisAccountError) return false;
  if (e instanceof TrafficStoppedError) return e.sent;
  if (e instanceof ApiError && e.status >= 400) return e.status === 502 || e.status === 504;
  return true;
}

/**
 * The question the one attempt asks of every change, at the moment its request is handed to the transport: may this
 * browser write to [vaultId] now. The open store's `mayWrite` where this tab has the account open; otherwise only the
 * personal vault this browser's own session record names (ui/session.ts policyWipeQuestion). A change it holds back is
 * not sent and counts as one that could not be sent.
 */
export type MayWrite = (vaultId: string) => boolean;

/** The question when nothing may be sent (a wipe tried again, which sends nothing). */
export const NOTHING_MAY_BE_WRITTEN: MayWrite = () => false;

/** Whether [mayWrite] lets a change through: it names a vault and the question says yes for it; a question that throws says no. */
function allowedBy(mayWrite: MayWrite): (m: Mutation) => boolean {
  return (m) => {
    try {
      return typeof m.vaultId === "string" && mayWrite(m.vaultId) === true;
    } catch {
      return false;
    }
  };
}

/**
 * Sends [pending] once through [send] (null: nothing is sent), in the server's batches, until the first request that
 * fails, or the attempt's limit at [deadline] on [clock]: then whatever is in flight is cut off and the run ends. Each
 * request also has its own limit ([requestMs]). A change is handed to [send] only where [mayWrite] says yes for its vault
 * in the same step (a question that throws says no); one it holds back is neither taken nor unsure, so it is counted as
 * not sent, and a batch it holds back whole makes no request. Never throws.
 */
export async function sendWaitingOnce(
  pending: readonly Mutation[],
  send: SendOnce | null,
  mayWrite: MayWrite,
  opts: { requestMs?: number; deadline?: number; clock?: PolicyWipeClock } = {},
): Promise<SentOnce> {
  const clock = opts.clock ?? realClock;
  const requestMs = opts.requestMs ?? POLICY_WIPE_REQUEST_LIMIT_MS;
  const deadline = opts.deadline ?? clock.now() + POLICY_WIPE_ATTEMPT_LIMIT_MS;
  const taken = new Set<string>();
  const unsure = new Set<string>();
  let requests = 0;
  if (send === null) return { taken, unsure, requests, end: "no_session" };
  const may = allowedBy(mayWrite);
  for (let at = 0; at < pending.length; at += POLICY_WIPE_BATCH) {
    const left = deadline - clock.now();
    if (left <= 0) return { taken, unsure, requests, end: "limit" };
    // Asked here, in the same step as the hand-over below (nothing is awaited between them).
    const batch = pending.slice(at, at + POLICY_WIPE_BATCH).filter(may);
    if (batch.length === 0) continue;
    const limit = new AbortController();
    type Outcome = { kind: "answer"; resp: PushResponse } | { kind: "error"; e: unknown } | { kind: "limit" };
    const outcome = await new Promise<Outcome>((resolve) => {
      const stopRequest = clock.after(requestMs, () => limit.abort());
      const stopAttempt = clock.after(left, () => {
        stopRequest();
        limit.abort(); // whatever is in flight is cut off: a re-send after a refresh then never leaves
        resolve({ kind: "limit" });
      });
      let p: Promise<PushResponse>;
      try {
        p = send(batch, limit.signal);
      } catch (e) {
        p = Promise.reject(e);
      }
      requests++;
      p.then(
        (resp) => resolve({ kind: "answer", resp }),
        (e: unknown) => resolve({ kind: "error", e }),
      ).finally(() => {
        stopRequest();
        stopAttempt();
      });
    });
    if (outcome.kind === "limit") {
      for (const m of batch) unsure.add(m.mutationId);
      return { taken, unsure, requests, end: "limit" };
    }
    if (outcome.kind === "error") {
      if (outcome.e instanceof NotThisAccountError) return { taken, unsure, requests: requests - 1, end: "not_this_account" };
      if (mayHaveArrived(outcome.e)) for (const m of batch) unsure.add(m.mutationId);
      return { taken, unsure, requests, end: "failed" }; // the first request that fails ends the run: no second try
    }
    const byId = new Map(outcome.resp.results.map((r) => [r.mutationId, r.status]));
    for (const m of batch) {
      const status = byId.get(m.mutationId);
      if (status === undefined) unsure.add(m.mutationId); // the answer does not say: it cannot be told
      else if (tookChange(m, status)) taken.add(m.mutationId);
    }
  }
  return { taken, unsure, requests, end: "done" };
}

/**
 * The one attempt's sender for [userId]'s copy, or null when this tab holds no live session of that account (none at
 * all, a session the server ended, or a pair that belongs to a sign-in under way): then nothing is sent. The same is
 * checked again at every request, in the same step that hands it to the transport (which sets the request's token
 * before it yields): once the tab holds no session of that account (signed out, signed in to another account, ended by
 * the server), the request is refused with {@link NotThisAccountError} and nothing more is sent.
 *
 * The sender asks [mayWrite] itself (the question {@link sendWaitingOnce} asks, ui/session.ts policyWipeQuestion): of each
 * batch it is handed, whoever hands it, only the changes the question allows in that same step are sent, and a batch it
 * holds back whole makes no request (it answers with no result for any change).
 */
export function senderForCopy(
  client: { getTokens(): unknown; boundUserId: string | null },
  wire: { pushMutations(mutations: Mutation[], opts: { signal?: AbortSignal }): Promise<PushResponse> },
  userId: string,
  mayWrite: MayWrite,
): SendOnce | null {
  const holds = (): boolean => client.getTokens() !== null && client.boundUserId === userId;
  if (!holds()) return null;
  const may = allowedBy(mayWrite);
  return (mutations, signal) => {
    if (!holds()) return Promise.reject(new NotThisAccountError());
    const allowed = mutations.filter(may);
    return allowed.length === 0 ? Promise.resolve({ rev: 0, results: [] }) : wire.pushMutations(allowed, { signal });
  };
}

/** The server's name as the person knows it here: the pinned card's name, or its address when the card names none. */
export function serverNameOf(pins: { pinFor(origin: string): { name: string } | null }, origin: string): string {
  const pin = pins.pinFor(origin);
  const name = pin ? decodeName(pin.name) ?? "" : "";
  return name !== "" ? name : origin;
}

// ---- The freeze: nothing new is queued into a copy the policy forbids ----

/**
 * §E.4 policy row: the LAST-KNOWN `offlineCacheAllowed === false` pin, device-wide (every tab of the origin reads it at
 * once), written on every policy read that forbids the copy (ui/session.ts applyOrgOfflineCachePolicy) and removed on one
 * that allows it. Presence = forbidden.
 */
export const ORG_CACHE_OFF_KEY = "andvari.orgCacheOff";

/**
 * Whether the server's policy forbids the offline copy, as last read on this browser. A store whose copy is still open
 * then queues nothing new into it and does not send from it: the policy's one attempt does that, then wipes it.
 */
export function policyForbidsCopy(): boolean {
  try {
    return localStorage.getItem(ORG_CACHE_OFF_KEY) !== null;
  } catch {
    return false;
  }
}

/**
 * The copies a server's policy is removing now, one device-wide key per copy (every tab reads it at once), set from the
 * moment the policy is read for that copy until it is gone or the held wipe ends. Only that copy is closed for new
 * changes: a tab of another account in the same browser goes on as before (its own policy read removes its copy).
 */
export const COPY_BEING_REMOVED_PREFIX = "andvari.copyBeingRemoved.";

/** The mark's value while the copy's deletion is held up by a connection of another tab that keeps it open. */
const REMOVAL_BLOCKED = "blocked";

/** Marks [userId]'s copy as being removed: its store queues nothing new into it from this moment. A mark that says the
 *  removal is held up stays as it is: a new run does not make it "in a moment" again. */
export function markCopyBeingRemoved(userId: string): void {
  try {
    if (localStorage.getItem(COPY_BEING_REMOVED_PREFIX + userId) === REMOVAL_BLOCKED) return;
    localStorage.setItem(COPY_BEING_REMOVED_PREFIX + userId, String(Date.now()));
  } catch {
    /* storage unreachable: the store cannot read the mark either */
  }
}

/** [userId]'s mark says whether its removal is held up now (another tab keeps the copy open) or is under way. */
function markRemoval(userId: string, blocked: boolean): void {
  try {
    localStorage.setItem(COPY_BEING_REMOVED_PREFIX + userId, blocked ? REMOVAL_BLOCKED : String(Date.now()));
  } catch {
    /* storage unreachable */
  }
}

/** Whether [userId]'s copy is being removed and its deletion is held up by another tab that keeps it open (any tab). */
export function copyRemovalBlocked(userId: string): boolean {
  try {
    return localStorage.getItem(COPY_BEING_REMOVED_PREFIX + userId) === REMOVAL_BLOCKED;
  } catch {
    return false;
  }
}

/** Ends the mark of [userId]'s copy: it is gone, or used again. */
export function clearCopyBeingRemoved(userId: string): void {
  try {
    localStorage.removeItem(COPY_BEING_REMOVED_PREFIX + userId);
  } catch {
    /* storage unreachable */
  }
}

/** The copies marked as being removed. */
function copiesBeingRemoved(): string[] {
  const out: string[] = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k !== null && k.startsWith(COPY_BEING_REMOVED_PREFIX)) out.push(k.slice(COPY_BEING_REMOVED_PREFIX.length));
    }
  } catch {
    /* storage unreachable */
  }
  return out;
}

/** Whether [userId]'s copy is being removed by a server's policy now (in any tab). */
export function copyIsBeingRemoved(userId: string): boolean {
  try {
    return localStorage.getItem(COPY_BEING_REMOVED_PREFIX + userId) !== null;
  } catch {
    return false;
  }
}

/**
 * A policy read that allows the copy: a mark left by a run that ended without clearing it (a tab closed in the middle) is
 * cleared under the copy's lock, once no run of it is under way and no wipe of it is held.
 */
export function releaseCopiesAfterLift(): void {
  for (const copy of copiesBeingRemoved()) {
    void exclusiveForCopy(copy, async () => {
      if (!policyForbidsCopy() && heldNotice(copy) === null && !deleting.has(copy)) clearCopyBeingRemoved(copy);
    }).catch(() => {});
  }
}

/** A change made while a server's policy is removing this browser's copy: refused, so nothing is queued into it. */
export class CopyBeingRemovedError extends Error {
  /** [blocked]: the removal is held up because another tab of this browser keeps the copy open (said as such). */
  constructor(readonly blocked: boolean = false) {
    super(
      blocked
        ? "the server's policy is removing this browser's offline copy, and another tab keeps it open: the change was not made"
        : "the server's policy is removing this browser's offline copy: the change was not made",
    );
    this.name = "CopyBeingRemovedError";
  }
}

// ---- The notice ----

/** What is said once the copy is gone: the server's name and the numbers, nothing else. */
export interface PolicyWipeNotice {
  readonly server: string;
  /** Changes that could not be sent, and are lost. Null: this browser could not read the copy, so it cannot tell. */
  readonly unsent: number | null;
  /** Changes whose request went out without an answer in time: they may or may not have arrived. */
  readonly unsure: number;
}

interface KeptNotice extends PolicyWipeNotice {
  /** Whether the copy is gone: the notice is said only then. */
  readonly gone: boolean;
}

/** Device-wide (not scoped to an account, so no account's own clean-up removes it before it is said): one entry per copy. */
export const POLICY_WIPE_NOTICE_KEY = "andvari.policyWipeNotice";

type Store = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function readAll(storage: Pick<Storage, "getItem">): Record<string, KeptNotice> {
  let o: unknown;
  try {
    const raw = storage.getItem(POLICY_WIPE_NOTICE_KEY);
    if (raw === null) return {};
    o = JSON.parse(raw);
  } catch {
    return {};
  }
  const out: Record<string, KeptNotice> = {};
  if (!o || typeof o !== "object" || Array.isArray(o)) return out;
  for (const [copy, v] of Object.entries(o as Record<string, unknown>)) {
    const n = v as { server?: unknown; unsent?: unknown; unsure?: unknown; gone?: unknown } | null;
    if (!n || typeof n !== "object" || typeof n.server !== "string" || typeof n.gone !== "boolean") continue;
    const count = (x: unknown): number | null => (typeof x === "number" && Number.isSafeInteger(x) && x >= 0 ? x : null);
    out[copy] = { server: n.server, unsent: count(n.unsent), unsure: count(n.unsure) ?? 0, gone: n.gone };
  }
  return out;
}

function writeAll(all: Record<string, KeptNotice>, storage: Store): void {
  if (Object.keys(all).length === 0) storage.removeItem(POLICY_WIPE_NOTICE_KEY);
  else storage.setItem(POLICY_WIPE_NOTICE_KEY, JSON.stringify(all));
}

/** Keeps [n] for [copy] (its account's id), replacing what was kept for that copy: one copy is counted once. */
export function keepPolicyWipeNotice(copy: string, n: PolicyWipeNotice, gone: boolean, storage: Store = localStorage): void {
  try {
    const all = readAll(storage);
    all[copy] = { server: n.server, unsent: n.unsent, unsure: n.unsure, gone };
    writeAll(all, storage);
  } catch {
    /* storage unreachable: the notice cannot be kept; the wipe itself is not held back for it */
  }
}

/**
 * "Forget the earlier account on this device" (decided on 2026-11-17) removed [copy]'s account and its copy: a notice kept
 * for it, a word owed to the person about changes that were lost, stays, but no longer names the account: it moves under a
 * key of its own (an opaque token), as gone, since the copy is. It is said once at the next start, whatever the policy says
 * by then, and no held wipe is run again for an account this browser forgot. A store that fails throws.
 */
export function detachPolicyWipeNotice(copy: string, storage: Store = localStorage): void {
  const all = readAll(storage);
  const n = all[copy];
  if (!n) return;
  delete all[copy];
  const token = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join("");
  all[`forgotten-${token}`] = { ...n, gone: true };
  writeAll(all, storage);
}

/** The notice kept for [copy] whose wipe was not made yet, or null. */
function heldNotice(copy: string, storage: Store = localStorage): PolicyWipeNotice | null {
  try {
    const n = readAll(storage)[copy];
    return n && !n.gone ? { server: n.server, unsent: n.unsent, unsure: n.unsure } : null;
  } catch {
    return null;
  }
}

function markGone(copy: string, storage: Store = localStorage): void {
  try {
    const all = readAll(storage);
    const n = all[copy];
    if (!n) return;
    all[copy] = { ...n, gone: true };
    writeAll(all, storage);
  } catch {
    /* storage unreachable */
  }
}

/**
 * The notices waiting to be said, for copies that are gone, taken as one: they are removed as they are read, so each is
 * said once. A copy whose wipe was not made yet keeps its notice, unsaid. Null when there is none.
 */
export function takePolicyWipeNotice(storage: Store = localStorage): PolicyWipeNotice | null {
  try {
    const all = readAll(storage);
    let said: PolicyWipeNotice | null = null;
    for (const [copy, n] of Object.entries(all)) {
      if (!n.gone) continue;
      said =
        said === null
          ? { server: n.server, unsent: n.unsent, unsure: n.unsure }
          : { server: n.server, unsent: said.unsent === null || n.unsent === null ? null : said.unsent + n.unsent, unsure: said.unsure + n.unsure };
      delete all[copy];
    }
    if (said !== null) writeAll(all, storage);
    return said;
  } catch {
    return null;
  }
}

/** Told when a wipe that was held up is made later (the app then takes the notice and says it). */
const madeLater = new Set<() => void>();

/** Calls [fn] whenever a wipe that could not be made at once is made later in this tab. The result stops it. */
export function onPolicyWipeMadeLater(fn: () => void): () => void {
  madeLater.add(fn);
  return () => {
    madeLater.delete(fn);
  };
}

// ---- The run ----

/** The changes that wait in a copy, counted against what the attempt brought. */
function counted(at: WaitingRead, sent: SentOnce | null): { unsent: number | null; unsure: number } {
  if (at.kind === "none") return { unsent: 0, unsure: 0 };
  if (at.kind === "unreadable") return { unsent: null, unsure: 0 };
  let unsent = at.staged.length + at.parked;
  let unsure = 0;
  for (const m of at.pending) {
    if (sent?.taken.has(m.mutationId)) continue;
    if (sent?.unsure.has(m.mutationId)) unsure++;
    else unsent++;
  }
  return { unsent, unsure };
}

/** One run per copy in this tab (a second call while one runs waits for it, then finds the copy gone). */
const running = new Map<string, Promise<unknown>>();

/** One run per copy across the browser's tabs: the Web Lock the code base already uses to keep tabs apart. */
async function acrossTabs<T>(copy: string, fn: () => Promise<T>): Promise<T> {
  const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
  if (!locks?.request) return fn(); // no Web Locks: one run per tab still holds
  return (await locks.request(`andvari-policy-wipe-${copy}`, fn)) as T;
}

/**
 * Runs [fn] while nothing else removes [userId]'s copy, in this tab and across the browser's tabs: the policy's run and
 * every other way a copy is wiped (a sign-out, the offline copy turned off in Settings, an account deletion) take this
 * one lock, so no wipe lands while the policy's run counts what waits in the copy. [fn] must not take it again.
 */
export function exclusiveForCopy<T>(userId: string, fn: () => Promise<T>): Promise<T> {
  const before = running.get(userId);
  const run = (async (): Promise<T> => {
    if (before) await before.catch(() => {});
    return acrossTabs(userId, fn);
  })();
  running.set(userId, run);
  void run
    .finally(() => {
      if (running.get(userId) === run) running.delete(userId);
    })
    .catch(() => {});
  return run;
}

/** How a run over a copy ended (for the caller and its tests). */
export interface PolicyWipeRun {
  /** What is said once the copy is gone; null when there was no copy here (or another run already wiped it). */
  readonly notice: PolicyWipeNotice | null;
  /** Whether the copy is gone now. */
  readonly gone: boolean;
  /** The attempt, when one was made by this run. */
  readonly sent: SentOnce | null;
}

/**
 * Sends what waits in [userId]'s copy once, with [send] (see {@link sendWaitingOnce}), counts what could not be sent at
 * the moment of the wipe, keeps that with [server]'s name, and wipes the copy. A copy whose earlier wipe was not made
 * is not sent from again: only its wipe is tried again. The notice is marked to be said only when the copy is gone; a
 * wipe that is held up and made later tells {@link onPolicyWipeMadeLater}. Never throws.
 */
export function removeCopyForPolicy(userId: string, server: string, send: SendOnce | null, mayWrite: MayWrite, limits: PolicyWipeLimits = {}): Promise<PolicyWipeRun> {
  return exclusiveForCopy(userId, () => runOnce(userId, server, send, mayWrite, limits));
}

/** [runOnceMarked] with [userId]'s copy closed for new changes while it runs, and after it while its wipe is held. */
async function runOnce(userId: string, server: string, send: SendOnce | null, mayWrite: MayWrite, limits: PolicyWipeLimits): Promise<PolicyWipeRun> {
  if (policyForbidsCopy()) markCopyBeingRemoved(userId);
  const r = await runOnceMarked(userId, server, send, mayWrite, limits);
  if (r.gone || (heldNotice(userId) === null && !deleting.has(userId))) clearCopyBeingRemoved(userId);
  return r;
}

async function runOnceMarked(userId: string, server: string, send: SendOnce | null, mayWrite: MayWrite, limits: PolicyWipeLimits): Promise<PolicyWipeRun> {
  const clock = limits.clock ?? realClock;
  const deadline = clock.now() + (limits.attemptMs ?? POLICY_WIPE_ATTEMPT_LIMIT_MS);
  const held = heldNotice(userId);
  if (held !== null) {
    // A policy read since then allows the copy (read again under the lock): the pending wipe and its notice end, and
    // nothing is wiped or said on the strength of the old policy.
    if (!policyForbidsCopy()) {
      dropHeldPolicyWipes(localStorage, userId);
      return { notice: null, gone: false, sent: null };
    }
    // An earlier run counted this copy and could not wipe it: nothing is sent again, the wipe is tried again.
    const gone = await wipe(userId, limits);
    return { notice: gone ? held : null, gone, sent: null };
  }
  const first = await readWaiting(userId);
  if (first.kind === "none") return { notice: null, gone: true, sent: null }; // no copy, or another run wiped it: nothing is said
  const sent = first.kind === "read" ? await sendWaitingOnce(first.pending, send, mayWrite, { requestMs: limits.requestMs, deadline, clock }) : null;
  const atWipe = first.kind === "read" ? await readWaiting(userId) : first;
  // The copy vanished under the run all the same (a wipe that did not take the lock, such as a store's own clean-up of a
  // copy it cannot write): what waited in it is counted from this run's own first read and what the server took since,
  // never as "nothing was lost".
  const notice: PolicyWipeNotice = { server, ...counted(first.kind === "read" && atWipe.kind === "none" ? first : atWipe, sent) };
  keepPolicyWipeNotice(userId, notice, false);
  const gone = await wipe(userId, limits);
  return { notice: gone ? notice : null, gone, sent };
}

/** Wipes the copy; marks its notice to be said when it is gone, now or when what held it up ends. */
async function wipe(userId: string, limits: PolicyWipeLimits): Promise<boolean> {
  const d = await deleteCopy(userId, limits.deleteWaitMs ?? POLICY_WIPE_DELETE_WAIT_MS, (goneLater) => {
    deleting.delete(userId);
    if (!goneLater) {
      markRemoval(userId, false); // no longer held up by a tab: refused after all, tried again at a later start
      return;
    }
    clearCopyBeingRemoved(userId); // the copy is gone: the account is open for changes again
    markGone(userId);
    for (const fn of [...madeLater]) fn();
  });
  if (d === "blocked") {
    deleting.add(userId); // still asked of the browser: it completes when what holds it up ends
    markRemoval(userId, true); // a change refused meanwhile says that another tab holds the copy open
  }
  if (d === "gone") markGone(userId);
  return d === "gone";
}

/** The copies whose deletion this tab asked for and the browser has not yet made (held up by an open connection). */
const deleting = new Set<string>();

/**
 * A policy read that allows the copy: every wipe the policy asked for that was not made ends, with its notice (all copies,
 * or only [only]'s), and the copy is used again. A deletion this tab already asked of the browser cannot be taken back:
 * its notice is kept, so that it is said when the deletion completes. Notices of copies that are gone stay to be said.
 */
export function dropHeldPolicyWipes(storage: Store = localStorage, only?: string): void {
  try {
    const all = readAll(storage);
    let changed = false;
    for (const [copy, n] of Object.entries(all)) {
      if (n.gone || deleting.has(copy) || (only !== undefined && copy !== only)) continue;
      delete all[copy];
      clearCopyBeingRemoved(copy); // the copy is used again
      changed = true;
    }
    if (changed) writeAll(all, storage);
  } catch {
    /* storage unreachable */
  }
}

/**
 * After a policy read at a start (boot or unlock) that forbids the copy: the wipes it asked for earlier that could not be
 * made are tried again (nothing is sent), and their notices become sayable once their copies are gone. Only while the
 * policy still forbids the copy: when it no longer does, the held wipes end ({@link dropHeldPolicyWipes}). Never throws.
 */
export async function retryHeldPolicyWipes(limits: PolicyWipeLimits = {}, storage: Store = localStorage): Promise<void> {
  if (!policyForbidsCopy()) {
    dropHeldPolicyWipes(storage);
    return;
  }
  let copies: string[];
  try {
    copies = Object.entries(readAll(storage))
      .filter(([, n]) => !n.gone)
      .map(([c]) => c);
  } catch {
    return;
  }
  for (const copy of copies) await removeCopyForPolicy(copy, "", null, NOTHING_MAY_BE_WRITTEN, limits);
}
