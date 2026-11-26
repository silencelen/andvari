import { ApiError, TrafficStoppedError } from "../api/client";
import { isNilUserId } from "../api/wireids";
import type { KeyValue } from "../api/devicesecret";
import { type LogAppendRequest, type LogAppendResponse, type LogDeleted, type LogPage, readLogDeleted } from "../api/wire";
import { adVkShared } from "../crypto/ad";
import { fromB64, toB64, toHexLower } from "../crypto/bytes";
import { open, seal } from "../crypto/envelope";
import { type KeyPairBytes, randomBytes, sha256Sync } from "../crypto/provider";
import { openVaultGrant, sealVaultGrant, signVaultGrant } from "../crypto/trust/grant";
import { fromB64Canonical } from "../crypto/trust/grammar";
import {
  decodeVaultState,
  encodeVaultState,
  keyMatches,
  type LogEntry,
  logPosition,
  MAX_OFFER_WINDOW_MS,
  parseLogEntry,
  signLogEntryChecked,
  type VaultRole,
  type VaultState,
  verifyLogEntry,
  vkCommit,
} from "../crypto/trust/vaultlog";
import { type AccountDocument, type VaultRecord, vaultRecordDue, withAccepted, withVaultHead } from "./accountdoc";
import type { AccountStateStore } from "./accountdocstore";
import { type AdoptCondition, checkGrant, checkWrap, latestAddSeq, type RecordRefusal, recordRefusal } from "./adoption";

/**
 * This browser's verified vault logs (design §3.9), on `GET` and `POST /vaults/{vaultId}/log` — the web twin of
 * core's `StoredVaultLogs`. For every vault it keeps the verified state, the hash of every verified entry, and a
 * status flag, all in its device storage:
 *
 * - **verified**: the log replays from the genesis to the served head;
 * - **failed**: an entry did not verify (its verdict is kept); the vault is read-only;
 * - **withheld**: the served log ends below what this browser verified, or below the account's vault record;
 * - **frozen** (sticky): two entries at one position, or a vault record naming another genesis;
 * - **purged**: the deletion in force was purged;
 * - **removed**: this account is no longer a member (left, or removed by the owner).
 *
 * The web reads no device-link checkpoint (it is never linked, §13). The earlier defects of the engine are not
 * reintroduced: a replayed leave or remove never rolls back the answer to a later add, and an item-head hint
 * above the verified head is chased once and then backs off.
 */

export type LogStatus =
  | { readonly kind: "unknown"; readonly vaultId: string }
  | { readonly kind: "verified"; readonly vaultId: string; readonly state: VaultState; readonly mayBeIncomplete: boolean }
  | { readonly kind: "failed"; readonly vaultId: string; readonly state: VaultState | null; readonly verdict: string }
  | { readonly kind: "withheld"; readonly vaultId: string; readonly state: VaultState; readonly servedSeq: number | null }
  | { readonly kind: "frozen"; readonly vaultId: string; readonly state: VaultState; readonly atSeq: number }
  | { readonly kind: "purged"; readonly vaultId: string; readonly state: VaultState; readonly purgedAt: number }
  | { readonly kind: "removed"; readonly vaultId: string; readonly state: VaultState; readonly byOwner: boolean };

/** The log routes and the self-wrap route (api/wireclient.ts WireApi has them). */
export interface LogWire {
  logPage(vaultId: string, after: number | null): Promise<LogPage>;
  appendLog(vaultId: string, req: LogAppendRequest): Promise<LogAppendResponse>;
  putSelfWrap(vaultId: string, wrappedVk: string): Promise<number>;
}

/** This account's own grant row for a vault, as the last sync served it: ciphertext only, decided on by §3.6. */
export interface GrantRowView {
  /** The account's own wrap of the vault key under its UVK (an owner wrap or a member self-wrap); empty when there is none. */
  readonly wrappedVk: string;
  /** The sealed 0x01 grant of the `add` that admitted the account, or null. */
  readonly signedGrant: string | null;
  /** The row's revision as the server served it (any write of the row, a re-add among them, moves it); absent where unknown. */
  readonly rev?: number;
}

/** What the mark of an own leave of a frozen vault holds at rest: the grant row it was made for (no key, no content). */
interface OwnLeaveMark {
  readonly rev: number;
  readonly row: string;
}

/** A digest of a grant row's served fields, to tell the row an own leave was made for from a row written after it. */
function grantRowDigest(row: GrantRowView): string {
  return toHexLower(sha256Sync(new TextEncoder().encode(`${row.wrappedVk}\n${row.signedGrant ?? ""}`)));
}

/**
 * The `add` entry through which [s] names [userId] as a member: its seq, 0 for the creator never added (named by the
 * genesis, seq 0), NaN where [s] does not name the account (a number no entry has, so nothing equals it).
 */
export function memberAddOf(s: VaultState, userId: string): number {
  const m = s.members[userId];
  return m === undefined ? Number.NaN : (m.addSeq ?? 0);
}

/** What the store asks of the session around it (the sync store and the contact book). */
export interface LogHost {
  /** This account's own grant row for [vaultId] from the last sync, or null. */
  grantRow(vaultId: string): GrantRowView | null;
  /** True when [userId] is a contact CURRENT on this browser with exactly [identityPub] (§6.9, §8.5). */
  isCurrentContact(userId: string, identityPub: string): boolean;
  /** The contact current on THIS browser for [userId]: its key and whether codes were compared; else null. */
  currentContact(userId: string): { readonly key: string; readonly compared: boolean } | null;
  /** The label to show for a current contact with that key (plain text), or null. */
  labelFor(userId: string, identityPub: string): string | null;
  /** The vault's name, decrypted under [vk]; plain text, or null. Called only after §3.6 (a) to (c) passed. */
  vaultName(vaultId: string, vk: Uint8Array): string | null;
  /**
   * The vault's sealed meta blob for a new vault's name; [moveOf]: the vault a move makes this one for, written as the
   * meta's optional {@link VAULT_META_MOVE_OF} entry.
   */
  sealMeta(vaultId: string, vk: Uint8Array, name: string, moveOf?: string): string;
  /** The name the server reports for the owner of a share from someone who is not a current contact, or null. */
  serverOwnerName(vaultId: string): string | null;
}

/** Where the session keeps the vault keys it adopted: the store installs a key here and removes it on a verified removal. */
export interface VaultKeyRing {
  get(vaultId: string): Uint8Array | undefined;
  has(vaultId: string): boolean;
  /** [addSeq]: the `add` entry of the verified log under which the key is adopted (the key works only while the log names the account through it). */
  set(vaultId: string, vk: Uint8Array, addSeq: number): unknown;
  delete(vaultId: string): unknown;
}

/** Why a key was not taken; a failing (e) says how it failed ({@link recordRefusal}: ahead, fork, another genesis). */
export type AdoptionRefusal = "log_not_verified" | "not_a_member" | "vk_commit_mismatch" | "grant_refused" | RecordRefusal | "no_key";

/**
 * Whether this browser may start using a shared vault's key (design §3.6). A caller can only read the outcome: the
 * store checks (a) the log verifies, (b) this account is a member, (c) the key matches the commitment, (d) the key
 * source's rule and (e) the account's vault record itself.
 */
export type Adoption =
  /**
   * All five hold, or (e) alone fails in a way that gives the key read-only (the record ahead of a withheld log, or beside
   * a frozen one; decided on 23 November 2026): the key is in the session's key ring. A vault whose log is not verified
   * here takes no write, whatever its key.
   */
  | { readonly kind: "adopted"; readonly vaultId: string; readonly source: "owner_wrap" | "self_wrap" | "grant" }
  /**
   * A grant from a current contact passed (a) to (c): the person must accept, once per account. [ownerLabel] is the
   * contact's label (it is shown only because the owner's key in the log equals the pinned key); [vaultName] was
   * decrypted only now and is plain text; [addSeq] is the `add` the answer binds to (FS-R6).
   */
  | { readonly kind: "ask"; readonly vaultId: string; readonly owner: string; readonly ownerLabel: string; readonly vaultName: string; readonly addSeq: number }
  /** The `add`'s actor is not a current contact with that key: "Connect with them first". Nothing was decrypted. */
  | { readonly kind: "connect_first"; readonly vaultId: string; readonly serverName: string | null }
  /**
   * The person declined this `add`: hidden on every device of the account. [leave], only where the answer was just
   * given: what became of the `leave` that tells the owner (`waiting`: held, sent again at the next unlock;
   * `not_stored`: not stored and not held). [frozen], only on a vault frozen on this browser (nothing of the leave is held
   * or sent again): what the browser knows of it, the server's word that it stored it, its refusal, or nothing.
   */
  | { readonly kind: "declined"; readonly vaultId: string; readonly leave?: "stored" | "waiting" | "not_stored"; readonly frozen?: "stored" | "refused" | "unknown" }
  /** The answer could not be written to the account state (unreachable, contended, full): nothing changed; ask again. */
  | {
      readonly kind: "not_recorded";
      readonly vaultId: string;
      readonly reason: string;
      /**
       * Set only where this browser could not tell the write's outcome (it went out and no answer told, or it never
       * left); absent on a refusal and on "contended". Taken from the write's kind, never from [reason], whose words a
       * server's refusal code can take too.
       */
      readonly outcomeNotKnown?: true;
    }
  | { readonly kind: "refused"; readonly vaultId: string; readonly reason: AdoptionRefusal };

export type LogAction =
  /**
   * [moveOf]: the vault is the target of "Move everything" out of that vault (its id): said in the new vault's own sealed
   * meta as the optional entry {@link VAULT_META_MOVE_OF}, so that another device can recognise an unfinished target.
   */
  | { readonly kind: "create"; readonly name: string; readonly moveOf?: string }
  | { readonly kind: "add"; readonly contactUserId: string; readonly role: "writer" | "reader"; readonly releaseUncompared: boolean }
  | { readonly kind: "role"; readonly member: string; readonly role: "writer" | "reader" }
  | { readonly kind: "remove"; readonly member: string }
  | { readonly kind: "leave" }
  | { readonly kind: "offer"; readonly to: string; readonly expiresInMs: number }
  | { readonly kind: "cancel" }
  | { readonly kind: "accept" }
  | { readonly kind: "delete" }
  | { readonly kind: "restore" };

/** The user id an action names (an add, a role, a remove, an offer), or null for one that names nobody. */
function namedMember(action: LogAction): string | null {
  switch (action.kind) {
    case "add":
      return action.contactUserId;
    case "role":
    case "remove":
      return action.member;
    case "offer":
      return action.to;
    default:
      return null;
  }
}

/**
 * What is known of a frame held in the pending-append record, from the answers this browser had (classified from what
 * is known, never from what is likely):
 *  - `stored`: the server's own complete answer said it is stored (a 2xx under the JSON type, decoded in full, whose head
 *    names this very frame), and this browser has not read it back in the verified log yet (the follow-up read failed).
 *  - `not_stored`: the server's own answer to this frame's first post refused it for now (`429 rate_limited`, or
 *    `409 log_head_moved` with the other entry not verified yet): it is not stored, and it is sent again later.
 *  - `unknown`: everything else: no answer, an answer cut off, a 5xx, a redirect, an answer that is not the server's,
 *    an answer the traffic gate dropped, or a re-post whose own answer settles nothing.
 */
export type HeldKnown = "stored" | "not_stored" | "unknown";

export type AppendOutcome =
  | { readonly kind: "appended"; readonly vaultId: string; readonly state: VaultState }
  /**
   * Kept in the pending-append record and re-posted byte for byte later; [known] says what is known of it. [listRead]
   * false: after "cannot tell" the vault could not be read from the server again (the screen's copy may be old).
   */
  | { readonly kind: "pending"; readonly vaultId: string; readonly known: HeldKnown; readonly listRead?: false }
  /**
   * This browser's traffic gate refused the frame's FIRST post before it left the browser (its record of the server was
   * forgotten or found forked meanwhile): nothing was sent, nothing changed, and nothing is held.
   */
  | { readonly kind: "not_sent"; readonly vaultId: string }
  /** Another entry was verified at this position: nothing of ours is pending; the caller may sign afresh. */
  | { readonly kind: "head_moved"; readonly vaultId: string }
  /**
   * The answer's head lay beyond the frame (it named no frame), and the log as read afterwards reaches that head, with
   * the hash the answer named there, and does not hold the frame: the change was not made, and nothing of it is held.
   */
  | { readonly kind: "not_made"; readonly vaultId: string }
  /** `400 at_ahead`: this browser's clock runs ahead of the server's. */
  | { readonly kind: "clock_ahead"; readonly vaultId: string }
  /**
   * Nothing is changed in this vault here: its log is not verified on this browser. [frozen], where the vault is frozen
   * (the server's record of it contradicts itself, for good), says what happened: `unsent`, it was frozen before this
   * change and nothing of the change was sent; `sent`, it froze after a change of it was sent (this one, or one held
   * before it), so nothing may be said of whether that change was made. [known]: what the server's answer said of the
   * change sent, where the read after it found the vault frozen and no contradiction of that answer. [leave]: a member's
   * leave of a vault frozen before it was sent (the one change a frozen vault still takes, decided on 2026-11-19), by the
   * server's answer alone: it named the leave (`stored`), refused it, or no answer told (`unknown`).
   */
  | { readonly kind: "read_only"; readonly vaultId: string; readonly frozen?: "unsent" | "sent"; readonly known?: HeldKnown; readonly leave?: "stored" | "refused" | "unknown" }
  | { readonly kind: "refused"; readonly vaultId: string; readonly code: string }
  /**
   * `409 vault_items_moved`: a vault's `delete` that named the point up to which its items were read ({@link
   * AppendOpts.itemsAtMost}) was refused because an item of the vault changed after it. Nothing is stored (the server's
   * own refusal proves it) and nothing is held: the caller reads the vault again and decides afresh.
   */
  | { readonly kind: "items_moved"; readonly vaultId: string }
  | { readonly kind: "not_allowed"; readonly reason: string };

interface Pending {
  readonly vaultId: string;
  readonly frame: string;
  readonly grant?: string;
  readonly wrappedVk?: string;
  readonly metaBlob?: string;
  /**
   * The old vault's `delete` signed by "Move everything" (design §3.13): only the move re-posts it, after its own checks
   * of the old vault; the general re-posting at an unlock leaves it alone.
   */
  readonly forMove?: true;
  /**
   * The `delete` of a stopped move's half-made vault, with the copies that move made in it (copy id and the revision the
   * server answered, null where not known; null where no record of them was kept). Never re-posted unread: the general
   * re-posting at an unlock leaves it alone, and the store sends it again only after a read of the vault showed nothing
   * but those copies ({@link VaultLogStore.heldHalfMadeDeletes}).
   */
  readonly halfMade?: { readonly copies: readonly (readonly [string, number | null])[] | null };
  /** A step of "Move everything" (its additions to the new vault): the move's own, never withdrawn one by one. */
  readonly moveStep?: true;
  /**
   * A `delete`'s read point ({@link AppendOpts.itemsAtMost}): sent beside the frame at every post of it. Unsigned, so a
   * re-post after a newer read carries that read's point ({@link VaultLogStore.retryHeld}).
   */
  readonly itemsAtMost?: number;
  /** The server's own complete answer said this frame is stored ({@link HeldKnown} `stored`); it waits to be read back. */
  readonly acked?: true;
  /**
   * The server's own answer to this frame's only post refused it for now ({@link HeldKnown} `not_stored`): no post of it
   * since can have arrived. Cleared before any later post leaves, so a re-post whose answer is lost is "cannot tell".
   */
  readonly notStored?: true;
  /** When the frame was first posted (this browser's clock, ms): a change of who may read a vault waits a day at most. */
  readonly heldAt?: number;
  /**
   * A head an answer of the server named at or beyond this frame's position, other than the frame itself (`beyond` of
   * {@link headNamesFrame}): the server's word that it holds the frame. Another entry at the frame's position in the
   * verified log then freezes the vault; "not made" is never said of it.
   */
  readonly beyond?: { readonly seq: number; readonly hash: string };
  /**
   * While the frame's FIRST request is out (when it left, this browser's clock): it cannot be withdrawn until that request
   * ended, in this tab or in another one. Cleared when it ends; a mark left by a tab closed meanwhile counts for at most
   * {@link FIRST_POST_OUT_MAX_MS}.
   */
  readonly firstOutAt?: number;
}

/**
 * The optional entry of a vault's sealed meta (spec 02 §4: a JSON object; a reader keeps and ignores what it does not
 * know) that says the vault is the target of "Move everything" out of another vault: `"moveOf": "<that vault's id>"`,
 * the id as the log writes it (a lowercase UUID). Written once, in the meta sealed with the new vault's genesis; a rename
 * keeps it.
 */
export const VAULT_META_MOVE_OF = "moveOf";

/** How long a first request's mark ({@link Pending.firstOutAt}) can stand: longer than any request of this client lasts. */
export const FIRST_POST_OUT_MAX_MS = 180_000;

/** How many changes of one vault are remembered after a withdrawal or give-up ({@link VaultLogStore.checkWatched}). */
export const WATCHES_PER_VAULT_MAX = 8;

/** What {@link VaultLogStore.append} is told beside the action. */
export interface AppendOpts {
  readonly forMove?: boolean;
  readonly expectHead?: { readonly seq: number; readonly hash: string };
  /** A stopped move's half-made vault is deleted ({@link Pending.halfMade}): the copies that move made in it. */
  readonly halfMade?: { readonly copies: ReadonlyMap<string, number | null> | null };
  /** A step of "Move everything" ({@link Pending.moveStep}). */
  readonly moveStep?: boolean;
  /**
   * A `delete` only: the sync `rev` of the read whose items decided it (spec 03 §10.3). The server refuses the deletion
   * when an item of the vault changed after it ({@link AppendOutcome} `items_moved`).
   */
  readonly itemsAtMost?: number;
}

/** A held `delete` of a stopped move's half-made vault ({@link VaultLogStore.heldHalfMadeDeletes}). */
export interface HeldHalfMadeDelete {
  readonly vaultId: string;
  /** The copies the move made in it (copy id to the revision the server answered, null where not known), or null. */
  readonly copies: ReadonlyMap<string, number | null> | null;
}

/** How long a held change of who may read a vault (an `add` or a `remove`) is sent again before it is given up. */
export const HELD_MEMBERSHIP_MAX_MS = 86_400_000;

/** A held change as the screens show it: what it is, whom it names, since when, and what is known of it. */
export interface HeldChange {
  readonly vaultId: string;
  /** The log entry's kind (`genesis` for a new vault). */
  readonly kind: LogEntry["kind"];
  /** The member it adds, removes or changes, or the person an ownership offer goes to; null for the others. */
  readonly member: string | null;
  /** That person's label as a current contact on this browser, or null. */
  readonly memberLabel: string | null;
  readonly heldAt: number | null;
  readonly known: HeldKnown;
  /** It changes who may read the vault and is known not stored: the person may withdraw it ({@link VaultLogStore.withdrawHeld}). */
  readonly withdrawable: boolean;
}

/**
 * What became of one held change when it was due to be sent again ({@link VaultLogStore.resendPending}): the re-post's
 * outcome, or `given_up`: a change of who may read the vault that waited longer than {@link HELD_MEMBERSHIP_MAX_MS}
 * and is not sent again. `made: false` when the log, read just then, does not hold it (or the server's own answer said
 * it was not stored and nothing was sent since); `made: "unknown"` when that cannot be told.
 */
export type ResendOutcome = AppendOutcome | { readonly kind: "given_up"; readonly vaultId: string; readonly made: false | "unknown" };

/**
 * A held change that did not happen when it was sent again (refused, its place taken, not made, given up), kept at rest
 * until the person dismissed its notice ({@link VaultLogStore.settledChanges}): it is never sent again. [id] is its
 * frame's hash.
 */
export interface SettledChange {
  readonly id: string;
  readonly change: HeldChange;
  readonly outcome: ResendOutcome;
}

/** A re-send outcome after which the change did not happen and its record is gone from the held ones. */
function didNotHappen(o: ResendOutcome): boolean {
  return o.kind !== "appended" && o.kind !== "pending";
}

/**
 * The kept changes of a shared vault a person could come to regret: shown as waiting, withdrawable, and given up after
 * {@link HELD_MEMBERSHIP_MAX_MS}. A change of who may read it (an addition, a removal), a change of role, a hand-over
 * (an ownership offer) and the vault's deletion.
 */
const MEMBERSHIP_KINDS: ReadonlySet<LogEntry["kind"]> = new Set(["add", "remove", "role", "offer", "delete"]);

/**
 * A change this browser withdrew or gave up while it could not tell whether the server had it (CL.5): remembered by
 * its frame's hash and position for as long as that position is free, so that a log that later holds it is said. [why]
 * how it ended here; [read] a read of the log since reached the server; [told] the person has been told what that read
 * found (a withdrawal is told once whether the log holds it; a given-up change was told at its own notice).
 */
interface Watch {
  readonly frame: string;
  readonly hash: string;
  readonly seq: number;
  /**
   * `half_made`: a deletion of a stopped move's half-made vault, dropped unsent or given up (never "withdrawn").
   * `answer_lost`: the person's own deletion of a vault, held because its answer was lost, that the log was found to hold
   * when it was looked for before asking them about it ({@link VaultLogStore.deletionsToAsk}): made, kept only until the
   * notice that the vault was deleted is dismissed.
   */
  readonly why: "withdrawn" | "given_up" | "half_made" | "answer_lost";
  /** `answer_lost`: the end of the deleted vault's grace as the server served it with the read that found the deletion. */
  readonly purgeAt?: number;
  readonly read: boolean;
  readonly told: boolean;
  /** A head the server's answer named at or beyond the frame ({@link Pending.beyond}): the server's word. */
  readonly beyond?: { readonly seq: number; readonly hash: string };
  /** The server's answer named the frame itself ({@link Pending.acked}): the server's word that it stored it. */
  readonly acked?: true;
  /**
   * The log holds it after all: no longer looked for, and kept at rest until the person dismissed its notice
   * ({@link VaultLogStore.madeWatches}, {@link VaultLogStore.dismissWatched}), so that a lock or a closed tab loses nothing.
   */
  readonly made?: true;
}

/**
 * The changes of one vault remembered after a withdrawal or a give-up, bounded: of those still looked for, beyond
 * {@link WATCHES_PER_VAULT_MAX} go first those whose outcome the person was told already (the oldest first), and one not
 * told yet goes only when none of those is left. One found made stays until its notice is dismissed.
 *
 * Its cost: a person who withdraws more than that many changes to one vault while nothing reaches it is not told if the
 * server makes the oldest of them after all.
 */
function boundWatches(list: readonly Watch[]): Watch[] {
  const looked = list.filter((w) => w.made !== true);
  let excess = looked.length - WATCHES_PER_VAULT_MAX;
  if (excess <= 0) return [...list];
  const drop = new Set<Watch>();
  for (const told of [true, false]) {
    for (const w of looked) {
      if (excess <= 0) break;
      if (w.told === told) {
        drop.add(w);
        excess--;
      }
    }
  }
  return list.filter((w) => !drop.has(w));
}

/**
 * The form of the lists this code keeps at rest beside a vault's log (the watches, the settled changes). An entry whose
 * `form` is above it was written by a newer form of this code: it is left as it is, never acted on and never consumed;
 * an entry this code cannot read is kept the same way. Fields an entry carries that this code does not know ride along
 * on every rewrite (entries are rewritten by spreading what was read). A tab still running a form from before this one
 * rewrites the lists in its own form until it reloads.
 */
const AT_REST_FORM = 1;

/** The entries of a stored list, as stored (none where it cannot be read as a list). */
function rawRecords(t: string | null): unknown[] {
  if (t === null) return [];
  try {
    const list = JSON.parse(t) as unknown;
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function newerForm(r: unknown): boolean {
  const form = typeof r === "object" && r !== null ? (r as { form?: unknown }).form : undefined;
  return typeof form === "number" && form > AT_REST_FORM;
}

function understood<T>(raw: readonly unknown[], is: (r: unknown) => r is T): T[] {
  return raw.filter((r): r is T => is(r) && !newerForm(r));
}

function notUnderstood<T>(raw: readonly unknown[], is: (r: unknown) => r is T): unknown[] {
  return raw.filter((r) => !is(r) || newerForm(r));
}

function isWatch(w: unknown): w is Watch {
  if (typeof w !== "object" || w === null) return false;
  const x = w as Partial<Watch>;
  return typeof x.frame === "string" && typeof x.hash === "string" && typeof x.seq === "number" && (x.why === "withdrawn" || x.why === "given_up" || x.why === "half_made" || x.why === "answer_lost");
}

function isSettledOf(vaultId: string): (r: unknown) => r is { pending: Pending; outcome: ResendOutcome } {
  return (r: unknown): r is { pending: Pending; outcome: ResendOutcome } => {
    if (typeof r !== "object" || r === null) return false;
    const x = r as { pending?: { frame?: unknown; vaultId?: unknown }; outcome?: { kind?: unknown } };
    return typeof x.pending?.frame === "string" && x.pending.vaultId === vaultId && typeof x.outcome?.kind === "string";
  };
}

/**
 * What a read of the log found of a change this browser withdrew or gave up without knowing whether it was made
 * ({@link VaultLogStore.checkWatched}): `made` (the log holds it after all; the person is told with the way to undo it),
 * or `not_made` (the log as read does not hold it; said once, after a withdrawal).
 */
export interface WatchFinding {
  /** The change's frame hash. */
  readonly id: string;
  readonly change: HeldChange;
  readonly found: "made" | "not_made";
  readonly why: "withdrawn" | "given_up" | "half_made" | "answer_lost";
  /** When the change was signed (its entry's `at`). */
  readonly at: number;
  /** `answer_lost`: the end of the deleted vault's grace as served when the deletion was found; absent when none was. */
  readonly purgeAt?: number;
}

/**
 * A member's leave posted to a vault frozen before it was sent, by the outcome its post came to. Nothing is held beside a
 * frozen vault (its record went at the first look), so a leave whose answer was lost or refused for now is never sent
 * again, and the log, read, cannot show it: what is said follows the server's answer alone. A leave read back in the log
 * (a vault frozen by a contradiction, whose later entries still verify) and every other outcome stay as they are.
 */
function frozenLeave(out: AppendOutcome): AppendOutcome {
  if (out.kind !== "read_only" && out.kind !== "pending" && out.kind !== "refused") return out;
  const known = out.kind === "refused" ? "not_stored" : out.known;
  return { kind: "read_only", vaultId: out.vaultId, frozen: "sent", leave: known === "stored" ? "stored" : known === "not_stored" ? "refused" : "unknown" };
}

/** What a held record says is known of its frame ({@link HeldKnown}). */
function knownOf(p: Pending): HeldKnown {
  return p.acked === true ? "stored" : p.notStored === true ? "not_stored" : "unknown";
}

/**
 * What a decoded append answer's head says of [frame]:
 *  - `frame`: it names this very frame (its position and the hash of the frame sent): only someone who saw the frame can
 *    give that, and the server answers only after its commit, so the change is stored.
 *  - `beyond`: any other head at or beyond the frame's position: one beyond it, or one at its position with another
 *    hash. The genuine server answers success only for a frame it then holds at its position (a new append, or a
 *    byte-identical retry answered with its head), so this too is the server's word that it holds the frame: a log that
 *    shows another entry at the frame's position contradicts it, and the vault freezes. Until the log shows the frame,
 *    "cannot tell".
 *  - `none`: a head below the frame's position: no answer about it (a replayed answer, say).
 */
function headNamesFrame(head: { readonly seq: number; readonly hash: string }, frame: string): "frame" | "beyond" | "none" {
  const bytes = fromB64(frame);
  const parsed = parseLogEntry(bytes);
  if (!parsed.ok) return "none";
  const seq = parsed.value.entry.seq;
  if (head.seq < seq) return "none";
  return head.seq === seq && head.hash === toHexLower(sha256Sync(bytes)) ? "frame" : "beyond";
}

/**
 * Whether the server's own answer called [x] (a held record, or a change remembered after it was let go of) stored: it
 * named the frame itself (`acked`), or another head at or beyond its position (`beyond`). That word stays with the change
 * whatever becomes of its record: a refusal of a later re-send, a withdrawal, a give-up, a drop.
 */
function hasWord(x: { readonly acked?: true; readonly beyond?: unknown }): boolean {
  return x.acked === true || x.beyond !== undefined;
}

/** The position of [frame] where the verified log ([hashes]) holds another entry there; null where it holds the frame or nothing. */
function takenAt(hashes: ReadonlyMap<number, string>, frame: string): number | null {
  const bytes = fromB64(frame);
  const parsed = parseLogEntry(bytes);
  if (!parsed.ok) return null;
  const at = hashes.get(parsed.value.entry.seq);
  return at !== undefined && at !== toHexLower(sha256Sync(bytes)) ? parsed.value.entry.seq : null;
}

/**
 * What a move whose old vault's `delete` is held had done (design §3.13), kept beside that held frame so the move can be
 * finished after a reload: the new vault, each item copied (the old item's id, the revision copied, the copy's id in
 * the new vault, and the copy's own revision at the server as the server answered it, null when it named none), who
 * was added, and the half-made vault of an earlier run it replaces with the copies that run made in it (each copy's id
 * and its revision at the server; null when not known, as in a record kept before these were). No name and no content:
 * the names are read from the vaults themselves.
 */
export interface MoveRecord {
  readonly newVaultId: string;
  readonly copied: readonly (readonly [string, number, string, number | null])[];
  readonly added: readonly string[];
  readonly discard: string | null;
  readonly discardCopies: readonly (readonly [string, number | null])[] | null;
  /**
   * A run that stopped with no delete of the old vault held (design §3.13 as decided on 2026-11-18): kept at rest from the
   * moment it made its new vault, so the next move of the same vault after a lock, a reload or a closed tab finds the
   * half-made vault. Absent (false) for a record kept beside a held delete, and for one kept before this field was.
   */
  readonly stopped?: boolean;
  /** A removal the move signed on the old vault is stored: no later line says the old vault "wasn't changed". */
  readonly removed?: boolean;
  /**
   * The old vault froze while this move's deletion of it was held: the deletion was dropped and can never be sent, so the
   * move can never finish. The items are in the new vault; the old one stays as it is on this browser.
   */
  readonly oldFrozen?: boolean;
}

/** A copy's id and its revision at the server ([1] null when not known), or false when [c] is not one. */
function parseCopyEntry(c: unknown): readonly [string, number | null] | false {
  if (!Array.isArray(c) || c.length !== 2 || typeof c[0] !== "string") return false;
  return c[1] === null || Number.isSafeInteger(c[1]) ? [c[0], c[1] as number | null] : false;
}

function parseMoveRecord(t: string | null): MoveRecord | null {
  if (t === null) return null;
  try {
    const r = JSON.parse(t) as { newVaultId?: unknown; copied?: unknown; added?: unknown; discard?: unknown; discardCopies?: unknown; stopped?: unknown; removed?: unknown; oldFrozen?: unknown };
    if ((r.stopped !== undefined && typeof r.stopped !== "boolean") || (r.removed !== undefined && typeof r.removed !== "boolean") || (r.oldFrozen !== undefined && typeof r.oldFrozen !== "boolean")) return null;
    if (typeof r.newVaultId !== "string" || !Array.isArray(r.copied) || !Array.isArray(r.added) || !r.added.every((a) => typeof a === "string")) return null;
    if (r.discard !== null && typeof r.discard !== "string") return null;
    const copied: (readonly [string, number, string, number | null])[] = [];
    for (const c of r.copied as unknown[]) {
      // A record kept before the copy's own revision was: three fields, the copy's revision not known.
      if (!Array.isArray(c) || (c.length !== 3 && c.length !== 4) || typeof c[0] !== "string" || !Number.isSafeInteger(c[1]) || typeof c[2] !== "string") return null;
      const copyRev = c.length === 4 ? c[3] : null;
      if (copyRev !== null && !Number.isSafeInteger(copyRev)) return null;
      copied.push([c[0], c[1] as number, c[2], copyRev as number | null]);
    }
    let discardCopies: (readonly [string, number | null])[] | null = null;
    if (Array.isArray(r.discardCopies)) {
      discardCopies = [];
      for (const c of r.discardCopies as unknown[]) {
        const e = parseCopyEntry(c);
        if (e === false) return null;
        discardCopies.push(e);
      }
    } else if (r.discardCopies !== undefined && r.discardCopies !== null) return null;
    return {
      newVaultId: r.newVaultId,
      copied,
      added: r.added as string[],
      discard: r.discard as string | null,
      discardCopies,
      ...(r.stopped === true ? { stopped: true } : {}),
      ...(r.removed === true ? { removed: true } : {}),
      ...(r.oldFrozen === true ? { oldFrozen: true } : {}),
    };
  } catch {
    return null;
  }
}

export const MAX_PAGES = 1000;
/** How long an unresolved item-head chase holds off the next one while the verified head stays put. */
export const HINT_BACKOFF_MS = 10 * 60 * 1000;

const uuidV4 = (): string => {
  const b = randomBytes(16);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
};

/**
 * The account's vault record as a lower bound (§3.6 (e), §3.9): [record] names [s]'s genesis at a place above [s]'s
 * verified head, an entry the served log must still reach before this browser writes to the vault.
 */
const recordAboveHead = (record: VaultRecord | undefined, s: VaultState): boolean => record !== undefined && record.genesisHash === s.genesisHash && record.seq > s.head.seq;

/** The hashes held in [t], the stored text of a vault's hash map, by seq. */
function parseHashes(t: string | null): Map<number, string> {
  const out = new Map<number, string>();
  if (t === null) return out;
  try {
    for (const [seq, h] of Object.entries(JSON.parse(t) as Record<string, unknown>)) {
      const n = Number(seq);
      if (Number.isSafeInteger(n) && n >= 0 && typeof h === "string") out.set(n, h);
    }
  } catch {
    /* an unreadable map is an empty one: the next refresh replays from the genesis */
  }
  return out;
}

/** The lowest place at which [a] and [b] hold two different hashes, or null where they agree on every place both hold. */
function firstClash(a: ReadonlyMap<number, string>, b: ReadonlyMap<number, string>): number | null {
  let at: number | null = null;
  for (const [seq, h] of b) {
    const other = a.get(seq);
    if (other !== undefined && other !== h && (at === null || seq < at)) at = seq;
  }
  return at;
}

/** [stored] with every hash of [mine] that it lacks; [stored] itself where it lacks none. */
function joinedHashes(stored: Map<number, string>, mine: ReadonlyMap<number, string>): Map<number, string> {
  let out: Map<number, string> | null = null;
  for (const [seq, h] of mine) {
    if (stored.has(seq)) continue;
    out ??= new Map(stored);
    out.set(seq, h);
  }
  return out ?? stored;
}

/** How the read (or the finding) that a caller hands {@link VaultLogStore.writeStanding} ended. */
type StandingWrite =
  /**
   * Every entry served was verified. [servedSeq]: the head the server served; [short]: the caller's own read found the
   * served log below what it held (its hashes, or the account's record); [purgedAt]: the server's purge of the deletion
   * in force, or null.
   */
  | { readonly kind: "read"; readonly servedSeq: number; readonly short: boolean; readonly purgedAt: number | null }
  /** An entry did not verify, and it is no fork. */
  | { readonly kind: "failed"; readonly verdict: string }
  /** Two entries at [at]: the caller's state is the one at the entry before it. */
  | { readonly kind: "fork"; readonly at: number }
  /** The vault freezes at [at] for a reason found outside a read (the caller hands no state). */
  | { readonly kind: "frozen"; readonly at: number };

/** A vault's stored standing as {@link VaultLogStore.writeStanding} left it. */
interface Standing {
  readonly state: VaultState | null;
  readonly hashes: ReadonlyMap<number, string>;
  readonly flag: string;
  /** After a complete read: the joined state is above the served head, or the caller's read found the log short. */
  readonly short: boolean;
  /** The vault was not frozen before this write, and is now. */
  readonly frozeNow: boolean;
}

export class VaultLogStore {
  private readonly identityPub: Uint8Array;
  /** The vaults whose decline this session signed a leave for (the answer itself, or {@link leaveAgainForDeclines}). */
  private readonly declineLeftThisSession = new Set<string>();

  constructor(
    private readonly me: string,
    private readonly signer: KeyPairBytes,
    /** Borrowed: the account's X25519 identity key pair (a grant is sealed to it). */
    private readonly identity: KeyPairBytes,
    /** Borrowed: the session's UVK (self-wraps and the owner wrap of a new vault). */
    private readonly uvk: Uint8Array,
    private readonly wire: LogWire,
    private readonly storage: KeyValue,
    private readonly account: Pick<AccountStateStore, "local" | "update">,
    private readonly host: LogHost,
    /** The vault keys this session adopted; a verified removal drops the key. */
    private readonly keys: VaultKeyRing,
    private readonly clock: () => number = Date.now,
  ) {
    this.identityPub = identity.publicKey;
  }

  /** The store's one question before a change leaves this browser (Account.mayWrite); until attached, every vault may be written. */
  private writeGate: (vaultId: string) => boolean = () => true;

  /** Attaches {@link writeGate}, asked before every entry of a vault's log is posted ({@link postOnce}). */
  attachWriteGate(mayWrite: (vaultId: string) => boolean): void {
    this.writeGate = mayWrite;
  }

  /** The vaults whose held change a re-send left unsent this session because the gate said no (sent again after a pull). */
  private readonly heldByGate = new Set<string>();

  /** Whether a re-send left a held change unsent because the gate said no; true once, then forgotten until it happens again. */
  takeHeldByGate(): boolean {
    const any = this.heldByGate.size > 0;
    this.heldByGate.clear();
    return any;
  }

  private k(vaultId: string, part: string): string {
    return `andvari.log2.${this.me}.${vaultId}.${part}`;
  }

  private loadState(vaultId: string): VaultState | null {
    const t = this.storage.get(this.k(vaultId, "state"));
    const s = t === null ? null : decodeVaultState(t);
    return s !== null && s.vaultId === vaultId ? s : null;
  }

  /** The hash of every entry this browser verified, by seq. */
  hashes(vaultId: string): Map<number, string> {
    return parseHashes(this.storage.get(this.k(vaultId, "hashes")));
  }

  /**
   * A reader of [vaultId]'s stored hashes as they are at each call: another tab of the profile may store more between
   * two calls. The text is parsed again only when it changed.
   */
  private storedHashes(vaultId: string): () => ReadonlyMap<number, string> {
    let text: string | null | undefined;
    let map: ReadonlyMap<number, string> = new Map();
    return () => {
      const t = this.storage.get(this.k(vaultId, "hashes"));
      if (t !== text) {
        text = t;
        map = parseHashes(t);
      }
      return map;
    };
  }

  /** Flags: "", "failed:<verdict>", "frozen:<seq>", "withheld:<seq>", "purged:<at>". Frozen is sticky. */
  private flag(vaultId: string): string {
    return this.storage.get(this.k(vaultId, "flag")) ?? "";
  }

  /**
   * The one writer of [vaultId]'s stored standing: its verified state, the hashes of its verified entries and its flag,
   * which every tab of the profile writes. In one step, with no wait between its read and its write, it reads what is
   * stored now and joins it with what the caller verified ([mine]; null for a caller that verified nothing, as a freeze
   * found outside a read), so that a tab whose read began before another tab stored more never lowers what that tab
   * stored (decided on 24 November 2026):
   *
   * - of two states of one genesis, the one with the higher head stands;
   * - every hash of both stands; two different hashes at one place are two entries this browser verified at one place,
   *   and the vault freezes at the lowest such place, what is stored being kept as it is;
   * - a caller's state of another genesis than the stored one freezes the vault at 0, and what is stored is kept;
   * - the one lowering: a read that found a fork ([how] `fork`) leaves the state at the entry before it, and it is
   *   written in the same step as the frozen flag (a frozen flag stays: it is sticky);
   * - a read that ended in an entry that does not verify, and is no fork, lowers nothing: the joined state, and its flag;
   * - after a complete read the flag is decided from the joined result against the head the server served: a joined
   *   head above it reads as withheld, also where the caller's own read verified everything it was served.
   *
   * Only what changed is written. Returns the joined standing, which the caller goes on with.
   */
  private writeStanding(vaultId: string, mine: { readonly state: VaultState | null; readonly hashes: ReadonlyMap<number, string> } | null, how: StandingWrite): Standing {
    const stored = this.loadState(vaultId);
    const storedHashes = this.hashes(vaultId);
    const flagNow = this.flag(vaultId);
    let state = stored;
    let hashes = storedHashes;
    let frozenAt: number | null = how.kind === "fork" || how.kind === "frozen" ? how.at : null;
    if (mine !== null) {
      const otherGenesis = stored !== null && mine.state !== null && mine.state.genesisHash !== stored.genesisHash;
      const clash = otherGenesis ? 0 : firstClash(storedHashes, mine.hashes);
      if (clash !== null) frozenAt = frozenAt === null ? clash : Math.min(frozenAt, clash);
      else {
        hashes = joinedHashes(storedHashes, mine.hashes);
        if (mine.state !== null && (how.kind === "fork" || stored === null || mine.state.head.seq > stored.head.seq)) state = mine.state;
      }
    }
    const head = state?.head.seq ?? -1;
    const short = how.kind === "read" && (how.short || head > how.servedSeq);
    let flag: string;
    if (flagNow.startsWith("frozen:")) flag = flagNow;
    else if (frozenAt !== null) flag = `frozen:${frozenAt}`;
    else if (how.kind === "failed") flag = `failed:${how.verdict}`;
    else if (how.kind !== "read") flag = flagNow;
    else if (short) flag = `withheld:${how.servedSeq}`;
    else flag = how.purgedAt !== null && state !== null && state.deleteId !== null && how.servedSeq === head ? `purged:${how.purgedAt}` : "";
    if (state !== null && state !== stored) this.storage.set(this.k(vaultId, "state"), encodeVaultState(state));
    if (hashes !== storedHashes) this.storage.set(this.k(vaultId, "hashes"), JSON.stringify(Object.fromEntries(hashes)));
    if (flag !== flagNow) {
      if (flag === "") this.storage.remove(this.k(vaultId, "flag"));
      else this.storage.set(this.k(vaultId, "flag"), flag);
    }
    return { state, hashes, flag, short, frozeNow: flag.startsWith("frozen:") && !flagNow.startsWith("frozen:") };
  }

  /**
   * The log's standing here (§3.9): what the last read left (its flags and verified state) and, for a log that read
   * verified, the account's record of the vault as stored at this moment. A record of this log's genesis above the
   * verified head names an entry the served log must still reach, so such a log reads as withheld, whatever its flag
   * says: the flag and the record live in the profile's storage, which every tab writes, and a tab whose read began
   * before a higher record landed may clear the flag another tab set (decided on 23 November 2026). Every write gate
   * asks this ({@link writeAllowed}, the store's `mayWrite`, the re-posts of held entries), and so does every screen.
   */
  status(vaultId: string): LogStatus {
    const st = this.lastReadStatus(vaultId);
    if (st.kind !== "verified" || !this.belowRecord(vaultId, st.state)) return st;
    return { kind: "withheld", vaultId, state: st.state, servedSeq: null };
  }

  /**
   * Whether the account's record of [vaultId], read from the account's stored document now, names [s]'s genesis at a
   * place above [s]'s head. The one place this is decided ({@link refresh} asks it too). An account document that
   * cannot be read here holds no record, as one whose local copy does not open reads as empty ({@link AccountStateStore.local}).
   */
  private belowRecord(vaultId: string, s: VaultState): boolean {
    let record: VaultRecord | undefined;
    try {
      record = this.account.local().vaults.get(vaultId);
    } catch {
      record = undefined;
    }
    return recordAboveHead(record, s);
  }

  /** The log's standing as the last read left it (its flags and verified state), without the account's record. */
  private lastReadStatus(vaultId: string): LogStatus {
    const s = this.loadState(vaultId);
    const f = this.flag(vaultId);
    const num = (p: string): number | null => {
      const n = Number(f.slice(p.length));
      return f.length > p.length && Number.isSafeInteger(n) ? n : null;
    };
    if (s === null) return f.startsWith("failed:") ? { kind: "failed", vaultId, state: null, verdict: f.slice(7) } : { kind: "unknown", vaultId };
    if (f.startsWith("frozen:")) return { kind: "frozen", vaultId, state: s, atSeq: num("frozen:") ?? s.head.seq };
    if (f.startsWith("failed:")) return { kind: "failed", vaultId, state: s, verdict: f.slice(7) };
    if (f.startsWith("withheld:")) return { kind: "withheld", vaultId, state: s, servedSeq: num("withheld:") };
    if (f.startsWith("purged:")) return { kind: "purged", vaultId, state: s, purgedAt: num("purged:") ?? 0 };
    if (!(this.me in s.members)) return { kind: "removed", vaultId, state: s, byOwner: this.storage.get(this.k(vaultId, "removedBy")) === "owner" };
    return { kind: "verified", vaultId, state: s, mayBeIncomplete: this.storage.get(this.k(vaultId, "hint")) === "1" };
  }

  /** The server's `deleted` record: the grace end it served beside the verified `delete` named by `deleteId`. */
  private graceRecord(vaultId: string): ({ deleteId: string } & LogDeleted) | null {
    const t = this.storage.get(this.k(vaultId, "grace"));
    if (t === null) return null;
    try {
      const g = JSON.parse(t) as { deleteId?: unknown };
      const d = readLogDeleted(g);
      return d !== null && typeof g.deleteId === "string" ? { deleteId: g.deleteId, ...d } : null;
    } catch {
      return null;
    }
  }

  /**
   * Keeps the server's [served] `deleted` beside [verified]'s standing `delete`, only when [head] (the answer's head) is
   * the verified head itself; drops a kept value once the verified state has no standing `delete`. [replace] false keeps
   * a value already kept for that `delete` (an append's answer yields to the refetch that followed it). Core
   * `StoredVaultLogs.noteGrace` twin. Nothing here reads it back except {@link serverGraceEnd}: no decision depends on it.
   */
  private noteGrace(verified: VaultState, head: { seq: number; hash: string }, served: LogDeleted | null, replace: boolean): void {
    const key = this.k(verified.vaultId, "grace");
    const deleteId = verified.deleteId;
    if (deleteId === null) {
      this.storage.remove(key);
      return;
    }
    if (served === null || head.seq !== verified.head.seq || head.hash !== verified.head.hash) return;
    if (!replace && this.graceRecord(verified.vaultId)?.deleteId === deleteId) return;
    this.storage.set(key, JSON.stringify({ deleteId, deletedAt: served.deletedAt, purgeAt: served.purgeAt }));
  }

  /**
   * The server's `deleted` for [vaultId] (spec 03 §10.3, §10.6), kept beside the `delete` this browser verified: answered
   * only while the stored verified state ends in that standing `delete` (never after a `restore`, nor for a later
   * `delete`). Null on an older server, before any answer carried it, or when the record cannot be read: the caller then
   * shows what it showed before. The server's word, for the "restorable until" a screen shows and nothing else.
   */
  serverGraceEnd(vaultId: string): LogDeleted | null {
    const g = this.graceRecord(vaultId);
    const deleteId = this.loadState(vaultId)?.deleteId ?? null;
    return g !== null && deleteId !== null && g.deleteId === deleteId ? { deletedAt: g.deletedAt, purgeAt: g.purgeAt } : null;
  }

  /** Every page after [after] (null: from the genesis) up to the served head, or null when unreachable. */
  private async fetchFrom(vaultId: string, after: number | null): Promise<{ frames: (Uint8Array | null)[]; page: LogPage } | null> {
    const frames: (Uint8Array | null)[] = [];
    let cursor = after;
    for (let pages = 0; ; pages++) {
      let page: LogPage;
      try {
        page = await this.wire.logPage(vaultId, cursor);
      } catch {
        return null;
      }
      for (const e of page.entries) frames.push(fromB64Canonical(e));
      const last = cursor === null ? page.entries.length - 1 : cursor + page.entries.length;
      if (page.entries.length === 0 || last >= page.head.seq || pages + 1 >= MAX_PAGES) return { frames, page };
      cursor = last;
    }
  }

  /**
   * Fetch and verify everything after the verified head (§3.9). [servedSeq]/[servedHash] are a head the server named
   * elsewhere (sync's vault row): when it equals the verified head nothing is fetched, unless [force].
   */
  async refresh(vaultId: string, servedSeq: number | null = null, servedHash: string | null = null, force = false, seen?: { read: boolean }): Promise<LogStatus> {
    let s = this.loadState(vaultId);
    const genesis = s?.genesisHash ?? null;
    // A flag one answer set (the newest entries withheld, an entry that did not verify) does not outlive the next full
    // read: while it stands, the read is never skipped because the served head equals the one held.
    const flagged = this.flag(vaultId).startsWith("withheld:") || this.flag(vaultId).startsWith("failed:");
    const record = this.account.local().vaults.get(vaultId);
    // The account's vault record is a lower bound too (§3.6 (e), §3.9): a record of this log's genesis above the verified
    // head, read from the account's state after this browser's last fetch, is one the served log must still reach. No
    // shortcut then: the log is read, and found withheld where the server serves less.
    const belowRecord = s !== null && recordAboveHead(record, s);
    if (!force && !flagged && !belowRecord && s !== null && servedSeq === s.head.seq && servedHash === s.head.hash) return this.status(vaultId);
    const hashes = this.hashes(vaultId);
    const known = new Map(hashes);
    if (record && s && record.genesisHash !== s.genesisHash) {
      this.freeze(vaultId, 0, null);
      return this.status(vaultId);
    }
    if (record && !known.has(record.seq)) known.set(record.seq, record.hash);
    // What the served entries are verified against: the hashes stored at the moment of each lookup first (another tab of
    // this profile may have stored more while this read waited: an entry served at a place where that tab stored another
    // verified hash is a fork), then what this read began with and verified itself.
    const storedNow = this.storedHashes(vaultId);
    const held = (seq: number): string | undefined => storedNow().get(seq) ?? known.get(seq);
    let fetched = await this.fetchFrom(vaultId, s?.head.seq ?? null);
    if (fetched === null) return this.status(vaultId);
    const servedAtHeld = held(fetched.page.head.seq);
    if (s !== null && fetched.page.head.seq <= s.head.seq && servedAtHeld !== undefined && servedAtHeld !== fetched.page.head.hash) {
      // The server names another entry at a position this browser verified: replay from the genesis with every held
      // hash, so two validly signed entries at one position come out as `fork`.
      fetched = await this.fetchFrom(vaultId, null);
      if (fetched === null) return this.status(vaultId);
      s = null;
    }
    // The account's record as stored now, after the fetch: another tab of this profile may have read a higher one while
    // this read was out. Its hash is held like the first one's, so a served log that holds another entry at its place
    // freezes here instead of being verified past it (and the record is then not replaced by this read's head).
    const recordNow = this.account.local().vaults.get(vaultId);
    if (recordNow && (genesis === null || recordNow.genesisHash === genesis) && !known.has(recordNow.seq)) known.set(recordNow.seq, recordNow.hash);
    const heldSeq = Math.max(s?.head.seq ?? -1, ...known.keys(), -1);
    for (const frame of fetched.frames) {
      const step = frame === null ? ({ ok: false, verdict: "bad_frame" } as const) : verifyLogEntry(vaultId, s, frame, held);
      if (!step.ok) {
        // A fork freezes the vault at its place and leaves the state at the entry before it (the one lowering, written
        // with the frozen flag); any other entry that does not verify lowers nothing.
        const fork = step.verdict === "fork";
        const at = (s?.head.seq ?? -1) + 1;
        const w = this.writeStanding(vaultId, { state: s, hashes }, fork ? { kind: "fork", at } : { kind: "failed", verdict: step.verdict });
        if (fork || w.frozeNow) this.forgetFrozen(vaultId, null);
        return this.status(vaultId);
      }
      s = step.value.state;
      hashes.set(step.value.entry.seq, step.value.hash);
      known.set(step.value.entry.seq, step.value.hash);
      await this.onVerifiedEntry(vaultId, step.value.entry, s);
    }
    if (s === null) return this.status(vaultId);
    const page = fetched.page;
    // Joined with what is stored now: a higher state another tab stored stands, and this read goes on with the joined
    // state and hashes (a joined head above the served head is withheld, and the read ends here).
    const w = this.writeStanding(vaultId, { state: s, hashes }, { kind: "read", servedSeq: page.head.seq, short: s.head.seq < heldSeq || page.head.seq < s.head.seq, purgedAt: page.purged?.purgedAt ?? null });
    if (w.frozeNow) this.forgetFrozen(vaultId, null);
    if (w.state === null || w.frozeNow) return this.status(vaultId);
    this.noteGrace(w.state, page.head, page.deleted, true);
    if (w.short) return this.status(vaultId);
    // [seen]: the log was read from the server and verified to the head it served, nothing withheld.
    if (seen !== undefined) seen.read = true;
    // A change the server's own answer called stored, and another entry at its position in the log as verified now: the
    // server contradicted its own word, and the vault freezes at THIS read, whether or not anything touches that change
    // later (a look, a re-send, a withdrawal, a move's step). Nothing is said of the change, and it is dropped (freeze).
    this.freezeWhereContradicted(vaultId, w.hashes);
    // A verified removal ends every write here at once (writeAllowed reads the members). The key itself is the
    // session's to drop: it first moves the vault's rows to the holding area, which re-seals them under that key.
    // §3.6 (e): a record is written when this browser adopts the vault or records the person's answer, never
    // because the server listed a log; once it exists it follows the verified head, batched.
    if (this.keys.has(vaultId) || this.account.local().vaults.get(vaultId)) await this.writeVaultRecord(w.state);
    return this.status(vaultId);
  }

  /**
   * After a complete verified read of [vaultId]'s log ([hashes]): the change held for it, and each change withdrawn or
   * given up that is still looked for ({@link checkWatched}), is checked against the log. Where the server's own answer
   * called it stored (its head named the frame at its position, or lay beyond it: spec 03 §10.3 answers a byte-identical
   * frame it holds with its head) and the log holds another entry at that position, the vault is frozen there
   * ({@link freeze}). True when something was found so.
   */
  private freezeWhereContradicted(vaultId: string, hashes: ReadonlyMap<number, string>): boolean {
    const p = this.pendingFor(vaultId);
    const words: string[] = [];
    if (p !== null && hasWord(p)) words.push(p.frame);
    for (const w of this.watchesOf(vaultId)) if (w.made !== true && hasWord(w)) words.push(w.frame);
    let found = false;
    for (const frame of words) {
      const at = takenAt(hashes, frame);
      if (at === null) continue;
      this.freeze(vaultId, at, toHexLower(sha256Sync(fromB64(frame))));
      found = true;
    }
    return found;
  }

  /**
   * The vault is frozen at [at], for good (two stories about one position: a fork, or the server's answer about a change
   * against its log). Its held change is dropped and never sent, shown or asked about (a move's own deletion leaves its
   * move marked, {@link MoveRecord.oldFrozen}, for the move's own line). Where [hash] names the change whose answer the
   * log contradicts, nothing is said of that change: its memory ends, and a "its place was taken" kept for it is taken back.
   */
  private freeze(vaultId: string, at: number, hash: string | null): void {
    this.writeStanding(vaultId, null, { kind: "frozen", at });
    this.forgetFrozen(vaultId, hash);
  }

  /** What a freeze at [vaultId] ends: its held change, and where [hash] names a change, that change's memory ({@link freeze}). */
  private forgetFrozen(vaultId: string, hash: string | null): void {
    this.dropFrozenHeld(vaultId);
    if (hash === null) return;
    const watches = this.watchesOf(vaultId);
    const rest = watches.filter((w) => !(w.hash === hash && w.made !== true));
    if (rest.length !== watches.length) this.saveWatches(vaultId, rest);
    const settled = this.settledOf(vaultId);
    const kept = settled.filter((r) => !(r.outcome.kind === "head_moved" && toHexLower(sha256Sync(fromB64(r.pending.frame))) === hash));
    if (kept.length !== settled.length) this.saveSettled(vaultId, kept);
  }

  /** Whether [vaultId] is frozen on this browser. */
  private frozen(vaultId: string): boolean {
    return this.flag(vaultId).startsWith("frozen:");
  }

  /**
   * Drops the change held for a frozen vault (at the freeze, and for a record kept at rest from before this rule, at the
   * first look at it): it is never sent, shown or asked about again. A move's own deletion marks its move.
   */
  private dropFrozenHeld(vaultId: string): void {
    const t = this.storage.get(this.k(vaultId, "pending"));
    if (t === null && !this.pendingVaults().includes(vaultId)) return;
    let forMove = false;
    try {
      forMove = t !== null && (JSON.parse(t) as { forMove?: unknown }).forMove === true;
    } catch {
      forMove = false;
    }
    this.savePending(null, vaultId);
    const rec = forMove ? this.moveRecord(vaultId) : null;
    if (rec !== null && rec.stopped !== true && rec.oldFrozen !== true) this.saveMoveRecord(vaultId, { ...rec, oldFrozen: true });
  }

  /**
   * The writer rule of §5.4: a verified leave or remove of this account declines its latest add. A record for a
   * HIGHER add (a later re-add this account answered) is never rolled back by an older leave replayed.
   */
  private async onVerifiedEntry(vaultId: string, entry: LogEntry, after: VaultState): Promise<void> {
    // §3.3: a `cancel` signed by the person the offer was made to is their refusal. The owner who asked is told once
    // (refusedOffer), until they dismiss it or make another offer.
    if (entry.kind === "cancel") {
      if (entry.actor !== after.owner && after.owner === this.me) this.storage.set(this.k(vaultId, "offerRefused"), JSON.stringify({ by: entry.actor, at: entry.at }));
      else this.storage.remove(this.k(vaultId, "offerRefused"));
    }
    if (entry.kind === "offer" || entry.kind === "accept") this.storage.remove(this.k(vaultId, "offerRefused"));
    const goneMe = (entry.kind === "leave" && entry.actor === this.me) || (entry.kind === "remove" && entry.member === this.me);
    if (!goneMe) return;
    this.storage.set(this.k(vaultId, "removedBy"), entry.kind === "remove" ? "owner" : "self");
    const addSeq = latestAddSeq(after, this.me) ?? 0;
    const held = this.account.local().accepted.get(vaultId);
    if (held && held.addSeq > addSeq) return;
    await this.account.update((doc: AccountDocument) => {
      const cur = doc.accepted.get(vaultId);
      if (cur && (cur.addSeq > addSeq || (cur.addSeq === addSeq && cur.decision === "decline"))) return doc;
      return withAccepted(doc, { vaultId, owner: after.owner, addSeq, at: this.clock(), decision: "decline" });
    });
  }

  /**
   * §3.6 for [vaultId], against every key source this browser holds for it: first this account's own wrap (an
   * owner wrap or a member self-wrap, opened under the UVK with the AD that names THIS log's genesis), then the
   * grant on its row. A key that passes is put in the session's key ring; a grant from a current contact that was
   * not answered yet is the acceptance prompt; one from anyone else is "connect with them first".
   */
  async adoption(vaultId: string): Promise<Adoption> {
    const s = this.loadState(vaultId);
    if (s === null || this.flag(vaultId).startsWith("failed:")) return { kind: "refused", vaultId, reason: "log_not_verified" };
    const hashes = this.hashes(vaultId);
    const served: string[] = [];
    for (let i = 0; i <= s.head.seq; i++) served.push(hashes.get(i) ?? "");
    const doc = this.account.local();
    const row = this.host.grantRow(vaultId);
    const record = doc.vaults.get(vaultId) ?? null;
    const accepted = doc.accepted.get(vaultId) ?? null;
    const log = this.status(vaultId);
    const w = await checkWrap(this.me, this.uvk, s, served, row !== null && row.wrappedVk !== "" ? row.wrappedVk : null, record, accepted, log);
    if (w.adopt) return this.adopted(s, w.vk, w.source);
    if (row === null || row.signedGrant === null) return this.refusal(vaultId, w.failed, s, served, record, log);
    // Served text: one that is not canonical base64url is a refused grant, never an exception.
    const sealed = fromB64Canonical(row.signedGrant);
    if (sealed === null) return { kind: "refused", vaultId, reason: "grant_refused" };
    const g = await openVaultGrant({ userId: this.me, identityPub: this.identity.publicKey, identityPriv: this.identity.privateKey }, vaultId, sealed, s);
    if (!g.ok) return { kind: "refused", vaultId, reason: "grant_refused" };
    const opened = g.value;
    try {
      const actor = opened.add.actor;
      if (!this.host.isCurrentContact(actor, opened.add.ownerKey)) return { kind: "connect_first", vaultId, serverName: this.host.serverOwnerName(vaultId) };
      const c = await checkGrant(this.me, s, served, opened, true, record, accepted, log);
      if (c.adopt) {
        // A key taken read-only (a log withheld or frozen here) posts no wrap: nothing is sent for such a vault.
        if (log.kind === "verified") await this.postSelfWrap(vaultId, s, c.vk);
        return this.adopted(s, c.vk, "grant");
      }
      if (c.failed.length === 1 && c.failed[0] === "d" && opened.add.seq === latestAddSeq(s, this.me)) {
        if (accepted !== null && accepted.addSeq === opened.add.seq && accepted.decision === "decline") return { kind: "declined", vaultId };
        // (a) to (c) passed and the sender is a current contact: only now is the name decrypted, as plain text.
        const vaultName = this.host.vaultName(vaultId, opened.vk) ?? "";
        return { kind: "ask", vaultId, owner: actor, ownerLabel: this.host.labelFor(actor, opened.add.ownerKey) ?? "", vaultName, addSeq: opened.add.seq };
      }
      return this.refusal(vaultId, c.failed, s, served, record, log);
    } finally {
      opened.vk.fill(0);
    }
  }

  /**
   * A vault whose log is withheld or frozen on this browser (§3.6 (e), decided on 23 November 2026): its key is decided
   * as for a verified vault, from the LAST VERIFIED state, with the log's status as an input ({@link checkWrap},
   * {@link checkGrant}). The account's record ahead of a withheld log, or beside a log frozen after its genesis, gives the
   * key read-only; a record that agrees, or none, gives it as well; a record of another genesis, a log frozen at its
   * genesis against a record that does not agree, and every other failing condition give none. The vault is read-only
   * for as long as the log is not verified: every write asks for a verified log. Only the key is decided here: nothing
   * is asked of the person, no wrap is posted, and the account's record is only ever raised (never lowered).
   *
   * [online] false (a reload's copy, nothing fetched): only this account's own wrap is tried, and nothing is written.
   * true: the grant on the row too, and the record is written where due ({@link adopted}). Null where the log is neither
   * withheld nor frozen, where no key is taken, and where the person left a frozen vault and the server took the leave
   * ({@link ownFrozenLeaveTaken}): a server that goes on serving the row does not bring back a vault the person was told
   * they left.
   */
  async readOnlyAdoption(vaultId: string, online: boolean): Promise<Adoption | null> {
    const st = this.status(vaultId);
    if (st.kind !== "withheld" && st.kind !== "frozen") return null;
    const s = st.state;
    if (this.keys.has(vaultId)) return { kind: "adopted", vaultId, source: s.owner === this.me ? "owner_wrap" : "self_wrap" };
    if (st.kind === "frozen" && this.ownFrozenLeaveTaken(vaultId)) return null;
    const served = this.servedOf(vaultId, s);
    const doc = this.account.local();
    const record = doc.vaults.get(vaultId) ?? null;
    const accepted = doc.accepted.get(vaultId) ?? null;
    const row = this.host.grantRow(vaultId);
    const w = await checkWrap(this.me, this.uvk, s, served, row !== null && row.wrappedVk !== "" ? row.wrappedVk : null, record, accepted, st);
    if (w.adopt) {
      if (online) return this.adopted(s, w.vk, w.source);
      this.keys.set(vaultId, w.vk, memberAddOf(s, this.me));
      return { kind: "adopted", vaultId, source: w.source };
    }
    if (!online || row === null || row.signedGrant === null) return null;
    const sealed = fromB64Canonical(row.signedGrant);
    if (sealed === null) return null;
    const g = await openVaultGrant({ userId: this.me, identityPub: this.identity.publicKey, identityPriv: this.identity.privateKey }, vaultId, sealed, s);
    if (!g.ok) return null;
    const opened = g.value;
    try {
      if (!this.host.isCurrentContact(opened.add.actor, opened.add.ownerKey)) return null;
      const c = await checkGrant(this.me, s, served, opened, true, record, accepted, st);
      return c.adopt ? this.adopted(s, c.vk, "grant") : null;
    } finally {
      opened.vk.fill(0);
    }
  }

  /** The hash of each entry of [s] this browser verified, from the genesis to its head ("" where one is missing). */
  private servedOf(vaultId: string, s: VaultState): string[] {
    const hashes = this.hashes(vaultId);
    const served: string[] = [];
    for (let i = 0; i <= s.head.seq; i++) served.push(hashes.get(i) ?? "");
    return served;
  }

  /**
   * A frozen vault's key through this account's own wrap on its row, against its last verified state [s], only to seal
   * the held copy of its removal ({@link keyToSealHeldCopy}); null where none opens. It lists nothing and opens nothing.
   */
  private async frozenOwnWrap(vaultId: string, s: VaultState): Promise<{ vk: Uint8Array; source: "owner_wrap" | "self_wrap" | "grant" } | null> {
    const row = this.host.grantRow(vaultId);
    if (row === null || row.wrappedVk === "") return null;
    const hashes = this.hashes(vaultId);
    const served: string[] = [];
    for (let i = 0; i <= s.head.seq; i++) served.push(hashes.get(i) ?? "");
    const w = await checkWrap(this.me, this.uvk, s, served, row.wrappedVk, null, this.account.local().accepted.get(vaultId) ?? null);
    return w.adopt ? { vk: w.vk, source: w.source } : null;
  }

  /** The first failing condition, by the design's order; a failing (e) says how it failed ({@link recordRefusal}). */
  private refusal(vaultId: string, failed: readonly AdoptCondition[], s: VaultState, served: readonly string[], record: VaultRecord | null, log: LogStatus): Adoption {
    const reason: AdoptionRefusal = failed.includes("a")
      ? "log_not_verified"
      : failed.includes("b")
        ? "not_a_member"
        : failed.includes("c")
          ? "vk_commit_mismatch"
          : failed.includes("e")
            ? recordRefusal(s, served, record, log)
            : "no_key";
    return { kind: "refused", vaultId, reason };
  }

  private async adopted(s: VaultState, vk: Uint8Array, source: "owner_wrap" | "self_wrap" | "grant"): Promise<Adoption> {
    // Every key that reaches here matched the commitment fixed at genesis, so one already held is the same key. It keeps
    // the `add` it was adopted under: a later adoption never moves that number on (only a removal carried out takes the
    // key out, and a key adopted again after it carries its new `add`).
    if (this.keys.has(s.vaultId)) vk.fill(0);
    else this.keys.set(s.vaultId, vk, memberAddOf(s, this.me));
    // Adopting writes the account's vault record (§3.6 (e)); nothing is written when it is already current.
    await this.writeVaultRecord(s);
    return { kind: "adopted", vaultId: s.vaultId, source };
  }

  /**
   * After adopting from a grant: post the key wrapped under the UVK with the genesis-bound AD (spec 03 §11.4), so the
   * account's other devices adopt through the wrap. A failed post changes nothing here: the grant path runs again at
   * the next sync, and posts again.
   */
  private async postSelfWrap(vaultId: string, s: VaultState, vk: Uint8Array): Promise<void> {
    if (s.owner === this.me) return;
    try {
      await this.wire.putSelfWrap(vaultId, toB64(seal(this.uvk, vk, adVkShared(vaultId, this.me, s.genesisHash))));
    } catch {
      /* retried by the next adoption through the grant */
    }
  }

  /**
   * The person's answer to an incoming vault (T-R4). The prompt is derived again from this browser's own verified
   * state: only the vault id, the `add` and the owner the person was shown are taken from the caller, and an answer
   * to a prompt that no longer stands changes nothing. Accept records `accepted` for that `add` and adopts; decline
   * records it and signs a `leave`, so the owner sees it and the server revokes the grant.
   */
  async answerIncoming(ask: { readonly vaultId: string; readonly addSeq: number; readonly owner: string }, accept: boolean): Promise<Adoption> {
    const fresh = await this.adoption(ask.vaultId);
    if (fresh.kind !== "ask" || fresh.addSeq !== ask.addSeq || fresh.owner !== ask.owner) return fresh;
    // §3.6 (a) "the log verifies": an accept adopts only from a log that is verified now. A vault that
    // turned withheld or frozen after the prompt was shown adopts nothing; a decline (a leave) is still signed.
    const unverified = (): Adoption | null => (accept && this.status(ask.vaultId).kind !== "verified" ? { kind: "refused", vaultId: ask.vaultId, reason: "log_not_verified" } : null);
    const early = unverified();
    if (early) return early;
    const s = this.loadState(ask.vaultId);
    if (s === null) return { kind: "refused", vaultId: ask.vaultId, reason: "log_not_verified" };
    // Recording the answer writes the vault record too, so a re-add of the same vault is checked against this genesis.
    const w = await this.account.update((doc) =>
      withVaultHead(withAccepted(doc, { vaultId: ask.vaultId, owner: fresh.owner, addSeq: fresh.addSeq, at: this.clock(), decision: accept ? "accept" : "decline" }), ask.vaultId, s.genesisHash, s.head.seq, s.head.hash),
    );
    const recorded = w.kind === "written" || w.kind === "unchanged";
    if (recorded) this.storage.set(this.k(ask.vaultId, "recordAt"), String(this.clock()));
    if (!accept) {
      // The leave is the decline: it is signed whether or not the record could be written (an account state that
      // is unreachable, full or damaged must not make a vault impossible to refuse). Its frame is kept in the
      // pending-append record until it is seen in the verified log, and verifying it writes the record again.
      // What became of the leave is said: stored (the owner sees the decline), held and sent again at the next unlock,
      // or not stored and not held (the owner may still see this account as invited).
      this.declineLeftThisSession.add(ask.vaultId);
      const left = await this.append(ask.vaultId, { kind: "leave" });
      const leave = left.kind === "appended" || (left.kind === "pending" && left.known === "stored") ? "stored" : left.kind === "pending" ? "waiting" : "not_stored";
      // A vault frozen here: nothing of the leave is held or sent again, so its line promises nothing of the kind, and it
      // says what this browser knows: the server named the leave as stored, refused it (or it was never sent), or no
      // answer told.
      if (left.kind === "read_only" && left.frozen !== undefined) {
        const known = left.leave ?? (left.frozen === "unsent" ? "refused" : left.known === "stored" ? "stored" : left.known === "not_stored" ? "refused" : "unknown");
        return { kind: "declined", vaultId: ask.vaultId, leave: known === "stored" ? "stored" : "not_stored", frozen: known };
      }
      return { kind: "declined", vaultId: ask.vaultId, leave };
    }
    // An accept that is not in the account state adopts nothing: (d) needs the record. The person is asked again.
    // [reason] "unknown" only for a write that went out and whose outcome cannot be told: it may be saved.
    if (!recorded) return { kind: "not_recorded", vaultId: ask.vaultId, reason: w.kind === "refused" ? w.code : w.kind === "unknown" ? (w.sent ? "unknown" : "unreachable") : w.kind, ...(w.kind === "unknown" ? { outcomeNotKnown: true as const } : {}) };
    return unverified() ?? this.adoption(ask.vaultId); // The log may have turned while the answer was written
  }

  /**
   * Once per unlock, after the first sync: a decline whose leave never got through is carried out again. For every vault
   * this account declined (its own account record), where the log, read afresh now, still lists this account as a member
   * through the very `add` it declined, the leave is signed again; once per session, and not where a leave is already
   * held (that one is sent again as it is). Where the log no longer lists this account, or lists it through a later
   * `add` (a new invitation, asked anew), nothing is signed. Nothing is said of it: the decline's own line said that the
   * owner may still see the invitation until it goes through. Never throws.
   */
  async leaveAgainForDeclines(): Promise<AppendOutcome[]> {
    const out: AppendOutcome[] = [];
    const memberThrough = (vaultId: string, addSeq: number): boolean => this.loadState(vaultId)?.members[this.me]?.addSeq === addSeq;
    for (const rec of [...this.account.local().accepted.values()]) {
      const v = rec.vaultId;
      if (rec.decision !== "decline" || this.declineLeftThisSession.has(v) || !memberThrough(v, rec.addSeq) || this.pendingFor(v) !== null) continue;
      try {
        await this.refresh(v, null, null, true);
        if (!memberThrough(v, rec.addSeq) || this.pendingFor(v) !== null) continue;
        this.declineLeftThisSession.add(v);
        out.push(await this.append(v, { kind: "leave" }));
      } catch {
        /* tried again at the next unlock */
      }
    }
    return out;
  }

  /** This account's role in the verified log (`owner`, `writer`, `reader`), or null when it is not a member there. */
  roleOf(vaultId: string): VaultRole | null {
    return this.loadState(vaultId)?.members[this.me]?.role ?? null;
  }

  /**
   * The key of a vault this browser holds but has not opened, taken through this account's own wrap on its grant row as
   * last held here, ONLY to seal the held copy of the vault's removal: a vault whose removal this browser verified and
   * did not carry out (its page closed part-way), one whose removal this account's record learned on another device first
   * (so the record no longer lets the key be adopted), or one frozen here that the person left here. For a vault that is
   * not frozen the wrap is checked against the verified log's key commitment, fixed at the genesis; for a frozen one
   * against its last verified state. The key is handed to the caller and never put in the session's key ring: by itself
   * it lists no vault, opens no item for show and allows no write. Null where no own wrap opens.
   */
  async keyToSealHeldCopy(vaultId: string): Promise<Uint8Array | null> {
    const st = this.status(vaultId);
    // A frozen vault's key comes from the wrap the account's record keeps; where that does not open, this account's own
    // wrap on its grant row is tried as for any other vault (the key only re-seals the held copy here, never anything sent).
    if (st.kind === "frozen") {
      const kept = (await this.frozenOwnWrap(vaultId, st.state))?.vk ?? null;
      if (kept !== null) return kept;
    }
    const row = this.host.grantRow(vaultId);
    if (row === null || row.wrappedVk === "") return null;
    return this.openOwnWrap(vaultId, row.wrappedVk);
  }

  /** Whether the last removal of this account that this browser verified in [vaultId]'s log was the owner's (else its own leave). */
  lastRemovalByOwner(vaultId: string): boolean {
    return this.storage.get(this.k(vaultId, "removedBy")) === "owner";
  }

  /**
   * This account's own wrap of [vaultId]'s key under its UVK, bound to the verified log's genesis (the self-wrap's AD,
   * §3.6), for the holding area (§3.8, §3.12): taken before the key leaves the ring at a removal, so items can still be
   * copied out of the held copy; {@link openOwnWrap} opens it again and checks it against the key commitment. Null
   * without a verified state or a key.
   */
  wrapForHolding(vaultId: string): string | null {
    const s = this.loadState(vaultId);
    const vk = this.keys.get(vaultId);
    if (s === null || !vk) return null;
    return toB64(seal(this.uvk, vk, adVkShared(vaultId, this.me, s.genesisHash)));
  }

  /**
   * The ownership offer this owner made on [vaultId] that its target refused (a `cancel` they signed, §3.3), until the
   * owner dismisses it or makes another offer; null otherwise.
   */
  refusedOffer(vaultId: string): { readonly by: string; readonly at: number } | null {
    const t = this.storage.get(this.k(vaultId, "offerRefused"));
    if (t === null) return null;
    try {
      const v = JSON.parse(t) as { by?: unknown; at?: unknown };
      return typeof v.by === "string" && typeof v.at === "number" ? { by: v.by, at: v.at } : null;
    } catch {
      return null;
    }
  }

  dismissRefusedOffer(vaultId: string): void {
    this.storage.remove(this.k(vaultId, "offerRefused"));
  }

  /** The verified state of [vaultId] as this browser holds it, or null. */
  verifiedState(vaultId: string): VaultState | null {
    return this.loadState(vaultId);
  }

  /** Items may be copied OUT of a vault in any state that holds a committed key (§3.6, T2-R-k). */
  copyOutAllowed(vaultId: string): boolean {
    return this.keys.has(vaultId);
  }

  private async writeVaultRecord(s: VaultState): Promise<void> {
    const existing = this.account.local().vaults.get(s.vaultId);
    const lastText = this.storage.get(this.k(s.vaultId, "recordAt"));
    const last = lastText === null ? null : Number(lastText);
    const now = this.clock();
    if (!vaultRecordDue(existing, s.head.seq, Number.isSafeInteger(last) ? last : null, now)) return;
    await this.account.update((doc) => withVaultHead(doc, s.vaultId, s.genesisHash, s.head.seq, s.head.hash));
    this.storage.set(this.k(s.vaultId, "recordAt"), String(now));
  }

  /**
   * An item names a log head: a hint, never a verdict (FS-R4). A hint above what this browser verified is chased
   * with one full refetch; an unresolved chase is remembered with the head it ran at, and until [HINT_BACKOFF_MS]
   * has passed or the verified head has moved no further hint is chased (the vault stays "may be incomplete").
   */
  async noteItemHead(vaultId: string, seq: number, hash: string): Promise<LogStatus> {
    const s = this.loadState(vaultId);
    if (s !== null) {
      const held = this.hashes(vaultId).get(seq);
      const mentionsMore = seq > s.head.seq || (held !== undefined && held !== hash);
      if (!mentionsMore) return this.status(vaultId);
    }
    const headBefore = s?.head.seq ?? -1;
    const nowMs = this.clock();
    if (this.chaseBackedOff(vaultId, headBefore, nowMs)) {
      if (s !== null) this.storage.set(this.k(vaultId, "hint"), "1");
      return this.status(vaultId);
    }
    const after = await this.refresh(vaultId, null, null, true);
    const now = this.loadState(vaultId);
    const resolved = now !== null && now.head.seq >= seq && this.hashes(vaultId).get(seq) === hash;
    if (now !== null) {
      if (resolved) this.storage.remove(this.k(vaultId, "hint"));
      else this.storage.set(this.k(vaultId, "hint"), "1");
    }
    if (resolved) this.storage.remove(this.k(vaultId, "hintChase"));
    else this.storage.set(this.k(vaultId, "hintChase"), `${now?.head.seq ?? -1}:${nowMs}`);
    return resolved ? after : this.status(vaultId);
  }

  private chaseBackedOff(vaultId: string, headSeq: number, nowMs: number): boolean {
    const t = this.storage.get(this.k(vaultId, "hintChase"));
    if (t === null) return false;
    const [h, a] = t.split(":");
    const chased = Number(h);
    const at = Number(a);
    if (!Number.isSafeInteger(chased) || !Number.isSafeInteger(at)) return false;
    return chased === headSeq && nowMs >= at && nowMs - at < HINT_BACKOFF_MS;
  }

  /**
   * Writes are allowed only on a verified log this account is a member of, with its key held. Verified is {@link status}:
   * never while the account's record, read now, is above the verified head.
   */
  writeAllowed(vaultId: string): boolean {
    const st = this.status(vaultId);
    return st.kind === "verified" && this.me in st.state.members && this.keys.has(vaultId);
  }

  /**
   * Signs and posts one entry (§3.7). Its frame is kept in the pending-append record until it is seen in the verified log.
   * [opts.forMove]: the `delete` of "Move everything", which only the move re-posts ({@link retryPending} skips it).
   * [opts.halfMade]: the `delete` of a stopped move's half-made vault, with the copies the move made in it; it is never
   * re-posted unread ({@link retryPending} skips it too).
   */
  async append(vaultId: string | null, action: LogAction, opts: AppendOpts = {}): Promise<AppendOutcome> {
    if (action.kind === "create") return this.create(action.name, action.moveOf);
    if (vaultId === null) return { kind: "not_allowed", reason: "no_vault" };
    // Design §3.13 as decided on 2026-11-17: while a move's deletion of this vault waits, nothing else is signed on its
    // log by any caller; the move re-posts its own frame through retryHeld, which signs nothing.
    if (this.holdsMoveDelete(vaultId)) return { kind: "not_allowed", reason: "move_delete_waiting" };
    // Core StoredVaultLogs.append twin: the all-zero user id is never an account, so nothing naming it is ever built.
    if (isNilUserId(namedMember(action))) return { kind: "not_allowed", reason: "nil_user_id" };
    const held = this.pendingFor(vaultId);
    if (held !== null) {
      // A held frame the server's own answer said it stored is looked for first (nothing is posted): once it is read back
      // the record goes, and this change is signed after it.
      const look = held.acked === true ? await this.lookHeld(vaultId) : { kind: "pending" as const };
      // The look found the server contradicting its word: the vault froze, and the held change went with it.
      if (look?.kind === "read_only") return look;
      if (look !== null && look.kind !== "appended") return { kind: "not_allowed", reason: held.acked === true ? "append_unread" : "append_pending" };
    }
    const st = this.status(vaultId);
    const s = this.loadState(vaultId);
    if (s === null) return { kind: "not_allowed", reason: "log_not_verified" };
    // A frozen vault was frozen before this change, and nothing of it is sent.
    if (st.kind !== "verified" && action.kind !== "leave") return st.kind === "frozen" ? { kind: "read_only", vaultId, frozen: "unsent" } : { kind: "read_only", vaultId };
    // Core StoredVaultLogs.append(expectHead) twin: a change is signed only over the head its caller checked. Compared
    // with the verified head just loaded, with no wait between this comparison and the signature below.
    if (opts.expectHead !== undefined && (s.head.seq !== opts.expectHead.seq || s.head.hash !== opts.expectHead.hash)) {
      return { kind: "not_allowed", reason: "log_moved_on" };
    }
    const pos = logPosition(s, this.clock());
    const head = { vaultId, seq: pos.seq, prev: pos.prev, actor: this.me, at: pos.at };
    let grant: string | undefined;
    let wrappedVk: string | undefined;
    let entry: LogEntry;
    switch (action.kind) {
      case "add": {
        const c = this.host.currentContact(action.contactUserId);
        if (c === null) return { kind: "not_allowed", reason: "not_a_current_contact" };
        if (!c.compared && !action.releaseUncompared) return { kind: "not_allowed", reason: "not_compared" };
        const vk = this.keys.get(vaultId);
        if (!vk) return { kind: "not_allowed", reason: "no_key" };
        const memberKey = fromB64Canonical(c.key);
        if (memberKey === null || memberKey.length !== 32) return { kind: "not_allowed", reason: "bad_contact_key" };
        const grantId = toB64(randomBytes(16));
        const frame = signVaultGrant(this.signer, { from: this.me, to: action.contactUserId, toKey: c.key, vaultId, grantId, issuedAt: pos.at, vk });
        grant = toB64(sealVaultGrant(memberKey, frame));
        entry = { ...head, kind: "add", member: action.contactUserId, memberKey: c.key, role: action.role, grantId };
        break;
      }
      case "role":
        entry = { ...head, kind: "role", member: action.member, role: action.role };
        break;
      case "remove":
        entry = { ...head, kind: "remove", member: action.member };
        break;
      case "leave":
        entry = { ...head, kind: "leave" };
        break;
      case "offer": {
        const to = s.members[action.to];
        if (!to) return { kind: "not_allowed", reason: "not_a_member" };
        if (action.expiresInMs <= 0 || action.expiresInMs > MAX_OFFER_WINDOW_MS - 10 * 60 * 1000) return { kind: "not_allowed", reason: "bad_expiry" };
        entry = { ...head, kind: "offer", to: action.to, toKey: to.key, offerId: toB64(randomBytes(16)), expiresAt: pos.at + action.expiresInMs };
        break;
      }
      case "cancel":
        if (s.pending === null) return { kind: "not_allowed", reason: "no_offer" };
        entry = { ...head, kind: "cancel", offerId: s.pending.offerId };
        break;
      case "accept": {
        if (s.pending === null) return { kind: "not_allowed", reason: "no_offer" };
        const vk = this.keys.get(vaultId);
        if (!vk) return { kind: "not_allowed", reason: "no_key" };
        const ad = adVkShared(vaultId, this.me, s.genesisHash);
        const w = seal(this.uvk, vk, ad);
        // Round trip: the wrap must open to the committed key before it is posted (spec 03 §10.2).
        let back: Uint8Array | null = null;
        try {
          back = open(this.uvk, w, ad);
        } catch {
          back = null;
        }
        const matches = back !== null && (await keyMatches(vaultId, s.vkCommit, back));
        back?.fill(0);
        if (!matches) return { kind: "not_allowed", reason: "wrap_round_trip" };
        wrappedVk = toB64(w);
        entry = { ...head, kind: "accept", offerId: s.pending.offerId };
        break;
      }
      case "delete":
        entry = { ...head, kind: "delete", deleteId: toB64(randomBytes(16)) };
        break;
      case "restore":
        if (s.deleteId === null) return { kind: "not_allowed", reason: "not_deleted" };
        entry = { ...head, kind: "restore", deleteId: s.deleteId };
        break;
    }
    // The standing is asked again after the wait above (an accept's comparison of the key with its commitment): another
    // tab, or the account's record, may have changed it meanwhile. From here to the post's own gate nothing waits.
    const stNow = this.status(vaultId);
    if (stNow.kind !== "verified" && action.kind !== "leave") return stNow.kind === "frozen" ? { kind: "read_only", vaultId, frozen: "unsent" } : { kind: "read_only", vaultId };
    const signed = signLogEntryChecked(this.signer, s, entry);
    if (!signed.ok) return { kind: "not_allowed", reason: signed.verdict };
    const forMove = opts.forMove === true && action.kind === "delete" ? { forMove: true as const } : {};
    const halfMade = opts.halfMade !== undefined && action.kind === "delete" ? { halfMade: { copies: opts.halfMade.copies === null ? null : [...opts.halfMade.copies] } } : {};
    const moveStep = opts.moveStep === true ? { moveStep: true as const } : {};
    const point = opts.itemsAtMost !== undefined && action.kind === "delete" ? { itemsAtMost: opts.itemsAtMost } : {};
    const sent = await this.post({ vaultId, frame: toB64(signed.value.frame), ...(grant ? { grant } : {}), ...(wrappedVk ? { wrappedVk } : {}), ...forMove, ...halfMade, ...moveStep, ...point }, true);
    if (st.kind !== "frozen") return sent;
    const out = frozenLeave(sent);
    if (out.kind === "read_only" && out.leave === "stored") this.markOwnFrozenLeave(vaultId);
    return out;
  }

  private async create(name: string, moveOf?: string): Promise<AppendOutcome> {
    const vaultId = uuidV4();
    const vk = randomBytes(32);
    const entry: LogEntry = { kind: "genesis", vaultId, seq: 0, prev: "0".repeat(64), actor: this.me, at: this.clock(), ownerKey: toB64(this.identityPub), vkCommit: await vkCommit(vk, vaultId) };
    const signed = signLogEntryChecked(this.signer, null, entry);
    if (!signed.ok) {
      vk.fill(0);
      return { kind: "not_allowed", reason: signed.verdict };
    }
    const genesisHash = signed.value.step.hash;
    const wrappedVk = toB64(seal(this.uvk, vk, adVkShared(vaultId, this.me, genesisHash)));
    const metaBlob = this.host.sealMeta(vaultId, vk, name, moveOf);
    // The genesis names its owner as the first member, through itself (seq 0): the key works once that is verified here.
    this.keys.set(vaultId, vk, 0);
    // §5.4's writer rule: the creating device's accepted record answers the genesis (addSeq 0).
    await this.account.update((doc) => withAccepted(doc, { vaultId, owner: this.me, addSeq: 0, at: this.clock(), decision: "accept" }));
    return this.post({ vaultId, frame: toB64(signed.value.frame), wrappedVk, metaBlob }, true);
  }

  private pendingFor(vaultId: string): Pending | null {
    const t = this.storage.get(this.k(vaultId, "pending"));
    if (t === null) return null;
    // A frozen vault holds nothing: a record still at rest for one (kept before this rule) goes at the first look.
    if (this.frozen(vaultId)) {
      this.dropFrozenHeld(vaultId);
      return null;
    }
    try {
      const p = JSON.parse(t) as Pending;
      if (typeof p.vaultId !== "string" || p.vaultId !== vaultId || typeof p.frame !== "string") return null;
      // A record kept before it carried its time counts its day from the first time it is seen.
      if (typeof p.heldAt !== "number") {
        const stamped: Pending = { ...p, heldAt: this.clock() };
        this.storage.set(this.k(vaultId, "pending"), JSON.stringify(stamped));
        return stamped;
      }
      return p;
    } catch {
      return null;
    }
  }

  private indexKey(): string {
    return `andvari.log2.${this.me}.pending-index`;
  }

  pendingVaults(): string[] {
    return (this.storage.get(this.indexKey()) ?? "").split(",").filter((x) => x !== "");
  }

  private savePending(p: Pending | null, vaultId: string): void {
    if (p === null) this.storage.remove(this.k(vaultId, "pending"));
    else this.storage.set(this.k(vaultId, "pending"), JSON.stringify(p));
    const ids = new Set(this.pendingVaults());
    if (p === null) ids.delete(vaultId);
    else ids.add(vaultId);
    const list = [...ids].sort();
    if (list.length === 0) this.storage.remove(this.indexKey());
    else this.storage.set(this.indexKey(), list.join(","));
  }

  /**
   * Posts [p] and says what is known of it ({@link HeldKnown}). [first]: the frame was signed just now and never posted
   * before, so an answer that refuses it settles that it is not stored; a re-post's refusal for now settles nothing
   * about an earlier post whose answer was lost.
   */
  private async post(given: Pending, first: boolean): Promise<AppendOutcome> {
    try {
      return await this.postOnce(given, first);
    } finally {
      // The first request has ended, whatever its outcome: from now on the change may be withdrawn.
      if (first) {
        const cur = this.pendingFor(given.vaultId);
        if (cur !== null && cur.frame === given.frame && cur.firstOutAt !== undefined) {
          const { firstOutAt: _out, ...done } = cur;
          this.savePending(done, given.vaultId);
        }
      }
    }
  }

  private async postOnce(given: Pending, first: boolean): Promise<AppendOutcome> {
    // What was known before this post: a frame the server's own answer already said it stored stays stored; one it said
    // it did not store, and that no post since can have reached, is not stored.
    const wasNotStored = given.notStored === true && given.acked !== true;
    const before: HeldKnown = given.acked === true ? "stored" : wasNotStored ? "not_stored" : "unknown";
    // From the moment this post may leave, an earlier "not stored" no longer holds (its answer may be lost).
    const { notStored: _was, firstOutAt: _out, ...rest } = given;
    const p: Pending = first ? { ...rest, heldAt: rest.heldAt ?? this.clock(), firstOutAt: this.clock() } : rest;
    this.savePending(p, p.vaultId);
    const held = (known: HeldKnown): AppendOutcome => {
      // Kept with what is known: "not stored" only from the server's own answer to a post nothing has followed. A change
      // withdrawn while this post was out is not brought back by its answer.
      if (known === "not_stored" && this.stillHeld(p)) this.savePending({ ...p, notStored: true }, p.vaultId);
      return { kind: "pending", vaultId: p.vaultId, known };
    };
    // THE one place through which this browser appends to a vault's log, first posts and re-posts alike. The entry goes
    // out only while the vault may be written to here (its key works): a member added or removed, a role, the vault's
    // deletion, a transfer, a move's entries. The exception: a leave, which a person may always make (and a decline's
    // leave is the product's own road). Two entries are not changes of a vault whose key could stop working: a genesis
    // starts a new log, and a restore is signed only by the owner on a log whose `delete` is in force, where no key
    // works for anyone and no removal of the owner can be owed (the owner is never removed from its own vault).
    // A re-post also needs the log's standing here to be verified: a vault whose served log is behind what this browser
    // verified or the account recorded (withheld) takes no change of its log until it has been read through (decided on
    // 24 November 2026), even where its key works; the owner's restore of its own deleted log too, for which no key works.
    // A first post was signed on a verified log ({@link append}).
    const kind = this.describe(p).kind;
    const free = kind === "leave" || (kind === "genesis" && this.loadState(p.vaultId) === null);
    const deletedOwnLog = kind === "restore" && this.loadState(p.vaultId)?.deleteId != null && this.loadState(p.vaultId)?.owner === this.me;
    if (!free && ((!deletedOwnLog && !this.writeGate(p.vaultId)) || (!first && this.status(p.vaultId).kind !== "verified"))) {
      // Nothing left the browser. A frame signed just now is not kept; a held one stays held, unsent, until the
      // removal's rule has run.
      if (!first) {
        this.heldByGate.add(p.vaultId);
        return held(before);
      }
      this.clearIfHeld(p);
      return { kind: "not_allowed", reason: "key_not_working" };
    }
    let answer: LogAppendResponse;
    try {
      answer = await this.wire.appendLog(p.vaultId, { entry: p.frame, ...(p.grant ? { grant: p.grant } : {}), ...(p.wrappedVk ? { wrappedVk: p.wrappedVk } : {}), ...(p.metaBlob ? { metaBlob: p.metaBlob } : {}), ...(p.itemsAtMost !== undefined ? { itemsAtMost: p.itemsAtMost } : {}) });
    } catch (e) {
      // Nothing left the browser: a frame never posted before is not kept (no server can hold it). A re-post that the gate
      // stopped leaves what an earlier post did as it was.
      if (e instanceof TrafficStoppedError && !e.sent) {
        if (!first) return held(before);
        this.clearIfHeld(p);
        return { kind: "not_sent", vaultId: p.vaultId };
      }
      // It may have arrived: "cannot tell", unless the server's own answer already said it is stored.
      if (!(e instanceof ApiError) || e.status === 0 || e.status >= 500) return held(before === "stored" ? "stored" : "unknown");
      if (e.code === "log_head_moved") {
        const settled = await this.settle(p, false, first ? "not_stored" : before);
        if (settled === null) return { kind: "head_moved", vaultId: p.vaultId };
        return settled.kind === "pending" ? held(settled.known) : settled;
      }
      // A refusal never drops a change the server's own answer called stored (as the record was posted, or as it is held
      // now: a re-post in another tab may have been answered meanwhile): it stays held and is sent again as it is, and
      // nothing is said of it as refused. Only the log, read, settles it.
      const now = this.pendingFor(p.vaultId);
      if (hasWord(p) || (now?.frame === p.frame && hasWord(now))) return held(before === "stored" || now?.acked === true ? "stored" : "unknown");
      if (e.code === "at_ahead") {
        this.clearIfHeld(p);
        return { kind: "clock_ahead", vaultId: p.vaultId };
      }
      // Kept and sent again at the next unlock (retryPending): a refusal for now, not of the change.
      if (e.code === "rate_limited") return held(first ? "not_stored" : before);
      // An item of the vault changed after the read this deletion named: not stored (a stored deletion's retry is answered
      // 200 before the point is looked at), so nothing is held; the caller reads the vault again.
      if (e.code === "vault_items_moved") {
        this.clearIfHeld(p);
        return { kind: "items_moved", vaultId: p.vaultId };
      }
      this.clearIfHeld(p);
      return { kind: "refused", vaultId: p.vaultId, code: e.code };
    }
    // A decoded answer (the transport hands one on only under the JSON type) whose head names this frame is the server's
    // own: the change is stored, whatever the follow-up read finds. A head beyond the frame names no frame: it is proof
    // only together with the log as read afterwards holding the frame (headNamesFrame).
    let rec = p;
    const named = headNamesFrame(answer.head, rec.frame);
    if (rec.acked !== true && named === "frame") {
      rec = { ...rec, acked: true };
      // A change withdrawn while this post was out stays withdrawn: its memory (the watch the withdrawal keeps) carries the
      // server's word, so that another entry at its position freezes the vault and "not made" is never said of it.
      if (this.stillHeld(p)) this.savePending(rec, rec.vaultId);
      else this.noteWord(rec, { acked: true });
    }
    // Another head at or beyond the frame is kept with the record (and with a withdrawal's watch, where the change was
    // withdrawn while this post was out): the server's word too.
    if (named === "beyond" && rec.acked !== true) {
      const beyond = { seq: answer.head.seq, hash: answer.head.hash };
      rec = { ...rec, beyond };
      if (this.stillHeld(p)) this.savePending(rec, rec.vaultId);
      else this.noteWord(rec, { beyond });
    }
    // The word is looked at against the log as verified already, at once: another entry verified at the frame's position
    // is the contradiction now, whatever the follow-up read below does (it may fail, or end short).
    if (named !== "none" && this.freezeWhereContradicted(rec.vaultId, this.hashes(rec.vaultId))) return { kind: "read_only", vaultId: rec.vaultId, frozen: "sent" };
    const known: HeldKnown = rec.acked === true ? "stored" : "unknown";
    let out: AppendOutcome;
    const seen = { read: false };
    try {
      out = (await this.settle(rec, true, known, seen)) ?? held(known);
    } catch {
      // The follow-up read failed: what the answer said stands (a head beyond the frame: "cannot tell").
      return held(known);
    }
    // The answer's head lay beyond the frame (the server's answer to a byte-identical frame it holds) and the log, read and
    // verified just now, does not hold it. A read that reached the frame's position found another entry there: the server
    // told two stories about one position, and that read froze the vault (freezeWhereContradicted); never "not made"
    // after the server said it holds the frame. A read that ends before that position leaves "cannot tell", held.
    if (named === "beyond" && rec.acked !== true && out.kind === "pending" && seen.read) return held(known);
    // The append's own `deleted` (§10.3), kept only when the refetch in settle carried none for this `delete`.
    const s = this.loadState(rec.vaultId);
    if (s !== null) this.noteGrace(s, answer.head, answer.deleted, false);
    return out;
  }

  /**
   * After an acknowledgement or a `log_head_moved`: refetch and look for OUR frame in the verified log. Stored: the
   * record goes. Acknowledged but not visible yet: it stays, to be re-posted byte for byte. Head moved: it goes only
   * once this browser VERIFIED another entry at its position (null: the caller may sign afresh). [known]: what is known
   * of a frame that stays held.
   */
  private async settle(p: Pending, acknowledged: boolean, known: HeldKnown, seen?: { read: boolean; held?: boolean; cur?: Pending | null }): Promise<AppendOutcome | null> {
    const frame = fromB64(p.frame);
    const frameHash = toHexLower(sha256Sync(frame));
    await this.refresh(p.vaultId, null, null, true, seen);
    // Whether [p] was still the held record once the read ended (it may have been withdrawn or replaced meanwhile), and
    // that record as it is held then, whole: a re-post of the same frame answered during the read may have changed it.
    if (seen !== undefined) {
      seen.cur = this.pendingFor(p.vaultId);
      seen.held = seen.cur?.frame === p.frame;
    }
    const hashes = this.hashes(p.vaultId);
    if ([...hashes.values()].includes(frameHash)) {
      this.clearIfHeld(p);
      const s = this.loadState(p.vaultId);
      if (s === null) return { kind: "pending", vaultId: p.vaultId, known: "stored" };
      if (s.creator === this.me && s.head.seq === 0) await this.writeVaultRecord(s);
      return { kind: "appended", vaultId: p.vaultId, state: s };
    }
    const parsed = parseLogEntry(frame);
    const seq = parsed.ok ? parsed.value.entry.seq : null;
    // The server's own answer called this frame stored (as [p] carries it, or as it is held now: a re-post answered during
    // the read), and the log as verified now holds another entry at its position: the server told two stories about one
    // position. Never "its place was taken": the vault freezes there, the change is dropped, and nothing is said of it.
    const cur = this.pendingFor(p.vaultId);
    if (seq !== null && hashes.has(seq) && (hasWord(p) || (cur?.frame === p.frame && hasWord(cur)))) {
      this.freeze(p.vaultId, seq, frameHash);
      return { kind: "read_only", vaultId: p.vaultId, frozen: "sent" };
    }
    // Frozen by this read or before it (a fork, or another change's contradiction): the change went with the freeze.
    if (this.frozen(p.vaultId)) return { kind: "read_only", vaultId: p.vaultId, frozen: "sent", known };
    if (acknowledged) return { kind: "pending", vaultId: p.vaultId, known };
    if (seq === null || !hashes.has(seq)) return { kind: "pending", vaultId: p.vaultId, known };
    // Another entry at its position, and no answer called it stored: its place was taken.
    this.clearIfHeld(p);
    return null;
  }

  /** Whether [p]'s frame is still the one held for its vault (not withdrawn, given up or replaced meanwhile). */
  private stillHeld(p: Pending): boolean {
    return this.pendingFor(p.vaultId)?.frame === p.frame;
  }

  /** Drops [p]'s held record, and only that one: a record signed after it for the same vault stays. */
  private clearIfHeld(p: Pending): void {
    if (this.stillHeld(p)) this.savePending(null, p.vaultId);
  }

  /**
   * Whether this account's own leave of [vaultId], posted while the vault was frozen here, was answered by the server
   * naming that very leave (its position and its frame's hash), and this account's grant row is still the one the leave
   * was made for. The log cannot show the leave, nor which removal a later one is, so the mark never makes a removal
   * quiet: while it stands the vault is not listed again, and the notice of the next removal says that the person left it
   * here. The mark is kept at rest, bound to that row: it goes when a pull serves the row written anew (a re-add), and it
   * is used up by the next removal ({@link forgetOwnFrozenLeave}).
   */
  ownFrozenLeaveTaken(vaultId: string): boolean {
    return this.ownLeaveMark(vaultId) !== null;
  }

  /**
   * Whether the person dismissed a notice that this account no longer has [vaultId]. Kept at rest, so that a full pull
   * with nothing held (a sign-in, a reload with no offline copy) does not tell that loss again; it goes only when a pull
   * lists the vault again ({@link forgetLossTold}).
   */
  goneTold(vaultId: string): boolean {
    return this.storage.get(this.k(vaultId, "goneTold")) !== null;
  }

  /** The person dismissed a notice that this account no longer has [vaultId] ({@link goneTold}). */
  noteGoneTold(vaultId: string): void {
    this.storage.set(this.k(vaultId, "goneTold"), "1");
  }

  /**
   * Whether the person removed this browser's held copy of [vaultId] since the vault was last listed. Kept at rest, so
   * that another tab, which still holds the vault from before, learns the same removal without writing that copy again
   * or telling it again; it goes only when a pull lists the vault again ({@link forgetLossTold}).
   */
  heldRemoved(vaultId: string): boolean {
    return this.storage.get(this.k(vaultId, "heldRemoved")) !== null;
  }

  /** The person removed this browser's held copy of [vaultId] ({@link heldRemoved}). */
  noteHeldRemoved(vaultId: string): void {
    this.storage.set(this.k(vaultId, "heldRemoved"), "1");
  }

  /**
   * A pull listed [vaultId] again (this account's grant row and the vault's own row): a later loss of it is told again
   * and held again. A grant row served alone lists nothing and forgets nothing.
   */
  forgetLossTold(vaultId: string): void {
    this.storage.remove(this.k(vaultId, "goneTold"));
    this.storage.remove(this.k(vaultId, "heldRemoved"));
  }

  /** The removal that {@link ownFrozenLeaveTaken} explains was learned: the mark has done its work. */
  forgetOwnFrozenLeave(vaultId: string): void {
    this.storage.remove(this.k(vaultId, "ownLeave"));
  }

  /**
   * This account's own grant row for [vaultId], as a pull (or the offline copy) served it: a row other than the one an own
   * leave's mark was made for (another revision or other fields) means the grant was written after the leave, so the mark
   * goes. The same row served again keeps it (a server may go on serving a row it took the leave of).
   */
  noteOwnGrantRow(vaultId: string, row: GrantRowView): void {
    const mark = this.ownLeaveMark(vaultId);
    if (mark !== null && (row.rev !== mark.rev || grantRowDigest(row) !== mark.row)) this.forgetOwnFrozenLeave(vaultId);
  }

  /** The mark of an own leave the server took, bound to this account's grant row as last served; none without that row. */
  private markOwnFrozenLeave(vaultId: string): void {
    const row = this.host.grantRow(vaultId);
    if (row === null || row.rev === undefined) return; // nothing to bind it to: the removal keeps its notice
    const mark: OwnLeaveMark = { rev: row.rev, row: grantRowDigest(row) };
    this.storage.set(this.k(vaultId, "ownLeave"), JSON.stringify(mark));
  }

  private ownLeaveMark(vaultId: string): OwnLeaveMark | null {
    const raw = this.storage.get(this.k(vaultId, "ownLeave"));
    if (raw === null) return null;
    try {
      const m = JSON.parse(raw) as Partial<OwnLeaveMark> | null;
      return m !== null && typeof m === "object" && typeof m.rev === "number" && typeof m.row === "string" ? { rev: m.rev, row: m.row } : null;
    } catch {
      return null;
    }
  }

  /** Whether a frame this account signed for [vaultId] is held in the pending-append record (its answer never came). */
  holds(vaultId: string): boolean {
    return this.pendingFor(vaultId) !== null;
  }

  /**
   * Looks before any re-post: refetches [vaultId]'s log and, when the held frame is in the verified log, the record goes
   * and the answer is `appended`. When this browser verified another entry at the held frame's position, the frame can
   * never be stored and the record goes by the log's own rule for a held change whose place was taken (spec 03 §10.3):
   * the answer is null. Otherwise it stays held (`pending`, also when the log could not be fetched). Nothing is posted.
   * Null also when nothing is held for that vault.
   */
  async lookHeld(vaultId: string): Promise<AppendOutcome | null> {
    const p = this.pendingFor(vaultId);
    if (p === null) return null;
    const known = knownOf(p);
    try {
      return await this.settle(p, false, known);
    } catch {
      return { kind: "pending", vaultId, known };
    }
  }

  /**
   * After an outcome that cannot be told: the vault's log is read from the server again (nothing is posted), so that the
   * members the person is sent to look at are the server's as read now. [outcome] is {@link lookHeld}'s (null: nothing
   * held any more, its place was taken); [read] whether the log was read and verified to the head the server served.
   */
  async readAfterUnknown(vaultId: string): Promise<{ readonly outcome: AppendOutcome | null; readonly read: boolean }> {
    const p = this.pendingFor(vaultId);
    if (p === null) return { outcome: null, read: false };
    const seen = { read: false };
    try {
      return { outcome: await this.settle(p, false, knownOf(p), seen), read: seen.read };
    } catch {
      return { outcome: { kind: "pending", vaultId, known: knownOf(p) }, read: false };
    }
  }

  /** What is known of [vaultId]'s held frame ({@link HeldKnown}), or null when none is held. Nothing is fetched. */
  heldKnown(vaultId: string): HeldKnown | null {
    const p = this.pendingFor(vaultId);
    return p === null ? null : knownOf(p);
  }

  /** The held change of [vaultId] as the screens show it ({@link HeldChange}), or null. A move's own `delete` included. */
  heldChange(vaultId: string): HeldChange | null {
    const p = this.pendingFor(vaultId);
    return p === null ? null : this.describe(p);
  }

  private describe(p: Pending): HeldChange {
    const parsed = parseLogEntry(fromB64(p.frame));
    const e = parsed.ok ? parsed.value.entry : null;
    const kind: LogEntry["kind"] = e?.kind ?? "genesis";
    let member: string | null = null;
    let key: string | null = null;
    if (e !== null && (e.kind === "add" || e.kind === "remove" || e.kind === "role")) member = e.member;
    if (e !== null && e.kind === "offer") member = e.to;
    if (e !== null && e.kind === "add") key = e.memberKey;
    if (e !== null && e.kind === "offer") key = e.toKey;
    if (member !== null && key === null) key = this.loadState(p.vaultId)?.members[member]?.key ?? this.host.currentContact(member)?.key ?? null;
    const known = knownOf(p);
    return {
      vaultId: p.vaultId,
      kind,
      member,
      memberLabel: member !== null && key !== null ? this.host.labelFor(member, key) : null,
      heldAt: typeof p.heldAt === "number" ? p.heldAt : null,
      known,
      // In both states it can be in before the server's word that it is stored: not stored, and cannot tell. Never a step
      // of a move (its own run decides) nor a half-made vault's deletion (sent only after its read).
      // Nor while its first request is out (here or in another tab): only once that request ended.
      withdrawable: known !== "stored" && MEMBERSHIP_KINDS.has(kind) && p.forMove !== true && p.halfMade === undefined && p.moveStep !== true && !this.firstPostOut(p),
    };
  }

  /** Whether [p]'s first request is still out ({@link Pending.firstOutAt}). */
  private firstPostOut(p: Pending): boolean {
    if (p.firstOutAt === undefined) return false;
    const age = this.clock() - p.firstOutAt;
    return age >= 0 && age < FIRST_POST_OUT_MAX_MS;
  }

  /**
   * Withdraws [vaultId]'s held change: this browser never sends it again ({@link HeldChange.withdrawable}; nothing is
   * posted). Where the server's own answer said it did not store it, with no post since, it was not made and will not
   * be. Where its answer was lost it may be made already: the frame's hash and position are kept ({@link checkWatched}),
   * so that the log, read as soon as it can be, says whether it was. True when it was withdrawn.
   */
  withdrawHeld(vaultId: string): boolean {
    return this.withdrawHeldAs(vaultId) !== null;
  }

  /**
   * {@link withdrawHeld}, answering what was known of the change at the moment it was withdrawn (the record as read
   * then, not as a screen drew it earlier), or null when nothing was withdrawn: the line after "Withdraw" follows it.
   */
  withdrawHeldAs(vaultId: string): HeldKnown | null {
    const p = this.pendingFor(vaultId);
    if (p === null || !this.describe(p).withdrawable) return null;
    const known = knownOf(p);
    this.savePending(null, vaultId);
    if (known !== "not_stored") this.watch(p, "withdrawn", false);
    return known;
  }

  private watchIndexKey(): string {
    return `andvari.log2.${this.me}.watch-index`;
  }

  private watchesOf(vaultId: string): Watch[] {
    return understood(rawRecords(this.storage.get(this.k(vaultId, "watch"))), isWatch);
  }

  /** Writes [vaultId]'s watches; the stored entries this code does not understand are carried as they are. */
  private saveWatches(vaultId: string, given: readonly Watch[]): void {
    const list: unknown[] = [...given, ...notUnderstood(rawRecords(this.storage.get(this.k(vaultId, "watch"))), isWatch)];
    if (list.length === 0) this.storage.remove(this.k(vaultId, "watch"));
    else this.storage.set(this.k(vaultId, "watch"), JSON.stringify(list));
    const ids = new Set((this.storage.get(this.watchIndexKey()) ?? "").split(",").filter((x) => x !== ""));
    if (list.length === 0) ids.delete(vaultId);
    else ids.add(vaultId);
    const all = [...ids].sort();
    if (all.length === 0) this.storage.remove(this.watchIndexKey());
    else this.storage.set(this.watchIndexKey(), all.join(","));
  }

  /**
   * Remembers [p]'s frame by its hash and position ({@link Watch}); [told]: the person was told its outcome already. A
   * watch whose position another entry took (already told) goes at once, and the vault's list is bounded.
   */
  private watch(p: Pending, why: Watch["why"], told: boolean): void {
    const frame = fromB64(p.frame);
    const parsed = parseLogEntry(frame);
    if (!parsed.ok) return;
    const hash = toHexLower(sha256Sync(frame));
    const verified = this.hashes(p.vaultId);
    // One not yet told stays, so that the next look tells it (checkWatched); one found made stays until dismissed.
    // One whose answer called it stored is never "taken": another entry at its place is the freeze below.
    const taken = (w: Watch) => w.made !== true && w.told && verified.has(w.seq) && verified.get(w.seq) !== w.hash && !hasWord(w);
    const list = this.watchesOf(p.vaultId).filter((w) => w.hash !== hash && !taken(w));
    // A half-made vault's deletion is said as what it is wherever it ends here: never as a change the person withdrew.
    const as: Watch["why"] = p.halfMade !== undefined ? "half_made" : why;
    // The server's word goes with it, in both its forms (an answer at its position naming it, or another head at or beyond).
    const word = { ...(p.beyond !== undefined ? { beyond: p.beyond } : {}), ...(p.acked === true ? { acked: true as const } : {}) };
    const entry: Watch = { frame: p.frame, hash, seq: parsed.value.entry.seq, why: as, read: false, told, ...word };
    this.saveWatches(p.vaultId, boundWatches([...list, entry]));
    // The word it carries is checked at once against the log as verified already.
    this.freezeWhereContradicted(p.vaultId, verified);
  }

  /**
   * A post's answer brought the server's word about [p]'s frame after the change was let go of here (withdrawn while the
   * post was out): its watch keeps that word, for an answer at its position as for one beyond it.
   */
  private noteWord(p: Pending, word: { readonly acked: true } | { readonly beyond: { readonly seq: number; readonly hash: string } }): void {
    const hash = toHexLower(sha256Sync(fromB64(p.frame)));
    const list = this.watchesOf(p.vaultId);
    if (!list.some((w) => w.hash === hash && w.made !== true)) return;
    this.saveWatches(p.vaultId, list.map((w) => (w.hash === hash && w.made !== true ? { ...w, ...word } : w)));
  }

  private watchIndex(): string[] {
    return (this.storage.get(this.watchIndexKey()) ?? "").split(",").filter((x) => x !== "");
  }

  /** The vaults with a change remembered by {@link watch} that is still looked for (not found made yet). */
  watchedVaults(): string[] {
    return this.watchIndex().filter((vaultId) => this.watchesOf(vaultId).some((w) => w.made !== true));
  }

  private findingOf(vaultId: string, w: Watch, found: WatchFinding["found"]): WatchFinding {
    const parsedAt = parseLogEntry(fromB64(w.frame));
    const at = parsedAt.ok ? parsedAt.value.entry.at : 0;
    return { id: w.hash, change: { ...this.describe({ vaultId, frame: w.frame }), withdrawable: false }, found, why: w.why, at, ...(typeof w.purgeAt === "number" ? { purgeAt: w.purgeAt } : {}) };
  }

  /**
   * Every change found made after all ({@link checkWatched}) whose notice the person has not dismissed yet: kept at rest,
   * as the settled changes are, so that a lock or a closed tab loses no "made after all". Nothing is fetched.
   */
  madeWatches(): WatchFinding[] {
    const out: WatchFinding[] = [];
    for (const vaultId of this.watchIndex()) for (const w of this.watchesOf(vaultId)) if (w.made === true) out.push(this.findingOf(vaultId, w, "made"));
    return out;
  }

  /** The person dismissed the notice that the change [id] of [vaultId] was made after all: it is forgotten. */
  dismissWatched(vaultId: string, id: string): void {
    const list = this.watchesOf(vaultId);
    const rest = list.filter((w) => !(w.hash === id && w.made === true));
    if (rest.length !== list.length) this.saveWatches(vaultId, rest);
  }

  /**
   * The notice that the change [id] of [vaultId] was not made ({@link checkWatched}) has been made: it is told, and not
   * said again. One whose place another entry took is forgotten now; one whose position is free is still looked for.
   */
  noteWatchTold(vaultId: string, id: string): void {
    const list = this.watchesOf(vaultId);
    const w = list.find((x) => x.hash === id && x.made !== true && !x.told);
    if (w === undefined) return;
    const hashes = this.hashes(vaultId);
    const gone = hashes.has(w.seq) && hashes.get(w.seq) !== w.hash && !hasWord(w);
    this.saveWatches(vaultId, gone ? list.filter((x) => x !== w) : list.map((x) => (x === w ? { ...x, told: true } : x)));
  }

  /**
   * The person chose to delete [vaultId] now, but its held deletion's day ran out after they were asked: it is given up
   * as the unlock's re-send gives one up ({@link resendPending}; the log is read, nothing is posted), and kept as
   * settled where it did not happen. Null when nothing of the kind is held (or it was withdrawn meanwhile).
   */
  async giveUpHeldDeletion(vaultId: string): Promise<ResendOutcome | null> {
    const p = this.pendingFor(vaultId);
    if (p === null || p.forMove === true || p.halfMade !== undefined) return null;
    const change = this.describe(p);
    if (change.kind !== "delete" || change.known === "stored") return null;
    const outcome = await this.giveUp(p, change.known);
    if (outcome !== null && didNotHappen(outcome)) this.keepSettled(p, outcome);
    return outcome;
  }

  /**
   * CL.5: for each change this browser withdrew or gave up without knowing whether the server had it, what the log says
   * now. The log is read from the server where [opts.read] asks for it or where no read has reached the server since the
   * change ended here (a failed read is tried again at the next call); otherwise the verified log this browser holds is
   * looked at, which every sync keeps up with the server's head. Nothing is posted.
   *  - the log holds the frame: `made` (after all), returned once, and kept at rest until its notice is dismissed
   *    ({@link madeWatches});
   *  - another entry holds its position: it can never be made, and it is forgotten (a withdrawal not yet told is told
   *    `not_made`); except where the server's answer to the change named a head beyond it: the server said it holds
   *    it, so the vault is frozen and nothing is said (the read itself froze it, {@link freezeWhereContradicted});
   *  - its position is free: a withdrawal is told `not_made` once a read reached the server, and it is remembered still;
   *    except where the server's answer to the change named a head beyond it ({@link Watch.beyond}): a read that reaches
   *    that head never shows the position free, so a read that does is short of it and finds nothing yet.
   */
  async checkWatched(opts: { readonly vaultId?: string; readonly read?: boolean } = {}): Promise<WatchFinding[]> {
    const out: WatchFinding[] = [];
    for (const vaultId of this.watchedVaults()) {
      if (opts.vaultId !== undefined && opts.vaultId !== vaultId) continue;
      const before = this.watchesOf(vaultId);
      if (before.length === 0) continue;
      let readNow = false;
      // Read from the server where asked, where no read reached it since a change ended here, and while a withdrawal's
      // outcome is not told yet (its "not made" is said only from a read made now).
      if (opts.read === true || before.some((w) => w.made !== true && (!w.read || (!w.told && w.why === "withdrawn" && !hasWord(w))))) {
        const seen = { read: false };
        try {
          await this.refresh(vaultId, null, null, true, seen);
        } catch {
          seen.read = false;
        }
        readNow = seen.read;
      }
      // The list as it is after the read: a freeze at the read ended the memory of a change it contradicted.
      const list = this.watchesOf(vaultId);
      const hashes = this.hashes(vaultId);
      const held = new Set(hashes.values());
      const keep: Watch[] = [];
      const contradicted: Watch[] = [];
      for (const w of list) {
        if (w.made === true) {
          keep.push(w);
          continue;
        }
        if (held.has(w.hash)) {
          out.push(this.findingOf(vaultId, w, "made"));
          keep.push({ ...w, read: true, made: true });
          continue;
        }
        const read = w.read || readNow;
        if (hashes.has(w.seq)) {
          // Where the server's answer called the change stored, another entry at its position freezes the vault: the
          // memory ends there, and nothing is said of the change.
          if (hasWord(w)) {
            contradicted.push(w);
            continue;
          }
          // It can never be made. A withdrawal not told yet is told, and remembered until its notice is made
          // (noteWatchTold): a lock before then does not lose it.
          if (!w.told && w.why === "withdrawn") {
            out.push(this.findingOf(vaultId, w, "not_made"));
            keep.push({ ...w, read });
          }
          continue;
        }
        // "Not made" as the log reads now, from a read made by this look; marked told only when its notice is made
        // (noteWatchTold), so a lock before the first sync's names does not lose it (the next look reads again).
        if (readNow && !w.told && w.why === "withdrawn" && !hasWord(w)) {
          out.push(this.findingOf(vaultId, w, "not_made"));
          keep.push({ ...w, read });
          continue;
        }
        keep.push({ ...w, read });
      }
      // Only what changed is written back (a vault whose list is unchanged is left as it was).
      if (JSON.stringify(keep) !== JSON.stringify(list)) this.saveWatches(vaultId, keep);
      for (const w of contradicted) this.freeze(vaultId, w.seq, w.hash);
    }
    return out;
  }

  /**
   * Re-posts the one held frame of [vaultId], byte for byte, and settles it as {@link append} does; null when none is held.
   * [itemsAtMost]: a held `delete` is sent with this read point (the read just made), in place of the one it kept.
   */
  async retryHeld(vaultId: string, itemsAtMost?: number): Promise<AppendOutcome | null> {
    const p = this.pendingFor(vaultId);
    if (p === null) return null;
    if (itemsAtMost === undefined || this.describe(p).kind !== "delete") return this.post(p, false);
    const pointed: Pending = { ...p, itemsAtMost };
    this.savePending(pointed, vaultId);
    return this.post(pointed, false);
  }

  /**
   * {@link retryHeld} of [vaultId]'s held frame only where it is a step of "Move everything" ({@link Pending.moveStep}):
   * a move re-posts its own entries for its new vault and nothing else held there. Null when no such step is held.
   */
  async retryMoveStep(vaultId: string): Promise<AppendOutcome | null> {
    const p = this.pendingFor(vaultId);
    return p === null || p.moveStep !== true ? null : this.post(p, false);
  }

  /**
   * Re-posts every pending-append record, byte for byte (at unlock and when the connection returns), except a move's
   * held `delete` (design §3.13): only the move re-posts that, after its own checks of the old vault.
   */
  async retryPending(): Promise<ResendOutcome[]> {
    return (await this.resendPending()).map((r) => r.outcome);
  }

  /**
   * {@link retryPending}, with what each change was (described BEFORE it was sent, since a change that is not made
   * leaves no record): the caller says every one that did not happen. A change of who may read a vault that waited
   * longer than {@link HELD_MEMBERSHIP_MAX_MS} is not sent again: the log is read first (it may be made after all, or
   * another entry took its place), and otherwise it is given up.
   *
   * A held `delete` of a stopped move's half-made vault is never sent from here: it goes only after a read of the vault
   * showed nothing but the move's copies ({@link heldHalfMadeDeletes}). That is the one marked so, and also a plain held
   * `delete` of a vault in [halfMade] (the half-made vaults the caller knows of: one signed before the mark existed).
   */
  async resendPending(halfMade: ReadonlySet<string> = new Set()): Promise<{ readonly change: HeldChange; readonly outcome: ResendOutcome }[]> {
    const out: { change: HeldChange; outcome: ResendOutcome }[] = [];
    for (const id of this.pendingVaults()) {
      const p = this.pendingFor(id);
      if (p === null || p.forMove === true || p.halfMade !== undefined) continue;
      const change = this.describe(p);
      if (change.kind === "delete" && halfMade.has(id)) continue;
      // One the server's own answer said it stored is made already: it only waits to be read back, and is never given up.
      const old = MEMBERSHIP_KINDS.has(change.kind) && change.known !== "stored" && change.heldAt !== null && this.clock() - change.heldAt >= HELD_MEMBERSHIP_MAX_MS;
      // A vault's deletion is sent again only at the person's own word ({@link heldDeletionsToAsk}): never from here
      // within its day. After that it is given up like the others.
      if (change.kind === "delete" && change.known !== "stored" && !old) continue;
      const outcome = old ? await this.giveUp(p, change.known) : await this.post(p, false);
      // Withdrawn or replaced during the give-up's read: not this re-send's to tell (the withdrawal's watch says it). Or
      // the vault froze at this re-send's read: the change went with the freeze, and nothing is said of it.
      if (outcome === null || outcome.kind === "read_only") continue;
      // Its held record is gone with the outcome: it is kept at rest as settled (never sent again) until its notice is
      // dismissed, so that a tab closed or locked right after this re-send does not lose the notice.
      if (didNotHappen(outcome)) this.keepSettled(p, outcome);
      out.push({ change, outcome });
    }
    return out;
  }

  private settledIndexKey(): string {
    return `andvari.log2.${this.me}.settled-index`;
  }

  private settledOf(vaultId: string): { readonly pending: Pending; readonly outcome: ResendOutcome }[] {
    return understood(rawRecords(this.storage.get(this.k(vaultId, "settled"))), isSettledOf(vaultId));
  }

  /** Writes [vaultId]'s settled changes; the stored entries this code does not understand are carried as they are. */
  private saveSettled(vaultId: string, given: readonly { readonly pending: Pending; readonly outcome: ResendOutcome }[]): void {
    const list: unknown[] = [...given, ...notUnderstood(rawRecords(this.storage.get(this.k(vaultId, "settled"))), isSettledOf(vaultId))];
    if (list.length === 0) this.storage.remove(this.k(vaultId, "settled"));
    else this.storage.set(this.k(vaultId, "settled"), JSON.stringify(list));
    const ids = new Set((this.storage.get(this.settledIndexKey()) ?? "").split(",").filter((x) => x !== ""));
    if (list.length === 0) ids.delete(vaultId);
    else ids.add(vaultId);
    const all = [...ids].sort();
    if (all.length === 0) this.storage.remove(this.settledIndexKey());
    else this.storage.set(this.settledIndexKey(), all.join(","));
  }

  private keepSettled(p: Pending, outcome: ResendOutcome): void {
    const id = toHexLower(sha256Sync(fromB64(p.frame)));
    const list = this.settledOf(p.vaultId).filter((r) => toHexLower(sha256Sync(fromB64(r.pending.frame))) !== id);
    // Only what describes the change: the frame (no sealed grant, key wrap or meta is needed for a notice).
    this.saveSettled(p.vaultId, [...list, { pending: { vaultId: p.vaultId, frame: p.frame, ...(p.heldAt !== undefined ? { heldAt: p.heldAt } : {}) }, outcome }]);
  }

  /**
   * Every held change of this account that did not happen when it was sent again, kept at rest until its notice is
   * dismissed ({@link dismissSettled}); never sent again. Described as {@link heldChange} describes a held one.
   */
  settledChanges(): SettledChange[] {
    const out: SettledChange[] = [];
    for (const vaultId of (this.storage.get(this.settledIndexKey()) ?? "").split(",").filter((x) => x !== "")) {
      for (const r of this.settledOf(vaultId)) out.push({ id: toHexLower(sha256Sync(fromB64(r.pending.frame))), change: this.describe(r.pending), outcome: r.outcome });
    }
    return out;
  }

  /** The person dismissed the notice of the settled change [id] of [vaultId]: its record goes. */
  dismissSettled(vaultId: string, id: string): void {
    const list = this.settledOf(vaultId);
    const rest = list.filter((r) => toHexLower(sha256Sync(fromB64(r.pending.frame))) !== id);
    if (rest.length !== list.length) this.saveSettled(vaultId, rest);
  }

  /**
   * A held change that waited too long: read the log; made, or its place taken, or given up (nothing is posted). Null
   * when, once the read ended, the held record was no longer [p] (withdrawn or replaced meanwhile, in this tab or another
   * one): then nothing is dropped, kept as settled or watched here, and a withdrawal's own watch is left as it is.
   *
   * It acts on the record as it is held once the read has ended, whole, not on the copy [p] it was called with: a
   * re-post of the same frame (a move's step, another tab's unlock) answered during the read may have made it known
   * stored (then it is not given up: `pending`, stored, it waits to be read back) or named a head beyond it (then that
   * head goes into what is remembered, and the outcome is "cannot tell").
   */
  private async giveUp(p: Pending, known: HeldKnown): Promise<ResendOutcome | null> {
    const seen: { read: boolean; held?: boolean; cur?: Pending | null } = { read: false };
    let look: AppendOutcome | null;
    try {
      look = await this.settle(p, false, known, seen);
    } catch {
      look = { kind: "pending", vaultId: p.vaultId, known };
      seen.cur = this.pendingFor(p.vaultId);
    }
    const cur = seen.cur ?? null;
    if (cur === null || cur.frame !== p.frame) return null;
    if (look === null) return { kind: "head_moved", vaultId: p.vaultId };
    if (look.kind === "appended") return look;
    // The server's own answer to a re-post during the read said it stored the frame: made already, never given up.
    if (cur.acked === true) return { kind: "pending", vaultId: p.vaultId, known: "stored" };
    const now = knownOf(cur);
    this.clearIfHeld(cur);
    // A frame that may have reached the server can still be appended while its position is free: it is remembered, and
    // the person is told if the log later holds it (its own notice says the rest).
    if (now !== "not_stored") this.watch(cur, "given_up", true);
    // "Not made" from the read only where no answer named a head beyond the frame: a read that reaches such a head never
    // shows the position free, so one that does is short of it.
    const notMade = now === "not_stored" || (seen.read && !hasWord(cur));
    return { kind: "given_up", vaultId: p.vaultId, made: notMade ? false : "unknown" };
  }

  /**
   * The vaults whose held change is this person's own deletion of the vault, not known stored, within its day: sent
   * again only at their word (the unlock asks: delete it now, or keep the vault, which withdraws it), never by the
   * unlock's re-send ({@link resendPending}). A move's deletion, a half-made vault's (marked so, or a plain one of a
   * vault in [halfMade]) are not among them. Nothing is posted.
   */
  heldDeletionsToAsk(halfMade: ReadonlySet<string> = new Set()): string[] {
    return this.pendingVaults().filter((vaultId) => {
      const p = this.pendingFor(vaultId);
      if (p === null || p.forMove === true || p.halfMade !== undefined || halfMade.has(vaultId)) return false;
      const c = this.describe(p);
      return c.kind === "delete" && c.known !== "stored" && (c.heldAt === null || this.clock() - c.heldAt < HELD_MEMBERSHIP_MAX_MS);
    });
  }

  /**
   * {@link heldDeletionsToAsk}, each looked for in the vault's log first (read from the server; nothing is posted), so
   * that the person is asked only about a deletion that is still held:
   *  - the log holds it: it was made (its answer was lost). Its record goes, and it is kept at rest as found made
   *    ({@link Watch} `answer_lost`, with the grace end the read served) until the notice that the vault was deleted is
   *    dismissed ({@link madeWatches});
   *  - another entry took its place: it did not happen, and never can. Its record goes, kept as settled (`head_moved`)
   *    until its notice is dismissed ({@link settledChanges});
   *  - otherwise (also where the read fails, or ends short of it): still held, and asked about.
   * A record withdrawn or replaced during the read is left to what holds now. Returns the vaults to ask about.
   */
  async deletionsToAsk(halfMade: ReadonlySet<string> = new Set()): Promise<string[]> {
    for (const vaultId of this.heldDeletionsToAsk(halfMade)) {
      const p = this.pendingFor(vaultId);
      if (p === null) continue;
      const seen: { read: boolean; held?: boolean; cur?: Pending | null } = { read: false };
      let look: AppendOutcome | null;
      try {
        look = await this.settle(p, false, knownOf(p), seen);
      } catch {
        continue;
      }
      if (seen.held !== true) continue;
      if (look === null) this.concludeLooked(p, "taken");
      else if (look.kind === "appended") this.concludeLooked(p, "made");
    }
    return this.heldDeletionsToAsk(halfMade);
  }

  /**
   * What a look (nothing posted) found of [p], whose record is gone with it: `taken` (another entry took its place: it
   * did not happen, kept as settled `head_moved` until its notice is dismissed), or `made` (the log holds it: the person's
   * own deletion of a vault is kept at rest as found made, {@link Watch} `answer_lost`, so that they are told the vault
   * was deleted; any other change shows in the vault as read).
   */
  private concludeLooked(p: Pending, found: "made" | "taken"): void {
    this.clearIfHeld(p);
    if (found === "taken") {
      this.keepSettled(p, { kind: "head_moved", vaultId: p.vaultId });
      return;
    }
    const frame = fromB64(p.frame);
    const parsed = parseLogEntry(frame);
    if (!parsed.ok || parsed.value.entry.kind !== "delete") return;
    const hash = toHexLower(sha256Sync(frame));
    const purgeAt = this.serverGraceEnd(p.vaultId)?.purgeAt;
    const entry: Watch = { frame: p.frame, hash, seq: parsed.value.entry.seq, why: "answer_lost", read: true, told: true, made: true, ...(typeof purgeAt === "number" ? { purgeAt } : {}) };
    this.saveWatches(p.vaultId, [...this.watchesOf(p.vaultId).filter((w) => w.hash !== hash), entry]);
  }

  /**
   * After a sync that brought vaults' logs up to the server's heads: each held change is looked for in the log this
   * browser verified (nothing is fetched, nothing is posted), so that a change the log already shows no longer reads as
   * waiting. By the same rules as a look at the unlock: the log holds the frame, and it was made (the record goes); another
   * entry took its position, and it did not happen (said as such) — where no answer of the server called it stored (one
   * that did contradicts the log, and the vault freezes: {@link freeze}); otherwise it stays held, and
   * nothing is said ("not made" is never said from a free position). A move's own deletion and steps, a half-made vault's deletion and a new
   * vault's genesis are left to their own roads. Returns the vaults whose held change was settled.
   */
  settleHeldFromLog(): string[] {
    const out: string[] = [];
    for (const vaultId of this.pendingVaults()) {
      const p = this.pendingFor(vaultId);
      if (p === null || p.forMove === true || p.halfMade !== undefined || p.moveStep === true) continue;
      const frame = fromB64(p.frame);
      const parsed = parseLogEntry(frame);
      if (!parsed.ok || parsed.value.entry.kind === "genesis") continue;
      const hashes = this.hashes(vaultId);
      const seq = parsed.value.entry.seq;
      if (hashes.get(seq) === toHexLower(sha256Sync(frame))) this.concludeLooked(p, "made");
      // Another entry where the server's own answer named this frame: the fork it is (settle), never "taken".
      else if (hashes.has(seq) && p.acked === true) {
        this.freeze(vaultId, seq, toHexLower(sha256Sync(frame)));
        continue;
      } else if (hashes.has(seq) && hasWord(p)) {
        // An answer beyond it, or at its position naming another entry: the server's word too.
        this.freeze(vaultId, seq, toHexLower(sha256Sync(frame)));
        continue;
      } else if (hashes.has(seq)) this.concludeLooked(p, "taken");
      else continue;
      out.push(vaultId);
    }
    return out;
  }

  /** The vaults whose held frame is a move's `delete` (design §3.13): each one is a move that is not finished. */
  heldMoveDeletes(): string[] {
    return this.pendingVaults().filter((id) => this.pendingFor(id)?.forMove === true);
  }

  /** Whether [vaultId]'s held frame is a move's `delete`. */
  holdsMoveDelete(vaultId: string): boolean {
    return this.pendingFor(vaultId)?.forMove === true;
  }

  /**
   * The held `delete`s of stopped moves' half-made vaults ({@link Pending.halfMade}), each with the copies the move made
   * in it. Nothing is posted: the store reads each vault first and only then sends it ({@link retryHeld}) or drops it
   * ({@link dropHeldHalfMadeDelete}).
   */
  heldHalfMadeDeletes(): HeldHalfMadeDelete[] {
    const out: HeldHalfMadeDelete[] = [];
    for (const vaultId of this.pendingVaults()) {
      const h = this.pendingFor(vaultId)?.halfMade;
      if (h === undefined) continue;
      let copies: Map<string, number | null> | null = null;
      if (Array.isArray(h.copies)) {
        copies = new Map();
        for (const c of h.copies) {
          if (!Array.isArray(c) || typeof c[0] !== "string" || (c[1] !== null && typeof c[1] !== "number")) {
            // A record that cannot be read in full names no copies: the vault is then kept, never deleted on a guess.
            copies = null;
            break;
          }
          copies.set(c[0], c[1]);
        }
      }
      out.push({ vaultId, copies });
    }
    return out;
  }

  /**
   * A half-made vault was read and holds something its move did not make: its held `delete` (marked so, or a plain one
   * the caller knows to be that vault's) is dropped and never sent. True when one was dropped; nothing is posted.
   */
  dropHeldHalfMadeDelete(vaultId: string): boolean {
    const p = this.pendingFor(vaultId);
    if (p === null || p.forMove === true || this.describe(p).kind !== "delete") return false;
    this.savePending(null, vaultId);
    // A deletion that may have reached the server (its answer was lost) can still be appended while its position is free:
    // it is remembered as a half-made vault's deletion (a plain one held from before the mark is one too: the caller knows
    // the vault), so that a log that later holds it is said, with the vault's restore.
    if (knownOf(p) !== "not_stored") this.watch({ ...p, halfMade: p.halfMade ?? { copies: null } }, "half_made", true);
    return true;
  }

  /**
   * Forgets [vaultId]'s held move `delete` once the vault's deletion is verified (stored, or purged): it can never be
   * posted again. Nothing is posted; any other held frame stays.
   */
  forgetHeldMoveDelete(vaultId: string): void {
    const s = this.loadState(vaultId);
    if (this.holdsMoveDelete(vaultId) && ((s !== null && s.deleteId !== null) || this.status(vaultId).kind === "purged")) this.savePending(null, vaultId);
  }

  /** The record of the move of [vaultId] whose delete is held, or null. */
  moveRecord(vaultId: string): MoveRecord | null {
    return parseMoveRecord(this.storage.get(this.k(vaultId, "move")));
  }

  saveMoveRecord(vaultId: string, r: MoveRecord | null): void {
    if (r === null) this.storage.remove(this.k(vaultId, "move"));
    else this.storage.set(this.k(vaultId, "move"), JSON.stringify(r));
    // The moves whose old vault froze are listed by an index of their own: a frozen vault may be missing from the vault
    // list after a reload, and its move is still said ({@link frozenMoves}).
    const ids = new Set(this.frozenMoves());
    if (r?.oldFrozen === true) ids.add(vaultId);
    else ids.delete(vaultId);
    const list = [...ids].sort();
    if (list.length === 0) this.storage.remove(`andvari.log2.${this.me}.move-frozen-index`);
    else this.storage.set(`andvari.log2.${this.me}.move-frozen-index`, list.join(","));
  }

  /** The old vaults of moves whose deletion a freeze dropped ({@link MoveRecord.oldFrozen}), until each is dismissed. */
  frozenMoves(): string[] {
    return (this.storage.get(`andvari.log2.${this.me}.move-frozen-index`) ?? "").split(",").filter((v) => v !== "" && this.moveRecord(v)?.oldFrozen === true);
  }

  /**
   * The vault key in this account's own wrap [wrappedVkB64] (the owner's wrap `GET /vaults/deleted` serves), opened
   * under the verified log's genesis and checked against its key commitment. Null when there is no verified state, the
   * wrap does not open, or the key is not the log's. Nothing is kept: the caller wipes the key after use.
   */
  async openOwnWrap(vaultId: string, wrappedVkB64: string): Promise<Uint8Array | null> {
    const s = this.loadState(vaultId);
    if (s === null) return null;
    let vk: Uint8Array;
    try {
      vk = open(this.uvk, fromB64(wrappedVkB64), adVkShared(vaultId, this.me, s.genesisHash));
    } catch {
      return null;
    }
    if (vk.length !== 32 || !(await keyMatches(vaultId, s.vkCommit, vk))) {
      vk.fill(0);
      return null;
    }
    return vk;
  }

  /** The vault key this session adopted, while this account is a member in the verified log; else null (callers do not keep it). */
  keyFor(vaultId: string): Uint8Array | null {
    const s = this.loadState(vaultId);
    if (s === null || !(this.me in s.members)) return null;
    return this.keys.get(vaultId) ?? null;
  }
}
