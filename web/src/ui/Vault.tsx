import { createContext, useCallback, useContext, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type ReactElement, type ReactNode } from "react";
import { ApiClient, ApiError, type SessionEndKind } from "../api/client";
import type { AttachmentRef, ItemDoc } from "../api/types";
import type { ClientPolicyV2 as ClientPolicy } from "../api/wire";
import { toB64 } from "../crypto/bytes";
import { generatePassword } from "../crypto/generator";
import { hibpCountInRange, hibpPrefix, hibpSha1UpperHex } from "../crypto/hibp";
import { KdfPolicyError } from "../crypto/keys";
import { randomBytes } from "../crypto/provider";
import { normalizeTotp, parseOtpauthUri, totpCode, totpSecondsRemaining } from "../crypto/totp";
import type { Account } from "../vault/account";
import { CARD_CREATE_ENABLED, brand, brandLabel, cardSubtitle, composeShortExpiry, digitsOnly, expiryLabel, groupNumber, isExpired, luhnValid, padMonth, yearTo4 } from "../vault/card";
import {
  CopyDeniedError,
  ALREADY_RECORDED,
  ItemChangedError,
  ItemChangedVaultsError,
  LEFT_UNPROVEN,
  type LifecycleNotice,
  type MoveGesture,
  MoveWaitingError,
  type PendingUpload,
  REMOVAL_REPLAY,
  REMOVED_LEGACY,
  type VaultInfo,
  type VaultItem,
  type VaultStore,
} from "../vault/store";
import { ImportError, MAX_BYTES, type ImportFormat, type ImportPlan, type ImportReport, type Parsed, type ParsedRow, parseCsvImport, planImport, rowOrdinalsByLine } from "../import/csv";
import { scheduleClipboardClear, writeClipboard } from "./clipboard";
import { useCopy } from "./usecopy";
import { copyRemovalText, saveErrorText } from "./saveerror";
import { UsageTracker, type UsageWire } from "../vault/usage";
import type { SettingsSession } from "../vault/settingsflow";
import { answerLimitText, CLIPBOARD_FAILED, CLIPBOARD_NOT_CLEARED, CLIPBOARD_NOT_CLEARED_SHORT, net, NetworkError, UNREACHABLE } from "./errors";
import { ExportPanel, type ExportMode } from "./ExportPanel";
import { Field } from "./Field";
import { fmtDay, fmtDayYear, humanSize } from "./format";
import { vaultLabel, vaultLabels } from "./vaultlabel";
import { applyListView, type SortMode, type TypeFilter } from "./listview";
import { hashToView, viewToHash } from "./routes";
import { safeSiteHref } from "./safeurl";
import { BackLink, BACK_GLYPH } from "./BackLink";
import { Busy } from "./Busy";
import { Announcer, Msg } from "./Msg";
import { Health } from "./Health";
import { useListedNow } from "./Staleness";
import { clampClipboardClearSeconds } from "./policyclamp";
import { Settings } from "./Settings";
import type { DeletionEnd, DeletionTrack } from "./DeleteAccount";
import { BrandSigil, Wordmark } from "./Sigil";
import { friendlyError, Sharing, UnfinishedMoves, withdrawnText } from "./Sharing";
import { Empty } from "./Empty";
import { estimateStrength } from "./strength";
import { windowRange, type WindowRange } from "./virtual";
import { NoPersonalVaultNotice } from "./NoPersonalVault";
import { SharedPrompts } from "./SharedPrompts";
import { EscrowPrompt } from "./EscrowPrompt";
import { QuotaShortError } from "../vault/quota";
import { quotaShortText } from "./quotatext";
import { heldNoticeText } from "./heldtext";
import { fill, RESEND_DELETE_ASK, RESEND_DELETE_ASK_KEEP, RESEND_DELETE_ASK_NOW, RESEND_DELETE_ASK_UNNAMED, RESEND_DELETE_MADE, RESEND_DELETE_MADE_UNNAMED, MOVE_STORED_COPIED, MOVE_STORED_COPY,MOVE_STORED_LATE, MOVE_STORED_NOTHING_LATE, MOVE_DELETED_OUTSIDE, MOVE_STORED_UNSEEN, MOVE_UNNAMED_OLD, MOVE_UNNAMED_VAULT, MOVE_WAITING_READ_ONLY, MOVE_WAITING_REFUSED, IMPORT_TOTP_DIFFERS, IMPORT_TOTP_DIFFERS_PREVIEW, MOVE_DISCARD_KEPT, ITEM_BROUGHT_BACK, ITEM_BROUGHT_BACK_MANY, ITEM_BROUGHT_BACK_UNNAMED, RESEND_DELETE_MADE_NO_DAY, RESEND_DELETE_MADE_UNNAMED_NO_DAY, ITEM_CLOSED, ITEM_CLOSED_EDITING, ITEM_CLOSED_EDITING_NOT_KEPT, ITEM_CLOSED_EDITING_SENT, EDITOR_VAULT_GONE } from "./copy";
import { DELETED_PARKED_ONE } from "./copy";
import {
  ITEMS_SET_ASIDE_FROZEN_NOTICE,
  ITEMS_SET_ASIDE_OTHER_NOTICE,
  ITEMS_SET_ASIDE_PERSONAL_NAME,
  ITEMS_SET_ASIDE_PERSONAL_NOTICE,
  ITEMS_SET_ASIDE_SHARED_NOTICE,
  VAULT_GONE_UNCHECKED_NOTICE,
  VAULT_LEFT_FROZEN_NOTICE,
} from "./copy";
import { CARD_FORK, COPY_FOLLOWS_SERVER, GENERATE_REPLACE_ASK, kdfRefusalText, OFFLINE_OPENED, OFFLINE_TRY_SERVER, PERSONAL_REMOVAL_REFUSED, OWNER_OUT_OF_SPACE, OWNER_OUT_OF_SPACE_THEIRS, OWNER_OUT_OF_SPACE_YOURS, SERVER_KEYS_NOT_KNOWN_OPENED, SESSION_ENDED_COPY, SESSION_NOT_CONFIRMED_COPY } from "./copy";
import { endedUnconfirmed } from "./sessionend";
import { CopyBeingRemovedError } from "../vault/policywipe";

type View = "vault" | "sharing" | "health" | "settings" | "admin" | "trash";

/** Audit F11 landmark plumbing: the skip link's target, and the name of each place — used for
 *  the page <h1> of the two title-less branches and for the tab title, which was the static
 *  "andvari" for every view (so neither the heading tree nor the tab said where you were).
 *  The names match the visible ViewHeader titles / nav buttons; Vault's switch mounts one. */
const MAIN_ID = "main-content";
const VIEW_TITLES: Record<View, string> = {
  vault: "Vault",
  sharing: "Sharing",
  health: "Vault health",
  settings: "Settings",
  admin: "Administration",
  trash: "Trash",
};

/**
 * F76: make hardware/gesture Back step through the vault's open UI layers instead of leaving
 * the SPA — leaving drops the in-memory keys and costs a full argon2 unlock. While any layer
 * is open ([deep]) we keep ONE sentinel history entry armed; a real Back pops it, we close the
 * topmost layer ([closeTop]) and re-arm. When the last layer is closed via an in-app control
 * we consume the sentinel with a self-initiated back() (flagged so the handler ignores it), so
 * no dangling entry lingers. A lock/sign-out unmounts Vault → the effect cleanup drops the
 * listener; a stray sentinel is harmless (same-URL pushState, consumed by the next Back).
 *
 * Route mirror (owner dev-note 2026-08-19, routes.ts): the guard also carries [routeHash] — the
 * current view's fragment — so BOTH history entries it juggles stay stamped with the view. Its
 * pushes pass the fragment as the entry URL, and the self-pop branch re-stamps the entry the
 * back() reveals (that entry's URL predates the view change that shallowed us — without the
 * re-stamp, returning to the vault list from a view left "#/health" in the address bar). This
 * stays the ONE popstate consumer; the [view]-keyed replaceState in Vault is a mirror, never a
 * navigation, so the two can't fight over entries.
 */
function useBackGuard(deep: boolean, closeTop: () => void, routeHash: React.MutableRefObject<string>) {
  const armed = useRef(false);
  const selfPop = useRef(false);
  const deepRef = useRef(deep);
  const closeRef = useRef(closeTop);
  deepRef.current = deep;
  closeRef.current = closeTop;

  useEffect(() => {
    if (typeof window === "undefined") return;
    // "" (the home view) must strip the fragment — a bare "" url argument would keep it.
    const hashUrl = () => routeHash.current || window.location.pathname + window.location.search;
    const onPop = () => {
      if (selfPop.current) {
        selfPop.current = false;
        armed.current = false;
        window.history.replaceState(null, "", hashUrl()); // re-stamp the revealed entry (header note)
        return;
      }
      if (deepRef.current) {
        closeRef.current(); // close exactly one layer
        window.history.pushState({ andvariBack: true }, "", hashUrl()); // re-arm — the browser consumed our sentinel
      } else {
        armed.current = false; // nothing open — let the pop stand (navigate away)
      }
    };
    window.addEventListener("popstate", onPop);
    return () => {
      window.removeEventListener("popstate", onPop);
      // Lock / sign-out can unmount us with a layer still open (deep→shallow never fires, so
      // effect-2's self-pop never runs). Consume the armed sentinel here or it lingers as the
      // current history top and — across repeated lock cycles — accumulates, each stray
      // silently eating a later Back press. The listener is already detached, so this same-URL
      // pop is invisible. (A mid-layer browser RELOAD can't be reconciled — no cleanup runs —
      // but a reload already dropped the keys, so F76's "don't waste an unlock" point is moot.)
      if (armed.current) window.history.back();
    };
    // routeHash is a ref — stable identity, read at event time.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    if (deep && !armed.current) {
      // The Vault-side mirror ran first (declared above this hook's call site), so the
      // underlying entry already carries the view's fragment; the sentinel inherits it here.
      window.history.pushState({ andvariBack: true }, "", routeHash.current || window.location.pathname + window.location.search);
      armed.current = true;
    } else if (!deep && armed.current) {
      selfPop.current = true; // a layer closed via an in-app control — reclaim our sentinel
      window.history.back();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deep]);
}

interface Props {
  account: Account;
  store: VaultStore;
  client: ApiClient;
  /** F80: the signed-in email for the appbar — a raw userId prefix reads as debug
   *  output. Empty when the persisted session predates the field (fallback below). */
  email: string;
  policy: ClientPolicy | null;
  /** Design §4.4: the session is the read-only copy under a forked pin (opened so, or frozen when a refresh found the
   *  fork): no events socket, no usage load or flush, and the fork warning. */
  readOnlyCopy?: boolean;
  /** The vault was opened from this browser's offline copy, the server out of reach: said in a line until a sync lands. */
  openedFromCopy?: boolean;
  /** Spec 01 §7: a sign-in over this browser's copy that the typed password did not open; said in one line for the session. */
  copySealedElsewhere?: boolean;
  isAdmin: boolean;
  mustChangePassword: boolean;
  /** §C6 (design 2026-07-13-web-offline-cache): this session came in via an OFFLINE unlock whose
   *  cached `recoveryConfirmed !== true` — show a persistent, NON-blocking reminder (never blocks;
   *  the online capture gate still hard-blocks the next time this device reconnects). */
  offlineRecoveryReminder: boolean;
  /** The usage ledger's routes (spec 03 §3) on the post-cut-over wire client. */
  usageWire: UsageWire;
  /** The session the post-cut-over Settings flows act for. */
  settings?: SettingsSession;
  /** F26: locks — keeps the persisted session; the user gets the Unlock card. */
  onLock: () => void;
  /** The session died server-side: App ends it (design §4.4: the offline copy stays; without one, a full sign-out).
   *  `kind` says whether it was an explicit revocation or plain expiry (the copy differs). */
  onRevoked: (kind: SessionEndKind) => void;
  /** A14 (F5): hand App this session's usage-ledger flush, so a lock that revokes the tab's tokens
   *  (no offline copy on this browser) lets the last uses land first (the H33 order). */
  registerUsageFlush?: (flush: (() => Promise<void>) | null) => void;
  /** Account deletion (spec 03 §13): this browser should forget the account (confirmed by the server, or chosen
   *  by the member after an unknown outcome) — App wipes its state and lands signed out. Absent ⇒ no deletion. */
  onAccountDeleted?: (end: DeletionEnd) => void;
  /** The deletion request's lifecycle (App holds back a session end that lands while it is in flight). */
  onDeletionTrack?: (event: DeletionTrack) => void;
}

export function Vault({ account, store, client, email, policy, readOnlyCopy: readOnlyProp = false, openedFromCopy = false, copySealedElsewhere = false, isAdmin, mustChangePassword, offlineRecoveryReminder, usageWire, settings, onLock, onRevoked, registerUsageFlush, onAccountDeleted, onDeletionTrack }: Props) {
  // §4.4: App's flag, or the store's own (a frozen store never thaws).
  const readOnlyCopy = readOnlyProp || store.isReadOnlyCopy();
  // Usage ledger (spec 02 §8.2) — one per unlocked session. Recording is in-memory and the flush
  // is debounced, because spec 03 §3 forbids a PUT per fill: that would turn the blob's own
  // updatedAt into a keystroke-grade activity trace, which is the leak the single-blob design
  // exists to avoid. A failure anywhere in here costs one health column and nothing else.
  const usageRef = useRef<UsageTracker | null>(null);
  if (!usageRef.current) usageRef.current = new UsageTracker(usageWire, account);
  const usage = usageRef.current;
  useEffect(() => {
    // §4.4: the ledger is a server blob; a read-only copy neither loads nor flushes it.
    if (readOnlyCopy) {
      usage.halt();
      return;
    }
    void usage.load();
    // pagehide, not unload: it is the one that fires reliably on mobile tab eviction, which is
    // exactly where a session's uses would otherwise be dropped.
    const onHide = () => void usage.flush();
    window.addEventListener("pagehide", onHide);
    registerUsageFlush?.(() => usage.flush());
    return () => {
      registerUsageFlush?.(null);
      window.removeEventListener("pagehide", onHide);
      // Flush BEFORE dispose (dispose clears the map), and never block teardown on it — the
      // Account in this closure outlives React's unmount, so the seal still has its key. A store frozen meanwhile (a
      // fork found during the session) halts the ledger instead: nothing goes to a forked origin.
      if (store.isReadOnlyCopy()) usage.halt();
      void usage.flush().finally(() => usage.dispose());
    };
  }, [usage, readOnlyCopy, store]);
  // Route structure (owner dev-note 2026-08-19): the mount reads the fragment back, and Vault
  // mounts AFTER the unlock gate — so a refresh on "#/health" unlocks and returns to Health.
  // Enroll fragments were already captured-and-stripped by module load, and "#recover" belongs
  // to the signed-out flow; both parse to the home view here (routes.ts is total).
  const [view, setView] = useState<View>(() => hashToView(typeof window === "undefined" ? "" : window.location.hash, isAdmin));
  // Spec 01 §7: after a sign-in over this browser's copy sealed under another master password, the line that says so
  // shows above the view the vault opens on (whichever it is, Settings included), once: leaving that view ends it.
  const [copyLineView, setCopyLineView] = useState<View | null>(() => (copySealedElsewhere ? view : null));
  useEffect(() => {
    if (copyLineView !== null && view !== copyLineView) setCopyLineView(null);
  }, [view, copyLineView]);
  // The list as the guarded reader handed it out at the last followStore; drawn only through `items` below.
  const [snapshot, setSnapshot] = useState<VaultItem[]>(() => store.list());
  // Lifecycle notices (spec 03 §11) — the banner reflects the store's list after every sync.
  const [notices, setNotices] = useState<LifecycleNotice[]>(store.notices());
  const [query, setQuery] = useState("");
  // Owner dev-note 2026-08-18: sort + facet state for the list (pure logic in listview.ts).
  // Session-scoped on purpose — a filter that silently persisted across unlocks would read
  // as missing items.
  const [sortMode, setSortMode] = useState<SortMode>("name");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [vaultFilter, setVaultFilter] = useState<string>("all");
  const [selected, setSelected] = useState<string | null>(null);
  // H117: the next Editor mount should open with a freshly generated password (the verification
  // run's post-"Wrong password" offer). Consumed by the Editor at mount and cleared with it.
  const [editorGenerate, setEditorGenerate] = useState(false);
  const [editing, setEditing] = useState<ItemDoc | null>(null);
  /** INV-EDIT (root cause A §5.1, A1b): the vault the open editor was bound to when it OPENED on an existing item.
   *  The save names it; a home that changed since refuses the save ("reopen it") instead of re-targeting it. */
  const [editingVaultId, setEditingVaultId] = useState<string | null>(null);
  // The open item and the editor as this render has them, for followStore (which runs outside a render), and whether
  // the mounted editor holds typing that was not saved (the Editor writes it at each of its renders).
  const selectedRef = useRef<string | null>(selected);
  selectedRef.current = selected;
  const editingRef = useRef<ItemDoc | null>(editing);
  editingRef.current = editing;
  const editorDirty = useRef(false);
  // Whether Save was pressed in the editor and the store's save has not settled yet (its answer may still be on its way).
  const saveWaiting = useRef(false);
  // Whether followStore closed the editor while that save waited (and said its outcome was unknown).
  const closedWhileSaving = useRef(false);
  // The one line that says why an open item or editor was closed (followStore); it goes with the next navigation.
  const [closedLine, setClosedLine] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [exportMode, setExportMode] = useState<ExportMode | null>(null);
  // DN-1 (A1): the Sharing view's per-vault settings layer. The id lives HERE — not in
  // Sharing — so the ONE back guard below can close it as the topmost layer (a second
  // useBackGuard anywhere under Vault is forbidden: double-popstate would make one Back
  // close two layers). null = Sharing shows the vaults list.
  const [sharingSettingsVaultId, setSharingSettingsVaultId] = useState<string | null>(null);
  const [mustChange, setMustChange] = useState(mustChangePassword);
  // Connectivity, split in two so F29's fallback poll has an honest gate:
  //  - wsUp: the dirty-bell socket state (onOpen/onDown from ApiClient.events);
  //  - syncOk: whether the LAST sync attempt landed (marked PENDING at socket open
  //    until the catch-up pull succeeds — green never sits over missed bells).
  // The dot shows their conjunction. Both start optimistic (green) so a healthy unlock
  // never flashes grey; a *sustained* WS drop turns it grey (onDown is debounced ~2.5s).
  const [wsUp, setWsUp] = useState(true);
  const [syncOk, setSyncOk] = useState(true);
  // The sentence for a last sync that one of the client's limits ended (errors.ts answerLimitText), else null.
  const [syncLimit, setSyncLimit] = useState<string | null>(null);
  // Opened from the offline copy: the line stays, and what needs the server is not offered, until a sync has landed.
  const [fromCopy, setFromCopy] = useState(openedFromCopy);
  const copySyncedAt = useRef(store.lastSyncAt);
  const online = wsUp && syncOk;
  const degraded = !wsUp || !syncOk;
  // a11yweb-04/AM-3: one connectivity string — the tooltip AND the visually-hidden text
  // twin in the appbar read from it, so a screen reader hears the state flip.
  const connStatus = online
    ? "Connected"
    : syncLimit !== null
      ? syncLimit
      : wsUp
      ? "Last sync failed — will retry"
      : "Live updates down — checking for changes every 60 s";
  // Manual "Sync now" (F29): disabled while a click-driven sync is in flight.
  const [syncBusy, setSyncBusy] = useState(false);
  // Type-to-search on unlock is a desktop convenience; autofocusing on touch pops the
  // keyboard over the vault on every open, so gate it to fine (mouse/trackpad) pointers.
  const finePointer = useMemo(
    () => typeof window !== "undefined" && !!window.matchMedia && window.matchMedia("(pointer: fine)").matches,
    [],
  );

  // Audit F11: the tab title tracks the mounted view — it was the static <title>andvari</title>
  // for every place in the app, so a user with several tabs (and every AT that reads the title
  // on tab switch) had nothing telling Vault from Health from Admin. Restored on unmount
  // (lock / sign-out), which lands back on the signed-out shell.
  useEffect(() => {
    document.title = view === "vault" ? "andvari" : `${VIEW_TITLES[view]} · andvari`;
    return () => {
      document.title = "andvari";
    };
  }, [view]);

  // The break-glass export suppression is GONE (design 2026-07-15 §5.4.2 — origin.ts deleted):
  // export renders whenever the vault is unlocked. It was SHOULD-level advertising only — this
  // page already holds the decrypted vault — and origin is no longer a posture signal.

  // F76: any open layer makes Back close it instead of leaving the vault. Topmost-first order
  // mirrors how the layers stack (editor/import/export over a view; detail over the list).
  const deep = view !== "vault" || selected !== null || editing !== null || importOpen || exportMode !== null;
  // Cut M (v2 #16): the mounted Editor parks its dirty-aware cancel here, so the ONE back
  // guard routes a hardware Back through the same "Discard changes?" arm as the cancel
  // button — popstate can never silently discard a typed draft. null = no editor mounted
  // (the fallback close keeps behavior sane if the ref is ever empty mid-teardown).
  const editorBack = useRef<(() => void) | null>(null);
  const closeTop = useCallback(() => {
    if (editing) return editorBack.current ? editorBack.current() : setEditing(null);
    if (importOpen) return setImportOpen(false);
    if (exportMode) return setExportMode(null);
    if (selected) return setSelected(null);
    // DN-1 (A1): the sharing settings layer closes before the view falls back — one Back
    // steps settings → vaults list, the next leaves Sharing. `deep` needs no change
    // (view !== "vault" already holds while Sharing is open).
    if (view === "sharing" && sharingSettingsVaultId) return setSharingSettingsVaultId(null);
    if (view !== "vault") return setView("vault");
  }, [editing, importOpen, exportMode, selected, view, sharingSettingsVaultId]);
  // The route MIRROR (routes.ts has the doctrine): replaceState only — the guard below owns
  // every real history-entry move, and this effect is declared BEFORE its call so a navigation
  // commit stamps the underlying entry first and the guard's sentinel push inherits it. Layers
  // and item ids deliberately never appear in the fragment.
  const routeHash = useRef(viewToHash(view));
  routeHash.current = viewToHash(view);
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (window.location.hash !== routeHash.current) {
      window.history.replaceState(null, "", routeHash.current || window.location.pathname + window.location.search);
    }
  }, [view]);
  useBackGuard(deep, closeTop, routeHash);

  /**
   * THE one function by which this screen follows the store: after every sync (syncNow), after every refresh (every
   * `refresh` below is this function), at the `storage` event by which the browser tells this tab that another tab of
   * the profile wrote a record (a vault's log among them), and at any render that finds the open item no longer handed
   * out. It re-reads the list and the notices through the store's guarded reader; where the open item (the detail, or the
   * editor of an existing item) is no longer handed out, it closes the editor and the detail and says why in one line.
   * Typing that was not saved is not kept and not made into a change: nobody pressed Save, and the line says it was not
   * kept. Everything else on this screen that shows an item reads through the guarded reader at each render.
   */
  const followStore = useCallback(() => {
    const next = store.list();
    setSnapshot((prev) => (sameItems(prev, next) ? prev : next));
    setNotices(store.notices());
    const open = selectedRef.current;
    if (open === null || store.get(open) !== undefined) return;
    const wasEditing = editingRef.current !== null;
    // A save still waiting for its answer may have reached the vault: it is said to be unknown, never "not saved".
    closedWhileSaving.current = wasEditing && saveWaiting.current;
    setClosedLine(!wasEditing ? ITEM_CLOSED : saveWaiting.current ? ITEM_CLOSED_EDITING_SENT : editorDirty.current ? ITEM_CLOSED_EDITING_NOT_KEPT : ITEM_CLOSED_EDITING);
    selectedRef.current = null;
    editingRef.current = null;
    editorDirty.current = false;
    setEditing(null);
    setEditorGenerate(false);
    setEditingVaultId(null);
    setSelected(null);
  }, [store]);
  const refresh = followStore;

  // Another tab of this browser profile moved a vault's log (or any record): the browser says so with a `storage` event.
  useEffect(() => {
    const onStorage = () => followStore();
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [followStore]);

  const dismissNotice = (id: string) => {
    store.dismissNotice(id);
    setNotices(store.notices());
  };

  // One sync path for the dirty-bell, every (re)open, the F29 offline poll, and the
  // manual "Sync now" button. It never throws (the WS callbacks run un-awaited inside
  // ApiClient.events), and it marks the sync healthy only AFTER a successful pull — so
  // the dot never shows "Connected" over data we failed to fetch. A SyncIntegrityError
  // (store's F31 rollback guard) lands in the same catch: state was kept, dot goes grey.
  const syncNow = useCallback(async () => {
    try {
      await store.sync();
      setSyncOk(true);
      // A pull that landed reached the server (its stamp moved past the copy's): the vault is no longer only this browser's copy.
      if (store.lastSyncAt !== copySyncedAt.current) setFromCopy(false);
      // G04: a landed full sync is the ONE moment the store's item set is provably COMPLETE, so
      // this is the only place the usage ledger may be pruned (usage.ts pruneUsage). The
      // pagehide/unmount/debounce flushes stay bare flush() — a partial/in-flight view there
      // would drop usage for items merely not loaded yet, which is data loss. The live set folds
      // in undecryptable/missing-VK ids too, so an item this device just can't read (newer fv,
      // unarrived grant) keeps its cross-device usage instead of being pruned away.
      void usage.flush(new Set([...store.list().map((it) => it.itemId), ...store.undecryptable().map((it) => it.itemId)]));
      setSyncLimit(null);
    } catch (e) {
      setSyncOk(false);
      // A sync the client's limit ended (the server stopped sending, or took too long) is said in a line of its own; the
      // poll below tries again, never without that word.
      setSyncLimit(answerLimitText(e));
    } finally {
      // Refresh on BOTH arms: a genuine offline-write denial THROWS out of sync() only
      // AFTER the pull applied and the store reverted the refused rows + minted the durable
      // "write-refused" notice — those must render even though this background catch
      // swallows the throw (the notice, not the throw, is the user-facing surface).
      followStore();
    }
  }, [store, usage, followStore]);

  // WS dirty-bell → pull. The bell auto-reconnects (client.ts: backoff + fresh ticket per
  // attempt) and onOpen fires on EVERY (re)open, so the sync there catches both the mint
  // round-trip window and any bells missed while the socket was down (no replay server-side).
  // The returned close fn is the effect cleanup — no socket leaks across lock/unlock cycles.
  useEffect(() => {
    if (readOnlyCopy) return; // §4.4: no socket to a forked origin (App closed a live one already)
    const close = client.events(
      (rev) => {
        // H38: remember the bell's rev BEFORE syncing — if this sync joins a pull already in
        // flight (single-flight), that pull's GET predates the bell's commit and would leave
        // the change invisible; store.sync() re-pulls once when the bell is still ahead.
        store.noteRev(rev);
        void syncNow(); // dirty bell
      },
      (kind) => onRevoked(kind), // session died server-side — App ends it (§4.4: the copy stays)
      () => {
        setWsUp(true);
        // PENDING until the catch-up pull lands: bells missed while the socket was
        // down aren't caught yet, so the dot must not go green on open alone.
        setSyncOk(false);
        void syncNow();
      },
      () => setWsUp(false), // sustained drop (debounced)
    );
    return close;
  }, [client, store, syncNow, onRevoked, readOnlyCopy]);

  // F29: with the socket down (WS-stripping proxy, blocked ticket mint) the bell can't
  // ring — and a bell-pull that FAILED with the socket healthy would otherwise never
  // retry. While either is unhealthy, poll over plain HTTP: first tick ~5 s after the
  // socket drops (a normal reconnect blip usually beats it) or ~10 s after a failed
  // sync, then every 60 s. Gating on the combined `degraded` keeps the chain
  // undisturbed across failures (a fail flips no state, so the cadence stays 60 s);
  // it stops the moment both are healthy again (effect cleanup). Timeouts are
  // chained, not an interval, so a slow sync never overlaps the next tick.
  useEffect(() => {
    if (!degraded) return;
    let cancelled = false;
    let timer: number | undefined;
    const tick = async () => {
      await syncNow();
      if (!cancelled) timer = window.setTimeout(() => void tick(), 60_000);
    };
    timer = window.setTimeout(() => void tick(), wsUp ? 10_000 : 5_000);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
    // wsUp only picks the first delay — re-arming on its change would reset the chain.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [degraded, syncNow]);

  const manualSync = async () => {
    setSyncBusy(true);
    try {
      await syncNow();
    } finally {
      setSyncBusy(false);
    }
  };

  // Vault metadata for badges + the new-item picker, read through the store's guarded reader at each render (a vault
  // whose key no longer works is not listed, whichever road moved its log), kept the same object while it reads the same.
  const vaultsNow = store.vaults();
  const vaultsKey = JSON.stringify(vaultsNow);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const vaultsInfo = useMemo(() => vaultsNow, [vaultsKey]);
  // The list's snapshot (re-read by followStore) shows, at each render, only the items of the vaults listed now: an
  // item of a vault that another tab, or any road outside this tab's sync, took away is not drawn even before the
  // snapshot is read again. Health, Staleness, Duplicates, the search and the rows all draw from this. The person's own
  // vault counts also where the server serves no row for it (VaultStore.shownVaultIds: named by the opened account only).
  const shownKey = store.shownVaultIds().join(",");
  const items = useMemo(() => {
    const listed = new Set(shownKey.split(","));
    return snapshot.filter((it) => listed.has(it.vaultId));
  }, [snapshot, shownKey]);
  const vaultNameById = useMemo(() => new Map(vaultsInfo.map((v) => [v.vaultId, v.name])), [vaultsInfo]);
  // Two vaults of one name are told apart by when each was made where vaults are listed to pick from. An item row's tag
  // keeps the plain name: on a phone the longer label pushed the item's own name out of its row.
  const vaultLabelById = useMemo(() => vaultLabels(vaultsInfo), [vaultsInfo]);

  // A vault filter pointing at a vault we no longer hold (left/revoked mid-session) degrades
  // to "all" instead of pinning the list to a silent empty set behind a blank select.
  const effVaultFilter = vaultFilter !== "all" && !vaultsInfo.some((v) => v.vaultId === vaultFilter) ? "all" : vaultFilter;
  const filtered = useMemo(() => {
    // Facets first (listview.ts), then the free-text search over what survives them.
    const base = applyListView(items, sortMode, typeFilter, effVaultFilter);
    const q = query.trim().toLowerCase();
    if (!q) return base;
    // F79: search name + username + EVERY uri (not just the first) + notes + a card's
    // brand/••last4 identity — so a login found only by its 2nd website, a secure note found
    // by its body, and a card found by "visa" all match. Secrets (passwords/PANs/CVVs) are
    // never search keys.
    return base.filter((it) => {
      const d = it.doc;
      if (d.name.toLowerCase().includes(q)) return true;
      if ((d.notes ?? "").toLowerCase().includes(q)) return true;
      if (d.type === "login" && d.login) {
        if ((d.login.username ?? "").toLowerCase().includes(q)) return true;
        if ((d.login.uris ?? []).some((u) => u.toLowerCase().includes(q))) return true;
      }
      if (d.type === "card") return cardSubtitle(d).toLowerCase().includes(q);
      return false;
    });
  }, [items, query, sortMode, typeFilter, effVaultFilter]);
  // New items may target the personal vault or any shared vault we can write to.
  // Design §3.13 as decided on 2026-11-17: a vault whose move's deletion waits takes nothing new, so it is no target.
  // Read per render from the store, not memoized: a move's deletion starts waiting, and a move's new vault appears,
  // without the item list changing (the walk of 2026-11-17 saw a stale picker offer the waiting vault).
  // Decided on 23 November 2026: a shared vault whose log is frozen or withheld here can be read and takes no write
  // (VaultStore.mayWrite), so it is no target either.
  const newItemVaultChoices = store.vaults().filter((v) => (v.type === "personal" || v.role === "owner" || v.role === "writer") && !store.moveDeleteWaiting(v.vaultId) && store.mayWrite(v.vaultId));
  // The one line above an item of such a vault, and above the list filtered to it.
  const moveWaitingLine = (vaultId: string | null | undefined) =>
    vaultId && store.moveDeleteWaiting(vaultId) ? (
      <div className="msg info" style={{ display: "block", marginTop: 12 }} role="status">{fill(MOVE_WAITING_READ_ONLY, vaultNameById.get(vaultId) ?? MOVE_UNNAMED_OLD)}</div>
    ) : null;

  // fv fail-close surface (design 2026-07-09): items sealed by a NEWER client sit in the
  // store's undecryptable set instead of degrading — surface a count so "invisible" reads
  // as "stored safely, pending an app update", for this fv bump and every future one.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const needsUpdate = useMemo(() => store.needsUpdateCount(), [store, items]);

  /**
   * quality-deadcode--6: ONE close-every-open-layer routine. This five-setter cluster used to be
   * hand-inlined at ten navigation/opener call sites, each with its own SUBSET — and the subsets
   * had already drifted: sharingSettingsVaultId (the layer added last) was missing from three of
   * them, so the recovery banner's "Go to Settings →" left a Sharing settings layer armed (and
   * an open Import/Export panel too), which then reappeared instead of the vaults list on the way
   * back. Callers now close everything and then open the ONE layer they want — the later setter
   * in the same batch wins — instead of expressing intent by which line they omitted.
   * Deliberately NOT used by save/remove (post-write teardown) or Detail's Edit (which keeps its
   * selection), neither of which is navigation. Layer z-order lives in closeTop above.
   */
  const closeLayers = useCallback(() => {
    setEditing(null);
    setEditorGenerate(false);
    setEditingVaultId(null);
    setImportOpen(false);
    setExportMode(null);
    setSelected(null);
    setSharingSettingsVaultId(null);
    setClosedLine(null);
  }, []);

  const startNew = (type: "login" | "note" | "card") => {
    closeLayers();
    setEditing(
      type === "login"
        ? { type, name: "", login: { username: "", password: "", uris: [""] } }
        : type === "card"
          ? { type, name: "", card: {} }
          : { type, name: "", notes: "" },
    );
  };

  const openItem = (it: VaultItem) => {
    closeLayers();
    setSelected(it.itemId);
  };

  const save = async (doc: ItemDoc, newFiles: PendingUpload[], onProgress?: (done: number, total: number) => void, vaultId?: string) => {
    // An edit names the vault its editor opened on (INV-EDIT); a new item names the picker's destination.
    saveWaiting.current = true;
    closedWhileSaving.current = false;
    try {
      await store.save(selected, doc, newFiles, onProgress, selected !== null ? (editingVaultId ?? undefined) : vaultId);
    } finally {
      saveWaiting.current = false;
    }
    // The save is done: the editor holds nothing unsaved any more. Its marks are cleared before the screen follows the
    // store, so that an item a removal took away meanwhile is closed as an item, never with "what you typed was not saved".
    editingRef.current = null;
    editorDirty.current = false;
    // Closed while it waited: the answer has come now, so the line no longer says the outcome is unknown.
    if (closedWhileSaving.current) {
      closedWhileSaving.current = false;
      setClosedLine((line) => (line === ITEM_CLOSED_EDITING_SENT ? ITEM_CLOSED : line));
    }
    refresh();
    setEditorGenerate(false);
    setEditing(null);
    setSelected(null);
  };

  const remove = async (itemId: string) => {
    await store.remove(itemId);
    leaveItem();
    refresh();
  };

  /** The person's own act took the open item off the list (a delete, a move): it is left, with no line about it. */
  const leaveItem = () => {
    selectedRef.current = null;
    setSelected(null);
  };

  /**
   * Jump to an item from a health/staleness surface. `generate` (H117) is the verification run's
   * post-"Wrong password" offer: the design's §4 table promises "bad → offers: open the item /
   * generate a new password", and the second one is only honest if it lands the user IN the
   * editor with a fresh password already in the field — an offer that merely opened the item
   * would be the first offer twice. Nothing is written until the user presses Save, so this is
   * still the human deciding; the Editor's own generate-confirm (which exists to stop a stray tap
   * clobbering a real password) is deliberately not re-asked here, because the whole click the
   * user just made WAS that consent.
   */
  const goToItem = (itemId: string, opts?: { generate?: boolean }) => {
    setView("vault");
    closeLayers();
    setSelected(itemId);
    if (opts?.generate) {
      const it = store.get(itemId);
      if (it && it.doc.type === "login") {
        setEditorGenerate(true);
        setEditing(it.doc);
        setEditingVaultId(it.vaultId);
      }
    }
  };

  const navBtn = (v: View, label: string) => (
    // a11yweb-05: aria-current marks the active view for AT (the .active class is visual only).
    <button className={`navbtn ${view === v ? "active" : ""}`} aria-current={view === v ? "page" : undefined} onClick={() => { if (editing && editorBack.current) return editorBack.current(); setView(v); closeLayers(); }}>{label}</button>
  );

  // The open item through the guarded reader at this render. The detail is drawn from it, and the editor of an existing
  // item is drawn only while it is handed out; a render that finds it gone has followStore close both and say why
  // (before the browser paints).
  const current = selected ? store.get(selected) : null;
  const openGone = selected !== null && current === undefined;
  useLayoutEffect(() => {
    if (openGone) followStore();
  }, [openGone, followStore]);
  const openGuard = useMemo(
    () => ({ shown: () => selected === null || store.get(selected) !== undefined, onGone: followStore }),
    [selected, store, followStore],
  );

  // One row for BOTH list paths — the virtualizer below is a slicing layer over
  // this exact element, not a second row implementation (F56).
  const renderRow = (it: VaultItem) => (
    <button className="item" key={it.itemId} onClick={() => openItem(it)}>
      <span className="glyph">{(it.doc.name || "?").charAt(0).toUpperCase()}</span>
      <span className="body">
        <div className="name">{it.doc.name || "(untitled)"}</div>
        <div className="sub">{it.doc.type === "login" ? it.doc.login?.username || it.doc.login?.uris?.[0] || "login" : it.doc.type === "card" ? cardSubtitle(it.doc) : "secure note"}</div>
      </span>
      {/* §D.3 (S4): an offline edit queued but not yet synced — the row reads as "saved here,
          will sync when you reconnect", never as lost. Cleared by the reconnect flush
          (syncNow/refresh re-render this row). */}
      {store.hasPendingSync(it.itemId) && (
        // a11y-webext--3: this used to paint with a --muted-strong fallback literal (#8a7a5c)
        // — the token is declared NOWHERE, so the literal always won, at 4.10:1 (dark) / 3.94:1 (light)
        // on the row surface: the app's lowest-contrast text on the one tag that says an
        // edit hasn't synced yet, and invisible to contrast.test.ts (it only reads tokens).
        // --ink-dim is the AA-cleared "stronger than muted" tone the fallback was reaching
        // for (6.3:1 / 5.8:1 on --bg-raised), and it is now pinned in that test.
        <span className="tag" title="Saved on this device — waiting to sync when you reconnect" aria-label="Pending sync" style={{ color: "var(--ink-dim)" }}>pending sync</span>
      )}
      {it.vaultId !== account.personalVaultId && (
        <span className="tag" style={{ color: "var(--gold-text)" }}>{vaultNameById.get(it.vaultId) ?? "shared"}</span>
      )}
      <span className="tag">{it.doc.type}</span>
    </button>
  );

  return (
    <div>
      {/* Audit F11: the signed-in app had NO landmarks but `nav`, so NVDA's landmark key and
          JAWS's region list offered no "main" to jump to — the appbar (brand + nav + status +
          Lock) and the vault view's 7-button toolbar had to be traversed on every arrival at
          content. The skip link is the first focusable node and is visible only on focus
          (.skip-link, styles.css, over the existing .visually-hidden utility). The extension's
          own options page already ships this shape (options.html header/main/section).
          G28: the activation is INTERCEPTED — the default jump would replace the whole fragment
          with #main-content (not a route, so routes.ts reads it as the vault list and refresh
          loses your place) AND push a history entry on top of useBackGuard's armed sentinel
          (whose self-pop would then consume this entry and orphan a sentinel that eats a later
          Back press). Focus moves to the <main> directly; fragment and history stay untouched. */}
      <a className="skip-link" href={`#${MAIN_ID}`} onClick={(e) => { e.preventDefault(); document.getElementById(MAIN_ID)?.focus(); }}>Skip to content</a>
      <header className="appbar">
        <div className="row">
          {/* The signed-in appbar carries the brand as every other header a browser draws does
              (the extension's popup and options headers, the web app's first screen): the rune,
              then the drawn name, so inside a browser the signed-in vault does not read as another
              product's chrome. The two native signed-in toolbars stay plain on purpose (the
              desktop's and the phone's title bars set the name as text in their title style): a
              platform toolbar is not browser chrome, and the phone shows its mark on its launcher
              icon. This is the lockup extension/popup.html ships (rune, then name, no whitespace
              between them: they are in inline flow, so a newline from JSX formatting would render
              as a gap); .brand .sigil-sm in styles.css is the twin of the popup.css rule. The rune
              is aria-hidden inside BrandSigil and the drawing is named "andvari", so a screen
              reader says the name once. */}
          <span className="brand"><span className="sigil-sm"><BrandSigil size={18} /></span><Wordmark /></span>
          <nav className="nav">
            {navBtn("vault", "Vault")}
            {navBtn("sharing", "Sharing")}
            {/* IA P1/DN-2, revised by owner dev-note 2026-08-18: Health grew into a two-view
                page (Passwords | Duplicates) and earned its nav place back; Trash stays a
                toolbar icon. Settings left the nav for the gear beside Lock — the appbar's
                right side is the session controls, and Settings is one. */}
            {navBtn("health", "Health")}
          </nav>
        </div>
        <div className="row">
          <span className="muted who" title={connStatus}>
            <span className={`dot ${online ? "on" : "off"}`} aria-hidden="true" />
            <span className="userid">{email || account.userId.slice(0, 8)}</span>
            {/* AM-3: a visually-hidden role=status TWIN inside .who. Its textContent mutates
                on the connectivity flip → announced; the email in .userid stays intact (an
                aria-label on .who would clobber it AND, as an attribute change, never announce). */}
            <span className="visually-hidden" role="status">{connStatus}</span>
          </span>
          {/* F29: while degraded, let the user pull over plain HTTP right now instead
              of waiting out the poll window. */}
          {/* §4.4: a read-only copy asks nothing of the server, so it offers no Sync now. */}
          {!online && !readOnlyCopy && (
            <button className="ghost" disabled={syncBusy} onClick={() => void manualSync()}>
              {syncBusy ? "Syncing…" : fromCopy ? OFFLINE_TRY_SERVER : "Sync now"}
            </button>
          )}
          {/* Owner dev-note 2026-08-18: the Settings entry point — a gear beside Lock. Same
              routing as the navBtn it replaces (editor back-guard first, then view + layers). */}
          <button
            type="button"
            className={`ghost ${view === "settings" ? "active" : ""}`}
            aria-label="Settings"
            title="Settings"
            aria-current={view === "settings" ? "page" : undefined}
            onClick={() => { if (editing && editorBack.current) return editorBack.current(); setView("settings"); closeLayers(); }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ verticalAlign: "-2px" }}>
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
          </button>
          <button className="ghost" onClick={onLock}>Lock</button>
        </div>
      </header>

      {mustChange && (
        <div className="banner">
          <span>Recovery sign-in — set a new master password now.</span>
          {/* quality-deadcode--6: this jump used to clear only editing+selected, so an open
              Import/Export panel or Sharing settings layer survived it and re-appeared on the
              way back (and left the F76 back guard armed over a layer that was no longer on
              screen). It closes every layer now, like the nav buttons it imitates. */}
          <button className="link" onClick={() => { if (editing && editorBack.current) return editorBack.current(); setView("settings"); closeLayers(); }}>Go to Settings →</button>
        </div>
      )}

      {/* Design §5.3: a withheld or unopenable personal wrap ⇒ "no personal vault" with the anomaly, no question. */}
      <NoPersonalVaultNotice account={account} />

      {/* §C6 (design 2026-07-13-web-offline-cache): an OFFLINE unlock with cached
          recoveryConfirmed !== true PROCEEDS with this persistent, non-dismissable REMINDER —
          deliberately reminder-not-error copy (the vault + account are fine; it also covers a
          cached flag left stale-false by a confirm on another device). It never blocks; the
          ONLINE capture gate (Welcome) still hard-blocks the next time this device reconnects,
          so the nag can't be ridden indefinitely. Same non-dismissable idiom as mustChange. */}
      {offlineRecoveryReminder && (
        <div className="banner">
          <span>Finish setting up your recovery phrase next time you're online.</span>
        </div>
      )}

      {/* Spec 02 §8: opened from this browser's offline copy, the server out of reach. The line stays until a sync lands,
          and the prompts below that need the server (shares to accept, a move to finish, the recovery copy's re-seal)
          wait for it instead of being offered as though they would work. */}
      {/* Sharing and Settings say it in their own line, beside what they show disabled: one line there, not two. */}
      {syncLimit !== null && !syncOk && (
        <div className="msg err top-prompt" style={{ display: "block" }} role="status" data-testid="sync-limit">{syncLimit}</div>
      )}
      {fromCopy && !readOnlyCopy && view !== "sharing" && view !== "settings" && (
        <div className="msg info top-prompt" style={{ display: "block" }} role="status">{OFFLINE_OPENED}</div>
      )}
      {/* Spec 01 §7, "leaves both": opened from the copy while the server serves keys this browser does not know; above
          every view, for the whole session. */}
      {settings?.wrap.serverKeysNotKnown === true && (
        <div className="msg err top-prompt" style={{ display: "block" }} role="status">{SERVER_KEYS_NOT_KNOWN_OPENED}</div>
      )}
      {/* Spec 01 §7: a sign-in over this browser's copy of the same account, sealed under another master password; the
          copy now follows the server's. One line, above the view the vault opened on, once (copyLineView). */}
      {copyLineView !== null && copyLineView === view && (
        <div className="msg info top-prompt" style={{ display: "block" }} role="status">{COPY_FOLLOWS_SERVER}</div>
      )}
      {!fromCopy && <SharedPrompts shared={store.sharedLogs()} onChanged={() => void syncNow()} />}
      {/* Design §3.13: a move whose old vault's deletion is signed and waiting says so here, first, and offers to finish. */}
      {!readOnlyCopy && !fromCopy && <UnfinishedMoves store={store} onChanged={() => void syncNow()} />}
      {/* Design §4.5 at unlock: the silent re-seal after a signed rotation, or "Keep that?" / the unsigned-change warning. */}
      <EscrowPrompt settings={readOnlyCopy || fromCopy ? undefined : settings} shared={store.sharedLogs()} />
      {/* §4.4: a copy read under a forked pin keeps the warning in view; it sends, accepts and writes nothing. */}
      {/* §4.4: the copy of a session the server ended says so instead ("with a notice in view"). */}
      {readOnlyCopy && store.readOnlyCopyReason() === "ended" ? (
        <div className="msg info" style={{ display: "block" }} role="status">{endedUnconfirmed(account.userId) ? SESSION_NOT_CONFIRMED_COPY : SESSION_ENDED_COPY}</div>
      ) : readOnlyCopy ? (
        <div className="msg err" style={{ display: "block" }} role="alert">{CARD_FORK}</div>
      ) : null}
      <NoticesBanner notices={notices} onDismiss={dismissNotice} store={store} onCopied={refresh} />

      {/* Calm, no-shame copy (the newer client is someone else's device, not an error), and
          deliberately non-dismissable — it clears itself once the items decrypt post-update
          (the mustChange banner idiom, not the dismissable notices one). */}
      {needsUpdate > 0 && (
        <div className="banner">
          <span>
            {needsUpdate === 1
              ? "1 item in your vaults was saved with a newer version of andvari — it’s stored safely and will appear here once this app is updated."
              : `${needsUpdate} items in your vaults were saved with a newer version of andvari — they’re stored safely and will appear here once this app is updated.`}
          </span>
        </div>
      )}

      {/* Audit F11: the one <main> of the signed-in app. The view switch below mounts exactly
          one view, and each view's ViewHeader title is that view's <h1> — so the landmark and
          the heading tree both say where the user is. */}
      <main className="wrap" id={MAIN_ID} tabIndex={-1}>
        <OpenItemGuard.Provider value={openGuard}>
        {/* The page heading for the two branches that render no ViewHeader — the vault
            (list / item / editor / import-export panels) and Trash. Visually hidden because
            both deliberately carry no visible view title; every other view's ViewHeader title
            IS the <h1>, so exactly one is mounted either way. */}
        {(view === "vault" || view === "trash") && <h1 className="visually-hidden">{VIEW_TITLES[view]}</h1>}
        {view === "health" ? (
          // bug-web--1: items (live state, refreshed by syncNow) — never the identity-stable
          // store, which froze Health's rows for the whole mount.
          <Health items={items} client={client} userId={account.userId} onOpenItem={goToItem} store={store} onChanged={refresh} clipboardClearSeconds={policy?.clipboardClearSeconds ?? 30} lastUsedAt={usage.lookup} onUsed={(id) => usage.record(id)} />
        ) : view === "trash" ? (
          <TrashView store={store} roleFor={(vaultId) => account.roleFor(vaultId)} onRestored={refresh} />
        ) : view === "sharing" ? (
          <Sharing
            account={account}
            store={store}
            client={client}
            onSynced={refresh}
            /* A8: "Back up first" leaves Sharing — the settings id clears with the other
               layer state, so the round-trip lands back on the vaults LIST. */
            onBackup={() => { setView("vault"); closeLayers(); setExportMode("backup"); }}
            settingsVaultId={sharingSettingsVaultId}
            onOpenSettings={setSharingSettingsVaultId}
            onCloseSettings={() => setSharingSettingsVaultId(null)}
            offline={fromCopy && !readOnlyCopy}
          />
        ) : view === "settings" ? (
          <Settings
            client={client}
            account={account}
            settings={settings}
            store={store}
            policy={policy}
            onPasswordChanged={() => setMustChange(false)}
            offline={fromCopy && !readOnlyCopy}
            /* IA P3: backing up from Settings flips to the vault view first so the ExportPanel
               layer renders (the view axis wins over exportMode in this switch), mirroring
               Sharing's "Back up first". Always offered while unlocked (§5.4.2). */
            onBackup={() => { setView("vault"); closeLayers(); setExportMode("backup"); }}
            onCsv={() => { setView("vault"); closeLayers(); setExportMode("csv"); }}
            /* Spec 03 §13: the deletion card's blocker links land where each blocker is resolved — the
               owned vault's settings under Sharing (Transfer / Delete), or Administration (invite an admin). */
            email={email}
            onAccountDeleted={onAccountDeleted}
            onDeletionTrack={onDeletionTrack}
            onOpenVaultSettings={(vaultId) => { setView("sharing"); closeLayers(); setSharingSettingsVaultId(vaultId); }}
          />
        ) : exportMode ? (
          <ExportPanel
            mode={exportMode}
            account={account}
            store={store}
            policy={policy}
            onClose={() => { setExportMode(null); refresh(); }}
          />
        ) : importOpen ? (
          <ImportPanel
            store={store}
            /* R47: the destination is resolved by identity, not by the server's `type` label. */
            personalVaultId={account.personalVaultId}
            // "‹ Back to vault" after an import that ran must show what it added, as Done does.
            onClose={() => { setImportOpen(false); refresh(); }}
            onDone={() => { setImportOpen(false); refresh(); }}
          />
        ) : editing && (selected === null || current) ? (
          <Editor
            initial={editing}
            policy={policy}
            // A new item is offered the vaults it may go to now, at each render; with the personal vault the only one, no
            // picker is drawn (the Editor draws one for more than one, or when the chosen vault is no longer offered).
            vaultChoices={selected === null ? newItemVaultChoices : undefined}
            dirtyRef={editorDirty}
            generateOnOpen={editorGenerate}
            onSave={save}
            // Whose space a refused save filled: the vault it goes to, as save() resolves it (an edit keeps its vault).
            ownsTarget={(picked) => {
              const target = selected !== null ? editingVaultId : (picked ?? account.personalVaultId);
              return target === null || target === undefined || target === account.personalVaultId || account.roleFor(target) === "owner";
            }}
            onCancel={() => { setEditing(null); setEditorGenerate(false); }}
            backRef={editorBack}
          />
        ) : current ? (
          <>
          {moveWaitingLine(current.vaultId)}
          <Detail
            item={current}
            client={client}
            store={store}
            policy={policy}
            readOnly={readOnlyCopy || account.roleFor(current.vaultId) === "reader" || store.moveDeleteWaiting(current.vaultId) || !store.mayWrite(current.vaultId)}
            // With readOnly, true only where the vault's log alone keeps it from being written: the key works here and
            // the member's role may write.
            copyOut={!readOnlyCopy && account.roleFor(current.vaultId) !== "reader" && !store.moveDeleteWaiting(current.vaultId) && account.mayWrite(current.vaultId)}
            vaultName={current.vaultId !== account.personalVaultId ? vaultNameById.get(current.vaultId) : undefined}
            moveTargets={newItemVaultChoices.filter((v) => v.vaultId !== current.vaultId)}
            onUsed={() => usage.record(current.itemId)}
            onEdit={() => { setEditing(current.doc); setEditingVaultId(current.vaultId); }}
            onDelete={() => remove(current.itemId)}
            onMoved={() => { leaveItem(); refresh(); }}
            onBack={() => setSelected(null)}
          />
          </>
        ) : (
          <>
            {closedLine !== null && <div className="msg info" style={{ display: "block", marginTop: 12 }} role="status" data-testid="item-closed">{closedLine}</div>}
            {effVaultFilter !== "all" && moveWaitingLine(effVaultFilter)}
            <div className="toolbar">
              <input aria-label="Search vault" placeholder="Search vault…" value={query} onChange={(e) => setQuery(e.target.value)} autoFocus={finePointer} />
              {/* §4.4: a read-only copy (a forked pin, a session the server ended) is read, copied from and exported;
                  nothing is written, so it offers no add and no import (the walk's C16 and C18 still showed them). */}
              {!readOnlyCopy && <button className="ghost" onClick={() => startNew("login")}>+ Login</button>}
              {!readOnlyCopy && <button className="ghost" onClick={() => startNew("note")}>+ Note</button>}
              {/* Dark until the Option A gate clears (0.2.x MSI retired) — see CARD_CREATE_ENABLED.
                  Everything downstream (row/detail/editor for EXISTING cards) renders regardless. */}
              {CARD_CREATE_ENABLED && !readOnlyCopy && <button className="ghost" onClick={() => startNew("card")}>+ Card</button>}
              {/* Owner dev-note 2026-08-18: Import/Export shrank to icons in the trash cluster so
                  the + buttons are the toolbar's only labeled actions; Health moved to the nav. */}
              {!readOnlyCopy && <button type="button" className="ghost" aria-label="Import" title="Import" onClick={() => { closeLayers(); setImportOpen(true); }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ verticalAlign: "-2px" }}>
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="3" x2="12" y2="15" />
                </svg>
              </button>}
              {/* The two export destinations live under one menu so the toolbar can't crush the
                  search box. Rendered whenever unlocked (§5.4.2 — the origin gate is gone). */}
              <ExportMenu
                onBackup={() => { closeLayers(); setExportMode("backup"); }}
                onCsv={() => { closeLayers(); setExportMode("csv"); }}
              />
              {/* DN-2: the Trash entry point — a small icon here instead of a main-nav item.
                  Mirrors navBtn's layer-clearing so it behaves like navigation, not a layer. */}
              <button
                type="button"
                className="ghost"
                aria-label="Trash"
                title="Trash"
                onClick={() => { closeLayers(); setView("trash"); }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ verticalAlign: "-2px" }}>
                  <path d="M3 6h18" /><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" /><path d="M10 11v6M14 11v6" />
                </svg>
              </button>
            </div>
            {/* Owner dev-note 2026-08-18: sort + facet row. Hidden while the vault is empty —
                there is nothing to arrange. The vault select only appears once a second vault
                exists (before that it could only ever say "all"). */}
            {items.length > 0 && (
              <div className="listctl">
                <select value={sortMode} aria-label="Sort" onChange={(e) => setSortMode(e.target.value as SortMode)}>
                  <option value="name">Sort: name</option>
                  <option value="recent">Sort: recently updated</option>
                </select>
                <select value={typeFilter} aria-label="Filter by type" onChange={(e) => setTypeFilter(e.target.value as TypeFilter)}>
                  <option value="all">All types</option>
                  <option value="login">Logins</option>
                  <option value="note">Notes</option>
                  {/* CARD_CREATE_ENABLED gates creation only — existing cards render regardless,
                      so the facet stays available. */}
                  <option value="card">Cards</option>
                </select>
                {vaultsInfo.length > 1 && (
                  <select value={effVaultFilter} aria-label="Filter by vault" onChange={(e) => setVaultFilter(e.target.value)}>
                    <option value="all">All vaults</option>
                    {vaultsInfo.map((v) => (
                      <option key={v.vaultId} value={v.vaultId}>{vaultLabelById.get(v.vaultId) ?? v.name}</option>
                    ))}
                  </select>
                )}
              </div>
            )}
            {filtered.length === 0 ? (
              <Empty>
                <p>{items.length === 0 ? "Your hoard is empty. Add your first secret." : query.trim() ? "Nothing matches that search." : "Nothing matches these filters."}</p>
              </Empty>
            ) : filtered.length > VIRTUAL_THRESHOLD ? (
              <VirtualList items={filtered} renderRow={renderRow} store={store} />
            ) : (
              <div className="list vault-list">{filtered.map(renderRow)}</div>
            )}
          </>
        )}
        </OpenItemGuard.Provider>
      </main>
    </div>
  );
}

/**
 * The open item's guard, for the item view and the editor and every part of them that renders by its own state (a Show,
 * a ticking code, typing, a history opened) without the vault screen rendering: [shown] asks the store's guarded reader at
 * that render whether the open item is still handed out; where it is not, the part draws nothing and [onGone] has the vault
 * screen follow the store (followStore), which closes the item and says why. Outside an open item it always answers yes.
 */
const OpenItemGuard = createContext<{ readonly shown: () => boolean; readonly onGone: () => void }>({ shown: () => true, onGone: () => {} });

function useStillShown(): boolean {
  const guard = useContext(OpenItemGuard);
  const here = guard.shown();
  useLayoutEffect(() => {
    if (!here) guard.onGone();
  }, [here, guard]);
  return here;
}

/** The import's destination is no longer one the person holds (it went while the panel was open, or the pick raced it). */
const DESTINATION_GONE = "That vault isn't available any more — it may have been removed. Pick another destination.";

/** Whether two reads of the list hand out the same items, in the same order (the store keeps an unchanged item's object). */
function sameItems(a: readonly VaultItem[], b: readonly VaultItem[]): boolean {
  return a.length === b.length && a.every((it, i) => it === b[i]);
}

// F56 vault-list windowing geometry. ROW_H/LIST_GAP mirror styles.css
// (.vault-list--virtual .item height / .list gap) — the three must move together. Audit F16:
// the pinned height now lives on the --virtual class, i.e. on exactly the path this stride
// describes; the plain branch's rows size to content and are not measured here.
const ROW_H = 72;
const LIST_GAP = 8;
const STRIDE = ROW_H + LIST_GAP;
const OVERSCAN = 8;
/** Perf addendum 2026-07-09: below ~500 rows the plain render wins on simplicity. */
const VIRTUAL_THRESHOLD = 500;

/**
 * F56: fixed-stride window over the vault list, engaged only past VIRTUAL_THRESHOLD.
 * The PAGE stays the scroller (no inner scrollbar, so the two render paths feel
 * identical); the visible slice derives from the host's viewport offset, recomputed
 * on scroll/resize behind one rAF. Keyboard focus needs no special casing in the
 * Tab direction: focusing a row near the window's edge makes the browser scroll it
 * into view, that scroll lands here, and the slice follows (overscan keeps the next
 * rows mounted for Tab). Accepted tradeoff (react-window has it too): a focused row
 * wheel-scrolled PAST the overscan unmounts and focus falls to body — restoring it
 * would yank the scroll back, which is worse; the plain ≤500 path keeps it mounted.
 *
 * The measuring effect is a LAYOUT effect: the initial state assumes scrollTop 0, and
 * a mount while scrolled deep (filter cleared) or a shrink via the background sync's
 * post-paint render would otherwise paint one stale/blank frame before correcting.
 *
 * It renders by its own state (a scroll, a resize) without the vault screen rendering, so it reads its rows through the
 * store's guarded reader at its own render (useListedNow, as Health does): a vault whose key stopped working by a road
 * this tab has not followed yet (another tab carried a removal out) draws no row.
 */
function VirtualList({ items: given, renderRow, store }: { items: VaultItem[]; renderRow: (it: VaultItem) => ReactElement; store: Pick<VaultStore, "shownVaultIds"> }) {
  const items = useListedNow(store, given);
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [range, setRange] = useState<WindowRange>(() => windowRange(0, window.innerHeight, STRIDE, OVERSCAN, items.length));

  useLayoutEffect(() => {
    let frame = 0;
    const update = () => {
      frame = 0;
      const host = hostRef.current;
      if (!host) return;
      // The host's viewport offset IS the list-relative scrollTop, negated.
      const next = windowRange(-host.getBoundingClientRect().top, window.innerHeight, STRIDE, OVERSCAN, items.length);
      setRange((r) => (next.start === r.start && next.end === r.end ? r : next));
    };
    const schedule = () => {
      if (!frame) frame = window.requestAnimationFrame(update);
    };
    update();
    // Capture-phase: scroll doesn't bubble, so any non-document ancestor scroller
    // would otherwise be invisible here.
    window.addEventListener("scroll", schedule, true);
    window.addEventListener("resize", schedule);
    return () => {
      window.removeEventListener("scroll", schedule, true);
      window.removeEventListener("resize", schedule);
      if (frame) window.cancelAnimationFrame(frame);
    };
  }, [items.length]);

  return (
    // The spacer holds the full scroll height (last row carries no trailing gap);
    // the absolutely-placed slice sits exactly where its rows would have laid out.
    <div ref={hostRef} style={{ position: "relative", height: items.length * STRIDE - LIST_GAP }}>
      {/* Audit F16: `vault-list--virtual` is what pins the 72px row height — ONLY this path
          needs one fixed stride (the plain ≤500-row branch sizes to content, so a raised
          browser minimum font size can't clip the row's `.sub` line there). */}
      <div className="list vault-list vault-list--virtual" style={{ position: "absolute", top: range.start * STRIDE, left: 0, right: 0 }}>
        {items.slice(range.start, range.end).map(renderRow)}
      </div>
    </div>
  );
}

export function noticeBody(n: LifecycleNotice): { body: string; warn: boolean } {
  const name = n.vaultName || "a vault";
  switch (n.kind) {
    case "personal-kept":
      return { warn: true, body: PERSONAL_REMOVAL_REFUSED };
    case "held-not-made":
    case "held-given-up":
    case "held-found-made":
      return { warn: true, body: heldNoticeText(n) };
    case "held-found-not-made":
      return { warn: false, body: heldNoticeText(n) };
    case "held-delete-ask":
      // A vault it cannot name has words of its own: never "the new vault", which is a move's.
      return { warn: true, body: n.vaultName ? fill(RESEND_DELETE_ASK, n.vaultName) : RESEND_DELETE_ASK_UNNAMED };
    case "held-delete-made":
      // The day only where the server served it; otherwise the line points to the list of deleted vaults.
      if (n.purgeAt === undefined) return { warn: true, body: n.vaultName ? fill(RESEND_DELETE_MADE_NO_DAY, n.vaultName) : RESEND_DELETE_MADE_UNNAMED_NO_DAY };
      return { warn: true, body: n.vaultName ? fill(RESEND_DELETE_MADE, n.vaultName, fmtDay(n.purgeAt)) : fill(RESEND_DELETE_MADE_UNNAMED, fmtDay(n.purgeAt)) };
    case "half-made-kept":
      return { warn: true, body: fill(MOVE_DISCARD_KEPT, n.vaultName || MOVE_UNNAMED_VAULT) };
    case "item-brought-back": {
      // One change has a line of its own, named or not; "1 of your changes" is never said.
      const count = n.parkedCount ?? 1;
      if (count === 1) return { warn: false, body: n.itemName !== undefined ? fill(ITEM_BROUGHT_BACK, n.itemName, name) : fill(ITEM_BROUGHT_BACK_UNNAMED, name) };
      return { warn: false, body: fill(ITEM_BROUGHT_BACK_MANY, String(count), name) };
    }
    case "move-stored": {
      // Design §3.13 as decided on 2026-11-17: never a quiet departure. What is late, and what this browser cannot save.
      const newName = n.newVaultName || MOVE_UNNAMED_VAULT;
      const added = n.lateAdded ?? 0;
      const changed = n.lateChanged ?? 0;
      const count = (k: number): string => `${k} ${k === 1 ? "item" : "items"}`;
      const late = added + changed === 0 ? fill(MOVE_STORED_NOTHING_LATE, newName) : fill(MOVE_STORED_LATE, count(added + changed), String(added), String(changed), newName);
      // Not "the server deleted": the same person may have deleted it from another device meanwhile (the stored deletion
      // is not compared with the held one), so the line names no one.
      return { warn: true, body: `${fill(MOVE_DELETED_OUTSIDE, name, newName)} ${late} ${MOVE_STORED_UNSEEN}` };
    }
    case "deleted":
      return {
        warn: false,
        body:
          `“${name}” was deleted by its owner. Its items were moved off this device` +
          // Design §3.8: the day this device's copy leaves the holding area, never the vault's purge time.
          (n.keptUntil ? ` (kept sealed until ${fmtDay(n.keptUntil)}, then removed).` : ".") +
          // One edit has a line of its own, never "1 of your edits".
          (n.parkedCount === 1 ? ` ${DELETED_PARKED_ONE}` : n.parkedCount ? ` ${n.parkedCount} of your edits hadn’t synced — they’ll be recovered if the vault is restored this week.` : ""),
      };
    case "removed":
      // A7 review MEDIUM-2 / LOW-3: TWINS of core HouseholdCopy.removalAlreadyRecordedNotice / removedLegacyNotice,
      // byte-equal (pinned by vault-copy.test.ts).
      if (n.reason === ALREADY_RECORDED) return { warn: false, body: `Your access to “${name}” was removed — already recorded on another of your devices.` };
      if (n.reason === REMOVED_LEGACY) return { warn: false, body: `Your access to “${name}” was removed (sent by an older app version).` };
      return { warn: false, body: `Your access to “${name}” was removed.` };
    case "left":
      // Root cause A §8.6 (branch A7): a leave with no proof, in the compatibility window, adds the one line that
      // lets the human catch a forged one. TWIN of core HouseholdCopy.leftUnprovenNotice, byte-equal (pinned).
      if (n.reason === LEFT_UNPROVEN) return { warn: true, body: `You left “${name}”. Didn't do this? Tell your admin.` };
      // A7 review MEDIUM-2: TWIN of core HouseholdCopy.leftAlreadyRecordedNotice, byte-equal.
      if (n.reason === ALREADY_RECORDED) return { warn: false, body: `You left “${name}” — already recorded on another of your devices.` };
      return { warn: false, body: `You left “${name}”.` };
    case "restored":
      return { warn: false, body: `“${name}” was restored.` };
    case "replay-denied": {
      // Root cause A §6.3 step 5 (branch A7): a REPLAYED removal proof (consumed nonce). Danger tone. TWIN of core
      // HouseholdCopy.removalReplayDeniedNotice, byte-equal (pinned by vault-copy.test.ts).
      if (n.reason === REMOVAL_REPLAY) {
        return {
          warn: true,
          body:
            `The server says you lost access to “${name}”, but it sent a removal notice that was already used once, so andvari did not trust it. ` +
            `A sealed copy of its data is kept on this device for 30 days (Sharing → the trash icon). ` +
            `If nobody in your household did this, tell your admin — the server may be misbehaving.`,
        };
      }
      // C1 (core LC-1): recovered (F21-parked) edits replayed after a restore, refused on the
      // now-live vault — the member's role likely changed across the grace. Calm, never an error.
      // TWIN of core HouseholdCopy.replayDeniedNotice, byte-equal — web can't import Kotlin, so
      // these two templates are pinned against the Kotlin source by vault-copy.test.ts
      // (ux-copy--3: this sentence had drifted three ways from the natives'). Both sides move
      // together; `count` is named to match the canon's parameter the pin substitutes.
      const count = n.parkedCount ?? 0;
      return {
        warn: false,
        body:
          count === 1
            ? `A recovered edit to “${name}” couldn't be applied — your access may have changed while the vault was deleted.`
            : `${count} recovered edits to “${name}” couldn't be applied — your access may have changed while the vault was deleted.`,
      };
    }
    case "write-refused": {
      // C2/M3: offline/queued changes genuinely denied at classification. The store restores
      // each refused item to its last synced value WHEN IT CAN (revertedCount) — the copy must
      // not claim a restore that didn't happen: an item the server itself deleted meanwhile
      // stays removed (removedCount, M1), and one with no usable snapshot may keep showing the
      // refused value until the vault next fully refreshes. This banner is the durable surface
      // (the sync() throw behind it is often swallowed by a background sync).
      const total = n.parkedCount ?? 0;
      const one = total === 1;
      const lead = one
        ? `An offline change to “${name}” was refused — you no longer have permission.`
        : `${total} offline changes to “${name}” were refused — you no longer have permission.`;
      let tail: string;
      if (total > 0 && (n.revertedCount ?? 0) === total) {
        tail = one ? "The item was restored to its last synced value." : "The items were restored to their last synced values.";
      } else if (total > 0 && (n.removedCount ?? 0) === total) {
        tail = one
          ? "That item was already deleted by someone else in your household, so it stays removed."
          : "Those items were already deleted by someone else in your household, so they stay removed.";
      } else {
        tail = one
          ? "The item couldn't be restored here and may be out of date until the vault next refreshes."
          : "Some items couldn't be restored here and may be out of date until the vault next refreshes.";
      }
      return { warn: true, body: `${lead} ${tail}` };
    }
    case "write-rejected": {
      // H03/H19: queued rows the server DEFINITIVELY refused (dangling attachment refs, over
      // cap) and the drain dropped as poison rows instead of re-sending forever. The LEAD is
      // core HouseholdCopy.writeRejectedNotice, byte-equal (pinned by vault-copy.test.ts —
      // the natives render the Kotlin function directly); the revert TAIL is web-only because
      // only web applies writes optimistically. NOT the write-refused (permission) sentence:
      // nothing about the member's access changed — the write could never apply as sent.
      const count = n.parkedCount ?? 0;
      const one = count === 1;
      const lead = one ? `An offline change to “${name}” couldn't be applied` : `${count} offline changes to “${name}” couldn't be applied`;
      let why: string;
      if (n.reason === "unknown_attachment" || n.reason === "attachment_mismatch") {
        why = one ? "an attachment it referenced no longer exists there." : "attachments they referenced no longer exist there.";
      } else if (n.reason === "item_attachment_quota" || n.reason === "body_too_large") {
        why = one ? "it was too large for the server to accept." : "they were too large for the server to accept.";
      } else {
        why = one ? "the server refused it." : "the server refused them.";
      }
      let tail: string;
      if (count > 0 && (n.revertedCount ?? 0) === count) {
        tail = one ? "The item was restored to its last synced value." : "The items were restored to their last synced values.";
      } else if (count > 0 && (n.removedCount ?? 0) === count) {
        tail = one
          ? "That item was already deleted by someone else in your household, so it stays removed."
          : "Those items were already deleted by someone else in your household, so they stay removed.";
      } else {
        tail = one
          ? "The item couldn't be restored here and may be out of date until the vault next refreshes."
          : "Some items couldn't be restored here and may be out of date until the vault next refreshes.";
      }
      return { warn: true, body: `${lead} — ${why} ${tail}` };
    }
    case "added":
      // TWIN of core HouseholdCopy.addedNotice without a label, byte-equal, pinned by vault-copy.test.ts. The web's one
      // "added" notice carries no adder (the label branch was dead and is gone).
      return { warn: false, body: `You were added to “${name}”.` };
    case "transfer-complete":
      return { warn: false, body: n.becameMine ? `You are now the owner of “${name}”.` : `“${name}” now has a new owner.` };
    case "transfer-anomaly":
      return {
        warn: true,
        body:
          `The server says “${name}” changed owners, but this couldn’t be verified with the vault’s own key. ` +
          `If nobody in your household did this, tell your admin — the server may be misbehaving.`,
      };
    case "anomaly":
      return {
        warn: true,
        body:
          `The server says you lost access to “${name}”, but this couldn’t be verified as a real owner action. ` +
          `A sealed copy of its data is kept on this device for 30 days (Sharing → the trash icon). ` +
          `If nobody in your household did this, tell your admin — the server may be misbehaving.`,
      };
    case "left-frozen":
      // A removal of a vault frozen here, after the person's own leave of it: never quiet, since nothing after the leave
      // can be checked. The copy is held as at the anomaly.
      return { warn: true, body: fill(VAULT_LEFT_FROZEN_NOTICE, name) };
    case "unchecked-gone":
      // A full pull that holds nothing of the vault no longer grants a shared vault frozen here: no name, nothing held.
      return { warn: true, body: VAULT_GONE_UNCHECKED_NOTICE };
    case "items-set-aside": {
      // A full list neither carried nor marked as deleted items this browser held: they were set aside, never dropped.
      const count = `${n.parkedCount ?? 0} ${n.parkedCount === 1 ? "item" : "items"}`;
      if (n.personal === true) return { warn: true, body: fill(ITEMS_SET_ASIDE_PERSONAL_NOTICE, count) };
      return { warn: true, body: fill(n.frozen === true ? ITEMS_SET_ASIDE_FROZEN_NOTICE : ITEMS_SET_ASIDE_SHARED_NOTICE, count, name) };
    }
    case "items-set-aside-other": {
      // Items set aside were sent again in their vault with other content than the copy kept here: the copy stays.
      const count = `${n.parkedCount ?? 0} ${n.parkedCount === 1 ? "item" : "items"}`;
      return { warn: true, body: fill(ITEMS_SET_ASIDE_OTHER_NOTICE, count, n.personal === true ? ITEMS_SET_ASIDE_PERSONAL_NAME : name) };
    }
    case "vk-mismatch":
      // Root cause A §3.1 (security review 2026-10): the held key was kept and a row's wrap of another key ignored.
      // TWIN of core HouseholdCopy.vkMismatchNotice, byte-equal, pinned by vault-copy.test.ts.
      return {
        warn: true,
        body: `The server sent a key for “${name}” that doesn't match the one saved for your account. andvari kept your own key and ignored the other. Tell your admin — the server may be misbehaving.`,
      };
    case "wrong-vault":
      // Root cause A §5.1 INV-HOME (A1b): a served row named another vault than the one this browser holds the item in;
      // it was not applied. TWIN of core HouseholdCopy.WRONG_VAULT_NOTICE, byte-equal, pinned by vault-copy.test.ts.
      return {
        warn: true,
        body: "The server sent an item under the wrong vault. andvari kept the item where it was and ignored the other copy. Tell your admin — the server may be misbehaving.",
      };
    case "bad-id":
      // Security review 2026-10 plugin scan F1 (A10): served rows with malformed ids were refused at the wire. TWIN of
      // core HouseholdCopy.BAD_ID_NOTICE, byte-equal, pinned by vault-copy.test.ts.
      return {
        warn: true,
        body: "The server sent records with malformed ids. andvari ignored them and kept your vaults as they were. Tell your admin — the server may be misbehaving.",
      };
    case "meta-regression":
      // spec 02 §4 warn-and-keep-newer: a delivered metaBlob whose metaV regressed below the
      // one held here was kept as-is (anti-replay). Calm, informational — never an error tone.
      return {
        warn: false,
        body:
          `A saved change to “${name}” looked older than expected and was kept as-is — ` +
          `if a recent change is missing, re-save it.`,
      };
  }
}

/** The lifecycle notices banner (spec 03 §11): attributed only when the proof verified; the
 *  anomaly warning renders in the danger tone. Each notice is individually dismissable. */
function NoticesBanner({ notices, onDismiss, store, onCopied }: { notices: LifecycleNotice[]; onDismiss: (id: string) => void; store?: VaultStore; onCopied?: () => void }) {
  if (notices.length === 0) return null;
  return (
    <div className="wrap" style={{ paddingBottom: 0 }}>
      {notices.map((n) => {
        const { body, warn } = noticeBody(n);
        return (
          <div key={n.id} className={`msg ${warn ? "err" : "info"}`} role={warn ? "alert" : undefined} style={{ display: "flex", alignItems: "flex-start", gap: 12 }}>
            <span style={{ flex: 1 }}>
              {body}
              {n.kind === "move-stored" && store !== undefined && <MoveLateCopy notice={n} store={store} onCopied={onCopied} />}
              {n.kind === "held-delete-ask" && store !== undefined && <HeldDeleteAsk notice={n} store={store} onDone={() => { onDismiss(n.id); onCopied?.(); }} />}
            </span>
            <button type="button" className="link" onClick={() => onDismiss(n.id)}>Dismiss</button>
          </div>
        );
      })}
    </div>
  );
}

/**
 * The two acts under a "held-delete-ask" notice: the person's deletion of the vault waits and is sent again only at
 * their word. Delete it now (sent once, byte for byte), or keep the vault (the deletion is withdrawn). Nothing is sent
 * until one is chosen; a failure is said under the notice.
 */
export function HeldDeleteAsk({ notice, store, onDone }: { notice: LifecycleNotice; store: VaultStore; onDone: () => void }) {
  const [busy, setBusy] = useState(false);
  const [line, setLine] = useState("");
  if (line === "" && store.heldChangeFor(notice.vaultId)?.kind !== "delete") return null;
  const deleteNow = async () => {
    setBusy(true);
    setLine("");
    try {
      await store.sendHeldDeletion(notice.vaultId);
      onDone();
    } catch (e) {
      setLine(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };
  const keep = () => {
    const known = store.withdrawHeldChangeAs(notice.vaultId);
    if (known === null) onDone();
    else setLine(withdrawnText(known));
  };
  return (
    <span style={{ display: "block", marginTop: 6 }}>
      {line !== "" && <span style={{ display: "block" }}>{line}</span>}
      {store.heldChangeFor(notice.vaultId)?.kind === "delete" && (
        <>
          <button type="button" className="ghost" disabled={busy} onClick={deleteNow} style={{ color: "var(--danger)" }}>{RESEND_DELETE_ASK_NOW}</button>{" "}
          <button type="button" className="ghost" disabled={busy} onClick={keep}>{RESEND_DELETE_ASK_KEEP}</button>
        </>
      )}
    </span>
  );
}

/**
 * Design §3.13 as decided on 2026-11-17: the offer under a "move-stored" notice, to copy what the move had not copied
 * from the copy kept here into the new vault. Shown only while the held copy has something late and the new vault is
 * this browser's; after the copy it says how many landed.
 */
export function MoveLateCopy({ notice, store, onCopied }: { notice: LifecycleNotice; store: VaultStore; onCopied?: () => void }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState("");
  const [err, setErr] = useState("");
  const late = store.moveLate(notice.vaultId);
  const newName = notice.newVaultName || MOVE_UNNAMED_VAULT;
  if (done !== "") return <span style={{ display: "block", marginTop: 6 }}>{done}</span>;
  if (late === null || late.added + late.changed === 0 || !store.vaults().some((v) => v.vaultId === late.newVaultId)) return null;
  const run = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await store.copyLateIntoMove(notice.vaultId);
      setDone(fill(MOVE_STORED_COPIED, `${r.copied} ${r.copied === 1 ? "item" : "items"}`, newName));
      onCopied?.(); // the list shows the copies at once (the walk of 2026-11-17 found it stale until the next sync)
    } catch (e) {
      setErr(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <span style={{ display: "block", marginTop: 6 }}>
      {err && <span style={{ display: "block" }}>{err}</span>}
      <button type="button" className="ghost" disabled={busy} onClick={run}>{fill(MOVE_STORED_COPY, newName)}</button>
    </span>
  );
}

/** Toolbar Export disclosure — folds the two export destinations under one button (they were
 *  the widest toolbar items and crushed the search box in 0.4.0; the trigger shrank to an icon
 *  with the 2026-08-18 toolbar reorg). Closes on outside-click, Escape, or scroll; supports
 *  arrow-key menu navigation; flips its horizontal anchor so it never renders off the viewport
 *  edge on a phone. */
function ExportMenu({ onBackup, onCsv }: { onBackup: () => void; onCsv: () => void }) {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const btnRef = useRef<HTMLButtonElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const close = (returnFocus: boolean) => {
    setOpen(false);
    if (returnFocus) btnRef.current?.focus();
  };

  const toggle = () => setOpen((o) => !o);

  // Clamp the (possibly wider-than-button) menu into the viewport regardless of where the
  // wrapped toolbar put the trigger — the long "Export…" label makes it ~315px, which
  // overflows a phone if simply anchored to one side. Runs pre-paint so there's no flicker.
  useLayoutEffect(() => {
    const m = menuRef.current;
    if (!open || !m) return;
    m.style.transform = "";
    const r = m.getBoundingClientRect();
    let shift = 0;
    if (r.right > window.innerWidth - 8) shift = window.innerWidth - 8 - r.right;
    if (r.left + shift < 8) shift = 8 - r.left;
    if (shift) m.style.transform = `translateX(${Math.round(shift)}px)`;
  }, [open]);

  // Focus the first item when the menu opens (keyboard menu semantics).
  useEffect(() => {
    if (open) itemRefs.current[0]?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => { if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false); };
    const onScroll = () => setOpen(false);
    document.addEventListener("mousedown", onDoc);
    // Scroll (esp. touch) would otherwise slide the open menu over the sticky appbar.
    window.addEventListener("scroll", onScroll, true);
    return () => { document.removeEventListener("mousedown", onDoc); window.removeEventListener("scroll", onScroll, true); };
  }, [open]);

  const onMenuKey = (e: React.KeyboardEvent) => {
    const items = itemRefs.current.filter(Boolean) as HTMLButtonElement[];
    const idx = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "Escape") { e.preventDefault(); close(true); }
    else if (e.key === "ArrowDown") { e.preventDefault(); items[(idx + 1 + items.length) % items.length]?.focus(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); items[(idx - 1 + items.length) % items.length]?.focus(); }
    // a11yweb-08: Tab closes the menu (no preventDefault, no focus return) so focus proceeds
    // out per the WAI-ARIA menu-button pattern instead of stranding an open menu behind it.
    else if (e.key === "Tab") setOpen(false);
  };

  const choose = (fn: () => void) => { close(false); fn(); };

  return (
    <div className="menu-wrap" ref={wrapRef}>
      <button ref={btnRef} type="button" className="ghost" aria-label="Export" title="Export" aria-haspopup="menu" aria-expanded={open} onClick={toggle}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ verticalAlign: "-2px" }}>
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" />
        </svg>
      </button>
      {open && (
        <div ref={menuRef} className="menu" role="menu" onKeyDown={onMenuKey}>
          <button ref={(el) => { itemRefs.current[0] = el; }} type="button" role="menuitem" onClick={() => choose(onBackup)}>Back up vault…</button>
          <button ref={(el) => { itemRefs.current[1] = el; }} type="button" role="menuitem" onClick={() => choose(onCsv)}>Export for another password manager…</button>
        </div>
      )}
    </div>
  );
}

// ---- copy with auto-clear ----
/** H53: the Detail's website rows — every NON-BLANK saved uri, in stored order (spec 02 §3.1 lets
 *  a login carry several; the search matches on all of them, F79, so the view lists all of them).
 *  Exported pure so vault-copy.test.ts can pin it without a render seam. */
export function detailUris(uris: string[] | undefined): string[] {
  return (uris ?? []).filter((u) => u.trim().length > 0);
}

/**
 * An item's detail. [readOnly]: nothing that writes the item or its vault is offered. [copyOut]: the person may copy the
 * item out though [readOnly] holds, which is so where only its vault's log keeps the vault from being written (frozen or
 * withheld here; decided on 23 November 2026: such a vault is read, written by no device, and its items are copied out).
 */
export function Detail({ item, client, store, policy, readOnly, copyOut, vaultName, moveTargets, onUsed, onEdit, onDelete, onMoved, onBack }: { item: VaultItem; client: ApiClient; store: VaultStore; policy: ClientPolicy | null; readOnly: boolean; copyOut: boolean; vaultName?: string; moveTargets: VaultInfo[]; onUsed: () => void; onEdit: () => void; onDelete: () => Promise<void>; onMoved: () => void; onBack: () => void }) {
  const shownNow = useStillShown();
  // §2.3 clamp (B1-1): a server-declared clipboard window is honored only inside [1, 300 s].
  const clearSecs = clampClipboardClearSeconds(policy?.clipboardClearSeconds ?? 30);
  const { flash, copyErr, wipeStuck, copy } = useCopy(clearSecs);
  const [deleting, setDeleting] = useState(false);
  const [delBusy, setDelBusy] = useState(false);
  const [delErr, setDelErr] = useState("");
  const doc = item.doc;
  /** The one copy-state pill for every secret row (audit F05): the auto-clear promise, retracted
   *  in place when the platform refused the wipe — it used to assert "clears in Ns" regardless. */
  const copyPill = (label: string) =>
    flash === label ? <span className="copy-flash">{wipeStuck ? CLIPBOARD_NOT_CLEARED_SHORT : `copied ✓ · clears in ${clearSecs}s`}</span> : null;

  // Mirror the Editor's save path: await the delete, and on failure keep the confirm open
  // with a message instead of silently closing it while the item still exists everywhere.
  // store.remove only throws when the delete did NOT commit (a post-commit reconcile
  // failure is swallowed there), so "nothing was removed" is truthful in every branch —
  // but a 403 is a permissions problem, not a connectivity one, and must say so.
  const confirmDelete = async () => {
    setDelErr("");
    setDelBusy(true);
    try {
      await onDelete(); // resolves → parent unmounts this Detail; no need to reset busy
    } catch (e) {
      setDelErr(
        e instanceof CopyBeingRemovedError
          ? copyRemovalText(e)
          : e instanceof ApiError && e.status === 403
          ? `You don't have permission to delete “${doc.name}” — your access to this vault may have been changed to view-only. Nothing was removed.`
          : e instanceof ApiError
            ? `The server refused to delete “${doc.name}” — nothing was removed. Try again in a moment.`
            : `Couldn't reach the server to delete “${doc.name}” — nothing was removed. Try again when you're connected.`,
      );
      setDelBusy(false);
    }
  };
  if (!shownNow) return null;
  return (
    <div className="sheet">
      {/* BL-1: copy confirmation is polite async info — the visible .copy-flash span mounts
          already-populated (silent), so announce it off this persistent region, named by
          which field was copied ("password copied", "code copied", …). */}
      <Announcer text={wipeStuck ? CLIPBOARD_NOT_CLEARED : copyErr ? CLIPBOARD_FAILED : flash ? `${flash} copied` : ""} />
      <BackLink label="Back to vault" onClick={onBack} />
      {/* ux-error--2: the visible half of the copy-failure surface — same canon sentence the
          extension popup shows on its toClipboard catch. */}
      {copyErr && <Msg kind="err">{CLIPBOARD_FAILED}</Msg>}
      {/* Audit F05: the copy landed but the auto-clear was refused (the pill is long gone by
          then, so the retraction needs a surface of its own). A retry is armed for the next
          focus — if it lands, this clears itself. */}
      {wipeStuck && <Msg kind="err">{CLIPBOARD_NOT_CLEARED}</Msg>}
      <h2 style={{ marginTop: 12 }}>{doc.name}</h2>
      <div className="muted" style={{ marginBottom: 18 }}>
        {/* Cards identify themselves by brand + ••last4 (design contract) — the one line
            that lets the user pick the right card without revealing the full PAN. */}
        {doc.type === "login" ? "Login" : doc.type === "card" ? (doc.card?.number ? cardSubtitle(doc) : "Card") : "Secure note"}
        {vaultName && <> · in “{vaultName}”</>}
        {readOnly && <> · view only</>}
      </div>

      {doc.type === "login" && doc.login && (
        <>
          {doc.login.username && (
            <div className="field">
              <label>Username</label>
              <div className="secret-row">
                <input readOnly aria-label="Username" value={doc.login.username} className="mono" />
                <button className="ghost" onClick={() => copy("username", doc.login!.username!)}>Copy</button>
              </div>
            </div>
          )}
          {doc.login.password && (
            <div className="field">
              <label>Password {copyPill("password")}</label>
              <div className="secret-row">
                <PasswordField label="Password" value={doc.login.password} />
                <button className="ghost" onClick={() => { onUsed(); copy("password", doc.login!.password!); }}>Copy</button>
              </div>
            </div>
          )}
          {doc.login.totp && <TotpView uri={doc.login.totp} pill={copyPill("code")} onCopy={(code) => { onUsed(); copy("code", code); }} />}
          {/* H53 (audit 2026-09-13): the website was a read-only text box — no link, no copy, and
              only uris[0] — while the extension detail, the Staleness run card and the Duplicates
              checker all offer a safeSiteHref link. Every saved uri is listed; a navigable one is
              an "open site" link (the click is a genuine use, as Staleness records — it is the
              sign-in the password was just copied for) and a rejected one (safeSiteHref: http(s)
              only — in a SHARED vault another member authored it, which is what makes a
              javascript: value a real vector) stays inert text, never rendered as a link anyway.
              Copy hands the raw stored value over, for parity with every other Detail row. */}
          {detailUris(doc.login.uris).length > 0 && (
            <div className="field">
              <span className="field-head">{detailUris(doc.login.uris).length === 1 ? "Website" : "Websites"}</span>
              {detailUris(doc.login.uris).map((uri, i) => {
                const href = safeSiteHref(uri);
                return (
                  <div className="secret-row" key={`${i}:${uri}`} style={{ marginBottom: 6 }}>
                    {href ? (
                      <a className="link site-uri" href={href} target="_blank" rel="noreferrer" onClick={onUsed}>{uri} ↗</a>
                    ) : (
                      <span className="site-uri">{uri}</span>
                    )}
                    <button className="ghost" onClick={() => copy("website", uri)}>Copy</button>
                  </div>
                );
              })}
            </div>
          )}
          {doc.login.password && <HealthLine password={doc.login.password} client={client} />}
        </>
      )}

      {doc.type === "card" && doc.card && (
        <>
          {doc.card.cardholderName && (
            <div className="field">
              <label>Cardholder</label>
              <div className="secret-row">
                <input readOnly aria-label="Cardholder" value={doc.card.cardholderName} />
                <button className="ghost" onClick={() => copy("cardholder", doc.card!.cardholderName!)}>Copy</button>
              </div>
            </div>
          )}
          {doc.card.number && (
            <div className="field">
              <label>Card number {copyPill("card number")}</label>
              {/* Reveal shows the grouped form; Copy hands checkout forms the bare digits. */}
              <div className="secret-row">
                <PasswordField label="Card number" value={groupNumber(doc.card.number)} />
                <button className="ghost" onClick={() => copy("card number", doc.card!.number!)}>Copy</button>
              </div>
            </div>
          )}
          {expiryLabel(doc.card) !== null && (
            <div className="field">
              <label>Expiry</label>
              <div className="secret-row" style={{ alignItems: "center" }}>
                <input readOnly aria-label="Expiry" className="mono" value={expiryLabel(doc.card)!} />
                {isExpired(doc.card.expMonth, doc.card.expYear) && <span className="tag expired">expired</span>}
                {/* Copy hands combined checkout inputs the canonical MM/YY (Tier 2 §6 parity) —
                    a half that won't canonicalize keeps the row copy-less, never copies junk. */}
                {composeShortExpiry(doc.card.expMonth ?? "", doc.card.expYear ?? "") !== null && (
                  <button className="ghost" onClick={() => copy("expiry", composeShortExpiry(doc.card!.expMonth ?? "", doc.card!.expYear ?? "")!)}>Copy</button>
                )}
              </div>
            </div>
          )}
          {doc.card.securityCode && (
            <div className="field">
              <label>Security code {copyPill("security code")}</label>
              <div className="secret-row">
                <PasswordField label="Security code" value={doc.card.securityCode} />
                <button className="ghost" onClick={() => copy("security code", doc.card!.securityCode!)}>Copy</button>
              </div>
            </div>
          )}
          {doc.card.postalCode && (
            <div className="field">
              <label>Billing ZIP / postal code</label>
              <div className="secret-row">
                <input readOnly aria-label="Billing ZIP / postal code" value={doc.card.postalCode} />
                <button className="ghost" onClick={() => copy("postal code", doc.card!.postalCode!)}>Copy</button>
              </div>
            </div>
          )}
        </>
      )}

      {doc.notes && (
        <Field label="Notes">
          <textarea readOnly rows={5} value={doc.notes} />
        </Field>
      )}

      {(doc.attachments?.length ?? 0) > 0 && <AttachmentList item={item} store={store} />}

      <ItemHistory key={item.itemId} item={item} store={store} readOnly={readOnly} onRestored={onBack} />

      {/* A reader-role member cannot edit/delete/attach — the push would be denied. */}
      {!readOnly && (
        <>
          {delErr && <div className="msg err" role="alert" style={{ marginTop: 18 }}>{delErr}</div>}
          <div className="actions">
            {deleting ? (
              <>
                {/* Audit F04: a restore drops the attachment refs (store.restoreDeleted's own
                    invariant — the blobs are unlinked server-side at delete), so "kept for 30
                    days" is only true of the FIELDS. The one moment that matters is here, before
                    the delete. Twin sentence on the Trash header below and on both natives. */}
                <span className="muted">
                  Delete “{doc.name}” from every device?
                  {(doc.attachments?.length ?? 0) > 0 && (
                    <> Its {doc.attachments!.length === 1 ? "attached file" : `${doc.attachments!.length} attached files`} cannot be restored, even from Deleted items.</>
                  )}
                </span>
                <div className="spacer" />
                <button className="ghost" disabled={delBusy} onClick={confirmDelete} style={{ color: "var(--danger)" }}>{delBusy ? "Deleting…" : "Confirm delete"}</button>
                <button className="ghost" disabled={delBusy} onClick={() => { setDeleting(false); setDelErr(""); }}>Keep</button>
              </>
            ) : (
              <>
                <button className="primary" onClick={onEdit}>Edit</button>
                <div className="spacer" />
                <button className="ghost" onClick={() => setDeleting(true)} style={{ color: "var(--danger)" }}>Delete</button>
              </>
            )}
          </div>
          {!deleting && moveTargets.length > 0 && <MoveCopyControl item={item} store={store} targets={moveTargets} onMoved={onMoved} />}
        </>
      )}
      {/* A vault only its log keeps from being written: its items are copied out, never moved (a move deletes the source). */}
      {readOnly && copyOut && moveTargets.length > 0 && <MoveCopyControl item={item} store={store} targets={moveTargets} onMoved={onMoved} copyOnly />}
    </div>
  );
}

/**
 * Item undelete (feature): "Recently deleted" — the tombstoned items the user can still recover.
 * Each is named from its last archived version (a tombstone's own blob is null); Restore re-creates
 * it live via the dedicated server route (clean un-tombstone, no spurious conflict copy).
 *
 * bug-web--3: this used to call retention unlimited, contradicting the rendered copy below — the
 * comment predates the bound F49 shipped. Retention is 30 DAYS, enforced
 * server-side by the Janitor's rule (c) (ITEM_TOMBSTONE_RETENTION_MS, one constant with the
 * changes-fence horizon by construction), which is what the copy, desktop and Android all say.
 * So this list is bounded to 30 days of deletions, not everything ever deleted.
 */
function TrashView({ store, roleFor, onRestored }: { store: VaultStore; roleFor: (vaultId: string) => string | null; onRestored: () => void }) {
  // The rows as `store.deletedItems()` gave them at the last load; drawn only through `items` below.
  const [loaded, setItems] = useState<{ itemId: string; vaultId: string; deletedAt: number; doc: ItemDoc | null }[] | null>(null);
  const [err, setErr] = useState("");
  const [restoringId, setRestoringId] = useState<string | null>(null);
  const [purgingId, setPurgingId] = useState<string | null>(null);
  const [confirmPurgeId, setConfirmPurgeId] = useState<string | null>(null);

  // parity--4: `keepErr` — the purge/restore handlers re-list to reconcile a lost-response
  // success, and that reconcile must not WIPE the failure message they just set (a failed
  // "Delete forever" then rendered as a clean, unchanged list: indistinguishable from success).
  // Only the mount/refresh path clears the bar; a load failure of its own still speaks up.
  const load = useCallback(async (keepErr = false) => {
    if (!keepErr) setErr("");
    try {
      setItems(await store.deletedItems());
    } catch (e) {
      setErr(e instanceof ApiError ? "Couldn't load deleted items from the server." : "Couldn't reach the server for deleted items.");
    }
  }, [store]);

  useEffect(() => { void load(); }, [load]);

  const purge = async (itemId: string, vaultId: string) => {
    setPurgingId(itemId);
    setErr("");
    try {
      await store.purgeDeleted(itemId, vaultId);
      // quality-perf--0: drop the row locally — a full load() re-runs one itemVersions
      // round trip per REMAINING tombstone, so every "Delete forever" used to re-spin
      // the whole list. Nothing else changed server-side; there is nothing to re-fetch.
      setItems((prev) => (prev ? prev.filter((d) => d.itemId !== itemId) : prev));
    } catch (e) {
      // G22: a 403 is the server's reader-role refusal (no_grant) — a permission fact, not a
      // transient; "try again" would loop the user straight back into the same 403.
      setErr(
        e instanceof MoveWaitingError
          ? MOVE_WAITING_REFUSED
          : e instanceof ApiError && e.status === 403
          ? "You don't have permission to delete items from this vault — your access may have been changed to view-only. Nothing was removed."
          : "Couldn't delete it permanently — try again.",
      );
      await load(true); // re-list on failure only: a lost-response success reconciles (the row drops out)
    } finally {
      setPurgingId(null);
      setConfirmPurgeId(null);
    }
  };

  const restore = async (d: { itemId: string; vaultId: string; doc: ItemDoc | null }) => {
    if (!d.doc) return; // nothing readable to restore
    setRestoringId(d.itemId);
    setErr("");
    try {
      await store.restoreDeleted(d.itemId, d.vaultId, d.doc);
      onRestored(); // re-sync so the item reappears in the vault
    } catch (e) {
      // G22: same 403 mapping as the purge arm — the honest permission sentence, never a retry.
      setErr(
        e instanceof MoveWaitingError
          ? MOVE_WAITING_REFUSED
          : e instanceof ApiError && e.status === 403
          ? "You don't have permission to restore items into this vault — your access may have been changed to view-only. Nothing was changed."
          : "Restore failed — try again.",
      );
    } finally {
      setRestoringId(null);
      // Always re-list: the restored item drops out (and a lost-response success reconciles).
      // keepErr — on the failure arm this would otherwise erase "Restore failed"; on the success
      // arm the bar was already cleared above, so there is nothing to keep.
      await load(true);
    }
  };

  // The rows loaded are drawn, at each render, only for the vaults the store's guarded reader lists now: a deleted item
  // of a vault the person was removed from (by a sync, or by another tab of this browser) is neither named nor offered.
  // The person's own vault counts also where the server serves no row for it (VaultStore.shownVaultIds).
  const listedVaults = new Set(store.shownVaultIds());
  const items = loaded === null ? null : loaded.filter((d) => listedVaults.has(d.vaultId));

  return (
    <div className="sheet">
      <h2>Trash</h2>
      <div className="muted" style={{ marginBottom: 18 }}>
        {/* Audit F04: the 30-day promise covered the item's FIELDS only — restoreDeleted drops the
            attachment refs because the blobs are unlinked server-side at delete time. Say it here
            (and at the delete confirm above); byte-twin of the Android/desktop Trash sentence. */}
        Deleted items you can still restore — kept for 30 days, then removed automatically.{" "}
        Restoring brings the item back, but not its attachments — those were permanently removed when the item was deleted.{" "}
        “Delete forever” removes it now.
      </div>
      {err && <Msg kind="err">{err}</Msg>}
      {[...new Set((items ?? []).map((d) => d.vaultId))].filter((v) => store.moveDeleteWaiting(v)).map((v) => (
        <div key={v} className="msg info" style={{ display: "block", marginTop: 12 }} role="status">{fill(MOVE_WAITING_READ_ONLY, store.vaults().find((x) => x.vaultId === v)?.name ?? MOVE_UNNAMED_OLD)}</div>
      ))}
      {items === null ? (
        <div className="muted"><Busy>Loading…</Busy></div>
      ) : items.length === 0 ? (
        <Empty><p>Nothing here — deleted items you can recover will show up in this list.</p></Empty>
      ) : (
        items.map((d) => {
          // G22: the deleted-items route is role-agnostic, so a reader's Trash lists shared-vault
          // tombstones — but the server refuses a reader's restore/purge (no_grant). Gate the
          // actions here like every sibling surface (Detail/ItemHistory) instead of offering a
          // guaranteed 403; same shape as the Android Trash row.
          // Design §3.13 as decided on 2026-11-17: a vault whose move's deletion waits takes no restore and no "Delete
          // forever" either; its rows read as view only, and the read-only line above the list says why. Nor does a shared
          // vault whose log is frozen or withheld here (VaultStore.mayWrite, decided on 23 November 2026).
          const readOnly = roleFor(d.vaultId) === "reader" || store.moveDeleteWaiting(d.vaultId) || !store.mayWrite(d.vaultId);
          return (
            <div key={d.itemId} className="secret-row" style={{ alignItems: "center", marginTop: 8 }}>
              <span style={{ flex: 1 }}>
                {d.doc ? d.doc.name : <span className="muted">(unrecoverable — no readable version)</span>}
                {/* bug-web--6 / ux-parity--6: was toISOString().slice(0,10) — a UTC substring, so
                    an 11 PM local delete rendered tomorrow's date, in an ISO dialect no other
                    surface speaks. fmtDay is the house "July 14" form, in the reader's timezone,
                    and Sharing's own recently-deleted list already uses it. */}
                <span className="muted mono" style={{ marginLeft: 8 }}>deleted {fmtDay(d.deletedAt)}{readOnly && " · view only"}</span>
              </span>
              {!readOnly &&
                (confirmPurgeId === d.itemId ? (
                  <>
                    <span className="muted">Delete forever?</span>
                    <button className="ghost" style={{ color: "var(--danger)" }} disabled={purgingId !== null} onClick={() => purge(d.itemId, d.vaultId)}>
                      {purgingId === d.itemId ? "Deleting…" : "Confirm"}
                    </button>
                    <button className="ghost" disabled={purgingId !== null} onClick={() => setConfirmPurgeId(null)}>Keep</button>
                  </>
                ) : (
                  <>
                    <button className="ghost" disabled={!d.doc || restoringId !== null || purgingId !== null} onClick={() => restore(d)}>
                      {restoringId === d.itemId ? "Restoring…" : "Restore"}
                    </button>
                    <button className="ghost" style={{ color: "var(--danger)" }} disabled={restoringId !== null || purgingId !== null} onClick={() => setConfirmPurgeId(d.itemId)}>
                      Delete forever
                    </button>
                  </>
                ))}
            </div>
          );
        })
      )}
    </div>
  );
}

/**
 * Item history & restore (feature: "the fat-finger seatbelt"). Fetches the archived versions the
 * server already keeps (up to the last 10), decrypts each under the held VK, and offers per-version
 * password reveal + "Restore" (a plain put over the live item). Readers can view but not restore.
 * Honest bound: "up to the last 10 saves" — never "nothing is ever lost" (spec 02 §7).
 */
function ItemHistory({ item, store, readOnly, onRestored }: { item: VaultItem; store: VaultStore; readOnly: boolean; onRestored: () => void }) {
  const shownNow = useStillShown();
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [versions, setVersions] = useState<{ rev: number; archivedAt: number; doc: ItemDoc }[] | null>(null);
  const [err, setErr] = useState("");
  const [restoringRev, setRestoringRev] = useState<number | null>(null);
  // Cut D (v2 #3): Restore was a one-click unconfirmed overwrite of the live item —
  // first click arms, second confirms (the Detail-delete inline idiom). Arming another
  // row re-arms to it; Hide disarms below; the key on <ItemHistory> resets per item.
  const [armedRev, setArmedRev] = useState<number | null>(null);

  const load = async () => {
    setOpen(true);
    if (versions !== null || loading) return;
    setLoading(true);
    setErr("");
    try {
      setVersions(await store.itemVersions(item.itemId, item.vaultId));
    } catch (e) {
      setErr(e instanceof ApiError ? "Couldn't load history from the server." : "Couldn't reach the server for history.");
    } finally {
      setLoading(false);
    }
  };

  const restore = async (v: { rev: number; doc: ItemDoc }) => {
    setRestoringRev(v.rev);
    setErr("");
    try {
      // H03: strip every attachment ref the LIVE item no longer carries — a version is verbatim
      // ciphertext from its day, and a ref to a since-removed (server-swept) attachment would make
      // this put a `rejected` row (core SyncEngine.versionDocForRestore twin).
      const liveIds = new Set((item.doc.attachments ?? []).map((a) => a.id));
      const doc: ItemDoc = { ...v.doc, attachments: v.doc.attachments?.filter((a) => liveIds.has(a.id)) };
      await store.save(item.itemId, doc, [], undefined, item.vaultId); // an ordinary put over the live item, bound to its vault
      onRestored(); // back to the vault; the live item now holds the restored version
    } catch {
      setErr("Restore failed — nothing changed. Try again.");
      setRestoringRev(null);
    }
  };

  if (!shownNow) return null;
  if (!open) {
    return <button className="link" style={{ marginTop: 12 }} onClick={load}>Version history</button>;
  }
  return (
    <div className="field" style={{ marginTop: 18 }}>
      <label>Version history <span className="muted">· up to the last 10 saves</span></label>
      {loading && <div className="muted"><Busy>Loading…</Busy></div>}
      {err && <Msg kind="err">{err}</Msg>}
      {versions?.length === 0 && <Empty><p>No earlier versions yet — history starts from the next change.</p></Empty>}
      {versions?.map((v) => (
        <div key={v.rev} className="secret-row" style={{ alignItems: "center", marginTop: 6 }}>
          {/* bug-web--6 / ux-parity--6: same UTC-ISO substring as Trash, same fix.
              H131: fmtDayYear, not fmtDay — the list is capped at ten SAVES with no age bound, so
              an item edited twice a year puts a 2024 version on screen as a bare "July 14" that
              reads as this July. Trash keeps fmtDay: its rows expire in 30 days. */}
          <span className="muted mono" style={{ minWidth: 92 }}>{fmtDayYear(v.archivedAt)}</span>
          {v.doc.type === "login" && v.doc.login?.password ? (
            <PasswordField label={`Password, version of ${fmtDayYear(v.archivedAt)}`} value={v.doc.login.password} />
          ) : (
            <span className="muted" style={{ flex: 1 }}>{v.doc.type === "login" ? "(no password in this version)" : v.doc.type === "card" ? cardSubtitle(v.doc) : "note"}</span>
          )}
          {!readOnly && (
            <button
              className="ghost"
              disabled={restoringRev !== null}
              onClick={() => (armedRev === v.rev ? (setArmedRev(null), restore(v)) : setArmedRev(v.rev))}
            >
              {restoringRev === v.rev ? "Restoring…" : armedRev === v.rev ? "Overwrite current?" : "Restore"}
            </button>
          )}
        </div>
      ))}
      <button className="link" style={{ marginTop: 8 }} onClick={() => { setArmedRev(null); setOpen(false); }}>Hide history</button>
    </div>
  );
}

/**
 * F19 (design §8): move or copy this item into another vault. Runs the store's copy-leg-first
 * gesture; a transient failure keeps the SAME gesture so Retry converges (never duplicates); a
 * denied copy or a changed source aborts with an honest message (source untouched).
 */
/** [copyOnly]: only "Copy to vault…" is offered (the item's vault may be read, not written). */
function MoveCopyControl({ item, store, targets, onMoved, copyOnly = false }: { item: VaultItem; store: VaultStore; targets: VaultInfo[]; onMoved: () => void; copyOnly?: boolean }) {
  const shownNow = useStillShown();
  const [mode, setMode] = useState<"move" | "copy" | null>(null);
  const [target, setTarget] = useState(targets[0]?.vaultId ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const gestureRef = useRef<MoveGesture | null>(null);

  const resetGesture = () => { gestureRef.current = null; };

  const run = async () => {
    if (!mode || !target) return;
    setBusy(true);
    setErr("");
    setProgress(null);
    try {
      const g = gestureRef.current ?? store.newMoveGesture(item.itemId, target, mode === "move");
      gestureRef.current = g; // reused verbatim on retry (server dedup converges)
      await store.runGesture(g, (done, total) => setProgress({ done, total }));
      resetGesture();
      onMoved();
    } catch (e) {
      if (e instanceof CopyDeniedError) {
        resetGesture();
        setErr("You don’t have permission to add items to that vault — nothing was moved.");
      } else if (e instanceof ItemChangedError) {
        resetGesture();
        setErr("This item changed while moving — go back, review it, and try again.");
      } else if (e instanceof ApiError && e.status === 403) {
        resetGesture();
        // ux-copy--2: the server's 403 body is the literal word "forbidden" — show the canon
        // 403 sentence instead (byte-twin of the natives' HouseholdCopy 403 row, the exact
        // mapping desktop's move flow applies here).
        setErr("You don't have permission to do that.");
      } else {
        // Transient — keep the gesture so Retry replays the same ids (no duplicate).
        setErr("That didn’t finish. Press Retry — it won’t create a duplicate.");
      }
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  if (!shownNow) return null;
  if (!mode) {
    return (
      <div className="actions" style={{ marginTop: 6 }}>
        {!copyOnly && <button type="button" className="ghost" onClick={() => { setMode("move"); resetGesture(); }}>Move to vault…</button>}
        <button type="button" className="ghost" onClick={() => { setMode("copy"); resetGesture(); }}>Copy to vault…</button>
      </div>
    );
  }

  return (
    <div className="field" style={{ marginTop: 12 }}>
      <label>{mode === "move" ? "Move to another vault" : "Copy to another vault"}</label>
      {err && <Msg kind="err">{err}</Msg>}
      {mode === "move" && (
        <p className="muted" style={{ marginTop: 0 }}>
          Members of “{store.vaults().find((v) => v.vaultId === item.vaultId)?.name ?? "this vault"}” may still have copies from before the move.
        </p>
      )}
      <div className="secret-row">
        <select value={target} aria-label={mode === "move" ? "Move to another vault" : "Copy to another vault"} onChange={(e) => { setTarget(e.target.value); resetGesture(); }} disabled={busy} style={{ width: "auto" }}>
          {targets.map((v) => (
            <option key={v.vaultId} value={v.vaultId}>{vaultLabel(v, targets)}{v.type === "personal" ? "" : " (shared)"}</option>
          ))}
        </select>
        <button type="button" className="primary" disabled={busy || !target} onClick={run}>
          {busy ? (progress && progress.total > 0 ? `Copying… ${progress.done}/${progress.total}` : "Working…") : err ? "Retry" : mode === "move" ? "Move" : "Copy"}
        </button>
        <button type="button" className="ghost" disabled={busy} onClick={() => { setMode(null); setErr(""); resetGesture(); }}>Cancel</button>
      </div>
    </div>
  );
}

/** Detail-view attachments: download → decrypt → hand the browser a one-shot object URL. */
function AttachmentList({ item, store }: { item: VaultItem; store: VaultStore }) {
  const shownNow = useStillShown();
  const [busyId, setBusyId] = useState<string | null>(null);
  const [err, setErr] = useState("");

  const download = async (ref: AttachmentRef) => {
    setErr("");
    setBusyId(ref.id);
    try {
      const plain = await store.downloadAttachment(item, ref);
      const url = URL.createObjectURL(new Blob([plain as BlobPart], { type: "application/octet-stream" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = ref.name || "attachment";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setErr(answerLimitText(e) ?? `Could not download “${ref.name}” — the blob is missing or failed to decrypt.`);
    } finally {
      setBusyId(null);
    }
  };

  if (!shownNow) return null;
  return (
    <div className="field">
      <label>Attachments</label>
      {err && <Msg kind="err">{err}</Msg>}
      <div className="attach-list">
        {item.doc.attachments!.map((ref) => (
          <div className="attach-row" key={ref.id}>
            <span className="attach-name">{ref.name}</span>
            <span className="muted">{humanSize(ref.size)}</span>
            <button type="button" className="ghost" disabled={busyId === ref.id} onClick={() => download(ref)}>
              {busyId === ref.id ? "Opening…" : "Download"}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function PasswordField({ value, label }: { value: string; label: string }) {
  const shownNow = useStillShown();
  const [show, setShow] = useState(false);
  if (!shownNow) return null;
  return (
    <>
      <input readOnly aria-label={label} className="mono" type={show ? "text" : "password"} value={value} />
      <button className="ghost" onClick={() => setShow((s) => !s)}>{show ? "Hide" : "Show"}</button>
    </>
  );
}

/** Editable sibling of PasswordField — masked by default with a reveal toggle. The editor
 *  CVV renders through this (design: SecretField); login passwords keep the plain editor
 *  idiom (generate-and-glance), a deliberate difference, not an oversight. */
function SecretInput({ value, onChange, ariaLabel }: { value: string; onChange: (v: string) => void; ariaLabel?: string }) {
  const shownNow = useStillShown();
  const [show, setShow] = useState(false);
  if (!shownNow) return null;
  return (
    <div className="secret-row">
      {/* BL-2: this custom input never gets Field's injected id, so name it here. */}
      {/* Cut E review: browsers ignore autocomplete="off" on password-type inputs —
          "new-password" is the signal that actually suppresses fill/save offers. */}
      <input className="mono" type={show ? "text" : "password"} inputMode="numeric" autoComplete="new-password" aria-label={ariaLabel} value={value} onChange={(e) => onChange(e.target.value)} />
      <button type="button" className="ghost" aria-label={show ? "Hide value" : "Show value"} onClick={() => setShow((s) => !s)}>{show ? "Hide" : "Show"}</button>
    </div>
  );
}

function TotpView({ uri, pill, onCopy }: { uri: string; pill: ReactNode; onCopy: (code: string) => void }) {
  // Asked at each tick's render too: the code ticks every second by this view's own state.
  const shownNow = useStillShown();
  const [code, setCode] = useState("······");
  const [remaining, setRemaining] = useState(30);
  const [period, setPeriod] = useState(30);
  // a11y-webext--6: the seconds-left description is addressed by id, so it needs a stable
  // one per mounted chip (the extension's totpChip mints its own via a counter).
  const secsId = useId();
  useEffect(() => {
    let cfg;
    try {
      // The SHARED normalize first (crypto/totp.ts — A5, the editor's own save path): a bare-base32
      // secret (imported / stored before the save-time normalize) renders its code instead of
      // "invalid" forever. Already-normalized otpauth URIs pass through unchanged.
      cfg = parseOtpauthUri(normalizeTotp(uri));
    } catch {
      setCode("invalid");
      return;
    }
    setPeriod(cfg.periodSeconds);
    const tick = async () => {
      const now = Math.floor(Date.now() / 1000);
      setCode(await totpCode(cfg!, now));
      setRemaining(totpSecondsRemaining(cfg!, now));
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [uri]);
  if (!shownNow) return null;
  return (
    <div className="field">
      {/* Same copy-flash pill as the password/card fields — TotpView owns the label, so the
          Detail parent hands the rendered pill down (audit F05: one pill, one place that knows
          whether the auto-clear actually landed) instead of re-stating the promise here. */}
      <label>One-time code {pill}</label>
      <div className="totp-wrap">
        {/* a11y-webext--6: the extension popup's chip contract, ported verbatim (popup.ts
            totpChip). a11yweb-09 named the affordance but baked the LIVE code into the name:
            it re-announced every 30 s (and mid-focus), read six digits as one number, and
            buried the verb — while the countdown, the one thing a sighted user gets for free,
            was aria-hidden with no text twin. So: a STABLE name, the digits aria-hidden (they
            are decoration once the name says what the button does), and seconds-left as an
            aria-describedby description — read on focus, not re-announced per tick. The one
            state the name still carries is "invalid": there is no code to copy, and that has
            to reach AT the way the visible text reaches a sighted user. */}
        <button className="totp link" aria-label={code === "invalid" ? "One-time code — unreadable" : "Copy one-time code"} aria-describedby={secsId} onClick={() => onCopy(code.replace(/\s/g, ""))} title="copy">
          <span aria-hidden="true">{code.replace(/(\d{3})(\d{3})/, "$1 $2")}</span>
          <span className="visually-hidden" id={secsId}>{remaining} seconds left</span>
        </button>
        {/* aria-hidden: the ring updates every second — it must NOT be a live region. */}
        <div className="ring" aria-hidden="true" style={{ ["--p" as string]: String((remaining / period) * 100) }} title={`${remaining}s`} />
      </div>
    </div>
  );
}

function HealthLine({ password, client }: { password: string; client: ApiClient }) {
  // R05 (H132's missed leg): the in-flight state is a real network wait — a k-anonymity range
  // fetch to the relay — so it renders as the shared <Busy> dial in sentence case like every
  // other wait in the app, not as a bare lower-case muted line. The VERDICTS below stay plain
  // text: they are results, and a dial spinning beside a finished answer reads as still-working.
  const shownNow = useStillShown();
  const guard = useContext(OpenItemGuard);
  const [status, setStatus] = useState<string>("");
  const [checking, setChecking] = useState(false);
  const check = async () => {
    setChecking(true);
    setStatus("");
    try {
      const hash = await hibpSha1UpperHex(password);
      // Asked again after the digest, before anything of it is sent: an item a removal took away meanwhile sends nothing.
      if (!guard.shown()) {
        guard.onGone();
        return;
      }
      const body = await client.hibpRange(hibpPrefix(hash));
      const count = hibpCountInRange(body, hash);
      setStatus(count > 0 ? `⚠ found in ${count.toLocaleString()} breaches — change it` : "✓ not in any known breach");
    } catch {
      setStatus("breach check unavailable");
    } finally {
      setChecking(false);
    }
  };
  if (!shownNow) return null;
  return (
    <div style={{ marginTop: 4 }}>
      {/* BL-1 (G25): the verdict is ASYNC info landing in a bare span — silent to AT. One
          persistent live region mounted from the start, the Detail/Staleness contract (a
          conditionally-mounted role=status is not announced). */}
      <Announcer text={checking ? "Checking…" : status} />
      <button className="link" onClick={check} disabled={checking}>Check breach exposure</button>
      {checking ? (
        <span style={{ marginLeft: 10 }}><Busy>Checking…</Busy></span>
      ) : (
        status && <span className="muted" style={{ marginLeft: 10, color: status.startsWith("⚠") ? "var(--danger)" : "var(--ink-dim)" }}>{status}</span>
      )}
    </div>
  );
}

const MONTH_CHOICES = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"];

/** Expiry-year picker: a rolling 16-year window, PLUS any stored out-of-window values
 *  (verbatim, prepended) — editing an old card must never silently change its year. */
function expiryYearChoices(stored: (string | undefined)[]): string[] {
  const first = new Date().getFullYear();
  const ys = Array.from({ length: 16 }, (_, i) => String(first + i));
  for (const y of stored) if (y && !ys.includes(y)) ys.unshift(y);
  return ys;
}

function Editor({ initial, policy, vaultChoices, generateOnOpen, onSave, onCancel, backRef, dirtyRef, ownsTarget }: { initial: ItemDoc; policy: ClientPolicy | null; vaultChoices?: VaultInfo[]; generateOnOpen?: boolean; ownsTarget: (pickedVaultId: string | undefined) => boolean; onSave: (d: ItemDoc, files: PendingUpload[], onProgress?: (done: number, total: number) => void, vaultId?: string) => Promise<void>; onCancel: () => void; backRef?: React.MutableRefObject<(() => void) | null>; dirtyRef?: React.MutableRefObject<boolean> }) {
  const shownNow = useStillShown();
  const [doc, setDoc] = useState<ItemDoc>(structuredClone(initial));
  // New items only: which vault to create in (existing items never move vaults). A9 review LOW-2: the default is the
  // PERSONAL vault; with none in force there is no default — the human picks (the select shows a placeholder) and Save
  // stays disabled until then, so nothing lands in a shared vault by omission.
  const [picked, setVaultId] = useState<string | undefined>(vaultChoices?.find((v) => v.type === "personal")?.vaultId);
  // A vault chosen here that is no longer offered (the person was removed from it, or it went read-only, while the editor
  // was open) is chosen no longer: nothing is saved into it, and nothing is saved elsewhere in its place. The person
  // picks again, and a line says why.
  const pickGone = vaultChoices !== undefined && picked !== undefined && !vaultChoices.some((v) => v.vaultId === picked);
  const vaultId = pickGone ? undefined : picked;
  const needsVaultPick = vaultChoices !== undefined && vaultId === undefined;
  const [pending, setPending] = useState<PendingUpload[]>([]);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [fileErr, setFileErr] = useState("");
  const [saveErr, setSaveErr] = useState("");
  const [busy, setBusy] = useState(false);
  // F78: the editor password is masked by default (reveal toggle), and Generate over an
  // EXISTING password asks first — a mistyped-then-generated field silently losing what the
  // user typed was the reported footgun.
  const [showPw, setShowPw] = useState(false);
  const [confirmGen, setConfirmGen] = useState(false);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const isLogin = doc.type === "login";
  const login = doc.login ?? {};
  const isCard = doc.type === "card";
  const card = doc.card ?? {};

  const setLogin = (patch: Partial<NonNullable<ItemDoc["login"]>>) => setDoc({ ...doc, login: { ...login, ...patch } });
  const setCard = (patch: Partial<NonNullable<ItemDoc["card"]>>) => setDoc({ ...doc, card: { ...card, ...patch } });

  // Generate: an empty field fills immediately; a non-empty one arms an inline confirm
  // (house style — no native dialogs) so a real password is never clobbered by a stray tap.
  // Either way the new password is revealed, so the user sees what will be saved.
  const gen = () => {
    if ((login.password ?? "").length > 0 && !confirmGen) {
      setConfirmGen(true);
      return;
    }
    setLogin({ password: generatePassword() });
    setShowPw(true);
    setConfirmGen(false);
  };

  // H117: opened FROM the verification run's "Generate a new password" offer — the new password is
  // in the field and revealed before the user's eyes land on it, and the notice says plainly that
  // nothing is saved yet. Deliberately not routed through gen()'s confirm arm: the offer click IS
  // the consent that arm exists to collect, and asking twice for one decision is the nag the
  // house idiom avoids. Runs once per mount (empty deps) — a re-render must never re-roll a
  // password the user is in the middle of reading or has already edited.
  const [generated, setGenerated] = useState(false);
  useEffect(() => {
    if (!generateOnOpen || !isLogin) return;
    setDoc((d) => ({ ...d, login: { ...(d.login ?? {}), password: generatePassword() } }));
    setShowPw(true);
    setGenerated(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Live editor signals off the typed number: decisive-prefix brand badge, and a Luhn check
  // that WARNS once a plausible PAN length is present — never blocks Save (store-what-the-
  // user-typed beats rejecting an odd-but-real number).
  const cardDigits = digitsOnly(card.number ?? "");
  const cardBrand = brandLabel(brand(cardDigits));
  const luhnWarn = cardDigits.length >= 12 && !luhnValid(cardDigits);
  // Injects the doc's stored years from `initial` so an old card's value stays offered for
  // the whole edit session — editing must never silently change it.
  const yearChoices = expiryYearChoices([card.expYear, initial.card?.expYear]);

  const maxBytes = policy?.attachmentMaxBytes ?? 25 * 1024 * 1024;

  const addFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setFileErr("");
    const errors: string[] = [];
    const newRefs: AttachmentRef[] = [];
    const newPending: PendingUpload[] = [];
    for (const file of Array.from(files)) {
      if (file.size === 0) {
        errors.push(`“${file.name}” is empty — empty files can't be attached.`);
        continue;
      }
      if (file.size > maxBytes) {
        errors.push(`“${file.name}” is ${humanSize(file.size)} — over the ${humanSize(maxBytes)} limit.`);
        continue;
      }
      const data = new Uint8Array(await file.arrayBuffer());
      const ref: AttachmentRef = { id: crypto.randomUUID(), name: file.name, size: file.size, fileKey: toB64(randomBytes(32)) };
      newRefs.push(ref);
      newPending.push({ id: ref.id, data });
    }
    if (newRefs.length > 0) {
      setDoc((d) => ({ ...d, attachments: [...(d.attachments ?? []), ...newRefs] }));
      setPending((p) => [...p, ...newPending]);
    }
    if (errors.length > 0) setFileErr(errors.join(" "));
    if (fileInput.current) fileInput.current.value = "";
  };

  const removeAttachment = (id: string) => {
    // Dropping the doc entry is enough — server-side GC reaps the orphaned blob.
    setDoc((d) => ({ ...d, attachments: (d.attachments ?? []).filter((a) => a.id !== id) }));
    setPending((p) => p.filter((f) => f.id !== id));
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    // TOTP normalizes ONCE here (never per keystroke); un-decodable text blocks the save.
    let toSave = doc;
    if (isLogin) {
      const rawTotp = (login.totp ?? "").trim();
      if (rawTotp) {
        const totp = normalizeTotp(rawTotp);
        if (!isValidTotp(totp)) {
          setSaveErr("TOTP secret isn't valid base32 or an otpauth:// link");
          return;
        }
        toSave = { ...doc, login: { ...login, totp } };
      } else if (login.totp) {
        // Field is blank or whitespace-only — persist it as absent, never a " " string the
        // Detail view would treat as truthy and render as a broken TOTP row.
        toSave = { ...doc, login: { ...login, totp: undefined } };
      }
    } else if (isCard) {
      // Cards normalize ONCE here too — spread-only (account.ts contract), so unknown keys
      // inside `card` survive the rewrite. brand is ALWAYS recomputed from the number
      // (display-only; a user-authored or stale brand must never persist). digits-only
      // strips separators AND stray non-digits from a hand-typed number; a card whose
      // every field normalizes to absent is a legal empty shell.
      toSave = {
        ...doc,
        card: {
          ...card,
          cardholderName: (card.cardholderName ?? "").trim() || undefined,
          number: cardDigits || undefined,
          expMonth: padMonth(card.expMonth ?? "") ?? undefined,
          expYear: yearTo4(card.expYear ?? "") ?? undefined,
          securityCode: digitsOnly(card.securityCode ?? "") || undefined,
          // G3 billing postal: verbatim (alphanumeric, never digits-only), just trimmed.
          postalCode: (card.postalCode ?? "").trim() || undefined,
          brand: brand(cardDigits) ?? undefined,
        },
      };
    }
    setBusy(true);
    setSaveErr("");
    setProgress(null);
    try {
      await onSave(toSave, pending, (done, total) => setProgress({ done, total }), vaultId);
    } catch (err) {
      // ux-copy--2, H03/R38, the owner's quota, the 413 row, the offline refusals and the anomaly refusals: saveerror.ts.
      setSaveErr(saveErrorText(err, ownsTarget(vaultId)));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const attachments = doc.attachments ?? [];
  const pendingIds = new Set(pending.map((p) => p.id));
  // Cut D review, made dirty-aware in Cut M (v2 #16): the two-click "Discard changes?"
  // inline arm (same idiom as history's Restore) now only stands between the user and
  // close when there is actually work to lose — a pristine editor cancels in one click.
  const [confirmCancel, setConfirmCancel] = useState(false);
  // Dirty = the doc differs from what the editor opened with, or uploads are queued.
  // JSON compare is honest here: `doc` starts as a structuredClone of `initial` and only
  // user edits rewrite it, spread-in-place, so an edit typed then reverted compares equal
  // again (attachments are metadata refs — file bytes live in `pending`, counted apart).
  // The vault <select> alone is deliberately NOT dirty: nothing typed, nothing to lose.
  const dirty = pending.length > 0 || JSON.stringify(doc) !== JSON.stringify(initial);
  // The screen asks this when it closes the editor because the item is no longer handed out (its line says whether
  // typing was lost). Written at each render, so it is current whenever the screen asks.
  if (dirtyRef) dirtyRef.current = dirty;
  // ONE cancel path for the button AND hardware Back: pristine closes immediately; dirty
  // arms the confirm first, and only the second press/tap discards for real.
  const cancel = () => (dirty && !confirmCancel ? setConfirmCancel(true) : onCancel());
  // Cut M review: disarm a stale "Discard changes?" the moment editing resumes — otherwise
  // one accidental Back arms it invisibly (the label is off-viewport on a scrolled form) and a
  // later cancel/Back discards with no visible confirm. Mirrors confirmGen's edit-reset idiom.
  useEffect(() => setConfirmCancel(false), [doc, pending]);
  // Cut M (v2 #16): park `cancel` in the parent's ref so Vault's single back guard routes
  // popstate here (a second useBackGuard under Vault is forbidden — see its closeTop).
  // Re-assigned every render so the ref never sees stale dirty/confirm state.
  useEffect(() => {
    if (!backRef) return;
    backRef.current = cancel;
    return () => { backRef.current = null; };
  });

  if (!shownNow) return null;
  return (
    // Cut E (v2 #4): autoComplete off — WITHOUT it the browser's own password manager
    // interposes save/fill prompts inside the vault's editor (its suggestions overlay the
    // generator, and it offers to save the household's secrets into the browser store).
    // Password fields ignore form-level "off", so the password input adds "new-password".
    <form className="sheet" autoComplete="off" onSubmit={submit}>
      <button type="button" className="link" onClick={cancel}>
        {/* H133: the two-state twin of BackLink — same glyph and casing, but the label flips to
            the armed discard confirm, so it composes BACK_GLYPH instead of taking the component. */}
        {confirmCancel ? "Discard changes?" : `${BACK_GLYPH} Cancel`}
      </button>
      <h2 style={{ marginTop: 12 }}>{initial.name ? "Edit" : isLogin ? "New login" : isCard ? "New card" : "New note"}</h2>
      {vaultChoices && (vaultChoices.length > 1 || needsVaultPick) && (
        <Field label="Vault">
          <select value={vaultId ?? ""} onChange={(e) => setVaultId(e.target.value || undefined)}>
            {needsVaultPick && <option value="">Choose a vault for this item.</option>}
            {vaultChoices.map((v) => (
              <option key={v.vaultId} value={v.vaultId}>
                {vaultLabel(v, vaultChoices)}{v.type === "personal" ? "" : " (shared)"}
              </option>
            ))}
          </select>
        </Field>
      )}
      {pickGone && <div className="msg info" style={{ display: "block", marginTop: 8 }} role="status" data-testid="editor-vault-gone">{EDITOR_VAULT_GONE}</div>}
      <Field label="Name">
        <input autoFocus value={doc.name} onChange={(e) => setDoc({ ...doc, name: e.target.value })} />
      </Field>
      {isLogin && (
        <>
          <Field label="Username">
            <input className="mono" value={login.username ?? ""} onChange={(e) => setLogin({ username: e.target.value })} />
          </Field>
          <div className="field">
            {/* BL-2: multi-child block (secret-row + confirm + StrengthBar) — Field can't wrap
                it, so name the inner <input> directly. */}
            <label>Password</label>
            <div className="secret-row">
              {/* Masked by default (F78); typing stays possible — a password field the user
                  can't read is the login-editor's one blind spot the reveal toggle fixes. */}
              <input className="mono" aria-label="Password" type={showPw ? "text" : "password"} autoComplete="new-password" value={login.password ?? ""} onChange={(e) => { setLogin({ password: e.target.value }); setConfirmGen(false); }} />
              <button type="button" className="ghost" aria-label={showPw ? "Hide password" : "Show password"} onClick={() => setShowPw((s) => !s)}>{showPw ? "Hide" : "Show"}</button>
              <button type="button" className="ghost" onClick={gen}>{confirmGen ? "Replace?" : "Generate"}</button>
            </div>
            {confirmGen && <span className="muted" style={{ color: "var(--gold-text)" }}>{GENERATE_REPLACE_ASK}</span>}
            {/* H117: arrived here from the verification run's "Generate a new password" offer.
                Say what happened AND that it is not saved yet — the whole point of landing in the
                editor rather than writing the password behind the user's back. */}
            {generated && <span className="muted" style={{ color: "var(--gold-text)" }}>a new password is ready — change it on the site, then press Save to keep it here</span>}
            {login.password && <StrengthBar password={login.password} />}
          </div>
          <Field label="Website">
            {/* Edits uris[0] only; the tail (extra URIs written by other clients) is preserved. */}
            <input value={login.uris?.[0] ?? ""} onChange={(e) => setLogin({ uris: e.target.value ? [e.target.value, ...(login.uris ?? []).slice(1)] : (login.uris ?? []).slice(1) })} placeholder="https://" />
          </Field>
          <Field label="TOTP secret (otpauth:// URI or base32)">
            {/* RAW text while typing — normalizing per keystroke rewrote the field to an
                otpauth:// URI on the first character. Normalized once, in submit. */}
            <input className="mono" data-print-secret value={login.totp ?? ""} onChange={(e) => setLogin({ totp: e.target.value })} placeholder="optional" />
          </Field>
        </>
      )}
      {isCard && (
        <>
          <Field label="Cardholder name">
            <input value={card.cardholderName ?? ""} onChange={(e) => setCard({ cardholderName: e.target.value })} />
          </Field>
          <Field
            label={<>Card number {cardBrand && <span className="tag brand">{cardBrand}</span>}</>}
            hint={
              luhnWarn ? (
                <div className="muted" style={{ marginTop: 6, color: "var(--gold-text)" }}>
                  this number doesn’t pass the usual check — you can still save it
                </div>
              ) : undefined
            }
          >
            {/* RAW text while typing (separators and all) — digits-only ONCE, in submit (the
                TOTP idiom). The badge + Luhn line read the live digits; warn, never block. */}
            <input className="mono" inputMode="numeric" autoComplete="off" data-print-secret value={card.number ?? ""} onChange={(e) => setCard({ number: e.target.value })} />
          </Field>
          <div className="field">
            <label>Expiry</label>
            {/* Both selects offer an empty choice — every card field is optional. The month
                VALUE renders through padMonth so a foreign-written "1" displays as "01".
                BL-2: two selects under one label — name each directly. */}
            <div className="row">
              <select value={padMonth(card.expMonth ?? "") ?? ""} aria-label="Expiry month" onChange={(e) => setCard({ expMonth: e.target.value })} style={{ width: "auto" }}>
                <option value="">month</option>
                {MONTH_CHOICES.map((m) => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
              <select value={card.expYear ?? ""} aria-label="Expiry year" onChange={(e) => setCard({ expYear: e.target.value })} style={{ width: "auto" }}>
                <option value="">year</option>
                {yearChoices.map((y) => (
                  <option key={y} value={y}>{y}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="field">
            <label>Security code <span className="muted">· optional — stored encrypted like everything else</span></label>
            {/* Masked-with-reveal (unlike the login password's plain editor field): a CVV is
                glanceable-short and worth shielding from shoulders by default. Digits-only
                is applied once, at submit, beside the other card normalizations. */}
            <SecretInput ariaLabel="Security code" value={card.securityCode ?? ""} onChange={(v) => setCard({ securityCode: v })} />
          </div>
          <Field label="Billing ZIP / postal code">
            {/* Verbatim (alphanumeric internationally) — trimmed once, at submit. */}
            {/* No inputMode="numeric": billing postcodes are alphanumeric outside the US (UK/CA/NL),
                and the G3 store rule above keeps the value verbatim — a numeric keypad would fight it. */}
            <input autoComplete="off" value={card.postalCode ?? ""} onChange={(e) => setCard({ postalCode: e.target.value })} />
          </Field>
        </>
      )}
      <Field label="Notes">
        <textarea rows={isLogin || isCard ? 3 : 6} value={doc.notes ?? ""} onChange={(e) => setDoc({ ...doc, notes: e.target.value })} />
      </Field>

      <div className="field">
        <label>Attachments</label>
        {fileErr && <Msg kind="err">{fileErr}</Msg>}
        {attachments.length > 0 && (
          <div className="attach-list">
            {attachments.map((ref) => (
              <div className="attach-row" key={ref.id}>
                <span className="attach-name">{ref.name}</span>
                <span className="muted">{humanSize(ref.size)}{pendingIds.has(ref.id) ? " · new" : ""}</span>
                <button type="button" className="ghost" onClick={() => removeAttachment(ref.id)} style={{ color: "var(--danger)" }}>Remove</button>
              </div>
            ))}
          </div>
        )}
        <input ref={fileInput} type="file" multiple aria-label="Attach files" style={{ display: "none" }} onChange={(e) => addFiles(e.target.files)} />
        <button type="button" className="ghost" onClick={() => fileInput.current?.click()}>+ Attach files</button>
        {/* Owner dev-note 2026-08-19: "encrypted on this device" read as DEVICE-LOCAL storage.
            It meant where the encryption happens; the sealed file syncs to every member of the
            vault like any item. Say both halves plainly. */}
        <span className="muted" style={{ marginLeft: 10 }}>encrypted before upload · syncs with the vault · up to {humanSize(maxBytes)} each</span>
      </div>

      {saveErr && <Msg kind="err">{saveErr}</Msg>}
      <div className="actions">
        <button className="primary" disabled={busy || !doc.name || needsVaultPick}>
          {busy ? (progress && progress.total > 0 ? `Sealing… ${Math.min(progress.done + 1, progress.total)}/${progress.total}` : "Sealing…") : "Save"}
        </button>
        <button type="button" className="ghost" onClick={cancel}>{confirmCancel ? "Discard changes?" : "Cancel"}</button>
      </div>
    </form>
  );
}

/**
 * The login editor's item-password bar. ExportPanel keeps a declared copy of this (importing it
 * back from here would make a Vault ⇄ ExportPanel cycle) — and that copy has since grown a
 * `caution` prop this one deliberately does NOT take. The divergence is a decision, not drift.
 *
 * `caution` exists to stop a bar affirming what a sentence beside it is denying: the export panel
 * renders <PasswordCautions> in the same hint, so a green bar over the pattern warning is the
 * "strength: fair ✓" defect (passwordadvice.tsx) in another costume.
 * This editor renders no such sentence — no floor, no pattern line, and no breach check bound to
 * the field (an item password's breach exposure is on demand instead: HealthLine's "Check breach
 * exposure" on the detail view, and the Health panel across the whole vault). Holding the bar out
 * of green here would be a signal with nothing to refer to — the user is told something is wrong
 * and given nowhere to read why.
 *
 * Staying uncautioned does not drop the F31 pattern penalty: `estimateStrength` collapses repeats
 * and runs before scoring (strength.ts), so `Password1!Password1!` already paints short and gold
 * off its own score. What is skipped is only the DEMOTION of a password whose honest, pattern-aware
 * score still clears "good" — and the stakes differ there. A backup passphrase is the one thing
 * protecting a file that has left the vault, chosen once at export time; an item password is
 * generated by default, sits a click from the Generate button directly above this bar, and is
 * re-rollable at any time.
 */
function StrengthBar({ password }: { password: string }) {
  const score = estimateStrength(password);
  const colors = ["var(--danger)", "var(--danger)", "var(--gold)", "var(--ok)", "var(--ok)"];
  return (
    <div className="strength">
      <span style={{ width: `${(score + 1) * 20}%`, background: colors[score] }} />
    </div>
  );
}

/** True when the SHARED normalizeTotp's output (crypto/totp.ts — A5: one normalize for
 *  editors and CSV adapters alike) is a parseable otpauth URI — the save-time gate
 *  (the Detail view would otherwise render the stored value as "invalid" forever). */
function isValidTotp(normalized: string): boolean {
  try {
    parseOtpauthUri(normalized);
    return true;
  } catch {
    return false;
  }
}

// ---- CSV import (spec 06 + design 2026-07-11 universal importer) ----

/** The per-source "How do I export from…?" help table — the ONE surviving per-source
 *  surface of the universal importer (design 2026-07-11). Content-aligned twin of core
 *  ImportHelp (the usual non-KMP mirror — keep the two in lockstep). Steps are best-effort
 *  export navigation docs (current as of 2026-07), NOT contracts — parsing never consults
 *  them; header detection is authoritative (csv.ts). */
interface ImportSource {
  label: string;
  steps: string[];
  note?: string;
}

const IMPORT_SOURCES: ImportSource[] = [
  {
    label: "Chrome",
    steps: [
      "Open chrome://password-manager/settings (Menu ⋮ → Passwords and autofill → Google Password Manager → Settings).",
      "Under “Export passwords”, choose Download file.",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Edge",
    steps: [
      "Open edge://wallet/passwords.",
      "Click ⋯ (More options) → Export passwords.",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Brave",
    steps: [
      "Open brave://password-manager/settings.",
      "Under “Export passwords”, choose Download file.",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Opera",
    steps: [
      "Open opera://settings/passwords.",
      "Next to “Saved Passwords”, click ⋮ → Export passwords.",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Firefox",
    steps: [
      "Open about:logins (Menu ☰ → Passwords).",
      "Click ⋯ (top right) → Export passwords…",
      "Confirm with your device sign-in and save the CSV.",
    ],
  },
  {
    label: "Bitwarden",
    steps: [
      "In the Bitwarden web vault or desktop app: Tools → Export vault.",
      "File format: .csv (not .json).",
      "Confirm with your master password and save the file.",
    ],
  },
  {
    label: "1Password",
    steps: [
      "In the 1Password desktop app (version 8 or newer): File → Export → your account.",
      "Choose the CSV format, confirm with your account password, and save the file.",
    ],
    note: "1Password 7 and older export a different CSV shape — update to 1Password 8 or newer, or route through Bitwarden/another CSV export as an intermediate.",
  },
  {
    // A10: pin the FILE-DOWNLOAD export path — the in-browser-tab route HTML-mangles values.
    label: "LastPass",
    steps: [
      "Sign in to your vault at lastpass.com.",
      "Open Advanced Options in the left menu → Export.",
      "Confirm with your master password — LastPass downloads a lastpass_export.csv file.",
    ],
    note: "Use that downloaded file directly. Don’t copy CSV text out of a browser tab into a file — that route mangles characters like “&”.",
  },
];

function friendlyParseError(e: unknown): string {
  if (e instanceof ImportError) {
    switch (e.code) {
      case "too_large":
        return "That file is larger than 10 MiB — far bigger than any real password export. Double-check you picked the right file.";
      case "too_many_rows":
        return "That file has more than 10,000 rows. Split it into smaller files and import them one at a time.";
      case "unrecognized_header":
        // Universal copy (design 2026-07-11): no pick exists to key a bespoke hint on,
        // so the old 1Password-specific hint folds into the one message.
        return "This file isn't a recognized password export. Make sure you exported a CSV (not JSON or a zip) — and if it came from 1Password, that you're on 1Password 8 or newer.";
      default:
        return `That file could not be read (${e.code}).`;
    }
  }
  return "That file could not be read. Make sure it's the CSV your password manager exported.";
}

/** ux-error--1: the transient import-push sentence — its promise is true, because the plan's
 *  itemIds double as push mutationIds and the server dedupes an already-applied put. */
const IMPORT_INTERRUPTED =
  "The import was interrupted before it finished. Everything that already landed is safe in your vault — press Retry to import the rest (it won’t create duplicates).";

/**
 * ux-error--1 (polish audit 2026-07-27): the import PUSH phase's outcome. The old catch-all
 * promised EVERY failure would finish on Retry, so a refusal replayed the same doomed push forever
 * under a sentence saying it would work. `fatal` drops the Retry affordance; the message then names
 * what the server actually refused. Named-terminal-first, transient-last — MoveCopyControl's
 * ladder shape, and its sentences are the same canon twins (core HouseholdCopy's status rows,
 * pinned by vault-copy.test.ts).
 *
 * Deliberately NOT enumerated: 401 (the client's definitive-401 path forgets the session, which
 * unmounts this panel) and 426 (api/client.ts fires onUpgradeRequired and App shows its sticky
 * "reload to update" banner) — both already answer GLOBALLY, and the natives' equivalents raise
 * their blocking upgrade screen, so a local sentence here would only compete with them.
 * Exported for import-push-outcome.test.ts (the offlineCopyModel idiom).
 */
export function importPushOutcome(e: unknown): { message: string; fatal: boolean } {
  // A push the client's limit ended (the server stopped answering): said so; Retry sends the same ids again.
  const limit = answerLimitText(e);
  if (limit !== null) return { message: limit, fatal: false };
  if (e instanceof KdfPolicyError) return { message: kdfRefusalText(e), fatal: true }; // H1 (spec 05 T1)
  // Spec 03 §14.4: the check before the import found the account short. Nothing was sent; a retry would be short again.
  if (e instanceof QuotaShortError) return { message: quotaShortText(e.limits), fatal: true };
  if (e instanceof ApiError && e.status === 403) return { message: "You don't have permission to do that.", fatal: true };
  if (e instanceof ApiError && e.status === 413) {
    return { message: "The server refused that upload — it may be too large, or storage may be full.", fatal: true };
  }
  return { message: IMPORT_INTERRUPTED, fatal: false };
}

function problemLabel(code: string): string {
  switch (code) {
    case "wrong_field_count":
      return "Wrong number of columns";
    case "bad_quote":
      return "Malformed quoting";
    default:
      return "Couldn't read this row";
  }
}

const FORMAT_LABEL: Record<ImportFormat, string> = {
  chrome: "Chrome/Edge (Chromium)",
  firefox: "Firefox",
  bitwarden: "Bitwarden",
  "1password": "1Password",
  lastpass: "LastPass",
};

/** A10 heuristic: multiple values carrying HTML entities smell like a copy-paste-from-a-
 *  browser-tab export (the classic LastPass trap). Hint ONLY — never auto-decode. */
const HTML_MANGLE = /&(amp|lt|gt|quot|#\d+);/;
function looksHtmlMangled(rows: ParsedRow[]): boolean {
  let hits = 0;
  for (const r of rows) {
    for (const v of [r.name, r.url, r.username, r.password, r.notes, r.totp ?? ""]) {
      if (HTML_MANGLE.test(v)) {
        hits++;
        if (hits >= 2) return true;
      }
    }
  }
  return false;
}

/** House idiom for the report's name lists: inline when short, summarized + expandable
 *  when long — every bucket stays enumerated BY NAME (A9), never reduced to a count. */
function NameList({ names }: { names: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const LIMIT = 8;
  if (names.length <= LIMIT) return <>{names.join(", ")}</>;
  if (expanded) {
    return (
      <>
        {names.join(", ")}{" "}
        <button type="button" className="link" onClick={() => setExpanded(false)}>show fewer</button>
      </>
    );
  }
  return (
    <>
      {names.slice(0, LIMIT).join(", ")}{" "}
      <button type="button" className="link" onClick={() => setExpanded(true)}>…and {names.length - LIMIT} more</button>
    </>
  );
}

/** Every report bucket, enumerated by name — rendered on the preview AND the finished
 *  screen so nothing about what the plan did is a surprise afterwards. */
/**
 * [preview]: the report shown before Import is pressed (nothing is imported yet), where "imported separately" would be
 * untrue: the preview's own lines say what will be done.
 */
/** The one-time-code group's line: on the preview, what will be done; on the finished screen, what was done. */
export function importTotpDiffersText(preview: boolean): string {
  return preview ? IMPORT_TOTP_DIFFERS_PREVIEW : IMPORT_TOTP_DIFFERS;
}

function ReportBuckets({ report, preview = false }: { report: ImportReport; preview?: boolean }) {
  const bucket = (names: string[], intro: string) =>
    names.length > 0 ? (
      <div className="msg info" style={{ display: "block" }}>
        {intro} <NameList names={names} />.
      </div>
    ) : null;
  return (
    <>
      {bucket(report.alreadyInVault, "Already in your vault — skipped:")}
      {bucket(report.passwordDiffers, preview ? "Same site and username as your vault, but a different password — will be imported separately (renamed) so you can review which one is current:" : "Same site and username as your vault, but a different password — imported separately (renamed) so you can review which one is current:")}
      {bucket(report.totpDiffers, importTotpDiffersText(preview))}
      {bucket(report.flagged, "Renamed so every item keeps a distinct name:")}
      {bucket(report.archivedSkipped, "Archived in the export — not imported:")}
      {bucket(report.unknownTypeSkipped, "Item types andvari can't import yet — skipped:")}
      {bucket(report.totpUnsupported, "One-time-code secrets in a format andvari can't verify — kept as text in each item's notes:")}
      {bucket(report.noteItems, "Secure notes imported:")}
    </>
  );
}

function ReportTiles({ report, done }: { report: ImportReport; done: boolean }) {
  return (
    <div className="tiles" style={{ marginTop: 4 }}>
      <div className="tile"><div className="tile-value tone-good">{report.imported}</div><div className="tile-label">{done ? "Imported" : "To import"}</div></div>
      {report.alreadyInVault.length > 0 && <div className="tile"><div className="tile-value">{report.alreadyInVault.length}</div><div className="tile-label">Already in vault</div></div>}
      {report.collapsed > 0 && <div className="tile"><div className="tile-value">{report.collapsed}</div><div className="tile-label">Merged (dupes)</div></div>}
      {report.flagged.length > 0 && <div className="tile"><div className="tile-value tone-mid">{report.flagged.length}</div><div className="tile-label">Renamed</div></div>}
      {report.skippedEmpty > 0 && <div className="tile"><div className="tile-value">{report.skippedEmpty}</div><div className="tile-label">Skipped (empty)</div></div>}
      {report.errors.length > 0 && <div className="tile"><div className="tile-value tone-bad">{report.errors.length}</div><div className="tile-label">Rows with problems</div></div>}
    </div>
  );
}

/**
 * Universal import (design 2026-07-11): one screen — "Choose file…" straight to the picker
 * (header detection decides the format; no source pick exists) → vault-aware plan preview →
 * encrypt-and-push. Everything happens on this device; the file
 * never leaves the browser. The plan's itemIds are minted once, so a mid-import failure is
 * fixed with Retry (idempotent replay of the SAME plan — each itemId doubles as the push
 * mutationId) rather than re-parsing; re-parsing mints new ids and would duplicate.
 * The plan compares against the DESTINATION vault (store.importProjections(vaultId), A8/S2 —
 * default personal, switchable to any writable shared vault): items already there are
 * skipped — including rows a previous import renamed to "name (k)" (rule 1 also
 * matches through the stripped base name). One exception keeps this short of a blanket
 * "re-import is safe": a row whose totp value doesn't parse is unmatchable by design (A7,
 * fp = null) and re-imports as a renamed copy — the preview shows it before anything lands.
 * S2 invariant: `planned` pairs each plan with the vault whose projections produced it, and
 * the commit reads THAT vault — never the picker — so plan and importDocs cannot disagree.
 */
function ImportPanel({ store, personalVaultId, onClose, onDone }: { store: VaultStore; personalVaultId: string; onClose: () => void; onDone: () => void }) {
  const fileInput = useRef<HTMLInputElement | null>(null);
  /** The "How do I export from…?" help block — collapsed by default (design 2026-07-11). */
  const [helpOpen, setHelpOpen] = useState(false);
  const [fileName, setFileName] = useState("");
  const [format, setFormat] = useState<ImportFormat | null>(null);
  const [planned, setPlanned] = useState<{ plan: ImportPlan; vault: VaultInfo } | null>(null);
  /** The parse, retained so a destination change can re-plan without re-reading the file. */
  const [parsed, setParsed] = useState<Parsed | null>(null);
  /** physical line → 1-based data-row ordinal, so errors render "row N (file line M)" (A9). */
  const [rowNoByLine, setRowNoByLine] = useState<Map<number, number>>(new Map());
  const [mangled, setMangled] = useState(false);
  const [parseErr, setParseErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [importErr, setImportErr] = useState("");
  /** ux-error--1: does [importErr] describe a failure a Retry can actually clear? A terminal
   *  refusal keeps importLocked (the plan's ids must not be re-minted) but drops the Retry. */
  const [importFatal, setImportFatal] = useState(false);
  /** S2: a non-locking notice for a failed destination PICK (vault vanished mid-sync) —
   *  deliberately not importErr, which would flip importLocked and freeze the very picker
   *  the user needs to choose again with. */
  const [pickErr, setPickErr] = useState("");
  const [finished, setFinished] = useState(false);

  // F18 idiom (mirrors newItemVaultChoices): personal + shared vaults we can WRITE to —
  // readers never appear. Computed per render, not memoized: the first sync can finish
  // while this panel is open and newly-held vaults must surface without a remount.
  const vaultChoices = store.vaults().filter((v) => (v.type === "personal" || v.role === "owner" || v.role === "writer") && !store.moveDeleteWaiting(v.vaultId) && store.mayWrite(v.vaultId));

  const reset = () => {
    setPlanned(null);
    setParsed(null);
    setFormat(null);
    setRowNoByLine(new Map());
    setMangled(false);
    setParseErr("");
    setImportErr("");
    setImportFatal(false);
    setFinished(false);
    setProgress(null);
  };

  const onFile = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    const file = files[0]!;
    reset();
    setFileName(file.name);
    try {
      // A8: the plan needs the vault's projections — REFUSE honestly when this device has
      // never completed a sync, rather than silently planning against an empty vault
      // (which would quietly re-import everything as new). The personal-vault lookup shares
      // the gate: post-sync it always exists, pre-sync store.vaults() may be empty.
      // H64 / R47: resolve the destination BY IDENTITY (`account.personalVaultId`), never by the
      // server's `type === "personal"` label. That column is server plaintext bound into no AD
      // (spec 02 §4), which is the whole reason H64 made Account.setPersonalVault refuse a vault
      // whose VK arrived by member grant. This call site never went through Account at all, so a
      // hostile server that withheld the real personal row and relabelled a SHARED vault could
      // redirect an ENTIRE imported CSV — every password in the file — into the housemates'
      // vault, while the preview called it "your personal vault". Identity fails CLOSED: when
      // `personalVaultId` is empty (H64's own fail-closed state, every candidate member-granted)
      // no choice matches and the honest refusal below fires instead of a wrong default.
      const personal = vaultChoices.find((v) => v.vaultId === personalVaultId);
      if (store.lastSyncAt === null || !personal) {
        setParseErr(
          "Your vault hasn't finished its first sync on this device, so the import can't check what you already have. Wait for the sync (or press Sync now in the top bar), then pick the file again.",
        );
        return;
      }
      // H77: SIZE FIRST, before a single byte is materialised. csv.ts's MAX_BYTES check runs
      // on an already-read buffer, so a mis-picked multi-GB file (a disk image, a video) used
      // to be pulled into memory in full — freezing or crashing a tab that has an UNLOCKED
      // vault in it — instead of producing the honest one-line refusal. Both natives already
      // stream through readBounded for exactly this reason (MainActivity's "BOUNDED read (never
      // buffer a multi-GB file)", DesktopState's "a mislabeled multi-GB pick is rejected without
      // being buffered"); `File.size` is available synchronously, so web can be as strict for
      // free. Thrown, not returned, so the refusal lands on the same friendlyParseError copy the
      // post-read gate produces — one sentence for one condition.
      if (file.size > MAX_BYTES) throw new ImportError("too_large");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const p = parseCsvImport(bytes);
      setFormat(p.format);
      setParsed(p);
      setRowNoByLine(rowOrdinalsByLine(bytes));
      setMangled(looksHtmlMangled(p.rows)); // A10 — hint only, never auto-decode
      // ids minted ONCE here, reused verbatim on Retry. Every fresh parse plans against
      // the DEFAULT destination — personal (S2 picker contract).
      setPlanned({ plan: planImport(p, store.importProjections(personal.vaultId), () => crypto.randomUUID()), vault: personal });
    } catch (e) {
      setParseErr(friendlyParseError(e));
    } finally {
      if (fileInput.current) fileInput.current.value = "";
    }
  };

  // Locked once an import attempt starts: re-planning after a partial import would mint new
  // ids (breaking Retry's idempotent replay) and strand already-landed rows in the old vault.
  const importLocked = busy || finished || importErr !== "";

  const changeDestination = (vaultId: string) => {
    const vault = vaultChoices.find((v) => v.vaultId === vaultId);
    if (!vault || !parsed || importLocked) return;
    // A sync-time removal can race the click (the option came from a render-closure
    // snapshot) — never re-plan against a vault we no longer hold: its projections read
    // empty and every row plans as "to import" (native importSetVault parity).
    if (!store.vaults().some((v) => v.vaultId === vault.vaultId)) {
      setPickErr(DESTINATION_GONE);
      return;
    }
    setPickErr("");
    // A plan is only valid against the vault whose projections it compared (the F75 dedupe
    // verdicts differ per vault) — so re-plan from the retained parse. planImport is
    // synchronous and plan+vault land in ONE state commit, so Confirm can never fire against
    // a stale pairing; fresh ids are safe here — nothing has been pushed yet (importLocked).
    setPlanned({ plan: planImport(parsed, store.importProjections(vault.vaultId), () => crypto.randomUUID()), vault });
  };

  // The plan's destination, read through the store's guarded reader at each render: a vault the person was removed from
  // while the panel was open is no destination; nothing is imported until another is picked (and re-planned).
  const destGone = planned !== null && !finished && !store.vaults().some((v) => v.vaultId === planned.vault.vaultId);
  // A finished import's report is derived from its destination's items ("already in the vault", a different password):
  // once that vault is no longer one whose items are shown (a removal carried out), the report is closed, read at each
  // render, and the panel with it.
  const reportGone = planned !== null && finished && !store.shownVaultIds().includes(planned.vault.vaultId);
  useEffect(() => {
    if (reportGone) onDone();
  }, [reportGone, onDone]);

  const runImport = async () => {
    if (!planned || destGone) return;
    setBusy(true);
    setImportErr("");
    setImportFatal(false);
    setProgress({ done: 0, total: planned.plan.items.length });
    try {
      // Reuse plan.items on every attempt: each carries its own itemId, used as the push
      // mutationId → the server dedupes an already-applied put, so Retry never duplicates.
      // Destination = the vault CAPTURED with the plan (S2 invariant), never the picker.
      await store.importDocs(planned.plan.items, (done, total) => setProgress({ done, total }), planned.vault.vaultId);
      setFinished(true);
    } catch (e) {
      const outcome = importPushOutcome(e);
      setImportFatal(outcome.fatal);
      setImportErr(outcome.message);
    } finally {
      setBusy(false);
    }
  };

  const report = planned?.plan.report ?? null;
  const nothingToImport = planned !== null && planned.plan.items.length === 0;
  // Destination shown in the plan summary + final report — "your personal vault" keeps the
  // pre-S2 copy for the default; a shared vault is named so the reader knows who sees it.
  const destLabel = planned ? (planned.vault.type === "personal" ? "your personal vault" : `“${planned.vault.name}” (shared)`) : "";

  return (
    <div className="sheet">
      {/* a11yweb-02/BL-1: announce the import lifecycle START + COMPLETE only (never the
          per-row progress label — that would be screen-reader spam). Persistent region so
          the completion, which swaps in the report branch, is not silently mounted. */}
      <Announcer
        text={
          finished && report && !reportGone
            ? `Import complete. Added ${report.imported} ${report.imported === 1 ? "item" : "items"} to ${destLabel}.`
            : busy && planned
              ? `Importing ${planned.plan.items.length} ${planned.plan.items.length === 1 ? "item" : "items"}…`
              : ""
        }
      />
      <BackLink label="Back to vault" onClick={onClose} />
      <h2 style={{ marginTop: 12 }}>Import passwords (CSV)</h2>
      <div className="muted" style={{ marginBottom: 18 }}>from a browser or another password manager · everything stays on this device</div>

      {/* Always-visible plaintext caution. */}
      <div className="msg info" style={{ display: "block" }}>
        <strong>⚠ An exported CSV holds every password in plaintext.</strong> Nothing about it
        is uploaded — parsing happens here in your browser and each item is encrypted before it
        is saved. Items already in your vault are skipped — the preview shows exactly what will
        be imported. When you're done, delete the CSV and empty your trash.
      </div>

      <input
        ref={fileInput}
        type="file"
        accept=".csv,text/csv,text/plain"
        aria-label="Choose a CSV file to import"
        style={{ display: "none" }}
        onChange={(e) => onFile(e.target.files)}
      />

      {reportGone ? null : finished && report ? (
        <>
          <ReportTiles report={report} done />
          <ReportBuckets report={report} />
          <div className="msg info" style={{ display: "block" }}>
            Added {report.imported} {report.imported === 1 ? "item" : "items"} to {destLabel}.
            Now delete <strong>{fileName || "the CSV file"}</strong> and empty your trash.
          </div>
          <div className="actions">
            <button type="button" className="primary" onClick={onDone}>Done</button>
          </div>
        </>
      ) : planned && report ? (
        <>
          <div className="muted" style={{ marginBottom: 12 }}>
            {fileName && <>“{fileName}” · </>}detected {format ? FORMAT_LABEL[format] : "password"} export · into {destLabel}
          </div>

          {(pickErr || destGone) && <div className="muted" style={{ marginBottom: 8 }}>{pickErr || DESTINATION_GONE}</div>}
          {/* S2: destination picker (F18 idiom — rendered only when there is a real choice, or when the planned
              destination is gone). Changing it re-plans against that vault's projections (changeDestination). */}
          {(vaultChoices.length > 1 || destGone) && (
            <Field label="Import into">
              <select value={destGone ? "" : planned.vault.vaultId} disabled={importLocked} onChange={(e) => changeDestination(e.target.value)}>
                {destGone && <option value="">—</option>}
                {vaultChoices.map((v) => (
                  <option key={v.vaultId} value={v.vaultId}>
                    {vaultLabel(v, vaultChoices)}{v.type === "personal" ? "" : " (shared)"}
                  </option>
                ))}
              </select>
            </Field>
          )}

          {/* A10: the copy-paste-from-a-browser-tab trap (classic LastPass). Hint only. */}
          {mangled && (
            <div className="msg info" style={{ display: "block" }}>
              Several values in this file look HTML-mangled {"— “&” written as “&amp;”, for example —"}
              which happens when CSV text is copied out of a browser tab instead of downloaded.
              Nothing was decoded automatically; for a clean import, re-export via Advanced Options → Export
              so a real file downloads.
            </div>
          )}

          <ReportTiles report={report} done={false} />
          <ReportBuckets report={report} preview />

          {report.errors.length > 0 && (
            <div className="field">
              <label>Rows skipped ({report.errors.length})</label>
              <div className="table-scroll">
                <table className="table">
                  <thead><tr><th>Row</th><th>Problem</th></tr></thead>
                  <tbody>
                    {/* Capped: a mass-mangled file yields up to 9,999 error rows — that many
                        <tr>s is real DOM/jank cost for zero review value. */}
                    {report.errors.slice(0, 100).map((err, idx) => (
                      <tr key={`${err.line}-${idx}`}>
                        <td className="mono">row {rowNoByLine.get(err.line) ?? "?"} (file line {err.line})</td>
                        <td>{problemLabel(err.code)}</td>
                      </tr>
                    ))}
                    {report.errors.length > 100 && (
                      <tr><td colSpan={2}>…and {report.errors.length - 100} more rows not shown — fix the export and re-select the file.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {nothingToImport && <div className="msg info" style={{ display: "block" }}>Nothing new to import from this file.</div>}
          {importErr && <Msg kind="err">{importErr}</Msg>}

          {busy && progress && (
            <div className="field" style={{ marginTop: 16 }}>
              <label>Importing… {Math.min(progress.done, progress.total)} / {progress.total}</label>
              <div className="strength" style={{ height: 6 }}>
                <span style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%`, background: "var(--gold)" }} />
              </div>
            </div>
          )}

          <div className="actions">
            {importErr && importFatal ? (
              /* ux-error--1: a terminal refusal offers the EXIT, not a Retry that replays the same
                 "no". onDone (not onClose) so the rows that did land show up in the vault. */
              <button type="button" className="primary" onClick={onDone}>Back to vault</button>
            ) : importErr ? (
              <button type="button" className="primary" disabled={busy} onClick={runImport}>{busy ? "Retrying…" : "Retry"}</button>
            ) : (
              <button type="button" className="primary" disabled={busy || nothingToImport || destGone} onClick={runImport}>
                {busy ? "Importing…" : `Import ${report.imported} ${report.imported === 1 ? "item" : "items"}`}
              </button>
            )}
            <div className="spacer" />
            {/* Locked in the PARTIAL state (importErr): reset() would wipe the plan's idempotent
                ids and a re-pick re-plans against personal by default — the exact cross-vault
                duplicate path importLocked exists to close. After a CLEAN finish it's fine
                (rows landed + synced; the next plan dedupes them). */}
            <button type="button" className="ghost" disabled={busy || importErr !== ""} onClick={() => { reset(); setFileName(""); }}>Choose a different file</button>
          </div>
        </>
      ) : (
        <>
          {/* The universal screen (design 2026-07-11): no source pick — the file decides. */}
          <div className="muted" style={{ marginBottom: 12 }}>
            Works with password exports from Chrome, Edge, Brave, Opera, Firefox, Bitwarden,
            1Password 8 or newer, LastPass, and Safari — the file itself decides how it's read.
          </div>
          {/* A-webError: this branch is parseErr's ONLY render site — a bad file must
              visibly fail right here, next to the picker button. */}
          {parseErr && <Msg kind="err">{parseErr}</Msg>}
          <div className="actions">
            <button type="button" className="primary" onClick={() => fileInput.current?.click()}>Choose file…</button>
            <div className="spacer" />
            <button type="button" className="ghost" onClick={onClose}>Cancel</button>
          </div>
          <div className="field" style={{ marginTop: 18 }}>
            <button type="button" className="link" aria-expanded={helpOpen} onClick={() => setHelpOpen((o) => !o)}>
              How do I export from…? {helpOpen ? "▴" : "▾"}
            </button>
            {helpOpen &&
              IMPORT_SOURCES.map((s) => (
                <div key={s.label} style={{ marginTop: 12 }}>
                  <label>{s.label}</label>
                  <ol className="steps">
                    {s.steps.map((step, i) => (
                      <li key={i}>{step}</li>
                    ))}
                  </ol>
                  {s.note && <div className="muted">{s.note}</div>}
                </div>
              ))}
          </div>
        </>
      )}
    </div>
  );
}
