import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError, TrafficStoppedError } from "../api/client";
import type { Account } from "../vault/account";
import { logActionText } from "./logactiontext";
import { QuotaShortError } from "../vault/quota";
import { quotaShortText } from "./quotatext";
import { ChangeNotStoredError, type DeletedVaultInfo, type DiscardOutcome, HeldKeyGoneError, type IncomingTransfer, LogActionError, type MoveMember, type MoveResult, MoveStoppedError, MoveWaitingError, OldVaultFrozenError, type UnfinishedMove, type VaultInfo, type VaultStore } from "../vault/store";
import type { Roster, RosterRow } from "../vault/sharedlogs";
import { LogAddMember } from "./LogAddMember";
import { MOVE_WAITING_REFUSED, HELD_ADDED_AGAIN, HELD_DELETED_BY_ME, HELD_COPIED, HELD_COPIED_NO_FILES, HELD_COPIED_UNREADABLE, HELD_COPY, HELD_COPY_ATTACHMENTS, HELD_COPY_OUT_OF_SPACE, HELD_NO_KEY, HELD_REMOVE_CONFIRM, REMOVE_FROM_THIS_DEVICE,CHECK_WHAT_YOU_COPY, DELETED_NOTE_ALONE, OFFER_REFUSED, ROLE_CHANGE_ASK, ROLE_CHANGE_CONFIRM, ROLE_CHANGE_READER, ROLE_CHANGE_RUNNING, ROLE_CHANGE_WRITER, MOVE_CANNOT_ADD, MOVE_CHANGED_MEANWHILE, MOVE_DISCARD_FAILED, MOVE_DISCARDED, MOVE_DISCARDED_SAME_NAME, MOVE_DONE, MOVE_DONE_ALONE, MOVE_DONE_KEPT, MOVE_EVERYTHING, MOVE_KEPT_MEMBERS_DIFFER, MOVE_INTRO, MOVE_INTRO_STAYS, MOVE_KEEPS_OLD, MOVE_KEPT_STAYS, MOVE_NAME, MOVE_NEEDS_SPACE, MOVE_NOBODY, MOVE_NOT_MOVED, MOVE_NOT_MOVED_STAYS, MOVE_PROGRESS, MOVE_REMOVING, MOVE_RESUME, MOVE_STOPPED_ADD, MOVE_STOPPED_COPY, MOVE_STOPPED_DELETE, MOVE_STOPPED_DELETE_HELD, MOVE_STOPPED_DELETE_WAITING, MOVE_STOPPED_START, MOVE_UNCOPYABLE, MOVE_FINISH, MOVE_UNFINISHED, MOVE_UNNAMED_OLD, MOVE_UNNAMED_VAULT, MOVE_WAITING_LOCKED, MOVE_WAITING_PANEL, OWNER_OUT_OF_SPACE, MOVE_STOPPED_DELETE_STORED, MOVE_STOPPED_REMOVE_HELD, MOVE_STOPPED_ADD_HELD, MOVE_DISCARD_WAITING, LOG_NOT_SENT, RENAME_UNKNOWN, MOVE_KEEPS_OLD_WAITING, MOVE_CHANGED_MOVED_ON, MOVE_CHANGED_AFTER_READ, MOVE_DONE_BANNER, MOVE_DONE_ALONE_BANNER, MOVE_DONE_NO_DAY, MOVE_DONE_ALONE_NO_DAY, MOVE_DONE_BANNER_NO_DAY, MOVE_DONE_ALONE_BANNER_NO_DAY, DELETED_NOTE_NO_DAY, DELETED_NOTE_ALONE_NO_DAY, MOVE_DISCARD_KEPT, MOVE_DISCARD_UNREAD, MOVE_DISCARD_NOT_HELD, MOVE_DISCARD_HOLDERS, MOVE_DISCARD_HOLDERS_UNNAMED, MOVE_DISCARD_HOLDERS_FOUND, MOVE_DISCARD_HOLDERS_FOUND_UNNAMED, MOVE_DISCARD_HOLDERS_FOUND_UNREAD, MOVE_DISCARD_HOLDERS_FOUND_UNREAD_UNNAMED, MOVE_DISCARDED_BEFORE_START, MOVE_STOPPED_START_REMOVED, MOVE_STOPPED_COPY_REMOVED, MOVE_STOPPED_ADD_REMOVED, MOVE_STOPPED_ADD_HELD_REMOVED } from "./copy";
import { fill, OFFER_IN_ACCEPT, OFFER_IN_ACCEPTING, OFFER_IN_BODY, OFFER_IN_DECLINE, OFFER_IN_OWNER_UNKNOWN, OFFER_IN_TITLE, OFFER_IN_UNTIL, OFFER_SIGNED, OWNERSHIP_OFFER_ASK, REMOVE_MEMBER_DOES_NOT, OWNERSHIP_OFFER_BODY, OWNERSHIP_OFFER_OPEN, OWNERSHIP_OFFER_TITLE, ROSTER_FROZEN, ROSTER_MAY_BE_INCOMPLETE, ROSTER_NONE, ROSTER_STALE, ROSTER_UNVERIFIED } from "./copy";
import { answerLimitText, UNREACHABLE } from "./errors";
import { fmtDay } from "./format";
import { madeWhen, storeVaultLabel, vaultLabel } from "./vaultlabel";
import { RESEND_WITHDRAW, RESEND_WITHDRAWN, RESEND_WITHDRAWN_UNKNOWN, OFFLINE_SHARING_WAIT, ROLE_LOCKED_NOW, SAME_NAME_MADE_LINE, MOVE_OLD_FROZEN } from "./copy";
import { ITEMS_SET_ASIDE_COPY, ITEMS_SET_ASIDE_INTRO, ITEMS_SET_ASIDE_LINE, ITEMS_SET_ASIDE_PERSONAL_NAME, ITEMS_SET_ASIDE_REMOVE_CONFIRM, ITEMS_SET_ASIDE_TITLE } from "./copy";
import type { HeldKnown } from "../vault/logstore";
import { heldWaitingText } from "./heldtext";
import { BackLink } from "./BackLink";
import { Announcer, Msg } from "./Msg";
import { settingsContentFor, showSettingsButton } from "./sharing-settings";
import { ViewHeader } from "./ViewHeader";

interface Props {
  account: Account;
  store: VaultStore;
  client: ApiClient;
  onSynced: () => void; // parent refresh — items may gain/lose vault badges, notices update
  onBackup: () => void; // open the full-vault backup panel (delete dialog "Back up first…")
  /** DN-1 (A1): the open per-vault settings layer, owned by Vault so its single back
   *  guard closes it as the topmost layer. null = the vaults list. */
  settingsVaultId: string | null;
  onOpenSettings: (vaultId: string) => void;
  onCloseSettings: () => void;
  /**
   * The vault was opened from this browser's offline copy and no sync has landed since (spec 02 §8): everything here
   * that needs the server is shown disabled under one line that says why. The list, the per-vault layers and this
   * browser's held copies stay readable; a held copy can still be removed from this device.
   */
  offline?: boolean;
}

/** Sharing view (spec 03 §10/§11 + DN-1): vaults, members, and the full lifecycle — delete,
 *  restore, leave, transfer, rename. Each SHARED vault row carries a Settings button opening
 *  that vault's settings layer (the F76 revealed-layer idiom) in place of the list: owners get
 *  the member panel, members get the read-only roster + Leave (re-homed off the row). Incoming
 *  ownership offers and the undecryptable-grants warning stay ABOVE the branch (A7), so they
 *  surface even with settings open; the Vaults sheet, NewVaultForm, and Recently-deleted are
 *  list-branch-only. */
export function Sharing({ account, store, client, onSynced, onBackup, settingsVaultId, onOpenSettings, onCloseSettings, offline = false }: Props) {
  // Keyed on `offline` so that what needs the server loads again once a sync lands.
  const needsServer = (key: string, children: React.ReactNode) => (
    <fieldset key={`${key}-${offline ? "offline" : "online"}`} className="needs-server" disabled={offline}>{children}</fieldset>
  );
  const [tick, setTick] = useState(0);
  // Owner dev-note 2026-08-19: the vault ids RecentlyDeleted currently offers to RESTORE.
  // The deleter's own device holds a sealed copy too, so the same vault showed in BOTH lists —
  // two rows telling one story. The Restore row is strictly more actionable, so the holding
  // area hides its twin; members who merely lost access still see theirs (they get no Restore).
  const [restorableIds, setRestorableIds] = useState<string[]>([]);
  // A3: every vault's DeleteVaultControl {copying, copiedNote} lives HERE, keyed by vaultId —
  // Sharing stays mounted across settings-layer cycles, so closing the layer mid-copy doesn't
  // orphan the rescue-copy progress, and a reopened panel shows honest state. (No store.ts
  // change: the in-flight copyAllToPersonal keeps reporting into these setters after the
  // panel unmounts.)
  const [copyingByVault, setCopyingByVault] = useState<Record<string, { done: number; total: number } | null>>({});
  const [copiedNoteByVault, setCopiedNoteByVault] = useState<Record<string, string>>({});
  // N2 §7: the post-delete note lives HERE too — deleteSharedVault drops the vault before
  // returning, so the very commit that could show a panel-local toast also nulls
  // vaults.find(…) and unmounts the settings layer. Only parent state survives that commit;
  // the list branch below renders it.
  const [deletedNote, setDeletedNote] = useState<{ vaultId: string; name: string; purgeAt: number | null; alone: boolean } | null>(null);
  // §3.13: what a finished move did. Held here for the same reason: a move that deletes the old vault unmounts its layer.
  const [movedNote, setMovedNote] = useState("");
  const refresh = () => {
    setTick((t) => t + 1);
    onSynced();
  };
  // DN-2: presentation-only disclosure for the recently-deleted-vaults section.
  const [trashOpen, setTrashOpen] = useState(false);
  // Derived each render (cheap) so a background WS sync that re-renders the parent is reflected.
  void tick;
  const vaults = store.vaults();
  const incoming = store.incomingTransfers();

  // DN-1: resolve the settings id against the CURRENT vaults each render (invariant 4) — a
  // vault revoked/deleted by another device degrades to the list, never a crash.
  const settingsContent = settingsContentFor(settingsVaultId, vaults);
  const settingsVault = settingsVaultId ? vaults.find((v) => v.vaultId === settingsVaultId) : undefined;

  // A2: a derive-only lookup would RESURRECT the layer (delete X in settings → restore X in
  // Recently deleted → settings X pops back open). Actively clear the id the moment it stops
  // resolving; the render below keeps its own null-guard for the same-frame gap.
  useEffect(() => {
    if (settingsVaultId && settingsContent === null) onCloseSettings();
  }, [settingsVaultId, settingsContent, onCloseSettings]);

  // N2 §7 clearing rule (the escape-hatch lesson): if the note's vault comes BACK — restored
  // from the trash section below, or by another device via a background sync — a lingering
  // "deleted until…" line would sit over a live vault. Clear on the TRANSITION absent→present,
  // not on presence itself (review MED): deleteSharedVault's reconcile can join an in-flight
  // STALE pull (the store's single-flight sync), so the vault can still read as present in the
  // very commit that sets the note — presence-based clearing would kill it instantly. Present
  // while never-yet-absent = that stale window; the note stands until a real sync drops the
  // row, and only a genuine reappearance after that clears it.
  const noteVaultPresent = deletedNote !== null && vaults.some((v) => v.vaultId === deletedNote.vaultId);
  const noteVaultWasAbsent = useRef(false);
  useEffect(() => {
    if (deletedNote === null) { noteVaultWasAbsent.current = false; return; }
    if (!noteVaultPresent) { noteVaultWasAbsent.current = true; return; }
    if (noteVaultWasAbsent.current) { noteVaultWasAbsent.current = false; setDeletedNote(null); }
  }, [deletedNote, noteVaultPresent]);

  return (
    <div>
      {/* BL-1: the post-delete note (rendered below in the list branch) mounts already-
          populated after the delete commit — announce it from this persistent region,
          which survives the settings-layer unmount that the delete triggers. */}
      <Announcer text={deletedNote ? deletedNoteText(deletedNote) : ""} />
      <ViewHeader
        title="Sharing"
        actions={
          !settingsVault && (
            /* DN-2: recently-deleted vaults live behind this icon instead of always rendering
               under the list — a disclosure toggle, deliberately NOT a back-guard layer. */
            <button
              type="button"
              className={`ghost ${trashOpen ? "active" : ""}`}
              aria-label="Recently deleted & removed vaults"
              title="Recently deleted & removed vaults"
              aria-expanded={trashOpen}
              onClick={() => setTrashOpen((o) => !o)}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ verticalAlign: "-2px" }}>
                <path d="M3 6h18" /><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2" /><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" /><path d="M10 11v6M14 11v6" />
              </svg>
            </button>
          )
        }
      />

      {offline && <div className="msg info" style={{ display: "block", marginTop: 16 }} role="status">{OFFLINE_SHARING_WAIT}</div>}

      {incoming.length > 0 && needsServer("incoming", incoming.map((t) => (
        <IncomingTransferCard key={t.vaultId} offer={t} store={store} client={client} onChanged={refresh} />
      )))}

      <UndecryptableGrantsWarning store={store} />

      <Announcer text={movedNote} />
      {movedNote && (
        <div className="msg info" style={{ marginTop: 16 }}>
          {movedNote}{" "}
          <button type="button" className="link" onClick={() => setMovedNote("")}>OK</button>
        </div>
      )}

      {settingsVault && settingsContent !== null ? (
        <>
          {/* DN-1 header: the layer's in-app back affordance; hardware/gesture Back closes it
              too, via Vault's closeTop (A1). The doubled vault name (this header + the panel's
              own H2) is the one accepted cosmetic drift (A10). */}
          <div className="sheet">
            <BackLink label="Back to vaults" onClick={onCloseSettings} />
            <h2 style={{ marginTop: 12, marginBottom: 0 }}>{settingsVault.name}</h2>
          </div>
          {needsServer("layer", settingsContent === "owner" ? (
            <MemberPanel
              key={settingsVault.vaultId}
              vault={settingsVault}
              store={store}
              client={client}
              onChanged={refresh}
              onBackup={onBackup}
              copying={copyingByVault[settingsVault.vaultId] ?? null}
              setCopying={(c) => setCopyingByVault((m) => ({ ...m, [settingsVault.vaultId]: c }))}
              copiedNote={copiedNoteByVault[settingsVault.vaultId] ?? ""}
              setCopiedNote={(note) => setCopiedNoteByVault((m) => ({ ...m, [settingsVault.vaultId]: note }))}
              onDeletedNote={setDeletedNote}
              onMovedNote={setMovedNote}
            />
          ) : (
            <>
              {/* F20: non-owners see WHO ELSE is in a shared vault they belong to (read-only). */}
              <MemberRosterPanel key={settingsVault.vaultId} vault={settingsVault} store={store} client={client} />
              {/* DN-1: Leave, re-homed off the vault row into the member vault's settings. */}
              <div className="sheet">
                <LeaveControl vault={settingsVault} store={store} onChanged={refresh} />
              </div>
            </>
          ))}
        </>
      ) : (
        <>
          {/* N2 §7: the post-delete note, rendered by the branch that survives the delete
              commit (the layer above unmounts in it). Same idiom as the panel toast it
              replaces; "the trash icon above" = the DN-2 disclosure in the header. */}
          {deletedNote && (
            <div className="msg info" style={{ marginTop: 16 }}>
              {deletedNoteText(deletedNote)}{" "}
              <button type="button" className="link" onClick={() => setDeletedNote(null)}>OK</button>
            </div>
          )}
          <div className="sheet">
            <h2>Vaults</h2>
            <p className="muted" style={{ marginTop: 0 }}>
              Every item lives in exactly one vault. Shared vaults are visible to everyone
              you add; only the vault owner manages members.
            </p>
            <div className="list">
              {vaults.map((v) => (
                <div className="item static" key={v.vaultId}>
                  <span className="glyph">{v.name.charAt(0).toUpperCase()}</span>
                  <span className="body">
                    {/* Two vaults of one name: when each was made goes on the second line, which a phone does not cut short. */}
                    <div className="name">{v.name}</div>
                    <div className="sub" style={vaultLabel(v, vaults) !== v.name ? { whiteSpace: "normal" } : undefined}>{v.type === "personal" ? "personal vault" : "shared vault"}{vaultLabel(v, vaults) !== v.name ? ` · ${fill(SAME_NAME_MADE_LINE, madeWhen(v.createdAt))}` : ""}</div>
                  </span>
                  <span className="tag">{v.role ?? "member"}</span>
                  {/* DN-1: shared vaults (owner and member alike) manage their lifecycle in the
                      settings layer; personal vaults have no lifecycle ops, so no button. Leave
                      moved off the row into settings — the row keeps its role tag. */}
                  {showSettingsButton(v) && (
                    <button type="button" className="ghost" onClick={() => onOpenSettings(v.vaultId)}>Settings</button>
                  )}
                </div>
              ))}
            </div>
            {needsServer("new", <NewVaultForm account={account} store={store} client={client} onCreated={refresh} />)}
          </div>

          {trashOpen && (
            <>
              {needsServer("deleted", <RecentlyDeleted store={store} refreshKey={tick} onChanged={refresh} onLoaded={setRestorableIds} />)}
              {/* IA P8: web finally has the holding-area surface Android has ("Recently
                  removed") — a read-only mirror; recovery is automatic on restore/re-add. */}
              <RecentlyRemoved store={store} hide={restorableIds} />
              <ItemsSetAside store={store} />
            </>
          )}
        </>
      )}
    </div>
  );
}

export function friendlyError(e: unknown): string {
  const limit = answerLimitText(e);
  if (limit !== null) return limit;
  if (e instanceof LogActionError || e instanceof ChangeNotStoredError) return logActionText(e);
  if (e instanceof MoveWaitingError) return MOVE_WAITING_REFUSED;
  if (e instanceof ApiError) {
    switch (e.code) {
      case "no_such_user": return "No account with that email address — they need to be invited and enrolled first.";
      case "already_member": return "That person is already a member of this vault.";
      case "cannot_target_self": return "That's your own account — you already own this vault.";
      case "user_inactive": return "That account has been disabled — ask your admin to re-enable it first.";
      case "not_vault_owner": return "Only the vault's owner can manage its members.";
      case "sharing_public_disabled": return "Sharing can't be managed from this public address — connect from inside (VPN/LAN) and try again.";
      // ---- lifecycle (spec 03 §11 / F48) ----
      case "owner_must_transfer_or_delete": return "You own this vault, so you can't just leave it — make someone else the owner first, or delete it.";
      case "vault_deleted": return "This vault was deleted. The owner can restore it for a few more days.";
      case "vault_gone": return "The restore window has passed — this vault's data has been erased.";
      case "vault_state_changed": return "This vault changed since you tried that — reload and try again.";
      case "transfer_not_pending": return "This ownership offer is no longer active.";
      case "not_transfer_target": return "This ownership offer isn't for you, or it couldn't be verified.";
      case "stale_meta": return "This vault changed somewhere else — reload and try the rename again.";
      case "not_a_member": return "They have to be a member of this vault first.";
    }
    // The server uses one generic "rate_limited" code for every limit; callers with a
    // known window (e.g. vault-create's 5/hour) refine the copy at the call site.
    if (e.status === 429) return "Too many requests — please wait a bit and try again.";
    if (e.status === 401) return "Your session has expired — lock and sign in again.";
    return "Something went wrong on the server — please try again.";
  }
  // Only a fetch() rejection (TypeError) means the server was unreachable. Anything else
  // thrown in these flows is a local decode/crypto failure — retrying or VPN-debugging
  // can't fix it, so say what it is.
  if (e instanceof TypeError) return UNREACHABLE;
  return "Something unexpected went wrong in the app — reload the page and try again.";
}

function NewVaultForm({ account, store, client, onCreated }: { account: Account; store: VaultStore; client: ApiClient; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      // A6b: the store records this account's own evidence that it owns the new vault (the server's role label is
      // never that evidence), and rolls back the optimistic local registration if the server refuses the create.
      await store.createSharedVault(name.trim());
      setName("");
      onCreated();
    } catch (err) {
      // vault-create's rate limit is 5 per hour — say so instead of the generic "wait a bit".
      setErr(
        err instanceof ApiError && err.status === 429
          ? "You can create up to 5 new shared vaults per hour — try again later."
          : friendlyError(err),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={create} style={{ marginTop: 18 }}>
      {err && <Msg kind="err">{err}</Msg>}
      <div className="field">
        <label>New shared vault</label>
        <div className="secret-row">
          <input aria-label="New shared vault" placeholder="e.g. Family" value={name} onChange={(e) => setName(e.target.value)} />
          <button className="ghost" disabled={busy || !name.trim()}>{busy ? "Creating…" : "Create"}</button>
        </div>
      </div>
    </form>
  );
}

// ---- leave (self-removal, spec 03 §11) ----

function LeaveControl({ vault, store, onChanged }: { vault: VaultInfo; store: VaultStore; onChanged: () => void }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const leave = async () => {
    setBusy(true);
    setErr("");
    try {
      await store.leaveSharedVault(vault.vaultId);
      onChanged();
    } catch (e) {
      setErr(friendlyError(e));
      setBusy(false);
    }
  };

  if (!confirming) {
    return (
      <button type="button" className="ghost" style={{ color: "var(--danger)" }} onClick={() => setConfirming(true)}>
        Leave
      </button>
    );
  }
  return (
    <span style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 6, flex: 2, minWidth: 0 }}>
      {err && <Msg kind="err">{err}</Msg>}
      {/* The 2026-11-16 walk: on its own sheet a right-aligned paragraph read ragged on the left; a sentence reads left to right. */}
      <span className="muted" style={{ alignSelf: "stretch" }}>
        Leave “{vault.name}”? You'll lose access on all your devices, and any edits you haven't
        synced will be discarded. The items stay with the owner and other members; only the owner
        can add you back. (Leaving doesn't erase what this device already knew.)
      </span>
      <span style={{ display: "flex", gap: 8 }}>
        <button type="button" className="ghost" disabled={busy} onClick={() => { setConfirming(false); setErr(""); }}>Cancel</button>
        <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={leave}>{busy ? "Leaving…" : "Leave vault"}</button>
      </span>
    </span>
  );
}

// ---- member management (owner-only panel per shared vault) ----

export function MemberPanel({ vault, store, client, onChanged, onBackup, copying, setCopying, copiedNote, setCopiedNote, onDeletedNote, onMovedNote }: { vault: VaultInfo; store: VaultStore; client: ApiClient; onChanged: () => void; onBackup: () => void; copying: { done: number; total: number } | null; setCopying: (c: { done: number; total: number } | null) => void; copiedNote: string; setCopiedNote: (note: string) => void; onDeletedNote: (note: { vaultId: string; name: string; purgeAt: number | null; alone: boolean }) => void; onMovedNote: (note: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [removing, setRemoving] = useState<string | null>(null); // userId pending remove confirm
  const [, setTick] = useState(0);
  const serverNames = useServerNames(client, vault.vaultId);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr("");
    try {
      await fn();
      setTick((t) => t + 1);
      onChanged();
    } catch (e) {
      setErr(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  // Design §3.7: every change is a signed log entry; the store's reconcile pull brings the log up to it. Choosing in the
  // drop-down only stages the change (arrowing through it with the keyboard signs nothing); the confirming step signs it.
  const [roleDraft, setRoleDraft] = useState<{ userId: string; role: "writer" | "reader" } | null>(null);
  const changeRole = (userId: string, role: "writer" | "reader") =>
    run(async () => {
      await store.setMemberRole(vault.vaultId, userId, role);
      setRoleDraft(null);
    });
  const remove = (userId: string) =>
    run(async () => {
      await store.removeVaultMember(vault.vaultId, userId);
      setRemoving(null);
    });
  // §3.13: "Move everything to a new vault", from the remove dialog (that member is not one of the remaining ones) or
  // on its own. `undefined`: closed.
  const [moving, setMoving] = useState<{ removing: string | null } | undefined>(undefined);
  // By keyboard: the button that opened the move's panel is gone while it is open; Cancel or Escape brings the focus
  // back to it (the panel's own "Finish the move" or "Move everything"), not to the page's start.
  const moveOpener = useRef<HTMLButtonElement>(null);
  const refocusOpener = useRef(false);
  useEffect(() => {
    if (moving === undefined && refocusOpener.current) moveOpener.current?.focus();
    refocusOpener.current = false;
  }, [moving]);

  // §3.9: the members are the verified log's, never the server's member list.
  const roster = store.memberRoster(vault.vaultId);
  const shared = store.sharedLogs();
  const pending = store.pendingTransferFor(vault.vaultId);
  const pendingRow = pending ? roster?.rows.find((r) => r.userId === pending.toUserId) : undefined;
  const targets = (roster?.rows ?? []).filter((r) => r.role !== "owner" && !r.self);
  // §3.3: the person an offer was made to refused it (their own `cancel`); the owner is told, not left to notice.
  const refused = pending === null ? (shared?.logs.refusedOffer(vault.vaultId) ?? null) : null;
  const refusedRow = refused ? roster?.rows.find((r) => r.userId === refused.by) : undefined;
  // Design §3.13: while the old vault's signed deletion waits, its log takes no other entry (the store refuses one with
  // `append_pending`), so renaming, roles, removing, adding, an ownership offer and deleting are not offered at all.
  const waiting = store.moveDeleteWaiting(vault.vaultId);

  return (
    <div className="sheet">
      <RenameHeader vault={vault} store={store} onRenamed={onChanged} locked={waiting} />
      <p className="muted" style={{ marginTop: 0 }}>
        {waiting ? fill(MOVE_WAITING_LOCKED, vault.name) : "You own this vault. Writers can add and edit items; readers can only view."}
      </p>
      {err && <Msg kind="err">{err}</Msg>}

      <RosterNotes roster={roster} />
      {/* A change of this vault kept to be sent again is shown as waiting where its members are, and an addition or a
          removal the server said it did not store can be withdrawn before it is sent. */}
      <WaitingChange vaultId={vault.vaultId} store={store} onChanged={onChanged} />
      {roster && (
        <div className="attach-list">
          {roster.rows.map((r) => (
            <div className="attach-row" key={r.userId} style={removing === r.userId || roleDraft?.userId === r.userId ? { flexWrap: "wrap" } : undefined}>
              {/* While removing, the name has the row's first line to itself, so a phone never cuts down whom it names. */}
              <span className="attach-name" style={removing === r.userId ? { flexBasis: "100%" } : undefined}>{memberName(r, serverNames)}</span>
              {r.role === "owner" ? (
                <span className="tag">owner</span>
              ) : waiting ? (
                // A role that cannot be changed while the deletion waits carries a small lock, and says so to a reader.
                <span className="tag role-locked" title={ROLE_LOCKED_NOW}>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ verticalAlign: "-1px", marginRight: 4 }}>
                    <rect x="5" y="11" width="14" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" />
                  </svg>
                  {r.role}
                  <span className="visually-hidden">{`, ${ROLE_LOCKED_NOW}`}</span>
                </span>
              ) : removing === r.userId ? (
                <>
                  {/* §3.13: the remove dialog says what removal does not do, in the design's own words. */}
                  <p className="muted" style={{ flexBasis: "100%", margin: "0 0 4px" }}>{REMOVE_MEMBER_DOES_NOT}</p>
                  <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => remove(r.userId)}>
                    {busy ? "Removing…" : "Confirm remove"}
                  </button>
                  <button type="button" className="ghost" disabled={busy} onClick={() => setRemoving(null)}>Keep</button>
                  {/* §3.13: offered right there. */}
                  {store.movePlan(vault.vaultId, r.userId) !== null && (
                    <button type="button" className="ghost" disabled={busy} onClick={() => { setMoving({ removing: r.userId }); setRemoving(null); }}>{MOVE_EVERYTHING}</button>
                  )}
                </>
              ) : roleDraft !== null && roleDraft.userId === r.userId ? (
                <>
                  <span style={{ flexBasis: "100%" }}>
                    <strong>{fill(ROLE_CHANGE_ASK, memberName(r, serverNames), roleDraft.role)}</strong>{" "}
                    <span className="muted">{roleDraft.role === "reader" ? ROLE_CHANGE_READER : ROLE_CHANGE_WRITER}</span>
                  </span>
                  <button type="button" className="ghost" disabled={busy} onClick={() => changeRole(r.userId, roleDraft.role)}>
                    {busy ? ROLE_CHANGE_RUNNING : ROLE_CHANGE_CONFIRM}
                  </button>
                  <button type="button" className="ghost" disabled={busy} onClick={() => setRoleDraft(null)}>Cancel</button>
                </>
              ) : (
                <>
                  <select
                    value={r.role}
                    disabled={busy || roleDraft !== null}
                    aria-label={`Role for ${memberName(r, serverNames)}`}
                    onChange={(e) => {
                      const role = e.target.value;
                      if ((role === "writer" || role === "reader") && role !== r.role) setRoleDraft({ userId: r.userId, role });
                    }}
                    style={{ width: "auto" }}
                  >
                    <option value="writer">writer</option>
                    <option value="reader">reader</option>
                  </select>
                  <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => setRemoving(r.userId)}>
                    Remove
                  </button>
                </>
              )}
            </div>
          ))}
        </div>
      )}

      {moving !== undefined ? (
        <MoveEverythingPanel
          vault={vault}
          store={store}
          serverNames={serverNames}
          removing={moving.removing}
          removingName={moving.removing === null ? "" : memberName(roster?.rows.find((r) => r.userId === moving.removing) ?? { userId: moving.removing, role: "writer", label: null, self: false }, serverNames)}
          onClose={() => {
            refocusOpener.current = true;
            setMoving(undefined);
          }}
          onMoved={(note) => {
            setMoving(undefined);
            onMovedNote(note);
            onChanged();
          }}
        />
      ) : store.moveDeleteWaiting(vault.vaultId) ? (
        // §3.13 as decided on 2026-11-16: the old vault's own panel says its deletion waits and the move must be finished.
        // On a phone the sentence beside its button was squeezed into a column of one or two words a line: it takes a
        // line of its own when the row is narrow, and the button wraps under it.
        <div className="msg info" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 12, marginTop: 14 }} role="status">
          <span style={{ flex: "1 1 16em" }}>{fill(MOVE_WAITING_PANEL, storeVaultLabel(store, vault.vaultId, vault.name), storeVaultLabel(store, store.movePlan(vault.vaultId)?.resume?.newVaultId ?? null, store.movePlan(vault.vaultId)?.resume?.name || MOVE_UNNAMED_VAULT))}</span>
          <button type="button" className="ghost" ref={moveOpener} disabled={busy || store.movePlan(vault.vaultId) === null} onClick={() => setMoving({ removing: null })}>{MOVE_FINISH}</button>
        </div>
      ) : (
        removing === null && store.movePlan(vault.vaultId) !== null && (
          <div className="actions" style={{ marginTop: 14 }}>
            <button type="button" className="ghost" ref={moveOpener} disabled={busy} onClick={() => setMoving({ removing: null })}>{MOVE_EVERYTHING}</button>
          </div>
        )
      )}

      {!waiting && refused !== null && (
        <div className="msg info" style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 14 }}>
          <span style={{ flex: 1 }}>
            {fill(OFFER_REFUSED, memberName(refusedRow ?? { userId: refused.by, role: "writer", label: null, self: false }, serverNames), vault.name)}
          </span>
          <button type="button" className="link" onClick={() => { shared?.logs.dismissRefusedOffer(vault.vaultId); setTick((t) => t + 1); }}>OK</button>
        </div>
      )}

      {waiting ? null : pending ? (
        <div className="msg info" style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 14 }}>
          <span style={{ flex: 1 }}>
            {fill(OWNERSHIP_OFFER_OPEN, pendingRow ? memberName(pendingRow, serverNames) : "a member", vault.name, fmtDay(pending.expiresAt))}
          </span>
          <button type="button" className="link" disabled={busy} onClick={() => run(() => store.cancelTransfer(vault.vaultId))}>
            Cancel offer
          </button>
        </div>
      ) : (
        <TransferOfferControl vault={vault} store={store} targets={targets.map((r) => ({ userId: r.userId, name: memberName(r, serverNames) }))} onOffered={async () => { setTick((t) => t + 1); onChanged(); }} onHeld={() => setTick((t) => t + 1)} />
      )}

      {!waiting && shared !== null && (
        <LogAddMember
          vaultId={vault.vaultId}
          store={store}
          shared={shared}
          onAdded={async () => {
            setTick((t) => t + 1);
            onChanged();
          }}
          // A held addition: the waiting line above (and its Withdraw button) is drawn now.
          onHeld={() => setTick((t) => t + 1)}
        />
      )}

      {!waiting && <DeleteVaultControl vault={vault} store={store} onDeleted={onChanged} onDeletedNote={onDeletedNote} onBackup={onBackup} copying={copying} setCopying={setCopying} copiedNote={copiedNote} setCopiedNote={setCopiedNote} onHeld={() => setTick((t) => t + 1)} />}
    </div>
  );
}

/** "1 item", "3 items": a count with its noun, for the placeholders that take one. */
function itemCount(n: number): string {
  return `${n} ${n === 1 ? "item" : "items"}`;
}

/**
 * The note after a vault was deleted: "Members lost access" only where it had other members. It names a day only where
 * the server served it ([purgeAt] null: an older server); otherwise it points to the list of deleted vaults.
 */
export function deletedNoteText(n: { name: string; purgeAt: number | null; alone: boolean }): string {
  if (n.purgeAt === null) return fill(n.alone ? DELETED_NOTE_ALONE_NO_DAY : DELETED_NOTE_NO_DAY, n.name);
  return n.alone
    ? fill(DELETED_NOTE_ALONE, n.name, fmtDay(n.purgeAt))
    : `“${n.name}” is deleted. Members lost access immediately. You can restore it until ${fmtDay(n.purgeAt)} (the trash icon above).`;
}

/**
 * What the move's panel says when "Move everything" did not finish: short of space before it started (spec 03 §14.4:
 * the approved out-of-space entry, which limits and by how much, nothing started), stopped part-way, or another failure.
 */
export function moveErrorText(e: unknown, oldName: string): string {
  if (e instanceof QuotaShortError) return quotaShortText(e.limits);
  return e instanceof MoveStoppedError ? moveStoppedText(e, oldName) : friendlyError(e);
}

/** A change of the vault's log that is held (signed, not read back), or refused because an earlier one of it is held. */
function heldChange(cause: unknown): boolean {
  if (cause instanceof ChangeNotStoredError) return true;
  return cause instanceof LogActionError && cause.outcome.kind === "not_allowed" && (cause.outcome.reason === "append_pending" || cause.outcome.reason === "append_unread");
}

/**
 * The sentence for a move that stopped part-way (§3.13): where it stopped, that nothing is in neither vault, then why;
 * then what became of an earlier run's half-made vault this run dealt with before copying anything.
 */
export function moveStoppedText(e: MoveStoppedError, oldName: string): string {
  return stoppedWhere(e, oldName) + discardText(e.discarded, e.newName, e.discarded?.name ?? "", e.newVaultId !== null);
}

function stoppedWhere(e: MoveStoppedError, oldName: string): string {
  // The old vault froze under the move's held deletion: dropped, never sent; the move's own line, never "finish the move".
  if (e.cause instanceof OldVaultFrozenError) return fill(MOVE_OLD_FROZEN, oldName, e.newName || MOVE_UNNAMED_VAULT);
  // The old vault's delete is signed and was never answered: neither kept nor deleted, and it cannot be taken back.
  if (e.stage === "delete" && e.cause instanceof ChangeNotStoredError) return fill(e.cause.known === "stored" ? MOVE_STOPPED_DELETE_STORED : MOVE_STOPPED_DELETE_HELD, String(e.copied), itemCount(e.total), e.newName || MOVE_UNNAMED_VAULT, oldName);
  // The removal or the addition this run signed is held: the step may be stored, so neither "wasn't changed" nor "not
  // everyone has been added" is said; the held change's own line follows.
  if (e.stage === "remove" && heldChange(e.cause)) return `${fill(MOVE_STOPPED_REMOVE_HELD, oldName)} ${friendlyError(e.cause)}`;
  if (e.stage === "add" && heldChange(e.cause)) return `${fill(e.oldChanged ? MOVE_STOPPED_ADD_HELD_REMOVED : MOVE_STOPPED_ADD_HELD, String(e.copied), itemCount(e.total), e.newName, oldName)} ${friendlyError(e.cause)}`;
  // A run finishing such a move stopped before it re-posted the delete: still waiting, and why.
  if (e.deleteWaiting) {
    const full = e.cause instanceof ApiError && e.cause.code === "quota_exceeded";
    return `${fill(MOVE_STOPPED_DELETE_WAITING, String(e.copied), itemCount(e.total), e.newName || MOVE_UNNAMED_VAULT, oldName)} ${full ? `${OWNER_OUT_OF_SPACE} ${MOVE_NEEDS_SPACE}` : friendlyError(e.cause)}`;
  }
  // After a removal the server stored, the old vault was changed (who is in it): no line says it "wasn't".
  const where =
    e.stage === "remove" || e.stage === "create"
      ? fill(e.oldChanged ? MOVE_STOPPED_START_REMOVED : MOVE_STOPPED_START, oldName)
      : fill(
          e.stage === "copy" ? (e.oldChanged ? MOVE_STOPPED_COPY_REMOVED : MOVE_STOPPED_COPY) : e.stage === "add" ? (e.oldChanged ? MOVE_STOPPED_ADD_REMOVED : MOVE_STOPPED_ADD) : MOVE_STOPPED_DELETE,
          String(e.copied),
          itemCount(e.total),
          e.newName,
          oldName,
        );
  const full = e.cause instanceof ApiError && e.cause.code === "quota_exceeded";
  return `${where} ${full ? `${OWNER_OUT_OF_SPACE} ${MOVE_NEEDS_SPACE}` : friendlyError(e.cause)}`;
}

/** What a finished move says: the old vault deleted (only once the server stored it), or kept and why. */
export function moveResultText(r: MoveResult, oldName: string, newName: string = r.name, discardedName: string | null = r.discarded?.name ?? null, inBanner = false): string {
  const kept =
    r.oldKept === "source_stays"
      ? MOVE_KEPT_STAYS
      : r.oldKept === "uncopyable"
        ? fill(MOVE_UNCOPYABLE, itemCount(r.uncopyable), oldName)
        : r.oldKept === "members_differ"
          ? fill(MOVE_KEPT_MEMBERS_DIFFER, oldName)
          : r.oldKept === "changed_meanwhile"
            ? // No change seen by the move's own read: the server refused the deletion (an item changed after that read).
              r.changed > 0 ? fill(MOVE_CHANGED_MEANWHILE, itemCount(r.changed), oldName) : fill(MOVE_CHANGED_AFTER_READ, "", oldName)
            : r.oldKept === "moved_on"
              ? fill(MOVE_CHANGED_MOVED_ON, "", oldName)
              : fill(MOVE_KEEPS_OLD, oldName);
  // "The people you added are asked to accept" only when this move added someone. [inBanner]: the note is the banner
  // above every view, where no trash icon is "above": the restore place is named as Sharing's.
  // The day only where the server served it; otherwise the line points to the list of deleted vaults.
  const noDay = r.oldDeleted?.purgeAt === null;
  const done = noDay
    ? inBanner ? (r.added > 0 ? MOVE_DONE_BANNER_NO_DAY : MOVE_DONE_ALONE_BANNER_NO_DAY) : r.added > 0 ? MOVE_DONE_NO_DAY : MOVE_DONE_ALONE_NO_DAY
    : inBanner ? (r.added > 0 ? MOVE_DONE_BANNER : MOVE_DONE_ALONE_BANNER) : r.added > 0 ? MOVE_DONE : MOVE_DONE_ALONE;
  const note = r.oldDeleted !== null ? fill(done, newName, oldName, ...(r.oldDeleted.purgeAt !== null ? [fmtDay(r.oldDeleted.purgeAt)] : [])) : `${fill(MOVE_DONE_KEPT, newName, oldName)} ${kept}`;
  return note + discardText(r.discarded, r.name, discardedName ?? r.discarded?.name ?? "", true);
}

/**
 * What became of the half-made vault of an earlier, stopped run (design §3.13 as decided on 2026-11-18), with a space in
 * front, or "" when there was none. "only copies" is said only of a vault read from the server and found so. Where it
 * was dealt with before the run copied anything and not deleted, who the move leaves out that can still open it, and the
 * copies in it, follow. [made]: this move has made its own new vault (finished, or stopped after that step).
 */
export function discardText(d: DiscardOutcome | null, runName: string, name: string, made: boolean): string {
  if (d === null) return "";
  const key =
    d.kept === true
      ? MOVE_DISCARD_KEPT
      : d.unread === true
        ? MOVE_DISCARD_UNREAD
        : d.notHeld === true
          ? MOVE_DISCARD_NOT_HELD
          : !d.deleted
            ? d.waiting === true
              ? MOVE_DISCARD_WAITING
              : MOVE_DISCARD_FAILED
            : !made
              ? MOVE_DISCARDED_BEFORE_START
              : d.name === runName
                ? MOVE_DISCARDED_SAME_NAME
                : MOVE_DISCARDED;
  let text = ` ${fill(key, name)}`;
  if (!d.deleted && d.notHeld !== true && d.holders !== undefined && d.holders.length > 0) {
    const named = d.holders.filter((h): h is string => h !== null);
    // A target found by its own meta: its items are not known to be the move's copies, and the number is what the read
    // from the server counted in it, its trash included (none where that read failed).
    const key =
      d.found !== true
        ? named.length > 0 ? MOVE_DISCARD_HOLDERS : MOVE_DISCARD_HOLDERS_UNNAMED
        : d.copies === undefined
          ? named.length > 0 ? MOVE_DISCARD_HOLDERS_FOUND_UNREAD : MOVE_DISCARD_HOLDERS_FOUND_UNREAD_UNNAMED
          : named.length > 0 ? MOVE_DISCARD_HOLDERS_FOUND : MOVE_DISCARD_HOLDERS_FOUND_UNNAMED;
    text += ` ${fill(key, named.join(", "), name, itemCount(d.copies ?? 0))}`;
  }
  return text;
}

/**
 * The first screen after an unlock (design §3.13 as decided on 2026-11-16): each move whose old vault's deletion is
 * signed and waiting for the server is named as unfinished, with a button that finishes it. The unlock's own re-posting
 * of held changes leaves that deletion alone; only finishing the move re-posts it.
 */
export function UnfinishedMoves({ store, onChanged }: { store: VaultStore; onChanged: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [said, setSaid] = useState<{ vaultId: string; text: string; ok: boolean } | null>(null);
  // By keyboard: the button pressed is disabled while the move runs and gone once it is finished, so the focus would drop
  // to the page's start. It moves to the note's OK instead, where the outcome is read; OK or Escape closes the note.
  const okRef = useRef<HTMLButtonElement>(null);
  const focusNote = useRef(false);
  useEffect(() => {
    if (said !== null && focusNote.current) okRef.current?.focus();
    focusNote.current = false;
  }, [said]);
  // Closing the note removes the control that held the focus: it goes to the page's main region (Vault's `main-content`,
  // the skip link's target), not back to the page's start.
  const closeNote = () => {
    const inside = okRef.current !== null && okRef.current.closest(".msg")?.contains(document.activeElement) === true;
    setSaid(null);
    if (inside) document.getElementById("main-content")?.focus();
  };
  const moves = store.unfinishedMoves();
  if (moves.length === 0 && said === null) return null;
  const finish = async (m: UnfinishedMove) => {
    setBusy(m.vaultId);
    setSaid(null);
    // Named as the list names it, read before the move (the old vault is gone after it).
    const oldName = storeVaultLabel(store, m.vaultId, m.name ?? MOVE_UNNAMED_OLD);
    try {
      const r = await store.finishMove(m);
      focusNote.current = true;
      setSaid({ vaultId: m.vaultId, text: moveResultText(r, oldName, storeVaultLabel(store, r.newVaultId, r.name), r.discarded && storeVaultLabel(store, r.discarded.vaultId, r.discarded.name), true), ok: true });
    } catch (e) {
      focusNote.current = true;
      setSaid({ vaultId: m.vaultId, text: moveErrorText(e, oldName), ok: false });
    } finally {
      setBusy(null);
      onChanged();
    }
  };
  return (
    <>
      {moves.map((m) =>
        m.oldFrozen === true ? (
          <div className="banner" key={m.vaultId} role="status">
            <span>{fill(MOVE_OLD_FROZEN, storeVaultLabel(store, m.vaultId, m.name ?? MOVE_UNNAMED_OLD), storeVaultLabel(store, m.newVaultId, m.newName ?? MOVE_UNNAMED_VAULT))}</span>
            <button type="button" className="link" disabled={busy !== null} onClick={() => { store.dismissFrozenMove(m.vaultId); onChanged(); }}>OK</button>
          </div>
        ) : (
          <div className="banner" key={m.vaultId} role="status">
            <span>{fill(MOVE_UNFINISHED, storeVaultLabel(store, m.vaultId, m.name ?? MOVE_UNNAMED_OLD), storeVaultLabel(store, m.newVaultId, m.newName ?? MOVE_UNNAMED_VAULT))}</span>
            <button type="button" className="link" disabled={busy !== null} onClick={() => void finish(m)}>{MOVE_FINISH}</button>
          </div>
        ),
      )}
      {said !== null && (
        <div className={`msg ${said.ok ? "info" : "err"}`} style={{ display: "flex", alignItems: "center", gap: 12 }} role={said.ok ? "status" : "alert"} onKeyDown={(e) => { if (e.key === "Escape") { e.stopPropagation(); closeNote(); } }}>
          <span style={{ flex: 1 }}>{said.text}</span>
          <button type="button" className="link" ref={okRef} onClick={closeNote}>OK</button>
        </div>
      )}
    </>
  );
}

/**
 * "Move everything to a new vault" (design §3.13): the new vault's name, who is added to it (on a frozen or failed
 * vault only the members ticked, none by default: FS-R3), why the old vault would be kept, and the progress. The
 * store runs the steps in the design's order and says where it stopped; running it again carries on from there.
 */
export function MoveEverythingPanel({ vault, store, serverNames, removing, removingName, onClose, onMoved }: { vault: VaultInfo; store: VaultStore; serverNames: ReadonlyMap<string, string>; removing: string | null; removingName: string; onClose: () => void; onMoved: (note: string) => void }) {
  const plan = store.movePlan(vault.vaultId, removing);
  const [name, setName] = useState(plan?.resume?.name ?? "");
  const [ticked, setTicked] = useState<ReadonlySet<string>>(new Set());
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  // By keyboard: the button that opened this panel is gone, so the focus comes here (the panel itself, read from its
  // heading, never its primary button), and Escape closes it as Cancel does, unless the move is running.
  const panelRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const at = document.activeElement;
    if (at === null || at === document.body) panelRef.current?.focus();
  }, []);
  if (plan === null) return null;
  // The old vault's deletion is signed and waiting: what is left is to finish the move, and the button says so.
  const deleteWaiting = store.moveDeleteWaiting(vault.vaultId);
  const who = (m: MoveMember): string => memberName({ userId: m.userId, role: m.role, label: m.label, self: false }, serverNames);
  const adding = plan.sourceStays ? plan.members.filter((m) => ticked.has(m.userId) && m.canBeAdded) : plan.members.filter((m) => m.canBeAdded);
  const someoneLeftOut = !plan.sourceStays && plan.members.some((m) => !m.canBeAdded);

  const go = async () => {
    setBusy(true);
    setErr("");
    // Named as the list names it, read before the move (the old vault may be gone after it).
    const oldName = storeVaultLabel(store, vault.vaultId, vault.name);
    try {
      const r = await store.moveEverything(vault.vaultId, { name, add: adding.map((m) => m.userId), removing }, (done, total) => setProgress({ done, total }));
      onMoved(moveResultText(r, oldName, storeVaultLabel(store, r.newVaultId, r.name), r.discarded && storeVaultLabel(store, r.discarded.vaultId, r.discarded.name)));
    } catch (e) {
      setErr(moveErrorText(e, oldName));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  return (
    <div
      className="field"
      style={{ marginTop: 18, borderTop: "1px solid var(--edge)", paddingTop: 16 }}
      ref={panelRef}
      tabIndex={-1}
      role="group"
      aria-label={MOVE_EVERYTHING}
      onKeyDown={(e) => {
        if (e.key === "Escape" && !busy) {
          e.stopPropagation();
          onClose();
        }
      }}
    >
      <label>{MOVE_EVERYTHING}</label>
      {plan.sourceStays && <Msg kind="err">{CHECK_WHAT_YOU_COPY}</Msg>}
      <p className="muted" style={{ marginTop: 0 }}>{fill(plan.sourceStays ? MOVE_INTRO_STAYS : MOVE_INTRO, vault.name)}</p>
      <p className="muted">{fill(plan.sourceStays ? MOVE_NOT_MOVED_STAYS : MOVE_NOT_MOVED, vault.name)}</p>
      {/* On a frozen or failed vault nothing is signed, so no one is "removed first". */}
      {/* The entry numbers the vault {0} and the person {1}, in every line of it. */}
      {removing !== null && !plan.sourceStays && <p className="muted">{fill(MOVE_REMOVING, vault.name, removingName)}</p>}
      {/* While the old vault's deletion waits, everything is copied and everyone added: "stopped after copying N items,
          moving again carries on" would say less than happened, beside the sentence that says so. */}
      {plan.resume !== null && !deleteWaiting && <div className="msg info" style={{ display: "block" }}>{fill(MOVE_RESUME, plan.resume.name, itemCount(plan.resume.copied))}</div>}
      <label className="prompt" htmlFor={`move-name-${vault.vaultId}`}>{MOVE_NAME}</label>
      <input id={`move-name-${vault.vaultId}`} aria-label={MOVE_NAME} value={name} onChange={(e) => setName(e.target.value)} disabled={busy || plan.resume !== null} />
      {plan.members.length === 0 && <p className="muted">{MOVE_NOBODY}</p>}
      {plan.members.length > 0 && (
        <div className="member-lines">
          {plan.members.map((m) =>
            plan.sourceStays ? (
              <label className="member-line" key={m.userId}>
                <input
                  type="checkbox"
                  checked={ticked.has(m.userId)}
                  disabled={busy || !m.canBeAdded}
                  onChange={(e) => setTicked((t) => { const n = new Set(t); if (e.target.checked) n.add(m.userId); else n.delete(m.userId); return n; })}
                />
                <span className="member-line-name">{who(m)}</span>
                <span className="tag">{m.role}</span>
                {!m.canBeAdded && <span className="muted member-line-note">{MOVE_CANNOT_ADD}</span>}
              </label>
            ) : (
              <div className="member-line" key={m.userId}>
                <span className="member-line-name">{who(m)}</span>
                <span className="tag">{m.role}</span>
                {!m.canBeAdded && <span className="muted member-line-note">{MOVE_CANNOT_ADD}</span>}
              </div>
            ),
          )}
        </div>
      )}
      {/* "won't be deleted, delete it yourself" is untrue once the old vault's deletion is signed and waiting: it cannot
          be taken back, and nothing else can be changed on that vault until the move is finished (the panel's own
          waiting line says so). */}
      {someoneLeftOut && !deleteWaiting && <p className="muted">{fill(MOVE_KEEPS_OLD, vault.name)}</p>}
      {someoneLeftOut && deleteWaiting && <p className="muted">{fill(MOVE_KEEPS_OLD_WAITING, vault.name)}</p>}
      {!plan.sourceStays && plan.uncopyable > 0 && <p className="muted">{fill(MOVE_UNCOPYABLE, itemCount(plan.uncopyable), vault.name)}</p>}
      {progress && <div className="msg info" style={{ display: "block" }} role="status">{fill(MOVE_PROGRESS, String(progress.done), String(progress.total))}</div>}
      {err && <Msg kind="err">{err}</Msg>}
      <div className="actions" style={{ marginTop: 10 }}>
        <button type="button" className="ghost" disabled={busy} onClick={onClose}>Cancel</button>
        <button type="button" className="primary" disabled={busy || name.trim() === ""} onClick={go}>{deleteWaiting ? MOVE_FINISH : MOVE_EVERYTHING}</button>
      </div>
    </div>
  );
}

/**
 * The server's display names, fetched only to show beside a member the log names but this browser has no current
 * contact for ("unverified member (as the server names them)", design §3.9). Never decides who is a member.
 */
function useServerNames(client: ApiClient, vaultId: string): ReadonlyMap<string, string> {
  const [names, setNames] = useState<ReadonlyMap<string, string>>(new Map());
  useEffect(() => {
    let live = true;
    client
      .vaultMembers(vaultId)
      .then((ms) => { if (live) setNames(new Map(ms.map((m) => [m.userId, m.displayName]))); })
      .catch(() => {});
    return () => { live = false; };
  }, [client, vaultId]);
  return names;
}

/** A member's name: "You", the current contact's label, or the server's name marked as unverified (§3.9, T-R5). */
export function memberName(r: RosterRow, serverNames: ReadonlyMap<string, string>): string {
  if (r.self) return "You";
  if (r.label !== null) return r.label;
  const s = serverNames.get(r.userId);
  return s ? `${s} — ${ROSTER_UNVERIFIED}` : ROSTER_UNVERIFIED;
}

/**
 * The line after a waiting change was withdrawn: one the server said it did not store will not be made; one whose answer
 * was lost will not be sent again, may already be made, and the vault is read to tell.
 */
export function withdrawnText(known: HeldKnown): string {
  return known === "not_stored" ? RESEND_WITHDRAWN : RESEND_WITHDRAWN_UNKNOWN;
}

/**
 * Runs a log action of the member panel; where it ends "cannot tell" or "slow down" (the change is held), [onHeld]
 * redraws the panel first, so that its waiting line and Withdraw show at once. The error goes on to the caller.
 */
export async function runNotingHeld<T>(act: () => Promise<T>, onHeld: () => void): Promise<T> {
  try {
    return await act();
  } catch (e) {
    if (e instanceof ChangeNotStoredError) onHeld();
    throw e;
  }
}

/** The change of this vault that waits to be sent again, and its withdrawal where it may be withdrawn. */
function WaitingChange({ vaultId, store, onChanged }: { vaultId: string; store: VaultStore; onChanged: () => void }) {
  // What was known of the change when it was withdrawn: one whose answer was lost may already be made.
  const [withdrawn, setWithdrawn] = useState<HeldKnown | null>(null);
  const change = store.heldChangeFor(vaultId);
  const line = heldWaitingText(change);
  if (withdrawn !== null && change === null) return <p className="muted">{withdrawnText(withdrawn)}</p>;
  if (line === null) return null;
  return (
    <p className="muted">
      {line}{" "}
      {change?.withdrawable === true && (
        <button
          type="button"
          className="ghost"
          onClick={() => {
            // The line follows the state the change had when it was withdrawn, not the one drawn here.
            const known = store.withdrawHeldChangeAs(vaultId);
            if (known !== null) setWithdrawn(known);
            onChanged();
          }}
        >
          {RESEND_WITHDRAW}
        </button>
      )}
    </p>
  );
}

/** The members' status line of a shared vault whose log does not verify now: a frozen one says so, for good. */
export function rosterNoteText(roster: Roster): string | null {
  if (roster.frozen) return ROSTER_FROZEN;
  return roster.stale ? ROSTER_STALE : null;
}

function RosterNotes({ roster }: { roster: Roster | null }) {
  if (roster === null) return <p className="muted">{ROSTER_NONE}</p>;
  const note = rosterNoteText(roster);
  return (
    <>
      {note !== null && <Msg kind="err">{note}</Msg>}
      {roster.mayBeIncomplete && <p className="muted">{ROSTER_MAY_BE_INCOMPLETE}</p>}
    </>
  );
}

// ---- read-only roster (member-role vaults, F20) ----

/**
 * A writer/reader's read-only view of who else is in a shared vault they belong to, from the verified log (§3.9):
 * no role selects, no remove, no transfer, no add, no delete. Management stays owner-only in MemberPanel above.
 */
function MemberRosterPanel({ vault, store, client }: { vault: VaultInfo; store: VaultStore; client: ApiClient }) {
  const serverNames = useServerNames(client, vault.vaultId);
  const roster = store.memberRoster(vault.vaultId);
  return (
    <div className="sheet">
      <h2>“{vault.name}” members</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        You're a {vault.role ?? "member"} of this shared vault. Only its owner can add, remove, or
        change who has access.
      </p>
      <RosterNotes roster={roster} />
      {roster && (
        <div className="attach-list">
          {roster.rows.map((r) => (
            <div className="attach-row" key={r.userId}>
              <span className="attach-name">{memberName(r, serverNames)}</span>
              <span className="tag">{r.role}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ---- undecryptable-grant warning (F20) ----

/**
 * A PERSISTENT, non-dismissable warning (distinct from the dismissable lifecycle notices): this
 * device holds a grant to a shared vault it cannot open — the vault key was sealed to a different
 * device/identity, or this app predates the grant's format. The store retains only the id (the
 * name is unreadable by definition) and clears the entry automatically once a later pull opens the
 * grant or the grant is revoked, so this row appears and disappears on its own with no user action.
 */
function UndecryptableGrantsWarning({ store }: { store: VaultStore }) {
  const vaultIds = store.undecryptableGrantVaults(); // derived each render — a background sync clears it
  if (vaultIds.length === 0) return null;
  const one = vaultIds.length === 1;
  return (
    <div className="sheet">
      <h2>Can't open a shared vault on this device</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        You were added to {one ? "a shared vault" : `${vaultIds.length} shared vaults`}, but this
        device can't unlock {one ? "it" : "them"} yet — the key may have been sealed to another of
        your devices, or this app is out of date. Open andvari on the device you enrolled with, or
        update this app; the warning clears on its own once it opens. Your other vaults are
        unaffected.
      </p>
    </div>
  );
}

// ---- inline rename (spec 03 §11 / F15) ----

/**
 * What a rename that threw says, from what is known: nothing was sent (the traffic gate stopped it before it left), the
 * server refused it (a 4xx, its own line), or it cannot be told (no answer, an answer cut off, a 5xx, a redirect, an
 * answer that is not the server's, an answer the gate dropped): the new name may be stored.
 */
export function renameErrorText(e: unknown): string {
  const limit = answerLimitText(e);
  if (limit !== null) return limit;
  if (e instanceof TrafficStoppedError && !e.sent) return LOG_NOT_SENT;
  if (e instanceof MoveWaitingError || e instanceof LogActionError) return friendlyError(e);
  if (e instanceof ApiError && !(e instanceof TrafficStoppedError) && e.status >= 400 && e.status < 500) return friendlyError(e);
  if (e instanceof ApiError || e instanceof TypeError || (typeof e === "object" && e !== null && ["AbortError", "TimeoutError"].includes(String((e as { name?: unknown }).name)))) return RENAME_UNKNOWN;
  return friendlyError(e);
}

function RenameHeader({ vault, store, onRenamed, locked = false }: { vault: VaultInfo; store: VaultStore; onRenamed: () => void; locked?: boolean }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(vault.name);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const save = async () => {
    const next = name.trim();
    if (!next || next === vault.name) { setEditing(false); return; }
    setBusy(true);
    setErr("");
    try {
      await store.renameVault(vault.vaultId, next);
      setEditing(false);
      onRenamed();
    } catch (e) {
      setErr(renameErrorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (!editing || locked) {
    return (
      <h2 style={{ display: "flex", alignItems: "center", gap: 10 }}>
        “{vault.name}” members
        {!locked && <button type="button" className="link" onClick={() => { setName(vault.name); setEditing(true); }}>Rename</button>}
      </h2>
    );
  }
  return (
    <div className="field">
      <label>Rename vault</label>
      {err && <Msg kind="err">{err}</Msg>}
      <div className="secret-row">
        <input autoFocus aria-label="Rename vault" value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
        <button type="button" className="primary" disabled={busy || !name.trim()} onClick={save}>{busy ? "Saving…" : "Save"}</button>
        <button type="button" className="ghost" disabled={busy} onClick={() => { setEditing(false); setErr(""); }}>Cancel</button>
      </div>
      <span className="muted">Encrypted — readable only with this vault's key. Syncs to every member.</span>
    </div>
  );
}

// ---- transfer offer (owner side, spec 03 §11) ----

function TransferOfferControl({ vault, store, targets, onOffered, onHeld }: { vault: VaultInfo; store: VaultStore; targets: { userId: string; name: string }[]; onOffered: () => Promise<void>; onHeld: () => void }) {
  const [target, setTarget] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  if (targets.length === 0) return null;
  const targetMember = targets.find((m) => m.userId === target);

  const offer = async () => {
    setBusy(true);
    setErr("");
    try {
      await runNotingHeld(() => store.offerTransfer(vault.vaultId, target), onHeld);
      setConfirming(false);
      setTarget("");
      await onOffered();
    } catch (e) {
      setErr(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="field" style={{ marginTop: 14 }}>
      <label>Make someone else the owner</label>
      {err && <Msg kind="err">{err}</Msg>}
      {confirming && targetMember ? (
        <>
          {/* The owner's approved entry 26 (OWNERSHIP_OFFER), word for word. */}
          <p style={{ marginTop: 0 }}><strong>{fill(OWNERSHIP_OFFER_TITLE, targetMember.name, vault.name)}</strong></p>
          <p className="muted">{OWNERSHIP_OFFER_BODY}</p>
          <div className="actions">
            <button type="button" className="primary" disabled={busy} onClick={offer}>{busy ? "Sending…" : fill(OWNERSHIP_OFFER_ASK, targetMember.name)}</button>
            <button type="button" className="ghost" disabled={busy} onClick={() => setConfirming(false)}>Cancel</button>
          </div>
        </>
      ) : (
        <div className="secret-row" style={{ flexWrap: "wrap" }}>
          <select value={target} aria-label="Make someone else the owner" onChange={(e) => setTarget(e.target.value)} style={{ width: "auto" }}>
            <option value="">choose a member…</option>
            {targets.map((m) => (
              <option key={m.userId} value={m.userId}>{m.name}</option>
            ))}
          </select>
          <button type="button" className="ghost" disabled={!target} onClick={() => setConfirming(true)}>Transfer ownership…</button>
        </div>
      )}
    </div>
  );
}

// ---- delete vault (owner side, spec 03 §11) ----

// A3: {copying, copiedNote} are LIFTED to Sharing-level state keyed by vaultId (threaded via
// MemberPanel) — this panel unmounts when the settings layer closes, and the rescue-copy
// progress / completion note must survive a close/reopen mid-copy instead of being orphaned.
// N2 §7: the post-delete note is lifted the same way (onDeletedNote) — deleteSharedVault drops
// the vault before returning, so the delete's own commit unmounts this panel; a local toast
// here could never paint. Sharing's list branch renders it.
function DeleteVaultControl({ vault, store, onDeleted, onDeletedNote, onBackup, copying, setCopying, copiedNote, setCopiedNote, onHeld }: { vault: VaultInfo; store: VaultStore; onDeleted: () => void; onDeletedNote: (note: { vaultId: string; name: string; purgeAt: number | null; alone: boolean }) => void; onBackup: () => void; copying: { done: number; total: number } | null; setCopying: (c: { done: number; total: number } | null) => void; copiedNote: string; setCopiedNote: (note: string) => void; onHeld: () => void }) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  // A3b (review HIGH): `busy` is LOCAL and dies when the settings layer unmounts this panel —
  // but the rescue copy keeps running via the lifted setters. A reopened panel must not offer
  // a second copy, and above all must not let Delete fire mid-rescue-copy (the exact ordering
  // this panel protects). The lifted `copying` is the surviving truth — gate on both.
  const inFlight = busy || copying !== null;

  const items = store.list().filter((it) => it.vaultId === vault.vaultId);
  const attachmentCount = items.reduce((n, it) => n + (it.doc.attachments?.length ?? 0), 0);
  const eraseDay = fmtDay(Date.now() + 7 * 86_400_000);

  const copyFirst = async () => {
    setBusy(true);
    setErr("");
    setCopiedNote("");
    try {
      const { copied } = await store.copyAllToPersonal(vault.vaultId, (done, total) => setCopying({ done, total }));
      setCopiedNote(`Copied ${copied} ${copied === 1 ? "item" : "items"} to your Personal vault. You can still change your mind — deleting won't remove those copies.`);
    } catch (e) {
      setErr(friendlyError(e));
    } finally {
      setBusy(false);
      setCopying(null);
    }
  };

  const del = async () => {
    setBusy(true);
    setErr("");
    try {
      // Whether anyone else was in it, from the verified log before the delete: the note must be true for a vault that
      // had no other members ("Members lost access" would not be).
      const alone = (store.memberRoster(vault.vaultId)?.rows ?? []).every((r) => r.self);
      const { purgeAt } = await runNotingHeld(() => store.deleteSharedVault(vault.vaultId), onHeld);
      onDeletedNote({ vaultId: vault.vaultId, name: vault.name, purgeAt, alone });
      setOpen(false);
      setTyped("");
      onDeleted();
    } catch (e) {
      setErr(friendlyError(e));
      setBusy(false);
    }
  };

  return (
    <>
      {/* BL-1 (audit F12): the rescue-copy confirmation lands after an awaited copyAllToPersonal
          — the `.msg info` boxes below mount already-populated, which a polite region does not
          announce (Msg.tsx), and this is "the one place the user can learn the rescue copy
          landed" before a shared vault is deleted. Mounted OUTSIDE the open/collapsed branch so
          it is one persistent node across the toggle, per that contract. */}
      <Announcer text={copiedNote} />
      {!open ? (
        <div className="actions" style={{ marginTop: 18 }}>
          {/* Review LOW: a copy that completed while the layer was closed must be visible from
              the collapsed state — the opener below clears the note, so this is the one place
              the user can learn the rescue copy landed. */}
          {copiedNote && <div className="msg info" style={{ display: "block", flexBasis: "100%" }}>{copiedNote}</div>}
          {copying && <div className="msg info" style={{ display: "block", flexBasis: "100%" }}>Copying items to your Personal vault… {copying.done}/{copying.total}</div>}
          <div className="spacer" />
          <button type="button" className="ghost" style={{ color: "var(--danger)" }} onClick={() => { setOpen(true); setErr(""); setCopiedNote(""); }}>
            Delete vault…
          </button>
        </div>
      ) : (
        // a11y-webext--3 (adjacent): --line is declared nowhere, so this divider always painted
        // the #333 fallback — a near-black hairline that vanished on the light theme's #fbf8f1
        // panel. --edge is the palette's hairline-divider token, themed in both schemes.
        <div className="field" style={{ marginTop: 18, borderTop: "1px solid var(--edge)", paddingTop: 16 }}>
          <label style={{ color: "var(--danger)" }}>Delete “{vault.name}”?</label>
          <p className="muted" style={{ marginTop: 0 }}>
            This removes the vault from everyone's andvari now. The server keeps its {items.length}{" "}
            {items.length === 1 ? "item" : "items"}{attachmentCount > 0 ? ` and ${attachmentCount} ${attachmentCount === 1 ? "attachment" : "attachments"}` : ""} for 7 days
            (until {eraseDay}) in case you change your mind — then erases them for good. Want to keep some of these?
          </p>
          <div className="actions" style={{ marginBottom: 8 }}>
            <button type="button" className="ghost" disabled={inFlight} onClick={copyFirst}>
              {copying ? `Copying… ${copying.done}/${copying.total}` : "Copy items to my Personal vault first…"}
            </button>
            <button type="button" className="ghost" disabled={inFlight} onClick={onBackup}>Back up first…</button>
          </div>
          {copiedNote && <div className="msg info" style={{ display: "block" }}>{copiedNote}</div>}

          <div className="msg info" style={{ display: "block" }}>
            <strong>Deleting can't take back what people already saw:</strong> anyone who had access may have
            kept copies of items or the vault key, and encrypted server backups age out on their own schedule
            (about a month). If a password really matters, change it at the website too.
          </div>

          {err && <Msg kind="err">{err}</Msg>}
          <label className="prompt" style={{ marginTop: 10 }}>Type the vault's name to delete it:</label>
          <input aria-label="Type the vault's name to delete it" value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={vault.name} disabled={inFlight} />
          <div className="actions" style={{ marginTop: 10 }}>
            <button type="button" className="ghost" disabled={busy} onClick={() => { setOpen(false); setTyped(""); setErr(""); }}>Cancel</button>
            <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={inFlight || typed !== vault.name} onClick={del}>
              {busy ? "Deleting…" : "Delete vault"}
            </button>
          </div>
        </div>
      )}
    </>
  );
}

// ---- transfer accept (target side consent screen, spec 03 §11) ----

/** Renders ONLY for an offer to this account in the verified log (design §3.5). The owner is named by the current
 *  contact's label for the log's owner key, and by nothing the server says. */
function IncomingTransferCard({ offer, store, client, onChanged }: { offer: IncomingTransfer; store: VaultStore; client: ApiClient; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const serverNames = useServerNames(client, offer.vaultId);
  const ownerRow = store.memberRoster(offer.vaultId)?.rows.find((r) => r.role === "owner");
  const ownerName = ownerRow ? memberName(ownerRow, serverNames) : OFFER_IN_OWNER_UNKNOWN;

  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr("");
    try {
      await fn();
      onChanged();
    } catch (e) {
      setErr(friendlyError(e));
      setBusy(false);
    }
  };

  return (
    <div className="sheet">
      <h2>{fill(OFFER_IN_TITLE, offer.vaultName)}</h2>
      <p style={{ marginTop: 0 }}>{fill(OFFER_IN_BODY, ownerName, offer.vaultName)} {fill(OFFER_IN_UNTIL, fmtDay(offer.expiresAt))}</p>
      <p className="muted">{fill(OFFER_SIGNED, ownerName)}</p>
      {err && <Msg kind="err">{err}</Msg>}
      <div className="actions">
        <button type="button" className="primary" disabled={busy} onClick={() => act(() => store.acceptTransfer(offer.vaultId, offer.offerId))}>{busy ? OFFER_IN_ACCEPTING : OFFER_IN_ACCEPT}</button>
        <button type="button" className="ghost" disabled={busy} onClick={() => act(() => store.cancelTransfer(offer.vaultId))}>{OFFER_IN_DECLINE}</button>
      </div>
    </div>
  );
}

// ---- recently deleted (restore, spec 03 §11) ----

/** IA P8: the holding area — vaults this account lost access to, a sealed local copy kept for
 *  a while (recovery is automatic on restore/re-add); mirrors Android's "Recently removed".
 *  Derived from store.heldVaults() each render. Its one action is the copy-out of §3.8. */
export function RecentlyRemoved({ store, hide }: { store: VaultStore; hide: string[] }) {
  // A vault the deleter can still RESTORE (RecentlyDeleted, above) hides its sealed-copy twin
  // here — one story, one row (owner dev-note 2026-08-19).
  const [, setRemovedTick] = useState(0);
  const held = store.heldVaults().filter((h) => !hide.includes(h.vaultId));
  if (held.length === 0) return null;
  // Design §3.8: every line names the day the copy leaves this device (30 days from the verification), never the
  // vault's purge time. While the copy is closed for an invitation its person can answer, the line says so, with the
  // vault's name as the invitation names it, filled as plain text (decided on 22 and 23 November 2026).
  const line = (h: { reason: string; verified: boolean; byMe: boolean; expungeAt: number; addedAgain?: boolean; invitationName?: string }): string => {
    if (h.addedAgain === true) return fill(HELD_ADDED_AGAIN, h.invitationName ?? "", fmtDay(h.expungeAt));
    if (h.reason === "deleted" && h.verified && h.byMe) return fill(HELD_DELETED_BY_ME, fmtDay(h.expungeAt));
    if (h.reason === "deleted" && h.verified) return `deleted by its owner · kept sealed until ${fmtDay(h.expungeAt)}`;
    if (h.reason === "left") return `you left · kept until ${fmtDay(h.expungeAt)}`;
    if (h.verified) return `access removed · kept until ${fmtDay(h.expungeAt)}`;
    return `unverified removal · kept until ${fmtDay(h.expungeAt)}`;
  };
  return (
    <div className="sheet">
      <h2>Recently removed</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Vaults this account lost access to. A sealed copy is kept on this device for a while in
        case of a mistake — if the vault is restored or you're re-added, everything (including
        unsynced edits) comes back on its own.
      </p>
      {held.map((h) => (
        <div key={h.vaultId} className="field" style={{ marginBottom: 8 }}>
          <div>“{h.name}”</div>
          <div className="muted" style={{ color: h.verified || h.reason === "left" ? undefined : "var(--danger)" }}>{line(h)}</div>
          <HeldCopyOut held={h} store={store} />
          <HeldRemove held={h} store={store} onRemoved={() => setRemovedTick((t) => t + 1)} />
        </div>
      ))}
    </div>
  );
}

/**
 * Items set aside (beside "Recently removed"): items of the personal vault, or of a shared vault still listed, that a
 * full list left out without saying they were deleted. Derived from store.itemsSetAside() each render; the same two
 * actions as a held copy: copy into the personal vault, and remove this browser's copy.
 */
export function ItemsSetAside({ store }: { store: VaultStore }) {
  const [, setRemovedTick] = useState(0);
  const sets = store.itemsSetAside();
  if (sets.length === 0) return null;
  return (
    <div className="sheet">
      <h2>{ITEMS_SET_ASIDE_TITLE}</h2>
      <p className="muted" style={{ marginTop: 0 }}>{ITEMS_SET_ASIDE_INTRO}</p>
      {sets.map((s) => {
        const name = s.personal ? ITEMS_SET_ASIDE_PERSONAL_NAME : s.name || "(vault)";
        return (
          <div key={s.vaultId} className="field" style={{ marginBottom: 8 }}>
            <div>“{name}”</div>
            <div className="muted">{fill(ITEMS_SET_ASIDE_LINE, itemCount(s.itemCount), fmtDay(s.expungeAt))}</div>
            <HeldCopyOut held={s} store={store} setAside />
            <HeldRemove held={{ vaultId: s.vaultId, name }} store={store} setAside onRemoved={() => setRemovedTick((t) => t + 1)} />
          </div>
        );
      })}
    </div>
  );
}

/** "Remove from this device" (spec 02 §10.6) on a held copy: confirmed once, then gone at once, whatever its date. */
function HeldRemove({ held, store, onRemoved, setAside = false }: { held: { vaultId: string; name: string }; store: VaultStore; onRemoved: () => void; setAside?: boolean }) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const remove = async () => {
    setBusy(true);
    setErr("");
    try {
      if (setAside) await store.removeSetAside(held.vaultId);
      else await store.removeHeldCopy(held.vaultId);
      onRemoved();
    } catch (e) {
      setErr(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };
  if (!confirming) {
    return (
      <div className="actions">
        <button type="button" className="ghost" onClick={() => setConfirming(true)}>{REMOVE_FROM_THIS_DEVICE}</button>
      </div>
    );
  }
  return (
    <>
      <p className="muted" style={{ margin: "6px 0" }}>{fill(setAside ? ITEMS_SET_ASIDE_REMOVE_CONFIRM : HELD_REMOVE_CONFIRM, held.name)}</p>
      {err && <Msg kind="err">{err}</Msg>}
      <div className="actions">
        <button type="button" className="ghost" disabled={busy} onClick={() => { setConfirming(false); setErr(""); }}>Cancel</button>
        <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={remove}>{REMOVE_FROM_THIS_DEVICE}</button>
      </div>
    </>
  );
}

/**
 * §3.8, §3.12: items can still be copied out of the holding area, into the personal vault. The key is this account's
 * own wrap kept with the held copy; attachments come along only where the server still serves them.
 */
/**
 * Why copying a held vault's items into the personal vault stopped. Out of space is the PERSON's account (the copy
 * lands in their personal vault), never "this vault's owner", which beside a held vault may be someone else.
 */
export function heldCopyErrorText(e: unknown): string {
  if (e instanceof HeldKeyGoneError) return HELD_NO_KEY;
  if (e instanceof ApiError && e.code === "quota_exceeded") return HELD_COPY_OUT_OF_SPACE;
  return friendlyError(e);
}

function HeldCopyOut({ held, store, setAside = false }: { held: { vaultId: string; itemCount: number; canCopyOut: boolean; addedAgain?: boolean }; store: VaultStore; setAside?: boolean }) {
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [note, setNote] = useState("");
  const [err, setErr] = useState("");
  if (held.itemCount === 0) return null;
  // Closed for an invitation: the row's line says why, and nothing is offered here (the key is not gone).
  if (held.addedAgain === true) return null;
  if (!held.canCopyOut) return <div className="muted">{HELD_NO_KEY}</div>;
  const copy = async () => {
    setBusy(true);
    setErr("");
    setNote("");
    try {
      const onProgress = (done: number, total: number) => setProgress({ done, total });
      const r = setAside ? await store.copySetAsideToPersonal(held.vaultId, onProgress) : await store.copyHeldToPersonal(held.vaultId, onProgress);
      setNote([fill(HELD_COPIED, itemCount(r.copied)), r.attachmentsLeftOut > 0 ? fill(HELD_COPIED_NO_FILES, `${r.attachmentsLeftOut} ${r.attachmentsLeftOut === 1 ? "attachment" : "attachments"}`) : "", r.unreadable > 0 ? fill(HELD_COPIED_UNREADABLE, itemCount(r.unreadable)) : ""].filter((x) => x !== "").join(" "));
    } catch (e) {
      setErr(heldCopyErrorText(e));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };
  return (
    <>
      <Announcer text={note} />
      <p className="muted" style={{ margin: "6px 0" }}>{CHECK_WHAT_YOU_COPY} {HELD_COPY_ATTACHMENTS}</p>
      {note && <div className="msg info" style={{ display: "block" }}>{note}</div>}
      {err && <Msg kind="err">{err}</Msg>}
      {note === "" && (
        <div className="actions">
          <button type="button" className="ghost" disabled={busy} onClick={copy}>
            {progress ? fill(MOVE_PROGRESS, String(progress.done), String(progress.total)) : setAside ? ITEMS_SET_ASIDE_COPY : HELD_COPY}
          </button>
        </div>
      )}
    </>
  );
}

function RecentlyDeleted({ store, refreshKey, onChanged, onLoaded }: { store: VaultStore; refreshKey: number; onChanged: () => void; onLoaded: (vaultIds: string[]) => void }) {
  const [deleted, setDeleted] = useState<DeletedVaultInfo[] | null>(null);
  const [err, setErr] = useState("");
  const [restoring, setRestoring] = useState<string | null>(null); // vaultId pending confirm
  const [busy, setBusy] = useState(false);

  const load = () =>
    store
      .listDeleted()
      .then((d) => {
        setDeleted(d);
        onLoaded(d.map((x) => x.vaultId)); // RecentlyRemoved hides these ids' sealed-copy twins
      })
      .catch((e) => setErr(friendlyError(e)));

  useEffect(() => {
    load();
    // Re-keyed on the parent's action tick — a vault deleted while Sharing is open must
    // appear here (the post-delete note points at this section).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [store, refreshKey]);

  const restore = async (d: DeletedVaultInfo) => {
    setBusy(true);
    setErr("");
    try {
      await store.restoreSharedVault(d.vaultId, d.deleteId);
      setRestoring(null);
      await load();
      onChanged();
    } catch (e) {
      setErr(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  if (!deleted || deleted.length === 0) return null;

  return (
    <div className="sheet">
      <h2>Recently deleted vaults</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Deleted vaults you can still restore. Restoring brings a vault back for every member with
        everything that was in it.
      </p>
      {err && <Msg kind="err">{err}</Msg>}
      <div className="attach-list">
        {deleted.map((d) => (
          <div className="attach-row" key={d.vaultId}>
            <span className="attach-name two-line">
              <span className="attach-title">“{d.name}”</span>
              <span className="muted attach-sub">deleted {fmtDay(d.deletedAt)} · erased for good {fmtDay(d.purgeAt)}</span>
            </span>
            {restoring === d.vaultId ? (
              <>
                <span className="muted" style={{ flex: 2, minWidth: 0 }}>
                  It comes back for every member. Devices on the latest app also recover edits members
                  hadn't synced; older devices may have discarded theirs.
                </span>
                <button type="button" className="ghost" disabled={busy} onClick={() => restore(d)}>{busy ? "Restoring…" : "Restore vault"}</button>
                <button type="button" className="ghost" disabled={busy} onClick={() => setRestoring(null)}>Cancel</button>
              </>
            ) : (
              <button type="button" className="ghost" onClick={() => setRestoring(d.vaultId)}>Restore</button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

