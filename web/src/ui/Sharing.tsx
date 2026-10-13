import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { UserLookupResponse, VaultMemberSummary } from "../api/types";
import type { Account } from "../vault/account";
import { type DeletedVaultInfo, type IncomingTransfer, type LegacyGrantRow, MemberNotVerifiedError, OwnershipNotConfirmedError, type OwnershipClaim, OwnershipTransferAckRequiredError, ReauthFailedError, type VaultInfo, type VaultStore } from "../vault/store";
import { VaultKeyNotVerifiedError } from "../vault/account";
import { VerifyMemberPanel } from "./Household";
import { LegacyReviewCard, PendingInvitationsCard } from "./SignedGrantCards";
import { UNREACHABLE } from "./errors";
import { Field } from "./Field";
import { fmtDay } from "./format";
import { BackLink } from "./BackLink";
import { Busy } from "./Busy";
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
}

/** Sharing view (spec 03 §10/§11 + DN-1): vaults, members, and the full lifecycle — delete,
 *  restore, leave, transfer, rename. Each SHARED vault row carries a Settings button opening
 *  that vault's settings layer (the F76 revealed-layer idiom) in place of the list: owners get
 *  the member panel, members get the read-only roster + Leave (re-homed off the row). Incoming
 *  ownership offers and the undecryptable-grants warning stay ABOVE the branch (A7), so they
 *  surface even with settings open; the Vaults sheet, NewVaultForm, and Recently-deleted are
 *  list-branch-only. */
export function Sharing({ account, store, client, onSynced, onBackup, settingsVaultId, onOpenSettings, onCloseSettings }: Props) {
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
  const [deletedNote, setDeletedNote] = useState<{ vaultId: string; name: string; purgeAt: number } | null>(null);
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
      <Announcer text={deletedNote ? `“${deletedNote.name}” is deleted. Members lost access immediately.` : ""} />
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

      {incoming.map((t) => (
        <IncomingTransferCard key={t.vaultId} offer={t} account={account} store={store} client={client} onChanged={refresh} />
      ))}

      {/* Root cause A §1.6 / §8.2 (A6): invitations from people not yet verified, and vaults an older grant
          format delivered (read-only until reviewed). Above the branch, like the warning below. */}
      <PendingInvitationsCard account={account} store={store} client={client} onChanged={refresh} />
      <LegacyReviewCard store={store} onChanged={refresh} />

      <UndecryptableGrantsWarning store={store} />

      {settingsVault && settingsContent !== null ? (
        <>
          {/* DN-1 header: the layer's in-app back affordance; hardware/gesture Back closes it
              too, via Vault's closeTop (A1). The doubled vault name (this header + the panel's
              own H2) is the one accepted cosmetic drift (A10). */}
          <div className="sheet">
            <BackLink label="Back to vaults" onClick={onCloseSettings} />
            <h2 style={{ marginTop: 12, marginBottom: 0 }}>{settingsVault.name}</h2>
          </div>
          {settingsContent === "owner" ? (
            <MemberPanel
              key={settingsVault.vaultId}
              vault={settingsVault}
              account={account}
              store={store}
              client={client}
              onChanged={refresh}
              onBackup={onBackup}
              copying={copyingByVault[settingsVault.vaultId] ?? null}
              setCopying={(c) => setCopyingByVault((m) => ({ ...m, [settingsVault.vaultId]: c }))}
              copiedNote={copiedNoteByVault[settingsVault.vaultId] ?? ""}
              setCopiedNote={(note) => setCopiedNoteByVault((m) => ({ ...m, [settingsVault.vaultId]: note }))}
              onDeletedNote={setDeletedNote}
            />
          ) : (
            <>
              {/* F20: non-owners see WHO ELSE is in a shared vault they belong to (read-only). */}
              <MemberRosterPanel key={settingsVault.vaultId} vault={settingsVault} account={account} store={store} client={client} />
              {/* DN-1: Leave, re-homed off the vault row into the member vault's settings. */}
              <div className="sheet">
                <LeaveControl vault={settingsVault} store={store} onChanged={refresh} />
              </div>
            </>
          )}
        </>
      ) : (
        <>
          {/* N2 §7: the post-delete note, rendered by the branch that survives the delete
              commit (the layer above unmounts in it). Same idiom as the panel toast it
              replaces; "the trash icon above" = the DN-2 disclosure in the header. */}
          {deletedNote && (
            <div className="msg info" style={{ marginTop: 16 }}>
              “{deletedNote.name}” is deleted. Members lost access immediately. You can restore it
              until {fmtDay(deletedNote.purgeAt)} (the trash icon above).{" "}
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
                    <div className="name">{v.name}</div>
                    <div className="sub">{v.type === "personal" ? "personal vault" : "shared vault"}</div>
                  </span>
                  <span className="tag">{v.role ?? "member"}</span>
                  {/* A6 §8.2: an older-format grant nobody vouched for yet — read-only until reviewed above. */}
                  {account.isLegacyReadOnly(v.vaultId) && <span className="tag">not yet verified</span>}
                  {/* DN-1: shared vaults (owner and member alike) manage their lifecycle in the
                      settings layer; personal vaults have no lifecycle ops, so no button. Leave
                      moved off the row into settings — the row keeps its role tag. */}
                  {showSettingsButton(v) && (
                    <button type="button" className="ghost" onClick={() => onOpenSettings(v.vaultId)}>Settings</button>
                  )}
                </div>
              ))}
            </div>
            <NewVaultForm account={account} store={store} client={client} onCreated={refresh} />
          </div>

          {trashOpen && (
            <>
              <RecentlyDeleted store={store} refreshKey={tick} onChanged={refresh} onLoaded={setRestorableIds} />
              {/* IA P8: web finally has the holding-area surface Android has ("Recently
                  removed") — a read-only mirror; recovery is automatic on restore/re-add. */}
              <RecentlyRemoved store={store} hide={restorableIds} />
            </>
          )}
        </>
      )}
    </div>
  );
}

function friendlyError(e: unknown): string {
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
      <span className="muted" style={{ textAlign: "right" }}>
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

function MemberPanel({ vault, account, store, client, onChanged, onBackup, copying, setCopying, copiedNote, setCopiedNote, onDeletedNote }: { vault: VaultInfo; account: Account; store: VaultStore; client: ApiClient; onChanged: () => void; onBackup: () => void; copying: { done: number; total: number } | null; setCopying: (c: { done: number; total: number } | null) => void; copiedNote: string; setCopiedNote: (note: string) => void; onDeletedNote: (note: { vaultId: string; name: string; purgeAt: number }) => void }) {
  const [members, setMembers] = useState<VaultMemberSummary[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [removing, setRemoving] = useState<string | null>(null); // userId pending remove confirm
  const [verifyingId, setVerifyingId] = useState<string | null>(null); // A6: one-tap pin from this list
  const [legacyTick, setLegacyTick] = useState(0); // A6b: reload the legacy-grants list after a verification

  const load = () =>
    client
      .vaultMembers(vault.vaultId)
      .then(setMembers)
      .catch((e) => setErr(friendlyError(e)));

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, vault.vaultId]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr("");
    try {
      await fn();
    } catch (e) {
      setErr(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  const changeRole = (userId: string, role: string) =>
    run(async () => {
      await client.setVaultMemberRole(vault.vaultId, userId, role);
      await store.sync();
      await load();
      onChanged();
    });

  // H06: the removal goes through the store so it carries the spec 03 §11 removal proof (nonce +
  // HMAC under the vault's lifecycle key). A bodyless client.removeVaultMember here made every
  // legitimate removal land on the removed member's devices as the "server may be misbehaving"
  // anomaly banner — the attribution copy inverted for the only case that ever occurs.
  const remove = (userId: string) =>
    run(async () => {
      await store.removeVaultMember(vault.vaultId, userId);
      setRemoving(null);
      await store.sync();
      await load();
      onChanged();
    });

  const pending = store.pendingTransferFor(vault.vaultId);
  const pendingMember = pending && members?.find((m) => m.userId === pending.toUserId);
  // A6b: owner-only signing actions (add member, re-share, transfer) need this account's OWN evidence that it owns the
  // vault; the server's role label alone only shows this panel. Until it is confirmed, those controls wait.
  const [, setOwnTick] = useState(0);
  const ownershipUnconfirmed = store.ownershipNeedsConfirmation(vault.vaultId);
  // Transfer targets: active members who are not the owner and not disabled.
  const targets = (members ?? []).filter((m) => m.role !== "owner" && (m.status ?? "active") === "active");

  return (
    <div className="sheet">
      <RenameHeader vault={vault} store={store} onRenamed={onChanged} />
      <p className="muted" style={{ marginTop: 0 }}>
        {ownershipUnconfirmed ? "The server reports you as this vault's owner." : "You own this vault."} Writers can add and edit items; readers can only view.
      </p>
      {err && <Msg kind="err">{err}</Msg>}
      {ownershipUnconfirmed && <ConfirmOwnership vault={vault} store={store} onConfirmed={() => setOwnTick((t) => t + 1)} />}

      {!members ? (
        <p className="muted"><Busy>Loading…</Busy></p>
      ) : (
        <div className="attach-list">
          {members.map((m) => (
            <div className="attach-row" key={m.userId}>
              <span className="attach-name">
                {m.displayName} <span className="muted">{m.email}</span>
                {(m.status ?? "active") !== "active" && <span className="tag" style={{ color: "var(--danger)" }}>disabled</span>}
                <MemberPinTag store={store} account={account} m={m} onVerify={() => setVerifyingId(m.userId)} />
              </span>
              {m.role === "owner" ? (
                <span className="tag">owner</span>
              ) : removing === m.userId ? (
                <>
                  <span className="muted" style={{ flex: 2, minWidth: 0 }}>
                    They keep anything they already saw; the vault key is not rotated in v1.
                  </span>
                  <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => remove(m.userId)}>
                    {busy ? "Removing…" : "Confirm remove"}
                  </button>
                  <button type="button" className="ghost" disabled={busy} onClick={() => setRemoving(null)}>Keep</button>
                </>
              ) : (
                <>
                  <select value={m.role} disabled={busy} aria-label={`Role for ${m.email}`} onChange={(e) => changeRole(m.userId, e.target.value)} style={{ width: "auto" }}>
                    <option value="writer">writer</option>
                    <option value="reader">reader</option>
                  </select>
                  <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => setRemoving(m.userId)}>
                    Remove
                  </button>
                </>
              )}
            </div>
          ))}
        </div>
      )}

      {verifyingId && members?.some((m) => m.userId === verifyingId) && (
        <VerifyMemberPanel
          client={client}
          account={account}
          store={store}
          presetServed={(() => {
            const m = members.find((x) => x.userId === verifyingId)!;
            return { userId: m.userId, displayName: m.displayName, identityPub: m.identityPub };
          })()}
          onDone={() => {
            setVerifyingId(null);
            // A6b: a newly verified legacy member shows a "Re-share" row below; nothing is re-issued on its own.
            void store.sync().catch(() => {}).then(() => { void load(); onChanged(); setLegacyTick((t) => t + 1); });
          }}
        />
      )}

      {!ownershipUnconfirmed && <LegacyGrantsPanel store={store} vault={vault} refreshKey={legacyTick} />}

      {ownershipUnconfirmed ? null : pending ? (
        <div className="msg info" style={{ display: "flex", alignItems: "center", gap: 12, marginTop: 14 }}>
          <span style={{ flex: 1 }}>
            Ownership offer to {pendingMember?.displayName ?? "a member"} — expires {fmtDay(pending.expiresAt)}
          </span>
          <button type="button" className="link" disabled={busy} onClick={() => run(async () => { await store.cancelTransfer(vault.vaultId); await load(); onChanged(); })}>
            Cancel offer
          </button>
        </div>
      ) : (
        members && <TransferOfferControl vault={vault} store={store} targets={targets} onOffered={async () => { await load(); onChanged(); }} />
      )}

      {!ownershipUnconfirmed && (
        <AddMember
          vaultId={vault.vaultId}
          account={account}
          store={store}
          client={client}
          onAdded={async () => {
            await store.sync();
            await load();
            onChanged();
          }}
        />
      )}

      <DeleteVaultControl vault={vault} store={store} onDeleted={onChanged} onDeletedNote={onDeletedNote} onBackup={onBackup} copying={copying} setCopying={setCopying} copiedNote={copiedNote} setCopiedNote={setCopiedNote} />
    </div>
  );
}

// ---- read-only roster (member-role vaults, F20) ----

/**
 * A writer/reader's read-only view of who else is in a shared vault they belong to. The server
 * already returns the roster to any grant-holder (listVaultMembers 403s only when the caller has
 * NO grant — owner-gating is on the mutating routes, not this GET), so this is pure transparency:
 * no role selects, no remove, no transfer, no add, no delete. Management stays owner-only in
 * MemberPanel above.
 */
function MemberRosterPanel({ vault, account, store, client }: { vault: VaultInfo; account: Account; store: VaultStore; client: ApiClient }) {
  const [members, setMembers] = useState<VaultMemberSummary[] | null>(null);
  const [err, setErr] = useState("");
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [, setTick] = useState(0);

  useEffect(() => {
    client
      .vaultMembers(vault.vaultId)
      .then(setMembers)
      .catch((e) => setErr(friendlyError(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client, vault.vaultId]);

  return (
    <div className="sheet">
      <h2>“{vault.name}” members</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        You're a {vault.role ?? "member"} of this shared vault. Only its owner can add, remove, or
        change who has access.
      </p>
      {err && <Msg kind="err">{err}</Msg>}
      {!members ? (
        <p className="muted"><Busy>Loading…</Busy></p>
      ) : (
        <div className="attach-list">
          {members.map((m) => (
            <div className="attach-row" key={m.userId}>
              <span className="attach-name">
                {m.displayName} <span className="muted">{m.email}</span>
                {(m.status ?? "active") !== "active" && <span className="tag" style={{ color: "var(--danger)" }}>disabled</span>}
                <MemberPinTag store={store} account={account} m={m} onVerify={() => setVerifyingId(m.userId)} />
              </span>
              <span className="tag">{m.role}</span>
            </div>
          ))}
        </div>
      )}
      {verifyingId && members?.some((m) => m.userId === verifyingId) && (
        <VerifyMemberPanel
          client={client}
          account={account}
          store={store}
          presetServed={(() => {
            const m = members.find((x) => x.userId === verifyingId)!;
            return { userId: m.userId, displayName: m.displayName, identityPub: m.identityPub };
          })()}
          onDone={() => {
            setVerifyingId(null);
            setTick((t) => t + 1);
          }}
        />
      )}
    </div>
  );
}

/**
 * Members-list one-tap pin (security review 2026-10, root cause A §8.2 step 6, A6): "Verified" for a member pinned
 * and current on this device with the key the server serves for them; "key changed" (danger) when the served key
 * differs from the pin; otherwise a one-tap "Verify" that opens the household verification ceremony against this
 * row's key. Nothing here pins a key by itself.
 */
function MemberPinTag({ store, account, m, onVerify }: { store: VaultStore; account: Account; m: VaultMemberSummary; onVerify: () => void }) {
  if (m.userId === account.userId) return null;
  const st = store.memberPinState(m.userId, m.identityPub);
  if (st === "pinned") return <span className="tag">verified</span>;
  if (st === "key-changed") return <span className="tag" style={{ color: "var(--danger)" }}>key changed — verify in person</span>;
  return (
    <button type="button" className="link" onClick={onVerify}>
      Verify
    </button>
  );
}

/**
 * "You own <vault>?" (security review 2026-10, root cause A, branch A6b; review MEDIUM-1): the server reports this
 * account as the owner, but this browser has no record that the account created the vault or that its owner
 * transferred it here. Like A5b's personal-vault choice, the confirmation first loads and shows what the server
 * reports (its owner, its last transfer, who else holds the vault), then asks for a fresh master password, checked
 * against this session's key. A vault this browser first received as a MEMBER also needs the explicit "This vault's
 * owner transferred it to me". Until then nothing is signed or sealed for it on the strength of the server's label.
 */
function ConfirmOwnership({ vault, store, onConfirmed }: { vault: VaultInfo; store: VaultStore; onConfirmed: () => void }) {
  const [claim, setClaim] = useState<OwnershipClaim | null>(null);
  const [password, setPassword] = useState("");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const open = async () => {
    setBusy(true);
    setErr("");
    try {
      setClaim(await store.describeOwnership(vault.vaultId));
    } catch (x) {
      setErr(x instanceof VaultKeyNotVerifiedError ? "This vault's key did not come from your own account, so it can't be claimed here." : friendlyError(x));
    } finally {
      setBusy(false);
    }
  };
  const cancel = () => {
    store.cancelOwnershipClaim();
    setClaim(null);
    setPassword("");
    setAck(false);
    setErr("");
  };
  const confirm = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!claim) return;
    setBusy(true);
    setErr("");
    try {
      await store.confirmOwnership(claim, password, ack);
      setPassword("");
      onConfirmed();
    } catch (x) {
      setErr(
        x instanceof ReauthFailedError ? "That master password isn't right."
          : x instanceof OwnershipTransferAckRequiredError ? x.message
          : friendlyError(x),
      );
    } finally {
      setBusy(false);
    }
  };
  const who = (c: { displayName: string; email: string; userId: string }) => (c.displayName ? `${c.displayName} (${c.email})` : "someone this browser can't name");
  return (
    <div className="msg info" style={{ display: "block", marginTop: 14 }}>
      <strong>You own “{vault.name}”?</strong> The server reports you as its owner, but this device has no record that you
      created this vault or that its owner transferred it to you. Only confirm if you created this vault, or its owner
      transferred it to you. Otherwise, don't confirm: tell your admin.
      {err && <Msg kind="err">{err}</Msg>}
      {!claim ? (
        <div className="actions" style={{ marginTop: 8 }}>
          <button type="button" className="ghost" disabled={busy} onClick={() => void open()}>{busy ? <Busy>Loading…</Busy> : `Confirm I own “${vault.name}”…`}</button>
        </div>
      ) : (
        <form onSubmit={confirm} style={{ marginTop: 8 }}>
          <ul className="plain-list">
            <li>
              {claim.lastTransferTo
                ? <>Last ownership transfer: to {who(claim.lastTransferTo)}, transfer #{claim.lastTransferSeq} <span className="muted">(as reported by the server)</span></>
                : <>Created by {claim.reportedOwner ? who(claim.reportedOwner) : "an unknown owner"}; no transfer on record <span className="muted">(as reported by the server)</span></>}
            </li>
            <li>
              Also holding this vault: {claim.coHolders.length === 0 ? "no one else" : claim.coHolders.map((c) => `${who(c)}, ${c.role}`).join("; ")}{" "}
              <span className="muted">(as reported by the server)</span>
            </li>
            {claim.receivedAsMember && <li><strong>This device first received this vault as a member.</strong></li>}
          </ul>
          {claim.receivedAsMember && (
            <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} disabled={busy} />
              This vault's owner transferred it to me
            </label>
          )}
          <div className="field">
            <label>Your master password</label>
            <div className="secret-row">
              <input type="password" autoComplete="current-password" aria-label="Your master password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={busy} />
              <button className="primary" disabled={busy || !password || (claim.receivedAsMember && !ack)}>{busy ? <Busy>Checking…</Busy> : "Confirm"}</button>
              <button type="button" className="ghost" disabled={busy} onClick={cancel}>Cancel</button>
            </div>
          </div>
        </form>
      )}
    </div>
  );
}

/**
 * §8.2 step 4, "Legacy grants" (A6b): the members the SERVER lists as still on the older grant format. Nothing is
 * re-shared on its own: the owner confirms each row, which names the vault and the member as this browser verified
 * them. (A member this account already re-shared with, for the same identity key, is renewed without a prompt.)
 */
function LegacyGrantsPanel({ store, vault, refreshKey }: { store: VaultStore; vault: VaultInfo; refreshKey: number }) {
  const [rows, setRows] = useState<LegacyGrantRow[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    let live = true;
    store.loadLegacyGrants(vault.vaultId).then((r) => { if (live) setRows(r); }).catch(() => { if (live) setRows([]); });
    return () => { live = false; };
  }, [store, vault.vaultId, refreshKey]);
  if (!rows || rows.length === 0) return null;
  const reshare = async (row: LegacyGrantRow) => {
    setBusy(row.userId);
    setErr("");
    try {
      await store.confirmReissue(row);
      setConfirming(null);
      setRows(store.legacyGrantRows(vault.vaultId));
    } catch (x) {
      setErr(x instanceof MemberNotVerifiedError || x instanceof OwnershipNotConfirmedError ? x.message : friendlyError(x));
    } finally {
      setBusy(null);
    }
  };
  const vaultName = (r: LegacyGrantRow) => r.vaultName ?? vault.name;
  return (
    <div className="msg info" style={{ display: "block", marginTop: 14 }}>
      <strong>Legacy grants.</strong> The server lists these members as still on the old sharing format. Only confirm people
      you shared this vault with.
      {err && <Msg kind="err">{err}</Msg>}
      <ul className="plain-list" style={{ marginTop: 6 }}>
        {rows.map((r) => (
          <li key={r.userId}>
            {r.pinState === "pinned" && r.verifiedLabel !== null ? (
              confirming === r.userId ? (
                <>
                  Re-share “{vaultName(r)}” with {r.verifiedLabel}?{" "}
                  <button type="button" className="primary" disabled={busy !== null} onClick={() => void reshare(r)}>{busy === r.userId ? "Re-sharing…" : "Re-share"}</button>{" "}
                  <button type="button" className="ghost" disabled={busy !== null} onClick={() => setConfirming(null)}>Cancel</button>
                </>
              ) : (
                <>
                  {r.verifiedLabel} <span className="muted">(verified; the server calls them {r.displayName}, {r.email})</span>{" "}
                  <button type="button" className="link" onClick={() => setConfirming(r.userId)}>Re-share “{vaultName(r)}”…</button>
                </>
              )
            ) : r.pinState === "key-changed" ? (
              <span style={{ color: "var(--danger)" }}>{r.displayName}: the server holds a different identity key than the one you verified. Don't re-share; check their code in person again.</span>
            ) : (
              <>Verify {r.displayName} ({r.email}) first (the Verify link above), then re-share “{vaultName(r)}” with them here.</>
            )}
          </li>
        ))}
      </ul>
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
    <div className="sheet" style={{ borderLeft: "3px solid var(--danger)" }}>
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

function RenameHeader({ vault, store, onRenamed }: { vault: VaultInfo; store: VaultStore; onRenamed: () => void }) {
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
      setErr(friendlyError(e));
    } finally {
      setBusy(false);
    }
  };

  if (!editing) {
    return (
      <h2 style={{ display: "flex", alignItems: "center", gap: 10 }}>
        “{vault.name}” members
        <button type="button" className="link" onClick={() => { setName(vault.name); setEditing(true); }}>Rename</button>
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

function TransferOfferControl({ vault, store, targets, onOffered }: { vault: VaultInfo; store: VaultStore; targets: VaultMemberSummary[]; onOffered: () => Promise<void> }) {
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
      await store.offerTransfer(vault.vaultId, target);
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
          <p className="muted" style={{ marginTop: 0 }}>
            Make {targetMember.displayName} the owner of “{vault.name}”? Nothing changes until they
            accept in their app (they have 14 days; you can cancel anytime). Afterwards they manage
            members and only they can rename, transfer, or delete it — you'll stay in it as a writer.
          </p>
          <div className="actions">
            <button type="button" className="primary" disabled={busy} onClick={offer}>{busy ? "Sending…" : `Ask ${targetMember.displayName} to take over`}</button>
            <button type="button" className="ghost" disabled={busy} onClick={() => setConfirming(false)}>Cancel</button>
          </div>
        </>
      ) : (
        <div className="secret-row">
          <select value={target} aria-label="Make someone else the owner" onChange={(e) => setTarget(e.target.value)} style={{ width: "auto" }}>
            <option value="">choose a member…</option>
            {targets.map((m) => (
              <option key={m.userId} value={m.userId}>{m.displayName} ({m.email})</option>
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
function DeleteVaultControl({ vault, store, onDeleted, onDeletedNote, onBackup, copying, setCopying, copiedNote, setCopiedNote }: { vault: VaultInfo; store: VaultStore; onDeleted: () => void; onDeletedNote: (note: { vaultId: string; name: string; purgeAt: number }) => void; onBackup: () => void; copying: { done: number; total: number } | null; setCopying: (c: { done: number; total: number } | null) => void; copiedNote: string; setCopiedNote: (note: string) => void }) {
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
      const { purgeAt } = await store.deleteSharedVault(vault.vaultId);
      onDeletedNote({ vaultId: vault.vaultId, name: vault.name, purgeAt });
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

/** Renders ONLY for a verified incoming offer (store.incomingTransfers() already gated on the
 *  offer proof verifying under the held VK). The in-person confirm is an ADVISORY, not proof. */
function IncomingTransferCard({ offer, account, store, client, onChanged }: { offer: IncomingTransfer; account: Account; store: VaultStore; client: ApiClient; onChanged: () => void }) {
  const [ownerName, setOwnerName] = useState<string>("the current owner");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    client
      .vaultMembers(offer.vaultId)
      .then((ms) => {
        const owner = ms.find((m) => m.role === "owner");
        if (owner) setOwnerName(owner.displayName);
      })
      .catch(() => {});
  }, [client, offer.vaultId]);

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
    <div className="sheet" style={{ borderLeft: "3px solid var(--gold)" }}>
      <h2>Become the owner of “{offer.vaultName}”?</h2>
      <p style={{ marginTop: 0 }}>{ownerName} wants to make you the owner of “{offer.vaultName}”.</p>
      <p className="muted">
        ✓ This offer was verified with the vault's own key. To be sure it really came from {ownerName} —
        and not a compromised server — confirm with them in person or by phone. As owner you'd manage
        members and be the only one who can rename, transfer, or delete it.
      </p>
      {err && <Msg kind="err">{err}</Msg>}
      <div className="actions">
        <button type="button" className="primary" disabled={busy} onClick={() => act(() => store.acceptTransfer(offer.vaultId))}>{busy ? "Taking over…" : "Become the owner"}</button>
        <button type="button" className="ghost" disabled={busy} onClick={() => act(() => store.cancelTransfer(offer.vaultId))}>Decline</button>
      </div>
    </div>
  );
}

// ---- recently deleted (restore, spec 03 §11) ----

/** IA P8: the holding area — vaults this account lost access to, a sealed local copy kept for
 *  a while. Read-only (recovery is automatic on restore/re-add); mirrors Android's "Recently
 *  removed". Derived from store.heldVaults() each render — no fetch, no action. */
function RecentlyRemoved({ store, hide }: { store: VaultStore; hide: string[] }) {
  // A vault the deleter can still RESTORE (RecentlyDeleted, above) hides its sealed-copy twin
  // here — one story, one row (owner dev-note 2026-08-19).
  const held = store.heldVaults().filter((h) => !hide.includes(h.vaultId));
  if (held.length === 0) return null;
  const line = (h: { reason: string; verified: boolean; purgeAt?: number; expungeAt: number }): string => {
    if (h.reason === "deleted" && h.verified) return `deleted by its owner · kept sealed until ${fmtDay(h.purgeAt ?? h.expungeAt)}`;
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
        </div>
      ))}
    </div>
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
            <span className="attach-name">
              “{d.name}” <span className="muted">deleted {fmtDay(d.deletedAt)} · erased for good {fmtDay(d.purgeAt)}</span>
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

/**
 * Add-member flow (security review 2026-10, root cause A §1.5, §7.2; branch A6): lookup by email, then
 *  - a member PINNED and current on this browser with the key the server serves: no fingerprint step ("Verified");
 *  - a member whose served key differs from the pin: refused (verify again in person; their key changed, or the
 *    server is substituting one);
 *  - anyone else: the household verification ceremony first (they read THEIR 32-hex code from THEIR screen; it is
 *    compared with SHA-256 of the served key, and on a match they are pinned).
 * The store then signs a v2 grant to the PIN key and dual-sends the v1 seal (also to the pin) for older clients.
 */
function AddMember({ vaultId, account, store, client, onAdded }: { vaultId: string; account: Account; store: VaultStore; client: ApiClient; onAdded: () => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [found, setFound] = useState<UserLookupResponse | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [role, setRole] = useState("writer");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [, setTick] = useState(0);

  const reset = () => {
    setFound(null);
    setVerifying(false);
    setRole("writer");
  };

  const lookup = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    reset();
    try {
      const u = await client.lookupUser(email.trim());
      if (u.userId === account.userId) {
        // You're already the owner — adding yourself would just fail server-side.
        setErr("That's your own account — you already own this vault.");
        return;
      }
      setFound(u);
    } catch (err) {
      setErr(friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

  const add = async () => {
    if (!found) return;
    setBusy(true);
    setErr("");
    try {
      await store.addVaultMember(vaultId, found.userId, role);
      setEmail("");
      reset();
      await onAdded();
    } catch (err) {
      setErr(err instanceof MemberNotVerifiedError ? err.message : friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

  const pinState = found ? store.memberPinState(found.userId, found.identityPub) : null;

  return (
    <div style={{ marginTop: 18 }}>
      {err && <Msg kind="err">{err}</Msg>}
      <form onSubmit={lookup}>
        <div className="field">
          <label>Add a member</label>
          <div className="secret-row">
            <input
              type="email"
              aria-label="Add a member (their email)"
              placeholder="their email"
              value={email}
              onChange={(e) => {
                setEmail(e.target.value);
                reset();
              }}
            />
            <button className="ghost" disabled={busy || !email.trim()}>{busy && !found ? "Looking…" : "Look up"}</button>
          </div>
        </div>
      </form>

      {found && pinState === "key-changed" && (
        <Msg kind="err">
          The server now holds a different identity key for {found.displayName} than the one you verified. Don't add them: check
          their code in person again (Settings, Household members), and tell your admin.
        </Msg>
      )}

      {found && pinState === "needs-verification" && (
        verifying ? (
          <VerifyMemberPanel
            client={client}
            account={account}
            store={store}
            presetServed={found}
            onDone={() => {
              setVerifying(false);
              setTick((t) => t + 1); // re-read the pin state: verified → the add controls below
            }}
          />
        ) : (
          <div className="field">
            <p className="muted" style={{ marginTop: 6 }}>
              You haven't verified {found.displayName} on this device yet. Do it together, in person or on a call you trust: they
              read the identity code from THEIR screen and you type it here. You do this once per person, not once per vault.
            </p>
            <button type="button" className="primary" onClick={() => setVerifying(true)}>Verify {found.displayName}</button>
          </div>
        )
      )}

      {found && pinState === "pinned" && (
        <>
          <p className="muted" style={{ marginTop: 6 }}>
            <span className="tag">verified</span> You've verified {found.displayName}; no code check needed.
          </p>
          <Field label="Role">
            <select value={role} onChange={(e) => setRole(e.target.value)} style={{ width: "auto" }}>
              <option value="writer">writer — can add and edit items</option>
              <option value="reader">reader — can only view</option>
            </select>
          </Field>
          <div className="actions">
            <button type="button" className="primary" disabled={busy} onClick={add}>
              {busy ? "Sealing…" : "Add to vault"}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
