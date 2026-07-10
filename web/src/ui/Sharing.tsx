import { useEffect, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { UserLookupResponse, VaultMemberSummary } from "../api/types";
import { fromB64 } from "../crypto/bytes";
import { shortIdentityFingerprint } from "../crypto/sharedgrant";
import type { Account } from "../vault/account";
import type { DeletedVaultInfo, IncomingTransfer, VaultInfo, VaultStore } from "../vault/store";
import { UNREACHABLE } from "./errors";
import { ViewHeader } from "./ViewHeader";

interface Props {
  account: Account;
  store: VaultStore;
  client: ApiClient;
  onSynced: () => void; // parent refresh — items may gain/lose vault badges, notices update
  onBackup: () => void; // open the full-vault backup panel (delete dialog "Back up first…")
}

/** "July 14"-style day (spec 03 §11 copy). */
function fmtDay(ms?: number): string {
  if (!ms) return "soon";
  return new Date(ms).toLocaleDateString(undefined, { month: "long", day: "numeric" });
}

/** Sharing view (spec 03 §10/§11): vaults, members, and the full lifecycle — delete, restore,
 *  leave, transfer, rename. Destructive actions live in the owner-only member panel per the
 *  capabilities table; leave lives on the member's vault row; incoming ownership offers surface
 *  at the top; a Recently-deleted section restores in-grace vaults. */
export function Sharing({ account, store, client, onSynced, onBackup }: Props) {
  const [tick, setTick] = useState(0);
  const refresh = () => {
    setTick((t) => t + 1);
    onSynced();
  };
  // Derived each render (cheap) so a background WS sync that re-renders the parent is reflected.
  void tick;
  const vaults = store.vaults();
  const incoming = store.incomingTransfers();
  const ownedShared = vaults.filter((v) => v.type === "shared" && v.role === "owner");
  const memberShared = vaults.filter((v) => v.type === "shared" && v.role !== "owner");

  return (
    <div>
      <ViewHeader title="Sharing" />

      {incoming.map((t) => (
        <IncomingTransferCard key={t.vaultId} offer={t} account={account} store={store} client={client} onChanged={refresh} />
      ))}

      <UndecryptableGrantsWarning store={store} />

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
              {v.type === "shared" && v.role !== "owner" ? (
                <LeaveControl vault={v} store={store} onChanged={refresh} />
              ) : (
                <span className="tag">{v.role ?? "member"}</span>
              )}
            </div>
          ))}
        </div>
        <NewVaultForm account={account} store={store} client={client} onCreated={refresh} />
      </div>

      {ownedShared.map((v) => (
        <MemberPanel key={v.vaultId} vault={v} account={account} store={store} client={client} onChanged={refresh} onBackup={onBackup} />
      ))}

      {/* F20: non-owners see WHO ELSE is in a shared vault they belong to (read-only). */}
      {memberShared.map((v) => (
        <MemberRosterPanel key={v.vaultId} vault={v} client={client} />
      ))}

      <RecentlyDeleted store={store} refreshKey={tick} onChanged={refresh} />
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
      case "sharing_public_disabled": return "Sharing can only be managed from the home network, not over the public address.";
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
    const { request, vaultId } = account.buildCreateSharedVault(name.trim());
    try {
      await client.createVault(request);
      await store.sync();
      setName("");
      onCreated();
    } catch (err) {
      account.removeVault(vaultId); // roll back the optimistic local registration
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
      {err && <div className="msg err">{err}</div>}
      <div className="field">
        <label>New shared vault</label>
        <div className="secret-row">
          <input placeholder="e.g. Family" value={name} onChange={(e) => setName(e.target.value)} />
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
      {err && <div className="msg err">{err}</div>}
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

function MemberPanel({ vault, account, store, client, onChanged, onBackup }: { vault: VaultInfo; account: Account; store: VaultStore; client: ApiClient; onChanged: () => void; onBackup: () => void }) {
  const [members, setMembers] = useState<VaultMemberSummary[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [removing, setRemoving] = useState<string | null>(null); // userId pending remove confirm

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

  const remove = (userId: string) =>
    run(async () => {
      await client.removeVaultMember(vault.vaultId, userId);
      setRemoving(null);
      await store.sync();
      await load();
      onChanged();
    });

  const pending = store.pendingTransferFor(vault.vaultId);
  const pendingMember = pending && members?.find((m) => m.userId === pending.toUserId);
  // Transfer targets: active members who are not the owner and not disabled.
  const targets = (members ?? []).filter((m) => m.role !== "owner" && (m.status ?? "active") === "active");

  return (
    <div className="sheet">
      <RenameHeader vault={vault} store={store} onRenamed={onChanged} />
      <p className="muted" style={{ marginTop: 0 }}>You own this vault. Writers can add and edit items; readers can only view.</p>
      {err && <div className="msg err">{err}</div>}

      {!members ? (
        <p className="muted">loading…</p>
      ) : (
        <div className="attach-list">
          {members.map((m) => (
            <div className="attach-row" key={m.userId}>
              <span className="attach-name">
                {m.displayName} <span className="muted">{m.email}</span>
                {(m.status ?? "active") !== "active" && <span className="tag" style={{ color: "var(--danger)" }}>disabled</span>}
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
                  <select value={m.role} disabled={busy} onChange={(e) => changeRole(m.userId, e.target.value)} style={{ width: "auto" }}>
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

      {pending ? (
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

      <AddMember
        vaultId={vault.vaultId}
        account={account}
        client={client}
        onAdded={async () => {
          await store.sync();
          await load();
          onChanged();
        }}
      />

      <DeleteVaultControl vault={vault} store={store} onDeleted={onChanged} onBackup={onBackup} />
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
function MemberRosterPanel({ vault, client }: { vault: VaultInfo; client: ApiClient }) {
  const [members, setMembers] = useState<VaultMemberSummary[] | null>(null);
  const [err, setErr] = useState("");

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
      {err && <div className="msg err">{err}</div>}
      {!members ? (
        <p className="muted">loading…</p>
      ) : (
        <div className="attach-list">
          {members.map((m) => (
            <div className="attach-row" key={m.userId}>
              <span className="attach-name">
                {m.displayName} <span className="muted">{m.email}</span>
                {(m.status ?? "active") !== "active" && <span className="tag" style={{ color: "var(--danger)" }}>disabled</span>}
              </span>
              <span className="tag">{m.role}</span>
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
      {err && <div className="msg err">{err}</div>}
      <div className="secret-row">
        <input autoFocus value={name} onChange={(e) => setName(e.target.value)} disabled={busy} />
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
      {err && <div className="msg err">{err}</div>}
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
          <select value={target} onChange={(e) => setTarget(e.target.value)} style={{ width: "auto" }}>
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

function DeleteVaultControl({ vault, store, onDeleted, onBackup }: { vault: VaultInfo; store: VaultStore; onDeleted: () => void; onBackup: () => void }) {
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [copying, setCopying] = useState<{ done: number; total: number } | null>(null);
  const [copiedNote, setCopiedNote] = useState("");
  const [toast, setToast] = useState("");

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
      setToast(`“${vault.name}” is deleted. Members lost access immediately. You can restore it until ${fmtDay(purgeAt)} (Recently deleted below).`);
      setOpen(false);
      setTyped("");
      onDeleted();
    } catch (e) {
      setErr(friendlyError(e));
      setBusy(false);
    }
  };

  if (toast) {
    return <div className="msg info" style={{ marginTop: 16 }}>{toast} <button type="button" className="link" onClick={() => setToast("")}>OK</button></div>;
  }

  if (!open) {
    return (
      <div className="actions" style={{ marginTop: 18 }}>
        <div className="spacer" />
        <button type="button" className="ghost" style={{ color: "var(--danger)" }} onClick={() => { setOpen(true); setErr(""); setCopiedNote(""); }}>
          Delete vault…
        </button>
      </div>
    );
  }

  return (
    <div className="field" style={{ marginTop: 18, borderTop: "1px solid var(--line, #333)", paddingTop: 16 }}>
      <label style={{ color: "var(--danger)" }}>Delete “{vault.name}”?</label>
      <p className="muted" style={{ marginTop: 0 }}>
        This removes the vault from everyone's andvari now. The server keeps its {items.length}{" "}
        {items.length === 1 ? "item" : "items"}{attachmentCount > 0 ? ` and ${attachmentCount} ${attachmentCount === 1 ? "attachment" : "attachments"}` : ""} for 7 days
        (until {eraseDay}) in case you change your mind — then erases them for good. Want to keep some of these?
      </p>
      <div className="actions" style={{ marginBottom: 8 }}>
        <button type="button" className="ghost" disabled={busy} onClick={copyFirst}>
          {copying ? `Copying… ${copying.done}/${copying.total}` : "Copy items to my Personal vault first…"}
        </button>
        <button type="button" className="ghost" disabled={busy} onClick={onBackup}>Back up first…</button>
      </div>
      {copiedNote && <div className="msg info" style={{ display: "block" }}>{copiedNote}</div>}

      <div className="msg info" style={{ display: "block" }}>
        <strong>Deleting can't take back what people already saw:</strong> anyone who had access may have
        kept copies of items or the vault key, and encrypted server backups age out on their own schedule
        (about a month). If a password really matters, change it at the website too.
      </div>

      {err && <div className="msg err">{err}</div>}
      <label style={{ marginTop: 10 }}>Type the vault's name to delete it:</label>
      <input value={typed} onChange={(e) => setTyped(e.target.value)} placeholder={vault.name} disabled={busy} />
      <div className="actions" style={{ marginTop: 10 }}>
        <button type="button" className="ghost" disabled={busy} onClick={() => { setOpen(false); setTyped(""); setErr(""); }}>Cancel</button>
        <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy || typed !== vault.name} onClick={del}>
          {busy ? "Deleting…" : "Delete vault"}
        </button>
      </div>
    </div>
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
      {err && <div className="msg err">{err}</div>}
      <div className="actions">
        <button type="button" className="primary" disabled={busy} onClick={() => act(() => store.acceptTransfer(offer.vaultId))}>{busy ? "Taking over…" : "Become the owner"}</button>
        <button type="button" className="ghost" disabled={busy} onClick={() => act(() => store.cancelTransfer(offer.vaultId))}>Decline</button>
      </div>
    </div>
  );
}

// ---- recently deleted (restore, spec 03 §11) ----

function RecentlyDeleted({ store, refreshKey, onChanged }: { store: VaultStore; refreshKey: number; onChanged: () => void }) {
  const [deleted, setDeleted] = useState<DeletedVaultInfo[] | null>(null);
  const [err, setErr] = useState("");
  const [restoring, setRestoring] = useState<string | null>(null); // vaultId pending confirm
  const [busy, setBusy] = useState(false);

  const load = () =>
    store
      .listDeleted()
      .then(setDeleted)
      .catch((e) => setErr(friendlyError(e)));

  useEffect(() => {
    load();
    // Re-keyed on the parent's action tick — a vault deleted while Sharing is open must
    // appear here (the post-delete toast points at this section).
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
      <h2>Recently deleted</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Deleted vaults you can still restore. Restoring brings a vault back for every member with
        everything that was in it.
      </p>
      {err && <div className="msg err">{err}</div>}
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
 * Add-member flow: lookup by email → MANDATORY out-of-band fingerprint verification
 * (spec 01 §5 — the only defense against a server substituting its own pubkey) →
 * seal the VK to the verified identity key → grant.
 */
function AddMember({ vaultId, account, client, onAdded }: { vaultId: string; account: Account; client: ApiClient; onAdded: () => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [found, setFound] = useState<(UserLookupResponse & { code: string }) | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [role, setRole] = useState("writer");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const reset = () => {
    setFound(null);
    setConfirmed(false);
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
      const fp = await shortIdentityFingerprint(fromB64(u.identityPub));
      setFound({ ...u, code: fp.match(/.{4}/g)!.join(" ") });
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
      const sealedVk = account.wrapVkForMember(fromB64(found.identityPub), vaultId);
      await client.addVaultMember(vaultId, { userId: found.userId, role, sealedVk });
      setEmail("");
      reset();
      await onAdded();
    } catch (err) {
      setErr(friendlyError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ marginTop: 18 }}>
      {err && <div className="msg err">{err}</div>}
      <form onSubmit={lookup}>
        <div className="field">
          <label>Add a member</label>
          <div className="secret-row">
            <input
              type="email"
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

      {found && (
        <>
          <div className="field">
            <label>{found.displayName}'s identity code</label>
            <div className="fingerprint" style={{ fontSize: 18, letterSpacing: "0.08em" }}>{found.code}</div>
            <p className="muted" style={{ marginTop: 6 }}>
              Ask {found.displayName} to read out the identity code shown in THEIR app's
              Settings. If it doesn't match exactly, stop — do not add them.
            </p>
          </div>
          <label className="check">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} />
            <span>I confirmed this code with {found.displayName} in person or by phone</span>
          </label>
          <div className="field">
            <label>Role</label>
            <select value={role} onChange={(e) => setRole(e.target.value)} style={{ width: "auto" }}>
              <option value="writer">writer — can add and edit items</option>
              <option value="reader">reader — can only view</option>
            </select>
          </div>
          <div className="actions">
            <button type="button" className="primary" disabled={busy || !confirmed} onClick={add}>
              {busy ? "Sealing…" : "Add to vault"}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
