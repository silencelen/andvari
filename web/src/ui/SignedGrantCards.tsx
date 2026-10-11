import { useEffect, useState } from "react";
import type { ApiClient } from "../api/client";
import type { UserLookupResponse } from "../api/types";
import type { Account } from "../vault/account";
import type { CoHolder } from "../vault/personalvault";
import type { LegacyVaultReview, PendingInvitation, VaultStore } from "../vault/store";
import { Busy } from "./Busy";
import { UNREACHABLE } from "./errors";
import { VerifyMemberPanel } from "./Household";
import { Msg } from "./Msg";

/*
 * Signed-grant surfaces (security review 2026-10, root cause A §1.6, §8.2; branch A6).
 *  - Pending invitations: a v2 grant from someone this browser has not verified. The vault NAME is not shown (it
 *    would decrypt under a key nobody authenticated). Verify = the household verification ceremony for the sender,
 *    then the grant is checked again; Decline hides it here.
 *  - "Review your shared vaults": vaults readable only through an older-format grant nobody has vouched for. They
 *    are read-only until accepted (trust on first use) or until the owner re-issues the grant from an updated app.
 */

function InvitationRow({ inv, account, store, client, onChanged }: { inv: PendingInvitation; account: Account; store: VaultStore; client: ApiClient; onChanged: () => void }) {
  const [sender, setSender] = useState<UserLookupResponse | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    store.invitationSender(inv).then(
      (s) => live && setSender(s),
      () => live && setSender(null),
    );
    return () => {
      live = false;
    };
  }, [inv, store]);

  const name = sender?.displayName ?? "Someone";
  return (
    <div style={{ marginBottom: 10 }}>
      <div>
        <strong>{name}</strong> wants to share a vault with you. Verify them to accept.{" "}
        <span className="muted">(The name is what the server reports.)</span>
      </div>
      {err && <Msg kind="err">{err}</Msg>}
      {verifying && sender ? (
        <VerifyMemberPanel
          client={client}
          account={account}
          store={store}
          presetServed={sender}
          onDone={(c) => {
            setVerifying(false);
            if (!c) return;
            setBusy(true);
            void store
              .sync()
              .catch(() => {})
              .then(() => {
                if (store.pendingInvitations().some((p) => p.vaultId === inv.vaultId)) setErr("Verified, but the invitation still doesn't check out. Tell your admin — the server may be misbehaving.");
                onChanged();
              })
              .finally(() => setBusy(false));
          }}
        />
      ) : (
        <div style={{ marginTop: 4 }}>
          <button type="button" className="primary" disabled={busy || !sender} onClick={() => setVerifying(true)}>{busy ? <Busy>Checking…</Busy> : `Verify ${name}`}</button>{" "}
          <button
            type="button"
            className="ghost"
            disabled={busy}
            onClick={() => {
              store.declineInvitation(inv);
              onChanged();
            }}
          >
            Decline
          </button>
          {sender === null && <span className="muted"> Couldn't load who sent it. {UNREACHABLE}</span>}
        </div>
      )}
    </div>
  );
}

/** §1.6 pending invitations. Renders nothing when there are none. */
export function PendingInvitationsCard({ account, store, client, onChanged }: { account: Account; store: VaultStore; client: ApiClient; onChanged: () => void }) {
  const invitations = store.pendingInvitations();
  if (invitations.length === 0) return null;
  return (
    <div className="sheet">
      <h2>Shared-vault invitations</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        andvari opens a shared vault only from someone you've verified, so the server can't slip you a vault of its own.
      </p>
      {invitations.map((inv) => (
        <InvitationRow key={inv.grantIdB64} inv={inv} account={account} store={store} client={client} onChanged={onChanged} />
      ))}
    </div>
  );
}

function ReviewRow({ r, store, onChanged }: { r: LegacyVaultReview; store: VaultStore; onChanged: () => void }) {
  const [owner, setOwner] = useState<CoHolder | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => {
    let live = true;
    store.reportedOwner(r.vaultId).then(
      (o) => live && setOwner(o),
      () => live && setOwner(null),
    );
    return () => {
      live = false;
    };
  }, [r.vaultId, store]);

  const run = async (fn: () => Promise<void>, failed: string) => {
    setBusy(true);
    setErr("");
    try {
      await fn();
      onChanged();
    } catch {
      setErr(failed);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ marginBottom: 10 }}>
      <div>
        <strong>{r.name ?? "A shared vault"}</strong> <span className="tag">not yet verified</span>{" "}
        <span className="muted">
          · {r.itemCount} {r.itemCount === 1 ? "item" : "items"} · owner {owner === undefined ? "…" : owner ? `${owner.displayName} (as reported by the server)` : "unknown"}
        </span>
      </div>
      {err && <Msg kind="err">{err}</Msg>}
      <div style={{ marginTop: 4 }}>
        <button type="button" className="ghost" disabled={busy} onClick={() => void run(() => store.acceptLegacyVault(r.vaultId), "Couldn't accept it. Try again.")}>
          Accept anyway
        </button>{" "}
        <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy} onClick={() => void run(() => store.leaveSharedVault(r.vaultId), "Couldn't leave. Try again.")}>
          Leave
        </button>
      </div>
    </div>
  );
}

/** §8.2 "Review your shared vaults": legacy-read-only vaults. Renders nothing when there are none. */
export function LegacyReviewCard({ store, onChanged }: { store: VaultStore; onChanged: () => void }) {
  const rows = store.legacyReviewVaults();
  if (rows.length === 0) return null;
  return (
    <div className="sheet">
      <h2>Review your shared vaults</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        {rows.length === 1 ? "This vault was" : "These vaults were"} shared with you by an older version of andvari, which can't prove who
        sent {rows.length === 1 ? "it" : "them"}. You can read {rows.length === 1 ? "it" : "them"}, but nothing is saved into{" "}
        {rows.length === 1 ? "it" : "them"} until you decide. The safest fix is to ask the owner to update andvari; you'll then be verified
        automatically. "Accept anyway" trusts {rows.length === 1 ? "it" : "them"} on first use: do that only if you expected this vault.
      </p>
      {rows.map((r) => (
        <ReviewRow key={r.vaultId} r={r} store={store} onChanged={onChanged} />
      ))}
    </div>
  );
}
