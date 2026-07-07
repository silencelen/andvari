import { useEffect, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { UserLookupResponse, VaultMemberSummary } from "../api/types";
import { fromB64 } from "../crypto/bytes";
import { shortIdentityFingerprint } from "../crypto/sharedgrant";
import type { Account } from "../vault/account";
import type { VaultInfo, VaultStore } from "../vault/store";

interface Props {
  account: Account;
  store: VaultStore;
  client: ApiClient;
  onSynced: () => void; // parent refresh — items may gain/lose vault badges
}

/** Sharing view (spec 03 §10): list vaults, create shared vaults, manage members. */
export function Sharing({ account, store, client, onSynced }: Props) {
  const [vaults, setVaults] = useState<VaultInfo[]>(store.vaults());

  const refresh = () => {
    setVaults(store.vaults());
    onSynced();
  };

  const ownedShared = vaults.filter((v) => v.type === "shared" && v.role === "owner");

  return (
    <div>
      <h2 className="view-title" style={{ margin: "22px 0 4px" }}>Sharing</h2>

      <div className="sheet">
        <h2>Vaults</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Every item lives in exactly one vault. Shared vaults are visible to everyone
          you add; only the vault owner manages members.
        </p>
        <div className="list">
          {vaults.map((v) => (
            <div className="item" key={v.vaultId} style={{ cursor: "default" }}>
              <span className="glyph">{v.name.charAt(0).toUpperCase()}</span>
              <span className="body">
                <div className="name">{v.name}</div>
                <div className="sub">{v.type === "personal" ? "personal vault" : "shared vault"}</div>
              </span>
              <span className="tag">{v.role ?? "member"}</span>
            </div>
          ))}
        </div>
        <NewVaultForm account={account} store={store} client={client} onCreated={refresh} />
      </div>

      {ownedShared.map((v) => (
        <MemberPanel key={v.vaultId} vault={v} account={account} store={store} client={client} onChanged={refresh} />
      ))}

      {ownedShared.length === 0 && vaults.some((v) => v.type === "shared") && (
        <p className="muted" style={{ marginTop: 14 }}>
          You are a member of the shared vault{vaults.filter((v) => v.type === "shared").length > 1 ? "s" : ""} above —
          only the owner manages who has access.
        </p>
      )}
    </div>
  );
}

function friendlyError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === "no_such_user") return "No account with that email address — they need to be invited and enrolled first.";
    if (e.code === "already_member") return "That person is already a member of this vault.";
    if (e.code === "sharing_public_disabled") return "Sharing can only be managed from the home network, not over the public address.";
    if (e.status === 429) return "Too many requests — wait a minute and try again.";
    return `${e.code}: ${e.message}`;
  }
  return "Request failed.";
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
      setErr(friendlyError(err));
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

// ---- member management (owner-only panel per shared vault) ----

function MemberPanel({ vault, account, store, client, onChanged }: { vault: VaultInfo; account: Account; store: VaultStore; client: ApiClient; onChanged: () => void }) {
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

  return (
    <div className="sheet">
      <h2>“{vault.name}” members</h2>
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
