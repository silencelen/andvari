import { useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { ClientPolicy } from "../api/types";
import { fromB64 } from "../crypto/bytes";
import { Account, deviceName } from "../vault/account";
import { VaultStore } from "../vault/store";
import { saveSession, type Session } from "./session";

type Mode = { unlock: Session } | { fresh: true };

interface Props {
  client: ApiClient;
  policy: ClientPolicy | null;
  mode: Mode;
  onReady: (account: Account, store: VaultStore) => void;
  onForget: () => void;
}

export function Welcome({ client, policy, mode, onReady, onForget }: Props) {
  if ("unlock" in mode) {
    return <Unlock client={client} session={mode.unlock} onReady={onReady} onForget={onForget} />;
  }
  return <FreshStart client={client} policy={policy} onReady={onReady} />;
}

/** Reload with an existing session: master password re-derives keys. */
function Unlock({ client, session, onReady, onForget }: { client: ApiClient; session: Session; onReady: (a: Account, s: VaultStore) => void; onForget: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const keys = await client.accountKeys();
      const account = await Account.unlock(session.userId, password, keys);
      const store = new VaultStore(client, account);
      await store.sync(); // rediscovers the personal vault id
      onReady(account, store);
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 401 ? "Session expired — sign in again." : "Wrong master password.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-shell">
      <form className="card" onSubmit={submit}>
        <div className="card-hero">
          <div className="sigil">ᛅ</div>
          <h1>Welcome back</h1>
          <p>{session.email}</p>
        </div>
        {err && <div className="msg err">{err}</div>}
        <div className="field">
          <label>Master password</label>
          <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </div>
        <button className="primary" disabled={busy || !password}>{busy ? "Unsealing…" : "Unlock"}</button>
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <button type="button" className="link" onClick={onForget}>Sign out / use a different account</button>
        </div>
      </form>
    </div>
  );
}

/** No session: sign in to an existing account, or enroll with an invite. */
function FreshStart({ client, policy, onReady }: { client: ApiClient; policy: ClientPolicy | null; onReady: (a: Account, s: VaultStore) => void }) {
  const [tab, setTab] = useState<"signin" | "enroll">("signin");
  return (
    <div className="auth-shell">
      <div className="card">
        <div className="card-hero">
          <div className="sigil">ᛅ</div>
          <h1 className="brand"><span className="a-mark">and</span>vari</h1>
          <p>the keeper of the hoard</p>
        </div>
        <div className="tabs">
          <button className={tab === "signin" ? "active" : ""} onClick={() => setTab("signin")}>Sign in</button>
          <button className={tab === "enroll" ? "active" : ""} onClick={() => setTab("enroll")}>Enroll</button>
        </div>
        {tab === "signin" ? <SignIn client={client} onReady={onReady} /> : <Enroll client={client} policy={policy} onReady={onReady} />}
      </div>
    </div>
  );
}

function SignIn({ client, onReady }: { client: ApiClient; onReady: (a: Account, s: VaultStore) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const pre = await client.prelogin(email);
      const authKey = await Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams);
      const s = await client.login(email, authKey, deviceName());
      const account = await Account.unlock(s.userId, password, s.accountKeys);
      const store = new VaultStore(client, account);
      await store.sync(); // discovers the personal vault id from grants
      saveSession({
        baseUrl: client.baseUrl,
        userId: s.userId,
        personalVaultId: account.personalVaultId,
        email,
        tokens: { accessToken: s.accessToken, refreshToken: s.refreshToken },
      });
      onReady(account, store);
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 401 ? "Wrong email or master password." : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      {err && <div className="msg err">{err}</div>}
      <div className="field">
        <label>Email</label>
        <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
      </div>
      <div className="field">
        <label>Master password</label>
        <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      <button className="primary" disabled={busy || !email || !password}>{busy ? "Unsealing…" : "Sign in"}</button>
    </form>
  );
}

function Enroll({ client, policy, onReady }: { client: ApiClient; policy: ClientPolicy | null; onReady: (a: Account, s: VaultStore) => void }) {
  const [invite, setInvite] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fpConfirmed, setFpConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const fp = policy?.recoveryFingerprint ?? "";
  const canSubmit = invite && email && password.length >= 8 && password === confirm && fpConfirmed && fp;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policy || !fp) return setErr("Server has no recovery key configured — enrollment is disabled.");
    setBusy(true);
    setErr("");
    try {
      const { request, account } = await Account.enroll({
        inviteToken: invite,
        email,
        displayName: name || email.split("@")[0]!,
        password,
        kdfParams: policy.kdfParams,
        recoveryPublicKey: await recoveryPubFromServer(client),
        recoveryFingerprint: fp,
      });
      const s = await client.register(request);
      client.setTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
      saveSession({
        baseUrl: client.baseUrl,
        userId: s.userId,
        personalVaultId: request.personalVault.vaultId,
        email,
        tokens: { accessToken: s.accessToken, refreshToken: s.refreshToken },
      });
      const store = new VaultStore(client, account);
      await store.sync();
      onReady(account, store);
    } catch (e) {
      setErr(e instanceof ApiError ? enrollError(e.code) : "Enrollment failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit}>
      {err && <div className="msg err">{err}</div>}
      <div className="field">
        <label>Invite token</label>
        <input className="mono" value={invite} onChange={(e) => setInvite(e.target.value)} placeholder="from your administrator" />
      </div>
      <div className="row">
        <div className="field" style={{ flex: 1 }}>
          <label>Email</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        </div>
        <div className="field" style={{ flex: 1 }}>
          <label>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="optional" />
        </div>
      </div>
      <div className="field">
        <label>Master password</label>
        <input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {password && password.length < 8 && <span className="muted">at least 8 characters</span>}
      </div>
      <div className="field">
        <label>Confirm master password</label>
        <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        {confirm && confirm !== password && <span className="muted" style={{ color: "var(--danger)" }}>passwords don't match</span>}
      </div>
      {fp ? (
        <>
          <label>Recovery key fingerprint — confirm it matches your printed sheet</label>
          <div className="fingerprint" style={{ marginBottom: 10 }}>{groupHex(fp)}</div>
          <label className="check">
            <input type="checkbox" checked={fpConfirmed} onChange={(e) => setFpConfirmed(e.target.checked)} />
            <span>This fingerprint matches the recovery sheet. I understand my master password can only be reset with that offline key.</span>
          </label>
        </>
      ) : (
        <div className="msg err">Server has no recovery key configured; enrollment is disabled until the escrow ceremony is done.</div>
      )}
      <button className="primary" disabled={busy || !canSubmit}>{busy ? "Forging your vault…" : "Create vault"}</button>
    </form>
  );
}

// ---- helpers ----

async function recoveryPubFromServer(client: ApiClient): Promise<Uint8Array> {
  // The org recovery PUBLIC key (safe to serve). Its fingerprint is shown and
  // confirmed against the printed sheet before the client seals escrow to it.
  const resp = await fetch(client.baseUrl + "/api/v1/recovery-pubkey");
  if (!resp.ok) throw new ApiError(resp.status, "no_recovery_pubkey", "recovery pubkey unavailable");
  return fromB64((await resp.text()).trim());
}

function groupHex(hex: string): string {
  return hex.replace(/(.{4})/g, "$1 ").trim();
}

function enrollError(code: string): string {
  switch (code) {
    case "invalid_invite": return "That invite token is not valid.";
    case "invite_used": return "That invite has already been used.";
    case "invite_expired": return "That invite has expired.";
    case "email_taken": return "An account with that email already exists.";
    case "escrow_fingerprint_mismatch": return "Recovery fingerprint mismatch — do not proceed; contact your admin.";
    default: return "Enrollment failed (" + code + ").";
  }
}
