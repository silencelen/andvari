import { useEffect, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { ClientPolicy, TotpSetupResponse, TotpStatus } from "../api/types";
import { Account } from "../vault/account";

interface Props {
  client: ApiClient;
  account: Account;
  policy: ClientPolicy | null;
  onPasswordChanged: () => void;
}

export function Settings({ client, account, policy, onPasswordChanged }: Props) {
  return (
    <div>
      <h2 className="view-title" style={{ margin: "22px 0 4px" }}>Settings</h2>
      <TotpCard client={client} />
      <PasswordCard client={client} account={account} policy={policy} onPasswordChanged={onPasswordChanged} />
    </div>
  );
}

/** One-shot clipboard copy with a transient "copied" flash. */
function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [flash, setFlash] = useState(false);
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    setFlash(true);
    window.setTimeout(() => setFlash(false), 1200);
  };
  return <button type="button" className="ghost" onClick={copy}>{flash ? "Copied ✓" : label}</button>;
}

// ---- server TOTP (spec 03 §2 — protects break-glass/public logins) ----

function TotpCard({ client }: { client: ApiClient }) {
  const [status, setStatus] = useState<TotpStatus | null>(null);
  const [setup, setSetup] = useState<TotpSetupResponse | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  useEffect(() => {
    client.totpStatus().then(setStatus).catch(() => setErr("Could not load TOTP status."));
  }, [client]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      await fn();
    } catch (e) {
      setErr(e instanceof ApiError && e.code === "bad_totp_code" ? "That code is wrong or expired — try the current one." : "Request failed.");
    } finally {
      setBusy(false);
    }
  };

  const begin = () =>
    run(async () => {
      setSetup(await client.totpSetup());
      setCode("");
    });

  const confirm = () =>
    run(async () => {
      setStatus(await client.totpConfirm(code.replace(/\s/g, "")));
      setSetup(null);
      setCode("");
      setMsg("Server TOTP enrolled. Public (break-glass) sign-ins now require a one-time code.");
    });

  const disable = () =>
    run(async () => {
      setStatus(await client.totpDisable(code.replace(/\s/g, "")));
      setCode("");
      setMsg("Server TOTP disabled. This account can no longer sign in from the public address.");
    });

  return (
    <div className="sheet">
      <h2>Two-factor (server TOTP)</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        A second factor checked by the server on break-glass sign-ins from the public internet.
        It is separate from your vault crypto — your master password alone still unseals the hoard.
      </p>
      {err && <div className="msg err">{err}</div>}
      {msg && <div className="msg info">{msg}</div>}

      {!status ? (
        <p className="muted">loading…</p>
      ) : status.enrolled ? (
        <>
          <div className="msg info">Enrolled ✓ — public sign-ins require your authenticator code.</div>
          <div className="field">
            <label>One-time code (required to disable)</label>
            <div className="secret-row">
              <input className="mono" inputMode="numeric" placeholder="123 456" value={code} onChange={(e) => setCode(e.target.value)} />
              <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy || !code.trim()} onClick={disable}>
                {busy ? "Working…" : "Disable"}
              </button>
            </div>
          </div>
        </>
      ) : setup ? (
        <>
          <p className="muted">
            Add this to your authenticator app, then confirm with a code. This protects
            break-glass/public logins — without it enrolled, this account cannot sign in
            from the public address at all.
          </p>
          <div className="field">
            <label>otpauth URI</label>
            <div className="secret-row">
              <input readOnly className="mono" value={setup.otpauthUri} />
              <CopyButton value={setup.otpauthUri} />
            </div>
          </div>
          <div className="field">
            <label>Secret (base32)</label>
            <div className="secret-row">
              <input readOnly className="mono" value={setup.secretBase32} />
              <CopyButton value={setup.secretBase32} />
            </div>
          </div>
          <div className="field">
            <label>Code from your app</label>
            <div className="secret-row">
              <input className="mono" inputMode="numeric" placeholder="123 456" value={code} onChange={(e) => setCode(e.target.value)} />
              <button type="button" className="ghost" disabled={busy || !code.trim()} onClick={confirm}>{busy ? "Working…" : "Confirm"}</button>
            </div>
          </div>
        </>
      ) : (
        <>
          {status.pendingSetup && <p className="muted">A previous setup was started but never confirmed — enabling again generates a fresh secret.</p>}
          <button type="button" className="ghost" disabled={busy} onClick={begin}>{busy ? "Working…" : "Enable TOTP"}</button>
        </>
      )}
    </div>
  );
}

// ---- master password change (spec 01 §6 — UVK never rotates) ----

function PasswordCard({ client, account, policy, onPasswordChanged }: Props) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  const canSubmit = current && next.length >= 8 && next === confirm;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      const keys = await client.accountKeys();
      const currentAuthKey = await Account.deriveAuthKey(current, keys.kdfSalt, keys.kdfParams);
      const change = await account.buildPasswordChange(next, policy?.kdfParams ?? keys.kdfParams);
      await client.changePassword({ currentAuthKey, ...change });
      setCurrent("");
      setNext("");
      setConfirm("");
      setMsg("Master password changed — sessions on other devices were signed out.");
      onPasswordChanged();
    } catch (e) {
      setErr(e instanceof ApiError && e.status === 401 ? "Current master password is wrong." : "Password change failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="sheet" onSubmit={submit}>
      <h2>Change master password</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Your vault keys stay the same — only the password that wraps them changes.
        All other devices are signed out and will need the new password.
      </p>
      {err && <div className="msg err">{err}</div>}
      {msg && <div className="msg info">{msg}</div>}
      <div className="field">
        <label>Current master password</label>
        <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
      </div>
      <div className="field">
        <label>New master password</label>
        <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        {next && next.length < 8 && <span className="muted">at least 8 characters</span>}
      </div>
      <div className="field">
        <label>Confirm new master password</label>
        <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        {confirm && confirm !== next && <span className="muted" style={{ color: "var(--danger)" }}>passwords don't match</span>}
      </div>
      <div className="actions">
        <button className="primary" disabled={busy || !canSubmit}>{busy ? "Re-forging…" : "Change password"}</button>
      </div>
    </form>
  );
}
