import { useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { ClientPolicy } from "../api/types";
import { fromB64 } from "../crypto/bytes";
import { shortFormMatches } from "../crypto/escrow";
import { Account, IdentityMismatchError, deviceName } from "../vault/account";
import { VaultStore } from "../vault/store";
import { NetworkError, POLICY_UNAVAILABLE, UNREACHABLE, net } from "./errors";
import { installId, saveSession, type Session } from "./session";

type Mode = { unlock: Session } | { fresh: true };

/** What the vault shell needs to know about how this session came to be. */
export interface LoginMeta {
  isAdmin: boolean;
  mustChangePassword: boolean;
  // F57: the account's escrow is sealed to a superseded recovery key (re-ceremony) and the
  // client should re-seal on this unlock. escrowFingerprint is the CURRENT org recovery
  // fingerprint (the re-seal target + the value the user verifies against the new sheet).
  escrowStale: boolean;
  escrowFingerprint: string;
}

interface Props {
  client: ApiClient;
  policy: ClientPolicy | null;
  policyError: boolean;
  onRetryPolicy: () => Promise<void>;
  mode: Mode;
  /** F26: one-line reason this screen is showing ("Locked.", revoked, …) — rendered on the card. */
  notice?: string;
  onReady: (account: Account, store: VaultStore, meta: LoginMeta) => void;
  onForget: () => void;
}

export function Welcome({ client, policy, policyError, onRetryPolicy, mode, notice, onReady, onForget }: Props) {
  if ("unlock" in mode) {
    return <Unlock client={client} session={mode.unlock} notice={notice} onReady={onReady} onForget={onForget} />;
  }
  return <FreshStart client={client} policy={policy} policyError={policyError} onRetryPolicy={onRetryPolicy} notice={notice} onReady={onReady} />;
}

/** Reload or F26 lock with an existing session: master password re-derives keys. */
function Unlock({ client, session, notice, onReady, onForget }: { client: ApiClient; session: Session; notice?: string; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void; onForget: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      // net() tags transport failures so a VPN drop / server restart can't be mistaken for
      // a bad password. Account.unlock is the only crypto step and is left un-wrapped, so a
      // throw from it (and only it) is unambiguously "wrong master password".
      const keys = await net(client.accountKeys());
      const account = await Account.unlock(session.userId, password, keys);
      const store = new VaultStore(client, account);
      await net(store.sync()); // rediscovers the personal vault id
      onReady(account, store, { isAdmin: session.isAdmin, mustChangePassword: false, escrowStale: keys.escrowStale ?? false, escrowFingerprint: keys.escrowFingerprint });
    } catch (e) {
      // Only a throw from Account.unlock (the sole un-wrapped, non-ApiError step) may be
      // blamed on the password — EXCEPT its IdentityMismatchError (F31/spec 01 §5),
      // which is a tampering signal and must never be softened into "wrong password".
      // A server that responded with an error is a server problem — the user's
      // password may be perfectly fine.
      setErr(
        e instanceof IdentityMismatchError
          ? e.message
          : e instanceof NetworkError
            ? UNREACHABLE
            : e instanceof ApiError && e.status === 401
              ? "Session expired — sign in again."
              : e instanceof ApiError
                ? "The server had a problem answering — your password may be fine. Try again in a moment."
                : "Wrong master password.",
      );
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
        {/* F26: why the user is here ("Locked after N minutes of inactivity.", …). */}
        {notice && !err && <div className="msg info">{notice}</div>}
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
function FreshStart({ client, policy, policyError, onRetryPolicy, notice, onReady }: { client: ApiClient; policy: ClientPolicy | null; policyError: boolean; onRetryPolicy: () => Promise<void>; notice?: string; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void }) {
  const [tab, setTab] = useState<"signin" | "enroll">("signin");
  return (
    <div className="auth-shell">
      <div className="card">
        <div className="card-hero">
          <div className="sigil">ᛅ</div>
          <h1 className="brand"><span className="a-mark">and</span>vari</h1>
          <p>the keeper of the hoard</p>
        </div>
        {/* F26: why a full sign-in is required ("This device's access was revoked."). */}
        {notice && <div className="msg info">{notice}</div>}
        <div className="tabs">
          <button className={tab === "signin" ? "active" : ""} onClick={() => setTab("signin")}>Sign in</button>
          <button className={tab === "enroll" ? "active" : ""} onClick={() => setTab("enroll")}>Enroll</button>
        </div>
        {tab === "signin" ? <SignIn client={client} onReady={onReady} /> : <Enroll client={client} policy={policy} policyError={policyError} onRetryPolicy={onRetryPolicy} onReady={onReady} />}
      </div>
    </div>
  );
}

function SignIn({ client, onReady }: { client: ApiClient; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [totpNeeded, setTotpNeeded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const pre = await net(client.prelogin(email));
      const authKey = await Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams);
      const code = totp.replace(/\s/g, "");
      // installId (F28): stable per-browser id so repeat sign-ins can share a device row.
      const s = await net(
        client.login(email, authKey, deviceName(), {
          totp: totpNeeded && code ? code : undefined,
          installId: installId(),
        }),
      );
      const account = await Account.unlock(s.userId, password, s.accountKeys);
      const store = new VaultStore(client, account);
      await net(store.sync()); // discovers the personal vault id from grants
      saveSession({
        baseUrl: client.baseUrl,
        userId: s.userId,
        personalVaultId: account.personalVaultId,
        email,
        isAdmin: s.isAdmin,
        tokens: { accessToken: s.accessToken, refreshToken: s.refreshToken },
      });
      onReady(account, store, { isAdmin: s.isAdmin, mustChangePassword: s.mustChangePassword, escrowStale: s.accountKeys.escrowStale ?? false, escrowFingerprint: s.accountKeys.escrowFingerprint });
    } catch (e) {
      if (e instanceof ApiError && e.code === "totp_required") {
        // Break-glass origin (spec 03 §2): the password checked out; the server
        // additionally wants the account's server-TOTP code.
        setTotpNeeded(true);
        setErr("");
      } else if (e instanceof ApiError && e.code === "public_login_requires_totp") {
        setErr("This account has no TOTP enrolled — sign-in from the public address is blocked. Connect from inside (VPN/LAN), enroll TOTP in Settings, then retry.");
      } else if (e instanceof IdentityMismatchError) {
        // F31/spec 01 §5: the password DID check out (login succeeded) — the server sent
        // an identity key our sealed seed does not derive. Never blame the password.
        setErr(e.message);
      } else if (e instanceof NetworkError) {
        setErr(UNREACHABLE);
      } else if (e instanceof ApiError && e.status === 401) {
        setErr(totpNeeded ? "Wrong email, master password, or one-time code." : "Wrong email or master password.");
      } else if (e instanceof ApiError) {
        setErr("The server had a problem answering — your details may be fine. Try again in a moment.");
      } else {
        setErr("Sign-in failed. Please try again.");
      }
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
      {totpNeeded && (
        <div className="field">
          <label>One-time code</label>
          <input
            className="mono"
            autoFocus
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123 456"
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
          />
          <span className="muted">You are connecting via the public address — enter the code from your authenticator app.</span>
        </div>
      )}
      <button className="primary" disabled={busy || !email || !password || (totpNeeded && !totp.trim())}>{busy ? "Unsealing…" : "Sign in"}</button>
    </form>
  );
}

function Enroll({ client, policy, policyError, onRetryPolicy, onReady }: { client: ApiClient; policy: ClientPolicy | null; policyError: boolean; onRetryPolicy: () => Promise<void>; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void }) {
  const [invite, setInvite] = useState("");
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fpConfirmed, setFpConfirmed] = useState(false);
  const [shortFp, setShortFp] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [retrying, setRetrying] = useState(false);

  // Visible feedback for the policy Retry: the label flips to "Retrying…" while the fetch
  // runs; if it fails again the policyError branch simply re-renders (label back to Retry).
  const retryPolicy = async () => {
    setRetrying(true);
    try {
      await onRetryPolicy();
    } finally {
      setRetrying(false);
    }
  };

  const fp = policy?.recoveryFingerprint ?? "";
  // shortFormMatches is false whenever fp is empty (nothing to match), so shortOk already
  // encodes the "server has a recovery key" precondition — no separate `&& fp` needed.
  const shortOk = shortFormMatches(shortFp, fp);
  const canSubmit = invite && email && password.length >= 8 && password === confirm && shortOk && fpConfirmed;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policy || !fp) return setErr(policyError ? POLICY_UNAVAILABLE : "Server has no recovery key configured — enrollment is disabled.");
    setBusy(true);
    setErr("");
    try {
      const { request, account } = await Account.enroll({
        inviteToken: invite,
        email,
        displayName: name || email.split("@")[0]!,
        password,
        kdfParams: policy.kdfParams,
        recoveryPublicKey: await net(recoveryPubFromServer(client)),
        recoveryFingerprint: fp,
        installId: installId(), // F28: same stable id as sign-in
      });
      const s = await net(client.register(request));
      client.setTokens({ accessToken: s.accessToken, refreshToken: s.refreshToken });
      saveSession({
        baseUrl: client.baseUrl,
        userId: s.userId,
        personalVaultId: request.personalVault.vaultId,
        email,
        isAdmin: s.isAdmin,
        tokens: { accessToken: s.accessToken, refreshToken: s.refreshToken },
      });
      const store = new VaultStore(client, account);
      // register() succeeded: the account exists and the invite is CONSUMED. From here on,
      // failure must not bounce back to the enroll form — a resubmit could only ever yield
      // "invite already used". A failed first sync just means an empty view until the vault
      // shell's reconnect logic pulls; proceed.
      await store.sync().catch(() => {});
      onReady(account, store, { isAdmin: s.isAdmin, mustChangePassword: s.mustChangePassword, escrowStale: s.accountKeys.escrowStale ?? false, escrowFingerprint: s.accountKeys.escrowFingerprint });
    } catch (e) {
      setErr(e instanceof NetworkError ? UNREACHABLE : e instanceof ApiError ? enrollError(e.code) : "Enrollment failed.");
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
          {/* spec 04 §2(3): the fingerprint is deliberately NOT displayed until it has been
              typed — showing it above the input would reduce the check to transcription. */}
          <div className="field">
            <label>Recovery check — type the FIRST 16 characters of the fingerprint on your printed recovery sheet</label>
            <input
              className="mono"
              placeholder="from the sheet, not this screen"
              value={shortFp}
              onChange={(e) => setShortFp(e.target.value)}
            />
            {shortFp.trim() && !shortOk && (
              <span className="muted" style={{ color: "var(--danger)" }}>
                doesn't match this server's recovery key — if you copied the sheet correctly, STOP and contact your admin
              </span>
            )}
            {shortOk && <span className="muted">matches — full fingerprint: {groupHex(fp)}</span>}
          </div>
          <label className="check">
            <input type="checkbox" checked={fpConfirmed} onChange={(e) => setFpConfirmed(e.target.checked)} disabled={!shortOk} />
            <span>This fingerprint matches the recovery sheet. I understand my master password can only be reset with that offline key.</span>
          </label>
        </>
      ) : policyError ? (
        // The policy fetch FAILED — don't claim the ceremony isn't done (it may well be),
        // and don't blame the network (the server may have answered with an error).
        <div className="msg err" style={{ display: "block" }}>
          {POLICY_UNAVAILABLE}{" "}
          <button type="button" className="link" disabled={retrying} onClick={retryPolicy}>{retrying ? "Retrying…" : "Retry"}</button>
        </div>
      ) : (
        // Policy loaded and the fingerprint is genuinely empty → the recovery key really
        // isn't configured on this server.
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
