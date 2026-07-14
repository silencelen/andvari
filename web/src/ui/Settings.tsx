import { useEffect, useMemo, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import type { ClientPolicy, TotpSetupResponse, TotpStatus } from "../api/types";
import { backupNudge, readLastExportAt } from "../export/plan";
import { qrModules } from "../vendor/qrcode-generator";
import { Account } from "../vault/account";
import { Busy } from "./Busy";
import { DevicesCard } from "./Devices";
import { UNREACHABLE } from "./errors";
import { Field } from "./Field";
import { fmtDate } from "./format";
import { Announcer, Msg } from "./Msg";
import { QrSvg } from "./QrSvg";
import { MasterPasswordHint } from "./Welcome";
import { meetsMasterPasswordFloor } from "./strength";
import { useThemePref, type ThemePref } from "./useTheme";
import { ViewHeader } from "./ViewHeader";

interface Props {
  client: ApiClient;
  account: Account;
  policy: ClientPolicy | null;
  onPasswordChanged: () => void;
  // IA P3: backups are actionable from here now (the card used to only point at the toolbar).
  // Undefined on the public break-glass origin (export is suppressed there), which also hides
  // the buttons — so the card degrades to describe-only, exactly as before, on that origin.
  onBackup?: () => void;
  onCsv?: () => void;
}

export function Settings({ client, account, policy, onPasswordChanged, onBackup, onCsv }: Props) {
  // IA P2: the install hub (a whole feature) was Settings' last card and dominated it — its own
  // sub-page now, reached from a link, symmetric with how the natives reach Autofill status.
  const [sub, setSub] = useState<"main" | "devices">("main");
  if (sub === "devices") {
    return (
      <div>
        <ViewHeader title="Your devices" actions={<button type="button" className="link" onClick={() => setSub("main")}>‹ Back to settings</button>} />
        <DevicesCard />
      </div>
    );
  }
  return (
    <div>
      <ViewHeader title="Settings" />
      <IdentityCard account={account} />
      <BackupCard account={account} onBackup={onBackup} onCsv={onCsv} />
      <TotpCard client={client} />
      <PasswordCard client={client} account={account} policy={policy} onPasswordChanged={onPasswordChanged} />
      <AppearanceCard />
      <div className="sheet">
        <button type="button" className="link" onClick={() => setSub("devices")}>Get andvari on your other devices →</button>
      </div>
    </div>
  );
}

// ---- backups (spec 07 §2.6 — lastExportAt is recorded LOCALLY, never server-side) ----

function BackupCard({ account, onBackup, onCsv }: { account: Account; onBackup?: () => void; onCsv?: () => void }) {
  const last = readLastExportAt(account.userId);
  const nudge = backupNudge(last);
  return (
    <div className="sheet">
      <h2>Backups</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        An encrypted backup is one file only your backup passphrase can open. This device only
        remembers when it last made one; the server is never told.
      </p>
      <div className="field">
        <label>Last backup</label>
        <div>{last !== null ? fmtDate(last) : "never (on this device)"}</div>
      </div>
      {nudge && <p className="muted">{nudge}</p>}
      {(onBackup || onCsv) && (
        <div className="actions">
          {onBackup && <button type="button" className="ghost" onClick={onBackup}>Back up vault…</button>}
          {onCsv && <button type="button" className="ghost" onClick={onCsv}>Export for another password manager…</button>}
        </div>
      )}
    </div>
  );
}

// ---- identity code (spec 01 §5 — seed-derived fingerprint, for sharing verification) ----

function IdentityCard({ account }: { account: Account }) {
  const [code, setCode] = useState("");
  useEffect(() => {
    // Derived on this device from the decrypted identity seed — never a server value.
    account.identityFingerprintShort().then((fp) => setCode(fp.match(/.{4}/g)!.join(" ")));
  }, [account]);
  return (
    <div className="sheet">
      <h2>Identity code</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        Someone sharing a vault with you will ask you to read this out.
      </p>
      <div className="field">
        {/* BL-2: secret-row (input + copy) is multi-child, so the label can't associate via
            Field — name the inner input directly. */}
        <label>My identity code</label>
        <div className="secret-row">
          <input readOnly className="mono" aria-label="My identity code" value={code || "…"} />
          <CopyButton value={code} />
        </div>
      </div>
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

  // Encode the otpauth URI once per fresh setup — NOT on every confirm-code keystroke.
  const otpModules = useMemo(() => (setup ? qrModules(setup.otpauthUri, "M") : null), [setup]);

  useEffect(() => {
    client.totpStatus().then(setStatus).catch(() => setErr("Couldn't check two-factor sign-in — reload to try again."));
  }, [client]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      await fn();
    } catch (e) {
      // #23 household voice (errors.ts canon): a fetch rejection (TypeError) is transport,
      // never the user's fault; everything else gets the neutral retryable sentence.
      setErr(
        e instanceof ApiError && e.code === "bad_totp_code"
          ? "That code is wrong or expired — try the current one."
          : e instanceof TypeError
            ? UNREACHABLE
            : "Something went wrong — please try again.",
      );
    } finally {
      setBusy(false);
    }
  };

  const begin = () =>
    run(async () => {
      setSetup(await client.totpSetup());
      setCode("");
    });

  // #23 household voice: "break-glass"/"public address" is ops jargon (it stays in code
  // comments) — members hear "outside your home network".
  const confirm = () =>
    run(async () => {
      setStatus(await client.totpConfirm(code.replace(/\s/g, "")));
      setSetup(null);
      setCode("");
      setMsg("Two-factor sign-in is on. Signing in from outside your home network now asks for a one-time code.");
    });

  const disable = () =>
    run(async () => {
      setStatus(await client.totpDisable(code.replace(/\s/g, "")));
      setCode("");
      setMsg("Two-factor sign-in is off. This account can no longer sign in from outside your home network.");
    });

  return (
    <div className="sheet">
      <h2>Two-factor sign-in (server)</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        An extra one-time code the server asks for when you sign in from outside your home
        network. It's separate from your vault's encryption — your master password alone
        still unseals the hoard.
      </p>
      {err && <Msg kind="err">{err}</Msg>}
      {msg && <Msg kind="info">{msg}</Msg>}
      {/* BL-1: the enroll/disable result ("enrolled"/"disabled") is async info — a polite
          region mounted with it already inside is silent, so drive the announce off this
          persistent (always-mounted) region instead. */}
      <Announcer text={msg} />

      {!status ? (
        <p className="muted"><Busy>loading…</Busy></p>
      ) : status.enrolled ? (
        <>
          <div className="msg info">On ✓ — signing in from outside your home network asks for your authenticator code.</div>
          <div className="field">
            <label>One-time code (required to turn off)</label>
            <div className="secret-row">
              <input className="mono" inputMode="numeric" aria-label="One-time code (required to turn off)" placeholder="123 456" value={code} onChange={(e) => setCode(e.target.value)} />
              <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy || !code.trim()} onClick={disable}>
                {busy ? <Busy>Working…</Busy> : "Turn off"}
              </button>
            </div>
          </div>
        </>
      ) : setup ? (
        <>
          <p className="muted">
            Add this to your authenticator app, then confirm with a code. It guards
            sign-ins from outside your home network — without it, this account can't
            sign in from out there at all.
          </p>
          {otpModules && (
            <div className="field">
              <QrSvg modules={otpModules} ariaLabel="Two-factor enrollment QR code" />
              <p className="muted" style={{ marginTop: 6 }}>
                Scan with an authenticator app (Aegis, Google Authenticator…) — or copy the setup link or code below.
              </p>
            </div>
          )}
          {/* #23: "otpauth URI" / "Secret (base32)" were developer labels; the wire shapes
              stay in the values, the labels say what a family member does with them. */}
          <div className="field">
            <label>Setup link (if you can't scan)</label>
            <div className="secret-row">
              <input readOnly className="mono" aria-label="Setup link (if you can't scan)" value={setup.otpauthUri} />
              <CopyButton value={setup.otpauthUri} />
            </div>
          </div>
          <div className="field">
            <label>Setup code (to type into your app)</label>
            <div className="secret-row">
              <input readOnly className="mono" aria-label="Setup code (to type into your app)" value={setup.secretBase32} />
              <CopyButton value={setup.secretBase32} />
            </div>
          </div>
          <div className="field">
            <label>Code from your app</label>
            <div className="secret-row">
              <input className="mono" inputMode="numeric" aria-label="Code from your app" placeholder="123 456" value={code} onChange={(e) => setCode(e.target.value)} />
              <button type="button" className="ghost" disabled={busy || !code.trim()} onClick={confirm}>{busy ? <Busy>Working…</Busy> : "Confirm"}</button>
            </div>
          </div>
        </>
      ) : (
        <>
          {status.pendingSetup && <p className="muted">A setup was started earlier but never finished — turning it on again starts fresh.</p>}
          <button type="button" className="ghost" disabled={busy} onClick={begin}>{busy ? <Busy>Working…</Busy> : "Turn on two-factor sign-in"}</button>
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

  // F60: same master-password floor as enrollment (score≥3), covering the forced-change path.
  const canSubmit = current && meetsMasterPasswordFloor(next) && next === confirm;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!meetsMasterPasswordFloor(next)) return setErr("Choose a stronger new password — mix length with upper/lower case, digits, or symbols."); // F60: enforce, not just disable
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
      setErr(e instanceof KdfPolicyError ? WEAK_KDF_MESSAGE : e instanceof ApiError && e.status === 401 ? "Current master password is wrong." : "Password change failed."); // H1 (spec 05 T1)
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
      {err && <Msg kind="err">{err}</Msg>}
      {msg && <Msg kind="info">{msg}</Msg>}
      {/* BL-1: "password changed — other devices signed out" is async info → persistent region. */}
      <Announcer text={msg} />
      <Field label="Current master password">
        <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
      </Field>
      <Field label="New master password" hint={<MasterPasswordHint password={next} />}>
        <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
      </Field>
      <Field
        label="Confirm new master password"
        hint={confirm && confirm !== next ? <span className="muted" style={{ color: "var(--danger)" }}>passwords don't match</span> : undefined}
      >
        <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </Field>
      <div className="actions">
        {/* UI-audit #24: the double Argon2id derivation here runs multi-second — show motion. */}
        <button className="primary" disabled={busy || !canSubmit}>{busy ? <Busy>Re-forging…</Busy> : "Change password"}</button>
      </div>
    </form>
  );
}

// ---- appearance (UI-audit #26 — user theme override) ----

const THEME_CHOICES: Array<{ value: ThemePref; label: string }> = [
  { value: "auto", label: "Match my device" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

function AppearanceCard() {
  const [pref, setPref] = useThemePref();
  return (
    <div className="sheet">
      <h2>Appearance</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        "Match my device" follows your device's light/dark setting. Picking one keeps
        andvari that way in this browser only — your other devices choose for themselves.
      </p>
      <div className="tabs" role="group" aria-label="Theme" style={{ maxWidth: 400, marginBottom: 0 }}>
        {THEME_CHOICES.map(({ value, label }) => (
          <button key={value} type="button" className={pref === value ? "active" : ""} aria-pressed={pref === value} onClick={() => setPref(value)}>
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}
