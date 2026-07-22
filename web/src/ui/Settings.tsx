import { useEffect, useMemo, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import type { ClientPolicy, TotpSetupResponse, TotpStatus } from "../api/types";
import { backupNudge, readLastExportAt } from "../export/plan";
import { qrModules } from "../vendor/qrcode-generator";
import { Account } from "../vault/account";
import type { VaultStore } from "../vault/store";
import { Busy } from "./Busy";
import { DevicesCard } from "./Devices";
import { UNREACHABLE } from "./errors";
import { Field } from "./Field";
import { fmtDate, humanSize } from "./format";
import { Announcer, Msg } from "./Msg";
import { QrSvg } from "./QrSvg";
import { MasterPasswordHint } from "./Welcome";
import {
  orgOfflineCacheDisallowed,
  refreshCachedAccountKeys,
  setOfflineCopyEnabled,
  webCacheEnabled,
  wipeVaultCache,
} from "./session";
import { meetsMasterPasswordFloor } from "./strength";
import { useThemePref, type ThemePref } from "./useTheme";
import { ViewHeader } from "./ViewHeader";

interface Props {
  client: ApiClient;
  account: Account;
  /** design 2026-07-13-web-offline-cache §E.3.4: the Offline-copy card reads the live cache state
   *  (cacheDurable/cacheDemoted/lastSyncAt/queuedMutationCount) from the store — the store owns the
   *  live truth while a vault is open (session.pendingSyncCount is the signed-out choke-point twin). */
  store: VaultStore;
  policy: ClientPolicy | null;
  onPasswordChanged: () => void;
  // IA P3: backups are actionable from here now (the card used to only point at the toolbar).
  // Kept optional for the describe-only degradation, but Vault passes both whenever unlocked —
  // the break-glass export suppression is gone (design 2026-07-15 §5.4.2).
  onBackup?: () => void;
  onCsv?: () => void;
}

export function Settings({ client, account, store, policy, onPasswordChanged, onBackup, onCsv }: Props) {
  // IA P2: the install hub (a whole feature) was Settings' last card and dominated it — its own
  // sub-page now, reached from a link, symmetric with how the natives reach Autofill status.
  const [sub, setSub] = useState<"main" | "devices">("main");
  if (sub === "devices") {
    return (
      <div>
        <ViewHeader title="Your devices" actions={<button type="button" className="link" onClick={() => setSub("main")}>‹ Back to settings</button>} />
        <DevicesCard canonicalOrigin={policy?.canonicalOrigin} />
      </div>
    );
  }
  return (
    <div>
      <ViewHeader title="Settings" />
      <IdentityCard account={account} />
      <BackupCard account={account} onBackup={onBackup} onCsv={onCsv} />
      <OfflineCopyCard store={store} userId={account.userId} />
      <TotpCard client={client} policy={policy} />
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

// ---- offline copy (design 2026-07-13-web-offline-cache §E.3/§B.5 — device-local, never server) ----

/** Everything the Offline-copy card renders, assembled once per (re-)load. Pure data so the
 *  card body is a static function of it (the repo's node-env test posture — see offline-copy-card.test.ts). */
export interface OfflineCopyModel {
  /** webCacheEnabled(userId) — the §F.1 gate: consented ON for THIS device + user (design 2026-07-15
   *  §5.4.1: per-device opt-in, default OFF, on every origin). */
  enabled: boolean;
  /** §E.4: org policy pins the cache off (last-known bit) — explains the missing toggle. */
  orgDisallowed: boolean;
  /** store.cacheDurable — a durable cache is attached to the LIVE session. */
  durable: boolean;
  /** store.cacheDemoted — the §D.1 stuck-cache breaker fired (storage error) this session. */
  demoted: boolean;
  /** store.lastSyncAt — the freshness stamp (§E.3.4). */
  lastSyncAt: number | null;
  /** navigator.storage.persisted() — eviction protection (§B.5); null = unknown/unsupported. */
  persisted: boolean | null;
  /** navigator.storage.estimate().usage — DISPLAY ONLY (§B.5: never enforced), origin-wide; null = unsupported. */
  usageBytes: number | null;
  /** store.queuedMutationCount() — unsynced offline edits a wipe would destroy (breaker #9). */
  queued: number;
}

/** Assemble the card's model from the frozen store surface + navigator.storage (both display-only
 *  best-effort: any probe failure degrades to "unknown", never a broken card). Exported for tests. */
export async function offlineCopyModel(
  store: Pick<VaultStore, "cacheDurable" | "cacheDemoted" | "lastSyncAt" | "queuedMutationCount">,
  userId: string,
): Promise<OfflineCopyModel> {
  let persisted: boolean | null = null;
  let usageBytes: number | null = null;
  try {
    const s = typeof navigator !== "undefined" ? navigator.storage : undefined;
    if (typeof s?.persisted === "function") persisted = (await s.persisted()) === true;
    if (typeof s?.estimate === "function") {
      const e = await s.estimate();
      usageBytes = typeof e?.usage === "number" ? e.usage : null;
    }
  } catch {
    /* display-only — unknown is an honest answer */
  }
  let queued = 0;
  try {
    queued = await store.queuedMutationCount();
  } catch {
    /* a count failure must never break the card (session.pendingSyncCount posture) */
  }
  return {
    enabled: webCacheEnabled(userId),
    orgDisallowed: orgOfflineCacheDisallowed(),
    durable: store.cacheDurable,
    demoted: store.cacheDemoted,
    lastSyncAt: store.lastSyncAt,
    persisted,
    usageBytes,
    queued,
  };
}

/**
 * The card body — a pure function of the model (exported for the static-render tests). ALWAYS
 * renders (design 2026-07-15 §5.4.3: the origin gate is gone — the card, with its default-off
 * toggle, is the standing consent entry point on every origin). States:
 *  - org-disallowed ⇒ the policy explanation, no toggle (the wipe already ran, §E.4);
 *  - demoted ⇒ the §D.1 "offline copy unavailable — storage error" row;
 *  - enabled+durable ⇒ last-synced / eviction-protection / size / queued rows + wipe-now;
 *  - enabled but not (yet) durable ⇒ "ready after your next unlock" (toggle just flipped ON,
 *    or this session's unlock degraded cache-less);
 *  - not enabled ⇒ the unchecked opt-in toggle (per-device consent, default OFF — §5.4.1).
 */
export function OfflineCopyBody({
  model,
  busy,
  notice,
  onToggle,
  onWipe,
}: {
  model: OfflineCopyModel;
  busy: boolean;
  notice: string;
  onToggle: (enabled: boolean) => void;
  onWipe: () => void;
}) {
  return (
    <div className="sheet">
      <h2>Offline copy</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        An encrypted copy of your vault kept in this browser, so you can open it even when the
        server can't be reached. Everything in it stays sealed — only your master password can
        open it, and your password itself is never stored.
      </p>
      {notice && <Msg kind="info">{notice}</Msg>}
      {/* BL-1 idiom: toggle/wipe results are async info — announce off a persistent region. */}
      <Announcer text={notice} />
      {model.orgDisallowed ? (
        <p className="muted">
          Offline copies are turned off by your household's policy — this device keeps none.
        </p>
      ) : (
        <>
          <label className="check">
            <input
              type="checkbox"
              checked={model.enabled}
              disabled={busy}
              onChange={(e) => onToggle(e.target.checked)}
            />
            <span>Keep an offline copy on this device</span>
          </label>
          {model.demoted && (
            <Msg kind="err">
              Offline copy unavailable — storage error. This browser couldn't keep the copy up to
              date, so it was removed for this session; it will be re-created at your next unlock.
            </Msg>
          )}
          {model.enabled && !model.demoted && !model.durable && (
            <p className="muted">
              Your offline copy will be ready after your next unlock or sign-in on this device.
            </p>
          )}
          {model.enabled && model.durable && (
            <>
              <div className="field">
                <label>Last synced</label>
                <div>{model.lastSyncAt !== null ? fmtDate(model.lastSyncAt) : "not yet"}</div>
              </div>
              <div className="field">
                <label>Protected from eviction</label>
                <div>
                  {model.persisted === null
                    ? "unknown (this browser doesn't say)"
                    : model.persisted
                      ? "yes"
                      : "best-effort — the browser may clear it under storage pressure"}
                </div>
              </div>
              {model.usageBytes !== null && (
                <div className="field">
                  <label>Storage used (all of andvari in this browser, approximate)</label>
                  <div>{humanSize(model.usageBytes)}</div>
                </div>
              )}
              {model.queued > 0 && (
                <div className="field">
                  <label>Waiting to sync</label>
                  <div>{model.queued === 1 ? "1 change waiting to sync" : `${model.queued} changes waiting to sync`}</div>
                </div>
              )}
              <div className="actions">
                <button
                  type="button"
                  className="ghost"
                  style={{ color: "var(--danger)" }}
                  disabled={busy}
                  onClick={onWipe}
                >
                  {busy ? <Busy>Working…</Busy> : "Remove the offline copy now"}
                </button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

/**
 * breaker #9 posture: destroying the cache destroys the QUEUE — a user erasing their own unsynced
 * edits gets a blocking confirm (same styling contract as App.signOut). The count is RE-READ at
 * click time from the live store — it reads the SHARED per-account DB, so edits another tab queued
 * after this card mounted are counted too. Gating on the mount-time model would stale-zero those
 * and skip the confirm, silently destroying that tab's unsynced edits (S5 review F2 — App.signOut
 * already re-reads pendingSyncCount at click time; this is its in-vault twin). A failing re-read
 * falls back to the mount-time count: a stale confirm beats a skipped one, and a count failure
 * must never wedge the control. Exported for tests; `ask` defaults to window.confirm, and
 * confirm-less environments proceed (the historical non-browser fall-through).
 */
export async function confirmQueueLoss(
  store: Pick<VaultStore, "queuedMutationCount">,
  mountCount: number,
  ask?: (message: string) => boolean,
): Promise<boolean> {
  let queued = mountCount;
  try {
    queued = await store.queuedMutationCount();
  } catch {
    /* count unreadable — the mount-time count still gates */
  }
  if (queued === 0) return true;
  const confirm =
    ask ?? (typeof window !== "undefined" && typeof window.confirm === "function" ? window.confirm.bind(window) : null);
  if (!confirm) return true;
  return confirm(
    `${queued} unsynced ${queued === 1 ? "change" : "changes"} on this device will be permanently lost. Continue?`,
  );
}

function OfflineCopyCard({ store, userId }: { store: VaultStore; userId: string }) {
  const [model, setModel] = useState<OfflineCopyModel | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  // (Re-)assemble the model; guarded so a slow probe never lands state on an unmounted card.
  useEffect(() => {
    let alive = true;
    void offlineCopyModel(store, userId).then((m) => {
      if (alive) setModel(m);
    });
    return () => {
      alive = false;
    };
  }, [store, userId]);

  if (!model) return null; // first probe still in flight — the card appears fully formed

  const refresh = async () => setModel(await offlineCopyModel(store, userId));

  const toggle = async (enabled: boolean) => {
    if (!enabled && !(await confirmQueueLoss(store, model.queued))) return;
    setBusy(true);
    setNotice("");
    try {
      await setOfflineCopyEnabled(userId, enabled);
      // CR-01: turning the copy OFF just deleted this account's cache DB out from under the LIVE
      // store's open handle. Demote it synchronously so — even before the versionchange callback
      // lands — a save()/remove() this session can't black-hole into the now-dead handle.
      if (!enabled) store.demoteCache();
      setNotice(
        enabled
          ? "Offline copy turned on — it will be created at your next unlock or sign-in."
          : "Offline copy removed from this device.",
      );
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const wipe = async () => {
    if (!(await confirmQueueLoss(store, model.queued))) return;
    setBusy(true);
    setNotice("");
    try {
      await wipeVaultCache(userId);
      // CR-01: the DB the live store held is gone — sever the store from the dead handle now so a
      // later write routes to the real send instead of no-oping into it (the versionchange callback
      // does this too; this is the synchronous belt).
      store.demoteCache();
      setNotice(
        "Offline copy removed. It will be re-created at your next unlock — turn the toggle off to keep this device clean.",
      );
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  return (
    <OfflineCopyBody
      model={model}
      busy={busy}
      notice={notice}
      onToggle={(e) => void toggle(e)}
      onWipe={() => void wipe()}
    />
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

// ---- server TOTP (spec 03 §2 — optional second factor, verified at every sign-in) ----

function TotpCard({ client, policy }: Pick<Props, "client" | "policy">) {
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

  // §2.6 model: an enrolled second factor is verified on EVERY sign-in, every origin —
  // the copy says "every sign-in", never the retired "outside your home network" framing.
  // (An armed break-glass origin is the only place location still matters; its refusal
  // copy lives in Welcome.tsx / HouseholdCopy.PUBLIC_LOGIN_REQUIRES_TOTP.)
  const confirm = () =>
    run(async () => {
      setStatus(await client.totpConfirm(code.replace(/\s/g, "")));
      setSetup(null);
      setCode("");
      setMsg("Two-factor sign-in is on. Every sign-in now also asks for a code from your authenticator app.");
    });

  const disable = () =>
    run(async () => {
      setStatus(await client.totpDisable(code.replace(/\s/g, "")));
      setCode("");
      setMsg(
        policy?.totpRequired
          ? "Two-factor sign-in is off. This server requires it, so your next sign-in will ask you to set it up again."
          : "Two-factor sign-in is off. Signing in now asks only for your master password.",
      );
    });

  return (
    <div className="sheet">
      <h2>Two-factor sign-in (server)</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        An extra one-time code the server asks for each time you sign in. Recommended:
        even someone who learns your master password can't sign in without your
        authenticator. It's separate from your vault's encryption — your master password
        alone still unseals the hoard.
      </p>
      {policy?.totpRequired && (
        <p className="muted">This server requires two-factor sign-in for every account.</p>
      )}
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
          <div className="msg info">On ✓ — every sign-in asks for your authenticator code.</div>
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
            Add this to your authenticator app, then confirm with a code. From then on,
            signing in asks for your current code alongside your master password.
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

function PasswordCard({ client, account, policy, onPasswordChanged }: Pick<Props, "client" | "account" | "policy" | "onPasswordChanged">) {
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
      // §D.2c/§E.4 (S3-2): the durable offline cache still holds the OLD kdfSalt/kdfParams/wrappedUvk,
      // so an offline unlock would reject the NEW password while the OLD (possibly compromised) one
      // still opens the cached vault until the next online unlock (the spec 05 T3 window). Refresh it
      // with the post-change accountKeys. Best-effort + gated (never creates a cache where caching is
      // off) — see session.refreshCachedAccountKeys; a cache failure never fails the committed change.
      await refreshCachedAccountKeys(client, account.userId);
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
