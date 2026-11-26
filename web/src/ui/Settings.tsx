import { useEffect, useMemo, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import { KdfPolicyError } from "../crypto/keys";
import type { TotpSetupResponse, TotpStatus } from "../api/types";
import type { ClientPolicyV2 as ClientPolicy } from "../api/wire";
import { backupNudge, readLastExportAt } from "../export/plan";
import { qrModules } from "../vendor/qrcode-generator";
import { Account, ReauthFailedError, ReauthStaleSessionError } from "../vault/account";
import { PasswordRuleRefused } from "../vault/kitflow";
import { SERVER_REFUSED_PROOF, TWO_STEP_CHECK_FAILED, TWO_STEP_QR_LABEL, TWO_STEP_REQUIRED_HERE, TWO_STEP_SECRET_CLEARS, TWO_STEP_TITLE, TWO_STEP_TURN_ON, TWO_STEP_TURNED_ON } from "./copy";
import { fill, kdfRefusalText, OFFLINE_COPY_ABOUT, passwordRuleText, OFFLINE_COPY_LIMIT, OFFLINE_SETTINGS_WAIT, SERVER_KEYS_NOT_KNOWN_SETTINGS, TOTP_OFF_PASSWORD_LABEL, TOTP_WRONG_CODE, TOTP_WRONG_PASSWORD } from "./copy";
import { UNSENT_ALL_SENT, UNSENT_SEND_FIRST, UNSENT_SEND_FIRST_FAILED, unsentLine } from "./copy";
import { unsentArmStep } from "./SignOutLink";
import type { VaultStore } from "../vault/store";
import { BackLink } from "./BackLink";
import { Busy } from "./Busy";
import { scheduleClipboardClear, writeClipboard } from "./clipboard";
import { DeleteAccountCard, type DeletionEnd, type DeletionTrack } from "./DeleteAccount";
import { DevicesCard } from "./Devices";
import { AccountDevicesCard } from "./AccountDevices";
import { RecoveryPostureCard } from "./RecoveryPostureCard";
import { RotateKitCard } from "./KitCard";
import { changePassword, NO_SESSION_WRAP, type SettingsSession, setUpTwoStep, turnOffTwoStep, type TwoStepOff, type TwoStepSetup } from "../vault/settingsflow";
import { passwordChangedText, passwordChangeText, twoStepOffText, twoStepSetupText, waitText } from "./reauthtext";
import { answerLimitText, CLIPBOARD_FAILED, CLIPBOARD_NOT_CLEARED, UNREACHABLE } from "./errors";
import { Field } from "./Field";
import { fmtDate, humanSize } from "./format";
import { Announcer, Msg } from "./Msg";
import { QrSvg } from "./QrSvg";
import { MasterPasswordHint } from "./passwordadvice";
import { clampClipboardClearSeconds } from "./policyclamp";
import {
  orgOfflineCacheDisallowed,
  setOfflineCopyEnabled,
  webCacheEnabled,
  wipeVaultCache,
} from "./session";
import { meetsMasterPasswordFloor } from "./strength";
import { useThemePref, type ThemePref } from "./useTheme";
import { ViewHeader } from "./ViewHeader";
import { PersonalVaultCard } from "./Household";
import { quotaLineText } from "./quotatext";

interface Props {
  client: ApiClient;
  account: Account;
  /** The session the post-cut-over Settings flows act for (vault/settingsflow.ts); absent in old callers. */
  settings?: SettingsSession;
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
  /** Account deletion (spec 03 §13): the signed-in address the typed confirmation must match ("" = unknown). */
  email?: string;
  /** This browser should forget the account — the server confirmed its deletion, or the member chose to after an unknown
   *  outcome left the account unable to sign in: App wipes this browser's state for it and lands signed out. */
  onAccountDeleted?: (end: DeletionEnd) => void;
  /** The deletion request's lifecycle, so App holds back a session end that lands while it is in flight. */
  onDeletionTrack?: (event: DeletionTrack) => void;
  /** A deletion blocker's link: the owned vault's settings under Sharing (transfer / delete live there). */
  onOpenVaultSettings?: (vaultId: string) => void;
  /** The last-admin blocker's link (admins only). */
  onOpenAdmin?: () => void;
  /**
   * The vault was opened from this browser's offline copy and no sync has landed since (spec 02 §8): the cards that need
   * the server are shown disabled under one line that says why, and come back when a sync lands.
   */
  offline?: boolean;
}

export function Settings({ client, account, store, policy, onPasswordChanged, onBackup, onCsv, email, onAccountDeleted, onDeletionTrack, onOpenVaultSettings, onOpenAdmin, settings, offline = false }: Props) {
  // IA P2: the install hub (a whole feature) was Settings' last card and dominated it — its own
  // sub-page now, reached from a link, symmetric with how the natives reach Autofill status.
  const [sub, setSub] = useState<"main" | "devices">("main");
  const keysNotKnown = settings?.wrap?.serverKeysNotKnown === true;
  if (sub === "devices") {
    return (
      <div>
        <ViewHeader title="Your devices" actions={<BackLink label="Back to settings" onClick={() => setSub("main")} />} />
        <DevicesCard canonicalOrigin={policy?.canonicalOrigin} client={client} />
      </div>
    );
  }
  return (
    <div>
      <ViewHeader title="Settings" />
      <PersonalVaultCard account={account} store={store} />
      <QuotaLine store={store} />
      <BackupCard account={account} onBackup={onBackup} onCsv={onCsv} />
      <OfflineCopyCard store={store} userId={account.userId} />
      {offline && <div className="msg info" style={{ display: "block", marginTop: 16 }} role="status">{OFFLINE_SETTINGS_WAIT}</div>}
      {/* Spec 01 §7, "leaves both": while the session is marked, every action below proves the master password to a
          server that serves keys this browser does not know, and would be refused. They are shown unavailable, under one
          line that says why, instead of offered and then refused. */}
      {!offline && keysNotKnown && <div className="msg info" style={{ display: "block", marginTop: 16 }} role="status">{SERVER_KEYS_NOT_KNOWN_SETTINGS}</div>}
      {/* The cards below need the server. Keyed on `offline` so that they load again once a sync lands. */}
      <fieldset key={offline ? "offline" : "online"} className="needs-server" disabled={offline || keysNotKnown}>
        <TotpCard client={client} policy={policy} account={account} settings={settings} offline={offline} />
        {settings && <PasswordCard account={account} policy={policy} onPasswordChanged={onPasswordChanged} settings={settings} />}
        {settings && <AccountDevicesCard settings={settings} offline={offline} />}
        {settings && <RotateKitCard settings={settings} />}
        {settings && store.sharedLogs() !== null && <RecoveryPostureCard settings={settings} shared={store.sharedLogs()!} />}
      </fieldset>
      <AppearanceCard />
      <div className="sheet">
        <button type="button" className="link" onClick={() => setSub("devices")}>Get andvari on your other devices →</button>
      </div>
      {/* Spec 03 §13 (store policy: in-app account deletion). Last on the page, where the irreversible action belongs. */}
      {onAccountDeleted && (
        <fieldset key={offline ? "delete-offline" : "delete-online"} className="needs-server" disabled={offline || keysNotKnown}>
        <DeleteAccountCard
          client={client}
          account={account}
          store={store}
          settings={settings}
          shared={store.sharedLogs()}
          email={email ?? ""}
          onDeleted={onAccountDeleted}
          onTrack={onDeletionTrack}
          onOpenVaultSettings={onOpenVaultSettings ?? (() => {})}
          onOpenAdmin={onOpenAdmin}
          onBackup={onBackup}
        />
        </fieldset>
      )}
    </div>
  );
}

/** Spec 03 §14.4: the account's own use and limits, as the newest sync served them; nothing when it served none. */
function QuotaLine({ store }: { store: VaultStore }) {
  const line = quotaLineText(store.quota());
  if (line === null) return null;
  return (
    <div className="sheet">
      <p className="muted" style={{ margin: 0 }}>{line}</p>
    </div>
  );
}

/** What the two-step card says when a step failed. */
export function totpErrorText(e: unknown): string {
  const limit = answerLimitText(e);
  if (limit !== null) return limit;
  // #23 household voice (errors.ts canon): a fetch rejection (TypeError) is transport, never the user's fault; everything
  // else gets the neutral retryable sentence.
  if (e instanceof ApiError && e.code === "bad_totp_code") return TOTP_WRONG_CODE;
  if (e instanceof ReauthFailedError) return TOTP_WRONG_PASSWORD;
  // Spec 01 §7: a proof the server refused was made here first (a wrong password is the line above, and sends nothing).
  if (e instanceof ApiError && e.code === "reauth_failed") return SERVER_REFUSED_PROOF;
  // The proofs' own back-off and the codes' (spec 03, 2026-11-16; neither blocks a sign-in), and the per-minute limit:
  // "too many tries" with the wait the server named (the sign-in back-off's sentence when it named none), never
  // "wrong password", and nothing is retried by itself.
  if (e instanceof ApiError && e.status === 429) return waitText(e.retryAfterS);
  if (e instanceof ReauthStaleSessionError) return e.message;
  if (e instanceof KdfPolicyError) return kdfRefusalText(e);
  if (e instanceof PasswordRuleRefused) return passwordRuleText(e.decision);
  if (e instanceof TypeError) return UNREACHABLE;
  return "Something went wrong — please try again.";
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
  pendingConfirm,
  onToggle,
  onWipe,
  onConfirm,
  onCancelConfirm,
  onSendFirst,
}: {
  model: OfflineCopyModel;
  busy: boolean;
  notice: string;
  /** H135: the armed destructive confirm — the inline row that replaced `window.confirm`.
   *  null = nothing armed. `verb` labels the button that actually does the destroying. */
  pendingConfirm: { question: string; verb: string } | null;
  onToggle: (enabled: boolean) => void;
  onWipe: () => void;
  onConfirm: () => void;
  onCancelConfirm: () => void;
  /** Design §4.4: "try sending them first", offered in the armed confirm where sending is possible (absent: it is not). */
  onSendFirst?: () => void;
}) {
  return (
    <div className="sheet">
      <h2>Offline copy</h2>
      {/* H48: the promise is QUALIFIED to what this client can actually keep. The offline copy is
          an IndexedDB envelope cache the unlock path reads without the server — but reaching the
          unlock card at all still needs index.html and the hashed bundle, and the web app ships no
          service-worker shell (design 2026-07-13-web-offline-cache D1, whose F.4 defers it). So a
          FRESH tab opened while the server is down gets the browser's own "site can't be reached"
          and never renders andvari at all. Promising more than that is the worst kind of untrue:
          the member turns the toggle on FOR the outage, and the failure mode gives them no hint
          that their vault copy is intact. The natives (Android/desktop) genuinely open cold offline
          and keep their own, stronger sentence — this qualification is the web's alone.

          R04: the sentence names the MECHANISM ("a fresh tab", "loads from nothing"), not the form
          factor, because web/public/manifest.webmanifest ships `display: standalone` — a member can
          install this browser copy to an Android home screen, where it looks exactly like the phone
          app the old wording said DID open cold. Same code, same limitation: no service-worker
          shell means the launcher icon gets the browser's error page too. "The andvari apps you
          install" is the honest boundary until D1 ships. */}
      <p className="muted" style={{ marginTop: 0 }}>{OFFLINE_COPY_ABOUT}</p>
      <p className="muted">{OFFLINE_COPY_LIMIT}</p>
      {notice && <Msg kind="info">{notice}</Msg>}
      {/* BL-1 idiom: toggle/wipe results AND the armed confirm are async info — announce both
          off this one persistent region (an armed confirm the SR user never hears is no confirm). */}
      <Announcer text={pendingConfirm ? pendingConfirm.question : notice} />
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
          {/* H135: destroying the copy destroys the QUEUE with it, so the loss is confirmed — but
              in the house inline idiom (Vault's Delete forever, Sharing's Leave/Delete vault),
              not the native dialog F07 shipped. It sits directly under the control it guards, so
              the sentence and the thing it is about are in the same place; the persistent
              Announcer carries it to AT, which a native dialog never could. */}
          {pendingConfirm && (
            <div className="confirm-row">
              <span>{pendingConfirm.question}</span>
              {onSendFirst && (
                <button type="button" className="ghost" disabled={busy} onClick={onSendFirst}>
                  {UNSENT_SEND_FIRST}
                </button>
              )}
              <button
                type="button"
                className="ghost"
                style={{ color: "var(--danger)" }}
                disabled={busy}
                onClick={onConfirm}
              >
                {pendingConfirm.verb}
              </button>
              <button type="button" className="ghost" disabled={busy} onClick={onCancelConfirm}>
                Keep it
              </button>
            </div>
          )}
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
 * edits must be told before it happens. This returns the SENTENCE that confirm has to carry, or
 * null when there is nothing to lose and the action should just run.
 *
 * H135 changed the shape, not the gate: it used to call `window.confirm` itself and answer
 * yes/no. It now hands the question back so the card can arm the house's inline two-step confirm
 * (no native dialogs — the Editor's rule), which is themable, non-blocking, and reachable by the
 * persistent Announcer. The count is still RE-READ at click time from the live store — it reads
 * the SHARED per-account DB, so edits another tab queued after this card mounted are counted too.
 * Gating on the mount-time model would stale-zero those and skip the confirm, silently destroying
 * that tab's unsynced edits (S5 review F2 — App.signOut's twin gate re-reads the same way).
 * Design §4.4 (decided on 2026-11-17): the count is the shared code's (the queue and the vaults held
 * back), and a failing re-read is said as "this browser can't tell" and still asks: a count failure
 * is never said as none, and never a number it did not read.
 */
export async function queueLossQuestion(store: Pick<VaultStore, "unsentChangeCount">): Promise<{ question: string; unsent: number | null } | null> {
  let unsent: number | null;
  try {
    unsent = await store.unsentChangeCount();
  } catch {
    unsent = null;
  }
  const question = unsentLine(unsent);
  return question === undefined ? null : { question, unsent };
}

function OfflineCopyCard({ store, userId }: { store: VaultStore; userId: string }) {
  const [model, setModel] = useState<OfflineCopyModel | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  // H135: the armed inline confirm. `run` is the destructive action the second click performs —
  // held here (not re-derived) so the confirm and the deed can never drift apart.
  const [pendingConfirm, setPendingConfirm] = useState<{ question: string; unsent: number | null; verb: string; run: () => Promise<void> } | null>(null);

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

  const toggleNow = async (enabled: boolean) => {
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

  const wipeNow = async () => {
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

  /** Arm the inline confirm when there is queued work to lose; otherwise just do it. */
  const guard = async (verb: string, run: () => Promise<void>) => {
    setNotice("");
    const ask = await queueLossQuestion(store);
    if (!ask) return run();
    setPendingConfirm({ ...ask, verb, run });
  };

  /** Design §4.4: "try sending them first", where the vault is open and its traffic not stopped. The count is read
   *  again after it: with none left the confirm goes (the act is one click again); otherwise it shows the new number. */
  const sendFirst = async () => {
    const armed = pendingConfirm;
    if (!armed) return;
    setBusy(true);
    try {
      const left = await store.sendBeforeDelete().catch(() => null);
      const line = unsentLine(left);
      if (line === undefined) {
        setPendingConfirm(null);
        setNotice(UNSENT_ALL_SENT);
      } else {
        setPendingConfirm({ ...armed, question: line, unsent: left });
        setNotice(UNSENT_SEND_FIRST_FAILED);
      }
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
      pendingConfirm={pendingConfirm}
      onToggle={(enabled) => {
        setPendingConfirm(null);
        // Turning it ON destroys nothing; only the OFF direction is gated.
        if (enabled) void toggleNow(true);
        else void guard("Turn it off and lose them", () => toggleNow(false));
      }}
      onWipe={() => void guard("Remove it and lose them", wipeNow)}
      onSendFirst={pendingConfirm && pendingConfirm.unsent !== null && !store.isReadOnlyCopy() ? () => void sendFirst() : undefined}
      onConfirm={() => {
        // The second click counts again: a count that moved since the first arms the confirm again with the new number.
        const armed = pendingConfirm;
        if (!armed) return;
        void queueLossQuestion(store).then((now) => {
          const step = unsentArmStep({ text: armed.question, unsent: armed.unsent }, now === null ? null : { text: now.question, unsent: now.unsent });
          if (step.act) {
            setPendingConfirm(null);
            void armed.run();
          } else if (now !== null) setPendingConfirm({ ...armed, ...now });
        });
      }}
      onCancelConfirm={() => setPendingConfirm(null)}
    />
  );
}

/**
 * One-shot clipboard copy with a transient "copied" flash — or the canon failure sentence
 * (ux-error--2: writeText rejects on focus loss / permissions-policy; Vault useCopy's twin).
 *
 * `clearSeconds` decides the clipboard CLASS, and the caller must decide it honestly (the Kotlin
 * clients' SelectableCopyRow/CopySecretRow contract, stated the same way): 0 = genuinely
 * non-secret material — no auto-clear; anything ≥1 = a secret, which arms the shared auto-clear
 * slot on the §2.3-clamped policy window exactly like an item password.
 *
 * Audit F25: this button's KDoc used to assert that EVERYTHING it copies is "setup material, not
 * a vault secret" and that the absent auto-clear was deliberate — while two of its three call
 * sites were the account's TOTP `otpauth://` URI and its base32 seed, which ARE the account's
 * second factor (the URI embeds the same seed). Anyone holding either mints valid codes for this
 * account forever, and they sat on the system clipboard indefinitely while every item password
 * was scrubbed. Setup material and second-factor seeds are not the same class; android and
 * desktop reclassified their twins in the same audit. The identity code — a public fingerprint
 * someone reads out loud to verify a share — is the one caller that really is non-secret and
 * keeps the plain path.
 */
function CopyButton({ value, label = "Copy", clearSeconds = 0 }: { value: string; label?: string; clearSeconds?: number }) {
  const [flash, setFlash] = useState(false);
  const [failed, setFailed] = useState(false);
  // Audit F05 idiom: the platform can REFUSE the wipe (an unfocused document is the common
  // case), which leaves the seed on the clipboard — say so rather than let the copy stand as if
  // it had been cleared. A retry is armed for the next focus (clipboard.ts).
  const [wipeStuck, setWipeStuck] = useState(false);
  const copy = async () => {
    const ok = await writeClipboard(value);
    setFailed(!ok);
    setFlash(ok);
    if (!ok) return;
    setWipeStuck(false);
    window.setTimeout(() => setFlash(false), 1200);
    if (clearSeconds > 0) {
      scheduleClipboardClear(clampClipboardClearSeconds(clearSeconds), (outcome) => setWipeStuck(outcome === "stuck"));
    }
  };
  return (
    <>
      <button type="button" className="ghost" onClick={() => void copy()}>{flash ? "Copied ✓" : label}</button>
      {failed && <Msg kind="err">{CLIPBOARD_FAILED}</Msg>}
      {wipeStuck && <Msg kind="err">{CLIPBOARD_NOT_CLEARED}</Msg>}
    </>
  );
}

// ---- server TOTP (spec 03 §2 — optional second factor, verified at every sign-in) ----

function TotpCard({ client, policy, account, settings, offline = false }: Pick<Props, "client" | "policy" | "account" | "settings" | "offline">) {
  const [status, setStatus] = useState<TotpStatus | null>(null);
  const [setup, setSetup] = useState<TotpSetupResponse | null>(null);
  const [code, setCode] = useState("");
  // Security review 2026-10: a first enrollment proves the master password (see totp-enrol.ts).
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");

  // Encode the otpauth URI once per fresh setup — NOT on every confirm-code keystroke.
  const otpModules = useMemo(() => (setup ? qrModules(setup.otpauthUri, "M") : null), [setup]);

  // F25: the enrollment link and the setup code are the account's second factor, so they copy as
  // vault-class — the §2.3-clamped policy window, same as an item password (clampClipboardClearSeconds
  // is applied inside CopyButton too; clamped here as well so the sentence below states the real
  // number a hostile policy value can't inflate).
  const clipClear = clampClipboardClearSeconds(policy?.clipboardClearSeconds ?? 30);

  // On the offline copy the server can't be reached: its state is not asked for (Settings says why in its own line).
  useEffect(() => {
    if (offline) return;
    client.totpStatus().then(setStatus).catch(() => setErr(TWO_STEP_CHECK_FAILED));
  }, [client, offline]);

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      await fn();
    } catch (e) {
      setErr(totpErrorText(e));
    } finally {
      setBusy(false);
    }
  };

  // Server rule of 2026-11-17: every setup takes the master password, also on an account with no factor yet and right
  // after a sign-in. The password is proven here first, as when turning it off (a wrong one sends nothing), and the
  // field is emptied whatever the answer. Without the session's Settings flows nothing is sent.
  const begin = () =>
    run(async () => {
      let r: TwoStepSetup;
      try {
        r = settings ? await setUpTwoStep(settings, password) : { kind: "refused", code: NO_SESSION_WRAP };
      } finally {
        setPassword("");
      }
      setCode("");
      if (r.kind === "setup") setSetup(r.setup);
      else setErr(twoStepSetupText(r));
    });

  // §2.6 model: an enrolled second factor is verified on EVERY sign-in, every origin —
  // the copy says "every sign-in", never the retired "outside your home network" framing.
  // (The break-glass twin origin and its refusal went with design §15.)
  const confirm = () =>
    run(async () => {
      // The route answers the plain-text `ok`, never a status (spec 03 §0.1 row 15): on once it resolves.
      await client.totpConfirm(code.replace(/\s/g, ""));
      setStatus({ enrolled: true, pendingSetup: false });
      setSetup(null);
      setCode("");
      setMsg(TWO_STEP_TURNED_ON);
    });

  // Server rule of 2026-11-16: turning it off takes the master password as well as a current code. The password is
  // proven here first (a wrong one sends nothing), and the field is emptied whatever the answer.
  const disable = () =>
    run(async () => {
      let r: TwoStepOff;
      try {
        r = settings ? await turnOffTwoStep(settings, code.replace(/\s/g, ""), password) : { kind: "refused", code: NO_SESSION_WRAP };
      } finally {
        setPassword("");
      }
      const t = twoStepOffText(r, policy?.totpRequired === true);
      if (r.kind === "done") setStatus({ enrolled: false, pendingSetup: false });
      // The code is spent or stale on every answer of the server; it stays only when nothing was sent.
      if (r.kind === "done" || r.kind === "wrong_code" || r.kind === "wait") setCode("");
      if (r.kind === "unknown") void client.totpStatus().then(setStatus).catch(() => undefined);
      if (t.kind === "info") setMsg(t.text);
      else setErr(t.text);
    });

  return (
    <div className="sheet">
      <h2>{TWO_STEP_TITLE}</h2>
      <p className="muted" style={{ marginTop: 0 }}>
        An extra one-time code the server asks for each time you sign in. Recommended:
        even someone who learns your master password can't sign in without your
        authenticator. It's separate from your vault's encryption — your master password
        alone still unseals the hoard.
      </p>
      {policy?.totpRequired && (
        <p className="muted">{TWO_STEP_REQUIRED_HERE}</p>
      )}
      {err && <Msg kind="err">{err}</Msg>}
      {msg && <Msg kind="info">{msg}</Msg>}
      {/* BL-1: the enroll/disable result ("enrolled"/"disabled") is async info — a polite
          region mounted with it already inside is silent, so drive the announce off this
          persistent (always-mounted) region instead. */}
      <Announcer text={msg} />

      {!status ? (
        offline ? null : <p className="muted"><Busy>Loading…</Busy></p>
      ) : status.enrolled ? (
        <>
          <div className="msg info">On ✓ — every sign-in asks for your authenticator code.</div>
          <div className="field">
            <label>{TOTP_OFF_PASSWORD_LABEL}</label>
            <div className="secret-row">
              <input type="password" autoComplete="current-password" aria-label={TOTP_OFF_PASSWORD_LABEL} value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
          </div>
          <div className="field">
            <label>One-time code (required to turn off)</label>
            <div className="secret-row">
              <input className="mono" inputMode="numeric" aria-label="One-time code (required to turn off)" placeholder="123 456" value={code} onChange={(e) => setCode(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && password && code.trim() && !busy) disable(); }} />
              <button type="button" className="ghost" style={{ color: "var(--danger)" }} disabled={busy || !code.trim() || !password} onClick={disable}>
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
              <QrSvg modules={otpModules} ariaLabel={TWO_STEP_QR_LABEL} />
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
              <CopyButton value={setup.otpauthUri} clearSeconds={clipClear} />
            </div>
          </div>
          <div className="field">
            <label>Setup code (to type into your app)</label>
            <div className="secret-row">
              <input readOnly className="mono" aria-label="Setup code (to type into your app)" value={setup.secretBase32} />
              <CopyButton value={setup.secretBase32} clearSeconds={clipClear} />
            </div>
          </div>
          {/* F25: say it, because a cleared clipboard the user wasn't told about reads as a bug —
              and because the value stays on screen, so the clear costs them nothing. */}
          <p className="muted" style={{ marginTop: 0 }}>
            {fill(TWO_STEP_SECRET_CLEARS, String(clipClear))} The values stay on this screen until you finish.
          </p>
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
          <div className="field">
            <label>Master password (to turn it on)</label>
            <div className="secret-row">
              <input type="password" autoComplete="current-password" aria-label="Master password" value={password} onChange={(e) => setPassword(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && password && !busy) begin(); }} />
            </div>
          </div>
          <button type="button" className="ghost" disabled={busy || !password} onClick={begin}>{busy ? <Busy>Working…</Busy> : TWO_STEP_TURN_ON}</button>
        </>
      )}
    </div>
  );
}

// ---- master password change (spec 01 §6 — UVK never rotates) ----

function PasswordCard({ account, policy, onPasswordChanged, settings }: Pick<Props, "account" | "policy" | "onPasswordChanged"> & { settings: SettingsSession }) {
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
    // The password rule, the proof on this device against the wrap the session keeps (spec 01 §7: a wrong password
    // sends nothing), then the change at the account's present cost, raised to the policy's only when an upgrade is due.
    try {
      const r = await changePassword(settings, current, next, policy?.kdfParams ?? null);
      if (r.kind === "done") {
        // The change's own keys, never a fetch: the session keeps them for later proofs, and the offline copy took them
        // (changePassword did both) so the old password stops opening it (spec 05 T3). A copy that did not take them is
        // said; the next online unlock repairs it.
        setCurrent("");
        setNext("");
        setConfirm("");
        setMsg(passwordChangedText(r.value));
        onPasswordChanged();
      } else {
        setErr(passwordChangeText(r));
        setCurrent(""); // as after any failure (and never kept for an automatic retry: nothing is retried by itself)
        // An outcome nobody knows may have made the new password the account's: it is not left typed in the form, ready
        // to be sent again (a walk saw both new-password fields still filled under "We couldn't tell…").
        if (r.kind === "unknown") {
          setNext("");
          setConfirm("");
        }
      }
    } catch (e) {
      setErr(passwordChangeText({ kind: "unknown", error: e }));
      setCurrent("");
      setNext("");
      setConfirm("");
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
      {/* F31: same advisory hint as enrollment, on the other surface a master password is
          CHOSEN. Warns only — a pattern-weak choice never blocks the change (a member locked
          out of changing their own password is the worse failure). Local only: no breach
          lookup, since its prefix would reach this server (security review 2026-10). */}
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
      {/* R10: says "the andvari web app", not "andvari". H134 gave the browser extension its own
          Appearance choice on its own origin (extension/options.html — a separate store this page
          cannot reach), so forcing Light here leaves the popup dark until it is set there too. The
          old sentence claimed the whole product and was the promise H134 was raised against; the
          honest version names the two surfaces and points at the other one. Pinned against the
          extension's sentence in vault-copy.test.ts so the pair cannot drift apart again. */}
      <p className="muted" style={{ marginTop: 0 }}>
        "Match my device" follows your device's light/dark setting. Picking one keeps the andvari
        web app that way in this browser only — the browser extension has its own Appearance
        setting, and your other devices choose for themselves.
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
