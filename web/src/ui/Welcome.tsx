import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { ClientPolicy } from "../api/types";
import { fromB64 } from "../crypto/bytes";
import { fingerprint, shortFingerprint, shortFormMatches } from "../crypto/escrow";
import { confirmMatches, displayForm } from "../crypto/member-recovery";
import { clearPendingEnroll, enrollPrefillFor, peekPendingEnroll, type EnrollPayload } from "../enroll/enrolllink";
import { enrollPosture, escrowGate, type EnrollPosture } from "../enroll/enrollposture";
import { Account, IdentityMismatchError, deviceName } from "../vault/account";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { maybeKdfUpgrade } from "../vault/kdfupgrade";
import { VaultStore } from "../vault/store";
import { NullCache, openVaultCache } from "../vault/idbcache";
import { unlockExistingSession } from "./unlock";
import { NetworkError, POLICY_UNAVAILABLE, UNREACHABLE, net } from "./errors";
import { Field } from "./Field";
import { fmtDate } from "./format";
import { Msg } from "./Msg";
import { Recover } from "./Recover";
import { needsRecoveryCapture, settleRecoveryConfirm, setupAndCommitRecovery } from "./recovery-capture";
import {
  clearSession,
  ensureCachePersistenceRequested,
  installId,
  offlineCopyStamp,
  refreshCachedAccountKeys,
  saveSession,
  webCacheEnabled,
  wipeVaultCache,
  type Session,
} from "./session";
import { BrandSigil } from "./Sigil";
import { clampClipboardClearSeconds } from "./policyclamp";
import { STRENGTH_LABELS, estimateStrength, masterPasswordHasNonAscii, meetsMasterPasswordFloor } from "./strength";
import { useAutoLock } from "./useAutoLock";

type Mode = { unlock: Session } | { fresh: true };

/**
 * CR-02 (compliance 2026-07-15): the recovery-phrase reveal / capture-gate / self-recovery screens
 * hold a fully-unlocked Account and/or a UVK-equivalent recovery secret (TM-R9) OUTSIDE the vault
 * phase, where App's inactivity auto-lock (keyed to phase.kind==="vault") never arms — so a
 * walked-away device could display a standing account-takeover credential indefinitely, outside the
 * TM-T4 auto-lock bound spec 05 claims exists (KH-22). A fixed conservative idle cap bounds it. The
 * same activity-reset useAutoLock as the vault, so an actively-typing user is never cut off; only a
 * genuinely-idle screen expires. On expiry: zero the secret, drop the held Account/store, land on the
 * sign-in/unlock card with a non-alarming notice — the capture/reveal re-fires with a FRESH phrase at
 * the next sign-in (recoveryConfirmed stays false), the finding's prescribed heal path.
 */
const REVEAL_TIMEOUT_S = 300; // 5 minutes idle
/** Static (never interpolated — §F.7). Never implies the account/vault is broken. */
const REVEAL_TIMEOUT_NOTICE = "Timed out for your security. Sign in again — a fresh recovery phrase will be shown.";

/** What the vault shell needs to know about how this session came to be. */
export interface LoginMeta {
  isAdmin: boolean;
  mustChangePassword: boolean;
  // F57: the account's escrow is sealed to a superseded recovery key (re-ceremony) and the
  // client should re-seal on this unlock. escrowFingerprint is the CURRENT org recovery
  // fingerprint (the re-seal target + the value the user verifies against the new sheet).
  escrowStale: boolean;
  escrowFingerprint: string;
  /** design 2026-07-13-web-offline-cache §C6: set ONLY by an OFFLINE unlock whose cached
   *  `recoveryConfirmed !== true`. The vault shows a persistent, NON-blocking reminder banner
   *  (never "broken" copy). An online unlock never sets it — the online capture gate hard-blocks
   *  instead — so the nag can't be ridden indefinitely by any device that ever reconnects. */
  offlineRecoveryReminder?: boolean;
}

/** design 2026-07-13 piece-binding: the STATIC notice for a `409 recovery_piece_stale` confirm — the
 *  phrase the user just typed back attests a piece a concurrent setup (another device's gate) rotated
 *  away. Static copy only, never interpolated (§F.7); shared verbatim by the enroll reveal and the
 *  vault-entry capture gate. */
const RECOVERY_PIECE_STALE_NOTICE =
  "This recovery phrase was replaced — a newer one was created, possibly from another device. A fresh phrase will be shown; discard any phrase you saved before it.";

/** §F.9 handoff to the vault-entry capture gate: a fully-unlocked account whose vault entry is BLOCKED
 *  until it captures a recovery phrase (`recoveryConfirmed !== true`). `currentAuthKey` is the login
 *  authKey derived from the just-typed master password (the server re-verifies it at self-setup). */
interface CaptureHandoff {
  account: Account;
  store: VaultStore;
  meta: LoginMeta;
  currentAuthKey: string;
}

interface Props {
  client: ApiClient;
  policy: ClientPolicy | null;
  policyError: boolean;
  policyErrorMessage?: string;
  onRetryPolicy: () => Promise<void>;
  mode: Mode;
  /** F26: one-line reason this screen is showing ("Locked.", revoked, …) — rendered on the card. */
  notice?: string;
  onReady: (account: Account, store: VaultStore, meta: LoginMeta) => void;
  /** Leave this card. An optional notice rides through to App.signOut so the definitive-401
   *  ("Session expired…") can wipe (§E.4) AND surface its reason on the next Welcome screen. */
  onForget: (notice?: string) => void;
}

export function Welcome({ client, policy, policyError, policyErrorMessage, onRetryPolicy, mode, notice, onReady, onForget }: Props) {
  if ("unlock" in mode) {
    return <Unlock client={client} policy={policy} session={mode.unlock} notice={notice} onReady={onReady} onForget={onForget} />;
  }
  return <FreshStart client={client} policy={policy} policyError={policyError} policyErrorMessage={policyErrorMessage} onRetryPolicy={onRetryPolicy} notice={notice} onReady={onReady} />;
}

/** design 2026-07-13-web-offline-cache §E.3.4: the Unlock-card transparency line — a borrowed-machine
 *  user SEES that this device holds a durable (encrypted) copy, and how fresh it is. Rendered only
 *  when a cache actually exists (offlineCopyStamp — a non-creating probe); null hides it entirely.
 *  Exported for the static-render test (the line must show ONLY with a cache). */
export function OfflineCopyUnlockLine({ stamp }: { stamp: { lastSyncAt: number | null } | null }) {
  if (!stamp) return null;
  return (
    <p className="muted" style={{ textAlign: "center", marginTop: 0 }}>
      Offline copy on this device — last synced {stamp.lastSyncAt !== null ? fmtDate(stamp.lastSyncAt) : "not yet"}
    </p>
  );
}

/** Reload or F26 lock with an existing session: master password re-derives keys. */
function Unlock({ client, policy, session, notice, onReady, onForget }: { client: ApiClient; policy: ClientPolicy | null; session: Session; notice?: string; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void; onForget: (notice?: string) => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  // §F.9: an unlock that succeeds but whose account has not durably CONFIRMED its recovery piece is
  // BLOCKED here — the capture gate takes over the card until the phrase is saved.
  const [capture, setCapture] = useState<CaptureHandoff | null>(null);
  // §E.3.4: does this device hold a durable offline copy for THIS account? Loaded async (IDB probe);
  // null (no cache / probe failed / still loading) renders nothing — the line never blocks unlock.
  const [copyStamp, setCopyStamp] = useState<{ lastSyncAt: number | null } | null>(null);
  useEffect(() => {
    let alive = true;
    void offlineCopyStamp(session.userId).then((s) => {
      if (alive) setCopyStamp(s);
    });
    return () => {
      alive = false;
    };
  }, [session.userId]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      // design 2026-07-13-web-offline-cache §C: online-first with an offline fallback. The whole
      // flow (net()-tagged server call, cache creation + re-cache, the C3/C4 gates, hydrate, the
      // first sync, and the C6-nag decision) lives in the total {@link unlockExistingSession} seam
      // so the node-env tests can drive it without a DOM; this handler only maps the outcome.
      // F61: the silent KDF re-key is deliberately NOT fired on this returning-session unlock — it
      // cannot observe must-change (accountKeys carries no flag, web doesn't persist it across a
      // lock), so the re-key rides ONLY the SignIn path below. That posture is unchanged here.
      const r = await unlockExistingSession(client, session, password);
      if (r.kind === "ready") return onReady(r.account, r.store, r.meta);
      if (r.kind === "capture") return setCapture({ account: r.account, store: r.store, meta: r.meta, currentAuthKey: r.currentAuthKey });
      // §E.4: a definitive-401 is routed through App.signOut (via onForget) so the cache is WIPED —
      // not Welcome's old copy-only path — while still surfacing the "session expired" reason.
      if (r.kind === "expired") return onForget("Session expired — sign in again.");
      setErr(r.message);
    } finally {
      setBusy(false);
    }
  };

  // §F.9: the un-skippable capture gate replaces the unlock card entirely (its own hero, no dismiss).
  if (capture) {
    return (
      <div className="auth-shell">
        <div className="card">
          <div className="card-hero">
            <div className="sigil"><BrandSigil /></div>
            <h1>One more step</h1>
            <p>save your recovery phrase</p>
          </div>
          <RecoveryCaptureGate
            client={client}
            account={capture.account}
            store={capture.store}
            meta={capture.meta}
            currentAuthKey={capture.currentAuthKey}
            clipboardClearSeconds={policy?.clipboardClearSeconds ?? 30}
            onReady={onReady}
            onSignOut={() => onForget()}
            // CR-02: on idle-timeout, sign out with the timeout notice (onForget routes it through
            // App.signOut → the §E.4 wipe + welcome card). The gate re-fires with a fresh phrase.
            onTimeout={() => onForget(REVEAL_TIMEOUT_NOTICE)}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="auth-shell">
      <form className="card" onSubmit={submit}>
        <div className="card-hero">
          <div className="sigil"><BrandSigil /></div>
          <h1>Welcome back</h1>
          <p>{session.email}</p>
        </div>
        {/* §E.3.4 transparency: a durable offline copy exists on this device — say so, with freshness. */}
        <OfflineCopyUnlockLine stamp={copyStamp} />
        {/* F26: why the user is here ("Locked after N minutes of inactivity.", …). The
            SPOKEN announce rides App's persistent Announcer (this box is silent-but-visible). */}
        {notice && !err && <Msg kind="info">{notice}</Msg>}
        {err && <Msg kind="err">{err}</Msg>}
        <Field label="Master password">
          <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <button className="primary" disabled={busy || !password}>{busy ? "Unsealing…" : "Unlock"}</button>
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <button type="button" className="link" onClick={() => onForget()}>Sign out / use a different account</button>
        </div>
      </form>
    </div>
  );
}

/**
 * §7.1/§2.1 the reference-instance landing decision — a pure CLIENT RENDERING of the server-
 * DECLARED `signupMode` (never a hostname sniff; the origin.ts heuristic is gone). Unit-pinnable
 * because the card itself reads window.location + module singletons and cannot render in the node
 * test env. Modes:
 *  - "landing"     → the reference-instance stranger landing (self-host nudge over invite-gated enroll);
 *  - "closed"      → sign-in only, NO invite/enroll UI (the per-origin break-glass overlay, §2.2);
 *  - "invite-only" → today's plain sign-in + invite-gated enroll.
 * "open" is RESERVED — treated as landing until the open-register path ships (§7.3). Absent (old
 * server / a failed policy fetch ⇒ policy null) and any unknown value from a newer server both
 * degrade to "invite-only": never an open-register surface (§2.1, §2.3 conservative default).
 */
export type LandingMode = "landing" | "closed" | "invite-only";
export function landingModeFor(signupMode: string | null | undefined): LandingMode {
  if (signupMode === "closed") return "closed";
  if (signupMode === "landing" || signupMode === "open") return "landing";
  return "invite-only";
}

/** The live per-render inputs {@link freshStartAffordances} maps to onboarding surfaces. `tab` is the
 *  user's current selection; `hasPendingLink`/`hasValidPrefill` come from a peeked enroll link
 *  (`pending !== null` / `enrollPrefillFor(...) !== null` for THIS origin); `consented`/`dismissed`
 *  are the consent-card outcome; `blocking` is set while a child reveal/capture gate is un-skippable. */
export interface FreshStartState {
  hasPendingLink: boolean;
  hasValidPrefill: boolean;
  tab: "signin" | "enroll";
  consented: boolean;
  dismissed: boolean;
  blocking: boolean;
}
/** What FreshStart's render is allowed to expose, given the mode + state. */
export interface FreshStartAffordances {
  enrollAvailable: boolean;
  effectiveTab: "signin" | "enroll";
  showConsentCard: boolean;
  showTabBar: boolean;
  showNudge: boolean;
  showMismatch: boolean;
}
/**
 * §2.1/§7.1/§4.4 the security-relevant mode→affordance WIRING for {@link FreshStart}: from the
 * server-DECLARED landing mode + the current link/consent/blocking state, decide which onboarding
 * surfaces the card may render. Extracted PURE and exported because FreshStart itself reads
 * window.location + module singletons and cannot render in the node test env — so THIS seam (not the
 * card) is where the wiring is unit-pinned (welcome-landing.test.ts). FreshStart must CALL this rather
 * than re-inline the booleans, or a future mis-wire (exposing enroll on a "closed" break-glass origin,
 * or failing to force the tab to sign-in) would ship untested. Security-load-bearing outputs:
 *  - enrollAvailable — any enroll surface at all; FALSE only on "closed" (the §2.2 break-glass overlay);
 *  - effectiveTab    — FORCED to "signin" whenever enroll is unavailable, even if a stale tab state (or
 *                      a landing→closed policy refresh) left `tab` on "enroll";
 *  - showConsentCard — the explicit origin-consent step (consume-semantics rule 4): only with enroll
 *                      available, a valid same-origin prefill, and neither consented nor dismissed —
 *                      "closed" never shows it, not even for a crafted same-origin link (§2.1);
 *  - showTabBar      — hidden while a child reveal blocks (escape-hatch guard, §F.7/§F.9) AND whenever
 *                      enroll is unavailable ("closed" ⇒ sign-in only);
 *  - showNudge       — the stranger self-host nudge: "landing" only, and not while blocking;
 *  - showMismatch    — the §4.4 terminal reject: a captured link present but NOT valid for this origin.
 */
export function freshStartAffordances(landingMode: LandingMode, s: FreshStartState): FreshStartAffordances {
  const enrollAvailable = landingMode !== "closed";
  return {
    enrollAvailable,
    effectiveTab: enrollAvailable ? s.tab : "signin",
    showConsentCard: enrollAvailable && s.hasValidPrefill && !s.consented && !s.dismissed,
    showTabBar: !s.blocking && enrollAvailable,
    showNudge: !s.blocking && landingMode === "landing",
    showMismatch: s.hasPendingLink && !s.hasValidPrefill,
  };
}

/** §2.3 R8 rule: `selfHostDocsUrl` is DECORATIVE, server-declared, and untrusted — render it as a
 *  raw link ONLY when it is a real http(s) URL, so a hostile server cannot slip a `javascript:` /
 *  `data:` href into the landing. Returns the url verbatim when safe, else null (link omitted). */
function safeHttpUrl(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const scheme = new URL(url).protocol;
    return scheme === "https:" || scheme === "http:" ? url : null;
  } catch {
    return null;
  }
}

/** §7.1 stranger landing banner (signupMode "landing"/"open"): the invite-only + self-host nudge.
 *  Static copy only — it adds NO account/enumeration surface (no email probe, no "account exists"
 *  oracle); server enforcement of register-without-invite is unchanged (invite-ROW gate). The
 *  self-host docs URL is rendered as a raw link, and only when present AND a safe http(s) URL. */
export function LandingNudge({ selfHostDocsUrl }: { selfHostDocsUrl?: string | null }) {
  const docs = safeHttpUrl(selfHostDocsUrl);
  return (
    <div className="msg info" style={{ display: "block" }}>
      This is a <strong>private, invite-only server</strong>. Have an invite? Paste it here. Want your own?{" "}
      andvari is self-hostable — <strong>run your own server</strong>
      {docs ? (
        <>
          {": "}
          <a href={docs} rel="noreferrer noopener">{docs}</a>
        </>
      ) : (
        "."
      )}
    </div>
  );
}

/** §4.4 web REJECT-on-mismatch (B2-2): a captured enroll link minted for a DIFFERENT origin than
 *  this page is a TERMINAL, non-actionable state. The foreign origin is shown as PLAIN TEXT — never
 *  a link, never a button, and with no "continue"/"switch" affordance — so this trusted page can
 *  never become an escort to the attacker origin, where post-navigation JS (T6) could phish the
 *  master password and replay it against the user's REAL server. There is deliberately no
 *  `enrollSwitchProposalFor`: on web the link IS the switch (opening the genuine link lands on the
 *  issuing server's own SPA). The user's own same-origin sign-in / enroll below stay available. */
export function EnrollMismatchNotice({ origin }: { origin: string }) {
  return (
    <div className="msg err" style={{ display: "block" }} role="alert">
      This invite belongs to <span className="mono">{origin}</span>. Open the original link you were given.
    </div>
  );
}

/** No session: sign in to an existing account, or enroll with an invite. */
function FreshStart({ client, policy, policyError, policyErrorMessage, onRetryPolicy, notice, onReady }: { client: ApiClient; policy: ClientPolicy | null; policyError: boolean; policyErrorMessage?: string; onRetryPolicy: () => Promise<void>; notice?: string; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void }) {
  // §7.1/§2.1 landing decision — the server-DECLARED signupMode drives which onboarding surface
  // renders (never a hostname sniff). "closed" ⇒ sign-in only (no enroll UI); "landing"/"open" ⇒
  // the stranger self-host nudge over the enroll form; else today's plain sign-in + invite enroll.
  const landingMode = landingModeFor(policy?.signupMode);
  // One-scan onboarding: peek (never consume) the captured enroll link so a StrictMode
  // double-invoked initializer reads the same value both times. The seed is read ONCE here.
  const [pending] = useState<EnrollPayload | null>(() => peekPendingEnroll());
  // Only a link minted for THIS exact origin applies (a mismatch → the terminal reject notice).
  const validPrefill = enrollPrefillFor(pending, window.location.origin);
  const [consented, setConsented] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  // Stranger-first on the reference-instance landing: open on the invite field ("paste it here",
  // §7.1); every other mode opens on Sign in. policy is fetched before the welcome phase mounts
  // (App boot awaits loadPolicy before setPhase), so the mode is settled at this first render.
  const [tab, setTab] = useState<"signin" | "enroll">(landingMode === "landing" ? "enroll" : "signin");
  // Self-service recovery (design §F.3): its own screen, reachable from the sign-in form or a
  // `#recover` deep link. On success it lands back on Sign in with a notice (sessions were revoked).
  const [recovering, setRecovering] = useState(() => typeof window !== "undefined" && window.location.hash === "#recover");
  const [localNotice, setLocalNotice] = useState("");
  // §F.7/§F.9: while a child is showing an un-skippable recovery reveal / capture gate (Enroll's
  // shown-once reveal, or SignIn's vault-entry capture), HIDE the Sign-in/Enroll tab bar — otherwise
  // a tab switch would navigate away from the reveal, unmounting it and losing the phrase the user
  // was told to save (a silent-total-loss escape). Whichever child is mounted reports this.
  const [blocking, setBlocking] = useState(false);

  // §2.1/§7.1/§4.4: the mode→affordance wiring lives in the pure, unit-pinned freshStartAffordances
  // (this card can't render in the node test env, so the booleans are proven THERE, not inline).
  const { effectiveTab, showConsentCard, showTabBar, showNudge, showMismatch } = freshStartAffordances(landingMode, {
    hasPendingLink: !!pending,
    hasValidPrefill: !!validPrefill,
    tab,
    consented,
    dismissed,
    blocking,
  });

  if (recovering) {
    return (
      <Recover
        client={client}
        policy={policy}
        onDone={(n) => { setRecovering(false); setTab("signin"); setLocalNotice(n); }}
        onCancel={() => setRecovering(false)}
        // CR-02: the reset step holds the UVK-equivalent recovery secret — an idle-timeout lands
        // back on Sign-in with the notice (same as onDone's placement, distinct semantics).
        onTimedOut={(n) => { setRecovering(false); setTab("signin"); setLocalNotice(n); }}
      />
    );
  }

  // Consume-semantics rule 4 (normative): a captured link must NOT auto-advance into the
  // prefilled form. Show an explicit origin-consent step first, so a silent drive-by
  // navigation (a hostile page replaying a photographed QR link) can't stage an enrollment
  // the member never saw and accepted. §2.1 "closed" renders no enroll UI at all — not even
  // the consent card for a (crafted) same-origin link a closed instance would never mint.
  if (showConsentCard) {
    return (
      <div className="auth-shell">
        <div className="card">
          <div className="card-hero">
            <div className="sigil"><BrandSigil /></div>
            <h1 className="brand"><span className="a-mark">and</span>vari</h1>
            <p>the keeper of the hoard</p>
          </div>
          <div className="msg info" style={{ display: "block" }}>
            Set up a <strong>new andvari account</strong> at <strong>{window.location.origin}</strong>? You'll need the <strong>printed recovery sheet</strong> from the person who invited you.
          </div>
          <button type="button" className="primary" onClick={() => { setConsented(true); setTab("enroll"); }}>Continue</button>
          <div style={{ textAlign: "center", marginTop: 12 }}>
            <button type="button" className="link" onClick={() => { setDismissed(true); clearPendingEnroll(); }}>Not now</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-shell">
      <div className="card">
        <div className="card-hero">
          <div className="sigil"><BrandSigil /></div>
          <h1 className="brand"><span className="a-mark">and</span>vari</h1>
          <p>the keeper of the hoard</p>
        </div>
        {/* F26: why a full sign-in is required ("This device's access was revoked."). App's
            persistent Announcer speaks it; this box is the sighted-user copy. */}
        {notice && <Msg kind="info">{notice}</Msg>}
        {localNotice && <Msg kind="info">{localNotice}</Msg>}
        {/* §4.4 reject-on-mismatch (B2-2): a foreign-origin invite link is TERMINAL + non-actionable
            — the origin is plain text, with NO affordance escorting the user to attacker turf. */}
        {showMismatch && <EnrollMismatchNotice origin={pending!.o} />}
        {/* §7.1 stranger landing: the self-host nudge frames the enroll form on a "landing"
            (reference-instance) or reserved-"open" server. Hidden while a child reveal blocks. */}
        {showNudge && <LandingNudge selfHostDocsUrl={policy?.selfHostDocsUrl} />}
        {/* §F.7/§F.9: the tab bar is the escape hatch out of an un-skippable reveal — hide it while a
            child is blocking so the reveal cannot be navigated away from without confirming.
            §2.1 "closed" ⇒ sign-in only: no tab bar, no enroll surface. */}
        {showTabBar && (
          <div className="tabs">
            <button className={effectiveTab === "signin" ? "active" : ""} aria-pressed={effectiveTab === "signin"} onClick={() => setTab("signin")}>Sign in</button>
            <button className={effectiveTab === "enroll" ? "active" : ""} aria-pressed={effectiveTab === "enroll"} onClick={() => setTab("enroll")}>Enroll</button>
          </div>
        )}
        {effectiveTab === "signin" ? (
          <SignIn client={client} policy={policy} onReady={onReady} onForgot={() => { setLocalNotice(""); setRecovering(true); }} onBlockingChange={setBlocking} />
        ) : (
          <Enroll client={client} policy={policy} policyError={policyError} policyErrorMessage={policyErrorMessage} onRetryPolicy={onRetryPolicy} onReady={onReady} prefill={consented ? validPrefill : null} onBlockingChange={setBlocking} onTimedOut={(n) => { setBlocking(false); setTab("signin"); setLocalNotice(n); }} />
        )}
      </div>
    </div>
  );
}

function SignIn({ client, policy, onReady, onForgot, onBlockingChange }: { client: ApiClient; policy: ClientPolicy | null; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void; onForgot: () => void; onBlockingChange: (blocking: boolean) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [totpNeeded, setTotpNeeded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  // §F.9: a sign-in that succeeds but whose account has not durably CONFIRMED its recovery piece is
  // BLOCKED here — the capture gate replaces the form until the phrase is saved.
  const [capture, setCapture] = useState<CaptureHandoff | null>(null);
  // Tell FreshStart to hide the tab bar while the capture gate holds (no navigation escape).
  // useLayoutEffect (A.5): the flag must land BEFORE paint — with useEffect the gate's first
  // frame rendered with the tab bar still visible (a 1-frame escape-hatch flash).
  useLayoutEffect(() => {
    onBlockingChange(capture !== null);
    return () => onBlockingChange(false);
  }, [capture, onBlockingChange]);

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
      // §D.2c login-response re-cache write point (design 2026-07-13-web-offline-cache): seed the
      // durable offline cache so a later returning-session unlock can go OFFLINE. §F.1 dark-ship
      // gate, consent-keyed (design 2026-07-15 §5.4.1): durable only with this user's per-device
      // opt-in — cache-less NullCache otherwise, on EVERY origin — so seeding here is deploy-safe
      // everywhere. hydrate is a cold no-op on a fresh/just-wiped DB, and the first sync populates
      // the row envelopes. Fresh sign-in itself stays online-only (§C.2) — no offline fallback on
      // this path.
      const cache = webCacheEnabled(s.userId) ? await openVaultCache(s.userId) : new NullCache();
      // §B.5 (S5): first durable enable on this device asks for eviction protection (once,
      // marker-deduped) — offline WRITES stay dark until persist() has been requested.
      if (cache.durable) ensureCachePersistenceRequested();
      await cache.setAccountKeys(s.accountKeys);
      const store = new VaultStore(client, account, cache);
      await store.hydrate();
      await net(store.sync()); // discovers the personal vault id from grants
      saveSession({
        baseUrl: client.baseUrl,
        userId: s.userId,
        personalVaultId: account.personalVaultId,
        email,
        isAdmin: s.isAdmin,
        tokens: { accessToken: s.accessToken, refreshToken: s.refreshToken },
      });
      const meta: LoginMeta = { isAdmin: s.isAdmin, mustChangePassword: s.mustChangePassword, escrowStale: s.accountKeys.escrowStale ?? false, escrowFingerprint: s.accountKeys.escrowFingerprint };
      if (needsRecoveryCapture(s.accountKeys)) {
        // `authKey` IS the login authKey derived from the just-typed master password — reuse it as
        // currentAuthKey (the server re-verifies it at self-setup). BLOCK on the capture gate.
        setCapture({ account, store, meta, currentAuthKey: authKey });
        return;
      }
      // F61 (spec 01 §7, Android runKdfUpgrade parity): the SOLE web re-key site — a full-master-
      // password sign-in WITH connectivity that was NOT routed to the capture gate. This path (unlike
      // the returning-session unlock above) carries the login response's accurate `mustChangePassword`
      // (meta.mustChangePassword ← s.mustChangePassword), so the silent re-key can safely honour A5.
      // Detached + best-effort: never blocks/fails sign-in; maybeKdfUpgrade no-ops before any argon2id
      // when already current or must-change. LIVE policy only (App.loadPolicy) — never a stale value.
      // CR-07: on a successful silent re-key, replace the durable cache's accountKeys (mirrors the
      // user-initiated Settings change at Settings.tsx) — else the pre-upgrade wrap lingers offline.
      if (policy) void maybeKdfUpgrade({ client, account, password, currentKdfSalt: s.accountKeys.kdfSalt, currentKdfParams: s.accountKeys.kdfParams, policyKdfParams: policy.kdfParams, mustChangePassword: meta.mustChangePassword, onUpgraded: () => refreshCachedAccountKeys(client, account.userId) });
      onReady(account, store, meta);
    } catch (e) {
      if (e instanceof ApiError && e.code === "totp_required") {
        // §2.6 row 1 (origin-independent): the account has server-TOTP enrolled; the
        // password checked out and the server additionally wants the current code.
        setTotpNeeded(true);
        setErr("");
      } else if (e instanceof ApiError && e.code === "public_login_requires_totp") {
        // Only an armed break-glass twin origin (opt-in dual-origin self-hosts) answers this.
        setErr("This account doesn't have two-factor sign-in turned on, and this address only accepts accounts that do. Connect from inside (VPN/LAN), turn it on in Settings, then retry.");
      } else if (e instanceof KdfPolicyError) {
        // H1 (spec 05 T1): the server tried to weaken the master-password KDF — a distinct
        // security block, never softened into a wrong-password/credentials error.
        setErr(WEAK_KDF_MESSAGE);
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

  // §F.9: the un-skippable capture gate replaces the sign-in form (it renders inside FreshStart's card,
  // whose brand hero + hidden-while-blocking tab bar already surround it).
  if (capture) {
    // Mirror App's signOut (unreachable from here): drop the persisted session + tokens and
    // fall back to the sign-in form. Signing out of the gate is SAFE — the flag is still false,
    // so the capture gate simply re-fires at the next sign-in.
    // §E.4 (S3-1): SignIn.submit already SEEDED the durable cache (openVaultCache + setAccountKeys)
    // BEFORE this gate mounted, so — unlike App.signOut, the choke point this path can't reach —
    // the wipe MUST happen here too, or a sign-out on a shared machine leaves crackable ciphertext +
    // the user's email in someone else's profile forever. Read the userId before clearSession, then
    // wipe (fire-and-forget; deleteDatabase self-completes, §D.5.3). `notice` (CR-02): the idle-
    // timeout escape surfaces the timeout copy on the returned sign-in form.
    const signOutOfCapture = (notice = "") => {
      const uid = capture.account.userId;
      clearSession();
      client.setTokens(null);
      void wipeVaultCache(uid);
      setPassword("");
      setTotp("");
      setTotpNeeded(false);
      setErr(notice);
      setCapture(null);
    };
    return (
      <RecoveryCaptureGate
        client={client}
        account={capture.account}
        store={capture.store}
        meta={capture.meta}
        currentAuthKey={capture.currentAuthKey}
        clipboardClearSeconds={policy?.clipboardClearSeconds ?? 30}
        onReady={onReady}
        onSignOut={() => signOutOfCapture()}
        // CR-02: idle-timeout → same safe teardown, with the timeout notice on the sign-in form.
        onTimeout={() => signOutOfCapture(REVEAL_TIMEOUT_NOTICE)}
      />
    );
  }

  return (
    <form onSubmit={submit}>
      {err && <Msg kind="err">{err}</Msg>}
      <Field label="Email">
        <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      <Field label="Master password">
        <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      {totpNeeded && (
        <Field
          label="One-time code"
          hint={<span className="muted">This account has two-factor sign-in — enter the code from your authenticator app.</span>}
        >
          <input
            className="mono"
            autoFocus
            inputMode="numeric"
            autoComplete="one-time-code"
            placeholder="123 456"
            value={totp}
            onChange={(e) => setTotp(e.target.value)}
          />
        </Field>
      )}
      <button className="primary" disabled={busy || !email || !password || (totpNeeded && !totp.trim())}>{busy ? "Unsealing…" : "Sign in"}</button>
      <div style={{ textAlign: "center", marginTop: 12 }}>
        <button type="button" className="link" onClick={onForgot}>Forgot your master password? Recover with your recovery phrase</button>
      </div>
    </form>
  );
}

function Enroll({ client, policy, policyError, policyErrorMessage, onRetryPolicy, onReady, prefill, onBlockingChange, onTimedOut }: { client: ApiClient; policy: ClientPolicy | null; policyError: boolean; policyErrorMessage?: string; onRetryPolicy: () => Promise<void>; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void; prefill?: EnrollPayload | null; onBlockingChange: (blocking: boolean) => void; onTimedOut: (notice: string) => void }) {
  // A prefill applies ONLY if the link was minted FOR this exact origin — the page IS served
  // by payload.o, so a mismatch means a redirect or a hand-mangled link; fall through to manual
  // entry rather than silently enrolling against the wrong server.
  const linkValid = !!prefill && prefill.o === window.location.origin;
  // §F.1: an `rfp` on the link means the invitee scanned an IN-PERSON QR off the admin's screen (a
  // server-composed emailed link is contractually rfp=null) — the sole human channel we may anchor on.
  const linkRfp = linkValid ? prefill!.rfp : undefined;

  const [invite, setInvite] = useState(linkValid ? prefill!.t : "");
  const [email, setEmail] = useState(linkValid ? prefill!.e : "");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  // Posture (§F.1): rfp ⇒ required-affirm; otherwise WAIVED by default, or required-typed if the
  // member declares they were handed a printed recovery sheet. NEVER auto-trust the server key.
  const [hasSheet, setHasSheet] = useState(false);
  const posture: EnrollPosture = enrollPosture(linkRfp, hasSheet);
  const [affirmConfirmed, setAffirmConfirmed] = useState(false); // required-affirm: eyeball the QR rfp
  const [shortFp, setShortFp] = useState("");                    // required-typed: the sheet's 16 hex
  const [fpConfirmed, setFpConfirmed] = useState(false);         // required-typed: checkbox gate
  const [waivedAck, setWaivedAck] = useState(false);             // waived: "no admin backstop" ack
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [retrying, setRetrying] = useState(false);

  // §F.7 shown-once: the recovery secret bytes live ONLY in this ref, zeroed the instant the confirm
  // passes. After register() succeeds we stash the ready session (plus the register-committed piece's
  // `recoveryPieceId`, design 2026-07-13 — the bound confirm presents it) and render the un-skippable
  // reveal gate BEFORE handing the account to the vault shell.
  const secretRef = useRef<Uint8Array | null>(null);
  const [ready, setReady] = useState<{ account: Account; store: VaultStore; meta: LoginMeta; pieceId: string | null } | null>(null);
  // design 2026-07-13: the confirm answered 409 recovery_piece_stale — a concurrent setup (another
  // device) rotated the register-committed piece away mid-reveal. The typed phrase is DEAD: surface
  // the static notice, then proceed unconfirmed on acknowledgment (no reauth in hand to re-setup here;
  // the vault-entry capture gate re-fires at the next unlock and heals).
  const [pieceStale, setPieceStale] = useState(false);
  // In-flight state for the awaited bound confirm (design 2026-07-13): once settlement starts we
  // replace the reveal with explicit "Saving…" feedback (mirrors the capture gate's stage="confirming"),
  // so a copied-reset timer firing mid-POST can't blank the reveal to a bare screen on the slow tunnel path.
  const [settling, setSettling] = useState(false);
  // One settlement per reveal (the confirm is now awaited, so the button outlives the first click).
  const settlingRef = useRef(false);
  const aliveRef = useRef(true);

  // §F.7: zero the raw recovery secret on unmount as well as on confirm (mirrors Recover.tsx's
  // cleanup) — if the reveal is interrupted (navigate away / lock), the secret never lingers in memory.
  // aliveRef re-arms across a StrictMode remount so a confirm settling after unmount can't call onReady.
  useEffect(() => {
    aliveRef.current = true;
    return () => { aliveRef.current = false; secretRef.current?.fill(0); secretRef.current = null; };
  }, []);
  // §F.7/§F.9: while the shown-once reveal (or the stale-piece notice) is up, tell FreshStart to HIDE
  // the Sign-in/Enroll tab bar so the user cannot navigate away from the reveal (unmounting it, losing
  // the phrase) without confirming. useLayoutEffect (A.5): pre-paint, so the bar never flashes for a
  // frame around the reveal mounting.
  const revealing = ready !== null && (secretRef.current !== null || pieceStale || settling);
  useLayoutEffect(() => { onBlockingChange(revealing); }, [revealing, onBlockingChange]);

  // CR-02: the shown-once reveal holds a freshly-enrolled unlocked Account and displays the raw
  // recovery phrase (UVK-equivalent). Bound the whole account-held window (ready !== null) by the
  // idle auto-lock. On expiry zero the secret, SIGN OUT (the session was already saved at register),
  // and route to Sign-in with the notice — the vault-entry capture gate re-fires with a fresh phrase
  // at the next sign-in (recoveryConfirmed stays false), the finding's enroll heal path. Disabled
  // (timeout 0) until a reveal is live. Activity resets it — an actively-typing member is never cut.
  useAutoLock(ready !== null ? REVEAL_TIMEOUT_S : 0, () => {
    const uid = ready?.account.userId;
    secretRef.current?.fill(0);
    secretRef.current = null;
    clearSession();
    client.setTokens(null);
    if (uid) void wipeVaultCache(uid);
    setReady(null);
    onTimedOut(REVEAL_TIMEOUT_NOTICE);
  });

  const retryPolicy = async () => {
    setRetrying(true);
    try {
      await onRetryPolicy();
    } finally {
      setRetrying(false);
    }
  };

  const fp = policy?.recoveryFingerprint ?? "";
  const shortOk = shortFormMatches(shortFp, fp);
  const pwStrongEnough = meetsMasterPasswordFloor(password);
  // Posture-specific gate: waived → ack; required-affirm → eyeball-confirm the scanned rfp;
  // required-typed → the typed-sheet ceremony against the server's advertised fingerprint.
  const postureOk =
    posture === "waived"
      ? waivedAck
      : posture === "required-affirm"
        ? affirmConfirmed && !!linkRfp
        : !!fp && shortOk && fpConfirmed;
  const canSubmit = !!invite && !!email && pwStrongEnough && password === confirm && postureOk;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!policy) return setErr(policyErrorMessage ?? (policyError ? POLICY_UNAVAILABLE : "Server settings are unavailable — try again in a moment."));
    if (posture !== "waived" && !fp) return setErr("This server has no recovery key configured — the admin backstop can't be set up. Ask your admin, or set up without a backstop.");
    if (!meetsMasterPasswordFloor(password)) return setErr("Choose a stronger master password — mix length with upper/lower case, digits, or symbols.");
    setBusy(true);
    setErr("");
    try {
      // Resolve the escrow decision. Waived seals NOTHING; the two required paths bind the seal to a
      // HUMAN anchor (a scanned QR rfp or a typed sheet) and fail closed on any mismatch — the server
      // pubkey is never trusted on its own.
      let recoveryPublicKey: Uint8Array | undefined;
      let recoveryFingerprint: string | undefined;
      if (posture !== "waived") {
        const pub = await net(recoveryPubFromServer(client));
        const pubShortFp = await shortFingerprint(pub);
        const gate = escrowGate({ posture, linkRfp, typedSheet: shortFp, serverFullFp: fp, pubShortFp });
        if (!gate.seal) {
          return setErr("The recovery key this server offers does not match the code your admin gave you. STOP and contact your admin.");
        }
        recoveryPublicKey = pub;
        // required-affirm anchored on the human-scanned short rfp; record the fetched pubkey's FULL
        // fingerprint. required-typed keeps the pre-rfp binding to the policy fingerprint.
        recoveryFingerprint = posture === "required-affirm" ? await fingerprint(pub) : fp;
      }

      const { request, account, recoverySecret } = await Account.enroll({
        inviteToken: invite,
        email,
        displayName: name || email.split("@")[0]!,
        password,
        kdfParams: policy.kdfParams,
        recoveryPublicKey,
        recoveryFingerprint,
        installId: installId(), // F28: same stable id as sign-in
      });
      const s = await net(client.register(request));
      // register() succeeded → the invite is CONSUMED. Stash the secret bytes for the ONE-TIME reveal
      // BEFORE anything can bounce us back to the form (a resubmit could only yield "invite used").
      secretRef.current = recoverySecret;
      clearPendingEnroll();
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
      await store.sync().catch(() => {});
      // Do NOT go straight to the vault — render the un-skippable recovery-phrase reveal first (§F.7).
      // `recoveryPieceId` is register-only (design 2026-07-13); an old server omits it ⇒ unbound confirm.
      setReady({ account, store, meta: { isAdmin: s.isAdmin, mustChangePassword: s.mustChangePassword, escrowStale: s.accountKeys.escrowStale ?? false, escrowFingerprint: s.accountKeys.escrowFingerprint }, pieceId: s.recoveryPieceId ?? null });
    } catch (e) {
      // Static error strings only — NEVER interpolate secret material.
      setErr(e instanceof KdfPolicyError ? WEAK_KDF_MESSAGE : e instanceof NetworkError ? UNREACHABLE : e instanceof ApiError ? enrollError(e.code) : "Enrollment failed.");
    } finally {
      setBusy(false);
    }
  };

  // design 2026-07-13: the stale-confirm notice — un-skippable acknowledgment BEFORE vault landing, so
  // the user never walks away believing the (dead) phrase they saved still works.
  if (ready && pieceStale) {
    return (
      <div>
        <Msg kind="err">{RECOVERY_PIECE_STALE_NOTICE}</Msg>
        <button
          type="button"
          className="primary"
          onClick={() => {
            const r = ready;
            setReady(null);
            onReady(r.account, r.store, r.meta);
          }}
        >
          I understand — continue
        </button>
      </div>
    );
  }

  // design 2026-07-13: the awaited bound confirm is settling — show explicit feedback instead of the
  // reveal (whose secret zero() nulls mid-flight), so the screen never blanks on the slow tunnel path.
  // Ordered after the stale branch (a 409 during settle wins) and before the reveal.
  if (ready && settling) {
    return (
      <div>
        <p className="muted">Saving your confirmation…</p>
      </div>
    );
  }

  // §F.7: the shown-once recovery-phrase reveal gates account usability — rendered after a successful
  // register, holding the secret in secretRef, and it won't hand the account to the vault until the
  // member types the phrase back (confirmMatches). No skip affordance (silent-total-loss guard).
  if (ready && secretRef.current) {
    return (
      <RecoveryReveal
        secretRef={secretRef}
        clipboardClearSeconds={policy?.clipboardClearSeconds ?? 30}
        onConfirmed={() => {
          if (settlingRef.current) return;
          settlingRef.current = true;
          setSettling(true);
          const r = ready;
          // §F.9 + design 2026-07-13: flip the server's recoveryConfirmed flag — the register-committed
          // piece IS what was just shown + confirmed (NO regenerate — that would clobber the phrase the
          // user saved) — now BOUND (register's recoveryPieceId) and AWAITED. Stale ⇒ the saved phrase
          // was rotated away: static notice, proceed unconfirmed on acknowledgment. Any other failure
          // proceeds as before — it only re-nudges via the vault-entry capture gate on the next unlock.
          void settleRecoveryConfirm(client, r.pieceId, {
            zero: () => { secretRef.current?.fill(0); secretRef.current = null; },
            onStale: () => { if (aliveRef.current) setPieceStale(true); },
            onProceed: () => {
              if (!aliveRef.current) return;
              setReady(null);
              onReady(r.account, r.store, r.meta);
            },
          });
        }}
      />
    );
  }

  return (
    <form onSubmit={submit}>
      {err && <Msg kind="err">{err}</Msg>}
      {linkValid && (
        <div className="msg info" style={{ display: "block" }}>
          Setting up a <strong>new account</strong> at <strong>{window.location.origin}</strong>.
        </div>
      )}
      <Field label="Invite token">
        <input className="mono" value={invite} onChange={(e) => setInvite(e.target.value)} placeholder="from your administrator" />
      </Field>
      <div className="row">
        <Field
          label="Email"
          style={{ flex: 1 }}
          hint={linkValid ? <span className="muted">from your invite — wrong address? ask your admin for a new one</span> : undefined}
        >
          <input type="email" value={email} readOnly={linkValid} onChange={(e) => setEmail(e.target.value)} />
        </Field>
        <Field label="Name" style={{ flex: 1 }}>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="optional" />
        </Field>
      </div>
      <Field label="Master password" hint={<MasterPasswordHint password={password} />}>
        <input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <Field
        label="Confirm master password"
        hint={confirm && confirm !== password ? <span className="muted" style={{ color: "var(--danger)" }}>passwords don't match</span> : undefined}
      >
        <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
      </Field>

      <FingerprintProvenance
        posture={posture}
        linkRfp={linkRfp}
        fp={fp}
        policyError={policyError}
        retrying={retrying}
        onRetryPolicy={retryPolicy}
        hasSheet={hasSheet}
        onToggleSheet={setHasSheet}
        affirmConfirmed={affirmConfirmed}
        onAffirm={setAffirmConfirmed}
        shortFp={shortFp}
        onShortFp={setShortFp}
        shortOk={shortOk}
        fpConfirmed={fpConfirmed}
        onFpConfirm={setFpConfirmed}
        waivedAck={waivedAck}
        onWaivedAck={setWaivedAck}
      />

      <button className="primary" disabled={busy || !canSubmit}>{busy ? "Forging your vault…" : "Create vault"}</button>
    </form>
  );
}

/**
 * The fingerprint-provenance UI (§F.1) — renders EXACTLY the anchor a posture allows, never a
 * server-sourced fingerprint presented as verified:
 *  - waived         → NO fingerprint UI; the "no admin backstop" acknowledgment (distinct copy).
 *  - required-affirm→ display the IN-PERSON-scanned rfp and a one-tap eyeball affirmation.
 *  - required-typed → the pre-rfp typed-sheet ceremony (deliberately not showing the value first).
 */
function FingerprintProvenance(p: {
  posture: EnrollPosture;
  linkRfp: string | undefined;
  fp: string;
  policyError: boolean;
  retrying: boolean;
  onRetryPolicy: () => void;
  hasSheet: boolean;
  onToggleSheet: (v: boolean) => void;
  affirmConfirmed: boolean;
  onAffirm: (v: boolean) => void;
  shortFp: string;
  onShortFp: (v: string) => void;
  shortOk: boolean;
  fpConfirmed: boolean;
  onFpConfirm: (v: boolean) => void;
  waivedAck: boolean;
  onWaivedAck: (v: boolean) => void;
}) {
  if (p.posture === "required-affirm") {
    // The rfp arrived via the human QR channel — show it so the invitee can eyeball it against the
    // admin's screen. This is the one place a value is shown first, because it is NOT server-sourced.
    return (
      <div className="check-block">
        <div className="msg info" style={{ display: "block" }}>
          Your admin is showing a <strong>recovery code</strong> on their screen. Check it matches this:
          <div className="mono fingerprint" style={{ marginTop: 6 }}>{groupHex(p.linkRfp ?? "")}</div>
        </div>
        <label className="check">
          <input type="checkbox" checked={p.affirmConfirmed} onChange={(e) => p.onAffirm(e.target.checked)} />
          <span>I scanned this from my admin's screen <strong>in person</strong>, and the code above matches what they're showing.</span>
        </label>
      </div>
    );
  }

  if (p.posture === "required-typed") {
    // The pre-rfp ceremony (spec 04 §2(3)): the fingerprint is deliberately NOT displayed until typed
    // — showing it first would reduce the check to transcription.
    return (
      <div className="check-block">
        {p.fp ? (
          <>
            <Field
              label="Recovery check — type the FIRST 16 characters of the fingerprint on your printed recovery sheet"
              hint={
                <>
                  {p.shortFp.trim() && !p.shortOk && (
                    <span className="muted" style={{ color: "var(--danger)" }}>
                      doesn't match this server's recovery key — if you copied the sheet correctly, STOP and contact your admin
                    </span>
                  )}
                  {p.shortOk && <span className="muted">matches — full fingerprint: {groupHex(p.fp)}</span>}
                </>
              }
            >
              <input className="mono" placeholder="from the sheet, not this screen" value={p.shortFp} onChange={(e) => p.onShortFp(e.target.value)} />
            </Field>
            <label className="check">
              <input type="checkbox" checked={p.fpConfirmed} onChange={(e) => p.onFpConfirm(e.target.checked)} disabled={!p.shortOk} />
              <span>This fingerprint matches the recovery sheet. I understand this account also has an admin backstop.</span>
            </label>
          </>
        ) : p.policyError ? (
          <div className="msg err" style={{ display: "block" }} role="alert">
            {POLICY_UNAVAILABLE}{" "}
            <button type="button" className="link" disabled={p.retrying} onClick={p.onRetryPolicy}>{p.retrying ? "Retrying…" : "Retry"}</button>
          </div>
        ) : (
          <Msg kind="err">This server has no recovery key configured — the admin backstop can't be set up.</Msg>
        )}
        <div style={{ marginTop: 8 }}>
          <button type="button" className="link" onClick={() => p.onToggleSheet(false)}>I don't have a recovery sheet — set up without an admin backstop</button>
        </div>
      </div>
    );
  }

  // waived — no fingerprint anywhere (there is no org pubkey to substitute). Distinct posture ack.
  return (
    <div className="check-block">
      <div className="msg err" style={{ display: "block" }} role="alert">
        <strong>There is NO admin backstop.</strong> Only your recovery phrase can restore this account. Lose
        both your master password and this phrase and this account is gone forever.
      </div>
      <label className="check">
        <input type="checkbox" checked={p.waivedAck} onChange={(e) => p.onWaivedAck(e.target.checked)} />
        <span>I understand: without my master password AND my recovery phrase, this account cannot be recovered by anyone.</span>
      </label>
      {p.linkRfp === undefined && (
        <div style={{ marginTop: 8 }}>
          <button type="button" className="link" onClick={() => p.onToggleSheet(true)}>My admin gave me a printed recovery sheet (add the admin backstop)</button>
        </div>
      )}
    </div>
  );
}

/**
 * §F.7 shown-once recovery-phrase reveal. The secret lives in `secretRef` (never useState, never
 * storage); the phrase renders as TEXT (never type=password); the "type it back" confirm input is
 * bound to its own `typed` state (never to the secret) with autoComplete off and sits OUTSIDE any
 * credential <form>; the copy button uses the SECRET clipboard-clear path. The gate is un-skippable
 * (no dismiss) — matching today's fpConfirmed gate.
 *
 * Cut M (v2 #7): the Copy button used to sit ABOVE the type-back, so copy → paste → confirm passed
 * the gate without the phrase ever being saved — and the clipboard auto-wipe then destroyed the only
 * copy (silent total loss for a waived account). Now the confirm input refuses pastes, and copying
 * is offered only AFTER the type-back has proven a saved copy exists (for the password-manager
 * use-case). This component is the ONE gate body — both surfaces (enroll reveal + vault-entry
 * capture gate) render it, so both are covered.
 */
function RecoveryReveal({
  secretRef,
  clipboardClearSeconds,
  onConfirmed,
}: {
  secretRef: React.MutableRefObject<Uint8Array | null>;
  clipboardClearSeconds: number;
  onConfirmed: () => void;
}) {
  const [typed, setTyped] = useState("");
  const [copied, setCopied] = useState(false);
  // Cut M (v2 #7): a refused paste/drop into the type-back sets this so the refusal is
  // explained in place rather than looking like a broken input.
  const [pasteTried, setPasteTried] = useState(false);
  const secret = secretRef.current;
  if (!secret) return null;
  const phrase = displayForm(secret); // base64url of the raw 32 bytes — computed per render, not stored
  const grouped = phrase.replace(/(.{4})/g, "$1 ").trim();
  const matches = confirmMatches(secret, typed);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(phrase);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
      // SECRET clipboard-clear (Vault.useCopy parity): wipe after the policy window, CLAMPED into
      // [1, CLIPBOARD_CLEAR_MAX_SECONDS] (design 2026-07-15 §2.3, B1-1) — a hostile server value
      // can never pin a recovery phrase on the clipboard past the ceiling.
      window.setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), clampClipboardClearSeconds(clipboardClearSeconds) * 1000);
    } catch {
      /* clipboard denied — the phrase is on screen to copy by hand */
    }
  };

  return (
    <div>
      <div className="msg info" style={{ display: "block" }}>
        <strong>Save your recovery phrase now.</strong> It is the only thing that can restore this account if you
        forget your master password. It is shown <strong>once</strong> — write it down or store it somewhere safe.
      </div>
      <div className="field">
        <label>Your recovery phrase</label>
        {/* Rendered as TEXT (never type=password); never written to storage (§F.7). */}
        <div
          className="mono"
          style={{ userSelect: "all", wordBreak: "break-all", padding: "10px 12px", border: "1px solid rgba(128,128,128,0.35)", borderRadius: 8 }}
        >
          {grouped}
        </div>
        {/* Cut M (v2 #7): no Copy button here — it moved BELOW the type-back gate (see the
            post-confirm section) so a clipboard round-trip can't stand in for saving. */}
      </div>
      <div className="field">
        <label>Type your recovery phrase back to confirm you saved it</label>
        <input
          className="mono"
          autoComplete="off"
          autoCapitalize="off"
          autoCorrect="off"
          spellCheck={false}
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          // Cut M (v2 #7): pasting (or dropping selected text) proves nothing about a saved
          // copy — refuse it and say why. Typing stays the only way through the gate.
          onPaste={(e) => { e.preventDefault(); setPasteTried(true); }}
          onDrop={(e) => { e.preventDefault(); setPasteTried(true); }}
          placeholder="type it in from where you saved it"
        />
        {pasteTried && !matches && (
          <span className="muted" style={{ display: "block", color: "var(--gold-text)" }}>
            Type it from your written note — pasting doesn't prove you saved it.
          </span>
        )}
        {typed.trim() && !matches && <span className="muted" style={{ color: "var(--danger)" }}>doesn't match — check what you saved</span>}
      </div>
      {/* Cut M (v2 #7): the gate is open — the phrase demonstrably exists outside this screen —
          so offering the clipboard here can no longer defeat it. Same SECRET clipboard-clear
          path as before (the secret is still live; it's only zeroed by onConfirmed). */}
      {matches && (
        <div className="msg info" style={{ display: "block" }}>
          That matches — your phrase is saved. Want it in another password manager too?{" "}
          <button type="button" className="ghost" onClick={copy}>{copied ? "Copied ✓" : "Copy phrase"}</button>
        </div>
      )}
      <button type="button" className="primary" disabled={!matches} onClick={onConfirmed}>I've saved it — open my vault</button>
    </div>
  );
}

/**
 * §F.9 vault-entry capture gate. Reached from Unlock / SignIn when the server reports this account's
 * recovery piece was never durably CONFIRMED (`recoveryConfirmed !== true`) — an interrupted reveal on
 * some device, or a pre-flag migration account. On mount it regenerates + COMMITS a fresh piece
 * (setupAndCommitRecovery → PUT /recovery/self-setup, which does NOT flip the flag — it runs before
 * capture), hands the fresh secret to the SAME un-skippable {@link RecoveryReveal}, and only on the
 * type-back confirm flips `recoveryConfirmed` via /recovery/self/confirm — BOUND to the committed
 * piece's `pieceId` and AWAITED (design 2026-07-13) — before proceeding to the vault. A stale confirm
 * (409: another device's gate rotated the piece mid-capture) shows the static replaced-phrase notice
 * and re-runs setup + reveal; the gate stays closed. `currentAuthKey` is the login authKey the caller
 * derived from the freshly-typed master password (the server re-verifies it, like changePassword).
 * Renders content only — callers wrap it in the card appropriate to their context. A failed commit
 * keeps the gate closed with a retry (never proceeds to the vault, never leaves a live secret
 * dangling — the secret is zeroed on failure). `onSignOut` (A.5) is the gate's only escape — safe:
 * the flag stays false, so the gate re-fires at the next sign-in.
 */
function RecoveryCaptureGate({
  client,
  account,
  store,
  meta,
  currentAuthKey,
  clipboardClearSeconds,
  onReady,
  onSignOut,
  onTimeout,
}: {
  client: ApiClient;
  account: Account;
  store: VaultStore;
  meta: LoginMeta;
  currentAuthKey: string;
  clipboardClearSeconds: number;
  onReady: (a: Account, s: VaultStore, m: LoginMeta) => void;
  onSignOut: () => void;
  /** CR-02: idle-timeout escape — the caller drops the held session and lands on the sign-in/unlock
   *  card with the timeout notice; the gate re-fires with a fresh phrase at next sign-in. */
  onTimeout: () => void;
}) {
  const secretRef = useRef<Uint8Array | null>(null);
  // design 2026-07-13: the server-minted id of the piece THIS gate committed + revealed — presented at
  // confirm so it can never attest a piece a concurrent setup rotated away. Lives beside secretRef;
  // the two are zeroed/cleared together (unmount, confirm, stale).
  const pieceIdRef = useRef<string | null>(null);
  const [stage, setStage] = useState<"working" | "reveal" | "confirming" | "error">("working");
  // design 2026-07-13: a confirm answered 409 recovery_piece_stale — the static notice explains the
  // fresh phrase the re-run is about to reveal. Sticky for the gate's lifetime (the old phrase stays dead).
  const [pieceStale, setPieceStale] = useState(false);
  const [err, setErr] = useState("");
  const startedRef = useRef(false);
  // One settlement per reveal (the confirm is awaited now, so the reveal outlives the first click).
  const settlingRef = useRef(false);
  const aliveRef = useRef(true);

  // CR-02: this gate holds a fully-unlocked Account for its whole lifetime and displays the raw
  // recovery phrase (a UVK-equivalent, TM-R9) once it reaches the reveal — bound it by the same idle
  // auto-lock the vault uses. On expiry zero the secret + its piece id and hand control to the
  // caller's timeout escape (drop the session, land on sign-in with the notice; the gate re-fires
  // with a fresh phrase next sign-in). Activity resets it, so a member actively typing the phrase
  // back is never interrupted.
  useAutoLock(REVEAL_TIMEOUT_S, () => {
    secretRef.current?.fill(0);
    secretRef.current = null;
    pieceIdRef.current = null;
    onTimeout();
  });

  // §F.7: zero the raw secret (and clear its piece id — together) on unmount as well as on confirm.
  // aliveRef re-arms across a StrictMode remount so a settlement landing after unmount can't onReady.
  useEffect(() => {
    aliveRef.current = true;
    return () => { aliveRef.current = false; secretRef.current?.fill(0); secretRef.current = null; pieceIdRef.current = null; };
  }, []);

  const run = useCallback(async () => {
    setStage("working");
    setErr("");
    try {
      const { recoverySecret, pieceId } = await net(setupAndCommitRecovery(client, account, currentAuthKey));
      if (!aliveRef.current) { recoverySecret.fill(0); return; } // unmounted mid-flight — never leave the secret live
      secretRef.current = recoverySecret;
      pieceIdRef.current = pieceId;
      setStage("reveal");
    } catch (e) {
      // Static copy only — NEVER interpolate secret material (§F.7).
      setErr(e instanceof NetworkError ? UNREACHABLE : "Couldn't set up your recovery phrase just now — try again in a moment.");
      setStage("error");
    }
  }, [client, account, currentAuthKey]);

  // Run once on mount (guarded against a StrictMode double-invoke so it can't double-commit).
  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    void run();
  }, [run]);

  const body =
    stage === "reveal" && secretRef.current ? (
      <RecoveryReveal
        secretRef={secretRef}
        clipboardClearSeconds={clipboardClearSeconds}
        onConfirmed={() => {
          if (settlingRef.current) return;
          settlingRef.current = true;
          setStage("confirming");
          // §F.9 (round-3) + design 2026-07-13: flip the durable flag only AFTER the type-back capture —
          // never at self-setup commit time — now BOUND to the piece this gate revealed and AWAITED.
          // Stale ⇒ the typed phrase attests a rotated-away piece: static notice + re-run (fresh
          // setup/reveal; the gate stays closed). Any other failure proceeds unconfirmed — the flag
          // stays 0, so the gate re-fires next entry (safe); it never marks an uncaptured phrase confirmed.
          void settleRecoveryConfirm(client, pieceIdRef.current, {
            zero: () => { secretRef.current?.fill(0); secretRef.current = null; pieceIdRef.current = null; },
            onStale: () => {
              if (!aliveRef.current) return;
              settlingRef.current = false;
              setPieceStale(true);
              void run();
            },
            onProceed: () => { if (aliveRef.current) onReady(account, store, meta); },
          });
        }}
      />
    ) : stage === "error" ? (
      <div>
        <Msg kind="err">{err}</Msg>
        <button type="button" className="primary" onClick={() => void run()}>Try again</button>
      </div>
    ) : (
      <p className="muted">{stage === "confirming" ? "Saving your confirmation…" : "Preparing your recovery phrase…"}</p>
    );

  return (
    <div>
      {pieceStale && <Msg kind="err">{RECOVERY_PIECE_STALE_NOTICE}</Msg>}
      {body}
      {/* A.5: the un-skippable gate still needs an escape that isn't "close the tab" — the same
          affordance as the Unlock card. Safe: recoveryConfirmed stays false, so the gate re-fires
          at the next sign-in (an un-captured phrase is replaced by the next run's fresh one). */}
      <div style={{ textAlign: "center", marginTop: 16 }}>
        <button type="button" className="link" onClick={onSignOut}>Sign out / use a different account</button>
      </div>
    </div>
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
    // Benign double-use dominates (a second family device scanning the same QR) — nudge to
    // Sign in rather than alarming.
    case "invite_used": return "That invite has already been used. Already set up this account? Switch to Sign in.";
    case "invite_expired": return "That invite has expired.";
    case "email_taken": return "An account with that email already exists.";
    case "invite_email_mismatch": return "This invite was created for a different email address — ask your admin for a new invite.";
    case "escrow_fingerprint_mismatch": return "Recovery fingerprint mismatch — do not proceed; contact your admin.";
    // design §F.4 register-gate refusals (posture ≠ invite): the client offered the wrong posture for
    // this invite. The invitee can't fix it — the admin re-issues an invite matching the intended posture.
    case "recovery_required": return "This invite needs the admin backstop set up — your admin should re-send it as an 'admin backstop' invite (or share the recovery sheet so you can confirm it).";
    case "escrow_not_allowed_when_waived": return "This invite is set to 'member-only' (no admin backstop) — reload and enroll without the recovery-sheet step, or ask your admin for a new invite.";
    default: return "Enrollment failed (" + code + ").";
  }
}

/**
 * F60 master-password hint (shared by enrollment + change-password): shows the live strength
 * label, whether it clears the floor, and a non-blocking non-ASCII caution (spec 01 §1). Purely
 * advisory — the actual gate lives in the forms' canSubmit + submit guards.
 */
export function MasterPasswordHint({ password }: { password: string }) {
  if (!password) return null;
  const score = estimateStrength(password);
  const ok = meetsMasterPasswordFloor(password);
  const nonAscii = masterPasswordHasNonAscii(password);
  return (
    <>
      <span className="muted" style={{ color: ok ? "var(--ok)" : "var(--danger)" }}>
        strength: {STRENGTH_LABELS[score]}{ok ? " ✓" : " — needs at least “good”"}
      </span>
      {nonAscii && (
        <span className="muted" style={{ display: "block", color: "var(--gold-text)" }}>
          contains non-ASCII characters — fine here, but they can be hard to type on some devices; make sure you can reproduce it
        </span>
      )}
    </>
  );
}
