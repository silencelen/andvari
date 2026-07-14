import { useCallback, useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import type { ClientPolicy } from "../api/types";
import { fromB64 } from "../crypto/bytes";
import { fingerprint, shortFingerprint, shortFormMatches } from "../crypto/escrow";
import { confirmMatches, displayForm } from "../crypto/member-recovery";
import { clearPendingEnroll, enrollPrefillFor, peekPendingEnroll, type EnrollPayload } from "../enroll/enrolllink";
import { enrollPosture, escrowGate, type EnrollPosture } from "../enroll/enrollposture";
import { Account, IdentityMismatchError, deviceName } from "../vault/account";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { VaultStore } from "../vault/store";
import { NetworkError, POLICY_UNAVAILABLE, UNREACHABLE, net } from "./errors";
import { Field } from "./Field";
import { Msg } from "./Msg";
import { Recover } from "./Recover";
import { confirmRegisteredRecovery, needsRecoveryCapture, setupAndCommitRecovery } from "./recovery-capture";
import { installId, saveSession, type Session } from "./session";
import { BrandSigil } from "./Sigil";
import { STRENGTH_LABELS, estimateStrength, masterPasswordHasNonAscii, meetsMasterPasswordFloor } from "./strength";

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
  onForget: () => void;
}

export function Welcome({ client, policy, policyError, policyErrorMessage, onRetryPolicy, mode, notice, onReady, onForget }: Props) {
  if ("unlock" in mode) {
    return <Unlock client={client} policy={policy} session={mode.unlock} notice={notice} onReady={onReady} onForget={onForget} />;
  }
  return <FreshStart client={client} policy={policy} policyError={policyError} policyErrorMessage={policyErrorMessage} onRetryPolicy={onRetryPolicy} notice={notice} onReady={onReady} />;
}

/** Reload or F26 lock with an existing session: master password re-derives keys. */
function Unlock({ client, policy, session, notice, onReady, onForget }: { client: ApiClient; policy: ClientPolicy | null; session: Session; notice?: string; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void; onForget: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  // §F.9: an unlock that succeeds but whose account has not durably CONFIRMED its recovery piece is
  // BLOCKED here — the capture gate takes over the card until the phrase is saved.
  const [capture, setCapture] = useState<CaptureHandoff | null>(null);

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
      const meta: LoginMeta = { isAdmin: session.isAdmin, mustChangePassword: false, escrowStale: keys.escrowStale ?? false, escrowFingerprint: keys.escrowFingerprint };
      if (needsRecoveryCapture(keys)) {
        // The master password is in hand — derive the login authKey (the server re-verifies it at
        // self-setup) and BLOCK on the capture gate rather than going straight to the vault.
        const currentAuthKey = await Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams);
        setCapture({ account, store, meta, currentAuthKey });
        return;
      }
      onReady(account, store, meta);
    } catch (e) {
      if (e instanceof KdfPolicyError) { setErr(WEAK_KDF_MESSAGE); return; } // H1 (spec 05 T1)
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
        {/* F26: why the user is here ("Locked after N minutes of inactivity.", …). The
            SPOKEN announce rides App's persistent Announcer (this box is silent-but-visible). */}
        {notice && !err && <Msg kind="info">{notice}</Msg>}
        {err && <Msg kind="err">{err}</Msg>}
        <Field label="Master password">
          <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <button className="primary" disabled={busy || !password}>{busy ? "Unsealing…" : "Unlock"}</button>
        <div style={{ textAlign: "center", marginTop: 16 }}>
          <button type="button" className="link" onClick={onForget}>Sign out / use a different account</button>
        </div>
      </form>
    </div>
  );
}

/** No session: sign in to an existing account, or enroll with an invite. */
function FreshStart({ client, policy, policyError, policyErrorMessage, onRetryPolicy, notice, onReady }: { client: ApiClient; policy: ClientPolicy | null; policyError: boolean; policyErrorMessage?: string; onRetryPolicy: () => Promise<void>; notice?: string; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void }) {
  // One-scan onboarding: peek (never consume) the captured enroll link so a StrictMode
  // double-invoked initializer reads the same value both times. The seed is read ONCE here.
  const [pending] = useState<EnrollPayload | null>(() => peekPendingEnroll());
  // Only a link minted for THIS exact origin applies (a mismatch → a notice + manual entry).
  const validPrefill = enrollPrefillFor(pending, window.location.origin);
  const [consented, setConsented] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [tab, setTab] = useState<"signin" | "enroll">("signin");
  // Self-service recovery (design §F.3): its own screen, reachable from the sign-in form or a
  // `#recover` deep link. On success it lands back on Sign in with a notice (sessions were revoked).
  const [recovering, setRecovering] = useState(() => typeof window !== "undefined" && window.location.hash === "#recover");
  const [localNotice, setLocalNotice] = useState("");
  // §F.7/§F.9: while a child is showing an un-skippable recovery reveal / capture gate (Enroll's
  // shown-once reveal, or SignIn's vault-entry capture), HIDE the Sign-in/Enroll tab bar — otherwise
  // a tab switch would navigate away from the reveal, unmounting it and losing the phrase the user
  // was told to save (a silent-total-loss escape). Whichever child is mounted reports this.
  const [blocking, setBlocking] = useState(false);

  if (recovering) {
    return (
      <Recover
        client={client}
        policy={policy}
        onDone={(n) => { setRecovering(false); setTab("signin"); setLocalNotice(n); }}
        onCancel={() => setRecovering(false)}
      />
    );
  }

  // Consume-semantics rule 4 (normative): a captured link must NOT auto-advance into the
  // prefilled form. Show an explicit origin-consent step first, so a silent drive-by
  // navigation (a hostile page replaying a photographed QR link) can't stage an enrollment
  // the member never saw and accepted.
  if (validPrefill && !consented && !dismissed) {
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
        {pending && !validPrefill && (
          <div className="msg err" style={{ display: "block" }} role="alert">
            This invite link is for a different address ({pending.o}) — open the exact link you were given, or sign in / enroll by hand.
          </div>
        )}
        {/* §F.7/§F.9: the tab bar is the escape hatch out of an un-skippable reveal — hide it while a
            child is blocking so the reveal cannot be navigated away from without confirming. */}
        {!blocking && (
          <div className="tabs">
            <button className={tab === "signin" ? "active" : ""} aria-pressed={tab === "signin"} onClick={() => setTab("signin")}>Sign in</button>
            <button className={tab === "enroll" ? "active" : ""} aria-pressed={tab === "enroll"} onClick={() => setTab("enroll")}>Enroll</button>
          </div>
        )}
        {tab === "signin" ? (
          <SignIn client={client} policy={policy} onReady={onReady} onForgot={() => { setLocalNotice(""); setRecovering(true); }} onBlockingChange={setBlocking} />
        ) : (
          <Enroll client={client} policy={policy} policyError={policyError} policyErrorMessage={policyErrorMessage} onRetryPolicy={onRetryPolicy} onReady={onReady} prefill={consented ? validPrefill : null} onBlockingChange={setBlocking} />
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
  useEffect(() => {
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
      const meta: LoginMeta = { isAdmin: s.isAdmin, mustChangePassword: s.mustChangePassword, escrowStale: s.accountKeys.escrowStale ?? false, escrowFingerprint: s.accountKeys.escrowFingerprint };
      if (needsRecoveryCapture(s.accountKeys)) {
        // `authKey` IS the login authKey derived from the just-typed master password — reuse it as
        // currentAuthKey (the server re-verifies it at self-setup). BLOCK on the capture gate.
        setCapture({ account, store, meta, currentAuthKey: authKey });
        return;
      }
      onReady(account, store, meta);
    } catch (e) {
      if (e instanceof ApiError && e.code === "totp_required") {
        // Break-glass origin (spec 03 §2): the password checked out; the server
        // additionally wants the account's server-TOTP code.
        setTotpNeeded(true);
        setErr("");
      } else if (e instanceof ApiError && e.code === "public_login_requires_totp") {
        setErr("This account has no TOTP enrolled — sign-in from the public address is blocked. Connect from inside (VPN/LAN), enroll TOTP in Settings, then retry.");
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
    return (
      <RecoveryCaptureGate
        client={client}
        account={capture.account}
        store={capture.store}
        meta={capture.meta}
        currentAuthKey={capture.currentAuthKey}
        clipboardClearSeconds={policy?.clipboardClearSeconds ?? 30}
        onReady={onReady}
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
          hint={<span className="muted">You are connecting via the public address — enter the code from your authenticator app.</span>}
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

function Enroll({ client, policy, policyError, policyErrorMessage, onRetryPolicy, onReady, prefill, onBlockingChange }: { client: ApiClient; policy: ClientPolicy | null; policyError: boolean; policyErrorMessage?: string; onRetryPolicy: () => Promise<void>; onReady: (a: Account, s: VaultStore, m: LoginMeta) => void; prefill?: EnrollPayload | null; onBlockingChange: (blocking: boolean) => void }) {
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
  // passes. After register() succeeds we stash the ready session and render the un-skippable reveal
  // gate BEFORE handing the account to the vault shell.
  const secretRef = useRef<Uint8Array | null>(null);
  const [ready, setReady] = useState<{ account: Account; store: VaultStore; meta: LoginMeta } | null>(null);

  // §F.7: zero the raw recovery secret on unmount as well as on confirm (mirrors Recover.tsx's
  // cleanup) — if the reveal is interrupted (navigate away / lock), the secret never lingers in memory.
  useEffect(() => () => { secretRef.current?.fill(0); secretRef.current = null; }, []);
  // §F.7/§F.9: while the shown-once reveal is up, tell FreshStart to HIDE the Sign-in/Enroll tab bar so
  // the user cannot navigate away from the reveal (unmounting it, losing the phrase) without confirming.
  const revealing = ready !== null && secretRef.current !== null;
  useEffect(() => { onBlockingChange(revealing); }, [revealing, onBlockingChange]);

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
      setReady({ account, store, meta: { isAdmin: s.isAdmin, mustChangePassword: s.mustChangePassword, escrowStale: s.accountKeys.escrowStale ?? false, escrowFingerprint: s.accountKeys.escrowFingerprint } });
    } catch (e) {
      // Static error strings only — NEVER interpolate secret material.
      setErr(e instanceof KdfPolicyError ? WEAK_KDF_MESSAGE : e instanceof NetworkError ? UNREACHABLE : e instanceof ApiError ? enrollError(e.code) : "Enrollment failed.");
    } finally {
      setBusy(false);
    }
  };

  // §F.7: the shown-once recovery-phrase reveal gates account usability — rendered after a successful
  // register, holding the secret in secretRef, and it won't hand the account to the vault until the
  // member types the phrase back (confirmMatches). No skip affordance (silent-total-loss guard).
  if (ready && secretRef.current) {
    return (
      <RecoveryReveal
        secretRef={secretRef}
        clipboardClearSeconds={policy?.clipboardClearSeconds ?? 30}
        onConfirmed={() => {
          const r = ready;
          secretRef.current?.fill(0);
          secretRef.current = null;
          setReady(null);
          // §F.9: flip the server's recoveryConfirmed flag — the register-committed piece IS what was
          // just shown + confirmed (NO regenerate — that would clobber the phrase the user saved).
          // Best-effort: a failure only re-nudges via the vault-entry capture gate on the next unlock.
          void confirmRegisteredRecovery(client).catch(() => {});
          onReady(r.account, r.store, r.meta);
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
      // SECRET clipboard-clear (Vault.useCopy parity): wipe after the policy window.
      window.setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), Math.max(1, clipboardClearSeconds) * 1000);
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
 * type-back confirm flips `recoveryConfirmed` via /recovery/self/confirm before proceeding to the vault.
 * `currentAuthKey` is the login authKey the caller derived from the freshly-typed master password
 * (the server re-verifies it, like changePassword). Renders content only — callers wrap it in the
 * card appropriate to their context. A failed commit keeps the gate closed with a retry (never
 * proceeds to the vault, never leaves a live secret dangling — the secret is zeroed on failure).
 */
function RecoveryCaptureGate({
  client,
  account,
  store,
  meta,
  currentAuthKey,
  clipboardClearSeconds,
  onReady,
}: {
  client: ApiClient;
  account: Account;
  store: VaultStore;
  meta: LoginMeta;
  currentAuthKey: string;
  clipboardClearSeconds: number;
  onReady: (a: Account, s: VaultStore, m: LoginMeta) => void;
}) {
  const secretRef = useRef<Uint8Array | null>(null);
  const [stage, setStage] = useState<"working" | "reveal" | "error">("working");
  const [err, setErr] = useState("");
  const startedRef = useRef(false);

  // §F.7: zero the raw secret on unmount as well as on confirm.
  useEffect(() => () => { secretRef.current?.fill(0); secretRef.current = null; }, []);

  const run = useCallback(async () => {
    setStage("working");
    setErr("");
    try {
      const secret = await net(setupAndCommitRecovery(client, account, currentAuthKey));
      secretRef.current = secret;
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

  if (stage === "reveal" && secretRef.current) {
    return (
      <RecoveryReveal
        secretRef={secretRef}
        clipboardClearSeconds={clipboardClearSeconds}
        onConfirmed={() => {
          secretRef.current?.fill(0);
          secretRef.current = null;
          // §F.9 (round-3): flip the durable flag only AFTER the type-back capture — exactly like the enroll
          // path — never at self-setup commit time. Best-effort: a failed confirm just re-fires the gate next
          // entry (safe), it never marks an unseen/uncaptured phrase confirmed.
          void confirmRegisteredRecovery(client).catch(() => {});
          onReady(account, store, meta);
        }}
      />
    );
  }
  if (stage === "error") {
    return (
      <div>
        <Msg kind="err">{err}</Msg>
        <button type="button" className="primary" onClick={() => void run()}>Try again</button>
      </div>
    );
  }
  return <p className="muted">Preparing your recovery phrase…</p>;
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
        <span className="muted" style={{ display: "block", color: "var(--gold)" }}>
          contains non-ASCII characters — fine here, but they can be hard to type on some devices; make sure you can reproduce it
        </span>
      )}
    </>
  );
}
