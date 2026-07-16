import { useEffect, useRef, useState } from "react";
import { ApiClient, ApiError } from "../api/client";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import type { ClientPolicy, RecoveryVerifyResponse } from "../api/types";
import { deriveAuthKey as deriveRecoveryAuthKey, parseSecret } from "../crypto/member-recovery";
import { Account, IdentityMismatchError } from "../vault/account";
import { NetworkError, UNREACHABLE, net } from "./errors";
import { Field } from "./Field";
import { Msg } from "./Msg";
import { BrandSigil } from "./Sigil";
import { STRENGTH_LABELS, estimateStrength, meetsMasterPasswordFloor } from "./strength";
import { useAutoLock } from "./useAutoLock";

/** CR-02 (compliance 2026-07-15): the reset step holds a UVK-equivalent recovery secret (TM-R9) in
 *  memory outside the vault phase, where App's auto-lock never arms. A fixed conservative idle cap
 *  (KH-22 / TM-T4) bounds a walked-away device; activity resets it. Kept in sync with Welcome's. */
const REVEAL_TIMEOUT_S = 300; // 5 minutes idle
const REVEAL_TIMEOUT_NOTICE = "Timed out for your security. Sign in again — a fresh recovery phrase will be shown.";

/**
 * Per-member SELF-service recovery (design 2026-07-12 §F.3) — the "I forgot my master password" path
 * for a member who saved their recovery phrase. Two phases against a mocked-in-tests api:
 *
 *   1. verify — enter email + recovery phrase → the client derives `recoveryAuthKey` (HKDF only, no
 *      Argon2id) and POSTs it. The server proves possession WITHOUT ever seeing the phrase, and on
 *      success hands back a single-use ticket + the material to open the UVK.
 *   2. reset  — the client opens the SAME UVK from the phrase, runs the spec 01 §5 identity-pubkey
 *      HARD-FAIL (a substituted identity key aborts here, BEFORE commit), then re-wraps the invariant
 *      UVK under a freshly-chosen password and commits. All sessions are revoked, so the member signs
 *      in fresh afterward.
 *
 * SHOWN-ONCE discipline (§F.7): the raw secret bytes live in a `useRef`, are zeroed the instant they
 * are no longer needed (commit success, cancel, or unmount), and are NEVER persisted or logged; error
 * strings are static and never interpolate secret material.
 */
export function Recover({
  client,
  policy,
  onDone,
  onCancel,
  onTimedOut,
}: {
  client: ApiClient;
  policy: ClientPolicy | null;
  /** Recovery committed — bounce back to Sign in with a success notice (sessions were revoked). */
  onDone: (notice: string) => void;
  onCancel: () => void;
  /** CR-02: idle-timeout while the recovery secret is live — zero it and bounce to Sign in with a notice. */
  onTimedOut: (notice: string) => void;
}) {
  const [step, setStep] = useState<"verify" | "reset">("verify");
  const [email, setEmail] = useState("");
  const [phrase, setPhrase] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [verify, setVerify] = useState<RecoveryVerifyResponse | null>(null);

  // The raw recovery secret (§F.7): held in a ref, zeroed as soon as it is spent.
  const secretRef = useRef<Uint8Array | null>(null);
  const clearSecret = () => {
    secretRef.current?.fill(0);
    secretRef.current = null;
  };
  // Zero the secret if the component unmounts mid-flow (navigate away / lock).
  useEffect(() => clearSecret, []);

  // CR-02: the "reset" step holds the raw recovery secret (secretRef) while the user picks a new
  // password. Bound that window by the idle auto-lock — on expiry zero the secret and bounce to
  // Sign in with the notice (disabled with timeout 0 during "verify", where no secret is held yet;
  // activity resets it so an actively-typing user is never interrupted).
  useAutoLock(step === "reset" ? REVEAL_TIMEOUT_S : 0, () => {
    clearSecret();
    onTimedOut(REVEAL_TIMEOUT_NOTICE);
  });

  const submitVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    // parseSecret is TOTAL — a malformed phrase is a user error, not an exception.
    const secret = parseSecret(phrase);
    if (!secret) return setErr("That doesn't look like a recovery phrase — check it and try again.");
    setBusy(true);
    try {
      const authKey = await deriveRecoveryAuthKey(secret);
      const resp = await net(client.recoverySelfVerify(email.trim(), authKey));
      // Keep ONLY the bytes; drop the typed string from state so it does not linger.
      clearSecret();
      secretRef.current = secret;
      setPhrase("");
      setVerify(resp);
      setStep("reset");
    } catch (e) {
      setErr(verifyErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const submitReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    if (!policy) return setErr("Couldn't reach the server for its settings — try again in a moment.");
    if (!verify || !secretRef.current) return setErr("Your recovery session expired — start again.");
    if (!meetsMasterPasswordFloor(password)) {
      return setErr("Choose a stronger master password — mix length with upper/lower case, digits, or symbols.");
    }
    if (password !== confirm) return setErr("The two passwords don't match.");
    setBusy(true);
    try {
      // recover() opens the SAME UVK and runs the identity hard-fail BEFORE producing the commit body;
      // a substituted identity key throws IdentityMismatchError (tampering), not a bad-secret error.
      const commit = await Account.recover({
        recoverySecret: secretRef.current,
        verify,
        newPassword: password,
        newKdfParams: policy.kdfParams,
      });
      await net(client.recoverySelfCommit(commit));
      clearSecret();
      setPassword("");
      setConfirm("");
      onDone("Master password reset — sign in with your new password.");
    } catch (e) {
      setErr(resetErrorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const pwStrongEnough = meetsMasterPasswordFloor(password);

  return (
    <div className="auth-shell">
      <div className="card">
        <div className="card-hero">
          <div className="sigil"><BrandSigil /></div>
          <h1>Recover your account</h1>
          <p>{step === "verify" ? "with your saved recovery phrase" : "choose a new master password"}</p>
        </div>
        {err && <Msg kind="err">{err}</Msg>}

        {step === "verify" ? (
          <form onSubmit={submitVerify}>
            <div className="msg info" style={{ display: "block" }}>
              Enter the <strong>recovery phrase</strong> you saved when you set up this account. Your master
              password is not needed — the phrase alone lets you set a new one.
            </div>
            <Field label="Email">
              <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
            </Field>
            <Field label="Recovery phrase" hint={<span className="muted">exactly as you saved it — spaces are ignored</span>}>
              <textarea
                className="mono"
                rows={2}
                autoComplete="off"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                value={phrase}
                onChange={(e) => setPhrase(e.target.value)}
                placeholder="your saved recovery phrase"
              />
            </Field>
            <button className="primary" disabled={busy || !email.trim() || !phrase.trim()}>{busy ? "Checking…" : "Continue"}</button>
            <div style={{ textAlign: "center", marginTop: 12 }}>
              <button type="button" className="link" onClick={onCancel}>Back to sign in</button>
            </div>
          </form>
        ) : (
          <form onSubmit={submitReset}>
            <div className="msg info" style={{ display: "block" }}>
              Your recovery phrase checked out. Choose a <strong>new master password</strong> — it re-locks the
              same vault; nothing you stored is lost.
            </div>
            <Field label="New master password" hint={<PwHint password={password} />}>
              <input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
            <Field
              label="Confirm new master password"
              hint={confirm && confirm !== password ? <span className="muted" style={{ color: "var(--danger)" }}>passwords don't match</span> : undefined}
            >
              <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </Field>
            <button className="primary" disabled={busy || !pwStrongEnough || password !== confirm}>{busy ? "Resetting…" : "Reset master password"}</button>
            <div style={{ textAlign: "center", marginTop: 12 }}>
              <button type="button" className="link" onClick={() => { clearSecret(); onCancel(); }}>Cancel</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

/**
 * Phase-1 (verify) error copy. Pure + exported so the server-code branches are unit-pinned. The server
 * values are the source of truth (RecoveryTest.kt): the public-origin refusal is `recovery_public_disabled`.
 * Uniform copy on 401 — the server is anti-enumeration (§F.5); never reveal which of email / phrase /
 * no-recovery-row was wrong. NEVER interpolates secret material (§F.7 static-error discipline).
 */
export function verifyErrorMessage(e: unknown): string {
  if (e instanceof KdfPolicyError) return WEAK_KDF_MESSAGE; // H1 (spec 05 T1)
  return e instanceof NetworkError
    ? UNREACHABLE
    : e instanceof ApiError && e.status === 401
      ? "We couldn't verify that email and recovery phrase."
      : e instanceof ApiError && e.code === "recovery_public_disabled"
        ? "Account recovery isn't available from this public address — connect from inside (VPN/LAN) and try again."
        : e instanceof ApiError
          ? "The server had a problem answering — try again in a moment."
          : "Recovery failed. Please try again.";
}

/**
 * Phase-2 (reset/commit) error copy. Pure + exported so the server-code branches are unit-pinned. An
 * expired/consumed ticket is `invalid_ticket` (the server value, pinned by RecoveryTest.kt).
 * IdentityMismatchError is a DISTINCT tampering signal — never softened into "wrong phrase".
 */
export function resetErrorMessage(e: unknown): string {
  if (e instanceof KdfPolicyError) return WEAK_KDF_MESSAGE; // H1 (spec 05 T1)
  return e instanceof IdentityMismatchError
    ? e.message
    : e instanceof NetworkError
      ? UNREACHABLE
      : e instanceof ApiError && (e.code === "invalid_ticket" || e.status === 401)
        ? "Your recovery session expired — start again."
        : e instanceof ApiError && e.code === "recovery_account_not_active"
          ? "This account is disabled — self-recovery isn't available. Ask your admin to recover it."
          : e instanceof ApiError
            ? "The server had a problem answering — try again in a moment."
            : "Recovery failed. Please try again.";
}

/** Minimal master-password strength hint (self-contained to avoid a Welcome ↔ Recover import cycle). */
function PwHint({ password }: { password: string }) {
  if (!password) return null;
  const score = estimateStrength(password);
  const ok = meetsMasterPasswordFloor(password);
  return (
    <span className="muted" style={{ color: ok ? "var(--ok)" : "var(--danger)" }}>
      strength: {STRENGTH_LABELS[score]}{ok ? " ✓" : " — needs at least “good”"}
    </span>
  );
}
