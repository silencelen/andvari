import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";
import type { ClientPolicyV2 } from "../api/wire";
import { KdfPolicyError, WEAK_KDF_MESSAGE } from "../crypto/keys";
import { decodeName, emailNorm, NONE } from "../crypto/trust/grammar";
import { ESCROW_WRONG_FORM, type OperatorOffer, operatorOffer, operatorRecoveryOffered, PROOF_REFUSED, refusalOf, SERVER_KEYS_NOT_KNOWN } from "../vault/settingsflow";
import type { SessionWrap } from "../vault/sessionwrap";
import { ONLY_ME, RecoveryChoice, type RecoveryChoiceValue, recoveryChoiceReady } from "./RecoveryChoice";
import { Account, deviceName } from "../vault/account";
import { accountId, SELF_IDENTITY_MISMATCH, wipeOpened, type OpenedAccount } from "../vault/accountopen";
import { boundAccountAt } from "../vault/selfidentity";
import { EarlierAccountOffer, type EarlierOffer, earlierOfferFor, identityRefusal } from "./ForgetEarlier";
import { abandonKit, commitKitRecovery, confirmKit, currentAuthKey, type FreshKit, type KitCommitResult, type KitInput, type KitVerified, parseKitInput, PasswordRuleRefused, rotateKit, verifyKit } from "../vault/kitflow";
import type { UnknownWhy } from "../vault/afterstore";
import { canCreateAccount, completeSignup, openFromCopy, type PinOutcome, settlePin, signIn, startSignup, type UnlockResult, unlockSession } from "../vault/onboardflow";
import type { CardStatus, FirstPin, WebPin } from "../vault/pinstore";
import { runPow } from "../vault/pow";
import type { SessionKeys } from "../vault/sessionwrap";
import type { VaultStore } from "../vault/store";
import { Busy } from "./Busy";
import {
  AGE_13_OR_OLDER,
  AS_THE_SERVER_NAMES_ITSELF,
  CARD_CHANGED_UPDATE,
  CARD_FORK,
  CARD_MOVED_UPDATE,
  CARD_MOVED_WEB,
  CARD_NOT_VERIFIED,
  CARD_OTHER_ADDRESS,
  CARD_OTHER_ADDRESS_TITLE,
  CARD_RECORD_DAMAGED,
  CARD_RECORD_DAMAGED_TITLE,
  CARD_REFUSED,
  CHANGE_NOT_STORED,
  CHANGE_NOT_STORED_UNDATED,
  WRONG_PASSWORD_KDF_NOT_USABLE,
  CARD_WITHHELD,
  CODE_SENT_DAILY,
  CREATE_ACCOUNT_HERE,
  EMAIL_CHECK_SPAM,
  ENDED_COPY_OPEN,
  ENDED_COPY_READ,
  ESCROW_WRONG_FORM_TEXT,
  fill,
  FORGET_ARMED_LABEL,
  FORGET_DELETES_COPY,
  FORGET_KEEP,
  FORGET_THIS_SERVER,
  UNSENT_SEND_FIRST_SIGN_IN,
  UNSENT_SEND_FIRST_UNLOCK,
  unsentLine,
  FORKED_COPY_OPEN,
  FORKED_COPY_READ,
  FORKED_NO_COPY,
  GATE_BASELINE,
  GATE_CALLS_ITSELF,
  GATE_CANCEL,
  GATE_CONTINUE,
  GATE_ENTERING_PASSWORD,
  GATE_KIND_CHANGE,
  GATE_KIND_CONTINUE,
  GATE_KIND_NOT_NOW,
  GATE_OPERATOR_KEY,
  GATE_TITLE_CONNECT,
  GATE_TITLE_KIND_CHANGE,
  IDENTITY_FAULT,
  KIT_PASTE_LABEL,
  KIT_RECOVER,
  KIT_RECOVER_SETS_PASSWORD,
  KIT_RECOVERY_STORED_UNCHECKED,
  passwordRuleText,
  REMADE_ACCOUNT_REFUSAL,
  KIT_RECOVERY_CONFIRM_SERVER_REFUSED,
  SIGNUP_CONFIRM_SERVER_REFUSED,
  CARD_KIND_CHANGED_RELOAD,
  KIT_RECOVERY_STORED_KIT_GONE,
  KIT_RECOVERY_UNKNOWN_KIT_GONE,
  SIGNUP_STORED_KIT_GONE,
  SIGNUP_UNKNOWN_KIT_GONE,
  KIT_RECOVERY_UNKNOWN,
  KIT_RECOVERY_UNKNOWN_SERVER_ERROR,
  KIT_RECOVERY_UNKNOWN_UNREADABLE,
  KIT_RECOVERY_NOT_SENT,
  KIT_REPLACED,
  KIT_WRONG_SERVER,
  LINK_REQUIRED_WEB,
  LINK_REQUIRED_WEB_TITLE,
  MAIL_UNAVAILABLE,
  MASTER_PASSWORD_FOR,
  OPERATOR_KIT_RESET_NOT_ON_WEB,
  RECOVERY_CHOICE_REFUSED,
  NAME_TOO_LONG,
  OPERATOR_NOT_ON_WEB,
  POW_PROGRESS,
  RECOVERY_KIT_ONLY,
  RECOVERY_ONLY_ME_DETAIL,
  KDF_NOT_USABLE,
  signInAnswerRefusedText,
  kdfRefusalText,
  OFFLINE_COPY_UNREADABLE,
  SERVER_KEYS_NOT_KNOWN_REFUSED,
  SERVER_KEYS_NOT_KNOWN_SIGN_IN,
  SERVER_REFUSED_PROOF,
  SESSION_ENDED_HELD,
  SESSION_NOT_CONFIRMED,
  SIGN_IN,
  SIGN_IN_FORGOT,
  SIGN_IN_KEYS_NOT_THIS_ACCOUNT,
  SIGN_IN_WAIT,
  SIGNIN_BACKOFF,
  SIGNUP_FULL,
  SIGNUP_STORED_UNCHECKED,
  SIGNUP_UNKNOWN,
  SIGNUP_UNKNOWN_SERVER_ERROR,
  SIGNUP_UNKNOWN_UNREADABLE,
  SIGNUP_NOT_SENT,
  USE_THE_APP,
} from "./copy";
import { answerLimitText, NetworkError, POLICY_UNAVAILABLE, UNREACHABLE } from "./errors";
import { nameText } from "./nametext";
import { Field } from "./Field";
import { fmtDate, fmtDayYear } from "./format";
import { instanceLabel, KitGate, StoredKitCard } from "./KitCard";
import { Announcer, Msg } from "./Msg";
import { cachedAccountKeys, copyAtUnlock, enterVault, knownIdentity, type LoginMeta, OperatorAccountError, type WebContext, writeSignupRecovery } from "./opensession";
import { MasterPasswordHint } from "./passwordadvice";
import { cachedPendingWraps, clearSession, offlineCopyStamp, revokeSessionBestEffort, type Session, tokensKeptAcrossLock, unsentChangeCount, wipeVaultCache } from "./session";
import { endedByServer, endedUnconfirmed } from "./sessionend";
import { BrandSigil, Wordmark } from "./Sigil";
import type { SessionHow } from "../vault/contactbook";
import { SignOutLink, type UnsentAsk, useUnsentArm } from "./SignOutLink";
import { meetsMasterPasswordFloor } from "./strength";
import { abandonSignIn, beginSignIn, beginUnlock, signInForm, type SignInFlow } from "./tabsession";

export type { LoginMeta } from "./opensession";

type Mode = { unlock: Session } | { fresh: true };
type Ready = (account: Account, store: VaultStore, meta: LoginMeta) => void;

/** Static (never interpolated). Shown after a kit screen sat idle: the kit is shown afresh at the next sign-in. */
const KIT_TIMEOUT_NOTICE = "Timed out for your security. Sign in again — a fresh recovery kit will be shown.";
const UNSEALING_NOTICE = "Unsealing your vault — this takes a few seconds.";
const WRONG_PASSWORD = "Wrong master password.";
/** The unlock card's session end when no App handler is wired (App passes onSessionEnded). */
const SESSION_EXPIRED_NOTICE = "Session expired — sign in again.";
const DEVICE_PROBLEM = "Something went wrong on this device while unsealing your vault — your password is probably fine. Reload this page and try again.";
/** PLACEHOLDER: a refused sign-up step (spec 03 §14.1 codes the design gives no sentence for). */
const SIGNUP_REFUSALS: Record<string, string> = {
  signup_closed: "This server isn't taking new accounts.",
  signup_full: SIGNUP_FULL,
  invalid_email: "That doesn't look like an email address.",
  email_domain_blocked: "This server doesn't take sign-ups from that email domain.",
  age_confirm_required: "Please confirm you are 13 or older.",
  pow_required: "Something went wrong getting ready to send the code. Try again.",
  bad_pow: "Something went wrong getting ready to send the code. Try again.",
  mail_unavailable: MAIL_UNAVAILABLE,
  bad_code: "That code is wrong or has expired.",
  bad_ticket: "This sign-up took too long. Start again.",
  email_taken: "An account with this email already exists. Sign in instead.",
  signup_daily_max: "This server has taken all the new accounts it can today. Try again tomorrow.",
  rate_limited: SIGNIN_BACKOFF,
  kdf_too_weak: WEAK_KDF_MESSAGE,
  [ESCROW_WRONG_FORM]: ESCROW_WRONG_FORM_TEXT,
};

/** The text for a refusal the flows hand back. Never the server's own message: that text is the server's to choose. */
export function refusalText(e: unknown): string {
  const limit = answerLimitText(e);
  if (limit !== null) return limit;
  if (e instanceof KdfPolicyError) return kdfRefusalText(e);
  if (e instanceof NetworkError || e instanceof TypeError) return UNREACHABLE;
  if (e instanceof ApiError) {
    const known = SIGNUP_REFUSALS[e.code];
    if (known) return known;
    if (e.status === 0) return "The server's answer didn't make sense, so nothing was changed.";
    if (e.status >= 500) return "The server had a problem answering. Try again in a moment.";
    return `The server refused this (${e.code}).`;
  }
  // The address grammar (spec 01 §5.5) refused locally, before anything was sent: the same sentence as the server's.
  if (e instanceof Error && e.message === "invalid_email") return SIGNUP_REFUSALS.invalid_email!;
  return DEVICE_PROBLEM;
}

/**
 * A refused sign-in's text. The sign-in's back-off has a line of its own (SIGN_IN_WAIT, "at least a minute"): the server
 * names a fixed wait there, since its caller has proven nothing, so its number is never shown, unlike the real wait a
 * signed-in session is told (reauthtext.ts). Everything else is {@link refusalText}.
 */
export function signInRefusalText(e: unknown): string {
  if (e instanceof ApiError && (e.code === "rate_limited" || e.status === 429)) return SIGN_IN_WAIT;
  return refusalText(e);
}

/**
 * What the person reads when the kit at sign-in (a fresh kit for an account whose kit was never confirmed) did not go
 * through. It reads the session's mark itself, as every other proof's text does: a proof the server refused while the
 * session is marked as holding keys the server does not ({@link SessionWrap.serverKeysNotKnown}) is said as that, never
 * as a wrong password, whatever path led here. [wrap] is the session's; a sign-in and an unlock of the served keys carry
 * none.
 */
/**
 * The line for a sign-in, a sign-up or a kit's check that stopped before anything was sent: the card's refusal only
 * where the pinned card failed (`pin`); where the password rule refused, the rule's own line by its decision, with the
 * confirmation's own line where "sign in again" is not open ([where]: a sign-up has no account yet, a kit recovery no
 * password).
 */
export function stoppedBeforeSendingText(r: { readonly kind: "pin" } | { readonly kind: "password_rule"; readonly decision: "trust_gate" | "refuse_entry" }, where: "sign_in" | "sign_up" | "kit_recovery"): string {
  if (r.kind === "pin") return CARD_REFUSED;
  if (r.decision === "trust_gate" && where === "sign_up") return SIGNUP_CONFIRM_SERVER_REFUSED;
  if (r.decision === "trust_gate" && where === "kit_recovery") return KIT_RECOVERY_CONFIRM_SERVER_REFUSED;
  return passwordRuleText(r.decision);
}

/**
 * The first screen's stop where the pinned server's newest card did not simply extend the pin: moved, changed its kind
 * (an update needed, or a change to show the person: never "couldn't verify", the card verified), or not verified.
 */
export function pinChangedText(s: CardStatus): string {
  if (s.kind === "moved") return fill(CARD_MOVED_WEB, s.newest.origin);
  if (s.kind === "kind_changed") return s.mustUpdate ? CARD_CHANGED_UPDATE : CARD_KIND_CHANGED_RELOAD;
  return CARD_REFUSED;
}

export function kitAtSignInText(e: unknown, wrap?: Pick<SessionWrap, "serverKeysNotKnown">): string {
  if (e instanceof PasswordRuleRefused) return passwordRuleText(e.decision);
  const r = refusalOf(e, wrap);
  if (r.kind === "refused" && r.code === SERVER_KEYS_NOT_KNOWN) return SERVER_KEYS_NOT_KNOWN_REFUSED;
  // The proof was made here (currentAuthKey opened the session's wrap first): the server's refusal is never a wrong password.
  if (r.kind === "refused" && r.code === PROOF_REFUSED) return SERVER_REFUSED_PROOF;
  return refusalText(e);
}

/**
 * The unlock card's sentence for the two results that say two things at once (spec 01 §7): a password that opens none of
 * this browser's own keys while the server's cost cannot be used; and the new password of a change made here that never
 * reached the server (with the day it was made, where the copy recorded it).
 */
export function unlockRefusalText(r: Extract<UnlockResult, { kind: "wrong_password_kdf_refused" | "change_not_stored" }>): string {
  if (r.kind === "wrong_password_kdf_refused") return WRONG_PASSWORD_KDF_NOT_USABLE;
  return r.at === null ? CHANGE_NOT_STORED_UNDATED : fill(CHANGE_NOT_STORED, fmtDayYear(r.at));
}

interface Props {
  ctx: WebContext;
  policy: ClientPolicyV2 | null;
  policyError: boolean;
  policyErrorMessage?: string;
  onRetryPolicy: () => Promise<void>;
  mode: Mode;
  notice?: string;
  /** The account of a session the server ended on this profile: the first screen offers "Sign in" to it first. */
  knownEmail?: string;
  onReady: Ready;
  /**
   * Leave this card. With no notice it is the person's own sign-out (SignOutLink asked first). With a notice it is a
   * sign-in this browser ended by itself (the kit timed out; the operator account) after ending that sign-in's own
   * session: App says the number of unsent changes first and deletes the copy only when there are none.
   */
  onForget: (notice?: string) => void;
  /** Design §4.4: the unlock found the session gone server-side (a definitive 401); App ends it and keeps the copy. */
  onSessionEnded?: () => void;
  /**
   * This browser itself ended the sign-in or session and kept the copy because it holds changes not sent (App
   * endByClient): the notice says why and how many, so the card does not also say that the server ended it.
   */
  endedByBrowser?: boolean;
}

export function Welcome(p: Props) {
  return (
    <div className="auth-shell">
      <div className="card">
        <div className="card-hero">
          <div className="sigil"><BrandSigil /></div>
          <h1><Wordmark /></h1>
        </div>
        {p.notice && <Msg kind="info">{p.notice}</Msg>}
        <PinSettled ctx={p.ctx} forPassword={"unlock" in p.mode} onForgotten={() => void p.onRetryPolicy()} held={"unlock" in p.mode ? { session: p.mode.unlock, onReady: p.onReady, onForget: p.onForget } : undefined}>
          {(pin, cardNotice) =>
            "unlock" in p.mode ? (
              <Unlock ctx={p.ctx} policy={p.policy} pin={pin} cardNotice={cardNotice} session={p.mode.unlock} onReady={p.onReady} onForget={p.onForget} onSessionEnded={p.onSessionEnded ?? (() => p.onForget(SESSION_EXPIRED_NOTICE))} endedByBrowser={p.endedByBrowser === true} />
            ) : (
              <FreshStart {...p} pin={pin} cardNotice={cardNotice} />
            )
          }
        </PinSettled>
      </div>
    </div>
  );
}

/** What the unlock card says of this browser's offline copy: none, one it cannot read, or one with its last sync. */
export type CopyStamp = { readonly lastSyncAt: number | null; readonly unreadable?: true };

/**
 * The unlock card's stamp for [userId]'s offline copy: null when this browser holds none. A copy that is there but cannot
 * be read here (its keys row not a usable key set, or the database fails to open: {@link copyAtUnlock}'s `unreadable`)
 * is said as that, never with a "last synced" time over keys nothing here can open. The copy is read only when the
 * probe found a database, so the card never makes one.
 */
export async function unlockCopyStamp(
  userId: string,
  stampOf: (userId: string) => Promise<{ lastSyncAt: number | null } | null> = offlineCopyStamp,
  copyOf: (userId: string) => Promise<{ kind: string }> = copyAtUnlock,
): Promise<CopyStamp | null> {
  const s = await stampOf(userId);
  if (s === null) return null;
  const c = await copyOf(userId).catch(() => ({ kind: "unreadable" }));
  return c.kind === "unreadable" ? { lastSyncAt: s.lastSyncAt, unreadable: true } : s;
}

/** design 2026-07-13 §E.3.4: the unlock card's line saying this browser holds an encrypted offline copy. */
export function OfflineCopyUnlockLine({ stamp }: { stamp: CopyStamp | null }) {
  if (!stamp) return null;
  if (stamp.unreadable === true) return <p className="muted" style={{ textAlign: "center", marginTop: 0 }}>{OFFLINE_COPY_UNREADABLE}</p>;
  return (
    <p className="muted" style={{ textAlign: "center", marginTop: 0 }}>
      Offline copy on this device — last synced {stamp.lastSyncAt !== null ? fmtDate(stamp.lastSyncAt) : "not yet"}
    </p>
  );
}

// ---- The pin -----------------------------------------------------------------------------------------------

/** The card's name as shown: decoded, plain text, marked for a pin nobody but the server vouches for (§4.5). */
export function shownName(pin: WebPin): string {
  const { name } = instanceLabel(pin);
  return pin.root === "trust_gate" ? `${name} ${AS_THE_SERVER_NAMES_ITSELF}` : name;
}

/** The line a card notice shows above the forms; null for none. */
export function cardNoticeText(n: CardStatus | null): string | null {
  if (n === null) return null;
  switch (n.kind) {
    case "withheld":
      return CARD_WITHHELD;
    case "not_verified":
      // Approved entry 11, in the place CARD_WITHHELD shows: the pin stays and nothing stops.
      return CARD_NOT_VERIFIED;
    case "moved":
      return fill(CARD_MOVED_WEB, n.newest.origin);
    case "kind_changed":
      return n.mustUpdate ? CARD_CHANGED_UPDATE : null;
    case "unreachable":
      return UNREACHABLE;
    default:
      return null;
  }
}

type PinView =
  | { kind: "checking" }
  | { kind: "ready"; pin: WebPin; notice: CardStatus | null }
  | { kind: "stop"; first: PinOutcome & { kind: "stop" } }
  | { kind: "kind_gate"; status: Extract<CardStatus, { kind: "kind_changed" }> }
  /** Design §4.4: a session this browser holds, at an origin with no pin record. */
  | { kind: "held_no_pin" };

/**
 * Settles this browser's pin of the origin that served it (§13) before any form shows: the baked root for the
 * public instance, the Trust Gate once per browser for any other origin, the stop screen on a fork or a damaged
 * record. The forms then work under the pin.
 */
/** A session this browser holds, for what a stop screen may still offer it (§4.4: its copy, read-only). */
type Held = { session: Session; onReady: Ready; onForget: (notice?: string) => void };

function PinSettled({ ctx, forPassword, held, onForgotten, children }: { ctx: WebContext; forPassword: boolean; held?: Held; onForgotten?: () => void; children: (pin: WebPin, notice: CardStatus | null) => JSX.Element }) {
  const [view, setView] = useState<PinView>({ kind: "checking" });
  const [busy, setBusy] = useState(false);
  const holding = held !== undefined;
  const check = useCallback(async () => {
    // Design §4.4 "No credential goes to an origin without a pin in force": a kept session whose origin holds no pin
    // record (a move that stopped half-way, a record that was lost) does not unlock and dials nothing, not even the
    // card chain of a first pin; it can only be forgotten.
    if (holding && ctx.pins.state(ctx.origin).kind === "none") {
      setView({ kind: "held_no_pin" });
      return;
    }
    setView({ kind: "checking" });
    const s = await settlePin(ctx.pins, ctx.origin);
    if (s.kind === "pinned") {
      if (s.notice?.kind === "kind_changed" && !s.notice.mustUpdate) setView({ kind: "kind_gate", status: s.notice });
      else setView({ kind: "ready", pin: s.pin, notice: s.notice });
    } else setView({ kind: "stop", first: s });
  }, [ctx, holding]);
  useEffect(() => {
    void check();
  }, [check]);

  if (view.kind === "checking") return <p className="muted"><Busy>Checking this server…</Busy></p>;
  if (view.kind === "held_no_pin") return held ? <HeldWithoutPin ctx={ctx} held={held} /> : <RecordDamaged origin={ctx.origin} onForget={() => { ctx.pins.forget(ctx.origin); clearSession(); void check(); }} />;
  if (view.kind === "ready") return children(view.pin, view.notice);
  if (view.kind === "kind_gate") {
    const { newest } = view.status;
    const accept = async () => {
      setBusy(true);
      try {
        await ctx.pins.acceptKindChange(ctx.origin, { newestHash: newest.hash });
      } finally {
        setBusy(false);
        void check();
      }
    };
    // No form shows while the gate stands, so nothing derived from a password can be asked for under it. Not now keeps
    // the old kind in force and closes the gate until the next unlock (this card mounts again then, and asks again).
    return <KindChangeGate newest={newest} busy={busy} onContinue={() => void accept()} onNotNow={() => setView({ kind: "ready", pin: view.status.pinned, notice: null })} />;
  }
  const first = view.first.first;
  if (first.kind === "needs_trust_gate") {
    const confirm = () => {
      const r = ctx.pins.confirmTrustGate(first.ticket);
      if (r.kind === "pinned") setView({ kind: "ready", pin: r.pin, notice: null });
      else setView({ kind: "stop", first: { kind: "stop", first: r } });
    };
    return <TrustGate origin={first.origin} name={decodeName(first.name) ?? ""} operatorShortFp={first.operatorShortFp} forPassword={forPassword} onContinue={confirm} />;
  }
  return <PinStop ctx={ctx} first={first} held={held} onRetry={() => void check()} onForgotten={onForgotten} />;
}

/**
 * §4.4 and §12.3, a verified card that changes the server's `kind`: approved entry 10's title and buttons over
 * GATE_KIND_CHANGE. Continue accepts the change (the chain is judged again first); Not now keeps the old kind.
 */
export function KindChangeGate({ newest, busy, onContinue, onNotNow }: { newest: WebPin; busy: boolean; onContinue: () => void; onNotNow: () => void }) {
  const { name, origin } = instanceLabel(newest);
  return (
    <div>
      <h2>{GATE_TITLE_KIND_CHANGE}</h2>
      <p>{fill(GATE_KIND_CHANGE, name, origin, newest.kind)}</p>
      <div className="stack">
        <button className="primary" disabled={busy} onClick={onContinue}>{busy ? <Busy>{GATE_KIND_CONTINUE}</Busy> : GATE_KIND_CONTINUE}</button>
        <button className="secondary" disabled={busy} onClick={onNotNow}>{GATE_KIND_NOT_NOW}</button>
      </div>
    </div>
  );
}

/** Approved entry 12: this browser can't read its record of the origin, which is blocked until it is forgotten.
 *  [userId]: the account whose copy forgetting deletes (none: this browser holds no session here). */
export function RecordDamaged({ origin, onForget, userId }: { origin: string; onForget: () => void; userId?: string | null }) {
  const [first, second] = fill(CARD_RECORD_DAMAGED, origin).split("\n");
  return (
    <div role="alert">
      <h2>{CARD_RECORD_DAMAGED_TITLE}</h2>
      <p><strong className="mono">{origin}</strong></p>
      <p>{first}</p>
      <p>{second}</p>
      <ForgetServerButton userId={userId ?? null} onForget={onForget} />
    </div>
  );
}

/**
 * Design §4.4 (decided on 2026-11-17): what "Forget this server" must say first, or null when it may forget on one click.
 * It deletes this browser's copy of [userId]'s account; with changes made here that were not sent (or when this browser
 * cannot tell), the first click says how many and the second forgets. Nothing can be sent first from here: the origin's
 * pin is not in force, so nothing goes to it.
 */
export async function forgetServerAsk(userId: string | null, unsent: (userId: string) => Promise<number | null> = unsentChangeCount): Promise<UnsentAsk | null> {
  if (!userId) return null;
  let n: number | null;
  try {
    n = await unsent(userId);
  } catch {
    n = null;
  }
  const line = unsentLine(n);
  return line === undefined ? null : { text: line, unsent: n };
}

/** "Forget this server", armed by unsent changes ({@link forgetServerAsk}). */
function ForgetServerButton({ userId, onForget }: { userId: string | null; onForget: () => void }) {
  const { armed, busy, click, cancel } = useUnsentArm(() => forgetServerAsk(userId), onForget);
  return (
    <>
      {armed && <Msg kind="info">{armed.text}</Msg>}
      <Announcer text={armed?.text ?? ""} />
      <button className="secondary" disabled={busy} onClick={() => void click()}>{armed ? FORGET_ARMED_LABEL : FORGET_THIS_SERVER}</button>
      {armed && (
        <button type="button" className="link" onClick={cancel}>
          {FORGET_KEEP}
        </button>
      )}
    </>
  );
}

/**
 * Approved entry 8: the newest card names another address than the one that served this page, so no pin was made and
 * nothing was sent. On the baked public instance core's CARD_MOVED_UPDATE shows instead. No buttons.
 */
export function OtherAddress({ dialed, cardOrigin, baked }: { dialed: string; cardOrigin: string; baked: boolean }) {
  if (baked) return <Msg kind="err">{CARD_MOVED_UPDATE}</Msg>;
  return (
    <Msg kind="err">
      <strong>{CARD_OTHER_ADDRESS_TITLE}</strong>
      <br />
      {fill(CARD_OTHER_ADDRESS, dialed, cardOrigin)}
    </Msg>
  );
}

/** §12.3 in its typed-address wording (§13: the person typed the address into the browser). */
export function TrustGate({ origin, name, operatorShortFp, forPassword, onContinue }: { origin: string; name: string; operatorShortFp: string; forPassword: boolean; onContinue: () => void }) {
  return (
    <div>
      <h2>{GATE_TITLE_CONNECT}</h2>
      <p><strong>{origin}</strong></p>
      <p>{GATE_BASELINE}</p>
      <p>{fill(GATE_CALLS_ITSELF, name)}</p>
      <p className="muted">
        {GATE_OPERATOR_KEY}: <span className="mono">{operatorShortFp.match(/.{1,4}/g)?.join(" ") ?? operatorShortFp}</span>
      </p>
      {forPassword && <p>{GATE_ENTERING_PASSWORD}</p>}
      <button className="primary" onClick={onContinue}>{GATE_CONTINUE}</button>
    </div>
  );
}

/**
 * Ends a held session on this device without telling the server (design §4.4: its origin's pin is not in force): the
 * pair is dropped before anything else, so nothing can carry it, then the copy and the record go, and App lands on
 * the first screen (its sign-out finds no pair to revoke and POSTs nothing).
 */
async function forgetHeldSession(ctx: WebContext, held: Held): Promise<void> {
  ctx.client.setTokens(null);
  await wipeVaultCache(held.session.userId).catch(() => {});
  clearSession();
}

/** Design §4.4: a kept session at an origin with no pin record is a blocked server that can be forgotten. Core's engine
 * shows that orphan as its `Damaged` state, so the web shows approved entry 12 for it too. */
function HeldWithoutPin({ ctx, held }: { ctx: WebContext; held: Held }) {
  const forget = async () => {
    await forgetHeldSession(ctx, held);
    held.onForget();
  };
  return <RecordDamaged origin={ctx.origin} onForget={() => void forget()} userId={held.session.userId} />;
}

export function PinStop({ ctx, first, held, onRetry, onForgotten }: { ctx: WebContext; first: FirstPin | { kind: "refused"; verdict: string; cardOrigin?: string }; held?: Held; onRetry: () => void; onForgotten?: () => void }) {
  const forget = async () => {
    // §4.4: "Forget this server" deletes this browser's copy too (it says so beside the button), and the held session
    // with it: its pair is dropped first, unsent, so the next pin of this origin never carries the forgotten one.
    if (held) await forgetHeldSession(ctx, held);
    ctx.pins.forget(ctx.origin);
    clearSession();
    if (held) held.onForget();
    else {
      onRetry();
      // The stop held back the server's settings too (the policy probe goes through the same gate): fetch them again,
      // or the first screen would show "couldn't load the server's settings" under the new Trust Gate's pin.
      onForgotten?.();
    }
  };
  if (first.kind === "blocked") {
    const forked = first.state.kind === "forked";
    // Approved entry 12: a record that does not decode checks nothing, so it stays blocked and offers no copy to open.
    if (!forked) return <RecordDamaged origin={ctx.origin} onForget={() => void forget()} userId={held?.session.userId ?? null} />;
    return (
      <div>
        <Msg kind="err">{CARD_FORK}</Msg>
        {forked && held && <HeldCopyUnlock ctx={ctx} held={held} mode="forked_copy" />}
        <p className="muted">{FORGET_DELETES_COPY}</p>
        <ForgetServerButton userId={held?.session.userId ?? null} onForget={() => void forget()} />
      </div>
    );
  }
  if (first.kind === "unreachable") {
    return (
      <div>
        <Msg kind="err">{UNREACHABLE}</Msg>
        <button className="secondary" onClick={onRetry}>Try again</button>
      </div>
    );
  }
  if (first.kind === "pin_changed") return <Msg kind="err">{pinChangedText(first.status)}</Msg>;
  const verdict = first.kind === "refused" ? first.verdict : first.kind;
  if (first.kind === "refused" && verdict === "origin_mismatch" && first.cardOrigin !== undefined) {
    return <OtherAddress dialed={ctx.origin} cardOrigin={first.cardOrigin} baked={ctx.pins.isBaked(ctx.origin)} />;
  }
  return (
    <div>
      {/* No raw verdict code under the sentence: §12.3 and §4.4 give these stops sentences, never a code. */}
      <Msg kind="err">{verdict === "update_required" ? CARD_CHANGED_UPDATE : CARD_REFUSED}</Msg>
      <button className="secondary" onClick={onRetry}>Try again</button>
    </div>
  );
}

/**
 * Design §4.4 "A fork stops traffic, not reading" and "A session the server ends does not delete the device's copy":
 * the copy this browser holds opens with the master password, as an offline unlock does, and is read-only: nothing is
 * sent to the origin, nothing from it is accepted, nothing written. [mode] says which of the two it is.
 */
function HeldCopyUnlock({ ctx, held, mode }: { ctx: WebContext; held: Held; mode: "forked_copy" | "ended_copy" }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const enter = useEnter(ctx, held.onReady, held.onForget);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const flow = beginUnlock(); // as at the unlock card: the held session is this act's own
    try {
      let known: Uint8Array | null;
      try {
        known = knownIdentity(held.session.email)(held.session.userId);
      } catch {
        setErr(IDENTITY_FAULT);
        return;
      }
      const uid = held.session.userId;
      const copy = await openFromCopy({ keys: await cachedAccountKeys(uid), pending: await cachedPendingWraps(uid), pins: ctx.pins, origin: ctx.origin, userId: uid, password, knownIdentityPub: known });
      if (copy.kind === "opened") {
        await enter({ opened: copy.opened, keys: copy.keys, wrap: copy.wrap, pending: copy.pending, email: held.session.email, pin: copy.pin, cardNotice: null, mode, flow });
        return;
      }
      setErr(copy.kind === "wrong_password" ? WRONG_PASSWORD : copy.kind === "identity_fault" ? IDENTITY_FAULT : copy.kind === "no_copy" ? FORKED_NO_COPY : copy.kind === "kdf_refused" ? KDF_NOT_USABLE : refusalText(copy.error));
    } finally {
      setBusy(false);
      setPassword(""); // after a refusal the typed password is not left in its field
    }
  };
  const ended = mode === "ended_copy";
  return (
    <form onSubmit={submit}>
      <p>{ended ? ENDED_COPY_READ : FORKED_COPY_READ}</p>
      {err && <Msg kind="err">{err}</Msg>}
      <Field label="Master password">
        <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <button className={ended ? "secondary" : "primary"} disabled={busy || !password}>{busy ? <Busy>Unsealing…</Busy> : ended ? ENDED_COPY_OPEN : FORKED_COPY_OPEN}</button>
    </form>
  );
}

// ---- The first screen (§12.2) ------------------------------------------------------------------------------

type Screen = "home" | "signin" | "signup" | "forgot";

export function FreshStart({ ctx, policy, policyError, policyErrorMessage, onRetryPolicy, onReady, onForget, pin, cardNotice, knownEmail }: Props & { pin: WebPin; cardNotice: CardStatus | null }) {
  const [screen, setScreen] = useState<Screen>("home");
  // Once the account exists (sign-up registered, or a recovery committed) the kit must be confirmed before the
  // vault opens (§10): there is no Back to the first screen from there, which would leave the kit unconfirmed.
  const [committed, setCommitted] = useState(false);
  const create = canCreateAccount(policy);
  const line = cardNoticeText(cardNotice);
  const back = <button type="button" className="link" onClick={() => setScreen("home")}>Back</button>;
  const { origin } = instanceLabel(pin);
  return (
    <>
      <p className="muted" style={{ textAlign: "center" }}>{shownName(pin)} · {origin}</p>
      {line && <Msg kind="info">{line}</Msg>}
      {screen === "home" && (
        <div className="stack">
          {/* A profile the server signed out still knows its account: signing in to it comes first, and is the primary. */}
          {knownEmail !== undefined && <button className="primary" onClick={() => setScreen("signin")}>{SIGN_IN}</button>}
          {create !== "hidden" && (
            <button className={knownEmail !== undefined ? "secondary" : "primary"} disabled={create === "full"} onClick={() => setScreen("signup")}>
              {create === "full" ? SIGNUP_FULL : CREATE_ACCOUNT_HERE}
            </button>
          )}
          {knownEmail === undefined && <button className={create === "hidden" ? "primary" : "secondary"} onClick={() => setScreen("signin")}>{SIGN_IN}</button>}
          <p className="muted">{USE_THE_APP}</p>
          {policyError && (
            <Msg kind="err">
              {policyErrorMessage ?? POLICY_UNAVAILABLE} <button className="link" onClick={() => void onRetryPolicy()}>Try again</button>
            </Msg>
          )}
        </div>
      )}
      {screen === "signin" && (
        <>
          <SignIn ctx={ctx} pin={pin} cardNotice={cardNotice} onReady={onReady} onForget={onForget} initialEmail={knownEmail} />
          <button type="button" className="link" onClick={() => setScreen("forgot")}>{SIGN_IN_FORGOT}</button>
          {back}
        </>
      )}
      {screen === "signup" && (
        <>
          {policy ? <SignUp ctx={ctx} policy={policy} pin={pin} cardNotice={cardNotice} onReady={onReady} onForget={onForget} onCommitted={setCommitted} /> : <Msg kind="err">{policyErrorMessage ?? POLICY_UNAVAILABLE}</Msg>}
          {!committed && back}
        </>
      )}
      {screen === "forgot" && (
        <>
          {policy ? <KitRecover ctx={ctx} policy={policy} pin={pin} cardNotice={cardNotice} onReady={onReady} onForget={onForget} onCommitted={setCommitted} /> : <Msg kind="err">{policyErrorMessage ?? POLICY_UNAVAILABLE}</Msg>}
          {!committed && back}
        </>
      )}
    </>
  );
}

// ---- The kit gate (ui/KitCard.tsx KitGate) --------------------------------------------------------------------

/** The kit gate before a session is kept: a timeout also revokes the session, which App's sign-out cannot reach yet. */
function EntryKitGate({ ctx, flow, onTimeout, ...rest }: Omit<Parameters<typeof KitGate>[0], "wire" | "describe"> & { ctx: WebContext; flow: SignInFlow | null }) {
  return (
    <KitGate
      {...rest}
      wire={ctx.wire}
      describe={(e) => kitAtSignInText(e)}
      onTimeout={() => {
        void abandonSignIn(ctx.client, flow);
        onTimeout();
      }}
    />
  );
}

/** Kit capture for an account whose kit was never confirmed: a fresh kit over this session (the rule is asked inside). */
async function rotateFor(ctx: WebContext, opened: OpenedAccount, email: string, password: string, wrap: SessionKeys): Promise<FreshKit> {
  const account = emailNorm(email);
  if (account === null) throw new Error("invalid_email");
  const ak = await currentAuthKey(ctx.pins, { origin: ctx.origin, account }, password, opened, wrap);
  return rotateKit(ctx.wire, opened, ak);
}

interface Capture {
  opened: OpenedAccount;
  keys: { kdfSalt: string; kdfParams: ClientPolicyV2["kdfParams"] };
  wrap: SessionKeys;
  email: string;
  pin: WebPin;
  cardNotice: CardStatus | null;
  kit: FreshKit;
  password: string;
  /** A sign-in over a copy of the same account that the typed password does not open (onboardflow `copySealedElsewhere`). */
  copySealedElsewhere?: boolean;
  /** The sign-in or unlock this capture belongs to: its way out ends that flow's own session alone. */
  flow: SignInFlow;
}

/** [how]: how the session is made (§8.5, the one-tap contact list); null for the unlock of a held session. */
/**
 * Design §12.2 rule 7: when the verified card names this account as the operator (a handover made this member the
 * operator), the keys are wiped, the session revoked and the browser signed out with the operator sentence; the
 * session-role check at sign-in cannot see this, and an unlock of a held session carries no role.
 */
function useEnter(ctx: WebContext, onReady: Ready, onForget: (notice?: string) => void, how: SessionHow | null = null) {
  return useCallback(
    async (c: { opened: OpenedAccount; keys: { kdfSalt: string }; wrap: SessionKeys; pending?: readonly SessionKeys[]; email: string; pin: WebPin; cardNotice: CardStatus | null; mode?: "online" | "offline" | "forked_copy" | "ended_copy"; password?: string; serverKeysNotKnown?: boolean; copySealedElsewhere?: boolean; flow: SignInFlow | null }) => {
      let r: Awaited<ReturnType<typeof enterVault>>;
      try {
        // [password]: only a full-password unlock that reached the server hands it in, for the quiet re-key (spec 01 §7).
        r = await enterVault(ctx, { opened: c.opened, keys: c.keys, wrap: c.wrap, pendingWraps: c.pending, email: c.email, pin: c.pin, cardNotice: c.cardNotice, how, mode: c.mode, ...(c.serverKeysNotKnown === true ? { serverKeysNotKnown: true } : {}), ...(c.copySealedElsewhere === true ? { copySealedElsewhere: true } : {}), ...(c.mode === undefined || c.mode === "online" ? { password: c.password } : {}) });
      } catch (e) {
        if (!(e instanceof OperatorAccountError)) throw e;
        wipeOpened(c.opened);
        void abandonSignIn(ctx.client, c.flow);
        onForget(OPERATOR_NOT_ON_WEB);
        return;
      }
      onReady(r.account, r.store, r.meta);
    },
    [ctx, onReady, onForget, how],
  );
}

// ---- Sign in -----------------------------------------------------------------------------------------------

/**
 * Email and master password (§8.5, spec 03 §2). The two-step code is asked on the same screen after the server
 * says `totp_required`, without asking for the password again; the password rule is asked again before the retry
 * (inside signIn). `link_required` says the account allows only linked devices, which the web cannot be.
 */
function SignIn({ ctx, pin, cardNotice, onReady, onForget, lockedEmail, initialEmail }: { ctx: WebContext; pin: WebPin; cardNotice: CardStatus | null; onReady: Ready; onForget: (notice?: string) => void; lockedEmail?: string; initialEmail?: string }) {
  const [email, setEmail] = useState(lockedEmail ?? initialEmail ?? "");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [errTitle, setErrTitle] = useState("");
  const [capture, setCapture] = useState<Capture | null>(null);
  // The offer to forget the earlier account under this address, under a refusal that is this browser's own record of it.
  const [earlier, setEarlier] = useState<EarlierOffer | null>(null);
  const [forgotLine, setForgotLine] = useState("");
  const enter = useEnter(ctx, onReady, onForget, "password");
  const { name, origin } = instanceLabel(pin);
  // One record per form (tabsession.ts signInForm): what its first submit found to replace stays named at the next ones.
  const form = useRef(signInForm(ctx.client, tokensKeptAcrossLock));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setErrTitle("");
    // Every new try takes the offer away; a refusal of the same kind raises it again.
    setEarlier(null);
    setForgotLine("");
    // Only the server's ask for the two-step code keeps the typed password (the code is asked without it, §8.5). After
    // any refusal it is not left in its field: the form starts again from the password (a two-step code included).
    let keepPassword = false;
    try {
      // The session this sign-in replaces (this tab's own pair only), named at every submit of this form, the one after a
      // request for the two-step code or a wrong password included; and the flow's own record: a way out ends only the
      // pair this submit's own login installed (tabsession.ts).
      const { flow, replaces } = form.current.submit();
      const r = await signIn({
        replaces,
        wire: ctx.wire,
        pins: ctx.pins,
        origin: ctx.origin,
        email,
        password,
        deviceName: deviceName(),
        totp: needTotp ? totp.trim() : undefined,
        session: null,
        knownIdentityPub: knownIdentity(email),
        // Spec 01 §7: a copy this browser holds of the answered account is compared with before anything is written over it.
        heldCopy: (userId) => copyAtUnlock(userId),
        installed: flow.installed,
      });
      switch (r.kind) {
        case "opened": {
          const keys = r.session.accountKeys;
          const copySealedElsewhere = r.copySealedElsewhere === true;
          if (!keys.recoveryConfirmed) {
            try {
              const kit = await rotateFor(ctx, r.opened, email, password, r.wrap);
              setCapture({ opened: r.opened, keys, wrap: r.wrap, email, pin: r.pin, cardNotice: r.notice, kit, password, copySealedElsewhere, flow });
            } catch (e) {
              wipeOpened(r.opened);
              void abandonSignIn(ctx.client, flow);
              setErr(kitAtSignInText(e)); // a sign-in, or an unlock of the served keys: never marked
            }
            return;
          }
          await enter({ opened: r.opened, keys, wrap: r.wrap, email, pin: r.pin, cardNotice: r.notice, password, copySealedElsewhere, flow });
          return;
        }
        case "keys_not_this_account":
          // Nothing was written over the copy or its waiting wraps; no session is kept.
          void abandonSignIn(ctx.client, flow);
          setErr(SIGN_IN_KEYS_NOT_THIS_ACCOUNT);
          return;
        case "totp_required":
          keepPassword = true;
          setNeedTotp(true);
          return;
        case "kdf_refused":
          void abandonSignIn(ctx.client, flow);
          setErr(KDF_NOT_USABLE);
          return;
        case "answer_refused": {
          // The server took this sign-in: the session its answer carried is ended BEFORE the refusal is said, and the line
          // says whether that end was confirmed.
          const ended = (await abandonSignIn(ctx.client, flow)) === true;
          setErr(signInAnswerRefusedText(r.reason, ended));
          return;
        }
        case "invalid_credentials":
          setErr(needTotp ? "Wrong email, master password, or one-time code." : "Wrong email or master password.");
          return;
        case "link_required":
          setErrTitle(LINK_REQUIRED_WEB_TITLE);
          setErr(fill(LINK_REQUIRED_WEB, email.trim() || "This account"));
          return;
        case "operator":
          void abandonSignIn(ctx.client, flow);
          setErr(OPERATOR_NOT_ON_WEB);
          return;
        case "identity_fault": {
          void abandonSignIn(ctx.client, flow);
          // With the offer, its own refusal line stands alone; the identity fault's plate only where nothing is offered.
          const f = identityRefusal(email, r.reason, r.servedUserId);
          setErr(f.err);
          setEarlier(f.offer);
          return;
        }
        case "pin":
        case "password_rule":
          setErr(stoppedBeforeSendingText(r, "sign_in"));
          return;
        case "refused":
        case "failed":
          void abandonSignIn(ctx.client, flow);
          setErr(signInRefusalText(r.error));
          return;
      }
    } finally {
      setBusy(false);
      if (!keepPassword) {
        setPassword("");
        setTotp("");
        setNeedTotp(false);
      }
    }
  };

  if (capture) {
    return (
      <EntryKitGate
        ctx={ctx}
        flow={capture.flow}
        kit={capture.kit}
        email={capture.email}
        pin={capture.pin}
        opened={capture.opened}
        rotate={() => rotateFor(ctx, capture.opened, capture.email, capture.password, capture.wrap)}
        onDone={() => void enter(capture)}
        onTimeout={() => {
          wipeOpened(capture.opened);
          onForget(KIT_TIMEOUT_NOTICE);
        }}
      />
    );
  }

  const shownEmail = email.trim() || "your account";
  return (
    <>
    <form onSubmit={submit}>
      {/* The 2026-11-16 walk: with the server gone the notice and the failed sign-in said the same sentence twice. */}
      {cardNoticeText(cardNotice) && lockedEmail && cardNoticeText(cardNotice) !== err && <Msg kind="info">{cardNoticeText(cardNotice)}</Msg>}
      {err && <Msg kind="err">{errTitle && <><strong>{errTitle}</strong><br /></>}{err}</Msg>}
      {forgotLine && <Msg kind="info">{forgotLine}</Msg>}
      <Announcer text={busy ? UNSEALING_NOTICE : ""} />
      <Field label="Email">
        <input type="email" autoComplete="username" value={email} disabled={!!lockedEmail || needTotp} autoFocus={!lockedEmail} onChange={(e) => { setEmail(e.target.value); setEarlier(null); }} />
      </Field>
      <Field label={fill(MASTER_PASSWORD_FOR, shownEmail, shownName(pin), origin)} prompt>
        <input type="password" autoComplete="current-password" value={password} disabled={needTotp} autoFocus={!!lockedEmail} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      {needTotp && (
        <Field label="One-time code">
          <input inputMode="numeric" autoComplete="one-time-code" value={totp} autoFocus onChange={(e) => setTotp(e.target.value)} />
        </Field>
      )}
      <button className="primary" disabled={busy || !email || !password || (needTotp && !totp.trim())}>{busy ? <Busy>Unsealing…</Busy> : SIGN_IN}</button>
    </form>
    {earlier && <EarlierAccountOffer offer={earlier} server={shownName(pin)} onKeep={() => setEarlier(null)} onDone={(l) => { setEarlier(null); setErr(""); setForgotLine(l); }} />}
    </>
  );
}

// ---- Unlock a session this browser holds ----------------------------------------------------------------

function Unlock({ ctx, policy, pin, cardNotice, session, onReady, onForget, onSessionEnded, endedByBrowser = false }: { ctx: WebContext; policy: ClientPolicyV2 | null; pin: WebPin; cardNotice: CardStatus | null; session: Session; onReady: Ready; onForget: (notice?: string) => void; onSessionEnded: () => void; endedByBrowser?: boolean }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [capture, setCapture] = useState<Capture | null>(null);
  /** Spec 01 §7: the server's keys could not be compared with anything this browser holds; a sign-in is offered. */
  const [notKnown, setNotKnown] = useState(false);
  const [signInInstead, setSignInInstead] = useState(false);
  // The address is bound here to another account than this kept session's: the offer to forget that earlier account.
  const [earlier, setEarlier] = useState<EarlierOffer | null>(null);
  const [forgotLine, setForgotLine] = useState("");
  const enter = useEnter(ctx, onReady, onForget);
  const { name, origin } = instanceLabel(pin);
  void policy;
  // Spec 05 T3, design 2026-07-13 §E.3.4: the unlock card says when this browser holds an offline copy of the account, so
  // a person on a borrowed computer can see it and remove it. The 2026-11-16 walk found the line rendered nowhere since the
  // sign-in screens were rewritten. Loaded from IndexedDB; null (no copy, a failed probe, still loading) shows nothing.
  const [copyStamp, setCopyStamp] = useState<CopyStamp | null>(null);
  useEffect(() => {
    let alive = true;
    void unlockCopyStamp(session.userId).then(
      (s) => alive && setCopyStamp(s),
      () => {},
    );
    return () => {
      alive = false;
    };
  }, [session.userId]);

  if (endedByServer(session)) {
    // Design §4.4: the server ended this session and the offline copy stayed. Signing in again to the same account
    // here, under the pin, restores the session (its unsent changes are sent then); the copy opens read-only meanwhile.
    // "Sign out" is the person's own act, and deletes the copy (it asks first when changes are unsent).
    return (
      <>
        <p style={{ textAlign: "center" }}>Welcome back</p>
        <OfflineCopyUnlockLine stamp={copyStamp} />
        {/* Ended by this browser itself (App endByClient): the notice above says why, the count, and what stays. */}
        {/* A session this browser could not confirm in time ended here, not at the server: said as that end. */}
        {!endedByBrowser && <Msg kind="info">{session.endedUnconfirmed === true || endedUnconfirmed(session.userId) ? SESSION_NOT_CONFIRMED : SESSION_ENDED_HELD}</Msg>}
        <SignIn ctx={ctx} pin={pin} cardNotice={cardNotice} onReady={onReady} onForget={onForget} lockedEmail={session.email} />
        <HeldCopyUnlock ctx={ctx} held={{ session, onReady, onForget }} mode="ended_copy" />
        <SignOutLink userId={session.userId} onSignOut={() => onForget()} sendFirst={UNSENT_SEND_FIRST_SIGN_IN} />
      </>
    );
  }

  if (!session.tokens || signInInstead) {
    // A browser without the offline copy keeps no token once locked: this is a full sign-in, the email fixed. And after
    // the server's keys could not be compared with anything here (spec 01 §7): the sign-in the unlock card offered.
    return (
      <>
        <p style={{ textAlign: "center" }}>Welcome back</p>
        <SignIn ctx={ctx} pin={pin} cardNotice={cardNotice} onReady={onReady} onForget={onForget} lockedEmail={session.email} />
        <SignOutLink userId={session.userId} onSignOut={() => onForget()} sendFirst={UNSENT_SEND_FIRST_SIGN_IN} />
      </>
    );
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setNotKnown(false);
    setEarlier(null);
    setForgotLine("");
    // The held session is the one this unlock opens: a way out the web must take ends it (abandonSignIn).
    const flow = beginUnlock();
    try {
      let known: Uint8Array | null;
      try {
        known = knownIdentity(session.email)(session.userId);
      } catch {
        // Offered only where the address names another account than this session's: this session's copy is never the
        // one a forgetting deletes. With the offer, its own refusal line stands alone; the plate only where none is made.
        const f = identityRefusal(session.email, SELF_IDENTITY_MISMATCH, session.userId);
        setErr(f.err);
        setEarlier(f.offer);
        return;
      }
      // Spec 01 §7: what this browser holds to compare the server's keys with (the offline copy's own keys and the wraps
      // pending beside it, no copy, or a copy it cannot read), so that a served wrap is never taken with no key compared.
      const r = await unlockSession({ wire: ctx.wire, pins: ctx.pins, origin: ctx.origin, userId: session.userId, password, knownIdentityPub: known, copy: await copyAtUnlock(session.userId) });
      switch (r.kind) {
        case "keys_differ":
          // Nothing here to compare the server's keys with: nothing is taken, the copy is left as it is, and a sign-in follows.
          setNotKnown(true);
          return;
        case "opened_from_copy":
          // "Leaves both": the vault opens from the copy, the session marked; no password is handed on (no re-key's proof).
          await enter({ opened: r.opened, keys: r.keys, wrap: r.wrap, pending: r.pending, email: session.email, pin: r.pin, cardNotice: r.notice, serverKeysNotKnown: true, flow });
          return;
        case "kdf_refused":
          setErr(KDF_NOT_USABLE);
          return;
        case "wrong_password_kdf_refused":
        case "change_not_stored":
          setErr(unlockRefusalText(r));
          return;
        case "opened":
          if (!r.keys.recoveryConfirmed) {
            try {
              const kit = await rotateFor(ctx, r.opened, session.email, password, r.wrap);
              setCapture({ opened: r.opened, keys: r.keys, wrap: r.wrap, email: session.email, pin: r.pin, cardNotice: r.notice, kit, password, flow });
            } catch (e) {
              wipeOpened(r.opened);
              setErr(kitAtSignInText(e)); // a sign-in, or an unlock of the served keys: never marked
            }
            return;
          }
          await enter({ opened: r.opened, keys: r.keys, wrap: r.wrap, email: session.email, pin: r.pin, cardNotice: r.notice, password, flow });
          return;
        case "wrong_password":
          setErr(WRONG_PASSWORD);
          return;
        case "expired":
          onSessionEnded();
          return;
        case "not_confirmed":
          // Ended here, not confirmed: the transport raised that one end already (App lands on its card); none of the card's.
          return;
        case "ended_elsewhere":
          // The session every tab shares was gone from the record: the transport raised that end already (App lands the
          // tab as another tab's sign-out, or another account's sign-in, lands it); no refusal's line before the landing.
          return;
        case "identity_fault":
          setErr(IDENTITY_FAULT);
          return;
        case "pin":
          setErr(CARD_REFUSED);
          return;
        case "failed": {
          // No answer (spec 02 §8): this browser's copy of the account keys opens offline, checked as online.
          const copy = await openFromCopy({ keys: await cachedAccountKeys(session.userId), pending: await cachedPendingWraps(session.userId), pins: ctx.pins, origin: ctx.origin, userId: session.userId, password, knownIdentityPub: known });
          if (copy.kind === "opened") {
            await enter({ opened: copy.opened, keys: copy.keys, wrap: copy.wrap, pending: copy.pending, email: session.email, pin: copy.pin, cardNotice: null, mode: "offline", flow });
            return;
          }
          setErr(copy.kind === "wrong_password" ? WRONG_PASSWORD : copy.kind === "identity_fault" ? IDENTITY_FAULT : copy.kind === "kdf_refused" ? KDF_NOT_USABLE : refusalText(r.error));
          return;
        }
        case "refused":
          setErr(refusalText(r.error));
          return;
      }
    } finally {
      setBusy(false);
      // After a refusal the typed password is not left in its field; an unlock that opened keeps its own copy (capture).
      setPassword("");
    }
  };

  if (capture) {
    return (
      <EntryKitGate
        ctx={ctx}
        flow={capture.flow}
        kit={capture.kit}
        email={capture.email}
        pin={capture.pin}
        opened={capture.opened}
        rotate={() => rotateFor(ctx, capture.opened, capture.email, capture.password, capture.wrap)}
        onDone={() => void enter(capture)}
        onTimeout={() => {
          wipeOpened(capture.opened);
          onForget(KIT_TIMEOUT_NOTICE);
        }}
      />
    );
  }

  return (
    <>
    <form onSubmit={submit}>
      <p style={{ textAlign: "center" }}>Welcome back</p>
      <OfflineCopyUnlockLine stamp={copyStamp} />
      {cardNoticeText(cardNotice) && cardNoticeText(cardNotice) !== err && <Msg kind="info">{cardNoticeText(cardNotice)}</Msg>}
      {err && <Msg kind="err">{err}</Msg>}
      {forgotLine && <Msg kind="info">{forgotLine}</Msg>}
      {/* The 2026-11-17 walk: a link inside the error plate read as plain text in the light theme; a button of its own. */}
      {notKnown && !err && (
        <>
          <Msg kind="err">{SERVER_KEYS_NOT_KNOWN_SIGN_IN}</Msg>
          <button type="button" className="ghost" style={{ width: "100%", marginBottom: 16 }} onClick={() => setSignInInstead(true)}>{SIGN_IN}</button>
        </>
      )}
      <Announcer text={busy ? UNSEALING_NOTICE : ""} />
      <Field label={fill(MASTER_PASSWORD_FOR, session.email, shownName(pin), origin)} prompt>
        <input type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
      </Field>
      <button className="primary" disabled={busy || !password}>{busy ? <Busy>Unsealing…</Busy> : "Unlock"}</button>
      <SignOutLink userId={session.userId} onSignOut={() => onForget()} sendFirst={UNSENT_SEND_FIRST_UNLOCK} />
    </form>
    {earlier && <EarlierAccountOffer offer={earlier} server={shownName(pin)} onKeep={() => setEarlier(null)} onDone={(l) => { setEarlier(null); setErr(""); setForgotLine(l); }} />}
    </>
  );
}

// ---- Sign up (§7.2, §7.3) ----------------------------------------------------------------------------------

type SignUpStep =
  | { kind: "email" }
  | { kind: "code"; pin: WebPin }
  | { kind: "account"; pin: WebPin; ticket: string }
  | { kind: "record"; opened: OpenedAccount; keys: { kdfSalt: string; kdfParams: ClientPolicyV2["kdfParams"] }; wrap: SessionKeys; kit: FreshKit; pin: WebPin; error: string }
  | { kind: "kit"; opened: OpenedAccount; keys: { kdfSalt: string; kdfParams: ClientPolicyV2["kdfParams"] }; wrap: SessionKeys; kit: FreshKit; pin: WebPin }
  /**
   * The server registered the account and this browser refused its answer, or whether it registered it cannot be told:
   * the account's kit is shown with [line] before anything is wiped.
   */
  | { kind: "stored"; kit: FreshKit; accountId: string; pin: WebPin; line: string; gone: string }
  /** The end of a stored or untold registration: its line alone, no form. */
  | { kind: "after"; line: string };

function SignUp({ ctx, policy, pin, cardNotice, onReady, onForget, onCommitted }: { ctx: WebContext; policy: ClientPolicyV2; pin: WebPin; cardNotice: CardStatus | null; onReady: Ready; onForget: (notice?: string) => void; onCommitted?: (committed: boolean) => void }) {
  const [step, setStep] = useState<SignUpStep>({ kind: "email" });
  const committed = step.kind === "record" || step.kind === "kit" || step.kind === "stored";
  useEffect(() => onCommitted?.(committed), [committed, onCommitted]);
  const stepRef = useRef(step);
  stepRef.current = step;
  useEffect(
    () => () => {
      const s = stepRef.current;
      if (s.kind === "stored") s.kit.secret.fill(0);
    },
    [],
  );
  const [email, setEmail] = useState("");
  const [age, setAge] = useState(false);
  const [code, setCode] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<number | null>(null);
  const [err, setErr] = useState("");
  // The registration was refused before anything was sent because the address is bound here: the offer to forget.
  const [earlier, setEarlier] = useState<EarlierOffer | null>(null);
  const [forgotLine, setForgotLine] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const enter = useEnter(ctx, onReady, onForget, "registered");
  // The registration's own record (tabsession.ts), kept for its later steps (the kit gate, the vault's entry).
  const flowRef = useRef<SignInFlow | null>(null);
  useEffect(() => () => abortRef.current?.abort(), []);
  // §7.7: on a private instance whose card names a recovery key, the choice is offered at sign-up too. The offer
  // walks the card chain again at this moment (the pin store keeps none); without one only "Only me" is shown.
  const [offer, setOffer] = useState<OperatorOffer | null>(null);
  const [recovery, setRecovery] = useState<RecoveryChoiceValue>(ONLY_ME);
  const chosen = useRef<{ posture: "private" | "operator"; fp: string }>({ posture: "private", fp: NONE });
  const accountPin = step.kind === "account" ? step.pin : null;
  useEffect(() => {
    if (accountPin === null || !operatorRecoveryOffered(accountPin)) return;
    let live = true;
    void operatorOffer({ wire: ctx.wire, pins: ctx.pins, origin: ctx.origin })
      .then((o) => {
        if (live) setOffer(o.kind === "offer" ? o.offer : null);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [accountPin, ctx]);
  const ageRequired = policy.signup.ageConfirmRequired;
  const recoveryLine = pin.kind === "public" ? RECOVERY_KIT_ONLY : RECOVERY_ONLY_ME_DETAIL;

  const sendCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    const ac = new AbortController();
    abortRef.current = ac;
    try {
      const r = await startSignup({
        wire: ctx.wire,
        pins: ctx.pins,
        origin: ctx.origin,
        email,
        ageConfirmed: age,
        powBits: policy.signup.powBits,
        pow: (em, bits) => {
          setProgress(0);
          return runPow(em, bits, Date.now(), (n) => setProgress(n), ac.signal);
        },
      });
      if (r.kind === "sent") setStep({ kind: "code", pin: r.pin });
      else if (r.kind === "refused" || r.kind === "failed") setErr(refusalText(r.error));
      else setErr(stoppedBeforeSendingText(r, "sign_up"));
    } finally {
      setBusy(false);
      setProgress(null);
    }
  };

  const verifyCode = async (e: React.FormEvent) => {
    e.preventDefault();
    if (step.kind !== "code") return;
    setBusy(true);
    setErr("");
    try {
      const v = await ctx.wire.signupVerify(email, code.trim());
      setStep({ kind: "account", pin: step.pin, ticket: v.signupTicket });
    } catch (e2) {
      setErr(refusalText(e2));
    } finally {
      setBusy(false);
    }
  };

  const writeRecord = async (s: { opened: OpenedAccount; keys: { kdfSalt: string; kdfParams: ClientPolicyV2["kdfParams"] }; wrap: SessionKeys; kit: FreshKit; pin: WebPin }) => {
    const kind = await writeSignupRecovery(ctx, s.opened, Date.now(), chosen.current);
    if (kind === "written" || kind === "unchanged") setStep({ kind: "kit", ...s });
    // PLACEHOLDER copy: the recovery record did not reach the account state.
    else setStep({ kind: "record", ...s, error: `Your recovery choice couldn't be saved to your account (${kind}).` });
  };

  const register = async (e: React.FormEvent) => {
    e.preventDefault();
    if (step.kind !== "account") return;
    const nameRefused = nameText(displayName.trim() || email.trim()); // spec 03 §0.1 `text`, before anything is sent
    if (nameRefused !== null) return setErr(nameRefused);
    setBusy(true);
    setErr("");
    setEarlier(null);
    setForgotLine("");
    try {
      // The flow's own record: a way out ends only the pair this registration's own answer installed.
      const flow = beginSignIn(ctx.client);
      flowRef.current = flow;
      const r = await completeSignup({
        boundHere: boundAccountAt,
        installed: flow.installed,
        wire: ctx.wire,
        pins: ctx.pins,
        origin: ctx.origin,
        pin: step.pin,
        policy,
        email,
        displayName: displayName.trim() || email.trim(),
        password,
        signupTicket: step.ticket,
        ageConfirmed: age,
        deviceName: deviceName(),
        nowMs: Date.now(),
        operator: recovery.posture === "operator" && offer !== null ? { offer, understood: recovery.understood, keepDespiteUnsignedChange: recovery.keepNewKey } : null,
      });
      switch (r.kind) {
        case "registered":
          chosen.current = recovery.posture === "operator" && offer !== null ? { posture: "operator", fp: offer.fp } : { posture: "private", fp: NONE };
          await writeRecord({ opened: r.opened, keys: r.session.accountKeys, wrap: r.wrap, kit: { secret: r.recoverySecret, pieceId: r.recoveryPieceId }, pin: step.pin });
          return;
        case "stored_unchecked":
          // The account exists: its session ends (by its own token), nothing is written, and its kit is shown first.
          void abandonSignIn(ctx.client, flow);
          setPassword("");
          setConfirmPw("");
          setStep({ kind: "stored", kit: r.kit, accountId: r.accountId, pin: step.pin, line: SIGNUP_STORED_UNCHECKED, gone: SIGNUP_STORED_KIT_GONE });
          return;
        case "unknown":
          // The account may exist: its kit is shown the same way, with the line that says how to tell.
          void abandonSignIn(ctx.client, flow);
          setPassword("");
          setConfirmPw("");
          setStep({ kind: "stored", kit: r.kit, accountId: r.accountId, pin: step.pin, line: unknownLine("signup", r.why), gone: SIGNUP_UNKNOWN_KIT_GONE });
          return;
        case "password_rule":
          setErr(stoppedBeforeSendingText(r, "sign_up"));
          return;
        case "not_sent":
          // The gate stopped the registration before it left: nothing was sent, no account was made.
          setErr(SIGNUP_NOT_SENT);
          return;
        case "recovery_choice":
          setErr(RECOVERY_CHOICE_REFUSED);
          return;
        case "identity_fault": {
          // Nothing was sent: the address is bound here to an earlier account. The ticket stays for the next try. The
          // offer's own lines say the refusal; where its records disagree (no offer) its refusal line alone.
          const o = earlierOfferFor(email, r.reason, "new");
          setEarlier(o);
          setErr(o === null ? fill(REMADE_ACCOUNT_REFUSAL, emailNorm(email) ?? email.trim(), shownName(pin)) : "");
          return;
        }
        case "name":
          // Checked above already for the display name; the device name is the browser's own (plain text by making).
          setErr(nameText(r.field === "displayName" ? displayName.trim() || email.trim() : deviceName()) ?? NAME_TOO_LONG);
          return;
        case "refused":
          if (r.error.code === "bad_ticket") setStep({ kind: "email" });
          setErr(refusalText(r.error));
          return;
        case "failed":
          setErr(refusalText(r.error));
          return;
      }
    } finally {
      setBusy(false);
    }
  };

  if (step.kind === "stored") {
    const line = step.line;
    return <StoredKitCard line={line} gone={step.gone} kit={step.kit} email={emailNorm(email) ?? email} pin={step.pin} accountId={step.accountId} onSeen={(stays) => setStep({ kind: "after", line: stays })} />;
  }
  if (step.kind === "after") return <Msg kind="err">{step.line}</Msg>;
  if (step.kind === "record") {
    return (
      <div>
        <Msg kind="err">{step.error}</Msg>
        <button className="primary" disabled={busy} onClick={() => { setBusy(true); void writeRecord(step).finally(() => setBusy(false)); }}>Try again</button>
      </div>
    );
  }
  if (step.kind === "kit") {
    return (
      <EntryKitGate
        ctx={ctx}
        flow={flowRef.current}
        kit={step.kit}
        email={emailNorm(email) ?? email}
        pin={step.pin}
        opened={step.opened}
        rotate={() => rotateFor(ctx, step.opened, email, password, step.wrap)}
        onDone={() => void enter({ opened: step.opened, keys: step.keys, wrap: step.wrap, email, pin: step.pin, cardNotice, flow: flowRef.current })}
        onTimeout={() => {
          wipeOpened(step.opened);
          onForget(KIT_TIMEOUT_NOTICE);
        }}
      />
    );
  }
  if (step.kind === "code") {
    return (
      <form onSubmit={verifyCode}>
        <p>{fill(CODE_SENT_DAILY, email.trim())}</p>
        <p className="muted">{EMAIL_CHECK_SPAM}</p>
        {err && <Msg kind="err">{err}</Msg>}
        <Field label="Code">
          <input inputMode="numeric" autoComplete="one-time-code" autoFocus value={code} onChange={(e) => setCode(e.target.value)} />
        </Field>
        <button className="primary" disabled={busy || !code.trim()}>{busy ? <Busy>Checking…</Busy> : "Continue"}</button>
        <button type="button" className="link" onClick={() => { setCode(""); setStep({ kind: "email" }); }}>Send a new code</button>
      </form>
    );
  }
  if (step.kind === "account") {
    const strong = meetsMasterPasswordFloor(password);
    return (
      <>
      <form onSubmit={register}>
        {err && <Msg kind="err">{err}</Msg>}
        {forgotLine && <Msg kind="info">{forgotLine}</Msg>}
        <Announcer text={busy ? UNSEALING_NOTICE : ""} />
        <Field label="Your name">
          <input autoComplete="name" autoFocus value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
        </Field>
        <Field label="Master password">
          <input type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <MasterPasswordHint password={password} />
        <Field label="Master password again">
          <input type="password" autoComplete="new-password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} />
        </Field>
        {offer !== null ? <RecoveryChoice offer={offer} value={recovery} onChange={setRecovery} /> : <p className="muted">{recoveryLine}</p>}
        <button className="primary" disabled={busy || !strong || password !== confirmPw || !recoveryChoiceReady(recovery, offer)}>{busy ? <Busy>Creating your account…</Busy> : "Create account"}</button>
      </form>
      {earlier && <EarlierAccountOffer offer={earlier} server={shownName(pin)} onKeep={() => setEarlier(null)} onDone={(l) => { setEarlier(null); setErr(""); setForgotLine(l); }} />}
      </>
    );
  }
  return (
    <form onSubmit={sendCode}>
      {err && <Msg kind="err">{err}</Msg>}
      <Field label="Email">
        <input type="email" autoComplete="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
      </Field>
      {ageRequired && (
        <label className="check">
          <input type="checkbox" checked={age} onChange={(e) => setAge(e.target.checked)} /> {AGE_13_OR_OLDER}
        </label>
      )}
      {progress !== null && (
        <p className="muted" role="status">
          <Busy>{POW_PROGRESS}</Busy> {progress > 0 ? `(${progress.toLocaleString()})` : ""}
        </p>
      )}
      <button className="primary" disabled={busy || emailNorm(email) === null || (ageRequired && !age)}>{busy ? <Busy>Sending…</Busy> : "Send me a code"}</button>
    </form>
  );
}

// ---- Recover with the kit (§10, §13) ----------------------------------------------------------------------

type RecoverStep =
  | { kind: "input" }
  | { kind: "confirm"; input: KitInput; email: string }
  | { kind: "password"; verified: KitVerified }
  | { kind: "kit"; opened: OpenedAccount; keys: { kdfSalt: string }; wrap: SessionKeys; kit: FreshKit; email: string; pin: WebPin }
  /**
   * The server stored the recovery and this browser refused its answer, or whether it stored it cannot be told: the new
   * kit is shown with [line] before anything is wiped.
   */
  | { kind: "stored"; kit: FreshKit; accountId: string; email: string; pin: WebPin; line: string; gone: string }
  /** The end of a stored or untold recovery: its line alone, no form (the master password is not typed here again). */
  | { kind: "after"; line: string };

function KitRecover({ ctx, policy, pin, cardNotice, onReady, onForget, onCommitted }: { ctx: WebContext; policy: ClientPolicyV2; pin: WebPin; cardNotice: CardStatus | null; onReady: Ready; onForget: (notice?: string) => void; onCommitted?: (committed: boolean) => void }) {
  const [step, setStep] = useState<RecoverStep>({ kind: "input" });
  const committed = step.kind === "kit" || step.kind === "stored";
  useEffect(() => onCommitted?.(committed), [committed, onCommitted]);
  const [text, setText] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPw, setConfirmPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  // The kit check was refused on this browser's own record of the address: the offer to forget the earlier account.
  const [earlier, setEarlier] = useState<EarlierOffer | null>(null);
  const [forgotLine, setForgotLine] = useState("");
  const enter = useEnter(ctx, onReady, onForget, "recovered");
  // The recovery's own record (tabsession.ts), kept for its later steps (the kit gate, the vault's entry).
  const flowRef = useRef<SignInFlow | null>(null);
  const { name, origin } = instanceLabel(pin);
  const stepRef = useRef(step);
  stepRef.current = step;
  useEffect(
    () => () => {
      const s = stepRef.current;
      if (s.kind === "confirm") (s.input.kind === "qr" ? s.input.kit.secret : s.input.secret).fill(0);
      if (s.kind === "password") abandonKit(s.verified);
      if (s.kind === "stored") s.kit.secret.fill(0);
    },
    [],
  );

  const parse = (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    setEarlier(null);
    setForgotLine("");
    const r = parseKitInput(text, email);
    if (r.kind === "bad_kit") return setErr("That isn't a recovery kit.");
    if (r.kind === "invalid_email") return setErr("Type the email address of the account this kit is for.");
    if (r.kind === "qr" && (r.kit.origin !== ctx.origin || r.kit.card0Hash !== pin.card0Hash)) {
      r.kit.secret.fill(0);
      return setErr(KIT_WRONG_SERVER);
    }
    setText("");
    setStep({ kind: "confirm", input: r, email: r.kind === "qr" ? r.kit.emailNorm : r.email });
  };

  const verify = async () => {
    if (step.kind !== "confirm") return;
    setBusy(true);
    setErr("");
    try {
      const r = await verifyKit({ wire: ctx.wire, pins: ctx.pins, origin: ctx.origin, input: step.input, knownIdentityPub: (u, em) => knownIdentity(em)(u) });
      switch (r.kind) {
        case "verified":
          setStep({ kind: "password", verified: r.verified });
          return;
        case "invalid_credentials":
          setStep({ kind: "input" });
          setErr("That kit doesn't open an account here."); // PLACEHOLDER
          return;
        case "wrong_server":
          setStep({ kind: "input" });
          setErr(KIT_WRONG_SERVER);
          return;
        case "operator":
          setStep({ kind: "input" });
          setErr(OPERATOR_NOT_ON_WEB);
          return;
        case "identity_fault": {
          setStep({ kind: "input" });
          // With the offer, its own refusal line stands alone; the identity fault's plate only where nothing is offered.
          const f = identityRefusal(step.email, r.reason, r.servedUserId);
          setErr(f.err);
          setEarlier(f.offer);
          return;
        }
        case "pin":
        case "password_rule":
          setStep({ kind: "input" });
          setErr(stoppedBeforeSendingText(r, "kit_recovery"));
          return;
        case "refused":
        case "failed":
          setStep({ kind: "input" });
          setErr(refusalText(r.error));
          return;
      }
    } catch {
      setStep({ kind: "input" });
      setErr(IDENTITY_FAULT);
    } finally {
      setBusy(false);
    }
  };

  const commit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (step.kind !== "password") return;
    setBusy(true);
    setErr("");
    try {
      // The flow's own record: a way out ends only the pair this recovery's own commit installed.
      const flow = beginSignIn(ctx.client);
      flowRef.current = flow;
      const v = step.verified;
      const r = await commitKitRecovery({ wire: ctx.wire, pins: ctx.pins, origin: ctx.origin, verified: v, newPassword: password, kdfParams: policy.kdfParams, deviceName: deviceName(), installed: flow.installed });
      if (r.kind === "recovered") {
        setStep({ kind: "kit", opened: r.opened, keys: r.session.accountKeys, wrap: r.wrap, kit: r.kit, email: v.email, pin: v.pin });
        return;
      }
      const s = kitCommitScreen(r);
      if (s.endSession) void abandonSignIn(ctx.client, flow);
      if (s.show === "stored") {
        setPassword("");
        setConfirmPw("");
        setStep({ kind: "stored", kit: s.kit, accountId: s.accountId, email: v.email, pin: v.pin, line: s.line, gone: s.gone });
        return;
      }
      setStep({ kind: "input" });
      setErr(s.err);
    } finally {
      setBusy(false);
    }
  };

  if (step.kind === "stored") {
    const line = step.line;
    return <StoredKitCard line={line} gone={step.gone} kit={step.kit} email={step.email} pin={step.pin} accountId={step.accountId} onSeen={(stays) => setStep({ kind: "after", line: stays })} />;
  }
  if (step.kind === "after") return <Msg kind="err">{step.line}</Msg>;
  if (step.kind === "kit") {
    return (
      <EntryKitGate
        ctx={ctx}
        flow={flowRef.current}
        kit={step.kit}
        email={step.email}
        pin={step.pin}
        opened={step.opened}
        rotate={() => rotateFor(ctx, step.opened, step.email, password, step.wrap)}
        onDone={() => void enter({ opened: step.opened, keys: step.keys, wrap: step.wrap, email: step.email, pin: step.pin, cardNotice, flow: flowRef.current })}
        onTimeout={() => {
          wipeOpened(step.opened);
          onForget(KIT_TIMEOUT_NOTICE);
        }}
      />
    );
  }
  if (step.kind === "password") {
    const strong = meetsMasterPasswordFloor(password);
    return (
      <form onSubmit={commit}>
        <p>{fill(KIT_RECOVER, step.verified.email, name, origin)}</p>
        {err && <Msg kind="err">{err}</Msg>}
        <Field label="New master password">
          <input type="password" autoComplete="new-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <MasterPasswordHint password={password} />
        <Field label="New master password again">
          <input type="password" autoComplete="new-password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} />
        </Field>
        <button className="primary" disabled={busy || !strong || password !== confirmPw}>{busy ? <Busy>Recovering…</Busy> : "Set the new master password"}</button>
      </form>
    );
  }
  if (step.kind === "confirm") {
    return (
      <div>
        <p><strong>{fill(KIT_RECOVER, step.email, name, origin)}</strong></p>
        <p>{KIT_RECOVER_SETS_PASSWORD}</p>
        {err && <Msg kind="err">{err}</Msg>}
        <button className="primary" disabled={busy} onClick={() => void verify()}>{busy ? <Busy>Checking the kit…</Busy> : "Continue"}</button>
        <button
          className="link"
          onClick={() => {
            (step.input.kind === "qr" ? step.input.kit.secret : step.input.secret).fill(0);
            setStep({ kind: "input" });
          }}
        >
          {GATE_CANCEL}
        </button>
      </div>
    );
  }
  return (
    <>
    <form onSubmit={parse} autoComplete="off">
      {err && <Msg kind="err">{err}</Msg>}
      {forgotLine && <Msg kind="info">{forgotLine}</Msg>}
      <Field label={KIT_PASTE_LABEL} prompt>
        <textarea rows={3} spellCheck={false} autoCapitalize="off" value={text} onChange={(e) => setText(e.target.value)} />
      </Field>
      {!text.trim().startsWith("andvari-kit:") && (
        <Field label="Email">
          <input type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
        </Field>
      )}
      <button className="primary" disabled={!text.trim()}>Continue</button>
    </form>
    {earlier && <EarlierAccountOffer offer={earlier} server={shownName(pin)} onKeep={() => setEarlier(null)} onDone={(l) => { setEarlier(null); setErr(""); setForgotLine(l); }} />}
    </>
  );
}

/**
 * What the kit recovery's screen does with a commit that did not open the vault: show a kit the person must keep with
 * its line, say a line alone (the form is gone: the new password must not be typed here again), or go back to the kit's
 * form with a line. [endSession]: a session may have been answered, and the sign-in's abandon ends it.
 */
export type KitCommitScreen =
  /** [gone]: the line that stays when the idle limit took the kit off the screen before it was typed back. */
  | { readonly show: "stored"; readonly kit: FreshKit; readonly accountId: string; readonly line: string; readonly gone: string; readonly endSession: true }
  | { readonly show: "form"; readonly err: string; readonly endSession: boolean };

/** The line of a write whose outcome cannot be told, by why: "the server didn't answer" only when it did not. */
export function unknownLine(flow: "kit_recovery" | "signup", why: UnknownWhy): string {
  if (flow === "kit_recovery") return why === "no_answer" ? KIT_RECOVERY_UNKNOWN : why === "server_error" ? KIT_RECOVERY_UNKNOWN_SERVER_ERROR : KIT_RECOVERY_UNKNOWN_UNREADABLE;
  return why === "no_answer" ? SIGNUP_UNKNOWN : why === "server_error" ? SIGNUP_UNKNOWN_SERVER_ERROR : SIGNUP_UNKNOWN_UNREADABLE;
}

export function kitCommitScreen(r: Exclude<KitCommitResult, { kind: "recovered" }>): KitCommitScreen {
  switch (r.kind) {
    case "stored_unchecked":
      // The server holds the new password and this kit; the old kit is dead. Nothing is written, and the kit is shown
      // with the refusal before anything is wiped.
      return { show: "stored", kit: r.kit, accountId: r.accountId, line: KIT_RECOVERY_STORED_UNCHECKED, gone: KIT_RECOVERY_STORED_KIT_GONE, endSession: true };
    case "unknown":
      // It may be stored: the new kit is shown the same way, and kept beside the old one (the line says so).
      return { show: "stored", kit: r.kit, accountId: r.accountId, line: unknownLine("kit_recovery", r.why), gone: KIT_RECOVERY_UNKNOWN_KIT_GONE, endSession: true };
    case "operator":
      // After the commit: the password was already reset and the kit replaced without being shown.
      return { show: "form", err: OPERATOR_KIT_RESET_NOT_ON_WEB, endSession: true };
    case "password_rule":
      // Nothing was sent and no card failed: the rule's own line (CARD_REFUSED is the card's refusal, not true here). A
      // person recovering with the kit has no password to sign in with: the confirmation has a line of its own here.
      return { show: "form", err: r.decision === "trust_gate" ? KIT_RECOVERY_CONFIRM_SERVER_REFUSED : passwordRuleText(r.decision), endSession: false };
    case "not_sent":
      // The gate stopped the commit before it left: nothing was sent, no kit is shown, the old kit and password stand.
      return { show: "form", err: KIT_RECOVERY_NOT_SENT, endSession: false };
    case "refused":
    case "failed":
      return { show: "form", err: refusalText(r.error), endSession: false };
  }
}

/** Ends a session the web must not keep (the operator account): revoke, then drop the pair. */
export async function dropSession(ctx: WebContext): Promise<void> {
  await revokeSessionBestEffort(ctx.client);
  ctx.client.setTokens(null);
}
