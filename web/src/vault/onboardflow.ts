import { ApiError, SessionEndedElsewhereError, SessionNotConfirmedError, TrafficStoppedError } from "../api/client";
import { AnsweredCostRefusedError, BAD_RESPONSE, type Replaces, type SessionInstalled, UnreadableAnswerError } from "../api/wireclient";
import type { AccountKeysV2, ClientPolicyV2, NewDevice, PreloginResponseV2, RegisterRequestV2, SessionResponseV2, SignupStartRequest, SignupVerifyResponse } from "../api/wire";
import { adUvk } from "../crypto/ad";
import { ctEquals, fromB64, toB64 } from "../crypto/bytes";
import { open, openKey } from "../crypto/envelope";
import { assertServerKdfParams, authKey as deriveAuthKey, KdfPolicyError, masterKey, wrapKey as deriveWrapKey } from "../crypto/keys";
import { emailNorm, NONE, textRefusal } from "../crypto/trust/grammar";
import { type AccountOpenResult, accountId, type OpenedAccount, openAccount, SELF_IDENTITY_MISMATCH, wipeOpened } from "./accountopen";
import { outcomeOfThrow, type UnknownWhy, unknownWhy } from "./afterstore";
import { decide, gatePinsOf } from "./passwordgate";
import type { CardStatus, FirstPin, PinStore, WebPin } from "./pinstore";
import { buildRegistration } from "./registration";
import { passesReKeyFence } from "./kdfupgrade";
import { loadSelfIdentityPub } from "./selfidentity";
import { sameWrap, type SessionKeys, wrapOf } from "./sessionwrap";
import type { OperatorOffer } from "./settingsflow";

/**
 * Sign-in and sign-up on the web (design §7.2, §7.3, §12.2), as flows the UI drives step by step. Every flow
 * first settles the instance pin (§4.4), then asks the password rule before ANY value derived from the
 * password, or the prelogin for an email, leaves this browser. Every outcome is a typed result: nothing is
 * swallowed, and no result or error text carries a secret.
 */

/** The calls these flows make (api/wireclient.ts WireApi has them all). */
export interface OnboardWire {
  newDevice(name: string): NewDevice;
  prelogin(email: string): Promise<PreloginResponseV2>;
  login(email: string, authKey: string, deviceName: string, totp?: string, installed?: SessionInstalled, replaces?: Replaces | null): Promise<SessionResponseV2>;
  signupStart(req: SignupStartRequest): Promise<void>;
  signupVerify(email: string, code: string): Promise<SignupVerifyResponse>;
  register(req: RegisterRequestV2, installed?: SessionInstalled): Promise<SessionResponseV2>;
  accountKeys(): Promise<AccountKeysV2>;
}

/** What settling the pin came to: a pin to work under (with a notice to show), or why the flow stops. */
export type PinOutcome =
  | { readonly kind: "pinned"; readonly pin: WebPin; readonly notice: CardStatus | null }
  | { readonly kind: "stop"; readonly first: FirstPin | { readonly kind: "refused"; readonly verdict: string } };

/**
 * The pin this browser works under for [origin] (§4.4). With a pin: the chain is refreshed against it. A fork
 * or a damaged record stops; a shorter chain, a chain that fails verification (the pin stays, nothing is followed:
 * approved entry 11), a move or a kind change keeps working under the existing pin with a notice (the web cannot
 * follow a move; a kind change waits for its gate). With no pin: the baked root, or the Trust Gate for the UI to show.
 */
export async function settlePin(pins: PinStore, origin: string): Promise<PinOutcome> {
  const st = pins.state(origin);
  if (st.kind === "damaged" || st.kind === "forked") return { kind: "stop", first: { kind: "blocked", state: st } };
  if (st.kind === "pinned") {
    const s = await pins.refresh(origin);
    // Another refresh (App's policy probe runs one beside this) may have marked the origin forked while this one's
    // answer was on its way; the transport then dropped that answer, and this one reads as unreachable. The durable
    // mark decides, never the answer that lost the race.
    const now = pins.state(origin);
    if (now.kind === "damaged" || now.kind === "forked") return { kind: "stop", first: { kind: "blocked", state: now } };
    switch (s.kind) {
      case "ok":
        return { kind: "pinned", pin: s.pin, notice: null };
      case "fork":
        return { kind: "stop", first: { kind: "blocked", state: pins.state(origin) } };
      case "refused":
        return { kind: "stop", first: { kind: "refused", verdict: s.verdict } };
      case "withheld":
      case "not_verified":
      case "moved":
      case "kind_changed":
      case "unreachable":
        return { kind: "pinned", pin: st.pin, notice: s };
    }
  }
  const first = await pins.begin(origin);
  if (first.kind === "pinned") return { kind: "pinned", pin: first.pin, notice: null };
  return { kind: "stop", first };
}

export type SignInResult =
  | {
      readonly kind: "opened";
      readonly session: SessionResponseV2;
      readonly opened: Extract<AccountOpenResult, { kind: "opened" }>["account"];
      readonly pin: WebPin;
      readonly notice: CardStatus | null;
      /** The wrap the password opened: the prelogin's salt and cost, and the wrapped UVK the login answered (spec 01 §7). */
      readonly wrap: SessionKeys;
      /**
       * Set when this browser holds a copy of the account, the signed-in key opened it (the same account key), and none of
       * the copy's own wraps opens with the typed password: the copy was sealed under another master password, and takes
       * the server's now. The vault says so in one line.
       */
      readonly copySealedElsewhere?: true;
    }
  /**
   * This browser holds a copy of this account, and the account key the server's wrap opened does not open it: the
   * server's keys are not this account's keys as this browser knows them. Nothing was written; the caller ends the session.
   */
  | { readonly kind: "keys_not_this_account" }
  /** The pin is not settled: show the Trust Gate, the blocked screen, or the refusal. Nothing was sent. */
  | { readonly kind: "pin"; readonly first: PinOutcome & { kind: "stop" } }
  /** The password rule did not say proceed. Nothing was sent. */
  | { readonly kind: "password_rule"; readonly decision: "trust_gate" | "refuse_entry" }
  | { readonly kind: "totp_required" }
  /** The prelogin's cost is outside the whole fence ({@link passesReKeyFence}): nothing was derived or sent. */
  | { readonly kind: "kdf_refused" }
  | { readonly kind: "invalid_credentials" }
  | { readonly kind: "link_required" }
  /**
   * The server took the sign-in (it issued a session and, for a device it did not know, made a device row), and this
   * browser refused its ANSWER: `cost`, the answered cost is outside the fence; `other_kdf`, the answer names another salt
   * or cost than the first exchange did. Something was sent. The transport holds the issued pair and handed it to
   * `installed`, and the row is remembered (a second try names it): the caller ends that session before it says so.
   */
  | { readonly kind: "answer_refused"; readonly reason: "cost" | "other_kdf" }
  /** The account is the operator account: the web does not sign in as it. The transport holds its tokens until the caller logs out. */
  | { readonly kind: "operator" }
  /**
   * The served keys failed an identity check (IDENTITY_MISMATCH copy), or the UVK did not open under the password's key.
   * [servedUserId]: with `self_identity_mismatch`, the account the server answered for, so that the screen can tell
   * another account under the address (a remade account, or a server that serves another) from the same account under
   * another key (never a remade account: nothing is offered for it).
   */
  | { readonly kind: "identity_fault"; readonly reason: string; readonly servedUserId?: string }
  | { readonly kind: "refused"; readonly error: ApiError }
  | { readonly kind: "failed"; readonly error: unknown };

/**
 * Password sign-in (spec 03 §2): pin, password rule, prelogin, the master key, login with this browser's
 * device object (and the two-step code when the server asked for one), then the unlock checks in the engine's
 * `AccountOpen` order. [session] is a session this browser already holds (for the rule's "existing session"
 * clause); [knownIdentityPub] is its own earlier record of the account's identity key, or null.
 */
export async function signIn(params: {
  wire: OnboardWire;
  pins: PinStore;
  origin: string;
  email: string;
  password: string;
  deviceName: string;
  totp?: string;
  session: { origin: string; account: string } | null;
  /** This browser's own record of the identity key, or a lookup by the answered userId that throws when its records disagree. */
  knownIdentityPub: Uint8Array | null | ((userId: string) => Uint8Array | null);
  /**
   * What this browser holds of the answered account to compare the signed-in keys with before they are written over it
   * (ui/opensession.ts copyAtUnlock). Absent: nothing held is compared (a caller that writes nothing over a copy).
   */
  heldCopy?: (userId: string) => Promise<CopyAtUnlock>;
  /** Told the pair this sign-in's login installed (ui/tabsession.ts SignInFlow), so that a way out ends that session alone. */
  installed?: SessionInstalled;
  /** The session this tab held and this sign-in replaces (ui/tabsession.ts replacedSession), named in the login; null: none. */
  replaces?: Replaces | null;
}): Promise<SignInResult> {
  const { wire, pins, origin, email } = params;
  const account = emailNorm(email);
  if (account === null) return { kind: "refused", error: new ApiError(400, "invalid_email", "invalid email") };
  const settled = await settlePin(pins, origin);
  if (settled.kind === "stop") return { kind: "pin", first: settled };
  const decision = decide({ purpose: "sign_in", origin, account, pins: gatePinsOf(origin, pins.state(origin)), session: params.session });
  if (decision !== "proceed") return { kind: "password_rule", decision };

  let authKey: Uint8Array | null = null;
  let wrapKey: Uint8Array | null = null;
  try {
    const pre = await wire.prelogin(email);
    // Spec 01 §7: the whole fence on the served cost before anything is derived at it (a ragged KiB is the server's fault).
    if (!passesReKeyFence(pre.kdfParams)) return { kind: "kdf_refused" };
    assertServerKdfParams(pre.kdfParams);
    const mk = masterKey(params.password, fromB64(pre.kdfSalt), pre.kdfParams);
    try {
      authKey = await deriveAuthKey(mk);
      wrapKey = await deriveWrapKey(mk);
    } finally {
      mk.fill(0);
    }
    let session: SessionResponseV2;
    try {
      session = await wire.login(email, toB64(authKey), params.deviceName, params.totp, params.installed, params.replaces ?? null);
    } catch (e) {
      // The login was answered and the answer's cost refused: the server's session is held, for the caller to end.
      if (e instanceof AnsweredCostRefusedError) return { kind: "answer_refused", reason: "cost" };
      if (e instanceof ApiError) {
        if (e.code === "totp_required") return { kind: "totp_required" };
        if (e.code === "invalid_credentials") return { kind: "invalid_credentials" };
        if (e.code === "link_required") return { kind: "link_required" };
        return { kind: "refused", error: e };
      }
      return { kind: "failed", error: e };
    }
    // Spec 01 §7, as the shared code's `KnownKdf`: the login's answer carries exactly the salt and cost the first exchange
    // named, the ones the password was derived under. Another salt or cost would be written into this browser's copy, and
    // the right password would read as wrong at every later unlock: refused as the server's answer, before anything is
    // written and before anything else derived from the password is sent. The server took the sign-in: the caller ends
    // this session, and says so.
    if (!sameKdf(pre, session.accountKeys)) return { kind: "answer_refused", reason: "other_kdf" };
    // The web never signs in as the operator account (design §9.1, §13): the caller ends this session at once.
    if (session.role !== "member") return { kind: "operator" };
    let uvk: Uint8Array;
    try {
      uvk = openKey(wrapKey, fromB64(session.accountKeys.wrappedUvk), adUvk(session.userId), "the account key's wrap");
    } catch {
      return { kind: "identity_fault", reason: "uvk_unopenable" };
    }
    let known: Uint8Array | null;
    try {
      known = typeof params.knownIdentityPub === "function" ? params.knownIdentityPub(session.userId) : params.knownIdentityPub;
    } catch {
      // This browser's own records disagree with the account the server answered for (another userId at this address).
      // Where it keeps the answered account's own key record and the account's key is not that key, it is the same account
      // under another key, whatever the address names: the fault without the account met, so nothing is offered.
      const own = loadSelfIdentityPub(session.userId);
      if (own !== null) {
        const asOwn = openAccount(session.userId, uvk, session.accountKeys, settled.pin.instanceId, own);
        if (asOwn.kind === "identity_fault") return asOwn;
        wipeOpened(asOwn.account);
      }
      uvk.fill(0);
      return { kind: "identity_fault", reason: "self_identity_mismatch", servedUserId: session.userId };
    }
    const opened = openAccount(session.userId, uvk, session.accountKeys, settled.pin.instanceId, known);
    if (opened.kind === "identity_fault") return opened.reason === SELF_IDENTITY_MISMATCH ? { ...opened, servedUserId: session.userId } : opened;
    const wrap: SessionKeys = { kdfSalt: pre.kdfSalt, kdfParams: pre.kdfParams, wrappedUvk: session.accountKeys.wrappedUvk };
    let copySealedElsewhere = false;
    if (params.heldCopy !== undefined) {
      let v: CopyVerdict;
      try {
        v = await againstHeldCopy(await params.heldCopy(session.userId), opened.account, wrap, session.userId, params.password, settled.pin.instanceId, known);
      } catch (e) {
        wipeOpened(opened.account);
        return { kind: "failed", error: e };
      }
      if (v.kind === "other_account_key") {
        wipeOpened(opened.account);
        return { kind: "keys_not_this_account" };
      }
      if (v.kind === "failed") {
        wipeOpened(opened.account);
        return v;
      }
      copySealedElsewhere = v.kind === "sealed_elsewhere";
    }
    return { kind: "opened", session, opened: opened.account, pin: settled.pin, notice: settled.notice, wrap, ...(copySealedElsewhere ? { copySealedElsewhere: true as const } : {}) };
  } catch (e) {
    // The wire's own fence refused a served cost (the prelogin's, before anything was derived at it).
    if (e instanceof KdfPolicyError) return { kind: "kdf_refused" };
    return e instanceof ApiError ? { kind: "refused", error: e } : { kind: "failed", error: e };
  } finally {
    authKey?.fill(0);
    wrapKey?.fill(0);
  }
}

type CopyVerdict =
  | { readonly kind: "no_copy" | "same" | "sealed_elsewhere" | "other_account_key" }
  | { readonly kind: "failed"; readonly error: unknown };

/**
 * A sign-in over the offline copy this browser holds for the same account (spec 01 §7): before the signed-in keys may be
 * written over it, the account key the server's wrap opened must open what the copy holds itself. The copy's own sealed
 * record is its identity seed (`encryptedIdentitySeed`, sealed under the account key with the account's userId as its
 * associated data). This browser took that record into the copy only after it had opened it under the account key it
 * held then (every write of the copy follows an {@link openAccount}), so an authenticated open of that same ciphertext
 * succeeds only under that same key: no server that does not hold the key can make another key open it. The seed it
 * opens must also give the copy's identity key, the one the signed-in keys gave, and pass the copy's genesis against the
 * pin, as at any opening of the copy.
 *
 * - `no_copy`: nothing held to compare with (the copy is off here, holds nothing yet, or cannot be read): a sign-in's
 *   checks are all there is, as on a browser that never held the account.
 * - `other_account_key`: the copy's record does not open under the signed-in key: nothing may be written over it.
 * - `same`: the same account key, and the signed-in wrap is the copy's own or a pending one, or the typed password opens
 *   one of them: nothing to tell.
 * - `sealed_elsewhere`: the same account key, and none of the copy's wraps opens with the typed password: the copy was
 *   sealed under another master password, and now follows the server's.
 */
async function againstHeldCopy(held: CopyAtUnlock, signedIn: OpenedAccount, wrap: SessionKeys, userId: string, password: string, instanceId: string, known: Uint8Array | null): Promise<CopyVerdict> {
  if (held.kind !== "copy") return { kind: "no_copy" };
  const asCopy = openAccount(userId, signedIn.uvk.slice(), held.keys, instanceId, known);
  if (asCopy.kind === "identity_fault") return { kind: "other_account_key" };
  const sameIdentity = ctEquals(asCopy.account.identity.publicKey, signedIn.identity.publicKey);
  wipeOpened(asCopy.account);
  if (!sameIdentity) return { kind: "other_account_key" };
  const wraps = [wrapOf(held.keys), ...held.pending];
  if (wraps.some((w) => sameWrap(w, wrap))) return { kind: "same" };
  const u = await firstOpening(wraps, userId, password);
  if (u.kind === "failed") return u;
  if (u.kind === "uvk") {
    const same = ctEquals(u.uvk, signedIn.uvk);
    u.uvk.fill(0);
    return { kind: same ? "same" : "other_account_key" };
  }
  // `kdf_refused`: a wrap of the copy could not be tried, so it is not known that the password does not open it.
  return u.kind === "wrong_password" ? { kind: "sealed_elsewhere" } : { kind: "same" };
}

/** The same salt (as bytes, in constant time) and the same cost: what the shared code's `KnownKdf` compares. */
function sameKdf(a: Pick<SessionKeys, "kdfSalt" | "kdfParams">, b: Pick<SessionKeys, "kdfSalt" | "kdfParams">): boolean {
  let x: Uint8Array;
  let y: Uint8Array;
  try {
    x = fromB64(a.kdfSalt);
    y = fromB64(b.kdfSalt);
  } catch {
    return false;
  }
  const p = a.kdfParams;
  const q = b.kdfParams;
  return x.length === y.length && ctEquals(x, y) && p.v === q.v && p.alg === q.alg && p.ops === q.ops && p.memBytes === q.memBytes;
}

export type UnlockResult =
  | {
      readonly kind: "opened";
      readonly keys: AccountKeysV2;
      readonly opened: Extract<AccountOpenResult, { kind: "opened" }>["account"];
      readonly pin: WebPin;
      readonly notice: CardStatus | null;
      /** The wrap the password opened (the fetched keys' own salt, cost and wrapped UVK). */
      readonly wrap: SessionKeys;
    }
  /**
   * Spec 01 §7, "leaves both": the served wrap is neither the copy's own nor a pending one, the password opened this
   * browser's own wrap, and the served one failed the fence, did not open, or opened to another account key ([cause]).
   * The vault opens from the copy (its keys, its own wrap and its pending ones); nothing of the served keys is taken
   * or written, and the session is marked as holding keys the server does not ({@link SessionWrap.serverKeysNotKnown}).
   */
  | {
      readonly kind: "opened_from_copy";
      readonly keys: AccountKeysV2;
      readonly opened: Extract<AccountOpenResult, { kind: "opened" }>["account"];
      readonly pin: WebPin;
      readonly notice: CardStatus | null;
      readonly wrap: SessionKeys;
      readonly pending: readonly SessionKeys[];
      readonly cause: "fence" | "not_open" | "other_key";
    }
  | { readonly kind: "pin"; readonly first: PinOutcome & { kind: "stop" } }
  | { readonly kind: "wrong_password" }
  /**
   * Spec 01 §7: the account's keys the server serves are not the ones this browser knows, and nothing here opened to
   * compare them with: the password opens the served wrap and none of this browser's own (`served_only`), or this
   * browser keeps a copy whose keys it cannot read (`copy_unreadable`). Nothing is taken, nothing is written, nothing
   * was sent; the way on is a sign-in, where a browser with no key to compare establishes one. Never a wrong password.
   */
  | { readonly kind: "keys_differ"; readonly reason: "served_only" | "copy_unreadable" }
  /**
   * The served hashing cost is outside the whole fence ({@link passesReKeyFence}: the scheme, whole numbers, floor,
   * ceiling, whole KiB), so nothing was derived at it and this browser's own wraps did not open: the server's fault,
   * never a wrong password.
   */
  | { readonly kind: "kdf_refused" }
  /**
   * The typed password opened none of this browser's own wraps (the copy's, or one kept pending), and the served cost is
   * outside the whole fence, so nothing was derived at it: both are said, the password and the server's fault.
   */
  | { readonly kind: "wrong_password_kdf_refused" }
  /**
   * Spec 01 §7: the server holds the copy's own wrap, the typed password does not open it, and it does open the wrap of a
   * password change this browser sent and kept waiting: that change got no answer and never reached the server, so the
   * earlier password is still the account's. Nothing is opened, taken or written; [at] the day the change was kept here
   * (ms since the epoch), or null when the copy recorded none.
   */
  | { readonly kind: "change_not_stored"; readonly at: number | null }
  | { readonly kind: "identity_fault"; readonly reason: string }
  /** The session is gone server-side (a definitive 401 after the transport's one refresh). */
  | { readonly kind: "expired" }
  /**
   * The session ended in this browser, not confirmed (a refresh whose answer never came had no try left): its one end was
   * raised by the transport already (api/client.ts SessionNotConfirmedError); the card raises none of its own.
   */
  | { readonly kind: "not_confirmed" }
  /**
   * The session every tab shares was gone from this browser's record (another tab signed out, ended it, or another account
   * signed in): nothing was sent, and the transport raised that end already (api/client.ts SessionEndedElsewhereError);
   * App lands the tab, and the card shows no line of its own.
   */
  | { readonly kind: "ended_elsewhere" }
  | { readonly kind: "refused"; readonly error: ApiError }
  | { readonly kind: "failed"; readonly error: unknown };

/**
 * What this browser holds to compare a served wrap with at an unlock (spec 01 §7):
 * - `copy`: the offline copy's own keys (with their genesis) and the wraps kept pending beside it;
 * - `none`: this browser keeps no copy of this account (the copy is off here, or on with nothing written yet): the unlock
 *   is a sign-in's checks, the whole fence and then the identity checks of {@link openAccount}, as a sign-in on a
 *   browser that never held the account;
 * - `unreadable`: the copy is on for this account, but its keys cannot be read: there is something to compare with
 *   that cannot be read, so nothing served is taken and the unlock says so (a sign-in follows).
 */
export type CopyAtUnlock =
  /** [pending]: each wrap with the day it was first kept here ([at], ms since the epoch) where the copy recorded one. */
  | { readonly kind: "copy"; readonly keys: AccountKeysV2; readonly pending: readonly (SessionKeys & { readonly at?: number })[] }
  | { readonly kind: "none" }
  | { readonly kind: "unreadable" };

/**
 * Unlocking a session this browser already holds (a reload or a lock that kept the tokens): the pin is settled,
 * the account keys are fetched with the session, and the password opens the UVK here. Nothing derived from the
 * password leaves the browser, so the password rule has nothing to decide; the unlock checks run as at sign-in.
 * Every served cost passes the whole fence ({@link passesReKeyFence}) before anything is derived at it.
 *
 * Spec 01 §7, with the offline copy ([copy] `copy`): a served wrap equal to the copy's own or a pending one is opened as
 * always. A served wrap that is neither (a server that answered "done" for a change it never stored, or stored one and
 * answered with a refusal, or kept an older password's wrap) is taken only when the password opens this browser's own
 * wrap and the served one to exactly the same account key: a served wrap is never taken with no key compared. When the
 * password opens this browser's own wrap and the served one fails the fence, does not open or opens to another key,
 * that is the case "leaves both": the vault opens from the copy (`opened_from_copy`). When the password opens none of
 * this browser's own wraps and does open the served one, nothing is taken (`keys_differ`, a sign-in follows). With no
 * copy ([copy] `none`, the default) the unlock is a sign-in's checks; with a copy that cannot be read, `keys_differ`.
 */
export async function unlockSession(params: {
  wire: Pick<OnboardWire, "accountKeys">;
  pins: PinStore;
  origin: string;
  userId: string;
  password: string;
  knownIdentityPub: Uint8Array | null;
  copy?: CopyAtUnlock;
}): Promise<UnlockResult> {
  const settled = await settlePin(params.pins, params.origin);
  if (settled.kind === "stop") return { kind: "pin", first: settled };
  let fetched: AccountKeysV2 | null;
  try {
    fetched = await params.wire.accountKeys();
  } catch (e) {
    if (e instanceof SessionNotConfirmedError) return { kind: "not_confirmed" };
    if (e instanceof SessionEndedElsewhereError) return { kind: "ended_elsewhere" };
    if (e instanceof ApiError && e.status === 401) return { kind: "expired" };
    // The wire's own fence refused the served cost (floor or ceiling) before anything was derived at it.
    if (e instanceof KdfPolicyError) fetched = null;
    else return e instanceof ApiError ? { kind: "refused", error: e } : { kind: "failed", error: e };
  }
  const copy = params.copy ?? { kind: "none" };
  if (copy.kind === "unreadable") return { kind: "keys_differ", reason: "copy_unreadable" };
  if (fetched === null && copy.kind === "none") return { kind: "kdf_refused" };
  const { pin, notice } = settled;
  if (fetched !== null && (copy.kind === "none" || [wrapOf(copy.keys), ...copy.pending].some((w) => sameWrap(w, wrapOf(fetched!))))) {
    // A sign-in's checks, or the wrap this browser already holds: the whole fence, the password, the identity checks.
    const u = await unwrapUvk(fetched, params.userId, params.password);
    if (u.kind === "uvk") return take(fetched, u.uvk);
    if (u.kind === "wrong_password" && copy.kind === "copy" && sameWrap(wrapOf(copy.keys), wrapOf(fetched))) {
      // The server holds the copy's own wrap: a password change this browser sent got no answer and was not stored. When
      // the typed password opens the wrap that change left waiting here, it is the new password of a change that never
      // reached the server, and the earlier password is still the one: said as that, never as a wrong password.
      const notStored = await changeNotStored(copy.pending.filter((w) => !sameWrap(w, wrapOf(fetched!))), params.userId, params.password);
      if (notStored !== null) return notStored;
    }
    return u;
  }
  if (copy.kind !== "copy") return { kind: "kdf_refused" };
  // Neither: the password against this browser's own wraps first, for the key to compare with.
  const own = wrapOf(copy.keys);
  const c = await firstOpening([own, ...copy.pending], params.userId, params.password);
  if (c.kind === "failed") return c;
  if (c.kind === "kdf_refused") return c;
  if (fetched === null || !passesReKeyFence(fetched.kdfParams)) {
    if (c.kind === "uvk") return fromCopy(c.uvk, "fence");
    // The typed password opened none of this browser's own wraps, and the server's cost cannot be used: both are so.
    return { kind: "wrong_password_kdf_refused" };
  }
  const keys: AccountKeysV2 = fetched;
  const u = await unwrapUvk(keys, params.userId, params.password);
  if (u.kind === "failed") {
    if (c.kind === "uvk") c.uvk.fill(0);
    return u;
  }
  if (c.kind !== "uvk") {
    // No key here to compare with: a served wrap that opens is never taken on its own word.
    if (u.kind === "uvk") {
      u.uvk.fill(0);
      return { kind: "keys_differ", reason: "served_only" };
    }
    return u.kind === "kdf_refused" ? u : { kind: "wrong_password" };
  }
  if (u.kind !== "uvk") return fromCopy(c.uvk, "not_open");
  if (ctEquals(u.uvk, c.uvk)) {
    c.uvk.fill(0);
    return take(keys, u.uvk);
  }
  u.uvk.fill(0);
  return fromCopy(c.uvk, "other_key");

  function take(keys: AccountKeysV2, uvk: Uint8Array): UnlockResult {
    const opened = openAccount(params.userId, uvk, keys, pin.instanceId, params.knownIdentityPub);
    if (opened.kind === "identity_fault") return opened;
    return { kind: "opened", keys, opened: opened.account, pin, notice, wrap: wrapOf(keys) };
  }

  function fromCopy(uvk: Uint8Array, cause: "fence" | "not_open" | "other_key"): UnlockResult {
    if (copy.kind !== "copy") throw new Error("unreachable");
    const opened = openAccount(params.userId, uvk, copy.keys, pin.instanceId, params.knownIdentityPub);
    if (opened.kind === "identity_fault") return opened;
    return { kind: "opened_from_copy", keys: copy.keys, opened: opened.account, pin, notice, wrap: own, pending: copy.pending.map(wrapOf), cause };
  }
}

/**
 * The change-not-stored reading (spec 01 §7): [pending] are the wraps of changes this browser sent and kept waiting, none
 * of them the one the server holds. The first one [password] opens: `change_not_stored`, with the day it was kept when
 * the copy recorded one; the key it opened is wiped, and nothing is taken. None: null.
 */
async function changeNotStored(pending: readonly (SessionKeys & { readonly at?: number })[], userId: string, password: string): Promise<UnlockResult | null> {
  for (const w of pending) {
    const u = await unwrapUvk(w, userId, password);
    if (u.kind === "failed") return u;
    if (u.kind === "uvk") {
      u.uvk.fill(0);
      return { kind: "change_not_stored", at: typeof w.at === "number" ? w.at : null };
    }
  }
  return null;
}

type Unwrapped = { readonly kind: "uvk"; readonly uvk: Uint8Array } | { readonly kind: "wrong_password" } | { readonly kind: "kdf_refused" } | { readonly kind: "failed"; readonly error: unknown };

/** The UVK the first of [wraps] the password opens, or why none did. Each wrap was fenced when it was kept; it is fenced again. */
async function firstOpening(wraps: readonly SessionKeys[], userId: string, password: string): Promise<Unwrapped> {
  let last: Unwrapped = { kind: "wrong_password" };
  for (const w of wraps) {
    const u = await unwrapUvk({ kdfSalt: w.kdfSalt, kdfParams: w.kdfParams, wrappedUvk: w.wrappedUvk } as AccountKeysV2, userId, password);
    if (u.kind === "uvk" || u.kind === "failed") return u;
    if (u.kind === "kdf_refused" && last.kind === "wrong_password") last = u;
  }
  return last;
}

/**
 * The UVK under [password], after the whole fence on the cost ({@link passesReKeyFence}): a cost outside it is
 * `kdf_refused` with nothing derived. The master and wrap keys are wiped on the way out.
 */
async function unwrapUvk(keys: Pick<AccountKeysV2, "kdfSalt" | "kdfParams" | "wrappedUvk">, userId: string, password: string): Promise<Unwrapped> {
  if (!passesReKeyFence(keys.kdfParams)) return { kind: "kdf_refused" };
  try {
    assertServerKdfParams(keys.kdfParams);
    const mk = masterKey(password, fromB64(keys.kdfSalt), keys.kdfParams);
    let wk: Uint8Array;
    try {
      wk = await deriveWrapKey(mk);
    } finally {
      mk.fill(0);
    }
    try {
      // A wrap the password opens to zeros is handed on as it is: openAccount refuses it as damaged keys
      // (accountopen.ts), never a wrong password and never a lock, and no comparison can match it.
      return { kind: "uvk", uvk: open(wk, fromB64(keys.wrappedUvk), adUvk(userId)) };
    } catch {
      return { kind: "wrong_password" };
    } finally {
      wk.fill(0);
    }
  } catch (e) {
    return { kind: "failed", error: e };
  }
}

export type CopyOpenResult =
  | {
      readonly kind: "opened";
      readonly keys: AccountKeysV2;
      readonly opened: Extract<AccountOpenResult, { kind: "opened" }>["account"];
      readonly pin: WebPin;
      /** The offline copy's own wrap: a tab opened from the copy proves against it, and against [pending]. */
      readonly wrap: SessionKeys;
      /** The pending wraps kept beside the copy, held pending in the session too (either password proves). */
      readonly pending: readonly SessionKeys[];
    }
  /** This browser holds no copy of the account keys, or no pin to check its genesis against. */
  | { readonly kind: "no_copy" }
  | { readonly kind: "wrong_password" }
  /** The copy's own cost is outside the whole fence: nothing was derived at it. */
  | { readonly kind: "kdf_refused" }
  | Extract<AccountOpenResult, { kind: "identity_fault" }>
  | { readonly kind: "failed"; readonly error: unknown };

/**
 * The offline unlock (spec 02 §8; design §4.4 "A fork stops traffic, not reading"): the account keys this browser
 * cached with their genesis, opened with the typed password and checked by openAccount against the STORED pin's
 * instance and this browser's own identity record, exactly as online. Nothing is fetched or sent. A `damaged` pin
 * checks nothing, so it opens nothing; a `forked` one still opens the copy (read-only, the caller's to enforce).
 */
export async function openFromCopy(params: {
  keys: AccountKeysV2 | null;
  pins: PinStore;
  origin: string;
  userId: string;
  password: string;
  knownIdentityPub: Uint8Array | null;
  /**
   * The wraps of password changes an earlier session here sent with no answer, kept beside the copy (spec 01 §7): the
   * copy opens with either password until the server's word settles them at the next online unlock.
   */
  pending?: readonly SessionKeys[];
}): Promise<CopyOpenResult> {
  const st = params.pins.state(params.origin);
  const pin = st.kind === "pinned" || st.kind === "forked" ? st.pin : null;
  if (params.keys === null || pin === null) return { kind: "no_copy" };
  const pending = params.pending ?? [];
  const u = await firstOpening([wrapOf(params.keys), ...pending], params.userId, params.password);
  if (u.kind !== "uvk") return u;
  const opened = openAccount(params.userId, u.uvk, params.keys, pin.instanceId, params.knownIdentityPub);
  if (opened.kind === "identity_fault") return opened;
  return { kind: "opened", keys: params.keys, opened: opened.account, pin, wrap: wrapOf(params.keys), pending: pending.map(wrapOf) };
}

/** Whether "Create an account here" is shown (§12.2): only in `open` mode, and not while sign-up is full. Decorative: the server enforces. */
export function canCreateAccount(policy: ClientPolicyV2 | null): "open" | "full" | "hidden" {
  if (!policy || policy.signup.mode !== "open") return "hidden";
  return policy.signup.full ? "full" : "open";
}

export type SignupStartResult =
  | { readonly kind: "sent"; readonly pin: WebPin }
  | { readonly kind: "pin"; readonly first: PinOutcome & { kind: "stop" } }
  | { readonly kind: "password_rule"; readonly decision: "trust_gate" | "refuse_entry" }
  | { readonly kind: "refused"; readonly error: ApiError }
  | { readonly kind: "failed"; readonly error: unknown };

/**
 * Step 1 of sign-up (spec 03 §14.1): settle the pin, ask the rule for `register` (any pin of the origin will
 * do: nothing of an existing account is sent), compute the proof of work when the instance asks for one, and
 * ask for the emailed code. The answer is the same whether or not the address has an account.
 */
export async function startSignup(params: {
  wire: OnboardWire;
  pins: PinStore;
  origin: string;
  email: string;
  ageConfirmed: boolean;
  powBits: number;
  pow: (email: string, powBits: number) => Promise<{ date: string; nonce: number }>;
}): Promise<SignupStartResult> {
  const settled = await settlePin(params.pins, params.origin);
  if (settled.kind === "stop") return { kind: "pin", first: settled };
  const decision = decide({ purpose: "register", origin: params.origin, account: emailNorm(params.email), pins: gatePinsOf(params.origin, params.pins.state(params.origin)), session: null });
  if (decision !== "proceed") return { kind: "password_rule", decision };
  try {
    const pow = params.powBits > 0 ? await params.pow(params.email, params.powBits) : undefined;
    await params.wire.signupStart({ email: params.email, ageConfirmed: params.ageConfirmed, ...(pow ? { pow } : {}) });
    return { kind: "sent", pin: settled.pin };
  } catch (e) {
    return e instanceof ApiError ? { kind: "refused", error: e } : { kind: "failed", error: e };
  }
}

export type SignupCompleteResult =
  | {
      readonly kind: "registered";
      readonly session: SessionResponseV2;
      readonly opened: Extract<AccountOpenResult, { kind: "opened" }>["account"];
      /** The kit to show and confirm BEFORE the vault opens (§10); the caller wipes it after. */
      readonly recoverySecret: Uint8Array;
      readonly recoveryPieceId: string | null;
      /** The wrap this browser sealed and registered (spec 01 §7: the session proves against it). */
      readonly wrap: SessionKeys;
    }
  | { readonly kind: "password_rule"; readonly decision: "trust_gate" | "refuse_entry" }
  /** The operator-recovery choice was refused before anything was derived or sent (stale offer, no consent...). */
  | { readonly kind: "recovery_choice"; readonly code: string }
  /**
   * The display name or the device name is not the server's `text` (spec 03 §0.1): found before anything was derived or
   * sent; the screen says which kind of character (ui/nametext.ts), never the server's `bad_display_name`.
   */
  | { readonly kind: "name"; readonly field: "displayName" | "deviceName"; readonly refusal: "empty" | "too_long" | "character" }
  /**
   * This browser binds the address to an account already ([reason] `self_identity_mismatch`): a new account under it would
   * be refused at its first opening here. Found before anything was derived or sent, so no account was made.
   */
  | { readonly kind: "identity_fault"; readonly reason: string }
  /** The server refused the registration (a 4xx answer): no account was made. */
  | { readonly kind: "refused"; readonly error: ApiError }
  /**
   * This browser's traffic gate stopped the registration before it left the browser ([reason]: the server's record here
   * was forgotten or found forked meanwhile, in this tab or another). Nothing was sent, so no account was made.
   */
  | { readonly kind: "not_sent"; readonly reason: string }
  /**
   * The server REGISTERED the account (it answered with success), and then this browser's own check of that answer
   * refused it: the answer, which named this account, carried keys other than the ones sent (`bad_answer`), keys that do
   * not open as the ones made here (an identity fault), was not in the route's shape, or served a cost outside the
   * fence. The account exists with the person's address,
   * master password and [kit]; nothing is opened or written here and the caller ends the answered session. The caller
   * shows [kit] with the refusal and wipes its secret only once the person has seen it. Never "nothing was changed".
   */
  | { readonly kind: "stored_unchecked"; readonly reason: string; readonly kit: { readonly secret: Uint8Array; readonly pieceId: null }; readonly accountId: string }
  /**
   * Whether the account was made cannot be told ([why]: no answer, an error answer, or an answer this browser could not
   * take as the server's). If it was, [kit] is its kit: the caller shows it as in the stored case and wipes its secret
   * only once the person has seen it. A sign-in with the address and password says which.
   */
  | { readonly kind: "unknown"; readonly error: unknown; readonly why: UnknownWhy; readonly kit: { readonly secret: Uint8Array; readonly pieceId: null }; readonly accountId: string }
  /** Something failed on this device before anything was sent. */
  | { readonly kind: "failed"; readonly error: unknown };

/**
 * The last step of sign-up (spec 03 §14.3): with the ticket from the emailed code, build the keys and the
 * genesis this browser signs for the PINNED instance, register, and run the unlock checks on the keys the
 * server answers, against the identity key this browser just made (so a server that substituted any of them is
 * caught before the vault opens). The password rule was asked at step 1 and is asked again here.
 */
export async function completeSignup(params: {
  wire: OnboardWire;
  pins: PinStore;
  origin: string;
  pin: WebPin;
  policy: ClientPolicyV2;
  email: string;
  displayName: string;
  password: string;
  signupTicket: string;
  ageConfirmed: boolean;
  deviceName: string;
  nowMs: number;
  /**
   * The recovery choice at sign-up on a private instance (design §7.7): absent or null is "Only me". "The operator
   * may restore" carries the offer this browser made and showed (settingsflow `operatorOffer`, which walked the card
   * chain again at that moment), the ticked box, and an explicit keep of any unsigned key change (§4.5).
   */
  operator?: { readonly offer: OperatorOffer; readonly understood: boolean; readonly keepDespiteUnsignedChange: boolean } | null;
  /** Told the pair the registration's answer installed (ui/tabsession.ts SignInFlow), so that a way out ends that session alone. */
  installed?: SessionInstalled;
  /**
   * The account this browser's own record binds the address to, or null (vault/selfidentity.ts boundAccountAt). Absent:
   * nothing is compared (a caller that keeps no record).
   */
  boundHere?: (email: string) => string | null;
}): Promise<SignupCompleteResult> {
  const decision = decide({ purpose: "register", origin: params.origin, account: emailNorm(params.email), pins: gatePinsOf(params.origin, params.pins.state(params.origin)), session: null });
  if (decision !== "proceed") return { kind: "password_rule", decision };
  // The shared code's keeper refuses a registration under an address bound to another account before it is made (decided
  // on 2026-11-17): here too, before the server makes an account this browser would refuse at its next opening.
  if (params.boundHere?.(params.email) != null) return { kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH };
  // Spec 03 §0.1 `text`, with the shared code's list: a name the server would refuse is never sent.
  for (const field of ["displayName", "deviceName"] as const) {
    const refusal = textRefusal(params[field]);
    if (refusal !== null) return { kind: "name", field, refusal };
  }
  const op = params.operator ?? null;
  if (op !== null) {
    // Every check that needs no secret, before anything is derived: the offer is still the pin's own.
    const pin = params.pins.pinFor(params.origin);
    if (pin === null || pin.kind !== "private" || pin.recoveryFp === NONE) return { kind: "recovery_choice", code: "operator_recovery_unavailable" };
    if (op.offer.origin !== params.origin || op.offer.pinHash !== pin.hash || op.offer.fp !== pin.recoveryFp || pin.hash !== params.pin.hash) return { kind: "recovery_choice", code: "stale_offer" };
    if (!op.understood) return { kind: "recovery_choice", code: "consent_required" };
    if (op.offer.unsignedChanges.length > 0 && !op.keepDespiteUnsignedChange) return { kind: "recovery_choice", code: "unsigned_change" };
  }
  assertServerKdfParams(params.policy.kdfParams);
  let reg;
  try {
    reg = await buildRegistration({
      email: params.email,
      displayName: params.displayName,
      password: params.password,
      kdfParams: params.policy.kdfParams,
      signupTicket: params.signupTicket,
      pin: params.pin,
      ageConfirmed: params.ageConfirmed,
      device: params.wire.newDevice(params.deviceName),
      nowMs: params.nowMs,
      ...(op !== null ? { operatorEscrow: { recoveryPub: op.offer.recoveryPub, fp: op.offer.fp } } : {}),
    });
  } catch (e) {
    return { kind: "failed", error: e };
  }
  // After a success answer the account exists: every refusal from here on hands the kit on to be shown, never wiped.
  const storedUnchecked = (reason: string): SignupCompleteResult => {
    reg.uvk.fill(0);
    return { kind: "stored_unchecked", reason, kit: { secret: reg.recoverySecret, pieceId: null }, accountId: accountId(fromB64(reg.request.identityPub)) };
  };
  // The account may exist: its kit is handed on to be shown, never wiped unseen.
  const untold = (error: unknown, why: UnknownWhy): SignupCompleteResult => {
    reg.uvk.fill(0);
    return { kind: "unknown", error, why, kit: { secret: reg.recoverySecret, pieceId: null }, accountId: accountId(fromB64(reg.request.identityPub)) };
  };
  let session: SessionResponseV2;
  try {
    session = await params.wire.register(reg.request, params.installed);
  } catch (e) {
    // "Stored" only for an answer that only this server could have given: it names the account this browser sent.
    const outcome = outcomeOfThrow(e, reg.userId);
    if (outcome === "stored") return storedUnchecked(e instanceof ApiError ? e.code : "kdf_refused");
    if (outcome === "unknown") return untold(e, unknownWhy(e));
    reg.uvk.fill(0);
    reg.recoverySecret.fill(0);
    if (outcome === "not_sent") return { kind: "not_sent", reason: e instanceof TrafficStoppedError ? e.reason : "traffic_stopped" };
    return { kind: "refused", error: e as ApiError };
  }
  // A session answer that names another account is not one only this server could have given for this registration.
  if (session.userId !== reg.userId) return untold(new UnreadableAnswerError("the answer names another account", true), "unreadable");
  // The answer's keys must be the salt, cost and wrapped key this browser registered (the shared code's KnownKdf at a
  // registration), before anything is opened under them or written: the same rule as at a sign-in and a kit recovery.
  const wrap: SessionKeys = { kdfSalt: reg.request.kdfSalt, kdfParams: reg.request.kdfParams, wrappedUvk: reg.request.wrappedUvk };
  if (!sameWrap(wrap, session.accountKeys)) return storedUnchecked(BAD_RESPONSE);
  let opened: AccountOpenResult;
  try {
    opened = openAccount(reg.userId, reg.uvk, session.accountKeys, params.pin.instanceId, fromB64(reg.request.identityPub));
  } catch {
    return storedUnchecked("unexpected");
  }
  if (opened.kind === "identity_fault") return storedUnchecked(opened.reason);
  return { kind: "registered", session, opened: opened.account, recoverySecret: reg.recoverySecret, recoveryPieceId: session.recoveryPieceId, wrap };
}
