import { ApiError, TrafficStoppedError } from "../api/client";
import type { NewDevice, RecoveryCommitRequestV2, RecoverySelfSetupRequestV2, RecoveryVerifyResponseV2, SessionResponseV2 } from "../api/wire";
import { adIdkey, adUvk } from "../crypto/ad";
import { ctEquals, fromB64, toB64 } from "../crypto/bytes";
import { openKey, seal } from "../crypto/envelope";
import { allZero } from "../crypto/keyfloor";
import { assertServerKdfParams, authKey as deriveAuthKey, type KdfParams, masterKey, wrapKey as deriveWrapKey } from "../crypto/keys";
import { deriveAuthKey as recoveryAuthKeyOf, generate as generateMemberRecovery, openUvk } from "../crypto/member-recovery";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { emailNorm, fromB64Exact } from "../crypto/trust/grammar";
import { type Kit, parseKitQr, parseTypedSecret } from "../crypto/trust/recoverykit";
import { type AccountOpenResult, accountId, openAccount, type OpenedAccount, SELF_IDENTITY_MISMATCH } from "./accountopen";
import { outcomeOfThrow, type UnknownWhy, unknownWhy } from "./afterstore";
import { decide, gatePinsOf, type GateDecision } from "./passwordgate";
import type { PinStore, WebPin } from "./pinstore";
import { loadSelfIdentityPub } from "./selfidentity";
import { sameWrap, type SessionKeys, SessionWrap } from "./sessionwrap";
import { BAD_RESPONSE, type SessionInstalled, UnreadableAnswerError } from "../api/wireclient";

/**
 * The recovery kit on the web (design §10, spec 03 §12): the in-session password proof every re-authenticated
 * route takes, rotating the kit (reveal and confirm), and recovering this browser's own account with a kit typed
 * or pasted on "Forgot your master password?" (§13). Every value derived from the password or the kit is sent only
 * after the password rule is asked AT THAT MOMENT (§4.4). No result or error carries a secret.
 */

export interface SessionRef {
  readonly origin: string;
  /** `emailNorm` of the account this browser holds a session for. */
  readonly account: string;
}

/** Asks the rule for a re-authenticated call at [origin] for the session's own account. */
export function reauthDecision(pins: PinStore, session: SessionRef): GateDecision {
  return decide({ purpose: "reauth", origin: session.origin, account: session.account, pins: gatePinsOf(session.origin, pins.state(session.origin)), session });
}

/** Thrown when the rule did not say proceed; carries no secret. */
export class PasswordRuleRefused extends Error {
  constructor(readonly decision: Exclude<GateDecision, "proceed">) {
    super(decision === "trust_gate" ? "this server must be confirmed first" : "this server is blocked on this browser");
    this.name = "PasswordRuleRefused";
  }
}

/** Thrown when the password does not open the session's wrap: found out here, and nothing was sent. */
export class WrapNotOpenedError extends Error {
  constructor() {
    super("the password does not open this session's wrap");
    this.name = "WrapNotOpenedError";
  }
}

/**
 * The `currentAuthKey` for [password], proven on this device against [wrap], the wrap THIS session opened or sealed
 * (spec 01 §7), under its own salt and cost, before anything is sent (the server re-verifies it). The rule is asked
 * first; the master key is wiped before this returns. Used at the kit capture right after an unlock, sign-up or kit
 * recovery, with the password that opened the session.
 */
export async function currentAuthKey(pins: PinStore, session: SessionRef, password: string, opened: Pick<OpenedAccount, "userId" | "uvk">, wrap: SessionKeys): Promise<string> {
  const d = reauthDecision(pins, session);
  if (d !== "proceed") throw new PasswordRuleRefused(d);
  const p = await new SessionWrap(wrap).prove(password, opened.userId, opened.uvk);
  switch (p.kind) {
    case "proven":
      return p.currentAuthKey;
    case "weakened":
      throw p.error;
    case "wrong_password":
    case "no_wrap":
      throw new WrapNotOpenedError();
  }
}

export interface KitWire {
  recoverySelfSetup(req: RecoverySelfSetupRequestV2): Promise<string>;
  recoverySelfConfirm(pieceId: string | null): Promise<void>;
}

/** A kit to show and confirm; the caller wipes [secret] once it is confirmed or abandoned. */
export interface FreshKit {
  readonly secret: Uint8Array;
  readonly pieceId: string | null;
}

/**
 * Rotate the kit (spec 03 §12, `PUT /recovery/self-setup`): a fresh secret over this session's UVK. The old kit
 * stops working when the server stores the new piece. The password rule is asked inside [currentAuthKey].
 */
export async function rotateKit(wire: KitWire, opened: Pick<OpenedAccount, "userId" | "uvk">, authKey: string): Promise<FreshKit> {
  const piece = await generateMemberRecovery(opened.userId, opened.uvk);
  try {
    const pieceId = await wire.recoverySelfSetup({ currentAuthKey: authKey, memberRecovery: { recoveryWrappedUvk: piece.recoveryWrappedUvk, recoveryAuthKey: piece.recoveryAuthKey } });
    return { secret: piece.recoverySecret, pieceId };
  } catch (e) {
    piece.recoverySecret.fill(0);
    throw e;
  }
}

export type ConfirmOutcome = { readonly kind: "confirmed" } | { readonly kind: "stale" } | { readonly kind: "failed"; readonly error: unknown };

/** The kit was typed back: tell the server, so it stops asking. `409 recovery_piece_stale`: another kit replaced it. */
export async function confirmKit(wire: KitWire, pieceId: string | null): Promise<ConfirmOutcome> {
  try {
    await wire.recoverySelfConfirm(pieceId);
    return { kind: "confirmed" };
  } catch (e) {
    if (e instanceof ApiError && e.code === "recovery_piece_stale") return { kind: "stale" };
    return { kind: "failed", error: e };
  }
}

// ---- Recovery with the kit (design §10, §13) ------------------------------------------------------------

/**
 * What the person typed or pasted on "Forgot your master password?": the kit QR text (it names the origin, card 0
 * and the email) or the typed secret (with the email typed beside it). Nothing else is accepted.
 */
export type KitInput = { readonly kind: "qr"; readonly kit: Kit } | { readonly kind: "typed"; readonly email: string; readonly secret: Uint8Array };

export function parseKitInput(text: string, typedEmail: string): KitInput | { readonly kind: "bad_kit" } | { readonly kind: "invalid_email" } {
  const t = text.trim();
  // Spec 01 rule 4: a kit whose secret is zeros is a bad kit, refused where it is read; nothing is derived from it.
  if (t.startsWith("andvari-kit:")) {
    const k = parseKitQr(t);
    if (k.ok && allZero(k.value.secret)) return { kind: "bad_kit" };
    return k.ok ? { kind: "qr", kit: k.value } : { kind: "bad_kit" };
  }
  const s = parseTypedSecret(text);
  if (!s.ok || allZero(s.value)) return { kind: "bad_kit" };
  const email = emailNorm(typedEmail);
  if (email === null) {
    s.value.fill(0);
    return { kind: "invalid_email" };
  }
  return { kind: "typed", email, secret: s.value };
}

export interface KitRecoveryWire {
  newDevice(name: string): NewDevice;
  recoverySelfVerify(email: string, recoveryAuthKey: string): Promise<RecoveryVerifyResponseV2>;
  recoverySelfCommit(email: string, req: RecoveryCommitRequestV2, installed?: SessionInstalled): Promise<SessionResponseV2>;
}

/** The verified first phase: the kit opened the account's UVK, and the served identity agrees with its seed. */
export interface KitVerified {
  readonly email: string;
  readonly userId: string;
  readonly ticket: string;
  /** Owned by the holder; wiped by [abandonKit] or consumed by [commitKitRecovery]. */
  readonly uvk: Uint8Array;
  readonly identityPub: Uint8Array;
  readonly pin: WebPin;
}

export function abandonKit(v: KitVerified): void {
  v.uvk.fill(0);
}

export type KitVerifyResult =
  | { readonly kind: "verified"; readonly verified: KitVerified }
  /** The kit names another server or another card 0 than the one this browser pinned: nothing was sent. */
  | { readonly kind: "wrong_server"; readonly kitOrigin: string | null }
  | { readonly kind: "pin"; readonly reason: string }
  | { readonly kind: "password_rule"; readonly decision: Exclude<GateDecision, "proceed"> }
  /** The uniform refusal: no such account, or the kit is not this account's current kit. */
  | { readonly kind: "invalid_credentials" }
  /**
   * The kit is the operator account's (the pinned card names that account): the web never holds an operator
   * session and never takes the operator's master password (§9.1, §13). Nothing was committed: the kit still works.
   */
  | { readonly kind: "operator" }
  /** [servedUserId]: with `self_identity_mismatch`, the account the server answered for (onboardflow SignInResult's). */
  | { readonly kind: "identity_fault"; readonly reason: string; readonly servedUserId?: string }
  | { readonly kind: "refused"; readonly error: ApiError }
  | { readonly kind: "failed"; readonly error: unknown };

/**
 * Phase one (spec 03 §12): the kit's server must be the one this browser pinned (the kit root never replaces a
 * pin, §4.4); the rule is asked; then `recoveryAuthKey` goes to `/recovery/self/verify`. The served wrapped UVK
 * must open under the kit's secret, and the served identity key must be the one the seed inside derives, and
 * this browser's own earlier record of it. An answer for the account the pinned card names as the operator stops
 * here, before a new password is asked for. [secret] is wiped before this returns.
 */
export async function verifyKit(params: {
  wire: KitRecoveryWire;
  pins: PinStore;
  origin: string;
  input: KitInput;
  knownIdentityPub: (userId: string, email: string) => Uint8Array | null;
}): Promise<KitVerifyResult> {
  const { input, pins, origin } = params;
  const secret = input.kind === "qr" ? input.kit.secret : input.secret;
  try {
    const email = input.kind === "qr" ? input.kit.emailNorm : input.email;
    const pin = pins.pinFor(origin);
    if (pin === null) return { kind: "pin", reason: pins.state(origin).kind };
    if (input.kind === "qr" && (input.kit.origin !== origin || input.kit.card0Hash !== pin.card0Hash)) {
      return { kind: "wrong_server", kitOrigin: input.kit.origin };
    }
    const d = decide({ purpose: "kit_recovery", origin, account: email, pins: gatePinsOf(origin, pins.state(origin)), session: null });
    if (d !== "proceed") return { kind: "password_rule", decision: d };
    let served: RecoveryVerifyResponseV2;
    try {
      served = await params.wire.recoverySelfVerify(email, await recoveryAuthKeyOf(secret));
    } catch (e) {
      if (e instanceof ApiError && e.code === "invalid_credentials") return { kind: "invalid_credentials" };
      return e instanceof ApiError ? { kind: "refused", error: e } : { kind: "failed", error: e };
    }
    // The operator account never recovers on the web (§9.1): its new master password would be typed into code
    // the server serves. The card this browser pinned names that account, so this is decided before the commit.
    if (served.userId === pin.operator) return { kind: "operator" };
    let uvk: Uint8Array;
    try {
      uvk = await openUvk(secret, served.recoveryWrappedUvk, served.userId);
    } catch {
      return { kind: "identity_fault", reason: "uvk_unopenable" };
    }
    let seed: Uint8Array;
    try {
      seed = openKey(uvk, fromB64(served.encryptedIdentitySeed), adIdkey(served.userId), "the identity seed");
    } catch {
      uvk.fill(0);
      return { kind: "identity_fault", reason: "seed_unopenable" };
    }
    const pair = boxKeypairFromSeed(seed);
    seed.fill(0);
    pair.privateKey.fill(0);
    const servedPub = fromB64Exact(served.identityPub, 32);
    if (servedPub === null || !ctEquals(servedPub, pair.publicKey)) {
      uvk.fill(0);
      return { kind: "identity_fault", reason: "identity_pub_mismatch" };
    }
    // This browser's own record of the account under the address (a lookup that throws: the address is bound to another
    // account, or its records disagree): a reason of its own, so that the screen can tell it from the server's key.
    let known: Uint8Array | null;
    try {
      known = params.knownIdentityPub(served.userId, email);
    } catch {
      uvk.fill(0);
      // Where this browser keeps the served account's own key record and the seed's key is not it, it is the same account
      // under another key, whatever the address names: the fault without the account met, so nothing is offered.
      const own = loadSelfIdentityPub(served.userId);
      if (own !== null && !ctEquals(own, pair.publicKey)) return { kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH };
      return { kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: served.userId };
    }
    if (known !== null && !ctEquals(known, pair.publicKey)) {
      uvk.fill(0);
      return { kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH, servedUserId: served.userId };
    }
    return { kind: "verified", verified: { email, userId: served.userId, ticket: served.recoveryTicket, uvk, identityPub: pair.publicKey, pin } };
  } finally {
    secret.fill(0);
  }
}

export type KitCommitResult =
  | {
      readonly kind: "recovered";
      readonly session: SessionResponseV2;
      readonly opened: OpenedAccount;
      /** The replacement kit, to show and confirm before the vault opens (§10: the commit replaces the kit). */
      readonly kit: FreshKit;
      /** The wrap this browser sealed under the new password and sent (spec 01 §7: the session proves against it). */
      readonly wrap: SessionKeys;
    }
  | { readonly kind: "password_rule"; readonly decision: Exclude<GateDecision, "proceed"> }
  /**
   * The answered session is the operator's although the pinned card named another account (the card this browser
   * holds is behind a handover). The web keeps no operator session (§9.1): the caller ends it at once. The commit
   * already replaced the kit, which was never shown, so the person makes a new one on a native device.
   */
  | { readonly kind: "operator" }
  /**
   * The server STORED the recovery (it answered the commit with success), and then this browser's own check of that
   * answer refused it: the answer, which named this account, carried keys other than the ones sent (`bad_answer`), did
   * not open as this account (an identity fault), was not in the route's shape, or served a cost outside the fence. The server now holds the new master password
   * and [kit]'s piece, and the kit the person typed no longer works. Nothing is opened or written here, and the caller
   * ends the answered session; but [kit] is the person's only kit now: the caller SHOWS it with the refusal and wipes
   * its secret only once the person has seen it. Never "nothing was changed".
   */
  | { readonly kind: "stored_unchecked"; readonly reason: string; readonly kit: FreshKit; readonly accountId: string }
  /** The commit was refused by the server (a 4xx answer): nothing was stored, and the kit the person typed still works. */
  | { readonly kind: "refused"; readonly error: ApiError }
  /**
   * This browser's traffic gate stopped the commit before it left the browser ([reason]: the server's record here was
   * forgotten or found forked meanwhile, in this tab or another). Nothing was sent: the old master password and the old
   * kit are as before. The new kit, which nothing holds, is wiped.
   */
  | { readonly kind: "not_sent"; readonly reason: string }
  /**
   * Whether the server stored the recovery cannot be told ([why]: no answer, an error answer, or an answer this browser
   * could not take as the server's). If it did, [kit] is the only kit that works; if it did not, the old one still does.
   * So the person must be able to hold both: the caller SHOWS [kit] as in the stored case, and wipes its secret only once
   * the person has seen it. The new master password says which, at the next sign-in.
   */
  | { readonly kind: "unknown"; readonly error: unknown; readonly why: UnknownWhy; readonly kit: FreshKit; readonly accountId: string }
  /** Something failed on this device before the commit was sent: nothing was sent. */
  | { readonly kind: "failed"; readonly error: unknown };

/**
 * Phase two (`/recovery/self/commit`): a new master password and a replacement kit, both over the UVK the kit
 * opened; the rule is asked again at this moment; the answered session is opened through the unlock checks
 * against the pinned instance and the identity key phase one verified. [verified]'s UVK is consumed.
 */
export async function commitKitRecovery(params: {
  wire: KitRecoveryWire;
  pins: PinStore;
  origin: string;
  verified: KitVerified;
  newPassword: string;
  kdfParams: KdfParams;
  deviceName: string;
  /** Told the pair this commit's answer installed (ui/tabsession.ts SignInFlow), so that a way out ends that session alone. */
  installed?: SessionInstalled;
}): Promise<KitCommitResult> {
  const { verified: v, pins, origin } = params;
  const d = decide({ purpose: "kit_recovery", origin, account: v.email, pins: gatePinsOf(origin, pins.state(origin)), session: null });
  if (d !== "proceed") {
    v.uvk.fill(0);
    return { kind: "password_rule", decision: d };
  }
  assertServerKdfParams(params.kdfParams);
  const salt = randomBytes(16);
  const mk = masterKey(params.newPassword, salt, params.kdfParams);
  let ak: Uint8Array | null = null;
  let wk: Uint8Array | null = null;
  let kitSecret: Uint8Array | null = null;
  // Set once the server answered the commit with success: from then on every way out keeps the new kit for the person.
  let stored = false;
  // The kit the server holds after a stored commit, handed to the caller with the refusal; the UVK is wiped.
  const storedUnchecked = (reason: string): KitCommitResult => {
    const kit: FreshKit = { secret: kitSecret!, pieceId: null };
    kitSecret = null;
    v.uvk.fill(0);
    return { kind: "stored_unchecked", reason, kit, accountId: accountId(v.identityPub) };
  };
  // It may be stored: the new kit is handed on to be shown and kept beside the old one, never wiped unseen.
  const untold = (error: unknown, why: UnknownWhy): KitCommitResult => {
    const kit: FreshKit = { secret: kitSecret!, pieceId: null };
    kitSecret = null;
    v.uvk.fill(0);
    return { kind: "unknown", error, why, kit, accountId: accountId(v.identityPub) };
  };
  try {
    ak = await deriveAuthKey(mk);
    wk = await deriveWrapKey(mk);
    mk.fill(0);
    const piece = await generateMemberRecovery(v.userId, v.uvk);
    kitSecret = piece.recoverySecret;
    let session: SessionResponseV2;
    const wrap: SessionKeys = { kdfSalt: toB64(salt), kdfParams: params.kdfParams, wrappedUvk: toB64(seal(wk, v.uvk, adUvk(v.userId))) };
    try {
      session = await params.wire.recoverySelfCommit(v.email, {
        recoveryTicket: v.ticket,
        newAuthKey: toB64(ak),
        newKdfSalt: wrap.kdfSalt,
        newKdfParams: params.kdfParams,
        newWrappedUvk: wrap.wrappedUvk,
        newMemberRecovery: { recoveryWrappedUvk: piece.recoveryWrappedUvk, recoveryAuthKey: piece.recoveryAuthKey },
        device: params.wire.newDevice(params.deviceName),
      }, params.installed);
    } catch (e) {
      // A success answer that only this server could have given (it names this account) and that this browser could not
      // read is a stored recovery: its kit is the person's only one now.
      const outcome = outcomeOfThrow(e, v.userId);
      if (outcome === "stored") return storedUnchecked(e instanceof ApiError ? e.code : "kdf_refused");
      if (outcome === "unknown") return untold(e, unknownWhy(e));
      kitSecret.fill(0);
      kitSecret = null;
      v.uvk.fill(0);
      if (outcome === "not_sent") return { kind: "not_sent", reason: e instanceof TrafficStoppedError ? e.reason : "traffic_stopped" };
      return { kind: "refused", error: e as ApiError };
    }
    // A session answer that names another account is not an answer only this server could have given for this
    // recovery (a front's own JSON can look like one): whether the recovery was stored cannot be told from it.
    if (session.userId !== v.userId) return untold(new UnreadableAnswerError("the answer names another account", true), "unreadable");
    stored = true;
    // The keys the answer carries are written into this browser's copy at the vault's opening: they must be the salt,
    // cost and wrapped key this browser sent (the shared code's KnownKdf at a recovery). Another salt would make the
    // right new password read as wrong at every later unlock here. Nothing is written, nothing more is derived.
    if (!sameWrap(wrap, session.accountKeys)) return storedUnchecked(BAD_RESPONSE);
    if (session.role !== "member") {
      kitSecret.fill(0);
      kitSecret = null;
      v.uvk.fill(0);
      return { kind: "operator" };
    }
    const opened: AccountOpenResult = openAccount(v.userId, v.uvk, session.accountKeys, v.pin.instanceId, v.identityPub);
    if (opened.kind === "identity_fault") return storedUnchecked(opened.reason);
    const kit: FreshKit = { secret: kitSecret, pieceId: session.recoveryPieceId };
    kitSecret = null;
    return { kind: "recovered", session, opened: opened.account, kit, wrap };
  } catch (e) {
    if (stored && kitSecret !== null) return storedUnchecked("unexpected");
    kitSecret?.fill(0);
    v.uvk.fill(0);
    return { kind: "failed", error: e };
  } finally {
    mk.fill(0);
    ak?.fill(0);
    wk?.fill(0);
  }
}
