import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AccountDeletePreviewV2, AccountKeysV2, AccountRecoveryPut, PasswordChangeRequestV2 } from "../api/wire";
import { fromB64, toB64 } from "../crypto/bytes";
import { authKey, type KdfParams, masterKey } from "../crypto/keys";
import { randomBytes } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { verifyCardChain } from "../crypto/trust/instancecard";
import { vector } from "../crypto/trust/vectors";
import { runAccountDeletion } from "../ui/account-delete";
import { passwordChangedText, passwordChangeText } from "../ui/reauthtext";
import { Account, ReauthFailedError, ReauthStaleSessionError } from "./account";
import { AccountStateStore } from "./accountdocstore";
import { openAccount, type OpenedAccount } from "./accountopen";
import { currentAuthKey, rotateKit, WrapNotOpenedError } from "./kitflow";
import { PinStore } from "./pinstore";
import { buildRegistration } from "./registration";
import { type SessionKeys, SessionWrap } from "./sessionwrap";
import {
  changePassword, type CopyKeeper, deleteAccount, keepOperatorRecovery, newPasswordCost, operatorOffer, type OperatorOffer, PENDING_CHANGE_UNSETTLED, revokeDevice, rotateKitFor,
  type SettingsSession, type SettingsWire, setRecoveryPosture, setRequireLink, setUpTwoStep, turnOffTwoStep, type TwoStepOff, type TwoStepSetup,
  labelAccount, LABEL_NOT_THIS_ACCOUNT,
} from "./settingsflow";
import { twoStepOffText, twoStepSetupText } from "../ui/reauthtext";
import { PASSWORD_CHANGE_NOT_CONFIRMED, PASSWORD_CHANGED_COPY_STALE, SERVER_KEYS_NOT_KNOWN_REFUSED, SERVER_REFUSED_PROOF, SIGNIN_BACKOFF, TOTP_SETUP_NOT_THIS_ACCOUNT } from "../ui/copy";
import { cardOutcomeOf } from "../ui/account-delete";
import { revokeOutcomeText } from "../ui/AccountDevices";
import { kitRotateText } from "../ui/reauthtext";
import { kitAtSignInText, refusalText } from "../ui/Welcome";
import type { Reauthed } from "./settingsflow";

/**
 * Spec 01 §7 ("the proof runs against the device's own wrap"), as decided for the web on 16 November 2026: before any
 * re-authentication leaves this browser, the typed password is proven against the wrap the session keeps, under that
 * wrap's own salt and cost. A wrong password sends no request of any kind; a server that names another salt, a weaker
 * cost or another wrap at that moment changes nothing that is sent.
 *
 * Every request is counted here: every method of the wire (whatever its name: an unknown one is recorded and fails),
 * the pin store's card fetch, and the browser's own `fetch`.
 */
const rec = vector("recovery.json");
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const WEAK: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 };
const RAISED: KdfParams = { v: 1, alg: "argon2id13", ops: 4, memBytes: 67_108_864 };
const EMAIL = "alice@example.com";
const PASSWORD = "correct horse battery";
const NEW_PASSWORD = "a brand new Password 1";
const NOW = 1_763_164_800_000;
const DEVICE = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const frames: string[] = rec.cardChains["rotated-once"].frames as string[];
let ORIGIN = "";

interface World {
  calls: string[];
  /** Each request's arguments, by method, in order. */
  sent: Record<string, unknown[][]>;
  /** What the "server" answers the routes a re-authentication must never use. */
  lie: boolean;
  /** Throws from the named method instead of answering. */
  fail: Partial<Record<string, unknown>>;
  /** The `otpauth` link the two-step setup answers with (this account's own label when unset). */
  totpUri?: string;
  pinFetches: number;
  s: SettingsSession;
  opened: OpenedAccount;
  honest: AccountKeysV2;
  state: AccountStateStore;
  storage: ReturnType<typeof memoryStorage>;
  offer: OperatorOffer;
  authKey: string;
  account: Account;
}

async function world(): Promise<World> {
  const storage = memoryStorage();
  const w = { calls: [] as string[], sent: {} as Record<string, unknown[][]>, lie: true, fail: {} as Partial<Record<string, unknown>>, pinFetches: 0 } as World;
  const pins = new PinStore(storage, async () => {
    w.pinFetches++;
    return { cards: frames, rotations: [rec.rotationFrames["A-to-B"]] };
  }, null);
  const g = await pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
  pins.confirmTrustGate(g.ticket);
  const pin = pins.pinFor(ORIGIN)!;
  const reg = await buildRegistration({
    email: EMAIL, displayName: "Alice", password: PASSWORD, kdfParams: KDF, signupTicket: "t", pin, ageConfirmed: true,
    device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: NOW,
  });
  const r = reg.request;
  const honest: AccountKeysV2 = { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub, recoveryConfirmed: true, personalWrap: r.personalWrap, genesis: r.genesis };
  // What a lying server names at the moment of a re-authentication: its own salt, the weakest cost, and a wrap of a
  // UVK it chose under the typed password's key. Never read by a re-authentication; served here so a read would show.
  const otherSalt = toB64(randomBytes(16));
  const lies: AccountKeysV2 = { ...honest, kdfSalt: otherSalt, kdfParams: WEAK, wrappedUvk: toB64(randomBytes(72)) };
  const preview: AccountDeletePreviewV2 = { blockers: [], deletedVaults: [], leftVaults: [], memberships: [], totpRequired: false };
  let seq = 0;
  let sealed: string | null = null;
  const answers: Record<string, (...a: never[]) => unknown> = {
    accountKeys: () => (w.lie ? lies : honest),
    prelogin: () => ({ kdfSalt: otherSalt, kdfParams: WEAK }),
    changePassword: () => undefined,
    revokeDevice: () => undefined,
    setRequireLink: () => undefined,
    recoverySelfSetup: () => "piece",
    recoverySelfConfirm: () => undefined,
    deletePreview: () => preview,
    deleteAccountWithLeaves: () => 5,
    instance: () => ({ cards: frames, rotations: [rec.rotationFrames["A-to-B"]] }),
    recoveryPubkey: () => rec.keys.recoveryB.publicKeyB64,
    accountState: () => ({ sealedState: sealed, seq }),
    putAccountState: (s: string) => ((sealed = s), { sealedState: s, seq: ++seq }),
    putRecovery: (req: AccountRecoveryPut) => ((sealed = req.accountState.sealedState), { sealedState: sealed, seq: ++seq }),
    totpSetup: () => ({ secretBase32: "S", otpauthUri: w.totpUri ?? `otpauth://totp/andvari:${EMAIL}?secret=S&issuer=andvari` }),
    totpDisable: () => undefined,
  };
  const wire = new Proxy({} as SettingsWire, {
    get: (_t, name) => {
      if (typeof name !== "string" || name === "then") return undefined;
      return async (...args: never[]) => {
        w.calls.push(name);
        (w.sent[name] ??= []).push(args);
        if (name in w.fail) throw w.fail[name];
        const f = answers[name];
        if (!f) throw new Error(`an unexpected route: ${name}`);
        return f(...args);
      };
    },
  });
  const o = openAccount(reg.userId, reg.uvk.slice(), honest, pin.instanceId, null);
  if (o.kind !== "opened") throw new Error(o.reason);
  // As the app opens it (ui/opensession.ts): the Account keeps the wrap the sign-up sealed, and the Settings flows of the
  // same session prove against that same keeper.
  w.account = Account.fromOpened(o.account, { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk });
  w.s = { wire, pins, origin: ORIGIN, account: EMAIL, opened: o.account, wrap: w.account.sessionWrap };
  w.opened = o.account;
  w.honest = honest;
  w.storage = storage;
  w.state = new AccountStateStore(o.account.userId, o.account.uvk, wire as unknown as ConstructorParameters<typeof AccountStateStore>[2], storage);
  const offer = await operatorOffer(w.s);
  if (offer.kind !== "offer") throw new Error(offer.reason);
  w.offer = offer.offer;
  w.authKey = r.authKey;
  return w;
}

/** Every action of the web client that asks for the master password again, as the screens call it. */
function actions(w: World): Record<string, (password: string) => Promise<unknown>> {
  const s = w.s;
  // The Account of the same session: the TOTP card and the old deletion path prove through it, against the same wrap.
  const account = w.account;
  const client = s.wire as unknown as Parameters<typeof runAccountDeletion>[0];
  return {
    "change the master password": (p) => changePassword(s, p, NEW_PASSWORD, KDF),
    "make a new recovery kit": (p) => rotateKitFor(s, p),
    "revoke a device": (p) => revokeDevice(s, DEVICE, p),
    "new devices must be linked": (p) => setRequireLink(s, true, p),
    "recovery settings: only me": (p) => setRecoveryPosture(s, w.state, w.storage, { posture: "private" }, p, NOW),
    "recovery settings: the operator": (p) => setRecoveryPosture(s, w.state, w.storage, { posture: "operator", offer: w.offer, understood: true, keepDespiteUnsignedChange: true }, p, NOW),
    "the unlock's escrow question: keep": (p) => keepOperatorRecovery(s, w.state, w.storage, p, true, NOW),
    "delete the account": (p) => deleteAccount(s, { typedEmail: EMAIL, password: p, verifiedState: () => null, nowMs: NOW }),
    "delete the account (the card's old path)": (p) => runAccountDeletion(client, account, { email: EMAIL, password: p, totp: "", totpRequired: false }),
    // Server rule of 2026-11-17: every setup carries the proof, also on an account with no factor yet.
    "turn two-step sign-in on": (p) => setUpTwoStep(s, p),
    // Server rule of 2026-11-16: turning it off carries the proof beside the code (spec 03 §0.1 row 16).
    "turn two-step sign-in off": (p) => turnOffTwoStep(s, "123456", p),
    "the kit at sign-in": async (p) => rotateKit(s.wire, s.opened, await currentAuthKey(s.pins, { origin: ORIGIN, account: EMAIL }, p, s.opened, s.wrap.current!)),
  };
}

/** What each action's screen says of its result (the screens' own text functions). */
function screensOf(w: World): Record<string, (r: unknown) => string> {
  return {
    "change the master password": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
    "make a new recovery kit": (r) => kitRotateText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
    "revoke a device": (r) => revokeOutcomeText(r as Reauthed<void>)!,
    "new devices must be linked": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
    "recovery settings: only me": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
    "recovery settings: the operator": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
    "the unlock's escrow question: keep": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
    "delete the account": (r) => (cardOutcomeOf(r as Parameters<typeof cardOutcomeOf>[0]) as { message: string }).message,
    "delete the account (the card's old path)": (r) => (r as { message: string }).message,
    "turn two-step sign-in on": (r) => twoStepSetupText(r as Exclude<TwoStepSetup, { kind: "setup" }>),
    "turn two-step sign-in off": (r) => twoStepOffText(r as TwoStepOff, false).text,
    // Never reached while the mark is set (an unlock that opens from the copy hands no password on, and a sign-in never
    // sets it), and its text reads the mark all the same, as every other proof's does.
    "the kit at sign-in": (e) => kitAtSignInText(e, w.s.wrap),
  };
}

/** The key each request carried, by route. */
function keysSent(w: World): string[] {
  return Object.values(w.sent).flat(2).flatMap((b) => (b !== null && typeof b === "object" && "currentAuthKey" in b ? [(b as { currentAuthKey: string }).currentAuthKey] : typeof b === "string" && b.length === 43 ? [b] : []));
}

const authKeyOf = async (password: string, wrap: SessionKeys): Promise<string> => toB64(await authKey(masterKey(password, fromB64(wrap.kdfSalt), wrap.kdfParams)));

describe("spec 01 §7: every re-authentication is proven on this device against the session's own wrap", () => {
  const fetchSpy = vi.fn(async () => {
    throw new Error("no request may leave");
  });

  beforeAll(async () => {
    await initSodium();
    ORIGIN = verifyCardChain(frames.map((f) => fromB64Canonical(f)!)).cards[0]!.fields.origin;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fetchSpy.mockClear();
  });

  it("a wrong password sends no request of any route, for every action", async () => {
    const w = await world();
    vi.stubGlobal("fetch", fetchSpy);
    const results: Record<string, unknown> = {};
    for (const [name, act] of Object.entries(actions(w))) {
      w.calls = [];
      w.pinFetches = 0;
      results[name] = await act("not the password").catch((e: unknown) => e);
      expect({ name, calls: w.calls, pinFetches: w.pinFetches }).toEqual({ name, calls: [], pinFetches: 0 });
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    // Each says so in its own terms; none of them is a guess about the server.
    for (const name of ["change the master password", "make a new recovery kit", "revoke a device", "new devices must be linked", "recovery settings: only me", "recovery settings: the operator", "the unlock's escrow question: keep", "delete the account", "turn two-step sign-in on", "turn two-step sign-in off"]) {
      expect(results[name], name).toEqual({ kind: "wrong_password" });
    }
    expect(results["delete the account (the card's old path)"]).toEqual({ kind: "error", message: new ReauthFailedError().message });
    expect(results["the kit at sign-in"]).toBeInstanceOf(WrapNotOpenedError);
  }, 300_000);

  it("a server that names another salt, a weaker cost and another wrap at that moment changes nothing that is sent", async () => {
    const w = await world();
    w.lie = true;
    vi.stubGlobal("fetch", fetchSpy);
    for (const [name, act] of Object.entries(actions(w))) {
      w.calls = [];
      w.sent = {};
      const r = await act(PASSWORD);
      expect(r, name).not.toEqual({ kind: "wrong_password" });
      // Nothing was dialed for the proof, and the key every request carried is the honest one, under the session's salt.
      expect(w.calls.filter((c) => c === "accountKeys" || c === "prelogin"), name).toEqual([]);
      const keys = keysSent(w);
      expect(keys.length, name).toBeGreaterThan(0);
      for (const k of keys) expect(k, name).toBe(w.authKey);
      // The change made above moved the session to the new password: put it back for the next action.
      if (name === "change the master password") w.s.wrap.changeMade({ kdfSalt: w.honest.kdfSalt, kdfParams: w.honest.kdfParams, wrappedUvk: w.honest.wrappedUvk });
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  }, 300_000);

  it("server 2026-11-16: a proof refused for the back-off (429) reads as the sign-in's 'too many tries' on all twelve actions, never as a wrong password, and is not retried", async () => {
    const w = await world();
    w.lie = false;
    const proofRoutes = ["changePassword", "recoverySelfSetup", "revokeDevice", "setRequireLink", "putRecovery", "putEscrowSelf", "deleteAccountWithLeaves", "deleteAccount", "totpSetup", "totpDisable"];
    for (const r of proofRoutes) w.fail[r] = new ApiError(429, "rate_limited", "slow down");
    const screens: Record<string, (r: unknown) => string> = {
      "change the master password": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
      "make a new recovery kit": (r) => kitRotateText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
      "revoke a device": (r) => revokeOutcomeText(r as Reauthed<void>)!,
      "new devices must be linked": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
      "recovery settings: only me": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>), // also the escrow question's "not now"
      "recovery settings: the operator": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
      "the unlock's escrow question: keep": (r) => passwordChangeText(r as Exclude<Reauthed<unknown>, { kind: "done" }>),
      "delete the account": (r) => (cardOutcomeOf(r as Parameters<typeof cardOutcomeOf>[0]) as { message: string }).message,
      "delete the account (the card's old path)": (r) => (r as { message: string }).message,
      "turn two-step sign-in on": (r) => twoStepSetupText(r as Exclude<TwoStepSetup, { kind: "setup" }>),
      "turn two-step sign-in off": (r) => twoStepOffText(r as TwoStepOff, false).text,
      "the kit at sign-in": (e) => refusalText(e),
    };
    const all = actions(w);
    expect(Object.keys(screens).sort()).toEqual(Object.keys(all).sort());
    for (const [name, act] of Object.entries(all)) {
      w.calls = [];
      const r = await act(PASSWORD).catch((e: unknown) => e);
      expect(screens[name]!(r), name).toBe(SIGNIN_BACKOFF);
      expect(screens[name]!(r), name).not.toBe(passwordChangeText({ kind: "wrong_password" }));
      // Sent once, never again by itself.
      const proofs = w.calls.filter((c) => proofRoutes.includes(c));
      expect(proofs.length, `${name}: ${w.calls.join(",")}`).toBe(1);
    }
    // The pending wrap of the change the back-off refused is dropped: the server answered, and nothing was changed.
    expect(w.s.wrap.pendingAll).toEqual([]);
  }, 300_000);

  it("spec 01 §7: a proof the server refuses while the session is marked as holding keys the server does not reads as that on every action, never as a wrong password", async () => {
    const w = await world();
    w.lie = false;
    const proofRoutes = ["changePassword", "recoverySelfSetup", "revokeDevice", "setRequireLink", "putRecovery", "putEscrowSelf", "deleteAccountWithLeaves", "deleteAccount", "totpSetup", "totpDisable"];
    for (const r of proofRoutes) w.fail[r] = new ApiError(403, "reauth_failed", "refused");
    const screens = screensOf(w);
    const all = actions(w);
    expect(Object.keys(screens).sort()).toEqual(Object.keys(all).sort());
    // Unmarked, the server's refusal of a proof made here is said as that, never as a wrong password, and the proof went
    // once. (A wrong password typed here is found here and sends nothing: the first test of this file.)
    const unmarked: Record<string, string> = {};
    for (const [name, show] of Object.entries(screens)) {
      w.calls = [];
      unmarked[name] = show(await all[name]!(PASSWORD).catch((e: unknown) => e));
      expect(unmarked[name], name).toBe(SERVER_REFUSED_PROOF);
      expect(w.calls.filter((c) => proofRoutes.includes(c)).length, name).toBe(1);
    }
    w.s.wrap.markServerKeysNotKnown();
    for (const [name, show] of Object.entries(screens)) {
      w.calls = [];
      const text = show(await all[name]!(PASSWORD).catch((e: unknown) => e));
      expect(text, name).toBe(SERVER_KEYS_NOT_KNOWN_REFUSED);
      expect(unmarked[name], name).not.toBe(SERVER_KEYS_NOT_KNOWN_REFUSED);
      expect(w.calls.filter((c) => proofRoutes.includes(c)).length, name).toBe(1);
    }
  }, 300_000);

  it("the right password works as before: each action sends exactly its own requests", async () => {
    const w = await world();
    const own: Record<string, string[]> = {
      "make a new recovery kit": ["recoverySelfSetup"],
      "revoke a device": ["revokeDevice"],
      "new devices must be linked": ["setRequireLink"],
      "delete the account": ["deletePreview", "deleteAccountWithLeaves"],
      "turn two-step sign-in on": ["totpSetup"],
      "turn two-step sign-in off": ["totpDisable"],
    };
    const all = actions(w);
    for (const [name, calls] of Object.entries(own)) {
      w.calls = [];
      const r = await all[name]!(PASSWORD);
      expect(w.calls, name).toEqual(calls);
      if (r !== null && typeof r === "object" && "kind" in r) expect((r as { kind: string }).kind, name).toMatch(/^(done|deleted|setup)$/);
    }
  }, 300_000);

  it("after a password change the new password proves and the old one sends nothing", async () => {
    const w = await world();
    const changed = await changePassword(w.s, PASSWORD, NEW_PASSWORD, null);
    expect(changed.kind).toBe("done");
    if (changed.kind !== "done") return;
    expect(w.s.wrap.current).toEqual(changed.value.keys);
    expect(changed.value.copy).toBe("none"); // this session keeps no offline copy
    expect(w.s.wrap.pending).toBeNull();
    for (const [name, act] of Object.entries(actions(w))) {
      w.calls = [];
      await act(PASSWORD).catch(() => undefined);
      expect({ name, calls: w.calls }).toEqual({ name, calls: [] });
    }
    w.calls = [];
    w.sent = {};
    expect((await rotateKitFor(w.s, NEW_PASSWORD)).kind).toBe("done");
    expect(w.calls).toEqual(["recoverySelfSetup"]);
    expect(keysSent(w)).toEqual([await authKeyOf(NEW_PASSWORD, changed.value.keys)]);
  }, 300_000);

  it("a change with no answer stays pending; the next proof settles it against the server's keys first and proves with the password the server holds; an answer that it was not made drops it", async () => {
    const w = await world();
    w.fail.changePassword = new TypeError("fetch failed");
    expect((await changePassword(w.s, PASSWORD, NEW_PASSWORD, null)).kind).toBe("unknown");
    const pending = w.s.wrap.pending!;
    expect(pending).not.toBeNull();
    delete w.fail.changePassword;
    // The server holds this session's own wrap: that change never landed. Before the proof (and until
    // 2026-11-18, either password proved and was sent while it hung) the keys are read: the old password
    // proves and is sent; the new one proves nothing and nothing is sent.
    w.lie = false;
    w.sent = {};
    w.calls = [];
    expect((await rotateKitFor(w.s, PASSWORD)).kind).toBe("done");
    expect(w.calls).toEqual(["accountKeys", "recoverySelfSetup"]);
    expect(w.s.wrap.pendingAll).toEqual([]);
    w.calls = [];
    expect((await rotateKitFor(w.s, NEW_PASSWORD)).kind).toBe("wrong_password");
    expect(w.calls).toEqual([]);
    expect(keysSent(w)).toEqual([w.authKey]);
    // A refusal of a change is an answer: its wrap goes, and only its own.
    w.fail.changePassword = new ApiError(400, "kdf_too_weak", "x");
    w.calls = [];
    expect((await changePassword(w.s, PASSWORD, "a third Password 33", null)).kind).toBe("refused");
    expect(w.calls).toEqual(["changePassword"]);
    expect(w.s.wrap.pendingAll).toEqual([]);
    w.calls = [];
    expect((await rotateKitFor(w.s, "a third Password 33")).kind).toBe("wrong_password");
    expect((await rotateKitFor(w.s, NEW_PASSWORD)).kind).toBe("wrong_password");
    expect(w.calls).toEqual([]);
    // The made change settles it: exactly the wrap that was sent is the session's own, and nothing is pending.
    delete w.fail.changePassword;
    const made = await changePassword(w.s, PASSWORD, "a fourth Password 44", null);
    expect(made.kind).toBe("done");
    if (made.kind === "done") expect(w.s.wrap.current).toEqual(made.value.keys);
    expect(w.s.wrap.pendingAll).toEqual([]);
    w.calls = [];
    expect((await rotateKitFor(w.s, PASSWORD)).kind).toBe("wrong_password");
    expect(w.calls).toEqual([]);
  }, 300_000);

  /** A Settings session's copy keeper that records what it is asked to keep, and can be told to fail. */
  function keeper(fail: { keep?: boolean; settle?: boolean } = {}) {
    const log: string[] = [];
    const kept: { pending: SessionKeys[]; own: SessionKeys | null } = { pending: [], own: null };
    const copy: CopyKeeper = {
      keepPending: async (p) => {
        log.push(`keep:${p.length}`);
        if (fail.keep) return "failed";
        kept.pending = [...p];
        return "written";
      },
      settle: async (own, p) => {
        log.push(`settle:${p.length}`);
        if (fail.settle) return "failed";
        kept.own = own;
        kept.pending = [...p];
        return "written";
      },
    };
    return { copy, log, kept };
  }

  it("the pending wrap is kept beside the copy before the request goes; a refusal drops only its own; a made change re-keys the copy", async () => {
    const w = await world();
    const k = keeper();
    const s: SettingsSession = { ...w.s, copy: k.copy };
    w.fail.changePassword = new TypeError("fetch failed");
    expect((await changePassword(s, PASSWORD, NEW_PASSWORD, null)).kind).toBe("unknown");
    expect(k.kept.pending).toHaveLength(1);
    expect(k.log).toEqual(["keep:1"]);
    expect(w.sent.changePassword).toHaveLength(1);
    const first = k.kept.pending[0]!;
    // The server says it holds the old wrap: the first never landed. The second is refused: nothing stays pending.
    w.lie = false;
    w.fail.changePassword = new ApiError(400, "kdf_too_weak", "x");
    expect((await changePassword(s, PASSWORD, "a third Password 33", null)).kind).toBe("refused");
    expect(k.log).toEqual(["keep:1", "settle:0", "keep:1", "keep:0"]);
    expect(k.kept.pending).toEqual([]);
    expect(k.kept.own).toEqual(w.s.wrap.current);
    expect(k.kept.own).not.toEqual(first);
    // Made: the copy takes exactly the wrap that was sent, and nothing is pending.
    delete w.fail.changePassword;
    const made = await changePassword(s, PASSWORD, NEW_PASSWORD, null);
    if (made.kind !== "done") throw new Error(made.kind);
    expect(made.value.copy).toBe("written");
    expect(k.kept.own).toEqual(made.value.keys);
    expect(k.kept.pending).toEqual([]);
    expect(passwordChangedText(made.value)).toBe("Master password changed — sessions on other devices were signed out.");
  }, 300_000);

  it("a failed write of the copy's keys is said, not swallowed", async () => {
    for (const fail of [{ settle: true }, { keep: true }]) {
      const w = await world();
      const k = keeper(fail);
      const made = await changePassword({ ...w.s, copy: k.copy }, PASSWORD, NEW_PASSWORD, null);
      if (made.kind !== "done") throw new Error(made.kind);
      expect(made.value.copy, JSON.stringify(fail)).toBe("failed");
      expect(passwordChangedText(made.value)).toContain(PASSWORD_CHANGED_COPY_STALE);
      // The change itself stands: the session proves with the new password.
      expect((await rotateKitFor(w.s, NEW_PASSWORD)).kind).toBe("done");
    }
  }, 300_000);

  it("after a lost answer the same form sent again settles the first change; the old password then proves nothing and nothing more is sent", async () => {
    const w = await world();
    const k = keeper();
    const s: SettingsSession = { ...w.s, copy: k.copy };
    w.lie = false;
    w.fail.changePassword = new TypeError("fetch failed");
    expect((await changePassword(s, PASSWORD, NEW_PASSWORD, null)).kind).toBe("unknown");
    // The server took it before the answer was lost: it holds the new wrap now.
    const req = w.sent.changePassword![0]![0] as PasswordChangeRequestV2;
    Object.assign(w.honest, { kdfSalt: req.newKdfSalt, kdfParams: req.newKdfParams, wrappedUvk: req.newWrappedUvk });
    delete w.fail.changePassword;
    w.calls = [];
    expect((await changePassword(s, PASSWORD, NEW_PASSWORD, null)).kind).toBe("wrong_password");
    expect(w.calls).toEqual(["accountKeys"]);
    expect(w.s.wrap.current?.wrappedUvk).toBe(req.newWrappedUvk);
    expect(w.s.wrap.pendingAll).toEqual([]);
    expect(k.kept.own?.wrappedUvk).toBe(req.newWrappedUvk);
    expect(k.kept.pending).toEqual([]);
    w.calls = [];
    expect((await rotateKitFor(w.s, PASSWORD)).kind).toBe("wrong_password");
    expect(w.calls).toEqual([]);
    expect((await rotateKitFor(w.s, NEW_PASSWORD)).kind).toBe("done");
  }, 300_000);

  it("a second change while the server holds neither wrap (changed elsewhere) sends nothing more, and keeps both for the next unlock", async () => {
    const w = await world();
    w.fail.changePassword = new TypeError("fetch failed");
    expect((await changePassword(w.s, PASSWORD, NEW_PASSWORD, null)).kind).toBe("unknown");
    delete w.fail.changePassword;
    w.lie = true; // the server answers a wrap that is neither this session's nor the pending one
    w.calls = [];
    const r = await changePassword(w.s, PASSWORD, "a third Password 33", null);
    expect(r).toEqual({ kind: "refused", code: PENDING_CHANGE_UNSETTLED });
    expect(w.calls).toEqual(["accountKeys"]);
    expect(w.s.wrap.pendingAll).toHaveLength(1);
    expect(passwordChangeText(r as Exclude<typeof r, { kind: "done" }>)).toBe(new ReauthStaleSessionError().message);
    // A wrong password with a change pending sends nothing derived from it: the server's keys are read first (to know
    // which password it holds) and, while they settle nothing, the proof is not made at all.
    w.calls = [];
    w.sent = {};
    expect(await changePassword(w.s, "not it at all", "x", null)).toEqual({ kind: "refused", code: PENDING_CHANGE_UNSETTLED });
    expect(w.calls).toEqual(["accountKeys"]);
    expect(keysSent(w)).toEqual([]);
  }, 300_000);

  it("no proof is sent while a password change hangs; where the server's keys can't be read, every action says the change wasn't confirmed and sends nothing", async () => {
    const w = await world();
    w.lie = false;
    w.fail.changePassword = new TypeError("fetch failed");
    expect((await changePassword(w.s, PASSWORD, NEW_PASSWORD, null)).kind).toBe("unknown");
    delete w.fail.changePassword;
    // The server took the change before its answer was lost: it holds the new wrap. The old password still proves here.
    const req = w.sent.changePassword![0]![0] as PasswordChangeRequestV2;
    Object.assign(w.honest, { kdfSalt: req.newKdfSalt, kdfParams: req.newKdfParams, wrappedUvk: req.newWrappedUvk });
    w.fail.accountKeys = new TypeError("fetch failed");
    const screens = screensOf(w);
    // The kit at sign-in is a sign-in's own proof: a session that just signed in has no change pending.
    delete screens["the kit at sign-in"];
    const all = actions(w);
    for (const [name, show] of Object.entries(screens)) {
      w.calls = [];
      w.sent = {};
      const text = show(await all[name]!(PASSWORD).catch((e: unknown) => e));
      // On the code before: the old password proved here and was sent, and the server's refusal read "That isn't a wrong
      // password" of a password the server no longer holds.
      expect(text, name).toBe(PASSWORD_CHANGE_NOT_CONFIRMED);
      expect(text, name).not.toBe(SERVER_REFUSED_PROOF);
      expect(w.calls, name).toEqual(["accountKeys"]);
      expect(keysSent(w), name).toEqual([]);
      expect(w.s.wrap.pending, name).not.toBeNull();
    }
    // Once the keys can be read, the change is settled as made: the old password proves nothing and sends nothing, and
    // the new one is the one sent.
    delete w.fail.accountKeys;
    w.calls = [];
    w.sent = {};
    expect((await rotateKitFor(w.s, PASSWORD)).kind).toBe("wrong_password");
    expect(w.calls).toEqual(["accountKeys"]);
    expect(w.s.wrap.pendingAll).toEqual([]);
    expect(w.s.wrap.current?.wrappedUvk).toBe(req.newWrappedUvk);
    expect((await rotateKitFor(w.s, NEW_PASSWORD)).kind).toBe("done");
    expect(keysSent(w)).toEqual([await authKeyOf(NEW_PASSWORD, w.s.wrap.current!)]);
  }, 300_000);

  it("the new password is derived at the account's present cost, raised only when an upgrade is due, never lowered", async () => {
    expect(newPasswordCost(KDF, null)).toEqual(KDF);
    expect(newPasswordCost(KDF, WEAK)).toEqual(KDF);
    expect(newPasswordCost(KDF, RAISED)).toEqual(RAISED);
    expect(newPasswordCost(RAISED, KDF)).toEqual(RAISED);
    // An account above the served cost on one figure and below it on the other takes the higher of each (a server whose
    // floor was raised refuses a wrap below it on either figure).
    const MORE_MEMORY: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 128 * 1_048_576 };
    expect(newPasswordCost(RAISED, MORE_MEMORY)).toEqual({ v: 1, alg: "argon2id13", ops: 4, memBytes: 128 * 1_048_576 });
    // A served cost outside this browser's own limits is not followed on any figure.
    expect(newPasswordCost(KDF, { v: 1, alg: "argon2id13", ops: 4, memBytes: 64 * 1024 * 1_048_576 })).toEqual(KDF);
    expect(newPasswordCost(KDF, { v: 1, alg: "argon2id13", ops: 4, memBytes: 67_108_864 + 1 })).toEqual(KDF);
    const w = await world();
    expect((await changePassword(w.s, PASSWORD, NEW_PASSWORD, WEAK)).kind).toBe("done");
    expect((w.sent.changePassword![0]![0] as PasswordChangeRequestV2).newKdfParams).toEqual(KDF);
  }, 300_000);

  it("tripwire: the account's keys are read from the server only by the unlock of a held session and to settle a pending password change, never for a proof", () => {
    const src = fileURLToPath(new URL("../", import.meta.url));
    const files: string[] = [];
    const walk = (d: string) => {
      for (const n of readdirSync(d)) {
        const p = join(d, n);
        if (statSync(p).isDirectory()) walk(p);
        else if (/\.(ts|tsx)$/.test(n) && !/\.test\.tsx?$/.test(n) && !p.includes(`${"/"}journeys${"/"}`)) files.push(p);
      }
    };
    walk(src);
    const reads = files.flatMap((f) =>
      readFileSync(f, "utf8").split("\n").flatMap((line, i) => (!/^\s*(\*|\/\*)/.test(line) && /\b(wire|client)\.accountKeys\(\)/.test(line.split("//")[0]!) ? [`${f.slice(src.length)}:${i + 1}`] : [])),
    );
    expect(reads.map((r) => r.replace(/:\d+$/, ""))).toEqual(["vault/onboardflow.ts", "vault/settingsflow.ts"]);
    // The settle's one read sits after the return that is taken when no change is pending.
    const flow = readFileSync(join(src, "vault/settingsflow.ts"), "utf8");
    const at = flow.indexOf("wire.accountKeys()");
    expect(flow.lastIndexOf("if (wrap.pendingAll.length === 0) return", at)).toBeGreaterThan(flow.lastIndexOf("export async function settlePendingChange(", at));
    expect(flow.lastIndexOf("export async function settlePendingChange(", at)).toBeGreaterThan(-1);
  });

  it("a session that keeps no wrap proves nothing and sends nothing; it never falls back to asking the server", async () => {
    const w = await world();
    const s: SettingsSession = { ...w.s, wrap: new SessionWrap(null) };
    w.calls = [];
    expect(await rotateKitFor(s, PASSWORD)).toEqual({ kind: "refused", code: "no_session_wrap" });
    expect(await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: () => null, nowMs: NOW })).toEqual({ kind: "refused", code: "no_session_wrap" });
    expect(w.calls).toEqual([]);
    // The screens say what to do in the core twin's words, never "the server refused".
    expect(passwordChangeText({ kind: "refused", code: "no_session_wrap" })).toBe("Lock and unlock andvari, then try again.");
  }, 120_000);
});

/**
 * Design §8 (decided on 2026-11-17), as the shared code's WireTwoStep checks it: a two-step setup is shown only when its
 * label names this account under the product's name. An authenticator app files a key under its label, and some replace
 * an entry with the same one; before, the browser showed the setup as served. The lies are the shared code's test's.
 */
describe("a two-step setup is shown only when it names this account", () => {
  const OTHERS = [
    "otpauth://totp/andvari:bob@example.org?secret=JBSWY3DPEHPK3PXP&issuer=andvari",
    "otpauth://totp/andvari:alice@example.org?secret=JBSWY3DPEHPK3PXP&issuer=andvari",
    "otpauth://totp/andvari:alice?secret=JBSWY3DPEHPK3PXP&issuer=andvari",
    "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP",
    "otpauth://totp/other:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=other",
    "otpauth://totp/andvari:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=other",
    "otpauth://totp/andvari:alice%4?secret=JBSWY3DPEHPK3PXP",
    "otpauth://hotp/andvari:alice@example.com?secret=JBSWY3DPEHPK3PXP",
  ];
  const OWN = [
    "otpauth://totp/andvari:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=andvari&algorithm=SHA1&digits=6&period=30",
    "otpauth://totp/andvari:Alice@Example.com?secret=JBSWY3DPEHPK3PXP",
    "otpauth://totp/andvari%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=andvari",
  ];

  it("reads the label as the shared code reads it", () => {
    for (const other of OTHERS) expect(labelAccount(other), other).not.toBe(EMAIL);
    for (const own of OWN) expect(labelAccount(own), own).toBe(EMAIL);
  });

  it("a setup that names anything else is not shown, and the person is told the server's answer could not be used", async () => {
    const w = await world();
    for (const other of OTHERS) {
      w.totpUri = other;
      const r = await setUpTwoStep(w.s, PASSWORD);
      expect(r, other).toEqual({ kind: "refused", code: LABEL_NOT_THIS_ACCOUNT });
      expect(twoStepSetupText(r as Exclude<TwoStepSetup, { kind: "setup" }>)).toBe(TOTP_SETUP_NOT_THIS_ACCOUNT);
    }
    for (const own of OWN) {
      w.totpUri = own;
      const r = await setUpTwoStep(w.s, PASSWORD);
      expect(r.kind, own).toBe("setup");
    }
  }, 120_000);
});
