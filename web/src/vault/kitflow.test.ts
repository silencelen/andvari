import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { AnswerCutOffError, ApiError, RedirectRefusedError, TrafficStoppedError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import { BAD_RESPONSE, UnreadableAnswerError } from "../api/wireclient";
import {
  KIT_RECOVERY_STORED_UNCHECKED,
  KIT_RECOVERY_STORED_KIT_GONE,
  KIT_RECOVERY_UNKNOWN_KIT_GONE,
  KIT_RECOVERY_UNKNOWN,
  KIT_RECOVERY_UNKNOWN_SERVER_ERROR,
  KIT_RECOVERY_UNKNOWN_UNREADABLE,
  SIGNUP_UNKNOWN,
  SIGNUP_UNKNOWN_SERVER_ERROR,
  SIGNUP_UNKNOWN_UNREADABLE,
} from "../ui/copy";
import { kitCommitScreen, unknownLine } from "../ui/Welcome";
import { type UnknownWhy, unknownWhy } from "./afterstore";
import type { AccountKeysV2, NewDevice, RecoveryCommitRequestV2, SessionResponseV2 } from "../api/wire";
import { adUvk } from "../crypto/ad";
import { ctEquals, fromB64, toB64 } from "../crypto/bytes";
import { accountId } from "./accountopen";
import { seal } from "../crypto/envelope";
import { authKey, masterKey, wrapKey } from "../crypto/keys";
import { randomBytes } from "../crypto/provider";
import { deriveAuthKey as recoveryAuthKeyOf } from "../crypto/member-recovery";
import { initSodium } from "../crypto/sodium";
import { composeKitQr, kitDisplayForm } from "../crypto/trust/recoverykit";
import { vector } from "../crypto/trust/vectors";
import { commitKitRecovery, currentAuthKey, parseKitInput, PasswordRuleRefused, verifyKit, WrapNotOpenedError, type KitRecoveryWire } from "./kitflow";
import { PinStore } from "./pinstore";
import { buildRegistration, type Registration } from "./registration";

/**
 * Kit recovery on the web (design §10, §13): the kit's server must be the pinned one, nothing is sent before the rule,
 * the served identity must be the one the kit's UVK opens, and the commit replaces the kit and is opened through the
 * unlock checks against the pinned instance.
 */
const cards = vector("instancecard.json");
const base: string[] = cards.chains.find((c: { name: string }) => c.name === "base").cards.map((c: { frameB64: string }) => c.frameB64);
const ORIGIN = "https://vault.example.org";
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const EMAIL = "alice@example.com";

class FakeServer implements KitRecoveryWire {
  sent: string[] = [];
  commit: RecoveryCommitRequestV2 | null = null;
  tamperPub: string | null = null;
  /** A lying server: the commit is answered with keys other than the ones sent. */
  tamperKeys: ((k: AccountKeysV2) => AccountKeysV2) | null = null;
  /** The kit's piece the server holds: the registration's, then each stored commit's. */
  piece: { recoveryWrappedUvk: string; recoveryAuthKey: string };
  /** After the commit is stored: the answer is replaced by this throw (an unreadable answer, a server error, no answer). */
  throwAfterStore: unknown = null;
  /** The commit is refused before anything is stored. */
  refuseCommit: ApiError | null = null;
  constructor(readonly reg: Registration) {
    this.piece = reg.request.memberRecovery;
  }
  newDevice(name: string): NewDevice {
    return { platform: "web", name, deviceSecret: "A".repeat(43) };
  }
  async recoverySelfVerify(email: string, recoveryAuthKey: string) {
    this.sent.push("verify");
    const r = this.reg.request;
    if (email !== EMAIL || recoveryAuthKey !== this.piece.recoveryAuthKey) throw new ApiError(401, "invalid_credentials", "x");
    return { recoveryTicket: "ticket", userId: r.userId, recoveryWrappedUvk: this.piece.recoveryWrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: this.tamperPub ?? r.identityPub };
  }
  async recoverySelfCommit(_email: string, req: RecoveryCommitRequestV2): Promise<SessionResponseV2> {
    this.sent.push("commit");
    if (this.refuseCommit) throw this.refuseCommit;
    this.commit = req;
    this.piece = req.newMemberRecovery;
    if (this.throwAfterStore !== null) throw this.throwAfterStore;
    const r = this.reg.request;
    const keys: AccountKeysV2 = {
      kdfSalt: req.newKdfSalt, kdfParams: req.newKdfParams, wrappedUvk: req.newWrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed,
      identityPub: r.identityPub, recoveryConfirmed: false, personalWrap: r.personalWrap, genesis: r.genesis,
    };
    const accountKeys = this.tamperKeys ? this.tamperKeys(keys) : keys;
    return { userId: r.userId, deviceId: "d0000000-0000-4000-8000-000000000001", accessToken: "a", refreshToken: "r", accountKeys, role: "member", totpEnrolled: false, mustEnrollTotp: false, recoveryPieceId: "piece2" };
  }
}

async function setup() {
  const pins = new PinStore(memoryStorage(), async () => ({ cards: base.slice(0, 2), rotations: [] }), null);
  const g = await pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error("gate");
  pins.confirmTrustGate(g.ticket);
  const pin = pins.pinFor(ORIGIN)!;
  const reg = await buildRegistration({
    email: EMAIL, displayName: "Alice", password: "correct horse", kdfParams: KDF, signupTicket: "t", pin, ageConfirmed: true,
    device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: 1763164800000,
  });
  return { pins, pin, reg, server: new FakeServer(reg) };
}

describe("kit recovery", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("a typed kit opens the account's UVK, and the commit replaces the kit and opens under the pin", async () => {
    const { pins, reg, server } = await setup();
    const input = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
    expect(input.kind).toBe("typed");
    if (input.kind !== "typed") return;
    const v = await verifyKit({ wire: server, pins, origin: ORIGIN, input, knownIdentityPub: () => null });
    expect(v.kind).toBe("verified");
    if (v.kind !== "verified") return;
    expect(ctEquals(v.verified.uvk, reg.uvk)).toBe(true);
    const c = await commitKitRecovery({ wire: server, pins, origin: ORIGIN, verified: v.verified, newPassword: "new horse battery", kdfParams: KDF, deviceName: "x" });
    expect(c.kind).toBe("recovered");
    if (c.kind !== "recovered") return;
    expect(c.opened.userId).toBe(reg.userId);
    expect(c.kit.pieceId).toBe("piece2");
    // The replacement kit is the one the server stored, and differs from the scanned one.
    expect(server.commit!.newMemberRecovery.recoveryAuthKey).toBe(await recoveryAuthKeyOf(c.kit.secret));
    expect(server.commit!.newMemberRecovery.recoveryAuthKey).not.toBe(reg.request.memberRecovery.recoveryAuthKey);
    expect(server.commit!.device.platform).toBe("web");
  }, 60_000);

  it("check W2: a commit the server stored and then answered with another salt, cost, wrapped key, account or identity, or an answer that cannot be read, hands on the kit it now holds", async () => {
    const { pins, reg, server } = await setup();
    const otherSalt = toB64(new Uint8Array(16).fill(9));
    const keyLies: [string, (k: AccountKeysV2) => AccountKeysV2, string][] = [
      ["salt and 4 passes", (k) => ({ ...k, kdfSalt: otherSalt, kdfParams: { ...k.kdfParams, ops: 4 } }), BAD_RESPONSE],
      ["salt alone", (k) => ({ ...k, kdfSalt: otherSalt }), BAD_RESPONSE],
      ["passes alone", (k) => ({ ...k, kdfParams: { ...k.kdfParams, ops: 4 } }), BAD_RESPONSE],
      ["memory alone", (k) => ({ ...k, kdfParams: { ...k.kdfParams, memBytes: k.kdfParams.memBytes * 2 } }), BAD_RESPONSE],
      ["the wrapped key alone", (k) => ({ ...k, wrappedUvk: reg.request.wrappedUvk }), BAD_RESPONSE],
      ["no genesis", (k) => ({ ...k, genesis: null }), "no_genesis"],
    ];
    // null: the answer does not name the account sent, so whether it was stored cannot be told ("unknown", the kit
    // still handed on to be kept beside the old one).
    const lies: [string, () => void, string | null][] = [
      ...keyLies.map(([what, lie, reason]): [string, () => void, string] => [what, () => (server.tamperKeys = lie), reason]),
      ["another account's id", () => {
        const commit = FakeServer.prototype.recoverySelfCommit.bind(server);
        server.recoverySelfCommit = async (email, req) => ({ ...(await commit(email, req)), userId: "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b" });
      }, null],
      ["the server's own JSON answer in a shape that cannot be read, naming the account", () => (server.throwAfterStore = new UnreadableAnswerError("x", true, { userId: reg.userId })), BAD_RESPONSE],
      ["JSON under the JSON type that names no account", () => (server.throwAfterStore = new UnreadableAnswerError("x", true, {})), null],
    ];
    // The kit the person typed: the registration's, then each one handed on.
    let typed = reg.recoverySecret.slice();
    for (const [what, lie, reason] of lies) {
      server.tamperKeys = null;
      server.throwAfterStore = null;
      delete (server as Partial<FakeServer>).recoverySelfCommit;
      lie();
      const input = parseKitInput(kitDisplayForm(typed), EMAIL);
      if (input.kind !== "typed") throw new Error("parse");
      const v = await verifyKit({ wire: server, pins, origin: ORIGIN, input, knownIdentityPub: () => null });
      if (v.kind !== "verified") throw new Error(`${what}: ${v.kind}`);
      const c = await commitKitRecovery({ wire: server, pins, origin: ORIGIN, verified: v.verified, newPassword: "new horse battery", kdfParams: KDF, deviceName: "x" });
      if (reason === null) {
        expect(c.kind, what).toBe("unknown");
        if (c.kind !== "unknown") return;
        expect(c.why, what).toBe("unreadable");
      } else {
        expect(c.kind, what).toBe("stored_unchecked");
        if (c.kind !== "stored_unchecked") return;
        expect(c.reason, what).toBe(reason);
        expect(Object.keys(c).sort(), what).toEqual(["accountId", "kind", "kit", "reason"]);
      }
      // The kit handed on is the one the server stored, whole; nothing of the account is handed on to be written.
      expect(await recoveryAuthKeyOf(c.kit.secret), what).toBe(server.piece.recoveryAuthKey);
      expect(c.kit.secret.some((x) => x !== 0), what).toBe(true);
      expect(c.accountId, what).toBe(accountId(fromB64(reg.request.identityPub)));
      expect([...v.verified.uvk].every((x) => x === 0), `${what}: the UVK is wiped`).toBe(true);
      // The kit typed before is dead at the server; the one handed on opens the account.
      const old = parseKitInput(kitDisplayForm(typed), EMAIL);
      if (old.kind !== "typed") throw new Error("parse");
      expect((await verifyKit({ wire: server, pins, origin: ORIGIN, input: old, knownIdentityPub: () => null })).kind, what).toBe("invalid_credentials");
      typed = c.kit.secret.slice();
    }
    // An honest answer that keeps the keys sent: recovered, with the wrap this browser sealed.
    server.tamperKeys = null;
    server.throwAfterStore = null;
    delete (server as Partial<FakeServer>).recoverySelfCommit;
    const input = parseKitInput(kitDisplayForm(typed), EMAIL);
    if (input.kind !== "typed") throw new Error("parse");
    const v = await verifyKit({ wire: server, pins, origin: ORIGIN, input, knownIdentityPub: () => null });
    if (v.kind !== "verified") throw new Error(v.kind);
    const c = await commitKitRecovery({ wire: server, pins, origin: ORIGIN, verified: v.verified, newPassword: "new horse battery", kdfParams: KDF, deviceName: "x" });
    expect(c.kind).toBe("recovered");
    if (c.kind !== "recovered") return;
    expect(c.session.accountKeys.kdfSalt).toBe(c.wrap.kdfSalt);
    expect(c.session.accountKeys.wrappedUvk).toBe(c.wrap.wrappedUvk);
    expect(c.session.accountKeys.kdfParams).toEqual(c.wrap.kdfParams);
  }, 300_000);

  it("a commit the server refused stored nothing and the typed kit still works; one whose outcome cannot be told hands on the new kit, which works exactly when it was stored", async () => {
    const { pins, reg, server } = await setup();
    // [stored]: whether the server stored the commit before the answer went wrong.
    const cases: [string, () => void, string, UnknownWhy | null, boolean][] = [
      ["a refusal", () => (server.refuseCommit = new ApiError(400, "bad_ticket", "x")), "refused", null, false],
      ["a server error after the store", () => (server.throwAfterStore = new ApiError(503, "http_503", "x")), "unknown", "server_error", true],
      ["no answer after the store", () => (server.throwAfterStore = new TypeError("Failed to fetch")), "unknown", "no_answer", true],
      ["no answer, nothing stored", () => (server.refuseCommit = new TypeError("Failed to fetch") as unknown as ApiError), "unknown", "no_answer", false],
      ["a proxy's page after the store", () => (server.throwAfterStore = new UnreadableAnswerError("x", false)), "unknown", "unreadable", true],
      ["a 502 from a proxy, nothing stored", () => (server.refuseCommit = new ApiError(502, "http_502", "x")), "unknown", "server_error", false],
    ];
    for (const [what, arrange, kind, why, stored] of cases) {
      server.refuseCommit = null;
      server.throwAfterStore = null;
      server.piece = reg.request.memberRecovery;
      arrange();
      const input = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
      if (input.kind !== "typed") throw new Error("parse");
      const v = await verifyKit({ wire: server, pins, origin: ORIGIN, input, knownIdentityPub: () => null });
      if (v.kind !== "verified") throw new Error(v.kind);
      const c = await commitKitRecovery({ wire: server, pins, origin: ORIGIN, verified: v.verified, newPassword: "new horse battery", kdfParams: KDF, deviceName: "x" });
      expect(c.kind, what).toBe(kind);
      expect([...v.verified.uvk].every((x) => x === 0), what).toBe(true);
      if (c.kind !== "unknown") {
        expect("kit" in c, `${what}: no kit is handed on`).toBe(false);
        continue;
      }
      expect(c.why, what).toBe(why);
      // The new kit is handed on whole, to be shown: the kit the commit carried.
      expect(c.kit.secret.some((x) => x !== 0), what).toBe(true);
      expect(await recoveryAuthKeyOf(c.kit.secret), what).toBe(server.commit?.newMemberRecovery.recoveryAuthKey ?? (await recoveryAuthKeyOf(c.kit.secret)));
      expect(c.accountId, what).toBe(accountId(fromB64(reg.request.identityPub)));
      // Both kits kept: exactly one of them opens the account, the new one when it was stored, the old one when not.
      const kitVerdict = async (secret: Uint8Array) => {
        const k = parseKitInput(kitDisplayForm(secret), EMAIL);
        if (k.kind !== "typed") throw new Error("parse");
        const r = await verifyKit({ wire: server, pins, origin: ORIGIN, input: k, knownIdentityPub: () => null });
        if (r.kind === "verified") r.verified.uvk.fill(0);
        return r.kind;
      };
      expect(await kitVerdict(c.kit.secret.slice()), `${what}: the new kit`).toBe(stored ? "verified" : "invalid_credentials");
      expect(await kitVerdict(reg.recoverySecret), `${what}: the old kit`).toBe(stored ? "invalid_credentials" : "verified");
      // The screen: the new kit shown under the line for this cause, as at a stored recovery.
      const screen = kitCommitScreen(c);
      expect(screen.show, what).toBe("stored");
      if (screen.show === "stored") expect(screen.line, what).toBe(unknownLine("kit_recovery", why!));
      server.commit = null;
    }
  }, 300_000);

  it("a write whose outcome cannot be told says why: the server didn't answer only when no answer came", () => {
    expect(unknownLine("kit_recovery", "no_answer")).toBe(KIT_RECOVERY_UNKNOWN);
    expect(unknownLine("kit_recovery", "server_error")).toBe(KIT_RECOVERY_UNKNOWN_SERVER_ERROR);
    expect(unknownLine("kit_recovery", "unreadable")).toBe(KIT_RECOVERY_UNKNOWN_UNREADABLE);
    expect(unknownLine("signup", "no_answer")).toBe(SIGNUP_UNKNOWN);
    expect(unknownLine("signup", "server_error")).toBe(SIGNUP_UNKNOWN_SERVER_ERROR);
    expect(unknownLine("signup", "unreadable")).toBe(SIGNUP_UNKNOWN_UNREADABLE);
    expect(new Set([KIT_RECOVERY_UNKNOWN, KIT_RECOVERY_UNKNOWN_SERVER_ERROR, KIT_RECOVERY_UNKNOWN_UNREADABLE, SIGNUP_UNKNOWN, SIGNUP_UNKNOWN_SERVER_ERROR, SIGNUP_UNKNOWN_UNREADABLE]).size).toBe(6);
    expect(unknownWhy(new TypeError("Failed to fetch"))).toBe("no_answer");
    expect(unknownWhy(Object.assign(new Error("x"), { name: "AbortError" }))).toBe("no_answer");
    expect(unknownWhy(Object.assign(new Error("x"), { name: "TimeoutError" }))).toBe("no_answer");
    expect(unknownWhy(new ApiError(503, "http_503", "x"))).toBe("server_error");
    expect(unknownWhy(new ApiError(502, "http_502", "x"))).toBe("server_error");
    expect(unknownWhy(new UnreadableAnswerError("x", false))).toBe("unreadable");
    expect(unknownWhy(new RedirectRefusedError(302))).toBe("unreadable");
    expect(unknownWhy(new TrafficStoppedError("forked", true))).toBe("unreadable");
    // An answer whose body broke off after its status arrived: the server answered, so never "no answer".
    expect(unknownWhy(new AnswerCutOffError(200, new TypeError("terminated")))).toBe("unreadable");
  });

  it("the screens: a stored recovery shows its kit with its own line, never the identity fault's or a nothing-was-changed line, and its session is ended", () => {
    const welcome = readFileSync(fileURLToPath(new URL("../ui/Welcome.tsx", import.meta.url)), "utf8");
    const commit = welcome.slice(welcome.indexOf("const commit = async"), welcome.indexOf("if (step.kind === \"password\") {", welcome.indexOf("const commit = async")));
    const kit = { secret: new Uint8Array(32).fill(1), pieceId: null };
    expect(kitCommitScreen({ kind: "stored_unchecked", reason: "x", kit, accountId: "id" })).toEqual({ show: "stored", kit, accountId: "id", line: KIT_RECOVERY_STORED_UNCHECKED, gone: KIT_RECOVERY_STORED_KIT_GONE, endSession: true });
    expect(kitCommitScreen({ kind: "unknown", error: new TypeError("x"), why: "no_answer", kit, accountId: "id" })).toEqual({ show: "stored", kit, accountId: "id", line: KIT_RECOVERY_UNKNOWN, gone: KIT_RECOVERY_UNKNOWN_KIT_GONE, endSession: true });
    expect(commit).toContain("if (s.endSession) void abandonSignIn(ctx.client, flow);");
    expect(commit).toContain('setStep({ kind: "stored", kit: s.kit, accountId: s.accountId, email: v.email, pin: v.pin, line: s.line, gone: s.gone });');
    expect(commit).not.toContain("IDENTITY_FAULT");
    // The line that stays is the one the card hands back: its own line once typed back, its "taken off the screen" one after the idle limit.
    expect(commit).toContain("<StoredKitCard line={line} gone={step.gone} kit={step.kit}");
    expect(commit).toContain('onSeen={(stays) => setStep({ kind: "after", line: stays })}');
    const signup = welcome.slice(welcome.indexOf("const register = async"), welcome.indexOf("if (step.kind === \"code\") {", welcome.indexOf("const register = async")));
    expect(signup).toMatch(/case "stored_unchecked":\s*\/\/[^\n]*\n\s*void abandonSignIn\(ctx\.client, flow\);/);
    expect(signup).toContain('setStep({ kind: "stored", kit: r.kit, accountId: r.accountId, pin: step.pin, line: SIGNUP_STORED_UNCHECKED, gone: SIGNUP_STORED_KIT_GONE });');
    expect(signup).toContain('setStep({ kind: "stored", kit: r.kit, accountId: r.accountId, pin: step.pin, line: unknownLine("signup", r.why), gone: SIGNUP_UNKNOWN_KIT_GONE });');
    expect(signup).not.toContain("IDENTITY_FAULT");
    expect(signup).toContain("<StoredKitCard line={line} gone={step.gone} kit={step.kit}");
    expect(signup).toContain('onSeen={(stays) => setStep({ kind: "after", line: stays })}');
  });

  it("a kit QR for another server or another card 0 sends nothing", async () => {
    const { pins, pin, reg, server } = await setup();
    for (const [origin, card0] of [["https://other.example.org", pin.card0Hash], [ORIGIN, "0".repeat(64)]] as const) {
      const input = parseKitInput(composeKitQr(origin, card0, EMAIL, reg.recoverySecret.slice()), "");
      expect(input.kind).toBe("qr");
      if (input.kind !== "qr") return;
      const v = await verifyKit({ wire: server, pins, origin: ORIGIN, input, knownIdentityPub: () => null });
      expect(v.kind).toBe("wrong_server");
    }
    expect(server.sent).toEqual([]);
  });

  it("a served identity key the kit's seed does not derive, or one this browser knows otherwise, is the identity fault", async () => {
    const { pins, reg, server } = await setup();
    server.tamperPub = "dmn5TI1-jtERdRVMZoWG5QFr3LXPGreVJcHDayMnGio";
    const a = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
    if (a.kind !== "typed") throw new Error("parse");
    expect((await verifyKit({ wire: server, pins, origin: ORIGIN, input: a, knownIdentityPub: () => null })).kind).toBe("identity_fault");
    server.tamperPub = null;
    const b = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
    if (b.kind !== "typed") throw new Error("parse");
    const other = new Uint8Array(32).fill(7);
    expect((await verifyKit({ wire: server, pins, origin: ORIGIN, input: b, knownIdentityPub: () => other })).kind).toBe("identity_fault");
  });

  it("the operator account's kit stops before a new password is asked for, and an operator session is never kept", async () => {
    const { pins, pin, reg, server } = await setup();
    // The server answers for the account the pinned card names as the operator: nothing is committed.
    const answer = server.recoverySelfVerify.bind(server);
    server.recoverySelfVerify = async (email, key) => ({ ...(await answer(email, key)), userId: pin.operator });
    const a = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
    if (a.kind !== "typed") throw new Error("parse");
    expect(await verifyKit({ wire: server, pins, origin: ORIGIN, input: a, knownIdentityPub: () => null })).toEqual({ kind: "operator" });
    expect(server.sent).toEqual(["verify"]);
    // A card behind a handover: the commit answers an operator session, which the flow refuses to open.
    server.recoverySelfVerify = answer;
    const commit = server.recoverySelfCommit.bind(server);
    server.recoverySelfCommit = async (email, req) => ({ ...(await commit(email, req)), role: "operator" });
    const b = parseKitInput(kitDisplayForm(reg.recoverySecret), EMAIL);
    if (b.kind !== "typed") throw new Error("parse");
    const v = await verifyKit({ wire: server, pins, origin: ORIGIN, input: b, knownIdentityPub: () => null });
    if (v.kind !== "verified") throw new Error(v.kind);
    const c = await commitKitRecovery({ wire: server, pins, origin: ORIGIN, verified: v.verified, newPassword: "new horse battery", kdfParams: KDF, deviceName: "x" });
    expect(c).toEqual({ kind: "operator" });
    expect([...v.verified.uvk].every((x) => x === 0)).toBe(true);
  }, 60_000);

  it("asks the rule for kit recovery, never for a sign-in (FS-B1)", () => {
    const source = readFileSync(fileURLToPath(new URL("./kitflow.ts", import.meta.url)), "utf-8");
    expect(source.match(/purpose: "kit_recovery"/g)?.length).toBe(2);
    expect(source).not.toContain('purpose: "sign_in"');
  });

  it("parses only a kit: anything else is bad_kit, and a typed secret needs an address", () => {
    expect(parseKitInput("https://andvaripass.com/l#x", EMAIL).kind).toBe("bad_kit");
    expect(parseKitInput("andvari-kit:2:junk", EMAIL).kind).toBe("bad_kit");
    expect(parseKitInput(kitDisplayForm(new Uint8Array(32).fill(7)), "not an address").kind).toBe("invalid_email");
  });

  it("spec 01 rule 4: a kit whose secret is zeros is a bad kit, typed or as its QR text, and nothing is asked of the server", () => {
    expect(parseKitInput(kitDisplayForm(new Uint8Array(32)), EMAIL).kind).toBe("bad_kit");
    expect(parseKitInput(kitDisplayForm(new Uint8Array(32)), "not an address").kind).toBe("bad_kit");
    const one = new Uint8Array(32);
    one[31] = 1; // the lowest secret the rule accepts
    expect(parseKitInput(kitDisplayForm(one), EMAIL).kind).toBe("typed");
    const qr = (secret: Uint8Array) => composeKitQr("https://vault.example.org", "a".repeat(64), EMAIL, secret);
    expect(parseKitInput(qr(one), EMAIL).kind).toBe("qr");
    expect(parseKitInput(qr(new Uint8Array(32)), EMAIL).kind).toBe("bad_kit");
  });

  it("the in-session password proof is refused on a blocked origin before anything is derived", async () => {
    const { pins } = await setup();
    const storage = memoryStorage();
    const blocked = new PinStore(storage, async () => ({ cards: [], rotations: [] }), null);
    storage.set("andvari.pin2." + ORIGIN, "{not json");
    // The session's own wrap: the UVK sealed under "pw" with the session's salt and cost.
    const userId = crypto.randomUUID();
    const uvk = randomBytes(32);
    const salt = randomBytes(16);
    const wrap = { kdfSalt: toB64(salt), kdfParams: KDF, wrappedUvk: toB64(seal(await wrapKey(masterKey("pw", salt, KDF)), uvk, adUvk(userId))) };
    await expect(currentAuthKey(blocked, { origin: ORIGIN, account: EMAIL }, "pw", { userId, uvk }, wrap)).rejects.toBeInstanceOf(PasswordRuleRefused);
    // Spec 01 §7: the key comes only from a password that opens the session's own wrap to its UVK.
    await expect(currentAuthKey(pins, { origin: ORIGIN, account: EMAIL }, "not pw", { userId, uvk }, wrap)).rejects.toBeInstanceOf(WrapNotOpenedError);
    await expect(currentAuthKey(pins, { origin: ORIGIN, account: EMAIL }, "pw", { userId, uvk: randomBytes(32) }, wrap)).rejects.toBeInstanceOf(WrapNotOpenedError);
    expect(await currentAuthKey(pins, { origin: ORIGIN, account: EMAIL }, "pw", { userId, uvk }, wrap)).toBe(toB64(await authKey(masterKey("pw", salt, KDF))));
  }, 60_000);
});
