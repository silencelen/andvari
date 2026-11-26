import { beforeAll, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import { AnsweredCostRefusedError, UnreadableAnswerError } from "../api/wireclient";
import type { AccountKeysV2, ClientPolicyV2, NewDevice, RegisterRequestV2, SessionResponseV2, SignupStartRequest } from "../api/wire";
import { KdfPolicyError } from "../crypto/keys";
import { deriveAuthKey as recoveryAuthKeyOf } from "../crypto/member-recovery";
import { initSodium } from "../crypto/sodium";
import { vector } from "../crypto/trust/vectors";
import { completeSignup, type OnboardWire, signIn, startSignup, unlockSession } from "./onboardflow";
import { PinStore } from "./pinstore";

/**
 * Sign-up and sign-in against a fake server (design §7.2, §7.3): the pin settles first, nothing derived from the
 * password leaves before the password rule says proceed, the genesis names the pinned instance, and the unlock
 * checks catch a server that substitutes the identity key or the genesis.
 */
const cards = vector("instancecard.json");
const base: string[] = cards.chains.find((c: { name: string }) => c.name === "base").cards.map((c: { frameB64: string }) => c.frameB64);
const ORIGIN = "https://vault.example.org";
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const COST_REFUSED = new KdfPolicyError("kdf_below_floor", { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 });
const policy = { kdfParams: KDF, signup: { mode: "open", full: false, ageConfirmRequired: true, powBits: 0 } } as unknown as ClientPolicyV2;

class FakeServer implements OnboardWire {
  reg: RegisterRequestV2 | null = null;
  sent: string[] = [];
  tamper: ((k: AccountKeysV2) => AccountKeysV2) | null = null;
  totp = false;
  role: "member" | "operator" = "member";
  async accountKeys(): Promise<AccountKeysV2> {
    this.sent.push("account/keys");
    return this.keys();
  }
  newDevice(name: string): NewDevice {
    return { platform: "web", name, deviceSecret: "A".repeat(43) };
  }
  async prelogin(email: string) {
    this.sent.push("prelogin");
    void email;
    return { kdfSalt: this.reg!.kdfSalt, kdfParams: this.reg!.kdfParams };
  }
  private keys(): AccountKeysV2 {
    const r = this.reg!;
    const k: AccountKeysV2 = {
      kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub,
      recoveryConfirmed: false, personalWrap: r.personalWrap, genesis: r.genesis,
    };
    return this.tamper ? this.tamper(k) : k;
  }
  /** An answer that names another account than the one registered. */
  userIdOverride: string | null = null;
  private session(): SessionResponseV2 {
    return { userId: this.userIdOverride ?? this.reg!.userId, deviceId: "d0000000-0000-4000-8000-000000000001", accessToken: "a", refreshToken: "r", accountKeys: this.keys(), role: this.role, totpEnrolled: false, mustEnrollTotp: false, recoveryPieceId: "piece" };
  }
  async login(email: string, authKey: string, _name: string, totp?: string) {
    this.sent.push("login");
    if (email !== this.reg!.email || authKey !== this.reg!.authKey) throw new ApiError(401, "invalid_credentials", "x");
    if (this.totp && !totp) throw new ApiError(401, "totp_required", "x");
    return this.session();
  }
  async signupStart(req: SignupStartRequest) {
    this.sent.push("signup/start");
    void req;
  }
  async signupVerify() {
    return { signupTicket: "ticket", expiresAt: 1 };
  }
  /** Thrown instead of the answer: before anything is stored ([refuse]) or after the account is registered ([after]). */
  refuse: unknown = null;
  /** Or built from the registration as it arrived (an answer that names the account sent). */
  after: unknown = null;
  async register(req: RegisterRequestV2) {
    this.sent.push("register");
    if (this.refuse !== null) throw this.refuse;
    this.reg = req;
    if (this.after !== null) throw typeof this.after === "function" ? (this.after as (r: RegisterRequestV2) => unknown)(req) : this.after;
    return this.session();
  }
}

async function pinned(): Promise<PinStore> {
  const pins = new PinStore(memoryStorage(), async () => ({ cards: base.slice(0, 2), rotations: [] }), null);
  const g = await pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error("gate");
  pins.confirmTrustGate(g.ticket);
  return pins;
}

async function signedUp(server: FakeServer, pins: PinStore) {
  const pin = pins.pinFor(ORIGIN)!;
  return completeSignup({ wire: server, pins, origin: ORIGIN, pin, policy, email: "alice@example.com", displayName: "Alice", password: "correct horse", signupTicket: "ticket", ageConfirmed: true, deviceName: "Firefox", nowMs: 1763164800000 });
}

describe("onboarding flows", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("sign-in on an unpinned origin sends nothing and asks for the Trust Gate", async () => {
    const server = new FakeServer();
    const pins = new PinStore(memoryStorage(), async () => ({ cards: base.slice(0, 2), rotations: [] }), null);
    const r = await signIn({ wire: server, pins, origin: ORIGIN, email: "alice@example.com", password: "pw", deviceName: "x", session: null, knownIdentityPub: null });
    expect(r.kind).toBe("pin");
    if (r.kind === "pin") expect(r.first.first.kind).toBe("needs_trust_gate");
    expect(server.sent).toEqual([]);
  });

  it("sign-up then sign-in: the genesis names the pinned instance and the unlock checks pass", async () => {
    const server = new FakeServer();
    const pins = await pinned();
    const start = await startSignup({ wire: server, pins, origin: ORIGIN, email: "alice@example.com", ageConfirmed: true, powBits: 0, pow: async () => ({ date: "x", nonce: 0 }) });
    expect(start.kind).toBe("sent");
    const up = await signedUp(server, pins);
    expect(up.kind).toBe("registered");
    if (up.kind !== "registered") return;
    expect(up.opened.genesis.fields.instanceId).toBe(pins.pinFor(ORIGIN)!.instanceId);
    expect(up.opened.personalVaultId).toBe(server.reg!.personalVault.vaultId);
    expect(up.recoverySecret.length).toBe(32);
    expect(server.reg!.recovery).toEqual({ posture: "private" });
    expect(server.reg!.auth).toEqual({ signupTicket: "ticket" });

    const wrong = await signIn({ wire: server, pins, origin: ORIGIN, email: "alice@example.com", password: "wrong", deviceName: "x", session: null, knownIdentityPub: null });
    expect(wrong.kind).toBe("invalid_credentials");
    const ok = await signIn({ wire: server, pins, origin: ORIGIN, email: "alice@example.com", password: "correct horse", deviceName: "x", session: null, knownIdentityPub: up.opened.identity.publicKey });
    expect(ok.kind).toBe("opened");
    server.totp = true;
    const two = await signIn({ wire: server, pins, origin: ORIGIN, email: "alice@example.com", password: "correct horse", deviceName: "x", session: null, knownIdentityPub: null });
    expect(two.kind).toBe("totp_required");
  }, 60_000);

  it("check W3: a registration the server stored and then answered with another salt, cost or wrapped key hands on the account's kit", async () => {
    const pins = await pinned();
    const otherSalt = "CQkJCQkJCQkJCQkJCQkJCQ";
    const lies: [string, (k: AccountKeysV2) => AccountKeysV2][] = [
      ["salt", (k) => ({ ...k, kdfSalt: otherSalt })],
      ["passes", (k) => ({ ...k, kdfParams: { ...k.kdfParams, ops: 4 } })],
      ["memory", (k) => ({ ...k, kdfParams: { ...k.kdfParams, memBytes: k.kdfParams.memBytes * 2 } })],
      ["wrapped key", (k) => ({ ...k, wrappedUvk: k.encryptedIdentitySeed })],
    ];
    for (const [what, lie] of lies) {
      const server = new FakeServer();
      server.tamper = lie;
      const r = await signedUp(server, pins);
      expect(r.kind, what).toBe("stored_unchecked");
      if (r.kind !== "stored_unchecked") return;
      expect(r.reason, what).toBe("bad_response");
      // No keys, no session, nothing to be written; only the kit the server registered, whole, to be shown.
      expect(Object.keys(r).sort(), what).toEqual(["accountId", "kind", "kit", "reason"]);
      expect(await recoveryAuthKeyOf(r.kit.secret), what).toBe(server.reg!.memberRecovery.recoveryAuthKey);
    }
    // The honest road: registered, the answer's keys the ones sent.
    const server = new FakeServer();
    const up = await signedUp(server, pins);
    expect(up.kind).toBe("registered");
  }, 120_000);

  it("a registration answered by a refusal made nothing; one answered in a shape that cannot be read was stored; one whose outcome cannot be told hands on the account's kit and says why", async () => {
    const pins = await pinned();
    const cases: [string, (s: FakeServer) => void, string, string | null][] = [
      ["a refusal", (s) => (s.refuse = new ApiError(409, "email_taken", "x")), "refused", null],
      ["the server's own JSON success in a shape that cannot be read, naming the account sent", (s) => (s.after = (r: RegisterRequestV2) => new UnreadableAnswerError("x", true, { userId: r.userId })), "stored_unchecked", null],
      ["JSON under the JSON type that names no account", (s) => (s.after = new UnreadableAnswerError("x", true, { error: "upstream_timeout" })), "unknown", "unreadable"],
      ["a success answer that is not the server's JSON", (s) => (s.after = new UnreadableAnswerError("x", false)), "unknown", "unreadable"],
      ["a served cost outside the fence, in an answer naming the account sent", (s) => (s.after = (r: RegisterRequestV2) => new AnsweredCostRefusedError(COST_REFUSED, true, { userId: r.userId })), "stored_unchecked", null],
      ["a served cost outside the fence, in an answer naming another account", (s) => (s.after = new AnsweredCostRefusedError(COST_REFUSED, true, { userId: "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b" })), "unknown", "unreadable"],
      ["a full session answer naming another account", (s) => (s.userIdOverride = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b"), "unknown", "unreadable"],
      ["a server error", (s) => (s.after = new ApiError(502, "http_502", "x")), "unknown", "server_error"],
      ["no answer", (s) => (s.after = new TypeError("Failed to fetch")), "unknown", "no_answer"],
    ];
    for (const [what, arrange, kind, why] of cases) {
      const server = new FakeServer();
      arrange(server);
      const r = await signedUp(server, pins);
      expect(r.kind, what).toBe(kind);
      if (r.kind === "stored_unchecked" || r.kind === "unknown") expect(await recoveryAuthKeyOf(r.kit.secret), what).toBe(server.reg!.memberRecovery.recoveryAuthKey);
      else expect("kit" in r, what).toBe(false);
      if (r.kind === "unknown") expect(r.why, what).toBe(why);
    }
  }, 120_000);

  it("a server that substitutes the identity key or drops the genesis is the identity fault", async () => {
    const server = new FakeServer();
    const pins = await pinned();
    server.tamper = (k) => ({ ...k, genesis: null });
    // At a registration the server already stored the account: its kit is handed on with the refusal.
    const up = await signedUp(server, pins);
    expect(up.kind === "stored_unchecked" && up.reason).toBe("no_genesis");
    expect(up.kind === "stored_unchecked" && (await recoveryAuthKeyOf(up.kit.secret))).toBe(server.reg!.memberRecovery.recoveryAuthKey);
    server.tamper = (k) => ({ ...k, identityPub: "dmn5TI1-jtERdRVMZoWG5QFr3LXPGreVJcHDayMnGio" });
    const r = await signIn({ wire: server, pins, origin: ORIGIN, email: "alice@example.com", password: "correct horse", deviceName: "x", session: null, knownIdentityPub: null });
    expect(r).toEqual({ kind: "identity_fault", reason: "identity_pub_mismatch" });
  }, 60_000);

  it("the operator account is refused on the web, and the browser's own records of another account are an identity fault", async () => {
    const server = new FakeServer();
    const pins = await pinned();
    const up = await signedUp(server, pins);
    expect(up.kind).toBe("registered");
    server.role = "operator";
    const op = await signIn({ wire: server, pins, origin: ORIGIN, email: "alice@example.com", password: "correct horse", deviceName: "x", session: null, knownIdentityPub: null });
    expect(op.kind).toBe("operator");
    server.role = "member";
    const other = await signIn({
      wire: server, pins, origin: ORIGIN, email: "alice@example.com", password: "correct horse", deviceName: "x", session: null,
      knownIdentityPub: () => {
        throw new Error("bound to another account");
      },
    });
    expect(other).toEqual({ kind: "identity_fault", reason: "self_identity_mismatch", servedUserId: server.reg!.userId });
  }, 60_000);

  it("unlocking a held session opens the account here and sends nothing derived from the password", async () => {
    const server = new FakeServer();
    const pins = await pinned();
    const up = await signedUp(server, pins);
    if (up.kind !== "registered") throw new Error("register");
    server.sent = [];
    const wrong = await unlockSession({ wire: server, pins, origin: ORIGIN, userId: server.reg!.userId, password: "nope", knownIdentityPub: null });
    expect(wrong.kind).toBe("wrong_password");
    const ok = await unlockSession({ wire: server, pins, origin: ORIGIN, userId: server.reg!.userId, password: "correct horse", knownIdentityPub: up.opened.identity.publicKey });
    expect(ok.kind).toBe("opened");
    expect(server.sent).toEqual(["account/keys", "account/keys"]);
    server.tamper = (k) => ({ ...k, genesis: null });
    const bad = await unlockSession({ wire: server, pins, origin: ORIGIN, userId: server.reg!.userId, password: "correct horse", knownIdentityPub: null });
    expect(bad).toEqual({ kind: "identity_fault", reason: "no_genesis" });
  }, 60_000);

  it("a forked origin stops sign-in before anything is sent", async () => {
    const server = new FakeServer();
    let served = base.slice(0, 2);
    const pins = new PinStore(memoryStorage(), async () => ({ cards: served, rotations: [] }), null);
    const g = await pins.begin(ORIGIN);
    if (g.kind !== "needs_trust_gate") throw new Error("gate");
    pins.confirmTrustGate(g.ticket);
    served = cards.chains.find((c: { name: string }) => c.name === "public").cards.map((c: { frameB64: string }) => c.frameB64);
    const r = await signIn({ wire: server, pins, origin: ORIGIN, email: "alice@example.com", password: "pw", deviceName: "x", session: null, knownIdentityPub: null });
    expect(r.kind).toBe("pin");
    expect(server.sent).toEqual([]);
  });
});
