import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { memoryStorage } from "../api/devicesecret";
import type { AccountKeysV2, ClientPolicyV2, NewDevice, PreloginResponseV2, RegisterRequestV2, SessionResponseV2 } from "../api/wire";
import { adIdkey, adUvk, adVkPersonal } from "../crypto/ad";
import { toB64 } from "../crypto/bytes";
import { seal } from "../crypto/envelope";
import { type KdfParams, KdfPolicyError, masterKey, wrapKey } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes, signKeypairFromSeed } from "../crypto/provider";
import { signGenesis } from "../crypto/trust/genesis";
import { initSodium } from "../crypto/sodium";
import { vector } from "../crypto/trust/vectors";
import { completeSignup, type CopyAtUnlock, type OnboardWire, openFromCopy, signIn, unlockSession } from "./onboardflow";
import { PinStore } from "./pinstore";
import { type SessionKeys, wrapOf } from "./sessionwrap";

/**
 * Spec 01 §7, a served wrap at the unlock of a held session. A served wrap is taken only when it opens to a key this
 * browser holds: the password must open this browser's own wrap (the offline copy's, or one kept pending beside it) and
 * the served one, to exactly the same account key. When the password opens this browser's own wrap and the served one
 * fails the fence, does not open, or opens to another key, the vault opens from the copy ("leaves both"). When nothing
 * here opens to compare with, nothing is taken. With no copy, the unlock is a sign-in's checks. Every served cost passes
 * the whole fence before anything is derived at it; every derivation is counted here.
 */
const counted = vi.hoisted(() => ({ derivations: [] as { ops: number; memBytes: number }[] }));
vi.mock("../crypto/provider", async (importOriginal) => {
  const real = await importOriginal<typeof import("../crypto/provider")>();
  return {
    ...real,
    argon2id: (password: Uint8Array, salt: Uint8Array, outLen: number, ops: number, memBytes: number) => {
      counted.derivations.push({ ops, memBytes });
      return real.argon2id(password, salt, outLen, ops, memBytes);
    },
  };
});

const cards = vector("instancecard.json");
const base: string[] = cards.chains.find((c: { name: string }) => c.name === "base").cards.map((c: { frameB64: string }) => c.frameB64);
const ORIGIN = "https://vault.example.org";
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const RAGGED: KdfParams = { ...KDF, memBytes: KDF.memBytes + 512 };
const OUTSIDE: readonly KdfParams[] = [RAGGED, { ...KDF, ops: 2 }, { ...KDF, ops: 11 }, { ...KDF, ops: 3.5 }, { ...KDF, memBytes: 1_073_741_824 + 1024 }];
const policy = { kdfParams: KDF, signup: { mode: "open", full: false, ageConfirmRequired: true, powBits: 0 } } as unknown as ClientPolicyV2;
const PW = "correct horse";
const NEW_PW = "battery staple 42";

/** A server whose account keys are its registration's, with the wrap part replaced at will (the lie it plays). */
class Server implements Pick<OnboardWire, "accountKeys" | "register" | "newDevice"> {
  reg: RegisterRequestV2 | null = null;
  sent: string[] = [];
  wrap: SessionKeys | null = null;
  /** Thrown from the read of the keys instead of answering (the wire's own fence, for one). */
  throws: unknown = null;
  async accountKeys(): Promise<AccountKeysV2> {
    this.sent.push("account/keys");
    if (this.throws !== null) throw this.throws;
    return this.keys();
  }
  keys(): AccountKeysV2 {
    const r = this.reg!;
    const w = this.wrap ?? { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk };
    return { ...w, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub, recoveryConfirmed: true, personalWrap: r.personalWrap, genesis: r.genesis };
  }
  newDevice(name: string): NewDevice {
    return { platform: "web", name, deviceSecret: "A".repeat(43) };
  }
  async register(req: RegisterRequestV2): Promise<SessionResponseV2> {
    this.reg = req;
    return { userId: req.userId, deviceId: "d0000000-0000-4000-8000-000000000001", accessToken: "a", refreshToken: "r", accountKeys: this.keys(), role: "member", totpEnrolled: false, mustEnrollTotp: false, recoveryPieceId: "piece" };
  }
}

/** A wrap of [uvk] under [password], a fresh salt and [kdfParams]: what a password change or a re-key seals. */
async function wrapUnder(userId: string, uvk: Uint8Array, password: string, kdfParams: KdfParams = KDF): Promise<SessionKeys> {
  const salt = randomBytes(16);
  const mk = masterKey(password, salt, kdfParams);
  const wk = await wrapKey(mk);
  mk.fill(0);
  try {
    return { kdfSalt: toB64(salt), kdfParams, wrappedUvk: toB64(seal(wk, uvk, adUvk(userId))) };
  } finally {
    wk.fill(0);
  }
}

async function setup() {
  const server = new Server();
  const pins = new PinStore(memoryStorage(), async () => ({ cards: base.slice(0, 2), rotations: [] }), null);
  const g = await pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error("gate");
  pins.confirmTrustGate(g.ticket);
  const up = await completeSignup({ wire: server as unknown as OnboardWire, pins, origin: ORIGIN, pin: pins.pinFor(ORIGIN)!, policy, email: "alice@example.com", displayName: "Alice", password: PW, signupTicket: "ticket", ageConfirmed: true, deviceName: "Firefox", nowMs: 1763164800000 });
  if (up.kind !== "registered") throw new Error(up.kind);
  const userId = up.opened.userId;
  const uvk = up.opened.uvk.slice();
  const identity = up.opened.identity.publicKey.slice();
  const full = server.keys();
  const original = wrapOf(full);
  server.sent = [];
  /** The offline copy as this browser would hold it: the account's keys with [own] as its wrap, and [pending] beside it. */
  const copyAt = (own: SessionKeys, pending: SessionKeys[] = []): CopyAtUnlock => ({ kind: "copy", keys: { ...full, ...own }, pending });
  const unlock = async (password: string, copy?: CopyAtUnlock, knownIdentityPub: Uint8Array | null = identity) => {
    counted.derivations = [];
    return unlockSession({ wire: server, pins, origin: ORIGIN, userId, password, knownIdentityPub, ...(copy ? { copy } : {}) });
  };
  const rewrap = (password: string, kdfParams: KdfParams = KDF, key: Uint8Array = uvk) => wrapUnder(userId, key, password, kdfParams);
  return { server, pins, userId, uvk, identity, full, original, copyAt, unlock, rewrap };
}

/**
 * A whole key set of another account key for [userId], as a server could make one: a fresh account key, identity seed and
 * personal vault key, the genesis signed for the pinned instance, and the account key wrapped under [password].
 */
async function anotherKeySet(userId: string, instanceId: string, password: string): Promise<AccountKeysV2> {
  const uvk = randomBytes(32);
  const seed = randomBytes(32);
  const vk = randomBytes(32);
  const identity = boxKeypairFromSeed(seed);
  const signing = signKeypairFromSeed(seed);
  const personalVaultId = "e0000000-0000-4000-8000-000000000001";
  const genesis = signGenesis(signing, { userId, identityKey: toB64(identity.publicKey), instanceId, personalVaultId, createdAt: 1763164800000 });
  const wrap = await wrapUnder(userId, uvk, password);
  return {
    ...wrap,
    encryptedIdentitySeed: toB64(seal(uvk, seed, adIdkey(userId))),
    identityPub: toB64(identity.publicKey),
    recoveryConfirmed: true,
    personalWrap: { vaultId: personalVaultId, wrappedVk: toB64(seal(uvk, vk, adVkPersonal(personalVaultId, userId))) },
    genesis: toB64(genesis),
  };
}

/** A sign-in's two calls: the first exchange answers [pre], the login answers [keys] as the account's keys. */
function signInWire(s: { userId: string }, sent: string[], pre: Pick<SessionKeys, "kdfSalt" | "kdfParams">, keys: AccountKeysV2): OnboardWire {
  return {
    prelogin: async (): Promise<PreloginResponseV2> => (sent.push("prelogin"), { kdfSalt: pre.kdfSalt, kdfParams: pre.kdfParams }) as PreloginResponseV2,
    login: async (): Promise<SessionResponseV2> => (sent.push("login"), { userId: s.userId, deviceId: "d0000000-0000-4000-8000-000000000001", accessToken: "a", refreshToken: "r", accountKeys: keys, role: "member", totpEnrolled: false, mustEnrollTotp: false, recoveryPieceId: null }),
  } as unknown as OnboardWire;
}

describe("a served wrap at the unlock of a held session (spec 01 §7)", () => {
  beforeAll(async () => {
    await initSodium();
  });
  beforeEach(() => {
    counted.derivations = [];
  });

  it("the served wrap is this browser's own or a pending one: opened as always, one derivation, and a wrong password is a wrong password", async () => {
    const s = await setup();
    expect((await s.unlock(PW, s.copyAt(s.original))).kind).toBe("opened");
    expect(counted.derivations).toEqual([{ ops: 3, memBytes: KDF.memBytes }]);
    expect((await s.unlock("nope", s.copyAt(s.original))).kind).toBe("wrong_password");
    const next = await s.rewrap(NEW_PW);
    s.server.wrap = next; // a change this browser sent and is still waiting on, stored
    const r = await s.unlock(NEW_PW, s.copyAt(s.original, [next]));
    expect(r.kind).toBe("opened");
    if (r.kind === "opened") expect(r.wrap).toEqual(next);
    expect(s.server.sent.every((x) => x === "account/keys")).toBe(true);
  }, 120_000);

  it("a “done” the server never stored: the copy holds the sent wrap, the server the old one; both open to the same key, so the served one is taken", async () => {
    const s = await setup();
    const sent = await s.rewrap(PW, { ...KDF, ops: 4 }); // the quiet re-key's wrap, same password, answered "done"
    const r = await s.unlock(PW, s.copyAt(sent));
    expect(r.kind).toBe("opened");
    if (r.kind === "opened") {
      expect(r.wrap).toEqual(s.original);
      expect(r.opened.uvk).toEqual(s.uvk);
    }
    // The copy's wrap, then the served one: two, each at its own cost.
    expect(counted.derivations).toEqual([{ ops: 4, memBytes: KDF.memBytes }, { ops: 3, memBytes: KDF.memBytes }]);
    expect(s.server.sent).toEqual(["account/keys"]);
  }, 120_000);

  it("stored, then answered with a refusal: the server holds the new wrap, the copy the old; both open to the same key, so it is taken", async () => {
    const s = await setup();
    const stored = await s.rewrap(PW, { ...KDF, ops: 4 });
    s.server.wrap = stored;
    const r = await s.unlock(PW, s.copyAt(s.original));
    expect(r.kind).toBe("opened");
    if (r.kind === "opened") expect(r.wrap).toEqual(stored);
    expect(s.server.sent).toEqual(["account/keys"]);
  }, 120_000);

  describe("nothing here opens to compare with: nothing is taken (a sign-in follows)", () => {
    it("an older password's wrap of the same account key, served to a browser whose copy is at the new password, with the older password typed: not taken, and the copy still opens only with the new password", async () => {
      const s = await setup();
      const old = s.original; // the wrap the server kept from before the change
      const current = await s.rewrap(NEW_PW); // the change made here: the copy holds it
      const copy = s.copyAt(current);
      s.server.wrap = old;
      expect(await s.unlock(PW, copy)).toEqual({ kind: "keys_differ", reason: "served_only" });
      expect(s.server.sent).toEqual(["account/keys"]);
      // Nothing of the served keys reached the copy: it opens with the new password and not with the old.
      if (copy.kind !== "copy") throw new Error("copy");
      expect((await openFromCopy({ keys: copy.keys, pins: s.pins, origin: ORIGIN, userId: s.userId, password: PW, knownIdentityPub: s.identity })).kind).toBe("wrong_password");
      expect((await openFromCopy({ keys: copy.keys, pins: s.pins, origin: ORIGIN, userId: s.userId, password: NEW_PW, knownIdentityPub: s.identity })).kind).toBe("opened");
    }, 120_000);

    it("this browser's own password change whose write to the copy failed: the new password opens the served wrap and not the copy's, so nothing is taken; the sign-in that follows opens", async () => {
      const s = await setup();
      const changed = await s.rewrap(NEW_PW); // stored by the server; the copy kept the old wrap and nothing pending
      s.server.wrap = changed;
      expect(await s.unlock(NEW_PW, s.copyAt(s.original))).toEqual({ kind: "keys_differ", reason: "served_only" });
      // The sign-in: prelogin at the served salt and cost, a login, then a sign-in's checks.
      const wire = {
        prelogin: async (): Promise<PreloginResponseV2> => ({ kdfSalt: changed.kdfSalt, kdfParams: changed.kdfParams }) as PreloginResponseV2,
        login: async () => ({ userId: s.userId, deviceId: "d0000000-0000-4000-8000-000000000001", accessToken: "a", refreshToken: "r", accountKeys: s.server.keys(), role: "member", totpEnrolled: false, mustEnrollTotp: false, recoveryPieceId: null }) as SessionResponseV2,
      } as unknown as OnboardWire;
      const r = await signIn({ wire, pins: s.pins, origin: ORIGIN, email: "alice@example.com", password: NEW_PW, deviceName: "Firefox", session: null, knownIdentityPub: s.identity });
      expect(r.kind).toBe("opened");
      if (r.kind === "opened") expect(r.wrap).toEqual(changed);
    }, 120_000);

    it("a copy whose keys cannot be read: nothing is derived, nothing taken", async () => {
      const s = await setup();
      expect(await s.unlock(PW, { kind: "unreadable" })).toEqual({ kind: "keys_differ", reason: "copy_unreadable" });
      expect(counted.derivations).toEqual([]);
    }, 120_000);

    it("a password that opens neither: a wrong password", async () => {
      const s = await setup();
      s.server.wrap = await s.rewrap(NEW_PW);
      expect((await s.unlock("nope", s.copyAt(s.original))).kind).toBe("wrong_password");
    }, 120_000);
  });

  describe("the copy's own wrap opened: the vault opens from the copy (“leaves both”), never a refusal and never a wrong password", () => {
    it("the served cost fails the whole fence (a ragged KiB, below the floor, above the ceiling, not a whole number): nothing is derived at it", async () => {
      const s = await setup();
      for (const kdfParams of OUTSIDE) {
        s.server.wrap = { ...s.original, kdfParams };
        const r = await s.unlock(PW, s.copyAt(s.original));
        expect(r.kind, JSON.stringify(kdfParams)).toBe("opened_from_copy");
        if (r.kind === "opened_from_copy") {
          expect(r.cause).toBe("fence");
          expect(r.wrap).toEqual(s.original);
          expect(r.opened.uvk).toEqual(s.uvk);
        }
        expect(counted.derivations, JSON.stringify(kdfParams)).toEqual([{ ops: 3, memBytes: KDF.memBytes }]);
      }
    }, 120_000);

    it("the wire's own fence refused the served cost: the same", async () => {
      const s = await setup();
      s.server.throws = new KdfPolicyError("kdf_below_floor", { ...KDF, ops: 1 });
      const r = await s.unlock(PW, s.copyAt(s.original));
      expect(r.kind === "opened_from_copy" && r.cause).toBe("fence");
      expect(counted.derivations).toEqual([{ ops: 3, memBytes: KDF.memBytes }]);
    }, 120_000);

    it("the served wrap does not open with the password", async () => {
      const s = await setup();
      s.server.wrap = await s.rewrap(NEW_PW); // under another password (changed elsewhere, or a lie)
      const r = await s.unlock(PW, s.copyAt(s.original));
      expect(r.kind === "opened_from_copy" && r.cause).toBe("not_open");
      if (r.kind === "opened_from_copy") expect(r.opened.uvk).toEqual(s.uvk);
    }, 120_000);

    it("the served wrap opens with the password, but to another account key: the copy's key opens the vault", async () => {
      const s = await setup();
      s.server.wrap = await s.rewrap(PW, KDF, randomBytes(32));
      const r = await s.unlock(PW, s.copyAt(s.original));
      expect(r.kind === "opened_from_copy" && r.cause).toBe("other_key");
      if (r.kind === "opened_from_copy") {
        expect(r.opened.uvk).toEqual(s.uvk);
        expect(r.keys.wrappedUvk).toBe(s.original.wrappedUvk);
      }
      expect(counted.derivations.length).toBe(2);
    }, 120_000);

    it("a pending wrap opened (the copy's own did not): the vault opens from the copy, the pending wraps kept", async () => {
      const s = await setup();
      const pending = await s.rewrap(NEW_PW, { ...KDF, ops: 4 });
      s.server.wrap = await s.rewrap("a third one");
      const r = await s.unlock(NEW_PW, s.copyAt(s.original, [pending]));
      expect(r.kind === "opened_from_copy" && r.cause).toBe("not_open");
      if (r.kind === "opened_from_copy") expect(r.pending).toEqual([pending]);
    }, 120_000);

    it("with no identity record kept here, the copy still decides: nothing served is taken", async () => {
      const s = await setup();
      s.server.wrap = await s.rewrap(PW, KDF, randomBytes(32));
      expect((await s.unlock(PW, s.copyAt(s.original), null)).kind).toBe("opened_from_copy");
      s.server.wrap = s.original;
      expect(await s.unlock(PW, s.copyAt(await s.rewrap(NEW_PW)), null)).toEqual({ kind: "keys_differ", reason: "served_only" });
    }, 120_000);
  });

  describe("no copy here: a sign-in's checks, never “opened as always”", () => {
    it("the served wrap opens with the password: the identity checks of a sign-in decide", async () => {
      const s = await setup();
      s.server.wrap = await s.rewrap(PW, { ...KDF, ops: 4 });
      expect((await s.unlock(PW)).kind).toBe("opened");
      expect((await s.unlock(PW, { kind: "none" })).kind).toBe("opened");
      // No identity record here either (storage cleared, a private window): the genesis and the pin still decide.
      expect((await s.unlock(PW, { kind: "none" }, null)).kind).toBe("opened");
      // An identity record that is not this account's key: refused as at a sign-in.
      expect((await s.unlock(PW, { kind: "none" }, randomBytes(32))).kind).toBe("identity_fault");
      // A served wrap of another account key: the identity seed does not open under it.
      s.server.wrap = await s.rewrap(PW, KDF, randomBytes(32));
      expect((await s.unlock(PW, { kind: "none" })).kind).toBe("identity_fault");
    }, 120_000);

    it("a served cost outside the whole fence: kdf_refused with nothing derived, never a wrong password", async () => {
      const s = await setup();
      for (const kdfParams of OUTSIDE) {
        s.server.wrap = { ...s.original, kdfParams };
        expect(await s.unlock(PW, { kind: "none" }), JSON.stringify(kdfParams)).toEqual({ kind: "kdf_refused" });
        expect(counted.derivations).toEqual([]);
      }
      s.server.wrap = null;
      s.server.throws = new KdfPolicyError("kdf_above_ceiling", { ...KDF, ops: 11 });
      expect(await s.unlock(PW, { kind: "none" })).toEqual({ kind: "kdf_refused" });
      expect(counted.derivations).toEqual([]);
    }, 120_000);
  });

  describe("two sentences that say what is so", () => {
    it("a wrong password while the served cost is outside the fence: both are said (the password opened none of this browser's wraps, and the cost cannot be used), with nothing derived at that cost", async () => {
      const s = await setup();
      for (const kdfParams of OUTSIDE) {
        s.server.wrap = { ...(await s.rewrap(NEW_PW)), kdfParams };
        s.server.sent = [];
        expect(await s.unlock("nope", s.copyAt(s.original)), JSON.stringify(kdfParams)).toEqual({ kind: "wrong_password_kdf_refused" });
        expect(counted.derivations).toEqual([{ ops: 3, memBytes: KDF.memBytes }]); // the copy's own wrap only
        expect(s.server.sent).toEqual(["account/keys"]);
      }
      // The wire's own fence refused it: the same.
      s.server.wrap = null;
      s.server.throws = new KdfPolicyError("kdf_above_ceiling", { ...KDF, ops: 11 });
      expect(await s.unlock("nope", s.copyAt(s.original))).toEqual({ kind: "wrong_password_kdf_refused" });
      // The right password still opens from the copy ("leaves both").
      expect((await s.unlock(PW, s.copyAt(s.original))).kind).toBe("opened_from_copy");
    }, 120_000);

    it("a password change with no answer that was not stored: the new password opens the waiting wrap, and the unlock says the change did not reach the server, never a wrong password", async () => {
      const s = await setup();
      const AT = 1763251200000;
      const waiting = { ...(await s.rewrap(NEW_PW)), at: AT };
      // The server holds the copy's own wrap: the change never reached it.
      const r = await s.unlock(NEW_PW, s.copyAt(s.original, [waiting]));
      expect(r).toEqual({ kind: "change_not_stored", at: AT });
      expect(s.server.sent).toEqual(["account/keys"]);
      // A wrap kept before the day was recorded: the same, with no day.
      const { at: _at, ...undated } = waiting;
      expect(await s.unlock(NEW_PW, s.copyAt(s.original, [undated]))).toEqual({ kind: "change_not_stored", at: null });
      // The earlier password opens as always; a password that opens neither is a wrong password.
      expect((await s.unlock(PW, s.copyAt(s.original, [waiting]))).kind).toBe("opened");
      expect((await s.unlock("nope", s.copyAt(s.original, [waiting]))).kind).toBe("wrong_password");
      // Stored after all (the server holds the waiting wrap): the new password opens it, as before.
      s.server.wrap = waiting;
      expect((await s.unlock(NEW_PW, s.copyAt(s.original, [waiting]))).kind).toBe("opened");
    }, 120_000);
  });

  describe("a sign-in pins the login's salt and cost to the first exchange's (the shared code's KnownKdf)", () => {
    it("the same wrapped key under another salt and cost: refused as the server's answer, nothing written, nothing more sent; the copy then opens with the right password", async () => {
      const s = await setup();
      const other = await s.rewrap(PW, { ...KDF, ops: 4 });
      const sent: string[] = [];
      const wire = signInWire(s, sent, { kdfSalt: s.original.kdfSalt, kdfParams: s.original.kdfParams }, { ...s.full, kdfSalt: other.kdfSalt, kdfParams: other.kdfParams });
      counted.derivations = [];
      const r = await signIn({ wire, pins: s.pins, origin: ORIGIN, email: "alice@example.com", password: PW, deviceName: "Firefox", session: null, knownIdentityPub: s.identity });
      // The server took the sign-in: its answer is refused as such (the caller ends the session it carried).
      expect(r).toEqual({ kind: "answer_refused", reason: "other_kdf" });
      expect(sent).toEqual(["prelogin", "login"]);
      expect(counted.derivations).toEqual([{ ops: 3, memBytes: KDF.memBytes }]);
      // Only the salt differs, or only the cost: each is refused.
      for (const keys of [{ ...s.full, kdfSalt: other.kdfSalt }, { ...s.full, kdfParams: { ...KDF, ops: 4 } }, { ...s.full, kdfParams: { ...KDF, memBytes: KDF.memBytes * 2 } }]) {
        const r2 = await signIn({ wire: signInWire(s, [], { kdfSalt: s.original.kdfSalt, kdfParams: s.original.kdfParams }, keys), pins: s.pins, origin: ORIGIN, email: "alice@example.com", password: PW, deviceName: "Firefox", session: null, knownIdentityPub: s.identity });
        expect(r2).toEqual({ kind: "answer_refused", reason: "other_kdf" });
      }
      // Nothing of the login's answer was handed on to be written, so the copy is as it was, and the next unlock with the
      // right password opens it.
      expect((await s.unlock(PW, s.copyAt(s.original))).kind).toBe("opened");
    }, 120_000);

    it("an honest sign-in: the login carries the first exchange's salt and cost, and opens as before", async () => {
      const s = await setup();
      const sent: string[] = [];
      const r = await signIn({ wire: signInWire(s, sent, { kdfSalt: s.original.kdfSalt, kdfParams: s.original.kdfParams }, s.full), pins: s.pins, origin: ORIGIN, email: "alice@example.com", password: PW, deviceName: "Firefox", session: null, knownIdentityPub: s.identity });
      expect(r.kind).toBe("opened");
      if (r.kind === "opened") {
        expect(r.wrap).toEqual(s.original);
        expect(wrapOf(r.session.accountKeys)).toEqual(s.original);
      }
      expect(sent).toEqual(["prelogin", "login"]);
    }, 120_000);
  });

  describe("a sign-in over a copy this browser holds for the same account compares before it writes", () => {
    const signInOver = (s: Awaited<ReturnType<typeof setup>>, password: string, served: SessionKeys, keys: AccountKeysV2, held: CopyAtUnlock | undefined, knownIdentityPub: Uint8Array | null = s.identity) => {
      counted.derivations = [];
      return signIn({ wire: signInWire(s, [], served, keys), pins: s.pins, origin: ORIGIN, email: "alice@example.com", password, deviceName: "Firefox", session: null, knownIdentityPub, ...(held ? { heldCopy: async () => held } : {}) });
    };

    it("the copy is at a new password and the server kept the older wrap; the older password is typed: the same account key, so it opens, and it says that the copy was sealed under another master password and now follows the server's", async () => {
      const s = await setup();
      const changed = await s.rewrap(NEW_PW); // this browser's change; the server kept the older wrap
      const r = await signInOver(s, PW, s.original, s.full, s.copyAt(changed));
      expect(r.kind).toBe("opened");
      if (r.kind !== "opened") throw new Error(r.kind);
      expect(r.copySealedElsewhere).toBe(true);
      // What the copy takes now: the older wrap, the one the server serves and the typed password opened.
      expect(r.wrap).toEqual(s.original);
      expect(r.opened.uvk).toEqual(s.uvk);
      // The sign-in's derivation, then the copy's own wrap tried with the typed password (it does not open).
      expect(counted.derivations).toEqual([{ ops: 3, memBytes: KDF.memBytes }, { ops: 3, memBytes: KDF.memBytes }]);
    }, 120_000);

    it("a server that serves another key for the same address: refused before anything is written, and nothing of the copy is derived", async () => {
      const s = await setup();
      const other = await anotherKeySet(s.userId, s.pins.pinFor(ORIGIN)!.instanceId, PW);
      // No identity record here (storage cleared, the copy kept): the sign-in's own checks pass on the other key set.
      expect((await signInOver(s, PW, other, other, undefined, null)).kind).toBe("opened");
      const r = await signInOver(s, PW, other, other, s.copyAt(s.original), null);
      expect(r).toEqual({ kind: "keys_not_this_account" });
      expect(counted.derivations).toEqual([{ ops: 3, memBytes: KDF.memBytes }]);
      // The same with a wrap pending beside the copy: the comparison is with the copy's sealed record, not a wrap.
      const pending = await s.rewrap(NEW_PW);
      expect(await signInOver(s, PW, other, other, s.copyAt(s.original, [pending]), null)).toEqual({ kind: "keys_not_this_account" });
    }, 120_000);

    it("the honest road: the password was changed on another device and the new one is typed: it opens, with the line", async () => {
      const s = await setup();
      const changed = await s.rewrap(NEW_PW);
      const keys = { ...s.full, ...changed };
      const r = await signInOver(s, NEW_PW, changed, keys, s.copyAt(s.original));
      expect(r.kind === "opened" && r.copySealedElsewhere).toBe(true);
      if (r.kind === "opened") expect(r.wrap).toEqual(changed);
    }, 120_000);

    it("no line when the copy knows the password: its own wrap, a pending one, or the same password at another salt and cost", async () => {
      const s = await setup();
      const own = await signInOver(s, PW, s.original, s.full, s.copyAt(s.original));
      expect(own.kind === "opened" && own.copySealedElsewhere).toBeUndefined();
      expect(counted.derivations.length).toBe(1); // the same wrap: nothing more derived
      const pending = await s.rewrap(NEW_PW);
      const p = await signInOver(s, NEW_PW, pending, { ...s.full, ...pending }, s.copyAt(s.original, [pending]));
      expect(p.kind === "opened" && p.copySealedElsewhere).toBeUndefined();
      const raised = await s.rewrap(PW, { ...KDF, ops: 4 }); // another device raised the cost, the same password
      const q = await signInOver(s, PW, raised, { ...s.full, ...raised }, s.copyAt(s.original));
      expect(q.kind === "opened" && q.copySealedElsewhere).toBeUndefined();
    }, 120_000);

    it("a sign-in with no copy, or a copy that cannot be read, is unchanged", async () => {
      const s = await setup();
      for (const held of [{ kind: "none" } as const, { kind: "unreadable" } as const, undefined]) {
        const r = await signInOver(s, PW, s.original, s.full, held);
        expect(r.kind).toBe("opened");
        if (r.kind === "opened") {
          expect(r.copySealedElsewhere).toBeUndefined();
          expect(r.wrap).toEqual(s.original);
        }
        expect(counted.derivations.length).toBe(1);
      }
    }, 120_000);
  });

  describe("the whole fence on every served cost, before anything is derived at it", () => {
    it("the matching wrap and a pending wrap at a cost outside the fence: kdf_refused, nothing derived", async () => {
      const s = await setup();
      const ragged = { ...s.original, kdfParams: RAGGED };
      s.server.wrap = ragged;
      expect(await s.unlock(PW, s.copyAt(ragged))).toEqual({ kind: "kdf_refused" });
      expect(counted.derivations).toEqual([]);
      expect(await s.unlock(PW, s.copyAt(await s.rewrap(NEW_PW), [ragged]))).toEqual({ kind: "kdf_refused" });
      expect(counted.derivations).toEqual([]);
    }, 120_000);

    it("the sign-in after the first exchange: a prelogin cost outside the fence derives nothing and sends no login", async () => {
      const s = await setup();
      for (const kdfParams of OUTSIDE) {
        const sent: string[] = [];
        const wire = {
          prelogin: async () => (sent.push("prelogin"), { kdfSalt: s.original.kdfSalt, kdfParams }),
          login: async () => {
            sent.push("login");
            throw new Error("never");
          },
        } as unknown as OnboardWire;
        counted.derivations = [];
        expect(await signIn({ wire, pins: s.pins, origin: ORIGIN, email: "alice@example.com", password: PW, deviceName: "Firefox", session: null, knownIdentityPub: s.identity }), JSON.stringify(kdfParams)).toEqual({ kind: "kdf_refused" });
        expect(counted.derivations).toEqual([]);
        expect(sent).toEqual(["prelogin"]);
      }
      // The wire's own fence refused it (api/wireclient.ts prelogin): the same, never a failure read as anything else.
      const wire = {
        prelogin: async () => {
          throw new KdfPolicyError("kdf_not_whole", RAGGED);
        },
      } as unknown as OnboardWire;
      counted.derivations = [];
      expect(await signIn({ wire, pins: s.pins, origin: ORIGIN, email: "alice@example.com", password: PW, deviceName: "Firefox", session: null, knownIdentityPub: s.identity })).toEqual({ kind: "kdf_refused" });
      expect(counted.derivations).toEqual([]);
    }, 120_000);

    it("the offline unlock from the copy: a copy kept at a cost outside the fence derives nothing", async () => {
      const s = await setup();
      counted.derivations = [];
      expect(await openFromCopy({ keys: { ...s.full, kdfParams: RAGGED }, pins: s.pins, origin: ORIGIN, userId: s.userId, password: PW, knownIdentityPub: s.identity })).toEqual({ kind: "kdf_refused" });
      expect(counted.derivations).toEqual([]);
    }, 120_000);
  });
});
