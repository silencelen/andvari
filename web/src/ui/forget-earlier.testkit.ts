import { ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AccountKeysV2, NewDevice, RecoveryCommitRequestV2, RegisterRequestV2, SessionResponseV2, SignupStartRequest } from "../api/wire";
import { fromB64 } from "../crypto/bytes";
import { vector } from "../crypto/trust/vectors";
import type { KitRecoveryWire } from "../vault/kitflow";
import type { OnboardWire } from "../vault/onboardflow";
import { PinStore } from "../vault/pinstore";
import { buildRegistration } from "../vault/registration";
import { useTabLocks, webLockRegistry } from "./weblocks.testkit";

/**
 * Test kit for "Forget the earlier account on this device" (decided on 2026-11-17): a server that keeps one account per
 * address (a deletion and a new registration under the same address replace it, as on the real server), a pinned origin,
 * and the browser's two storages as plain maps.
 */
const cards = vector("instancecard.json");
const base: string[] = cards.chains.find((c: { name: string }) => c.name === "base").cards.map((c: { frameB64: string }) => c.frameB64);
export const ORIGIN = "https://vault.example.org";
export const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };

export class RemakeServer implements OnboardWire, KitRecoveryWire {
  readonly accounts = new Map<string, { req: RegisterRequestV2; piece: { recoveryWrappedUvk: string; recoveryAuthKey: string } }>();
  sent: string[] = [];
  private current: string | null = null;
  newDevice(name: string): NewDevice {
    return { platform: "web", name, deviceSecret: "A".repeat(43) };
  }
  private keys(req: RegisterRequestV2): AccountKeysV2 {
    return { kdfSalt: req.kdfSalt, kdfParams: req.kdfParams, wrappedUvk: req.wrappedUvk, encryptedIdentitySeed: req.encryptedIdentitySeed, identityPub: req.identityPub, recoveryConfirmed: true, personalWrap: req.personalWrap, genesis: req.genesis };
  }
  private session(req: RegisterRequestV2): SessionResponseV2 {
    this.current = req.email;
    return { userId: req.userId, deviceId: "d0000000-0000-4000-8000-000000000001", accessToken: "a", refreshToken: "r", accountKeys: this.keys(req), role: "member", totpEnrolled: false, mustEnrollTotp: false, recoveryPieceId: "piece" };
  }
  private of(email: string) {
    const a = this.accounts.get(email.trim().toLowerCase());
    if (!a) throw new ApiError(401, "invalid_credentials", "x");
    return a;
  }
  async prelogin(email: string) {
    this.sent.push("prelogin");
    const a = this.of(email);
    return { kdfSalt: a.req.kdfSalt, kdfParams: a.req.kdfParams };
  }
  async login(email: string, authKey: string) {
    this.sent.push("login");
    const a = this.of(email);
    if (authKey !== a.req.authKey) throw new ApiError(401, "invalid_credentials", "x");
    return this.session(a.req);
  }
  async signupStart(req: SignupStartRequest) {
    this.sent.push("signup/start");
    void req;
  }
  async signupVerify() {
    return { signupTicket: "ticket", expiresAt: 1 };
  }
  async register(req: RegisterRequestV2) {
    this.sent.push("register");
    this.accounts.set(req.email.trim().toLowerCase(), { req, piece: req.memberRecovery });
    return this.session(req);
  }
  async accountKeys() {
    this.sent.push("account/keys");
    if (this.current === null) throw new ApiError(401, "unauthorized", "x");
    return this.keys(this.of(this.current).req);
  }
  async recoverySelfVerify(email: string, recoveryAuthKey: string) {
    this.sent.push("verify");
    const a = this.of(email);
    if (recoveryAuthKey !== a.piece.recoveryAuthKey) throw new ApiError(401, "invalid_credentials", "x");
    return { recoveryTicket: "ticket", userId: a.req.userId, recoveryWrappedUvk: a.piece.recoveryWrappedUvk, encryptedIdentitySeed: a.req.encryptedIdentitySeed, identityPub: a.req.identityPub };
  }
  async recoverySelfCommit(email: string, req: RecoveryCommitRequestV2): Promise<SessionResponseV2> {
    this.sent.push("commit");
    const a = this.of(email);
    a.piece = req.newMemberRecovery;
    a.req = { ...a.req, kdfSalt: req.newKdfSalt, kdfParams: req.newKdfParams, wrappedUvk: req.newWrappedUvk };
    return this.session(a.req);
  }
  /** The account under [email] is deleted at the server and a new one is made under the same address, with [password]. */
  async remake(pins: PinStore, email: string, password: string) {
    const reg = await buildRegistration({ email, displayName: "Again", password, kdfParams: KDF, signupTicket: "t", pin: pins.pinFor(ORIGIN)!, ageConfirmed: true, device: this.newDevice("x"), nowMs: 1763164800000 });
    this.accounts.set(email.trim().toLowerCase(), { req: reg.request, piece: reg.request.memberRecovery });
    return { ...reg, identityPub: fromB64(reg.request.identityPub) };
  }
}

export async function pinnedStore(): Promise<PinStore> {
  const pins = new PinStore(memoryStorage(), async () => ({ cards: base.slice(0, 2), rotations: [] }), null);
  const g = await pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error("gate");
  pins.confirmTrustGate(g.ticket);
  return pins;
}

/** A Storage over a Map, with every key listable (the shape the browser's own stores have). */
export function mapStorage(): Storage & { readonly map: Map<string, string> } {
  const map = new Map<string, string>();
  return {
    map,
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (k: string) => map.get(k) ?? null,
    key: (i: number) => [...map.keys()][i] ?? null,
    removeItem: (k: string) => void map.delete(k),
    setItem: (k: string, v: string) => void map.set(k, String(v)),
  } as Storage & { readonly map: Map<string, string> };
}

/**
 * Puts map-backed localStorage and sessionStorage in place, and this tab's Web Locks (of one browser, [locks], whose
 * other tabs a test can take with `locks.tab()`); returns the two maps, the locks and the way back.
 */
export function browserStorages(): {
  local: Storage & { readonly map: Map<string, string> };
  tab: Storage & { readonly map: Map<string, string> };
  locks: ReturnType<typeof webLockRegistry>;
  restore: () => void;
} {
  const g = globalThis as Record<string, unknown>;
  const had = { local: Object.getOwnPropertyDescriptor(g, "localStorage"), tab: Object.getOwnPropertyDescriptor(g, "sessionStorage") };
  const local = mapStorage();
  const tab = mapStorage();
  Object.defineProperty(g, "localStorage", { value: local, configurable: true });
  Object.defineProperty(g, "sessionStorage", { value: tab, configurable: true });
  const locks = webLockRegistry();
  const unlock = useTabLocks(locks.tab());
  return {
    local,
    tab,
    locks,
    restore: () => {
      unlock();
      if (had.local) Object.defineProperty(g, "localStorage", had.local);
      else delete g.localStorage;
      if (had.tab) Object.defineProperty(g, "sessionStorage", had.tab);
      else delete g.sessionStorage;
    },
  };
}
