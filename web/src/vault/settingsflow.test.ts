import { beforeAll, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AccountDeletePreviewV2, AccountKeysV2, AccountRecoveryPut, AccountStateResponseV2, EscrowSelfPut, PasswordChangeRequestV2 } from "../api/wire";
import { adUvk } from "../crypto/ad";
import { ctEquals, fromB64, toB64 } from "../crypto/bytes";
import { open } from "../crypto/envelope";
import { masterKey, wrapKey } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { copyOf, copyOfAny } from "../crypto/escrow-v3.testkit";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical, NONE } from "../crypto/trust/grammar";
import { verifyCardChain } from "../crypto/trust/instancecard";
import { verifyVeto } from "../crypto/trust/recovery";
import { parseLogEntry, signLogEntryChecked, type VaultState, vkCommit } from "../crypto/trust/vaultlog";
import { vector } from "../crypto/trust/vectors";
import { openAccount, type OpenedAccount } from "./accountopen";
import { AccountStateStore } from "./accountdocstore";
import { PinStore } from "./pinstore";
import { readMirror } from "./recoverymirror";
import { buildRegistration, type Registration } from "./registration";
import { recordRecoveryChoice } from "./recoverymirror";
import { SessionWrap } from "./sessionwrap";
import {
  buildLeaves, changePassword, DELETE_TRIES, deleteAccount, escrowAtUnlock, FUTURE_LIMIT_MS, operatorOffer, PROOF_REFUSED, readEscrowSeen, reauth, refusalOf, type SettingsSession, type SettingsWire,
  setRecoveryPosture, vetoRecoveryRequest, writeEscrowSeen,
} from "./settingsflow";

/**
 * Settings on the post-cut-over routes (design §13): the one re-authentication path, the password change, the
 * recovery posture with its first consent, the veto, and the deletion's leaves. The journeys run the same flows
 * against the real server; these tests pin what must hold whatever a server answers.
 */
const rec = vector("recovery.json");
const KDF = { v: 1, alg: "argon2id13", ops: 3, memBytes: 67_108_864 };
const EMAIL = "alice@example.com";
const RECOVERY_SEEDS = ["recoveryA", "recoveryB", "recoveryC"].map((k) => rec.keys[k].seedB64 as string);
const PASSWORD = "correct horse battery";
const NOW = 1_763_164_800_000;
const framesOf = (chain: string): string[] => rec.cardChains[chain].frames as string[];
/** The origin the vector's cards name; read from card 0 once sodium is up. */
let ORIGIN = "";

class FakeWire implements SettingsWire {
  calls: string[] = [];
  keys!: AccountKeysV2;
  cards: string[] = framesOf("rotated-once");
  rotations: string[] = [rec.rotationFrames["A-to-B"]];
  pubkey: string = rec.keys.recoveryB.publicKeyB64;
  password: PasswordChangeRequestV2 | null = null;
  recovery: AccountRecoveryPut | null = null;
  preview: AccountDeletePreviewV2 = { blockers: [], deletedVaults: [], leftVaults: [], memberships: [], totpRequired: false };
  deleteAnswer: () => number = () => 5;
  deleted: { leaves: string[]; confirmEmail: string; totp?: string } | null = null;
  veto: { requestId: string; statement: string } | null = null;
  stateSeq = 0;
  sealedState: string | null = null;
  fail: Partial<Record<string, ApiError>> = {};
  private hit(name: string): void {
    this.calls.push(name);
    const e = this.fail[name];
    if (e) throw e;
  }
  async accountKeys() {
    this.hit("accountKeys");
    return this.keys;
  }
  async changePassword(req: PasswordChangeRequestV2) {
    this.hit("changePassword");
    this.password = req;
  }
  async devices() {
    return [];
  }
  async revokeDevice() {
    this.hit("revokeDevice");
  }
  async setRequireLink() {
    this.hit("setRequireLink");
  }
  async totpDisable() {
    this.hit("totpDisable");
  }
  async totpSetup(): Promise<never> {
    this.hit("totpSetup");
    throw new Error("not in these tests");
  }
  async instance() {
    this.hit("instance");
    return { cards: this.cards, rotations: this.rotations };
  }
  async recoveryPubkey() {
    this.hit("recoveryPubkey");
    return this.pubkey;
  }
  async putRecovery(req: AccountRecoveryPut): Promise<AccountStateResponseV2> {
    this.hit("putRecovery");
    this.recovery = req;
    this.sealedState = req.accountState.sealedState;
    return { sealedState: this.sealedState, seq: ++this.stateSeq };
  }
  async recoveryRequests() {
    return [];
  }
  async vetoRecoveryRequest(requestId: string, statement: string) {
    this.hit("veto");
    this.veto = { requestId, statement };
  }
  async deletePreview() {
    this.hit("deletePreview");
    return this.preview;
  }
  async deleteAccountWithLeaves(req: { leaves: string[]; confirmEmail: string; totp?: string }) {
    this.hit("deleteAccountWithLeaves");
    this.deleted = req;
    return this.deleteAnswer();
  }
  async recoverySelfSetup() {
    this.hit("recoverySelfSetup");
    return "piece";
  }
  async recoverySelfConfirm() {}
  escrowSelf: EscrowSelfPut | null = null;
  async putEscrowSelf(req: EscrowSelfPut) {
    this.hit("putEscrowSelf");
    this.escrowSelf = req;
  }
  async accountState(): Promise<AccountStateResponseV2> {
    return { sealedState: this.sealedState, seq: this.stateSeq };
  }
  async putAccountState(sealedState: string): Promise<AccountStateResponseV2> {
    this.sealedState = sealedState;
    return { sealedState, seq: ++this.stateSeq };
  }
}

async function setup(chain = "rotated-once") {
  const wire = new FakeWire();
  wire.cards = framesOf(chain);
  const storage = memoryStorage();
  const pins = new PinStore(storage, async () => ({ cards: wire.cards, rotations: wire.rotations }), null);
  const g = await pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
  pins.confirmTrustGate(g.ticket);
  const pin = pins.pinFor(ORIGIN)!;
  const reg: Registration = await buildRegistration({
    email: EMAIL, displayName: "Alice", password: PASSWORD, kdfParams: KDF, signupTicket: "t", pin, ageConfirmed: true,
    device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: NOW,
  });
  const r = reg.request;
  wire.keys = { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub, recoveryConfirmed: true, personalWrap: r.personalWrap, genesis: r.genesis };
  const o = openAccount(reg.userId, reg.uvk.slice(), wire.keys, pin.instanceId, null);
  if (o.kind !== "opened") throw new Error(o.reason);
  const opened: OpenedAccount = o.account;
  // The wrap the session keeps: the one sign-up sealed (spec 01 §7).
  const s: SettingsSession = { wire, pins, origin: ORIGIN, account: EMAIL, opened, wrap: new SessionWrap({ kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk }) };
  return { wire, storage, pins, pin, reg, opened, s };
}

describe("settings flows", () => {
  beforeAll(async () => {
    await initSodium();
    ORIGIN = verifyCardChain(framesOf("rotated-once").map((f) => fromB64Canonical(f)!)).cards[0]!.fields.origin;
  });

  it("re-authenticates only with a password that opens this session's own wrap to its UVK, and dials nothing for it", async () => {
    const { wire, reg, s, storage } = await setup();
    expect(await reauth(s, "not the password")).toEqual({ kind: "wrong_password" });
    expect(wire.calls).toEqual([]);
    const ok = await reauth(s, PASSWORD);
    expect(ok).toMatchObject({ kind: "key", currentAuthKey: reg.request.authKey });
    // A kept wrap that the password opens, but to another UVK: not this account as this session unlocked it.
    const other = await buildRegistration({ email: EMAIL, displayName: "A", password: PASSWORD, kdfParams: KDF, signupTicket: "t", pin: s.pins.pinFor(ORIGIN)!, ageConfirmed: true, device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: NOW });
    const foreign = { ...s, wrap: new SessionWrap({ kdfSalt: other.request.kdfSalt, kdfParams: KDF, wrappedUvk: toB64(fromB64(other.request.wrappedUvk)) }) };
    expect((await reauth(foreign, PASSWORD)).kind).not.toBe("key");
    // A server that answers the account's keys with another account's salt and wrap changes nothing: they are not read.
    wire.keys = { ...wire.keys, kdfSalt: other.request.kdfSalt, wrappedUvk: other.request.wrappedUvk };
    expect(await reauth(s, PASSWORD)).toMatchObject({ kind: "key", currentAuthKey: reg.request.authKey });
    expect(wire.calls).toEqual([]);
    // A blocked origin: the rule refuses before anything is fetched or derived.
    storage.set("andvari.pin2." + ORIGIN, "{not json");
    wire.calls = [];
    expect(await reauth(s, PASSWORD)).toEqual({ kind: "password_rule", decision: "refuse_entry" });
    expect(wire.calls).toEqual([]);
  }, 120_000);

  it("KDF parameters outside the client's fence are a typed refusal before anything derives under them or is sent", async () => {
    const { wire, s } = await setup();
    const weak = { ...KDF, memBytes: 8192 };
    // A kept cost under the floor: the re-authentication stops at the fence.
    const kept = s.wrap.current!;
    wire.calls = [];
    expect(await reauth({ ...s, wrap: new SessionWrap({ ...kept, kdfParams: weak }) }, PASSWORD)).toEqual({ kind: "refused", code: "kdf_below_floor" });
    expect(wire.calls).toEqual([]);
    // A weak policy for the NEW password is no upgrade: the new password keeps the account's present cost.
    const r = await changePassword(s, PASSWORD, "a brand new Password 1", weak);
    expect(r.kind).toBe("done");
    expect(wire.password!.newKdfParams).toEqual(KDF);
    expect(wire.calls).toEqual(["changePassword"]);
  }, 120_000);

  it("a password change sends the current proof and the same UVK under the new password's key", async () => {
    const { wire, reg, s, opened } = await setup();
    expect((await changePassword(s, "wrong", "a brand new Password 1", KDF)).kind).toBe("wrong_password");
    expect(wire.password).toBeNull();
    const r = await changePassword(s, PASSWORD, "a brand new Password 1", KDF);
    expect(r.kind).toBe("done");
    if (r.kind !== "done") return;
    expect(wire.password!.currentAuthKey).toBe(reg.request.authKey);
    expect(wire.password!.newAuthKey).not.toBe(reg.request.authKey);
    expect(wire.password!.newWrappedUvk).toBe(r.value.keys.wrappedUvk);
    const mk = masterKey("a brand new Password 1", fromB64(r.value.keys.kdfSalt), KDF);
    expect(ctEquals(open(await wrapKey(mk), fromB64(r.value.keys.wrappedUvk), adUvk(reg.userId)), opened.uvk)).toBe(true);
  }, 120_000);

  it("maps a refusal without guessing whether a change landed", () => {
    // A proof is made here first: the server's refusal of it is its own result, never a wrong password (spec 01 §7).
    expect(refusalOf(new ApiError(403, "reauth_failed", "x"))).toEqual({ kind: "refused", code: PROOF_REFUSED });
    expect(refusalOf(new ApiError(401, "credential_changed", "x"))).toEqual({ kind: "session_ended" });
    expect(refusalOf(new ApiError(400, "kdf_too_weak", "x"))).toEqual({ kind: "refused", code: "kdf_too_weak" });
    expect(refusalOf(new ApiError(503, "http_503", "x")).kind).toBe("unknown");
    expect(refusalOf(new ApiError(0, "bad_response", "x")).kind).toBe("unknown");
    expect(refusalOf(new TypeError("fetch failed")).kind).toBe("unknown");
  });

  it("offers operator recovery only from the pinned private card, with the first-consent walk and the served key at full length", async () => {
    const { wire, s } = await setup();
    const clean = await operatorOffer(s);
    expect(clean).toMatchObject({ kind: "offer", offer: { fp: rec.keys.recoveryB.fingerprint, origin: ORIGIN, unsignedChanges: [] } });
    // The same chain without the rotation: the change at card 2 is unsigned, which the offer carries for the warning.
    wire.rotations = [];
    const warn = await operatorOffer(s);
    expect(warn.kind === "offer" && warn.offer.unsignedChanges).toEqual([{ seq: 2, fromFp: rec.keys.recoveryA.fingerprint, toFp: rec.keys.recoveryB.fingerprint }]);
    // A served key that does not hash to the card's recoveryFp is no offer.
    wire.pubkey = rec.keys.recoveryA.publicKeyB64;
    expect(await operatorOffer(s)).toEqual({ kind: "unavailable", reason: "recovery_key_mismatch" });
    // A served chain that is not the pin's own (another chain's card 0) is no offer.
    wire.pubkey = rec.keys.recoveryB.publicKeyB64;
    const pinned = wire.cards;
    const original = wire.instance.bind(wire);
    wire.instance = async () => ({ ...(await original()), cards: framesOf("turned-on-later") });
    expect(await operatorOffer(s)).toEqual({ kind: "unavailable", reason: "card_unverified" });
    wire.instance = original;
    wire.cards = pinned;
    expect((await operatorOffer(s)).kind).toBe("offer");
  }, 120_000);

  it("turns operator recovery on only after the box and an explicit answer to an unsigned change; the record and the mirror follow", async () => {
    const { wire, s, storage, opened } = await setup();
    wire.rotations = [];
    const o = await operatorOffer(s);
    if (o.kind !== "offer") throw new Error(o.reason);
    const state = new AccountStateStore(opened.userId, opened.uvk, wire, storage);
    wire.calls = [];
    expect(await setRecoveryPosture(s, state, storage, { posture: "operator", offer: o.offer, understood: false, keepDespiteUnsignedChange: true }, PASSWORD, NOW)).toEqual({ kind: "refused", code: "consent_required" });
    expect(await setRecoveryPosture(s, state, storage, { posture: "operator", offer: o.offer, understood: true, keepDespiteUnsignedChange: false }, PASSWORD, NOW)).toEqual({ kind: "refused", code: "unsigned_change" });
    expect(await setRecoveryPosture(s, state, storage, { posture: "operator", offer: { ...o.offer, pinHash: "0".repeat(64) }, understood: true, keepDespiteUnsignedChange: true }, PASSWORD, NOW)).toEqual({ kind: "refused", code: "stale_offer" });
    // None of those touched the network or the password.
    expect(wire.calls).toEqual([]);
    const on = await setRecoveryPosture(s, state, storage, { posture: "operator", offer: o.offer, understood: true, keepDespiteUnsignedChange: true }, PASSWORD, NOW);
    expect(on).toMatchObject({ kind: "done", value: { posture: "operator", fp: o.offer.fp, at: NOW } });
    expect(wire.recovery).toMatchObject({ posture: "operator", escrow: { fingerprint: o.offer.fp } });
    // Spec 04 §3: turning operator recovery on seals the version-3 copy, naming the session's address.
    expect(copyOfAny((wire.recovery as { escrow: { sealed: string } }).escrow.sealed, RECOVERY_SEEDS)).toEqual({ v: 3, email: EMAIL });
    expect(wire.recovery!.accountState.baseSeq).toBe(0);
    expect(readMirror(storage, opened.userId)).toEqual({ posture: "operator", fp: o.offer.fp, at: NOW });
    // Off again, on a browser whose clock is behind: the record is stamped past the one it replaces, with no escrow.
    const off = await setRecoveryPosture(s, state, storage, { posture: "private" }, PASSWORD, NOW - 5000);
    expect(off).toMatchObject({ kind: "done", value: { posture: "private", fp: NONE, at: NOW + 1 } });
    expect(wire.recovery!.escrow).toBeUndefined();
    expect(state.local().recovery).toMatchObject({ posture: "private", at: NOW + 1 });
    // A wrong password is caught here and sends nothing.
    wire.calls = [];
    expect((await setRecoveryPosture(s, state, storage, { posture: "private" }, "wrong", NOW)).kind).toBe("wrong_password");
    expect(wire.calls).toEqual([]);
  }, 180_000);

  it("a public card never offers operator recovery, whatever it names (variant R)", async () => {
    const { s, storage, pin } = await setup();
    storage.set("andvari.pin2." + ORIGIN, JSON.stringify({ ...pin, kind: "public" }));
    expect(await operatorOffer(s)).toEqual({ kind: "unavailable", reason: "not_offered" });
  }, 120_000);

  it("the veto is a statement of this account for that request, signed with its key", async () => {
    const { wire, s, opened } = await setup();
    const requestId = toB64(randomBytes(16));
    expect(await vetoRecoveryRequest(s, requestId, NOW)).toEqual({ kind: "vetoed" });
    const v = verifyVeto(fromB64(wire.veto!.statement), opened.identity.publicKey, opened.userId, requestId);
    expect(v.ok && v.value).toMatchObject({ requestId, userId: opened.userId, issuedAt: NOW });
    expect(await vetoRecoveryRequest(s, "not an id", NOW)).toEqual({ kind: "refused", code: "bad_request_id" });
    wire.fail.veto = new ApiError(404, "request_unknown", "x");
    expect(await vetoRecoveryRequest(s, requestId, NOW)).toEqual({ kind: "refused", code: "request_unknown" });
  }, 120_000);

  it("places a leave from this browser's own verified head, and holds an unverified head to one day ahead", async () => {
    const { opened } = await setup();
    const vaultId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const g = signLogEntryChecked(opened.signing, null, { kind: "genesis", vaultId, seq: 0, prev: "0".repeat(64), actor: opened.userId, at: NOW - 1000, ownerKey: toB64(opened.identity.publicKey), vkCommit: await vkCommit(randomBytes(32), vaultId) });
    if (!g.ok) throw new Error(g.verdict);
    const state: VaultState = g.value.step.state;
    const verified = (id: string) => (id === vaultId ? state : null);
    const far = NOW + 400 * 24 * 60 * 60 * 1000;
    // The served `at` beside a head this browser verified is never signed after: its own state places the leave.
    const leaves = buildLeaves(opened.userId, opened.signing, [{ vaultId, head: { seq: 0, hash: state.head.hash, at: far } }, { vaultId: other, head: { seq: 4, hash: "c".repeat(64), at: NOW + 5000 } }], verified, NOW);
    const [mine, theirs] = leaves!.map((f) => parseLogEntry(fromB64(f)));
    expect(mine!.ok && mine!.value.entry).toMatchObject({ kind: "leave", vaultId, seq: 1, prev: state.head.hash, actor: opened.userId, at: NOW });
    expect(theirs!.ok && theirs!.value.entry).toMatchObject({ kind: "leave", vaultId: other, seq: 5, prev: "c".repeat(64), at: NOW + 5000 });
    // An unverified head more than a day ahead: nothing is signed for any vault.
    expect(buildLeaves(opened.userId, opened.signing, [{ vaultId, head: { seq: 0, hash: state.head.hash, at: far } }, { vaultId: other, head: { seq: 4, hash: "c".repeat(64), at: NOW + FUTURE_LIMIT_MS + 1 } }], verified, NOW)).toBeNull();
    // The same vault at another served head is not this browser's verified head: the bound applies to it too.
    expect(buildLeaves(opened.userId, opened.signing, [{ vaultId, head: { seq: 1, hash: "d".repeat(64), at: far } }], verified, NOW)).toBeNull();
  }, 120_000);

  it("deletes only after every check that needs no secret, and never reports an unclear answer as an outcome", async () => {
    const { wire, s } = await setup();
    const none = () => null;
    expect(await deleteAccount(s, { typedEmail: "bob@example.com", password: PASSWORD, verifiedState: none, nowMs: NOW })).toEqual({ kind: "email_mismatch" });
    expect(wire.calls).toEqual([]);
    wire.preview = { ...wire.preview, blockers: [{ kind: "shared_vault", vaultId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", others: 2 }] };
    expect((await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).kind).toBe("blocked");
    wire.preview = { ...wire.preview, blockers: [], totpRequired: true };
    expect(await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).toEqual({ kind: "totp_needed" });
    wire.preview = { ...wire.preview, totpRequired: false, memberships: [{ vaultId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", head: { seq: 2, hash: "e".repeat(64), at: NOW + 2 * FUTURE_LIMIT_MS } }] };
    expect(await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).toEqual({ kind: "future_head" });
    // Nothing above reached the password or the delete route.
    expect(wire.calls.filter((c) => c !== "deletePreview")).toEqual([]);
    wire.preview = { ...wire.preview, memberships: [{ vaultId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", head: { seq: 2, hash: "e".repeat(64), at: NOW } }] };
    const stale = new ApiError(409, "account_delete_log_stale", "x");
    stale.extras = { kind: "account_delete_log_stale", vaultIds: ["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"] };
    wire.fail.deleteAccountWithLeaves = stale;
    expect(await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).toEqual({ kind: "log_stale", vaultIds: ["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"] });
    wire.fail.deleteAccountWithLeaves = new ApiError(502, "http_502", "x");
    expect((await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).kind).toBe("unknown");
    wire.fail.deleteAccountWithLeaves = new ApiError(400, "at_ahead", "x");
    expect(await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).toEqual({ kind: "clock_ahead" });
    delete wire.fail.deleteAccountWithLeaves;
    expect(await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).toEqual({ kind: "deleted", deletedAt: 5 });
    expect(wire.deleted!.leaves).toHaveLength(1);
    expect(wire.deleted!.confirmEmail).toBe(EMAIL);

    // The memberships' logs are refreshed before the leaves are placed (the verified state is read after it), and a
    // refresh that fails still lets the deletion go on from the served heads.
    const order: string[] = [];
    const refreshLogs = async (ms: readonly { vaultId: string }[]) => {
      order.push(`refresh:${ms.map((m) => m.vaultId).join(",")}`);
    };
    const traced = (id: string) => {
      order.push(`state:${id}`);
      return null;
    };
    expect((await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: traced, nowMs: NOW, refreshLogs })).kind).toBe("deleted");
    expect(order).toEqual(["refresh:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "state:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]);
    const failing = async () => {
      throw new Error("offline");
    };
    expect((await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW, refreshLogs: failing })).kind).toBe("deleted");
  }, 240_000);

  it("a stale leave is answered by reading the heads again and retrying; the refusal is said only once every try met a vault that moved on", async () => {
    const { wire, s } = await setup();
    const none = () => null;
    const vaultId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const stale = () => {
      const e = new ApiError(409, "account_delete_log_stale", "x");
      e.extras = { kind: "account_delete_log_stale", vaultIds: [vaultId] };
      return e;
    };
    // The vault's log moves on once between the preview and the deletion: the second try reads the new head and goes through.
    let seq = 2;
    wire.deletePreview = async () => {
      wire.calls.push("deletePreview");
      return { ...wire.preview, memberships: [{ vaultId, head: { seq, hash: (seq === 2 ? "e" : "f").repeat(64), at: NOW } }] };
    };
    const sent: string[][] = [];
    wire.deleteAccountWithLeaves = async (req) => {
      wire.calls.push("deleteAccountWithLeaves");
      sent.push(req.leaves);
      if (sent.length === 1) {
        seq = 3;
        throw stale();
      }
      return 5;
    };
    wire.calls = [];
    expect(await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).toEqual({ kind: "deleted", deletedAt: 5 });
    expect(wire.calls).toEqual(["deletePreview", "deleteAccountWithLeaves", "deletePreview", "deleteAccountWithLeaves"]);
    const placed = sent.map((ls) => parseLogEntry(fromB64(ls[0]!)));
    expect(placed.map((p) => p.ok && p.value.entry.seq)).toEqual([3, 4]);
    expect(placed.map((p) => p.ok && p.value.entry.prev)).toEqual(["e".repeat(64), "f".repeat(64)]);

    // A vault that keeps moving: every try is refused, and only then is the refusal handed to the screen.
    wire.deleteAccountWithLeaves = async (req) => {
      wire.calls.push("deleteAccountWithLeaves");
      sent.push(req.leaves);
      throw stale();
    };
    wire.calls = [];
    expect(await deleteAccount(s, { typedEmail: EMAIL, password: PASSWORD, verifiedState: none, nowMs: NOW })).toEqual({ kind: "log_stale", vaultIds: [vaultId] });
    expect(wire.calls.filter((c) => c === "deleteAccountWithLeaves")).toHaveLength(DELETE_TRIES);
    expect(wire.calls.filter((c) => c === "deletePreview")).toHaveLength(DELETE_TRIES);
    expect(DELETE_TRIES).toBeGreaterThan(1);
  }, 240_000);

  /** An account whose consent names key A, while the pinned card (rotated-once) names key B. */
  async function consentedToA(opts: { mirror: boolean; seen: string | null }) {
    const t = await setup();
    const state = new AccountStateStore(t.opened.userId, t.opened.uvk, t.wire, t.storage);
    const A = rec.keys.recoveryA.fingerprint;
    expect((await recordRecoveryChoice(state, t.storage, t.opened.userId, { posture: "operator", fp: A }, NOW)).kind).toBe("written");
    if (!opts.mirror) t.storage.remove(`andvari.recmirror.${t.opened.userId}`);
    writeEscrowSeen(t.storage, t.opened.userId, opts.seen);
    t.wire.calls = [];
    return { ...t, state, A, B: rec.keys.recoveryB.fingerprint };
  }

  it("§4.5 at unlock: with its own mirror, a signed rotation re-seals unasked through PUT /escrow/self, and the consent follows", async () => {
    const { wire, s, state, storage, opened, A, B } = await consentedToA({ mirror: true, seen: rec.keys.recoveryA.fingerprint });
    expect(await escrowAtUnlock(s, state, storage, NOW + 10)).toEqual({ kind: "settled", resealed: true });
    expect(wire.escrowSelf).toMatchObject({ fingerprint: B, rotations: [rec.rotationFrames["A-to-B"]] });
    // The re-seal after a rotation is version 3 too (spec 04 §3), under key B.
    expect(copyOf(wire.escrowSelf!.sealed, boxKeypairFromSeed(fromB64(rec.keys.recoveryB.seedB64)))).toEqual({ v: 3, email: EMAIL });
    expect(wire.calls).not.toContain("putRecovery");
    expect(readEscrowSeen(storage, opened.userId)).toBe(B);
    expect(readMirror(storage, opened.userId)).toMatchObject({ posture: "operator", fp: B });
    expect((await state.read()).document.recovery).toMatchObject({ posture: "operator", fp: B });
    expect(A).not.toBe(B);
    // The next unlock has nothing left to do.
    wire.escrowSelf = null;
    expect(await escrowAtUnlock(s, state, storage, NOW + 20)).toEqual({ kind: "settled", resealed: false });
    expect(wire.escrowSelf).toBeNull();
  }, 120_000);

  it("spec 04 §3: a session whose address is not already an emailNorm seals nothing, at the re-seal or when turning operator recovery on", async () => {
    const t = await consentedToA({ mirror: true, seen: rec.keys.recoveryA.fingerprint });
    const odd = { ...t.s, account: "Alice@Example.com" };
    expect(await escrowAtUnlock(odd, t.state, t.storage, NOW + 10)).toEqual({ kind: "unavailable", reason: "operator_recovery_unavailable" });
    expect(t.wire.calls).not.toContain("putEscrowSelf");
    t.wire.rotations = [];
    const o = await operatorOffer(odd);
    if (o.kind !== "offer") throw new Error(o.reason);
    t.wire.calls = [];
    expect(await setRecoveryPosture(odd, t.state, t.storage, { posture: "operator", offer: o.offer, understood: true, keepDespiteUnsignedChange: true }, PASSWORD, NOW)).toEqual({ kind: "refused", code: "operator_recovery_unavailable" });
    expect(t.wire.calls).not.toContain("putRecovery");
  }, 120_000);

  it("§4.5 at unlock: without its own mirror, or without a seen escrow to chain from, it asks and seals nothing", async () => {
    for (const opts of [{ mirror: false, seen: rec.keys.recoveryA.fingerprint }, { mirror: true, seen: null }]) {
      const { wire, s, state, storage } = await consentedToA(opts);
      const r = await escrowAtUnlock(s, state, storage, NOW + 10);
      expect(r).toMatchObject({ kind: "ask", decision: { kind: "ask", origin: ORIGIN } });
      expect(wire.calls).not.toContain("putEscrowSelf");
      expect(wire.calls).not.toContain("putRecovery");
    }
  }, 240_000);

  it("§4.5 at unlock: a key change no rotation covers is the unsigned-change warning, and a private record does nothing", async () => {
    const { wire, s, state, storage, opened, A, B } = await consentedToA({ mirror: true, seen: rec.keys.recoveryA.fingerprint });
    wire.rotations = [];
    expect(await escrowAtUnlock(s, state, storage, NOW + 10)).toMatchObject({ kind: "ask", decision: { kind: "unsigned_change", fromFp: A, toFp: B } });
    expect(wire.calls).not.toContain("putEscrowSelf");
    await recordRecoveryChoice(state, storage, opened.userId, { posture: "private", fp: NONE }, NOW + 20);
    wire.calls = [];
    expect(await escrowAtUnlock(s, state, storage, NOW + 30)).toEqual({ kind: "settled", resealed: false });
    expect(wire.calls).toEqual([]);
  }, 120_000);
});
