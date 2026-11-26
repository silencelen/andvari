import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { ApiError } from "../api/client";
import { memoryStorage } from "../api/devicesecret";
import type { AccountKeysV2, PasswordChangeRequestV2 } from "../api/wire";
import { adUvk } from "../crypto/ad";
import { fromB64, toB64 } from "../crypto/bytes";
import { open } from "../crypto/envelope";
import { assertServerKdfParams, authKey, type KdfParams, masterKey, wrapKey } from "../crypto/keys";
import { initSodium } from "../crypto/sodium";
import { fromB64Canonical } from "../crypto/trust/grammar";
import { verifyCardChain } from "../crypto/trust/instancecard";
import { vector } from "../crypto/trust/vectors";
import { openAccount, type OpenedAccount } from "./accountopen";
import { passesReKeyFence, shouldUpgrade } from "./kdfupgrade";
import { PinStore } from "./pinstore";
import { quietReKey, type QuietReKeyInputs } from "./rekey";
import { buildRegistration } from "./registration";
import { type SessionKeys, SessionWrap } from "./sessionwrap";
import type { CopyKeeper, CopyWrite, SettingsSession, SettingsWire } from "./settingsflow";

/**
 * Spec 01 §7, "KDF upgrade (F61, normative)": `shouldUpgrade` is a verbatim replica of core `KdfUpgrade.shouldUpgrade`
 * (the never-sideways/down/absurd decision); `quietReKey` (vault/rekey.ts) is the web's quiet re-key after a
 * full-password unlock that reached the server, through the one password change of the web (settingsflow).
 */

const p = (memBytes: number, ops: number, v = 1): KdfParams => ({ v, alg: "argon2id13", ops, memBytes });

// core KdfUpgrade fence numbers, mirrored (⇔ crypto/keys.ts KDF_MIN_/MAX_*).
const FLOOR = p(67_108_864, 3); // 64 MiB / t=3 — the at-floor DEFAULT policy.
const BELOW_FLOOR = p(33_554_432, 2); // 32 MiB / t=2 — a legacy account under the raised floor.
const RAISED = p(134_217_728, 4); // 128 MiB / t=4.
const OPS_UP = p(67_108_864, 4); // the cheapest upgrade of the floor, for the re-key tests below.

describe("shouldUpgrade — verbatim mirror of core KdfUpgrade.shouldUpgrade", () => {
  it("FIRES when the account is below the policy on BOTH axes (the raised-floor upgrade)", () => {
    expect(shouldUpgrade(BELOW_FLOOR, FLOOR)).toBe(true);
    expect(shouldUpgrade(FLOOR, RAISED)).toBe(true);
  });

  it("FIRES when strictly greater on only ONE axis (memBytes up, ops equal — and vice versa)", () => {
    expect(shouldUpgrade(p(67_108_864, 3), p(134_217_728, 3))).toBe(true); // mem up
    expect(shouldUpgrade(p(67_108_864, 3), p(67_108_864, 4))).toBe(true); // ops up
  });

  it("does NOT fire when the params are ALREADY CURRENT (equal is a no-op, not an upgrade)", () => {
    expect(shouldUpgrade(FLOOR, FLOOR)).toBe(false);
    expect(shouldUpgrade(RAISED, RAISED)).toBe(false);
  });

  it("does NOT fire on a DOWNGRADE (policy strictly below the account on either axis)", () => {
    expect(shouldUpgrade(RAISED, FLOOR)).toBe(false);
    expect(shouldUpgrade(p(134_217_728, 4), p(134_217_728, 3))).toBe(false); // ops down
  });

  it("does NOT fire on a SIDEWAYS move (higher on one axis, lower on the other — partial-order gap)", () => {
    expect(shouldUpgrade(p(134_217_728, 3), p(67_108_864, 4))).toBe(false);
    expect(shouldUpgrade(p(67_108_864, 4), p(134_217_728, 3))).toBe(false);
  });

  it("REFUSES a policy below the 64 MiB floor even when it dominates the account (disguised weakening)", () => {
    // account at 16 MiB/t2, policy at 32 MiB/t3: policy dominates, but 32 MiB < the floor → refused.
    expect(shouldUpgrade(p(16_777_216, 2), p(33_554_432, 3))).toBe(false);
  });

  it("REFUSES a policy above the 1 GiB / t=10 ceiling (per-unlock DoS)", () => {
    expect(shouldUpgrade(FLOOR, p(2_147_483_648, 4))).toBe(false); // 2 GiB
    expect(shouldUpgrade(FLOOR, p(134_217_728, 11))).toBe(false); // t=11
  });

  it("fails closed on a version regression (policy.v < account.v)", () => {
    expect(shouldUpgrade(p(67_108_864, 3, 2), p(134_217_728, 4, 1))).toBe(false);
  });

  it("REFUSES a memory cost that is not a whole number of KiB, inside every other bound (spec 01 §7)", () => {
    expect(shouldUpgrade(FLOOR, p(67_108_864 + 512, 3))).toBe(false); // half a KiB over: mem up on one axis only
    expect(shouldUpgrade(FLOOR, p(134_217_728 + 1, 4))).toBe(false);
    expect(shouldUpgrade(FLOOR, p(67_108_864 + 1024, 3))).toBe(true); // one whole KiB more is an upgrade
  });
});

describe("passesReKeyFence: the fence of a re-key target and of a served wrap neither known nor pending", () => {
  it("passes the floor, the ceiling and any whole-KiB cost between", () => {
    expect(passesReKeyFence(FLOOR)).toBe(true);
    expect(passesReKeyFence(p(1_073_741_824, 10))).toBe(true);
    expect(passesReKeyFence(p(67_108_864 + 1024, 3))).toBe(true);
  });

  it("refuses below the floor, above the ceiling, a ragged KiB, a fraction, another scheme", () => {
    for (const bad of [BELOW_FLOOR, p(67_108_864, 2), p(2_147_483_648, 4), p(67_108_864, 11), p(67_108_864 + 512, 3), p(67_108_864, 3.5), p(67_108_864, 3, 2), { ...FLOOR, alg: "argon2i" }]) {
      expect(passesReKeyFence(bad), JSON.stringify(bad)).toBe(false);
    }
  });
});

// ---- the quiet re-key ---------------------------------------------------------------------------------------

const rec = vector("recovery.json");
const frames: string[] = rec.cardChains["rotated-once"].frames as string[];
const EMAIL = "kdf@example.com";
const PASSWORD = "correct horse battery staple";
let ORIGIN = "";

/** The server as the re-key sees it: the account's keys it holds, and every request, in order. */
interface World {
  calls: string[];
  puts: PasswordChangeRequestV2[];
  /** What the server holds: the wrap a sign-in would serve. */
  held: SessionKeys;
  /** How `PUT /account/password` is answered: made, refused (an answer that it was not made), or no answer (with or without storing it). */
  answer: "made" | "refused" | "no_answer_stored" | "no_answer";
  policy: () => Promise<{ kdfParams: KdfParams }>;
  s: SettingsSession;
  opened: OpenedAccount;
  /** The offline copy's keeper: what was kept beside the copy, in order. */
  copyLog: string[];
  copyPending: readonly SessionKeys[];
  copyOwn: SessionKeys | null;
}

async function world(own: KdfParams = FLOOR, policy: KdfParams = OPS_UP): Promise<World> {
  const storage = memoryStorage();
  const pins = new PinStore(storage, async () => ({ cards: frames, rotations: [rec.rotationFrames["A-to-B"]] }), null);
  const g = await pins.begin(ORIGIN);
  if (g.kind !== "needs_trust_gate") throw new Error(g.kind);
  pins.confirmTrustGate(g.ticket);
  const pin = pins.pinFor(ORIGIN)!;
  const reg = await buildRegistration({
    email: EMAIL, displayName: "K", password: PASSWORD, kdfParams: own, signupTicket: "t", pin, ageConfirmed: true,
    device: { platform: "web", name: "x", deviceSecret: "A".repeat(43) }, nowMs: 1_763_164_800_000,
  });
  const r = reg.request;
  const keys: AccountKeysV2 = { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk, encryptedIdentitySeed: r.encryptedIdentitySeed, identityPub: r.identityPub, recoveryConfirmed: true, personalWrap: r.personalWrap, genesis: r.genesis };
  const o = openAccount(reg.userId, reg.uvk.slice(), keys, pin.instanceId, null);
  if (o.kind !== "opened") throw new Error(o.reason);
  const w = { calls: [] as string[], puts: [] as PasswordChangeRequestV2[], held: { kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk }, answer: "made", copyLog: [] as string[], copyPending: [] as readonly SessionKeys[], copyOwn: null as SessionKeys | null } as World;
  w.policy = async () => {
    w.calls.push("clientPolicy");
    assertServerKdfParams(policy); // the wire's own fence (api/wireclient.ts clientPolicy)
    return { kdfParams: policy };
  };
  const wire = new Proxy({} as SettingsWire, {
    get: (_t, name) => {
      if (typeof name !== "string" || name === "then") return undefined;
      return async (req: PasswordChangeRequestV2) => {
        w.calls.push(name);
        if (name === "accountKeys") return w.held;
        if (name !== "changePassword") throw new Error(`an unexpected route: ${name}`);
        w.puts.push(req);
        const next = { kdfSalt: req.newKdfSalt, kdfParams: req.newKdfParams, wrappedUvk: req.newWrappedUvk };
        if (w.answer === "refused") throw new ApiError(409, "concurrent_change", "refused");
        if (w.answer === "made" || w.answer === "no_answer_stored") w.held = next;
        if (w.answer !== "made") throw new ApiError(0, "network", "no answer");
        return undefined;
      };
    },
  });
  const copy: CopyKeeper = {
    keepPending: async (pending): Promise<CopyWrite> => ((w.copyPending = pending.map((x) => ({ ...x }))), w.copyLog.push(`pending:${pending.length}`), "written"),
    settle: async (o2, pending): Promise<CopyWrite> => ((w.copyOwn = { ...o2 }), (w.copyPending = pending.map((x) => ({ ...x }))), w.copyLog.push(`settle:${pending.length}`), "written"),
  };
  w.opened = o.account;
  w.s = { wire, pins, origin: ORIGIN, account: EMAIL, opened: o.account, wrap: new SessionWrap({ kdfSalt: r.kdfSalt, kdfParams: r.kdfParams, wrappedUvk: r.wrappedUvk }), copy };
  return w;
}

const run = (w: World, over: Partial<QuietReKeyInputs> = {}) => quietReKey({ settings: w.s, password: PASSWORD, unlock: "full_password_online", policy: w.policy, ...over });

/** The UVK [wrap] opens to with [password], as hex-free base64; throws when it does not open. */
async function opens(password: string, wrap: SessionKeys, userId: string): Promise<string> {
  return toB64(open(await wrapKey(masterKey(password, fromB64(wrap.kdfSalt), wrap.kdfParams)), fromB64(wrap.wrappedUvk), adUvk(userId)));
}

describe("the quiet re-key after a full-password unlock (spec 01 §7, F61)", () => {
  beforeAll(async () => {
    await initSodium();
    ORIGIN = verifyCardChain(frames.map((f) => fromB64Canonical(f)!)).cards[0]!.fields.origin;
  });

  it("an upgrade due: re-keys once with the same password, the proof derived on this device from the session's own wrap, the same UVK under the policy's cost", async () => {
    const w = await world();
    const before = w.s.wrap.current!;
    const uvk = toB64(w.opened.uvk);
    expect(await run(w)).toBe("rekeyed");
    // The policy, then the change: no prelogin, no GET /account/keys (nothing pending), no other route.
    expect(w.calls).toEqual(["clientPolicy", "changePassword"]);
    const put = w.puts[0]!;
    // The in-session proof: the current password's auth key under the salt and cost of the wrap this session keeps.
    expect(put.currentAuthKey).toBe(toB64(await authKey(masterKey(PASSWORD, fromB64(before.kdfSalt), before.kdfParams))));
    expect(put.newKdfParams).toEqual(OPS_UP);
    expect(put.newKdfSalt).not.toBe(before.kdfSalt);
    expect(await opens(PASSWORD, { kdfSalt: put.newKdfSalt, kdfParams: put.newKdfParams, wrappedUvk: put.newWrappedUvk }, w.opened.userId)).toBe(uvk);
    // The session and the offline copy keep exactly the wrap that was sent; the pending record was kept before it went.
    expect(w.s.wrap.current).toEqual(w.held);
    expect(w.s.wrap.pendingAll).toEqual([]);
    expect(w.copyLog).toEqual(["pending:1", "settle:0"]);
    expect(w.copyOwn).toEqual(w.held);
  }, 120_000);

  it("upgrade only: equal, lower and sideways policies send nothing and derive nothing", async () => {
    for (const [own, policy] of [[FLOOR, FLOOR], [OPS_UP, FLOOR], [p(134_217_728, 3), OPS_UP]] as const) {
      const w = await world(own, policy);
      expect(await run(w), JSON.stringify([own, policy])).toBe("not_due");
      expect(w.calls).toEqual(["clientPolicy"]);
      expect(w.copyLog).toEqual([]);
    }
  }, 120_000);

  it("never on the server's word alone: a policy below the floor or above the ceiling is refused where it is read, or by the decision, and nothing is sent", async () => {
    // Above the ceiling, but well-formed for the wire: the decision refuses it.
    const ceiling = await world(FLOOR, p(67_108_864, 11));
    ceiling.policy = async () => ({ kdfParams: p(67_108_864, 11) });
    expect(await run(ceiling)).toBe("not_due");
    expect(ceiling.puts).toEqual([]);
    // Below the floor: the wire's fence refuses the policy itself, so it is treated as unreadable.
    const floor = await world(FLOOR, p(33_554_432, 4));
    expect(await run(floor)).toBe("no_policy");
    expect(floor.puts).toEqual([]);
    // A policy the wire would refuse, handed straight to the decision (a fence bypassed): still no upgrade.
    expect(shouldUpgrade(FLOOR, p(33_554_432, 4))).toBe(false);
  }, 120_000);

  it("full-password unlocks that reached the server only: an unlock from the offline copy or a read-only copy looks at nothing", async () => {
    for (const unlock of ["offline_copy", "read_only_copy"] as const) {
      const w = await world();
      expect(await run(w, { unlock })).toBe("not_counted");
      expect(w.calls).toEqual([]);
    }
    // The screens hand the password in only from the two full-password unlocks (and the kit gate that follows them):
    // never from the copy, sign-up or a kit recovery; enterVault passes it on only for an online unlock.
    const welcome = readFileSync(fileURLToPath(new URL("../ui/Welcome.tsx", import.meta.url)), "utf8");
    expect(welcome.match(/cardNotice: r\.notice, password(, copySealedElsewhere)?, flow \}\);/g)).toHaveLength(2);
    expect(welcome).toContain('...(c.mode === undefined || c.mode === "online" ? { password: c.password } : {})');
    expect(welcome.match(/mode: "offline", flow \}\);/g)?.length).toBe(1);
    const open2 = readFileSync(fileURLToPath(new URL("../ui/opensession.ts", import.meta.url)), "utf8");
    expect(open2).toContain('unlock: mode === "online" ? "full_password_online" : "offline_copy"');
  }, 120_000);

  it("the server unreachable: skipped without a word, nothing sent", async () => {
    const w = await world();
    w.policy = async () => {
      w.calls.push("clientPolicy");
      throw new ApiError(0, "network", "offline");
    };
    expect(await run(w)).toBe("no_policy");
    expect(w.calls).toEqual(["clientPolicy"]);
  }, 120_000);

  it("a refusal changes nothing: the session keeps its wrap, nothing stays pending, and the account opens with the password as before", async () => {
    const w = await world();
    const before = w.s.wrap.current!;
    w.answer = "refused";
    expect(await run(w)).toBe("failed");
    expect(w.s.wrap.current).toEqual(before);
    expect(w.s.wrap.pendingAll).toEqual([]);
    expect(w.copyPending).toEqual([]);
    expect(w.held).toEqual(before);
    expect(await opens(PASSWORD, w.held, w.opened.userId)).toBe(toB64(w.opened.uvk));
  }, 120_000);

  it("no answer (a closed tab, a lost connection): the account opens with exactly one of the two wraps, each with the same password, and the next unlock settles it", async () => {
    for (const answer of ["no_answer", "no_answer_stored"] as const) {
      const w = await world();
      const before = w.s.wrap.current!;
      w.answer = answer;
      expect(await run(w)).toBe("failed");
      // Kept as pending beside the copy before the request went: the copy opens with the password whichever the server took.
      expect(w.copyPending).toHaveLength(1);
      const pending = w.copyPending[0]!;
      // The server holds exactly one of the two wraps, and the same password opens it.
      expect([before, pending].filter((x) => x.wrappedUvk === w.held.wrappedUvk)).toHaveLength(1);
      expect(w.held).toEqual(answer === "no_answer" ? before : pending);
      expect(await opens(PASSWORD, w.held, w.opened.userId)).toBe(toB64(w.opened.uvk));
      // The next unlock (the next re-key here) settles it against the server's keys before anything is sent.
      w.answer = "made";
      w.calls = [];
      w.puts = [];
      const again = await run(w);
      if (answer === "no_answer_stored") {
        // The change landed: the session takes it, and no second change is sent (it would be sideways).
        expect(again).toBe("not_due");
        expect(w.calls).toEqual(["clientPolicy", "accountKeys"]);
        expect(w.s.wrap.current).toEqual(pending);
      } else {
        expect(again).toBe("rekeyed");
        expect(w.calls).toEqual(["clientPolicy", "accountKeys", "changePassword"]);
      }
      expect(w.s.wrap.pendingAll).toEqual([]);
    }
  }, 240_000);

  it("the password is not kept for this: the re-key is awaited inside the unlock and nothing it returns or keeps holds it", async () => {
    const w = await world();
    const r = await run(w);
    expect(r).toBe("rekeyed");
    expect(JSON.stringify({ r, wrap: w.s.wrap.current, pending: w.s.wrap.pendingAll, copy: w.copyOwn })).not.toContain(PASSWORD);
    const open2 = readFileSync(fileURLToPath(new URL("../ui/opensession.ts", import.meta.url)), "utf8");
    // Awaited before enterVault returns (never detached), and the password appears only in that call.
    // Spec 01 §7, "leaves both": a session opened from the copy while the server serves keys this browser does not know
    // runs no re-key (its proof would be refused).
    expect(open2).toContain("const reKey = params.password === undefined || notKnown ? \"not_counted\" : await quietReKey({ settings, password: params.password,");
    expect(open2.match(/params\.password/g)).toHaveLength(2);
  }, 120_000);
});
