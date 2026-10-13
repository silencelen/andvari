import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { KdfParams } from "../crypto/keys";
import { initSodium } from "../crypto/sodium";
import { adUvk } from "../crypto/ad";
import { fromB64, toB64 } from "../crypto/bytes";
import { open } from "../crypto/envelope";
import { fingerprint } from "../crypto/escrow";
import { authKey, masterKey, wrapKey } from "../crypto/keys";
import { boxKeypairFromSeed, randomBytes } from "../crypto/provider";
import { Account } from "./account";
import { maybeKdfUpgrade, shouldUpgrade } from "./kdfupgrade";

/**
 * F61 silent KDF re-key (spec 01 §7) — the web mirror of Android's post-unlock re-key. `shouldUpgrade`
 * is a verbatim replica of core `KdfUpgrade.shouldUpgrade` (Kotlin-only), so the cases below pin the
 * SAME never-sideways/down/absurd contract; `maybeKdfUpgrade` is the best-effort driver the unlock /
 * sign-in paths kick DETACHED. Web has no offline or quick-unlock/biometric path — the driver is only
 * ever invoked on the online full-password path — so the Android "never on offline / quick-unlock"
 * exclusions map here to "never fires when already-current / a downgrade / mustChangePassword".
 */

const p = (memBytes: number, ops: number, v = 1): KdfParams => ({ v, alg: "argon2id13", ops, memBytes });

// core KdfUpgrade fence numbers, mirrored (⇔ crypto/keys.ts KDF_MIN_/MAX_*).
const FLOOR = p(67_108_864, 3); // 64 MiB / t=3 — the at-floor DEFAULT policy.
const BELOW_FLOOR = p(33_554_432, 2); // 32 MiB / t=2 — a legacy account under the raised floor.
const RAISED = p(134_217_728, 4); // 128 MiB / t=4.

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
});

describe("maybeKdfUpgrade — best-effort driver", () => {
  beforeAll(async () => {
    await initSodium();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const change = { newKdfSalt: "salt64", newKdfParams: FLOOR, newAuthKey: "new-auth", newWrappedUvk: "new-uvk" };
  // A9 (M-1): the current-password proof is the account's fenced reauth derivation, not the pre-session static.
  const mocks = () => ({
    client: { changePassword: vi.fn(async () => undefined) },
    account: { buildPasswordChange: vi.fn(async () => change), reauthAuthKey: vi.fn(async () => "current-auth") },
  });

  it("FIRES the re-key exactly once: derives currentAuthKey, re-derives under the policy, PUTs the change", async () => {
    const { client, account } = mocks();
    await maybeKdfUpgrade({
      client,
      account,
      password: "correct horse",
      currentKdfSalt: "old-salt",
      currentKdfParams: BELOW_FLOOR,
      currentWrappedUvk: "old-wrap",
      policyKdfParams: FLOOR,
      mustChangePassword: false,
    });
    // F3 (A10): the proof opens the served wrap, so the wrap rides along with the salt and params.
    expect(account.reauthAuthKey).toHaveBeenCalledWith("correct horse", { kdfSalt: "old-salt", kdfParams: BELOW_FLOOR, wrappedUvk: "old-wrap" });
    expect(account.buildPasswordChange).toHaveBeenCalledWith("correct horse", FLOOR); // re-key under the POLICY
    expect(client.changePassword).toHaveBeenCalledTimes(1);
    expect(client.changePassword).toHaveBeenCalledWith({ currentAuthKey: "current-auth", ...change });
  });

  it("CR-07: calls onUpgraded AFTER changePassword resolves (re-cache the post-upgrade accountKeys)", async () => {
    const { client, account } = mocks();
    const order: string[] = [];
    client.changePassword = vi.fn(async () => {
      order.push("changePassword");
    });
    const onUpgraded = vi.fn(async () => {
      order.push("onUpgraded");
    });
    await maybeKdfUpgrade({
      client,
      account,
      password: "correct horse",
      currentKdfSalt: "old-salt",
      currentKdfParams: BELOW_FLOOR,
      currentWrappedUvk: "old-wrap",
      policyKdfParams: FLOOR,
      mustChangePassword: false,
      onUpgraded,
    });
    expect(onUpgraded).toHaveBeenCalledTimes(1);
    expect(order).toEqual(["changePassword", "onUpgraded"]); // strictly after the server-side change
  });

  it("CR-07: does NOT call onUpgraded when no upgrade fires (already at policy params)", async () => {
    const { client, account } = mocks();
    const onUpgraded = vi.fn();
    await maybeKdfUpgrade({
      client,
      account,
      password: "pw",
      currentKdfSalt: "s",
      currentKdfParams: FLOOR,
      currentWrappedUvk: "old-wrap",
      policyKdfParams: FLOOR,
      mustChangePassword: false,
      onUpgraded,
    });
    expect(client.changePassword).not.toHaveBeenCalled();
    expect(onUpgraded).not.toHaveBeenCalled();
  });

  it("CR-07: an onUpgraded failure is swallowed — the re-key still counts as done (best-effort)", async () => {
    const { client, account } = mocks();
    const onUpgraded = vi.fn(async () => {
      throw new Error("cache write blew up");
    });
    await expect(
      maybeKdfUpgrade({
        client,
        account,
        password: "pw",
        currentKdfSalt: "s",
        currentKdfParams: BELOW_FLOOR,
        currentWrappedUvk: "old-wrap",
        policyKdfParams: FLOOR,
        mustChangePassword: false,
        onUpgraded,
      }),
    ).resolves.toBeUndefined();
    expect(client.changePassword).toHaveBeenCalledTimes(1);
    expect(onUpgraded).toHaveBeenCalledTimes(1);
  });

  it("does NOT fire when the account is ALREADY at the policy params (no argon2id, no PUT)", async () => {
    const { client, account } = mocks();
    await maybeKdfUpgrade({
      client,
      account,
      password: "pw",
      currentKdfSalt: "s",
      currentKdfParams: FLOOR,
      currentWrappedUvk: "old-wrap",
      policyKdfParams: FLOOR,
      mustChangePassword: false,
    });
    expect(account.reauthAuthKey).not.toHaveBeenCalled();
    expect(account.buildPasswordChange).not.toHaveBeenCalled();
    expect(client.changePassword).not.toHaveBeenCalled();
  });

  it("does NOT fire while mustChangePassword is set, even though the policy would upgrade (A5)", async () => {
    const { client, account } = mocks();
    await maybeKdfUpgrade({
      client,
      account,
      password: "temp",
      currentKdfSalt: "s",
      currentKdfParams: BELOW_FLOOR,
      currentWrappedUvk: "old-wrap",
      policyKdfParams: FLOOR,
      mustChangePassword: true,
    });
    expect(account.reauthAuthKey).not.toHaveBeenCalled();
    expect(client.changePassword).not.toHaveBeenCalled();
  });

  it("does NOT fire on a downgrade policy (the web analogue of the offline / quick-unlock exclusion)", async () => {
    const { client, account } = mocks();
    await maybeKdfUpgrade({
      client,
      account,
      password: "pw",
      currentKdfSalt: "s",
      currentKdfParams: RAISED,
      currentWrappedUvk: "old-wrap",
      policyKdfParams: FLOOR,
      mustChangePassword: false,
    });
    expect(client.changePassword).not.toHaveBeenCalled();
    expect(account.reauthAuthKey).not.toHaveBeenCalled();
  });

  it("SWALLOWS a changePassword failure (best-effort) — resolves, never rejects", async () => {
    const { account } = mocks();
    const client = {
      changePassword: vi.fn(async () => {
        throw new Error("server 503");
      }),
    };
    await expect(
      maybeKdfUpgrade({
        client,
        account,
        password: "pw",
        currentKdfSalt: "s",
        currentKdfParams: BELOW_FLOOR,
        currentWrappedUvk: "old-wrap",
        policyKdfParams: FLOOR,
        mustChangePassword: false,
      }),
    ).resolves.toBeUndefined();
    expect(client.changePassword).toHaveBeenCalledTimes(1);
  });
});

/**
 * Security review 2026-10 plugin scan F3 (A10, an A9 regression): the driver's current-password proof is
 * `Account.reauthAuthKey`, which OPENS the served wrappedUvk to the session UVK. The driver passed only the salt and
 * params, so the proof threw inside the catch-all and the silent upgrade never ran on web. Driven here with a REAL
 * Account (the mocks above cannot see the shape of the keys object): the re-key must derive the current authKey,
 * re-wrap the SAME UVK under the policy's params, and PUT the change.
 */
describe("maybeKdfUpgrade — with a real Account (F3)", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("derives the current proof from the served wrap and uploads a re-wrap of the same UVK under the policy params", async () => {
    const recovery = boxKeypairFromSeed(randomBytes(32));
    const password = "correct horse battery staple";
    const email = `kdf-${Math.random().toString(16).slice(2)}@example.com`;
    const { request, account } = await Account.enroll({
      inviteToken: "t", email, displayName: email, password, kdfParams: FLOOR,
      recoveryPublicKey: recovery.publicKey, recoveryFingerprint: await fingerprint(recovery.publicKey),
    });
    const keys = {
      kdfSalt: request.kdfSalt, kdfParams: request.kdfParams, wrappedUvk: request.wrappedUvk, encryptedIdentitySeed: request.encryptedIdentitySeed,
      identityPub: request.identityPub, escrowFingerprint: request.escrow!.fingerprint, personalWrap: request.personalWrap,
    };
    const device = await Account.unlock(request.userId, password, keys);
    const puts: { currentAuthKey: string; newKdfSalt: string; newKdfParams: KdfParams; newAuthKey: string; newWrappedUvk: string }[] = [];
    let upgraded = 0;
    await maybeKdfUpgrade({
      client: { changePassword: async (req) => { puts.push(req); } },
      account: device,
      password,
      currentKdfSalt: keys.kdfSalt,
      currentKdfParams: keys.kdfParams,
      currentWrappedUvk: keys.wrappedUvk,
      policyKdfParams: RAISED,
      mustChangePassword: false,
      onUpgraded: () => { upgraded++; },
    });
    expect(puts, "the re-key ran exactly once").toHaveLength(1);
    expect(upgraded).toBe(1);
    const put = puts[0]!;
    expect(put.newKdfParams).toEqual(RAISED);
    // The proof is the CURRENT password's auth key under the current salt/params...
    expect(put.currentAuthKey).toBe(toB64(await authKey(masterKey(password, fromB64(keys.kdfSalt), keys.kdfParams))));
    // ...and the uploaded wrap opens, under the NEW salt/params, to the SAME UVK the old wrap held.
    const oldUvk = open(await wrapKey(masterKey(password, fromB64(keys.kdfSalt), keys.kdfParams)), fromB64(keys.wrappedUvk), adUvk(request.userId));
    const newUvk = open(await wrapKey(masterKey(password, fromB64(put.newKdfSalt), put.newKdfParams)), fromB64(put.newWrappedUvk), adUvk(request.userId));
    expect(toB64(newUvk)).toBe(toB64(oldUvk));
    expect(put.newKdfSalt).not.toBe(keys.kdfSalt);
    expect(put.newAuthKey).toBe(toB64(await authKey(masterKey(password, fromB64(put.newKdfSalt), put.newKdfParams))));
    expect(account.userId).toBe(device.userId);
  }, 120_000);
});
