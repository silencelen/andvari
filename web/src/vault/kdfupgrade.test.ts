import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { KdfParams } from "../crypto/keys";
import { initSodium } from "../crypto/sodium";
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
  const mocks = () => ({
    client: { changePassword: vi.fn(async () => undefined) },
    account: { buildPasswordChange: vi.fn(async () => change) },
  });

  it("FIRES the re-key exactly once: derives currentAuthKey, re-derives under the policy, PUTs the change", async () => {
    const deriveSpy = vi.spyOn(Account, "deriveAuthKey").mockResolvedValue("current-auth");
    const { client, account } = mocks();
    await maybeKdfUpgrade({
      client,
      account,
      password: "correct horse",
      currentKdfSalt: "old-salt",
      currentKdfParams: BELOW_FLOOR,
      policyKdfParams: FLOOR,
      mustChangePassword: false,
    });
    expect(deriveSpy).toHaveBeenCalledWith("correct horse", "old-salt", BELOW_FLOOR);
    expect(account.buildPasswordChange).toHaveBeenCalledWith("correct horse", FLOOR); // re-key under the POLICY
    expect(client.changePassword).toHaveBeenCalledTimes(1);
    expect(client.changePassword).toHaveBeenCalledWith({ currentAuthKey: "current-auth", ...change });
  });

  it("does NOT fire when the account is ALREADY at the policy params (no argon2id, no PUT)", async () => {
    const deriveSpy = vi.spyOn(Account, "deriveAuthKey").mockResolvedValue("current-auth");
    const { client, account } = mocks();
    await maybeKdfUpgrade({
      client,
      account,
      password: "pw",
      currentKdfSalt: "s",
      currentKdfParams: FLOOR,
      policyKdfParams: FLOOR,
      mustChangePassword: false,
    });
    expect(deriveSpy).not.toHaveBeenCalled();
    expect(account.buildPasswordChange).not.toHaveBeenCalled();
    expect(client.changePassword).not.toHaveBeenCalled();
  });

  it("does NOT fire while mustChangePassword is set, even though the policy would upgrade (A5)", async () => {
    const deriveSpy = vi.spyOn(Account, "deriveAuthKey").mockResolvedValue("current-auth");
    const { client, account } = mocks();
    await maybeKdfUpgrade({
      client,
      account,
      password: "temp",
      currentKdfSalt: "s",
      currentKdfParams: BELOW_FLOOR,
      policyKdfParams: FLOOR,
      mustChangePassword: true,
    });
    expect(deriveSpy).not.toHaveBeenCalled();
    expect(client.changePassword).not.toHaveBeenCalled();
  });

  it("does NOT fire on a downgrade policy (the web analogue of the offline / quick-unlock exclusion)", async () => {
    const deriveSpy = vi.spyOn(Account, "deriveAuthKey").mockResolvedValue("current-auth");
    const { client, account } = mocks();
    await maybeKdfUpgrade({
      client,
      account,
      password: "pw",
      currentKdfSalt: "s",
      currentKdfParams: RAISED,
      policyKdfParams: FLOOR,
      mustChangePassword: false,
    });
    expect(client.changePassword).not.toHaveBeenCalled();
    expect(deriveSpy).not.toHaveBeenCalled();
  });

  it("SWALLOWS a changePassword failure (best-effort) — resolves, never rejects", async () => {
    vi.spyOn(Account, "deriveAuthKey").mockResolvedValue("current-auth");
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
        policyKdfParams: FLOOR,
        mustChangePassword: false,
      }),
    ).resolves.toBeUndefined();
    expect(client.changePassword).toHaveBeenCalledTimes(1);
  });
});
