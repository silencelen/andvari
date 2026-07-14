import { beforeAll, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import type { KdfParams } from "../crypto/keys";
import { deriveAuthKey as deriveRecoveryAuthKey } from "../crypto/member-recovery";
import { initSodium } from "../crypto/sodium";
import { Account } from "../vault/account";
import { needsRecoveryCapture, settleRecoveryConfirm, setupAndCommitRecovery } from "./recovery-capture";

/**
 * design §F.9 — the web vault-entry recovery-capture gate. Pinned as the two seams the Unlock/SignIn
 * and Enroll flows wrap around a mocked api: the block-path REGENERATES + commits (self-setup), the
 * post-type-back settlement CONFIRMS without regenerating (self/confirm) — so the phrase the user
 * already saved is never clobbered. design 2026-07-13 piece-binding: the confirm is BOUND (presents
 * the pieceId of the piece this surface revealed) + AWAITED, and a stale answer NEVER proceeds.
 */
const KDF: KdfParams = { v: 1, alg: "argon2id13", ops: 1, memBytes: 8192 }; // min-cost — this tests the flow, not the KDF

async function enrolledAccount(): Promise<Account> {
  const { account } = await Account.enroll({
    inviteToken: "t",
    email: "u@example.com",
    displayName: "u",
    password: "the old master password",
    kdfParams: KDF, // waived: no recoveryPublicKey
  });
  return account;
}

const stalePiece = () => new ApiError(409, "recovery_piece_stale", "conflict");

describe("needsRecoveryCapture — fail-SAFE: BLOCK unless the server says it's confirmed", () => {
  it("blocks when the flag is false or absent (an old server omits it)", () => {
    expect(needsRecoveryCapture({ recoveryConfirmed: false })).toBe(true);
    expect(needsRecoveryCapture({})).toBe(true);
    expect(needsRecoveryCapture({ recoveryConfirmed: undefined })).toBe(true);
  });
  it("passes ONLY when the flag is explicitly true", () => {
    expect(needsRecoveryCapture({ recoveryConfirmed: true })).toBe(false);
  });
});

describe("setupAndCommitRecovery — the BLOCK path regenerates + commits, then reveals", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("commits a fresh piece via /recovery/self-setup and returns the raw 256-bit secret + its pieceId", async () => {
    const account = await enrolledAccount();
    const recoverySelfSetup = vi.fn().mockResolvedValue({ pieceId: "piece-1" });
    const { recoverySecret, pieceId } = await setupAndCommitRecovery({ recoverySelfSetup }, account, "the-current-auth-key");

    // The raw secret is the 32 CSPRNG bytes the RecoveryReveal will show once; the pieceId is the
    // server-minted handle the type-back confirm must present (design 2026-07-13).
    expect(recoverySecret).toBeInstanceOf(Uint8Array);
    expect(recoverySecret.length).toBe(32);
    expect(pieceId).toBe("piece-1");

    // Exactly one commit, carrying the fresh master-password reauth + the new member-recovery block.
    expect(recoverySelfSetup).toHaveBeenCalledTimes(1);
    const req = recoverySelfSetup.mock.calls[0]![0];
    expect(req.currentAuthKey).toBe("the-current-auth-key");
    expect(typeof req.memberRecovery.recoveryWrappedUvk).toBe("string");
    // Byte-parity with the recovery path: the auth key the server stores/verifies is exactly what
    // deriveAuthKey computes from the shown secret — so the phrase the user saves IS the one that works.
    expect(req.memberRecovery.recoveryAuthKey).toBe(await deriveRecoveryAuthKey(recoverySecret));
  });

  it("normalizes a pre-binding server's missing pieceId to null (legacy unbound confirm)", async () => {
    const account = await enrolledAccount();
    const recoverySelfSetup = vi.fn().mockResolvedValue({});
    const { pieceId } = await setupAndCommitRecovery({ recoverySelfSetup }, account, "k");
    expect(pieceId).toBeNull();
  });

  it("rethrows on a failed commit so the gate stays CLOSED (never proceeds to the vault)", async () => {
    const account = await enrolledAccount();
    const boom = new Error("server said no");
    const recoverySelfSetup = vi.fn().mockRejectedValue(boom);
    const err = await setupAndCommitRecovery({ recoverySelfSetup }, account, "k").catch((e) => e);
    expect(err).toBe(boom);
  });
});

describe("settleRecoveryConfirm — BOUND + AWAITED; a stale piece NEVER proceeds", () => {
  beforeAll(async () => {
    await initSodium();
  });

  it("zeroes first, presents the held pieceId, and proceeds on 200", async () => {
    const recoverySelfConfirm = vi.fn().mockResolvedValue("ok");
    const calls: string[] = [];
    await settleRecoveryConfirm({ recoverySelfConfirm }, "piece-1", {
      zero: () => calls.push("zero"),
      onStale: () => calls.push("stale"),
      onProceed: () => calls.push("proceed"),
    });
    expect(recoverySelfConfirm).toHaveBeenCalledWith("piece-1");
    expect(calls).toEqual(["zero", "proceed"]); // zero BEFORE the wire call — never a live secret past type-back
  });

  it("null pieceId (pre-binding server) still confirms — the legacy empty-body shape", async () => {
    const recoverySelfConfirm = vi.fn().mockResolvedValue("ok");
    await settleRecoveryConfirm({ recoverySelfConfirm }, null, { zero: () => {}, onStale: () => {}, onProceed: () => {} });
    expect(recoverySelfConfirm).toHaveBeenCalledWith(null);
  });

  it("the stale seam: 409 → secret zeroed → re-setup invoked → onReady NOT called on the stale pass", async () => {
    const account = await enrolledAccount();
    // The gate's sequence with real seams: setup mints piece-1, a concurrent device rotates it away,
    // the bound confirm 409s, and the stale handler re-runs setup (fresh piece-2, fresh secret).
    const recoverySelfSetup = vi.fn().mockResolvedValueOnce({ pieceId: "piece-1" }).mockResolvedValueOnce({ pieceId: "piece-2" });
    const first = await setupAndCommitRecovery({ recoverySelfSetup }, account, "k");
    expect(first.pieceId).toBe("piece-1");

    const recoverySelfConfirm = vi.fn().mockRejectedValue(stalePiece());
    const onReady = vi.fn();
    let rerun: Promise<{ recoverySecret: Uint8Array; pieceId: string | null }> | null = null;
    await settleRecoveryConfirm({ recoverySelfConfirm }, first.pieceId, {
      zero: () => first.recoverySecret.fill(0),
      onStale: () => { rerun = setupAndCommitRecovery({ recoverySelfSetup }, account, "k"); },
      onProceed: onReady,
    });

    expect(recoverySelfConfirm).toHaveBeenCalledWith("piece-1"); // bound to the piece THIS gate revealed
    expect(onReady).not.toHaveBeenCalled(); // the gate stays closed on the stale pass
    expect(Array.from(first.recoverySecret)).toEqual(new Array(32).fill(0)); // the dead phrase is zeroed
    const second = await rerun!;
    expect(recoverySelfSetup).toHaveBeenCalledTimes(2); // fresh setup + reveal
    expect(second.pieceId).toBe("piece-2");
    expect(second.recoverySecret.some((b) => b !== 0)).toBe(true); // a genuinely fresh secret to show
  });

  it("any OTHER failure proceeds unconfirmed (flag stays 0 → the gate re-fires next entry and heals)", async () => {
    const onStale = vi.fn();
    const onProceed = vi.fn();
    for (const boom of [new ApiError(503, "http_503", "down"), new Error("network")]) {
      const recoverySelfConfirm = vi.fn().mockRejectedValue(boom);
      await settleRecoveryConfirm({ recoverySelfConfirm }, "piece-1", { zero: () => {}, onStale, onProceed });
    }
    expect(onStale).not.toHaveBeenCalled();
    expect(onProceed).toHaveBeenCalledTimes(2);
  });
});
