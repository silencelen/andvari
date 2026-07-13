import { beforeAll, describe, expect, it, vi } from "vitest";
import type { KdfParams } from "../crypto/keys";
import { deriveAuthKey as deriveRecoveryAuthKey } from "../crypto/member-recovery";
import { initSodium } from "../crypto/sodium";
import { Account } from "../vault/account";
import { confirmRegisteredRecovery, needsRecoveryCapture, setupAndCommitRecovery } from "./recovery-capture";

/**
 * design §F.9 — the web vault-entry recovery-capture gate. Pinned as the two seams the Unlock/SignIn
 * and Enroll flows wrap around a mocked api: the block-path REGENERATES + commits (self-setup), the
 * enroll happy-path CONFIRMS without regenerating (self/confirm) — so the phrase the user already
 * saved is never clobbered.
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

  it("commits a fresh piece via /recovery/self-setup and returns the raw 256-bit secret to show once", async () => {
    const account = await enrolledAccount();
    const recoverySelfSetup = vi.fn().mockResolvedValue("ok");
    const secret = await setupAndCommitRecovery({ recoverySelfSetup }, account, "the-current-auth-key");

    // The raw secret is the 32 CSPRNG bytes the RecoveryReveal will show once.
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);

    // Exactly one commit, carrying the fresh master-password reauth + the new member-recovery block.
    expect(recoverySelfSetup).toHaveBeenCalledTimes(1);
    const req = recoverySelfSetup.mock.calls[0]![0];
    expect(req.currentAuthKey).toBe("the-current-auth-key");
    expect(typeof req.memberRecovery.recoveryWrappedUvk).toBe("string");
    // Byte-parity with the recovery path: the auth key the server stores/verifies is exactly what
    // deriveAuthKey computes from the shown secret — so the phrase the user saves IS the one that works.
    expect(req.memberRecovery.recoveryAuthKey).toBe(await deriveRecoveryAuthKey(secret));
  });

  it("rethrows on a failed commit so the gate stays CLOSED (never proceeds to the vault)", async () => {
    const account = await enrolledAccount();
    const boom = new Error("server said no");
    const recoverySelfSetup = vi.fn().mockRejectedValue(boom);
    const err = await setupAndCommitRecovery({ recoverySelfSetup }, account, "k").catch((e) => e);
    expect(err).toBe(boom);
  });
});

describe("confirmRegisteredRecovery — the ENROLL happy path confirms WITHOUT regenerating", () => {
  it("calls recoverySelfConfirm and returns its result (flips the flag, no key material)", async () => {
    const recoverySelfConfirm = vi.fn().mockResolvedValue("ok");
    await expect(confirmRegisteredRecovery({ recoverySelfConfirm })).resolves.toBe("ok");
    expect(recoverySelfConfirm).toHaveBeenCalledTimes(1);
    // No argument (unlike self-setup, which regenerates) — the register-committed piece IS what was shown.
    expect(recoverySelfConfirm.mock.calls[0]!.length).toBe(0);
  });
});
