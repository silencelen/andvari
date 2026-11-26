import { beforeAll, describe, expect, it } from "vitest";
import { fromB64 } from "../crypto/bytes";
import { boxKeypairFromSeed, signKeypairFromSeed } from "../crypto/provider";
import { initSodium } from "../crypto/sodium";
import { gradeEvery, vector } from "../crypto/trust/vectors";
import { checkOpened, IDENTITY_PUB_MISMATCH, NO_GENESIS, SELF_IDENTITY_MISMATCH } from "./accountopen";

/**
 * The unlock checks in the engine's AccountOpen order, graded on every row of accountgenesis.json: the genesis
 * verdicts (VR-13) and, on ok rows, whether the personal vault is in force (§5.3). Plus the three checks the
 * file does not cover: the served identityPub, a missing genesis, and this browser's own record of the key.
 */
const v = vector("accountgenesis.json");

describe("accountopen", () => {
  beforeAll(async () => {
    await initSodium();
  });

  const keys = () => {
    const seed = fromB64(v.account.seedB64);
    return { identity: boxKeypairFromSeed(seed), signing: signKeypairFromSeed(seed) };
  };

  it("grades accountgenesis.json", () => {
    gradeEvery("accountgenesis.rows (web unlock)", v.rows, (row: { name: string; genesisB64: string; sessionUserId: string; pinnedInstanceId: string; personalWrap: { vaultId: string; wrappedVkB64: string } | null; expect: { verdict: string; personalVaultInForce?: boolean } }) => {
      const { identity, signing } = keys();
      const r = checkOpened(
        row.sessionUserId,
        fromB64(v.account.uvkB64),
        identity,
        signing,
        v.account.identityPubB64,
        row.genesisB64,
        row.personalWrap ? { vaultId: row.personalWrap.vaultId, wrappedVk: row.personalWrap.wrappedVkB64 } : null,
        row.pinnedInstanceId,
        null,
      );
      if (row.expect.verdict === "ok") {
        expect(r.kind, row.name).toBe("opened");
        if (r.kind === "opened") expect(r.account.personalVaultId !== null, row.name).toBe(row.expect.personalVaultInForce);
      } else {
        expect(r, row.name).toEqual({ kind: "identity_fault", reason: row.expect.verdict });
      }
    });
  });

  it("the served identityPub, a missing genesis and this browser's own record are checked, and keys are wiped on a fault", () => {
    const row = v.rows.find((r: { expect: { verdict: string } }) => r.expect.verdict === "ok");
    const uvk = () => fromB64(v.account.uvkB64);
    let k = keys();
    const other = boxKeypairFromSeed(new Uint8Array(32).fill(7)).publicKey;
    expect(checkOpened(row.sessionUserId, uvk(), k.identity, k.signing, "dmn5TI1-jtERdRVMZoWG5QFr3LXPGreVJcHDayMnGia", row.genesisB64, null, row.pinnedInstanceId, null)).toEqual({ kind: "identity_fault", reason: IDENTITY_PUB_MISMATCH });
    expect([...k.identity.privateKey].every((b) => b === 0)).toBe(true);
    k = keys();
    expect(checkOpened(row.sessionUserId, uvk(), k.identity, k.signing, v.account.identityPubB64, null, null, row.pinnedInstanceId, null)).toEqual({ kind: "identity_fault", reason: NO_GENESIS });
    k = keys();
    expect(checkOpened(row.sessionUserId, uvk(), k.identity, k.signing, v.account.identityPubB64, row.genesisB64, null, row.pinnedInstanceId, other)).toEqual({ kind: "identity_fault", reason: SELF_IDENTITY_MISMATCH });
  });
});
