import { beforeAll, describe, expect, it } from "vitest";
import { fromB64, toB64 } from "../bytes";
import { boxKeypairFromSeed } from "../provider";
import { initSodium } from "../sodium";
import { openVaultGrant, sealVaultGrant, signVaultGrant } from "./grant";
import { latestAddOf, NONE_HELD, replayLog } from "./vaultlog";
import { expectSections, gradeEvery, gradeEveryAsync, vector } from "./vectors";

/**
 * Grants under design 2026-11-15 §3.5, graded off the REWRITTEN `sharedgrant-v2.json` from the
 * independent oracle (the same file core's `VaultGrantVectorTest` consumes). It lives in
 * `spec/test-vectors/next/` until integration; the web no longer reads the old file of that name
 * (its reader, `signedgrant.test.ts`, went with `signedgrant.ts`).
 */
const v = vector("next/sharedgrant-v2.json");

beforeAll(async () => {
  await initSodium();
});

describe("next/sharedgrant-v2.json", () => {
  it("the file has the sections this suite grades, and no other", () => {
    expectSections(v, ["_about", "vaultId", "otherVaultId", "vkB64", "vkCommitHex", "accounts", "logs", "cases"]);
  });

  it("every log replays to its own verdict", () => {
    gradeEvery("sharedgrant-v2.logs", Object.entries<any>(v.logs), ([name, log]) => {
      const replay = replayLog(v.vaultId, log.frames.map(fromB64), null, NONE_HELD);
      expect(replay.verdict ?? "ok", `log ${name}`).toBe(log.verdict);
      if (replay.verdict !== null) {
        expect(replay.accepted, `log ${name}`).toBe(log.failedAt);
      } else if (log.state === null) {
        expect(replay.state, `log ${name}: no entry, no state`).toBeNull();
      } else {
        const s = replay.state!;
        expect([s.head.seq, s.head.hash, s.owner, s.ownerKey, s.vkCommit], `log ${name}`).toEqual([
          log.state.head.seq, log.state.head.hash, log.state.owner, log.state.ownerKey, log.state.vkCommit,
        ]);
        expect(Object.keys(s.members).sort(), `log ${name}`).toEqual(Object.keys(log.state.members).sort());
      }
    });
  });

  it("every case gets its exact verdict", async () => {
    const replays: Record<string, ReturnType<typeof replayLog>> = {};
    for (const [name, log] of Object.entries<{ frames: string[] }>(v.logs)) replays[name] = replayLog(v.vaultId, log.frames.map(fromB64), null, NONE_HELD);
    await gradeEveryAsync("sharedgrant-v2.cases", v.cases, async (c: any) => {
      const account = v.accounts[c.me];
      const box = boxKeypairFromSeed(fromB64(account.seedB64));
      expect(toB64(box.publicKey), c.name).toBe(account.identityPubB64);
      const me = { userId: account.userId as string, identityPub: box.publicKey, identityPriv: box.privateKey };
      const expected: string = c.expect.verdict;
      // The log is replayed before any grant is opened; one that does not verify decides alone.
      const replay = replays[c.log];
      expect(replay, `${c.name}: logs.${c.log}`).toBeDefined();
      if (replay!.verdict !== null) {
        expect(replay!.verdict, `${c.name}: ${c.why}`).toBe(expected);
        return;
      }
      const result = await openVaultGrant(me, c.rowVaultId, fromB64(c.sealedB64), replay!.state);
      expect(result.ok ? "ok" : result.verdict, `${c.name}: ${c.why}`).toBe(expected);
      if (result.ok) {
        expect(toB64(result.value.vk), c.name).toBe(c.expect.vkB64);
        expect(result.value.from, c.name).toBe(c.expect.from);
        expect(result.value.grantId, c.name).toBe(c.expect.grantId);
        expect(result.value.issuedAt, c.name).toBe(c.expect.issuedAt);
        expect([result.value.add.grantId, result.value.add.member, result.value.add.actor], c.name).toEqual([c.expect.grantId, account.userId, c.expect.from]);
        // The grant is bound to this account's LATEST add, the one record the state keeps for it.
        expect(result.value.add, c.name).toEqual(latestAddOf(replay!.state!, account.userId));
      }
    });
  });

  it("a grant this client builds opens for its recipient, and only with a verified log", async () => {
    const alice = v.accounts.alice;
    const bob = v.accounts.bob;
    const state = replayLog(v.vaultId, v.logs.base.frames.map(fromB64), null, NONE_HELD).state!;
    const add = latestAddOf(state, bob.userId)!;
    const { signKeypairFromSeed } = await import("../provider");
    const frame = signVaultGrant(signKeypairFromSeed(fromB64(alice.seedB64)), {
      from: alice.userId, to: bob.userId, toKey: bob.identityPubB64, vaultId: v.vaultId, grantId: add.grantId, issuedAt: 1_763_164_860_000, vk: fromB64(v.vkB64),
    });
    const box = boxKeypairFromSeed(fromB64(bob.seedB64));
    const me = { userId: bob.userId as string, identityPub: box.publicKey, identityPriv: box.privateKey };
    const sealed = sealVaultGrant(box.publicKey, frame);
    const opened = await openVaultGrant(me, v.vaultId, sealed, state);
    expect(opened.ok && toB64(opened.value.vk)).toBe(v.vkB64);
    const noLog = await openVaultGrant(me, v.vaultId, sealed, null);
    expect(noLog.ok ? "ok" : noLog.verdict).toBe("no_add_entry");
    expect(() => signVaultGrant(signKeypairFromSeed(fromB64(alice.seedB64)), {
      from: alice.userId, to: alice.userId, toKey: alice.identityPubB64, vaultId: v.vaultId, grantId: add.grantId, issuedAt: 1, vk: fromB64(v.vkB64),
    })).toThrow(); // from == to
  });
});
