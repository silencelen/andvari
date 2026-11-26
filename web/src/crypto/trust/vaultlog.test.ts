import { beforeAll, describe, expect, it } from "vitest";
import { fromB64 } from "../bytes";
import { signKeypairFromSeed } from "../provider";
import { initSodium } from "../sodium";
import { compareCheckpoint } from "./checkpoints";
import { frameHash, splitFrame } from "./frame";
import { INT_CEILING } from "./grammar";
import {
  decodeVaultState, encodeVaultState, keyMatches, latestAddOf, logPosition, MAX_OFFER_WINDOW_MS, NONE_HELD, parseLogEntry, replayLog,
  signLogEntry, signLogEntryChecked, type VaultState, verifyLogEntry, vkCommit,
} from "./vaultlog";
import { expectSections, gradeEvery, gradeEveryAsync, vector } from "./vectors";

/**
 * The vault log of design 2026-11-15 §3.1–§3.4, graded off the SAME `vaultlog.json` core's
 * `VaultLogVectorTest` consumes: five chains with the state after every entry, one rejection per signer
 * rule and precondition of §3.3, the check order, the time rules (the clock-free row with
 * `at = 2^53 − 1` included), undefined signer keys, forks, the checkpoint comparison and `vkCommit`.
 */
const v = vector("vaultlog.json");
const vaultId: string = v.vaultId;
const chains: Record<string, { frameB64: string; hash: string; state: Record<string, unknown>; signer: string; statementUtf8: string; why: string }[]> =
  Object.fromEntries(v.chains.map((c: { name: string; entries: unknown[] }) => [c.name, c.entries]));
const framesOf = (chain: string, count: number): Uint8Array[] => chains[chain]!.slice(0, count).map((e) => fromB64(e.frameB64));

beforeAll(async () => {
  await initSodium();
});

// The chain rules alone, from the genesis, on a client that holds no hash for any position. The `forks`
// rows are the ones that hold something, and they say so where they call the verifier.
const replayAll = (vault: string, frames: readonly Uint8Array[]) => replayLog(vault, frames, null, NONE_HELD);
const verifyOne = (vault: string, prior: VaultState | null, frame: Uint8Array) => verifyLogEntry(vault, prior, frame, NONE_HELD);

/** The state as the vector writes it: §3.3's S, with `head.at` and null for "none". */
function vectorForm(s: VaultState) {
  return {
    vaultId: s.vaultId,
    head: { seq: s.head.seq, hash: s.head.hash, at: s.at },
    owner: s.owner,
    ownerKey: s.ownerKey,
    vkCommit: s.vkCommit,
    members: Object.fromEntries(Object.entries(s.members).map(([id, m]) => [id, { key: m.key, role: m.role }])),
    pending: s.pending,
    deleted: s.deleteId === null ? null : { deleteId: s.deleteId },
  };
}

describe("vaultlog.json", () => {
  it("constants match the file", () => {
    expect(MAX_OFFER_WINDOW_MS).toBe(v.offerMaxLifetimeMs);
    expect(INT_CEILING - 1).toBe(v.maxMs);
  });

  it("the file has the sections this suite grades, and no other", () => {
    expectSections(v, [
      "_about", "vaultId", "otherVaultId", "vkB64", "vkCommitHex", "offerMaxLifetimeMs", "maxMs", "accounts", "vkCommit", "chains", "reject", "forks",
      "checkpoints",
    ]);
    expectSections(v.vkCommit, ["derive", "check"]);
  });

  it("chains: every entry verifies and gives the expected state", () => {
    gradeEvery("vaultlog.chains", Object.entries(chains), ([name, entries]) => {
      let state: VaultState | null = null;
      gradeEvery(`vaultlog.chains.${name}`, entries, (e, i) => {
        const why = `${name}[${i}] ${e.why}`;
        const frame = fromB64(e.frameB64);
        const step = verifyOne(vaultId, state, frame);
        expect(step.ok, why).toBe(true);
        if (!step.ok) return;
        expect(step.value.hash, `${why}: H(frame)`).toBe(e.hash);
        expect(step.value.entry.seq, why).toBe(i);
        expect(vectorForm(step.value.state), why).toEqual(e.state);

        // The typed entry is the statement: signing it again with the row's signer gives the same bytes.
        const signer = signKeypairFromSeed(fromB64(v.accounts[e.signer].seedB64));
        expect(signLogEntry(signer, step.value.entry), `${why}: re-sign`).toEqual(frame);
        const parsed = parseLogEntry(frame);
        expect(parsed.ok && parsed.value.entry, why).toEqual(step.value.entry);
        const split = splitFrame(frame);
        expect(split.ok && new TextDecoder().decode(split.value.statement), why).toBe(e.statementUtf8);

        expect(step.value.state.genesisHash, why).toBe(entries[0]!.hash);
        expect(step.value.state.creator, why).toBe((entries[0]!.state as { owner: string }).owner);

        // A stored state restores to an equal one, and the log goes on from it.
        const restored = decodeVaultState(encodeVaultState(step.value.state));
        expect(restored, why).toEqual(step.value.state);
        state = restored;
      });
      const replay = replayAll(vaultId, entries.map((e) => fromB64(e.frameB64)));
      expect(replay.verdict, name).toBeNull();
      expect(replay.accepted, name).toBe(entries.length);
      expect(replay.state, name).toEqual(state);
    });
  });

  it("reject: every row gets its exact verdict, and the state stays", () => {
    gradeEvery("vaultlog.reject", v.reject, (r: any) => {
      const asVault: string = r.vaultId ?? vaultId;
      const before = replayAll(asVault, framesOf(r.chain, r.after));
      expect(before.verdict, `${r.name}: the entries before the row verify`).toBeNull();
      const result = verifyOne(asVault, before.state, fromB64(r.frameB64));
      expect(result.ok ? "ok" : result.verdict, `${r.name}: ${r.why}`).toBe(r.expect.verdict);

      const whole = replayAll(asVault, [...framesOf(r.chain, r.after), fromB64(r.frameB64)]);
      expect(whole.verdict, r.name).toBe(r.expect.verdict);
      expect(whole.accepted, r.name).toBe(r.after);
      expect(whole.state, r.name).toEqual(before.state);
    });
  });

  it("forks: a different valid entry at a seen position", () => {
    gradeEvery("vaultlog.forks", v.forks, (r: any) => {
      const seen = new Map<number, string>(r.seen.map((s: { seq: number; hash: string }) => [s.seq, s.hash]));
      // What this client holds for a position: the one place in this file where fork detection has something to detect.
      const replay = replayLog(vaultId, r.frames.map(fromB64), null, (seq) => seen.get(seq));
      if (r.expect.verdict === "ok") {
        expect(replay.verdict, r.name).toBeNull();
        expect(replay.accepted, r.name).toBe(r.frames.length);
      } else {
        expect(replay.verdict, `${r.name}: ${r.why}`).toBe(r.expect.verdict);
        expect(replay.accepted, `${r.name}: failedAt`).toBe(r.expect.failedAt);
      }
    });
  });

  it("checkpoints: a served chain against a held head", () => {
    gradeEvery("vaultlog.checkpoints", v.checkpoints, (r: any) => {
      const served: Uint8Array[] = r.frames.map(fromB64);
      expect(replayAll(vaultId, served).verdict, r.name).toBeNull();
      expect(compareCheckpoint(r.held, served.map(frameHash)), `${r.name}: ${r.why}`).toBe(r.expect.verdict);
    });
  });

  it("vkCommit: derive and check", async () => {
    await gradeEveryAsync("vaultlog.vkCommit.derive", v.vkCommit.derive, async (r: any) => {
      expect(await vkCommit(fromB64(r.vkB64), r.vaultId), r.why).toBe(r.vkCommit);
    });
    await gradeEveryAsync("vaultlog.vkCommit.check", v.vkCommit.check, async (r: any) => {
      expect(await keyMatches(r.vaultId, r.vkCommit, fromB64(r.candidateVkB64)), r.why).toBe(r.matches);
    });
    const state = replayAll(vaultId, framesOf("lifecycle", 1)).state!;
    expect(state.vkCommit).toBe(v.vkCommitHex);
    expect(await keyMatches(state.vaultId, state.vkCommit, fromB64(v.vkB64))).toBe(true);
    expect(await keyMatches(state.vaultId, state.vkCommit, new Uint8Array(32))).toBe(false);
    expect(await keyMatches(state.vaultId, state.vkCommit, new Uint8Array(31))).toBe(false);
  });

  it("the builders sign only what this client would accept", () => {
    const alice = signKeypairFromSeed(fromB64(v.accounts.alice.seedB64));
    const bob = signKeypairFromSeed(fromB64(v.accounts.bob.seedB64));
    const state = replayAll(vaultId, framesOf("lifecycle", 1)).state!;
    const p = logPosition(state, state.at - 60_000);
    expect(p).toEqual({ seq: 1, prev: state.head.hash, at: state.at }); // a slow clock never deadlocks the vault

    const owner = state.owner;
    const remove = { kind: "remove", vaultId, seq: p.seq, prev: p.prev, actor: owner, at: p.at, member: v.accounts.bob.userId } as const;
    const refusedRow = signLogEntryChecked(alice, state, remove);
    expect(refusedRow.ok ? "ok" : refusedRow.verdict).toBe("precondition"); // bob is not a member yet
    const add = { kind: "add", vaultId, seq: p.seq, prev: p.prev, actor: owner, at: p.at, member: v.accounts.bob.userId, memberKey: v.accounts.bob.identityPubB64, role: "reader", grantId: "AAAAAAAAAAAAAAAAAAAAAA" } as const;
    const byBob = signLogEntryChecked(bob, state, { ...add, actor: v.accounts.bob.userId });
    expect(byBob.ok ? "ok" : byBob.verdict).toBe("not_authorized");
    const good = signLogEntryChecked(alice, state, add);
    expect(good.ok).toBe(true);
    if (good.ok) {
      expect(good.value.step.state.members[v.accounts.bob.userId]).toEqual({ key: v.accounts.bob.identityPubB64, role: "reader", addSeq: 1 });
      expect(good.value.step.state.members[owner]!.addSeq).toBeNull(); // the creator has no add (FN-2)
      expect(good.value.step.state.latestAdds).toEqual({
        [v.accounts.bob.userId]: { seq: 1, actor: owner, ownerKey: state.ownerKey, member: v.accounts.bob.userId, memberKey: v.accounts.bob.identityPubB64, role: "reader", grantId: add.grantId },
      });
      expect(latestAddOf(good.value.step.state, v.accounts.bob.userId)?.seq).toBe(1);
      expect(latestAddOf(good.value.step.state, owner)).toBeNull();
    }
    expect(() => signLogEntry(alice, { ...add, seq: 0 })).toThrow(); // seq 0 is the genesis's
    expect(() => signLogEntry(alice, { ...add, at: 1.5 })).toThrow();
    expect(() => signLogEntry(alice, { ...add, member: 'x","y":"z' })).toThrow();
  });

  it("a stored state is refused unless it is exactly what this client wrote", () => {
    const state = replayAll(vaultId, framesOf("lifecycle", 4)).state!;
    const text = encodeVaultState(state);
    expect(decodeVaultState(text)).toEqual(state);
    expect(decodeVaultState("")).toBeNull();
    expect(decodeVaultState("{}")).toBeNull();
    expect(decodeVaultState(text.replace('"v":2', '"v":3'))).toBeNull();
    // The form of an earlier build (version 1, which kept every add in `adds`) is not read: the log is replayed.
    expect(decodeVaultState(text.replace('"v":2', '"v":1'))).toBeNull();
    expect(decodeVaultState(text.replace('"v":2', '"v":1').replace(/"latestAdds":\{.*\}\}$/, '"adds":[]}'))).toBeNull();
    // A member whose add record is missing, or names another seq, is not a state this client wrote.
    const bob = v.accounts.bob.userId as string;
    expect(state.members[bob]!.addSeq).toBe(1);
    expect(decodeVaultState(text.replace(`"${bob}":{"key":"${state.members[bob]!.key}","role":"writer","addSeq":1}`, `"${bob}":{"key":"${state.members[bob]!.key}","role":"writer","addSeq":2}`))).toBeNull();
    expect(decodeVaultState(text.replace(vaultId, "not-a-uuid"))).toBeNull();
    expect(decodeVaultState(text.replace(state.ownerKey, v.accounts.eve.identityPubB64))).toBeNull(); // only the first: the owner member keeps its key
    expect(decodeVaultState(text.slice(0, -1) + ',"extra":1}')).toBeNull();
  });

  // The brand on a state is a type, and a type is erased at
  // run time. What keeps a verified state verified is that no caller can change it, at any level.
  it("a verified state cannot be changed at any level, whichever function gave it", () => {
    // A position with members beside the owner, an add record and a pending offer, found in the file.
    const at = (() => {
      for (const [name, entries] of Object.entries(chains)) {
        const i = entries.findIndex((e) => e.state.pending !== null && Object.keys(e.state.members as object).length > 1);
        if (i >= 0) return { name, count: i + 1 };
      }
      throw new Error("no chain entry with a pending offer and a second member");
    })();
    const frames = framesOf(at.name, at.count);
    const replayed = replayAll(vaultId, frames).state!;
    const stepped = (() => {
      const before = replayAll(vaultId, frames.slice(0, -1)).state;
      const step = verifyOne(vaultId, before, frames[frames.length - 1]!);
      if (!step.ok) throw new Error(step.verdict);
      expect(Object.isFrozen(step.value)).toBe(true);
      expect(Object.isFrozen(step.value.entry)).toBe(true);
      return step.value.state;
    })();
    const restored = decodeVaultState(encodeVaultState(replayed))!;
    const eve = { userId: v.accounts.eve.userId as string, key: v.accounts.eve.identityPubB64 as string };

    for (const [how, state] of Object.entries({ replayed, stepped, restored })) {
      const stored = encodeVaultState(state);
      const member = Object.keys(state.members).find((id) => id !== state.owner)!;
      const added = Object.keys(state.latestAdds)[0]!;
      expect(state.pending, how).not.toBeNull();
      const open = state as any; // what a caller without the types sees
      const changes: Record<string, () => void> = {
        "the owner": () => { open.owner = eve.userId; },
        "the owner key": () => { open.ownerKey = eve.key; },
        "the head": () => { open.head = { seq: 0, hash: "00".repeat(32) }; },
        "the head's hash": () => { open.head.hash = "00".repeat(32); },
        "the head's seq": () => { open.head.seq = 0; },
        "a new member": () => { open.members[eve.userId] = { key: eve.key, role: "writer", addSeq: 1 }; },
        "a member's role": () => { open.members[member].role = "owner"; },
        "a member's key": () => { open.members[member].key = eve.key; },
        "a member removed": () => { delete open.members[member]; },
        "the member map": () => { open.members = {}; },
        "a new add record": () => { open.latestAdds[eve.userId] = { ...open.latestAdds[added], member: eve.userId }; },
        "an add record's grant": () => { open.latestAdds[added].grantId = "AAAAAAAAAAAAAAAAAAAAAA"; },
        "an add record removed": () => { delete open.latestAdds[added]; },
        "the add records": () => { open.latestAdds = {}; },
        "the pending offer's recipient": () => { open.pending.to = eve.userId; },
        "the pending offer": () => { open.pending = null; },
        "the deletion": () => { open.deleteId = "AAAAAAAAAAAAAAAAAAAAAA"; },
        "a new field": () => { open.extra = 1; },
      };
      for (const [what, change] of Object.entries(changes)) expect(change, `${how}: ${what}`).toThrow(TypeError);
      expect(encodeVaultState(state), how).toBe(stored);
      expect(eve.userId in state.members, how).toBe(false);
    }
    // A replay that goes on from a state hands back a new one and leaves the first as it was.
    const earlier = replayAll(vaultId, frames.slice(0, 1)).state!;
    const stored = encodeVaultState(earlier);
    const later = replayLog(vaultId, frames.slice(1), earlier, NONE_HELD).state!;
    expect(later).toEqual(replayed);
    expect(encodeVaultState(earlier)).toBe(stored);
  });

  it("fork detection is never off by default: a caller says what it holds", () => {
    const frames = framesOf("lifecycle", 3);
    for (const seq of [0, 1, 2 ** 53 - 1]) expect(NONE_HELD(seq)).toBeNull();
    // The same log, held by a client that has another hash for position 1, and by one that holds none.
    const other = "ab".repeat(32);
    const holdingAnother = replayLog(vaultId, frames, null, (seq) => (seq === 1 ? other : null));
    expect([holdingAnother.verdict, holdingAnother.accepted]).toEqual(["fork", 1]);
    expect(replayLog(vaultId, frames, null, NONE_HELD).verdict).toBeNull();
    const first = verifyLogEntry(vaultId, null, frames[0]!, () => other);
    expect(first.ok ? "ok" : first.verdict).toBe("fork");

    // Leaving it out does not compile, and a caller without the types is refused before any frame is read
    // (a frame that fails earlier than the fork check included).
    // @ts-expect-error `known` has no default
    expect(() => replayLog(vaultId, frames, null)).toThrow();
    // @ts-expect-error `from` and `known` have no default
    expect(() => replayLog(vaultId, frames)).toThrow();
    // @ts-expect-error `known` has no default
    expect(() => verifyLogEntry(vaultId, null, frames[0]!)).toThrow();
    // @ts-expect-error `known` has no default
    expect(() => verifyLogEntry(vaultId, null, new Uint8Array(3))).toThrow();
    // @ts-expect-error `known` has no default
    expect(() => replayLog(vaultId, [], null)).toThrow();
  });
});
