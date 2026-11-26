import { beforeAll, describe, expect, it, vi } from "vitest";
import { concat, toB64 } from "../bytes";
import { boxKeypairFromSeed, signKeypairFromSeed } from "../provider";
import { initSodium } from "../sodium";
import { encodeStatement } from "./codec";
import { frameHash, MAGIC } from "./frame";
import { ZERO_HASH } from "./grammar";
import { decodeVaultState, encodeVaultState, latestAddOf, NONE_HELD, replayLog, type VaultState, verifyLogEntry } from "./vaultlog";

/**
 * A replay costs one step per entry. It used to copy
 * the member map and the list of adds for every entry, so a log of n adds cost n squared: 8,000 adds
 * took seconds, and the list of adds never shrank, so add and leave cycles grew every member's stored
 * state for good.
 *
 * The signature check is stubbed out for this file ONLY, and the map from a signer key to its X25519
 * image is computed once per key and remembered. Both cost the same for every entry, so they add
 * nothing to the question asked here (how the cost grows with the log) and would drown the answer;
 * every other check, the hashing and the state transitions are the real ones. Nothing here asserts
 * seconds: two sizes are compared.
 */
vi.mock("../provider", async (importOriginal) => {
  const real = await importOriginal<typeof import("../provider")>();
  const images = new Map<string, Uint8Array>();
  return {
    ...real,
    signVerifyDetached: (): boolean => true,
    ed25519PkToCurve25519: (publicKey: Uint8Array): Uint8Array => {
      const id = String.fromCharCode(...publicKey);
      let image = images.get(id);
      if (image === undefined) {
        image = real.ed25519PkToCurve25519(publicKey);
        images.set(id, image);
      }
      return image.slice();
    },
  };
});

const VAULT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OWNER = "11111111-1111-4111-8111-111111111111";
const AT = "1763164800000";
const GRANT = "AAAAAAAAAAAAAAAAAAAAAA";
const uuid = (n: number): string => `00000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;

let signerPub: Uint8Array;
let ownerKey: string;

/** A replay of this file's vault on a client that holds no hash for any position. */
const replay = (frames: readonly Uint8Array[], from: VaultState | null = null) => replayLog(VAULT, frames, from, NONE_HELD);

beforeAll(async () => {
  await initSodium();
  const seed = new Uint8Array(32).fill(7);
  signerPub = signKeypairFromSeed(seed).publicKey;
  ownerKey = toB64(boxKeypairFromSeed(seed).publicKey);
});

/** A log under one key pair: every entry carries that signer, and each member is given that same key, so a `leave` binds too. */
class Log {
  readonly frames: Uint8Array[] = [];
  private prev = ZERO_HASH;

  constructor() {
    this.push({ kind: "genesis", actor: OWNER, ownerKey, vkCommit: "ab".repeat(32) });
  }

  private push(fields: Record<string, string>): void {
    const statement = encodeStatement("vault-log", { vaultId: VAULT, seq: String(this.frames.length), prev: this.prev, at: AT, ...fields });
    const frame = concat(MAGIC, Uint8Array.of(0x03), signerPub, new Uint8Array(64), statement);
    this.frames.push(frame);
    this.prev = frameHash(frame);
  }

  add(member: string): this {
    this.push({ kind: "add", actor: OWNER, member, memberKey: ownerKey, role: "reader", grantId: GRANT });
    return this;
  }

  leave(member: string): this {
    this.push({ kind: "leave", actor: member });
    return this;
  }

  remove(member: string): this {
    this.push({ kind: "remove", actor: OWNER, member });
    return this;
  }
}

/** The fastest of `runs` replays of `frames`, in milliseconds; each must verify every frame. */
function replayMs(frames: readonly Uint8Array[], runs: number): number {
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    const result = replay(frames);
    best = Math.min(best, performance.now() - t0);
    expect(result.verdict).toBeNull();
    expect(result.accepted).toBe(frames.length);
  }
  return best;
}

describe("replaying a long log", () => {
  it("20,000 entries replay in time that grows with the log, not with its square", () => {
    const small = new Log();
    for (let i = 1; i <= 2_000; i++) small.add(uuid(i));
    const big = new Log();
    for (let i = 1; i <= 20_000; i++) big.add(uuid(i));

    replayMs(small.frames, 2); // warm up
    const smallMs = replayMs(small.frames, 3);
    const bigMs = replayMs(big.frames, 2);
    // Ten times the entries: about ten times the work when a replay is linear, about a hundred when every entry
    // copies the state. The bound sits between the two with room on each side.
    expect(bigMs / smallMs, `2,000 entries in ${smallMs.toFixed(1)} ms, 20,000 in ${bigMs.toFixed(1)} ms`).toBeLessThan(30);

    const state = replay(big.frames.slice(0, 5_001)).state!;
    expect(Object.keys(state.members).length).toBe(5_001);
    expect(latestAddOf(state, uuid(5_000))?.seq).toBe(5_000);
  }, 120_000);

  it("add and leave cycles do not grow the state: one latest add per account", () => {
    const log = new Log();
    const member = uuid(1);
    for (let i = 0; i < 2_000; i++) log.add(member).leave(member);
    log.add(member).add(uuid(2)).remove(uuid(2));
    const state = replay(log.frames).state!;
    expect(state.head.seq).toBe(4_003);
    expect(Object.keys(state.latestAdds).sort()).toEqual([member, uuid(2)]);
    expect(latestAddOf(state, member)?.seq).toBe(4_001); // the latest add, not the first
    expect(state.members[member]?.addSeq).toBe(4_001);
    expect(latestAddOf(state, uuid(2))?.seq).toBe(4_002); // kept for an account that was removed: its grant answers `removed`
    expect(Object.keys(state.members).sort()).toEqual([OWNER, member].sort());
    const stored = encodeVaultState(state);
    expect(stored.length).toBeLessThan(2_000);
    expect(decodeVaultState(stored)).toEqual(state);
  }, 120_000);

  it("a replay and entry-by-entry verification reach the same state, and a refused frame changes nothing", () => {
    const log = new Log();
    for (let i = 1; i <= 40; i++) {
      log.add(uuid(i));
      if (i % 3 === 0) log.remove(uuid(i));
      if (i % 5 === 0 && (i - 1) % 3 !== 0) log.leave(uuid(i - 1)); // a member that is still one
    }
    let state: ReturnType<typeof replayLog>["state"] = null;
    for (const frame of log.frames) {
      const step = verifyLogEntry(VAULT, state, frame, NONE_HELD);
      expect(step.ok).toBe(true);
      if (step.ok) state = step.value.state;
    }
    const whole = replay(log.frames);
    expect(whole.state).toEqual(state);

    // The same frames with one that does not belong: the state is the one after the last good entry,
    // and it is the same state a replay of only the good entries gives.
    const cut = 25;
    const broken = [...log.frames.slice(0, cut), log.frames[cut + 1]!, ...log.frames.slice(cut + 1)];
    const partial = replay(broken);
    expect(partial.accepted).toBe(cut);
    expect(partial.verdict).toBe("bad_seq");
    expect(partial.state).toEqual(replay(log.frames.slice(0, cut)).state);
    // Replaying on from a state leaves that state as it was.
    const from = replay(log.frames.slice(0, cut)).state!;
    const before = encodeVaultState(from);
    expect(replay(log.frames.slice(cut), from).state).toEqual(whole.state);
    expect(encodeVaultState(from)).toBe(before);
    // Nothing applied: the very state that was given comes back.
    expect(replay([log.frames[0]!], from).state).toBe(from);
  });
});
