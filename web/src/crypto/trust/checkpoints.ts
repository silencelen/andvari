/**
 * Comparing a served chain with a held head (design 2026-11-15 §2.4 "Checkpoints", VR-17; §3.9, §4.4):
 * ONE pure function for vault logs and card chains, shared with core `Checkpoints` and graded by
 * `vaultlog.json` and `instancecard.json`. It compares hashes only; whether the served entries VERIFY
 * is the verifier's question, and a client asks both.
 */

/** A `{seq, hash}` head a client HOLDS for a chain it verified. */
export interface Checkpoint {
  readonly seq: number;
  readonly hash: string;
}

export type CheckpointVerdict = "ok" | "withheld" | "fork";

/**
 * `held` against a chain served from its start (`servedHashes[i]` is the frame hash of the entry with
 * `seq = i`): `withheld` when the chain ends below `held.seq` (or nothing was served), `fork` when it
 * has another hash at `held.seq`, `ok` otherwise.
 */
export function compareCheckpoint(held: Checkpoint, servedHashes: readonly string[]): CheckpointVerdict {
  if (servedHashes.length <= held.seq) return "withheld";
  return servedHashes[held.seq] === held.hash ? "ok" : "fork";
}

/**
 * The card form (§4.4, §2.4 "Pinning"): a pinned card of the chain whose card 0 hashes to `card0Hash`.
 * No card served is `withheld`. A served card 0 that is not `card0Hash` is a `fork`, HOWEVER SHORT the
 * served chain is: it is another chain (an operator reset under the same `instanceId`, or another
 * instance), and `withheld` is only the SAME chain ending below the pin.
 */
export function compareCardPin(card0Hash: string, held: Checkpoint, servedHashes: readonly string[]): CheckpointVerdict {
  if (servedHashes.length === 0) return "withheld";
  if (servedHashes[0] !== card0Hash) return "fork";
  return compareCheckpoint(held, servedHashes);
}
