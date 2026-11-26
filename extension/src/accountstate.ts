import { open } from "./crypto.ts";
import { isHex64, isUuid } from "./statement.ts";

/**
 * What the extension reads of the UVK-sealed account state (design 2026-11-15-onboarding-trust §5.4, §12.2
 * rule 1; spec 03 §3): the `vaults` records, for the genesis hash a shared-vault wrap's AD names, and the
 * `decision` of the `accepted` records. The extension never writes the document. It keeps, per origin and
 * account, its own memory of what it has opened: the highest in-blob `seq` (the high-water mark) and the
 * `vaults` records, merged by §5.4's rule so a later copy can never change a vault's genesis.
 *
 * Graded by `next/accountstate.json` (the merge rows whose `records` is ["vaults"], and the acceptance rows'
 * `extensionOpens`). LEAF module: no chrome.
 */

export interface VaultRecord {
  readonly genesisHash: string;
  readonly seq: number;
  readonly hash: string;
  /** A field a newer build wrote is kept as written (§5.4 "Edges"). */
  readonly [extra: string]: unknown;
}

export interface AcceptedRecord {
  readonly owner: string;
  readonly addSeq: number;
  readonly at: number;
  readonly decision: "accept" | "decline";
}

/** The parts of a decoded document the extension uses. */
export interface ExtAccountState {
  readonly seq: number;
  readonly vaults: Readonly<Record<string, VaultRecord>>;
  readonly accepted: Readonly<Record<string, AcceptedRecord>>;
  /** Records that failed their own shape and were dropped (the rest of the document is used). */
  readonly dropped: number;
}

const isInt = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0 && v < 2 ** 53;
const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** The AD of the account-state blob (spec 03 §3). */
export const adAccountState = (userId: string): Uint8Array => new TextEncoder().encode(`andvari/v1|account-state|${userId}`);

export type DecodeResult = { ok: true; state: ExtAccountState } | { ok: false; reason: "unopenable" | "refused" };

/**
 * Decode a document's plaintext for `userId` (§5.4): refused whole when it is not a JSON object, `v` is not
 * 2, `userId` is another account's, or `seq` is not an `int`; a map that is absent reads as empty; a
 * `vaults` or `accepted` record that fails its shape is dropped and counted.
 */
export function decodeAccountState(plaintext: string, userId: string): DecodeResult {
  let doc: unknown;
  try {
    doc = JSON.parse(plaintext);
  } catch {
    return { ok: false, reason: "refused" };
  }
  if (!isObject(doc) || doc.v !== 2 || doc.userId !== userId || !isInt(doc.seq)) return { ok: false, reason: "refused" };
  let dropped = 0;
  const vaults: Record<string, VaultRecord> = {};
  const accepted: Record<string, AcceptedRecord> = {};
  const rawVaults = doc.vaults === undefined ? {} : doc.vaults;
  const rawAccepted = doc.accepted === undefined ? {} : doc.accepted;
  if (!isObject(rawVaults) || !isObject(rawAccepted)) return { ok: false, reason: "refused" };
  for (const [vaultId, r] of Object.entries(rawVaults)) {
    if (isUuid(vaultId) && isObject(r) && typeof r.genesisHash === "string" && isHex64(r.genesisHash) && isInt(r.seq) && typeof r.hash === "string" && isHex64(r.hash)) {
      vaults[vaultId] = r as VaultRecord;
    } else dropped++;
  }
  for (const [vaultId, r] of Object.entries(rawAccepted)) {
    if (isUuid(vaultId) && isObject(r) && typeof r.owner === "string" && isUuid(r.owner) && isInt(r.addSeq) && isInt(r.at) && (r.decision === "accept" || r.decision === "decline")) {
      accepted[vaultId] = { owner: r.owner, addSeq: r.addSeq, at: r.at, decision: r.decision };
    } else dropped++;
  }
  return { ok: true, state: { seq: doc.seq, vaults, accepted, dropped } };
}

/** Open the served `sealedState` under the UVK with the account's AD, then decode it. */
export function openAccountState(sealed: Uint8Array, uvk: Uint8Array, userId: string): DecodeResult {
  let plain: Uint8Array;
  try {
    plain = open(uvk, sealed, adAccountState(userId));
  } catch {
    return { ok: false, reason: "unopenable" };
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(plain);
  } catch {
    return { ok: false, reason: "refused" };
  }
  return decodeAccountState(text, userId);
}

export interface VaultsMerge {
  readonly vaults: Record<string, VaultRecord>;
  /** Vaults whose served record names another genesis than the local one (the local record stays). */
  readonly genesisAnomalies: string[];
  /** Vaults with the same genesis and `seq` and another hash (the local record stays). */
  readonly forks: string[];
}

/**
 * The `vaults` merge of §5.4: `genesisHash` is immutable (a served record naming another genesis is an
 * anomaly, and the local record stays); otherwise the higher `seq` wins, whole; the same `seq` with another
 * hash is a fork, and the local record stays. A record present on one side only is taken.
 */
export function mergeVaults(local: Readonly<Record<string, VaultRecord>>, served: Readonly<Record<string, VaultRecord>>): VaultsMerge {
  const vaults: Record<string, VaultRecord> = { ...local };
  const genesisAnomalies: string[] = [];
  const forks: string[] = [];
  for (const [vaultId, s] of Object.entries(served)) {
    const l = local[vaultId];
    if (l === undefined) vaults[vaultId] = s;
    else if (l.genesisHash !== s.genesisHash) genesisAnomalies.push(vaultId);
    else if (s.seq > l.seq) vaults[vaultId] = s;
    else if (s.seq === l.seq && s.hash !== l.hash) forks.push(vaultId);
  }
  genesisAnomalies.sort();
  forks.sort();
  return { vaults, genesisAnomalies, forks };
}

/**
 * The served document against the high-water mark (spec 03 §3): a rollback when its in-blob `seq` is below
 * the mark, or when nothing is served after a document with a `seq` above 0 was opened. `highWater` null
 * means this extension has opened no document yet.
 */
export function isRollback(servedSeq: number | null, highWater: number | null): boolean {
  if (servedSeq === null) return highWater !== null && highWater > 0;
  return highWater !== null && servedSeq < highWater;
}

/** The extension's memory of the account state, per origin and account. */
export interface StateMemory {
  readonly highWater: number;
  readonly vaults: Readonly<Record<string, VaultRecord>>;
}

/** Decode a stored {@link StateMemory}, or null when it is damaged (the caller treats damage as a block, never as "none"). */
export function decodeStateMemory(raw: unknown): StateMemory | null {
  if (!isObject(raw) || !isInt(raw.highWater) || !isObject(raw.vaults)) return null;
  for (const [vaultId, r] of Object.entries(raw.vaults)) {
    if (!isUuid(vaultId) || !isObject(r) || typeof r.genesisHash !== "string" || !isHex64(r.genesisHash) || !isInt(r.seq) || typeof r.hash !== "string" || !isHex64(r.hash)) {
      return null;
    }
  }
  return { highWater: raw.highWater, vaults: raw.vaults as Record<string, VaultRecord> };
}

/**
 * What a read of the account state leaves the extension with: the records a shared-vault wrap may be opened
 * under (`usable`: null while the served copy is a rollback or nothing is served, so no shared-vault wrap
 * opens at all) and the memory to keep. The memory's mark only rises; its vault records merge by §5.4.
 */
export function applyServedState(memory: StateMemory | null, served: ExtAccountState | null): {
  usable: { vaults: Record<string, VaultRecord>; accepted: Readonly<Record<string, AcceptedRecord>> } | null;
  memory: StateMemory | null;
  rollback: boolean;
  genesisAnomalies: string[];
  forks: string[];
} {
  const rollback = isRollback(served?.seq ?? null, memory?.highWater ?? null);
  const merged = mergeVaults(memory?.vaults ?? {}, served?.vaults ?? {});
  const next: StateMemory | null =
    served === null && memory === null ? null : { highWater: Math.max(memory?.highWater ?? 0, served?.seq ?? 0), vaults: merged.vaults };
  const usable = served === null || rollback ? null : { vaults: merged.vaults, accepted: served.accepted };
  return { usable, memory: next, rollback, genesisAnomalies: merged.genesisAnomalies, forks: merged.forks };
}
