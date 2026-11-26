import { adVkShared } from "../crypto/ad";
import { fromB64 } from "../crypto/bytes";
import { open } from "../crypto/envelope";
import { compareCheckpoint } from "../crypto/trust/checkpoints";
import type { OpenedGrant } from "../crypto/trust/grant";
import { keyMatches, latestAddOf, type VaultState } from "../crypto/trust/vaultlog";
import type { AcceptedRecord, VaultRecord } from "./accountdoc";
import type { LogStatus } from "./logstore";

/**
 * Design §3.6 for a key from this account's OWN wrap (an owner wrap or a member self-wrap), as one pure
 * decision graded by `wrapad.json` `adopt` (the full client's expectations). Behaviour twin of core
 * `AdoptionRules.checkWrap`. Every condition is evaluated and reported, except that a log that does not verify
 * ((a) fails) makes the others meaningless and is reported alone:
 *
 * - (a) the served log verifies ([state] is the twin's replay of it; null when it did not);
 * - (b) this account is in the verified members;
 * - (c) the key passes the commitment (checked only when a key was obtained);
 * - (d) the wrap opens under the AD that names THIS log's genesis hash, and either this account is the genesis
 *   owner with no `add` of itself in the log (FN-2), or an `accepted` record with `accept` answers its latest
 *   `add` (FC-7, FS-R6);
 * - (e) the account's vault record agrees: the same genesis, and the served chain holds its hash at its seq.
 *   No record passes (T2-R-d). When (e) alone fails and the record names the served chain's genesis, the key is
 *   still taken read-only where the log store's status ([log]) calls the vault withheld with the record above the
 *   served head, or frozen at a place after the genesis ({@link readOnlyStanding}, decided on 23 November 2026); in
 *   every other way (e) can fail it refuses. Nothing lowers the record: it stays the account's lower bound.
 *
 * A key from a grant (§3.6 (d) third bullet) is {@link checkGrant}: it needs the `add`'s actor to be a contact
 * that is CURRENT on this browser. The web makes no contacts (§13), but a contact from account state becomes
 * current here when the person confirms it (§6.9 (c), or the one-tap list of §8.5 (d); vault/contactbook.ts).
 */
export type AdoptCondition = "a" | "b" | "c" | "d" | "e";

/**
 * How the account's vault record stands against the served chain when (e) fails in one of the two ways that still give
 * a read-only key (core `RecordStanding`). Both need the record to name the served chain's own genesis.
 *
 * - `ahead`: the record is above the served head, and nothing the browser holds contradicts the served chain (the log
 *   store calls the vault withheld). An honest restore of the server from an earlier day looks like this.
 * - `fork`: the served chain carries another entry at a place, after the genesis, that the record or the browser's own
 *   log knows (the log store calls the vault frozen).
 */
export type RecordStanding = "ahead" | "fork";

/** The log store's status of the vault, as far as the rule reads it: its kind, its vault, and where a frozen one froze. */
export type AdoptionLogStatus = Pick<LogStatus, "kind" | "vaultId"> & { readonly atSeq?: number };

/**
 * The outcome of a check: the key when every condition holds, else every failing condition. [readOnly] is set when (e)
 * alone failed, in one of the ways {@link RecordStanding} names: the key is taken, and the vault is read-only in this
 * browser for as long as the log store calls it withheld or frozen (a frozen vault, for good).
 */
export type AdoptCheck =
  | { readonly adopt: true; readonly vk: Uint8Array; readonly source: "owner_wrap" | "self_wrap"; readonly readOnly: RecordStanding | null }
  | { readonly adopt: false; readonly failed: readonly AdoptCondition[] };

/**
 * Whether a failing (e) still gives a read-only key, judged from the record, the served chain ([state],
 * [servedHashes]: the verified replay of it) and the log store's status of the vault ([log]). Core
 * `AdoptionRules.readOnlyStanding` twin:
 *
 * - never without a record or a status, nor when the record, or the served chain's first entry, names another genesis
 *   than the verified state's (another chain under the same id is not this vault's chain);
 * - `ahead` when the log is withheld and the served chain ends below the record;
 * - `fork` when the log is frozen at a place after the genesis that the verified state has not reached, and the record
 *   is not on the served chain;
 * - otherwise null: (e) refuses as before.
 */
export function readOnlyStanding(state: VaultState, servedHashes: readonly string[], record: VaultRecord | VaultRecordFields | null, log: AdoptionLogStatus | null): RecordStanding | null {
  if (record === null || log === null || log.vaultId !== state.vaultId) return null;
  if (record.genesisHash !== state.genesisHash || servedHashes[0] !== state.genesisHash) return null;
  const verdict = compareCheckpoint({ seq: record.seq, hash: record.hash }, servedHashes);
  if (log.kind === "withheld" && verdict === "withheld") return "ahead";
  if (log.kind === "frozen" && log.atSeq !== undefined && log.atSeq >= 1 && log.atSeq > state.head.seq && verdict !== "ok") return "fork";
  return null;
}

/** How (e) failed, by the names a refusal gives it (core `AdoptionRefusal.RECORD_*`). */
export type RecordRefusal = "record_ahead" | "record_fork" | "record_genesis_mismatch";

/**
 * The refusal that names how (e) failed, core `AdoptionRules.recordRefusal` twin: `record_genesis_mismatch` when the
 * record names another genesis than the served chain's (or the log froze at the genesis); `record_fork` when the log is
 * frozen after the genesis or the served chain holds another hash at the record's place; `record_ahead` when the served
 * chain ends below the record.
 */
export function recordRefusal(state: VaultState, servedHashes: readonly string[], record: VaultRecord | VaultRecordFields | null, log: AdoptionLogStatus | null): RecordRefusal {
  if (record === null || record.genesisHash !== state.genesisHash) return "record_genesis_mismatch";
  const verdict = compareCheckpoint({ seq: record.seq, hash: record.hash }, servedHashes);
  if (log !== null && log.kind === "frozen" && log.atSeq === 0) return "record_genesis_mismatch";
  if ((log !== null && log.kind === "frozen") || verdict === "fork") return "record_fork";
  if (verdict === "withheld") return "record_ahead";
  return "record_genesis_mismatch";
}

/** {@link readOnlyStanding} when (e) is the one failing condition and a key was obtained; otherwise null. */
function readOnlyWhenOnlyRecordFails(
  failed: ReadonlySet<AdoptCondition>,
  vk: Uint8Array | null,
  state: VaultState,
  servedHashes: readonly string[],
  record: VaultRecord | VaultRecordFields | null,
  log: AdoptionLogStatus | null,
): RecordStanding | null {
  return vk !== null && failed.size === 1 && failed.has("e") ? readOnlyStanding(state, servedHashes, record, log) : null;
}

/** The seq of this account's latest `add` in the verified log, or null when the log has none. */
export function latestAddSeq(state: VaultState, me: string): number | null {
  return latestAddOf(state, me)?.seq ?? null;
}

/** (e): no record passes; otherwise the same genesis, and the served chain has the record's hash at its seq. */
export function recordAgrees(state: VaultState, servedHashes: readonly string[], record: VaultRecord | VaultRecordFields | null): boolean {
  if (record === null) return true;
  if (record.genesisHash !== state.genesisHash) return false;
  return compareCheckpoint({ seq: record.seq, hash: record.hash }, servedHashes) === "ok";
}

/** A vault record's three fields, without the extras (the vectors hand records in this form). */
export interface VaultRecordFields {
  readonly genesisHash: string;
  readonly seq: number;
  readonly hash: string;
}

export async function checkWrap(
  me: string,
  uvk: Uint8Array,
  state: VaultState | null,
  servedHashes: readonly string[],
  wrappedVkB64: string | null,
  record: VaultRecord | VaultRecordFields | null,
  accepted: Pick<AcceptedRecord, "addSeq" | "decision"> | null,
  log: AdoptionLogStatus | null = null,
): Promise<AdoptCheck> {
  if (state === null) return { adopt: false, failed: ["a"] };
  const failed = new Set<AdoptCondition>();
  if (!Object.prototype.hasOwnProperty.call(state.members, me)) failed.add("b");
  let vk: Uint8Array | null = null;
  if (wrappedVkB64 !== null) {
    try {
      vk = open(uvk, fromB64(wrappedVkB64), adVkShared(state.vaultId, me, state.genesisHash));
      if (vk.length !== 32) vk = null;
    } catch {
      vk = null;
    }
  }
  if (vk !== null && !(await keyMatches(state.vaultId, state.vkCommit, vk))) failed.add("c");
  const latest = latestAddSeq(state, me);
  const genesisOwner = me === state.creator && latest === null;
  const answered = latest !== null && accepted !== null && accepted.decision === "accept" && accepted.addSeq === latest;
  if (vk === null || !(genesisOwner || answered)) failed.add("d");
  if (!recordAgrees(state, servedHashes, record)) failed.add("e");
  const readOnly = readOnlyWhenOnlyRecordFails(failed, vk, state, servedHashes, record, log);
  if ((failed.size > 0 && readOnly === null) || vk === null) {
    vk?.fill(0);
    return { adopt: false, failed: [...failed].sort() };
  }
  return { adopt: true, vk, source: me === state.owner ? "owner_wrap" : "self_wrap", readOnly };
}

export type GrantAdoptCheck =
  | { readonly adopt: true; readonly vk: Uint8Array; readonly source: "grant"; readonly readOnly: RecordStanding | null }
  | { readonly adopt: false; readonly failed: readonly AdoptCondition[] };

/**
 * Design §3.6 for a key from a grant the twin opened and bound to an `add` ([grant]; §3.5's ten checks are the
 * twin's, crypto/trust/grant.ts). Behaviour twin of core `AdoptionRules.checkGrant`:
 *
 * - (a), (b), (c), (e) as for a wrap, the read-only standing of a failing (e) included ([log]);
 * - (d) the `add`'s actor is a contact CURRENT on this browser with the owner key the log names at that entry
 *   ([actorIsCurrentContact], §6.9), the grant answers THIS account's latest `add`, and an `accepted` record with
 *   `accept` answers that same `add` (T-R4, FS-R6): a grant is never adopted unasked, and a re-add asks again.
 *
 * A copy of the grant's key is returned on adoption; the caller wipes the opened grant either way.
 */
export async function checkGrant(
  me: string,
  state: VaultState | null,
  servedHashes: readonly string[],
  grant: Pick<OpenedGrant, "vk" | "add"> | null,
  actorIsCurrentContact: boolean,
  record: VaultRecord | VaultRecordFields | null,
  accepted: Pick<AcceptedRecord, "addSeq" | "decision"> | null,
  log: AdoptionLogStatus | null = null,
): Promise<GrantAdoptCheck> {
  if (state === null) return { adopt: false, failed: ["a"] };
  const failed = new Set<AdoptCondition>();
  if (!Object.prototype.hasOwnProperty.call(state.members, me)) failed.add("b");
  const vk = grant?.vk ?? null;
  if (vk !== null && (vk.length !== 32 || !(await keyMatches(state.vaultId, state.vkCommit, vk)))) failed.add("c");
  const latest = latestAddSeq(state, me);
  const answered = latest !== null && grant !== null && grant.add.seq === latest && accepted !== null && accepted.decision === "accept" && accepted.addSeq === latest;
  if (vk === null || !actorIsCurrentContact || !answered) failed.add("d");
  if (!recordAgrees(state, servedHashes, record)) failed.add("e");
  const readOnly = readOnlyWhenOnlyRecordFails(failed, vk, state, servedHashes, record, log);
  if ((failed.size > 0 && readOnly === null) || vk === null) return { adopt: false, failed: [...failed].sort() };
  return { adopt: true, vk: vk.slice(), source: "grant", readOnly };
}
