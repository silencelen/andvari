package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.state.AcceptedRecord
import io.silencelen.andvari.core.client.state.VaultRecord
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.trust.Checkpoint
import io.silencelen.andvari.core.trust.CheckpointVerdict
import io.silencelen.andvari.core.trust.Checkpoints
import io.silencelen.andvari.core.trust.OpenedGrant
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.core.trust.VaultState

/** The conditions of design §3.6, by the letters the design gives them. */
enum class AdoptCondition(val letter: String) { LOG("a"), MEMBER("b"), COMMIT("c"), SOURCE("d"), RECORD("e") }

/**
 * How the account's vault record stands against the served chain when (e) fails in one of the two ways that still give a
 * read-only key (design §3.6 (e), decided on 23 November 2026). Both need the record to name the served chain's own
 * genesis.
 *
 * - [AHEAD]: the record is above the served head, and nothing the device holds contradicts the served chain (the log
 *   engine calls the vault withheld). An honest restore of the server from an earlier day looks like this.
 * - [FORK]: the served chain carries another entry at a place, after the genesis, that the record or the device's own log
 *   knows (the log engine calls the vault frozen).
 */
enum class RecordStanding { AHEAD, FORK }

/**
 * The outcome of [AdoptionRules.check]: the key when every condition holds, else every failing condition. [readOnly] is
 * set when (e) alone failed, in one of the ways [RecordStanding] names: the key is taken, and the vault is read-only on
 * this device for as long as the log engine calls it withheld or frozen (a frozen vault, for good).
 */
sealed class AdoptCheck {
    class Adopt(val vk: ByteArray, val source: KeySource, val readOnly: RecordStanding? = null) : AdoptCheck()
    data class Refuse(val failed: Set<AdoptCondition>) : AdoptCheck()
}

/**
 * Design §3.6 as one pure function, graded by `wrapad.json` (`adopt`) and, for grants,
 * `next/sharedgrant-v2.json`. Every condition is evaluated and reported, except that a log that does not
 * verify ((a) fails) makes the others meaningless and is reported alone.
 *
 * - (a) the served log verifies ([state] is the shared verifier's replay of it; null when it did not);
 * - (b) this account is in the verified members;
 * - (c) the key passes the commitment `vkCommit` (only checked when a key was obtained);
 * - (d) the key's source: this account's own wrap opening under the AD that names THIS log's genesis
 *   hash, and either the genesis-owner path (the creator, with no `add` of itself in the log, FN-2) or an
 *   `accepted` record with `accept` that answers its latest `add` (FC-7, FS-R6); or a grant from a
 *   current contact (the `add`'s actor) that the person accepted for that same latest `add`;
 * - (e) the account's vault record agrees: same genesis, and the served chain holds its hash at its
 *   `seq` ([Checkpoints.compare]). No record passes (T2-R-d). When (e) alone fails and the record names the served
 *   chain's genesis, the key is still taken read-only where the log engine's status ([log]) calls the vault withheld
 *   with the record above the served head, or frozen at a place after the genesis ([readOnlyStanding]); in every other
 *   way (e) can fail it refuses. Nothing lowers the record: it stays the account's lower bound.
 *
 * Trust: nothing served decides anything here except through the shared verifier's verified [state]; the wrap is opened
 * under the account's UVK, so the server can only withhold or replay one.
 */
object AdoptionRules {
    /** A key from this account's own owner wrap or member self-wrap ([wrappedVkB64], under [uvk]). */
    fun checkWrap(
        crypto: CryptoProvider,
        me: String,
        uvk: ByteArray,
        state: VaultState?,
        servedHashes: List<String>,
        wrappedVkB64: String?,
        record: VaultRecord?,
        accepted: AcceptedRecord?,
        log: VaultLogStatus? = null,
    ): AdoptCheck {
        if (state == null) return AdoptCheck.Refuse(setOf(AdoptCondition.LOG))
        val failed = HashSet<AdoptCondition>()
        if (me !in state.members) failed += AdoptCondition.MEMBER
        val vk = wrappedVkB64?.let {
            runCatching { Envelope.openB64(crypto, uvk, it, Ad.vkShared(state.vaultId, me, state.genesisHash)) }.getOrNull()
        }
        if (vk != null && !VaultLog.keyMatches(crypto, state, vk)) failed += AdoptCondition.COMMIT
        val latestAdd = latestAddSeq(state, me)
        val genesisOwner = me == state.creator && latestAdd == null
        val answered = latestAdd != null && accepted != null && accepted.decision == AcceptedRecord.ACCEPT && accepted.addSeq == latestAdd
        if (vk == null || !(genesisOwner || answered)) failed += AdoptCondition.SOURCE
        if (!recordAgrees(state, servedHashes, record)) failed += AdoptCondition.RECORD
        val readOnly = readOnlyWhenOnlyRecordFails(failed, vk, state, servedHashes, record, log)
        if ((failed.isNotEmpty() && readOnly == null) || vk == null) {
            vk?.fill(0)
            return AdoptCheck.Refuse(failed)
        }
        return AdoptCheck.Adopt(vk, if (me == state.owner) KeySource.OWNER_WRAP else KeySource.SELF_WRAP, readOnly)
    }

    /**
     * A key from a grant the shared verifiers opened and bound to an `add` ([grant]; its log checks are theirs). The
     * `add`'s actor must be a current contact with the owner key the log names ([actorIsCurrentContact]),
     * and the person must have accepted THIS account's latest `add`: a grant for an earlier `add` still
     * opens after a remove and a re-add, but asks again.
     */
    fun checkGrant(
        crypto: CryptoProvider,
        me: String,
        state: VaultState?,
        servedHashes: List<String>,
        grant: OpenedGrant?,
        actorIsCurrentContact: Boolean,
        record: VaultRecord?,
        accepted: AcceptedRecord?,
        log: VaultLogStatus? = null,
    ): AdoptCheck {
        if (state == null) return AdoptCheck.Refuse(setOf(AdoptCondition.LOG))
        val failed = HashSet<AdoptCondition>()
        if (me !in state.members) failed += AdoptCondition.MEMBER
        val vk = grant?.vk
        if (vk != null && !VaultLog.keyMatches(crypto, state, vk)) failed += AdoptCondition.COMMIT
        val latestAdd = latestAddSeq(state, me)
        val answered = latestAdd != null && grant != null && grant.add.seq == latestAdd &&
            accepted != null && accepted.decision == AcceptedRecord.ACCEPT && accepted.addSeq == latestAdd
        if (vk == null || !actorIsCurrentContact || !answered) failed += AdoptCondition.SOURCE
        if (!recordAgrees(state, servedHashes, record)) failed += AdoptCondition.RECORD
        val readOnly = readOnlyWhenOnlyRecordFails(failed, vk, state, servedHashes, record, log)
        if ((failed.isNotEmpty() && readOnly == null) || vk == null) {
            vk?.fill(0)
            return AdoptCheck.Refuse(failed)
        }
        return AdoptCheck.Adopt(vk, KeySource.GRANT, readOnly)
    }

    /** [readOnlyStanding] when (e) is the one failing condition and a key was obtained; otherwise null. */
    private fun readOnlyWhenOnlyRecordFails(
        failed: Set<AdoptCondition>, vk: ByteArray?, state: VaultState, servedHashes: List<String>, record: VaultRecord?, log: VaultLogStatus?,
    ): RecordStanding? =
        if (vk != null && failed == setOf(AdoptCondition.RECORD)) readOnlyStanding(state, servedHashes, record, log) else null

    /**
     * Whether a failing (e) still gives a read-only key ([RecordStanding]), judged from the record, the served chain
     * ([state], [servedHashes]: the verified replay of it) and the log engine's status of the vault ([log]):
     *
     * - never without a record, nor when the record, or the served chain's first entry, names another genesis than the
     *   verified state's (another chain under the same id is not this vault's chain);
     * - [RecordStanding.AHEAD] when the log is withheld and the served chain ends below the record;
     * - [RecordStanding.FORK] when the log is frozen at a place after the genesis that the verified state has not reached,
     *   and the record is not on the served chain;
     * - otherwise null: (e) refuses as before.
     */
    fun readOnlyStanding(state: VaultState, servedHashes: List<String>, record: VaultRecord?, log: VaultLogStatus?): RecordStanding? {
        if (record == null || log == null || log.vaultId != state.vaultId) return null
        if (record.genesisHash != state.genesisHash || servedHashes.firstOrNull() != state.genesisHash) return null
        val verdict = Checkpoints.compare(Checkpoint(record.seq, record.hash), servedHashes)
        return when {
            log is VaultLogStatus.Withheld && verdict == CheckpointVerdict.WITHHELD -> RecordStanding.AHEAD
            log is VaultLogStatus.Frozen && log.seq >= 1 && log.seq > state.head.seq && verdict != CheckpointVerdict.OK -> RecordStanding.FORK
            else -> null
        }
    }

    /**
     * The refusal that names how (e) failed: [AdoptionRefusal.RECORD_GENESIS_MISMATCH] when the record names another
     * genesis than the served chain's; [AdoptionRefusal.RECORD_FORK] when the log is frozen after the genesis or the served
     * chain holds another hash at the record's place; [AdoptionRefusal.RECORD_AHEAD] when the served chain ends below the
     * record.
     */
    fun recordRefusal(state: VaultState, servedHashes: List<String>, record: VaultRecord?, log: VaultLogStatus?): AdoptionRefusal {
        if (record == null || record.genesisHash != state.genesisHash) return AdoptionRefusal.RECORD_GENESIS_MISMATCH
        val verdict = Checkpoints.compare(Checkpoint(record.seq, record.hash), servedHashes)
        return when {
            log is VaultLogStatus.Frozen && log.seq == 0L -> AdoptionRefusal.RECORD_GENESIS_MISMATCH
            log is VaultLogStatus.Frozen || verdict == CheckpointVerdict.FORK -> AdoptionRefusal.RECORD_FORK
            verdict == CheckpointVerdict.WITHHELD -> AdoptionRefusal.RECORD_AHEAD
            else -> AdoptionRefusal.RECORD_GENESIS_MISMATCH
        }
    }

    /** The `seq` of this account's latest `add` in the verified log, or null when the log has none. */
    fun latestAddSeq(state: VaultState, me: String): Long? = state.latestAdd(me)?.seq

    /** (e): no record passes; otherwise the same genesis, and the served chain has the record's hash at its seq. */
    fun recordAgrees(state: VaultState, servedHashes: List<String>, record: VaultRecord?): Boolean {
        if (record == null) return true
        if (record.genesisHash != state.genesisHash) return false
        return Checkpoints.compare(Checkpoint(record.seq, record.hash), servedHashes) == CheckpointVerdict.OK
    }

    /** `H(frame)` of each served frame, in order: what [recordAgrees] compares against. */
    fun hashes(crypto: CryptoProvider, frames: List<ByteArray>): List<String> = frames.map { Bytes.toHexLower(crypto.sha256(it)) }
}
