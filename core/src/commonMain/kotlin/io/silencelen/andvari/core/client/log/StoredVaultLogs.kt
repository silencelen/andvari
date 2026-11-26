package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.ORIGIN_STOPPED
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.state.AcceptedRecord
import io.silencelen.andvari.core.client.state.AccountMerge
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.client.state.VaultRecord
import io.silencelen.andvari.core.client.state.VaultRecordBatching
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.client.onboard.GuardedKey
import io.silencelen.andvari.core.client.onboard.GuardedKeyPair
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogDeleted
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.VaultMemberSummary
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.Checkpoint
import io.silencelen.andvari.core.trust.GrantFields
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.trust.LogKind
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.core.trust.SignedFrame
import io.silencelen.andvari.core.trust.VaultGrant
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.core.trust.VaultLogVerdict
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import io.silencelen.andvari.core.trust.VaultState
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer

/** What the vault-log engine needs from the rest of the client (the sync engine and the contact book). */
interface VaultLogHost {
    /** This account's own grant row for [vaultId] from the last sync, or null. */
    fun grantRow(vaultId: String): SyncGrant?

    /** True when [userId] is a contact CURRENT on this device with exactly [identityPub] (design §6.9). */
    fun isCurrentContact(userId: String, identityPub: String): Boolean

    /** The pinned key and the `compared` flag of a current contact, or null. */
    fun currentContact(userId: String): Pair<String, Boolean>?

    /** The label to show for a current contact (plain text), or null. */
    fun labelFor(userId: String, identityPub: String): String?

    /** Decrypt the vault's metadata name under [vk]; plain text, or null. Called only after (a)–(c) pass. */
    fun vaultName(vaultId: String, vk: ByteArray): String?

    /** The vault's encrypted metadata for a new vault ([vk], AD `andvari/v1|vaultmeta|…`). */
    fun sealMeta(vaultId: String, vk: ByteArray, name: String): String

    /** The name the server reports for the owner of an unconnected share, shown "as the server reports it". */
    fun serverOwnerName(vaultId: String): String?
}

/**
 * The vault-log engine (design §3): fetch and verify through the trust layer's [VaultLog], adoption by
 * [AdoptionRules], durable per-vault state in device state, the pending-append record, and the
 * account-state writer rules (vault records batched; `accepted` written at creation and on a verified
 * leave or remove of this account).
 *
 * Trust: a served head, `purged`, a grant row's role and the members list never become state; only
 * entries the shared verifier checked against the previous verified state move it. The account's vault record, the vault's
 * checkpoint from a device-link bundle and every hash this device has seen are passed to the verifier as known
 * hashes, so a different entry at one of those positions is a `fork`; the record and the checkpoint are lower
 * bounds too, so a served log that ends below either is withheld (design §3.9, §8.3).
 *
 * [bundleCheckpoint] answers the checkpoint a device-link bundle carried for a vault: the session layer wires it to
 * `BundleCheckpoints(state).get(origin, userId, vaultId)` (null on a device that was not linked).
 */
class StoredVaultLogs(
    private val me: String,
    private val signer: GuardedKeyPair,
    private val boxKeys: GuardedKeyPair,
    private val uvk: GuardedKey,
    private val client: WireClient,
    private val crypto: CryptoProvider,
    private val state: DeviceState,
    private val account: AccountStateStore,
    private val host: VaultLogHost,
    private val clock: () -> Long,
    private val bundleCheckpoint: (vaultId: String) -> Checkpoint?,
) : VaultLogEngine {
    @Serializable
    /**
     * A signed frame held until the server's word settles it. [notStored]: every send of it so far was answered
     * `429 rate_limited`, which the server answers before it looks at the frame, so it is known not stored (and may be
     * withdrawn). Every send clears it at rest before it leaves ([sends]); only that send's own "slow down" sets it again,
     * and a send without a known outcome leaves it cleared for good. An older record reads false.
     * [acked]: a send of it was answered `200` (the server's word that it took it) and the log as read does not hold it
     * yet. [namedSeq]/[namedHash]: the latest head a `409 log_head_moved` answer to it named, kept so that "not made" is
     * never said from a read that ends before it (a `200`'s head is [ackSeq]/[ackHash]). [heldAt]: the engine's clock when it was first held (an older
     * record is stamped the first time it is seen). [movesOwn]: signed by a move for its own run.
     */
    private data class Pending(
        val vaultId: String, val frame: String, val grant: String? = null, val wrappedVk: String? = null, val metaBlob: String? = null,
        val notStored: Boolean = false,
        val acked: Boolean = false,
        val namedSeq: Long? = null,
        val namedHash: String? = null,
        val heldAt: Long? = null,
        val movesOwn: Boolean = false,
        /** A deletion's read point ([LogAction.DeleteVault.itemsAtMost]): unsigned, sent beside the frame at every post. */
        val itemsAtMost: Long? = null,
        /**
         * How many sends of it were started, by any engine over this device's records. Each send writes the record "cannot
         * tell" with its own number before it leaves; a "slow down" makes it "known not stored" again only while the record
         * still carries that send's number (no send started after it) and every earlier send was answered so.
         */
        val sends: Long = 0,
        /**
         * The highest head a `200` answer to it named at or beyond its position ([acked]), in fields of its own: never
         * overwritten by a refusal's head ([namedSeq] is a `409`'s) nor taken away by a later answer naming a lower one. A
         * `200` naming a head below its position is no answer about it: it sets neither [acked] nor these. The server said it holds this frame at its position under that head, so a verified log
         * that does not hold the frame, with another entry at either position, contradicts the server's answer where the
         * head is at or beyond the frame ([contradiction]).
         */
        val ackSeq: Long? = null,
        val ackHash: String? = null,
        /**
         * An addition signed for a contact whose codes were not compared, at the person's word after the warning: sent again
         * only while that contact is current here with the same key ([letGoForContact]), compared or not. False for every
         * other record, an older one included: an addition is then sent again only while its contact is still compared.
         */
        val uncompared: Boolean = false,
    )

    /**
     * A change this device let go of while it may already be stored (withdrawn while its outcome could not be told, or
     * given up after a day): its signed entry's [hash] and [seq], what it was, and the head an answer to it named. Kept
     * while its position is free in the log as verified here; ends when the log holds it (a finding "made after all"),
     * when another entry takes its position, or when the vault's list is full (the oldest go first). Nothing sealed.
     */
    @Serializable
    private data class Watch(
        val hash: String, val seq: Long, val kind: String, val names: String? = null, val signedAt: Long, val why: String,
        val namedSeq: Long? = null, val namedHash: String? = null, val since: Long, val told: Boolean = false,
        /** The head a `200` answer to it named ([Pending.ackSeq]), also one that arrived after it was let go of. */
        val ackSeq: Long? = null, val ackHash: String? = null,
        /** As [HeldChange.memberKey] and [HeldFinding.roleBefore], when it was let go of (null in an older record). */
        val memberKey: String? = null, val roleBefore: String? = null,
    )

    /** A [HeldFinding] at rest, until the layer says it was shown. */
    @Serializable
    private data class Found(
        val id: String, val kind: String, val names: String? = null, val what: String, val letGo: String? = null,
        val final: Boolean = false, val absentAtRead: Boolean = false, val code: String? = null, val signedAt: Long, val at: Long,
        val memberKey: String? = null, val roleBefore: String? = null,
    )

    /** Per frame hash, how many requests of it are out from this engine now; and the frames whose FIRST request is out. */
    private val requestsOut = HashMap<String, Int>()
    private val firstOut = HashSet<String>()

    /** Per vault, how many reads of its log reached the server and verified to the head it served ([refresh]). */
    private val completeReads = HashMap<String, Long>()

    /**
     * The account's guard: the vault keys below were unwrapped from the account's keys, so they are read
     * and written under its guard and wiped with them, whoever wipes first.
     */
    private val guard = uvk.guard

    /** Where the mark that this account's records stand is kept ([LIVE_PART]). */
    private val liveKey = "ovh.log|$me|$LIVE_PART"

    /**
     * The mark this engine found (or wrote) when it began. Every record write checks that the records still carry it:
     * after [forgetAccount] they carry none (or a later engine's), and this engine writes nothing more. Null where the
     * store could not be read or written when the engine began: such an engine never takes a mark later (an account
     * forgotten meanwhile would get a new one), so it writes nothing and sends no write of the account's state.
     */
    private val liveToken: String? = try {
        synchronized(writeLock) { state.get(liveKey) ?: Bytes.toHexLower(crypto.randomBytes(16)).also { state.set(liveKey, it) } }
    } catch (e: Exception) {
        null
    }

    /**
     * Throws [LogStoreFaultException] where this engine could not establish its mark when it began, and
     * [AccountForgottenException] where the account's records were forgotten since (the mark is gone or another
     * engine's). Called under [writeLock].
     */
    private fun checkLiveLocked() {
        val mine = liveToken ?: throw LogStoreFaultException()
        if (state.get(liveKey) != mine) throw AccountForgottenException()
    }

    /** Before a write of the account's state on the server: nothing is sent for a forgotten account. */
    private fun checkLive() = synchronized(writeLock) { checkLiveLocked() }

    /** Every record this engine writes or removes, only while the account's records stand ([checkLiveLocked]). */
    private fun putRecord(key: String, value: String?) = synchronized(writeLock) {
        checkLiveLocked()
        state.set(key, value)
    }

    private val keys = HashMap<String, ByteArray>()

    /** Keys held for copy-out after a verified leave or remove ([hold]); never used for a write. */
    private val heldKeys = HashMap<String, ByteArray>()

    /**
     * True until the account state has been read since the last sync round told this engine anything: the answer
     * another device of the account recorded (`accepted`, design §3.6, §5.4) lives there, and this device's copy of it
     * is only as new as its last read. [adoption] reads it at most once per sync round, and only when a vault's latest
     * `add` has no answer in the copy held. A round is the sync's own pass: its [refresh] calls (not forced) all come
     * before its adoptions (`SessionVaultKeys.served`), so however many vaults wait for an answer, the first adoption
     * that needs one reads and the rest of the round (the app's own pass included) uses that copy. A forced refresh (a
     * hint chased while the round applies its items, a post drained, a screen's own look) does not start a round.
     */
    private var accountStale = true

    /** The account state's counter the current sync round's answer carried ([accountStateServed]); null when none. */
    private var roundCounter: Long? = null

    override fun accountStateServed(counter: Long?) {
        roundCounter = counter
    }

    /**
     * Whether this round may find the account state changed (spec 03 §4 `accountStateSeq`): always without a counter or
     * without one held here; with both, unless they are equal. A counter below the one held (a lie, or a server rolled
     * back) or far above it is read, never skipped.
     */
    private fun stateMayHaveMoved(): Boolean {
        val served = roundCounter ?: return true
        val held = account.heldCounter() ?: return true
        return served != held
    }

    /** This device's last self-wrap post for a vault: the grant row's rev when the server answered it, null when it did not, and when. */
    private class WrapPost(val rev: Long?, val at: Long)

    /** Per vault, the last self-wrap post this session made ([ensureSelfWrap]). */
    private val wrapPosts = HashMap<String, WrapPost>()

    init {
        guard.whenWiped { clearKeys() }
    }

    /** [vk] held as [vaultId]'s adopted key, under the guard; once the account is wiped it is zeroed and refused. */
    private fun putKey(vaultId: String, vk: ByteArray) {
        try {
            guard.use { keys.put(vaultId, vk)?.fill(0) }
        } catch (e: KeysGoneException) {
            vk.fill(0)
            throw e
        }
    }

    private fun k(vaultId: String, part: String) = recordKey(me, vaultId, part)

    private fun loadState(vaultId: String): VaultState? = state.get(k(vaultId, STATE_PART))?.let(VaultState::decode)?.takeIf { it.vaultId == vaultId }

    private fun loadHashes(vaultId: String): MutableMap<Long, String> = loadHashesOrNull(vaultId) ?: error("unreadable hashes")

    /** Every hash this device verified for [vaultId]: empty when none is stored, null when one is stored and cannot be read. */
    private fun loadHashesOrNull(vaultId: String): MutableMap<Long, String>? {
        val text = state.get(k(vaultId, "hashes")) ?: return HashMap()
        return runCatching { WireJson.json.decodeFromString(MapSerializer(Long.serializer(), String.serializer()), text) }.getOrNull()?.toMutableMap()
    }

    /**
     * True when every trust record this engine keeps for [vaultId] can be read (design §4.4 "A trust record that cannot
     * be read is not an empty one"): the verified hashes, the status flag, the pending record, the account's own copy
     * (its vault record is the log's lower bound) and the device-link bundle's checkpoint. When one cannot, the vault is
     * [VaultLogStatus.Failed] with [RECORD_UNREADABLE]: nothing is fetched, verified, signed or written for it, so no such
     * record is rebuilt from what the server serves. A stored state that does not decode is NOT such a record: the log is
     * replayed from the genesis against the held hashes and the lower bounds (an older state version decodes to null).
     */
    private fun readable(vaultId: String): Boolean = try {
        state.get(k(vaultId, "flag"))
        loadState(vaultId)
        val pending = state.get(k(vaultId, "pending"))
        bundleCheckpoint(vaultId)
        loadHashesOrNull(vaultId) != null && account.localReadable() && (pending == null || decodePending(pending) != null)
    } catch (e: Exception) {
        // A lock is not an unreadable record: it is said as itself.
        if (e is KeysGoneException) throw e
        false
    }

    private fun decodePending(text: String): Pending? = runCatching { WireJson.json.decodeFromString(Pending.serializer(), text) }.getOrNull()

    private fun saveVerified(s: VaultState, hashes: Map<Long, String>) {
        putRecord(k(s.vaultId, STATE_PART), s.encode())
        putRecord(k(s.vaultId, "hashes"), WireJson.json.encodeToString(MapSerializer(Long.serializer(), String.serializer()), hashes))
    }

    /** Status flags: "", "failed:<verdict>", "frozen:<seq>", "withheld:<seq>", "purged:<at>". Frozen is sticky. */
    private fun flag(vaultId: String): String = state.get(k(vaultId, "flag")) ?: ""
    private fun setFlag(vaultId: String, f: String) { if (!flag(vaultId).startsWith("frozen:")) putRecord(k(vaultId, "flag"), f.ifEmpty { null }) }

    override fun status(vaultId: String): VaultLogStatus {
        if (!readable(vaultId)) return VaultLogStatus.Failed(vaultId, null, RECORD_UNREADABLE)
        val s = loadState(vaultId) ?: return flag(vaultId).let { f ->
            if (f.startsWith("failed:")) VaultLogStatus.Failed(vaultId, null, f.removePrefix("failed:")) else VaultLogStatus.Unknown(vaultId)
        }
        val v = view(s)
        val f = flag(vaultId)
        return when {
            f.startsWith("frozen:") -> VaultLogStatus.Frozen(vaultId, v, f.removePrefix("frozen:").toLongOrNull() ?: s.head.seq)
            f.startsWith("failed:") -> VaultLogStatus.Failed(vaultId, v, f.removePrefix("failed:"))
            f.startsWith("withheld:") -> VaultLogStatus.Withheld(vaultId, v, f.removePrefix("withheld:").toLongOrNull())
            f.startsWith("purged:") -> VaultLogStatus.Purged(vaultId, v, f.removePrefix("purged:").toLongOrNull() ?: 0)
            me !in s.members -> VaultLogStatus.Removed(vaultId, v, state.get(k(vaultId, "removedBy")) == "owner")
            else -> VaultLogStatus.Verified(vaultId, v, state.get(k(vaultId, "hint")) != null)
        }
    }

    private fun view(s: VaultState) = VerifiedVaultState(
        s.vaultId, s.head.seq, s.head.hash, s.at, s.genesisHash, s.owner, s.ownerKey, s.vkCommit,
        s.members.mapValues { (id, m) -> LogMember(id, m.key, m.role.literal, m.addSeq) },
        s.pending?.let { PendingOffer(it.offerId, it.to, it.toKey, it.expiresAt) }, s.deleteId,
    )

    override suspend fun refresh(vaultId: String, servedSeq: Long?, servedHash: String?, force: Boolean): VaultLogStatus {
        // A stopped origin is not dialed (design §4.4); an unreadable record is not rebuilt from what is served.
        if (client.stopped || !readable(vaultId)) return status(vaultId)
        // Only a sync's own pass opens a new read of the account state, once for the whole round: a forced re-read of one
        // log (a hint chased, a post drained, a screen's own look) is not a sync round.
        // With the sync answer's counter, a round in which it stands where this device last saw it reads nothing (spec 03 §4).
        if (!force) accountStale = stateMayHaveMoved()
        var s = loadState(vaultId)
        val checkpoint = bundleCheckpoint(vaultId)
        // A checkpoint above the verified head is a lower bound the served log must still reach: no shortcut then.
        val belowCheckpoint = s != null && checkpoint != null && checkpoint.seq > s.head.seq
        // The account's vault record is a lower bound too (design §3.6 (e), §3.9): a record above the verified head, read
        // from the account's state after this device's last fetch, is one the served log must still reach. No shortcut then.
        val belowRecord = s != null && account.local().vaults[vaultId]?.let { it.genesisHash == s.genesisHash && it.seq > s.head.seq } == true
        // The served head is the verified head: nothing to fetch, unless the vault is withheld or failed, which ends only
        // when a fetch reaches the verified head again (design §3.9: re-checked at every sync while in either state).
        val stuck = flag(vaultId).let { it.startsWith("withheld:") || it.startsWith("failed:") }
        // A change withdrawn while its outcome could not be told, whose finding is not said yet: its log is read at every
        // look until one read reaches the server (CJ: the person is told what the read found).
        if (!force && !belowCheckpoint && !belowRecord && !stuck && s != null && servedSeq == s.head.seq && servedHash == s.head.hash && !untoldWithdrawal(vaultId)) {
            // Design §5.4: the batching interval limits the rate and cancels nothing; a deferred head is written now.
            if (guard.locked { keys.containsKey(vaultId) } || account.local().vaults[vaultId] != null) writeVaultRecord(s)
            ensureSelfWrap(s)
            resolveHint(vaultId)
            return status(vaultId)
        }
        val hashes = loadHashes(vaultId)
        val record = account.local().vaults[vaultId]
        val known = HashMap(hashes)
        if (record != null && s != null && record.genesisHash != s.genesisHash) { setFlag(vaultId, "frozen:0"); return status(vaultId) }
        record?.let { r -> if (r.seq !in known) known[r.seq] = r.hash }
        checkpoint?.let { c ->
            // Two heads this account's own devices verified name different entries at one position: a fork.
            val held = known[c.seq]
            if (held != null && held != c.hash) { setFlag(vaultId, "frozen:${c.seq}"); return status(vaultId) }
            known[c.seq] = c.hash
        }
        // Fetch every page after the verified head.
        var fetched = fetchFrom(vaultId, s?.head?.seq) ?: return status(vaultId)
        val servedAtHeld = known[fetched.second.head.seq]
        val besideHead = s != null && fetched.second.head.seq <= s.head.seq && servedAtHeld != null && servedAtHeld != fetched.second.head.hash
        // The first entry served after the verified head does not chain onto it: the served chain parted from this
        // device's at or before its head (a server put back from a backup, and written to since).
        val head = s?.head
        val departed = head != null && fetched.first.firstOrNull()?.let { VaultLog.parse(crypto, it).valueOrNull()?.entry }
            ?.let { it.seq == head.seq + 1 && it.prev != head.hash } == true
        if (besideHead || departed) {
            // The server names another entry at a position this device verified, or a chain that left it: replay from the
            // genesis with every held hash, so two validly signed entries at one position come out as `fork`. A read that
            // gets no answer leaves the log failed: it is not verified at the head this device holds.
            fetched = fetchFrom(vaultId, null) ?: run {
                setFlag(vaultId, "failed:${VaultLogVerdict.BAD_PREV.code}")
                return status(vaultId)
            }
            s = null
        }
        val frames = fetched.first
        val page = fetched.second
        lastServed[vaultId] = page.head
        val heldSeq = maxOf(s?.head?.seq ?: -1, known.keys.maxOrNull() ?: -1)
        // Verify the new entries in one replay (one step per entry, design §3.9), split only after an entry that takes this
        // account out of the vault: its decline record needs the verified state right after it, not the state at the end.
        val removedBefore = s != null && me !in s.members
        var from = 0
        while (from < frames.size) {
            val end = cutAfterOwnExit(frames, from)
            val chunk = frames.subList(from, end)
            val before = s
            val r = VaultLog.replay(crypto, vaultId, chunk, before, KnownHashes { known[it] })
            // The accepted frames sit at consecutive positions after the state they were replayed from.
            val first = (before?.head?.seq ?: -1L) + 1
            for (i in 0 until r.accepted) {
                val hash = SignedFrame.hash(crypto, chunk[i])
                hashes[first + i] = hash
                known[first + i] = hash
            }
            s = r.state
            val verdict = r.verdict
            if (verdict != null) {
                s?.let { saveVerified(it, hashes) }
                val at = (s?.head?.seq ?: -1L) + 1
                setFlag(vaultId, if (verdict == VaultLogVerdict.FORK) "frozen:$at" else "failed:${verdict.code}")
                if (verdict == VaultLogVerdict.FORK) dropHeldPastFork(vaultId, at, hashes)
                return status(vaultId)
            }
            // Every frame of the chunk verified, so its last entry (when it is this account's exit) is a verified one.
            val last = VaultLog.parse(crypto, chunk.last())
            if (last is Checked.Ok && isOwnExit(last.value.entry)) onVerifiedEntry(vaultId, last.value.entry, s!!)
            from = end
        }
        val verified = s ?: return status(vaultId)
        saveVerified(verified, hashes)
        if (verified.head.seq < heldSeq || page.head.seq < verified.head.seq) {
            setFlag(vaultId, "withheld:${page.head.seq}")
            return status(vaultId)
        }
        // A read that reached the server and verified to the head it served: what this device let go of is looked for.
        completeReads[vaultId] = (completeReads[vaultId] ?: 0) + 1
        checkWatches(vaultId, hashes)
        checkHeld(vaultId, hashes)
        val purged = page.purged
        setFlag(vaultId, if (purged != null && verified.isDeleted && page.head.seq == verified.head.seq) "purged:${purged.purgedAt}" else "")
        noteGrace(verified, page.head, page.deleted, replace = true)
        // The key leaves the adopted set (no write under it), and is held for copy-out of the holding area (spec 02 §10.6).
        if (!removedBefore && me !in verified.members) guard.locked { keys.remove(vaultId) }?.let { hold(verified, it) }
        // Design §3.6 (e): a record is written when this device adopts the vault or records the person's
        // answer, never because the server listed a log; once it exists it follows the verified head (batched).
        if (guard.locked { keys.containsKey(vaultId) } || account.local().vaults[vaultId] != null) writeVaultRecord(verified)
        if (flag(vaultId).isEmpty()) ensureSelfWrap(verified)
        resolveHint(vaultId)
        return status(vaultId)
    }

    /**
     * Design §3.6 "After adoption": the account's other devices adopt through this device's self-wrap. A post that did
     * not land (no answer, a refusal, an answer the server did not act on) would leave them without the vault until this
     * device next adopted it from the grant, which it never does while it holds the key. So while this device holds the
     * key of a vault it is a member (not the owner) of, and its own grant row as last synced carries no wrap, it posts
     * the wrap again. A post the server answered is not repeated while the row keeps that rev (the row it answered for
     * is still the one served), so a server that keeps serving the row without a wrap gets one post per change of the
     * row; an unanswered or refused post is tried again at a sync at least [WRAP_RETRY_MS] later, never at every sync.
     * The wrap is sealed under the account's guard; the key itself never leaves it.
     */
    private suspend fun ensureSelfWrap(s: VaultState) {
        if (s.owner == me || me !in s.members || s.isDeleted) return
        val row = host.grantRow(s.vaultId) ?: return
        if (row.userId != me || row.wrappedVk.isNotEmpty()) return
        val now = clock()
        val last = wrapPosts[s.vaultId]
        if (last != null && (last.rev == row.rev || (last.rev == null && now >= last.at && now - last.at < WRAP_RETRY_MS))) return
        val wrapped = guard.use { keys[s.vaultId]?.let { vk -> uvk.use { Envelope.sealB64(crypto, it, vk, Ad.vkShared(s.vaultId, me, s.genesisHash)) } } } ?: return
        wrapPosts[s.vaultId] = WrapPost(if (postWrapped(s.vaultId, wrapped)) row.rev else null, now)
    }

    /**
     * The account's copy of the person's answer to [vaultId]'s latest `add` ([latestAdd]), read from the server first when
     * the copy held has none and a sync came since the last read ([accountStale]): the answer may have been given on
     * another device of the account (design §3.6 "so the account's other devices do not ask again"). Served state is
     * merged, never adopted ([AccountStateStore.read]), so the server alone can only withhold an answer, never forge one.
     */
    private suspend fun answeredDoc(latestAdd: Long?, vaultId: String): io.silencelen.andvari.core.client.state.AccountDocument {
        val held = account.local()
        if (latestAdd == null || held.accepted[vaultId]?.addSeq == latestAdd) return held
        if (!accountStale || client.stopped || !account.localReadable()) return held
        accountStale = false
        account.read()
        return account.local()
    }

    /**
     * Design §5.4: a vault-record head the 10-minute batching deferred is written at the first sync, unlock or lock after
     * the interval, whether or not another entry arrives. The sync path does it in [refresh]; the session calls this at
     * unlock and at lock. Sends nothing under a stopped origin, and nothing for a vault whose records cannot be read.
     */
    suspend fun flushVaultRecords() {
        if (client.stopped || !account.localReadable()) return
        for (id in (account.local().vaults.keys + guard.locked { keys.keys.toList() }).sorted()) {
            if (!readable(id)) continue
            loadState(id)?.let { writeVaultRecord(it) }
        }
    }

    /** The unresolved item hint (FC-10) as `seq:hash`, cleared once the verified log holds that hash at that position (design §3.9). */
    private fun resolveHint(vaultId: String) {
        val text = state.get(k(vaultId, "hint")) ?: return
        // A mark written before the hint carried its position ("1") names nothing to wait for: the next verify clears it.
        val seq = text.substringBefore(':').toLongOrNull()
        if (seq != null && loadHashes(vaultId)[seq] != text.substringAfter(':')) return
        putRecord(k(vaultId, "hint"), null)
        putRecord(k(vaultId, "hintChase"), null)
    }

    /**
     * Remembers an unresolved hint: the latest one named. Any writer can put any head on an item, so no hint is kept
     * beyond the next one that resolves (a resolved chase clears the mark, as does a sync that verifies the latest).
     */
    private fun markHint(vaultId: String, seq: Long, hash: String) = putRecord(k(vaultId, "hint"), "$seq:$hash")

    /** Every page after [after] (null: from the genesis) up to the served head, or null when unreachable. */
    private suspend fun fetchFrom(vaultId: String, after: Long?): Pair<List<ByteArray>, LogPage>? {
        val frames = ArrayList<ByteArray>()
        var cursor = after
        var pages = 0
        while (true) {
            val r = client.call(WireRoute.LOG_FETCH, mapOf("vaultId" to vaultId), cursor?.let { "after=$it" },
                decode = { WireJson.json.decodeFromString(LogPage.serializer(), it) })
            val page = (r as? WireResult.Ok)?.value ?: return null
            for (e in page.entries) frames += runCatching { Bytes.fromB64(e) }.getOrElse { ByteArray(0) }
            val last = cursor?.let { it + page.entries.size } ?: (page.entries.size - 1L)
            if (page.entries.isEmpty() || last >= page.head.seq || ++pages > MAX_PAGES) return frames to page
            cursor = last
        }
    }

    /**
     * The writer rule of design §5.4: a verified leave or remove of this account declines its current add. The
     * decline goes through the merge's own pick, so a record for a HIGHER `addSeq` (a later re-add this account
     * answered) is never rolled back by replaying an older leave; for the same `addSeq` the decline wins.
     */
    /** A `leave` by this account or a `remove` of it: the entries [onVerifiedEntry] acts on. */
    private fun isOwnExit(entry: LogEntry): Boolean =
        (entry is LogEntry.Leave && entry.actor == me) || (entry is LogEntry.Remove && entry.member == me)

    /**
     * The end (exclusive) of the replay chunk starting at [from]: just after the first frame that parses as this
     * account's exit, or the end of [frames]. The parse only places the cut; the replay alone decides what verified.
     */
    private fun cutAfterOwnExit(frames: List<ByteArray>, from: Int): Int {
        for (i in from until frames.size) {
            val p = VaultLog.parse(crypto, frames[i])
            if (p is Checked.Ok && isOwnExit(p.value.entry)) return i + 1
        }
        return frames.size
    }

    private suspend fun onVerifiedEntry(vaultId: String, entry: LogEntry, after: VaultState) {
        if (!isOwnExit(entry)) return
        putRecord(k(vaultId, "removedBy"), if (entry is LogEntry.Remove) "owner" else "self")
        val addSeq = AdoptionRules.latestAddSeq(after, me) ?: 0L
        val held = account.local().accepted[vaultId]
        if (held != null && held.addSeq > addSeq) return
        checkLive()
        account.update { doc ->
            val decline = AcceptedRecord(vaultId, after.owner, addSeq, clock(), AcceptedRecord.DECLINE)
            val cur = doc.accepted[vaultId]
            val pick = if (cur == null) decline else AccountMerge.pickAccepted(cur, decline)
            if (pick == cur || (cur != null && cur.addSeq == addSeq && cur.decision == AcceptedRecord.DECLINE)) doc
            else doc.copy(accepted = doc.accepted + (vaultId to pick))
        }
    }

    private suspend fun writeVaultRecord(s: VaultState) {
        // The record follows only a log this device verified to the head the server serves (design §3.6 (e)): nothing is
        // written while the log is withheld, frozen or failed, not at an adoption and not at the flush of an unlock.
        val log = status(s.vaultId)
        if (log is VaultLogStatus.Withheld || log is VaultLogStatus.Frozen || log is VaultLogStatus.Failed) return
        val candidate = VaultRecord(s.vaultId, s.genesisHash, s.head.seq, s.head.hash)
        val existing = account.local().vaults[s.vaultId]
        val last = state.get(k(s.vaultId, "recordAt"))?.toLongOrNull()
        val now = clock()
        if (!VaultRecordBatching.due(existing, candidate, last, now)) return
        checkLive()
        account.update { doc ->
            val cur = doc.vaults[s.vaultId]
            if (cur != null && (cur.genesisHash != candidate.genesisHash || cur.seq >= candidate.seq)) doc
            else doc.copy(vaults = doc.vaults + (s.vaultId to candidate))
        }
        putRecord(k(s.vaultId, "recordAt"), now.toString())
    }

    override suspend fun adoption(vaultId: String): Adoption = adoptionRules(vaultId).also { noteVerdict(vaultId, it) }

    /**
     * The vaults whose latest verdict this engine handed out ([adoption], [answerIncoming]) is [Adoption.AskAccept], each
     * with the place in the vault's log of the `add` that verdict asked about: an invitation its person can answer on this
     * device. It counts only while that add is this account's latest add in the verified log ([answerable], decided on
     * 24 November 2026), so an invitation shown for an earlier add closes nothing for a later one. Kept in memory: after
     * a restart none is open until adoption runs.
     */
    private val asking = HashMap<String, Long>()

    /**
     * A verdict that asks remembers its add; any other verdict ends the invitation. Only an adoption ends a remembered
     * refusal ([answerRefused]): a verdict that does not ask (a grant left out of one answer, or one that does not verify)
     * leaves it, so a server cannot close the copy again by answering differently for one sync.
     */
    private fun noteVerdict(vaultId: String, verdict: Adoption) {
        when (verdict) {
            is Adoption.AskAccept -> asking[vaultId] = verdict.addSeq
            is Adoption.Adopted -> {
                asking -= vaultId
                answerRefused -= vaultId
            }
            else -> asking -= vaultId
        }
    }

    /**
     * The vaults whose invitation of the given `add` no longer closes the kept copy ([answerable]), in this run of the
     * program: an answer to it whose write the server refused to record (refused, or it kept meeting newer writes;
     * decided on 23 November 2026), and every decline of it given on this device, whatever the server answered, did not
     * answer or stored, also one that threw (decided on 24 November 2026). Such an invitation may stay to be answered
     * again, but a server cannot hold the copy closed until its day. Remembered for that one add, whatever the verdicts
     * after it, until the vault is adopted (decided on 24 November 2026); a later add is asked afresh. Kept in memory, as
     * the verdict is: after a restart the copy closes again until an answer is refused, or a decline given, again.
     */
    private val answerRefused = HashMap<String, Long>()

    /**
     * Whether this device holds an invitation to [vaultId] that its person can answer now: the latest verdict asked about
     * the latest add of this account in [s], and the account's copy of the answers (as this device holds it, read only)
     * records none for that add. An answer given on another device since then ends it, and so does an answer to that add
     * whose write the server refused, or a decline of it given on this device ([answerRefused]).
     */
    private fun answerable(vaultId: String, s: VaultState): Boolean {
        val add = AdoptionRules.latestAddSeq(s, me) ?: return false
        if (asking[vaultId] != add) return false
        if (answerRefused[vaultId] == add) return false
        val answered = try { account.local().accepted[vaultId] } catch (e: Exception) { if (e is KeysGoneException) throw e; null }
        return answered == null || answered.addSeq != add
    }

    private suspend fun adoptionRules(vaultId: String): Adoption {
        val s = loadState(vaultId) ?: return Adoption.Refused(vaultId, AdoptionRefusal.LOG_NOT_VERIFIED)
        val log = status(vaultId)
        if (log is VaultLogStatus.Failed) return Adoption.Refused(vaultId, AdoptionRefusal.LOG_NOT_VERIFIED)
        val hashes = loadHashes(vaultId)
        val served = (0..s.head.seq).map { hashes[it] ?: "" }
        // The answer may have been given on another device of this account: read before deciding (design §3.6).
        val doc = answeredDoc(AdoptionRules.latestAddSeq(s, me), vaultId)
        val row = host.grantRow(vaultId)
        val record = doc.vaults[vaultId]
        val accepted = doc.accepted[vaultId]
        val wrap = row?.wrappedVk?.takeIf { it.isNotEmpty() }
        // A record ahead of, or beside, the served chain gives the key read-only (design §3.6 (e)): the log's own status,
        // withheld or frozen, is what keeps every write out.
        val w = uvk.use { AdoptionRules.checkWrap(crypto, me, it, s, served, wrap, record, accepted, log) }
        if (w is AdoptCheck.Adopt) return adopted(s, w.vk, w.source)
        val refuse = { failed: Set<AdoptCondition> -> refusal(vaultId, failed, s, served, record, log) }
        // Through a grant from a current contact.
        val sealed = row?.signedGrant ?: return refuse((w as AdoptCheck.Refuse).failed)
        // Served text: one that is not base64url is a refused grant, never an exception.
        val sealedBytes = try {
            Bytes.fromB64(sealed)
        } catch (e: CryptoException) {
            return Adoption.Refused(vaultId, AdoptionRefusal.GRANT_REFUSED)
        }
        val opened = when (val g = boxKeys.use { VaultGrant.open(crypto, me, it.publicKey, it.privateKey, vaultId, sealedBytes, s) }) {
            is Checked.Ok -> g.value
            is Checked.Refused -> return Adoption.Refused(vaultId, AdoptionRefusal.GRANT_REFUSED)
        }
        try {
            val actor = opened.add.actor
            val current = host.isCurrentContact(actor, opened.add.ownerKey)
            if (!current) return Adoption.ConnectFirst(vaultId, host.serverOwnerName(vaultId))
            val c = AdoptionRules.checkGrant(crypto, me, s, served, opened, true, record, accepted, log)
            if (c is AdoptCheck.Adopt) {
                // The key is a copy held across the post (a wait): zeroed when the post fails or a lock cancels it;
                // otherwise [adopted] takes it.
                try {
                    postSelfWrap(vaultId, s, c.vk, row?.rev ?: -1L)
                } catch (t: Throwable) {
                    c.vk.fill(0)
                    throw t
                }
                return adopted(s, c.vk, c.source)
            }
            val failed = (c as AdoptCheck.Refuse).failed
            if (failed == setOf(AdoptCondition.SOURCE) && opened.add.seq == AdoptionRules.latestAddSeq(s, me)) {
                if (accepted != null && accepted.addSeq == opened.add.seq && accepted.decision == AcceptedRecord.DECLINE) return Adoption.Declined(vaultId)
                val vk = opened.vk
                val name = try { host.vaultName(vaultId, vk) } finally { vk.fill(0) } ?: ""
                return Adoption.AskAccept(vaultId, actor, host.labelFor(actor, opened.add.ownerKey) ?: "", name, opened.add.seq)
            }
            return refuse(failed)
        } finally {
            opened.wipe()
        }
    }

    override fun reopenAdopted(vaultId: String): Adoption {
        // Reads only: no fetch, no self-wrap post, no vault record. A record that cannot be read reopens nothing.
        if (!readable(vaultId)) return Adoption.Refused(vaultId, AdoptionRefusal.LOG_NOT_VERIFIED)
        val s = loadState(vaultId) ?: return Adoption.Refused(vaultId, AdoptionRefusal.LOG_NOT_VERIFIED)
        val log = status(vaultId)
        if (log is VaultLogStatus.Failed) return Adoption.Refused(vaultId, AdoptionRefusal.LOG_NOT_VERIFIED)
        val wrap = host.grantRow(vaultId)?.wrappedVk?.takeIf { it.isNotEmpty() } ?: return Adoption.Refused(vaultId, AdoptionRefusal.NO_KEY)
        val hashes = loadHashes(vaultId)
        val served = (0..s.head.seq).map { hashes[it] ?: "" }
        val doc = account.local()
        val record = doc.vaults[vaultId]
        return when (val w = uvk.use { AdoptionRules.checkWrap(crypto, me, it, s, served, wrap, record, doc.accepted[vaultId], log) }) {
            is AdoptCheck.Adopt -> {
                putKey(vaultId, w.vk)
                Adoption.Adopted(vaultId, w.source)
            }
            is AdoptCheck.Refuse -> refusal(vaultId, w.failed, s, served, record, log)
        }
    }

    /** The first failing condition, by the design's order; a failing (e) says how it failed ([AdoptionRules.recordRefusal]). */
    private fun refusal(vaultId: String, failed: Set<AdoptCondition>, s: VaultState, served: List<String>, record: VaultRecord?, log: VaultLogStatus): Adoption =
        Adoption.Refused(vaultId, when {
            AdoptCondition.LOG in failed -> AdoptionRefusal.LOG_NOT_VERIFIED
            AdoptCondition.MEMBER in failed -> AdoptionRefusal.NOT_A_MEMBER
            AdoptCondition.COMMIT in failed -> AdoptionRefusal.KEY_COMMIT_MISMATCH
            AdoptCondition.RECORD in failed -> AdoptionRules.recordRefusal(s, served, record, log)
            else -> AdoptionRefusal.NO_KEY
        })

    private suspend fun adopted(s: VaultState, vk: ByteArray, source: KeySource): Adoption {
        // After the self-wrap's post (a wait): a lock in it keeps nothing, and the key is zeroed.
        putKey(s.vaultId, vk)
        // Adopting writes the account's vault record (design §3.6 (e)); a no-op when it is already current.
        writeVaultRecord(s)
        return Adoption.Adopted(s.vaultId, source)
    }

    /** After adopting from a grant, post the genesis-bound self-wrap so the account's other devices adopt through it (design §3.6). */
    private suspend fun postSelfWrap(vaultId: String, s: VaultState, vk: ByteArray, rowRev: Long) {
        if (s.owner == me) return
        val at = clock()
        val ok = postWrapped(vaultId, uvk.use { Envelope.sealB64(crypto, it, vk, Ad.vkShared(vaultId, me, s.genesisHash)) })
        wrapPosts[vaultId] = WrapPost(if (ok) rowRev else null, at)
    }

    /**
     * `PUT /vaults/{id}/grant/self-wrap` with [wrapped]: true when the server answered it. The answer decides nothing about
     * the vault (a later sync shows what is stored); it only spaces out [ensureSelfWrap]'s posts.
     */
    private suspend fun postWrapped(vaultId: String, wrapped: String): Boolean {
        val body = WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.SelfWrapPut.serializer(), io.silencelen.andvari.core.model.wire.SelfWrapPut(wrapped))
        return client.call(WireRoute.VAULT_SELF_WRAP, mapOf("vaultId" to vaultId), bodyJson = body, decode = { it }) is WireResult.Ok
    }

    override suspend fun answerIncoming(ask: Adoption.AskAccept, accept: Boolean): Adoption {
        // A decline opens the kept copy for the add it answers, whatever the server makes of its writes (decided on
        // 24 November 2026). Remembered before the answer is written, so that it holds also when this device's store
        // throws while the answer is read or written.
        if (!accept) answerRefused[ask.vaultId] = ask.addSeq
        return answerRules(ask, accept).also { noteVerdict(ask.vaultId, it) }
    }

    private suspend fun answerRules(ask: Adoption.AskAccept, accept: Boolean): Adoption {
        // Re-derive the prompt from this device's own verified state; the handed-back object only names the vault.
        val fresh = adoption(ask.vaultId)
        if (fresh !is Adoption.AskAccept || fresh.addSeq != ask.addSeq || fresh.owner != ask.owner) return fresh
        val decision = if (accept) AcceptedRecord.ACCEPT else AcceptedRecord.DECLINE
        // The answer supersedes any record held for the vault (design §5.4): stamped after it.
        checkLive()
        val written = account.update { doc ->
            val at = AccountMerge.supersedingAt(clock(), doc.accepted[fresh.vaultId]?.at)
            doc.copy(accepted = doc.accepted + (fresh.vaultId to AcceptedRecord(fresh.vaultId, fresh.owner, fresh.addSeq, at, decision)))
        }
        // Known not recorded (the server refused the write, or it kept meeting newer writes): nothing was decided, and the
        // question stands as it was asked; no leave is signed for a decline that was not recorded. Before, the answer
        // went on as recorded. A write whose outcome is not known goes on as today (it may be stored); a decline, whatever
        // its outcome, is already remembered ([answerIncoming]).
        // The kept copy of the vault no longer stays closed for this invitation ([answerRefused]).
        if (written is io.silencelen.andvari.core.client.state.AccountStateWrite.Refused || written is io.silencelen.andvari.core.client.state.AccountStateWrite.Contended) {
            answerRefused[fresh.vaultId] = fresh.addSeq
            return fresh
        }
        // A write whose outcome is not known (no answer to it; also a read before it that failed) cannot be told either way:
        // a result of its own, never "recorded" and never "not recorded".
        val unknown = written is io.silencelen.andvari.core.client.state.AccountStateWrite.Unknown
        // Recording the answer writes the vault record too, so a re-add of the same vault is checked against this genesis.
        loadState(ask.vaultId)?.let { writeVaultRecord(it) }
        if (!accept) {
            // This unlock's leave for the decline: [leaveAgainForDeclines] signs no second one.
            declineLeftHere += ask.vaultId
            val left = append(ask.vaultId, LogAction.Leave)
            // A leave the log holds takes this account out of the vault whatever the record says: declined.
            if (unknown && left !is AppendOutcome.Appended) return Adoption.AnswerNotKnown(ask.vaultId, accepted = false, adopted = false)
            return Adoption.Declined(ask.vaultId)
        }
        val after = adoption(ask.vaultId)
        if (unknown) return Adoption.AnswerNotKnown(ask.vaultId, accepted = true, adopted = after is Adoption.Adopted)
        return after
    }

    /** Vaults this engine signed a declined share's leave for (the answer's own, or [leaveAgainForDeclines]'s). */
    private val declineLeftHere = HashSet<String>()

    override suspend fun leaveAgainForDeclines(): List<LeftAgain> {
        val declined = account.local().accepted.values.filter { it.decision == AcceptedRecord.DECLINE }.sortedBy { it.vaultId }
        val out = ArrayList<LeftAgain>()
        for (rec in declined) {
            val v = rec.vaultId
            if (v in declineLeftHere || !mayLeaveAgain(v, rec.addSeq)) continue
            // Read afresh before signing: the owner may have removed this account, or added it again, meanwhile.
            if (refresh(v, null, null, force = true) !is VaultLogStatus.Verified || !mayLeaveAgain(v, rec.addSeq)) continue
            declineLeftHere += v
            out += LeftAgain(v, append(v, LogAction.Leave))
        }
        return out
    }

    /**
     * Whether a declined share's leave is owed for [vaultId]: its records read, nothing held for it, and its verified log
     * lists this account as a member through the declined `add` at [addSeq] (not a later one), in a vault not deleted.
     */
    private fun mayLeaveAgain(vaultId: String, addSeq: Long): Boolean {
        if (!readable(vaultId) || pendingRecord(vaultId) != null) return false
        if (status(vaultId) !is VaultLogStatus.Verified) return false
        val s = loadState(vaultId) ?: return false
        return !s.isDeleted && me in s.members && AdoptionRules.latestAddSeq(s, me) == addSeq
    }

    /**
     * An item names a log head: a hint, never a verdict (FS-R4). A hint that names more than this device verified is
     * chased with one full refetch. Any writer can put any head on an item, so a chase that found the hint unresolved
     * is remembered per vault with the verified head it ran at: until [HINT_BACKOFF_MS] has passed or the verified
     * head has moved, further hints are not chased again and the vault stays "may be incomplete".
     */
    override suspend fun noteItemHead(vaultId: String, seq: Long, hash: String): VaultLogStatus {
        if (client.stopped || !readable(vaultId)) return status(vaultId)
        val s = loadState(vaultId)
        if (s != null) {
            val hashes = loadHashes(vaultId)
            val mentionsMore = seq > s.head.seq || (hashes[seq] != null && hashes[seq] != hash)
            if (!mentionsMore) {
                // This item names nothing new; a hint another item left is resolved once the verified log holds it (H3).
                resolveHint(vaultId)
                return status(vaultId)
            }
        }
        val headBefore = s?.head?.seq ?: -1L
        val nowMs = clock()
        if (chaseBackedOff(vaultId, headBefore, nowMs)) {
            if (s != null) markHint(vaultId, seq, hash)
            return status(vaultId)
        }
        val after = refresh(vaultId, null, null, force = true)
        val now = loadState(vaultId)
        val resolved = now != null && now.head.seq >= seq && loadHashes(vaultId)[seq] == hash
        if (now != null && !resolved) markHint(vaultId, seq, hash)
        if (resolved) putRecord(k(vaultId, "hint"), null)
        // Remember an unresolved chase at the head it ran at; a resolved one clears the back-off.
        putRecord(k(vaultId, "hintChase"), if (resolved) null else "${now?.head?.seq ?: -1L}:$nowMs")
        return if (resolved) after else status(vaultId)
    }

    /** True when an unresolved chase ran at verified head [headSeq] less than [HINT_BACKOFF_MS] before [nowMs]. */
    private fun chaseBackedOff(vaultId: String, headSeq: Long, nowMs: Long): Boolean {
        val text = state.get(k(vaultId, "hintChase")) ?: return false
        val at = text.substringAfter(':').toLongOrNull() ?: return false
        val chasedHead = text.substringBefore(':').toLongOrNull() ?: return false
        return chasedHead == headSeq && nowMs >= at && nowMs - at < HINT_BACKOFF_MS
    }

    /**
     * This device's own verified state of [vaultId]'s log, for a caller in the engine that signs after it (account
     * deletion's leaves, design §3.11). Null when none is stored, or when any trust record for the vault cannot be read
     * (design §4.4 "A trust record that cannot be read is not an empty one"): then the caller treats the served head as
     * one this device has not verified. Internal, so a host can never hand the signer a made-up state.
     */
    internal fun verifiedState(vaultId: String): VaultState? = try {
        if (readable(vaultId)) loadState(vaultId) else null
    } catch (e: Exception) {
        if (e is KeysGoneException) throw e
        null
    }

    override fun writeAllowed(vaultId: String): Boolean = status(vaultId).let { it is VaultLogStatus.Verified && me in loadState(vaultId)!!.members } && guard.locked { keys.containsKey(vaultId) }

    override fun copyOutAllowed(vaultId: String): Boolean = guard.locked { keys.containsKey(vaultId) } || heldKey(vaultId) != null

    /**
     * The adopted key, or a held key of a vault whose verified log does not name this account a member ([heldKeyUntil]).
     * A held key of a vault that names it a member again leaves the adoption rules to run (the add is to be answered) and
     * never makes the vault one this account may use.
     */
    override fun adoptionSettled(vaultId: String): Boolean =
        guard.locked { keys.containsKey(vaultId) } || (heldKeyUntil(vaultId) != null && heldKey(vaultId) != null)

    /**
     * The end of the holding period of the key held for [vaultId] ([hold]: [HOLDING_MS] after this device verified the
     * leave or remove), or null: no record, a time that does not read, the period over, or this account a member again.
     * Reads only; [heldKey] wipes a record whose time is over. Whether the sealed key still opens is [withKey]'s answer.
     */
    private fun heldKeyUntil(vaultId: String): Long? {
        val text = try { state.get(k(vaultId, "held")) } catch (e: Exception) { null } ?: return null
        val until = text.substringBefore(':').toLongOrNull() ?: return null
        if (clock() >= until) return null
        val s = try { loadState(vaultId) } catch (e: Exception) { null } ?: return null
        return if (me in s.members) null else until
    }

    /**
     * The same reading as [heldKey], where it refuses the held key: a held record whose time reads and is not over, the
     * verified state names this account a member again, and this device holds an invitation its person can answer now
     * ([answerable], decided on 23 November 2026). Added again in any other state (the grant refused, connect first, a
     * decline recorded or given on this device, an answer given on another device, another refusal), the copy stays an
     * ordinary kept copy. Once
     * the vault's own key is adopted it is false through [answerable]: every adoption either notes its verdict (which
     * ends [asking]) or, for a key from a self-wrap, needs the account's recorded acceptance of the latest add (which
     * ends [answerable]). Reads only, wipes nothing.
     */
    override fun heldWhileMemberAgain(vaultId: String): Boolean {
        val text = try { state.get(k(vaultId, "held")) } catch (e: Exception) { null } ?: return false
        val until = text.substringBefore(':').toLongOrNull() ?: return false
        if (clock() >= until) return false
        val s = try { loadState(vaultId) } catch (e: Exception) { null } ?: return false
        return me in s.members && answerable(vaultId, s)
    }

    /**
     * The adopted key, or, for a vault this account left or was removed from (verified in its log), the key it held then,
     * for copying items out of the holding area until [HOLDING_MS] after the verification (spec 02 §10.6). A held key is
     * never one [writeAllowed] accepts: no write is sealed under it.
     */
    override fun <T> withKey(vaultId: String, block: (ByteArray) -> T): T? = guard.use {
        val vk = keys[vaultId] ?: heldKey(vaultId)
        if (vk == null) null else io.silencelen.andvari.core.client.onboard.KeyEscape.refuse(block(vk), vk)
    }

    /** The server's `deleted`, kept with the `deleteId` of the verified `delete` it was served beside. Display only. */
    @Serializable
    private data class Grace(val deleteId: String, val deletedAt: Long, val purgeAt: Long)

    private fun graceRecord(vaultId: String): Grace? = state.get(k(vaultId, GRACE_PART))
        ?.let { runCatching { WireJson.json.decodeFromString(Grace.serializer(), it) }.getOrNull() }
        ?.takeIf { it.deletedAt >= 0 && it.purgeAt >= it.deletedAt }

    /**
     * Keeps the server's [served] `deleted` beside [verified]'s standing `delete`, only when [head] (the answer's head)
     * is the verified head itself; drops any kept value once the verified state has no standing `delete`. [replace]
     * false keeps a value already kept for that `delete` (the append's answer yields to the refetch that followed it).
     * Nothing in this engine reads the record back except [serverGraceEnd]: no decision depends on it.
     */
    private fun noteGrace(verified: VaultState, head: LogHead, served: LogDeleted?, replace: Boolean) {
        val key = k(verified.vaultId, GRACE_PART)
        val deleteId = verified.deleteId
        if (deleteId == null) {
            if (state.get(key) != null) putRecord(key, null)
            return
        }
        if (served == null || head.seq != verified.head.seq || head.hash != verified.head.hash) return
        if (!replace && graceRecord(verified.vaultId)?.deleteId == deleteId) return
        putRecord(key, WireJson.json.encodeToString(Grace.serializer(), Grace(deleteId, served.deletedAt, served.purgeAt)))
    }

    /** The head the last fetch in [refresh] was served, by vault: only for [serverGrants]'s "verified to the served head". */
    private val lastServed = HashMap<String, LogHead>()

    /** The verified status after a forced fetch, when the verified head is the head that fetch was served; else null. */
    private suspend fun verifiedToServedHead(vaultId: String): VaultLogStatus.Verified? {
        lastServed.remove(vaultId)
        val st = refresh(vaultId, null, null, force = true) as? VaultLogStatus.Verified ?: return null
        val served = lastServed[vaultId] ?: return null
        return st.takeIf { served.seq == it.state.headSeq && served.hash == it.state.headHash }
    }

    override suspend fun serverGrants(vaultId: String): ServerGrants {
        fun unknown(reason: String) = ServerGrants.Unknown(vaultId, reason)
        if (client.stopped) return unknown(ORIGIN_STOPPED)
        // Design §3.11: the log first, so a `remove` or `leave` the server stored is
        // verified before an absence from the list could be read as "no grant".
        val before = verifiedToServedHead(vaultId) ?: return unknown(ServerGrants.LOG_NOT_VERIFIED)
        if (before.state.deletedId != null) return unknown(ServerGrants.VAULT_DELETED)
        val r = client.call(WireRoute.VAULT_MEMBERS, mapOf("vaultId" to vaultId),
            decode = { WireJson.json.decodeFromString(ListSerializer(VaultMemberSummary.serializer()), it) })
        val rows = (r as? WireResult.Ok)?.value ?: return unknown(ServerGrants.LIST_UNREADABLE)
        // And the log again: a list read across a move of the head may predate an entry this device has not verified.
        val after = verifiedToServedHead(vaultId) ?: return unknown(ServerGrants.LOG_NOT_VERIFIED)
        if (after.state.headSeq != before.state.headSeq || after.state.headHash != before.state.headHash) return unknown(ServerGrants.LOG_MOVED)
        val listed = rows.mapTo(HashSet()) { it.userId }
        val members = after.state.members.keys
        return ServerGrants.Read(vaultId, after.state.headSeq, after.state.headHash,
            members.filterTo(LinkedHashSet()) { it in listed }, members.filterNotTo(LinkedHashSet()) { it in listed })
    }

    override fun serverGraceEnd(vaultId: String): LogDeleted? = try {
        val g = graceRecord(vaultId)
        val deleteId = loadState(vaultId)?.deleteId
        if (g != null && deleteId != null && g.deleteId == deleteId) LogDeleted(g.deletedAt, g.purgeAt) else null
    } catch (e: Exception) {
        null
    }

    /**
     * Keeps [vk] for copy-out after a verified leave or remove of this account: in memory, and sealed under the UVK in
     * device state with the time the holding period ends, so it survives a lock or a restart for that period.
     */
    private fun hold(s: VaultState, vk: ByteArray) {
        val until = clock() + HOLDING_MS
        // [vk] is zeroed on every exit but the one that hands it to [heldKeys]: a
        // lock, and a write between the seal and the map entry that throws, too.
        var kept = false
        try {
            val sealed = uvk.use { Envelope.sealB64(crypto, it, vk, Ad.vkShared(s.vaultId, me, s.genesisHash)) }
            putRecord(k(s.vaultId, "held"), "$until:$sealed")
            guard.use { heldKeys.put(s.vaultId, vk)?.fill(0) }
            kept = true
        } finally {
            if (!kept) vk.fill(0)
        }
    }

    /**
     * The key held for copy-out of [vaultId], or null: none held, the holding period over (the record is then wiped), this
     * account a member again with an invitation it can answer now ([answerable]: the vault adopts afresh), or a record
     * that cannot be read or opened (nothing is offered). A member again with no invitation to answer here keeps the
     * held key for copying out; [adoptionSettled] keeps it from ever making the vault one this account may use.
     */
    private fun heldKey(vaultId: String): ByteArray? {
        val text = try { state.get(k(vaultId, "held")) } catch (e: Exception) { null }
        if (text == null) {
            guard.locked { heldKeys.remove(vaultId) }?.fill(0)
            return null
        }
        val until = text.substringBefore(':').toLongOrNull()
        if (until == null || clock() >= until) {
            dropHeld(vaultId)
            return null
        }
        val s = try { loadState(vaultId) } catch (e: Exception) { null } ?: return null
        if (me in s.members && answerable(vaultId, s)) return null
        // Under the account's guard: a wiped account throws here (a lock is not "no held key"), and the key opened is
        // held only while the account is not wiped.
        return uvk.use { u ->
            heldKeys[vaultId] ?: run {
                val vk = try {
                    Envelope.openB64(crypto, u, text.substringAfter(':'), Ad.vkShared(vaultId, me, s.genesisHash))
                } catch (e: Exception) {
                    if (e is KeysGoneException) throw e
                    null
                }
                if (vk != null) heldKeys[vaultId] = vk
                vk
            }
        }
    }

    /**
     * Wipes every vault key this engine holds in memory: the adopted ones and those held for copy-out. The session keeper
     * calls it at lock, after [flushVaultRecords]. Afterwards no key is offered until the next session adopts again (a key
     * held for copy-out reopens from its sealed record under the next session's UVK).
     */
    fun wipeKeys() {
        try {
            guard.use { clearKeys() }
        } catch (e: KeysGoneException) {
            // The account was wiped first: its wipe cleared these under the same guard.
        }
    }

    private fun clearKeys() {
        for (vk in keys.values) vk.fill(0)
        keys.clear()
        for (vk in heldKeys.values) vk.fill(0)
        heldKeys.clear()
    }

    private fun dropHeld(vaultId: String) {
        guard.locked { heldKeys.remove(vaultId) }?.fill(0)
        // A store that cannot be written keeps the record; it is past its time and offers nothing.
        try { putRecord(k(vaultId, "held"), null) } catch (e: Exception) {}
    }

    override suspend fun append(vaultId: String?, action: LogAction): AppendOutcome = append(vaultId, action, null)

    override suspend fun append(vaultId: String?, action: LogAction, expectHead: Checkpoint?): AppendOutcome {
        // Nothing is signed for a server this device may not talk to (design §4.4): a signed entry is material for it.
        if (client.stopped) return AppendOutcome.NotAllowed(ORIGIN_STOPPED)
        // A new vault has no head to have checked.
        if (action is LogAction.Create) return if (expectHead == null) create(action) else AppendOutcome.NotAllowed(BAD_EXPECT_HEAD)
        val id = vaultId ?: return AppendOutcome.NotAllowed("no_vault")
        if (!readable(id)) return AppendOutcome.NotAllowed(RECORD_UNREADABLE)
        // Design §3.7 (hostile-server finding H8): while a frame is pending for this vault the device signs nothing else
        // for it. The pending frame is re-posted byte for byte first; acknowledged (or answered by another entry this
        // device verified at its position), the action goes on from the new head; still unanswered, it is refused. Nothing
        // is queued behind a pending frame, and the pending record is never overwritten. This re-post is the general one: a
        // held change of a day is given up after a read instead, and a held deletion is never sent here (the person's waits
        // for their word, a move's is the move's), so the vault takes nothing new while one waits. An addition whose contact
        // is gone, has another key or is no longer compared is let go of unsent ([letGoForContact]), and the action goes on.
        pendingRecord(id)?.let { h ->
            val held = stamped(h)
            when {
                // Settled by what a read verified since (a deletion stored outside the move, say): nothing is sent.
                settledLocally(held) != null -> {}
                dueToGiveUp(held) -> giveUp(held)
                kindOf(entryOf(held.frame)) == HeldKind.DELETE -> return AppendOutcome.NotAllowed(APPEND_PENDING)
                else -> resendOne(held)
            }
            if (pendingRecord(id) != null) return AppendOutcome.NotAllowed(APPEND_PENDING)
        }
        // A user id of all zeros is never an account: no action that names one is ever built, whatever the verified log
        // says about it (a server can register such an account and have it added).
        val named = when (action) {
            is LogAction.Add -> action.contactUserId
            is LogAction.Role -> action.member
            is LogAction.Remove -> action.member
            is LogAction.Offer -> action.to
            else -> null
        }
        if (io.silencelen.andvari.core.client.UserIds.isNil(named)) return AppendOutcome.NotAllowed(NIL_USER_ID)
        val st = status(id)
        val s = loadState(id) ?: return AppendOutcome.NotAllowed("log_not_verified")
        // The head the caller checked is the head signed over, or nothing is signed: from here to the signature there is no
        // wait, so the state compared is the state the entry (and an add's grant) is built and signed on.
        if (expectHead != null && (expectHead.seq != s.head.seq || expectHead.hash != s.head.hash)) return AppendOutcome.NotAllowed(LOG_MOVED_ON)
        if (st !is VaultLogStatus.Verified && action !is LogAction.Leave) return AppendOutcome.VaultReadOnly
        val pos = VaultLog.position(s, clock())
        var grant: String? = null
        var wrappedVk: String? = null
        var uncompared = false
        val entry: LogEntry = when (action) {
            is LogAction.Add -> {
                val (key, compared) = host.currentContact(action.contactUserId) ?: return AppendOutcome.NotAllowed("not_a_current_contact")
                if (!compared && !action.releaseUncompared) return AppendOutcome.NotAllowed("not_compared")
                uncompared = !compared
                val role = MemberRole.fromLiteral(action.role) ?: return AppendOutcome.NotAllowed("bad_role")
                val grantId = Bytes.toB64(crypto.randomBytes(16))
                // The vault key and the signing key under the account's guard: the pending post above was a wait.
                val frame = guard.use { keys[id]?.let { vk -> signer.use { s -> VaultGrant.sign(crypto, s, GrantFields(me, action.contactUserId, key, id, grantId, pos.at, vk)) } } }
                    ?: return AppendOutcome.NotAllowed("no_key")
                // The signed frame holds the vault key in the clear: zeroed once sealed.
                grant = try { Bytes.toB64(VaultGrant.seal(crypto, Bytes.fromB64(key), frame)) } finally { frame.fill(0) }
                LogEntry.Add(id, pos.seq, pos.prev, me, pos.at, action.contactUserId, key, role, grantId)
            }
            is LogAction.Role -> LogEntry.Role(id, pos.seq, pos.prev, me, pos.at, action.member, MemberRole.fromLiteral(action.role) ?: return AppendOutcome.NotAllowed("bad_role"))
            is LogAction.Remove -> LogEntry.Remove(id, pos.seq, pos.prev, me, pos.at, action.member)
            LogAction.Leave -> LogEntry.Leave(id, pos.seq, pos.prev, me, pos.at)
            is LogAction.Offer -> {
                val to = s.members[action.to] ?: return AppendOutcome.NotAllowed("not_a_member")
                if (action.expiresInMs <= 0 || action.expiresInMs > VaultLog.MAX_OFFER_WINDOW_MS - 10 * 60 * 1000) return AppendOutcome.NotAllowed("bad_expiry")
                LogEntry.Offer(id, pos.seq, pos.prev, me, pos.at, action.to, to.key, Bytes.toB64(crypto.randomBytes(16)), pos.at + action.expiresInMs)
            }
            LogAction.Cancel -> LogEntry.Cancel(id, pos.seq, pos.prev, me, pos.at, s.pending?.offerId ?: return AppendOutcome.NotAllowed("no_offer"))
            LogAction.Accept -> {
                val p = s.pending ?: return AppendOutcome.NotAllowed("no_offer")
                val ad = Ad.vkShared(id, me, s.genesisHash)
                // The vault key and the UVK under the account's guard: the pending post above was a wait.
                val w = guard.use { keys[id]?.let { vk -> uvk.use { u -> Envelope.sealB64(crypto, u, vk, ad) } } } ?: return AppendOutcome.NotAllowed("no_key")
                // Round trip: the wrap must open to the committed key before it is posted (spec 03 §10.2).
                val back = uvk.use { u -> runCatching { Envelope.openB64(crypto, u, w, ad) }.getOrNull() }
                if (back == null || !VaultLog.keyMatches(crypto, s, back)) {
                    back?.fill(0)
                    return AppendOutcome.NotAllowed("wrap_round_trip")
                }
                back.fill(0)
                wrappedVk = w
                LogEntry.Accept(id, pos.seq, pos.prev, me, pos.at, p.offerId)
            }
            LogAction.Delete, is LogAction.DeleteVault -> LogEntry.Delete(id, pos.seq, pos.prev, me, pos.at, Bytes.toB64(crypto.randomBytes(16)))
            LogAction.Restore -> LogEntry.Restore(id, pos.seq, pos.prev, me, pos.at, s.deleteId ?: return AppendOutcome.NotAllowed("not_deleted"))
            is LogAction.Create -> error("unreachable")
        }
        val signed = when (val c = signer.use { VaultLog.signChecked(crypto, it, s, entry) }) {
            is Checked.Ok -> c.value
            is Checked.Refused -> return AppendOutcome.NotAllowed(c.verdict.code)
        }
        val movesOwn = (action is LogAction.Add && action.movesOwn) || (action is LogAction.DeleteVault && action.movesOwn)
        val itemsAtMost = (action as? LogAction.DeleteVault)?.itemsAtMost
        return post(Pending(id, Bytes.toB64(signed.frame), grant, wrappedVk, null, movesOwn = movesOwn, itemsAtMost = itemsAtMost, uncompared = uncompared))
    }

    private suspend fun create(action: LogAction.Create): AppendOutcome {
        action.vaultId?.let { id -> resumeCreate(id)?.let { return it } }
        val vaultId = action.vaultId ?: Bytes.uuidV4FromBytes(crypto.randomBytes(16))
        val vk = crypto.randomBytes(32)
        val entry = LogEntry.Genesis(vaultId, me, clock(), Bytes.toB64(boxKeys.publicKey), VaultLog.vkCommit(crypto, vk, vaultId))
        val signed = when (val c = try { signer.use { VaultLog.signChecked(crypto, it, null, entry) } } catch (e: KeysGoneException) { vk.fill(0); throw e }) {
            is Checked.Ok -> c.value
            is Checked.Refused -> { vk.fill(0); return AppendOutcome.NotAllowed(c.verdict.code) }
        }
        val genesisHash = signed.step.hash
        val wrapped = try {
            uvk.use { Envelope.sealB64(crypto, it, vk, Ad.vkShared(vaultId, me, genesisHash)) }
        } catch (e: KeysGoneException) {
            vk.fill(0)
            throw e
        }
        val meta = host.sealMeta(vaultId, vk, action.vaultName)
        putKey(vaultId, vk)
        // The writer rule of design §5.4: the creator's accepted record answers the genesis (addSeq 0).
        checkLive()
        account.update { doc -> doc.copy(accepted = doc.accepted + (vaultId to AcceptedRecord(vaultId, me, 0, clock(), AcceptedRecord.ACCEPT))) }
        return post(Pending(vaultId, Bytes.toB64(signed.frame), null, wrapped, meta))
    }

    /**
     * A create for a caller-supplied [vaultId] (a resumable restore, spec 07 §3): the answer when this device already
     * holds something for that id, or null when a new genesis may be signed for it. A held genesis of this account is
     * re-posted byte for byte (never re-signed: two genesis frames for one vault would be a fork); a verified log this
     * account created answers as appended; anything else this device holds for that id refuses.
     */
    private suspend fun resumeCreate(vaultId: String): AppendOutcome? {
        if (!TrustGrammar.isUuid(vaultId)) return AppendOutcome.NotAllowed(BAD_VAULT_ID)
        if (!readable(vaultId)) return AppendOutcome.NotAllowed(RECORD_UNREADABLE)
        pendingRecord(vaultId)?.let { held ->
            val entry = VaultLog.parse(crypto, Bytes.fromB64(held.frame)).valueOrNull()?.entry
            return if (entry is LogEntry.Genesis && entry.actor == me) post(held) else AppendOutcome.NotAllowed(VAULT_ID_TAKEN)
        }
        val s = loadState(vaultId)
        if (s != null) return if (s.creator == me) AppendOutcome.Appended(view(s)) else AppendOutcome.NotAllowed(VAULT_ID_TAKEN)
        // A failed or withheld log with no verified state is not a free id either.
        if (flag(vaultId).isNotEmpty()) return AppendOutcome.NotAllowed(VAULT_ID_TAKEN)
        return null
    }

    private fun savePending(p: Pending?, vaultId: String) {
        putRecord(k(vaultId, "pending"), p?.let { WireJson.json.encodeToString(Pending.serializer(), it) })
        val ids = pendingIds().toMutableSet()
        if (p != null) ids += vaultId else ids -= vaultId
        putRecord(indexKey, ids.sorted().joinToString(",").ifEmpty { null })
    }

    private val indexKey = "ovh.log|$me|pending-index"

    private fun pendingIds(): List<String> = state.get(indexKey)?.split(',')?.filter { it.isNotEmpty() } ?: emptyList()

    private fun pendingRecord(vaultId: String): Pending? = state.get(k(vaultId, "pending"))?.let(::decodePending)

    private suspend fun post(p: Pending): AppendOutcome = postTracked(p).first

    /**
     * [post], and whether it was this post that dropped the held record (so that only the hand that dropped it says why).
     * Every write of the record after the request (and inside [settle]) is made only while the held record is still this
     * frame: an answer that arrives for a change withdrawn meanwhile does not bring it back, and a record signed later for
     * the vault is never dropped or changed by an older post.
     */
    private suspend fun postTracked(p: Pending): Pair<AppendOutcome, Boolean> {
        // Never replace a pending frame with another one (design §3.7): two signed entries for one position are a fork.
        val held = pendingRecord(p.vaultId)
        if (held != null && held.frame != p.frame) return AppendOutcome.NotAllowed(APPEND_PENDING) to false
        // Every road that sends a held change again comes here: an addition goes out again only to the contact it was
        // signed for, compared with what the device holds now, with no wait between that comparison and the send.
        if (held != null) letGoForContact(held)?.let { return it to true }
        // Known not stored so far: never sent before, or every send of it answered "slow down".
        val notStoredSoFar = held?.notStored ?: true
        val first = held == null
        val record = held?.let { if (it.heldAt == null) it.copy(heldAt = clock()) else it } ?: p.copy(heldAt = clock())
        savePending(record, p.vaultId)
        // Built from the account's keys, maybe before a wait (the account-state write of a create): never sent once the
        // keys are wiped. The pending record stays and is re-posted, byte for byte, after the next unlock.
        guard.check()
        // From here the send may leave: the record at rest says "cannot tell" before it does, so that another engine over
        // the same records (built after a lock and an unlock while this request is out) never reads it as known not stored.
        val send = record.sends + 1
        savePending(record.copy(notStored = false, sends = send), p.vaultId)
        val body = WireJson.json.encodeToString(LogAppendRequest.serializer(), LogAppendRequest(p.frame, p.grant, p.wrappedVk, p.metaBlob, p.itemsAtMost))
        val hash = frameHash(p.frame)
        requestsOut[hash] = (requestsOut[hash] ?: 0) + 1
        if (first) firstOut += hash
        val r = try {
            client.call(WireRoute.LOG_APPEND, mapOf("vaultId" to p.vaultId), bodyJson = body,
                decode = { WireJson.json.decodeFromString(LogAppendResponse.serializer(), it) })
        } finally {
            val n = (requestsOut[hash] ?: 1) - 1
            if (n <= 0) requestsOut.remove(hash) else requestsOut[hash] = n
            if (first) firstOut -= hash
        }
        var dropped = false
        fun drop() { if (stillHeld(p)) { savePending(null, p.vaultId); dropped = true } }
        // A send whose outcome is not known: the frame may be stored from now on, so it is never again "not stored".
        fun unknown(): AppendOutcome {
            keepIfHeld(p) { if (it.notStored) it.copy(notStored = false) else it }
            return AppendOutcome.Pending
        }
        // A refusal of the entry. Known not stored (never sent before, or every send "slow down"): dropped, [refused]. The
        // server's own answer called it stored: kept and sent again as it is, nothing said ([AppendOutcome.Pending]).
        // Otherwise it cannot be told: given up with the refusal's reason and remembered, so the next verified read
        // settles it ([AppendOutcome.Pending] with the record dropped; the general re-send says [HeldResend.GivenUp]).
        fun refusedForEntry(code: String, refused: AppendOutcome): AppendOutcome {
            val cur = pendingRecord(p.vaultId)?.takeIf { it.frame == p.frame }
            return when {
                notStoredSoFar || cur == null -> { drop(); refused }
                cur.acked -> AppendOutcome.Pending
                else -> {
                    savePending(null, p.vaultId)
                    dropped = true
                    remember(cur, LetGo.GIVEN_UP, told = true)
                    addFinding(cur, FoundKind.GIVEN_UP, code = code)
                    AppendOutcome.Pending
                }
            }
        }
        val outcome = when (r) {
            is WireResult.Ok -> {
                // The server's word that it took the frame, and the head it named: "stored" still needs the log. A change let
                // go of meanwhile keeps that head in its memory.
                // An answer whose head is below the frame's position cannot be about this frame (a replayed answer, say): it
                // marks nothing as stored by the server's word and names no head for it. The head named at or beyond it is
                // never taken away by a later answer: the highest stays.
                val head = r.value.head
                val about = entryOf(p.frame)?.seq?.let { head.seq >= it } ?: false
                if (about) {
                    if (stillHeld(p)) keepIfHeld(p) { if (it.ackSeq != null && it.ackSeq >= head.seq) it.copy(acked = true) else it.copy(acked = true, ackSeq = head.seq, ackHash = head.hash) }
                    else noteAck(p.vaultId, hash, head.seq, head.hash)
                }
                settle(p, acknowledged = about, answer = r.value.takeIf { about }) { dropped = true } ?: if (about) unknown() else AppendOutcome.HeadMoved
            }
            is WireResult.NoAnswer -> unknown()
            // A refusal about the session (it has ended), not about the entry: nothing is said of the change, and the record
            // stands as it was, whatever its state.
            is WireResult.Refused -> if (r.status == 401) {
                keepIfHeld(p) { if (it.sends == send) it.copy(notStored = notStoredSoFar && held != null) else it }
                AppendOutcome.Pending
            } else when (r.code) {
                WireErrors.LOG_HEAD_MOVED -> {
                    // The head the refusal named: a read that ends before it says nothing of this frame.
                    if (r.error.seq != null && r.error.hash != null) keepIfHeld(p) { it.copy(namedSeq = r.error.seq, namedHash = r.error.hash) }
                    settle(p, acknowledged = false) { dropped = true } ?: AppendOutcome.HeadMoved
                }
                WireErrors.AT_AHEAD -> refusedForEntry(r.code, AppendOutcome.ClockAhead)
                // A deletion refused because the vault's items moved after its read point: the server proves the frame is
                // not stored (a retry of a stored deletion is answered 200 before the point is looked at). Dropped, never
                // "cannot tell"; its own code, so the caller reads again and may sign afresh.
                WireErrors.VAULT_ITEMS_MOVED -> { drop(); AppendOutcome.Refused(r.code) }
                // The server answers "slow down" before it looks at the frame: this send stored nothing. Known not stored
                // again only where no earlier send of it could have been and no later send was started since (the record
                // still carries this send's number); the frame is kept either way and sent again.
                WireErrors.RATE_LIMITED -> {
                    var known = false
                    keepIfHeld(p) { if (notStoredSoFar && it.sends == send) { known = true; it.copy(notStored = true) } else it }
                    when {
                        known -> AppendOutcome.Refused(r.code, r.retryAfterSeconds, held = true)
                        notStoredSoFar && !stillHeld(p) -> AppendOutcome.Refused(r.code, r.retryAfterSeconds, held = false)
                        else -> AppendOutcome.Pending
                    }
                }
                // The guard's own stop: nothing left this device, and the record stands as it was.
                io.silencelen.andvari.core.client.net.ORIGIN_STOPPED -> {
                    keepIfHeld(p) { if (it.sends == send) it.copy(notStored = notStoredSoFar && held != null) else it }
                    AppendOutcome.Pending
                }
                else -> if (r.status in 400..499) refusedForEntry(r.code, AppendOutcome.Refused(r.code)) else unknown()
            }
        }
        return outcome to dropped
    }

    /**
     * A held addition about to be sent again ([held] is the record at rest): the key in its signed entry is compared with
     * the device's current contact for that member. Where the contact is gone, has another key, or is no longer compared
     * (one released uncompared at the person's word needs only the same key), it is not sent: the record is dropped here,
     * remembered where an earlier send may have stored it (a later read that finds it says "made after all"), and a
     * [FoundKind.CONTACT_CHANGED] finding says so ([HeldFinding.final] where it was known not stored). Null where it may be sent.
     */
    private fun letGoForContact(held: Pending): AppendOutcome? {
        val e = entryOf(held.frame) as? LogEntry.Add ?: return null
        val current = host.currentContact(e.member)
        if (current != null && current.first == e.memberKey && (current.second || held.uncompared)) return null
        val knownNotStored = held.notStored && (requestsOut[frameHash(held.frame)] ?: 0) == 0
        savePending(null, held.vaultId)
        if (!knownNotStored) remember(held, LetGo.CONTACT_CHANGED, told = true)
        addFinding(held, FoundKind.CONTACT_CHANGED, final = knownNotStored)
        return AppendOutcome.NotAllowed(CONTACT_CHANGED)
    }

    private fun frameHash(frame: String): String = Bytes.toHexLower(crypto.sha256(Bytes.fromB64(frame)))

    private fun entryOf(frame: String): LogEntry? = VaultLog.parse(crypto, Bytes.fromB64(frame)).valueOrNull()?.entry

    /** True while [p]'s frame is the one held for its vault. */
    private fun stillHeld(p: Pending): Boolean = pendingRecord(p.vaultId)?.frame == p.frame

    /** Changes the held record only while it is still [p]'s frame (read afresh, so nothing a concurrent post wrote is lost). */
    private fun keepIfHeld(p: Pending, change: (Pending) -> Pending) {
        val h = pendingRecord(p.vaultId)?.takeIf { it.frame == p.frame } ?: return
        val n = change(h)
        if (n != h) savePending(n, p.vaultId)
    }

    /** [p], stamped with the engine's clock where it is a record from before [Pending.heldAt]: its day counts from now. */
    private fun stamped(p: Pending): Pending {
        if (p.heldAt != null) return p
        val s = p.copy(heldAt = clock())
        keepIfHeld(p) { if (it.heldAt == null) it.copy(heldAt = s.heldAt) else it }
        return pendingRecord(p.vaultId)?.takeIf { it.frame == p.frame } ?: s
    }

    private fun kindOf(e: LogEntry?): HeldKind = when (e) {
        is LogEntry.Genesis -> HeldKind.CREATE
        is LogEntry.Add -> HeldKind.ADD
        is LogEntry.Role -> HeldKind.ROLE
        is LogEntry.Remove -> HeldKind.REMOVE
        is LogEntry.Leave -> HeldKind.LEAVE
        is LogEntry.Offer -> HeldKind.OFFER
        is LogEntry.Cancel -> HeldKind.CANCEL
        is LogEntry.Accept -> HeldKind.ACCEPT
        is LogEntry.Delete -> HeldKind.DELETE
        is LogEntry.Restore -> HeldKind.RESTORE
        null -> HeldKind.OTHER
    }

    private fun namesOf(e: LogEntry?): String? = when (e) {
        is LogEntry.Add -> e.member
        is LogEntry.Role -> e.member
        is LogEntry.Remove -> e.member
        is LogEntry.Offer -> e.to
        else -> null
    }

    private fun describe(p: Pending): HeldChange {
        val e = entryOf(p.frame)
        val kind = kindOf(e)
        val hash = frameHash(p.frame)
        val out = (requestsOut[hash] ?: 0) > 0
        val known = when {
            // "Not stored" holds only while no send of it is out: one that is may store it.
            p.notStored && !out -> HeldKnown.NOT_STORED
            p.acked -> HeldKnown.STORED_BY_SERVERS_WORD
            else -> HeldKnown.CANNOT_TELL
        }
        val role = when (e) {
            is LogEntry.Add -> e.role.literal
            is LogEntry.Role -> e.role.literal
            else -> null
        }
        return HeldChange(
            p.vaultId, kind, namesOf(e), role, p.heldAt ?: clock(), known, out,
            // The server's own answer called it stored: it is made, and withdrawing could not undo it.
            withdrawable = kind in REGRETTABLE && !p.movesOwn && hash !in firstOut && !p.acked,
            waitsForWord = kind == HeldKind.DELETE && !p.movesOwn,
            movesOwn = p.movesOwn,
            hash = hash,
            memberKey = keyNamed(p.vaultId, e),
        )
    }

    /**
     * [HeldChange.memberKey]: the key an addition or an ownership offer names, as signed; for a removal or a change of role,
     * the member's key in the log as verified here (null where it does not list them).
     */
    private fun keyNamed(vaultId: String, e: LogEntry?): String? = when (e) {
        is LogEntry.Add -> e.memberKey
        is LogEntry.Offer -> e.toKey
        is LogEntry.Remove -> loadState(vaultId)?.members?.get(e.member)?.key
        is LogEntry.Role -> loadState(vaultId)?.members?.get(e.member)?.key
        else -> null
    }

    /** For a change of role: the role its member holds in the log as verified here (the one an undo goes back to). */
    private fun roleBeforeOf(vaultId: String, e: LogEntry?): String? =
        (e as? LogEntry.Role)?.let { loadState(vaultId)?.members?.get(it.member)?.role?.literal }

    /** The hash of the signed entry held for [vaultId] as it is at rest, settled against nothing (for tests). */
    internal fun heldEntryHash(vaultId: String): String? = pendingRecord(vaultId)?.frame?.let(::frameHash)

    /** A change of who may read the vault, or of the vault itself, held a day: not sent again (a move's deletion is the move's). */
    private fun dueToGiveUp(p: Pending): Boolean {
        val kind = kindOf(entryOf(p.frame))
        if (kind !in REGRETTABLE || (kind == HeldKind.DELETE && p.movesOwn)) return false
        // The server's own answer called it stored: never given up as "cannot tell"; it is sent as it is until the log shows it.
        if (p.acked) return false
        return clock() - (p.heldAt ?: clock()) >= GIVE_UP_MS
    }

    override fun heldChanges(): List<HeldChange> = pendingIds().mapNotNull { heldChange(it) }

    override fun heldChange(vaultId: String): HeldChange? {
        if (!readable(vaultId)) return null
        val p = pendingRecord(vaultId)?.let(::stamped) ?: return null
        // Settled first against what this device already verified (a sync's read, say), with nothing sent: a change the
        // log holds, or whose place was taken, is no longer reported as waiting.
        if (settledLocallyNow(p) != null) return null
        return describe(p)
    }

    override suspend fun lookHeld(vaultId: String): HeldLook {
        if (!readable(vaultId)) return HeldLook.Unreadable(vaultId)
        val looked = pendingRecord(vaultId) ?: return HeldLook.NothingHeld(vaultId)
        val before = completeReads[vaultId] ?: 0
        // The log is read; nothing is sent, and no other vault's change is touched.
        if (!client.stopped) refresh(vaultId, null, null, force = true)
        val p = pendingRecord(vaultId)?.let(::stamped)
            ?: return if (droppedByFreeze(vaultId, looked.frame)) HeldLook.Frozen(vaultId) else HeldLook.NothingHeld(vaultId)
        return when (val here = settledLocally(p)) {
            null -> HeldLook.StillHeld(describe(p), readReached = (completeReads[vaultId] ?: 0) > before)
            is HeldRepost.Stored -> HeldLook.Made(vaultId, here.state)
            is HeldRepost.Refused -> HeldLook.Frozen(vaultId)
            else -> HeldLook.PlaceTaken(vaultId)
        }
    }

    override fun withdrawHeld(vaultId: String): Boolean {
        if (!readable(vaultId)) return false
        val held = pendingRecord(vaultId) ?: return false
        // Known not stored only while no send of it is out.
        if (!held.notStored || (requestsOut[frameHash(held.frame)] ?: 0) > 0) return false
        savePending(null, vaultId)
        return true
    }

    override suspend fun withdraw(vaultId: String, expectHash: String): HeldWithdrawal {
        if (!readable(vaultId)) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.RECORD_UNREADABLE)
        val held = pendingRecord(vaultId)?.let(::stamped) ?: return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOTHING_HELD)
        // Only the change the caller named: another one held now is not touched (no wait between this and the drop below).
        if (frameHash(held.frame) != expectHash) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOT_THIS_CHANGE)
        // Settled first against what this device verified: a change the log already holds (or whose place was taken) is
        // not withdrawn; what was found is a finding.
        if (settledLocallyNow(held) != null) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOTHING_HELD)
        val change = describe(held)
        if (frameHash(held.frame) in firstOut) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.FIRST_REQUEST_OUT)
        if (held.acked && change.kind in REGRETTABLE && !held.movesOwn) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.STORED_BY_SERVERS_WORD)
        if (!change.withdrawable) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOT_WITHDRAWABLE)
        // Decided on the record as it is now, not on what a screen drew: no wait between this read and the drop.
        savePending(null, vaultId)
        if (change.known == HeldKnown.NOT_STORED) return HeldWithdrawal.Withdrawn(change, HeldKnown.NOT_STORED)
        remember(held, LetGo.WITHDRAWN, told = false)
        // The log is read now where it can be; what the read finds is kept for the layer ([checkWatches]). The withdrawal
        // has taken effect: a lock that cuts off this read does not make it answer otherwise (the next read looks).
        if (!client.stopped) {
            try {
                refresh(vaultId, null, null, force = true)
            } catch (e: KeysGoneException) {
                // Locked during the read: what it would have found is found by the next read of the vault.
            }
        }
        return HeldWithdrawal.Withdrawn(change, change.known)
    }

    override fun dropHalfMade(vaultId: String): HeldWithdrawal {
        if (!readable(vaultId)) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.RECORD_UNREADABLE)
        val held = pendingRecord(vaultId)?.let(::stamped) ?: return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOTHING_HELD)
        // Settled already by what this device verified: nothing is held to drop (a finding says what was found).
        if (settledLocallyNow(held) != null) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOTHING_HELD)
        val change = describe(held)
        if (change.kind != HeldKind.DELETE) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.NOT_A_DELETION)
        if (frameHash(held.frame) in firstOut) return HeldWithdrawal.Kept(vaultId, HeldWithdrawal.FIRST_REQUEST_OUT)
        // Decided on the record as it is now: no wait between this read and the drop. Nothing is sent or read.
        savePending(null, vaultId)
        if (change.known == HeldKnown.NOT_STORED) return HeldWithdrawal.Withdrawn(change, HeldKnown.NOT_STORED)
        // Remembered as a kind of its own, with no "not made" line: only a log that holds it after all is told.
        remember(held, LetGo.HALF_MADE, told = true)
        return HeldWithdrawal.Withdrawn(change, change.known)
    }

    // ---- what this device let go of, and what the person must be told ----

    private val watchIndexKey = "ovh.log|$me|found-index"

    private fun loadWatches(vaultId: String): MutableList<Watch> = state.get(k(vaultId, "watch"))
        ?.let { runCatching { WireJson.json.decodeFromString(ListSerializer(Watch.serializer()), it) }.getOrNull() }?.toMutableList() ?: ArrayList()

    private fun saveWatches(vaultId: String, list: List<Watch>) {
        putRecord(k(vaultId, "watch"), if (list.isEmpty()) null else WireJson.json.encodeToString(ListSerializer(Watch.serializer()), list))
    }

    private fun loadFound(vaultId: String): MutableList<Found> = state.get(k(vaultId, "found"))
        ?.let { runCatching { WireJson.json.decodeFromString(ListSerializer(Found.serializer()), it) }.getOrNull() }?.toMutableList() ?: ArrayList()

    private fun foundIds(): List<String> = state.get(watchIndexKey)?.split(',')?.filter { it.isNotEmpty() } ?: emptyList()

    private fun saveFound(vaultId: String, list: List<Found>) {
        putRecord(k(vaultId, "found"), if (list.isEmpty()) null else WireJson.json.encodeToString(ListSerializer(Found.serializer()), list))
        val ids = foundIds().toMutableSet()
        if (list.isEmpty()) ids -= vaultId else ids += vaultId
        putRecord(watchIndexKey, ids.sorted().joinToString(",").ifEmpty { null })
    }

    private fun untoldWithdrawal(vaultId: String): Boolean = try {
        loadWatches(vaultId).any { it.why == LetGo.WITHDRAWN.name && !it.told }
    } catch (e: Exception) {
        if (e is KeysGoneException) throw e
        false
    }

    /** [p] remembered by its entry's hash and position. A memory of the same frame already kept (a withdrawal's) is never overwritten. */
    private fun remember(p: Pending, why: LetGo, told: Boolean) {
        val e = entryOf(p.frame) ?: return
        val hash = frameHash(p.frame)
        val list = loadWatches(p.vaultId)
        if (list.any { it.hash == hash }) return
        list += Watch(hash, e.seq, kindOf(e).name, namesOf(e), e.at, why.name, p.namedSeq, p.namedHash, clock(), told, p.ackSeq, p.ackHash,
            keyNamed(p.vaultId, e), roleBeforeOf(p.vaultId, e))
        // Bounded: withdrawals already told "not made" go first, then changes given up (or dropped by a move), then
        // withdrawals not told yet, each oldest first. The cost: past the bound, the oldest of those is never told if the
        // server makes it after all.
        while (list.size > MAX_WATCHES) list.remove(list.minWith(compareBy<Watch>({ evictionRank(it) }, { it.since })))
        saveWatches(p.vaultId, list)
    }

    private fun evictionRank(w: Watch): Int = when {
        w.why == LetGo.WITHDRAWN.name && w.told -> 0
        w.why != LetGo.WITHDRAWN.name -> 1
        else -> 2
    }

    private fun addFinding(vaultId: String, hash: String, kind: String, names: String?, signedAt: Long, what: FoundKind,
                           letGo: LetGo? = null, final: Boolean = false, absentAtRead: Boolean = false, code: String? = null,
                           memberKey: String? = null, roleBefore: String? = null) {
        val id = findingId(what, vaultId, hash)
        val list = loadFound(vaultId)
        if (list.any { it.id == id }) return
        // The server's code is its own text: kept at rest only as a code this client knows, else as "other".
        val kept = code?.let { if (it in KNOWN_REFUSALS) it else OTHER_REFUSAL }
        list += Found(id, kind, names, what.name, letGo?.name, final, absentAtRead, kept, signedAt, clock(), memberKey, roleBefore)
        // Bounded, oldest first; a change found made (after all, or a deletion that waited) goes only when nothing else is left.
        while (list.size > MAX_FINDINGS) list.remove(list.minWith(compareBy<Found>({ it.what == FoundKind.MADE_AFTER_ALL.name || it.what == FoundKind.MADE.name }, { it.at })))
        saveFound(vaultId, list)
    }

    private fun addFinding(p: Pending, what: FoundKind, letGo: LetGo? = null, final: Boolean = false, absentAtRead: Boolean = false, code: String? = null) {
        val e = entryOf(p.frame)
        addFinding(p.vaultId, frameHash(p.frame), kindOf(e).name, namesOf(e), e?.at ?: 0, what, letGo, final, absentAtRead, code,
            keyNamed(p.vaultId, e), roleBeforeOf(p.vaultId, e))
    }

    /**
     * "Absent" may be said from a read only where no answer named a head, or where the read reached the named head with the
     * same hash (CL, second point): a read that ends before a head the server named says nothing of the frame.
     */
    private fun readReachesNamed(namedSeq: Long?, namedHash: String?, hashes: Map<Long, String>): Boolean =
        namedSeq == null || (namedHash != null && hashes[namedSeq] == namedHash)

    /**
     * Where a `200` answer named a frame at [seq] (hash [hash]) stored under a head [ackSeq]/[ackHash] at or beyond it:
     * the position at which the verified log ([hashes]) contradicts that answer (another entry at the frame's own position,
     * or another hash at the named head), or null: no such answer, the log holds the frame (made, whatever else the answer
     * said), or nothing read there yet (short of those positions nothing is said). An answer naming a head below the frame
     * cannot be this frame's (a replayed answer, say): it is no answer about it and is never kept ([Pending.ackSeq]).
     */
    private fun contradiction(seq: Long?, hash: String, ackSeq: Long?, ackHash: String?, hashes: Map<Long, String>): Long? {
        if (ackSeq == null || seq == null || ackSeq < seq || hash in hashes.values) return null
        hashes[seq]?.let { if (it != hash) return seq }
        if (ackHash != null) hashes[ackSeq]?.let { if (it != ackHash) return ackSeq }
        return null
    }

    /** The server's answer and its log cannot both be true: the vault is frozen as for any fork (sticky). */
    private fun freeze(vaultId: String, at: Long, hash: String) {
        setFlag(vaultId, "frozen:$at")
        // The freeze rule says nothing of the change: a "its place was taken" kept for it is taken back.
        val list = loadFound(vaultId)
        if (list.removeAll { it.id == findingId(FoundKind.PLACE_TAKEN, vaultId, hash) }) saveFound(vaultId, list)
    }

    private fun findingId(what: FoundKind, vaultId: String, hash: String) = "${what.name.lowercase()}:$vaultId:$hash"

    /** A `200` that arrived for [hash] after it was let go of: its head goes into the memory. */
    private fun noteAck(vaultId: String, hash: String, seq: Long, headHash: String) {
        val list = loadWatches(vaultId)
        if (list.none { it.hash == hash }) return
        saveWatches(vaultId, list.map { if (it.hash == hash && (it.ackSeq == null || it.ackSeq < seq)) it.copy(ackSeq = seq, ackHash = headHash) else it })
    }

    /** The memory of [hash] ends with nothing said (the vault was frozen over it). */
    private fun forgetWatch(vaultId: String, hash: String) {
        val list = loadWatches(vaultId)
        if (list.any { it.hash == hash }) saveWatches(vaultId, list.filter { it.hash != hash })
    }

    /**
     * At a read of [vaultId]'s log that reached the server and verified to its served head ([hashes]): each memory is
     * looked for. Held: "made after all", kept as a finding, the memory ends. Another entry at its position: the memory
     * ends (a withdrawal not yet told is told "not made", for good). Its position free: a withdrawal not yet told is told
     * "not made" as the log shows it, once, and stays remembered, unless an answer named a head this read does not reach
     * or a request of that very frame is out from this engine now (its answer may still store it).
     */
    private fun checkWatches(vaultId: String, hashes: Map<Long, String>) {
        val list = try { loadWatches(vaultId) } catch (e: Exception) { if (e is KeysGoneException) throw e; return }
        if (list.isEmpty()) return
        val known = hashes.values.toHashSet()
        val keep = ArrayList<Watch>()
        var changed = false
        for (w in list) {
            val withdrawn = w.why == LetGo.WITHDRAWN.name
            val contradicted = contradiction(w.seq, w.hash, w.ackSeq, w.ackHash, hashes)
            if (contradicted != null) freeze(vaultId, contradicted, w.hash)
            when {
                w.hash in known -> {
                    addFinding(vaultId, w.hash, w.kind, w.names, w.signedAt, FoundKind.MADE_AFTER_ALL, letGo = LetGo.valueOf(w.why),
                        memberKey = w.memberKey, roleBefore = w.roleBefore)
                    changed = true
                }
                // The server's answer named it there and the log says otherwise: frozen, and nothing is said of it.
                contradicted != null -> changed = true
                hashes[w.seq] != null -> {
                    if (withdrawn && !w.told) addFinding(vaultId, w.hash, w.kind, w.names, w.signedAt, FoundKind.NOT_MADE, final = true,
                        memberKey = w.memberKey, roleBefore = w.roleBefore)
                    changed = true
                }
                // "Not made" never where a 200 named it: the server said it holds it.
                withdrawn && !w.told && w.ackSeq == null && readReachesNamed(w.namedSeq, w.namedHash, hashes) && (requestsOut[w.hash] ?: 0) == 0 -> {
                    addFinding(vaultId, w.hash, w.kind, w.names, w.signedAt, FoundKind.NOT_MADE, final = false,
                        memberKey = w.memberKey, roleBefore = w.roleBefore)
                    keep += w.copy(told = true)
                    changed = true
                }
                else -> keep += w
            }
        }
        if (changed) saveWatches(vaultId, keep)
    }

    /**
     * At the same read: the held change is looked at for a contradiction only, as the memories are. A `200` named it stored
     * at or beyond its position and the log holds another entry there: the vault freezes at this read, the record is dropped,
     * a "place taken" kept for it is taken back, and nothing is said of it. Whether it is stored, or its place was taken,
     * stays with the roads that settle a held change. A road whose own read dropped its frame here answers frozen
     * ([frozenAtRead]).
     */
    private fun checkHeld(vaultId: String, hashes: Map<Long, String>) {
        val p = pendingRecord(vaultId) ?: return
        val hash = frameHash(p.frame)
        val at = contradiction(entryOf(p.frame)?.seq, hash, p.ackSeq, p.ackHash, hashes) ?: return
        freeze(vaultId, at, hash)
        savePending(null, vaultId)
        forgetWatch(vaultId, hash)
        frozenAtRead[vaultId] = hash
    }

    /**
     * At a read that froze [vaultId] at [at] over another chain: a change held at or after that place, which the verified
     * entries ([hashes]) do not hold, names an entry of the chain the served one left, so it can never be stored. It is
     * dropped as at a freeze over a held change ([checkHeld]): nothing is said of it, and the roads that settle a held
     * change answer frozen ([frozenAtRead]).
     */
    private fun dropHeldPastFork(vaultId: String, at: Long, hashes: Map<Long, String>) {
        val p = pendingRecord(vaultId) ?: return
        val hash = frameHash(p.frame)
        val seq = entryOf(p.frame)?.seq ?: return
        if (seq < at || hash in hashes.values) return
        savePending(null, vaultId)
        forgetWatch(vaultId, hash)
        frozenAtRead[vaultId] = hash
    }

    /** By vault: the hash of the held frame a read dropped because the vault froze over it ([checkHeld]). */
    private val frozenAtRead = HashMap<String, String>()

    private fun droppedByFreeze(vaultId: String, frame: String): Boolean = frozenAtRead[vaultId] == frameHash(frame)

    override fun heldFindings(): List<HeldFinding> = foundIds().flatMap { vaultId ->
        loadFound(vaultId).map {
            HeldFinding(it.id, vaultId, runCatching { HeldKind.valueOf(it.kind) }.getOrDefault(HeldKind.OTHER), it.names,
                FoundKind.valueOf(it.what), it.letGo?.let(LetGo::valueOf), it.final, it.absentAtRead, it.code, it.signedAt, it.at,
                it.memberKey, it.roleBefore)
        }
    }

    override fun findingShown(id: String) {
        for (vaultId in foundIds()) {
            val list = loadFound(vaultId)
            if (list.removeAll { it.id == id }) saveFound(vaultId, list)
        }
    }

    /**
     * A held change of a day, not sent again: the log is read first. Held there: stored. Its place taken: dropped, never to
     * be made. Otherwise given up: dropped, and remembered where it may have reached the server. Like a send, it acts only
     * while the held record is still [p]'s frame after the read (a change withdrawn or signed meanwhile is never dropped,
     * and a withdrawal's memory is never overwritten), and never while a request of that frame is out.
     */
    private suspend fun giveUp(p: Pending): HeldResend {
        val before = completeReads[p.vaultId] ?: 0
        if (!client.stopped) refresh(p.vaultId, null, null, force = true)
        val cur = pendingRecord(p.vaultId)?.takeIf { it.frame == p.frame }
            ?: return if (droppedByFreeze(p.vaultId, p.frame)) HeldResend.Frozen(p.vaultId) else HeldResend.NotHeld(p.vaultId)
        val hash = frameHash(cur.frame)
        val hashes = loadHashes(p.vaultId)
        val seq = entryOf(cur.frame)?.seq
        val contradicted = contradiction(seq, hash, cur.ackSeq, cur.ackHash, hashes)
        if (contradicted != null) freeze(p.vaultId, contradicted, hash)
        if (hash in hashes.values) {
            savePending(null, p.vaultId)
            if (personsDeletion(cur)) addFinding(cur, FoundKind.MADE)
            val s = loadState(p.vaultId) ?: return HeldResend.Waiting(p.vaultId)
            return HeldResend.Stored(p.vaultId, view(s))
        }
        if (contradicted != null) {
            savePending(null, p.vaultId)
            return HeldResend.Frozen(p.vaultId)
        }
        if (seq != null && hashes[seq] != null) {
            savePending(null, p.vaultId)
            addFinding(cur, FoundKind.PLACE_TAKEN)
            return HeldResend.PlaceTaken(p.vaultId)
        }
        if ((requestsOut[hash] ?: 0) > 0) return HeldResend.Waiting(p.vaultId)
        // A try answered during the read with the server's word that it stored it: kept, and sent as it is.
        if (cur.acked) return HeldResend.Waiting(p.vaultId)
        val reached = (completeReads[p.vaultId] ?: 0) > before
        savePending(null, p.vaultId)
        val notStored = cur.notStored
        if (!notStored) remember(cur, LetGo.GIVEN_UP, told = true)
        addFinding(cur, FoundKind.GIVEN_UP, final = notStored, absentAtRead = !notStored && reached && readReachesNamed(cur.namedSeq, cur.namedHash, hashes))
        return HeldResend.GivenUp(p.vaultId)
    }

    /** One held change sent again by the general re-send; a drop it made is kept as a finding. */
    private suspend fun resendOne(p: Pending): HeldResend {
        val (r, dropped) = postTracked(p)
        if (r is AppendOutcome.Appended) return HeldResend.Stored(p.vaultId, r.state)
        if (stillHeld(p)) return HeldResend.Waiting(p.vaultId)
        if (!dropped) return HeldResend.NotHeld(p.vaultId)
        return when (r) {
            AppendOutcome.HeadMoved -> { addFinding(p, FoundKind.PLACE_TAKEN); HeldResend.PlaceTaken(p.vaultId) }
            AppendOutcome.VaultReadOnly -> HeldResend.Frozen(p.vaultId)
            // Refused for the entry while its outcome could not be told: given up, with its reason, and remembered.
            AppendOutcome.Pending -> HeldResend.GivenUp(p.vaultId)
            // An addition whose contact changed: let go of unsent (its finding says so).
            is AppendOutcome.NotAllowed -> if (r.reason == CONTACT_CHANGED) HeldResend.ContactChanged(p.vaultId) else HeldResend.NotHeld(p.vaultId)
            AppendOutcome.ClockAhead -> { addFinding(p, FoundKind.REFUSED, code = WireErrors.AT_AHEAD); HeldResend.Refused(p.vaultId, WireErrors.AT_AHEAD) }
            is AppendOutcome.Refused -> { addFinding(p, FoundKind.REFUSED, code = r.code); HeldResend.Refused(p.vaultId, r.code) }
            else -> HeldResend.NotHeld(p.vaultId)
        }
    }

    override suspend fun resendHeld(): List<HeldResend> {
        if (client.stopped) return emptyList()
        val out = ArrayList<HeldResend>()
        for (id in pendingIds()) {
            if (!readable(id)) continue
            val p = pendingRecord(id)?.let(::stamped) ?: continue
            val kind = kindOf(entryOf(p.frame))
            val here = settledLocally(p)
            out += when {
                here is HeldRepost.Stored -> HeldResend.Stored(id, here.state)
                here is HeldRepost.Refused -> HeldResend.Frozen(id)
                here != null -> HeldResend.PlaceTaken(id)
                kind == HeldKind.DELETE && p.movesOwn -> HeldResend.MovesOwn(id)
                dueToGiveUp(p) -> giveUp(p)
                kind == HeldKind.DELETE -> HeldResend.WaitsForWord(id)
                else -> resendOne(p)
            }
        }
        return out
    }

    /**
     * After an acknowledgement or a `log_head_moved`: refetch and look for OUR frame in the verified log.
     * - Stored: the pending record goes and the state includes it.
     * - Acknowledged but not visible yet (the refetch failed): the record stays and is re-posted byte for
     *   byte later; the server answers a byte-identical frame `200` (spec 03 §10.3).
     * - Head moved: the frame is discarded only once this device has VERIFIED another entry at its
     *   position (null: the caller may sign afresh at the new head); otherwise the record stays.
     * - Contradicted: a `200` named this frame stored under a head at or beyond its position (now or earlier), and the
     *   verified log, which does not hold the frame, holds another entry there or another hash at the head it named: the
     *   vault is frozen, the frame is dropped and nothing is said of it ([AppendOutcome.VaultReadOnly]). Short of those
     *   positions nothing is said yet.
     */
    private suspend fun settle(p: Pending, acknowledged: Boolean, answer: LogAppendResponse? = null, onDrop: () -> Unit = {}): AppendOutcome? {
        val frame = Bytes.fromB64(p.frame)
        val frameHash = Bytes.toHexLower(crypto.sha256(frame))
        refresh(p.vaultId, null, null, force = true)
        // That read froze the vault over this very frame and dropped it: frozen, and nothing is said of it.
        if (!stillHeld(p) && droppedByFreeze(p.vaultId, p.frame)) { onDrop(); return AppendOutcome.VaultReadOnly }
        // The read was a wait: only a record that is still this frame is dropped (a change withdrawn meanwhile stays gone,
        // and its memory tells the person; a change signed meanwhile is never dropped by this one's outcome).
        fun drop() { if (stillHeld(p)) { savePending(null, p.vaultId); onDrop() } }
        val hashes = loadHashes(p.vaultId)
        val seqOf = VaultLog.parse(crypto, frame).valueOrNull()?.entry?.seq
        // The head a 200 named (this answer's, or an earlier one's kept with the record or its memory): another entry at
        // either position is a contradiction between the server's answer and its log.
        val kept = pendingRecord(p.vaultId)?.takeIf { it.frame == p.frame } ?: p
        // The highest head named at or beyond the frame: the one kept, or this answer's where it is higher.
        val fromAnswer = answer?.head?.takeIf { kept.ackSeq == null || it.seq > kept.ackSeq }
        val ackSeq = fromAnswer?.seq ?: kept.ackSeq
        val ackHash = fromAnswer?.hash ?: kept.ackHash
        val contradicted = contradiction(seqOf, frameHash, ackSeq, ackHash, hashes)
        if (contradicted != null) freeze(p.vaultId, contradicted, frameHash)
        if (frameHash in hashes.values) {
            drop()
            val s = loadState(p.vaultId) ?: return AppendOutcome.Pending
            // The append's own `deleted` (the answer to the `delete` itself), when the refetch did not carry one.
            answer?.let { noteGrace(s, it.head, it.deleted, replace = false) }
            if (s.creator == me && s.head.seq == 0L) writeVaultRecord(s)
            return AppendOutcome.Appended(view(s))
        }
        if (contradicted != null) {
            // Frozen; nothing is said of the change, and it is neither kept nor remembered.
            drop()
            forgetWatch(p.vaultId, frameHash)
            return AppendOutcome.VaultReadOnly
        }
        if (acknowledged) return AppendOutcome.Pending
        val seq = seqOf ?: return AppendOutcome.Pending
        if (hashes[seq] == null) return AppendOutcome.Pending
        drop()
        return null
    }

    override suspend fun repostHeld(vaultId: String, expectHash: String): HeldRepost {
        // A record that cannot be read says nothing either way; it is not rebuilt, and nothing is sent for it.
        if (!readable(vaultId)) return HeldRepost.Waiting
        // This is the call of its own (the person's word, or a move's own road): it sends a held deletion too, and it does
        // not give a change up after a day; the general re-send ([resendHeld]) does neither.
        val held = pendingRecord(vaultId)?.let(::stamped) ?: return HeldRepost.NothingHeld
        // Only the change the caller named: another one held now is never sent by this call.
        if (frameHash(held.frame) != expectHash) return HeldRepost.NotThisChange
        settledHere(held)?.let { return it }
        if (client.stopped) return HeldRepost.Waiting
        // The held frame only: [post] signs nothing, and checks the keys are still there before it sends.
        val (r, dropped) = postTracked(held)
        if (r is AppendOutcome.Appended) return HeldRepost.Stored(r.state)
        if (stillHeld(held)) return HeldRepost.Waiting
        // Withdrawn while it was out: not this call's to say anything of.
        if (!dropped) return HeldRepost.NothingHeld
        return when (r) {
            AppendOutcome.HeadMoved -> HeldRepost.Dropped
            AppendOutcome.VaultReadOnly -> HeldRepost.Refused(VAULT_FROZEN)
            // Refused for the entry while its outcome could not be told: given up and remembered; the GIVEN_UP finding (with
            // the refusal's code) says it, never "refused, not made" (a later read may show it made).
            AppendOutcome.Pending -> HeldRepost.RefusedCannotTell(
                loadFound(vaultId).firstOrNull { it.id == findingId(FoundKind.GIVEN_UP, vaultId, frameHash(held.frame)) }?.code ?: OTHER_REFUSAL)
            AppendOutcome.ClockAhead -> HeldRepost.Refused(WireErrors.AT_AHEAD)
            is AppendOutcome.Refused -> HeldRepost.Refused(r.code, r.retryAfterSeconds)
            else -> HeldRepost.Waiting
        }
    }

    override suspend fun retryPending() {
        resendHeld()
    }

    /** [settledLocallyNow], and the vault record of a genesis it found stored. */
    private suspend fun settledLocally(p: Pending): HeldRepost? = settledLocallyNow(p).also { genesisRecord(p.vaultId, it) }

    /**
     * [settledHereNow] for the general roads (every road but the person's own "delete it now"): a held change whose place
     * was taken is kept as a [FoundKind.PLACE_TAKEN] finding, and the person's own deletion of a vault found stored as a
     * [FoundKind.MADE] one (the vault was deleted; it can be restored while its grace lasts).
     */
    private fun settledLocallyNow(p: Pending): HeldRepost? = settledHereNow(p).also {
        if (it == HeldRepost.Dropped) addFinding(p, FoundKind.PLACE_TAKEN)
        if (it is HeldRepost.Stored && personsDeletion(p)) addFinding(p, FoundKind.MADE)
    }

    private fun personsDeletion(p: Pending): Boolean = !p.movesOwn && kindOf(entryOf(p.frame)) == HeldKind.DELETE

    /** [settledHereNow], and the vault record of a genesis it found stored. */
    private suspend fun settledHere(p: Pending): HeldRepost? = settledHereNow(p).also { genesisRecord(p.vaultId, it) }

    private suspend fun genesisRecord(vaultId: String, r: HeldRepost?) {
        if (r !is HeldRepost.Stored) return
        val s = loadState(vaultId) ?: return
        if (s.creator == me && s.head.seq == 0L) writeVaultRecord(s)
    }

    /**
     * [p] settled by what this device already verified (a sync read the log since), with nothing sent: the log holds it
     * (stored), or another entry holds its position (dropped, never to be stored). Null when neither: it still waits.
     */
    private fun settledHereNow(p: Pending): HeldRepost? {
        val hashes = loadHashes(p.vaultId)
        val hash = frameHash(p.frame)
        val seq = entryOf(p.frame)?.seq
        // A 200 named it, and the log holds another entry at its position or another hash at the named head: frozen.
        val contradicted = contradiction(seq, hash, p.ackSeq, p.ackHash, hashes)
        if (contradicted != null) freeze(p.vaultId, contradicted, hash)
        if (hash in hashes.values) {
            savePending(null, p.vaultId)
            val s = loadState(p.vaultId) ?: return HeldRepost.Waiting
            return HeldRepost.Stored(view(s))
        }
        if (contradicted != null) {
            savePending(null, p.vaultId)
            return HeldRepost.Refused(VAULT_FROZEN)
        }
        if (seq != null && hashes[seq] != null) {
            savePending(null, p.vaultId)
            return HeldRepost.Dropped
        }
        return null
    }

    companion object {
        /** How long an unanswered or refused self-wrap post waits before [ensureSelfWrap] tries it again. */
        const val WRAP_RETRY_MS: Long = 60_000

        const val MAX_PAGES = 1000

        /** How long a held change of [REGRETTABLE] kind is sent again before it is given up (by the engine's clock). */
        const val GIVE_UP_MS: Long = 24L * 60 * 60 * 1000

        /**
         * The memories of let-go changes kept per vault ([remember]). Past it, withdrawals already told "not made" go first,
         * then changes given up or dropped by a move, then withdrawals not told yet, each oldest first. The cost: a person
         * who lets go of more than this many changes to one vault while nothing reaches it is not told if the server makes
         * the one that went after all.
         */
        const val MAX_WATCHES = 16

        /**
         * The findings kept per vault until shown; the oldest go first, but a change found made ([FoundKind.MADE_AFTER_ALL],
         * [FoundKind.MADE]) only when every finding left is one. The cost: past it, the oldest notice is lost unshown.
         */
        const val MAX_FINDINGS = 32

        /** [HeldFinding.code] for a refusal code this client does not know (the server's own text is never kept). */
        const val OTHER_REFUSAL = "other"

        /**
         * [AppendOutcome.NotAllowed] of a held addition's re-send: the contact it names is gone, has another key or is no
         * longer compared, so it was let go of unsent ([FoundKind.CONTACT_CHANGED]).
         */
        const val CONTACT_CHANGED = "contact_changed"

        /** The refusal codes of a log append this client knows ([HeldFinding.code]); any other is kept as [OTHER_REFUSAL]. */
        private val KNOWN_REFUSALS = setOf(
            WireErrors.AT_AHEAD, WireErrors.BAD_AFTER, WireErrors.BAD_EXPIRY, WireErrors.BAD_FRAME, WireErrors.BAD_GRANT,
            WireErrors.BAD_META_BLOB, WireErrors.BAD_REQUEST, WireErrors.BAD_SIGNATURE, WireErrors.BAD_SIGNER,
            WireErrors.BAD_STATEMENT, WireErrors.BAD_WRAPPED_VK, WireErrors.MEMBER_LIMIT, WireErrors.NO_GRANT,
            WireErrors.NON_CANONICAL, WireErrors.NOT_CONNECTED, WireErrors.NOT_SHARED_VAULT, WireErrors.NOT_VAULT_OWNER,
            WireErrors.OFFER_EXPIRED, WireErrors.OWNER_WRAP_IMMUTABLE, WireErrors.PRECONDITION, WireErrors.STALE_META,
            WireErrors.VAULT_DELETED, WireErrors.VAULT_ID_TAKEN, WireErrors.WRONG_VAULT, WireErrors.RATE_LIMITED,
            WireErrors.VAULT_ITEMS_MOVED, WireErrors.LOG_HEAD_MOVED,
        )

        /** The kinds a person could come to regret: shown as waiting, withdrawable, given up after a day. */
        private val REGRETTABLE = setOf(HeldKind.ADD, HeldKind.REMOVE, HeldKind.ROLE, HeldKind.OFFER, HeldKind.DELETE)

        /**
         * The log engine of [account]'s session, with its keys taken from the opened account itself, so a host never holds
         * them as values (its signing and identity keys and its UVK stay inside the engine, and [account]'s wipe wipes
         * them here too). The same engine as the constructor's.
         */
        fun forAccount(
            account: io.silencelen.andvari.core.client.onboard.OpenedAccount,
            client: WireClient,
            crypto: CryptoProvider,
            state: DeviceState,
            store: AccountStateStore,
            host: VaultLogHost,
            clock: () -> Long,
            bundleCheckpoint: (vaultId: String) -> Checkpoint?,
        ): StoredVaultLogs = StoredVaultLogs(account.userId, account.signing, account.identity, account.uvk, client, crypto, state, store, host, clock, bundleCheckpoint)

        /**
         * Removes everything this engine keeps for account [userId] in [state] (every `ovh.log|<userId>|…` record: verified
         * states and hashes, held changes, memories and findings, and their indexes), for an account's deletion on this
         * device. Nothing is dialed. True when all of it is gone; false when the store cannot list its keys (the indexed
         * held changes and findings and the mark that the records stand are removed then, and the rest stays) or a removal
         * failed.
         *
         * From this call on, no engine that was over these records before it writes or removes anything of the account, nor
         * sends a write it had not sent yet: a request already out when the account is forgotten writes nothing when its
         * answer comes (it ends in [AccountForgottenException], a [KeysGoneException]). An engine made after it (the account
         * signed in again) starts afresh and is not touched by the older one.
         */
        fun forgetAccount(state: DeviceState, userId: String): Boolean = synchronized(writeLock) {
            val prefix = "ovh.log|$userId|"
            var all = true
            val keys = try { state.keys() } catch (e: Exception) { null }
            val doomed = if (keys != null) {
                keys.filter { it.startsWith(prefix) }
            } else {
                all = false
                val listed = listOf("pending-index", "found-index").flatMap { idx ->
                    (try { state.get(prefix + idx) } catch (e: Exception) { null })?.split(',')?.filter { it.isNotEmpty() } ?: emptyList()
                }
                listed.flatMap { v -> listOf("pending", "watch", "found").map { recordKey(userId, v, it) } } +
                    listOf(prefix + "pending-index", prefix + "found-index", prefix + LIVE_PART)
            }
            for (key in doomed) {
                try { state.set(key, null) } catch (e: Exception) { all = false }
            }
            all
        }

        /**
         * One lock for every record write of every engine and for [forgetAccount], so that the check that the account's
         * records stand ([LIVE_PART]) and the write after it are one step against a forgetting on another thread.
         */
        private val writeLock = SynchronizedObject()

        /**
         * [recordKey]-style part (account-wide, `ovh.log|<userId>|live`) holding a random token, written by the first engine
         * over the account's records and read by every later one. Its absence, or another token, means the records were
         * forgotten since this engine began: it writes nothing more ([AccountForgottenException]).
         */
        internal const val LIVE_PART = "live"

        /** The one spelling of the key of every per-vault record this engine keeps for account [me] (`k`, [storedHead]). */
        internal fun recordKey(me: String, vaultId: String, part: String): String = "ovh.log|$me|$vaultId|$part"

        /** [recordKey]'s part for the verified state. */
        internal const val STATE_PART = "state"

        /** [recordKey]'s part for the server's `deleted` ([serverGraceEnd]); not a trust record. */
        internal const val GRACE_PART = "grace"

        /**
         * The head this device verified for [vaultId]'s log as [me], read from [state] where this engine keeps it (same key
         * and codec), when that log's genesis is [genesisHash]; null when none is stored, it does not decode, it is another
         * log, or the store cannot be read (the caller then keeps its own lower value: never raised from an unread record).
         */
        internal fun storedHead(state: DeviceState, me: String, vaultId: String, genesisHash: String): Checkpoint? = try {
            state.get(recordKey(me, vaultId, STATE_PART))?.let(VaultState::decode)
                ?.takeIf { it.vaultId == vaultId && it.genesisHash == genesisHash }
                ?.let { Checkpoint(it.head.seq, it.head.hash) }
        } catch (e: Exception) {
            null
        }

        /**
         * [AppendOutcome.NotAllowed]'s reason while a frame this device signed for the vault is still unanswered after its
         * re-post (design §3.7): the app says the last change to this vault has not reached the server yet.
         */
        const val APPEND_PENDING = "append_pending"

        /**
         * [AppendOutcome.NotAllowed]'s reason for an append with an expected head that is not the verified head the engine
         * would sign over: the log moved on since the caller checked it. Nothing was signed; the caller reads again.
         */
        const val LOG_MOVED_ON = "log_moved_on"

        /** [AppendOutcome.NotAllowed]'s reason for an action that names the all-zero user id ([io.silencelen.andvari.core.client.UserIds.NIL]): nothing was built. */
        const val NIL_USER_ID = "nil_user_id"

        /** [AppendOutcome.NotAllowed]'s reason when an expected head is given for a [LogAction.Create]: a new vault has none. */
        const val BAD_EXPECT_HEAD = "bad_expect_head"

        /** [AppendOutcome.NotAllowed]'s reason from an engine that cannot compare an expected head: nothing was signed. */
        const val EXPECT_HEAD_UNSUPPORTED = "expect_head_unsupported"

        /** [VaultLogStatus.Failed]'s reason when a trust record this engine keeps for the vault cannot be read (design §4.4). */
        const val RECORD_UNREADABLE = "record_unreadable"

        /**
         * [HeldRepost.Refused]'s code where the server's own `200` named the held change at its position and the verified
         * log holds another entry there (or another hash at the head it named): the vault is frozen and the change is
         * dropped, with nothing said of it ([HeldResend.Frozen] on the general re-send).
         */
        const val VAULT_FROZEN = "vault_frozen"

        /** [LogAction.Create] with a vault id that is not a lowercase uuid. */
        const val BAD_VAULT_ID = "bad_vault_id"

        /** [LogAction.Create] with a vault id this device holds for a vault this account did not create (or cannot judge). */
        const val VAULT_ID_TAKEN = "vault_id_taken"

        /** How long an unresolved item-head chase holds off the next one while the verified head stays put. */
        const val HINT_BACKOFF_MS: Long = 10L * 60 * 1000

        /** How long a departed vault's key stays offered for copy-out: the holding area's 30 days (spec 02 §10.6). */
        const val HOLDING_MS: Long = 30L * 24 * 60 * 60 * 1000
    }
}

/**
 * The account's vault-log records were forgotten on this device ([StoredVaultLogs.forgetAccount]) while this engine was
 * at work: nothing more of the account is written, removed or sent by it. A [KeysGoneException], so every caller that
 * stops quietly at a lock stops so here too; the account is gone from this device.
 */
class AccountForgottenException : KeysGoneException("this account was forgotten on this device: nothing more of it is written")

/**
 * This device's records could not be read or written when the vault-log engine began, so it could not tell later whether
 * the account's records still stand: it writes nothing of the account and sends no write of its state. The store's
 * fault, never said as the account forgotten nor as a lock; a new engine (the next unlock) tries again.
 */
class LogStoreFaultException : IllegalStateException("this device's records could not be read when the vault-log engine began: nothing is written")
