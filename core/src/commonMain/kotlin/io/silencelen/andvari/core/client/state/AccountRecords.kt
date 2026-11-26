package io.silencelen.andvari.core.client.state

/**
 * The records of the UVK-sealed account-state document after the cut-over (design §5.4, spec 02 §9),
 * and their merge rules, pinned by `spec/test-vectors/accountstate.json`.
 *
 * Who can write: any holder of the account's UVK (the account's devices, a hostile web bundle, the
 * operator of an operator-posture account who opened its escrow; R35). The server alone can only serve
 * an older copy. So a record here can REFUSE (a vault record refuses a log; a key-change contact goes
 * to the prompt) but never makes anything pass on its own.
 */

/**
 * A contact (design §6.9). [label] is the `name` type (base64url UTF-8). [method] is always `link`; a
 * decoder refuses any other value. [compared] is set only by this device's own typed match (design
 * §6.11) and merges as OR between records with the same key. [madeOn] is the device that made the pin;
 * shown in the per-device prompt only, never trusted (a web bundle can forge it).
 */
data class ContactRecord(
    val userId: String,
    /** `b64_32` X25519 identity key. */
    val identityPub: String,
    val label: String,
    val method: String = METHOD_LINK,
    val verifiedAt: Long,
    val compared: Boolean,
    val madeOn: String,
    /** Fields this build does not know, as raw JSON by name, kept and written back as they came (design §5.4 "Edges"). */
    val extra: Map<String, String> = emptyMap(),
) {
    companion object {
        const val METHOD_LINK = "link"
    }
}

/** A removed contact: wins over a pin not newer than [removedAt]. Kept at most 1,000, oldest dropped first. */
data class ContactTombstone(val userId: String, val removedAt: Long)

/**
 * `vaults[vaultId]` (design §3.6 (e)): the genesis hash (immutable), and the highest verified head any
 * device of the account recorded. Written at once for a new vault, otherwise at most once every 10
 * minutes per device (design §5.4, the batching rule).
 */
data class VaultRecord(
    val vaultId: String,
    val genesisHash: String,
    val seq: Long,
    val hash: String,
    /** Fields this build does not know, kept as written (design §5.4 "Edges"). */
    val extra: Map<String, String> = emptyMap(),
)

/** `accepted[vaultId]` (design §3.6): the person's answer to the `add` at [addSeq]. [decision] is `accept` or `decline`. */
data class AcceptedRecord(
    val vaultId: String,
    val owner: String,
    val addSeq: Long,
    val at: Long,
    val decision: String,
    /** Fields this build does not know, kept as written (design §5.4 "Edges"). */
    val extra: Map<String, String> = emptyMap(),
) {
    companion object {
        const val ACCEPT = "accept"
        const val DECLINE = "decline"
    }
}

/** `recovery` (design §4.5): [posture] `private` or `operator`, [fp] the consented `hex64` or `none`. */
data class RecoveryRecord(
    val posture: String,
    val fp: String,
    val at: Long,
    /** Fields this build does not know, kept as written (design §5.4 "Edges"). */
    val extra: Map<String, String> = emptyMap(),
)

/**
 * The whole document. [seq] is the AUTHENTICATED in-blob counter (FI-B14), never the server's CAS token.
 * [unknown] carries every top-level key this build does not know, as raw JSON, so a newer build's
 * records survive this build's merge (design §5.4).
 */
data class AccountDocument(
    val seq: Long,
    val contacts: Map<String, ContactRecord>,
    val contactTombstones: Map<String, ContactTombstone>,
    val vaults: Map<String, VaultRecord>,
    val accepted: Map<String, AcceptedRecord>,
    val recovery: RecoveryRecord?,
    val unknown: Map<String, String>,
) {
    companion object {
        const val MAX_CONTACTS = 1000
        const val MAX_TOMBSTONES = 1000
        val EMPTY = AccountDocument(0, emptyMap(), emptyMap(), emptyMap(), emptyMap(), null, emptyMap())
    }
}

/** Something a merge refused to fold in silently; each is shown, none changes the local record. */
sealed class MergeAnomaly {
    /** A served contact with another key for a pinned userId: kept aside for the key-change prompt (design §6.8 step 6). */
    data class ContactKeyChange(val local: ContactRecord, val served: ContactRecord) : MergeAnomaly()

    /** A served vault record names another genesis: the local record stays. */
    data class VaultGenesisMismatch(val local: VaultRecord, val served: VaultRecord) : MergeAnomaly()

    /** The same `seq` with another hash: a fork of that vault's log (design §3.9). */
    data class VaultRecordFork(val local: VaultRecord, val served: VaultRecord) : MergeAnomaly()

    /** The served document's in-blob `seq` is below this device's high-water mark: a rollback, merged so nothing local is lost. */
    data class Rollback(val servedSeq: Long, val highWater: Long) : MergeAnomaly()

    /** The server withheld the blob after one was seen. */
    data object Withheld : MergeAnomaly()
}

/**
 * The merged document and what the merge would not fold in. [fits] is false when the document is still
 * over [AccountLimits.sealedChars] after every drop design §5.4 names: it is still used for reading, but
 * it is not written (`account_state_full`).
 */
data class MergeResult(val document: AccountDocument, val anomalies: List<MergeAnomaly>, val fits: Boolean = true) {
    /**
     * Why the merged document is for reading only, or null when it may be written (design §5.4 "Edges",
     * `accountstate.json` `expect.notWritten`): `account_state_damaged` when its `seq` cannot be advanced (checked
     * first, as the writer does), `account_state_full` when it does not fit after every drop.
     */
    val notWritten: String? get() = when {
        document.seq >= StoredAccountState.MAX_SEQ -> StoredAccountState.DAMAGED
        !fits -> StoredAccountState.FULL
        else -> null
    }
}

/**
 * The three limits of design §5.4 / spec 02 §9. The pure merge takes them as a parameter so the vectors
 * can grade the caps on small documents; the apps use [DEFAULT].
 */
data class AccountLimits(
    val contacts: Int = AccountDocument.MAX_CONTACTS,
    val tombstones: Int = AccountDocument.MAX_TOMBSTONES,
    /** `ACCOUNT_STATE_SEALED_MAX`: the length of the sealed state as sent (base64 of the envelope). */
    val sealedChars: Int = SEALED_MAX,
) {
    companion object {
        const val SEALED_MAX = 1_048_576
        val DEFAULT = AccountLimits()
    }
}

/** How an `accepted` record answers the account's latest `add` (design §2.4 "Acceptance", §3.6 (d)). */
enum class Acceptance(val code: String) { ACCEPT("accept"), DECLINE("decline"), ASK("ask") }

/** The pure merges of design §5.4 / spec 02 §9. Commutative: merging A into B and B into A give the same records. */
object AccountMerge {
    /**
     * Merges [served] into [local] (both decrypted and decoded). The result's `seq` is the higher of the
     * two; the writer bumps it. Unknown keys are unioned, the higher-`seq` document's value winning.
     */
    fun merge(local: AccountDocument, served: AccountDocument, limits: AccountLimits = AccountLimits.DEFAULT): MergeResult {
        val anomalies = ArrayList<MergeAnomaly>()
        // Contacts and tombstones.
        val tombs = HashMap<String, ContactTombstone>()
        for (t in local.contactTombstones.values + served.contactTombstones.values) {
            val cur = tombs[t.userId]
            if (cur == null || t.removedAt > cur.removedAt) tombs[t.userId] = t
        }
        val contacts = HashMap<String, ContactRecord>()
        for (id in local.contacts.keys + served.contacts.keys) {
            val l = local.contacts[id]
            val s = served.contacts[id]
            val merged = when {
                l == null -> s!!
                s == null -> l
                l.identityPub != s.identityPub -> { anomalies += MergeAnomaly.ContactKeyChange(l, s); l }
                else -> {
                    val newer = when {
                        l.verifiedAt != s.verifiedAt -> if (l.verifiedAt > s.verifiedAt) l else s
                        else -> {
                            val byLabel = byteCompare(l.label, s.label)
                            when {
                                byLabel != 0 -> if (byLabel > 0) l else s
                                else -> if (byteCompare(l.madeOn, s.madeOn) >= 0) l else s
                            }
                        }
                    }
                    newer.copy(compared = l.compared || s.compared)
                }
            }
            val t = tombs[id]
            if (t != null && t.removedAt >= merged.verifiedAt) continue
            contacts[id] = merged
        }
        // Every tombstone has removed its contacts above, from both copies, before the cap drops any (§5.4 "Edges").
        // Vault records.
        val vaults = HashMap<String, VaultRecord>()
        for (id in local.vaults.keys + served.vaults.keys) {
            val l = local.vaults[id]
            val s = served.vaults[id]
            vaults[id] = when {
                l == null -> s!!
                s == null -> l
                l.genesisHash != s.genesisHash -> { anomalies += MergeAnomaly.VaultGenesisMismatch(l, s); l }
                l.seq == s.seq && l.hash != s.hash -> { anomalies += MergeAnomaly.VaultRecordFork(l, s); l }
                else -> if (s.seq > l.seq) s else l
            }
        }
        // Accepted records.
        val accepted = HashMap<String, AcceptedRecord>()
        for (id in local.accepted.keys + served.accepted.keys) {
            val l = local.accepted[id]
            val s = served.accepted[id]
            accepted[id] = when {
                l == null -> s!!
                s == null -> l
                else -> pickAccepted(l, s)
            }
        }
        // Recovery.
        val recovery = pickRecovery(local.recovery, served.recovery)
        // Unknown keys: union, the higher-seq document wins a shared key.
        val (low, high) = if (served.seq > local.seq) local to served else served to local
        val unknown = low.unknown + high.unknown
        val doc = AccountDocument(maxOf(local.seq, served.seq), contacts, tombs, vaults, accepted, recovery, unknown)
        val bounded = bound(doc, limits)
        return MergeResult(bounded.document, anomalies, bounded.fits)
    }

    /** A document held to [limits], and whether it fits the sealed size after every drop. */
    data class Bounded(val document: AccountDocument, val fits: Boolean)

    /**
     * Holds [doc] to [limits] (design §5.4, spec 02 §9), on merge and on write alike:
     * - the contact and tombstone caps keep the newest (`verifiedAt`, `removedAt`), among equals the smaller `userId`;
     * - when the sealed document would exceed `sealedChars`, unknown top-level keys go first, the largest first;
     *   then the `vaults` and `accepted` records of vaults the account has left (its `accepted` record says
     *   `decline`), the smallest `at` first, then the smaller `vaultId`; `recovery` is never dropped.
     * [Bounded.fits] is false when it is still over after all that.
     */
    fun bound(doc: AccountDocument, limits: AccountLimits): Bounded {
        var d = doc
        if (d.contactTombstones.size > limits.tombstones) {
            d = d.copy(contactTombstones = d.contactTombstones.values
                .sortedWith(compareByDescending<ContactTombstone> { it.removedAt }.thenComparator { a, b -> byteCompare(a.userId, b.userId) })
                .take(maxOf(limits.tombstones, 0)).associateBy { it.userId })
        }
        if (d.contacts.size > limits.contacts) {
            d = d.copy(contacts = d.contacts.values
                .sortedWith(compareByDescending<ContactRecord> { it.verifiedAt }.thenComparator { a, b -> byteCompare(a.userId, b.userId) })
                .take(maxOf(limits.contacts, 0)).associateBy { it.userId })
        }
        if (sealedChars(d) <= limits.sealedChars) return Bounded(d, true)
        // Unknown keys first, the largest first (ties: the larger key first, so every device sheds the same one).
        val unknownOrder = d.unknown.entries.sortedWith(
            compareByDescending<Map.Entry<String, String>> { it.key.encodeToByteArray().size + it.value.encodeToByteArray().size }
                .thenComparator { a, b -> byteCompare(b.key, a.key) },
        ).map { it.key }
        for (k in unknownOrder) {
            d = d.copy(unknown = d.unknown - k)
            if (sealedChars(d) <= limits.sealedChars) return Bounded(d, true)
        }
        // Then the vaults the account has left, the oldest `at` first, then the smaller vaultId.
        val left = d.accepted.values.filter { it.decision == AcceptedRecord.DECLINE }
            .sortedWith(compareBy<AcceptedRecord> { it.at }.thenComparator { a, b -> byteCompare(a.vaultId, b.vaultId) })
        for (a in left) {
            d = d.copy(vaults = d.vaults - a.vaultId, accepted = d.accepted - a.vaultId)
            if (sealedChars(d) <= limits.sealedChars) return Bounded(d, true)
        }
        return Bounded(d, false)
    }

    /**
     * The length of [doc] sealed as it is sent: base64url (unpadded) of the envelope, which is the compact
     * JSON plaintext plus [ENVELOPE_OVERHEAD] bytes. The document's `userId` is always a 36-character UUID,
     * so a fixed one of that length gives the exact size.
     */
    fun sealedChars(doc: AccountDocument): Int {
        val n = AccountDocumentCodec.encode(SIZE_USER_ID, doc).encodeToByteArray().size + ENVELOPE_OVERHEAD
        return (n * 4 + 2) / 3
    }

    /** Envelope version and suite (2) + nonce (24) + Poly1305 tag (16). */
    const val ENVELOPE_OVERHEAD = 42
    private const val SIZE_USER_ID = "00000000-0000-4000-8000-000000000000"

    /** Field text compared byte by byte, as stored (design §5.4 "Ties"). */
    internal fun byteCompare(a: String, b: String): Int =
        AccountDocumentCodec.compareBytes(a.encodeToByteArray(), b.encodeToByteArray())

    /**
     * The higher `addSeq` wins; for the same `addSeq` a `decline` wins whatever `at` says (a leave is final
     * for that add); between two records with the same decision the newest `at`; then the larger `owner`.
     */
    fun pickAccepted(a: AcceptedRecord, b: AcceptedRecord): AcceptedRecord = when {
        a.addSeq != b.addSeq -> if (a.addSeq > b.addSeq) a else b
        a.decision != b.decision -> if (a.decision == AcceptedRecord.DECLINE) a else b
        a.at != b.at -> if (a.at > b.at) a else b
        else -> if (byteCompare(a.owner, b.owner) >= 0) a else b
    }

    /** The newest `at` wins; a tie goes to `private`, then (same posture) to the smaller `fp`, so every device agrees. */
    fun pickRecovery(a: RecoveryRecord?, b: RecoveryRecord?): RecoveryRecord? = when {
        a == null -> b
        b == null -> a
        a.at != b.at -> if (a.at > b.at) a else b
        a.posture != b.posture -> if (a.posture == "private") a else b
        else -> if (byteCompare(a.fp, b.fp) <= 0) a else b
    }

    /** The `accepted` record that answers the account's latest `add` at [latestAddSeq], or null (FS-R6): a stale one answers nothing. */
    fun acceptedFor(doc: AccountDocument, vaultId: String, latestAddSeq: Long): AcceptedRecord? =
        doc.accepted[vaultId]?.takeIf { it.addSeq == latestAddSeq }

    /** [acceptedFor] as design §2.4's three answers. */
    fun acceptance(doc: AccountDocument, vaultId: String, latestAddSeq: Long): Acceptance = when (acceptedFor(doc, vaultId, latestAddSeq)?.decision) {
        AcceptedRecord.ACCEPT -> Acceptance.ACCEPT
        AcceptedRecord.DECLINE -> Acceptance.DECLINE
        else -> Acceptance.ASK
    }

    /**
     * The one stamping rule for a record that supersedes another (design §5.4, "A record that supersedes another is
     * stamped later than it"): a device writing a record meant to replace the one it holds, stamped at [heldAt], stamps
     * it at `max(nowMs, heldAt + 1)`, so a clock that runs behind cannot write a record that loses the merge to the one
     * it replaces. [heldAt] null (nothing held) leaves [nowMs]. Every writer of a superseding record goes through here:
     * a recovery choice ([supersedingRecovery]), a contact pinned or re-pinned over a held pin or tombstone
     * ([supersedingContactAt]), and a contact's tombstone ([removeContact]).
     */
    fun supersedingAt(nowMs: Long, heldAt: Long?): Long = if (heldAt == null) nowMs else maxOf(nowMs, heldAt + 1)

    /** [next] stamped to supersede [held] ([supersedingAt]): a new recovery choice always wins the merge over the one it replaces. */
    fun supersedingRecovery(next: RecoveryRecord, held: RecoveryRecord?): RecoveryRecord =
        next.copy(at = supersedingAt(next.at, held?.at))

    /**
     * The `verifiedAt` of a contact for [userId] that [doc] is about to take ([supersedingAt]): later than the pin it
     * replaces, and later than the contact's tombstone, which would otherwise remove it again (a tombstone not older than
     * a pin removes it).
     */
    fun supersedingContactAt(doc: AccountDocument, userId: String, nowMs: Long): Long {
        val held = listOfNotNull(doc.contacts[userId]?.verifiedAt, doc.contactTombstones[userId]?.removedAt).maxOrNull()
        return supersedingAt(nowMs, held)
    }

    /**
     * Removing a contact (spec 02 §9): the tombstone supersedes the pin it removes and any earlier tombstone
     * ([supersedingAt]), so the newest human act wins whatever the clocks say.
     */
    fun removeContact(doc: AccountDocument, userId: String, nowMs: Long): AccountDocument {
        val at = supersedingContactAt(doc, userId, nowMs)
        val tombs = doc.contactTombstones + (userId to ContactTombstone(userId, at))
        return doc.copy(contacts = doc.contacts - userId, contactTombstones = tombs)
    }
}

/** What a read of the account state found. */
sealed class AccountStateRead {
    data class Ok(val document: AccountDocument, val anomalies: List<MergeAnomaly>) : AccountStateRead()

    /** The blob did not open under the UVK (or failed the strict decode): the local copy stays in force. */
    data object Unopenable : AccountStateRead()

    data object Unreachable : AccountStateRead()

    /**
     * Nothing was sent and nothing written ([code]): the origin is stopped (`origin_stopped`, a forked or damaged pin,
     * design §4.4), or a record this device keeps for the account (its local copy, its high-water mark) is there but
     * cannot be read (`record_unreadable`). An unreadable record is "unknown", never empty: it is not written back
     * from what the server serves (design §4.4 "A trust record that cannot be read is not an empty one").
     */
    data class Stopped(val code: String) : AccountStateRead()
}

/** What a write came to. */
sealed class AccountStateWrite {
    data class Written(val document: AccountDocument) : AccountStateWrite()

    /** The change was already in the merged document; nothing written. */
    data class Unchanged(val document: AccountDocument) : AccountStateWrite()

    /** `409 stale_state` kept coming back after the bounded merge-and-retry. */
    data object Contended : AccountStateWrite()

    /** No answer: the write may or may not have landed; the next read merges either way. */
    data object Unknown : AccountStateWrite()

    data class Refused(val code: String) : AccountStateWrite()
}

/**
 * The account-state store (spec 03 §3): read and merge on every read and every `409`, keep the
 * high-water mark and a sealed copy in durable device state, write with compare-and-set. The UVK never
 * leaves the engine.
 */
interface AccountStateStore {
    /** The merged document as this device holds it now (no network). */
    fun local(): AccountDocument

    /**
     * False when this device holds a copy (or a high-water mark) that cannot be read: [local] then answers EMPTY for
     * display only, and nothing that the copy guards (the vault records as lower bounds, design §3.6 (e)) may act on it.
     */
    fun localReadable(): Boolean = true

    /** GET, open, merge with the local copy, persist. */
    suspend fun read(): AccountStateRead

    /** Apply [change] to the freshly merged document and PUT it with CAS, merging and retrying on `409`. */
    suspend fun update(change: (AccountDocument) -> AccountDocument): AccountStateWrite

    /**
     * The device-link bundle's `accountState` checkpoint (design §8.3, FI-B14): the in-blob `seq` of the last served or
     * written blob this device opened, and the hex SHA-256 over the ASCII bytes of that `sealedState` string; null
     * when this device has seen none.
     */
    fun checkpoint(): Pair<Long, String>? = null

    /** Raise the high-water mark of the in-blob `seq` (a device-link bundle's checkpoint, design §8.3): a served state below it is a rollback. */
    fun raiseHighWater(seq: Long) {}

    /**
     * The server's counter of the account state (its compare-and-set token, spec 03 §3) as this device last saw it: in
     * the answer of its last completed read or write. Null when none was kept or it cannot be read. A sync answer whose
     * `accountStateSeq` equals it says no other device of the account wrote since (spec 03 §4).
     */
    fun heldCounter(): Long? = null
}

/**
 * The vault-record batching rule (spec 02 §9, design §5.4): a device writes a new vault's record at
 * once, and later heads at most once every 10 minutes. A stale record is still a valid lower bound.
 */
object VaultRecordBatching {
    const val INTERVAL_MS: Long = 10 * 60 * 1000

    /** True when this device should write [candidate] now, given the record in the document and its own last write for the vault. */
    fun due(existing: VaultRecord?, candidate: VaultRecord, lastWriteAtMs: Long?, nowMs: Long): Boolean = when {
        existing == null -> true
        candidate.seq <= existing.seq -> false
        lastWriteAtMs == null -> true
        else -> nowMs - lastWriteAtMs >= INTERVAL_MS || nowMs < lastWriteAtMs
    }
}
