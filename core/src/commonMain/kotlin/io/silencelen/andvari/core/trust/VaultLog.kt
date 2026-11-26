package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.KeyPairBytes
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** The ten kinds of a vault-log entry (design 2026-11-15 §3.1). */
enum class LogKind(val literal: String) {
    GENESIS("genesis"),
    ADD("add"),
    ROLE("role"),
    REMOVE("remove"),
    LEAVE("leave"),
    OFFER("offer"),
    CANCEL("cancel"),
    ACCEPT("accept"),
    DELETE("delete"),
    RESTORE("restore"),
    ;

    companion object {
        fun fromLiteral(literal: String): LogKind? = entries.firstOrNull { it.literal == literal }
    }
}

/** The `role` value type (§2.2): what an `add` or `role` entry can give. Never `owner`. */
@Serializable
enum class MemberRole(val literal: String) {
    WRITER("writer"),
    READER("reader"),
    ;

    val asVaultRole: VaultRole get() = if (this == WRITER) VaultRole.WRITER else VaultRole.READER

    companion object {
        fun fromLiteral(literal: String): MemberRole? = entries.firstOrNull { it.literal == literal }
    }
}

/** A member's role in the vault state (§3.3). `OWNER` comes only from `genesis` and `accept`. */
@Serializable
enum class VaultRole(val literal: String) {
    OWNER("owner"),
    WRITER("writer"),
    READER("reader"),
}

/**
 * One entry of a shared vault's log (§3.1), as its statement says it. Ids, keys and hashes are the
 * canonical statement text ([TrustGrammar]): `vaultId`, `actor`, `member`, `to` are `uuid`; `prev` and
 * `vkCommit` are `hex64`; `ownerKey`, `memberKey`, `toKey` are `b64_32` X25519 identity keys; `grantId`,
 * `offerId`, `deleteId` are `b64_16`; `at` and `expiresAt` are `ms`.
 *
 * An instance is only DATA. One built by a caller is a request to sign ([VaultLog.sign]); one read from
 * a frame is trusted only as the `entry` of a [VaultLogStep], which only [VaultLog.verify] mints.
 */
sealed class LogEntry {
    abstract val vaultId: String

    /** `seq`: 0 for `genesis`, the previous entry's plus one otherwise (§3.2). */
    abstract val seq: Long

    /** `prev`: 64 zeros for `genesis`, `H(previous frame)` otherwise (§3.2). */
    abstract val prev: String

    /** The account that signed the entry. */
    abstract val actor: String

    /** The signer's own clock, used only for the time rules of §3.3. */
    abstract val at: Long
    abstract val kind: LogKind

    /** Creates the vault: [actor] is its owner, [ownerKey] its identity key, [vkCommit] commits to the vault key (§3.4). */
    data class Genesis(override val vaultId: String, override val actor: String, override val at: Long, val ownerKey: String, val vkCommit: String) : LogEntry() {
        override val seq: Long get() = 0
        override val prev: String get() = TrustGrammar.ZERO_HASH
        override val kind get() = LogKind.GENESIS
    }

    /** The owner adds [member] with [memberKey] and [role]; [grantId] names the grant sealed to that key (§3.5). */
    data class Add(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
        val member: String, val memberKey: String, val role: MemberRole, val grantId: String,
    ) : LogEntry() {
        override val kind get() = LogKind.ADD
    }

    /** The owner changes [member]'s role. */
    data class Role(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
        val member: String, val role: MemberRole,
    ) : LogEntry() {
        override val kind get() = LogKind.ROLE
    }

    /** The owner removes [member]. */
    data class Remove(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
        val member: String,
    ) : LogEntry() {
        override val kind get() = LogKind.REMOVE
    }

    /** [actor] leaves the vault. Also what a decline signs (§3.6), and what an account deletion signs (§3.11). */
    data class Leave(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
    ) : LogEntry() {
        override val kind get() = LogKind.LEAVE
    }

    /** The owner offers ownership to member [to], whose key is [toKey], until [expiresAt]. */
    data class Offer(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
        val to: String, val toKey: String, val offerId: String, val expiresAt: Long,
    ) : LogEntry() {
        override val kind get() = LogKind.OFFER
    }

    /** The owner, or the offer's target, withdraws the pending offer [offerId]. */
    data class Cancel(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
        val offerId: String,
    ) : LogEntry() {
        override val kind get() = LogKind.CANCEL
    }

    /** The offer's target takes ownership. */
    data class Accept(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
        val offerId: String,
    ) : LogEntry() {
        override val kind get() = LogKind.ACCEPT
    }

    /** The owner deletes the vault (its grace period starts); [deleteId] names this deletion. */
    data class Delete(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
        val deleteId: String,
    ) : LogEntry() {
        override val kind get() = LogKind.DELETE
    }

    /** The owner undoes the deletion [deleteId]. */
    data class Restore(
        override val vaultId: String, override val seq: Long, override val prev: String, override val actor: String, override val at: Long,
        val deleteId: String,
    ) : LogEntry() {
        override val kind get() = LogKind.RESTORE
    }
}

/** A log's head (§3.2): `(seq, H(frame))` of its last entry. */
@Serializable
data class LogHead(val seq: Long, val hash: String)

/**
 * One member in the vault state (§3.3).
 *
 * [addSeq] is the `seq` of the `add` entry that made this account a member (the `addSeq` an `accepted`
 * record answers, §3.6, §5.4, FS-R6). It is null for exactly one case: the genesis creator who has
 * never left or been removed, which is §3.6 (d)'s "the log has no `add` of this account" (FN-2).
 */
@Serializable
data class VaultMember(val key: String, val role: VaultRole, val addSeq: Long?)

/** The pending ownership offer in the vault state (§3.3). */
@Serializable
data class PendingOffer(val offerId: String, val to: String, val toKey: String, val expiresAt: Long)

/**
 * One `add` entry of the verified log, kept in the state so that a grant can be bound to it without
 * the frames (§3.5 step 6): [actor] is the owner who signed it (O) and [ownerKey] the owner key at that
 * entry (K). The state keeps ONE per account, its latest ([VaultState.latestAdd]): a grant binds to an
 * account's latest `add` only, so earlier ones are not kept.
 */
@Serializable
data class AddRecord(
    val seq: Long,
    val actor: String,
    val ownerKey: String,
    val member: String,
    val memberKey: String,
    val role: MemberRole,
    val grantId: String,
)

/**
 * The vault state S that replaying entries 0..n yields (§3.3):
 *
 * ```
 * S = { vaultId, head, owner, ownerKey, vkCommit,
 *       members: userId -> { key, role },
 *       pending: { offerId, to, toKey, expiresAt } | none,
 *       deleted: { deleteId } | none }
 * ```
 *
 * plus what the design derives from the same entries: [at] (the head entry's `at`, for the time rules
 * and for `at = max(own clock, head.at)`), [genesisHash] (the wrap AD of §2.3 and the vault record of
 * §3.6 (e)), [creator] (§3.6 (d), FN-2) and [latestAdds] (§3.5 step 6).
 *
 * **Where one comes from.** Only [VaultLog.verify] and [VaultLog.replay] build a state, and
 * [decode] restores one THIS DEVICE stored with [encode]. Nothing a server sends is ever a state. A
 * device keeps it durably beside the verified head (§3.9); the stored form is this build's own and is
 * not a wire format.
 *
 * **Its size.** One entry per current member and one add record per account ever added: it grows with
 * the accounts a vault has had, never with the length of its log, however often an account was added
 * and left again.
 */
class VaultState internal constructor(internal val doc: Doc) {
    /**
     * The stored form. Version 2 keeps one latest `add` per account ([latestAdds]); version 1 kept
     * every `add` of the log in a list. A stored state of another version decodes to null ([decode]),
     * and the device replays the log from its genesis, which is the rule for any state it cannot read.
     */
    @Serializable
    internal data class Doc(
        val v: Int = STORED_VERSION,
        val vaultId: String,
        val head: LogHead,
        val at: Long,
        val genesisHash: String,
        val creator: String,
        val owner: String,
        val ownerKey: String,
        val vkCommit: String,
        val members: Map<String, VaultMember>,
        val pending: PendingOffer? = null,
        val deleteId: String? = null,
        val latestAdds: Map<String, AddRecord> = emptyMap(),
    )

    val vaultId: String get() = doc.vaultId

    /** `(seq, H(frame))` of the last verified entry. */
    val head: LogHead get() = doc.head

    /** The last verified entry's `at`. The next entry needs `at >= ` this (§3.3, T-R1). */
    val at: Long get() = doc.at

    /** `H(genesis frame)`: names this log in the shared-vault wrap AD (§2.3) and the vault record (§3.6 (e)). */
    val genesisHash: String get() = doc.genesisHash

    /** The genesis entry's `actor`: the account that created the vault. */
    val creator: String get() = doc.creator

    /** The current owner: the creator, or the target of the last `accept`. */
    val owner: String get() = doc.owner

    /** The current owner's identity key (`b64_32`): from genesis, or from the last `accept`. */
    val ownerKey: String get() = doc.ownerKey

    /** The commitment to the vault key, fixed at genesis (§3.4). */
    val vkCommit: String get() = doc.vkCommit

    /** Every current member, the owner included, by `userId`. */
    val members: Map<String, VaultMember> get() = doc.members

    /** The pending ownership offer, or null. An offer whose `expiresAt` passed stays here until an entry with a later `at` clears it. */
    val pending: PendingOffer? get() = doc.pending

    /** The `deleteId` of the deletion in force, or null when the vault is not deleted. */
    val deleteId: String? get() = doc.deleteId
    val isDeleted: Boolean get() = doc.deleteId != null

    /**
     * Each account's LATEST `add` entry, by `userId` (§3.5 step 6), also for an account that left or was
     * removed since: one record per account ever added.
     */
    val latestAdds: Map<String, AddRecord> get() = doc.latestAdds

    /**
     * The latest `add` of [userId], or null when the log never added that account (the genesis creator,
     * until it leaves and is added again). A grant is bound to this entry and to no earlier one, and an
     * `accepted` record answers its `seq` (FS-R6).
     */
    fun latestAdd(userId: String): AddRecord? = doc.latestAdds[userId]

    /** The device-local stored form of this state. */
    fun encode(): String = stored.encodeToString(Doc.serializer(), doc)

    override fun equals(other: Any?): Boolean = other is VaultState && other.doc == doc
    override fun hashCode(): Int = doc.hashCode()
    override fun toString(): String = "VaultState($vaultId @${head.seq})"

    companion object {
        /** The version of the stored form this build writes and reads ([Doc]). */
        internal const val STORED_VERSION = 2

        /** Every field is written, the version included, and nothing unknown is read back. */
        private val stored = Json { encodeDefaults = true }

        /**
         * Restore a state this device stored with [encode]. Null when [text] is not one (damaged, or
         * from another build): the device then replays the log from its genesis. Never call this on a
         * value that came from a server.
         */
        fun decode(text: String): VaultState? {
            val doc = try {
                stored.decodeFromString(Doc.serializer(), text)
            } catch (e: Exception) {
                return null
            }
            return if (wellFormed(doc)) VaultState(doc) else null
        }

        /** Every field of a restored state is back inside the grammar it had when the verifier built it. */
        private fun wellFormed(d: Doc): Boolean {
            val g = TrustGrammar
            if (d.v != STORED_VERSION || !g.isUuid(d.vaultId) || !g.isInt(d.head.seq) || !g.isHex64(d.head.hash) || !g.isMs(d.at)) return false
            if (!g.isHex64(d.genesisHash) || !g.isUuid(d.creator) || !g.isUuid(d.owner) || !g.isB64_32(d.ownerKey) || !g.isHex64(d.vkCommit)) return false
            for ((member, a) in d.latestAdds) {
                if (a.member != member) return false // filed under the account it adds
                if (a.seq < 1 || a.seq > d.head.seq || !g.isUuid(a.actor) || !g.isB64_32(a.ownerKey)) return false
                if (!g.isUuid(a.member) || !g.isB64_32(a.memberKey) || !g.isB64_16(a.grantId)) return false
            }
            for ((userId, m) in d.members) {
                if (!g.isUuid(userId) || !g.isB64_32(m.key)) return false
                if ((m.role == VaultRole.OWNER) != (userId == d.owner)) return false
                // A member's addSeq is its latest add; only the creator, while never added, has none (FN-2).
                val add = d.latestAdds[userId]
                if (m.addSeq == null) {
                    if (userId != d.creator || add != null) return false
                } else if (add == null || add.seq != m.addSeq || add.memberKey != m.key) {
                    return false
                }
            }
            if (d.members[d.owner]?.key != d.ownerKey) return false
            val p = d.pending
            if (p != null && !(g.isB64_16(p.offerId) && g.isUuid(p.to) && g.isB64_32(p.toKey) && g.isMs(p.expiresAt))) return false
            if (d.deleteId != null && !g.isB64_16(d.deleteId)) return false
            return true
        }
    }
}

/**
 * Why [VaultLog.verify] refused an entry (§3.3 "Verdicts, in check order"). The [code] is the design's
 * name; §3.7's table maps each to its wire answer. `not_authorized` and `fork` are client verdicts.
 */
enum class VaultLogVerdict(val code: String) {
    /** 1. The §2 parse: see [FrameVerdict]. */
    BAD_FRAME("bad_frame"),
    UNKNOWN_FORMAT("unknown_format"),
    NON_CANONICAL("non_canonical"),
    BAD_STATEMENT("bad_statement"),

    /** 2. The entry's `vaultId` is not the vault being verified (§3.2: "`vaultId` is constant along the chain"). */
    WRONG_VAULT("wrong_vault"),

    /** 3. `seq` is not the previous entry's plus one (or not 0 where a genesis is due). */
    BAD_SEQ("bad_seq"),

    /** 4. `prev` is not `H(previous frame)`. */
    BAD_PREV("bad_prev"),

    /** 5. The signer key the transition table names is not the one in the frame, or `actor` is not the required account. */
    NOT_AUTHORIZED("not_authorized"),

    /** 6. The Ed25519 signature does not verify. */
    BAD_SIGNATURE("bad_signature"),

    /** 7. A row condition failed, a time rule failed, or the key the row names does not exist in the state (FI-B1). */
    PRECONDITION("precondition"),

    /** 8. A different valid entry at a sequence number this device already saw. */
    FORK("fork"),
    ;

    companion object {
        internal fun of(v: FrameVerdict): VaultLogVerdict = when (v) {
            FrameVerdict.BAD_FRAME -> BAD_FRAME
            FrameVerdict.UNKNOWN_FORMAT -> UNKNOWN_FORMAT
            FrameVerdict.NON_CANONICAL -> NON_CANONICAL
            FrameVerdict.BAD_STATEMENT -> BAD_STATEMENT
        }
    }
}

/**
 * An entry that passed the strict parse only: NOT authenticated and not placed in any chain. It exists
 * so that the server can run §3.7 steps 3 and 4 and a client can read where an entry claims to sit; a
 * [VaultLogStep] is the verified form.
 */
class UnverifiedLogEntry internal constructor(val entry: LogEntry, val hash: String, internal val parts: FrameParts) {
    /** The Ed25519 key the frame says signed it. Never a key to verify that same frame against. */
    val signerPub: ByteArray get() = parts.signerPub
}

/** One verified step: [entry] verified against the state before it, and [state] after it. [hash] is `H(frame)`. */
class VaultLogStep internal constructor(val state: VaultState, val entry: LogEntry, val hash: String)

/**
 * The result of [VaultLog.replay]: [state] is the state after the last GOOD entry (null when not even
 * the first verified), [accepted] how many frames verified, and [verdict] the first failing frame's
 * verdict, or null when every frame verified (§3.9: "a failure leaves the verified state at the last
 * good entry").
 */
class VaultLogReplay internal constructor(val state: VaultState?, val accepted: Int, val verdict: VaultLogVerdict?)

/** Where the next entry of a log sits: [seq], [prev] and the `at` a signer must use (§3.3: `at = max(own clock, head.at)`). */
data class LogPosition(val seq: Long, val prev: String, val at: Long)

/** §3.7 step 4, the server's hygiene check of who signed a posted entry. */
enum class LogSignerCheck {
    /** `actor` is the caller, the signer maps to the caller's identity key, and the signature verifies. */
    OK,

    /** `actor` is not the caller, or the signer does not map to the caller's stored `identityPub` (`400 bad_signer`). */
    BAD_SIGNER,

    /** The signature does not verify (`400 bad_signature`). */
    BAD_SIGNATURE,
}

/**
 * What a device already knows about a log's positions, for fork detection (§3.9).
 *
 * [VaultLog.verify] and [VaultLog.replay] cannot be called without one: a caller that left it out used
 * to get a verifier with fork detection silently off. A caller that really holds nothing says so with
 * [NONE_HELD].
 */
fun interface KnownHashes {
    /**
     * `H(frame)` this device holds for [seq], or null when it holds none: the hash of an entry it
     * verified, a device-link checkpoint (§8.3) or the account's vault record (§3.6 (e)).
     */
    fun at(seq: Long): String?

    companion object {
        /**
         * For a verifier that holds NO hash of its own for any position, so that the `fork` verdict
         * cannot arise: **the server**, whose stored chain is the only copy it has and which accepts an
         * entry only at its stored head (`bad_seq`, `bad_prev`), and a caller that verifies a log it
         * has never seen before with nothing to compare it to.
         *
         * A device that has verified entries of the log, holds a device-link checkpoint or has the
         * account's vault record for it never passes this: it passes what it holds.
         */
        val NONE_HELD: KnownHashes = KnownHashes { null }
    }
}

/**
 * The shared vault log (design 2026-11-15 §3): templates (§3.1), chain (§3.2), state and transitions
 * (§3.3) and the key commitment (§3.4). Every client and the server run THIS verifier (§3.7 step 7,
 * T-R2), so no second implementation of §3.3 can accept an entry another refuses.
 *
 * Verifying needs no contact pins: every signer key comes from the log itself (`ownerKey` from genesis
 * or the last `accept`, member keys from `add`, the target key from `offer`). Whether a device ADOPTS a
 * vault is a separate decision (§3.6), made by the engine on top of the state this returns.
 */
object VaultLog {
    /** §3.3 `offer`: `expiresAt <= at + 14 d + 10 min`. */
    const val MAX_OFFER_WINDOW_MS: Long = 14L * 24 * 60 * 60 * 1000 + 10L * 60 * 1000

    // ---- §3.4 key commitment -------------------------------------------------------------------------

    /**
     * `vkCommit = hexLower(HKDF-SHA-256(ikm = VK, salt = empty, info = "andvari/v2|vk-commit|" + vaultId, L = 32))`
     * (§2.3, §3.4).
     */
    fun vkCommit(crypto: CryptoProvider, vk: ByteArray, vaultId: String): String {
        require(vk.size == 32) { "vault key must be 32 bytes" }
        require(TrustGrammar.isUuid(vaultId)) { "vaultId is not a lowercase uuid" }
        val out = Hkdf.sha256(crypto, ikm = vk, salt = ByteArray(0), info = "andvari/v2|vk-commit|$vaultId".encodeToByteArray(), length = 32)
        return Bytes.toHexLower(out)
    }

    /**
     * §3.4: "Every vault key a client obtains, from any source, is checked against `S.vkCommit` before
     * use": the creator's own wrap, a member self-wrap, a new owner's wrap, or a grant. False means the
     * key is REFUSED: nothing is decrypted or written under it, and the anomaly is shown.
     */
    fun keyMatches(crypto: CryptoProvider, state: VaultState, vk: ByteArray): Boolean =
        keyMatches(crypto, state.vaultId, state.vkCommit, vk)

    /** [keyMatches] against a commitment and vault id taken from a verified state (or from the genesis a creator is about to sign). */
    fun keyMatches(crypto: CryptoProvider, vaultId: String, vkCommit: String, vk: ByteArray): Boolean =
        // A key of zeros matches no commitment (nothing is derived from one): a served one is refused.
        vk.size == 32 && !io.silencelen.andvari.core.crypto.KeyFloor.allZero(vk) && TrustGrammar.isUuid(vaultId) &&
            Bytes.ctEquals(vkCommit(crypto, vk, vaultId).encodeToByteArray(), vkCommit.encodeToByteArray())

    // ---- parse ---------------------------------------------------------------------------------------

    /**
     * The §2 parse of one entry, and nothing more (§3.3 verdict 1): the frame, purpose 0x03, the strict
     * canonical parse of §3.1's template for its `kind`, and §3.2's own rules (`seq = 0` exactly when
     * the kind is `genesis`; a genesis has `prev` = 64 zeros). No chain, no signer, no signature.
     */
    fun parse(crypto: CryptoProvider, frame: ByteArray): Checked<UnverifiedLogEntry, VaultLogVerdict> =
        when (val parsed = StatementCodec.parseFrame(frame, TrustPurpose.VAULT_LOG)) {
            is Checked.Ok -> Checked.Ok(UnverifiedLogEntry(entryOf(parsed.value.raw), SignedFrame.hash(crypto, frame), parsed.value.parts))
            is Checked.Refused -> Checked.Refused(VaultLogVerdict.of(parsed.verdict))
        }

    /**
     * §3.7 step 4 (server): `entry.actor` is [callerUserId], the signer maps to [callerIdentityPub]
     * (the caller's stored X25519 `identityPub`, 32 bytes), and the Ed25519 signature verifies. This is
     * hygiene for the server; clients never rely on it, and it is not part of [verify].
     */
    fun signedByCaller(crypto: CryptoProvider, entry: UnverifiedLogEntry, callerUserId: String, callerIdentityPub: ByteArray): LogSignerCheck = when {
        entry.entry.actor != callerUserId -> LogSignerCheck.BAD_SIGNER
        !SignedFrame.signerMapsTo(crypto, entry.parts, callerIdentityPub) -> LogSignerCheck.BAD_SIGNER
        !SignedFrame.signatureValid(crypto, entry.parts) -> LogSignerCheck.BAD_SIGNATURE
        else -> LogSignerCheck.OK
    }

    // ---- §3.3 the verifier ---------------------------------------------------------------------------

    /**
     * Verify ONE entry against the state before it (§3.3). [prior] is the state after the previous
     * entry, or null when [frame] must be the genesis. [vaultId] is the vault being verified: the path
     * on the server, the vault row on a client. Clock-free: no time is read (T2-R-a); the server's
     * `at_ahead` ceiling is applied outside.
     *
     * The first failure is the verdict, in this order:
     * 1. `bad_frame`, `unknown_format`, `non_canonical`, `bad_statement`: [parse];
     * 2. `wrong_vault`: the entry's `vaultId` is not [vaultId];
     * 3. `bad_seq`: `seq` is not 0 for a genesis (no [prior]), or not `prior.head.seq + 1`;
     * 4. `bad_prev`: `prev` is not `prior.head.hash`;
     * 5. `not_authorized`: the signer key the kind's row names is not the frame's, or `actor` is not
     *    the required account. Before this step an offer whose `expiresAt` is below the entry's `at`
     *    is cleared from the state the entry is judged against (T-R1). If the key the row names does
     *    not exist in that state, the verdict is `precondition` and checking stops (FI-B1): an
     *    `accept`, or a `cancel` by anyone but the owner, with no pending offer; a `leave` by an
     *    account that is not a member;
     * 6. `bad_signature`;
     * 7. `precondition`: `at` below the previous entry's `at` (T-R1), or a condition of the kind's row;
     * 8. `fork`: [known] holds another hash for this `seq`. The entry is valid in every other respect,
     *    which is what makes it a fork and not noise (FS-R4: "two validly signed entries"). [known] has
     *    no default: a caller says what it holds, or says [KnownHashes.NONE_HELD].
     *
     * The rows (signer; preconditions; effect), all judged against the state BEFORE the entry:
     * - `genesis`: signed by its own `ownerKey`. Sets `owner = actor`, `ownerKey`, `vkCommit`,
     *   `members = { actor: owner }`, no pending offer, not deleted.
     * - `add`: owner. Not deleted; `member` is not a member. Adds `{memberKey, role}`.
     * - `role`: owner. Not deleted; `member` is a member and not the owner. Replaces the role; clears a
     *   pending offer to that member.
     * - `remove`: owner. Not deleted; `member` is a member and not the owner. Removes the member;
     *   clears a pending offer to that member.
     * - `leave`: `members[actor].key`. `actor` is a member and not the owner. ALLOWED WHILE DELETED
     *   (B2). Removes the actor; clears a pending offer to the actor.
     * - `offer`: owner. Not deleted; `to` is a member and not the owner; `toKey` is that member's key;
     *   `at < expiresAt <= at + 14 d + 10 min`; no pending offer (an expired one was cleared).
     * - `cancel`: owner, or the pending offer's `toKey` with `actor` its `to`. A pending offer exists
     *   and `offerId` is its id. Clears it.
     * - `accept`: the pending offer's `toKey`, with `actor` its `to`. Not deleted; a pending offer
     *   exists; `offerId` is its id; `at <= expiresAt`. The old owner becomes a writer, the target the
     *   owner; clears the offer.
     * - `delete`: owner. Not deleted. Sets the `deleteId`; clears the pending offer.
     * - `restore`: owner. Deleted, with this `deleteId`. Clears the deletion.
     */
    fun verify(
        crypto: CryptoProvider,
        vaultId: String,
        prior: VaultState?,
        frame: ByteArray,
        known: KnownHashes,
    ): Checked<VaultLogStep, VaultLogVerdict> {
        // One entry: the state it is judged against is copied once, and the copy becomes the state after it.
        return when (val step = advance(crypto, vaultId, prior?.let { Working(it) }, frame, known)) {
            is Checked.Ok -> Checked.Ok(VaultLogStep(step.value.working.freeze(), step.value.entry, step.value.hash))
            is Checked.Refused -> step
        }
    }

    /**
     * The state while entries are applied to it: [VaultState.Doc]'s fields, with the two maps changed IN
     * PLACE. A replay works on one of these from its first frame to its last and freezes it once, so its
     * cost is one step per entry. (Copying the member map and the list of adds for every entry, as the
     * state transitions did, made a replay quadratic in the length of the log.) A [VaultMember] or an
     * [AddRecord] inside is never changed, only replaced.
     */
    private class Working(
        val vaultId: String,
        var head: LogHead,
        var at: Long,
        val genesisHash: String,
        val creator: String,
        var owner: String,
        var ownerKey: String,
        val vkCommit: String,
        val members: MutableMap<String, VaultMember>,
        var pending: PendingOffer?,
        var deleteId: String?,
        val latestAdds: MutableMap<String, AddRecord>,
    ) {
        /** A working copy of a verified state: the maps are copied once, so the state itself is never touched. */
        constructor(state: VaultState) : this(
            state.doc.vaultId, state.doc.head, state.doc.at, state.doc.genesisHash, state.doc.creator, state.doc.owner, state.doc.ownerKey,
            state.doc.vkCommit, LinkedHashMap(state.doc.members), state.doc.pending, state.doc.deleteId, LinkedHashMap(state.doc.latestAdds),
        )

        private var frozen = false

        /** The state as it stands. The maps are handed over, not copied, so this object is never advanced again. */
        fun freeze(): VaultState {
            check(!frozen) { "a working state is frozen once" }
            frozen = true
            return VaultState(
                VaultState.Doc(VaultState.STORED_VERSION, vaultId, head, at, genesisHash, creator, owner, ownerKey, vkCommit, members, pending, deleteId, latestAdds),
            )
        }

        fun requireLive() = check(!frozen) { "a frozen state is never changed" }
    }

    /** What [advance] did: the working state after the entry, the entry and its frame hash. */
    private class Advanced(val working: Working, val entry: LogEntry, val hash: String)

    /**
     * Steps 1 to 8 for one frame against the working state [w] (null: the frame must be the genesis). On
     * success [w] has become the state after the entry (for a genesis, a new one is made). On ANY refusal
     * [w] is exactly as it was: every check, the fork check included, comes before the first change.
     */
    private fun advance(crypto: CryptoProvider, vaultId: String, w: Working?, frame: ByteArray, known: KnownHashes): Checked<Advanced, VaultLogVerdict> {
        // 1. The §2 parse, with §3.2's template rules.
        val parsed = when (val p = parse(crypto, frame)) {
            is Checked.Ok -> p.value
            is Checked.Refused -> return p
        }
        val e = parsed.entry
        // 2. wrong_vault.
        if (e.vaultId != vaultId || (w != null && w.vaultId != vaultId)) return refuse(VaultLogVerdict.WRONG_VAULT)
        // 3. bad_seq. A first entry must sit at 0 and every later one at the head plus one. The template
        //    rules already tied seq 0 to the kind genesis, so position alone decides here (VR-1).
        if (e.seq != (if (w == null) 0L else w.head.seq + 1)) return refuse(VaultLogVerdict.BAD_SEQ)
        // 4. bad_prev. A genesis has its zero prev from the template rule.
        if (w != null && e.prev != w.head.hash) return refuse(VaultLogVerdict.BAD_PREV)
        // 8. fork: the entry is valid in every other respect, and this device holds another hash for its seq.
        fun forked(): Boolean {
            val seen = known.at(e.seq)
            return seen != null && seen != parsed.hash
        }

        if (w == null) {
            // Steps 5 and 6 for the first entry (VR-2: a genesis signs itself), and the state it sets up.
            val g = e as? LogEntry.Genesis ?: return refuse(VaultLogVerdict.BAD_SEQ) // not reachable: seq 0 is a genesis
            if (!signerMaps(crypto, parsed.parts, g.ownerKey)) return refuse(VaultLogVerdict.NOT_AUTHORIZED)
            if (!SignedFrame.signatureValid(crypto, parsed.parts)) return refuse(VaultLogVerdict.BAD_SIGNATURE)
            if (forked()) return refuse(VaultLogVerdict.FORK)
            val members = LinkedHashMap<String, VaultMember>()
            members[g.actor] = VaultMember(g.ownerKey, VaultRole.OWNER, null)
            val made = Working(g.vaultId, LogHead(0, parsed.hash), g.at, parsed.hash, g.actor, g.actor, g.ownerKey, g.vkCommit, members, null, null, LinkedHashMap())
            return Checked.Ok(Advanced(made, e, parsed.hash))
        }

        // Steps 5 to 7 for an entry after the genesis, judged against the state before it.
        w.requireLive()
        val s = w
        // T-R1, FI-B1: an offer whose expiresAt is below this entry's `at` is cleared BEFORE step 5, so
        // everything below sees the state without it.
        val pending = s.pending?.takeIf { e.at <= it.expiresAt }

        // 5. The signer key the kind's row names. A key that does not exist in the state is
        //    `precondition`, and checking stops (FI-B1).
        val signerKey: String = when (e) {
            is LogEntry.Genesis -> return refuse(VaultLogVerdict.BAD_SEQ) // not reachable: a genesis has seq 0
            is LogEntry.Add, is LogEntry.Role, is LogEntry.Remove, is LogEntry.Offer, is LogEntry.Delete, is LogEntry.Restore -> {
                if (e.actor != s.owner) return refuse(VaultLogVerdict.NOT_AUTHORIZED)
                s.ownerKey
            }
            is LogEntry.Leave -> s.members[e.actor]?.key ?: return refuse(VaultLogVerdict.PRECONDITION)
            is LogEntry.Cancel -> when {
                e.actor == s.owner -> s.ownerKey
                pending == null -> return refuse(VaultLogVerdict.PRECONDITION)
                e.actor == pending.to -> pending.toKey
                else -> return refuse(VaultLogVerdict.NOT_AUTHORIZED)
            }
            is LogEntry.Accept -> when {
                pending == null -> return refuse(VaultLogVerdict.PRECONDITION)
                e.actor != pending.to -> return refuse(VaultLogVerdict.NOT_AUTHORIZED)
                else -> pending.toKey
            }
        }
        if (!signerMaps(crypto, parsed.parts, signerKey)) return refuse(VaultLogVerdict.NOT_AUTHORIZED)
        // 6. bad_signature.
        if (!SignedFrame.signatureValid(crypto, parsed.parts)) return refuse(VaultLogVerdict.BAD_SIGNATURE)

        // 7. precondition: the time rule, then the kind's row. Every failure here is the same verdict.
        //    Each row first CHECKS, against the state before the entry, and names its effect; nothing
        //    is changed until the fork check below has passed too, so a refused entry leaves the state
        //    as it was. Every effect is one step, whatever the size of the state.
        if (e.at < s.at) return refuse(VaultLogVerdict.PRECONDITION)
        val deleted = s.deleteId != null
        val change: () -> Unit = when (e) {
            is LogEntry.Genesis -> return refuse(VaultLogVerdict.BAD_SEQ)
            is LogEntry.Add -> {
                if (deleted || e.member in s.members) return refuse(VaultLogVerdict.PRECONDITION)
                val record = AddRecord(e.seq, e.actor, s.ownerKey, e.member, e.memberKey, e.role, e.grantId)
                val effect = {
                    s.members[e.member] = VaultMember(e.memberKey, e.role.asVaultRole, e.seq)
                    // This account's latest add replaces any earlier one: a grant binds to the latest only (§3.5 step 6).
                    s.latestAdds[e.member] = record
                }
                effect
            }
            is LogEntry.Role -> {
                val member = s.members[e.member]
                if (deleted || member == null || e.member == s.owner) return refuse(VaultLogVerdict.PRECONDITION)
                val effect = {
                    s.members[e.member] = member.copy(role = e.role.asVaultRole)
                    s.pending = pending?.takeIf { it.to != e.member }
                }
                effect
            }
            is LogEntry.Remove -> {
                if (deleted || e.member !in s.members || e.member == s.owner) return refuse(VaultLogVerdict.PRECONDITION)
                val effect = {
                    s.members.remove(e.member)
                    s.pending = pending?.takeIf { it.to != e.member }
                }
                effect
            }
            is LogEntry.Leave -> {
                // Step 5 established that the actor is a member. A leave is allowed while the vault is deleted (B2).
                if (e.actor == s.owner) return refuse(VaultLogVerdict.PRECONDITION)
                val effect = {
                    s.members.remove(e.actor)
                    s.pending = pending?.takeIf { it.to != e.actor }
                }
                effect
            }
            is LogEntry.Offer -> {
                val target = s.members[e.to]
                if (deleted || target == null || e.to == s.owner || target.key != e.toKey) return refuse(VaultLogVerdict.PRECONDITION)
                // at < expiresAt <= at + 14 d + 10 min, as a difference so that no sum leaves the exact range.
                if (e.expiresAt <= e.at || e.expiresAt - e.at > MAX_OFFER_WINDOW_MS) return refuse(VaultLogVerdict.PRECONDITION)
                // "pending = none, or pending.expiresAt < at": an expired offer was cleared above.
                if (pending != null) return refuse(VaultLogVerdict.PRECONDITION)
                val effect = { s.pending = PendingOffer(e.offerId, e.to, e.toKey, e.expiresAt) }
                effect
            }
            is LogEntry.Cancel -> {
                if (pending == null || pending.offerId != e.offerId) return refuse(VaultLogVerdict.PRECONDITION)
                val effect = { s.pending = null }
                effect
            }
            is LogEntry.Accept -> {
                if (deleted || pending == null || pending.offerId != e.offerId || e.at > pending.expiresAt) return refuse(VaultLogVerdict.PRECONDITION)
                val oldOwnerId = s.owner
                val oldOwner = s.members[oldOwnerId] ?: return refuse(VaultLogVerdict.PRECONDITION)
                val newOwner = s.members[pending.to] ?: return refuse(VaultLogVerdict.PRECONDITION)
                val effect = {
                    s.members[oldOwnerId] = oldOwner.copy(role = VaultRole.WRITER)
                    s.members[pending.to] = newOwner.copy(role = VaultRole.OWNER)
                    s.owner = pending.to
                    s.ownerKey = pending.toKey
                    s.pending = null
                }
                effect
            }
            is LogEntry.Delete -> {
                if (deleted) return refuse(VaultLogVerdict.PRECONDITION)
                val effect = {
                    s.deleteId = e.deleteId
                    s.pending = null
                }
                effect
            }
            is LogEntry.Restore -> {
                if (s.deleteId == null || s.deleteId != e.deleteId) return refuse(VaultLogVerdict.PRECONDITION)
                val effect = { s.deleteId = null }
                effect
            }
        }
        if (forked()) return refuse(VaultLogVerdict.FORK)
        // Every check passed: only now is the state changed.
        s.pending = pending
        change()
        s.head = LogHead(e.seq, parsed.hash)
        s.at = e.at
        return Checked.Ok(Advanced(s, e, parsed.hash))
    }

    private fun refuse(verdict: VaultLogVerdict): Checked.Refused<VaultLogVerdict> = Checked.Refused(verdict)

    /** The X25519 form of the signer binding against a key the state holds as `b64_32` text. */
    private fun signerMaps(crypto: CryptoProvider, parts: FrameParts, keyB64: String): Boolean {
        val key = Bytes.fromB64Exact(keyB64, 32) ?: return false
        return SignedFrame.signerMapsTo(crypto, parts, key)
    }

    /**
     * Verify [frames] in order, starting from [from] (null: from the genesis), and stop at the first
     * that fails (§3.9). The state of the last good entry is returned with the failing verdict, so a
     * caller keeps what verified and learns why the rest did not.
     *
     * The cost is one step per entry, whatever the vault's size: the state is built in place and
     * frozen once, at the end or at the first frame that fails. (Calling [verify] in a loop copies the
     * member map for every entry; a caller with many frames uses this.) [from] itself is never changed.
     *
     * Neither [from] nor [known] has a default: a caller says where it starts (null for the genesis)
     * and what it holds ([KnownHashes.NONE_HELD] for nothing).
     */
    fun replay(
        crypto: CryptoProvider,
        vaultId: String,
        frames: List<ByteArray>,
        from: VaultState?,
        known: KnownHashes,
    ): VaultLogReplay {
        var working = from?.let { Working(it) }
        var applied = 0
        // Nothing applied yet: the state is [from] itself. After that, the working state, frozen.
        fun stateNow(): VaultState? = if (applied == 0) from else working?.freeze()
        for ((i, frame) in frames.withIndex()) {
            when (val step = advance(crypto, vaultId, working, frame, known)) {
                is Checked.Ok -> {
                    working = step.value.working
                    applied++
                }
                is Checked.Refused -> return VaultLogReplay(stateNow(), i, step.verdict)
            }
        }
        return VaultLogReplay(stateNow(), frames.size, null)
    }

    // ---- building ------------------------------------------------------------------------------------

    /** Where the entry after [state]'s head sits, with `at = max(clockMs, state.at)` (§3.3, T-R1). */
    fun position(state: VaultState, clockMs: Long): LogPosition =
        LogPosition(state.head.seq + 1, state.head.hash, maxOf(clockMs, state.at))

    /**
     * Where the entry after a SERVED head sits (§3.11): for the leaves of an account deletion, built
     * at the head the server reports without this device having verified that log. The caller applies
     * FS-R7 first (it refuses a `headAt` more than a day ahead of its clock).
     */
    fun positionAfter(headSeq: Long, headHash: String, headAt: Long, clockMs: Long): LogPosition =
        LogPosition(headSeq + 1, headHash, maxOf(clockMs, headAt))

    /**
     * Encode [entry] and sign it with [signer], the account's joint Ed25519 key
     * (`CryptoProvider.signKeypairFromSeed` over the identity seed). Refuses
     * (`IllegalArgumentException`) an entry outside the grammar. It does NOT check the entry against a
     * state: use [signChecked] for that, or [verify] the result. A client keeps the returned bytes in
     * its pending-append record and re-posts THESE bytes; it never re-signs with a new `at` (§3.7, T-R2).
     */
    fun sign(crypto: CryptoProvider, signer: KeyPairBytes, entry: LogEntry): ByteArray =
        SignedFrame.sign(crypto, signer, TrustPurpose.VAULT_LOG, StatementCodec.encode(TrustPurpose.VAULT_LOG, fieldsOf(entry), entry.kind.literal))

    /**
     * [sign], then [verify] the result against [prior]: the frame comes back only if this device's own
     * verifier accepts it at that position, so a client never posts an entry every device would refuse.
     *
     * The entry is judged against [prior] alone, with no held hashes: it is this device's own new entry,
     * signed at the head it verified, and nothing served is being accepted. Whether the device may sign
     * at that head at all (it is not behind a checkpoint or the account's vault record) is the caller's
     * question, asked before it builds the entry.
     */
    fun signChecked(
        crypto: CryptoProvider,
        signer: KeyPairBytes,
        prior: VaultState?,
        entry: LogEntry,
    ): Checked<SignedLogEntry, VaultLogVerdict> {
        val frame = sign(crypto, signer, entry)
        return when (val step = verify(crypto, entry.vaultId, prior, frame, KnownHashes.NONE_HELD)) {
            is Checked.Ok -> Checked.Ok(SignedLogEntry(frame, step.value))
            is Checked.Refused -> step
        }
    }

    // ---- entry <-> statement -------------------------------------------------------------------------

    private fun entryOf(raw: RawStatement): LogEntry {
        val vaultId = raw.str("vaultId")
        val seq = raw.long("seq")
        val prev = raw.str("prev")
        val actor = raw.str("actor")
        val at = raw.long("at")
        fun role() = if (raw.str("role") == MemberRole.WRITER.literal) MemberRole.WRITER else MemberRole.READER
        return when (raw.str("kind")) {
            "genesis" -> LogEntry.Genesis(vaultId, actor, at, raw.str("ownerKey"), raw.str("vkCommit"))
            "add" -> LogEntry.Add(vaultId, seq, prev, actor, at, raw.str("member"), raw.str("memberKey"), role(), raw.str("grantId"))
            "role" -> LogEntry.Role(vaultId, seq, prev, actor, at, raw.str("member"), role())
            "remove" -> LogEntry.Remove(vaultId, seq, prev, actor, at, raw.str("member"))
            "leave" -> LogEntry.Leave(vaultId, seq, prev, actor, at)
            "offer" -> LogEntry.Offer(vaultId, seq, prev, actor, at, raw.str("to"), raw.str("toKey"), raw.str("offerId"), raw.long("expiresAt"))
            "cancel" -> LogEntry.Cancel(vaultId, seq, prev, actor, at, raw.str("offerId"))
            "accept" -> LogEntry.Accept(vaultId, seq, prev, actor, at, raw.str("offerId"))
            "delete" -> LogEntry.Delete(vaultId, seq, prev, actor, at, raw.str("deleteId"))
            else -> LogEntry.Restore(vaultId, seq, prev, actor, at, raw.str("deleteId")) // "restore": the codec admits no other kind
        }
    }

    private fun fieldsOf(e: LogEntry): Map<String, String> {
        val m = linkedMapOf(
            "vaultId" to e.vaultId, "seq" to e.seq.toString(), "prev" to e.prev, "kind" to e.kind.literal,
            "actor" to e.actor, "at" to e.at.toString(),
        )
        when (e) {
            is LogEntry.Genesis -> {
                m["ownerKey"] = e.ownerKey
                m["vkCommit"] = e.vkCommit
            }
            is LogEntry.Add -> {
                m["member"] = e.member
                m["memberKey"] = e.memberKey
                m["role"] = e.role.literal
                m["grantId"] = e.grantId
            }
            is LogEntry.Role -> {
                m["member"] = e.member
                m["role"] = e.role.literal
            }
            is LogEntry.Remove -> m["member"] = e.member
            is LogEntry.Leave -> Unit
            is LogEntry.Offer -> {
                m["to"] = e.to
                m["toKey"] = e.toKey
                m["offerId"] = e.offerId
                m["expiresAt"] = e.expiresAt.toString()
            }
            is LogEntry.Cancel -> m["offerId"] = e.offerId
            is LogEntry.Accept -> m["offerId"] = e.offerId
            is LogEntry.Delete -> m["deleteId"] = e.deleteId
            is LogEntry.Restore -> m["deleteId"] = e.deleteId
        }
        return m
    }
}

/** An entry this device signed and verified against its own state: the [frame] to post and the [step] it produces. */
class SignedLogEntry internal constructor(frame: ByteArray, val step: VaultLogStep) {
    private val frameBytes = frame.copyOf()
    val frame: ByteArray get() = frameBytes.copyOf()
}
