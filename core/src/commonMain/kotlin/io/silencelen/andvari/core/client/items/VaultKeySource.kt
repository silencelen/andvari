package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncVault

/**
 * How far this device trusts a vault's history, as far as the item plane needs to know (design §3.9). The trust
 * engine decides it; [ItemEngine] only reads it.
 */
enum class VaultStanding {
    /** The personal vault, or a shared vault whose log verified with this account in its members: read, and write as the role allows. */
    VERIFIED,

    /**
     * The server shows less than this device verified, or says this account lost the vault without a verified
     * `remove`, `leave`, `delete` or purge (spec 02 §10.6 "withholding"): the copy stays, read-only, with copy-out.
     */
    WITHHELD,

    /** An entry failed verification (design §3.9): read-only until the log verifies again. */
    FAILED,

    /** Two signed entries at one position (a fork of the vault's log): read-only. */
    FROZEN,
}

/** One vault this account may READ right now, and what it may do there. */
class VaultAccess(
    val vaultId: String,
    /** True only for the vault the account genesis names (design §5.3); never taken from the served `type` label. */
    val personal: Boolean,
    /** `owner`, `writer` or `reader` as this DEVICE verified it: the log's role, never the served grant row's. */
    val role: String,
    val standing: VaultStanding,
) {
    /** Design §3.6: an item is written only into a verified vault, and never by a reader. */
    val writable: Boolean get() = standing == VaultStanding.VERIFIED && role != ROLE_READER

    companion object {
        const val ROLE_OWNER = "owner"
        const val ROLE_WRITER = "writer"
        const val ROLE_READER = "reader"
    }
}

/** Why a vault this device held is no longer the account's to use, once the trust engine VERIFIED it (spec 02 §10.6). */
enum class VaultDeparture(val code: String) {
    /** The owner's signed `remove` of this account. */
    REMOVED("removed"),

    /** This account's own signed `leave` (a decline included). */
    LEFT("left"),

    /** The owner's signed `delete`, with no `restore` after it: in its grace, a `restore` brings the vault back. */
    DELETED("deleted"),

    /** Verified through the tombstone's final head: deleted for good. */
    PURGED("purged"),
}

/** The verified head of a shared vault's log, as a writer stamps it into an item (spec 02 §3 `logHead`). */
class LogHeadStamp(val seq: Long, val hash: String)

/**
 * What one pull showed about vaults (spec 03 §4), exactly as served. [lostAccess] is `removedGrants` plus, on a full
 * snapshot, every vault this device held that the snapshot no longer lists.
 */
class ServedVaults(
    val full: Boolean,
    val vaults: List<SyncVault>,
    val grants: List<SyncGrant>,
    val lostAccess: Set<String>,
    /** The answer's `accountStateSeq` (spec 03 §4), the account state's counter; null when the answer carried none. */
    val accountStateSeq: Long? = null,
)

/**
 * Which vaults this account may read and write right now, and under which key. It is the ONLY place [ItemEngine]
 * gets a key from, and the item engine never opens a wrap or a grant and never decides trust.
 *
 * **Contract.**
 * - **The personal vault** is the one the account genesis names, with the key of the personal wrap the session opened
 *   (design §5.3, spec 02 §4). [personalVaultId] is null when that wrap was withheld or did not open: the account then
 *   has NO personal vault (no default save destination, no usage ledger), and nothing else ever stands in for it. The
 *   served `type` label is never an input.
 * - **A shared vault** is here only with a key the vault-log engine ADOPTED after its own checks (design §3.6). A vault
 *   the account has not accepted, was not asked about yet, declined, or whose log this device never verified is absent:
 *   [access] and [withKey] answer null and the engine keeps its rows as ciphertext it cannot read.
 * - **[access]** names what the vault's status allows (design §3.6, §3.9): [VaultStanding.VERIFIED] reads and, for an
 *   owner or writer, writes; [VaultStanding.WITHHELD], [VaultStanding.FAILED] and [VaultStanding.FROZEN] read only (the
 *   engine still decrypts what it holds and lets items be copied out, and seals or sends nothing under that key).
 * - **[withKey]** lends the key to a block under the account's guard; no copy leaves. It is non-null for every vault [access] lists, and may be non-null
 *   for a vault in [departure] while the trust engine still offers its key: that one is for reading the device's held
 *   copy out of the holding area, never for a write.
 * - **[departure]** is non-null only for a reason the trust engine verified in the vault's log. A vault the server
 *   merely stopped serving has no departure: it stays [VaultStanding.WITHHELD] (spec 02 §10.6: a server cannot make a
 *   device drop its copy by revoking a grant or claiming a purge).
 * - **Reports.** The engine calls [served] with every pull's vault and grant rows BEFORE it applies that pull's items,
 *   [reopen] once per session with the rows of its cache before it decrypts anything from it, and [itemHead] for a log
 *   head an item carried. [served] and [itemHead] may use the network (a log fetch); [reopen] reads this device's own
 *   state and the rows it is handed. After any of them [access], [withKey] and [departure] may answer differently.
 * - Nothing here throws, and an anomaly is a state, never an exception; the one exception is a wiped account
 *   ([io.silencelen.andvari.core.crypto.KeysGoneException]): a lock is not an anomaly of a vault, and no vault of a
 *   wiped account is "verified" or "absent". Every answer is this device's own belief;
 *   a served row is only ever a hint.
 */
interface VaultKeySource {
    /** The account's one personal vault, or null: "no personal vault" (the anomaly of design §5.3). */
    val personalVaultId: String?

    /** [vaultId] as this account may use it now, or null when it may not be read. */
    fun access(vaultId: String): VaultAccess?

    /**
     * [block] with [vaultId]'s key, under the guard of the account it belongs to, or null when the trust
     * engine offers none. Once the account's keys are wiped (a lock, the end of the session) it throws
     * [io.silencelen.andvari.core.crypto.KeysGoneException] rather than answering null: a lock is never "no key". [block]
     * cannot wait, and keeps no reference to the key: no key array leaves the account.
     */
    fun <T> withKey(vaultId: String, block: (ByteArray) -> T): T?

    /**
     * False once the account's keys are wiped: nothing more is sealed under them or sent for them. Asked after every
     * wait, before anything is sent.
     */
    val keysLive: Boolean get() = true

    /** Why [vaultId] is no longer this account's, when that is verified; null otherwise. */
    fun departure(vaultId: String): VaultDeparture?

    /**
     * True while the copy held of [vaultId] does not open because the vault's verified log names this account a member
     * again and this device holds an invitation to it that its person can answer now (decided on 22 and 23 November
     * 2026: closed for that stretch only). Reads only.
     */
    fun heldClosedAsMemberAgain(vaultId: String): Boolean = false

    /** The verified head to stamp into an item written to [vaultId]; null for the personal vault and for any vault that is not verified. */
    fun logHead(vaultId: String): LogHeadStamp?

    /** One pull's vault and grant rows, and the vaults the server says this account lost. */
    suspend fun served(report: ServedVaults)

    /** The cached rows of the last applied pull, at the start of a session: adopt what this device may, without a pull. */
    suspend fun reopen(vaults: List<SyncVault>, grants: List<SyncGrant>)

    /** An item decrypted under [vaultId]'s key names the log head [seq]/[hash]: a hint to fetch, never a verdict (design §3.9). */
    suspend fun itemHead(vaultId: String, seq: Long, hash: String)
}
