package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentRules
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.client.items.QuotaRoom
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.QuotaUse

/** What the check before a large copy found (spec 03 §14.4, "The check before a large copy"). */
enum class SpaceVerdict {
    /** Every limit the copy grows has room for it. The server still decides. */
    ROOM,

    /** The server gave no use and limits (or none that can be meters): the work starts and the server decides. */
    UNKNOWN,

    /** The account is short: the work was NOT started. [SpaceCheck.limits] says which limit and by how much. */
    NOT_ENOUGH,

    /**
     * Short only by the file sizes the items' documents state, which another member of the vault may have written:
     * the work goes on and the server decides; the screen says so ([SpaceCheck.line]).
     */
    NOT_ENOUGH_ON_DECLARED_SIZES,
}

/** What a check before a large copy was made for. */
enum class SpaceFor {
    /** [VaultContent.confirmImport] (and, from the last value this device holds, the plan before it). */
    CSV_IMPORT,

    /** [VaultContent.saveVaultItemsToPersonal]. */
    INTO_PERSONAL,

    /** [VaultContent.moveOrCopyItem] into a vault the account owns. */
    MOVE_OR_COPY,

    /** [VaultContent.spaceForMoveEverything]: "Move everything to a new vault" (design §3.13). */
    MOVE_EVERYTHING,
}

/** One limit a copy would pass: [quota] the meter's name (spec 03 §14.4: `accountBytes`, `items`, `ownedSharedVaults`). */
class SpaceShortfall internal constructor(
    val quota: String,
    /** The meter as the server served it. */
    val used: Long,
    val limit: Long,
    /** What the copy adds to it. */
    val adds: Long,
    /** How much it is short: at least 1. */
    val by: Long,
)

/**
 * The check before a large copy, as a screen shows it (design §3.13: "the app checks first and says so"). Made on the
 * use and limits of a FRESH sync, except the import plan's early line, which reads the last value this device holds
 * and is checked again, fresh, on confirm.
 */
class SpaceCheck internal constructor(
    val verdict: SpaceVerdict,
    val forWhat: SpaceFor,
    /** The vault written into; null for the new vault of "Move everything". */
    val vaultId: String?,
    /** Every limit that is short, the one the line names first; empty unless [verdict] is NOT_ENOUGH or NOT_ENOUGH_ON_DECLARED_SIZES. */
    val limits: List<SpaceShortfall>,
    /**
     * What to say (keys awaiting the owner's words): for NOT_ENOUGH, which limit, by how much, and that the operator can raise
     * it ([CopyKey.SPACE_SHORT_BYTES], [CopyKey.SPACE_SHORT_ITEMS], [CopyKey.SPACE_SHORT_VAULTS]); for
     * NOT_ENOUGH_ON_DECLARED_SIZES, that the work goes on and the server decides ([CopyKey.SPACE_SHORT_DECLARED]); null
     * otherwise.
     */
    val line: CopyLine?,
) {
    /** The work was started (or may be): only NOT_ENOUGH stops it. */
    val started: Boolean get() = verdict != SpaceVerdict.NOT_ENOUGH

    internal companion object {
        fun of(room: QuotaRoom, forWhat: SpaceFor, vaultId: String?): SpaceCheck = when (room) {
            QuotaRoom.Room -> SpaceCheck(SpaceVerdict.ROOM, forWhat, vaultId, emptyList(), null)
            QuotaRoom.Unknown -> SpaceCheck(SpaceVerdict.UNKNOWN, forWhat, vaultId, emptyList(), null)
            is QuotaRoom.Short -> {
                val limits = room.limits.map { SpaceShortfall(it.quota, it.used, it.limit, it.adds, it.by) }
                val first = limits.first()
                if (room.restsOnDeclaredSizes) {
                    SpaceCheck(SpaceVerdict.NOT_ENOUGH_ON_DECLARED_SIZES, forWhat, vaultId, limits,
                        CopyLine.of(CopyKey.SPACE_SHORT_DECLARED, AttachmentRules.size(first.limit), AttachmentRules.size(first.by)))
                } else {
                    SpaceCheck(SpaceVerdict.NOT_ENOUGH, forWhat, vaultId, limits, shortLine(first))
                }
            }
        }

        private fun shortLine(s: SpaceShortfall): CopyLine = when (s.quota) {
            QuotaName.ITEMS ->
                if (s.by == 1L) CopyLine.of(CopyKey.SPACE_SHORT_ITEMS_ONE_OVER, s.limit.toString())
                else CopyLine.of(CopyKey.SPACE_SHORT_ITEMS, s.limit.toString(), s.by.toString())
            QuotaName.OWNED_SHARED_VAULTS ->
                if (s.limit == 1L) CopyLine.of(CopyKey.SPACE_SHORT_VAULTS_ONE)
                else CopyLine.of(CopyKey.SPACE_SHORT_VAULTS, s.limit.toString())
            else -> CopyLine.of(CopyKey.SPACE_SHORT_BYTES, AttachmentRules.size(s.limit), AttachmentRules.size(s.by))
        }
    }
}

/** One of the account's meters (spec 03 §14.4), as the server served it. */
class StorageMeter internal constructor(val used: Long, val limit: Long)

/**
 * The account's own use and limits, for Settings' storage line (spec 03 §14.4, "What an account is told"): the four
 * meters as the freshest completed sync served them. [ContentState.storage] is null when the server gave none (an older
 * server) or none that can be meters: Settings then shows nothing at all.
 */
class AccountStorage internal constructor(
    /** Item ciphertext plus attachment bytes in the vaults the account owns. */
    val accountBytes: StorageMeter,
    /** Live items across the vaults the account owns. */
    val items: StorageMeter,
    val ownedSharedVaults: StorageMeter,
    val openLinks: StorageMeter,
) {
    internal companion object {
        fun of(quota: QuotaUse?): AccountStorage? {
            if (quota == null || !quota.isWhole()) return null
            fun m(q: QuotaMeter) = StorageMeter(q.used, q.limit)
            return AccountStorage(m(quota.accountBytes), m(quota.items), m(quota.ownedSharedVaults), m(quota.openLinks))
        }
    }
}
