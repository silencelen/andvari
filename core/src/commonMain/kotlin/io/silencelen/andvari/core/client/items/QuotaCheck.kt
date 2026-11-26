package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.QuotaUse

/**
 * What one large copy writes into vaults the account owns (spec 03 §14.4, "The check before a large copy"): an import,
 * "Move everything to a new vault" (design §3.13), a copy or a move into another vault the account owns.
 *
 * - [bytes], **B**: the blob lengths of the items as they will be sent, plus the attachments' stored sizes
 *   ([ItemEngine.importSize] and [ItemEngine.vaultSize] work it out);
 * - [items], **N**: the number of items written;
 * - [newSharedVault], **V**: whether the copy creates a new shared vault;
 * - [metaBytes], **M**: that new vault's `metaBlob` length (0 when no vault is created);
 * - [declaredBytes]: the part of [bytes] that rests on sizes the items' documents DECLARE (an attachment's `size`), which
 *   any writer of the vault, a hostile one included, chooses; the rest this device measured itself.
 *
 * None is negative, and [declaredBytes] is at most [bytes].
 */
class CopySize(
    val bytes: Long,
    val items: Long,
    val newSharedVault: Boolean = false,
    val metaBytes: Long = 0,
    val declaredBytes: Long = 0,
    /**
     * **V** as a count: how many shared vaults the copy makes, the ones about to be made by the same gesture included
     * (several vaults moved at once each make one). 1 when [newSharedVault] alone says so; 0 exactly when it is false.
     */
    val newVaults: Long = if (newSharedVault) 1L else 0L,
) {
    init {
        require(bytes >= 0 && items >= 0 && metaBytes >= 0) { "a copy's size is never negative" }
        require(declaredBytes in 0..bytes) { "the declared part of a copy's size is within it" }
        require(newSharedVault || metaBytes == 0L) { "only a new vault has a metaBlob" }
        require(newVaults >= 0 && newSharedVault == (newVaults > 0)) { "the count of new vaults agrees with newSharedVault" }
    }

    override fun toString(): String =
        "CopySize(bytes=$bytes, items=$items, newSharedVault=$newSharedVault, metaBytes=$metaBytes, declaredBytes=$declaredBytes, newVaults=$newVaults)"
}

/** One limit the copy would pass: [quota] its [QuotaName], the meter as served, what the copy [adds], and [by] how much it is short. */
data class Shortfall(val quota: String, val used: Long, val limit: Long, val adds: Long) {
    /** `used + adds - limit`, at least 1; [Long.MAX_VALUE] when the true figure is larger. */
    val by: Long get() = QuotaCheck.excess(used, adds, limit)
}

/** The answer of [QuotaCheck.room]. */
sealed class QuotaRoom {
    /** Every limit the copy grows has room for it. The server's refusal stays authoritative (spec 03 §14.4, point 1). */
    object Room : QuotaRoom() {
        override fun toString(): String = "Room"
    }

    /**
     * The server gave no numbers, or numbers that cannot be meters (negative, or an object that is not one): nothing is
     * known, so this is never room. An app may start the copy and rely on the server's own refusal, or ask first.
     */
    object Unknown : QuotaRoom() {
        override fun toString(): String = "Unknown"
    }

    /**
     * The account is short: the app does not start, and says which limit and by how much, and that the operator can
     * raise it (design §3.13). [limits] holds every limit that is short, in the order `accountBytes`, `items`,
     * `ownedSharedVaults`; never empty.
     */
    class Short internal constructor(
        val limits: List<Shortfall>,
        /**
         * True when the copy is short ONLY because of sizes the items' documents declare ([CopySize.declaredBytes]),
         * which any writer of the vault chooses: without them every limit has room. The app may then let the person go
         * on and the server decide, rather than refuse on a co-member's word.
         */
        val restsOnDeclaredSizes: Boolean = false,
    ) : QuotaRoom() {
        /** The first limit that is short: what a one-line message names. */
        val first: Shortfall get() = limits.first()

        override fun toString(): String = "Short($limits, restsOnDeclaredSizes=$restsOnDeclaredSizes)"
    }
}

/**
 * The one check every app makes before a large copy (spec 03 §14.4, "The check before a large copy"), on the `quota` of
 * a FRESH `GET /sync` ([ItemEngine.roomFor] syncs first). The account is short when any limit the copy grows would be
 * passed:
 * - `accountBytes.used + max(B, M) > accountBytes.limit`;
 * - `items.used + N > items.limit`;
 * - `ownedSharedVaults.used + V > ownedSharedVaults.limit`.
 *
 * A limit the copy does not grow (it adds 0) is never short, as the server refuses only a request that grows a meter
 * (spec 03 §14.4, point 4). Landing exactly on a limit is room. The sums cannot overflow: a meter at the top of `Long`
 * plus anything is short, never wrapped round to room. A server that lies in `quota` can therefore only make the app
 * refuse early or run into the server's own refusal.
 */
object QuotaCheck {
    fun room(quota: QuotaUse?, size: CopySize): QuotaRoom {
        if (quota == null || !quota.isWhole()) return QuotaRoom.Unknown
        val short = listOfNotNull(
            shortOf(QuotaName.ACCOUNT_BYTES, quota.accountBytes, maxOf(size.bytes, size.metaBytes)),
            shortOf(QuotaName.ITEMS, quota.items, size.items),
            shortOf(QuotaName.OWNED_SHARED_VAULTS, quota.ownedSharedVaults, size.newVaults),
        )
        if (short.isEmpty()) return QuotaRoom.Room
        // Short only on the bytes, and not short on what this device measured itself: it rests on declared sizes.
        val measured = maxOf(size.bytes - size.declaredBytes, size.metaBytes)
        val declaredOnly = size.declaredBytes > 0 && short.all { it.quota == QuotaName.ACCOUNT_BYTES } &&
            shortOf(QuotaName.ACCOUNT_BYTES, quota.accountBytes, measured) == null
        return QuotaRoom.Short(short, declaredOnly)
    }

    /** `a + b` for two numbers at least 0, saturated at [Long.MAX_VALUE]: never negative, never a throw. */
    fun saturatedSum(a: Long, b: Long): Long = if (a > Long.MAX_VALUE - b) Long.MAX_VALUE else a + b

    private fun shortOf(name: String, m: QuotaMeter, adds: Long): Shortfall? =
        if (adds > 0 && excess(m.used, adds, m.limit) > 0) Shortfall(name, m.used, m.limit, adds) else null

    /**
     * `used + adds - limit` for whole numbers, saturated at [Long.MAX_VALUE]: positive exactly when `used + adds > limit`.
     * `limit - used` cannot overflow for two numbers at least 0.
     */
    internal fun excess(used: Long, adds: Long, limit: Long): Long {
        val free = limit - used
        return if (free < 0 && adds > Long.MAX_VALUE + free) Long.MAX_VALUE else adds - free
    }
}
