package io.silencelen.andvari.core.client

/**
 * Sentences of the personal-vault notice that every client says the same way.
 *
 * Two cases are easy to misread when two vaults carry the same name (a device showed "Your account's personal vault is
 * Personal, but the server sent Personal"):
 *  - the account's record and the record the server sent name the SAME vault: nothing conflicts, the device has only not
 *    been asked yet ([sameVaultTitle], [sameVaultBody]);
 *  - they name two DIFFERENT vaults: said in so many words ([DIFFERENT_VAULTS]).
 * And each vault on offer gets a line of facts that tells it from another of the same name ([facts]).
 */
object PersonalVaultCopy {
    /** How a vault id is shown: its last six characters. */
    fun idTail(vaultId: String): String = vaultId.takeLast(6)

    /** PROPOSED with the account's record and the served one naming the same vault. */
    fun sameVaultTitle(name: String): String = "Confirm your personal vault on this device: $name."

    /** What follows [sameVaultTitle]; the client adds what the wait means on that client. */
    fun sameVaultBody(vaultId: String): String =
        "Your account's record and the server name the same vault (id ending ${idTail(vaultId)}). A device asks once before it uses a personal vault, and this one hasn't been asked yet."

    /** Put before the explanation of a CHANGED notice, or a PROPOSED one whose two records name different vaults. */
    const val DIFFERENT_VAULTS = "These are two different vaults."

    /**
     * What tells one vault from another when their names are the same: how much is in it, when it was created and last
     * changed (UTC days), and the end of its id. Unknown dates are left out.
     */
    fun facts(itemCount: Int, createdAtMs: Long?, lastChangedMs: Long?, vaultId: String): String =
        listOfNotNull(
            if (itemCount == 1) "1 item" else "$itemCount items",
            createdAtMs?.takeIf { it > 0 }?.let { "created ${day(it)}" },
            lastChangedMs?.takeIf { it > 0 }?.let { "last changed ${day(it)}" },
            "id ending ${idTail(vaultId)}",
        ).joinToString(" · ")

    /** [facts] for [vaultId] as this device's copy of the vault holds it. Facts this device holds, never the server's say. */
    fun facts(engine: SyncEngine, vaultId: String): String {
        val items = engine.items().filter { it.vaultId == vaultId }
        val created = engine.vaultRows().firstOrNull { it.vaultId == vaultId }?.createdAt
        return facts(items.size, created, items.maxOfOrNull { it.updatedAt }, vaultId)
    }

    private fun day(ms: Long): String = kotlinx.datetime.Instant.fromEpochMilliseconds(ms).toString().take(10)
}
