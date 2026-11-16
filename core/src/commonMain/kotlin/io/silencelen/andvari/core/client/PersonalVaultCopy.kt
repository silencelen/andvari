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
     * The PROPOSED notice as the Android and desktop apps word it, from its two records: [currentVaultId] the account's
     * record ("" when it names none), [servedVaultId] the server's, and their names. Since a first sign-in's proposal is
     * described against the account's record once that is read ([Account.describeProposalAgainst]), the two routinely name
     * the SAME vault on a new device: that is one vault to confirm, with nothing to keep, never "Your account's personal
     * vault is Personal, but the server sent Personal". No record leaves the server's word alone; two different vaults are
     * said to be two, and the account's is the one to keep.
     */
    fun proposedNotice(currentVaultId: String, servedVaultId: String, currentName: String?, servedName: String): ProposedNotice = when {
        currentVaultId == servedVaultId -> ProposedNotice(
            sameVaultTitle(servedName),
            sameVaultBody(servedVaultId) + " Until you confirm, new items need a vault picked by hand.",
            keepName = null,
        )
        currentVaultId.isEmpty() -> ProposedNotice(
            "The server says your personal vault is $servedName.",
            "This device hasn't confirmed it yet, so it uses no personal vault until you decide: new items need a vault picked by hand.",
            keepName = null,
        )
        else -> {
            val kept = currentName ?: "another vault"
            ProposedNotice(
                "Your account's personal vault is $kept, but the server sent $servedName.",
                "$DIFFERENT_VAULTS Another of your devices chose $kept, or the server sent an older record. This device uses no personal vault until you decide.",
                keepName = kept,
            )
        }
    }

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

/** What a PROPOSED personal-vault notice says ([PersonalVaultCopy.proposedNotice]); [keepName] names the vault "Keep" keeps (the
 *  account's record), null when there is no other vault to keep. */
class ProposedNotice(val title: String, val body: String, val keepName: String?)
