package io.silencelen.andvari.core.client

/*
 * What the human sees when choosing the personal vault (security review 2026-10, root cause A, branch A5b,
 * A5 re-review M-2). The choice is the only thing that makes a vault "personal", so it must be hard to get
 * wrong: every option says who else holds the vault and whether this account created it or received it by
 * transfer, a first designation goes through an explicit confirmation naming the vault and its co-holders,
 * and a served wrap that names another vault than this device's is a notice, never a silent switch.
 *
 * The co-holder list and the transfer record are what the SERVER reports. They inform the human; they never
 * decide anything (a server that hides a member makes the list shorter, it cannot make a vault personal).
 */

/** Another account the server reports as holding a vault. */
data class CoHolder(val userId: String, val displayName: String, val email: String, val role: String)

/** One vault as the personal-vault question and the Settings re-designation list show it. */
data class PersonalChoiceInfo(
    val vaultId: String,
    val name: String?,
    val itemCount: Int,
    val origin: Origin,
    /** Everyone else the server reports on the vault; null until loaded ([SyncEngine.refreshPersonalChoiceDetails]). */
    val coHolders: List<CoHolder>?,
    /** The vault this device already had as personal (its cached wrap, else the last one it used) (L-1). */
    val onThisDevice: Boolean,
) {
    enum class Origin {
        /** No transfer to this account on record: created by this account. */
        CREATED,

        /** The vault's last ownership transfer names this account as the new owner. */
        RECEIVED_BY_TRANSFER,
    }
}

/**
 * A pending, not yet confirmed, personal-vault designation. Only [SyncEngine.proposePersonalVault] makes one,
 * and only the engine that made it, while it is still the pending one, accepts it in
 * [SyncEngine.confirmPersonalVault]. Proposing mints nothing and sends nothing but the member lookup.
 */
class PersonalVaultProposal internal constructor(
    val vaultId: String,
    val name: String?,
    val origin: PersonalChoiceInfo.Origin,
    /** Who else the server reports as holding the vault; the confirmation names them. */
    val coHolders: List<CoHolder>,
    /** The personal vault in force on this device now (a re-designation replaces it), or null. */
    val replacing: String?,
)

/** A served wrap naming another vault than this device's ([Account.PersonalStatus.CHANGED]). */
data class PersonalChange(val currentVaultId: String, val servedVaultId: String)
