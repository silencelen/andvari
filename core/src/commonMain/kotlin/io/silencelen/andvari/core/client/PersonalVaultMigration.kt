package io.silencelen.andvari.core.client

/**
 * The once-per-account personal-vault migration (security review 2026-10, root cause A §8.5), as a pure
 * decision so `spec/test-vectors/personalwrap.json` pins it for both engines (web twin:
 * `web/src/vault/personalvault.ts`).
 *
 * A vault is a candidate when (1) the server labels it `personal` and (2) its VK opened from a UVK wrap on
 * OUR OWN grant row and from no seal. The client mints the personal wrap AUTOMATICALLY only when exactly
 * one vault meets (1) and (2), its decrypted name is exactly `Personal` (the enrolment value), and, when
 * this device remembers the personal vault it last used, it is that vault. Anything else asks the human
 * ("Which vault is your Personal vault?"), listing only the vaults that pass (1) and (2); until they answer
 * there is no default destination. This is the one step where the server's pre-upgrade label still
 * matters; the strict rule and the re-designation route (owner decision Q9) bound it.
 */
object PersonalVaultMigration {
    const val ENROLMENT_NAME = "Personal"

    /** One vault as the migration sees it. [labelledPersonal] is the server's (untrusted) hint;
     *  [ownUvkWrap] is the client's own provenance record; [name] the decrypted meta name or null. */
    data class Candidate(
        val vaultId: String,
        val labelledPersonal: Boolean,
        val ownUvkWrap: Boolean,
        val name: String?,
        val itemCount: Int = 0,
    )

    sealed class Decision {
        /** Mint the wrap for [vaultId] without asking. */
        data class Auto(val vaultId: String) : Decision()

        /** Ask the human; [choices] are the vaults passing conditions (1) and (2), possibly empty. */
        data class Ask(val choices: List<Candidate>) : Decision()
    }

    fun decide(candidates: List<Candidate>, lastUsedPersonalVaultId: String?): Decision {
        val eligible = candidates.filter { it.labelledPersonal && it.ownUvkWrap }.sortedBy { it.vaultId }
        val only = eligible.singleOrNull()
        if (only != null && only.name == ENROLMENT_NAME &&
            (lastUsedPersonalVaultId.isNullOrEmpty() || lastUsedPersonalVaultId == only.vaultId)
        ) {
            return Decision.Auto(only.vaultId)
        }
        return Decision.Ask(eligible)
    }
}
