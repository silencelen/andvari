package io.silencelen.andvari.core.client

/**
 * The once-per-account personal-vault QUESTION (security review 2026-10, root cause A §8.5, as amended by the
 * A5 review, H-1). Pure, so `spec/test-vectors/personalwrap.json` (`migration`) pins it for every engine (web
 * twin: `web/src/vault/personalvault.ts`).
 *
 * There is NO automatic pick. The design's §8.5 auto rule ("one vault labelled personal, own wrap, named
 * Personal") let the server's label decide whenever it withheld the wrap, and the client then MINTED a
 * genuine wrap for that pick, turning an unauthenticated signal into authenticated state on every device.
 * Now, with no wrap served and none cached on this device, the client asks "Which vault is your Personal
 * vault?" and mints only on the human's answer. The choices are EVERY held vault whose key opened from a UVK
 * wrap on our own grant row (no seal on the row), regardless of the server's label or role, which neither
 * filters nor orders them: the vault this device last used (if any) first, then by vaultId.
 */
object PersonalVaultMigration {
    /** One vault as the question sees it. No server label: it decides nothing here. */
    data class Candidate(
        val vaultId: String,
        val ownUvkWrap: Boolean,
        val name: String?,
        val itemCount: Int = 0,
    )

    fun choices(candidates: List<Candidate>, lastUsedPersonalVaultId: String?): List<Candidate> =
        candidates.filter { it.ownUvkWrap }
            .sortedWith(compareBy<Candidate> { it.vaultId != lastUsedPersonalVaultId }.thenBy { it.vaultId })
}
