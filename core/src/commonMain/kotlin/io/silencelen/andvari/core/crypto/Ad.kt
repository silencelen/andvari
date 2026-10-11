package io.silencelen.andvari.core.crypto

/**
 * spec 02 §2 — associated-data construction. Components are `|`-joined; conforming
 * components (fixed labels, lowercase UUIDs, small integers) cannot contain `|`.
 */
object Ad {
    private const val NS = "andvari/v1"

    private fun join(vararg parts: String): ByteArray {
        for (p in parts) require('|' !in p) { "AD component must not contain '|'" }
        return (NS + "|" + parts.joinToString("|")).encodeToByteArray()
    }

    fun item(vaultId: String, itemId: String, formatVersion: Int): ByteArray =
        join("item", vaultId, itemId, formatVersion.toString())

    fun uvk(userId: String): ByteArray = join("uvk", userId)

    /** spec 04 §per-member (design 2026-07-12 §F.6) — the per-member self-service recovery
     *  envelope binding. Distinct from [uvk] (`recovery-uvk` vs `uvk`), so a recovery blob and a
     *  password-wrapped UVK blob can never be cross-substituted between slots for the same user. */
    fun recovery(userId: String): ByteArray = join("recovery-uvk", userId)

    fun idkey(userId: String): ByteArray = join("idkey", userId)

    fun vk(vaultId: String, userId: String): ByteArray = join("vk", vaultId, userId)

    /**
     * Security review 2026-10, root cause A §4.1: the PERSONAL wrap of the personal vault key,
     * `AccountKeys.personalWrap`. A distinct purpose from [vk], so an owner wrap of a shared vault can
     * never open as a personal wrap (and the reverse): only this user's UVK can mint one, which is
     * what makes "personal" a client-held, authenticated property instead of a server label.
     */
    fun vkPersonal(vaultId: String, userId: String): ByteArray = join("vk-personal", vaultId, userId)

    /** Root cause A §4.2: the per-user account-state blob (contact pins, org fp, consumed nonces),
     *  sealed under the UVK and bound to the userId so one member's blob never opens in another slot. */
    fun accountState(userId: String): ByteArray = join("account-state", userId)

    fun vaultMeta(vaultId: String): ByteArray = join("vaultmeta", vaultId)

    /** spec 02 §8.2 (design 2026-08-22) — the per-user usage ledger envelope. Bound to the userId
     *  so one member's ledger can never be served into another's slot on a shared endpoint. */
    fun usage(userId: String): ByteArray = join("usage", userId)

    /** spec 07 §2.4 — backup items envelope. Binds the plaintext header's `v` and the
     *  per-file `fileId`, so a future v2 file can never be downgrade-opened under v1 rules
     *  and a section 0 can never be transplanted between backup files. */
    fun export(v: Int, fileId: String): ByteArray = join("export", v.toString(), fileId)
}
