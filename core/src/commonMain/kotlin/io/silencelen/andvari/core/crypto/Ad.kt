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

    fun idkey(userId: String): ByteArray = join("idkey", userId)

    fun vk(vaultId: String, userId: String): ByteArray = join("vk", vaultId, userId)

    fun vaultMeta(vaultId: String): ByteArray = join("vaultmeta", vaultId)
}
