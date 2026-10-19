package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes

/**
 * The recovered-member backstop (security review 2026-10, root cause A §2.4; spec 01 §5): every
 * device that has unlocked an account keeps the SEED-DERIVED `identityPub` it saw, and passes it to
 * [Account.unlock] / [Account.unlockWithUvk] on every later unlock. If the identity seed ever derives
 * a different key, unlock hard-fails with the spec 01 §5 security-fault copy.
 *
 * Why it exists: an org recovery for a member whose admin had no identity anchor (owner decision Q2,
 * `--no-identity-anchor`) cannot tell a genuine escrow blob from a server-minted one with a matching
 * forged seed. A forged recovery must change the identity seed, and every device that knew the real
 * key refuses it.
 *
 * Storage rule (platform stores): the record is PUBLIC data (the server holds the same key) and must
 * SURVIVE sign-out and session revocation — an admin recovery revokes every session first, so a pin
 * wiped with the session would protect nothing. It is written once, from an unlock that passed, and
 * never overwritten from a server value. Keyed by (origin, userId).
 *
 * Security review 2026-10, branch A11 (q08): the userId key is the SERVER's choice (the login response), so a
 * server that answers the same typed email with a new userId got a pin miss and its identity became the new pin.
 * Platform stores now ALSO keep an email [Binding]: (origin, the email the user typed, normalised) → the
 * (userId, identityPub) this device saw at its first passing unlock. [resolve] turns a changed userId for the same
 * email into the §5 security fault. A pre-A11 userId-keyed pin is bound to the email of the session that owns it
 * (platform stores do that at startup and lazily), so existing pins carry over.
 */
object SelfIdentityPin {
    /** Decode a stored record. A malformed local record is treated as absent (local corruption is not
     *  an adversary capability here; refusing on it would lock the member out of their own vault). */
    fun decode(stored: String?): ByteArray? =
        stored?.let { runCatching { Bytes.fromB64(it.trim()) }.getOrNull() }?.takeIf { it.size == 32 }

    /** What a platform store records after an unlock passed: the account's seed-derived identityPub. */
    fun encode(account: Account): String = Bytes.toB64(account.identityPub)

    /** The device-chosen half of the key: the email exactly as a person would retype it. */
    fun normalizeEmail(email: String): String = email.trim().lowercase()

    /** A self-identity binding for one typed email: the userId and identityPub of the first passing unlock. */
    class Binding(val userId: String, val identityPub: ByteArray)

    /** Wire form of a [Binding]: `<userId>\n<base64url identityPub>`. */
    fun encodeBinding(userId: String, account: Account): String {
        require(io.silencelen.andvari.core.model.WireIds.isUuid(userId)) { "malformed self-identity binding userId" }
        return userId + "\n" + Bytes.toB64(account.identityPub)
    }

    /** Decode a stored binding; malformed reads as absent (local corruption, see [decode]). */
    fun decodeBinding(stored: String?): Binding? {
        val parts = stored?.trim()?.split("\n") ?: return null
        if (parts.size != 2 || !io.silencelen.andvari.core.model.WireIds.isUuid(parts[0])) return null
        val pub = decode(parts[1]) ?: return null
        return Binding(parts[0], pub)
    }

    /**
     * The pin to hand [Account.unlock] for an unlock of [userId] the server answered for the email whose [binding]
     * this device holds (null: none yet), with [legacy] the userId-keyed pin. Throws the §5 security-fault
     * [io.silencelen.andvari.core.crypto.CryptoException] when the binding names another userId, or when the two
     * device records contradict each other. No binding: the legacy pin (null on a first unlock).
     */
    fun resolve(binding: Binding?, userId: String, legacy: ByteArray?): ByteArray? {
        if (binding == null) return legacy
        if (binding.userId != userId) throw io.silencelen.andvari.core.crypto.CryptoException(Account.IDENTITY_MISMATCH_MESSAGE)
        if (legacy != null && !Bytes.ctEquals(legacy, binding.identityPub)) {
            throw io.silencelen.andvari.core.crypto.CryptoException(Account.IDENTITY_MISMATCH_MESSAGE)
        }
        return binding.identityPub
    }

    /**
     * The pin logic over ONE origin's string key-value namespace (Android prefs; the desktop keeps files with the
     * same semantics). Keys: `selfIdentityPub.<userId>` (the pre-A11 pin, unchanged) and
     * `selfIdentityByEmail.<normalised email>` (the [Binding]). Both are written once and never overwritten.
     */
    class KeyValueStore(private val get: (String) -> String?, private val put: (String, String) -> Unit) {
        private fun legacyKey(userId: String) = "selfIdentityPub.$userId"
        private fun bindingKey(email: String) = "selfIdentityByEmail.${normalizeEmail(email)}"

        /** The pin for an unlock of [userId] reached by typing [email]; throws the §5 fault on a changed userId. */
        fun pinFor(email: String, userId: String): ByteArray? {
            val binding = if (email.isBlank()) null else decodeBinding(get(bindingKey(email)))
            return resolve(binding, userId, decode(get(legacyKey(userId))))
        }

        /** Record both records once, from an unlock that passed. */
        fun record(userId: String, email: String, account: Account) {
            if (get(legacyKey(userId)) == null) put(legacyKey(userId), encode(account))
            if (email.isNotBlank() && get(bindingKey(email)) == null) put(bindingKey(email), encodeBinding(userId, account))
        }

        /** Migration: bind a pre-A11 pin of the saved session ([userId], [email]) to that email, once. */
        fun bindLegacy(userId: String, email: String) {
            if (email.isBlank() || !io.silencelen.andvari.core.model.WireIds.isUuid(userId)) return
            val pub = decode(get(legacyKey(userId))) ?: return
            if (get(bindingKey(email)) == null) put(bindingKey(email), userId + "\n" + Bytes.toB64(pub))
        }
    }
}
