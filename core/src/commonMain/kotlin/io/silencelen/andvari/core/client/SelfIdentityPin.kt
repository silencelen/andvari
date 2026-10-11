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
 */
object SelfIdentityPin {
    /** Decode a stored record. A malformed local record is treated as absent (local corruption is not
     *  an adversary capability here; refusing on it would lock the member out of their own vault). */
    fun decode(stored: String?): ByteArray? =
        stored?.let { runCatching { Bytes.fromB64(it.trim()) }.getOrNull() }?.takeIf { it.size == 32 }

    /** What a platform store records after an unlock passed: the account's seed-derived identityPub. */
    fun encode(account: Account): String = Bytes.toB64(account.identityPub)
}
