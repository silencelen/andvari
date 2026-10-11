package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.SharedGrant

/**
 * The identity QR a member shows on "Verify a household member" and on the last enrolment screen
 * (security review 2026-10, root cause A §7.2): `andvari-id:1:<userId>:<hex64>`, where hex64 is the FULL
 * identity fingerprint `hex(SHA-256(identityPub))` over the member's seed-derived key. A scanner compares
 * it at full length against the key the server serves for that userId ([ContactPin.fromQr]); a prefix is
 * never accepted from a machine. Web twin: `web/src/vault/contacts.ts`.
 */
object IdentityQr {
    const val PREFIX = "andvari-id:1:"
    private val RE = Regex("^andvari-id:1:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([0-9a-f]{64})$")

    class Parsed(val userId: String, val fingerprint: String)

    fun compose(crypto: CryptoProvider, userId: String, identityPub: ByteArray): String =
        PREFIX + userId + ":" + SharedGrant.fingerprint(crypto, identityPub)

    /** Strict: exact prefix, lowercase uuid, exactly 64 lowercase hex, nothing else. Null otherwise. */
    fun parse(payload: String): Parsed? {
        val m = RE.matchEntire(payload) ?: return null
        return Parsed(m.groupValues[1], m.groupValues[2])
    }
}

/** What the server served for a user (`POST /users/lookup`, `GET /users/{id}/identity`, a member row):
 *  untrusted until a human compares it. */
class ServedIdentity(val userId: String, val identityPub: String)

/**
 * The ONLY ways a contact gets pinned (root cause A §4.2, §7.2; owner decision Q4: pairwise only).
 * Every function compares a HUMAN-sourced value with `SHA-256` of the key the server served and returns
 * null on any mismatch; nothing here, or anywhere else, turns a served key into a pin on its own.
 *
 *  - [fromTyped]: the member TYPED the other person's 32-hex short form, read from THEIR screen (the A2
 *    human-only prefix rule: exactly 32 hex after normalising, never a machine-supplied value).
 *  - [fromQr]: a camera scan of the other person's identity QR, compared at FULL length.
 *  - [fromEnrolLink]: the in-person enrolment link's `ifp`/`iu`, ONLY after the invitee typed the
 *    in-person code shown on the admin's screen ([EnrollLink.checkCode]), compared at full length.
 */
object ContactPin {
    private val HEX64_RE = Regex("^[0-9a-f]{64}$")

    private fun servedFingerprint(crypto: CryptoProvider, served: ServedIdentity): String? {
        val key = runCatching { Bytes.fromB64(served.identityPub) }.getOrNull() ?: return null
        if (key.size != 32) return null
        return SharedGrant.fingerprint(crypto, key)
    }

    fun fromTyped(crypto: CryptoProvider, typedEntry: String, served: ServedIdentity, label: String, now: Long): Contact? {
        val fp = servedFingerprint(crypto, served) ?: return null
        if (!Fingerprint.matchesShort(typedEntry, fp)) return null
        return Contact(served.userId, served.identityPub, label, now, Contact.METHOD_TYPED)
    }

    fun fromQr(crypto: CryptoProvider, qrPayload: String, served: ServedIdentity, label: String, now: Long): Contact? {
        val qr = IdentityQr.parse(qrPayload) ?: return null
        if (qr.userId != served.userId) return null
        val fp = servedFingerprint(crypto, served) ?: return null
        if (!Fingerprint.matchesFull(qr.fingerprint, fp)) return null
        return Contact(served.userId, served.identityPub, label, now, Contact.METHOD_QR)
    }

    /**
     * [inPersonVerified] is the caller's statement that the human typed the link's in-person code and
     * it matched ([EnrollLink.checkCodeMatches]); without it the link is just text the server could
     * have composed, and nothing is pinned.
     */
    fun fromEnrolLink(
        crypto: CryptoProvider,
        payload: EnrollPayload,
        inPersonVerified: Boolean,
        served: ServedIdentity,
        label: String,
        now: Long,
    ): Contact? {
        if (!inPersonVerified) return null
        val ifp = payload.ifp ?: return null
        val iu = payload.iu ?: return null
        if (!HEX64_RE.matches(ifp) || iu != served.userId) return null
        val fp = servedFingerprint(crypto, served) ?: return null
        if (!Fingerprint.matchesFull(ifp, fp)) return null
        return Contact(served.userId, served.identityPub, label, now, Contact.METHOD_ENROL)
    }

    /** How a served key relates to this account's pins, for the sharing flow (root cause A §7.2). */
    enum class PinState { PINNED_MATCH, PINNED_MISMATCH, UNPINNED }

    fun pinState(state: AccountStateDoc?, served: ServedIdentity): PinState {
        val c = state?.contact(served.userId) ?: return PinState.UNPINNED
        val pinned = runCatching { Bytes.fromB64(c.identityPub) }.getOrNull()
        val offered = runCatching { Bytes.fromB64(served.identityPub) }.getOrNull()
        return if (pinned != null && offered != null && Bytes.ctEquals(pinned, offered)) PinState.PINNED_MATCH else PinState.PINNED_MISMATCH
    }
}
