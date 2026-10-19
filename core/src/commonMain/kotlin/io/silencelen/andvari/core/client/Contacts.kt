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
 *    in-person code shown on the admin's screen ([EnrollLink.checkCode]) AND affirmed, first person, that
 *    they are reading that screen in person (A5c), compared at full length.
 */
object ContactPin {
    private val HEX64_RE = Regex("^[0-9a-f]{64}$")

    private fun servedFingerprint(crypto: CryptoProvider, served: ServedIdentity): String? {
        val key = runCatching { Bytes.fromB64(served.identityPub) }.getOrNull() ?: return null
        if (key.size != 32) return null
        return SharedGrant.fingerprint(crypto, key)
    }

    /** The one email normalisation every add-member comparison uses (A11): trimmed, lowercase. */
    fun normalizeEmail(e: String): String = e.trim().lowercase()

    /** The email a ceremony records (A11, q00): the address the HUMAN typed to find the person, normalised, or null
     *  when none was typed (or it is not one). A server-reported address is never recorded. */
    private fun recordedEmail(verifiedEmail: String?): String? = verifiedEmail?.let(::normalizeEmail)?.takeIf(Contact::isEmail)

    /** [verifiedEmail] (A11): the address the human typed to look them up, when there was one. */
    fun fromTyped(crypto: CryptoProvider, typedEntry: String, served: ServedIdentity, label: String, now: Long, verifiedEmail: String? = null): Contact? {
        val fp = servedFingerprint(crypto, served) ?: return null
        if (!Fingerprint.matchesShort(typedEntry, fp)) return null
        return Contact(served.userId, served.identityPub, label, now, Contact.METHOD_TYPED, recordedEmail(verifiedEmail))
    }

    fun fromQr(crypto: CryptoProvider, qrPayload: String, served: ServedIdentity, label: String, now: Long, verifiedEmail: String? = null): Contact? {
        val qr = IdentityQr.parse(qrPayload) ?: return null
        if (qr.userId != served.userId) return null
        val fp = servedFingerprint(crypto, served) ?: return null
        if (!Fingerprint.matchesFull(qr.fingerprint, fp)) return null
        return Contact(served.userId, served.identityPub, label, now, Contact.METHOD_QR, recordedEmail(verifiedEmail))
    }

    /**
     * Who an add-member request names, against the pins (security review 2026-10, branch A11, q00; web
     * `addIdentityCheck` twin). The owner TYPED [typedEmail]; the server answered with [lookedUpUserId]; [pins] are
     * this account's pins. The server's display name is not an input.
     */
    sealed class AddIdentity {
        /** The looked-up account's pin records exactly the typed email. */
        class Match(val pin: Contact) : AddIdentity()

        /** A pre-A11 pin (no email recorded): the add needs the human to confirm the PIN's own label + fingerprint. */
        class Legacy(val pin: Contact) : AddIdentity()

        /** The looked-up account's pin records another email, or ANOTHER pin ([claimedBy]) records the typed one: the
         *  server answered the owner's address with someone else's account. Refused, whatever the human confirms. */
        class Mismatch(val pin: Contact?, val claimedBy: Contact?) : AddIdentity()

        /** No (current) pin: the ceremony first. */
        object Unpinned : AddIdentity()
    }

    fun addIdentity(lookedUpUserId: String, typedEmail: String, pins: List<Contact>): AddIdentity {
        val typed = normalizeEmail(typedEmail)
        val pin = pins.firstOrNull { it.userId == lookedUpUserId }
        val claimedBy = pins.firstOrNull { it.userId != lookedUpUserId && it.email != null && it.email == typed }
        return when {
            claimedBy != null -> AddIdentity.Mismatch(pin, claimedBy)
            pin == null -> AddIdentity.Unpinned
            pin.email == null -> AddIdentity.Legacy(pin)
            pin.email == typed -> AddIdentity.Match(pin)
            else -> AddIdentity.Mismatch(pin, null)
        }
    }

    /**
     * The in-person evidence is two HUMAN acts, both re-checked here from the raw inputs (security review
     * 2026-10, A5c — API review #4): [typedCode], the in-person code the invitee typed from the admin's screen
     * ([EnrollLink.checkCodeMatches]), and [inPersonAffirmed], their first-person statement that they are
     * reading that screen right now. The code is an unkeyed hash of the link itself, so whoever composed the
     * link (the server emails invites) can hand the invitee "the code" through the same channel; nothing the
     * invitee's client can verify is beyond the server's reach, so the anchor is necessarily the human's
     * comparison, and a navigated link plus a correct code is never in-person evidence on its own. Without
     * both, the link is just text the server could have composed, nothing is pinned, and the admin stays a
     * pending verification for the "Verify a household member" ceremony.
     */
    fun fromEnrolLink(
        crypto: CryptoProvider,
        payload: EnrollPayload,
        typedCode: String,
        inPersonAffirmed: Boolean,
        served: ServedIdentity,
        label: String,
        now: Long,
    ): Contact? {
        if (!inPersonAffirmed) return null
        if (!EnrollLink.checkCodeMatches(crypto, payload, typedCode)) return null
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
