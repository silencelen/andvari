package io.silencelen.andvari.core.crypto

/**
 * The HUMAN short form of a fingerprint, shared by the recovery fingerprint (spec 04 §1,
 * [Escrow.fingerprint]) and the identity fingerprint (spec 01 §5, [SharedGrant.fingerprint]).
 *
 * Security review 2026-10 (root cause A, §7): the short form a human READS or TYPES is the first
 * **32 lowercase hex = 128 bits**, not 16. A 64-bit (16-hex) truncated second preimage is grindable
 * by a hostile server; 128 bits is out of reach. The underlying construction is unchanged
 * (`SHA-256(pub)`); only the human-visible truncation length and the compare helper changed.
 *
 * **A prefix (short) match is intended ONLY for a human-typed entry** ([matchesShort]). Machine-
 * supplied values should be compared at full 64-hex length by their own callers, and
 * [Account.resealEscrowFor] does so today. NOT YET TRUE everywhere: the in-person-QR `rfp` value and
 * the admin sheet-confirm are still compared on a 16-hex short id ([Escrow.shortFingerprint]); moving
 * them to a full-length compare is tracked for a later branch of this security review.
 *
 * One helper, two engines: the web twin is `web/src/crypto/fingerprint.ts`.
 */
object Fingerprint {
    /** Human short-form length in hex chars (128 bits). */
    const val SHORT_HEX_LEN = 32

    /** The short form: the first [SHORT_HEX_LEN] lowercase hex chars of a full fingerprint. */
    fun shortForm(fullFingerprintHex: String): String =
        fullFingerprintHex.lowercase().take(SHORT_HEX_LEN)

    /**
     * True iff a HUMAN-TYPED [entry] is the 32-hex short form of [fullFingerprintHex]. Spaces,
     * dashes and case in [entry] are normalised away; after normalising it must be EXACTLY 32 hex
     * digits and equal the short form. The UI must not display the fingerprint before a correct
     * entry (so a hostile server cannot win a lazy eyeball-match).
     */
    fun matchesShort(entry: String, fullFingerprintHex: String): Boolean {
        val norm = entry.lowercase().filter { it in "0123456789abcdef" }
        return norm.length == SHORT_HEX_LEN && shortForm(fullFingerprintHex) == norm
    }

    /**
     * Display grouping for the 32-hex short form: 8 groups of 4, split across two lines (4 groups
     * per line, joined by '\n'). A full-length hex string is impractical to read aloud; this is
     * the eyeball/verify form. Compose renders the '\n' directly; the web twin renders two lines.
     */
    fun groupedShort(fullOrShortHex: String): String {
        val groups = shortForm(fullOrShortHex).chunked(4)
        return groups.take(4).joinToString(" ") + "\n" + groups.drop(4).joinToString(" ")
    }
}
