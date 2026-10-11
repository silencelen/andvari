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
 * **A prefix (short) match is accepted ONLY from a human-typed entry** ([matchesShort]). Every
 * machine-supplied value is compared at full 64-hex length with [matchesFull]: the in-person-QR `rfp`
 * and `ifp` (minted full-length by the admin client and checked full-length by the invitee), the admin
 * sheet-confirm (the typed 32 hex anchors a locally computed full fingerprint, which is what the QR
 * stamps), the identity QR, and [Account.resealEscrowFor]. No path compares a 16-hex id any more
 * (security review 2026-10, root cause A, branch A5).
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
     * True iff a MACHINE-supplied [value] (a QR payload, a link field, a file) is EXACTLY the 64
     * lowercase hex [fullFingerprintHex]. No normalising and no prefix: a value that did not come from a
     * human has no excuse to be short or differently cased, so anything else is a mismatch.
     */
    fun matchesFull(value: String, fullFingerprintHex: String): Boolean =
        value.length == FULL_HEX_LEN && FULL_RE.matches(value) && value == fullFingerprintHex

    /** Full fingerprint length in hex chars (256 bits). */
    const val FULL_HEX_LEN = 64
    private val FULL_RE = Regex("^[0-9a-f]{64}$")

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
