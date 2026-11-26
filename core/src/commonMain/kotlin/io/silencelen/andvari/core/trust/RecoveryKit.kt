package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.MemberRecovery

/**
 * The recovery kit's encodings (design 2026-11-15 §10): how the 32-byte `recoverySecret` is shown,
 * typed back and confirmed, and the kit QR. The secret itself and its key split are unchanged
 * ([MemberRecovery], spec 01 §2.1): it is never typed into a KDF, only decoded back to the same bytes.
 *
 * Twin: `web/src/crypto/trust/recoverykit.ts`. Vectors: `spec/test-vectors/recoverykit.json`.
 */
object RecoveryKit {
    /** §10: 43 base64url characters in 11 groups, ten of 4 and one of 3. */
    const val GROUPS = 11

    /** §10: the confirmation asks for three distinct groups. */
    const val CONFIRM_GROUPS = 3

    /** The kit QR's fixed prefix: `andvari-kit:2:`. Deliberately not a URL, so a camera app offers nothing for it. */
    const val QR_PREFIX = "andvari-kit:2:"

    /** A bound on the QR payload so that parsing stays total on hostile input. */
    const val MAX_QR_LENGTH = 1024

    /** A parsed kit QR. [secret] is copied in and out. */
    class Kit internal constructor(val origin: String, val card0Hash: String, val emailNorm: String, secret: ByteArray) {
        private val secretBytes = secret.copyOf()
        val secret: ByteArray get() = secretBytes.copyOf()
        fun wipe() = secretBytes.fill(0)
    }

    /**
     * The 11 display groups of [recoverySecret] (32 bytes): its 43 base64url characters, ten groups of 4 and a last one of 3.
     * The secret becomes TEXT here because a person reads it: a `String` cannot be wiped, so these groups live until the
     * runtime collects them, and the same holds for [composeQr] and for whatever a person types back ([parseSecret]).
     */
    fun groups(recoverySecret: ByteArray): List<String> {
        require(recoverySecret.size == MemberRecovery.SECRET_BYTES) { "recovery secret must be 32 bytes" }
        return Bytes.toB64(recoverySecret).chunked(4)
    }

    /** The display form: the 11 [groups] separated by single spaces. */
    fun displayForm(recoverySecret: ByteArray): String = groups(recoverySecret).joinToString(" ")

    /**
     * A typed or scanned-back secret, or null when it is not one (§2.4: `bad_kit`). Total. The parser
     * ignores SPACES AND LINE BREAKS ONLY (U+0020, CR, LF): a tab is not ignored, and neither is a dash,
     * because base64url uses `-` (FI-B10). What remains must be canonical unpadded base64url of exactly
     * 32 bytes.
     */
    fun parseSecret(typed: String): ByteArray? {
        val text = stripTypedSpace(typed)
        if (text.length != 43) return null
        return Bytes.fromB64Exact(text, MemberRecovery.SECRET_BYTES)
    }

    /** What a typed kit text ignores (§10): U+0020, CR and LF, and nothing else. */
    private fun stripTypedSpace(text: String): String = text.filterNot { it == ' ' || it == '\r' || it == '\n' }

    /**
     * Three distinct group numbers, 1..11, chosen uniformly from [crypto]'s CSPRNG and returned in
     * ascending order ("Type groups 2, 7 and 10"). Rejection sampling keeps every group equally likely.
     */
    fun confirmGroups(crypto: CryptoProvider): List<Int> {
        val picked = LinkedHashSet<Int>()
        while (picked.size < CONFIRM_GROUPS) {
            for (b in crypto.randomBytes(16)) {
                val v = b.toInt() and 0xFF
                if (v >= 253) continue // 253 = 11 * 23: a byte of 253 or more would favour the low groups
                picked += v % GROUPS + 1
                if (picked.size == CONFIRM_GROUPS) break
            }
        }
        return picked.sorted()
    }

    /** A valid challenge (§10): exactly three DISTINCT group numbers, each in 1..11, in any order. */
    fun isGroupChoice(groupNumbers: List<Int>): Boolean =
        groupNumbers.size == CONFIRM_GROUPS && groupNumbers.toSet().size == CONFIRM_GROUPS && groupNumbers.all { it in 1..GROUPS }

    /**
     * The confirmation (§10): [typed]`[i]` must be group [groupNumbers]`[i]` of [recoverySecret], in
     * the order asked, compared exactly and case-sensitively once space, CR and LF in the typed group
     * are ignored (around it or inside it, as in a typed secret; a tab is not ignored). False for any
     * other shape: a challenge that is not an [isGroupChoice], or another count of typed groups.
     */
    fun confirmMatches(recoverySecret: ByteArray, groupNumbers: List<Int>, typed: List<String>): Boolean {
        if (!isGroupChoice(groupNumbers) || typed.size != CONFIRM_GROUPS) return false
        val all = groups(recoverySecret)
        var ok = true
        for (i in groupNumbers.indices) {
            val entry = stripTypedSpace(typed[i])
            if (!Bytes.ctEquals(entry.encodeToByteArray(), all[groupNumbers[i] - 1].encodeToByteArray())) ok = false
        }
        return ok
    }

    /**
     * The kit QR (§10): `andvari-kit:2:<O>:<C>:<E>:<S>`, where `O` is the unpadded base64url of the
     * origin, `C` the instance's `card0Hash` (64 lowercase hex), `E` the unpadded base64url of
     * `emailNorm`, and `S` the unpadded base64url of the 32-byte secret. Null when a part is outside
     * its grammar: compose never makes a payload [parseQr] would refuse, and the payload it makes
     * parses back to exactly the parts it was given (so a `card0Hash` with white space in it, which
     * the parser would strip, is refused here).
     */
    fun composeQr(origin: String, card0Hash: String, emailNorm: String, recoverySecret: ByteArray): String? {
        if (recoverySecret.size != MemberRecovery.SECRET_BYTES) return null
        val payload = QR_PREFIX + Bytes.toB64(origin.encodeToByteArray()) + ":" + card0Hash + ":" +
            Bytes.toB64(emailNorm.encodeToByteArray()) + ":" + Bytes.toB64(recoverySecret)
        val parsed = parseQr(payload) ?: return null
        parsed.wipe()
        return if (parsed.origin == origin && parsed.card0Hash == card0Hash && parsed.emailNorm == emailNorm) payload else null
    }

    /**
     * Total, canonical parse of a kit QR (§10: "exactly as for links"): null on any malformed input
     * (§2.4: `bad_kit`). ASCII white space (space, tab, CR, LF) is stripped first, and what is left is
     * at most 1,024 characters; the prefix is exact; there are exactly four `:`-separated parts; `O`
     * decodes to an `origin` (§2.2) and `E` to an `emailNorm`, both re-encoding identically (so padded
     * or non-canonical forms are refused); `C` is 64 lowercase hex; `S` decodes to exactly 32 bytes.
     *
     * A kit is accepted ONLY on Sign in → Forgot your master password? → Scan your recovery kit
     * (FS-B1). That entry rule is the engine's `PasswordGate`; this function only parses.
     */
    fun parseQr(payload: String): Kit? {
        val text = TrustGrammar.stripAsciiSpace(payload)
        if (text.length > MAX_QR_LENGTH || !text.startsWith(QR_PREFIX)) return null
        val parts = text.substring(QR_PREFIX.length).split(':')
        if (parts.size != 4) return null
        val origin = Bytes.fromB64Canonical(parts[0])?.let(::asciiText) ?: return null
        if (!TrustGrammar.isOrigin(origin)) return null
        if (!TrustGrammar.isHex64(parts[1])) return null
        val email = Bytes.fromB64Canonical(parts[2])?.let(::asciiText) ?: return null
        if (TrustGrammar.emailNorm(email) != email) return null
        val secret = Bytes.fromB64Exact(parts[3], MemberRecovery.SECRET_BYTES) ?: return null
        return Kit(origin, parts[1], email, secret).also { secret.fill(0) }
    }

    /** [bytes] as text when every byte is printable ASCII, else null (an origin and an `emailNorm` are both ASCII). */
    private fun asciiText(bytes: ByteArray): String? =
        if (bytes.all { it in 0x20..0x7E }) bytes.decodeToString() else null
}
