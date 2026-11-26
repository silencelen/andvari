package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes

/**
 * Why the shared reader refused what the operator gave as an answer (spec 04 §7 step 3, "Reading an answer"). Nothing
 * is sent and no password is asked for any of them.
 */
enum class AnswerRefusal(val code: String) {
    /** Nothing but white space. */
    EMPTY("answer_empty"),

    /** The recovery copy (the escrow download), which `recovery-cli assist` reads, not the answer it writes. */
    IS_THE_COPY("answer_is_the_copy"),

    /** Neither a token nor anything the reader can name. */
    NOT_AN_ANSWER("not_an_answer"),

    /** A sealed answer without its request (the old tool's output, or a token's tail): the whole last line is needed. */
    BARE("answer_bare"),

    /** The token names another request ([AnswerRead.Refused.namedRequest] is the id it carries). */
    OTHER_REQUEST("answer_other_request"),

    /** The token names this request's id with another request key: it was made for another request's key. */
    OTHER_REQUEST_KEY("answer_other_request_key"),

    /** The sealed part is shorter than an answer for this request's address. */
    CUT_SHORT("answer_cut_short"),

    /** The sealed part is longer than an answer for this request's address. */
    TOO_LONG("answer_too_long"),
}

/** What [AnswerToken.read] made of the operator's text. */
sealed class AnswerRead {
    /** The four parts a client uploads, exactly (spec 03 §18.6). Only the reader makes one. */
    class Ok internal constructor(val requestId: String, val requestKey: String, val commitHash: String, val sealed: String) : AnswerRead() {
        /** The token itself, as the tool printed it. */
        val token: String get() = AnswerToken.format(requestId, requestKey, commitHash, sealed)
    }

    /** Not an answer for this request: [refusal] says why; [namedRequest] is the other request's id for [AnswerRefusal.OTHER_REQUEST]. */
    class Refused internal constructor(val refusal: AnswerRefusal, val namedRequest: String? = null) : AnswerRead()
}

/**
 * The answer token and its one shared reader (spec 04 §7 step 3): the console and
 * `andvari-cli operator fulfil` both read what the operator gives through [read], before the master password is asked.
 *
 * The token is the last line `recovery-cli assist` prints: `andvari-answer:3:<requestId>:<requestKey>:<commitHash>:<sealed>`.
 * It binds an answer to its request outside the seal, as a convenience and not as a boundary: the check inside the seal
 * on the person's device stays the authority, and the commit value inside the answer is what lets the commit through.
 */
object AnswerToken {
    const val PREFIX = "andvari-answer:"
    const val VERSION = "3"

    /** The bytes of a sealed version-3 answer besides the address: seal 48, frame header 101, statement 376 (spec 04 §7 step 3). */
    const val SEALED_BYTES_WITHOUT_ADDRESS = 525

    /**
     * The one size of a sealed version-3 answer for an account whose `emailNorm` is [emailNorm]: `525 + E`, with `E` the
     * length of the unpadded base64url of its octets (`ceil(4n / 3)`), and a 13-digit `issuedAt`.
     */
    fun sealedBytes(emailNorm: String): Int {
        val n = emailNorm.encodeToByteArray().size
        return SEALED_BYTES_WITHOUT_ADDRESS + (4 * n + 2) / 3
    }

    /** The token for the four parts, as the tool prints it. [sealed] is the sealed answer's bytes. */
    fun format(requestId: String, requestKey: String, commitHash: String, sealed: ByteArray): String =
        format(requestId, requestKey, commitHash, Bytes.toB64(sealed))

    internal fun format(requestId: String, requestKey: String, commitHash: String, sealedB64: String): String =
        "$PREFIX$VERSION:$requestId:$requestKey:$commitHash:$sealedB64"

    /** Text of base64url characters alone is `answer_bare` only from this many characters (spec 04 §7 step 3, reader step 3). */
    const val BARE_MIN_CHARS = 100

    /**
     * [read] for a file's bytes (spec 04 §7 step 3): they are read as UTF-8, and bytes that are not UTF-8 are
     * `not_an_answer`.
     */
    fun readFile(bytes: ByteArray, requestId: String, requestKey: String, emailNorm: String): AnswerRead {
        val text = try {
            bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (e: CharacterCodingException) {
            return AnswerRead.Refused(AnswerRefusal.NOT_AN_ANSWER)
        }
        return read(text, requestId, requestKey, emailNorm)
    }

    private fun isB64urlChars(s: String): Boolean = s.isNotEmpty() && s.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_' }

    /**
     * Read [text] (a paste, or a file's text) as the answer for the request [requestId] whose request key is
     * [requestKey] (its `rPub` as listed) and whose address is [emailNorm], in the specification's order; the first
     * failure decides. See spec 04 §7 step 3, "Reading an answer".
     */
    fun read(text: String, requestId: String, requestKey: String, emailNorm: String): AnswerRead {
        // 1. Lines, without a leading byte-order mark, trimmed of space and tab, empty ones dropped.
        val lines = text.removePrefix("\uFEFF").split("\r\n", "\n", "\r").map { it.trim(' ', '\t') }.filter { it.isNotEmpty() }
        if (lines.isEmpty()) return AnswerRead.Refused(AnswerRefusal.EMPTY)
        // 2. A JSON document: the recovery copy, or something else.
        if (lines.first().startsWith("{")) {
            return AnswerRead.Refused(
                if (text.contains("\"encryptedIdentitySeed\"") || text.contains("\"identityPub\"")) AnswerRefusal.IS_THE_COPY else AnswerRefusal.NOT_AN_ANSWER,
            )
        }
        // 3. The token's line, and the lines a terminal may have wrapped it onto.
        val starts = lines.withIndex().filter { it.value.startsWith(PREFIX) }
        val token = when {
            starts.size > 1 -> return AnswerRead.Refused(AnswerRefusal.NOT_AN_ANSWER)
            starts.size == 1 -> {
                // A terminal may wrap the token inside its head as well as its sealed part: base64url and ':' only.
                val after = lines.subList(starts.single().index + 1, lines.size)
                if (!after.all { line -> line.all { it == ':' || isB64urlChars(it.toString()) } }) return AnswerRead.Refused(AnswerRefusal.NOT_AN_ANSWER)
                starts.single().value + after.joinToString("")
            }
            // A bare sealed answer is longer than an id, a key or a hash and shorter than any answer.
            lines.all(::isB64urlChars) && lines.sumOf { it.length } >= BARE_MIN_CHARS -> return AnswerRead.Refused(AnswerRefusal.BARE)
            else -> return AnswerRead.Refused(AnswerRefusal.NOT_AN_ANSWER)
        }
        // 4. Six parts, each in its grammar.
        val parts = token.split(':')
        if (parts.size != 6 || parts[0] != PREFIX.dropLast(1) || parts[1] != VERSION || !TrustGrammar.isB64_16(parts[2]) ||
            !TrustGrammar.isB64_32(parts[3]) || !TrustGrammar.isHex64(parts[4]) || !isB64urlChars(parts[5])
        ) {
            return AnswerRead.Refused(AnswerRefusal.NOT_AN_ANSWER)
        }
        // 5. This request, and this request's key.
        if (parts[2] != requestId) return AnswerRead.Refused(AnswerRefusal.OTHER_REQUEST, parts[2])
        if (parts[3] != requestKey) return AnswerRead.Refused(AnswerRefusal.OTHER_REQUEST_KEY)
        // 6. Exactly the one size for this request's address.
        val expected = sealedBytes(emailNorm)
        val bytes = Bytes.fromB64Canonical(parts[5])
        val length = bytes?.size ?: (3 * parts[5].length / 4)
        bytes?.fill(0)
        return when {
            bytes != null && length == expected -> AnswerRead.Ok(parts[2], parts[3], parts[4], parts[5])
            length < expected -> AnswerRead.Refused(AnswerRefusal.CUT_SHORT)
            length > expected -> AnswerRead.Refused(AnswerRefusal.TOO_LONG)
            else -> AnswerRead.Refused(AnswerRefusal.NOT_AN_ANSWER)
        }
    }
}
