package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive

/**
 * The parsed one-scan enroll link payload (design 2026-07-10 one-scan onboarding).
 * Carries NO key material and NO fingerprint — exactly {v, o, t, e}. [e] is verbatim
 * (no case/unicode normalization here; the server does the case-insensitive bind).
 */
data class EnrollPayload(val v: Int, val o: String, val t: String, val e: String)

/**
 * Enroll-link compose/parse — one of two byte-identical twins (the other is
 * web/src/enroll/enrolllink.ts), pinned to spec/test-vectors/enrolllink.json. Any
 * behavioral divergence between the twins is a vector failure, so every rule below is
 * mirrored verbatim and pinned by a row:
 *
 *  - Link shape: `<origin>/enroll#a1.<b64url-nopad(compact {"v":1,"o","t","e"})>`.
 *  - [parse] is TOTAL: null on ANY malformed input, never throws — it runs in UI layers
 *    on three platforms and a throwing parser is a crash primitive (the BUG-0 lesson).
 *  - [compose] rejects (null) ill-formed UTF-16 input: on a lone surrogate the twins'
 *    JSON encoders genuinely diverge (plain Kotlin encoding U+FFFD-replaces; ES2019+
 *    JSON.stringify escapes as \udXXX) — identical input, different links — so reject
 *    is the only pinnable agreement (composeRejects vectors). Well-formed astral pairs
 *    (emoji) pass through as raw 4-byte UTF-8 on both twins (roundTrips vectors).
 *  - Normalize before decode: strip ASCII whitespace (chat apps hard-wrap b64), then
 *    trailing '=' padding (core's decoder tolerates padding, web's does not — the strip
 *    makes them agree), then require the b64url alphabet and that the decoded bytes
 *    RE-ENCODE to the same body (canonical-form pin — masks decoder-leniency differences
 *    such as nonzero trailing bits).
 *  - JSON: unknown keys are ACCEPTED (forward compat; ignoreUnknownKeys=true matches
 *    JSON.parse). DUPLICATE top-level keys are REJECTED on both twins via a shared
 *    lexical scan (JS is silently last-wins, kotlinx is version-dependent — reject is the
 *    only pinnable agreement); a backslash escape inside a key also rejects, so a
 *    unicode-escaped key cannot alias a plain `t`. Raw control chars in the decoded text reject
 *    (JSON.parse and kotlinx disagree about them in places; compose never emits any).
 *  - v compares NUMERICALLY (`1.0` parses to 1 — post-JSON.parse JS cannot tell them
 *    apart, so the Kotlin twin matches); the STRING "1" rejects.
 *  - `o` must be a canonical lowercase http(s) origin — scheme EXACTLY http or https
 *    (kills javascript:/data:/file:), host[:port] only, no path/slash/userinfo. This is
 *    well-formedness + scheme safety ONLY; private-vs-public judgment is the consumer's.
 *  - Total input length is capped at [MAX_LEN] (QR payloads are ~3 KB at most; the cap
 *    bounds the regex/scan work on hostile input). `t` and `e` must be non-empty.
 */
object EnrollLink {
    private const val PREFIX = "a1."
    private const val MAX_LEN = 8192
    private const val WHITESPACE = " \t\n\r\u000B\u000C"
    private val B64URL = Regex("^[A-Za-z0-9_-]*$")
    private val ORIGIN = Regex(
        "^https?://(\\[[0-9a-f:.]+\\]|[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*)(:[0-9]{1,5})?$",
    )
    private val json = Json { ignoreUnknownKeys = true }

    /** Wire shape for compose — v as Int (no default, so encodeDefaults can never omit it). */
    @Serializable
    private data class WireOut(val v: Int, val o: String, val t: String, val e: String)

    /**
     * Wire shape for parse — v as JsonPrimitive so quoted-vs-bare and 1-vs-1.0 are checked
     * explicitly instead of trusting kotlinx numeric coercion to match JS.
     */
    @Serializable
    private data class WireIn(val v: JsonPrimitive, val o: String, val t: String, val e: String)

    /**
     * Build `<origin>/enroll#a1.<b64url(payload)>`, or null when any input carries
     * ill-formed UTF-16 (a lone/unpaired surrogate) — see the header: a lone surrogate
     * would mint DIFFERENT links on the two twins, so rejection is the pinned agreement,
     * and null mirrors [parse]'s failure convention. No other validation: [origin] is the
     * minting client's `location.origin` equivalent (a non-canonical origin simply
     * produces a link [parse] refuses).
     */
    fun compose(origin: String, token: String, email: String): String? {
        val payload = json.encodeToString(WireOut.serializer(), WireOut(1, origin, token, email))
        // kotlinx writes surrogates through raw, so a lone one in ANY input survives into
        // [payload] and trips the strict encoder here (the sibling decode in parseInner
        // uses the same flag).
        val bytes = try {
            payload.encodeToByteArray(throwOnInvalidSequence = true)
        } catch (_: Exception) {
            return null
        }
        return "$origin/enroll#a1." + Bytes.toB64(bytes)
    }

    /** Parse any string containing an enroll fragment. Null on any malformed input; never throws. */
    fun parse(input: String): EnrollPayload? = try {
        parseInner(input)
    } catch (_: Exception) {
        null // TOTAL by contract — any unanticipated throw is a malformed input, not a crash
    }

    private fun parseInner(input: String): EnrollPayload? {
        if (input.length > MAX_LEN) return null
        val hash = input.indexOf('#')
        if (hash < 0) return null
        val fragment = input.substring(hash + 1)
        if (!fragment.startsWith(PREFIX)) return null
        val body = fragment.substring(PREFIX.length)
            .filterNot { it in WHITESPACE }
            .trimEnd('=')
        if (!B64URL.matches(body)) return null
        val bytes = try {
            Bytes.fromB64(body)
        } catch (_: Exception) {
            return null
        }
        if (Bytes.toB64(bytes) != body) return null // canonical-form pin
        val text = try {
            bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (_: Exception) {
            return null
        }
        if (text.startsWith('\uFEFF')) return null // BOM: JSON.parse rejects; pin the twin
        for (c in text) if (c.code < 0x20) return null
        if (hasHostileTopLevelKeys(text)) return null
        val w = try {
            json.decodeFromString(WireIn.serializer(), text)
        } catch (_: Exception) {
            return null
        }
        if (w.v.isString || w.v.content.toDoubleOrNull() != 1.0) return null
        if (!ORIGIN.matches(w.o)) return null
        if (w.t.isEmpty() || w.e.isEmpty()) return null
        return EnrollPayload(1, w.o, w.t, w.e)
    }

    /**
     * True when the top-level JSON object literal repeats a key, or uses a backslash
     * escape inside a key. Purely lexical and deliberately lenient about malformedness —
     * anything else is left for the real JSON parser to reject. Mirrored line-for-line in
     * the web twin.
     */
    private fun hasHostileTopLevelKeys(text: String): Boolean {
        var i = 0
        val n = text.length
        while (i < n && text[i] == ' ') i++ // controls were pre-rejected; only spaces remain
        if (i >= n || text[i] != '{') return false // not an object — the JSON parse rejects it
        i++
        var depth = 1
        var inString = false
        var escaped = false
        var readingKey = false
        var expectKey = true
        val keys = HashSet<String>()
        val cur = StringBuilder()
        while (i < n) {
            val c = text[i]
            if (inString) {
                when {
                    escaped -> escaped = false
                    c == '\\' -> {
                        if (readingKey) return true // escaped keys could alias across the twins' parsers
                        escaped = true
                    }
                    c == '"' -> {
                        inString = false
                        if (readingKey) {
                            if (!keys.add(cur.toString())) return true
                            readingKey = false
                        }
                    }
                    else -> if (readingKey) cur.append(c)
                }
            } else {
                when (c) {
                    '"' -> {
                        inString = true
                        if (depth == 1 && expectKey) {
                            readingKey = true
                            expectKey = false
                            cur.setLength(0)
                        }
                    }
                    '{', '[' -> depth++
                    '}', ']' -> {
                        depth--
                        if (depth == 0) return false // past the top object; trailing garbage is the parser's problem
                    }
                    ',' -> if (depth == 1) expectKey = true
                }
            }
            i++
        }
        return false
    }
}
