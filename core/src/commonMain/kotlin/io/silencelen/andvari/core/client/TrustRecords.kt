package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.model.WireIds
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/**
 * The device-local trust records as JSON (security review 2026-10, plugin scan F1/F2; branch A10).
 *
 * Before A10 every one of these was a newline-joined set of `|`-joined lines, and a server-chosen id that carried
 * either delimiter wrote extra lines into the record — a forged vouch, held-key tag or tombstone for a vault the
 * human never reviewed. Each record is now a JSON array of objects (or of strings, for the plain id sets) with a
 * STRICT decode: exactly the expected keys, the expected types, and every id in the UUID grammar ([WireIds]) or
 * the token grammar (the SAFE_ID shape, for base64url grant ids and nonces); anything else is refused. The encoders
 * THROW on the same rows (A10 review LOW-1: a silently dropped row is a record that lies — product code that reaches
 * an encoder with a malformed row has a bug upstream, and the throw names it), so a malformed id can neither be
 * written nor read back.
 *
 * Migration: a value that is not a JSON array is a pre-A10 line record. It is parsed ONCE with the old grammar,
 * line by line, keeping only the lines that have exactly the old field count and well-formed ids, and the caller
 * re-persists the result as JSON ([Decoded.rewrite]). A JSON record that had to drop a row is rewritten too.
 *
 * Web twin: `web/src/vault/trustrecords.ts` (byte-compatible encodings, same rules).
 */
object TrustRecords {
    private val HEX64 = Regex("^[0-9a-f]{64}$")
    /** base64url grant ids and removal nonces (ItemDocShape.SAFE_ID's grammar, kept local so this file has no engine deps). */
    private val TOKEN = Regex("^[A-Za-z0-9_-]{1,128}$")
    private val json = Json

    /** §8.2 vouch: this device vouches for the key whose SHA-256 is [tag] on [vaultId]; [kind] = `frozen` | `confirmed`. */
    data class Vouch(val vaultId: String, val tag: String, val kind: String)
    /** A7 held-key memory: the first key this device adopted for [vaultId]. */
    data class HeldKey(val vaultId: String, val tag: String)
    /** A9 M-3: THIS device removed [userId] from [vaultId] at [at] (device clock, ms). */
    data class Tombstone(val vaultId: String, val userId: String, val at: Long)
    /** A5/A6: a human confirmed the identity key whose SHA-256 is [keyTag] for [userId] on this device. */
    data class ConfirmedPin(val userId: String, val keyTag: String)
    /** A7: a removal nonce this device consumed for [vaultId]. */
    data class ConsumedNonce(val vaultId: String, val nonce: String, val issuedAt: Long)

    /** The decoded rows; [rewrite] = the stored form must be replaced by [rows] re-encoded (legacy, or junk dropped). */
    data class Decoded<T>(val rows: List<T>, val rewrite: Boolean)

    // ---- vouches ----

    fun decodeVouches(raw: String?): Decoded<Vouch> = decode(
        raw,
        keys = setOf("vaultId", "tag", "kind"),
        fromJson = { o -> vouch(str(o, "vaultId"), str(o, "tag"), str(o, "kind")) },
        fromLine = { p -> if (p.size == 3) vouch(p[0], p[1], p[2]) else null },
    )

    fun encodeVouches(rows: Collection<Vouch>): String? = encode(rows.map { vouch(it.vaultId, it.tag, it.kind) ?: malformed("vouch", it) }) { v ->
        buildJsonObject { put("vaultId", v.vaultId); put("tag", v.tag); put("kind", v.kind) }
    }

    private fun vouch(vaultId: String?, tag: String?, kind: String?): Vouch? =
        if (WireIds.isUuid(vaultId) && tag != null && HEX64.matches(tag) && (kind == "frozen" || kind == "confirmed")) Vouch(vaultId!!, tag, kind) else null

    // ---- held keys ----

    fun decodeHeldKeys(raw: String?): Decoded<HeldKey> = decode(
        raw,
        keys = setOf("vaultId", "tag"),
        fromJson = { o -> held(str(o, "vaultId"), str(o, "tag")) },
        fromLine = { p -> if (p.size == 2) held(p[0], p[1]) else null },
    )

    fun encodeHeldKeys(rows: Collection<HeldKey>): String? = encode(rows.map { held(it.vaultId, it.tag) ?: malformed("held key", it) }) { h ->
        buildJsonObject { put("vaultId", h.vaultId); put("tag", h.tag) }
    }

    private fun held(vaultId: String?, tag: String?): HeldKey? =
        if (WireIds.isUuid(vaultId) && tag != null && HEX64.matches(tag)) HeldKey(vaultId!!, tag) else null

    // ---- plain sets ----

    /** A set of vault ids (member-granted). */
    fun decodeIdSet(raw: String?): Decoded<String> = decodeStrings(raw) { if (WireIds.isUuid(it)) it else null }

    fun encodeIdSet(rows: Collection<String>): String? = encodeStrings(rows.map { if (WireIds.isUuid(it)) it else malformed("vault id", it) })

    /** A set of opaque tokens (declined grant ids, base64url). */
    fun decodeTokenSet(raw: String?): Decoded<String> = decodeStrings(raw) { if (TOKEN.matches(it)) it else null }

    fun encodeTokenSet(rows: Collection<String>): String? = encodeStrings(rows.map { if (TOKEN.matches(it)) it else malformed("token", it) })

    // ---- issued tombstones ----

    fun decodeTombstones(raw: String?): Decoded<Tombstone> = decode(
        raw,
        keys = setOf("vaultId", "userId", "at"),
        fromJson = { o -> tomb(str(o, "vaultId"), str(o, "userId"), num(o, "at")) },
        fromLine = { p -> if (p.size == 3) tomb(p[0], p[1], p[2].toLongOrNull()) else null },
    )

    fun encodeTombstones(rows: Collection<Tombstone>): String? = encode(rows.map { tomb(it.vaultId, it.userId, it.at) ?: malformed("tombstone", it) }) { t ->
        buildJsonObject { put("vaultId", t.vaultId); put("userId", t.userId); put("at", t.at) }
    }

    private fun tomb(vaultId: String?, userId: String?, at: Long?): Tombstone? =
        if (WireIds.isUuid(vaultId) && WireIds.isUuid(userId) && at != null) Tombstone(vaultId!!, userId!!, at) else null

    // ---- confirmed pins ----

    fun decodeConfirmedPins(raw: String?): Decoded<ConfirmedPin> = decode(
        raw,
        keys = setOf("userId", "keyTag"),
        fromJson = { o -> pin(str(o, "userId"), str(o, "keyTag")) },
        fromLine = { p -> if (p.size == 2) pin(p[0], p[1]) else null },
    )

    fun encodeConfirmedPins(rows: Collection<ConfirmedPin>): String? = encode(rows.map { pin(it.userId, it.keyTag) ?: malformed("confirmed pin", it) }) { c ->
        buildJsonObject { put("userId", c.userId); put("keyTag", c.keyTag) }
    }

    private fun pin(userId: String?, keyTag: String?): ConfirmedPin? =
        if (WireIds.isUuid(userId) && keyTag != null && HEX64.matches(keyTag)) ConfirmedPin(userId!!, keyTag) else null

    // ---- consumed nonces ----

    fun decodeConsumedNonces(raw: String?): Decoded<ConsumedNonce> = decode(
        raw,
        keys = setOf("vaultId", "nonce", "issuedAt"),
        fromJson = { o -> nonce(str(o, "vaultId"), str(o, "nonce"), num(o, "issuedAt")) },
        fromLine = { p -> if (p.size == 3) nonce(p[0], p[1], p[2].toLongOrNull()) else null },
    )

    fun encodeConsumedNonces(rows: Collection<ConsumedNonce>): String? = encode(rows.map { nonce(it.vaultId, it.nonce, it.issuedAt) ?: malformed("consumed nonce", it) }) { n ->
        buildJsonObject { put("vaultId", n.vaultId); put("nonce", n.nonce); put("issuedAt", n.issuedAt) }
    }

    private fun nonce(vaultId: String?, nonce: String?, issuedAt: Long?): ConsumedNonce? =
        if (WireIds.isUuid(vaultId) && nonce != null && TOKEN.matches(nonce) && issuedAt != null) ConsumedNonce(vaultId!!, nonce, issuedAt) else null

    // ---- the shared machinery ----

    /** An encoder was handed a row the strict grammar refuses: a bug upstream, never a row to drop quietly. */
    private fun malformed(what: String, row: Any): Nothing =
        throw IllegalArgumentException("malformed $what record: ${row.toString().replace("\n", "\\n").take(200)}")

    private fun str(o: JsonObject, key: String): String? = (o[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
    private fun num(o: JsonObject, key: String): Long? = (o[key] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull

    /** The stored value as JSON (see [parseJson]). */
    private sealed interface Parsed {
        class Rows(val rows: JsonArray) : Parsed
        object WrongShape : Parsed
        object Legacy : Parsed
    }

    /**
     * The stored value as JSON: an array, [Parsed.WrongShape] for a value that PARSES as a JSON object (refused whole),
     * or [Parsed.Legacy] when it does not parse as a JSON array or object, which makes it a legacy line record (a bare
     * scalar, such as a lone all-digit token, goes to the line grammar, which decides it row by row). Security review
     * 2026-10, branch A11 (c11/c16): the A10 migration decided "JSON" from the first character, so a legacy record whose
     * first line began with `[` or `{` (a server-planted id that sorted first) was refused whole and every well-formed
     * line was lost.
     */
    private fun parseJson(raw: String): Parsed =
        when (val e = runCatching { json.parseToJsonElement(raw) }.getOrNull()) {
            is JsonArray -> Parsed.Rows(e)
            is JsonObject -> Parsed.WrongShape
            else -> Parsed.Legacy
        }

    /**
     * Strict JSON first (exactly [keys] per object, every row through [fromJson]); otherwise the legacy line record
     * through [fromLine] over each line's `|` parts (any value that does not parse as a JSON array or object, A11). A
     * JSON object is refused whole; an array a row of which was refused comes back without the refused rows. Both are
     * flagged for rewrite.
     */
    private fun <T> decode(raw: String?, keys: Set<String>, fromJson: (JsonObject) -> T?, fromLine: (List<String>) -> T?): Decoded<T> {
        if (raw.isNullOrEmpty()) return Decoded(emptyList(), false)
        val parsed = parseJson(raw)
        if (parsed is Parsed.WrongShape) return Decoded(emptyList(), true) // JSON of an unknown shape: refused
        if (parsed is Parsed.Rows) {
            val rows = ArrayList<T>()
            var dropped = false
            for (e in parsed.rows) {
                val o = e as? JsonObject
                val row = if (o != null && o.keys == keys) fromJson(o) else null
                if (row == null) dropped = true else rows += row
            }
            return Decoded(rows, dropped)
        }
        val rows = raw.split('\n').filter { it.isNotEmpty() }.mapNotNull { line -> fromLine(line.split('|')) }
        return Decoded(rows, true)
    }

    private fun <T> encode(rows: List<T>, toJson: (T) -> JsonElement): String? =
        if (rows.isEmpty()) null else json.encodeToString(JsonArray.serializer(), buildJsonArray { for (r in rows) add(toJson(r)) })

    private fun decodeStrings(raw: String?, accept: (String) -> String?): Decoded<String> {
        if (raw.isNullOrEmpty()) return Decoded(emptyList(), false)
        val parsed = parseJson(raw)
        if (parsed is Parsed.WrongShape) return Decoded(emptyList(), true)
        if (parsed is Parsed.Rows) {
            val rows = ArrayList<String>()
            var dropped = false
            for (e in parsed.rows) {
                val s = (e as? JsonPrimitive)?.takeIf { it.isString }?.content?.let(accept)
                if (s == null) dropped = true else rows += s
            }
            return Decoded(rows.distinct(), dropped)
        }
        return Decoded(raw.split('\n').filter { it.isNotEmpty() }.mapNotNull(accept).distinct(), true)
    }

    private fun encodeStrings(rows: List<String>): String? =
        if (rows.isEmpty()) null else json.encodeToString(JsonArray.serializer(), buildJsonArray { for (r in rows.distinct().sorted()) add(JsonPrimitive(r)) })

    /**
     * Read one record through [decoder], migrating the stored form when it asks for a rewrite. [get] / [set] are
     * the record's own store (cache client state, device state, …).
     */
    fun <T> load(key: String, get: (String) -> String?, set: (String, String?) -> Unit, decoder: (String?) -> Decoded<T>, encoder: (List<T>) -> String?): List<T> {
        val d = decoder(get(key))
        if (d.rewrite) set(key, encoder(d.rows))
        return d.rows
    }
}
