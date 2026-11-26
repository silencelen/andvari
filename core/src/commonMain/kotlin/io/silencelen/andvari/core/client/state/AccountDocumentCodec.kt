package io.silencelen.andvari.core.client.state

import io.silencelen.andvari.core.model.wire.WireGrammar
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * The account-state document's JSON (spec 02 §9):
 *
 * ```
 * {"v":2,"userId":…,"seq":…,
 *  "contacts":{<userId>:{"userId","identityPub","label","method":"link","verifiedAt","compared","madeOn"}},
 *  "contactTombstones":{<userId>:<removedAt>},
 *  "vaults":{<vaultId>:{"genesisHash","seq","hash"}},
 *  "accepted":{<vaultId>:{"owner","addSeq","at","decision"}},
 *  "recovery":{"posture","fp","at"},   (absent until chosen)
 *  …every other key, preserved as it came}
 * ```
 *
 * Decoding is strict per record and lenient per document: a record that fails its grammar (a `method`
 * other than `link`, a key that is not 32 bytes, a `decision` other than accept or decline, …) is
 * dropped and counted, never trusted; a document of another version or another account is refused as a
 * whole. Unknown top-level keys are kept verbatim so a newer build's records survive (design §5.4).
 */
object AccountDocumentCodec {
    const val VERSION = 2L
    private val KNOWN = setOf("v", "userId", "seq", "contacts", "contactTombstones", "vaults", "accepted", "recovery")
    private val CONTACT_FIELDS = setOf("userId", "identityPub", "label", "method", "verifiedAt", "compared", "madeOn")
    private val VAULT_FIELDS = setOf("genesisHash", "seq", "hash")
    private val ACCEPTED_FIELDS = setOf("owner", "addSeq", "at", "decision")
    private val RECOVERY_FIELDS = setOf("posture", "fp", "at")

    /** A decoded document and how many records were dropped as malformed. */
    data class Decoded(val document: AccountDocument, val droppedRecords: Int)

    fun encode(userId: String, doc: AccountDocument): String = buildJsonObject {
        put("v", JsonPrimitive(VERSION))
        put("userId", JsonPrimitive(userId))
        put("seq", JsonPrimitive(doc.seq))
        put("contacts", JsonObject(inByteOrder(doc.contacts).mapValues { (_, c) ->
            buildJsonObject {
                put("userId", JsonPrimitive(c.userId)); put("identityPub", JsonPrimitive(c.identityPub)); put("label", JsonPrimitive(c.label))
                put("method", JsonPrimitive(c.method)); put("verifiedAt", JsonPrimitive(c.verifiedAt)); put("compared", JsonPrimitive(c.compared))
                put("madeOn", JsonPrimitive(c.madeOn))
                putExtra(c.extra, CONTACT_FIELDS)
            }
        }))
        put("contactTombstones", JsonObject(inByteOrder(doc.contactTombstones).mapValues { (_, t) -> JsonPrimitive(t.removedAt) }))
        put("vaults", JsonObject(inByteOrder(doc.vaults).mapValues { (_, v) ->
            buildJsonObject { put("genesisHash", JsonPrimitive(v.genesisHash)); put("seq", JsonPrimitive(v.seq)); put("hash", JsonPrimitive(v.hash)); putExtra(v.extra, VAULT_FIELDS) }
        }))
        put("accepted", JsonObject(inByteOrder(doc.accepted).mapValues { (_, a) ->
            buildJsonObject { put("owner", JsonPrimitive(a.owner)); put("addSeq", JsonPrimitive(a.addSeq)); put("at", JsonPrimitive(a.at)); put("decision", JsonPrimitive(a.decision)); putExtra(a.extra, ACCEPTED_FIELDS) }
        }))
        doc.recovery?.let { r -> put("recovery", buildJsonObject { put("posture", JsonPrimitive(r.posture)); put("fp", JsonPrimitive(r.fp)); put("at", JsonPrimitive(r.at)); putExtra(r.extra, RECOVERY_FIELDS) }) }
        putExtra(doc.unknown, KNOWN)
    }.toString()

    /** Writes fields this build does not know back as they came, in byte order; never over a known one. */
    private fun kotlinx.serialization.json.JsonObjectBuilder.putExtra(extra: Map<String, String>, known: Set<String>) {
        for ((k, raw) in inByteOrder(extra)) {
            if (k in known) continue
            put(k, runCatching { io.silencelen.andvari.core.model.wire.WireJson.json.parseToJsonElement(raw) }.getOrDefault(JsonNull))
        }
    }

    private fun extraOf(o: JsonObject, known: Set<String>): Map<String, String> =
        o.filterKeys { it !in known }.mapValues { (_, v: JsonElement) -> v.toString() }

    /**
     * [map]'s entries in a map whose iteration order is its keys' ascending UTF-8 byte order (design §5.4,
     * "writers emit each map's keys in ascending byte order"). Sorted explicitly: `String.compareTo` is
     * UTF-16 code-unit order, which differs from byte order above U+FFFF, and `toSortedMap` is JVM-only.
     */
    internal fun <V> inByteOrder(map: Map<String, V>): Map<String, V> {
        val keyed = map.keys.map { it to it.encodeToByteArray() }.sortedWith { a, b -> compareBytes(a.second, b.second) }
        val out = LinkedHashMap<String, V>(map.size)
        for ((k, _) in keyed) out[k] = map.getValue(k)
        return out
    }

    /** Unsigned lexicographic comparison of two byte strings. */
    internal fun compareBytes(a: ByteArray, b: ByteArray): Int {
        val n = minOf(a.size, b.size)
        for (i in 0 until n) {
            val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff)
            if (d != 0) return d
        }
        return a.size - b.size
    }

    /** Decode [text] for [userId]; null when it is not a v2 document of this account. */
    fun decode(userId: String, text: String): Decoded? {
        val o = runCatching { io.silencelen.andvari.core.model.wire.WireJson.strict.parseToJsonElement(text) }.getOrNull() as? JsonObject ?: return null
        if (WireGrammar.intOf(o["v"]) != VERSION) return null
        if (WireGrammar.stringOf(o["userId"]) != userId) return null
        val seq = WireGrammar.intOf(o["seq"]) ?: return null
        var dropped = 0
        fun <T> records(key: String, f: (String, JsonObject) -> T?): Map<String, T> {
            val m = o[key] as? JsonObject ?: return emptyMap()
            val out = HashMap<String, T>()
            for ((id, e) in m) {
                val r = (e as? JsonObject)?.let { f(id, it) }
                if (r == null) dropped++ else out[id] = r
            }
            return out
        }
        val contacts = records("contacts") { id, c ->
            val uid = WireGrammar.stringOf(c["userId"])?.takeIf { it == id && WireGrammar.isUuid(it) } ?: return@records null
            val key = WireGrammar.stringOf(c["identityPub"])?.takeIf(WireGrammar::isB64_32) ?: return@records null
            val label = WireGrammar.stringOf(c["label"])?.takeIf(WireGrammar::isName) ?: return@records null
            if (WireGrammar.stringOf(c["method"]) != ContactRecord.METHOD_LINK) return@records null
            val verifiedAt = WireGrammar.intOf(c["verifiedAt"]) ?: return@records null
            val compared = (c["compared"] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toBooleanStrictOrNull() ?: return@records null
            val madeOn = WireGrammar.stringOf(c["madeOn"])?.takeIf(WireGrammar::isUuid) ?: return@records null
            ContactRecord(uid, key, label, ContactRecord.METHOD_LINK, verifiedAt, compared, madeOn, extraOf(c, CONTACT_FIELDS))
        }
        val tombs = HashMap<String, ContactTombstone>()
        (o["contactTombstones"] as? JsonObject)?.forEach { (id, e) ->
            val at = WireGrammar.intOf(e)
            if (at == null || !WireGrammar.isUuid(id)) dropped++ else tombs[id] = ContactTombstone(id, at)
        }
        val vaults = records("vaults") { id, v ->
            if (!WireGrammar.isUuid(id)) return@records null
            val g = WireGrammar.stringOf(v["genesisHash"])?.takeIf(WireGrammar::isHex64) ?: return@records null
            val s = WireGrammar.intOf(v["seq"]) ?: return@records null
            val h = WireGrammar.stringOf(v["hash"])?.takeIf(WireGrammar::isHex64) ?: return@records null
            VaultRecord(id, g, s, h, extraOf(v, VAULT_FIELDS))
        }
        val accepted = records("accepted") { id, a ->
            if (!WireGrammar.isUuid(id)) return@records null
            val owner = WireGrammar.stringOf(a["owner"])?.takeIf(WireGrammar::isUuid) ?: return@records null
            val addSeq = WireGrammar.intOf(a["addSeq"]) ?: return@records null
            val at = WireGrammar.intOf(a["at"]) ?: return@records null
            val d = WireGrammar.stringOf(a["decision"])?.takeIf { it == AcceptedRecord.ACCEPT || it == AcceptedRecord.DECLINE } ?: return@records null
            AcceptedRecord(id, owner, addSeq, at, d, extraOf(a, ACCEPTED_FIELDS))
        }
        val recovery = (o["recovery"] as? JsonObject)?.let { r ->
            val p = WireGrammar.stringOf(r["posture"])?.takeIf { it == "private" || it == "operator" }
            val fp = WireGrammar.stringOf(r["fp"])?.takeIf(WireGrammar::isHex64n)
            val at = WireGrammar.intOf(r["at"])
            if (p == null || fp == null || at == null) { dropped++; null } else RecoveryRecord(p, fp, at, extraOf(r, RECOVERY_FIELDS))
        }
        val unknown = extraOf(o, KNOWN)
        return Decoded(AccountDocument(seq, contacts, tombs, vaults, accepted, recovery, unknown), dropped)
    }
}
