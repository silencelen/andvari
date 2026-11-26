package io.silencelen.andvari.hostile.proxy

import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.security.MessageDigest
import java.util.Base64

// What the hostile server needs to read and rewrite the wire: JSON surgery, and the outside of a signed frame. It
// uses none of the engine's own code for this, so a rule never leans on the thing under test.

fun JsonObject.str(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
fun JsonObject.long(key: String): Long? = (this[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()
fun JsonObject.obj(key: String): JsonObject? = this[key] as? JsonObject
fun JsonObject.arr(key: String): JsonArray? = this[key] as? JsonArray

/** This object with [key] set to [value] (null: removed). */
fun JsonObject.set(key: String, value: JsonElement?): JsonObject = JsonObject(if (value == null) this - key else this + (key to value))
fun JsonObject.set(key: String, value: String): JsonObject = set(key, JsonPrimitive(value))
fun JsonObject.set(key: String, value: Long): JsonObject = set(key, JsonPrimitive(value))

/** This object with the JSON `null` at [key] (a field the route serves as an explicit null). */
fun JsonObject.setNull(key: String): JsonObject = set(key, JsonNull)

/** This object with the object at [key] changed by [f]; unchanged when there is none. */
fun JsonObject.edit(key: String, f: (JsonObject) -> JsonObject): JsonObject = obj(key)?.let { set(key, f(it)) } ?: this

/** This object with each object of the array at [key] changed by [f]. */
fun JsonObject.editEach(key: String, f: (JsonObject) -> JsonObject): JsonObject =
    arr(key)?.let { a -> set(key, JsonArray(a.map { e -> (e as? JsonObject)?.let(f) ?: e })) } ?: this

/**
 * A signed statement frame from the outside (design §2.1): 101 bytes of magic, purpose, signer and signature, then the
 * statement's canonical JSON. A server sees log entries and cards in the clear, so the proxy reads them the same way.
 */
object Frames {
    private const val STATEMENT_AT = 101

    fun bytes(b64: String): ByteArray = Base64.getUrlDecoder().decode(b64)

    fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    /** `H(frame)`: lowercase hex SHA-256 of the whole frame. */
    fun hash(b64: String): String = MessageDigest.getInstance("SHA-256").digest(bytes(b64)).joinToString("") { "%02x".format(it) }

    fun statement(b64: String): JsonObject = Json.parseToJsonElement(bytes(b64).let { it.copyOfRange(STATEMENT_AT, it.size) }.decodeToString()).jsonObject

    fun seq(b64: String): Long = statement(b64).getValue("seq").jsonPrimitive.long

    fun kind(b64: String): String = statement(b64).getValue("kind").jsonPrimitive.content

    /** The log head an entry makes: `{seq, hash, at}`. */
    fun head(b64: String): JsonObject = statement(b64).let { s ->
        buildJsonObject { put("seq", s.getValue("seq")); put("hash", JsonPrimitive(hash(b64))); put("at", s.getValue("at")) }
    }

    /** The frame with one bit of its signature flipped: every field still parses, and nobody signed it. */
    fun withBrokenSignature(b64: String): String = b64(bytes(b64).also { it[60] = (it[60].toInt() xor 1).toByte() })
}

/** The entries of a served log page (spec 03 §10.5), as their base64url frames. */
fun logEntries(page: JsonObject): List<String> = page.arr("entries")?.map { it.jsonPrimitive.content } ?: emptyList()

/**
 * The page the real server would send this device from scratch (`GET /sync?since=0`), asked with its own credentials.
 * A `/sync` delta carries only the rows that changed since the device's cursor (spec 03 §4), so a lie told in a row
 * the delta does not carry never reaches the device; a hostile server that wants a device to see a row puts it in, and
 * this is where it finds the row.
 */
fun Ctx.fullSyncPage(): JsonObject? = ask(WireRoute.SYNC, query = "since=0").takeIf { it.ok }?.json

/** This page with every row of [full]'s [key] array that [pick] chooses and this page lacks (by [id]) added. */
fun JsonObject.withRowsFrom(full: JsonObject, key: String, id: (JsonObject) -> String?, pick: (JsonObject) -> Boolean): JsonObject {
    val have = arr(key)?.mapNotNullTo(HashSet()) { (it as? JsonObject)?.let(id) } ?: emptySet<String>()
    val add = full.arr(key)?.mapNotNull { it as? JsonObject }?.filter { pick(it) && id(it) !in have } ?: emptyList()
    return if (add.isEmpty()) this else set(key, JsonArray((arr(key) ?: emptyList()) + add))
}

/** The vault row, this account's grant row and (with [items]) the item rows of [vaultId] in [full], added where this page lacks them. */
fun JsonObject.withVaultRowsFrom(full: JsonObject, vaultId: String, items: Boolean = false): JsonObject {
    val of = { row: JsonObject -> row.str("vaultId") == vaultId }
    val page = withRowsFrom(full, "vaults", { it.str("vaultId") }, of).withRowsFrom(full, "grants", { it.str("vaultId") }, of)
    return if (items) page.withRowsFrom(full, "items", { it.str("itemId") }, of) else page
}

/**
 * The server serves [tag] the genuine rows of [vaultId] in its next [times] `/sync` answers (null: every one), whether
 * or not they changed since the device's cursor: how a server that stops lying shows a device the true head (or grant,
 * or items) again. An honest server would send nothing until the vault changes, and a device would stay on the lie.
 */
fun HostileProxy.serveVaultRows(tag: String, vaultId: String, times: Int? = 1, items: Boolean = false): Rule =
    on(WireRoute.SYNC, tag, name = "serveVaultRows $vaultId@$tag", times = times) { x ->
        val real = x.forward()
        val full = x.fullSyncPage()
        if (!real.ok || full == null) real else real.withJson { it.withVaultRowsFrom(full, vaultId, items) }
    }

/**
 * Serve the device [tag] a chosen history for [vaultId]: on every log fetch and in the vault's `/sync` row, which the
 * proxy puts into every `/sync` answer while the device holds a grant, changed since its cursor or not (a consistent
 * liar). [view] gets the vault's genuine log as the real server stores it (asked with the device's own credentials;
 * empty when the server refuses it) and answers the frames to present, genesis first. Cutting the list is withholding
 * or a rollback; swapping an entry for another genuine one at the same position is equivocation.
 */
fun HostileProxy.serveLog(tag: String, vaultId: String, view: (genuine: List<String>) -> List<String>): List<Rule> {
    fun presented(x: Ctx): List<String> {
        val real = x.ask(WireRoute.LOG_FETCH, mapOf("vaultId" to vaultId))
        return view(real.json?.takeIf { real.ok }?.let(::logEntries) ?: emptyList())
    }
    val fetch = on(WireRoute.LOG_FETCH, tag, name = "serveLog fetch $vaultId@$tag", where = { it.param("vaultId") == vaultId }) { x ->
        val frames = presented(x)
        if (frames.isEmpty()) return@on x.forward()
        val after = x.req.queryParam("after")?.toLongOrNull() ?: -1L
        Resp.json(200, buildJsonObject {
            put("entries", JsonArray(frames.filter { Frames.seq(it) > after }.map(::JsonPrimitive)))
            put("head", Frames.head(frames.last()))
        })
    }
    val sync = on(WireRoute.SYNC, tag, name = "serveLog sync $vaultId@$tag") { x ->
        val real = x.forward()
        if (!real.ok || real.json == null) return@on real
        // The device holds no grant for the vault: the server would list no row for it, and does not.
        val full = x.fullSyncPage() ?: return@on real
        if (full.arr("vaults")?.none { it.jsonObject.str("vaultId") == vaultId } != false) return@on real
        val frames = presented(x)
        if (frames.isEmpty()) return@on real
        val head = Frames.head(frames.last())
        real.withJson { body ->
            body.withRowsFrom(full, "vaults", { it.str("vaultId") }, { it.str("vaultId") == vaultId })
                .editEach("vaults") { v -> if (v.str("vaultId") == vaultId) v.set("logHead", buildJsonObject { put("seq", head.getValue("seq")); put("hash", head.getValue("hash")) }) else v }
        }
    }
    return listOf(fetch, sync)
}

/**
 * Serve the device [tag] (null: every device) a chosen card chain at `GET /instance`: [view] gets the genuine chain,
 * card 0 first, and answers the frames to present. The rotations ride along untouched.
 */
fun HostileProxy.serveCards(tag: String?, view: (genuine: List<String>) -> List<String>): Rule =
    on(WireRoute.INSTANCE, tag, name = "serveCards" + (tag?.let { "@$it" } ?: ""), handler = editAnswer { body ->
        body.set("cards", JsonArray(view(body.arr("cards")?.map { it.jsonPrimitive.content } ?: emptyList()).map(::JsonPrimitive)))
    })

/** Serve [tag] the vault's genuine log cut off after [maxSeq]. */
fun HostileProxy.cutLogAt(tag: String, vaultId: String, maxSeq: Long): List<Rule> =
    serveLog(tag, vaultId) { genuine -> genuine.filter { Frames.seq(it) <= maxSeq } }

fun List<Rule>.remove() = forEach { it.remove() }
