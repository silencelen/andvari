package io.silencelen.andvari.core.client

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * A decrypted item document failed [ItemDocShape] (spec 02 §3.2). Thrown by [Account.decryptItem];
 * every SyncEngine path already treats a decrypt failure as "undecryptable, envelope retained", so
 * the item is QUARANTINED — kept by identity for backup enumeration, never shown, never matched.
 * Deliberately not a CryptoException: the envelope opened fine, its author is what is wrong.
 */
class MalformedItemException(message: String) : Exception(message)

/** A vault meta document that opened under the VK but is not a JSON object (security review 2026-10, branch A11, q55;
 *  web MalformedVaultMetaError twin): its author, a holder of the vault key, is what is wrong. */
class MalformedVaultMetaException(vaultId: String) : Exception("the meta document of vault $vaultId is not a JSON object")

/**
 * The shape check every client applies to a decrypted document BEFORE using it (spec 02 §3.2,
 * security review 2026-10). A document that opens under a vault key was still WRITTEN by whoever
 * holds that key — any writer of a shared vault — so it is untrusted input. Twins:
 * web `web/src/vault/itemdoc-shape.ts`, extension `extension/src/itemdocshape.ts`; all three are
 * graded by `spec/test-vectors/itemdoc-validate.json` so they quarantine exactly the same items.
 *
 * Why core checks the raw JSON rather than trusting its typed decode: kotlinx's tree decoder
 * accepts a quoted `"1"` for a Long and `"true"` for a Boolean, which web and the extension would
 * refuse — the fleet would disagree on the same item — and a type cannot say "a path-safe id" or
 * "a non-negative size".
 *
 * Unknown keys are never inspected (spec 02 §3 forward compatibility).
 */
object ItemDocShape {
    /** A path segment every client may put into an authenticated URL ([AndvariApi.pathSeg]). */
    val SAFE_ID = Regex("^[A-Za-z0-9_-]{1,128}$")

    /** 2^53 − 1: the largest integer every engine represents exactly (JS Number.MAX_SAFE_INTEGER). */
    private const val MAX_SAFE_INTEGER = 9007199254740991L
    private val INTEGER_TOKEN = Regex("^-?(0|[1-9][0-9]*)$")

    /** Null when [doc] is a well-formed item document; otherwise the first problem found. */
    fun problem(doc: JsonElement): String? {
        val o = doc as? JsonObject ?: return "doc is not an object"
        if (!isString(o["type"])) return "type"
        if (!isString(o["name"])) return "name"
        optString(o, "notes")?.let { return it }
        o["favorite"]?.let { if (!isBoolean(it)) return "favorite" }
        optString(o, "dupeAck")?.let { return it }
        o["login"]?.let { if (it !is JsonNull) loginProblem(it)?.let { p -> return "login.$p" } }
        o["card"]?.let { if (it !is JsonNull) cardProblem(it)?.let { p -> return "card.$p" } }
        o["check"]?.let { if (it !is JsonNull) checkProblem(it)?.let { p -> return "check.$p" } }
        o["attachments"]?.let { a ->
            val arr = a as? JsonArray ?: return "attachments"
            arr.forEachIndexed { i, ref -> attachmentProblem(ref)?.let { return "attachments[$i].$it" } }
        }
        return null
    }

    /** A vault metaBlob's display name (spec 02 §4): only a JSON string counts; anything else is
     *  null, which every caller already maps to its generic vault label. */
    fun vaultName(meta: JsonElement): String? =
        ((meta as? JsonObject)?.get("name") as? JsonPrimitive)?.takeIf { it.isString }?.content

    private fun loginProblem(e: JsonElement): String? {
        val o = e as? JsonObject ?: return "not an object"
        for (k in listOf("username", "password", "totp")) optString(o, k)?.let { return it }
        o["uris"]?.let { u ->
            val arr = u as? JsonArray ?: return "uris"
            if (!arr.all { isString(it) }) return "uris"
        }
        o["passwordHistory"]?.let { h ->
            val arr = h as? JsonArray ?: return "passwordHistory"
            for (entry in arr) {
                val eo = entry as? JsonObject ?: return "passwordHistory"
                if (!isString(eo["password"]) || !isInteger(eo["retiredAt"])) return "passwordHistory"
            }
        }
        return null
    }

    private fun cardProblem(e: JsonElement): String? {
        val o = e as? JsonObject ?: return "not an object"
        for (k in listOf("cardholderName", "number", "expMonth", "expYear", "securityCode", "brand", "postalCode")) optString(o, k)?.let { return it }
        return null
    }

    private fun checkProblem(e: JsonElement): String? {
        val o = e as? JsonObject ?: return "not an object"
        if (!isInteger(o["at"])) return "at"
        if (!isString(o["result"])) return "result"
        for (k in listOf("okAt", "until")) o[k]?.let { if (it !is JsonNull && !isInteger(it)) return k }
        return null
    }

    private fun attachmentProblem(e: JsonElement): String? {
        val o = e as? JsonObject ?: return "not an object"
        val id = o["id"]
        if (!isString(id) || !SAFE_ID.matches((id as JsonPrimitive).content)) return "id"
        if (!isString(o["name"])) return "name"
        if (!isString(o["fileKey"])) return "fileKey"
        val size = o["size"]
        if (!isInteger(size) || (size as JsonPrimitive).content.startsWith("-")) return "size"
        return null
    }

    private fun isString(e: JsonElement?): Boolean = e is JsonPrimitive && e !is JsonNull && e.isString

    private fun isBoolean(e: JsonElement): Boolean =
        e is JsonPrimitive && e !is JsonNull && !e.isString && (e.content == "true" || e.content == "false")

    /** An optional string field: absent and JSON null are fine, anything but a string is not. */
    private fun optString(o: JsonObject, k: String): String? {
        val e = o[k] ?: return null
        return if (e is JsonNull || isString(e)) null else k
    }

    /** A JSON number token that is a canonical integer within ±(2^53 − 1). */
    private fun isInteger(e: JsonElement?): Boolean {
        if (e !is JsonPrimitive || e is JsonNull || e.isString) return false
        if (!INTEGER_TOKEN.matches(e.content)) return false
        val v = e.content.toLongOrNull() ?: return false
        return v in -MAX_SAFE_INTEGER..MAX_SAFE_INTEGER
    }
}
