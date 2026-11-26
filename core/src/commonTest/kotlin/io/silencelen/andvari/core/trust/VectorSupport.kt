package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Reading the conformance vectors of the onboarding and trust design (spec/test-vectors, §17). */
internal fun vector(name: String): JsonObject = Json.parseToJsonElement(readVector(name)).jsonObject

internal fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
internal fun JsonObject.sOrNull(key: String): String? = (this[key] as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content
internal fun JsonObject.l(key: String): Long = getValue(key).jsonPrimitive.content.toLong()
internal fun JsonObject.bool(key: String): Boolean = getValue(key).jsonPrimitive.content.toBooleanStrict()
internal fun JsonObject.o(key: String): JsonObject = getValue(key).jsonObject
internal fun JsonObject.oOrNull(key: String): JsonObject? = this[key] as? JsonObject
internal fun JsonObject.rows(key: String): List<JsonObject> = getValue(key).jsonArray.map { it.jsonObject }
internal fun JsonObject.b64(key: String): ByteArray = Bytes.fromB64(s(key))
internal fun JsonArray.strings(): List<String> = map { it.jsonPrimitive.content }

/** A statement's values as the codec takes them: every primitive as its text, in the vector's order. */
internal fun JsonObject.asFields(): Map<String, String> = entries.associate { (k, v: JsonElement) -> k to v.jsonPrimitive.content }

/**
 * Grades every row of one section, in file order. The count comes from the file, never from the test:
 * a section that is missing or empty fails here, and the tally proves no row was passed over. The line
 * it prints (`graded <label> n/N`, in the JUnit XML's system-out) is the count a conformance sweep reports.
 */
internal fun <T> gradeEvery(label: String, rows: List<T>, grade: (T) -> Unit) {
    assertTrue(rows.isNotEmpty(), "$label: the section is missing or empty")
    var graded = 0
    for (row in rows) {
        grade(row)
        graded++
    }
    assertEquals(rows.size, graded, "$label: rows graded")
    println("graded $label $graded/${rows.size}")
}

/**
 * The file's top-level keys are exactly the ones its suite reads (or names as another suite's). A section
 * the oracle adds later then fails here instead of going ungraded.
 */
internal fun assertSections(file: JsonObject, vararg known: String) {
    assertEquals(known.sorted(), file.keys.sorted(), "the file's sections: one this suite does not know would go ungraded")
}

/**
 * A row's `expect` holds exactly the keys its grader checked ([graded]): a key the oracle adds later
 * then fails here instead of going unread.
 */
internal fun assertExpectGraded(expect: JsonObject, graded: Set<String>, label: String) {
    assertEquals(graded.sorted(), expect.keys.sorted(), "$label: the expectations this grader checks, and no other")
}

/** A row's inputs are among the ones its harness reads ([known]): an input the oracle adds later fails here. */
internal fun assertInputsKnown(row: JsonObject, known: Set<String>, label: String) {
    val unknown = row.keys - known
    assertTrue(unknown.isEmpty(), "$label: inputs this harness does not read: $unknown")
}

internal fun hexBytes(hex: String): ByteArray = Bytes.fromHexLower(hex) ?: error("not lowercase hex: $hex")

/** The joint Ed25519 key of a cast account, or the signing key of a recovery seed (`crypto_sign_seed_keypair`). */
internal fun signerOf(crypto: CryptoProvider, cast: JsonObject, name: String): KeyPairBytes =
    crypto.signKeypairFromSeed(cast.o(name).b64("seedB64"))
