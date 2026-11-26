package io.silencelen.andvari.core.crypto

import io.silencelen.andvari.core.readVector
import io.silencelen.andvari.core.trust.assertSections
import io.silencelen.andvari.core.trust.gradeEvery
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The genesis-bound shared-vault wrap AD (design 2026-11-15 §2.3, T-B3), graded off the `ad`, `seal`
 * and `open` rows of `wrapad.json` from the independent oracle: a wrap made for genesis A is refused
 * under genesis B, and the personal wrap is unchanged. The file's `adopt` rows are the engine's.
 */
class WrapAdVectorTest {
    private val crypto = createCryptoProvider()
    private val v: JsonObject = Json.parseToJsonElement(readVector("wrapad.json")).jsonObject
    private fun JsonObject.s(key: String): String = getValue(key).jsonPrimitive.content
    private fun JsonObject.b(key: String): ByteArray = Bytes.fromB64(s(key))
    private fun rows(key: String): List<JsonObject> = v.getValue(key).jsonArray.map { it.jsonObject }

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andTheAdoptionRowsThatAreTheEngines() {
        // `adopt` is graded by core/client's AdoptionVectorTest; everything else is this suite's.
        assertSections(v, "_about", "vaultId", "vkB64", "vkCommitHex", "accounts", "logs", "ad", "seal", "open", "adopt")
    }

    @Test
    fun ad_sharedNamesTheGenesis_personalIsUnchanged() {
        gradeEvery("wrapad.ad", rows("ad")) { r ->
            val ad = when (r.s("kind")) {
                "shared" -> Ad.vkShared(r.s("vaultId"), r.s("userId"), r.s("genesisHash"))
                "personal" -> Ad.vkPersonal(r.s("vaultId"), r.s("userId"))
                else -> error("unknown kind in ${r.s("why")}")
            }
            assertEquals(r.s("adUtf8"), ad.decodeToString(), r.s("why"))
        }
        assertFailsWith<IllegalArgumentException> { Ad.vkShared("a|b", "u", "h") }
    }

    @Test
    fun seal_isByteExact() {
        gradeEvery("wrapad.seal", rows("seal")) { r ->
            val wrapped = Envelope.sealWithNonce(crypto, r.b("uvkB64"), r.b("nonceB64"), r.b("vkB64"), r.s("adUtf8").encodeToByteArray())
            assertEquals(r.s("wrappedVkB64"), Bytes.toB64(wrapped), r.s("name"))
        }
    }

    @Test
    fun open_onlyUnderItsOwnAd() {
        gradeEvery("wrapad.open", rows("open")) { r ->
            val expect = r.getValue("expect").jsonObject
            val opened = try {
                Envelope.open(crypto, r.b("uvkB64"), r.b("wrappedVkB64"), r.s("adUtf8").encodeToByteArray())
            } catch (e: CryptoException) {
                null
            }
            assertEquals(expect.s("opens").toBooleanStrict(), opened != null, "${r.s("name")}: ${r.s("why")}")
            if (opened != null) assertContentEquals(expect.b("vkB64"), opened, r.s("name"))
        }
    }
}
