package io.silencelen.andvari.core.client.pin

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * [PublicInstanceSpec], the run-time reader of `spec/public-instance.json` the iPhone app uses. Plain kotlin.test over
 * shared code: it can move to commonTest unchanged, where the JVM runs it.
 */
class PublicInstanceSpecTest {
    private fun spec(instanceId: String, card0Hash: String, joinBase: String = "https://andvaripass.com", v: String = "1") = """
        {
          "_comment": "x",
          "v": $v,
          "PUBLIC_INSTANCE": {
            "origin": "https://vault.andvaripass.com",
            "instanceId": "$instanceId",
            "card0Hash": "$card0Hash",
            "kind": "public",
            "name": "andvari"
          },
          "joinBase": "$joinBase",
          "ios": { "bundleId": "com.silencelen.andvari" }
        }
    """.trimIndent()

    @Test
    fun placeholdersBakeNothingAndAreNamed() {
        val s = assertNotNull(PublicInstanceSpec.parse(spec("PLACEHOLDER: the uuid", "PLACEHOLDER: the hash")))
        assertNull(s.baked, "a placeholder anywhere in the four values bakes no instance (the Android build's rule)")
        assertEquals(listOf("instanceId", "card0Hash"), s.placeholders)
        assertEquals("https://andvaripass.com", s.joinBase)
    }

    @Test
    fun aCompleteSpecBakesTheInstance() {
        val hash = "a".repeat(64)
        val s = assertNotNull(PublicInstanceSpec.parse(spec("11111111-2222-3333-4444-555555555555", hash)))
        assertEquals(BakedInstance("https://vault.andvaripass.com", "11111111-2222-3333-4444-555555555555", hash, "public"), s.baked)
        assertEquals(emptyList(), s.placeholders)
    }

    @Test
    fun oneMissingValueBakesNothing() {
        val text = spec("11111111-2222-3333-4444-555555555555", "b".repeat(64)).replace("\"kind\": \"public\",", "")
        val s = assertNotNull(PublicInstanceSpec.parse(text))
        assertNull(s.baked)
    }

    @Test
    fun aPlaceholderJoinBaseIsNoJoinBase() {
        val s = assertNotNull(PublicInstanceSpec.parse(spec("PLACEHOLDER: x", "PLACEHOLDER: y", joinBase = "PLACEHOLDER: later")))
        assertNull(s.joinBase)
        assertEquals(listOf("instanceId", "card0Hash", "joinBase"), s.placeholders)
    }

    @Test
    fun anotherShapeOrVersionIsNotTheSpec() {
        assertNull(PublicInstanceSpec.parse("not json"))
        assertNull(PublicInstanceSpec.parse("[]"))
        assertNull(PublicInstanceSpec.parse(spec("a", "b", v = "2")))
        assertNull(PublicInstanceSpec.parse("""{"v": 1}"""))
    }

    @Test
    fun aNumberWhereAStringBelongsIsMissing() {
        val text = spec("11111111-2222-3333-4444-555555555555", "c".repeat(64)).replace("\"kind\": \"public\"", "\"kind\": 7")
        assertNull(assertNotNull(PublicInstanceSpec.parse(text)).baked)
    }
}
