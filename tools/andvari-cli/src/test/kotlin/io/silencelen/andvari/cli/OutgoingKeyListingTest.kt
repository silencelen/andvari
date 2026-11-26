package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * `operator recovery-requests` for a request whose recovery copy the server says is sealed to an outgoing recovery key
 * (spec 03 §18.6, `escrowFingerprint`): the row says which key the server names and which the card names, and what each
 * way the key can have changed means (both sheets after a signed rotation; no sheet after operator recovery was turned off
 * and a key set again: the row cannot tell which it was). Nothing is said when the key is the one the pinned card names
 * or when the server sent none, and a key that is not `hex64` fails the row's check.
 */
class OutgoingKeyListingTest {
    private val crypto = createCryptoProvider()
    private fun b64(n: Int) = Bytes.toB64(crypto.randomBytes(n))

    private fun row(email: String, escrowFingerprint: String?): JsonObject = buildJsonObject {
        put("requestId", JsonPrimitive(b64(16))); put("userId", JsonPrimitive("11111111-2222-4333-8444-555555555555")); put("email", JsonPrimitive(email))
        put("accountId", JsonPrimitive("0123456789abcdef0123456789abcdef")); put("rPub", JsonPrimitive(b64(32))); put("platform", JsonPrimitive("android"))
        put("createdAt", JsonPrimitive(1_700_000_000_000)); put("verifiedAt", JsonPrimitive(1_700_000_100_000)); put("holdEndsAt", JsonPrimitive(1_700_604_900_000))
        put("state", JsonPrimitive("awaiting_operator"))
        escrowFingerprint?.let { put("escrowFingerprint", JsonPrimitive(it)) }
    }

    @Test fun aCopySealedToAnOutgoingKeyIsSaidOnItsRowAndNeedsBothSheets() {
        // A server whose card 0 names a recovery key: the current one.
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(crypto.boxKeypairFromSeed(ByteArray(32) { 7 }).publicKey))).use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val current = Regex("recoveryFp:\\s+(\\S+)").find(w.run(w.op, "card", "show").ok())!!.groupValues[1]
            assertNotEquals("none", current, "this server's card names a recovery key")
            val outgoing = "ab".repeat(32)
            p.lie = mapOf(WireRoute.ADMIN_RECOVERY_REQUESTS to { _ ->
                JsonArray(listOf(row("old@example.org", outgoing), row("same@example.org", current), row("unsaid@example.org", null)))
            })
            val out = w.run(w.op, "operator", "recovery-requests", dial = p.address).ok()
            val lines = out.lines()
            fun after(email: String) = lines.getOrNull(lines.indexOfFirst { it.contains("  for $email  ") } + 1).orEmpty()
            val said = after("old@example.org")
            assertEquals("  " + fill(ShownRequest.OUTGOING_KEY_LINE, outgoing, current), said, out)
            assertEquals(1, out.lines().count { it.contains("both recovery sheets") }, "only that row: $out")
            assertFalse(after("same@example.org").contains("recovery sheets"), out)
            assertFalse(after("unsaid@example.org").contains("recovery sheets"), out)

            // --json: the server's word, as served, null when it sent none.
            val rows = Json.parseToJsonElement(w.run(w.op, "operator", "recovery-requests", "--json", dial = p.address).ok()).jsonArray
            assertEquals(listOf(outgoing, current, null), rows.map { (it.jsonObject["escrowFingerprint"] as? JsonPrimitive)?.takeIf { v -> v.isString }?.content })

            // A key that is not 64 lowercase hex digits fails the row's check, like any other lie.
            p.lie = mapOf(WireRoute.ADMIN_RECOVERY_REQUESTS to { _ -> JsonArray(listOf(row("ok@example.org", null), row("bad@example.org", "AB".repeat(32)))) })
            val lied = w.run(w.op, "operator", "recovery-requests", dial = p.address)
            assertEquals(EXIT_SERVER_ANSWER, lied.code, lied.out + lied.err)
            assertTrue(lied.err.contains("[$KEY_SERVER_ROW_REFUSED]") && lied.err.contains("1 a recovery request"), lied.err)
            assertFalse(lied.out.contains("bad@example.org"), lied.out)
        } }
    }
}
