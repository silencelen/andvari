package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The three commands that had no `--json`: the check before an account deletion, the list of link
 * answers and the cancel of a recovery request. Each prints ONE JSON document on standard output and nothing else, in
 * the form the other commands use (a list is an array, a state an object, absent values null).
 */
class JsonMoreCommandsTest {
    private fun doc(r: CliRun) = Json.parseToJsonElement(r.ok().trim())

    @Test fun theCheckBeforeADeletionIsAnObject() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val check = assertIs<JsonObject>(doc(w.run(me, "account", "delete", "--check", "--json")))
            assertEquals(mapOf("origin" to s.origin, "account" to "me@example.org", "state" to "exists"), check.mapValues { it.value.jsonPrimitive.content })
        }
    }

    @Test fun theLinkAnswersAreAnArrayOfRows() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val friend = w.account("friend@example.org")
            val url = w.run(me, "link", "create").ok().lines().last { it.contains("://") }.trim()
            val linkFile = File(w.tmp, "link.txt").also { it.writeText(url) }
            w.run(friend, "link", "open", "--link-file", linkFile.path).ok()
            val row = doc(w.run(me, "link", "answers", "--json")).jsonArray.single().jsonObject
            assertEquals(setOf("outcome", "userId", "label", "code", "linkId", "reason"), row.keys)
            assertEquals("connected", row.getValue("outcome").jsonPrimitive.content)
            assertEquals(w.userId("friend@example.org"), row.getValue("userId").jsonPrimitive.content)
            assertEquals(JsonNull, row.getValue("reason"))
            // Nothing left to process: an empty array.
            assertEquals(JsonArray(emptyList()), doc(w.run(me, "link", "answers", "--json")))
        }
    }

    @Test fun theVetoOfARecoveryRequestIsAnObject() {
        val pub = createCryptoProvider().let { it.boxKeypairFromSeed(it.randomBytes(32)).publicKey }
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            w.run(me, "recovery", "operator", "--i-understand").ok()
            val seen = Steps.mailCount(s, "me@example.org", "recovery_request_code")
            w.run(File(w.tmp, "someone"), "recover", "assist", "--email", "me@example.org", "--trust-card", w.card0,
                stdin = { Steps.awaitCode(s, "me@example.org", "recovery_request_code", seen) }).ok()
            val live = doc(w.run(me, "recovery-requests", "--json")).jsonObject.getValue("requests").jsonArray
            val id = live.single().jsonObject.getValue("requestId").jsonPrimitive.content
            val veto = assertIs<JsonObject>(doc(w.run(me, "recovery-requests", "veto", id, "--json")))
            assertEquals(mapOf("requestId" to id, "state" to "vetoed"), veto.mapValues { it.value.jsonPrimitive.content })
            // A failure prints nothing on standard output.
            val again = w.run(me, "recovery-requests", "veto", id, "--json")
            assertTrue(again.code != 0 && again.out.isEmpty(), again.out + again.err)
        }
    }
}
