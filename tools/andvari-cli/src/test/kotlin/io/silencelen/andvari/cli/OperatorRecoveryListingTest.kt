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
import kotlin.test.assertTrue

/**
 * `operator recovery-requests` against a server that lies in its rows: the listing offers
 * nothing of the server's as something to check against (no account ID, and words that say the checks come from the
 * person), and a row is shown only when every field is what the protocol allows. A row that is not is left out, and the
 * command fails with `[server_row_refused]`; with `--json` nothing is printed at all.
 */
class OperatorRecoveryListingTest {
    private val crypto = createCryptoProvider()
    private fun b64(n: Int) = Bytes.toB64(crypto.randomBytes(n))
    private val esc = Char(0x1b)

    private fun row(
        requestId: String = b64(16), email: String = "alice@example.org", accountId: String = "0123456789abcdef0123456789abcdef",
        rPub: String = b64(32), platform: String = "android", userId: String = "11111111-2222-4333-8444-555555555555",
        state: String? = "awaiting_operator",
    ): JsonObject = buildJsonObject {
        put("requestId", JsonPrimitive(requestId)); put("userId", JsonPrimitive(userId)); put("email", JsonPrimitive(email))
        put("accountId", JsonPrimitive(accountId)); put("rPub", JsonPrimitive(rPub)); put("platform", JsonPrimitive(platform))
        put("createdAt", JsonPrimitive(1_700_000_000_000)); put("verifiedAt", JsonPrimitive(1_700_000_100_000)); put("holdEndsAt", JsonPrimitive(1_700_604_900_000))
        state?.let { put("state", JsonPrimitive(it)) }
    }

    /**
     * The listing holds rows still in their hold beside rows past it, so no heading says "past
     * their hold"; each row says its own state. And the guidance names every argument recovery-cli assist requires, the
     * typed address among them, typed from the operator's own knowledge of the person and never copied from the list.
     */
    @Test fun eachRowSaysItsOwnStateAndTheGuidanceNamesEveryArgumentOfTheOfflineTool() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val holding = row(email = "hal@example.org", state = "holding")
            val waiting = row(email = "wes@example.org", state = "awaiting_operator")
            val answered = row(email = "ann@example.org", state = "ready")
            val unsaid = row(email = "una@example.org", state = null)
            p.lie = mapOf(WireRoute.ADMIN_RECOVERY_REQUESTS to { _ -> JsonArray(listOf(holding, waiting, answered, unsaid)) })
            val out = w.run(w.op, "operator", "recovery-requests", dial = p.address).ok()
            assertFalse(out.contains("past their hold") || out.contains("past its hold"), out)
            fun line(email: String) = out.lines().single { it.contains("  for $email  ") }
            assertTrue(line("hal@example.org").contains("holding until 2023-11-21T22:15:00Z"), out)
            assertTrue(line("wes@example.org").contains("waiting for the operator (the hold ended 2023-11-21T22:15:00Z)"), out)
            assertTrue(line("ann@example.org").contains("answered ("), out)
            assertTrue(line("una@example.org").contains("state not given by the server"), out)
            for (flag in listOf("--instance", "--request ", "--request-key", "--user", "--request-code", "--email", "--identity-fp", "--identity-file"))
                assertTrue(out.contains(flag), "the guidance names $flag: $out")
            assertTrue(out.contains("--email: the person's address, typed from your own knowledge of the person, never copied from this list"), out)

            // --json: each row's state, null when the server sent none.
            val rows = Json.parseToJsonElement(w.run(w.op, "operator", "recovery-requests", "--json", dial = p.address).ok()).jsonArray
            assertEquals(listOf("holding", "awaiting_operator", "ready", null), rows.map { (it.jsonObject["state"] as? JsonPrimitive)?.takeIf { v -> v.isString }?.content })

            // A state no listed request can be in is a row refused like any other lie.
            p.lie = mapOf(WireRoute.ADMIN_RECOVERY_REQUESTS to { _ -> JsonArray(listOf(waiting, row(state = "vetoed"), row(state = "$esc[2Jready"))) })
            val lied = w.run(w.op, "operator", "recovery-requests", dial = p.address)
            assertEquals(EXIT_SERVER_ANSWER, lied.code, lied.out + lied.err)
            assertTrue(lied.err.contains("2 recovery requests"), lied.err)
            assertFalse(lied.out.contains(esc), lied.out)
        } }
    }

    @Test fun theListingOffersNothingOfTheServersToCheckAgainstAndShowsOnlyRowsThatPassEveryCheck() {
        TestServer().use { s -> LyingProxy(s).use { p ->
            val w = CliWorld(s)
            val good = row(accountId = "fedcba9876543210fedcba9876543210")
            val goodId = (good["requestId"] as JsonPrimitive).content
            val bad = listOf(
                "a request key that is not 32 bytes" to row(rPub = "AAAA"),
                "a request key with a command after a line break" to row(rPub = b64(32) + "\nrm -rf ~"),
                "a request key that is not canonical" to row(rPub = b64(32).dropLast(1) + "_"),
                "a platform outside the closed list" to row(platform = "$esc[2Jandroid"),
                "the request code shown as a platform" to row(platform = "code 1234-5678"),
                "an address that is not normalised" to row(email = "Alice@Example.org"),
                "an address with a direction override" to row(email = "alice@example.org" + Char(0x202e)),
                "an address with a line break" to row(email = "alice@example.org\nrun this"),
                "a request id that is not an id" to row(requestId = "../../etc"),
                "a user id that is not a uuid" to row(userId = "Bob"),
                "an account ID that is not 32 hex digits" to row(accountId = "not-an-account-id"),
            )
            p.lie = mapOf(WireRoute.ADMIN_RECOVERY_REQUESTS to { _ -> JsonArray(listOf(good) + bad.map { it.second }) })

            val listed = w.run(w.op, "operator", "recovery-requests", dial = p.address)
            assertEquals(EXIT_SERVER_ANSWER, listed.code, listed.out + listed.err)
            assertTrue(listed.err.contains("[$KEY_SERVER_ROW_REFUSED]") && listed.err.contains("${bad.size} recovery requests"), listed.err)
            assertTrue(listed.out.lines().any { it.startsWith("$goodId  for alice@example.org  request key ") }, listed.out)
            assertEquals(1, listed.out.lines().count { it.contains("for alice@example.org") || it.contains("for Alice") }, "only the good row: ${listed.out}")
            for ((what, r) in bad) for (field in listOf("requestId", "rPub", "platform", "userId")) {
                val v = (r[field] as JsonPrimitive).content
                if (v != (good[field] as JsonPrimitive).content && v.length > 4) assertFalse(listed.out.contains(v.lines().first()), "$what: $field is not shown: ${listed.out}")
            }
            assertFalse(listed.out.contains(esc) || listed.out.contains(Char(0x202e)) || listed.out.contains("rm -rf") || listed.out.contains("1234-5678"), listed.out)

            // The server's account ID is never shown, and the listing says where the checks come from.
            assertFalse(listed.out.contains("fedcba9876543210fedcba9876543210"), "the server's account ID is offered: ${listed.out}")
            assertFalse(listed.out.contains("account ID fedcba") || Regex("account [0-9a-f]{32}").containsMatchIn(listed.out), listed.out)
            assertTrue(listed.out.contains("What you check comes from the person, never from this list"), listed.out)
            assertTrue(listed.out.contains("This list shows no account ID, and nothing in it is a value to check against"), listed.out)

            // --json: a failure prints nothing on standard output.
            val asJson = w.run(w.op, "operator", "recovery-requests", "--json", dial = p.address)
            assertEquals(EXIT_SERVER_ANSWER, asJson.code, asJson.err)
            assertEquals("", asJson.out)

            // Only rows that pass: the command succeeds, and its JSON rows carry no account ID either.
            p.lie = mapOf(WireRoute.ADMIN_RECOVERY_REQUESTS to { _ -> JsonArray(listOf(good)) })
            assertTrue(w.run(w.op, "operator", "recovery-requests", dial = p.address).ok().contains(goodId))
            val rows = Json.parseToJsonElement(w.run(w.op, "operator", "recovery-requests", "--json", dial = p.address).ok()).jsonArray
            val only = rows.single().jsonObject
            assertEquals(goodId, (only["requestId"] as JsonPrimitive).content)
            assertFalse("accountId" in only, "the JSON row offers the server's account ID: $only")
            assertEquals(setOf("requestId", "userId", "email", "rPub", "platform", "createdAt", "verifiedAt", "holdEndsAt", "state", "escrowFingerprint"), only.keys)
        } }
    }
}
