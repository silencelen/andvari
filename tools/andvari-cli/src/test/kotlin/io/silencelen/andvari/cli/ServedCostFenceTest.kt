package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec 01 §7, the client-side bounds, on every hashing cost a server serves (the reopen's keys, the sign-in's first
 * exchange, the keys read again after a re-key): a memory cost that is not a whole number of KiB is refused before
 * anything is derived at it, as a fault of the server's answer and never as a wrong password. Against the real server
 * through a proxy that serves the cost one byte above 64 MiB, which the engines would round differently.
 */
class ServedCostFenceTest {
    private val ragged = 64L * 1024 * 1024 + 1

    private fun raggedCost(e: JsonElement): JsonElement {
        val o = e.jsonObject
        val p = o.getValue("kdfParams").jsonObject
        return JsonObject(o + ("kdfParams" to JsonObject(p + ("memBytes" to JsonPrimitive(ragged)))))
    }

    private fun refusedAsTheServers(r: CliRun) {
        assertEquals(EXIT_SERVER_ANSWER, r.code, r.out + r.err)
        // The approved sentence, its slots filled: the passes and bytes served, and the fence's own limits.
        assertTrue(r.err.contains("[$KEY_SERVED_COST_REFUSED]: The server at ") && r.err.contains("passes over $ragged bytes of memory") &&
            r.err.contains(fill(SERVED_COST_REFUSED.substringAfter("{2}"), "", "", "", io.silencelen.andvari.core.client.KdfUpgrade.MIN_OPS,
                io.silencelen.andvari.core.client.KdfUpgrade.MAX_OPS)), r.err)
        assertFalse(r.err.contains("wrong master password") || r.err.contains("wrong email") || r.err.contains("is wrong"), r.err)
        assertEquals("", r.out)
    }

    @Test fun aRaggedCostAtTheReopenOrAtTheSignInIsRefusedBeforeAnythingIsDerived() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")

                // The reopen: the saved session's keys at a ragged cost. Nothing is derived, no sign-in is tried instead.
                p.lie = mapOf(WireRoute.ACCOUNT_KEYS to ::raggedCost)
                var counted = CountingCrypto()
                var mark = p.seen.size
                val reopen = w.run(me, "item", "list", "personal", dial = p.address, crypto = counted)
                refusedAsTheServers(reopen)
                assertEquals(emptyList(), counted.derivations, "nothing derived")
                assertEquals(listOf("GET /api/v1/account/keys"), p.seen.drop(mark).map { it.substringBefore('?') }, "only the keys were read")

                // The sign-in's first exchange on a new device: the prelogin's cost is ragged. No derivation, no login.
                p.lie = mapOf(WireRoute.PRELOGIN to ::raggedCost)
                counted = CountingCrypto()
                mark = p.seen.size
                val signIn = w.run(w.home("new@example.org"), "sign-in", "--email", "me@example.org", "--trust-card", w.card0, dial = p.address, crypto = counted)
                refusedAsTheServers(signIn)
                assertEquals(emptyList(), counted.derivations, "nothing derived")
                assertTrue(p.seen.drop(mark).none { it.contains("/auth/login") }, "no login was sent: ${p.seen.drop(mark)}")

                // An honest server, the same device: it goes on.
                p.lie = emptyMap()
                w.run(me, "item", "list", "personal", dial = p.address).ok()
            }
        }
    }

    @Test fun aRaggedCostInTheKeysReadAfterAReKeyIsNeverDerivedAtAndTheRunsProofsAreRefused() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                var reads = 0
                p.lie = mapOf(
                    WireRoute.CLIENT_POLICY to { e ->
                        val o = e.jsonObject
                        JsonObject(o + ("kdfParams" to JsonObject(o.getValue("kdfParams").jsonObject + ("ops" to JsonPrimitive(4)))))
                    },
                    WireRoute.ACCOUNT_KEYS to { e -> if (reads++ == 0) e else raggedCost(e) },
                )
                val counted = CountingCrypto()
                val r = w.run(me, "account", "password", dial = p.address, crypto = counted, env = {
                    when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> "a brand new master password 77"; else -> null }
                })
                // The server's answer at fault, in its own words and code, ahead of "the keys are not known here".
                refusedAsTheServers(r)
                assertFalse(r.err.contains("[$KEY_KEYS_NOT_KNOWN]"), r.err)
                assertTrue(counted.derivations.none { it.second == ragged }, "nothing derived at the ragged cost: ${counted.derivations}")
                // The reopen, the re-key's new wrap and its proof; no try of the served wrap, and nothing for the change:
                // its proof would be refused here, so its new wrap is not derived either.
                assertEquals(listOf(3L, 4L, 3L), counted.derivations.map { it.first }, counted.derivations.toString())
                assertEquals(1, p.seen.count { it.startsWith("PUT /api/v1/account/password") }, "only the re-key was sent: ${p.seen}")
                assertEquals(2, reads, "the reopen's keys, and the keys read again after the re-key")
            }
        }
    }
}
