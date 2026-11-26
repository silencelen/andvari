package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec 01 §7, the pending-record rule: after a run sent a change of the account's keys, a proof in that run is refused when
 * the keys the server holds are not the ones it knows, and the person is told what is so in each case, against the real
 * server through a proxy that lies:
 * - the keys read again do not open here to the account's key: they changed while the run went on (exit 6);
 * - the keys could not be read again, for no usable answer: said as that, not as a change (exit 6);
 * - the keys read again name a cost outside the fence: the server's answer at fault, its own words and exit 3, ahead of 6.
 */
class KeysNotKnownWordsTest {
    private val change: (String) -> String? = {
        when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> "a brand new master password 77"; else -> null }
    }

    private fun withPasses(e: JsonElement, ops: Long): JsonElement {
        val o = e.jsonObject
        return JsonObject(o + ("kdfParams" to JsonObject(o.getValue("kdfParams").jsonObject + ("ops" to JsonPrimitive(ops)))))
    }

    private val put = "PUT /api/v1/account/password"

    /** The run stopped before its password change sent anything, with exit 6 and never as a wrong password. */
    private fun notKnown(p: LyingProxy, mark: Int, r: CliRun) {
        assertEquals(EXIT_KEYS_NOT_KNOWN, r.code, r.out + r.err)
        assertTrue(r.err.contains("[$KEY_KEYS_NOT_KNOWN]") && r.err.contains("sent nothing for this command") &&
            r.err.contains("That isn't a wrong password") && r.err.contains("Run the command again"), r.err)
        assertFalse(r.err.contains("is wrong") || r.err.contains("wrong master password"), r.err)
        assertEquals(1, p.seen.drop(mark).count { it.startsWith(put) }, "only the re-key; the change sent nothing: ${p.seen.drop(mark)}")
    }

    @Test fun keysThatDoNotOpenHereAreSaidToHaveChanged() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                var reads = 0
                p.lie = mapOf(
                    WireRoute.CLIENT_POLICY to { e -> withPasses(e, 4) },
                    WireRoute.ACCOUNT_KEYS to { e ->
                        if (reads++ == 0) e else {
                            val o = e.jsonObject
                            val wrap = o.getValue("wrappedUvk").jsonPrimitive.content
                            val i = wrap.length / 2
                            JsonObject(o + ("wrappedUvk" to JsonPrimitive(wrap.substring(0, i) + (if (wrap[i] == 'A') 'B' else 'A') + wrap.substring(i + 1))))
                        }
                    },
                )
                p.answer = mapOf(WireRoute.PASSWORD_CHANGE to { _, _ -> 200 to "{}" })
                val mark = p.seen.size
                val r = w.run(me, "account", "password", env = change, dial = p.address)
                notKnown(p, mark, r)
                assertTrue(r.err.contains("[$KEY_KEYS_NOT_KNOWN]: ${fill(KEYS_CHANGED, s.origin)}"), r.err)
                assertFalse(r.err.contains(fill(KEYS_NOT_READ, s.origin)), r.err)
            }
        }
    }

    @Test fun keysThatCouldNotBeReadAgainAreSaidAsThatAndNotAsAChange() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                var reads = 0
                p.lie = mapOf(WireRoute.CLIENT_POLICY to { e -> withPasses(e, 4) })
                // The re-key is stored and answered; the keys read again get an answer nobody can read.
                p.answer = mapOf(WireRoute.ACCOUNT_KEYS to { _, forward ->
                    if (reads++ == 0) forward().let { it.first to String(it.second) } else 200 to """{"not":"the keys"}"""
                })
                val mark = p.seen.size
                val r = w.run(me, "account", "password", env = change, dial = p.address)
                notKnown(p, mark, r)
                assertTrue(r.err.contains("[$KEY_KEYS_NOT_KNOWN]: ${fill(KEYS_NOT_READ, s.origin)}"), r.err)
                assertFalse(r.err.contains(fill(KEYS_CHANGED, s.origin)), r.err)
                assertEquals(2, reads)

                // Run again, it goes: the keys the server holds open with the same password at the raised cost.
                p.lie = emptyMap()
                p.answer = emptyMap()
                w.run(me, "item", "list", "personal", dial = p.address).ok()
            }
        }
    }

    @Test fun keysReadAgainAtACostOutsideTheFenceAreTheServersFaultWithExitThree() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val ragged = 64L * 1024 * 1024 + 1
                var reads = 0
                p.lie = mapOf(
                    WireRoute.CLIENT_POLICY to { e -> withPasses(e, 4) },
                    WireRoute.ACCOUNT_KEYS to { e ->
                        if (reads++ == 0) e else {
                            val o = e.jsonObject
                            JsonObject(o + ("kdfParams" to JsonObject(o.getValue("kdfParams").jsonObject + ("memBytes" to JsonPrimitive(ragged)))))
                        }
                    },
                )
                val mark = p.seen.size
                val r = w.run(me, "account", "password", env = change, dial = p.address)
                assertEquals(EXIT_SERVER_ANSWER, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_SERVED_COST_REFUSED]") && r.err.contains("$ragged bytes") &&
                    r.err.contains(SERVED_COST_REFUSED.substringAfterLast("}")), r.err)
                assertFalse(r.err.contains("[$KEY_KEYS_NOT_KNOWN]") || r.err.contains("is wrong"), r.err)
                assertEquals(1, p.seen.drop(mark).count { it.startsWith(put) }, p.seen.drop(mark).toString())
            }
        }
    }
}
