package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec 01 §7, the pending-record rule, inside the one run of the tool that re-keyed: the answer to the quiet re-key may be
 * a lie, so the tool reads the account's keys again and settles the proof it holds against the wrap the server holds
 * before any proof in that run. Against the real server, through a proxy that lies about the re-key's answer:
 * - "done" for a change it never stored, then a password change in the same run: it is taken;
 * - a change stored and answered with a refusal, then the same: it is taken;
 * - keys read afterwards that do not open here to the account's key: the password change refuses before anything is
 *   sent, in words that say what is so, with an exit code of its own; run again, it goes;
 * - a proof the server refuses although the password opened the account here is never "wrong password: nothing was
 *   sent";
 * - an honest run sends nothing more than before when nothing is due, and one more read of the keys after a re-key.
 */
class ReKeyLieInOneRunTest {
    private val newPassword = "a brand new master password 77"
    private val change: (String) -> String? = {
        when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> newPassword; else -> null }
    }
    private val withNew: (String) -> String? = { if (it == "ANDVARI_PASSWORD") newPassword else null }

    private fun withPasses(e: JsonElement, ops: Long): JsonElement {
        val o = e.jsonObject
        val p = o.getValue("kdfParams").jsonObject
        return JsonObject(o + ("kdfParams" to JsonObject(p + ("ops" to JsonPrimitive(ops)))))
    }

    private fun count(p: LyingProxy, from: Int, request: String) = synchronized(p.seen) { p.seen.drop(from).count { it.startsWith(request) } }
    private val keys = "GET /api/v1/account/keys"
    private val put = "PUT /api/v1/account/password"

    /** The password change of [r] was taken, and the account opens with the new password afterwards. */
    private fun changed(w: CliWorld, home: File, r: CliRun) {
        assertEquals(0, r.code, r.out + r.err)
        assertTrue(r.out.contains(PASSWORD_CHANGED.substringAfterLast("}")), r.out)
        assertFalse(r.err.contains("wrong", ignoreCase = true), r.err)
        w.run(home, "item", "list", "personal", env = withNew).ok()
    }

    @Test fun afterADoneTheServerNeverStoredOrAStoredChangeItRefusedAPasswordChangeInTheSameRunIsTaken() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)

                // "Done", never stored: the server keeps the old wrap, and the tool's held session the one it sent.
                val one = w.account("one@example.org")
                p.lie = mapOf(WireRoute.CLIENT_POLICY to { e -> withPasses(e, 4) })
                var lies = 1
                p.answer = mapOf(WireRoute.PASSWORD_CHANGE to { _, forward ->
                    if (lies-- > 0) 200 to "{}" else forward().let { it.first to String(it.second) }
                })
                var mark = p.seen.size
                val a = w.run(one, "account", "password", env = change, dial = p.address)
                changed(w, one, a)
                assertEquals(2, count(p, mark, put), "the re-key the server dropped, then the password change: ${p.seen.drop(mark)}")
                assertEquals(2, count(p, mark, keys), "the keys of the reopen, and the keys read again after the re-key")

                // Stored, then answered with a refusal: the server holds the new wrap, the tool's held session the old one.
                val two = w.account("two@example.org")
                lies = 1
                p.answer = mapOf(WireRoute.PASSWORD_CHANGE to { _, forward ->
                    val (status, body) = forward()
                    if (lies-- > 0) {
                        assertEquals(200, status, String(body))
                        400 to """{"error":"bad_request","message":"refused"}"""
                    } else status to String(body)
                })
                mark = p.seen.size
                val b = w.run(two, "account", "password", env = change, dial = p.address)
                changed(w, two, b)
                assertEquals(2, count(p, mark, put), p.seen.drop(mark).toString())
                assertEquals(2, count(p, mark, keys), p.seen.drop(mark).toString())
            }
        }
    }

    @Test fun keysThatDoNotSettleRefuseEveryProofOfThatRunBeforeAnythingIsSentAndTheNextRunGoesOn() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                var reads = 0
                p.lie = mapOf(
                    WireRoute.CLIENT_POLICY to { e -> withPasses(e, 4) },
                    // The keys read again after the re-key serve a wrap that does not open here.
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
                assertEquals(EXIT_KEYS_NOT_KNOWN, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_KEYS_NOT_KNOWN]"), r.err)
                assertTrue(r.err.contains(fill(KEYS_CHANGED, s.origin)), r.err)
                assertFalse(r.err.contains("is wrong") || r.err.contains("wrong master password"), r.err)
                assertEquals("", r.out)
                assertEquals(1, count(p, mark, put), "only the re-key the server dropped; the change sent nothing: ${p.seen.drop(mark)}")

                // As the sentence says: run it again, and it goes (the server never took a change, so the old password is in force).
                p.lie = emptyMap()
                p.answer = emptyMap()
                changed(w, me, w.run(me, "account", "password", env = change, dial = p.address))
            }
        }
    }

    @Test fun aProofTheServerRefusesIsSaidAsSuchAndAnHonestRunSendsNothingMore() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")

                // Nothing due: one read of the keys (the reopen's), no change, as before.
                var mark = p.seen.size
                val listed = w.run(me, "item", "list", "personal", dial = p.address).ok()
                assertEquals(1, count(p, mark, keys), p.seen.drop(mark).toString())
                assertEquals(0, count(p, mark, put))

                // The server refuses a proof the password made here: said as the server's refusal of a proof that was sent.
                p.wrongProofs = 1
                mark = p.seen.size
                val r = w.run(me, "account", "password", env = change, dial = p.address)
                assertEquals(1, p.proofsChanged.get())
                assertEquals(EXIT_PROOF_REFUSED, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_PROOF_REFUSED]") && r.err.contains("refused the proof of your master password") &&
                    r.err.contains("although that password opened the account on this device") && r.err.contains("The proof was sent"), r.err)
                assertFalse(r.err.contains("nothing was sent") || r.err.contains("is wrong"), r.err)
                assertEquals(1, count(p, mark, put))

                // An honest raise: the re-key, one more read of the keys, the same output; then a change in the same run goes.
                p.lie = mapOf(WireRoute.CLIENT_POLICY to { e -> withPasses(e, 4) })
                mark = p.seen.size
                assertEquals(listed, w.run(me, "item", "list", "personal", dial = p.address).ok())
                assertEquals(2, count(p, mark, keys), p.seen.drop(mark).toString())
                assertEquals(1, count(p, mark, put))
                p.lie = mapOf(WireRoute.CLIENT_POLICY to { e -> withPasses(e, 5) })
                mark = p.seen.size
                changed(w, me, w.run(me, "account", "password", env = change, dial = p.address))
                assertEquals(2, count(p, mark, put), "the honest re-key, then the change: ${p.seen.drop(mark)}")
            }
        }
    }
}
