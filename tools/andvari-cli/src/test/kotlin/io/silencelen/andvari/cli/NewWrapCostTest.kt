package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.util.Collections
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Spec 01 §7, "never derived at a lower cost than the account already had", in the command-line tool against the real
 * server: `account password` derives the new master password at the account's own cost, raised to the server's policy
 * where that is higher; never at the default cost. So a password change right after an honest raise keeps the raise, the
 * next run has nothing to re-key, and the account's other device is not signed out a second time for it.
 */
class NewWrapCostTest {
    private val email = "me@example.org"
    private val p1 = "a brand new master password 77"
    private val p2 = "another new master password 88"

    private fun env(current: String, next: String? = null): (String) -> String? = {
        when (it) { "ANDVARI_PASSWORD" -> current; "ANDVARI_NEW_PASSWORD" -> next; else -> null }
    }

    private fun withPasses(e: JsonElement, ops: Long): JsonElement {
        val o = e.jsonObject
        val p = o.getValue("kdfParams").jsonObject
        return JsonObject(o + ("kdfParams" to JsonObject(p + ("ops" to JsonPrimitive(ops)))))
    }

    /** What went past the proxy: the passes of every password change sent, and the passes of every keys read. */
    private class Wire {
        val sent: MutableList<Long> = Collections.synchronizedList(ArrayList())
        val keys: MutableList<Long> = Collections.synchronizedList(ArrayList())
        fun sentSince(mark: Int) = synchronized(sent) { sent.drop(mark) }
        fun keysSince(mark: Int) = synchronized(keys) { keys.drop(mark) }
    }

    /** The proxy passes everything on and records [w]; with [policyOps], the policy asks for that many passes. */
    private fun watch(p: LyingProxy, w: Wire, policyOps: Long?) {
        p.lie = buildMap<WireRoute, (JsonElement) -> JsonElement> {
            if (policyOps != null) put(WireRoute.CLIENT_POLICY) { e: JsonElement -> withPasses(e, policyOps) }
            put(WireRoute.ACCOUNT_KEYS) { e: JsonElement ->
                w.keys += e.jsonObject.getValue("kdfParams").jsonObject.getValue("ops").jsonPrimitive.long
                e
            }
        }
        p.answer = mapOf(WireRoute.PASSWORD_CHANGE to { body, forward ->
            w.sent += Json.parseToJsonElement(String(body)).jsonObject.getValue("newKdfParams").jsonObject.getValue("ops").jsonPrimitive.long
            forward().let { it.first to String(it.second) }
        })
    }

    private fun changed(r: CliRun) {
        assertEquals(0, r.code, r.out + r.err)
        assertTrue(r.out.contains(PASSWORD_CHANGED.substringAfterLast("}")), r.out)
    }

    @Test fun aPasswordChangeAfterAnHonestRaiseKeepsTheRaiseAndTheNextRunReKeysNothing() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account(email)
                val other = w.home("other@example.org")
                w.run(other, "sign-in", "--email", email, "--trust-card", w.card0).ok()
                val wire = Wire()

                // The policy asks for 4 passes: the reopen re-keys, then the password changes in the same run.
                watch(p, wire, policyOps = 4)
                changed(w.run(me, "account", "password", env = env(Steps.PASSWORD, p1), dial = p.address))
                assertEquals(listOf(4L, 4L), wire.sentSince(0), "the re-key, then the change, both at the raised cost")

                // The other device was signed out by them; it signs in again with the new password.
                assertEquals(1, w.run(other, "item", "list", "personal", env = env(p1)).code)
                w.run(other, "sign-in", "--email", email, "--trust-card", w.card0, env = env(p1)).ok()

                // The next run reads the account at 4 passes and has nothing to re-key.
                var sent = wire.sent.size
                val keys = wire.keys.size
                val listed = w.run(me, "item", "list", "personal", env = env(p1), dial = p.address).ok()
                assertTrue(wire.keysSince(keys).isNotEmpty() && wire.keysSince(keys).all { it == 4L }, "the server stored 4 passes: ${wire.keysSince(keys)}")
                assertEquals(emptyList(), wire.sentSince(sent), "no second re-key")
                // So the other device is not signed out a second time.
                assertEquals(listed, w.run(other, "item", "list", "personal", env = env(p1)).ok())

                // A policy lower than the account (the server's own, 3 passes) lowers nothing: the change stays at 4.
                watch(p, wire, policyOps = null)
                sent = wire.sent.size
                changed(w.run(me, "account", "password", env = env(p1, p2), dial = p.address))
                assertEquals(listOf(4L), wire.sentSince(sent), "the account's own cost")
                w.run(me, "item", "list", "personal", env = env(p2)).ok()
            }
        }
    }

    @Test fun thePasswordChangeOfARunThatSignedInKeepsTheAccountsCostAndItsRaise() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account(email)
                val wire = Wire()

                // Signed out, then `account password` signs in with the password, re-keys to the policy's 4 passes, and
                // changes the password in the same run.
                w.run(me, "sign-out", "--email", email).ok()
                watch(p, wire, policyOps = 4)
                changed(w.run(me, "account", "password", "--email", email, "--trust-card", w.card0, env = env(Steps.PASSWORD, p1), dial = p.address))
                assertEquals(listOf(4L, 4L), wire.sentSince(0), "the re-key, then the change, both at the raised cost")
                var sent = wire.sent.size
                val keys = wire.keys.size
                w.run(me, "item", "list", "personal", env = env(p1), dial = p.address).ok()
                assertTrue(wire.keysSince(keys).isNotEmpty() && wire.keysSince(keys).all { it == 4L }, "stored at 4 passes: ${wire.keysSince(keys)}")
                assertEquals(emptyList(), wire.sentSince(sent), "nothing more to re-key")

                // Signed out again, the account already at the policy's cost: the sign-in re-keys nothing, and the change
                // is derived at the cost the sign-in's answer named, not at the default.
                w.run(me, "sign-out", "--email", email).ok()
                sent = wire.sent.size
                changed(w.run(me, "account", "password", "--email", email, "--trust-card", w.card0, env = env(p1, p2), dial = p.address))
                assertEquals(listOf(4L), wire.sentSince(sent), "the account's own cost, from the sign-in")
                w.run(me, "item", "list", "personal", env = env(p2)).ok()
            }
        }
    }
}
