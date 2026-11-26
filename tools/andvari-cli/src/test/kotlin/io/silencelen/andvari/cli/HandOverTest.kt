package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Handing the server to another operator from the command line (design §4.2, §4.3, §9.1; the desktop's console sends the
 * operator here), against a real server: the new operator's user id and signing key come from their own device
 * (`account signing-key`); what the old operator keeps and loses is said before the typed confirmation; a key that is not
 * that account's is refused and nothing changes; afterwards the new account runs the server and the old one cannot.
 */
class HandOverTest {
    @Test fun theServerIsHandedToAnotherOperatorNamedByWhatTheirOwnDeviceShows() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val bob = w.account("bob@example.org")
            val carol = w.account("carol@example.org")
            fun ownKey(home: File): Pair<String, String> {
                val o = Json.parseToJsonElement(w.run(home, "account", "signing-key", "--json").ok()).jsonObject
                return o.getValue("userId").jsonPrimitive.content to o.getValue("signingKey").jsonPrimitive.content
            }
            val (bobId, bobKey) = ownKey(bob)
            val (_, carolKey) = ownKey(carol)
            assertTrue(w.run(bob, "account", "signing-key").ok().contains("not from the server"))
            fun operatorOnCard() = Regex("operator:\\s+(\\S+)").find(w.run(w.op, "card", "show").ok())!!.groupValues[1]
            val opId = operatorOnCard()
            fun handOver(vararg extra: String, key: String = bobKey) = w.run(w.op, "operator", "hand-over", "--to-user", bobId, "--to-key", key, *extra)

            // Not a user id: refused before anything.
            assertEquals(2, w.run(w.op, "operator", "hand-over", "--to-user", "bob@example.org", "--to-key", bobKey).code)
            // What it does is said first; without the typed confirmation nothing happens.
            val asked = handOver()
            assertEquals(2, asked.code, asked.err)
            assertTrue(asked.err.contains("is an ordinary member") && asked.err.contains("can no longer sign the server's card") &&
                asked.err.contains("instance recovery sheet") && asked.err.contains("--confirm \"HAND OVER ${bobId.take(8)}\""), asked.err)
            assertEquals(1, handOver("--confirm", "yes").code)
            assertEquals(opId, operatorOnCard())

            // Carol's key under Bob's id: the server refuses the card, and nothing changes.
            val wrongKey = handOver("--confirm", "HAND OVER ${bobId.take(8)}", key = carolKey)
            assertEquals(1, wrongKey.code, wrongKey.out + wrongKey.err)
            assertTrue(wrongKey.err.contains("bad_card"), wrongKey.err)
            assertEquals(opId, operatorOnCard())

            // Bob's own id and key: card 1 names him.
            val done = handOver("--confirm", "HAND OVER ${bobId.take(8)}").ok()
            assertTrue(done.contains("card 1 stored") && done.contains("handed over"), done)
            assertEquals(bobId, operatorOnCard())

            // The old operator's commands are refused on the card's word, before anything is sent, also its card signing.
            val old = w.run(w.op, "operator", "accounts")
            assertEquals(1, old.code, old.out + old.err)
            assertFalse(old.out.contains("bob@example.org"), old.out)
            assertTrue(old.err.contains("[$KEY_NOT_THE_OPERATOR]") && old.err.contains("names another account as the operator"), old.err)
            val oldCard = w.run(w.op, "card", "sign", "--name", "Not mine any more")
            assertEquals(1, oldCard.code, oldCard.err)
            assertTrue(oldCard.err.contains("[$KEY_NOT_THE_OPERATOR]") && !oldCard.err.contains("Master password"), oldCard.err)
            // The new operator's very next command is served, in the session opened before the hand-over (item 5);
            // signing a card there says what to do, before the password, as the shared card path goes by the session's role.
            assertTrue(w.run(bob, "operator", "accounts").ok().contains("op@example.org"))
            val early = w.run(bob, "card", "sign", "--name", "Bob's server")
            assertEquals(1, early.code, early.err)
            assertTrue(early.err.contains("[$KEY_SESSION_ROLE_STALE]") && early.err.contains("andvari-cli sign-out") && !early.err.contains("Master password"), early.err)
            w.run(bob, "sign-out").ok()
            w.run(bob, "sign-in", "--email", "bob@example.org", "--trust-card", w.card0).ok()
            assertTrue(w.run(bob, "operator", "accounts").ok().contains("op@example.org"))
            assertTrue(w.run(bob, "card", "sign", "--name", "Bob's server").ok().contains("card 2 stored"))
        }
    }
}
