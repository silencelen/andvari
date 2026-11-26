package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import java.nio.file.Files
import java.util.Collections
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Spec 01 §7, "KDF upgrade", in the command-line tool against the real server: after it reopens a saved session with the
 * password, and after a sign-in with the password, it re-keys the account quietly when the policy asks for a legitimate
 * raise. The person sees nothing of it; the account's other devices are signed out once and told so in words that do
 * not suggest anything is wrong with the account.
 */
class QuietReKeyCommandsTest {
    private val email = "me@example.org"

    /** The account's keys as each run read them: salt and passes, in order. */
    private class Seen {
        val keys: MutableList<Pair<String, Long>> = Collections.synchronizedList(ArrayList())
        fun since(mark: Int) = synchronized(keys) { keys.drop(mark) }
    }

    private fun withPasses(e: JsonElement, ops: Long): JsonElement {
        val o = e.jsonObject
        val p = o.getValue("kdfParams").jsonObject
        return JsonObject(o + ("kdfParams" to JsonObject(p + ("ops" to JsonPrimitive(ops)))))
    }

    private fun lies(p: LyingProxy, seen: Seen, policyOps: Long) {
        p.lie = mapOf(
            WireRoute.CLIENT_POLICY to { e -> withPasses(e, policyOps) },
            WireRoute.ACCOUNT_KEYS to { e ->
                val o = e.jsonObject
                seen.keys += o.getValue("kdfSalt").jsonPrimitive.content to o.getValue("kdfParams").jsonObject.getValue("ops").jsonPrimitive.long
                e
            },
        )
    }

    /** Nothing about the re-key, and nothing secret, reaches the person. */
    private fun quiet(r: CliRun, what: String) {
        for (text in listOf(r.out, r.err)) {
            assertFalse(text.contains(Steps.PASSWORD), "$what: the password is never printed")
            for (word in listOf("re-key", "rekey", "ReKey", "kdf", "KDF", "Argon", "upgrade")) assertFalse(text.contains(word), "$what: nothing is said of the re-key: $text")
        }
    }

    @Test fun aRaisedPolicyIsFollowedOnceAfterAReopenAndAfterASignInAndTheOtherDevicesAreSignedOutOnce() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val tmp = Files.createTempDirectory("andvari-cli").toFile()
                val op = File(tmp, "operator")
                val me = File(tmp, "me")
                val other = File(tmp, "other")
                val third = File(tmp, "third")
                CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
                val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
                CliRun.run(s, me, "enrol", Steps.enrolLink(s, email), "--email", email, "--kit-out", File(tmp, "me-kit.txt").path, "--trust-card", card0).ok()
                CliRun.run(s, other, "sign-in", "--email", email, "--trust-card", card0).ok()
                val seen = Seen()
                lies(p, seen, policyOps = 3)
                val before = CliRun.run(s, me, "item", "list", "personal", dial = p.address).ok()

                // The policy asks for 4 passes. The next command re-keys after it reopens the saved session, once.
                lies(p, seen, policyOps = 4)
                var mark = seen.keys.size
                val first = CliRun.run(s, me, "item", "list", "personal", dial = p.address)
                assertEquals(0, first.code, first.out + first.err)
                assertEquals(before, first.out, "the person sees the same as before")
                quiet(first, "the re-keying run")
                val (oldSalt, oldOps) = seen.since(mark).first()
                assertEquals(3L, oldOps)
                mark = seen.keys.size
                val second = CliRun.run(s, me, "item", "list", "personal", dial = p.address)
                assertEquals(before, second.ok())
                quiet(second, "the run after it")
                val afterFirst = seen.since(mark)
                assertTrue(afterFirst.isNotEmpty())
                assertTrue(afterFirst.all { it.second == 4L }, "the account is at the policy's cost: $afterFirst")
                val newSalt = afterFirst.first().first
                assertNotEquals(oldSalt, newSalt, "under a fresh salt")
                assertTrue(afterFirst.all { it.first == newSalt }, "the run after the re-key sends no second one: $afterFirst")
                mark = seen.keys.size
                CliRun.run(s, me, "item", "list", "personal", dial = p.address).ok()
                assertTrue(seen.since(mark).all { it.first == newSalt }, "nor does the next")

                // The account's other device is signed out once, in the tool's own words for a session the server ended.
                val ended = CliRun.run(s, other, "item", "list", "personal")
                assertEquals(1, ended.code, ended.out + ended.err)
                assertTrue(ended.err.contains("ended this device's session") && ended.err.contains("andvari-cli sign-in"), ended.err)
                assertTrue(ended.err.contains("the master password was changed or its key settings were raised on another of your devices"), ended.err)
                for (alarm in listOf("compromis", "attack", "stolen", "breach", "someone", "suspicious", "SECURITY")) {
                    assertFalse(ended.err.contains(alarm, ignoreCase = true), "the words suggest nothing is wrong: $alarm in ${ended.err}")
                }
                assertFalse(ended.err.contains("Exception"), ended.err)
                CliRun.run(s, other, "sign-in", "--email", email, "--trust-card", card0).ok()
                assertEquals(before, CliRun.run(s, other, "item", "list", "personal").ok(), "signed in again, it goes on")

                // A sign-in with the password re-keys too: the policy asks for 5 passes, and a new device signs in.
                lies(p, seen, policyOps = 5)
                val signIn = CliRun.run(s, third, "sign-in", "--email", email, "--trust-card", card0, dial = p.address)
                assertEquals(0, signIn.code, signIn.out + signIn.err)
                quiet(signIn, "the sign-in")
                mark = seen.keys.size
                CliRun.run(s, third, "item", "list", "personal", dial = p.address).ok()
                val afterSignIn = seen.since(mark)
                assertTrue(afterSignIn.isNotEmpty() && afterSignIn.all { it.second == 5L }, "the sign-in raised it to the policy's cost: $afterSignIn")
                val thirdSalt = afterSignIn.first().first
                mark = seen.keys.size
                CliRun.run(s, third, "item", "list", "personal", dial = p.address).ok()
                assertTrue(seen.since(mark).all { it.first == thirdSalt }, "once")
                // The first device's session was ended by that change, once; signing in again goes on.
                val meEnded = CliRun.run(s, me, "item", "list", "personal", dial = p.address)
                assertEquals(1, meEnded.code, meEnded.out + meEnded.err)
                assertTrue(meEnded.err.contains("ended this device's session"), meEnded.err)
                CliRun.run(s, me, "sign-in", "--email", email, "--trust-card", card0, dial = p.address).ok()
                mark = seen.keys.size
                assertEquals(before, CliRun.run(s, me, "item", "list", "personal", dial = p.address).ok())
                assertTrue(seen.since(mark).all { it.first == thirdSalt && it.second == 5L }, "nothing more was re-keyed")
                tmp.deleteRecursively()
            }
        }
    }
}
