package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Await
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.server.queryOne
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A session the tool refuses after the server opened it is ended at the server by its own refresh token
 * (`POST /auth/end-session`), and no other session: never the logout, which ends every session of the device there. And a
 * recovery of an account on a home that keeps another account at that server stops before anything is sent, so the
 * person's kit and any request for help stay as they were. Each against the real server, counting the account's live
 * sessions there before and after.
 */
class RefusedSessionEndsAloneTest {
    private val endSession = "POST /api/v1/auth/end-session"
    private val logout = "POST /api/v1/auth/logout"
    private val newPassword = "a new Password after the kit 7"

    /** The sessions of [email]'s account the server still takes: not ended, and not given up for a newer one by a refresh. */
    private fun live(s: TestServer, email: String): Long = s.services.db.read { c ->
        c.queryOne(
            "SELECT COUNT(*) FROM sessions se JOIN users u ON u.userId = se.userId " +
                "WHERE u.email=? AND se.revokedAt IS NULL AND se.refreshConsumedAt IS NULL", email,
        ) { it.getLong(1) }
    } ?: 0L

    /** [b64] with one character changed, still well formed: what it seals no longer opens. */
    private fun changed(b64: String): String = b64.substring(0, 20) + (if (b64[20] == 'A') "B" else "A") + b64.substring(21)

    /** What [p] passed since [mark]: exactly one end of a session, and never a logout. */
    private fun endedOneAlone(p: LyingProxy, mark: Int) {
        val sent = p.seen.drop(mark)
        assertEquals(1, sent.count { it.startsWith(endSession) }, "the refused session ended by its own token: $sent")
        assertTrue(sent.none { it.startsWith(logout) }, "no logout of the device: $sent")
    }

    /** A sign-in whose answer this device refuses (its key does not open under the password): that session alone ends. */
    @Test fun aSignInTheToolRefusesEndsThatSessionAndTheAccountsOtherSessionLives() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val before = live(s, "me@example.org")
                assertEquals(1L, before, "the session kept on the first home")
                p.lie = mapOf(WireRoute.LOGIN to { e: JsonElement ->
                    val o = e.jsonObject
                    val keys = o.getValue("accountKeys").jsonObject
                    JsonObject(o + ("accountKeys" to JsonObject(keys + ("wrappedUvk" to JsonPrimitive(changed(keys.getValue("wrappedUvk").jsonPrimitive.content))))))
                })
                val mark = p.seen.size
                val r = w.run(File(w.tmp, "second"), "sign-in", "--email", "me@example.org", "--trust-card", w.card0, dial = p.address)
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("SECURITY") && r.err.contains("uvk_unopenable"), r.err)
                assertTrue(p.seen.drop(mark).any { it.startsWith("POST /api/v1/auth/login") }, "the sign-in was answered: ${p.seen.drop(mark)}")
                endedOneAlone(p, mark)
                assertEquals(before, live(s, "me@example.org"), "the refused session is not live, the first home's still is")
                assertTrue(w.run(me, "whoami").ok().isNotEmpty())
                w.run(me, "item", "list", "personal").ok()
            }
        }
    }

    /**
     * A device link whose pickup this device refuses (the answer names a role the engine does not know): the session the
     * pickup opened ends alone, by its own token, through the shared flow.
     */
    @Test fun aDeviceLinkPickupTheToolRefusesEndsThatSessionAlone() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val before = live(s, "me@example.org")
                p.lie = mapOf(WireRoute.DEVICE_LINK_PICKUP to { e: JsonElement ->
                    val o = e.jsonObject
                    JsonObject(o + ("session" to JsonObject(o.getValue("session").jsonObject + ("role" to JsonPrimitive("admin")))))
                })
                val mark = p.seen.size
                val r = link(w, p, me, "new")
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("identity_mismatch"), r.err)
                assertTrue(p.seen.drop(mark).any { it.endsWith("/pickup") }, "the pickup was answered: ${p.seen.drop(mark)}")
                endedOneAlone(p, mark)
                assertEquals(before, live(s, "me@example.org"), "the pickup's session is not live, the showing home's still is")
                w.run(me, "item", "list", "personal").ok()
            }
        }
    }

    /**
     * A kit recovery whose answer this device refuses after the server committed it (a recovery piece id that is none):
     * the server ended the account's other sessions with the commit, as every recovery does, and the session it opened
     * for this device ends too, by its own token. Nothing of the account stays live.
     */
    @Test fun aKitRecoveryTheToolRefusesAfterTheCommitEndsTheSessionItOpened() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                w.account("me@example.org")
                assertEquals(1L, live(s, "me@example.org"))
                p.lie = mapOf(WireRoute.RECOVERY_SELF_COMMIT to { e: JsonElement -> JsonObject(e.jsonObject + ("recoveryPieceId" to JsonPrimitive("x"))) })
                val mark = p.seen.size
                val r = w.run(File(w.tmp, "lost"), "recover", "kit", "--kit-file", w.kit("me@example.org").path, "--kit-out", File(w.tmp, "new-kit.txt").path,
                    origin = null, dial = p.address, env = { if (it == "ANDVARI_PASSWORD") newPassword else null })
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("bad_response"), r.err)
                assertTrue(p.seen.drop(mark).any { it.startsWith("POST /api/v1/recovery/self/commit") }, "the commit was answered")
                endedOneAlone(p, mark)
                assertEquals(0L, live(s, "me@example.org"), "the session the commit opened ended; the commit ended the others")
            }
        }
    }

    /**
     * A recovery of another account on a home that keeps one at that server (also the operator's own home): stopped
     * before anything is dialed, said as what it is; the account kept and the one asked for keep their sessions, and the
     * other account's kit still works afterwards. The account's own kit on its own home is not stopped.
     */
    @Test fun aRecoveryOfAnotherAccountOnAHomeThatKeepsOneStopsBeforeAnythingIsSent() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            w.account("bo@example.org")
            val liveMe = live(s, "me@example.org")
            val liveBo = live(s, "bo@example.org")
            val liveOp = live(s, "op@example.org")
            val boKit = w.kit("bo@example.org")
            val pw: (String) -> String? = { if (it == "ANDVARI_PASSWORD") newPassword else null }
            // On the operator's home the sentence says it is the operator's account, and that the way on is another home.
            for ((home, said) in listOf(
                me to "[$KEY_ANOTHER_ACCOUNT_KEPT]: " + fill(ANOTHER_ACCOUNT_KEPT, s.origin, "me@example.org", ACT_RECOVERY),
                w.op to "[$KEY_OPERATOR_ACCOUNT_HELD]: " + fill(OPERATOR_ACCOUNT_HELD, s.origin, "op@example.org", ACT_RECOVERY),
            )) {
                ConnectionCounter().use { counter ->
                    val newKit = File(w.tmp, "bo-new-${home.name}.txt")
                    val r = w.run(home, "recover", "kit", "--kit-file", boKit.path, "--kit-out", newKit.path, origin = null, dial = counter.address, env = pw)
                    assertEquals(1, r.code, r.out + r.err)
                    assertTrue(r.err.contains(said), r.err)
                    assertEquals(0, counter.settled(), "nothing dialed on ${home.name}'s home")
                    assertFalse(newKit.exists())
                }
            }
            ConnectionCounter().use { counter ->
                val r = w.run(me, "recover", "assist", "--email", "bo@example.org", "--trust-card", w.card0, dial = counter.address)
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains(fill(ANOTHER_ACCOUNT_KEPT, s.origin, "me@example.org", ACT_RECOVERY)), r.err)
                assertEquals(0, counter.settled(), "nothing dialed for the request")
            }
            assertEquals(liveMe, live(s, "me@example.org"))
            assertEquals(liveBo, live(s, "bo@example.org"))
            assertEquals(liveOp, live(s, "op@example.org"))
            w.run(me, "item", "list", "personal").ok()

            // The kit that was not used still works, on a home that keeps no other account.
            val recovered = w.run(File(w.tmp, "fresh"), "recover", "kit", "--kit-file", boKit.path, "--kit-out", File(w.tmp, "bo-new.txt").path, origin = null, env = pw)
            assertEquals(0, recovered.code, recovered.out + recovered.err)
            assertTrue(recovered.out.contains("recovered: bo@example.org"), recovered.out)
            // The account's own kit on the home that keeps it is not stopped.
            val own = w.run(me, "recover", "kit", "--kit-file", w.kit("me@example.org").path, "--kit-out", File(w.tmp, "me-new.txt").path, origin = null, env = pw)
            assertEquals(0, own.code, own.out + own.err)
            assertTrue(own.out.contains("recovered: me@example.org"), own.out)
        }
    }

    private fun await(buf: ByteArrayOutputStream, re: Regex): String =
        Await.until("a line matching ${re.pattern} from the other process", 120_000, { "its output so far: $buf" }) {
            re.find(buf.toString())?.groupValues?.get(1)
        }

    /** `link-device show` on [me], and `link-device` on a new device [name] whose requests go through [p]: the new device's run. */
    private fun link(w: CliWorld, p: LyingProxy, me: File, name: String): CliRun {
        val shown = ByteArrayOutputStream()
        val joined = ByteArrayOutputStream()
        val shownEnv: (String) -> String? = { n ->
            when (n) {
                "ANDVARI_PASSWORD" -> Steps.PASSWORD
                "ANDVARI_DEVICE_CODE" -> await(joined, Regex("Type this code on your other device: ([0-9 ]+)"))
                else -> null
            }
        }
        val pool = Executors.newFixedThreadPool(2)
        try {
            val show = pool.submit<CliRun> { CliRun.run(w.s, me, "link-device", "show", env = shownEnv, out = shown, captureErr = false) }
            val url = await(shown, Regex("(?m)^(\\S+://\\S+)$"))
            val linkFile = File(w.tmp, "device-link-$name.txt").also { it.writeText(url) }
            val joining = pool.submit<CliRun> {
                CliRun.run(w.s, File(w.tmp, name), "link-device", "--link-file", linkFile.path, "--trust-card", w.card0, origin = null, out = joined, dial = p.address)
            }
            val r = joining.get(5, TimeUnit.MINUTES)
            assertTrue(show.get(5, TimeUnit.MINUTES).out.contains("approved"), "the other device approved the link")
            return r
        } finally {
            pool.shutdownNow()
        }
    }
}
