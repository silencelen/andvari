package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Await
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.server.queryOne
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A device link whose pickup the server took while another run kept another account on the joining home: the server has
 * already added the device to the account. The tool does not keep the session, ends it there, and says that the device is
 * listed and how to remove it; never "nothing was linked". Over the real server.
 */
class LinkPickupRaceTest {
    private fun count(s: TestServer, sql: String, vararg args: Any): Long = s.services.db.read { c -> c.queryOne(sql, *args) { it.getLong(1) } } ?: 0L

    private fun await(buf: ByteArrayOutputStream, re: Regex): String =
        Await.until("a line matching ${re.pattern}", 120_000, { "so far: $buf" }) { re.find(buf.toString())?.groupValues?.get(1) }

    @Test fun aPickupTakenWhileAnotherAccountWasKeptHereSaysTheDeviceIsListedAndHowToRemoveIt() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                w.account("bo@example.org")
                val meId = w.userId("me@example.org")
                val d = File(w.tmp, "d")
                val devicesBefore = count(s, "SELECT COUNT(*) FROM devices WHERE userId=? AND revokedAt IS NULL", meId)
                // While the pickup is at the server, the joining home starts keeping bo: from outside the lock a command
                // holds on its home (another run of the tool now waits for it, HomeLockTest).
                NotKeptAfterCommitTest.boKeptMeanwhile(p, s, w, WireRoute.DEVICE_LINK_PICKUP, d)
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
                val r = try {
                    val show = pool.submit<CliRun> { CliRun.run(s, me, "link-device", "show", env = shownEnv, out = shown, captureErr = false) }
                    val url = await(shown, Regex("(?m)^(\\S+://\\S+)$"))
                    val linkFile = File(w.tmp, "device-link.txt").also { it.writeText(url) }
                    val joining = pool.submit<CliRun> {
                        CliRun.run(s, d, "link-device", "--link-file", linkFile.path, "--trust-card", w.card0, origin = null, out = joined, dial = p.address)
                    }
                    joining.get(5, TimeUnit.MINUTES).also { show.get(5, TimeUnit.MINUTES) }
                } finally {
                    pool.shutdownNow()
                }
                p.answer = emptyMap()
                assertEquals(1, r.code, r.out + r.err)

                // What the server holds: the device was added to me's account, and its session there is ended.
                assertEquals(devicesBefore + 1, count(s, "SELECT COUNT(*) FROM devices WHERE userId=? AND revokedAt IS NULL", meId))
                val device = s.services.db.read { c ->
                    c.queryOne("SELECT deviceId FROM devices WHERE userId=? AND how='linked' AND revokedAt IS NULL", meId) { it.getString(1) }
                }!!
                assertEquals(0L, count(s, "SELECT COUNT(*) FROM sessions WHERE deviceId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL", device))
                assertTrue(r.err.contains("[$KEY_LINK_ADDED_NOT_KEPT]: " + fill(LINK_ADDED_NOT_KEPT, s.origin, "me@example.org", device, "bo@example.org")), r.err)
                assertFalse(r.err.contains("nothing was linked", ignoreCase = true), r.err)

                // The way out it names works, and the joining home keeps bo as it was.
                w.run(me, "account", "revoke-device", device).ok()
                assertEquals(devicesBefore, count(s, "SELECT COUNT(*) FROM devices WHERE userId=? AND revokedAt IS NULL", meId))
                w.run(d, "item", "list", "personal", "--email", "bo@example.org").ok()
            }
        }
    }
}
