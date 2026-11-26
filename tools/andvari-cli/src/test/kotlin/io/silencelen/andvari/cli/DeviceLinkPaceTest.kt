package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Await
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A device link at a person's pace, with the tool on both sides against the real server and the new device's requests
 * through a proxy that times them. Both sides ask every two seconds; the server lets one address make 60 of the new
 * device's checks a minute, so a person who takes three minutes to type the code is never refused. When the server does
 * refuse such a check as too many (another device asking from the same address at the same time), the link stops, and
 * the tool says that, with the server's wait: never that the server cannot be reached.
 */
class DeviceLinkPaceTest {
    private fun await(buf: ByteArrayOutputStream, re: Regex, ms: Long = 120_000): String =
        Await.until("a line matching ${re.pattern} from the other process", ms, { "its output so far: $buf" }) {
            re.find(buf.toString())?.groupValues?.get(1)
        }

    /**
     * `link-device show` on [me], whose person types the code after [typing] returns, and `link-device` on a new device
     * through [p]: both runs, the new device's first.
     */
    private fun link(w: CliWorld, p: LyingProxy, me: File, showDial: String? = null, typing: () -> Unit): Pair<CliRun, CliRun> {
        val shown = ByteArrayOutputStream()
        val joined = ByteArrayOutputStream()
        val shownEnv: (String) -> String? = { n ->
            when (n) {
                "ANDVARI_PASSWORD" -> Steps.PASSWORD
                "ANDVARI_DEVICE_CODE" -> await(joined, Regex("Type this code on your other device: ([0-9 ]+)")).also { typing() }
                else -> null
            }
        }
        val pool = Executors.newFixedThreadPool(2)
        val slow = SlowRunReport("paced link", {
            "-- the showing device's output:\n$shown\n-- the new device's output:\n$joined\n-- what the proxy passed:\n" + synchronized(p.timed) { p.timed.joinToString("\n") }
        }, listOf(260_000, 320_000))
        try {
            val show = pool.submit<CliRun> { CliRun.run(w.s, me, "link-device", "show", env = shownEnv, out = shown, captureErr = false, dial = showDial) }
            val url = await(shown, Regex("(?m)^(\\S+://\\S+)$"))
            val linkFile = File(w.tmp, "device-link-paced.txt").also { it.writeText(url) }
            val joining = pool.submit<CliRun> {
                CliRun.run(w.s, File(w.tmp, "new"), "link-device", "--link-file", linkFile.path, "--trust-card", w.card0, origin = null,
                    out = joined, dial = p.address)
            }
            val n = joining.get(6, TimeUnit.MINUTES)
            return n to show.get(6, TimeUnit.MINUTES)
        } finally {
            slow.close()
            pool.shutdownNow()
        }
    }

    /**
     * The person types the code three minutes after it is shown, while the server's clock follows the real one: every
     * check of the new device is answered, none is refused as too many, and the link finishes.
     */
    @Test fun anApprovalAfterThreeMinutesIsNeverRefusedAsTooMany() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                // The server's clock moves with the real one while the link waits, as a server's does.
                val ticking = Thread {
                    try { while (true) { Thread.sleep(1000); s.advance(1000) } } catch (e: InterruptedException) { }
                }.apply { isDaemon = true; start() }
                val (n, e) = try {
                    link(w, p, me) { Thread.sleep(180_000) }
                } finally {
                    ticking.interrupt()
                }
                assertEquals(0, n.code, n.out + n.err)
                assertTrue(n.out.contains("linked: this device is"), n.out)
                assertTrue(e.out.contains("approved"), e.out)
                val polls = synchronized(p.timed) { p.timed.filter { it.contains("/poll ") } }
                assertTrue(polls.size >= 80, "the new device kept asking every two seconds: ${polls.size}")
                assertTrue(synchronized(p.timed) { p.timed.none { it.endsWith("-> 429") } }, "nothing refused as too many: ${p.timed}")
            }
        }
    }

    /**
     * The device that shows the link waits for the new device's reveal at the same pace as for its claim: here the new
     * device's check after the nonce is slow (the proxy holds it ten seconds), and the showing device asks for the link's
     * view every two seconds meanwhile, never as fast as it can (it used to, and spent its views of a minute in a second
     * or two: the server refused the rest, and the link stopped before anyone could approve it).
     */
    @Test fun theShowingDeviceWaitsForTheRevealAtAPersonsPace() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                LyingProxy(s).use { shows ->
                    val w = CliWorld(s)
                    val me = w.account("me@example.org")
                    val polls = java.util.concurrent.atomic.AtomicInteger()
                    p.answer = mapOf(io.silencelen.andvari.core.model.wire.WireRoute.DEVICE_LINK_POLL to { _, forward ->
                        // The second check is the first one after the showing device's nonce can be there: held ten seconds.
                        if (polls.incrementAndGet() == 2) Thread.sleep(10_000)
                        forward().let { (status, text) -> status to String(text) }
                    })
                    val (n, e) = link(w, p, me, showDial = shows.address) { }
                    assertEquals(0, n.code, n.out + n.err)
                    assertTrue(e.out.contains("approved"), e.out + e.err)
                    val views = synchronized(shows.timed) { shows.timed.filter { it.contains(" GET /api/v1/device-links/") } }
                    assertTrue(views.size <= 15, "the showing device asked every two seconds, not as fast as it could: ${views.size} views\n$views")
                    assertTrue(synchronized(shows.timed) { shows.timed.none { it.endsWith("-> 429") } }, "${shows.timed}")
                }
            }
        }
    }

    /**
     * The new device's checks refused as too many from its address (here the address's 60 a minute are used up by other
     * requests while the person reads the code): a check can wait, so the link waits the time the server named, within
     * its own time, and the tool says that it waits, with that time; once it has passed, the link goes on and finishes.
     * Never "cannot be reached", and never a stop (it used to stop the link, said as too many).
     */
    @Test fun aCheckRefusedAsTooManyWaitsTheServersTimeAndSaysSo() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build()
                var waits: String? = null
                val (n, e) = link(w, p, me) {
                    val linkId = synchronized(p.seen) { p.seen.firstNotNullOf { Regex("/device-links/([^/?]+)/poll").find(it)?.groupValues?.get(1) } }
                    for (i in 1..80) {
                        val r = http.send(HttpRequest.newBuilder(URI.create("${s.origin}/api/v1/device-links/$linkId/poll"))
                            .POST(HttpRequest.BodyPublishers.ofString("{}")).header("Content-Type", "application/json").build(),
                            HttpResponse.BodyHandlers.ofString())
                        if (r.statusCode() == 429) { waits = r.headers().firstValue("Retry-After").orElse("?"); break }
                    }
                    Await.until("the new device's next check to be refused", 60_000, { "the proxy: ${p.timed}" }) {
                        synchronized(p.timed) { p.timed.lastOrNull()?.takeIf { it.endsWith("-> 429") } }
                    }
                    // The time the server named passes, on the clock the server and both devices go by.
                    val named = synchronized(p.retryAfters) { p.retryAfters.last { it.first.contains("/poll") }.second.trim().toLong() }
                    s.advance((named + 1) * 1000)
                    Unit
                }
                assertNotNull(waits, "the address's checks were used up")
                val named = synchronized(p.retryAfters) { p.retryAfters.first { it.first.contains("/poll") }.second.trim().toLong() }
                assertEquals(0, n.code, n.out + n.err)
                assertTrue(n.out.contains("linked: this device is"), n.out)
                assertTrue(e.out.contains("approved"), e.out)
                assertTrue(n.err.contains(fill(LINK_WAITS, s.origin, seconds(named))), n.err)
                assertFalse(n.err.contains("be reached") || n.err.contains(KEY_LINK_TOO_MANY), n.err)
            }
        }
    }

    /**
     * The approval refused as too many (made here by the proxy in front of the showing device, with the server's own
     * envelope and a wait): a step that cannot wait, so the link stops, and the showing device says so with the wait it
     * was given and how to go on from there; never the bare code, never "cannot be reached".
     */
    @Test fun anApprovalRefusedAsTooManyStopsTheLinkWithTheServersWait() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                LyingProxy(s).use { shows ->
                    val w = CliWorld(s)
                    val me = w.account("me@example.org")
                    shows.answer = mapOf(io.silencelen.andvari.core.model.wire.WireRoute.DEVICE_LINK_APPROVE to { _, _ ->
                        429 to """{"error":"rate_limited","message":"too many"}"""
                    })
                    val shown = ByteArrayOutputStream()
                    val joined = ByteArrayOutputStream()
                    val shownEnv: (String) -> String? = { k ->
                        when (k) {
                            "ANDVARI_PASSWORD" -> Steps.PASSWORD
                            "ANDVARI_DEVICE_CODE" -> await(joined, Regex("Type this code on your other device: ([0-9 ]+)"))
                            else -> null
                        }
                    }
                    val pool = Executors.newFixedThreadPool(2)
                    try {
                        val show = pool.submit<CliRun> { CliRun.run(w.s, me, "link-device", "show", env = shownEnv, out = shown, dial = shows.address) }
                        val url = await(shown, Regex("(?m)^(\\S+://\\S+)$"))
                        val linkFile = File(w.tmp, "device-link-approve.txt").also { it.writeText(url) }
                        pool.submit<CliRun> {
                            CliRun.run(w.s, File(w.tmp, "new"), "link-device", "--link-file", linkFile.path, "--trust-card", w.card0, origin = null,
                                out = joined, captureErr = false, dial = p.address)
                        }
                        val r = show.get(4, TimeUnit.MINUTES)
                        assertEquals(1, r.code, r.out + r.err)
                        assertTrue(r.err.contains("[$KEY_LINK_TOO_MANY]: " + fill(LINK_TOO_MANY_SHOWN, s.origin, WAIT_UNNAMED)), r.err)
                        assertFalse(r.err.contains("be reached") || r.err.contains("stopped: rate_limited"), r.err)
                    } finally {
                        pool.shutdownNow()
                    }
                }
            }
        }
    }
}
