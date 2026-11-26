package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Await
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.server.queryOne
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Another account under an address this home knows, on the roads the check of the address's record reached only by
 * reading: the recovery with the operator's help (at the pickup, and at the commit's own take), and a device link after
 * a sign-out. Over the real server, the operator's side run as an operator runs it.
 */
class AnotherAccountRoadsTest {
    private val crypto = createCryptoProvider()
    private val recoverySeed = crypto.randomBytes(32)
    private val newPw = "recovered by the operator 4711"
    private fun pw(p: String): (String) -> String? = { if (it == "ANDVARI_PASSWORD") p else null }
    private val email = "roads@example.org"

    private fun server() = TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(crypto.boxKeypairFromSeed(recoverySeed).publicKey)))

    /** [email] made on [home] and signed in there, with operator recovery on; answers (its user id, its kit's account id). */
    private fun made(w: CliWorld, home: File, kit: File): Pair<String, String> {
        w.s.advance(2 * 3_600_000L)
        w.run(home, "enrol", Steps.enrolLink(w.s, email), "--email", email, "--kit-out", kit.path, "--trust-card", w.card0).ok()
        w.run(home, "sign-in", "--trust-card", w.card0).ok()
        assertTrue(w.run(home, "recovery", "operator", "--i-understand").ok().contains("recovery: operator"))
        val accountId = Regex("account ([0-9a-f]{32})").find(kit.readLines().first())!!.groupValues[1]
        return w.userId(email) to accountId
    }

    /** A request for help made on [d], answered by the operator after its hold for the account of [accountId]. */
    private fun answered(w: CliWorld, d: File, accountId: String) {
        val s = w.s
        val seen = Steps.mailCount(s, email, "recovery_request_code")
        val asked = w.run(d, "recover", "assist", "--email", email, "--trust-card", w.card0, env = pw(newPw),
            stdin = { Steps.awaitCode(s, email, "recovery_request_code", seen) })
        assertEquals(0, asked.code, asked.out + asked.err)
        val requestCode = Regex("request code: ([A-Za-z0-9 -]+?)\\s{3}").find(asked.out)!!.groupValues[1].trim()
        s.advance(7 * 86_400_000L + 60_000)
        val listed = w.run(w.op, "operator", "recovery-requests").ok()
        val m = Regex("^(\\S+)\\s+for ${Regex.escape(email)}\\s+request key (\\S+)\\s+user (\\S+)", RegexOption.MULTILINE).find(listed)!!
        val (requestId, rPub, userId) = m.destructured
        val escrow = File(w.tmp, "escrow-${d.name}.json")
        w.run(w.op, "operator", "escrow", email, "--out", escrow.path).ok()
        val instanceId = s.setup["instanceId"]!!.toString().trim('"')
        val assistOut = s.recoveryCli(
            listOf("assist", "--instance", instanceId, "--request", requestId, "--request-key", rPub, "--request-code", requestCode,
                "--email", email, "--user", userId, "--identity-fp", accountId, "--identity-file", escrow.path),
            Bytes.toB64(recoverySeed) + "\n" + "RECOVER ${userId.take(8)}\n",
        )
        val sealed = File(w.tmp, "answer-${d.name}.txt").apply { writeText(assistOut) }
        w.run(w.op, "operator", "fulfil", requestId, "--sealed-file", sealed.path).ok()
    }

    private fun liveSessions(s: TestServer, userId: String): Long = s.services.db.read { c ->
        c.queryOne("SELECT COUNT(*) FROM sessions WHERE userId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL AND refreshExpiresAt>?",
            userId, s.now()) { it.getLong(1) }
    } ?: 0L

    /**
     * The home keeps the address's record of U after a sign-out; U is deleted and made again elsewhere as V, and the
     * operator answers V's request made on this home: the pickup is refused with both possibilities and the offer, and
     * nothing is committed (V's password still opens V, no kit is written).
     */
    @Test fun theOperatorsHelpForAnotherAccountUnderAKnownAddressIsRefusedAtThePickup() {
        server().use { s ->
            val w = CliWorld(s)
            val first = File(w.tmp, "first")
            val (u, _) = made(w, first, File(w.tmp, "kit-u"))
            val d = File(w.tmp, "d")
            w.run(d, "sign-in", "--email", email, "--trust-card", w.card0).ok()
            w.run(d, "sign-out", "--email", email).ok()
            assertEquals(u, CliHome(d).deviceState().get("${Host.CLI_ADDRESS}${s.origin}|$email"))
            w.run(first, "account", "delete", "--confirm-email", email).ok()
            val (v, accountId) = made(w, File(w.tmp, "remade"), File(w.tmp, "kit-v"))
            assertTrue(u != v)

            answered(w, d, accountId)
            val kit = File(w.tmp, "kit-new")
            val r = w.run(d, "recover", "assist", "--account-id", accountId, "--kit-out", kit.path, env = pw(newPw))
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED, s.origin, email, ACT_RECOVERY)), r.err)
            assertFalse(kit.exists(), "nothing committed: no kit")
            assertNull(CliHome(d).secureState().get("cli.session|${s.origin}|$email"), "no session kept")
            assertEquals(u, CliHome(d).deviceState().get("${Host.CLI_ADDRESS}${s.origin}|$email"), "the record is as it was")
            w.run(File(w.tmp, "check"), "sign-in", "--email", email, "--trust-card", w.card0).ok()
        }
    }

    /**
     * The pickup passes (this home knows nothing of the address), and the record of another account under the address is
     * written meanwhile by a writer outside the tool's lock (the proxy, when the server has taken the commit): the commit's
     * own take refuses the session. The recovery went through, the kit is kept, no session is kept and the server's session
     * is ended, the record is as the other writer left it.
     */
    @Test fun theOperatorsCommitMeetingARecordOfAnotherAccountKeepsNoSession() {
        server().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val (v, accountId) = made(w, File(w.tmp, "owner"), File(w.tmp, "kit-v"))
                val d = File(w.tmp, "d")
                answered(w, d, accountId)
                val record = "${Host.CLI_ADDRESS}${s.origin}|$email"
                val other = "00000000-0000-4000-8000-000000000001"
                p.answer = mapOf(WireRoute.RECOVERY_REQUEST_COMMIT to { _, forward ->
                    val (status, text) = forward()
                    assertEquals(200, status, "the server took the commit")
                    CliHome(d).deviceState().set(record, other)
                    status to String(text)
                })
                val before = liveSessions(s, v)
                val kit = File(w.tmp, "kit-new")
                val r = w.run(d, "recover", "assist", "--account-id", accountId, "--kit-out", kit.path, env = pw(newPw), dial = p.address)
                p.answer = emptyMap()
                println("the commit's take: ${r.err}")
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_COMMITTED_NOT_KEPT]: "), r.err)
                assertTrue(r.err.contains(fill(NOT_KEPT_EARLIER, email)) && !r.err.contains(EARLIER_ACCOUNT_KNOWN + "."), "the reason in words: ${r.err}")
                assertTrue(kit.exists(), "the kit is kept")
                assertNull(CliHome(d).secureState().get("cli.session|${s.origin}|$email"), "no session kept")
                assertEquals(other, CliHome(d).deviceState().get(record))
                assertTrue(liveSessions(s, v) <= before, "the session the commit opened is ended")
            }
        }
    }

    /**
     * The home signed out of U (the record stays); U is deleted and made again elsewhere as V, whose device shows a link
     * this home joins: refused before the pickup with the link's own sentence and the offer; V keeps one device.
     */
    @Test fun aDeviceLinkUnderAnAddressRecordedAsAnotherAccountAfterASignOutIsRefused() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val a = File(w.tmp, "a")
            w.s.advance(2 * 3_600_000L)
            w.run(a, "enrol", Steps.enrolLink(s, email), "--email", email, "--kit-out", File(w.tmp, "kit-u").path, "--trust-card", w.card0).ok()
            w.run(a, "sign-in", "--trust-card", w.card0).ok()
            w.run(a, "sign-out", "--email", email).ok()
            val b = File(w.tmp, "elsewhere")
            w.run(b, "sign-in", "--email", email, "--trust-card", w.card0).ok()
            w.run(b, "account", "delete", "--confirm-email", email).ok()
            val c = File(w.tmp, "c")
            s.advance(2 * 3_600_000L)
            w.run(c, "enrol", Steps.enrolLink(s, email), "--email", email, "--kit-out", File(w.tmp, "kit-v").path, "--trust-card", w.card0).ok()
            w.run(c, "sign-in", "--trust-card", w.card0).ok()
            val v = w.userId(email)
            fun devices() = s.services.db.read { conn -> conn.queryOne("SELECT COUNT(*) FROM devices WHERE userId=?", v) { it.getLong(1) } } ?: 0L
            val devicesBefore = devices()

            val r = link(w, c, a)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED_LINK, s.origin, email, ACT_LINK)), r.err)
            assertNull(CliHome(a).secureState().get("cli.session|${s.origin}|$email"), "nothing kept")
            assertEquals(devicesBefore, devices(), "nothing was picked up")
        }
    }

    private fun await(buf: ByteArrayOutputStream, re: Regex): String =
        Await.until("a line matching ${re.pattern}", 120_000, { "so far: $buf" }) { re.find(buf.toString())?.groupValues?.get(1) }

    /** `link-device show` on [shows] and `link-device` on [joins]: the joining run. */
    private fun link(w: CliWorld, shows: File, joins: File): CliRun {
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
            val show = pool.submit<CliRun> { CliRun.run(w.s, shows, "link-device", "show", env = shownEnv, out = shown, captureErr = false) }
            val url = await(shown, Regex("(?m)^(\\S+://\\S+)$"))
            val linkFile = File(w.tmp, "device-link-${joins.name}.txt").also { it.writeText(url) }
            val joining = pool.submit<CliRun> { CliRun.run(w.s, joins, "link-device", "--link-file", linkFile.path, "--trust-card", w.card0, origin = null, out = joined) }
            val r = joining.get(5, TimeUnit.MINUTES)
            show.get(5, TimeUnit.MINUTES)
            return r
        } finally {
            pool.shutdownNow()
        }
    }
}
