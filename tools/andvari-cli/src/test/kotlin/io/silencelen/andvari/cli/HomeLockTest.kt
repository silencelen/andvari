package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Await
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * One andvari-cli command at a time in a home ([HomeLock]): two shells in one home, as the two sequences an independent
 * check found, over the real server; and the lock against another process, alive and killed.
 */
class HomeLockTest {
    /** The master password, and a short wait for the home: the command that finds it held stops quickly. */
    private val shortWait: (String) -> String? = { when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; HomeLock.WAIT_ENV -> "300"; else -> null } }

    private fun records(home: File): Map<String, String?> {
        val h = CliHome(home)
        return listOf("state" to h.deviceState(), "secure" to h.secureState()).flatMap { (n, st) -> st.keys()!!.map { "$n:$it" to st.get(it) } }.toMap()
    }

    private fun savedUserId(home: File, origin: String, email: String): String? =
        CliHome(home).secureState().get("cli.session|$origin|$email")?.let { WireJson.json.parseToJsonElement(it).jsonObject["userId"]?.jsonPrimitive?.content }

    /**
     * A shell holds the earlier account's session (`sync`, stopped at the server's answer to its reopening) while another
     * shell runs `forget-earlier-account --yes` in the same home. Before, the second said "forgotten" and the first then
     * wrote the tie back when it ended: the forgetting was undone after it was said. Now the second waits, says that another
     * command is running in this home, and changes nothing; the first ends with the account kept as it was.
     */
    @Test fun aForgettingWaitsForAShellThatHoldsTheEarlierAccount() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = "two-shells@example.org"
                val a = w.account(me)
                val u = w.userId(me)
                s.advance(2 * 3_600_000L)
                val refused = w.run(a, "enrol", Steps.enrolLink(s, me), "--email", me, "--kit-out", File(w.tmp, "kit-2").path)
                assertEquals(1, refused.code, refused.out + refused.err)
                assertTrue(refused.err.contains("[$EARLIER_ACCOUNT_KNOWN]: "), refused.err)

                var second: CliRun? = null
                var before: Map<String, String?>? = null
                var after: Map<String, String?>? = null
                p.answer = mapOf(WireRoute.ACCOUNT_KEYS to { _, forward ->
                    if (second == null) {
                        before = records(a)
                        second = CliRun.run(s, a, "forget-earlier-account", "--email", me, "--yes", env = shortWait)
                        after = records(a)
                    }
                    val (status, text) = forward()
                    status to String(text)
                })
                val first = CliRun.run(s, a, "sync", dial = p.address, captureErr = false)
                p.answer = emptyMap()
                assertEquals(0, first.code, first.out)
                val f = assertNotNull(second, "the second shell ran while the first held the account")
                assertEquals(EXIT_HOME_BUSY, f.code, f.out + f.err)
                assertTrue(f.err.contains("[$KEY_HOME_BUSY]: " + fill(HOME_BUSY, a.path, "300 milliseconds")), f.err)
                assertEquals("", f.out, "nothing said forgotten")
                assertEquals(before, after, "the second shell changed nothing")
                assertEquals(u, savedUserId(a, s.origin, me), "the account stays kept, as the first shell ended it")
            }
        }
    }

    /**
     * A registration from this home whose check passed (the home kept nothing) is at the server while another shell signs
     * the earlier account in under the same address in that home; that account is then deleted and the registration made
     * under the address. Before, the second shell signed in, and the registration's session was then saved over the tie
     * it had made without a word (the commit's check is skipped where a session of the address is kept). Now the second
     * shell waits, says that another command is running, and changes nothing; the registration is kept as the only account.
     */
    @Test fun aSignInWaitsForARegistrationUnderWay() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = "commit@example.org"
                val elsewhere = w.account(me)
                val a = File(w.tmp, "a")
                s.advance(2 * 3_600_000L)
                val link = Steps.enrolLink(s)
                var second: CliRun? = null
                p.answer = mapOf(WireRoute.REGISTER to { _, forward ->
                    second = CliRun.run(s, a, "sign-in", "--email", me, "--trust-card", w.card0, env = shortWait)
                    w.run(elsewhere, "account", "delete", "--confirm-email", me).ok()
                    val (status, text) = forward()
                    status to String(text)
                })
                val first = CliRun.run(s, a, "enrol", link, "--email", me, "--kit-out", File(w.tmp, "kit-v").path, "--trust-card", w.card0,
                    dial = p.address, captureErr = false)
                p.answer = emptyMap()
                val b = assertNotNull(second, "the second shell ran while the registration was at the server")
                assertEquals(EXIT_HOME_BUSY, b.code, b.out + b.err)
                assertTrue(b.err.contains("[$KEY_HOME_BUSY]: "), b.err)
                assertEquals(0, first.code, first.out)
                assertEquals(w.userId(me), savedUserId(a, s.origin, me), "the account made is the one kept")
            }
        }
    }

    /**
     * The lock against another process: a real andvari-cli process holds the home (a sign-in waiting for its password on
     * standard input). A command in this process waits the time asked and then stops, changing nothing. The holder is
     * killed: the system drops its lock, and the same command goes through at once (with no wait at all).
     */
    @Test fun anotherProcessHoldsTheHomeAndALockLeftByAKilledOneDoesNotBlock() {
        val home = Files.createTempDirectory("andvari-cli-lock").toFile()
        val origin = "http://127.0.0.1:9"
        val me = "lock@example.org"
        CliHome(home).deviceState().set("${Ctx.K_EMAIL}|$origin", me)
        val java = File(System.getProperty("java.home"), "bin/java").path
        val err = File(home.parentFile, "${home.name}.holder-err")
        val pb = ProcessBuilder(listOf(java, "-cp", System.getProperty("andvari.cli.runtimeClasspath")!!, "io.silencelen.andvari.cli.MainKt",
            "--home", home.path, "--origin", origin, "sign-in", "--email", me)).redirectError(err).redirectOutput(ProcessBuilder.Redirect.DISCARD)
        pb.environment().remove("ANDVARI_PASSWORD")
        pb.environment().remove(HomeLock.WAIT_ENV)
        val holder = pb.start()
        try {
            Await.until("the other process waiting for its password", 60_000, { err.readText() }) { err.readText().takeIf { it.contains("Master password") } }
            val started = System.nanoTime()
            val busy = tool(home, origin, "sign-out", "--email", me, wait = "500")
            val waited = (System.nanoTime() - started) / 1_000_000
            assertEquals(EXIT_HOME_BUSY, busy.code, busy.out + busy.err)
            assertTrue(busy.err.contains("[$KEY_HOME_BUSY]: " + fill(HOME_BUSY, home.path, "500 milliseconds")), busy.err)
            assertTrue(waited in 500..10_000, "waited $waited ms")
            assertEquals(me, CliHome(home).deviceState().get("${Ctx.K_EMAIL}|$origin"), "nothing changed")
        } finally {
            holder.destroyForcibly()
            holder.waitFor(60, TimeUnit.SECONDS)
        }
        val done = tool(home, origin, "sign-out", "--email", me, wait = "0")
        assertEquals(0, done.code, done.out + done.err)
        assertTrue(done.out.contains("signed out"), done.out)
        assertNull(CliHome(home).deviceState().get("${Ctx.K_EMAIL}|$origin"))
    }

    /** The tool in this process on [home], with no server: [wait] as the home's wait. */
    private fun tool(home: File, origin: String, vararg args: String, wait: String): CliRun {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val old = System.err
        System.setErr(PrintStream(err, true))
        val code = try {
            Cli.runWith(listOf("--home", home.path, "--origin", origin) + args, PrintStream(out, true), { if (it == HomeLock.WAIT_ENV) wait else null },
                { null }, System::currentTimeMillis, null)
        } finally {
            System.setErr(old)
        }
        return CliRun(code, out.toString(), err.toString())
    }
}
