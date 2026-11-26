package io.silencelen.andvari.server

import io.silencelen.andvari.server.BackupFixture.Server
import io.silencelen.andvari.server.BackupFixture.process
import io.silencelen.andvari.server.BackupFixture.server
import io.silencelen.andvari.server.BackupFixture.startServer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A run of `andvari admin backup` that works prints nothing, whatever the settings file says; the settings warnings
 * belong to the server's start, which prints each of them as before (decided on 2026-11-22). Over the real path: the
 * server's real start and the real command, each in a process of its own, with a settings file outside test mode that
 * has a plain-http origin and a variable no setting has. Not real: the classes and libraries come from this test's class
 * path rather than the image's jar.
 */
class ServerBackupSilenceTest {
    private val plainHttp = "[andvari] WARNING: a plain-http origin is for development only"
    private val unknown = "[andvari] env WARNING: unknown env var ANDVARI_NO_SUCH_SETTING (typo? renamed?)"

    /** A server folder whose settings file is outside test mode, with a plain-http origin and an unknown variable. */
    private fun outsideTestMode(): Server = server().also { s ->
        HostCli.editEnvFile(
            s.env,
            mapOf(
                "ANDVARI_TEST_MODE" to "0", "ANDVARI_MAIL_SINK" to "", "ANDVARI_TEST_CLOCK" to "",
                "ANDVARI_SIGNUP_MODE" to "links", "ANDVARI_NO_SUCH_SETTING" to "1",
            ),
        )
        assertTrue(HostCli.readEnvFile(s.env).getValue("ANDVARI_CANONICAL_ORIGIN").startsWith("http://"))
    }

    @Test
    fun aRunThatWorks_printsNothingWhateverTheSettingsFileSays_andTheServersStartPrintsEachWarning() {
        val s = outsideTestMode()
        val started = startServer(s)
        try {
            val lines = started.lines()
            assertTrue(started.process.isAlive, "the server runs: $lines")
            assertTrue(plainHttp in lines, "the server's start prints the plain-http line: $lines")
            assertTrue(unknown in lines, "the server's start prints the line of the unknown variable: $lines")
            val r = process("admin", "backup", "--env-file", s.env.path)
            assertEquals(listOf(0, "", ""), listOf(r.code, r.out, r.err), "a run that works: status 0, nothing on either output")
            assertTrue(BackupFixture.exists(s.nightly))
        } finally {
            started.kill()
        }
    }

    @Test
    fun aRunThatFails_printsExactlyItsOneLine_andNoSettingsWarning() {
        val s = outsideTestMode()
        val started = startServer(s)
        assertEquals(137, started.kill())
        val r = process("admin", "backup", "--env-file", s.env.path)
        assertEquals(1, r.code, r.err)
        assertEquals("", r.out)
        assertEquals(1, r.err.count { it == '\n' }, "exactly one line: <${r.err}>")
        assertTrue(r.err.startsWith("andvari: backup stopped at the server: "), r.err)
    }
}
