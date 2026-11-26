package io.silencelen.andvari.server

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Setup writes `ANDVARI_STRICT_ENV=1`, so the settings file it writes must be one the strict start takes: the server's
 * real start on an ordinary setup's files prints no warning about its settings and does not refuse. And setup never
 * writes a value the strict start would refuse: a flag that is blank, or holds a line break, is refused before anything
 * is written (decided on 22 November 2026).
 */
class SetupStrictStartTest {
    private fun setup(vararg argv: String): Pair<Int, String> {
        val buf = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val before = System.err
        val code = synchronized(System::class.java) {
            System.setErr(PrintStream(err, true))
            try {
                HostCli.run(listOf("setup") + argv, PrintStream(buf)) { null }
            } finally {
                System.setErr(before)
            }
        }
        return code to (buf.toString() + err.toString())
    }

    private val smtp = arrayOf("--smtp-host", "smtp.example.org", "--smtp-port", "587", "--smtp-user", "vault", "--smtp-pass", "a mail password", "--smtp-from", "vault@example.org")
    private val graph = arrayOf("--graph-tenant", "tenant", "--graph-client-id", "client", "--graph-client-secret", "a secret", "--graph-sender", "vault@example.org")

    /**
     * The ordinary forms: the guide's own line (a private server, people join by link, no mail); a public server; a private
     * server with SMTP mail where people join on their own, with a cap and who may make links; and one with Microsoft
     * Graph mail, sign-up closed and the age confirmation.
     */
    private val ordinary = listOf(
        "guide's line" to arrayOf("--origin", "https://vault.example.org"),
        "public" to arrayOf("--origin", "https://vault.example.org", "--kind", "public"),
        "SMTP, open, cap, links by members" to arrayOf("--origin", "https://vault.example.org", "--mode", "open", "--cap", "50", "--register-links", "members", *smtp),
        "Graph, closed, age confirmation" to arrayOf("--origin", "https://vault.example.org:8443", "--mode", "closed", "--age-confirm", *graph),
    )

    @Test
    fun theServerStartsOnAnOrdinarySetupsFilesUnderTheStrictLine_withNoWarning() {
        for ((form, args) in ordinary) {
            val s = BackupFixture.Server(TestKit.tempDir())
            val (code, out) = setup(*args, "--env-file", s.env.path, "--data-dir", s.data.path)
            assertEquals(0, code, "$form: $out")
            assertTrue(s.env.readLines().contains("ANDVARI_STRICT_ENV=1"), "$form: ${s.env.readText()}")
            val started = BackupFixture.startServer(s)
            try {
                val lines = started.lines()
                assertTrue(lines.any { BackupFixture.LISTENING in it }, "$form: ${lines.joinToString("\n")}")
                assertFalse(lines.any { "env WARNING" in it || "refusing" in it }, "$form: ${lines.joinToString("\n")}")
            } finally {
                started.term()
            }
        }
    }

    @Test
    fun aBlankFlagOrALineBreakInOneIsRefusedBeforeAnythingIsWritten() {
        val cases = listOf(
            Triple("--smtp-port blank", arrayOf("--origin", "https://vault.example.org", *smtp.toList().map { if (it == "587") "" else it }.toTypedArray()), "--smtp-port"),
            Triple("--register-links blank", arrayOf("--origin", "https://vault.example.org", "--register-links="), "--register-links"),
            Triple("a line break in --smtp-from", arrayOf("--origin", "https://vault.example.org", *smtp.toList().map { if (it == "vault@example.org") "vault@example.org\nANDVARI_TOTP_REQURED=1" else it }.toTypedArray()), "--smtp-from"),
        )
        for ((label, args, flag) in cases) {
            val dir = TestKit.tempDir()
            val env = File(dir, "andvari.env")
            val data = File(dir, "data")
            val (code, out) = setup(*args, "--env-file", env.path, "--data-dir", data.path)
            assertEquals(1, code, "$label: $out")
            assertTrue("andvari: $flag " in out && "Nothing was created or changed." in out, "$label: $out")
            assertFalse(env.exists(), "$label: no settings file is written")
            assertFalse(data.exists(), "$label: no data folder is made")
            assertEquals(emptyList(), dir.list()!!.toList(), "$label: the folder is as it was")
        }
    }
}
