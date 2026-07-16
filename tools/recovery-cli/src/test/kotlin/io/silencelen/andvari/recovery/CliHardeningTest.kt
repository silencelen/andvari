package io.silencelen.andvari.recovery

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * spec 04 §5 offline-guard + §1 sheet-contents pins for the CLI entrypoint (the crypto
 * behind the commands is covered by RecoveryCeremonyTest / EscrowVerifyTest).
 */
class CliHardeningTest {

    @Test
    fun serverUrlArgs_areDetected() {
        assertEquals(
            "https://andvari.taila2dff2.ts.net",
            serverUrlArg(arrayOf("recover", "https://andvari.taila2dff2.ts.net")),
        )
        assertNotNull(serverUrlArg(arrayOf("verify", "seed.txt", "http://192.168.7.122:8080/api")))
        assertNotNull(serverUrlArg(arrayOf("keygen", "--server", "andvari.taila2dff2.ts.net"))) // bare tailnet host
        assertNotNull(serverUrlArg(arrayOf("canary", "make", "ANDVARI.MONAHANHOSTING.COM"))) // case-insensitive
        assertNotNull(serverUrlArg(arrayOf("wss://andvari.taila2dff2.ts.net/api/v1/events")))
    }

    @Test
    fun legitimateArgs_pass() {
        assertNull(serverUrlArg(emptyArray()))
        assertNull(serverUrlArg(arrayOf("keygen")))
        assertNull(serverUrlArg(arrayOf("fingerprint", "Zm9vYmFyLWZha2UtcHVia2V5X2I2NHVybA")))
        assertNull(serverUrlArg(arrayOf("verify", "/tmp/seed.txt", "./andvari-escrow-dump.json")))
        assertNull(serverUrlArg(arrayOf("canary", "verify", "c29tZS1zZWFsZWQtYmxvYl9iNjR1cmw")))
        assertNull(serverUrlArg(arrayOf("recover", "C:\\Users\\owner\\sealed-blob.txt")))
    }

    @Test
    fun keygenSheet_carriesGenerationDateAndRecoveryPointer() {
        val sheet = keygenSheet(ByteArray(32) { 1 }, LocalDate.of(2026, 7, 14))
        assertTrue("Generated: 2026-07-14" in sheet, "sheet must carry its generation date (spec 04 §1)")
        assertTrue("recovery-cli recover" in sheet, "sheet must carry the recovery one-liner (spec 04 §1)")
        // The pre-existing anchors stay put.
        assertTrue("ANDVARI_RECOVERY_PUBKEY" in sheet)
        assertTrue("canary verify" in sheet)
    }

    @Test
    fun keygenSheet_defaultsToToday() {
        val before = LocalDate.now()
        val sheet = keygenSheet(ByteArray(32) { 2 })
        val after = LocalDate.now() // straddling midnight must not flake the nightly run
        assertTrue("Generated: $before" in sheet || "Generated: $after" in sheet)
    }

    /**
     * PT-L10 (CR-13): the org recovery seed must never be echoed to the terminal. Under the
     * gradle test JVM no console is attached, so [readSecret] takes the piped stdin fallback —
     * assert it reads the line WITHOUT echoing the seed to stdout (scrollback) and prompts on
     * stderr so a redirected stdout (`recover ... > bundle.json`) stays clean.
     */
    @Test
    fun readSecret_pipedFallback_readsStdinWithoutEchoingToStdout() {
        val origIn = System.`in`
        val origOut = System.out
        val origErr = System.err
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val secret: String
        try {
            System.setIn(ByteArrayInputStream("MY-SECRET-SEED-B64\n".toByteArray()))
            System.setOut(PrintStream(out))
            System.setErr(PrintStream(err))
            secret = readSecret("Paste the recovery seed from the PRINTED SHEET (base64url): ")
        } finally {
            System.setIn(origIn)
            System.setOut(origOut)
            System.setErr(origErr)
        }
        assertEquals("MY-SECRET-SEED-B64", secret, "piped fallback must return the seed line")
        assertEquals("", out.toString(), "the seed read must write NOTHING to stdout (no scrollback echo)")
        assertFalse("MY-SECRET-SEED-B64" in out.toString(), "the seed must never reach stdout")
        assertTrue("Paste the recovery seed" in err.toString(), "the prompt must go to stderr, not stdout")
    }
}
