package io.silencelen.andvari.recovery

import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
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
}
