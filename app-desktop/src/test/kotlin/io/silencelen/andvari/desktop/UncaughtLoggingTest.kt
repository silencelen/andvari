package io.silencelen.andvari.desktop

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Uncaught errors go through the redacting log, not to standard error with their messages. */
class UncaughtLoggingTest {
    private val before = Thread.getDefaultUncaughtExceptionHandler()
    private val err = System.err

    @AfterTest
    fun restore() {
        Thread.setDefaultUncaughtExceptionHandler(before)
        System.setErr(err)
        DesktopDiagnostics.logFileOverride = null
    }

    @Test
    fun anUncaughtErrorIsLoggedRedactedAndItsMessageGoesNowhere() {
        val dir = Files.createTempDirectory("andvari-l7-uncaught").toFile().also { it.deleteOnExit() }
        val log = File(dir, "diagnostic.log")
        DesktopDiagnostics.logFileOverride = log
        val captured = ByteArrayOutputStream()
        System.setErr(PrintStream(captured, true))

        DesktopDiagnostics.installUncaughtLogging()
        val secret = "hunter2-the-decrypted-note"
        Thread { throw IllegalStateException(secret) }.apply { start(); join() }

        val written = log.readText()
        assertTrue("uncaught" in written && "IllegalStateException" in written, "logged, with the class")
        assertFalse(secret in written, "the message is redacted in the log")
        assertFalse(secret in captured.toString(), "and never printed to standard error")
        dir.deleteRecursively()
    }
}
