package io.silencelen.andvari.cli

import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Run by [LoggingTest] in a JVM of its own: the tool's logging set up as `main` sets it up, then one line per level. */
object LogProbe {
    @JvmStatic fun main(args: Array<String>) {
        useOwnLogging()
        val log = io.ktor.util.logging.KtorSimpleLogger("io.silencelen.andvari.cli.probe")
        log.debug("a debug line")
        log.info("an info line")
        log.warn("a warning")
        log.error("an error")
        println("probe: stdout")
    }
}

/**
 * The tool ships the server's logging backend (logback, approved by the owner on 2026-11-15) with a configuration that
 * keeps a command's output clean. Each run is a JVM of its own on exactly the classpath the distribution ships, so no
 * test-only library or configuration (the server's own logback.xml is on the test classpath) can stand in for it.
 */
class LoggingTest {
    private val shipped: List<String> = System.getProperty("andvari.cli.runtimeClasspath")!!.split(File.pathSeparator)

    private class Ran(val code: Int, val out: String, val err: String)

    private fun java(classpath: List<String>, main: String, vararg args: String): Ran {
        val java = File(System.getProperty("java.home"), "bin/java").path
        val dir = Files.createTempDirectory("andvari-cli-log").toFile()
        try {
            val out = File(dir, "out")
            val err = File(dir, "err")
            val p = ProcessBuilder(listOf(java, "-cp", classpath.joinToString(File.pathSeparator), main) + args)
                .redirectOutput(out).redirectError(err).redirectInput(ProcessBuilder.Redirect.from(File("/dev/null"))).start()
            check(p.waitFor(120, TimeUnit.SECONDS)) { "$main did not finish" }
            return Ran(p.exitValue(), out.readText(), err.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun whoami(classpath: List<String>): Ran {
        val home = Files.createTempDirectory("andvari-cli-home").toFile()
        try {
            return java(classpath, "io.silencelen.andvari.cli.MainKt", "--home", home.path, "--origin", "http://127.0.0.1:1", "whoami")
        } finally {
            home.deleteRecursively()
        }
    }

    private fun meaningful(text: String) = text.lines().filter { it.isNotBlank() }

    @Test fun aCommandNoLongerWarnsThatSlf4jHasNoProviderAndPrintsNothingElse() {
        assertTrue(shipped.any { File(it).name.startsWith("logback-classic-") }, "the distribution ships logback-classic: $shipped")
        // The same command on the same classpath without the backend: the warning, so this test can see it.
        val without = whoami(shipped.filterNot { File(it).name.startsWith("logback-") })
        assertEquals(0, without.code, without.err)
        assertTrue(without.err.contains("No SLF4J providers were found"), without.err)

        val with = whoami(shipped)
        assertEquals(0, with.code, with.err)
        assertFalse(with.err.contains("SLF4J"), with.err)
        assertEquals(without.out, with.out, "standard output is unchanged")
        assertTrue(with.out.contains("not pinned on this device"), with.out)
        assertEquals(meaningful(without.err).filterNot { it.startsWith("SLF4J") }, meaningful(with.err), "nothing was added to standard error")
    }

    @Test fun warningsAndErrorsGoToStandardErrorNothingIsLoggedToStandardOutputAndThereIsNoBanner() {
        val tests = File(LogProbe::class.java.protectionDomain.codeSource.location.toURI()).path
        val r = java(shipped + tests, LogProbe::class.java.name)
        assertEquals(0, r.code, r.err)
        assertEquals(listOf("probe: stdout"), meaningful(r.out), "standard output holds the command's own output only")
        val err = meaningful(r.err)
        assertEquals(2, err.size, "one warning and one error, no debug or info line, no logback status: $err")
        assertTrue(err[0].startsWith("andvari-cli: WARN") && err[0].endsWith("a warning"), err[0])
        assertTrue(err[1].startsWith("andvari-cli: ERROR") && err[1].endsWith("an error"), err[1])
    }
}
