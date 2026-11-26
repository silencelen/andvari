package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Redirect
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.test.assertEquals

/** One run of the tool: its exit code, standard output and standard error. */
class CliRun(val code: Int, val out: String, val err: String) {
    /** Standard output of a run that must succeed. */
    fun ok(): String { assertEquals(0, code, out + err); return out }

    companion object {
        private val errLock = Any()

        /**
         * Runs the tool on the device [home] against [s] (its test clock); [origin] is passed as `--origin` unless null. The
         * master password comes from the environment, [stdin] answers line by line, and standard error is captured
         * unless [captureErr] is false (one run at a time captures it, so runs that wait on each other pass false; [out]
         * may be shared with a thread that watches it). With [dial], every request for [origin] is sent to that listener
         * instead ([Redirect]).
         */
        fun run(
            s: TestServer, home: File, vararg args: String, origin: String? = s.origin, stdin: () -> String? = { null },
            env: (String) -> String? = { if (it == "ANDVARI_PASSWORD") Steps.PASSWORD else null }, out: ByteArrayOutputStream = ByteArrayOutputStream(),
            captureErr: Boolean = true, dial: String? = null, crypto: CountingCrypto? = null,
        ): CliRun {
            val global = listOf("--home", home.path) + (origin?.let { listOf("--origin", it) } ?: emptyList())
            val http = dial?.let { d -> { Redirect.client(origin ?: s.origin, d) } }
            val view = crypto?.let { c -> { p: io.silencelen.andvari.core.crypto.CryptoProvider -> c.over(p) } }
            val err = ByteArrayOutputStream()
            if (!captureErr) return CliRun(Cli.runWith(global + args, PrintStream(out, true), env, stdin, s::now, http, view), out.toString(), "")
            val code = synchronized(errLock) {
                val old = System.err
                System.setErr(PrintStream(err, true))
                try { Cli.runWith(global + args, PrintStream(out, true), env, stdin, s::now, http, view) } finally { System.setErr(old) }
            }
            return CliRun(code, out.toString(), err.toString())
        }

        /** [run] with [text]'s non-empty lines as standard input. */
        fun lines(text: String): () -> String? {
            val it = text.lines().filter { l -> l.isNotEmpty() }.iterator()
            return { if (it.hasNext()) it.next() else null }
        }
    }
}
