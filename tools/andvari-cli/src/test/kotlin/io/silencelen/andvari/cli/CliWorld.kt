package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import kotlin.test.assertTrue

/**
 * Command-level tests' world on [s]: the operator through the setup link, and everyday accounts each on a device (a home)
 * of its own, all driven through the tool's commands with no terminal.
 */
class CliWorld(val s: TestServer) {
    val tmp: File = Files.createTempDirectory("andvari-cli").toFile()
    val op = File(tmp, "operator")
    val card0: String

    init {
        // --age-confirm: a public instance asks every registration for it (design §7.6); a private one ignores it.
        run(op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--age-confirm", "--kit-out", File(tmp, "op-kit.txt").path).ok()
        card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(run(op, "card", "show").ok())!!.groupValues[1]
    }

    fun home(email: String) = File(tmp, email.substringBefore('@'))
    fun kit(email: String) = File(tmp, "$email-kit.txt")

    fun run(
        home: File, vararg args: String, env: (String) -> String? = { if (it == "ANDVARI_PASSWORD") Steps.PASSWORD else null },
        stdin: () -> String? = { null }, origin: String? = s.origin, dial: String? = null, out: ByteArrayOutputStream = ByteArrayOutputStream(),
        crypto: CountingCrypto? = null,
    ): CliRun = CliRun.run(s, home, *args, origin = origin, env = env, stdin = stdin, dial = dial, out = out, crypto = crypto)

    /** [email] through a host enrol link on its own device, then one password sign-in (an enrol pin is no password pin). */
    fun account(email: String): File {
        val home = home(email)
        run(home, "enrol", Steps.enrolLink(s, email), "--email", email, "--kit-out", kit(email).path, "--trust-card", card0, "--device-name", email.substringBefore('@')).ok()
        run(home, "sign-in", "--trust-card", card0).ok()
        return home
    }

    /** The user id `enrol` printed for the account of [home], read back from `operator accounts`. */
    fun userId(email: String): String =
        run(op, "operator", "accounts").ok().lines().first { it.contains(" $email ") }.substringBefore(' ')

    /**
     * Connects the accounts of [a] and [b] through a connect link [a] creates, and both compare codes. Answers (the user id
     * of [a]'s account, that of [b]'s) as each side names the other.
     */
    fun connect(a: File, b: File): Pair<String, String> {
        val url = run(a, "link", "create").ok().lines().last { it.contains("://") }.trim()
        val linkFile = File(tmp, "connect-${a.name}-${b.name}.txt").also { it.writeText(url) }
        val aId = Regex("answered: contact ([0-9a-f-]{36})").find(run(b, "link", "open", "--link-file", linkFile.path).ok())!!.groupValues[1]
        val answers = run(a, "link", "answers").ok()
        val bId = Regex("connected: ([0-9a-f-]{36})").find(answers)?.groupValues?.get(1) ?: error(answers)
        fun code(home: File, contact: String) = Regex("Your code: ([0-9 ]+?)\\s{2,}").find(run(home, "link", "code", contact).ok())!!.groupValues[1]
        val aCode = code(a, bId)
        val bCode = code(b, aId)
        assertTrue(run(a, "link", "compare", bId, "--code", bCode).ok().contains("codes match"))
        assertTrue(run(b, "link", "compare", aId, "--code", aCode).ok().contains("codes match"))
        return aId to bId
    }

    companion object {
        /** The vault id a log command printed (`<vaultId>  seq N`). */
        fun vaultId(out: String): String = Regex("(?m)^([0-9a-f-]{36})  seq ").find(out)?.groupValues?.get(1) ?: error("no vault id in: $out")
    }
}
