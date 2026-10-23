package io.silencelen.andvari.backup

import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupException
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File

/**
 * andvari backup-cli — OFFLINE reader of record for `.andvari` backup files
 * (spec 07 §3): until client restore ships, this is how a backup is proven restorable
 * and how its contents come back out. Same discipline as recovery-cli: no network I/O
 * anywhere (verified by test: no HTTP classes on the classpath); the decrypted vault
 * exists only in memory during a command — and on disk only where `extract` was
 * explicitly pointed.
 *
 * Commands:
 *   verify  <file.andvari>              open the container + check EVERY attachment
 *                                       section's tag; summary table; exit 0 iff all good,
 *                                       1 with the spec error code otherwise
 *   dump    <file.andvari> [--secrets]  authenticated payload as pretty JSON on stdout.
 *                                       every password, TOTP seed, fileKey, card number,
 *                                       CVV and note body is REDACTED ("•••") by default;
 *                                       --secrets prints them IN THE CLEAR
 *   extract <file.andvari> <outDir>     write each embedded attachment to
 *                                       outDir/<itemName>-<attachmentName> (never overwrites)
 *
 * The passphrase is prompted: no-echo via the console when attached to a terminal,
 * else a plaintext line from stdin (piped use — same posture as recovery-cli's prompts).
 */

private val crypto = createCryptoProvider()

fun main(args: Array<String>) {
    try {
        when (args.getOrNull(0)) {
            "verify" -> verify(argOrDie(args, 1, "file.andvari"))
            "dump" -> {
                val rest = args.drop(1)
                val file = rest.firstOrNull { it != "--secrets" } ?: die("missing argument: file.andvari")
                dump(file, secrets = rest.contains("--secrets"))
            }
            "extract" -> extract(argOrDie(args, 1, "file.andvari"), argOrDie(args, 2, "outDir"))
            else -> die(
                """
                andvari backup-cli (OFFLINE — reader of record for .andvari backups, spec 07 §3)
                  verify  <file.andvari>              open + check every section; exit 0 iff all good
                  dump    <file.andvari> [--secrets]  payload as pretty JSON (secrets redacted as •••)
                  extract <file.andvari> <outDir>     write embedded attachments out (never overwrites)

                --secrets prints every ${Redact.secretsDescription} IN THE CLEAR on stdout.
                Only use it on a trusted machine, only when actually recovering values — the
                default redacted dump is the one that is safe to scroll, share, or attach.
                """.trimIndent(),
            )
        }
    } catch (e: BackupException) {
        die(BackupInspect.errorLine(e.code, e.message))
    } catch (e: Exception) {
        die(BackupInspect.errorLine(null, e.message))
    }
}

private fun verify(path: String) {
    val file = readBackupFile(path)
    val report = BackupInspect.verify(crypto, readPassphrase(), file)
    // A14 (F12): the renderer escapes every payload-authored string before it reaches the terminal.
    print(BackupInspect.renderVerify(path, report))
    println()

    if (report.pass) {
        println("VERIFY PASS — header valid, payload authenticated, every attachment section's tag checked.")
    } else {
        die("VERIFY FAILED — see FAIL rows above; this file will not fully restore.")
    }
}

private fun dump(path: String, secrets: Boolean) {
    val file = readBackupFile(path)
    val opened = Backup.open(crypto, readPassphrase(), file)
    // Banner on stderr so stdout stays pure JSON (pipeable to jq/less).
    if (secrets) {
        System.err.println("WARNING: --secrets — every ${Redact.secretsDescription} follows IN THE CLEAR.")
    } else {
        System.err.println("(secrets redacted as ${Redact.MASK}; --secrets prints them raw — recovery only)")
    }
    println(BackupInspect.dumpJson(opened.payload, secrets))
}

private fun extract(path: String, outDirPath: String) {
    val file = readBackupFile(path)
    val opened = Backup.open(crypto, readPassphrase(), file)
    val written = BackupInspect.extract(opened, File(outDirPath))
    if (written.isEmpty()) {
        println("no attachments embedded in this file (items-only backup)")
        return
    }
    for (w in written) println("wrote ${w.file} (${w.bytes} bytes)")
    println("${written.size} attachment(s) extracted to $outDirPath — plaintext now on disk; delete when done.")
}

private fun readBackupFile(path: String): ByteArray {
    val f = File(path)
    if (!f.isFile) die("no such file: $path")
    // Same cap Backup.open enforces — checked here so a mis-pointed path can't balloon memory.
    if (f.length() > Backup.MAX_FILE_BYTES) throw BackupException(Backup.ERR_TOO_LARGE, "file exceeds 256 MiB")
    return f.readBytes()
}

/**
 * No-echo when a real console is attached to BOTH stdin and stdout; otherwise (piped stdin —
 * scripts/drills — OR, on JDK 17 where `System.console()` is null unless both streams are ttys,
 * a redirected stdout) a plaintext line from stdin, with the prompt on stderr so `dump ... >
 * payload.json` never captures the prompt. Caveat: TYPING the passphrase while stdout is
 * redirected takes this fallback and the terminal echoes it — we warn loudly (parity with
 * recovery-cli's readSecret).
 */
private fun readPassphrase(): String {
    System.console()?.let { console ->
        val chars = console.readPassword("Backup passphrase: ") ?: die("no input")
        return String(chars).also { chars.fill(' ') }
    }
    System.err.println(
        "WARNING: no secure console (stdout is redirected or not a terminal). If you TYPE the " +
            "passphrase here it WILL appear in your terminal scrollback. Pipe it via stdin instead, " +
            "or re-run without redirecting stdout.",
    )
    System.err.print("Backup passphrase: ")
    System.err.flush()
    return readlnOrNull() ?: die("no input")
}

private fun argOrDie(args: Array<String>, i: Int, name: String): String =
    args.getOrNull(i) ?: die("missing argument: $name")

private fun die(message: String): Nothing {
    System.err.println(message)
    kotlin.system.exitProcess(1)
}
