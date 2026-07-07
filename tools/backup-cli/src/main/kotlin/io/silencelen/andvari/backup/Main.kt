package io.silencelen.andvari.backup

import io.silencelen.andvari.core.client.Backup
import io.silencelen.andvari.core.client.BackupException
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.time.Instant

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
 *                                       passwords/TOTP/fileKeys are REDACTED ("•••") by
 *                                       default; --secrets prints them IN THE CLEAR
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

                --secrets prints every password, TOTP seed and fileKey IN THE CLEAR on stdout.
                Only use it on a trusted machine, only when actually recovering values — the
                default redacted dump is the one that is safe to scroll, share, or attach.
                """.trimIndent(),
            )
        }
    } catch (e: BackupException) {
        die("error [${e.code}]: ${e.message}")
    } catch (e: Exception) {
        die("error: ${e.message}")
    }
}

private fun verify(path: String) {
    val file = readBackupFile(path)
    val report = BackupInspect.verify(crypto, readPassphrase(), file)
    val payload = report.opened.payload

    println("andvari backup — $path")
    println("  fileId        ${report.opened.header.fileId}")
    println("  exportedAt    ${Instant.ofEpochMilli(payload.exportedAt)} (authenticated)")
    if (payload.origin.isNotEmpty()) println("  origin        ${payload.origin} (advisory)")
    if (payload.userId.isNotEmpty()) println("  userId        ${payload.userId} (advisory)")
    println()

    println("Items per vault (${payload.items.size} total):")
    for ((label, count) in report.itemsPerVault) println("  %-52s %d".format(label, count))
    println()

    if (report.checks.isEmpty()) {
        println("Attachments: none embedded (items-only backup)")
    } else {
        println("Attachments (${report.checks.size} in manifest):")
        println("  %-44s %-6s %s".format("item-attachment", "result", "detail"))
        for (c in report.checks) {
            println("  %-44s %-6s %s".format("${c.itemName}-${c.entry.name}", if (c.pass) "OK" else "FAIL", c.detail))
        }
    }
    report.framingMismatch?.let { println("  FRAMING FAIL: $it") }
    println()

    val s = payload.skipped
    if (s.undecryptable.isEmpty() && s.attachmentsOverCap.isEmpty() && s.attachmentFetchFailed.isEmpty()) {
        println("Skips recorded in file: none")
    } else {
        println("Skips recorded in file (by the exporting client — these are NOT in the backup):")
        if (s.undecryptable.isNotEmpty()) println("  undecryptable items:     ${s.undecryptable.joinToString { it.itemId }}")
        if (s.attachmentsOverCap.isNotEmpty()) println("  attachments over cap:    ${s.attachmentsOverCap.joinToString()}")
        if (s.attachmentFetchFailed.isNotEmpty()) println("  attachment fetch failed: ${s.attachmentFetchFailed.joinToString()}")
    }
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
        System.err.println("WARNING: --secrets — every password, TOTP seed and fileKey follows IN THE CLEAR.")
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
 * No-echo when a real console is attached; otherwise (piped stdin — scripts, drills)
 * a plaintext line exactly like recovery-cli's seed prompts. The prompt goes to stderr
 * so `dump ... > payload.json` never captures it.
 */
private fun readPassphrase(): String {
    System.console()?.let { console ->
        val chars = console.readPassword("Backup passphrase: ") ?: die("no input")
        return String(chars).also { chars.fill(' ') }
    }
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
