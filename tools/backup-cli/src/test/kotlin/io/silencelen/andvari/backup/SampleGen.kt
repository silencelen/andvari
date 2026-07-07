package io.silencelen.andvari.backup

import java.io.File

/**
 * Smoke-fixture generator — TEST sourceset only, never in the shipped jar's usage.
 * Writes a small REAL `.andvari` container (FAST kdf params — the vector-gen pattern,
 * never a production exporter) so the fat jar can be smoke-tested end-to-end:
 *
 *   java -cp tools/backup-cli/build/classes/kotlin/test:tools/backup-cli/build/libs/andvari-backup-cli.jar \
 *        io.silencelen.andvari.backup.SampleGenKt /tmp/sample.andvari ["passphrase"]
 *
 * Default passphrase: "drill passphrase".
 */
fun main(args: Array<String>) {
    val out = args.getOrNull(0) ?: error("usage: SampleGenKt <out.andvari> [passphrase]")
    val passphrase = args.getOrNull(1) ?: "drill passphrase"
    val sample = TestBackups.buildSample(passphrase)
    File(out).writeBytes(sample.file)
    println("wrote $out (${sample.file.size} bytes; passphrase: \"$passphrase\")")
}
