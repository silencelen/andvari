package io.silencelen.andvari.recovery

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.RecoveryUpload
import kotlinx.serialization.json.Json
import java.io.File
import java.time.LocalDate

/**
 * andvari recovery-cli — OFFLINE escrow ceremony + recovery (spec 04).
 * Runs on an air-gapped machine. No network I/O anywhere (verified by test:
 * no HTTP classes on the classpath), and a server-URL argument anywhere on the
 * command line is refused outright (spec 04 §5). The org recovery private seed
 * lives only in memory during a command and on the printed sheet / USB — never
 * on disk here, never on the server, never in git/PBS/B2.
 *
 * Commands:
 *   keygen                              generate the org recovery keypair + printable sheet
 *   fingerprint <pubkeyB64>             show the fingerprint of a public key
 *   canary make <pubkeyB64>             seal the fixed canary blob (store server-side)
 *   canary verify <sealedB64>           open the canary with the printed seed (proves the sheet works)
 *   verify <seedFile> <dumpJson>        fleet canary: unseal EVERY escrow blob from a sqlite dump,
 *                                       PASS/FAIL per user, exit 1 on any FAIL (docs/drills/escrow-canary-drill.md)
 *   recover <sealedBlobB64>             unseal a user's UVK and emit an admin recovery upload bundle
 */

private val crypto = createCryptoProvider()
private val json = Json { prettyPrint = true }

fun main(args: Array<String>) {
    // spec 04 §5: this tool is OFFLINE — no command takes a server address, so a server
    // URL among the args means a confused (or hostile) invocation. Refuse before dispatch.
    serverUrlArg(args)?.let {
        die("refusing to run: argument '$it' looks like an andvari server URL — recovery-cli is offline-only and never contacts a server (spec 04 §5)")
    }
    try {
        when (args.getOrNull(0)) {
            "keygen" -> keygen()
            "fingerprint" -> fingerprint(argOrDie(args, 1, "pubkeyB64"))
            "canary" -> when (args.getOrNull(1)) {
                "make" -> canaryMake(argOrDie(args, 2, "pubkeyB64"))
                "verify" -> canaryVerify(argOrDie(args, 2, "sealedB64"))
                else -> die("usage: canary make <pubkeyB64> | canary verify <sealedB64>")
            }
            "verify" -> verifyDump(argOrDie(args, 1, "seedFile"), argOrDie(args, 2, "escrowDumpJson"))
            "recover" -> recover(argOrDie(args, 1, "sealedBlobB64"))
            else -> die(
                """
                andvari recovery-cli (OFFLINE — run air-gapped)
                  keygen
                  fingerprint <pubkeyB64>
                  canary make <pubkeyB64>
                  canary verify <sealedB64>
                  verify <seedFile> <escrowDumpJson>
                  recover <sealedBlobB64>
                """.trimIndent(),
            )
        }
    } catch (e: Exception) {
        die("error: ${e.message}")
    }
}

/**
 * spec 04 §5 guard: any URL-ish argument — a scheme (`https://…`, `wss://…`), or a bare
 * server-host shape — marks the invocation as confused/hostile. HOST-AGNOSTIC by design
 * (2026-07-15 §5.5): andvari is self-hostable, so ANY origin must be refused as loudly as the
 * reference instance's — no hardcoded hostnames. A bare host is: dotted DNS labels with at
 * least three labels (`andvari.monahanhosting.com`, any `*.ts.net` tailnet name, an IPv4), or
 * any dotted name carrying a `:port` (`myvault.net:8443`). Legitimate arguments are
 * subcommands, base64url blobs, and local file paths — none contain "://", and anything with a
 * path separator is never host-shaped, so a multi-dotted FILENAME that trips the guard can
 * always be passed as `./name`.
 */
internal fun serverUrlArg(args: Array<String>): String? = args.firstOrNull { arg ->
    val a = arg.lowercase()
    "://" in a || BARE_HOST.matches(a)
}

private const val HOST_LABEL = """[a-z0-9]([a-z0-9-]*[a-z0-9])?"""
private val BARE_HOST = Regex("""$HOST_LABEL(\.$HOST_LABEL){2,}(:\d{1,5})?|$HOST_LABEL(\.$HOST_LABEL)+:\d{1,5}""")

private fun keygen() {
    print(keygenSheet(crypto.randomBytes(32)))
}

/**
 * The printable recovery sheet (spec 04 §1): seed (base64url + QR), pubkey, fingerprints,
 * generation date, env snippet, and next steps including the recovery one-liner. A pure
 * text builder so tests can pin the sheet's required fields without capturing stdout.
 */
internal fun keygenSheet(seed: ByteArray, generatedOn: LocalDate = LocalDate.now()): String = buildString {
    val kp = crypto.boxKeypairFromSeed(seed)
    val fp = Escrow.fingerprint(crypto, kp.publicKey)
    val short = Escrow.shortFingerprint(crypto, kp.publicKey)

    appendLine("=".repeat(64))
    appendLine("  andvari ORG RECOVERY KEY — PRINT THIS SHEET x2, COPY SEED TO USB")
    appendLine("  The private seed below can decrypt EVERY escrowed vault.")
    appendLine("  Store the two sheets + USB in separate secure places. Never photograph")
    appendLine("  to a networked device, never type into the server or any online machine.")
    appendLine("=".repeat(64))
    appendLine()
    appendLine("Generated: $generatedOn") // spec 04 §1: the sheet carries its generation date
    appendLine()
    appendLine("Recovery seed (base64url) — SECRET:")
    appendLine("    ${Bytes.toB64(seed)}")
    appendLine()
    appendLine("Public key (base64url) — pin in server config ANDVARI_RECOVERY_PUBKEY:")
    appendLine("    ${Bytes.toB64(kp.publicKey)}")
    appendLine()
    appendLine("Fingerprint (ANDVARI_RECOVERY_FINGERPRINT):")
    appendLine("    $fp")
    appendLine("Short fingerprint (say this aloud when confirming at enrollment):")
    appendLine("    $short")
    appendLine()
    appendLine("Seed QR (scan back to verify the print is readable):")
    appendLine(qr(Bytes.toB64(seed)))
    appendLine()
    appendLine("Config snippet for /etc/andvari/andvari.env:")
    appendLine("    ANDVARI_RECOVERY_PUBKEY=${Bytes.toB64(kp.publicKey)}")
    appendLine("    ANDVARI_RECOVERY_FINGERPRINT=$fp")
    appendLine()
    appendLine("Next: (1) pin the pubkey+fingerprint in server config, (2) run")
    appendLine("      'canary make <pubkey>' and store the sealed blob server-side, then")
    appendLine("      'canary verify <sealed>' FROM THE PRINTED SEED before any real account.")
    appendLine()
    appendLine("Recovery (when a member is locked out): run 'recovery-cli recover' and follow prompts.")
}

private fun fingerprint(pubB64: String) {
    val pub = Bytes.fromB64(pubB64)
    require(pub.size == 32) { "public key must be 32 bytes" }
    println("fingerprint: ${Escrow.fingerprint(crypto, pub)}")
    println("short:       ${Escrow.shortFingerprint(crypto, pub)}")
}

private fun canaryMake(pubB64: String) {
    val pub = Bytes.fromB64(pubB64)
    val sealed = Escrow.sealCanary(crypto, pub)
    println("Canary sealed blob (store server-side as the ceremony canary):")
    println(Bytes.toB64(sealed))
}

private fun canaryVerify(sealedB64: String) {
    val seedB64 = readSecret("Paste the recovery seed from the PRINTED SHEET (base64url): ")
    val seed = Bytes.fromB64(seedB64.trim())
    val kp = crypto.boxKeypairFromSeed(seed)
    val payload = Escrow.open(crypto, kp.publicKey, kp.privateKey, Bytes.fromB64(sealedB64))
    require(payload.keyType == Escrow.KEY_TYPE_CANARY) { "not a canary blob (keyType=${payload.keyType})" }
    require(payload.userId == Escrow.CANARY_USER_ID) { "canary userId mismatch" }
    require(Bytes.fromB64(payload.key).contentEquals(Escrow.CANARY_KEY)) { "canary key mismatch" }
    println("CANARY VERIFIED ✓  print → restore → unseal works end-to-end.")
    println("Fingerprint of the sheet's key: ${Escrow.fingerprint(crypto, kp.publicKey)}")
}

/**
 * Fleet escrow canary (spec 04; docs/drills/escrow-canary-drill.md): open every escrowed
 * blob with the printed seed and prove the accounts are recoverable. The seed comes from
 * a FILE (typed/scanned from the sheet onto the air-gapped box, or the USB copy) so the
 * drill is scriptable; the dump is `sqlite3 -json` output of the server's escrow table.
 */
private fun verifyDump(seedFile: String, dumpFile: String) {
    val seed = Bytes.fromB64(File(seedFile).readText().trim())
    require(seed.size == 32) { "seed file must contain a base64url 32-byte seed" }
    val rows = EscrowVerify.parseDump(File(dumpFile).readText())
    if (rows.isEmpty()) die("no escrow rows in $dumpFile — export with: sqlite3 -json <db> \"SELECT userId, sealed, fingerprint, updatedAt FROM escrow\"")

    val kp = crypto.boxKeypairFromSeed(seed)
    println("Escrow fleet verify — recovery key ${Escrow.shortFingerprint(crypto, kp.publicKey)} (${rows.size} blob(s))")
    println()
    val results = EscrowVerify.verify(crypto, seed, rows)
    println("%-38s %-6s %s".format("userId", "result", "detail"))
    for (r in results) println("%-38s %-6s %s".format(r.userId, if (r.pass) "PASS" else "FAIL", r.detail))
    val fails = results.count { !it.pass }
    println()
    println("${results.size - fails}/${results.size} PASS")
    if (fails > 0) die("$fails escrow blob(s) FAILED — those accounts are NOT recoverable with this key (spec 04 §4: P1 incident, re-ceremony + re-escrow)")
    println("All escrowed accounts are recoverable with this sheet.")
}

private fun recover(sealedBlobB64: String) {
    val seedB64 = readSecret("Paste the recovery seed from the PRINTED SHEET (base64url): ")
    val seed = Bytes.fromB64(seedB64.trim())
    val kp = crypto.boxKeypairFromSeed(seed)
    val payload = Escrow.open(crypto, kp.publicKey, kp.privateKey, Bytes.fromB64(sealedBlobB64))
    require(payload.keyType == Escrow.KEY_TYPE_UVK) { "not a UVK escrow blob (keyType=${payload.keyType})" }
    val uvk = Bytes.fromB64(payload.key)
    val userId = payload.userId

    // Generate a one-time temporary password + fresh KDF material, re-wrap UVK under it.
    val tempPassword = humanTempPassword()
    val tempSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
    val params = KdfParams.DEFAULT
    val mk = Keys.masterKey(crypto, tempPassword, tempSalt, params)
    val tempAuthKey = Keys.authKey(crypto, mk)
    val tempWrapKey = Keys.wrapKey(crypto, mk)
    val tempWrappedUvk = Envelope.seal(crypto, tempWrapKey, uvk, Ad.uvk(userId))

    val bundle = recoveryBundle(userId, tempAuthKey, tempWrappedUvk, tempSalt, params)
    val bundleJson = json.encodeToString(RecoveryUpload.serializer(), bundle)

    println()
    println("RECOVERY BUNDLE for userId=$userId")
    println("UVK was unsealed offline; it never touches the online machine except re-wrapped.")
    println()
    println("1. Give the user this ONE-TIME temporary password (out-of-band, e.g. in person):")
    println("       $tempPassword")
    println()
    println("2. Upload this bundle to the server: POST /api/v1/admin/recovery")
    println("   (as admin; the server sets mustChangePassword and revokes their sessions)")
    println()
    println(bundleJson)
    println()
    println("3. User logs in with the temp password on any client → forced password change.")
    File("andvari-recovery-$userId.json").writeText(bundleJson + "\n")
    println("(also written to andvari-recovery-$userId.json)")
}

/**
 * Build the admin recovery-upload bundle as the server's EXACT [RecoveryUpload] type so the
 * emitted JSON is round-trip-guaranteed to decode. PRC-1: hand-building a JsonObject let
 * `tempKdfParams` serialize as a JSON STRING (`"{}"`) instead of the object the server's
 * non-lenient decoder expects, so `POST /admin/recovery` 400'd — the household's only path
 * back from a forgotten master password broke at the final admin-upload step. Serializing the
 * typed value cannot drift from the wire contract; [RecoveryCeremonyTest] round-trips it.
 */
internal fun recoveryBundle(
    userId: String,
    tempAuthKey: ByteArray,
    tempWrappedUvk: ByteArray,
    tempKdfSalt: ByteArray,
    params: KdfParams,
): RecoveryUpload = RecoveryUpload(
    userId = userId,
    tempAuthKey = Bytes.toB64(tempAuthKey),
    tempWrappedUvk = Bytes.toB64(tempWrappedUvk),
    tempKdfSalt = Bytes.toB64(tempKdfSalt),
    tempKdfParams = params,
)

// A readable temp password: 4 short words + digits (owner types it once).
private fun humanTempPassword(): String =
    PasswordGenerator.generate(crypto, io.silencelen.andvari.core.crypto.GeneratorOptions(length = 16, symbols = false, avoidAmbiguous = true))

private fun qr(text: String): String {
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0)
    val sb = StringBuilder()
    // Two rows per printed line using half-block chars keeps the QR roughly square.
    var y = 0
    while (y < matrix.height) {
        for (x in 0 until matrix.width) {
            val top = matrix.get(x, y)
            val bottom = if (y + 1 < matrix.height) matrix.get(x, y + 1) else false
            sb.append(if (top && bottom) '█' else if (top) '▀' else if (bottom) '▄' else ' ')
        }
        sb.append('\n')
        y += 2
    }
    return sb.toString()
}

/**
 * No-echo read of a SECRET — here the org recovery seed, which can decrypt EVERY escrowed
 * UVK and lives only in offline/printed-sheet custody (ER-1). No-echo via the console when a
 * real terminal is attached to BOTH stdin and stdout (the char[] is zeroed after copying it
 * out); otherwise a plaintext line from stdin for piped drills/scripts, with the prompt on
 * stderr so a redirected stdout (`recover ... > bundle.json`) never captures the prompt.
 * PT-L10 caveat (JDK 17): `System.console()` is null when EITHER stream is not a tty — so
 * TYPING the seed while stdout is redirected takes this fallback and the TERMINAL echoes it to
 * scrollback. We warn loudly on stderr; the fully-safe paths are: pipe the seed via stdin, or
 * don't redirect stdout. Mirrors backup-cli's readPassphrase.
 */
internal fun readSecret(message: String): String {
    System.console()?.let { console ->
        val chars = console.readPassword(message) ?: die("no input")
        return String(chars).also { chars.fill(' ') }
    }
    System.err.println(
        "WARNING: no secure console (stdout is redirected or not a terminal). If you TYPE the " +
            "seed here it WILL appear in your terminal scrollback. Pipe it via stdin instead, or " +
            "re-run without redirecting stdout.",
    )
    System.err.print(message)
    System.err.flush()
    return readlnOrNull() ?: die("no input")
}

private fun argOrDie(args: Array<String>, i: Int, name: String): String =
    args.getOrNull(i) ?: die("missing argument: $name")

private fun die(message: String): Nothing {
    System.err.println(message)
    kotlin.system.exitProcess(1)
}
