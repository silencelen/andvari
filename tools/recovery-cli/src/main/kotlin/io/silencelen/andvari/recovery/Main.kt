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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File

/**
 * andvari recovery-cli — OFFLINE escrow ceremony + recovery (spec 04).
 * Runs on an air-gapped machine. No network I/O anywhere (verified by test:
 * no HTTP classes on the classpath). The org recovery private seed lives only in
 * memory during a command and on the printed sheet / USB — never on disk here,
 * never on the server, never in git/PBS/B2.
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

private fun keygen() {
    val seed = crypto.randomBytes(32)
    val kp = crypto.boxKeypairFromSeed(seed)
    val fp = Escrow.fingerprint(crypto, kp.publicKey)
    val short = Escrow.shortFingerprint(crypto, kp.publicKey)

    println("=".repeat(64))
    println("  andvari ORG RECOVERY KEY — PRINT THIS SHEET x2, COPY SEED TO USB")
    println("  The private seed below can decrypt EVERY escrowed vault.")
    println("  Store the two sheets + USB in separate secure places. Never photograph")
    println("  to a networked device, never type into the server or any online machine.")
    println("=".repeat(64))
    println()
    println("Recovery seed (base64url) — SECRET:")
    println("    ${Bytes.toB64(seed)}")
    println()
    println("Public key (base64url) — pin in server config ANDVARI_RECOVERY_PUBKEY:")
    println("    ${Bytes.toB64(kp.publicKey)}")
    println()
    println("Fingerprint (ANDVARI_RECOVERY_FINGERPRINT):")
    println("    $fp")
    println("Short fingerprint (say this aloud when confirming at enrollment):")
    println("    $short")
    println()
    println("Seed QR (scan back to verify the print is readable):")
    println(qr(Bytes.toB64(seed)))
    println()
    println("Config snippet for /etc/andvari/andvari.env:")
    println("    ANDVARI_RECOVERY_PUBKEY=${Bytes.toB64(kp.publicKey)}")
    println("    ANDVARI_RECOVERY_FINGERPRINT=$fp")
    println()
    println("Next: (1) pin the pubkey+fingerprint in server config, (2) run")
    println("      'canary make <pubkey>' and store the sealed blob server-side, then")
    println("      'canary verify <sealed>' FROM THE PRINTED SEED before any real account.")
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
    val seedB64 = prompt("Paste the recovery seed from the PRINTED SHEET (base64url): ")
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
    val seedB64 = prompt("Paste the recovery seed from the PRINTED SHEET (base64url): ")
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

    val bundle = buildJsonObject {
        put("userId", userId)
        put("tempAuthKey", Bytes.toB64(tempAuthKey))
        put("tempWrappedUvk", Bytes.toB64(tempWrappedUvk))
        put("tempKdfSalt", Bytes.toB64(tempSalt))
        put("tempKdfParams", json.encodeToString(KdfParams.serializer(), params))
    }

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
    println(json.encodeToString(kotlinx.serialization.json.JsonObject.serializer(), bundle))
    println()
    println("3. User logs in with the temp password on any client → forced password change.")
    File("andvari-recovery-$userId.json").writeText(
        json.encodeToString(kotlinx.serialization.json.JsonObject.serializer(), bundle) + "\n",
    )
    println("(also written to andvari-recovery-$userId.json)")
}

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

private fun prompt(message: String): String {
    print(message)
    System.out.flush()
    return readlnOrNull() ?: die("no input")
}

private fun argOrDie(args: Array<String>, i: Int, name: String): String =
    args.getOrNull(i) ?: die("missing argument: $name")

private fun die(message: String): Nothing {
    System.err.println(message)
    kotlin.system.exitProcess(1)
}
