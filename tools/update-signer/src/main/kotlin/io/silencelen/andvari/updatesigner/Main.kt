package io.silencelen.andvari.updatesigner

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.system.exitProcess

/**
 * andvari update-signer — OFFLINE Ed25519 signing for the `/downloads` update manifest (H2, design
 * 2026-07-13-signed-updates §F/§G). Runs on the OWNER'S WORKSTATION (Option B): the private key never
 * leaves it and never touches CT122. No network on the classpath. Signs the EXACT bytes of the
 * manifest (raw-bytes-detached, §M-D6) so the client verifies over what it fetched, no canonical-JSON.
 *
 * Commands:
 *   keygen [--out <privkeyfile>]
 *       Mint an Ed25519 keypair. PUBLIC key → stdout as `ANDVARI_UPDATE_PUBKEY=<base64url>` (pin it in
 *       core UpdateVerify.PINNED). Private key → <privkeyfile> (default ./andvari-update-signing.key,
 *       0600 on POSIX). KEEP THE PRIVATE KEY SAFE — never on a server, never in git.
 *   sign <manifest.json> --key <privkeyfile> [--out <sigfile>]
 *       Detached Ed25519 signature over the exact bytes of <manifest.json> → <sigfile>
 *       (default <manifest.json>.sig, base64url). Self-verifies before writing.
 *   verify <manifest.json> <sigfile> <pubkeyB64>
 *       Self-check a signed manifest against a pinned public key.
 */
private val ls = LazySodiumJava(SodiumJava())
private val crypto = createCryptoProvider()

fun main(args: Array<String>) {
    try {
        when (args.getOrNull(0)) {
            "keygen" -> keygen(flag(args, "--out") ?: "andvari-update-signing.key")
            "sign" -> sign(args)
            "verify" -> verify(args)
            else -> usage()
        }
    } catch (e: Exception) {
        System.err.println("error: ${e.message}")
        exitProcess(1)
    }
}

private fun flag(args: Array<String>, name: String): String? {
    val i = args.indexOf(name)
    return if (i >= 0 && i + 1 < args.size) args[i + 1] else null
}

internal fun keygen(outPath: String) {
    val pk = ByteArray(32)
    val sk = ByteArray(64) // libsodium Ed25519 secret key = seed(32) || pubkey(32)
    check(ls.cryptoSignKeypair(pk, sk)) { "crypto_sign_keypair failed" }

    // ASVS V14 restrictive-permission secret storage (CR-19 / same class the repo's own PT-L9
    // flagged). Never leave the H2 signing root world-readable for even a moment, and never
    // clobber an existing key silently (it would destroy the only copy of the private key).
    val path = File(outPath).toPath()
    if (Files.exists(path)) {
        error("refusing to overwrite existing key file $path — this would destroy the current signing key; move it aside first")
    }
    val posix = path.fileSystem.supportedFileAttributeViews().contains("posix")
    val ownerOnly = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    // ATOMIC create-then-VERIFY-then-write: the file exists with owner-only 0600 perms AND we
    // confirm them BEFORE any secret byte lands. `supportedFileAttributeViews().contains("posix")`
    // is a property of the JVM's default provider, NOT of the mount — on a FAT/exFAT/CIFS mount (a
    // plausible offline-key USB) createFile silently yields the mount-default (world-readable) perms
    // with no exception, so we re-read and refuse if 0600 didn't take, deleting the empty file so no
    // secret is ever written to a readable location. createFile also throws if the path already
    // exists (race-safe O_EXCL — also refuses a dangling-symlink outPath).
    if (posix) {
        Files.createFile(path, PosixFilePermissions.asFileAttribute(ownerOnly))
        val got = Files.getPosixFilePermissions(path)
        if (got != ownerOnly) {
            Files.deleteIfExists(path)
            error("cannot enforce owner-only (0600) perms on $path (got $got) — refusing to write the signing key to a world-readable location (a FAT/exFAT/CIFS mount? write it to a POSIX filesystem)")
        }
    } else {
        Files.createFile(path)
        System.err.println("WARNING: non-POSIX filesystem — cannot set owner-only (0600) permissions on $path at create time; secure it yourself (this key can forge update manifests).")
    }
    Files.write(path, Bytes.toB64(sk).toByteArray(Charsets.UTF_8))

    // Belt-and-braces re-check after write (a chmod under us is out of scope but cheap to catch); if
    // it somehow reads back non-0600 now, DELETE the secret-bearing file — never just warn.
    if (posix) {
        val perms = Files.getPosixFilePermissions(path)
        if (perms != ownerOnly) {
            Files.deleteIfExists(path)
            error("could not keep $path at 0600 (got $perms) — deleted it; refusing to leave the signing key readable")
        }
        System.err.println("private key → ${path.toAbsolutePath()} (0600) — KEEP SAFE; never on a server or in git.")
    } else {
        System.err.println("private key → ${path.toAbsolutePath()} — KEEP SAFE; never on a server or in git.")
    }

    println("ANDVARI_UPDATE_PUBKEY=${Bytes.toB64(pk)}")
    System.err.println("→ send that ANDVARI_UPDATE_PUBKEY line back to pin it in core UpdateVerify.PINNED.")
}

private fun sign(args: Array<String>) {
    val manifest = args.getOrNull(1)?.let(::File) ?: error("usage: sign <manifest.json> --key <privkeyfile> [--out <sigfile>]")
    val sk = Bytes.fromB64((flag(args, "--key") ?: error("--key <privkeyfile> required")).let(::File).readText().trim())
    require(sk.size == 64) { "private key must be 64 bytes (base64url from keygen)" }
    val bytes = manifest.readBytes()
    val sig = ByteArray(64)
    check(ls.cryptoSignDetached(sig, bytes, bytes.size.toLong(), sk)) { "crypto_sign_detached failed" }
    // self-verify (pubkey = last 32 bytes of the Ed25519 secret key) before declaring success
    val pk = sk.copyOfRange(32, 64)
    check(crypto.signVerifyDetached(pk, sig, bytes)) { "self-verify failed — key/manifest mismatch" }
    val sigOut = flag(args, "--out") ?: "${manifest.path}.sig"
    File(sigOut).writeText(Bytes.toB64(sig))
    System.err.println("signed ${manifest.name} → $sigOut (self-verify OK; pubkey ${Bytes.toB64(pk).take(16)}…)")
}

private fun verify(args: Array<String>) {
    val manifest = args.getOrNull(1)?.let(::File) ?: error("usage: verify <manifest.json> <sigfile> <pubkeyB64>")
    val sig = Bytes.fromB64(File(args.getOrNull(2) ?: error("sigfile required")).readText().trim())
    val pk = Bytes.fromB64(args.getOrNull(3) ?: error("pubkeyB64 required"))
    val ok = crypto.signVerifyDetached(pk, sig, manifest.readBytes())
    println(if (ok) "OK: signature valid" else "FAIL: signature INVALID")
    if (!ok) exitProcess(1)
}

private fun usage() {
    System.err.println(
        """
        andvari update-signer (H2, Option B — the private key stays on the owner's workstation)
          keygen [--out <privkeyfile>]                          mint a keypair; pubkey→stdout, privkey→file
          sign <manifest.json> --key <privkeyfile> [--out <s>]  detached Ed25519 sig over the exact bytes
          verify <manifest.json> <sigfile> <pubkeyB64>          self-check a signed manifest
        """.trimIndent(),
    )
    exitProcess(2)
}
