package io.silencelen.andvari.updatesigner

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Round-trip: a workstation-minted Ed25519 keypair signs manifest bytes, and the CLIENT verify
 * primitive (core CryptoProvider.signVerifyDetached — the exact fn desktop/extension use via
 * UpdateVerify) accepts it; any tamper or wrong key is rejected. Proves signer ⇄ verifier agree.
 */
class UpdateSignerTest {
    private val ls = LazySodiumJava(SodiumJava())
    private val crypto = createCryptoProvider()

    @Test
    fun signThenClientVerifyRoundTrips_andTamperRejected() {
        val pk = ByteArray(32)
        val sk = ByteArray(64)
        assertTrue(ls.cryptoSignKeypair(pk, sk))
        // the pubkey the owner pins == the last 32 bytes of the Ed25519 secret key (seed||pubkey)
        assertTrue(pk.contentEquals(sk.copyOfRange(32, 64)))

        val manifest = """{"seq":1,"linux":{"version":"0.16.0","url":"/downloads/andvari-0.16.0.deb"}}""".encodeToByteArray()
        val sig = ByteArray(64)
        assertTrue(ls.cryptoSignDetached(sig, manifest, manifest.size.toLong(), sk))

        assertTrue(crypto.signVerifyDetached(pk, sig, manifest), "the client verify primitive must accept the signer's output")
        assertFalse(crypto.signVerifyDetached(pk, sig, manifest + 0x20), "appended manifest byte rejected")
        assertFalse(crypto.signVerifyDetached(pk, sig.copyOf().also { it[10] = (it[10] + 1).toByte() }, manifest), "flipped sig rejected")

        val pk2 = ByteArray(32)
        val sk2 = ByteArray(64)
        assertTrue(ls.cryptoSignKeypair(pk2, sk2))
        assertFalse(crypto.signVerifyDetached(pk2, sig, manifest), "a different key must reject")
    }

    /**
     * CR-19 (ASVS V14): the private signing key must be created owner-only (0600) BEFORE any
     * secret byte lands — never world-readable-then-restricted. On POSIX, assert the perms.
     */
    @Test
    fun keygen_writesPrivateKeyOwnerOnly() {
        val dir = createTempDirectory("update-signer-perms").toFile()
        try {
            val keyPath = File(dir, "signing.key")
            keygen(keyPath.path)
            assertTrue(keyPath.isFile, "keygen must write the private key file")
            // Round-trips as a base64url 64-byte Ed25519 secret key (seed||pubkey).
            assertEquals(64, Bytes.fromB64(keyPath.readText().trim()).size)
            val path = keyPath.toPath()
            if (path.fileSystem.supportedFileAttributeViews().contains("posix")) {
                assertEquals(
                    setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(path),
                    "the private signing key must be 0600 (owner-only)",
                )
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    /**
     * CR-19: keygen must REFUSE to overwrite an existing key file (a silent clobber would
     * destroy the only copy of the H2 signing root) and leave the existing bytes untouched.
     */
    @Test
    fun keygen_refusesToOverwriteExistingKey() {
        val dir = createTempDirectory("update-signer-overwrite").toFile()
        try {
            val keyPath = File(dir, "existing.key")
            keyPath.writeText("PRE-EXISTING-KEY")
            val e = assertFailsWith<IllegalStateException> { keygen(keyPath.path) }
            assertTrue("refusing to overwrite" in (e.message ?: ""), e.message ?: "")
            assertEquals("PRE-EXISTING-KEY", keyPath.readText(), "the existing key must be left byte-for-byte intact")
        } finally {
            dir.deleteRecursively()
        }
    }
}
