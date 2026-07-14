package io.silencelen.andvari.core.crypto

import com.goterl.lazysodium.LazySodium
import com.goterl.lazysodium.interfaces.AEAD
import com.goterl.lazysodium.interfaces.Box
import com.goterl.lazysodium.interfaces.PwHash
import com.goterl.lazysodium.interfaces.SecretStream
import com.sun.jna.NativeLong
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Adapter from [CryptoProvider] to a lazysodium binding. This file is compiled into
 * BOTH the jvm and android targets (srcDir-shared, see core/build.gradle.kts) against
 * their respective lazysodium artifacts — the com.goterl.lazysodium API is identical.
 */
internal class LazySodiumCryptoProvider(private val ls: LazySodium) : CryptoProvider {

    override fun randomBytes(n: Int): ByteArray = ls.randomBytesBuf(n)

    override fun argon2id(
        password: ByteArray,
        salt: ByteArray,
        outLen: Int,
        opsLimit: Long,
        memLimitBytes: Long,
    ): ByteArray {
        require(salt.size == PwHash.SALTBYTES) { "argon2id salt must be ${PwHash.SALTBYTES} bytes" }
        val out = ByteArray(outLen)
        val ok = ls.cryptoPwHash(
            out, out.size, password, password.size, salt,
            opsLimit, NativeLong(memLimitBytes), PwHash.Alg.PWHASH_ALG_ARGON2ID13,
        )
        if (!ok) throw CryptoException("crypto_pwhash (argon2id) failed")
        return out
    }

    private fun hmac(algorithm: String, key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return mac.doFinal(data)
    }

    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray = hmac("HmacSHA256", key, data)

    override fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray = hmac("HmacSHA1", key, data)

    override fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray = hmac("HmacSHA512", key, data)

    override fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    override fun sha1(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)

    override fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray {
        require(key.size == AEAD.XCHACHA20POLY1305_IETF_KEYBYTES) { "AEAD key must be 32 bytes" }
        require(nonce.size == AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES) { "AEAD nonce must be 24 bytes" }
        val out = ByteArray(plaintext.size + AEAD.XCHACHA20POLY1305_IETF_ABYTES)
        val outLen = LongArray(1)
        val ok = ls.cryptoAeadXChaCha20Poly1305IetfEncrypt(
            out, outLen, plaintext, plaintext.size.toLong(), ad, ad.size.toLong(), null, nonce, key,
        )
        if (!ok) throw CryptoException("xchacha20poly1305 encrypt failed")
        return out
    }

    override fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray {
        if (ciphertext.size < AEAD.XCHACHA20POLY1305_IETF_ABYTES) throw CryptoException("ciphertext too short")
        val out = ByteArray(ciphertext.size - AEAD.XCHACHA20POLY1305_IETF_ABYTES)
        val outLen = LongArray(1)
        val ok = ls.cryptoAeadXChaCha20Poly1305IetfDecrypt(
            out, outLen, null, ciphertext, ciphertext.size.toLong(), ad, ad.size.toLong(), nonce, key,
        )
        if (!ok) throw CryptoException("xchacha20poly1305 decrypt failed (bad MAC or AD)")
        return out
    }

    override fun boxKeypairFromSeed(seed: ByteArray): KeyPairBytes {
        require(seed.size == Box.SEEDBYTES) { "box seed must be ${Box.SEEDBYTES} bytes" }
        val pk = ByteArray(Box.PUBLICKEYBYTES)
        val sk = ByteArray(Box.SECRETKEYBYTES)
        if (!ls.cryptoBoxSeedKeypair(pk, sk, seed)) throw CryptoException("crypto_box_seed_keypair failed")
        return KeyPairBytes(pk, sk)
    }

    override fun sealTo(recipientPublicKey: ByteArray, plaintext: ByteArray): ByteArray {
        val out = ByteArray(plaintext.size + Box.SEALBYTES)
        if (!ls.cryptoBoxSeal(out, plaintext, plaintext.size.toLong(), recipientPublicKey)) {
            throw CryptoException("crypto_box_seal failed")
        }
        return out
    }

    override fun sealOpen(publicKey: ByteArray, privateKey: ByteArray, sealed: ByteArray): ByteArray {
        if (sealed.size < Box.SEALBYTES) throw CryptoException("sealed box too short")
        val out = ByteArray(sealed.size - Box.SEALBYTES)
        if (!ls.cryptoBoxSealOpen(out, sealed, sealed.size.toLong(), publicKey, privateKey)) {
            throw CryptoException("crypto_box_seal_open failed (wrong key or corrupt box)")
        }
        return out
    }

    override fun secretstreamEncrypt(key: ByteArray, chunks: List<ByteArray>): SecretStreamResult {
        require(key.size == SecretStream.KEYBYTES) { "secretstream key must be ${SecretStream.KEYBYTES} bytes" }
        val state = SecretStream.State()
        val header = ByteArray(SecretStream.HEADERBYTES)
        if (!ls.cryptoSecretStreamInitPush(state, header, key)) {
            throw CryptoException("secretstream init_push failed")
        }
        val out = chunks.mapIndexed { i, chunk ->
            val tag = if (i == chunks.lastIndex) SecretStream.TAG_FINAL else SecretStream.TAG_MESSAGE
            val cipher = ByteArray(chunk.size + SecretStream.ABYTES)
            if (!ls.cryptoSecretStreamPush(state, cipher, chunk, chunk.size.toLong(), tag)) {
                throw CryptoException("secretstream push failed at chunk $i")
            }
            cipher
        }
        return SecretStreamResult(header, out)
    }

    override fun secretstreamDecrypt(key: ByteArray, header: ByteArray, chunks: List<ByteArray>): List<ByteArray> {
        val state = SecretStream.State()
        if (!ls.cryptoSecretStreamInitPull(state, header, key)) {
            throw CryptoException("secretstream init_pull failed (bad header)")
        }
        val tag = ByteArray(1)
        return chunks.mapIndexed { i, cipher ->
            if (cipher.size < SecretStream.ABYTES) throw CryptoException("secretstream chunk $i too short")
            val message = ByteArray(cipher.size - SecretStream.ABYTES)
            if (!ls.cryptoSecretStreamPull(state, message, tag, cipher, cipher.size.toLong())) {
                throw CryptoException("secretstream pull failed at chunk $i (corrupt or reordered)")
            }
            val isLast = i == chunks.lastIndex
            val isFinal = tag[0] == SecretStream.TAG_FINAL
            if (isLast != isFinal) throw CryptoException("secretstream truncated or trailing data (final-tag mismatch)")
            message
        }
    }

    // H2 signed-update channel: Ed25519 crypto_sign_verify_detached. Verify-only (clients never sign).
    // Fail-closed on bad sizes; lazysodium returns false on a bad signature (never throws here).
    override fun signVerifyDetached(publicKey: ByteArray, signature: ByteArray, message: ByteArray): Boolean =
        signature.size == 64 && publicKey.size == 32 &&
            ls.cryptoSignVerifyDetached(signature, message, message.size, publicKey)
}
