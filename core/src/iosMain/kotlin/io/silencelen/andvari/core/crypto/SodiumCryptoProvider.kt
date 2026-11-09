@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core.crypto

import io.silencelen.andvari.core.crypto.sodium.*
import kotlinx.cinterop.*
import platform.CoreCrypto.*

/**
 * iOS [CryptoProvider]: libsodium through cinterop, and CommonCrypto for the HMAC and hash primitives
 * the JVM adapter takes from javax.crypto. The size guards and the exception type chosen for each one
 * match LazySodiumCryptoProvider line for line, because the unlock and save ladders classify on them:
 * a bad input on an OPEN path is a [CryptoException] (a result), on a SEAL path an
 * IllegalArgumentException (our own bug). spec/test-vectors pins the outputs.
 */
internal class SodiumCryptoProvider : CryptoProvider {

    private companion object {
        val AEAD_KEY = crypto_aead_xchacha20poly1305_ietf_keybytes().toInt()
        val AEAD_NONCE = crypto_aead_xchacha20poly1305_ietf_npubbytes().toInt()
        val AEAD_TAG = crypto_aead_xchacha20poly1305_ietf_abytes().toInt()
        val BOX_SEED = crypto_box_seedbytes().toInt()
        val BOX_PUB = crypto_box_publickeybytes().toInt()
        val BOX_SEC = crypto_box_secretkeybytes().toInt()
        val BOX_SEAL = crypto_box_sealbytes().toInt()
        val SIGN_SEED = crypto_sign_seedbytes().toInt()
        val SIGN_PUB = crypto_sign_publickeybytes().toInt()
        val SIGN_SEC = crypto_sign_secretkeybytes().toInt()
        val SIGN_BYTES = crypto_sign_bytes().toInt()
        val STREAM_KEY = crypto_secretstream_xchacha20poly1305_keybytes().toInt()
        val STREAM_HEADER = crypto_secretstream_xchacha20poly1305_headerbytes().toInt()
        val STREAM_TAG = crypto_secretstream_xchacha20poly1305_abytes().toInt()
        val TAG_MESSAGE = crypto_secretstream_xchacha20poly1305_tag_message()
        val TAG_FINAL = crypto_secretstream_xchacha20poly1305_tag_final()
        val PWHASH_SALT = crypto_pwhash_saltbytes().toInt()
    }

    /** A valid pointer for every array: `addressOf(0)` throws on an empty one, and a zero-length input is legal. */
    private inline fun <R> ByteArray.u(block: (CPointer<UByteVar>) -> R): R =
        (if (isEmpty()) ByteArray(1) else this).usePinned { block(it.addressOf(0).reinterpret()) }

    private inline fun <R> ByteArray.b(block: (CPointer<ByteVar>) -> R): R =
        (if (isEmpty()) ByteArray(1) else this).usePinned { block(it.addressOf(0)) }

    override fun randomBytes(n: Int): ByteArray {
        val out = ByteArray(n)
        out.u { randombytes_buf(it, n.toULong()) }
        return out
    }

    override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
        require(salt.size == PWHASH_SALT) { "argon2id salt must be $PWHASH_SALT bytes" }
        val out = ByteArray(outLen)
        val rc = out.u { o ->
            password.b { p ->
                salt.u { s ->
                    crypto_pwhash(
                        o, outLen.toULong(), p, password.size.toULong(), s,
                        opsLimit.toULong(), memLimitBytes.toULong(), crypto_pwhash_alg_argon2id13(),
                    )
                }
            }
        }
        if (rc != 0) throw CryptoException("crypto_pwhash (argon2id) failed")
        return out
    }

    private fun hmac(algorithm: CCHmacAlgorithm, size: Int, key: ByteArray, data: ByteArray): ByteArray {
        require(key.isNotEmpty()) { "Empty key" } // javax.crypto's SecretKeySpec refuses it too
        val out = ByteArray(size)
        out.u { o -> key.u { k -> data.u { d -> CCHmac(algorithm, k, key.size.toULong(), d, data.size.toULong(), o) } } }
        return out
    }

    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray = hmac(kCCHmacAlgSHA256, CC_SHA256_DIGEST_LENGTH, key, data)

    override fun hmacSha1(key: ByteArray, data: ByteArray): ByteArray = hmac(kCCHmacAlgSHA1, CC_SHA1_DIGEST_LENGTH, key, data)

    override fun hmacSha512(key: ByteArray, data: ByteArray): ByteArray = hmac(kCCHmacAlgSHA512, CC_SHA512_DIGEST_LENGTH, key, data)

    override fun sha256(data: ByteArray): ByteArray {
        val out = ByteArray(CC_SHA256_DIGEST_LENGTH)
        out.u { o -> data.u { d -> CC_SHA256(d, data.size.toUInt(), o) } }
        return out
    }

    override fun sha1(data: ByteArray): ByteArray {
        val out = ByteArray(CC_SHA1_DIGEST_LENGTH)
        out.u { o -> data.u { d -> CC_SHA1(d, data.size.toUInt(), o) } }
        return out
    }

    override fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray {
        require(key.size == AEAD_KEY) { "AEAD key must be 32 bytes" }
        require(nonce.size == AEAD_NONCE) { "AEAD nonce must be 24 bytes" }
        val out = ByteArray(plaintext.size + AEAD_TAG)
        val rc = out.u { o ->
            plaintext.u { m ->
                ad.u { a ->
                    nonce.u { n ->
                        key.u { k ->
                            crypto_aead_xchacha20poly1305_ietf_encrypt(
                                o, null, m, plaintext.size.toULong(), a, ad.size.toULong(), null, n, k,
                            )
                        }
                    }
                }
            }
        }
        if (rc != 0) throw CryptoException("xchacha20poly1305 encrypt failed")
        return out
    }

    override fun aeadDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, ad: ByteArray): ByteArray {
        if (key.size != AEAD_KEY) throw CryptoException("AEAD key must be 32 bytes")
        if (nonce.size != AEAD_NONCE) throw CryptoException("AEAD nonce must be 24 bytes")
        if (ciphertext.size < AEAD_TAG) throw CryptoException("ciphertext too short")
        val out = ByteArray(ciphertext.size - AEAD_TAG)
        val rc = out.u { o ->
            ciphertext.u { c ->
                ad.u { a ->
                    nonce.u { n ->
                        key.u { k ->
                            crypto_aead_xchacha20poly1305_ietf_decrypt(
                                o, null, null, c, ciphertext.size.toULong(), a, ad.size.toULong(), n, k,
                            )
                        }
                    }
                }
            }
        }
        if (rc != 0) throw CryptoException("xchacha20poly1305 decrypt failed (bad MAC or AD)")
        return out
    }

    override fun boxKeypairFromSeed(seed: ByteArray): KeyPairBytes {
        require(seed.size == BOX_SEED) { "box seed must be $BOX_SEED bytes" }
        val pk = ByteArray(BOX_PUB)
        val sk = ByteArray(BOX_SEC)
        val rc = pk.u { p -> sk.u { s -> seed.u { d -> crypto_box_seed_keypair(p, s, d) } } }
        if (rc != 0) throw CryptoException("crypto_box_seed_keypair failed")
        return KeyPairBytes(pk, sk)
    }

    override fun sealTo(recipientPublicKey: ByteArray, plaintext: ByteArray): ByteArray {
        if (recipientPublicKey.size != BOX_PUB) throw CryptoException("box public key must be $BOX_PUB bytes")
        val out = ByteArray(plaintext.size + BOX_SEAL)
        val rc = out.u { o -> plaintext.u { m -> recipientPublicKey.u { p -> crypto_box_seal(o, m, plaintext.size.toULong(), p) } } }
        if (rc != 0) throw CryptoException("crypto_box_seal failed")
        return out
    }

    override fun sealOpen(publicKey: ByteArray, privateKey: ByteArray, sealed: ByteArray): ByteArray {
        if (publicKey.size != BOX_PUB) throw CryptoException("box public key must be $BOX_PUB bytes")
        if (privateKey.size != BOX_SEC) throw CryptoException("box private key must be $BOX_SEC bytes")
        if (sealed.size < BOX_SEAL) throw CryptoException("sealed box too short")
        val out = ByteArray(sealed.size - BOX_SEAL)
        val rc = out.u { o ->
            sealed.u { c -> publicKey.u { p -> privateKey.u { s -> crypto_box_seal_open(o, c, sealed.size.toULong(), p, s) } } }
        }
        if (rc != 0) throw CryptoException("crypto_box_seal_open failed (wrong key or corrupt box)")
        return out
    }

    override fun secretstreamEncrypt(key: ByteArray, chunks: List<ByteArray>): SecretStreamResult = memScoped {
        require(key.size == STREAM_KEY) { "secretstream key must be $STREAM_KEY bytes" }
        val state = alloc<crypto_secretstream_xchacha20poly1305_state>()
        val header = ByteArray(STREAM_HEADER)
        val init = header.u { h -> key.u { k -> crypto_secretstream_xchacha20poly1305_init_push(state.ptr, h, k) } }
        if (init != 0) throw CryptoException("secretstream init_push failed")
        val out = chunks.mapIndexed { i, chunk ->
            val tag = if (i == chunks.lastIndex) TAG_FINAL else TAG_MESSAGE
            val cipher = ByteArray(chunk.size + STREAM_TAG)
            val rc = cipher.u { c ->
                chunk.u { m ->
                    crypto_secretstream_xchacha20poly1305_push(state.ptr, c, null, m, chunk.size.toULong(), null, 0u, tag.toUByte())
                }
            }
            if (rc != 0) throw CryptoException("secretstream push failed at chunk $i")
            cipher
        }
        SecretStreamResult(header, out)
    }

    override fun secretstreamDecrypt(key: ByteArray, header: ByteArray, chunks: List<ByteArray>): List<ByteArray> = memScoped {
        if (key.size != STREAM_KEY) throw CryptoException("secretstream key must be $STREAM_KEY bytes")
        if (header.size != STREAM_HEADER) throw CryptoException("secretstream header must be $STREAM_HEADER bytes")
        val state = alloc<crypto_secretstream_xchacha20poly1305_state>()
        val init = header.u { h -> key.u { k -> crypto_secretstream_xchacha20poly1305_init_pull(state.ptr, h, k) } }
        if (init != 0) throw CryptoException("secretstream init_pull failed (bad header)")
        val tag = alloc<UByteVar>()
        chunks.mapIndexed { i, cipher ->
            if (cipher.size < STREAM_TAG) throw CryptoException("secretstream chunk $i too short")
            val message = ByteArray(cipher.size - STREAM_TAG)
            val rc = message.u { m ->
                cipher.u { c ->
                    crypto_secretstream_xchacha20poly1305_pull(state.ptr, m, null, tag.ptr, c, cipher.size.toULong(), null, 0u)
                }
            }
            if (rc != 0) throw CryptoException("secretstream pull failed at chunk $i (corrupt or reordered)")
            val isLast = i == chunks.lastIndex
            val isFinal = tag.value == TAG_FINAL
            if (isLast != isFinal) throw CryptoException("secretstream truncated or trailing data (final-tag mismatch)")
            message
        }
    }

    override fun signVerifyDetached(publicKey: ByteArray, signature: ByteArray, message: ByteArray): Boolean =
        signature.size == 64 && publicKey.size == 32 &&
            signature.u { s -> message.u { m -> publicKey.u { p -> crypto_sign_verify_detached(s, m, message.size.toULong(), p) } } } == 0

    override fun signKeypairFromSeed(seed: ByteArray): KeyPairBytes {
        require(seed.size == SIGN_SEED) { "sign seed must be $SIGN_SEED bytes" }
        val pk = ByteArray(SIGN_PUB)
        val sk = ByteArray(SIGN_SEC)
        val rc = pk.u { p -> sk.u { s -> seed.u { d -> crypto_sign_seed_keypair(p, s, d) } } }
        if (rc != 0) throw CryptoException("crypto_sign_seed_keypair failed")
        return KeyPairBytes(pk, sk)
    }

    override fun signDetached(secretKey: ByteArray, message: ByteArray): ByteArray {
        require(secretKey.size == SIGN_SEC) { "sign secret key must be $SIGN_SEC bytes" }
        val sig = ByteArray(SIGN_BYTES)
        val rc = sig.u { s -> message.u { m -> secretKey.u { k -> crypto_sign_detached(s, null, m, message.size.toULong(), k) } } }
        if (rc != 0) throw CryptoException("crypto_sign_detached failed")
        return sig
    }

    override fun ed25519PkToCurve25519(ed25519PublicKey: ByteArray): ByteArray {
        if (ed25519PublicKey.size != SIGN_PUB) throw CryptoException("ed25519 public key must be $SIGN_PUB bytes")
        val out = ByteArray(BOX_PUB)
        val rc = out.u { o -> ed25519PublicKey.u { p -> crypto_sign_ed25519_pk_to_curve25519(o, p) } }
        if (rc != 0) throw CryptoException("ed25519 public key has no curve25519 image (invalid or small-order point)")
        return out
    }
}
