package io.silencelen.andvari.core.crypto

/**
 * Attachment content crypto (spec 02 §6): crypto_secretstream_xchacha20poly1305
 * over 64 KiB plaintext chunks. The wire/storage shape is `header (24B)` followed
 * by the ordered ciphertext chunks concatenated; chunk boundaries are implicit
 * because every ciphertext chunk except the last is exactly CIPHER_CHUNK bytes.
 */
object Attachments {
    const val CHUNK = 64 * 1024
    const val STREAM_ABYTES = 17 // secretstream per-chunk overhead
    const val CIPHER_CHUNK = CHUNK + STREAM_ABYTES
    const val HEADER_BYTES = 24

    class Encrypted(val header: ByteArray, val ciphertext: ByteArray)

    /** Chunk + encrypt. Empty plaintext is rejected (spec: last chunk is 1..65536 bytes). */
    fun encrypt(crypto: CryptoProvider, fileKey: ByteArray, plaintext: ByteArray): Encrypted {
        if (plaintext.isEmpty()) throw CryptoException("attachment plaintext must not be empty")
        val chunks = ArrayList<ByteArray>((plaintext.size + CHUNK - 1) / CHUNK)
        var off = 0
        while (off < plaintext.size) {
            val end = minOf(off + CHUNK, plaintext.size)
            chunks.add(plaintext.copyOfRange(off, end))
            off = end
        }
        val result = crypto.secretstreamEncrypt(fileKey, chunks)
        val total = result.chunks.sumOf { it.size }
        val out = ByteArray(total)
        var o = 0
        for (c in result.chunks) {
            c.copyInto(out, o)
            o += c.size
        }
        return Encrypted(result.header, out)
    }

    /** Split the concatenated ciphertext back into chunks by the fixed chunk size. */
    fun splitChunks(ciphertext: ByteArray): List<ByteArray> {
        if (ciphertext.size <= STREAM_ABYTES) throw CryptoException("attachment ciphertext truncated")
        val n = (ciphertext.size + CIPHER_CHUNK - 1) / CIPHER_CHUNK
        val last = ciphertext.size - (n - 1) * CIPHER_CHUNK
        if (last <= STREAM_ABYTES) throw CryptoException("attachment ciphertext has a malformed final chunk")
        return (0 until n).map { i ->
            val start = i * CIPHER_CHUNK
            val end = if (i == n - 1) start + last else start + CIPHER_CHUNK
            ciphertext.copyOfRange(start, end)
        }
    }

    /** Decrypt; throws [CryptoException] on any corrupt, reordered, or truncated chunk (spec 02 §6). */
    fun decrypt(crypto: CryptoProvider, fileKey: ByteArray, header: ByteArray, ciphertext: ByteArray): ByteArray {
        if (header.size != HEADER_BYTES) throw CryptoException("attachment header must be $HEADER_BYTES bytes")
        val plain = crypto.secretstreamDecrypt(fileKey, header, splitChunks(ciphertext))
        val total = plain.sumOf { it.size }
        val out = ByteArray(total)
        var o = 0
        for (p in plain) {
            p.copyInto(out, o)
            o += p.size
        }
        return out
    }
}
