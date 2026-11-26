package io.silencelen.andvari.app.trust

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.InputStream

/**
 * Reading a document the person picked, never past a limit. A pick could be any size, and reading it whole before its
 * size is known would take the app down on a very large one. So the document's size is asked first
 * ([OpenableColumns.SIZE]); because a provider can say nothing or say less than it gives, the read itself also stops one
 * byte past the limit. Every buffer the read let go of is zeroed: a picked file can be a secret.
 */
internal object PickedFiles {
    /** What reading a pick came to. */
    sealed class Picked {
        /** The whole document, at most the limit. The caller owns [bytes] and zeroes them. */
        class Read(val name: String, val bytes: ByteArray) : Picked()

        /** Larger than the limit: [size] is what the provider said, or the limit plus one when it said less or nothing. */
        class TooLarge(val size: Long) : Picked()

        /** It could not be opened or read. */
        data object NotRead : Picked()
    }

    /** The first buffer when the size is not known; it grows by doubling, up to the limit plus one. */
    private const val FIRST_BUFFER = 64 * 1024

    /**
     * The whole of [input] when it is at most [limit] bytes, or null when there is more ([limit] + 1 bytes are read at
     * most). [sizeHint] (the size the provider gave) only sizes the first buffer. Nothing that is let go is left unzeroed.
     */
    fun readAtMost(input: InputStream, limit: Int, sizeHint: Long? = null): ByteArray? {
        require(limit >= 0)
        val cap = if (limit == Int.MAX_VALUE) limit else limit + 1
        val first = (sizeHint?.takeIf { it in 0..cap.toLong() }?.toInt()?.let { it + 1 } ?: FIRST_BUFFER).coerceIn(1, cap.coerceAtLeast(1))
        var buf = ByteArray(first)
        var n = 0
        try {
            while (n < cap) {
                if (n == buf.size) {
                    val grown = buf.copyOf(minOf(cap, if (buf.size > cap / 2) cap else buf.size * 2))
                    buf.fill(0)
                    buf = grown
                }
                val got = input.read(buf, n, buf.size - n)
                if (got < 0) break
                n += got
            }
            if (n > limit) return null
            val out = buf.copyOf(n)
            return out
        } finally {
            buf.fill(0)
        }
    }

    /** What the provider says the document's size is, or null when it does not say. */
    fun declaredSize(context: Context, uri: Uri): Long? = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { cur ->
            if (cur.moveToFirst() && !cur.isNull(0)) cur.getLong(0) else null
        }
    }.getOrNull()?.takeIf { it >= 0 }

    /** The display name the provider gives the document, or null. */
    fun queriedName(context: Context, uri: Uri): String? = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cur ->
            if (cur.moveToFirst() && !cur.isNull(0)) cur.getString(0) else null
        }
    }.getOrNull()

    /** The document's display name, or the URI's last segment. */
    fun displayName(context: Context, uri: Uri): String? = queriedName(context, uri) ?: uri.lastPathSegment

    /** Reads the document at [uri] when it is at most [limit] bytes. Blocking: call it off the main thread. */
    fun read(context: Context, uri: Uri, limit: Long): Picked {
        val max = limit.coerceIn(0, Int.MAX_VALUE.toLong() - 1).toInt()
        val declared = declaredSize(context, uri)
        if (declared != null && declared > max) return Picked.TooLarge(declared)
        val name = displayName(context, uri) ?: return Picked.NotRead
        return try {
            val input = context.contentResolver.openInputStream(uri) ?: return Picked.NotRead
            input.use { readAtMost(it, max, declared) }?.let { Picked.Read(name, it) } ?: Picked.TooLarge(max.toLong() + 1)
        } catch (e: Exception) {
            Picked.NotRead
        }
    }
}
