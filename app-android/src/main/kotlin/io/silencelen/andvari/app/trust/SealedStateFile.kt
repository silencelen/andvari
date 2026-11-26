package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.client.DeviceStateFile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/** Bytes kept in one file, replaced whole. */
internal interface BytesFile {
    /** The contents, or null when there is no file. An I/O failure other than "no file" throws. */
    fun read(): ByteArray?

    fun write(bytes: ByteArray)

    fun delete()

    val exists: Boolean
}

/** What seals the session-grade store. [open] throws [KeyGone] when the key is gone for good; any other throw is the key store not answering. */
internal interface Sealer {
    fun seal(plain: ByteArray): ByteArray

    fun open(sealed: ByteArray): ByteArray
}

/** The key a sealed file was made with is gone for good (or the bytes are not a file this app made): asking again changes nothing. */
internal class KeyGone(cause: Throwable? = null) : Exception(cause)

/**
 * The session-grade store's file logic (the engine's `secure`), apart from Android's Keystore so a JVM test can drive it
 * ([KeystoreSealedFile] is the app's instance).
 *
 * A kept session that cannot be opened is
 * "unknown", never "no session", and what was set aside is read back when the key store answers again.
 * - A key store that does not answer is asked again ([tries], with [pause] between) before its refusal is taken; a key
 *   that is gone for good ([KeyGone]) is not asked again.
 * - A file that still cannot be opened is copied aside, whole, before core sees "nothing" (core cannot yet take a
 *   throwing read of its session as "unknown": that is asked of core), so nothing core writes next can destroy it.
 * - At every later read, the copy set aside is tried again. When it opens, what it held is read back: its records come
 *   back under what the live file holds now (a record written since wins), the result is written to the live file and
 *   the copy goes. Core never saw what was set aside, so nothing in it was cleared on purpose.
 * - The copy also goes when a new session is written and opened ([newSessionWritten]): the person signed in again.
 */
internal class SealedStateFile(
    private val main: BytesFile,
    private val aside: BytesFile,
    private val sealer: Sealer,
    private val tries: Int = 3,
    private val pause: (attempt: Int) -> Unit = {},
) : DeviceStateFile {
    /** A copy is set aside because it could not be opened: the first screen says the saved sign-in can't be read now. */
    val unreadable: Boolean get() = aside.exists

    override fun read(): String? {
        val sealed = main.read()
        val live = sealed?.let { open(it) }
        val kept = aside.read()
        if (kept != null) {
            val back = open(kept) ?: return live // still unreadable: what the live file holds, if anything
            if (sealed != null && live == null) return back // the live file cannot be opened now: nothing is written over it
            val merged = merge(back, live)
            runCatching {
                main.write(sealer.seal(merged.encodeToByteArray()))
                aside.delete()
            }
            return merged
        }
        if (sealed != null && live == null && !aside.exists) runCatching { aside.write(sealed) }
        return live
    }

    /** A new session was written and opened: the copy set aside has been replaced and goes. */
    fun newSessionWritten() {
        if (aside.exists) aside.delete()
    }

    override fun replace(text: String) {
        main.write(sealer.seal(text.encodeToByteArray()))
    }

    /** The text, or null when it cannot be opened after [tries] (a key that is gone is not asked again). */
    private fun open(sealed: ByteArray): String? {
        val attempts = tries.coerceAtLeast(1)
        for (attempt in 1..attempts) {
            try {
                return sealer.open(sealed).decodeToString()
            } catch (gone: KeyGone) {
                return null
            } catch (t: Exception) {
                if (attempt < attempts) pause(attempt)
            }
        }
        return null
    }

    private companion object {
        val json = Json { ignoreUnknownKeys = true }

        fun parse(text: String): JsonObject? = runCatching { json.parseToJsonElement(text).jsonObject }.getOrNull()

        /** [io.silencelen.andvari.core.client.JsonDeviceState]'s flat map: the records set aside, the live file's over them. */
        fun merge(back: String, live: String?): String {
            if (live == null) return back
            val kept = parse(back) ?: return live
            val now = parse(live) ?: return live
            return JsonObject(kept + now).toString()
        }
    }
}
