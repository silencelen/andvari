package io.silencelen.andvari.core.client

import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File

/**
 * File-backed [DeviceState] for both native apps (security review 2026-10, root cause A, branch A5b, M-1):
 * one small JSON map, [FILE_NAME], in the (origin, user) namespace directory the platform passes. The
 * platform purges (cache policy flip, revocation, sign-out) delete named files in that directory and never
 * this one, exactly like the self-identity pin. Values are public ids or UVK-sealed blobs.
 *
 * Writes go to a sibling temp file and are renamed over the target, so a crash mid-write leaves the previous
 * copy. A file that does not parse reads as empty (local corruption is not an adversary capability here;
 * the device then behaves like one that never saw a wrap, which asks the human and mints nothing on its own).
 */
class FileDeviceState(private val dir: File) : DeviceState {
    companion object {
        const val FILE_NAME = "device-state.json"
        private val json = Json { ignoreUnknownKeys = true }
        private val codec = MapSerializer(String.serializer(), String.serializer())
    }

    private val file get() = File(dir, FILE_NAME)

    @Synchronized
    private fun readAll(): Map<String, String> =
        runCatching { json.decodeFromString(codec, file.readText()) }.getOrDefault(emptyMap())

    override fun get(key: String): String? = readAll()[key]

    @Synchronized
    override fun set(key: String, value: String?) {
        val next = readAll().toMutableMap()
        if (value == null) { if (next.remove(key) == null) return } else { if (next[key] == value) return; next[key] = value }
        dir.mkdirs()
        val tmp = File(dir, "$FILE_NAME.tmp")
        tmp.delete()
        tmp.createNewFile()
        // Owner-only before any byte is written (best effort: a no-op where the platform has no such bits).
        tmp.setReadable(false, false); tmp.setReadable(true, true)
        tmp.setWritable(false, false); tmp.setWritable(true, true)
        tmp.writeText(json.encodeToString(codec, next))
        if (!tmp.renameTo(file)) {
            file.delete()
            if (!tmp.renameTo(file)) { file.writeText(tmp.readText()); tmp.delete() }
        }
    }
}
