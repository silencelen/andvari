package io.silencelen.andvari.core.client

import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/** The platform half of a file-backed [DeviceState]: one small file, read whole and replaced whole. */
interface DeviceStateFile {
    /** The current contents, or null when there is no readable file. */
    fun read(): String?

    /** Replaces the contents so that a crash leaves the old copy or the new one, never part of one. */
    fun replace(text: String)
}

/**
 * File-backed [DeviceState] for the native apps (security review 2026-10, root cause A, branch A5b, M-1):
 * one small JSON map, [FILE_NAME], in the (origin, user) namespace directory the platform passes. The
 * platform purges (cache policy flip, revocation, sign-out) delete named files in that directory and never
 * this one, exactly like the self-identity pin. Values are public ids or UVK-sealed blobs.
 *
 * A file that does not parse reads as empty (local corruption is not an adversary capability here; the
 * device then behaves like one that never saw a wrap, which asks the human and mints nothing on its own).
 */
class JsonDeviceState(private val file: DeviceStateFile) : DeviceState {
    companion object {
        const val FILE_NAME = "device-state.json"
        private val json = Json { ignoreUnknownKeys = true }
        private val codec = MapSerializer(String.serializer(), String.serializer())
    }

    private val lock = SynchronizedObject()

    private fun readAll(): Map<String, String> =
        runCatching { file.read()?.let { json.decodeFromString(codec, it) } }.getOrNull() ?: emptyMap()

    override fun get(key: String): String? = synchronized(lock) { readAll()[key] }

    override fun set(key: String, value: String?): Unit = synchronized(lock) {
        val next = readAll().toMutableMap()
        if (value == null) { if (next.remove(key) == null) return } else { if (next[key] == value) return; next[key] = value }
        file.replace(json.encodeToString(codec, next))
    }
}
