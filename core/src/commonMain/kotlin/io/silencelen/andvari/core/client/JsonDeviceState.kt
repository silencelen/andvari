package io.silencelen.andvari.core.client

import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

/** The platform half of a file-backed [DeviceState]: one small file, read whole and replaced whole. */
interface DeviceStateFile {
    /** The current contents, or null when there is no file. A file that is there and cannot be read may throw instead
     *  (iOS, while the device keeps it protected), and nothing is then written over it. */
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
 * A file that cannot be read, or does not parse, is never taken for an empty one (design §4.4 "A trust record that
 * cannot be read is not an empty one"): [get] throws and [set] writes nothing, because [set] writes the whole map
 * back and that would replace every record (pins, fork marks, high-water marks, vault checkpoints) with what is
 * written next. The engine reads a throwing record as unknown and keeps what it guards closed (a pin reads as
 * damaged). The way out is the platform's: removing the namespace ("Forget this server").
 */
class JsonDeviceState(private val file: DeviceStateFile) : DeviceState {
    companion object {
        const val FILE_NAME = "device-state.json"
        private val json = Json { ignoreUnknownKeys = true }
        private val codec = MapSerializer(String.serializer(), String.serializer())
    }

    private val lock = SynchronizedObject()

    private fun readAll(): Map<String, String> {
        val text = file.read() ?: return emptyMap()
        return runCatching { json.decodeFromString(codec, text) }.getOrNull() ?: throw IllegalStateException("device state does not parse")
    }

    override fun get(key: String): String? = synchronized(lock) { readAll()[key] }

    override fun keys(): Set<String> = synchronized(lock) { readAll().keys.toSet() }

    override fun set(key: String, value: String?): Unit = synchronized(lock) {
        val next = readAll().toMutableMap()
        if (value == null) { if (next.remove(key) == null) return } else { if (next[key] == value) return; next[key] = value }
        file.replace(json.encodeToString(codec, next))
    }
}
