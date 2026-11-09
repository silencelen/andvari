package io.silencelen.andvari.core.client

import java.io.File

/**
 * [JsonDeviceState] in a directory on the JVM and Android. Writes go to a sibling temp file and are
 * renamed over the target, so a crash mid-write leaves the previous copy.
 */
class FileDeviceState(dir: File) : DeviceState by JsonDeviceState(JvmDeviceStateFile(dir)) {
    companion object {
        const val FILE_NAME = JsonDeviceState.FILE_NAME
    }
}

private class JvmDeviceStateFile(private val dir: File) : DeviceStateFile {
    private val file get() = File(dir, JsonDeviceState.FILE_NAME)

    override fun read(): String? = runCatching { file.readText() }.getOrNull()

    override fun replace(text: String) {
        dir.mkdirs()
        val tmp = File(dir, "${JsonDeviceState.FILE_NAME}.tmp")
        tmp.delete()
        tmp.createNewFile()
        // Owner-only before any byte is written (best effort: a no-op where the platform has no such bits).
        tmp.setReadable(false, false); tmp.setReadable(true, true)
        tmp.setWritable(false, false); tmp.setWritable(true, true)
        tmp.writeText(text)
        if (!tmp.renameTo(file)) {
            file.delete()
            if (!tmp.renameTo(file)) { file.writeText(tmp.readText()); tmp.delete() }
        }
    }
}
