@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.client

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Foundation.stringWithContentsOfFile
import platform.Foundation.writeToFile

/** [JsonDeviceState] in a directory on iOS. Foundation's atomic write replaces the file by rename. */
fun fileDeviceState(dirPath: String): DeviceState = JsonDeviceState(IosDeviceStateFile(dirPath))

private class IosDeviceStateFile(private val dir: String) : DeviceStateFile {
    private val path get() = "$dir/${JsonDeviceState.FILE_NAME}"

    override fun read(): String? = NSString.stringWithContentsOfFile(path, NSUTF8StringEncoding, null)

    override fun replace(text: String) {
        NSFileManager.defaultManager.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = null, error = null)
        val ok = NSString.create(string = text).writeToFile(path, atomically = true, encoding = NSUTF8StringEncoding, error = null)
        check(ok) { "could not write ${JsonDeviceState.FILE_NAME}" }
    }
}
