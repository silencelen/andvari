@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.client

import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Foundation.NSDataWritingAtomic
import platform.Foundation.NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.Foundation.stringWithContentsOfFile
import platform.Foundation.writeToFile

/** [JsonDeviceState] in a directory on iOS. Foundation's atomic write replaces the file by rename. */
fun fileDeviceState(dirPath: String): DeviceState = JsonDeviceState(IosDeviceStateFile(dirPath))

/**
 * The device state, readable after the first unlock since the device started
 * (NSFileProtectionCompleteUntilFirstUserAuthentication, not the app's default Complete): it is read whole on every
 * look-up, and a sync or a save in the upload grace can look up and write while the person has locked the phone
 * (IosStorage.kt FileClasses). Its values are public ids, key tags and UVK-sealed blobs.
 */
private class IosDeviceStateFile(private val dir: String) : DeviceStateFile {
    private val path get() = "$dir/${JsonDeviceState.FILE_NAME}"

    /** Null when there is no file; a file that is there and cannot be read (protected now) throws, so that nothing writes
     *  over a state it could not read. */
    override fun read(): String? {
        val text = NSString.stringWithContentsOfFile(path, NSUTF8StringEncoding, null)
        if (text == null && NSFileManager.defaultManager.fileExistsAtPath(path)) error("${JsonDeviceState.FILE_NAME} cannot be read now")
        return text
    }

    override fun replace(text: String) {
        NSFileManager.defaultManager.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = null, error = null)
        val data = NSString.create(string = text).dataUsingEncoding(NSUTF8StringEncoding) ?: error("could not encode ${JsonDeviceState.FILE_NAME}")
        val ok = data.writeToFile(path, options = NSDataWritingAtomic or NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication, error = null)
        check(ok) { "could not write ${JsonDeviceState.FILE_NAME}" }
    }
}
