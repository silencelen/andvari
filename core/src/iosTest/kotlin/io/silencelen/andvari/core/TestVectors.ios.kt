@file:OptIn(ExperimentalForeignApi::class)

package io.silencelen.andvari.core

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.stringWithContentsOfFile
import platform.posix.getenv

actual fun readVector(name: String): String {
    val dir = getenv("ANDVARI_VECTORS_DIR")?.toKString() ?: error("ANDVARI_VECTORS_DIR not set")
    return NSString.stringWithContentsOfFile("$dir/$name", NSUTF8StringEncoding, null) ?: error("cannot read $name")
}

actual fun newTempDir(prefix: String): String {
    val path = NSTemporaryDirectory() + prefix + NSUUID().UUIDString
    NSFileManager.defaultManager.createDirectoryAtPath(path, withIntermediateDirectories = true, attributes = null, error = null)
    return path
}

actual fun deleteDir(path: String) {
    NSFileManager.defaultManager.removeItemAtPath(path, error = null)
}
