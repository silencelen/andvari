@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.ios

import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.fileDeviceState
import io.silencelen.andvari.core.client.session.KeyValuePrefs
import io.silencelen.andvari.core.client.session.NamespaceStorage
import io.silencelen.andvari.core.client.session.SecretStore
import io.silencelen.andvari.core.client.sqliteVaultCache
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.CoreFoundation.CFDictionaryAddValue
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFMutableDictionaryRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFStringRef
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSFileProtectionCompleteUnlessOpen
import platform.Foundation.NSFileProtectionKey
import platform.Foundation.NSFileSize
import platform.Foundation.NSSearchPathForDirectoriesInDomains
import platform.Foundation.NSString
import platform.Foundation.NSURL
import platform.Foundation.NSURLIsExcludedFromBackupKey
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.NSUserDefaults
import platform.Foundation.NSUserDomainMask
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrAccessGroup
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
import platform.Security.kSecAttrAccount
import platform.Security.kSecAttrService
import platform.Security.kSecClass
import platform.Security.kSecClassGenericPassword
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitOne
import platform.Security.kSecReturnData
import platform.Security.kSecValueData
import platform.posix.memcpy
import platform.posix.rename

/** Non-secret state in NSUserDefaults: the app's standard defaults, or the [suite] (an App Group, later). */
internal class UserDefaultsPrefs(suite: String?) : KeyValuePrefs {
    private val defaults: NSUserDefaults = if (suite == null) NSUserDefaults.standardUserDefaults else NSUserDefaults(suiteName = suite)

    override fun getString(key: String): String? = defaults.stringForKey(key)

    override fun putString(key: String, value: String?) {
        if (value == null) defaults.removeObjectForKey(key) else defaults.setObject(value, forKey = key)
    }
}

/**
 * Secrets in the Keychain: generic passwords under [service] (and [accessGroup], when shared), readable after the
 * first unlock since boot, on this device only (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`): they never
 * reach a backup or another device.
 */
internal class KeychainSecrets(private val service: String, private val accessGroup: String?) : SecretStore {
    override fun read(name: String): String? = memScoped {
        val owned = CfOwned()
        val query = owned.dictionary(
            kSecClass to kSecClassGenericPassword,
            kSecAttrService to owned.retain(service),
            kSecAttrAccount to owned.retain(name),
            kSecReturnData to kCFBooleanTrue,
            kSecMatchLimit to kSecMatchLimitOne,
            *owned.group(accessGroup),
        )
        val out = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, out.ptr)
        owned.release()
        if (status != errSecSuccess) return@memScoped null
        val data = CFBridgingRelease(out.value) as? NSData ?: return@memScoped null
        NSString.create(data = data, encoding = NSUTF8StringEncoding)?.toString()
    }

    override fun write(name: String, value: String?): Boolean {
        val owned = CfOwned()
        try {
            val match = owned.dictionary(
                kSecClass to kSecClassGenericPassword,
                kSecAttrService to owned.retain(service),
                kSecAttrAccount to owned.retain(name),
                *owned.group(accessGroup),
            )
            if (value == null) {
                val status = SecItemDelete(match)
                return status == errSecSuccess || status == errSecItemNotFound
            }
            val data = NSString.create(string = value).dataUsingEncoding(NSUTF8StringEncoding) ?: return false
            // Update in place when the item exists, so a crash never leaves the name without a value.
            val changes = owned.dictionary(kSecValueData to owned.retain(data))
            val updated = SecItemUpdate(match, changes)
            if (updated == errSecSuccess) return true
            if (updated != errSecItemNotFound) return false
            val add = owned.dictionary(
                kSecClass to kSecClassGenericPassword,
                kSecAttrService to owned.retain(service),
                kSecAttrAccount to owned.retain(name),
                kSecAttrAccessible to kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                kSecValueData to owned.retain(data),
                *owned.group(accessGroup),
            )
            return SecItemAdd(add, null) == errSecSuccess
        } finally {
            owned.release()
        }
    }
}

/**
 * The Core Foundation objects one Keychain call builds, released together. Values are retained into the
 * dictionaries ([kCFTypeDictionaryValueCallBacks]), so the bridged copies made here are released after the call.
 */
internal class CfOwned {
    private val objects = mutableListOf<CFTypeRef>()

    /** A bridged, retained copy of [value] (a String, NSData, NSNumber or an Objective-C object). */
    fun retain(value: Any): CFTypeRef? = CFBridgingRetain(value)?.also { objects += it }

    /** The access-group entry, when there is a group. */
    fun group(accessGroup: String?): Array<Pair<CFStringRef?, CFTypeRef?>> =
        if (accessGroup == null) emptyArray() else arrayOf(kSecAttrAccessGroup to retain(accessGroup))

    fun dictionary(vararg pairs: Pair<CFStringRef?, CFTypeRef?>): CFMutableDictionaryRef? {
        val dict = CFDictionaryCreateMutable(kCFAllocatorDefault, pairs.size.convert(), kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)
        for ((key, value) in pairs) CFDictionaryAddValue(dict, key, value)
        if (dict != null) objects += dict
        return dict
    }

    fun release() {
        objects.forEach { CFRelease(it) }
        objects.clear()
    }
}

/**
 * The namespace directories (design 2026-07-15 §4.2) under Application Support/andvari: one per (origin, user),
 * excluded from backup and created with file protection that keeps an open database writable while the device
 * locks (`NSFileProtectionCompleteUnlessOpen`). The files are ciphertext either way.
 */
internal class IosNamespaceStorage(private val root: String = defaultRoot()) : NamespaceStorage {
    private fun dir(originKey: String, userId: String) = "$root/${OriginCanon.pathSafe(originKey)}/${OriginCanon.pathSafe(userId)}"

    private fun cachePath(originKey: String, userId: String) = "${dir(originKey, userId)}/vault-${OriginCanon.pathSafe(userId)}.db"

    private fun ensure(path: String): String {
        val fm = NSFileManager.defaultManager
        fm.createDirectoryAtPath(path, withIntermediateDirectories = true, attributes = mapOf<Any?, Any?>(NSFileProtectionKey to NSFileProtectionCompleteUnlessOpen), error = null)
        // Excluding the root excludes everything under it; set once more here in case the root was made elsewhere.
        NSURL.fileURLWithPath(root).setResourceValue(true, forKey = NSURLIsExcludedFromBackupKey, error = null)
        return path
    }

    override fun openVaultCache(originKey: String, userId: String): VaultCache {
        ensure(dir(originKey, userId))
        return sqliteVaultCache(cachePath(originKey, userId), userId)
    }

    override fun deviceState(originKey: String, userId: String): DeviceState = fileDeviceState(ensure(dir(originKey, userId)))

    override fun deleteVaultCache(originKey: String, userId: String) {
        val path = cachePath(originKey, userId)
        for (suffix in listOf("", "-wal", "-shm", "-journal")) {
            runCatching { NSFileManager.defaultManager.removeItemAtPath(path + suffix, error = null) }
        }
    }

    companion object {
        fun defaultRoot(): String {
            val support = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, true).firstOrNull() as? String
                ?: error("no Application Support directory")
            return "$support/andvari"
        }
    }
}

/** Bytes for the Security framework. */
internal fun ByteArray.toNSData(): NSData =
    if (isEmpty()) NSData() else usePinned { NSData.create(bytes = it.addressOf(0), length = size.convert()) }

/** Bytes out of the Security framework. */
internal fun NSData.toByteArray(): ByteArray {
    val n = length.toInt()
    if (n == 0) return ByteArray(0)
    val out = ByteArray(n)
    out.usePinned { memcpy(it.addressOf(0), bytes, length) }
    return out
}

/**
 * The AutoFill snapshot: one file, replaced by a rename so a reader sees the old one or the new one, never a torn
 * one. Ciphertext, excluded from backup, with the protection class of the vault cache.
 */
internal class FileFillSnapshots(private val path: String) : FillSnapshotStore {
    override fun write(bytes: ByteArray): Boolean = runCatching {
        val fm = NSFileManager.defaultManager
        val tmp = "$path.tmp"
        val attributes = mapOf<Any?, Any?>(NSFileProtectionKey to NSFileProtectionCompleteUnlessOpen)
        if (!fm.createFileAtPath(tmp, contents = bytes.toNSData(), attributes = attributes)) return@runCatching false
        if (rename(tmp, path) != 0) {
            fm.removeItemAtPath(tmp, error = null)
            return@runCatching false
        }
        NSURL.fileURLWithPath(path).setResourceValue(true, forKey = NSURLIsExcludedFromBackupKey, error = null)
        true
    }.getOrDefault(false)

    override fun read(): ByteArray? = runCatching { NSFileManager.defaultManager.contentsAtPath(path)?.toByteArray() }.getOrNull()

    override fun delete() {
        runCatching { NSFileManager.defaultManager.removeItemAtPath(path, error = null) }
        runCatching { NSFileManager.defaultManager.removeItemAtPath("$path.tmp", error = null) }
    }
}

/**
 * The save queue in a directory of the App Group container: `key.json` is the published key, and each queued save is
 * `q-<id>.json`. The Safari extension's native handler writes entries in this same layout
 * (SafariWebExtensionHandler.swift). Every write is a rename into place; entries are ciphertext.
 */
internal class FileSaveQueue(private val dir: String) : SaveQueueStore {
    private val fm get() = NSFileManager.defaultManager
    private val attributes get() = mapOf<Any?, Any?>(NSFileProtectionKey to NSFileProtectionCompleteUnlessOpen)

    private fun writeWhole(path: String, bytes: ByteArray): Boolean = runCatching {
        fm.createDirectoryAtPath(dir, withIntermediateDirectories = true, attributes = attributes, error = null)
        NSURL.fileURLWithPath(dir).setResourceValue(true, forKey = NSURLIsExcludedFromBackupKey, error = null)
        val tmp = "$path.tmp"
        if (!fm.createFileAtPath(tmp, contents = bytes.toNSData(), attributes = attributes)) return@runCatching false
        if (rename(tmp, path) != 0) {
            fm.removeItemAtPath(tmp, error = null)
            return@runCatching false
        }
        true
    }.getOrDefault(false)

    private fun names(): List<String> = runCatching { fm.contentsOfDirectoryAtPath(dir, error = null)?.mapNotNull { it as? String } }.getOrNull().orEmpty()

    override fun publication(): ByteArray? = runCatching { fm.contentsAtPath("$dir/$KEY_FILE")?.toByteArray() }.getOrNull()

    override fun publish(bytes: ByteArray?) {
        if (bytes == null) runCatching { fm.removeItemAtPath("$dir/$KEY_FILE", error = null) } else writeWhole("$dir/$KEY_FILE", bytes)
    }

    /**
     * The entries, bounded before anything is read: a file is sized first and never read past the entry bound, at
     * most [SaveQueue.MAX_ENTRIES] are returned, and whatever else sits in the directory as an entry (a name that is
     * not an id, an oversized file, one past the count) is removed. Another process writes here.
     */
    override fun entries(): Map<String, ByteArray> {
        val out = LinkedHashMap<String, ByteArray>()
        for (name in names().sorted()) {
            if (name == KEY_FILE) continue
            val path = "$dir/$name"
            val id = name.removePrefix(ENTRY_PREFIX).removeSuffix(ENTRY_SUFFIX)
            val listed = name.startsWith(ENTRY_PREFIX) && name.endsWith(ENTRY_SUFFIX) && SaveQueue.validId(id)
            val size = runCatching { (fm.attributesOfItemAtPath(path, error = null)?.get(NSFileSize) as? Number)?.toLong() }.getOrNull()
            if (!listed || size == null || size > SaveQueue.MAX_ENTRY_BYTES || out.size >= SaveQueue.MAX_ENTRIES) {
                // A temporary file of a write in flight is left to its writer for a moment; everything else goes.
                if (!name.endsWith(".tmp")) runCatching { fm.removeItemAtPath(path, error = null) }
                continue
            }
            runCatching { fm.contentsAtPath(path)?.toByteArray() }.getOrNull()?.let { out[id] = it }
        }
        return out
    }

    override fun put(id: String, bytes: ByteArray): Boolean = SaveQueue.validId(id) && writeWhole("$dir/$ENTRY_PREFIX$id$ENTRY_SUFFIX", bytes)

    override fun remove(id: String) {
        if (SaveQueue.validId(id)) runCatching { fm.removeItemAtPath("$dir/$ENTRY_PREFIX$id$ENTRY_SUFFIX", error = null) }
    }

    override fun clear() {
        for (name in names()) runCatching { fm.removeItemAtPath("$dir/$name", error = null) }
    }

    private companion object {
        const val KEY_FILE = "key.json"
        const val ENTRY_PREFIX = "q-"
        const val ENTRY_SUFFIX = ".json"
    }
}
