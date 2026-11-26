@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.ios

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.content.KeptStorage
import io.silencelen.andvari.core.client.DeviceStateFile
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.pin.NamespaceMover
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSFileProtectionKey
import platform.Foundation.NSString
import platform.Foundation.NSURL
import platform.Foundation.NSURLIsExcludedFromBackupKey
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.Security.SecItemAdd
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecItemUpdate
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
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
import platform.posix.ENOENT
import platform.posix.RENAME_EXCL
import platform.posix.errno
import platform.posix.renamex_np
import platform.posix.usleep

/**
 * The new path's session-grade store on the iPhone (the engine's `secure`; Android's `KeystoreSealedFile`): the whole
 * JSON map of [io.silencelen.andvari.core.client.JsonDeviceState] as ONE generic-password Keychain item, [service] /
 * [account], readable after the first unlock since boot, on this device only
 * (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, as the old path's tokens): it never reaches a backup or another
 * device. It holds the session's tokens, an operator-help request key and, once quick unlock exists, the sealed
 * vault-key record ([io.silencelen.andvari.core.client.session.QuickUnlockKeeper]); none of it is shared with the
 * extensions (design 2026-11-09, "What is at rest").
 *
 * No access group is named, as the old path's tokens name none: the item goes to the app's DEFAULT group. Today the
 * app's only entitlement is `com.apple.security.application-groups`, and an App Group comes LAST in the default order
 * (Apple, "Sharing access to keychain items among a collection of apps"), so the default is the app's own
 * application-identifier group. MAC DAY: read the item back with `kSecReturnAttributes` and check that its
 * `kSecAttrAccessGroup` is `<team>.com.silencelen.andvari`, not `group.com.silencelen.andvari`; and anyone who adds a
 * `keychain-access-groups` entitlement must keep the app's own group first.
 *
 * **Unknown is never "no session"** (the rule the Android app keeps too, which this follows): the Keychain answers
 * "not found" for no item and something else when the item is there but cannot be read now. Only "not found" reads as
 * nothing. Any other answer is asked again ([tries], with a short pause), then core is handed "nothing" (core cannot
 * yet take a throwing read of its session as "unknown": it would not start) and [unreadable] says so for the first
 * screen. Unlike Android's file nothing has to be set aside: the item stays where it is, and the Keychain itself refuses
 * to write over an item it cannot open now (an update fails, and an add finds a duplicate), so [replace] throws and
 * nothing core writes meanwhile can destroy it. The next read finds it again.
 * MAC DAY: which status a device that has not been unlocked since boot answers (expected
 * `errSecInteractionNotAllowed`, -25308), and that an update then fails rather than replacing the item.
 */
internal class KeychainStateFile(
    private val service: String,
    private val account: String,
    private val tries: Int = 3,
    private val pause: (attempt: Int) -> Unit = { usleep((50_000 * it).convert()) },
) : DeviceStateFile {
    /** The item is there but could not be read at the last read: the first screen says the saved sign-in can't be read now. */
    var unreadable: Boolean = false
        private set

    override fun read(): String? {
        val attempts = tries.coerceAtLeast(1)
        for (attempt in 1..attempts) {
            when (val got = readOnce()) {
                is Got.Text -> {
                    unreadable = false
                    return got.text
                }
                Got.None -> {
                    unreadable = false
                    return null
                }
                is Got.Status -> if (attempt < attempts) pause(attempt)
            }
        }
        unreadable = true
        return null
    }

    /** A new session was written and read back: nothing is held back any more. */
    fun signedInAgain() {
        unreadable = false
    }

    private sealed class Got {
        class Text(val text: String) : Got()

        data object None : Got()

        class Status(val status: Int) : Got()
    }

    private fun readOnce(): Got = memScoped {
        val owned = CfOwned()
        try {
            val query = owned.dictionary(
                kSecClass to kSecClassGenericPassword,
                kSecAttrService to owned.retain(service),
                kSecAttrAccount to owned.retain(account),
                kSecReturnData to kCFBooleanTrue,
                kSecMatchLimit to kSecMatchLimitOne,
            )
            val out = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, out.ptr)
            if (status == errSecItemNotFound) return@memScoped Got.None
            if (status != errSecSuccess) return@memScoped Got.Status(status)
            val data = CFBridgingRelease(out.value) as? NSData ?: return@memScoped Got.Status(status)
            // An item that is there and does not decode is not "no session" either.
            val text = NSString.create(data = data, encoding = NSUTF8StringEncoding)?.toString() ?: return@memScoped Got.Status(status)
            Got.Text(text)
        } finally {
            owned.release()
        }
    }

    /** Throws when the Keychain refused: a failure is never swallowed (core then keeps what it had). */
    override fun replace(text: String) {
        val owned = CfOwned()
        try {
            val data = NSString.create(string = text).dataUsingEncoding(NSUTF8StringEncoding) ?: error("the session-grade store could not be encoded")
            val match = owned.dictionary(
                kSecClass to kSecClassGenericPassword,
                kSecAttrService to owned.retain(service),
                kSecAttrAccount to owned.retain(account),
            )
            // Update in place when the item exists, so a crash never leaves the store without a value.
            val updated = SecItemUpdate(match, owned.dictionary(kSecValueData to owned.retain(data)))
            if (updated == errSecSuccess) return
            check(updated == errSecItemNotFound) { "the Keychain refused to update the session-grade store ($updated)" }
            val add = owned.dictionary(
                kSecClass to kSecClassGenericPassword,
                kSecAttrService to owned.retain(service),
                kSecAttrAccount to owned.retain(account),
                kSecAttrAccessible to kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                kSecValueData to owned.retain(data),
            )
            val added = SecItemAdd(add, null)
            check(added == errSecSuccess) { "the Keychain refused to add the session-grade store ($added)" }
        } finally {
            owned.release()
        }
    }

    /** The item goes (an earlier install's, at the first start of this one). True when it is gone or was never there. */
    fun delete(): Boolean {
        val owned = CfOwned()
        try {
            val status = SecItemDelete(
                owned.dictionary(kSecClass to kSecClassGenericPassword, kSecAttrService to owned.retain(service), kSecAttrAccount to owned.retain(account)),
            )
            return status == errSecSuccess || status == errSecItemNotFound
        } finally {
            owned.release()
        }
    }
}

/** The file calls the new path's stores share on the iPhone (Android's `AppFiles`). */
internal object IosFiles {
    private val fm get() = NSFileManager.defaultManager

    fun exists(path: String): Boolean = fm.fileExistsAtPath(path)

    /**
     * [path] as a directory, made with [protection] when it is not there, and excluded from backup. Returns [path].
     * Excluding a directory excludes everything under it.
     */
    fun dir(path: String, protection: Any?): String {
        val attributes = protection?.let { mapOf<Any?, Any?>(NSFileProtectionKey to it) }
        fm.createDirectoryAtPath(path, withIntermediateDirectories = true, attributes = attributes, error = null)
        NSURL.fileURLWithPath(path).setResourceValue(true, forKey = NSURLIsExcludedFromBackupKey, error = null)
        return path
    }

    /**
     * The vault cache's rename for a followed move ([io.silencelen.andvari.core.app.engine.VaultCacheFiles.rename]),
     * Android's `AppFiles.moveWithoutReplacing`: true once [from] is at [to], or when there is no [from]; false, with
     * both names as they were, when something is already at [to] or the rename failed. Never replaces anything:
     * `renamex_np` with `RENAME_EXCL` fails with `EEXIST` when [to] is taken (APFS supports it; the save queue already
     * relies on it, here and in the Safari handler).
     */
    fun moveWithoutReplacing(from: String, to: String): Boolean {
        if (!exists(from)) return true
        if (exists(to)) return false
        if (renamex_np(from, to, RENAME_EXCL.convert()) == 0) return true
        // Gone from under us between the look and the rename: done only if it is where it should be.
        return errno == ENOENT && !exists(from) && exists(to)
    }

    /** The vault cache's delete of one path: true when nothing is left at it. */
    fun remove(path: String): Boolean {
        if (!exists(path)) return true
        fm.removeItemAtPath(path, error = null)
        return !exists(path)
    }

    /** The names in [dir], or null when it cannot be listed. */
    fun list(dir: String): List<String>? = fm.contentsOfDirectoryAtPath(dir, error = null)?.mapNotNull { it as? String }

    fun isDir(path: String): Boolean = memScoped {
        val flag = alloc<kotlinx.cinterop.BooleanVar>()
        fm.fileExistsAtPath(path, isDirectory = flag.ptr) && flag.value
    }

    /** An empty file at [path] (the install marker); true when it is there now. */
    fun touch(path: String): Boolean {
        runCatching {
            fm.createDirectoryAtPath(path.substringBeforeLast('/'), withIntermediateDirectories = true, attributes = null, error = null)
            fm.createFileAtPath(path, contents = null, attributes = null)
        }
        return exists(path)
    }
}

/**
 * The host's side of a followed server move on the iPhone (design §4.4, [NamespaceMover]): Android's
 * `AndroidNamespaceMover`, rule for rule, over `<base>/ns/<originKey>/<userId>/`. Every account directory under the old
 * address's folder is moved into the new address's folder (one rename each: whole or not at all), then the emptied old
 * folder goes. It is called again after a crash or a failure, so nothing at the old address is success, a part-done move
 * is finished from where it stopped, and an account directory at BOTH addresses is never merged or overwritten: that is
 * a failure, and the new address stays closed.
 *
 * Where it differs from Android, and why: every rename is `renamex_np` with `RENAME_EXCL`, which never replaces what is
 * at the target; Java's `File.renameTo` (rename(2)) replaces an EMPTY directory there, which Android's code avoids by
 * looking first. A file system that refuses throws nothing here (Foundation answers false), so false is the failure.
 *
 * Today nothing of the new path's own lives under `ns/` on either platform (the kept records are named by core per
 * origin and account, and the vault cache's files are renamed through the cache's own rename): the mover is wired
 * because the engine closes the new address until it says true, and it must keep saying true for an empty layout.
 */
internal class IosNamespaceMover(private val base: String) : NamespaceMover {
    private fun originDir(origin: String): String = "$base/ns/${OriginCanon.pathSafe(OriginCanon.originKey(origin))}"

    override fun onMoved(from: String, to: String): Boolean {
        val old = originDir(from)
        val new = originDir(to)
        if (old == new) return true
        if (!IosFiles.exists(old)) return true
        if (!IosFiles.isDir(old)) return false
        if (IosFiles.exists(new) && !IosFiles.isDir(new)) return false
        // The usual case: nothing at the new address yet, and the whole folder moves in one rename.
        if (!IosFiles.exists(new) && renamex_np(old, new, RENAME_EXCL.convert()) == 0) return true
        if (!IosFiles.isDir(new)) {
            NSFileManager.defaultManager.createDirectoryAtPath(new, withIntermediateDirectories = true, attributes = null, error = null)
            if (!IosFiles.isDir(new)) return false
        }
        val children = IosFiles.list(old) ?: return false
        for (child in children) {
            val target = "$new/$child"
            if (IosFiles.exists(target)) return false
            if (renamex_np("$old/$child", target, RENAME_EXCL.convert()) != 0) return false
        }
        // Everything moved: the old folder must be gone for the move to count (a later call then sees nothing there).
        if (IosFiles.list(old)?.isEmpty() != true) return false
        NSFileManager.defaultManager.removeItemAtPath(old, error = null)
        return !IosFiles.exists(old)
    }
}

/**
 * The content's kept records on the iPhone ([io.silencelen.andvari.core.app.content.ContentStores]'s `disk`; Android's
 * `AndroidKeptStorage`), over the file stores the old path already runs: one [FileFillSnapshots] per record and one
 * [FileBlobStore] per set of files, under [dir] in the app's own container (never the App Group), readable after the
 * first unlock ([FileClasses.AFTER_FIRST_UNLOCK]: the lists are read whole and rewritten after a save, and the files
 * set aside are read in the upload grace while the person may have locked the phone). Core seals every record to its
 * account and names them per (origin, account); it uses these files only while the server's policy allows an offline
 * copy.
 */
internal class IosKeptStorage(private val dir: String) : KeptStorage {
    override fun record(name: String): FillSnapshotStore = FileFillSnapshots("$dir/${safe(name)}", FileClasses.AFTER_FIRST_UNLOCK)

    override fun blobs(name: String): BlobStore = FileBlobStore("$dir/${safe(name)}")

    internal companion object {
        private val NAME = Regex("^[A-Za-z0-9._-]{1,128}$")

        /** Core's names are hex and dashes; anything else never names a file here. */
        fun safe(name: String): String {
            require(NAME.matches(name) && name != "." && name != "..") { "not a kept record's name" }
            return name
        }
    }
}
