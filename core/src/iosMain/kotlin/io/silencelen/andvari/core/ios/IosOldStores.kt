@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.ios

import io.silencelen.andvari.core.app.PreCutoverStore
import io.silencelen.andvari.core.app.PreCutoverStores
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.CoreFoundation.CFRetain
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFBooleanTrue
import platform.Foundation.CFBridgingRelease
import platform.Foundation.NSData
import platform.Foundation.NSFileManager
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.NSUserDefaults
import platform.Foundation.create
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecClass
import platform.Security.kSecClassKey
import platform.Security.kSecMatchLimit
import platform.Security.kSecMatchLimitAll
import platform.Security.kSecReturnAttributes

/**
 * Where the old app (the pre-cut-over build of this bundle id) kept each of its stores: the defaults of
 * [IosStorageConfig], [IosSeams] and [IosNamespaceStorage] as they shipped. An iPhone that keeps its bundle id inherits
 * all of it (§12.4).
 */
internal class IosOldLayout(
    /** `Application Support/andvari`: `<originKey>/<userId>/` per namespace, and the content's record files at its root. */
    val root: String,
    /** The App Group container's path, or null where it is not provisioned. */
    val groupContainer: String?,
    /** The app's private defaults (null: the standard ones) and the App Group's suite (null: none). */
    val defaultsSuite: String?,
    val sharedSuite: String?,
    /** The old Keychain services: the session's tokens, and the quick-unlock blobs (in [quickAccessGroup]). */
    val keychainService: String,
    val quickAccessGroup: String?,
) {
    companion object {
        fun shipping(): IosOldLayout {
            val config = IosStorageConfig()
            return IosOldLayout(
                IosNamespaceStorage.defaultRoot(),
                NSFileManager.defaultManager.containerURLForSecurityApplicationGroupIdentifier(IOS_APP_GROUP)?.path,
                config.defaultsSuite,
                config.sharedSuite,
                config.keychainService,
                config.keychainAccessGroup,
            )
        }
    }
}

/**
 * The first-launch wipe on the iPhone (§12.4, R9; [PreCutoverStores]): the six stores of the old app, the desktop's
 * `DesktopOldStores` store for store, over the old path's own storage code. Core calls [wipe] for each store not yet
 * known to be gone, keyed by a format marker per store, before the first screen; the new path reads none of these.
 *
 * Only the old app's things go: its exact Keychain services, its key tags, the defaults keys `PrefsSessionPersistence`
 * wrote, and the files `IosNamespaceStorage` and `IosSeams` made. Nothing is deleted by looking: every listing only
 * reads, and nothing the Swift app keeps in the same defaults (its own settings) matches a key named here. The new
 * path's folder, App Group folder and Keychain service ([IosAppLayout]) are never under any of these names.
 *
 * True only when everything of the store is gone, or was never there; false leaves the marker unset, so the next start
 * tries again. Never throws.
 *
 * COMPILED, NEVER RUN. MAC DAY, in this order: (1) install the old build, sign in, turn Face ID on, let AutoFill write a
 * snapshot and queue a save; (2) install this build over it; (3) check each store is gone (the Keychain by a query per
 * service and the key enumeration below, the defaults with `defaults read` on the simulator, the files), that the
 * Swift app's own settings are still there, that `.installed` is still there, and that every store's marker is set;
 * (4) launch again: nothing is wiped twice.
 */
internal class IosOldStores(private val old: IosOldLayout) : PreCutoverStores {
    private val fm get() = NSFileManager.defaultManager

    // Each store's parts are all tried, whatever an earlier part answered (no `&&` short cut): a Keychain that refuses
    // now does not keep the files and defaults of the same store from going.
    override fun wipe(store: PreCutoverStore): Boolean = runCatching {
        when (store) {
            PreCutoverStore.OFFLINE_CACHE -> removeAll(namespaced { it.startsWith("vault-") && it.contains(".db") } + contentRecords())
            PreCutoverStore.SAVED_SESSIONS ->
                all(attempt { KeychainSecrets(old.keychainService, null).deleteAll() }, attempt { removeDefaults { isSessionKey(it) } })
            PreCutoverStore.TRUST_RECORDS ->
                // The old device state held the trust records (and the personal wrap, below); the identity pins were in
                // the defaults' `ns.` keys.
                all(attempt { removeAll(namespaced { it == DEVICE_STATE }) }, attempt { removeDefaults { isTrustKey(it) } }, attempt { pruneEmpty() })
            // The personal wrap and the pinned personal vault lived in the old device state.
            PreCutoverStore.PERSONAL_WRAP_CACHE -> removeAll(namespaced { it == DEVICE_STATE })
            PreCutoverStore.QUICK_UNLOCK_KEYS ->
                all(attempt { KeychainSecrets("${old.keychainService}.quickunlock", old.quickAccessGroup).deleteAll() }, attempt { deleteOldQuickKeys() })
            PreCutoverStore.APP_GROUP_SNAPSHOT_AND_SAVE_QUEUE -> {
                val group = old.groupContainer
                // The old snapshot and its temporary, and the whole old queue directory (the new path's are under `ovh/`).
                group == null || removeAll(listOf("$group/autofill-snapshot.json", "$group/autofill-snapshot.json.tmp", "$group/saves"))
            }
        }
    }.getOrDefault(false)

    private fun attempt(part: () -> Boolean): Boolean = runCatching(part).getOrDefault(false)

    private fun all(vararg parts: Boolean): Boolean = parts.all { it }

    // ---- files ----

    /** Files in `<root>/<originKey>/<userId>/` matching [match]: plain directories only, nothing followed. */
    private fun namespaced(match: (String) -> Boolean): List<String> {
        val out = ArrayList<String>()
        for (o in IosFiles.list(old.root).orEmpty()) {
            val od = "${old.root}/$o"
            if (o.startsWith(".") || !IosFiles.isDir(od)) continue
            for (u in IosFiles.list(od).orEmpty()) {
                val ud = "$od/$u"
                if (!IosFiles.isDir(ud)) continue
                IosFiles.list(ud).orEmpty().filter(match).forEach { out += "$ud/$it" }
            }
        }
        return out
    }

    /**
     * The content's records the old path kept at the root of its folder (`IosSeams`): the applied saves, the unfinished
     * moves, the saves with files and their files. Sealed to the account in an old format the new path never reads; they
     * are the device's copy, so they go with the offline cache.
     */
    private fun contentRecords(): List<String> =
        listOf("applied-saves.json", "move-memos.json", "pending-saves.json").flatMap { listOf("${old.root}/$it", "${old.root}/$it.tmp") } +
            "${old.root}/pending-files"

    /** Each path goes as itself (a link is removed, never followed); true when none of them is left. */
    private fun removeAll(paths: List<String>): Boolean = paths.map { IosFiles.remove(it) }.all { it }

    /** Empty namespace directories go; one still holding something stays and does not fail the wipe. */
    private fun pruneEmpty(): Boolean {
        for (o in IosFiles.list(old.root).orEmpty()) {
            val od = "${old.root}/$o"
            if (o.startsWith(".") || !IosFiles.isDir(od)) continue
            for (u in IosFiles.list(od).orEmpty()) {
                val ud = "$od/$u"
                if (IosFiles.isDir(ud) && IosFiles.list(ud)?.isEmpty() == true) fm.removeItemAtPath(ud, error = null)
            }
            if (IosFiles.list(od)?.isEmpty() == true) fm.removeItemAtPath(od, error = null)
        }
        return true
    }

    // ---- defaults ----

    /**
     * Every key [match] names goes from the app's private defaults and from the App Group's copy of them. True when
     * none is left. The listing is `dictionaryRepresentation`, which also shows the global domain's keys: only the old
     * path's names are matched, so nothing else is touched.
     */
    private fun removeDefaults(match: (String) -> Boolean): Boolean {
        val domains = listOfNotNull(
            if (old.defaultsSuite == null) NSUserDefaults.standardUserDefaults else NSUserDefaults(suiteName = old.defaultsSuite),
            old.sharedSuite?.takeIf { it != old.defaultsSuite }?.let { NSUserDefaults(suiteName = it) },
        )
        var gone = true
        for (d in domains) {
            val keys = d.dictionaryRepresentation().keys.mapNotNull { it as? String }.filter(match)
            keys.forEach { d.removeObjectForKey(it) }
            if (keys.any { d.objectForKey(it) != null }) gone = false
        }
        return gone
    }

    // ---- quick-unlock keys ----

    /**
     * The old Secure Enclave keys (and the simulator's stand-ins): every EC key in the quick-unlock access group whose
     * application tag starts with the old path's prefix (`IosQuickUnlockKeys.tag`), each deleted by its own tag. Not
     * `IosQuickUnlockKeys.wipeAll`, which deletes EVERY EC key of the group: if this wipe ran again after the new path's
     * Face ID key existed (a store whose marker stayed unset), it would take that key too.
     *
     * MAC DAY: that listing attributes of keys made with `biometryCurrentSet` raises no Face ID prompt and does not answer
     * `errSecInteractionNotAllowed` (only the attributes are asked for, no reference and no data); if it does, add
     * an `LAContext` with `interactionNotAllowed = true` as `kSecUseAuthenticationContext`.
     */
    private fun deleteOldQuickKeys(): Boolean = memScoped {
        val owned = CfOwned()
        try {
            val query = owned.dictionary(
                kSecClass to kSecClassKey,
                kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
                kSecReturnAttributes to kCFBooleanTrue,
                kSecMatchLimit to kSecMatchLimitAll,
                *owned.group(old.quickAccessGroup),
            )
            val out = alloc<CFTypeRefVar>()
            val status = SecItemCopyMatching(query, out.ptr)
            if (status == errSecItemNotFound) return@memScoped true
            if (status != errSecSuccess) return@memScoped false
            val rows = CFBridgingRelease(out.value) as? List<*> ?: return@memScoped false
            val tagKey = CFBridgingRelease(CFRetain(kSecAttrApplicationTag)) as? String ?: return@memScoped false
            var ok = true
            for (row in rows) {
                val tag = ((row as? Map<*, *>)?.get(tagKey) as? NSData) ?: continue
                val text = NSString.create(data = tag, encoding = NSUTF8StringEncoding)?.toString() ?: continue
                if (!text.startsWith(OLD_KEY_TAG_PREFIX)) continue
                val one = CfOwned()
                try {
                    val deleted = SecItemDelete(
                        one.dictionary(
                            kSecClass to kSecClassKey,
                            kSecAttrKeyType to kSecAttrKeyTypeECSECPrimeRandom,
                            kSecAttrApplicationTag to one.retain(tag),
                            *one.group(old.quickAccessGroup),
                        ),
                    )
                    if (deleted != errSecSuccess && deleted != errSecItemNotFound) ok = false
                } finally {
                    one.release()
                }
            }
            ok
        } finally {
            owned.release()
        }
    }

    internal companion object {
        const val DEVICE_STATE = "device-state.json"

        /** The old path's quick-unlock key tags: `io.silencelen.andvari.quickunlock.<originKey>.<userId>`. */
        const val OLD_KEY_TAG_PREFIX = "io.silencelen.andvari.quickunlock."

        /** The old session's own keys (PrefsSessionPersistence; `appServer` is the copy the Safari handler read). */
        private val SESSION_KEYS = setOf("baseUrl", "pendingServer", "session", "mustChangePassword", "highWaterWallMs", "lastSyncAt", IOS_APP_SERVER_KEY)

        /** The per-origin session material: the policy mirrors, the cached account keys and the password stamps. */
        private val SESSION_NS_FIELDS = setOf("cacheAllowed", "autoLockSeconds", "policyFetchedAt", "serverTimeFloor")

        private fun nsField(key: String): String? = if (key.startsWith("ns.")) key.removePrefix("ns.").substringAfter('.', "").takeIf { it.isNotEmpty() } else null

        fun isSessionKey(key: String): Boolean {
            if (key in SESSION_KEYS) return true
            val field = nsField(key) ?: return false
            return field in SESSION_NS_FIELDS || field.startsWith("accountKeys.") || field.startsWith("stamp.")
        }

        /** Every other `ns.<originKey>.` key: the identity pins (`SelfIdentityPin`'s records). */
        fun isTrustKey(key: String): Boolean = nsField(key) != null && !isSessionKey(key)
    }
}
