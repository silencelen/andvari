@file:OptIn(ExperimentalForeignApi::class, BetaInteropApi::class)

package io.silencelen.andvari.core.ios

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.PreCutoverStores
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.app.content.ContentStores
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.app.engine.SqliteVaultCacheFiles
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.JsonDeviceState
import io.silencelen.andvari.core.client.fileDeviceState
import io.silencelen.andvari.core.client.net.Dialer
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.pin.PublicInstanceSpec
import io.silencelen.andvari.core.client.session.IosClocks
import io.silencelen.andvari.core.client.session.PlatformKeyWrap
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.cinterop.BetaInteropApi
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.coroutines.Dispatchers
import platform.Foundation.NSApplicationSupportDirectory
import platform.Foundation.NSBundle
import platform.Foundation.NSFileManager
import platform.Foundation.NSSearchPathForDirectoriesInDomains
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.NSUserDomainMask
import platform.Foundation.stringWithContentsOfFile
import platform.UIKit.UIApplication
import platform.UIKit.UIDevice

/**
 * Where the new path keeps its things on the iPhone. Nothing of it is the old path's: its own folder in the app's
 * container, its own folder in the App Group, its own Keychain service. So the first-launch wipe of the old stores
 * (§12.4, [IosOldStores]) can never reach the new path's, and the old path's code never reads the new path's.
 *
 * - [root]: `Application Support/andvari-ovh` in the app's own container (Android: `no_backup/ovh`), excluded from
 *   backup. The device state, the install marker, the vault cache, the kept records and `ns/`.
 * - [groupDir]: `<App Group container>/ovh`, or null where the group is not provisioned (then nothing is shared): the
 *   extensions' fill snapshot and save queue, and nothing else.
 * - [keychainService]: the session-grade store's Keychain service; the old path's is `io.silencelen.andvari` (and
 *   `.quickunlock`), matched exactly by the Keychain, so neither path's deletes reach the other's items.
 */
class IosAppLayout internal constructor(
    val root: String,
    val groupDir: String?,
    val keychainService: String,
) {
    internal val deviceStateDir: String get() = root
    internal val installMarker: String get() = "$root/.installed"
    internal val vaultCacheDir: String get() = "$root/vault-cache"
    internal val keptDir: String get() = "$root/kept"
    internal val fillSnapshotPath: String? get() = groupDir?.let { "$it/autofill-snapshot.json" }
    internal val saveQueueDir: String? get() = groupDir?.let { "$it/saves" }

    companion object {
        /** The new path's Keychain service. */
        const val KEYCHAIN_SERVICE: String = "io.silencelen.andvari.ovh"

        /** The account of the one item that holds the session-grade store. */
        internal const val SECURE_ACCOUNT: String = "secure-state"

        /** The shipping layout. */
        fun shipping(): IosAppLayout {
            val support = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, true).firstOrNull() as? String
                ?: error("no Application Support directory")
            val group = NSFileManager.defaultManager.containerURLForSecurityApplicationGroupIdentifier(IOS_APP_GROUP)?.path
            return IosAppLayout("$support/andvari-ovh", group?.let { "$it/ovh" }, KEYCHAIN_SERVICE)
        }

        /** A layout under [root] with no App Group, for tests (the Keychain service is the caller's). */
        internal fun under(root: String, groupDir: String?, keychainService: String): IosAppLayout = IosAppLayout(root, groupDir, keychainService)
    }
}

/**
 * The engine-backed app API of the new path on the iPhone, and what the first screens need beside it: the iPhone's
 * twin of Android's `TrustSeam` (`app-android/.../trust/TrustSeam.kt`), built from the iPhone code the old path
 * already runs. Built once per process, in the APP only: the AutoFill and Safari extensions never build one (they hold
 * no tokens and send nothing, design 2026-11-09 "AutoFill").
 *
 * COMPILED, NEVER RUN: everything here compiles for both iPhone targets on Linux against Apple's interfaces; nothing of
 * it has been linked or run. Each MAC DAY note says what the first run must check.
 */
class IosAppSeam internal constructor(
    /** The app API; already started ([AppApi.start]). */
    val api: AppApi,
    /** Where invite and device links point (`spec/public-instance.json`'s `joinBase`), or null when the bundle has none. */
    val joinBase: String?,
    /** What the bundled spec still holds as a placeholder (empty in a build that may ship). */
    val placeholders: List<String>,
    private val secureFile: KeychainStateFile,
    internal val crypto: CryptoProvider,
) {
    /** The saved sign-in is there but cannot be read now: the first screen says so instead of being silent. */
    val savedSignInUnreadable: Boolean get() = secureFile.unreadable

    /**
     * A new session was written and read back (Android's `newSessionWritten`). Not called `new…`: Kotlin/Native exports a
     * name that starts with `new`, `copy`, `alloc` or `init` with a `do` prefix.
     */
    fun signedInAgain() = secureFile.signedInAgain()

    internal companion object {
        /**
         * Build and start the app API over [layout], or null when this is the first start of an install and what an
         * earlier install left in the Keychain could not be deleted yet (Swift asks again once the protected data can
         * be read: `UIApplication.protectedDataDidBecomeAvailableNotification`, or the next foreground).
         *
         * [keyWrap] is quick unlock's platform key. **Pass null today**: the iPhone's `PlatformKeyWrap` (the Face ID
         * key wrap) is not written (its platform interface is about to change, census F2), and with no key wrap core
         * shows quick unlock as [io.silencelen.andvari.core.app.QuickUnlockState.UNAVAILABLE] and offers nothing.
         *
         * [oldStores] is the first-launch wipe of the old app's stores (§12.4): [IosOldStores] in the app, since the
         * iPhone keeps its bundle id and inherits them (Android's `NoOldStores` answers "gone" because Android installs
         * under a new id and starts empty; that answer would be false here). [bakedSpec] is the text of
         * `public-instance.json` from the app bundle (null: nothing baked).
         */
        fun build(
            layout: IosAppLayout,
            keyWrap: PlatformKeyWrap?,
            oldStores: PreCutoverStores,
            bakedSpec: String?,
            protectedDataAvailable: () -> Boolean = ::protectedDataReadableNow,
            deviceName: String = UIDevice.currentDevice.model,
        ): IosAppSeam? {
            IosFiles.dir(layout.root, FileClasses.OPEN_OR_NEW)
            val secureFile = KeychainStateFile(layout.keychainService, IosAppLayout.SECURE_ACCOUNT)
            if (!firstStartSettled(layout, secureFile, protectedDataAvailable)) return null
            val spec = bakedSpec?.let(PublicInstanceSpec::parse)
            val state = fileDeviceState(layout.deviceStateDir)
            // The only public way to open a client: the Dialer carries the guard that stops all traffic to a server whose
            // identity failed, over the same pin store as the engine's CardTrust (the engine's `state`).
            //
            // No socket of the iPhone's own (Android needs one: OkHttp cannot bound a message before it holds it). The
            // bell's socket goes over the Darwin engine, an NSURLSessionWebSocketTask, which Apple documents as bounding
            // what it buffers: `maximumMessageSize`, "the maximum number of bytes to buffer before the receive call fails
            // with an error. This value includes the sum of all bytes from continuation frames." ktor 3.0.3's Darwin
            // session maps `maxFrameSize` onto it (its klib names `setMaximumMessageSize` in the session's IR; read on
            // Linux, not run), so KtorBellWire's `maxFrameSize = 64 KiB` bounds a message before it is held, and its own
            // count of what it is handed stays as the second check.
            // MAC DAY: (1) that setting `maxFrameSize` on the open session does not throw (KtorBellWire records it in
            // `engineTookCap`); (2) that it applies to the receive already pending when it is set, or else that the first
            // message is bounded by the task's default; (3) a message of 64 KiB + 1 closes the socket.
            //
            // Redirects: the Dialer turns ktor's off (`followRedirects = false`). NSURLSession follows them by itself
            // unless its delegate's `willPerformHTTPRedirection` hands back nil ("NULL to refuse the redirect and return
            // the body of the redirect response", Apple); ktor's Darwin delegate implements that method (its klib names
            // it) and, as I read ktor, answers nil so that ktor's own plugin decides. Background sessions follow
            // redirects regardless (Apple), and this client is a default session.
            // MAC DAY: a server answering 302 to another host must come back as a 3xx answer, the other host never dialed.
            //
            // Plain http: the old path's `httpsOnly` guard is an interceptor on this client, and ktor's `config {}` (which
            // the Dialer uses to turn redirects off) builds a client from the configuration only, so the guard does not
            // carry to the Dialer's clients. What still refuses plain http there is core's origin grammar and App
            // Transport Security. Android's client has no such guard either. MAC DAY: that a dial to `http://` (not
            // loopback) through the seam's Dialer is refused.
            //
            // Timeouts: Android's client also carries an engine-level call timeout. This one is the old path's client as
            // it has run, with NSURLSession's defaults (60 s without a byte); core bounds every call itself (BoundedOps).
            // `timeoutIntervalForResource` is not set because Apple does not document what it does to a WebSocket task,
            // which would carry the bell. MAC DAY: decide with a run whether the bell survives one.
            val dialer = Dialer(PinStore(state), IosHttpClients.create(), AppPlatform.IOS.wireName)
            val crypto = createCryptoProvider()
            val api: AppApi = EngineAppApi(
                AppEngine(
                    platform = AppPlatform.IOS,
                    deviceName = deviceName,
                    // Every client, and the event bell's socket, from the one dialer and its guard.
                    transport = dialingTransport(dialer),
                    state = state,
                    secure = JsonDeviceState(secureFile),
                    crypto = crypto,
                    clock = { IosClocks.wallMs() },
                    baked = spec?.baked,
                    // True in every build of this app, the safer reading (as Android): a build never follows a move or
                    // `kind` change of the baked instance (§4.4, T-R7). With nothing baked it changes nothing.
                    storeBuild = true,
                    stores = oldStores,
                    // Android uses Main.immediate too. MAC DAY: that kotlinx.coroutines' Darwin main dispatcher runs
                    // `immediate` work in place on the main thread (it is documented to).
                    main = Dispatchers.Main.immediate,
                    keyWrap = keyWrap,
                    // Quick unlock's freshness rule reads the monotonic clock and the boot identity; the old path's
                    // clocks, as they have run. Core offers quick unlock only with a key wrap as well.
                    clocks = IosClocks,
                    // A followed server move takes this app's per-(server, account) folders with it (design §4.4).
                    namespaceMover = IosNamespaceMover(layout.root),
                    // The vault's offline copy, as SQLite files in the app's own container, excluded from backup, created
                    // with the class that keeps an open database writable while the device locks (FileClasses.OPEN_OR_NEW:
                    // SQLite creates its journals while it writes). Core decides per session whether a file may be kept
                    // at all. The rename never replaces a file, so a followed move carries the copy to the new names.
                    // The cache opens through `openSqlBox`, whose iPhone actual (SqlBox.ios.kt) needs the sqlite3 interop:
                    // the Linux compile probe stubs it, so the SQLite side of this has been compiled only on a Mac.
                    cacheFiles = SqliteVaultCacheFiles(
                        IosFiles.dir(layout.vaultCacheDir, FileClasses.OPEN_OR_NEW),
                        IosFiles::moveWithoutReplacing,
                        IosFiles::remove,
                    ),
                    // What a lock cut short (a move, a save with files, the applied saves), over the old path's file
                    // stores in the app's own container; the save queue and the fill snapshot in the App Group, where the
                    // extensions reach them. Core keeps its records as files only while the policy allows an offline copy,
                    // and deletes the fill snapshot when it does not.
                    contentStores = ContentStores(
                        crypto,
                        IosKeptStorage(IosFiles.dir(layout.keptDir, FileClasses.AFTER_FIRST_UNLOCK)),
                        layout.saveQueueDir?.let(::FileSaveQueue) ?: SaveQueueStore.None,
                        layout.fillSnapshotPath?.let { FileFillSnapshots(it, FileClasses.OPEN_OR_NEW) } ?: FillSnapshotStore.None,
                    ),
                ),
            )
            // Started where it is built, as on Android: nothing in the API works before start(), which is idempotent.
            // GAP (as Android's): live updates after a network change. Android watches the platform's network notices
            // and calls returnedToForeground(); the iPhone app does the same from Swift (NWPathMonitor) or leaves it to
            // the bell's own ladder (at most 60 s). Nothing here watches the network.
            api.start()
            return IosAppSeam(api, spec?.joinBase, spec?.placeholders.orEmpty(), secureFile, crypto)
        }

        /**
         * The first start of an install (a fresh install, or a reinstall: the Keychain outlives an uninstall, the app's
         * container does not) deletes what an earlier install of the NEW path left in the Keychain, the session-grade
         * store, before anything reads it: otherwise a reinstall would find a session whose device state (its pins) is
         * gone. The old path's rule (round-8 review L, `IosSeams`), on the new path's own marker and item.
         *
         * The marker is in the new path's folder of the app's container; its existence can be seen before the first
         * unlock. Nothing is deleted unless it is absent AND the protected data can be read now (a launch iOS prewarmed
         * before the first unlock cannot delete an item it cannot reach either). The marker is written once the delete
         * succeeded or found nothing. False: not settled, so nothing may be built yet.
         *
         * Unlike the old path there is no "the private store already holds state" escape: the new path's device state
         * is in the same folder as its marker, so a missing marker means a container with nothing of the new path in it.
         * A marker that could not be written makes the next start delete again: a sign-in lost, never a stale one kept.
         */
        internal fun firstStartSettled(layout: IosAppLayout, secure: KeychainStateFile, protectedDataAvailable: () -> Boolean): Boolean {
            if (IosFiles.exists(layout.installMarker)) return true
            if (!protectedDataAvailable()) return false
            if (!secure.delete()) return false
            IosFiles.touch(layout.installMarker)
            return true
        }

        /** The bundled spec's text: `public-instance.json` at the bundle's root, or null when the bundle has none. */
        fun bundledSpec(): String? =
            NSBundle.mainBundle.pathForResource("public-instance", ofType = "json")?.let { NSString.stringWithContentsOfFile(it, NSUTF8StringEncoding, null) }
    }
}

/** UIApplication's word on the protected data; false where there is no application to ask (a test process). */
internal fun protectedDataReadableNow(): Boolean = runCatching { UIApplication.sharedApplication.protectedDataAvailable }.getOrDefault(false)
