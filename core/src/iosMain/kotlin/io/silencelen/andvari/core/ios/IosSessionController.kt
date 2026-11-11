package io.silencelen.andvari.core.ios

import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.silencelen.andvari.core.app.AutofillVault
import io.silencelen.andvari.core.app.FillAvailability
import io.silencelen.andvari.core.app.FillCredential
import io.silencelen.andvari.core.app.FillLogin
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.FillUnlock
import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.app.ServerShare
import io.silencelen.andvari.core.app.SessionController
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.session.HttpClients
import io.silencelen.andvari.core.client.session.IosClocks
import io.silencelen.andvari.core.client.session.NamespaceStorage
import io.silencelen.andvari.core.client.session.PrefsSessionPersistence
import io.silencelen.andvari.core.client.session.QuickUnlockKeys
import io.silencelen.andvari.core.client.session.SecretStore
import io.silencelen.andvari.core.client.session.SessionPersistence
import io.silencelen.andvari.core.client.session.httpsOnly
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import platform.Foundation.NSFileManager
import platform.Foundation.NSUserDefaults
import platform.UIKit.UIDevice
import kotlin.coroutines.cancellation.CancellationException

/** The App Group the app shares with its Safari and AutoFill extensions. */
const val IOS_APP_GROUP: String = "group.com.silencelen.andvari"

/** The key in the shared suite that holds the app's server origin. SafariWebExtensionHandler.swift reads the same key. */
const val IOS_APP_SERVER_KEY: String = "appServer"

/**
 * Where the iOS app keeps its state (design 2026-11-09). The app and its extensions share an App Group: the
 * non-secret session state (policy mirrors, freshness stamps, identity pins), the quick-unlock blob and its Secure
 * Enclave key, and the AutoFill snapshot live there, so the AutoFill extension can unlock with Face ID under the
 * app's own gates. The session's tokens are never shared: they stay in the app's private Keychain group, whatever
 * this says.
 */
class IosStorageConfig(
    /** The NSUserDefaults suite for non-secret state; null for the app's standard defaults. */
    val defaultsSuite: String?,
    /** The Keychain service the session tokens and quick-unlock blobs are stored under. */
    val keychainService: String,
    /** The Keychain access group of the quick-unlock blob and key only; null for the app's default group. */
    val keychainAccessGroup: String?,
    /**
     * The App Group shared with the extensions; null shares nothing. The server origin ([IOS_APP_SERVER_KEY]) is
     * written to its suite and the AutoFill snapshot to its container.
     */
    val sharedSuite: String?,
) {
    /** The shipping layout: everything shareable in [IOS_APP_GROUP]. */
    constructor() : this(IOS_APP_GROUP, "io.silencelen.andvari", IOS_APP_GROUP, IOS_APP_GROUP)
}

/** What the iOS biometric prompt shows: [reason], or the controller's default when null. */
class IosBiometricHost(val reason: String?) : BiometricHost

/** The hosts iOS dials over plain http, as Android: loopback only, and no NSAllowsLocalNetworking. */
val IOS_CLEARTEXT_EXEMPT_HOSTS: Set<String> = setOf("127.0.0.1")

/**
 * The iOS assembly of [SessionController]: the platform seams over NSUserDefaults, the Keychain, Application
 * Support, the Darwin HTTP engine and the Secure Enclave, published on the main thread.
 */
class IosSessionController private constructor(seams: IosSeams) : SessionController(
    seams.store,
    seams.namespaces,
    seams.http,
    seams.quickKeys,
    IosClocks,
    IOS_CLEARTEXT_EXEMPT_HOSTS,
    Dispatchers.Main,
    { reason -> IosBiometricHost(reason) },
    1_000L,
    seams.serverShare,
    seams.snapshots,
    seams.saveQueue,
) {
    constructor(config: IosStorageConfig) : this(IosSeams(config))

    constructor() : this(IosStorageConfig())
}

/** The platform seams one controller uses. Building them migrates an older layout once ([migrate]). */
internal class IosSeams(
    config: IosStorageConfig,
    snapshotPath: String? = config.sharedSuite?.let(::groupSnapshotPath),
    savesDir: String? = config.sharedSuite?.let(::groupSavesDir),
) {
    private val prefs = UserDefaultsPrefs(config.defaultsSuite)

    init {
        runCatching { migrate(config, prefs) }
    }

    /** Non-secret state in NSUserDefaults; only the session's tokens in the Keychain, in the app's own group. */
    val store: SessionPersistence = PrefsSessionPersistence(prefs, KeychainSecrets(config.keychainService, null))
    val namespaces: NamespaceStorage = IosNamespaceStorage()
    val http: HttpClients = IosHttpClients
    val quickKeys: QuickUnlockKeys = quickUnlockKeys(config)
    val serverShare: ServerShare = config.sharedSuite?.let(::AppGroupServerShare) ?: ServerShare {}
    val snapshots: FillSnapshotStore = snapshotPath?.let(::FileFillSnapshots) ?: FillSnapshotStore.None
    val saveQueue: SaveQueueStore = savesDir?.let(::FileSaveQueue) ?: SaveQueueStore.None

    private companion object {
        const val MOVED = "ios.sharedLayout.v1"

        /**
         * Once per install: the non-secret state an earlier build kept in the app's standard defaults moves to the
         * shared suite, and a quick-unlock enrollment made in the app's private Keychain group is removed (its Secure
         * Enclave key cannot be read from the extension, so Face ID is turned on again, once, in Settings).
         */
        fun migrate(config: IosStorageConfig, prefs: UserDefaultsPrefs) {
            if (config.defaultsSuite == null || prefs.getString(MOVED) != null) return
            val old = NSUserDefaults.standardUserDefaults
            if (prefs.getString("baseUrl") == null) {
                for ((key, value) in old.dictionaryRepresentation()) {
                    val name = key as? String ?: continue
                    if (name.startsWith("ns.") || name in GLOBAL_KEYS) (value as? String)?.let { prefs.putString(name, it) }
                }
            }
            for (key in old.dictionaryRepresentation().keys) {
                val name = key as? String ?: continue
                if (name.startsWith("ns.") || name in GLOBAL_KEYS) old.removeObjectForKey(name)
            }
            if (config.keychainAccessGroup != null) sweepLegacyQuickUnlock("${config.keychainService}.quickunlock")
            prefs.putString(MOVED, "1")
        }

        /** [PrefsSessionPersistence]'s global keys. */
        val GLOBAL_KEYS = setOf("baseUrl", "pendingServer", "session", "mustChangePassword", "highWaterWallMs", "lastSyncAt")
    }
}

internal fun quickUnlockKeys(config: IosStorageConfig): QuickUnlockKeys =
    IosQuickUnlockKeys(KeychainSecrets("${config.keychainService}.quickunlock", config.keychainAccessGroup), config.keychainAccessGroup)

/** The snapshot's path in [group]'s container; null where the group is not provisioned (nothing is then written). */
internal fun groupSnapshotPath(group: String): String? =
    NSFileManager.defaultManager.containerURLForSecurityApplicationGroupIdentifier(group)?.path?.let { "$it/autofill-snapshot.json" }

/** The save queue's directory in [group]'s container; null where the group is not provisioned. */
internal fun groupSavesDir(group: String): String? =
    NSFileManager.defaultManager.containerURLForSecurityApplicationGroupIdentifier(group)?.path?.let { "$it/saves" }

/** A secret store that holds nothing: the extensions' view of the session's tokens. */
internal object NoSecrets : SecretStore {
    override fun read(name: String): String? = null

    override fun write(name: String, value: String?): Boolean = false
}

/**
 * The AutoFill extension's vault (design 2026-11-09, "AutoFill"), and the Safari handler's: the shared state read
 * from the App Group, the snapshot, and the quick-unlock key behind Face ID. It has no tokens and sends nothing.
 */
class IosAutofill internal constructor(config: IosStorageConfig, snapshotPath: String?, savesDir: String?) {
    constructor() : this(IosStorageConfig(), groupSnapshotPath(IOS_APP_GROUP), groupSavesDir(IOS_APP_GROUP))

    private val saves: SaveQueueStore = savesDir?.let(::FileSaveQueue) ?: SaveQueueStore.None

    private val vault = AutofillVault(
        PrefsSessionPersistence(UserDefaultsPrefs(config.defaultsSuite), NoSecrets),
        snapshotPath?.let(::FileFillSnapshots) ?: FillSnapshotStore.None,
        quickUnlockKeys(config),
        IosClocks,
        IosHttpClients,
    )

    /** Whether a fill can start, before any prompt. */
    fun availability(): FillAvailability = vault.availability()

    /** Face ID ([reason] is what the prompt says), then the snapshot opened in memory. */
    @Throws(CancellationException::class)
    suspend fun unlock(reason: String?): FillUnlock = vault.unlock(IosBiometricHost(reason))

    /** The logins, those matching one of [hosts] first; empty while locked. */
    fun logins(hosts: List<String>): List<FillLogin> = vault.logins(hosts)

    fun credential(itemId: String): FillCredential? = vault.credential(itemId)

    fun oneTimeCode(itemId: String): String? = vault.oneTimeCode(itemId)

    /**
     * Queue a login the system asked this extension to save (iOS 26.2): sealed to the account's public key, for the app
     * to show and import at its next unlock. [id] names the form's session, so a later event for the same form
     * replaces its entry. Needs no unlock and sends nothing.
     */
    fun queueSave(id: String, site: String, username: String, password: String): SaveQueued =
        runCatching { SaveQueue.enqueue(saves, createCryptoProvider(), saveId(id), site, username, password, IosClocks.wallMs(), "autofill") }.getOrDefault(SaveQueued.REFUSED)

    private fun saveId(raw: String): String = "s-" + OriginCanon.pathSafe(raw).filter { it.isLetterOrDigit() || it == '-' }.take(48).ifEmpty { "form" }

    /** End the fill: the keys are zeroed. */
    fun close() = vault.close()
}

/**
 * The app's server origin in the App Group [suite], where the Safari extension's native handler reads it. The origin
 * is the Trust-Gate-confirmed one the app dials; null removes it, and the extension then asks the person to choose a
 * server in the app.
 */
internal class AppGroupServerShare(suite: String) : ServerShare {
    private val prefs = UserDefaultsPrefs(suite)

    override fun publish(origin: String?) = prefs.putString(IOS_APP_SERVER_KEY, origin)
}

/** The Darwin engine, https only (loopback excepted), tagged "ios" for the server's version pins (spec 03 §1). */
internal object IosHttpClients : HttpClients {
    override fun create(): HttpClient = HttpClient(Darwin).httpsOnly(IOS_CLEARTEXT_EXEMPT_HOSTS)

    override val wirePlatform: String = "ios"

    /** The model ("iPhone", "iPad"): the device's own name needs an entitlement since iOS 16. */
    override val deviceName: String get() = UIDevice.currentDevice.model
}
