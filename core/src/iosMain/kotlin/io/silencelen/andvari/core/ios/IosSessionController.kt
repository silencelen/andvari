package io.silencelen.andvari.core.ios

import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.silencelen.andvari.core.app.SessionController
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.session.HttpClients
import io.silencelen.andvari.core.client.session.InMemoryPrefs
import io.silencelen.andvari.core.client.session.InMemorySecrets
import io.silencelen.andvari.core.client.session.IosClocks
import io.silencelen.andvari.core.client.session.NamespaceStorage
import io.silencelen.andvari.core.client.session.PrefsSessionPersistence
import io.silencelen.andvari.core.client.session.QuickRecover
import io.silencelen.andvari.core.client.session.QuickUnlockKeys
import io.silencelen.andvari.core.client.session.SessionPersistence
import kotlinx.coroutines.Dispatchers

/**
 * Where the iOS app keeps its state (design 2026-11-09). One object, so the locations can move to an App
 * Group suite and a shared Keychain access group when the AutoFill extension needs freshness and policy
 * state. The extension never needs the tokens.
 */
class IosStorageConfig(
    /** The NSUserDefaults suite for non-secret state; null for the app's standard defaults. */
    val defaultsSuite: String?,
    /** The Keychain service the session tokens and quick-unlock blobs are stored under. */
    val keychainService: String,
    /** The Keychain access group; null for the app's default group. */
    val keychainAccessGroup: String?,
) {
    /** The app's own defaults and Keychain group. */
    constructor() : this(null, "io.silencelen.andvari", null)
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
) {
    constructor(config: IosStorageConfig) : this(IosSeams(config))

    constructor() : this(IosStorageConfig())
}

/** The platform seams one controller uses. The API surface lands first; the storage seams follow it. */
internal class IosSeams(config: IosStorageConfig) {
    val store: SessionPersistence = PrefsSessionPersistence(InMemoryPrefs(), InMemorySecrets())
    val namespaces: NamespaceStorage = object : NamespaceStorage {
        override fun openVaultCache(originKey: String, userId: String): VaultCache = InMemoryVaultCache()
        override fun deviceState(originKey: String, userId: String): DeviceState = MemoryDeviceState()
    }
    val http: HttpClients = object : HttpClients {
        override fun create(): HttpClient = HttpClient(Darwin)
        override val wirePlatform: String = "ios"
        override val deviceName: String = "iPhone"
    }
    val quickKeys: QuickUnlockKeys = object : QuickUnlockKeys {
        override fun hasStrongBiometric(): Boolean = false
        override fun isEnrolled(originKey: String, userId: String): Boolean = false
        override suspend fun recover(host: BiometricHost, originKey: String, userId: String): QuickRecover = QuickRecover.Fallback(null)
        override fun wipe(originKey: String, userId: String) {}
    }
}
