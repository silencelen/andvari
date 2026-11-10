package io.silencelen.andvari.core.ios

import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.silencelen.andvari.core.app.SessionController
import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.session.HttpClients
import io.silencelen.andvari.core.client.session.IosClocks
import io.silencelen.andvari.core.client.session.NamespaceStorage
import io.silencelen.andvari.core.client.session.PrefsSessionPersistence
import io.silencelen.andvari.core.client.session.QuickUnlockKeys
import io.silencelen.andvari.core.client.session.SessionPersistence
import io.silencelen.andvari.core.client.session.httpsOnly
import kotlinx.coroutines.Dispatchers
import platform.UIKit.UIDevice

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

/** The platform seams one controller uses. */
internal class IosSeams(config: IosStorageConfig) {
    /** Non-secret state in NSUserDefaults; only the session's tokens in the Keychain. */
    val store: SessionPersistence = PrefsSessionPersistence(
        UserDefaultsPrefs(config.defaultsSuite),
        KeychainSecrets(config.keychainService, config.keychainAccessGroup),
    )
    val namespaces: NamespaceStorage = IosNamespaceStorage()
    val http: HttpClients = IosHttpClients
    val quickKeys: QuickUnlockKeys = IosQuickUnlockKeys(KeychainSecrets("${config.keychainService}.quickunlock", config.keychainAccessGroup), config.keychainAccessGroup)
}

/** The Darwin engine, https only (loopback excepted), tagged "ios" for the server's version pins (spec 03 §1). */
internal object IosHttpClients : HttpClients {
    override fun create(): HttpClient = HttpClient(Darwin).httpsOnly(IOS_CLEARTEXT_EXEMPT_HOSTS)

    override val wirePlatform: String = "ios"

    /** The model ("iPhone", "iPad"): the device's own name needs an entitlement since iOS 16. */
    override val deviceName: String get() = UIDevice.currentDevice.model
}
