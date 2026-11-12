package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.SelfIdentityPin
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.client.VaultCache
import io.silencelen.andvari.core.model.AccountKeys

/** The platform seams, in memory, so the shared session rules run the same on every target. */
internal class FakeClocks(var wall: Long = 1_000L, var mono: Long = 1_000L, var boot: String? = null) : Clocks {
    override fun wallMs() = wall
    override fun monotonicMs() = mono
    override fun bootId() = boot
}

internal class FakeOriginStore : OriginStore {
    override var cacheAllowed = true
    override var autoLockSeconds = 0
    override var policyFetchedAt = 0L
    override var serverTimeFloorMs = 0L
    val clearedAccountKeys = mutableListOf<String>()
    val clearedStamps = mutableListOf<String>()
    private val pinMap = mutableMapOf<String, String>()

    /** The offline copy of the account keys (one slot, as on Android) and the full-password stamps. */
    var accountKeys: AccountKeys? = null
    val stamps = mutableMapOf<String, PasswordStamp>()

    override fun loadAccountKeys(userId: String): AccountKeys? = accountKeys
    override fun saveAccountKeys(userId: String, keys: AccountKeys) {
        accountKeys = keys
    }
    override fun clearAccountKeys(userId: String) {
        clearedAccountKeys += userId
        accountKeys = null
    }

    override fun passwordStamp(userId: String): PasswordStamp? = stamps[userId]
    override fun setPasswordStamp(userId: String, stamp: PasswordStamp) {
        stamps[userId] = stamp
    }
    override fun clearPasswordStamp(userId: String) {
        clearedStamps += userId
        stamps.remove(userId)
    }

    override fun identityPins() = SelfIdentityPin.KeyValueStore({ pinMap[it] }, { k, v -> pinMap[k] = v })
}

internal class FakeSessionPersistence(override var baseUrl: String?) : SessionPersistence {
    override var pendingServer: PendingServer? = null
    var stored: StoredSession? = null
    var clearCalls = 0

    /** Session and origin writes, in order. */
    val writes = mutableListOf<String>()

    override fun moveOrigin(origin: String) {
        writes += "origin:$origin"
        baseUrl = origin
    }

    override fun load() = stored
    override fun save(s: StoredSession) {
        stored = s
    }

    override fun updateTokens(t: Tokens?) {
        if (t == null) clear() else stored = stored?.copy(accessToken = t.accessToken, refreshToken = t.refreshToken)
    }

    override fun replaceTokensIf(origin: String, userId: String, expectedRefreshToken: String, t: Tokens?): Boolean {
        val s = stored ?: return false
        if (s.userId != userId || !sessionBelongsTo(s.baseUrl, origin) || s.refreshToken != expectedRefreshToken) return false
        updateTokens(t)
        return true
    }

    override fun clear() {
        clearCalls++
        stored = null
    }

    override fun clearSessionTokens() {
        writes += "drop-session"
        stored = null
    }

    override var mustChangePassword = false
    override var highWaterWallMs = 0L
    override var lastSyncAt = 0L
    private val origins = mutableMapOf<String, FakeOriginStore>()

    override fun origin(key: String): FakeOriginStore = origins.getOrPut(key) { FakeOriginStore() }
}

/** Records every purge of a durable artifact, in order. */
internal class RecordingArtifacts(private val onDelete: () -> Unit = {}) : OfflineArtifacts {
    val events = mutableListOf<String>()

    override fun deleteVaultCache(originKey: String, userId: String) {
        onDelete()
        events += "cache:$originKey/$userId"
    }

    override fun wipeQuickUnlock(originKey: String, userId: String) {
        events += "blob:$originKey/$userId"
    }
}

/** The namespace directories, in memory: every cache is in-memory, and each open is recorded. */
internal class FakeNamespaces : NamespaceStorage {
    val opened = mutableListOf<String>()

    /** When set, opening a cache throws it (a corrupt cache file). */
    var failOpen: Throwable? = null

    override fun openVaultCache(originKey: String, userId: String): VaultCache {
        failOpen?.let { throw it }
        opened += "$originKey/$userId"
        return caches.getOrPut("$originKey/$userId") { InMemoryVaultCache() }
    }

    /** The device state of each namespace, kept so a test can fill one in advance (the personal vault this device confirmed). */
    val devices = mutableMapOf<String, MemoryDeviceState>()

    override fun deviceState(originKey: String, userId: String): DeviceState = devices.getOrPut("$originKey/$userId") { MemoryDeviceState() }

    /** Caches a test filled in advance, by "originKey/userId"; any other namespace opens empty. */
    val caches = mutableMapOf<String, VaultCache>()
    val deleted = mutableListOf<String>()

    override fun deleteVaultCache(originKey: String, userId: String) {
        deleted += "$originKey/$userId"
    }
}

/** The quick-unlock key wrapping, in memory: what the next prompt releases is up to the test. */
internal class FakeQuickKeys : QuickUnlockKeys {
    var biometric = true
    val enrolled = mutableSetOf<String>()
    val wiped = mutableListOf<String>()
    var prompts = 0
    var next: () -> QuickRecover = { QuickRecover.Fallback(null) }

    /** What the next enrollment prompt does; by default it consents and wraps a copy of the UVK. */
    var enrollNext: (io.silencelen.andvari.core.client.Account) -> QuickEnroll = { account ->
        runCatching { account.uvkCopyForPlatformWrap().fill(0) }.fold({ QuickEnroll.Ok }, { QuickEnroll.Failed(null) })
    }
    val enrolledFor = mutableListOf<String>()

    override fun hasStrongBiometric() = biometric
    override fun isEnrolled(originKey: String, userId: String) = "$originKey/$userId" in enrolled
    override suspend fun recover(host: BiometricHost, originKey: String, userId: String): QuickRecover {
        prompts++
        return next()
    }

    override suspend fun enroll(host: BiometricHost, originKey: String, userId: String, account: io.silencelen.andvari.core.client.Account): QuickEnroll {
        prompts++
        val r = enrollNext(account)
        if (r == QuickEnroll.Ok) {
            enrolled += "$originKey/$userId"
            enrolledFor += "$originKey/$userId"
        }
        return r
    }

    override fun wipe(originKey: String, userId: String) {
        wiped += "$originKey/$userId"
        enrolled -= "$originKey/$userId"
    }
}
