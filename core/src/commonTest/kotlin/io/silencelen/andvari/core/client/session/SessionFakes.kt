package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.SelfIdentityPin
import io.silencelen.andvari.core.client.Tokens
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

    override fun loadAccountKeys(userId: String): AccountKeys? = null
    override fun saveAccountKeys(userId: String, keys: AccountKeys) {}
    override fun clearAccountKeys(userId: String) {
        clearedAccountKeys += userId
    }

    override fun passwordStamp(userId: String): PasswordStamp? = null
    override fun setPasswordStamp(userId: String, stamp: PasswordStamp) {}
    override fun clearPasswordStamp(userId: String) {
        clearedStamps += userId
    }

    override fun identityPins() = SelfIdentityPin.KeyValueStore({ pinMap[it] }, { k, v -> pinMap[k] = v })
}

internal class FakeSessionPersistence(override var baseUrl: String?) : SessionPersistence {
    override var pendingServer: PendingServer? = null
    var stored: StoredSession? = null
    var clearCalls = 0

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
