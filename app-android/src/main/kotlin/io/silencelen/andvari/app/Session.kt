package io.silencelen.andvari.app

import android.content.Context
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.model.AccountKeys
import kotlinx.serialization.json.Json

/**
 * Non-secret session persisted across launches (SharedPreferences). Tokens are here
 * (MVP); the vault KEY is NEVER stored — a relaunch re-prompts for the master
 * password (spec 01 §8; Keystore-wrapped quick-unlock is a follow-up).
 */
data class Session(
    val baseUrl: String,
    val userId: String,
    val email: String,
    val accessToken: String,
    val refreshToken: String,
) {
    fun tokens() = Tokens(accessToken, refreshToken)
}

class SessionStore(context: Context) {
    private val prefs = context.getSharedPreferences("andvari", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    var baseUrl: String
        get() = prefs.getString("baseUrl", DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL
        set(v) = prefs.edit().putString("baseUrl", v).apply()

    /**
     * Last-known org `offlineCacheAllowed`, persisted so a forbidding policy is still
     * honored when the app cold-starts OFFLINE (policy fetch fails → this is the fallback,
     * spec 02 §8). Fail-open default true until the first policy is seen.
     */
    var cacheAllowed: Boolean
        get() = prefs.getBoolean("cacheAllowed", true)
        set(v) = prefs.edit().putBoolean("cacheAllowed", v).apply()

    /**
     * Last-known org `autoLockSeconds` (spec 01 §8; 0 = disabled), persisted so the idle
     * window is enforced on OFFLINE cold starts and on the autofill unlock path (which
     * never fetches policy itself). Default 0 until the first policy is seen — nothing can
     * be unlocked before a first online contact anyway (no cached accountKeys yet).
     */
    var autoLockSeconds: Int
        get() = prefs.getInt("autoLockSeconds", 0)
        set(v) = prefs.edit().putInt("autoLockSeconds", v).apply()

    /**
     * When the last spec 07 backup was produced (unix ms; 0 = never). Recorded LOCALLY
     * only — the server is never told an export happened (spec 07 §2.6). Drives the
     * "Last backup: N days ago" line + the >90-day nudge in Settings.
     */
    var lastExportAt: Long
        get() = prefs.getLong("lastExportAt", 0L)
        set(v) = prefs.edit().putLong("lastExportAt", v).apply()

    /** When the last SUCCESSFUL sync finished (unix ms; 0 = unknown) — the timestamp the
     *  spec 07 offline-export note shows ("vault as of last sync <time>"). */
    var lastSyncAt: Long
        get() = prefs.getLong("lastSyncAt", 0L)
        set(v) = prefs.edit().putLong("lastSyncAt", v).apply()

    fun load(): Session? {
        val userId = prefs.getString("userId", null) ?: return null
        return Session(
            baseUrl = baseUrl,
            userId = userId,
            email = prefs.getString("email", "") ?: "",
            accessToken = prefs.getString("accessToken", "") ?: "",
            refreshToken = prefs.getString("refreshToken", "") ?: "",
        )
    }

    fun save(s: Session) {
        prefs.edit()
            .putString("baseUrl", s.baseUrl)
            .putString("userId", s.userId)
            .putString("email", s.email)
            .putString("accessToken", s.accessToken)
            .putString("refreshToken", s.refreshToken)
            .apply()
    }

    fun updateTokens(t: Tokens?) {
        if (t == null) { clear(); return }
        prefs.edit().putString("accessToken", t.accessToken).putString("refreshToken", t.refreshToken).apply()
    }

    /**
     * The server's accountKeys payload — all ciphertext/public (wrappedUvk,
     * encryptedIdentitySeed, identityPub) + salts/params, same trust class as the tokens
     * already here. Enables offline unlock (spec 02 §8); wiped on sign-out / revocation.
     */
    fun saveAccountKeys(keys: AccountKeys) {
        prefs.edit().putString("accountKeys", json.encodeToString(AccountKeys.serializer(), keys)).apply()
    }

    fun loadAccountKeys(): AccountKeys? =
        prefs.getString("accountKeys", null)?.let { runCatching { json.decodeFromString(AccountKeys.serializer(), it) }.getOrNull() }

    fun clearAccountKeys() { prefs.edit().remove("accountKeys").apply() }

    fun clear() {
        prefs.edit().remove("userId").remove("email").remove("accessToken").remove("refreshToken").remove("accountKeys").apply()
    }

    /**
     * One-time bump of the persisted server URL from the old VLAN-2 LAN default to the
     * tailnet HTTPS default (reachable from any Tailscale device; the LAN IP isn't, off-VLAN-2).
     * Only rewrites the exact legacy default, so a deliberate custom URL is left alone.
     */
    fun migrateDefaultOnce() {
        if (prefs.getBoolean("baseUrlMigratedTailnet", false)) return
        if (prefs.getString("baseUrl", null) == LEGACY_LAN_DEFAULT) {
            prefs.edit().putString("baseUrl", DEFAULT_BASE_URL).apply()
        }
        prefs.edit().putBoolean("baseUrlMigratedTailnet", true).apply()
    }

    companion object {
        const val DEFAULT_BASE_URL = "https://andvari.taila2dff2.ts.net"
        private const val LEGACY_LAN_DEFAULT = "http://192.168.2.122:8080"
    }
}
