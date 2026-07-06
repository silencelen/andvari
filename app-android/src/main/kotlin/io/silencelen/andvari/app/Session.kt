package io.silencelen.andvari.app

import android.content.Context
import io.silencelen.andvari.core.client.Tokens

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

    var baseUrl: String
        get() = prefs.getString("baseUrl", DEFAULT_BASE_URL) ?: DEFAULT_BASE_URL
        set(v) = prefs.edit().putString("baseUrl", v).apply()

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

    fun clear() {
        prefs.edit().remove("userId").remove("email").remove("accessToken").remove("refreshToken").apply()
    }

    companion object {
        const val DEFAULT_BASE_URL = "http://192.168.2.122:8080"
    }
}
