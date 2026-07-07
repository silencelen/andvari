package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.model.AccountKeys
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File

/**
 * Non-secret desktop session persisted to ~/.andvari-desktop/session.json. Tokens
 * are here (MVP); the vault KEY is NEVER stored — a relaunch re-prompts for the
 * master password (spec 01 §8). DPAPI+PIN quick-unlock is a documented Windows
 * follow-up (see ops/windows-build.md).
 */
@Serializable
data class DesktopSession(
    val baseUrl: String,
    val userId: String,
    val email: String,
    val accessToken: String,
    val refreshToken: String,
) {
    fun tokens() = Tokens(accessToken, refreshToken)
}

class DesktopSessionStore {
    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }
    private val dir = File(System.getProperty("user.home"), ".andvari-desktop")
    private val file = File(dir, "session.json")
    private val prefsFile = File(dir, "prefs.json")
    private val keysFile = File(dir, "account-keys.json")

    /** Where the per-account durable cache DB lives (spec 02 §8). */
    val cacheDir: File get() = dir

    @Serializable
    private data class Prefs(val baseUrl: String = DEFAULT_BASE_URL)

    var baseUrl: String
        get() = runCatching { json.decodeFromString(Prefs.serializer(), prefsFile.readText()).baseUrl }.getOrDefault(DEFAULT_BASE_URL)
        set(v) { dir.mkdirs(); prefsFile.writeText(json.encodeToString(Prefs.serializer(), Prefs(v))) }

    fun load(): DesktopSession? =
        runCatching { json.decodeFromString(DesktopSession.serializer(), file.readText()) }.getOrNull()

    fun save(s: DesktopSession) {
        dir.mkdirs()
        file.writeText(json.encodeToString(DesktopSession.serializer(), s))
        // 0600 on POSIX; best-effort on Windows.
        runCatching { file.setReadable(false, false); file.setReadable(true, true); file.setWritable(false, false); file.setWritable(true, true) }
    }

    fun updateTokens(t: Tokens?) {
        if (t == null) { clear(); return }
        load()?.let { save(it.copy(accessToken = t.accessToken, refreshToken = t.refreshToken)) }
    }

    /** Cached accountKeys for offline unlock (spec 02 §8) — all ciphertext/public. */
    fun saveAccountKeys(keys: AccountKeys) {
        dir.mkdirs()
        keysFile.writeText(json.encodeToString(AccountKeys.serializer(), keys))
        runCatching { keysFile.setReadable(false, false); keysFile.setReadable(true, true); keysFile.setWritable(false, false); keysFile.setWritable(true, true) }
    }

    fun loadAccountKeys(): AccountKeys? =
        runCatching { json.decodeFromString(AccountKeys.serializer(), keysFile.readText()) }.getOrNull()

    fun clear() { file.delete(); keysFile.delete() }

    companion object {
        const val DEFAULT_BASE_URL = "http://192.168.2.122:8080"
    }
}
