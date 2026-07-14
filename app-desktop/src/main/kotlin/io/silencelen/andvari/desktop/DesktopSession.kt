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
    private data class Prefs(
        val baseUrl: String = DEFAULT_BASE_URL,
        val cacheAllowed: Boolean = true,
        val baseUrlMigratedTailnet: Boolean = false,
        val autoLockSeconds: Int = 0,
        val lastExportAt: Long = 0,
        val lastSyncAt: Long = 0,
        // UI-audit #26: the user's Auto/Light/Dark override ("auto"/"light"/"dark"). Additive with
        // a default, so a pre-#26 prefs.json parses unchanged. Kept a plain STRING (not an enum):
        // an unrecognized value must degrade to Auto in the reader, never fail the whole Prefs
        // decode (which getOrDefault would silently reset to factory settings).
        val themeMode: String = "auto",
        // H2 signed updates (design 2026-07-13-signed-updates §B/§M-D4): the highest `seq` of any
        // VERIFIED downloads manifest this install ever accepted — the anti-rollback floor a
        // replayed old-but-validly-signed manifest is refused against. Additive; ratchets up only.
        val lastAcceptedSeq: Long = 0,
    )

    private fun prefs(): Prefs = runCatching { json.decodeFromString(Prefs.serializer(), prefsFile.readText()) }.getOrDefault(Prefs())
    private fun writePrefs(p: Prefs) { dir.mkdirs(); prefsFile.writeText(json.encodeToString(Prefs.serializer(), p)) }

    var baseUrl: String
        get() = prefs().baseUrl
        set(v) { writePrefs(prefs().copy(baseUrl = v)) }

    /**
     * One-time bump of an old VLAN-2 LAN default to the tailnet HTTPS default (reachable
     * from anywhere a Tailscale node runs; the LAN IP is off-VLAN-2-only). Rewrites ONLY the
     * exact legacy default, so a deliberately-set custom URL is untouched. Mirrors Android.
     */
    fun migrateDefaultOnce() {
        val p = prefs()
        if (p.baseUrlMigratedTailnet) return
        writePrefs(p.copy(baseUrl = if (p.baseUrl == LEGACY_LAN_DEFAULT) DEFAULT_BASE_URL else p.baseUrl, baseUrlMigratedTailnet = true))
    }

    /** Last-known org offlineCacheAllowed — honored when a cold start is offline (spec 02 §8). */
    var cacheAllowed: Boolean
        get() = prefs().cacheAllowed
        set(v) { writePrefs(prefs().copy(cacheAllowed = v)) }

    /**
     * Last-known org autoLockSeconds (spec 01 §8; 0 = disabled) — enforced on offline cold
     * starts, before the first live policy fetch lands. Mirrors Android's SessionStore.
     */
    var autoLockSeconds: Int
        get() = prefs().autoLockSeconds
        set(v) { writePrefs(prefs().copy(autoLockSeconds = v)) }

    /**
     * When the last spec 07 backup was produced (unix ms; 0 = never). Recorded LOCALLY
     * only — the server is never told an export happened (spec 07 §2.6). Drives the
     * "Last backup: N days ago" line + the >90-day nudge in Settings.
     */
    var lastExportAt: Long
        get() = prefs().lastExportAt
        set(v) { writePrefs(prefs().copy(lastExportAt = v)) }

    /** When the last SUCCESSFUL sync finished (unix ms; 0 = unknown) — the timestamp the
     *  spec 07 offline-export note shows ("vault as of last sync <time>"). */
    var lastSyncAt: Long
        get() = prefs().lastSyncAt
        set(v) { writePrefs(prefs().copy(lastSyncAt = v)) }

    /** UI-audit #26: the persisted Auto/Light/Dark theme override (see the Prefs field note —
     *  raw store string; [ThemeMode.fromStore] does the lenient parse). */
    var themeMode: String
        get() = prefs().themeMode
        set(v) { writePrefs(prefs().copy(themeMode = v)) }

    /** H2 anti-rollback floor (signed updates §M): highest verified manifest `seq` ever accepted.
     *  Written only after [io.silencelen.andvari.core.client.UpdateVerify] passed on the raw bytes
     *  (design §D#5 — never persisted off an unverified fetch). */
    var lastAcceptedSeq: Long
        get() = prefs().lastAcceptedSeq
        set(v) { writePrefs(prefs().copy(lastAcceptedSeq = v)) }

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
            // H1 cache belt (spec 05 T1): evict a cache poisoned pre-fix with sub-floor / absurd KDF
            // params -> null = cache miss -> the caller refetches through the fenced AndvariApi.
            ?.takeIf { runCatching { io.silencelen.andvari.core.client.KdfUpgrade.requireServerKdfParams(it.kdfParams) }.isSuccess }

    fun clearAccountKeys() { keysFile.delete() }

    fun clear() { file.delete(); keysFile.delete() }

    companion object {
        const val DEFAULT_BASE_URL = "https://andvari.taila2dff2.ts.net"
        private const val LEGACY_LAN_DEFAULT = "http://192.168.2.122:8080"
    }
}
