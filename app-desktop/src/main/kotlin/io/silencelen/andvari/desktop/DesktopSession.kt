package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.model.AccountKeys
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.nio.file.Files

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

/**
 * On-disk layout (design 2026-07-15-multi-tenant-endpoints §4.2 — (origin, userId) namespacing):
 *
 *     ~/.andvari-desktop/
 *       session.json                       — the single current session (unchanged)
 *       prefs.json                         — device prefs + per-origin `origins` map
 *       ns/<originKey>/<userId>/           — ONE origin's namespace ([originKey])
 *         vault-<userId>.db{,-wal,-shm}    — the encrypted durable vault cache (spec 02 §8)
 *         account-keys.json                — cached accountKeys for offline unlock
 *
 * Every destructive path here takes an explicit originKey: a purge triggered by ONE server's
 * policy (or its 401) can only ever reach that origin's own namespace — probing a forbidding
 * server must never destroy the home server's offline data (§4.2, B2-3). Switch round trips
 * (A→B→A) leave the other origin's material intact (B2-7).
 *
 * [dir] is injectable for tests only; production always uses the default.
 */
class DesktopSessionStore(
    private val dir: File = File(System.getProperty("user.home"), ".andvari-desktop"),
) {
    private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }
    private val file = File(dir, "session.json")
    private val prefsFile = File(dir, "prefs.json")
    // LEGACY pre-§4.2 unscoped account-keys location — touched ONLY by [adoptNamespacesOnce].
    private val legacyKeysFile = File(dir, "account-keys.json")

    /**
     * §4.2: one origin's slice of the device prefs, keyed by [originKey] in [Prefs.origins].
     * Everything an untrusted server can influence — its declared policy fallbacks — and the
     * user's per-origin consent live HERE, never in a global field a different origin would read.
     */
    @Serializable
    private data class OriginPrefs(
        // Last-known org offlineCacheAllowed for THIS origin (honored when a cold start is
        // offline, spec 02 §8). Default FALSE — a never-probed origin gets the §2.3
        // fetch-failure posture (durable cache OFF) until its policy is actually seen;
        // adoption seeds the pre-namespacing value for the existing origin (continuity).
        val cacheAllowed: Boolean = false,
        // §5.3 (B1-4): per-(device, origin) durable-cache consent. null = never answered (the
        // one-time post-first-unlock prompt is still owed; NOTHING persists at rest meanwhile),
        // true = opted in (or continuity-adopted), false = declined.
        val cacheConsent: Boolean? = null,
        // Last-known org autoLockSeconds for THIS origin (offline cold-start fallback; stored
        // pre-clamped by DesktopState.applyPolicy — §2.3 B1-1).
        val autoLockSeconds: Int = 0,
    )

    @Serializable
    private data class Prefs(
        val baseUrl: String = DEFAULT_BASE_URL,
        // LEGACY (pre-§4.2) GLOBAL fallbacks — kept ONLY so an old prefs.json still parses and
        // [adoptNamespacesOnce] can seed the current origin's entry from them. Never written
        // again; the per-origin [origins] map is the live store.
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
        // §4.2: per-origin client state, keyed by [originKey]. Additive with a default so a
        // pre-namespacing prefs.json parses unchanged.
        val origins: Map<String, OriginPrefs> = emptyMap(),
        // §4.2 adoption one-shot flag — see [adoptNamespacesOnce].
        val nsAdoptedOnce: Boolean = false,
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
     *
     * WAVE-4 NOTE (design 2026-07-15 §6): the multi-tenant rollout replaces this with
     * `migrateDefaultOnce` v2 (new flag, tailnet→public constant rewrite). v2 MUST keep running
     * BEFORE [adoptNamespacesOnce] — see the coupling note there.
     */
    fun migrateDefaultOnce() {
        val p = prefs()
        if (p.baseUrlMigratedTailnet) return
        writePrefs(p.copy(baseUrl = if (p.baseUrl == LEGACY_LAN_DEFAULT) DEFAULT_BASE_URL else p.baseUrl, baseUrlMigratedTailnet = true))
    }

    // ---- §4.2 per-origin prefs ----

    private fun originPrefs(key: String): OriginPrefs = prefs().origins[key] ?: OriginPrefs()

    private fun writeOrigin(key: String, mut: (OriginPrefs) -> OriginPrefs) {
        val p = prefs()
        writePrefs(p.copy(origins = p.origins + (key to mut(p.origins[key] ?: OriginPrefs()))))
    }

    /** Last-known org offlineCacheAllowed for [key]'s origin (spec 02 §8 offline fallback). */
    fun orgCacheAllowed(key: String): Boolean = originPrefs(key).cacheAllowed
    fun setOrgCacheAllowed(key: String, v: Boolean) = writeOrigin(key) { it.copy(cacheAllowed = v) }

    /** §5.3 per-(device, origin) durable-cache consent — null until the one-time prompt is answered. */
    fun cacheConsent(key: String): Boolean? = originPrefs(key).cacheConsent
    fun setCacheConsent(key: String, v: Boolean) = writeOrigin(key) { it.copy(cacheConsent = v) }

    /** Last-known org autoLockSeconds for [key]'s origin (offline cold-start fallback; pre-clamped). */
    fun originAutoLockSeconds(key: String): Int = originPrefs(key).autoLockSeconds
    fun setOriginAutoLockSeconds(key: String, v: Int) = writeOrigin(key) { it.copy(autoLockSeconds = v) }

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

    // ---- §4.2 namespaced on-disk layout ----

    /** ONE (origin, user)'s namespace dir: `ns/<originKey>/<userId>/` (spec 02 §8 cache home).
     *  Both segments are laundered through [pathSafe] — `userId` is SERVER-SUPPLIED and the
     *  server is untrusted: a hostile `../<victim>` id must never traverse into another
     *  origin's namespace (Android `OriginNamespace.dir` twin). No side effects (writers
     *  mkdirs at the use site). */
    fun nsDir(key: String, userId: String): File = File(File(File(dir, "ns"), pathSafe(key)), pathSafe(userId))

    /** The per-account durable vault-cache DB inside [nsDir] (caller mkdirs the parent on create). */
    fun cacheDbFile(key: String, userId: String): File = File(nsDir(key, userId), "vault-${pathSafe(userId)}.db")

    /** Delete ONE origin's vault-cache DB set — never another origin's (§4.2). */
    fun deleteCacheDb(key: String, userId: String) {
        for (suffix in listOf("", "-wal", "-shm")) {
            val f = File(nsDir(key, userId), "vault-${pathSafe(userId)}.db$suffix")
            // Windows: a straggler handle (AV/indexer) can defeat the unlink — retry at JVM exit.
            if (!f.delete() && f.exists()) f.deleteOnExit()
        }
    }

    private fun accountKeysFile(key: String, userId: String) = File(nsDir(key, userId), "account-keys.json")

    /** Cached accountKeys for offline unlock (spec 02 §8) — all ciphertext/public; per-origin (§4.2). */
    fun saveAccountKeys(key: String, userId: String, keys: AccountKeys) {
        val f = accountKeysFile(key, userId)
        f.parentFile?.mkdirs()
        f.writeText(json.encodeToString(AccountKeys.serializer(), keys))
        runCatching { f.setReadable(false, false); f.setReadable(true, true); f.setWritable(false, false); f.setWritable(true, true) }
    }

    fun loadAccountKeys(key: String, userId: String): AccountKeys? =
        runCatching { json.decodeFromString(AccountKeys.serializer(), accountKeysFile(key, userId).readText()) }.getOrNull()
            // H1 cache belt (spec 05 T1): evict a cache poisoned pre-fix with sub-floor / absurd KDF
            // params -> null = cache miss -> the caller refetches through the fenced AndvariApi.
            ?.takeIf { runCatching { io.silencelen.andvari.core.client.KdfUpgrade.requireServerKdfParams(it.kdfParams) }.isSuccess }

    /** §4.2: per-origin — clearing keys for one origin never touches another's namespace. */
    fun clearAccountKeys(key: String, userId: String) { accountKeysFile(key, userId).delete() }

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

    /** Drop the persisted session + the CURRENT origin's cached account keys for its user.
     *  §4.2: a session teardown on the current origin must never reach into another origin's
     *  namespace (the other origins' keys stay, bounded by their own purge paths). */
    fun clear() {
        load()?.let { s -> clearAccountKeys(originKey(baseUrl), s.userId) }
        file.delete()
    }

    /**
     * §4.2 adoption one-shot: on the first run of this build, move the legacy UNSCOPED layout
     * (`vault-<userId>.db{,-wal,-shm}` + `account-keys.json` at the store root) into the current
     * baseUrl origin's namespace `ns/<originKey>/<userId>/`, seed that origin's prefs entry from
     * the legacy global fields, and — B1-4 continuity — adopt cacheConsent=ON when the install
     * already held a cache, so nobody's offline access silently vanishes under the new
     * consent-default-OFF regime (§5.3). Fresh installs just set the flag (consent stays
     * unanswered ⇒ the one-time prompt is owed and nothing persists until it's answered).
     *
     * Best-effort by design: a file that cannot move (e.g. a Windows AV handle on first launch)
     * stays behind, unreachable by the ns-scoped readers — equivalent to a cache miss the next
     * sync repopulates; never block or crash first launch on it.
     *
     * ORDERING (binding, §4.2): runs AFTER [migrateDefaultOnce], so data adopts under the key of
     * the URL the app will actually dial.
     *
     * WAVE-4 COUPLING — FLAGGED, DO NOT GUESS (design §4.2 adoption bullet + §6.2): Wave 4 ships
     * migrateDefaultOnce v2 (tailnet→public default rewrite) and MUST sequence that rewrite
     * BEFORE this adoption on installs where [Prefs.nsAdoptedOnce] is still false. AND, because
     * THIS build may already have adopted under the tailnet default's key, Wave 4 must also carry
     * the already-adopted namespace across the rewrite (move `ns/<originKey(tailnet)>/` →
     * `ns/<originKey(public)>/` + its [Prefs.origins] entry — same instance, two fronts, §6.2's
     * "the rename doesn't orphan native offline data"). Wave 4 owns that sequencing; this method
     * only guarantees its own AFTER-migration position.
     */
    fun adoptNamespacesOnce() {
        val p = prefs()
        if (p.nsAdoptedOnce) return
        val key = originKey(p.baseUrl)
        var hadLegacyCache = false
        // 1) Vault-cache DB sets: the legacy filename embeds the userId — re-home each file
        //    under (current origin, that user).
        dir.listFiles()?.forEach { f ->
            val m = LEGACY_CACHE_NAME.matchEntire(f.name) ?: return@forEach
            hadLegacyCache = true
            moveIntoNs(f, File(nsDir(key, m.groupValues[1]), f.name))
        }
        // 2) The single legacy accountKeys cache belongs to the persisted session's user. With no
        //    session it is unreachable (offline unlock needs session.json) — leave it in place
        //    rather than guess an owner; nothing reads the legacy path again.
        val s = load()
        if (legacyKeysFile.exists()) {
            hadLegacyCache = true
            if (s != null) moveIntoNs(legacyKeysFile, accountKeysFile(key, s.userId))
        }
        // 3) Seed the current origin's entry from the legacy global fields (continuity: the
        //    pre-namespacing install's last-known policy keeps governing its own origin), and
        //    adopt consent=ON iff a cache already existed (B1-4 first branch, §5.3).
        val cur = p.origins[key] ?: OriginPrefs()
        writePrefs(
            p.copy(
                origins = p.origins + (key to cur.copy(
                    cacheAllowed = p.cacheAllowed,
                    autoLockSeconds = p.autoLockSeconds,
                    cacheConsent = if (hadLegacyCache) true else cur.cacheConsent,
                )),
                nsAdoptedOnce = true,
            ),
        )
    }

    private fun moveIntoNs(src: File, dst: File) {
        dst.parentFile?.mkdirs()
        runCatching { Files.move(src.toPath(), dst.toPath()) }.recoverCatching {
            // Cross-store or locked-source fallback; overwrite=false — an existing ns copy wins.
            src.copyTo(dst, overwrite = false)
            src.delete()
        }
    }

    companion object {
        const val DEFAULT_BASE_URL = "https://andvari.taila2dff2.ts.net"
        private const val LEGACY_LAN_DEFAULT = "http://192.168.2.122:8080"

        /** The pre-§4.2 unscoped cache filename shape — group 1 is the userId. */
        private val LEGACY_CACHE_NAME = Regex("^vault-(.+)\\.db(-wal|-shm)?$")
    }
}
