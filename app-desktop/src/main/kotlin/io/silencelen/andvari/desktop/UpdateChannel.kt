package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppSnapshot
import java.net.URI

/**
 * Where the update check asks for the signed update list (the owner's decision of
 * 2026-11-15: "the andvari server the user attaches to sets the update channel for desktop. default should be from
 * the github releases").
 *
 * Whatever the source, the list is verified against the key this build pins ([io.silencelen.andvari.core.client.UpdateVerify])
 * before anything is read from it, with the rollback floor: a source can withhold an update, it cannot forge one.
 */
sealed class UpdateSource {
    /** The signed list; its detached signature is at [signatureUrl]. */
    abstract val manifestUrl: String

    val signatureUrl: String get() = "$manifestUrl.sig"

    /** How About names the source. The banner never names a source: it names the list's own address ([UpdateChannel.bannerAddress]). */
    abstract val shown: String

    /** The server the person attached, at the routes it serves today. */
    data class Server(val origin: String) : UpdateSource() {
        override val manifestUrl: String get() = "$origin/downloads/manifest.json"
        override val shown: String get() = origin
    }

    /** The andvari repository's latest GitHub release, the default channel. */
    data object GitHubReleases : UpdateSource() {
        override val manifestUrl: String get() = UpdateChannel.GITHUB_MANIFEST_URL
        override val shown: String get() = UpdateChannel.GITHUB_RELEASES_PAGE
    }
}

/** The update banner's words (a marked placeholder): the version and where to download it ([UpdateCheck.Available.downloadUrl]). */
fun updateBanner(a: UpdateCheck.Available): io.silencelen.andvari.desktop.trust.UiText =
    io.silencelen.andvari.desktop.trust.UiText.ph(io.silencelen.andvari.desktop.trust.Placeholder.UPDATE_AVAILABLE_BANNER, a.version, a.downloadUrl)

/**
 * The server this computer is attached to is one it holds an
 * account on, a kept or open session: the lock screen, the open vault, or the journey of an account its server signed
 * out ([AppSnapshot.keptSignedOut]). A server only on show (an invite link opened, an address typed, a Trust Gate not yet
 * answered) is not attached, and before there is an account nothing is asked of anyone.
 */
fun attachedOrigin(s: AppSnapshot?): String? = when (s?.phase) {
    AppPhase.LOCKED, AppPhase.UNLOCKED -> s.locked?.prompt?.instance?.origin ?: s.instance?.label?.origin
    AppPhase.ENTRY -> s.keptSignedOut?.instance?.origin
    else -> null
}

/**
 * What a check leaves behind: only a verified list ratchets the rollback floor (signed updates §D#5) and is recorded
 * as the last check, with its source.
 */
internal fun recordUpdateReport(prefs: DesktopSessionStore, r: UpdateReport) {
    if (!r.verified) return
    r.seq?.let { if (it > prefs.lastAcceptedSeq) prefs.lastAcceptedSeq = it }
    r.from?.let { prefs.recordUpdateCheck(r.atMs, it.shown, r.signedAt) }
}

object UpdateChannel {
    /**
     * The one switch: whether GitHub may be asked before any server is chosen. Off: before a server is attached,
     * nothing is asked (whether GitHub may be asked from first launch is not decided yet).
     */
    const val ASK_GITHUB_BEFORE_A_SERVER: Boolean = false

    const val GITHUB_REPOSITORY = "silencelen/andvari"

    /**
     * GitHub's address for an asset of the latest release (`/releases/latest/download/<name>`): it answers with a
     * redirect to the asset's storage. "Latest" is the newest release that is neither a draft nor a pre-release.
     */
    const val GITHUB_MANIFEST_URL = "https://github.com/$GITHUB_REPOSITORY/releases/latest/download/manifest.json"

    const val GITHUB_RELEASES_PAGE = "https://github.com/$GITHUB_REPOSITORY/releases/latest"

    /** The pre-cut-over address. It is never asked, as a source or as a redirect's target. */
    const val RETIRED_HOST = "andvari.monahanhosting.com"

    /**
     * The sources, in the order they are asked: the attached server (unless it is the retired address or not an
     * http(s) origin), then GitHub. With no server attached: nothing, unless [askGitHubBeforeAServer].
     */
    fun sources(attachedOrigin: String?, askGitHubBeforeAServer: Boolean = ASK_GITHUB_BEFORE_A_SERVER): List<UpdateSource> {
        if (attachedOrigin == null) return if (askGitHubBeforeAServer) listOf(UpdateSource.GitHubReleases) else emptyList()
        return listOfNotNull(serverOrigin(attachedOrigin)?.let { UpdateSource.Server(it) }, UpdateSource.GitHubReleases)
    }

    /** [origin] as a source's base (no trailing slash), or null when it may not be asked. */
    internal fun serverOrigin(origin: String): String? {
        val o = origin.trim().trimEnd('/')
        val uri = runCatching { URI(o) }.getOrNull() ?: return null
        if (uri.scheme?.lowercase() !in setOf("https", "http")) return null
        if (uri.rawUserInfo != null || uri.host.isNullOrEmpty()) return null
        // An origin only: a path, query or fragment would make the list's address another
        // than the server's own two files.
        if (!uri.rawPath.isNullOrEmpty() || uri.rawQuery != null || uri.rawFragment != null) return null
        if (!mayAsk(uri)) return null
        return o
    }

    /**
     * Whether a request may go to [uri]: https, or http to the attached server's own origin when that is http (the
     * list is verified either way); never the retired host or a name under it.
     */
    fun mayAsk(uri: URI): Boolean {
        val host = uri.host?.lowercase()?.trimEnd('.') ?: return false
        if (host == RETIRED_HOST || host.endsWith(".$RETIRED_HOST")) return false
        return uri.scheme?.lowercase() in setOf("https", "http")
    }

    /**
     * GitHub's own hosts a release asset's address redirects to (`/releases/latest/download/…` answers with the asset's
     * storage). Nothing else is followed from GitHub.
     */
    val GITHUB_ASSET_HOSTS: Set<String> = setOf("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")

    /**
     * The update fetch follows no redirect to another host. A source's request that
     * started at [start] may be redirected only to the same host; one that started at github.com, only within GitHub's
     * own asset hosts ([GITHUB_ASSET_HOSTS]), which its latest-release address needs. So an attached server cannot make
     * this computer ask an address of its choosing.
     */
    fun mayRedirect(start: URI, to: URI): Boolean {
        val from = start.host?.lowercase()?.trimEnd('.') ?: return false
        val host = to.host?.lowercase()?.trimEnd('.') ?: return false
        // The same host at the same port (another port of the same name is another service).
        if (host == from) return portOf(start) == portOf(to)
        return from == "github.com" && host in GITHUB_ASSET_HOSTS && portOf(to) == 443
    }

    private fun portOf(u: URI): Int = if (u.port != -1) u.port else if (u.scheme.equals("http", ignoreCase = true)) 80 else 443

    /** The publisher's hosts a download may be named on: the project's GitHub releases, and `andvaripass.com`. */
    const val PUBLISHER_HOST = "andvaripass.com"

    /**
     * The banner's address. It is the download address the **signed list itself** carries
     * for this platform, only when that is an absolute https address with no user name or port of its own, on the
     * publisher's hosts: the project's GitHub releases (`https://github.com/silencelen/andvari/releases/…`) or
     * `andvaripass.com`. Anything else, a relative address included (which would read as the relaying server's own),
     * gives the project's GitHub releases page. Never an address made from the relaying server's origin.
     */
    fun bannerAddress(listUrl: String?): String {
        val uri = listUrl?.trim()?.let { runCatching { URI(it) }.getOrNull() } ?: return GITHUB_RELEASES_PAGE
        val host = uri.host?.lowercase() ?: return GITHUB_RELEASES_PAGE
        // A browser resolves dot segments (`/releases/../../another/repo`), plain or percent-encoded, and an
        // encoded slash; none passes, so the path checked is the path opened.
        val path = uri.rawPath.orEmpty()
        if (uri.normalize().rawPath != path || path.contains("%2e", ignoreCase = true) || path.contains("%2f", ignoreCase = true) || path.contains("%5c", ignoreCase = true)) {
            return GITHUB_RELEASES_PAGE
        }
        val ok = uri.isAbsolute && uri.scheme.equals("https", ignoreCase = true) && uri.rawUserInfo == null && uri.port == -1 &&
            (host == PUBLISHER_HOST || (host == "github.com" && (uri.rawPath ?: "").startsWith("/$GITHUB_REPOSITORY/releases/")))
        return if (ok) uri.toString() else GITHUB_RELEASES_PAGE
    }
}
