package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.SaveQueue
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.app.SaveQueued
import io.silencelen.andvari.core.client.autofill.UriMatch
import io.silencelen.andvari.core.crypto.CryptoProvider

/**
 * A login Android's autofill service captured (the system's save prompt), put into the same queue the iPhone's
 * extensions use, so the content confirms and saves it under the queue's rules and nothing else writes it.
 *
 * - **What the service passes:** the [SaveQueueStore] the app gave its [ContentStores] (the same instance), the site
 *   ([appSite] for a login typed in an app, [webSite] for one typed on a page of a browser whose web domain the service
 *   trusts), the user name and the password as captured, and the wall clock.
 * - **What is sealed:** the whole capture (site, user name, password, time, source `autofill`, and the origin and
 *   account it is for) in a sealed box to the account's identity key as the store's publication names it. Only the
 *   unlocked account opens it; the service needs no key and never holds one, and works while the vault is locked.
 * - **Where it is kept:** one new entry of the store (never replacing one), in the app's own storage.
 * - **How the content reads it:** at the next sync of an unlocked vault, or at once through
 *   [VaultContent.readSaveQueue] when the app is open: a new login for a site is saved by itself and listed in
 *   [ContentState.appliedSaves] (with undo); anything else waits in [ContentState.pendingSaves] for the person.
 *
 * [SaveQueued.NO_ACCOUNT] when no key is published (nobody is signed in, or the server's policy forbids keeping data
 * on this device: then the queue is not read at all); [SaveQueued.REFUSED] for a capture the queue does not take (no
 * password, a field too long, a site that is neither, the queue full).
 */
object ContentCapture {
    /** The source a capture by the system's save prompt carries; the content's lists word it as such. */
    const val SOURCE = "autofill"

    /** Android package names: dot-separated Java identifiers, at least two segments. */
    private val PACKAGE = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")
    private const val MAX_PACKAGE_CHARS = 255

    /** The site of a login captured in the app [packageName] (`androidapp://<package>`), or null for a name that is no package. */
    fun appSite(packageName: String): String? =
        packageName.trim().takeIf { it.length <= MAX_PACKAGE_CHARS && PACKAGE.matches(it) }?.let { UriMatch.ANDROID_APP_SCHEME + it }

    /**
     * The site of a login captured on a page of [domain], with the page's [scheme] (`https` or `http`) when the browser
     * reported it, or null (the domain alone: the person is asked before it is saved). Null for a domain that is no host.
     */
    fun webSite(domain: String, scheme: String?): String? {
        val host = domain.trim()
        if (host.isEmpty() || host.contains("://") || UriMatch.normalizeHost(host) == null) return null
        return when (scheme?.trim()?.lowercase()) {
            "https" -> "https://$host"
            "http" -> "http://$host"
            null, "" -> host
            else -> null
        }
    }

    /** Queue one captured login (see the class). [site] is one [appSite] or [webSite] made. */
    fun queue(store: SaveQueueStore, crypto: CryptoProvider, site: String, username: String, password: String, nowMs: Long): SaveQueued {
        if (appPackage(site) == null && (isApp(site) || UriMatch.normalizeHost(site) == null)) return SaveQueued.REFUSED
        return SaveQueue.enqueue(store, crypto, site, username, password, nowMs, SOURCE)
    }

    /** True for a capture made in an app (`androidapp://`), valid or not: never read as a web address. */
    internal fun isApp(site: String): Boolean = site.trim().startsWith(UriMatch.ANDROID_APP_SCHEME, ignoreCase = true)

    /** The package of an app capture, or null (a web capture, or an app address that names no package). */
    internal fun appPackage(site: String): String? {
        if (!isApp(site)) return null
        val pkg = site.trim().substring(UriMatch.ANDROID_APP_SCHEME.length)
        return pkg.takeIf { it.length <= MAX_PACKAGE_CHARS && PACKAGE.matches(it) }
    }
}
