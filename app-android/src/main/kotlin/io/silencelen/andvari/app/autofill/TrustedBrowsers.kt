package io.silencelen.andvari.app.autofill

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import java.security.MessageDigest

/**
 * Browsers whose `ViewNode.getWebDomain()` we trust for domain matching — verified by
 * SIGNING CERTIFICATE, not just package name. Any app populates its own ViewStructure, so
 * `getWebDomain()` is attacker-controlled; and an `applicationId` is only unique per-device,
 * so a malicious app can install under an allowlisted-but-absent browser's package id and
 * claim `webDomain=github.com`. We therefore check the installed package's real signing cert
 * against the pinned digest(s) below and **fail closed**: an uninstalled, unpinned, or
 * cert-mismatched package gets `webHost = null` → web items match nothing, only
 * `androidapp://<pkg>` URIs can match it. A wrong/missing pin only costs functionality (that
 * browser won't offer autofill until its digest is added), never safety.
 *
 * Digests are SHA-256 of the DER cert, standard base64. Capture a browser's digest on-device:
 *   apksigner verify --print-certs <apk> | grep 'SHA-256'   (hex → convert), or
 *   adb shell dumpsys package <pkg> | grep -A1 'signatures'.
 */
object TrustedBrowsers {
    // Well-known release-signing certs. Chrome (Google-signed) + Firefox are high-confidence;
    // the rest are best-effort published values — fail-closed if any is stale.
    private val GOOGLE = setOf("8P1sW0EPJcslw7UzRsiXL64w+O50Ed+RBICtay1g24=")
    private val MOZILLA = setOf("p4tipRZbRJSy/q2edqKA0i2Tf+5iUa7OWZRGsuoxmwA=")
    private val SAMSUNG = setOf("ABi2fbt8vkzj7SJ8aD5jDS6NAd5w6Rj0FfJqLnBiHmM=")

    private val PINS: Map<String, Set<String>> = buildMap {
        // Chrome + channels (Google-signed)
        for (p in listOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary", "com.google.android.apps.chrome")) put(p, GOOGLE)
        // Firefox + channels (Mozilla-signed)
        for (p in listOf("org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.focus", "org.mozilla.klar")) put(p, MOZILLA)
        // Samsung Internet
        for (p in listOf("com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta")) put(p, SAMSUNG)
        // Others the household may add a verified digest for (fail-closed until then). Their
        // package ids are recorded so a future pin only needs the digest, not a code change.
        for (p in listOf(
            "com.microsoft.emmx", "com.brave.browser", "com.opera.browser", "com.opera.gx",
            "com.vivaldi.browser", "com.duckduckgo.mobile.android", "com.kiwibrowser.browser",
            "org.torproject.torbrowser",
        )) putIfAbsent(p, emptySet())
    }

    /** True iff [pkg] is a pinned browser AND its installed signing cert matches a pinned digest. */
    fun isTrusted(context: Context, pkg: String): Boolean {
        val pins = PINS[pkg] ?: return false
        if (pins.isEmpty()) return false // known browser, no verified digest yet → fail closed
        val signatures = try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= 28) {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                val si = info.signingInfo ?: return false
                if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures
            }
        } catch (e: PackageManager.NameNotFoundException) {
            return false // not installed
        } catch (t: Throwable) {
            return false
        } ?: return false
        val md = MessageDigest.getInstance("SHA-256")
        return signatures.any { Base64.encodeToString(md.digest(it.toByteArray()), Base64.NO_WRAP) in pins }
    }
}
