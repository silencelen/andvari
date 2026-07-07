package io.silencelen.andvari.app.autofill

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import io.silencelen.andvari.core.client.autofill.BrowserCertPins
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
    // The pin table (package → accepted cert digests) lives in :core so its format is
    // gate-tested (BrowserCertPinsTest); the manifest <queries> block MUST list the same
    // package ids or getPackageInfo throws NameNotFound on API 30+ and the check fails closed.
    private val PINS: Map<String, Set<String>> get() = BrowserCertPins.TABLE

    /** Observed standard-base64 SHA-256 of [pkg]'s installed signing cert, or null if the
     *  package isn't installed / isn't visible. Powers the Autofill-status diagnostic's
     *  cert-mismatch surface: it prints exactly what to add to [BrowserCertPins] for the
     *  owner's real browser. Never trusts this value — only [isTrusted] gates fills. */
    fun observedCertDigest(context: Context, pkg: String): String? {
        val sig = signingCerts(context, pkg) ?: return null
        val md = MessageDigest.getInstance("SHA-256")
        return sig.firstOrNull()?.let { Base64.encodeToString(md.digest(it.toByteArray()), Base64.NO_WRAP) }
    }

    /** True iff [pkg] is a pinned browser AND its installed signing cert matches a pinned digest. */
    fun isTrusted(context: Context, pkg: String): Boolean {
        val pins = PINS[pkg] ?: return false
        if (pins.isEmpty()) return false // known browser, no verified digest yet → fail closed
        val signatures = signingCerts(context, pkg) ?: return false
        val md = MessageDigest.getInstance("SHA-256")
        return signatures.any { Base64.encodeToString(md.digest(it.toByteArray()), Base64.NO_WRAP) in pins }
    }

    private fun signingCerts(context: Context, pkg: String): Array<android.content.pm.Signature>? {
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= 28) {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                val si = info.signingInfo ?: return null
                if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures
            }
        } catch (e: PackageManager.NameNotFoundException) {
            null // not installed, or not visible (missing <queries> entry) on API 30+
        } catch (t: Throwable) {
            null
        }
    }
}
