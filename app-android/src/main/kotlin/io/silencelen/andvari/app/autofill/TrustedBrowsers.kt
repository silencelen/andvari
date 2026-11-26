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
        return observedDigestOf(sig.map { Base64.encodeToString(md.digest(it.toByteArray()), Base64.NO_WRAP) })
    }

    /**
     * True iff [pkg] is a known browser whose installed signing cert is trusted — either by a
     * shipped verified pin OR by the owner's on-device approval ([ApprovedBrowsers]). The decision
     * rule lives in :core ([BrowserCertPins.isTrusted]) so it's gate-tested; this only does the
     * on-device cert lookup + reads the local approval. Re-checks the LIVE cert every call.
     */
    fun isTrusted(context: Context, pkg: String): Boolean {
        if (pkg !in PINS) return false // not a known browser → fail closed (cheap early exit)
        val signatures = signingCerts(context, pkg) ?: return false
        val md = MessageDigest.getInstance("SHA-256")
        val digests = signatures.map { Base64.encodeToString(md.digest(it.toByteArray()), Base64.NO_WRAP) }
        return decide(pkg, digests, ApprovedBrowsers.approvedDigest(context, pkg))
    }

    /**
     * The trust rule over plain values: an id with a pinned certificate is trusted ONLY by
     * its pin, never by an approval on this device (a look-alike under `com.android.chrome` on a phone without Chrome
     * is a mismatch, not a browser to approve); an id with no pin is trusted only by an approval of exactly the signer
     * it carries now.
     */
    internal fun decide(pkg: String, observedDigests: List<String>, approvedDigest: String?): Boolean {
        val pins = PINS[pkg] ?: return false
        return BrowserCertPins.isTrusted(pkg, observedDigests, if (pins.isEmpty()) approvedDigest else null)
    }

    /**
     * A browser is trusted by its CURRENT signer. The signing
     * history lists every key the app was ever signed with, oldest first; only its last entry signs the app now (or,
     * for an app signed by several keys at once, all of its content signers). An approval given to one signer does not
     * cover another that only appears in the history: after a browser's key rotation the person is asked again (the
     * trust card's "signer changed"), and an APK signed with the retired key alone is not the browser that was approved.
     * The pin table is read against the current signer the same way.
     */
    internal fun <T> currentSigners(multipleSigners: Boolean, contents: List<T>, history: List<T>): List<T> = when {
        multipleSigners -> contents
        else -> listOfNotNull(history.lastOrNull())
    }

    /** The digest the trust card shows and an approval stores: the current signer's ([currentSigners]). */
    internal fun observedDigestOf(current: List<String>): String? = current.firstOrNull()

    private fun signingCerts(context: Context, pkg: String): Array<android.content.pm.Signature>? {
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= 28) {
                val info = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES)
                val si = info.signingInfo ?: return null
                currentSigners(si.hasMultipleSigners(), si.apkContentsSigners?.toList().orEmpty(), si.signingCertificateHistory?.toList().orEmpty()).toTypedArray()
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
