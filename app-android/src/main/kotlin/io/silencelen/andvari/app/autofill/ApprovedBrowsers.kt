package io.silencelen.andvari.app.autofill

import android.content.Context
import io.silencelen.andvari.core.client.autofill.BrowserCertPins

/**
 * Device-local record of browsers the owner has explicitly trusted for autofill web-domain
 * matching, via **Autofill status → "Trust this browser"**. Stores `package → the signing-cert
 * digest that was approved`.
 *
 * This is the self-service path for browsers andvari can't ship a verifiable static pin for —
 * Samsung Internet, Brave, Firefox — whose real digest is install-source-specific (Play App
 * Signing / pre-install / direct APK all differ), so a blind-shipped pin would silently
 * never-match. The owner approves the *actual* on-device digest instead.
 *
 * NOT synced (cert trust is per-device) and NOT secret (a public cert hash).
 * [TrustedBrowsers.isTrusted] re-reads the LIVE cert and compares it to the stored value on every
 * fill request, so a browser that is later re-signed — or a hostile app squatting the package id —
 * drops trust until the owner re-approves. Clearing it is one tap (revoke) or an app-data wipe.
 */
object ApprovedBrowsers {
    private const val PREFS = "andvari_trusted_browsers"

    fun approvedDigest(context: Context, pkg: String): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(pkg, null)

    /** Only an id with no pinned certificate can be approved; a pinned one is refused here too. */
    fun approve(context: Context, pkg: String, digest: String): Boolean {
        if (offer(pkg, digest, null) == Offer.PINNED_MISMATCH) return false
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(pkg, digest).apply()
        return true
    }

    /** What the trust card offers for [pkg] carrying [observedDigest] now, given the signer it was approved with. */
    enum class Offer {
        /** Never approved on this device: the card asks. */
        FIRST_TIME,

        /** Approved before with ANOTHER signer: not trusted, and the card asks again with the changed-signer warning. */
        SIGNER_CHANGED,

        /** An id with a pinned certificate that does not carry it: a warning, never an approval, no fill. */
        PINNED_MISMATCH,
    }

    /** The approval rule above, as a plain function. */
    fun offer(pkg: String, observedDigest: String, approvedDigest: String?): Offer = when {
        !BrowserCertPins.TABLE[pkg].isNullOrEmpty() -> Offer.PINNED_MISMATCH
        approvedDigest != null && approvedDigest != observedDigest -> Offer.SIGNER_CHANGED
        else -> Offer.FIRST_TIME
    }

    fun revoke(context: Context, pkg: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(pkg).apply()
    }

    /** Note 11: forgotten at the person's own ends (sign-out, a forgotten server, a deletion, another account). */
    fun clearAll(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }

    /** All approved entries (package → digest), for the management list. */
    fun all(context: Context): Map<String, String> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).all
            .mapNotNull { (k, v) -> (v as? String)?.let { k to it } }
            .toMap()
}
