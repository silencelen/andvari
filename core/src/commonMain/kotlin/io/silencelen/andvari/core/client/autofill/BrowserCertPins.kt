package io.silencelen.andvari.core.client.autofill

/**
 * Canonical browser signing-certificate pin table for autofill web-domain trust
 * (spec 05 §autofill). Each digest is the **standard base64** (RFC 4648, `+/=`) of the
 * SHA-256 over a browser's DER release cert. Lives in `:core` — not app-android — so the
 * table's format invariant (every digest decodes to exactly 32 bytes) is asserted by
 * [BrowserCertPinsTest] in the same gate that runs the crypto vectors. app-android's
 * `TrustedBrowsers` does the on-device PackageManager cert lookup against this table and
 * **fails closed**: a package with no pin, an empty pin set, or a cert mismatch gets no
 * web-domain trust (web items match nothing for it). A wrong/missing pin only costs that
 * browser autofill until its real digest is captured — never safety.
 *
 * Capturing a digest on-device (for the empty-pinned browsers below, or to fix a stale one):
 *   the in-app **Autofill status** screen prints the observed cert digest of the last
 *   caller, or `adb shell pm dump <pkg> | grep -A2 signatures`. Pin exactly what the device
 *   reports, then keep [TABLE]'s keys in lockstep with the manifest `<queries>` block
 *   (package visibility — without it the cert lookup can't even run on API 30+).
 */
object BrowserCertPins {
    // com.android.chrome release cert f0fd6c5b…db83 — the ONLY digest verified against a
    // published value. Google-signed; covers all Chrome channels.
    private val GOOGLE = setOf("8P1sW0EPJcslw7UzRsiXL64w+O50Ed+RBICtay1g24M=")
    // Firefox and Samsung Internet ship no reliably-verifiable public release-cert digest
    // (Play App Signing rewrites them per-app, and two candidate Mozilla values differ only
    // in their last byte with no way to tell which is live). Per this file's own lesson —
    // never ship a pin you can't verify, or it silently never-matches — they are left EMPTY
    // (fail closed). The in-app Autofill-status screen prints the caller's observed digest on
    // NO_PIN_DIGEST, so the owner captures the real value on-device and we pin exactly that.
    private val EMPTY = emptySet<String>()

    /**
     * Pure trust decision, gate-tested here so the security rule can't drift. A browser's observed
     * signing-cert digest(s) are trusted for web-domain matching iff:
     *  - the package is a KNOWN browser ([TABLE] has it — an unknown package is never trusted), AND
     *  - either a **verified static pin** matches (the shipped, cross-checked digests above),
     *  - or the owner **approved exactly this digest on-device** (Autofill status → "Trust this
     *    browser"): the device-local self-service path for browsers we can't ship a verifiable pin
     *    for (Samsung Internet, Brave, Firefox — their digest is install-source-specific). The
     *    caller passes the LIVE observed digest each time, so a re-signed/replaced browser drops
     *    trust until re-approved. `approvedDigest` is null when the owner hasn't approved [pkg].
     */
    fun isTrusted(pkg: String, observedDigests: List<String>, approvedDigest: String?): Boolean {
        val pins = TABLE[pkg] ?: return false // not a known browser → fail closed
        if (pins.isNotEmpty() && observedDigests.any { it in pins }) return true // verified static pin
        return approvedDigest != null && approvedDigest in observedDigests // owner-approved on this device
    }

    /** package id → accepted signing-cert digest set (empty = known browser, fail closed). */
    val TABLE: Map<String, Set<String>> = buildMap {
        // Chrome + channels (Google-signed, verified)
        for (p in listOf("com.android.chrome", "com.chrome.beta", "com.chrome.dev", "com.chrome.canary", "com.google.android.apps.chrome")) put(p, GOOGLE)
        // Firefox + channels — capture on-device (see EMPTY note)
        for (p in listOf("org.mozilla.firefox", "org.mozilla.firefox_beta", "org.mozilla.fenix", "org.mozilla.focus", "org.mozilla.klar")) put(p, EMPTY)
        // Samsung Internet — capture on-device (likely the Fold's default browser)
        for (p in listOf("com.sec.android.app.sbrowser", "com.sec.android.app.sbrowser.beta")) put(p, EMPTY)
        // Others the household may add a verified digest for (fail closed until then). Their
        // package ids are recorded so a future pin only needs the digest, not a code change.
        for (p in listOf(
            "com.microsoft.emmx", "com.brave.browser", "com.opera.browser", "com.opera.gx",
            "com.vivaldi.browser", "com.duckduckgo.mobile.android", "com.kiwibrowser.browser",
            "org.torproject.torbrowser",
        )) putIfAbsent(p, emptySet())
    }
}
