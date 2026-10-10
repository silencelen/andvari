package io.silencelen.andvari.app.autofill

/** Anything that names the app it was parsed for — [ParsedForm] in production. */
interface PackageBound {
    val appPackage: String
}

/**
 * Which form may an autofill AUTHENTICATION activity fill? Security review 2026-10, root cause G.
 *
 * The activities ([AutofillUnlockActivity], [TrustBrowserActivity]) are launched through a MUTABLE
 * PendingIntent, and the platform routes the launch through the HOST app's process: the
 * `EXTRA_ASSIST_STRUCTURE` that arrives with it rides the fill-in intent the host app controls.
 * A malicious app could therefore hand us a structure claiming `com.android.chrome` plus any web
 * domain and receive that site's logins. Identity must come from what the service itself parsed in
 * `onFillRequest` (where the system sanitises the requesting component) and baked into the
 * PendingIntent's BASE intent — `Intent.fillIn` never overrides an extra the base already carries.
 *
 * The rule, kept pure so the JVM suite can pin it (AutofillAuthBindingTest):
 *  - no baked binding, or a baked package that is blank or disagrees with its own baked form → refuse;
 *  - a host-delivered structure that names a DIFFERENT package than the bake → refuse (someone is
 *    lying about who is asking, and it is not the service);
 *  - otherwise fill from the BAKED form only. The injected structure is a cross-check, never a source.
 */
object AutofillAuthGate {
    fun <F : PackageBound> resolve(bakedForm: F?, bakedPackage: String?, injectedPackage: String?): F? {
        if (bakedForm == null || bakedPackage.isNullOrEmpty()) return null
        if (bakedForm.appPackage != bakedPackage) return null
        if (injectedPackage != null && injectedPackage != bakedPackage) return null
        return bakedForm
    }
}
