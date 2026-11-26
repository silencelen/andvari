package io.silencelen.andvari.app.autofill

import android.content.Intent
import android.os.Build
import android.os.Bundle
import io.silencelen.andvari.core.client.autofill.AppFillGate

/**
 * Security review 2026-10, A14 (F7): the service-side app-identity verdict a confirm row carries, in
 * the PendingIntent's BASE intent — the [FillBinding] rule (root cause G): `Intent.fillIn` lays the
 * base's extras over the fill-in's, so the host app cannot override the baked bundle, and nothing the
 * host delivers is read. [AppFillConfirmActivity] shows exactly this identity and re-reads the live
 * signer before it releases anything.
 */
object AppFillBinding {
    private const val EXTRA = "io.silencelen.andvari.autofill.APP_GATE"
    private const val K_PKG = "pkg"
    private const val K_LABEL = "label"
    private const val K_SYSTEM = "system"
    private const val K_INSTALLER = "installer"
    private const val K_INSTALLER_LABEL = "installerLabel"
    private const val K_INSTALLER_SYSTEM = "installerSystem"
    private const val K_SIGNER = "signer"
    private const val K_FAILED = "failed"
    private const val K_VERDICT = "verdict"
    private const val K_ITEM = "item"
    private const val K_PAGE = "page"

    /** The service's verdict for one requesting app. */
    data class AppGate(val identity: AppFillGate.Identity, val verdict: AppFillGate.Verdict, val installerLabel: String?)

    /**
     * What a confirm row names: the gate plus the one item it would release, and [pageDomain] when the row fills a web
     * page inside the app that is not one of the login's own sites ([FillRow.LoginConfirm.pageDomain]): the confirm
     * then names that page, releases only its fields, and remembers nothing.
     */
    data class Bake(val identity: AppFillGate.Identity, val verdict: AppFillGate.Verdict, val installerLabel: String?, val itemId: String, val pageDomain: String? = null)

    fun bake(intent: Intent, gate: AppGate, itemId: String, pageDomain: String? = null): Intent = intent.putExtra(EXTRA, gateBundle(gate, itemId, pageDomain))

    /** The gate alone, for andvari's own chooser ([FillChooserActivity]): no item, the person picks it there. */
    fun bakeGate(intent: Intent, gate: AppGate): Intent = intent.putExtra(GATE_EXTRA, gateBundle(gate, null, null))

    /** The gate [bakeGate] baked, or null when absent or malformed (the chooser then releases nothing). */
    fun resolveGate(intent: Intent): AppGate? = runCatching {
        @Suppress("DEPRECATION")
        val b = (if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(GATE_EXTRA, Bundle::class.java) else intent.getParcelableExtra(GATE_EXTRA)) ?: return null
        val (identity, verdict) = identityOf(b) ?: return null
        AppGate(identity, verdict, b.getString(K_INSTALLER_LABEL))
    }.getOrNull()

    /** The confirm's bake for one item the person picked in the chooser: the same gate, now naming [itemId]. */
    fun bakeFor(gate: AppGate, itemId: String, pageDomain: String?): Bake =
        Bake(gate.identity, gate.verdict, gate.installerLabel, itemId, pageDomain)

    private const val GATE_EXTRA = "io.silencelen.andvari.autofill.APP_GATE_ONLY"

    private fun identityOf(b: Bundle): Pair<AppFillGate.Identity, AppFillGate.Verdict>? {
        val pkg = b.getString(K_PKG) ?: return null
        val verdict = b.getString(K_VERDICT)?.let { n -> AppFillGate.Verdict.entries.firstOrNull { it.name == n } } ?: return null
        return AppFillGate.Identity(
            pkg = pkg,
            label = b.getString(K_LABEL),
            system = if (b.containsKey(K_SYSTEM)) b.getBoolean(K_SYSTEM) else null,
            installer = b.getString(K_INSTALLER),
            signerDigest = b.getString(K_SIGNER),
            lookupFailed = b.getBoolean(K_FAILED),
            installerSystem = if (b.containsKey(K_INSTALLER_SYSTEM)) b.getBoolean(K_INSTALLER_SYSTEM) else null,
        ) to verdict
    }

    private fun gateBundle(gate: AppGate, itemId: String?, pageDomain: String?): Bundle =
        Bundle().apply {
            val id = gate.identity
            putString(K_PKG, id.pkg)
            putString(K_LABEL, id.label)
            id.system?.let { putBoolean(K_SYSTEM, it) }
            putString(K_INSTALLER, id.installer)
            putString(K_INSTALLER_LABEL, gate.installerLabel)
            id.installerSystem?.let { putBoolean(K_INSTALLER_SYSTEM, it) }
            putString(K_SIGNER, id.signerDigest)
            putBoolean(K_FAILED, id.lookupFailed)
            putString(K_VERDICT, gate.verdict.name)
            itemId?.let { putString(K_ITEM, it) }
            pageDomain?.let { putString(K_PAGE, it) }
        }

    /** The baked verdict, or null when absent or malformed (the activity then releases nothing). */
    fun resolve(intent: Intent): Bake? = runCatching {
        val b = intent.bundle() ?: return null
        val pkg = b.getString(K_PKG) ?: return null
        val item = b.getString(K_ITEM) ?: return null
        val verdict = b.getString(K_VERDICT)?.let { n -> AppFillGate.Verdict.entries.firstOrNull { it.name == n } } ?: return null
        val identity = AppFillGate.Identity(
            pkg = pkg,
            label = b.getString(K_LABEL),
            system = if (b.containsKey(K_SYSTEM)) b.getBoolean(K_SYSTEM) else null,
            installer = b.getString(K_INSTALLER),
            signerDigest = b.getString(K_SIGNER),
            lookupFailed = b.getBoolean(K_FAILED),
            installerSystem = if (b.containsKey(K_INSTALLER_SYSTEM)) b.getBoolean(K_INSTALLER_SYSTEM) else null,
        )
        // A key that is there but empty is malformed, never "no page": the activity then releases nothing.
        val page = if (b.containsKey(K_PAGE)) b.getString(K_PAGE)?.takeIf { it.isNotBlank() } ?: return null else null
        Bake(identity, verdict, b.getString(K_INSTALLER_LABEL), item, page)
    }.getOrNull()

    @Suppress("DEPRECATION")
    private fun Intent.bundle(): Bundle? =
        if (Build.VERSION.SDK_INT >= 33) getParcelableExtra(EXTRA, Bundle::class.java) else getParcelableExtra(EXTRA)
}
