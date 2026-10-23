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
    private const val K_SIGNER = "signer"
    private const val K_FAILED = "failed"
    private const val K_VERDICT = "verdict"
    private const val K_ITEM = "item"

    /** The service's verdict for one requesting app. */
    data class AppGate(val identity: AppFillGate.Identity, val verdict: AppFillGate.Verdict, val installerLabel: String?)

    /** What a confirm row names: the gate plus the one item it would release. */
    data class Bake(val identity: AppFillGate.Identity, val verdict: AppFillGate.Verdict, val installerLabel: String?, val itemId: String)

    fun bake(intent: Intent, gate: AppGate, itemId: String): Intent = intent.putExtra(
        EXTRA,
        Bundle().apply {
            val id = gate.identity
            putString(K_PKG, id.pkg)
            putString(K_LABEL, id.label)
            id.system?.let { putBoolean(K_SYSTEM, it) }
            putString(K_INSTALLER, id.installer)
            putString(K_INSTALLER_LABEL, gate.installerLabel)
            putString(K_SIGNER, id.signerDigest)
            putBoolean(K_FAILED, id.lookupFailed)
            putString(K_VERDICT, gate.verdict.name)
            putString(K_ITEM, itemId)
        },
    )

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
        )
        Bake(identity, verdict, b.getString(K_INSTALLER_LABEL), item)
    }.getOrNull()

    @Suppress("DEPRECATION")
    private fun Intent.bundle(): Bundle? =
        if (Build.VERSION.SDK_INT >= 33) getParcelableExtra(EXTRA, Bundle::class.java) else getParcelableExtra(EXTRA)
}
