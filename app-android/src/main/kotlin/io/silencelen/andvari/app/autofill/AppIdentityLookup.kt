package io.silencelen.andvari.app.autofill

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.text.TextUtils
import io.silencelen.andvari.core.client.autofill.AppFillGate
import java.security.MessageDigest

/**
 * Security review 2026-10, A14 (F7): the requesting app's identity, from PackageManager in andvari's
 * own process — never from the AssistStructure or a fill-in intent, which the host app delivers
 * (root cause G). Every lookup is guarded: a throw (not installed, or not visible to andvari under
 * API 30+ package visibility) leaves its field null and sets [AppFillGate.Identity.lookupFailed], and
 * [AppFillGate.decide] then takes the confirm path. GET_SIGNING_CERTIFICATES is the same source
 * [TrustedBrowsers] pins browsers by (minSdk 29, so the API 28 signing info is always there).
 */
object AppIdentityLookup {
    /** Lowercase hex SHA-256 of each CURRENT signer's certificate, sorted and joined with ':' (one
     *  signer: just its hex), so a multi-signer app has one stable identity. */
    fun signerDigest(certs: List<ByteArray>): String =
        certs.map { cert -> MessageDigest.getInstance("SHA-256").digest(cert).joinToString("") { "%02x".format(it) } }
            .sorted()
            .joinToString(":")

    fun lookup(context: Context, pkg: String): AppFillGate.Identity {
        val pm = context.packageManager
        var failed = false
        val app = runCatching { pm.getApplicationInfo(pkg, 0) }.onFailure { failed = true }.getOrNull()
        val system = app?.let { (it.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0 }
        val label = app?.let { runCatching { safeLabel(pm.getApplicationLabel(it).toString()) }.getOrNull() }
        val installer = runCatching { installerOf(pm, pkg) }.onFailure { failed = true }.getOrNull()
        val signers = runCatching { currentSigners(pm, pkg) }.onFailure { failed = true }.getOrNull()
        val digest = signers?.takeIf { it.isNotEmpty() }?.let(::signerDigest)
        return AppFillGate.Identity(
            pkg = pkg, label = label, system = system, installer = installer, signerDigest = digest, lookupFailed = failed,
            installerSystem = installerSystemOf(pm, installer),
        )
    }

    /** A14 review N1: whether the INSTALLER is itself a system app, so a sideloaded app that took the Play
     *  Store's package name is not Play. Null when it cannot be resolved (not installed, or not visible:
     *  the manifest queries the Play package by name and every launcher app by intent). */
    private fun installerSystemOf(pm: PackageManager, installer: String?): Boolean? {
        if (installer.isNullOrBlank()) return null
        val info = runCatching { pm.getApplicationInfo(installer, 0) }.getOrNull() ?: return null
        return (info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
    }

    /** A14 review N2: an app label is the app's own choice. The platform's presentation sanitizer drops
     *  HTML and control characters and keeps one line; the confirm then escapes what is left onto one
     *  bounded line (AppFillGate.oneLine) and renders it maxLines = 1. */
    private fun safeLabel(raw: String): String? =
        TextUtils.makeSafeForPresentation(raw, 0, 0f, TextUtils.SAFE_STRING_FLAG_TRIM or TextUtils.SAFE_STRING_FLAG_SINGLE_LINE)
            .toString().takeIf { it.isNotBlank() }

    /** API 30+: InstallSourceInfo.installingPackageName. API 29 (minSdk): getInstallerPackageName, the
     *  same recorded value before InstallSourceInfo existed. */
    private fun installerOf(pm: PackageManager, pkg: String): String? =
        if (Build.VERSION.SDK_INT >= 30) {
            pm.getInstallSourceInfo(pkg).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(pkg)
        }

    /** The CURRENT signer(s): all content signers for a multi-signer APK, else the last entry of the
     *  rotation history (index 0 is the original key, the last is the one signing now). */
    private fun currentSigners(pm: PackageManager, pkg: String): List<ByteArray>? {
        val si = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo ?: return null
        val sigs = if (si.hasMultipleSigners()) si.apkContentsSigners?.toList().orEmpty() else listOfNotNull(si.signingCertificateHistory?.lastOrNull())
        return sigs.map { it.toByteArray() }
    }

    /** The installer's label for the confirm ("Google Play Store"), made safe like an app label, else its
     *  package name, else null. The confirm shows the package and system flag beside it (A14 review N2). */
    fun installerLabel(context: Context, installer: String?): String? {
        if (installer.isNullOrBlank()) return null
        val pm = context.packageManager
        return runCatching { safeLabel(pm.getApplicationLabel(pm.getApplicationInfo(installer, 0)).toString()) }.getOrNull() ?: installer
    }
}
