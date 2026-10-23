package io.silencelen.andvari.core.client.autofill

import io.silencelen.andvari.core.crypto.Fingerprint

/**
 * Security review 2026-10, A14 (F7) — owner decision: gate package-only app-URI fills by installer.
 *
 * A saved `androidapp://<pkg>` login matches on the requesting package name alone ([UriMatch]), and a
 * package name is only unique per device: on a phone where the real app is not installed, anything
 * sideloaded under that id received the credential with one tap. A web login is bound to a domain the
 * browser vouches for; an app login had no equivalent. This is the decision the Android fill path asks
 * before it releases an app login:
 *
 *  - [Verdict.SILENT] — a system app (FLAG_SYSTEM / FLAG_UPDATED_SYSTEM_APP), an app Play installed
 *    ([PLAY_INSTALLER]; Play enforces package ownership), or an app whose (package, signer) this device
 *    already confirmed;
 *  - [Verdict.CONFIRM] — anything else: another installer, no installer recorded, or ANY lookup that
 *    failed (package visibility, a throw, an unreadable signer). Never silent on an error;
 *  - [Verdict.CONFIRM_SIGNER_CHANGED] — this package was confirmed with a DIFFERENT signer: confirm
 *    again, with a warning.
 *
 * The [Identity] is gathered from PackageManager in andvari's own process (the service, or the
 * confirm activity re-reading it), never from the host-delivered AssistStructure or fill-in intent.
 */
object AppFillGate {
    /** The Play Store's package: the installer whose installs Play's package-ownership rule backs. */
    const val PLAY_INSTALLER = "com.android.vending"

    /**
     * What PackageManager says about the requesting app. A null field was not recorded or could not be
     * read; [lookupFailed] is true when any lookup threw (including a visibility denial).
     */
    data class Identity(
        val pkg: String,
        /** The app's label, for the confirm (null: unreadable — the package is shown instead). */
        val label: String?,
        /** FLAG_SYSTEM or FLAG_UPDATED_SYSTEM_APP; null when ApplicationInfo could not be read. */
        val system: Boolean?,
        /** The installing package (API 30+: InstallSourceInfo.installingPackageName); null if none. */
        val installer: String?,
        /** Lowercase hex SHA-256 of the current signing certificate(s); null when unreadable. */
        val signerDigest: String?,
        val lookupFailed: Boolean = false,
    )

    enum class Verdict { SILENT, CONFIRM, CONFIRM_SIGNER_CHANGED }

    /** The rule. [rememberedDigest] is the signer this device confirmed for [Identity.pkg], if any. */
    fun decide(id: Identity, rememberedDigest: String?): Verdict {
        val signer = id.signerDigest
        if (id.lookupFailed || signer == null || id.system == null) return Verdict.CONFIRM
        if (id.system || id.installer == PLAY_INSTALLER) return Verdict.SILENT
        return when (rememberedDigest) {
            null -> Verdict.CONFIRM
            signer -> Verdict.SILENT
            else -> Verdict.CONFIRM_SIGNER_CHANGED
        }
    }

    /** "installed by <installer>" / "installer unknown" — the confirm's installer line. */
    fun installerLine(installerLabel: String?): String =
        if (installerLabel.isNullOrBlank()) "installer unknown" else "installed by $installerLabel"

    /** The signer in the house short form (the first 32 hex, grouped), or "signer unknown". */
    fun signerLine(signerDigest: String?): String =
        if (signerDigest == null) "signer unknown" else Fingerprint.groupedShort(signerDigest)
}
