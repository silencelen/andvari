package io.silencelen.andvari.core.client.autofill

import io.silencelen.andvari.core.client.TerminalText
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
 *    already confirmed. "Play installed" means the recorded installer is named [PLAY_INSTALLER] AND is
 *    itself a system app (A14 review N1): on a device with no real Play (a de-Googled ROM, Fire, Huawei)
 *    any sideloaded app can take that package name, and the apps IT installs must not fill silently.
 *    No Play signing-certificate pin: Google publishes no authoritative digest for it, and a guessed one
 *    would only make real Play installs confirm;
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
        /** Whether [installer] is itself a system app (FLAG_SYSTEM / FLAG_UPDATED_SYSTEM_APP); null when it
         *  could not be resolved (not installed, or not visible to andvari). A14 review N1. */
        val installerSystem: Boolean? = null,
    )

    enum class Verdict { SILENT, CONFIRM, CONFIRM_SIGNER_CHANGED }

    /** The rule. [rememberedDigest] is the signer this device confirmed for [Identity.pkg], if any. */
    fun decide(id: Identity, rememberedDigest: String?): Verdict {
        val signer = id.signerDigest
        if (id.lookupFailed || signer == null || id.system == null) return Verdict.CONFIRM
        if (id.system || isPlayInstall(id)) return Verdict.SILENT
        return when (rememberedDigest) {
            null -> Verdict.CONFIRM
            signer -> Verdict.SILENT
            else -> Verdict.CONFIRM_SIGNER_CHANGED
        }
    }

    /** A14 review N1: Play only when the recorded installer is the Play package AND a system app. An
     *  installer that could not be resolved is not Play. */
    fun isPlayInstall(id: Identity): Boolean = id.installer == PLAY_INSTALLER && id.installerSystem == true

    /**
     * The confirm's installer line (A14 review N2). A label is the installer's own choice (any store can
     * call itself "Google Play Store"), so the line names the installer's PACKAGE and whether it is a
     * system app. It carries no label (A14 review 3, A1): the package and kind LEAD, and the card never
     * ellipsizes this line, so an 80-character label can no longer push "NOT a system app" off-screen.
     * The label, when there is one, is [installerLabelLine], a line of its own.
     */
    fun installerLine(installer: String?, installerSystem: Boolean?): String {
        val pkg = installer?.trim()?.takeIf { it.isNotEmpty() } ?: return "installer unknown"
        val kind = when (installerSystem) {
            true -> "a system app"
            false -> "NOT a system app"
            null -> "could not check whether it is a system app"
        }
        return "installed by ${TerminalText.escape(pkg)} ($kind)"
    }

    /**
     * The installer's label as its own line under [installerLine] (A14 review 3, A1): one escaped, bounded
     * line ([oneLine]), or null when there is no installer, no label, or the label is just the package.
     */
    fun installerLabelLine(installer: String?, installerLabel: String?): String? {
        val pkg = installer?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val label = oneLine(installerLabel)?.takeIf { it != TerminalText.escape(pkg) } ?: return null
        return "which calls itself $label"
    }

    /** The most characters of app- or member-authored text the confirm shows on one line. */
    const val ONE_LINE_MAX = 80

    /**
     * App- or member-authored text (an app label, an item name, a username) as ONE bounded line for the
     * confirm (A14 review N2): trimmed, every control, line separator and bidi control shown escaped
     * ([TerminalText.escape]), at most [ONE_LINE_MAX] characters then an ellipsis. Null for nothing.
     */
    fun oneLine(text: String?): String? {
        val t = text?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val e = TerminalText.escape(t)
        return if (e.length <= ONE_LINE_MAX) e else e.take(ONE_LINE_MAX) + "\u2026"
    }

    /**
     * A14 review N7: the identity read again at the user's tap must be the one the confirm showed —
     * same package, signer, installer, installer kind, system flag and lookup outcome. The label may
     * differ (a locale change) and is not compared. An identity that could not be read stays
     * confirmable (it is never remembered: a binding needs a signer).
     */
    fun unchangedSince(shown: Identity, live: Identity): Boolean =
        live.pkg == shown.pkg && live.signerDigest == shown.signerDigest && live.installer == shown.installer &&
            live.installerSystem == shown.installerSystem && live.system == shown.system && live.lookupFailed == shown.lookupFailed

    /** The signer in the house short form (the first 32 hex, grouped), or "signer unknown". */
    fun signerLine(signerDigest: String?): String =
        if (signerDigest == null) "signer unknown" else Fingerprint.groupedShort(signerDigest)
}
