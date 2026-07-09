package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.view.View
import io.silencelen.andvari.core.client.autofill.FieldClassifier
import io.silencelen.andvari.core.client.autofill.FieldKind

/**
 * Credentials a user typed into a submitted form, for "Save to andvari?". [webDomain] is the
 * password field's frame domain (null for a native app); [appPackage] is the requesting app.
 */
data class SavedCredentials(
    val username: String?,
    val password: String?,
    val webDomain: String?,
    val appPackage: String,
) {
    /** A login is only worth saving if it has a password. */
    val savable: Boolean get() = !password.isNullOrEmpty()

    /** The URI to store on the new login so it matches next time (spec: web host, else app package). */
    fun uri(): String = webDomain?.let { "https://$it" } ?: "androidapp://$appPackage"

    /** A human title for the saved item: the site host, else a readable app name. */
    fun title(): String = webDomain ?: appPackage.substringAfterLast('.').replaceFirstChar { it.uppercase() }
}

/**
 * Reads the typed username/password out of a submitted form's AssistStructure — the ONE place the
 * autofill service reads field VALUES (the fill path is value-blind by design). Classifies fields
 * with the same pure [FieldClassifier] the fill path uses (via [StructureParser.signalOf]), then
 * reads each matched field's current value. NEVER logs a value; the result is handed straight to the
 * confirm UI + client-side item encryption. Takes the FIRST username/password it finds (login forms
 * have one of each; a change-password form's "new password" is the first PASSWORD field).
 */
object SaveExtractor {
    private const val MAX_DEPTH = 25

    fun extract(structure: AssistStructure): SavedCredentials {
        val appPackage = structure.activityComponent?.packageName ?: ""
        var username: String? = null
        var password: String? = null
        var domain: String? = null

        fun visit(node: AssistStructure.ViewNode, inheritedDomain: String?, depth: Int) {
            if (depth > MAX_DEPTH) return
            if (node.importantForAutofill == View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS) return
            val nodeDomain = node.webDomain?.takeIf { it.isNotEmpty() } ?: inheritedDomain
            if (node.autofillId != null && node.importantForAutofill != View.IMPORTANT_FOR_AUTOFILL_NO) {
                val value = textValue(node)
                if (value != null) {
                    when (FieldClassifier.classify(StructureParser.signalOf(node))) {
                        FieldKind.PASSWORD -> if (password == null) { password = value; if (domain == null) domain = nodeDomain }
                        FieldKind.USERNAME -> if (username == null) { username = value; if (domain == null) domain = nodeDomain }
                        // Card kinds are captured by the dedicated card SaveExtractor path (0.7.0 phase 5);
                        // the login extractor ignores them.
                        else -> {}
                    }
                }
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i), nodeDomain, depth + 1)
        }
        for (i in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(i).rootViewNode, null, 0)
        return SavedCredentials(username, password, domain, appPackage)
    }

    /** The field's current text: the typed AutofillValue if present, else the node's own text. */
    private fun textValue(node: AssistStructure.ViewNode): String? {
        val v = node.autofillValue
        val text = if (v != null && v.isText) v.textValue?.toString() else node.text?.toString()
        return text?.takeIf { it.isNotEmpty() }
    }
}
