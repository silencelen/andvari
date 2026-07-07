package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.view.View
import android.view.autofill.AutofillId
import io.silencelen.andvari.core.client.autofill.FieldClassifier
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FieldSignal

/**
 * One classified fillable field. [webDomain] is the nearest ancestor frame's
 * `getWebDomain()` — carried PER FIELD so a cross-origin iframe cannot borrow another
 * frame's domain (binding requirement). Null when no frame domain applies (native app,
 * or a frame that declared none).
 */
data class ParsedField(val id: AutofillId, val kind: FieldKind, val webDomain: String?)

/**
 * The classified form. [fields] holds only USERNAME/PASSWORD fields (NONE is dropped).
 * [appPackage] is the requesting app; [allIds] is what the locked-path
 * `setAuthentication` covers.
 */
data class ParsedForm(val fields: List<ParsedField>, val appPackage: String) {
    val allIds: List<AutofillId> get() = fields.map { it.id }
}

/**
 * Walks the latest AssistStructure and classifies fields via the pure-Kotlin
 * [FieldClassifier]. Reads only field SIGNALS (autofillHints, inputType, htmlInfo,
 * resource id) — NEVER node text/values. Propagates each field's nearest-frame
 * `getWebDomain()` down the tree so matching is per-frame.
 */
object StructureParser {
    private const val MAX_DEPTH = 25
    private const val CLASS_MASK = 0x0000000f // android.text.InputType.TYPE_MASK_CLASS
    private const val VARIATION_MASK = 0x00000ff0 // android.text.InputType.TYPE_MASK_VARIATION

    fun parse(structure: AssistStructure): ParsedForm {
        val appPackage = structure.activityComponent?.packageName ?: ""
        val fields = ArrayList<ParsedField>()
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode, null, 0, fields)
        }
        return ParsedForm(fields, appPackage)
    }

    private fun walk(node: AssistStructure.ViewNode, inheritedDomain: String?, depth: Int, out: MutableList<ParsedField>) {
        if (depth > MAX_DEPTH) return
        val important = node.importantForAutofill
        // A subtree marked NO_EXCLUDE_DESCENDANTS opts itself and its children out entirely.
        if (important == View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS) return

        // This node's frame domain overrides the inherited one for itself + its subtree.
        val domain = node.webDomain?.takeIf { it.isNotEmpty() } ?: inheritedDomain

        val id = node.autofillId
        if (id != null && important != View.IMPORTANT_FOR_AUTOFILL_NO) {
            val kind = FieldClassifier.classify(signalOf(node))
            if (kind == FieldKind.USERNAME || kind == FieldKind.PASSWORD) {
                out.add(ParsedField(id, kind, domain))
            }
        }
        for (i in 0 until node.childCount) walk(node.getChildAt(i), domain, depth + 1, out)
    }

    private fun signalOf(node: AssistStructure.ViewNode): FieldSignal {
        val hints = node.autofillHints?.toList() ?: emptyList()
        val inputType = node.inputType
        val html = node.htmlInfo
        val attrs = html?.attributes
        fun attr(name: String): String? = attrs?.firstOrNull { it.first == name }?.second
        // Prefer HTML name/id (web forms); fall back to the Android resource id entry
        // (native apps), which is only exposed from API 30.
        val nameOrId = attr("name")
            ?: attr("id")
            ?: (if (Build.VERSION.SDK_INT >= 30) runCatching { node.idEntry }.getOrNull() else null)
        return FieldSignal(
            hints = hints,
            inputTypeClass = inputType and CLASS_MASK,
            inputTypeVariation = inputType and VARIATION_MASK,
            htmlTag = html?.tag,
            htmlType = attr("type"),
            htmlNameOrId = nameOrId,
        )
    }
}
