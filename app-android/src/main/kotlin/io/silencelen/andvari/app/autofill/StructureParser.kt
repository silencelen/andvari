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
 * or a frame that declared none). [signal] is the diagnostic-only "winning signal" label
 * (e.g. "hint:password", "html:type=password", "inputType:0xE1") for the Autofill-status
 * screen — it names WHICH signal classified the field, never a field value.
 */
data class ParsedField(val id: AutofillId, val kind: FieldKind, val webDomain: String?, val signal: String = "")

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
            val sig = signalOf(node)
            val kind = FieldClassifier.classify(sig)
            if (kind == FieldKind.USERNAME || kind == FieldKind.PASSWORD) {
                out.add(ParsedField(id, kind, domain, winningSignal(sig, kind)))
            }
        }
        for (i in 0 until node.childCount) walk(node.getChildAt(i), domain, depth + 1, out)
    }

    /**
     * Diagnostic label for WHICH signal group won the classification, derived by ablation
     * against the real [FieldClassifier] (never a re-implementation of its rules): replay
     * the classifier with only one signal group at a time, in the classifier's own
     * priority order, and name the first group that alone reproduces [kind]. Values only
     * name signal METADATA (hints, html type/name attr, InputType bits) — never field text.
     */
    private fun winningSignal(s: FieldSignal, kind: FieldKind): String {
        if (s.hints.isNotEmpty() && FieldClassifier.classify(FieldSignal(hints = s.hints)) == kind) {
            return "hint:" + s.hints.joinToString(",") { it.take(32) }
        }
        if (FieldClassifier.classify(FieldSignal(htmlTag = s.htmlTag, htmlType = s.htmlType, htmlNameOrId = s.htmlNameOrId)) == kind) {
            return buildString {
                append("html:")
                s.htmlType?.let { append("type=").append(it.take(32)) }
                s.htmlNameOrId?.let { if (length > 5) append(","); append("name=").append(it.take(32)) }
            }
        }
        if (FieldClassifier.classify(FieldSignal(inputTypeClass = s.inputTypeClass, inputTypeVariation = s.inputTypeVariation)) == kind) {
            return "inputType:0x" + (s.inputTypeClass or s.inputTypeVariation).toString(16).uppercase()
        }
        return "combined" // only the full signal set reproduces the verdict
    }

    /** Field-classification signals (metadata only — never node text/values). `internal` so the
     *  save-flow's [SaveExtractor] classifies fields with the exact same signals as the fill path. */
    internal fun signalOf(node: AssistStructure.ViewNode): FieldSignal {
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
