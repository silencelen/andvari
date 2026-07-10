package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.os.Build
import android.view.View
import android.view.autofill.AutofillId
import io.silencelen.andvari.core.client.autofill.CardForm
import io.silencelen.andvari.core.client.autofill.FieldClassifier
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FieldSignal
import io.silencelen.andvari.core.client.autofill.FormKind
import io.silencelen.andvari.core.client.autofill.isCardKind

/**
 * One classified fillable field. [webDomain] is the nearest ancestor frame's
 * `getWebDomain()` — carried PER FIELD so a cross-origin iframe cannot borrow another
 * frame's domain (binding requirement). Null when no frame domain applies (native app,
 * or a frame that declared none). [signal] is the diagnostic-only "winning signal" label
 * (e.g. "hint:password", "html:type=password", "inputType:0xE1") for the Autofill-status
 * screen — it names WHICH signal classified the field, never a field value.
 * [autofillType] is the node's `View.AUTOFILL_TYPE_*` and [options] a LIST node's choice
 * labels — both METADATA describing the input control (CardFill's type-pinning consumes
 * them: forText only on TEXT nodes, forList only on LIST nodes), never anything typed.
 */
data class ParsedField(
    val id: AutofillId,
    val kind: FieldKind,
    val webDomain: String?,
    val signal: String = "",
    val autofillType: Int = 0, // View.AUTOFILL_TYPE_NONE; TEXT(1)/LIST(3) are the fillable ones
    val options: List<String> = emptyList(),
    /** The control's declared capacity (HTML maxlength / maxTextLength; null = undeclared) —
     *  CardFill's fit-guard consumes it so a LengthFilter can never truncate a fill. */
    val maxLength: Int? = null,
)

/**
 * The classified form. [fields] holds only USERNAME/PASSWORD fields (NONE is dropped) —
 * every existing login consumer is unchanged. [ccFields] holds the CC_* fields of a
 * card/mixed checkout ([formKind] is the form-level verdict), kept SEPARATE so nothing
 * login-shaped ever iterates a card field by accident. [appPackage] is the requesting
 * app; [allIds] is what the locked-path `setAuthentication` covers — login AND card
 * fields, so unlock-and-refill works from a card-only checkout too.
 */
data class ParsedForm(
    val fields: List<ParsedField>,
    val appPackage: String,
    val ccFields: List<ParsedField> = emptyList(),
    val formKind: FormKind = FormKind.LOGIN,
) {
    val allIds: List<AutofillId> get() = (fields + ccFields).map { it.id }

    /** Anything for the fill path to act on? Login fields, or a PAN-ANCHORED card form —
     *  [formKind] != LOGIN ⟺ some frame cluster holds a CC_NUMBER (CardForm.refine), so a
     *  stray cc-ish field (a lone "expiration" input on a passport form) never wakes the
     *  service where it stayed silent before 0.7.0. */
    val fillable: Boolean get() = fields.isNotEmpty() || formKind != FormKind.LOGIN
}

/**
 * Walks the latest AssistStructure and classifies the WHOLE FORM ONCE via the pure-Kotlin
 * [CardForm.refine] (index-aligned kinds + the frame-cluster CSC demotion + [FormKind]).
 * For card-free forms refine() is bit-identical to the old per-field
 * [FieldClassifier.classify] by construction — the demotion can only run where a
 * CC_NUMBER exists. Reads only field SIGNALS (autofillHints, inputType, htmlInfo,
 * resource id, autofill type/options) — NEVER node text/values (the one value-reading
 * path is [SaveExtractor]). Propagates each field's nearest-frame `getWebDomain()` down
 * the tree so matching and frame clustering are per-frame.
 */
object StructureParser {
    private const val MAX_DEPTH = 25
    private const val CLASS_MASK = 0x0000000f // android.text.InputType.TYPE_MASK_CLASS
    private const val VARIATION_MASK = 0x00000ff0 // android.text.InputType.TYPE_MASK_VARIATION

    /** A walked node's classification inputs — signals + control metadata, no values. */
    private class Candidate(
        val id: AutofillId,
        val signal: FieldSignal,
        val domain: String?,
        val autofillType: Int,
        val options: List<String>,
    )

    fun parse(structure: AssistStructure): ParsedForm {
        val appPackage = structure.activityComponent?.packageName ?: ""
        val candidates = ArrayList<Candidate>()
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode, null, 0, candidates)
        }
        val refined = CardForm.refine(candidates.map { it.signal })
        val fields = ArrayList<ParsedField>()
        val ccFields = ArrayList<ParsedField>()
        for ((i, c) in candidates.withIndex()) {
            val kind = refined.kinds[i]
            val target = when {
                kind == FieldKind.USERNAME || kind == FieldKind.PASSWORD -> fields
                kind.isCardKind -> ccFields
                else -> continue // NONE dropped, as before
            }
            target.add(ParsedField(c.id, kind, c.domain, winningSignal(c.signal, kind), c.autofillType, c.options, c.signal.maxLength))
        }
        return ParsedForm(fields, appPackage, ccFields, refined.formKind)
    }

    private fun walk(node: AssistStructure.ViewNode, inheritedDomain: String?, depth: Int, out: MutableList<Candidate>) {
        if (depth > MAX_DEPTH) return
        val important = node.importantForAutofill
        // A subtree marked NO_EXCLUDE_DESCENDANTS opts itself and its children out entirely.
        if (important == View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS) return

        // This node's frame domain overrides the inherited one for itself + its subtree.
        val domain = node.webDomain?.takeIf { it.isNotEmpty() } ?: inheritedDomain

        val id = node.autofillId
        if (id != null && important != View.IMPORTANT_FOR_AUTOFILL_NO) {
            out.add(
                Candidate(
                    id = id,
                    signal = signalOf(node, domain),
                    domain = domain,
                    autofillType = node.autofillType,
                    // LIST nodes' choice labels: metadata describing the picker UI (what COULD
                    // be selected), never what the user typed — the walk stays value-blind.
                    options = node.autofillOptions?.map(CharSequence::toString) ?: emptyList(),
                ),
            )
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
        // A verdict the field's own classify() can't reproduce came from the CardForm.refine
        // post-pass (the frame-cluster CSC demotion) — no single-signal ablation can name it.
        if (FieldClassifier.classify(s) != kind) return "refine:csc-demotion"
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

    /**
     * Field-classification signals (metadata only — never node text/values). `internal` so the
     * save-flow's [SaveExtractor] classifies fields with the exact same signals as the fill path.
     * [frameDomain] is the node's resolved nearest-frame domain (the caller threads it in so
     * both walks resolve inheritance identically); maxLength/inputMode feed only
     * [CardForm.refine]'s CSC demotion — [FieldClassifier.classify] never reads them.
     */
    internal fun signalOf(node: AssistStructure.ViewNode, frameDomain: String?): FieldSignal {
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
        val inputClass = inputType and CLASS_MASK
        return FieldSignal(
            hints = hints,
            inputTypeClass = inputClass,
            inputTypeVariation = inputType and VARIATION_MASK,
            htmlTag = html?.tag,
            htmlType = attr("type"),
            htmlNameOrId = nameOrId,
            // Declared max length: HTML maxlength attr, else the platform value (-1/0 =
            // undeclared → null). inputMode: the HTML attr, with numeric-class InputType as
            // the native-app equivalent (a numeric 3-4 char password field IS inputmode-numeric).
            maxLength = attr("maxlength")?.trim()?.toIntOrNull()?.takeIf { it > 0 }
                ?: node.maxTextLength.takeIf { it > 0 },
            inputMode = attr("inputmode") ?: (if (inputClass == FieldSignal.CLASS_NUMBER) "numeric" else null),
            frameDomain = frameDomain,
        )
    }
}
