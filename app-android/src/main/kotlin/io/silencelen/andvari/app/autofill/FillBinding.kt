package io.silencelen.andvari.app.autofill

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import io.silencelen.andvari.core.client.autofill.FieldKind
import io.silencelen.andvari.core.client.autofill.FormKind

/**
 * The service's own fill verdict, carried in an authentication PendingIntent's BASE intent
 * (security review 2026-10, root cause G).
 *
 * At `onFillRequest` the service has a structure whose requesting component the SYSTEM sanitised.
 * The authentication activities it launches do not: their `EXTRA_ASSIST_STRUCTURE` rides the fill-in
 * intent, delivered through the host app's process, so the host can substitute one that claims to
 * be a trusted browser on any domain. So the service bakes the whole [ParsedForm] — requesting
 * package, the classified AutofillIds, each field's frame domain — into the base intent, and the
 * activities fill from that alone ([resolve]). `Intent.fillIn` copies the fill-in's extras first
 * and then lays the base's over them, so a host cannot override a baked key; one bundle under one
 * key means there is no absent sub-key for it to add either.
 *
 * Everything here is metadata the service already holds for the fill (no values, no vault data),
 * and the PendingIntent never leaves the system server / the requesting app's fill flow.
 */
object FillBinding {
    private const val EXTRA_BINDING = "io.silencelen.andvari.autofill.BINDING"
    private const val K_PKG = "pkg"
    private const val K_FIELDS = "fields"
    private const val K_CC = "cc"
    private const val K_FORM_KIND = "formKind"
    private const val K_FOCUSED = "focused"
    private const val F_ID = "id"
    private const val F_KIND = "kind"
    private const val F_DOMAIN = "domain"
    private const val F_SIGNAL = "signal"
    private const val F_TYPE = "type"
    private const val F_OPTIONS = "options"
    private const val F_MAXLEN = "maxLen"
    private const val F_NEWPW = "newPw"

    /** Put [form] into [intent] (the PendingIntent's base) and return it. */
    fun bake(intent: Intent, form: ParsedForm): Intent = intent.putExtra(EXTRA_BINDING, toBundle(form))

    /**
     * The form an authentication activity may fill, or null to refuse. Only the baked binding is a
     * source; the host-delivered structure is read for its package and nothing else, as a
     * cross-check ([AutofillAuthGate]).
     */
    fun resolve(intent: Intent): ParsedForm? {
        val baked = runCatching { intent.bundleExtra(EXTRA_BINDING)?.let(::fromBundle) }.getOrNull()
        val injectedPkg = runCatching { intent.assistStructure()?.activityComponent?.packageName }.getOrNull()
        return AutofillAuthGate.resolve(bakedForm = baked, bakedPackage = baked?.appPackage, injectedPackage = injectedPkg)
    }

    private fun toBundle(form: ParsedForm): Bundle = Bundle().apply {
        putString(K_PKG, form.appPackage)
        putParcelableArrayList(K_FIELDS, ArrayList(form.fields.map(::fieldBundle)))
        putParcelableArrayList(K_CC, ArrayList(form.ccFields.map(::fieldBundle)))
        putString(K_FORM_KIND, form.formKind.name)
        form.focusedId?.let { putParcelable(K_FOCUSED, it) }
    }

    private fun fieldBundle(f: ParsedField): Bundle = Bundle().apply {
        putParcelable(F_ID, f.id)
        putString(F_KIND, f.kind.name)
        putString(F_DOMAIN, f.webDomain)
        putString(F_SIGNAL, f.signal)
        putInt(F_TYPE, f.autofillType)
        putStringArrayList(F_OPTIONS, ArrayList(f.options))
        f.maxLength?.let { putInt(F_MAXLEN, it) }
        putBoolean(F_NEWPW, f.isNewPassword)
    }

    /** Null on anything malformed — a binding that does not read back whole is no binding. */
    private fun fromBundle(b: Bundle): ParsedForm? {
        val pkg = b.getString(K_PKG) ?: return null
        val fields = b.bundleList(K_FIELDS)?.map { fieldFrom(it) ?: return null } ?: return null
        val cc = b.bundleList(K_CC)?.map { fieldFrom(it) ?: return null } ?: return null
        val formKind = b.getString(K_FORM_KIND)?.let { n -> FormKind.entries.firstOrNull { it.name == n } } ?: return null
        return ParsedForm(fields, pkg, cc, formKind, b.autofillId(K_FOCUSED))
    }

    private fun fieldFrom(b: Bundle): ParsedField? {
        val id = b.autofillId(F_ID) ?: return null
        val kind = b.getString(F_KIND)?.let { n -> FieldKind.entries.firstOrNull { it.name == n } } ?: return null
        return ParsedField(
            id = id,
            kind = kind,
            webDomain = b.getString(F_DOMAIN),
            signal = b.getString(F_SIGNAL) ?: "",
            autofillType = b.getInt(F_TYPE),
            options = b.getStringArrayList(F_OPTIONS) ?: emptyList(),
            maxLength = if (b.containsKey(F_MAXLEN)) b.getInt(F_MAXLEN) else null,
            isNewPassword = b.getBoolean(F_NEWPW),
        )
    }

    @Suppress("DEPRECATION")
    private fun Intent.bundleExtra(key: String): Bundle? =
        if (Build.VERSION.SDK_INT >= 33) getParcelableExtra(key, Bundle::class.java) else getParcelableExtra(key)

    @Suppress("DEPRECATION")
    private fun Bundle.bundleList(key: String): List<Bundle>? =
        if (Build.VERSION.SDK_INT >= 33) getParcelableArrayList(key, Bundle::class.java) else getParcelableArrayList(key)

    @Suppress("DEPRECATION")
    private fun Bundle.autofillId(key: String): AutofillId? =
        if (Build.VERSION.SDK_INT >= 33) getParcelable(key, AutofillId::class.java) else getParcelable(key)

    @Suppress("DEPRECATION")
    private fun Intent.assistStructure(): AssistStructure? =
        if (Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, AssistStructure::class.java)
        } else {
            getParcelableExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE)
        }
}
