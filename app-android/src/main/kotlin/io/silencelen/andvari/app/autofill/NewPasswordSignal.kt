package io.silencelen.andvari.app.autofill

import io.silencelen.andvari.core.client.autofill.FieldClassifier

/**
 * The one signal [io.silencelen.andvari.core.client.autofill.FieldClassifier] deliberately
 * discards: whether a PASSWORD field is the form's NEW password (a signup or change-password
 * box) rather than the CURRENT one. `PASSWORD_HINTS` collapses `newPassword` / `new-password`
 * into the same [io.silencelen.andvari.core.client.autofill.FieldKind.PASSWORD] verdict the
 * `password` / `current-password` hints get — correct for classification (the field IS a
 * password box), but it leaves both the fill and the save side unable to tell the two apart.
 *
 * Audit 2026-09-13 H04 / H21: that loss had two consequences on real change-password forms
 * (GitHub, Google, Microsoft, most frameworks order current-password first and hint it):
 *  - FILL wrote the stored password into EVERY password-classified field, new and confirm boxes
 *    included, so picking a login pre-filled "new password" with the old one behind masking dots;
 *  - SAVE captured the FIRST password field — the current password — so the vault silently kept
 *    the old password after a change and the next fill was wrong.
 * The extension has had this distinction since 0.22.0 (`detect.ts` `isNewPassword` → the fill
 * primary is the non-new field; the capture target is the new one). This is Android's twin of
 * that flag, read from the same two places the extension reads it: the W3C `autocomplete`
 * tokens (which Chrome maps into `autofillHints`, and which also arrive verbatim as an
 * `HtmlInfo` attribute) and the platform's own `AUTOFILL_HINT_NEW_PASSWORD` (`"newPassword"`).
 *
 * Hint normalization matches `FieldClassifier.classify` step 0 exactly (lowercase, strip `_`
 * and `-`) so `new-password`, `new_password` and `newPassword` all collapse to one token —
 * the flag can never disagree with the classifier about which spelling counts.
 *
 * Pure and value-blind: it reads only field metadata, never text.
 */
object NewPasswordSignal {
    /**
     * @param hints the node's `autofillHints` (Android hints and/or Chrome-mapped autocomplete tokens)
     * @param autocompleteAttr the raw HTML `autocomplete` attribute, when the structure carries one
     *
     * R19: the hint test IS core's `FieldClassifier.hasNewPasswordHint` (one normalizer, the one
     * classify() step 0 uses); this object only adds the raw-attribute belt.
     */
    fun isNewPassword(hints: List<String>, autocompleteAttr: String?): Boolean {
        if (FieldClassifier.hasNewPasswordHint(hints)) return true
        // `autocomplete="section-x shipping new-password"` — a space-separated token list; only
        // the exact token counts (a substring match would read "renew-password" as new).
        val attr = autocompleteAttr ?: return false
        return attr.split(' ').any { it.isNotEmpty() && FieldClassifier.hasNewPasswordHint(listOf(it)) }
    }

    /**
     * The password field a SAVE captures, given the form's valued PASSWORD fields in tree order
     * (H04). The first hinted new-password field wins — the value the site is about to adopt is
     * the one the vault must learn. With no hint at all, a three-or-more password form is the
     * classic hintless change-password shape (current / new / confirm), whose NEW value sits
     * SECOND; a one- or two-field form (login, or signup password + confirm) keeps first-wins,
     * which was correct for those shapes all along. Extension twin: `capturePassword =
     * newPasswords[0] ?? password` plus the same ≥3-unflagged fallback.
     */
    fun <T> capturePassword(passwords: List<T>, isNew: (T) -> Boolean): T? {
        if (passwords.isEmpty()) return null
        passwords.firstOrNull(isNew)?.let { return it }
        return if (passwords.size >= 3) passwords[1] else passwords[0]
    }

    /**
     * The password fields a stored password may be FILLED into (H21) — the extension's primary
     * rule (`detect.ts` `primary = passwords.find(p => !p.isNewPassword) ?? passwords[0]`):
     * when at least one password field is NOT hinted new, only the non-new ones take the stored
     * value, so a change-password page's new + confirm boxes stay empty for the user to type
     * into. A form whose password fields are ALL hinted new (a bare signup form) keeps today's
     * behaviour — every one of them is offered, which is what a user re-registering with a
     * stored password expects.
     */
    fun <T> fillablePasswordFields(passwords: List<T>, isNew: (T) -> Boolean): List<T> =
        FieldClassifier.passwordFillTargetsBy(passwords, isNew) // R19: core owns the set rule
}
