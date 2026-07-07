package io.silencelen.andvari.core.client.autofill

/**
 * Autofill field classification — pure, vector-tested, mirrored in web. Sees only field
 * SIGNALS (autofill hints, InputType, HTML tag/attrs), never field values. Priority:
 * autofill hints → HTML input type + name/id keywords → Android InputType variations.
 */
enum class FieldKind { USERNAME, PASSWORD, NONE }

/** Signals extracted at the Android boundary; InputType constants are stable AOSP values. */
data class FieldSignal(
    val hints: List<String> = emptyList(),
    val inputTypeClass: Int = 0,       // InputType.TYPE_MASK_CLASS
    val inputTypeVariation: Int = 0,   // InputType.TYPE_MASK_VARIATION
    val htmlTag: String? = null,
    val htmlType: String? = null,      // <input type="...">
    val htmlNameOrId: String? = null,
) {
    companion object {
        // AOSP android.text.InputType constants (stable).
        const val CLASS_TEXT = 0x00000001
        const val CLASS_NUMBER = 0x00000002
        const val VARIATION_PASSWORD = 0x00000080
        const val VARIATION_WEB_PASSWORD = 0x000000e0
        const val VARIATION_VISIBLE_PASSWORD = 0x00000090
        const val VARIATION_EMAIL_ADDRESS = 0x00000020
        const val VARIATION_WEB_EMAIL_ADDRESS = 0x000000d0
        const val NUMBER_VARIATION_PASSWORD = 0x00000010
    }
}

object FieldClassifier {
    // W3C autofill tokens + Android View hints.
    private val USERNAME_HINTS = setOf("username", "emailaddress", "email", "newusername", "personname")
    private val PASSWORD_HINTS = setOf("password", "newpassword", "current-password", "new-password")
    private val NEGATIVE_HINTS = setOf("smsotpcode", "otpcode", "cardnumber", "creditcardnumber", "postalcode", "creditcardsecuritycode")
    private val NAME_POSITIVE_USER = listOf("user", "email", "login", "account", "userid")
    private val NAME_POSITIVE_PASS = listOf("pass", "pwd", "passwd")
    private val NAME_NEGATIVE = listOf("search", "otp", "captcha", "code", "query", "phone")

    fun classify(s: FieldSignal): FieldKind {
        val hints = s.hints.map { it.lowercase().replace("_", "").replace("-", "") }
        // 1. Autofill hints win.
        if (hints.any { it in NEGATIVE_HINTS }) return FieldKind.NONE
        if (hints.any { it in PASSWORD_HINTS.map { p -> p.replace("-", "") } }) return FieldKind.PASSWORD
        if (hints.any { it in USERNAME_HINTS }) return FieldKind.USERNAME

        val nameId = s.htmlNameOrId?.lowercase() ?: ""
        val negativeName = NAME_NEGATIVE.any { it in nameId }

        // 2. HTML input type + name/id keyword.
        when (s.htmlType?.lowercase()) {
            "password" -> return FieldKind.PASSWORD
            "email" -> if (!negativeName) return FieldKind.USERNAME
            "search", "tel", "number" -> return FieldKind.NONE
            "text", "" -> {
                if (!negativeName && NAME_POSITIVE_PASS.any { it in nameId }) return FieldKind.PASSWORD
                if (!negativeName && NAME_POSITIVE_USER.any { it in nameId }) return FieldKind.USERNAME
            }
        }

        // 3. Android InputType variations.
        if (s.inputTypeClass == FieldSignal.CLASS_TEXT) {
            when (s.inputTypeVariation) {
                FieldSignal.VARIATION_PASSWORD, FieldSignal.VARIATION_WEB_PASSWORD, FieldSignal.VARIATION_VISIBLE_PASSWORD -> return FieldKind.PASSWORD
                FieldSignal.VARIATION_EMAIL_ADDRESS, FieldSignal.VARIATION_WEB_EMAIL_ADDRESS -> if (!negativeName) return FieldKind.USERNAME
            }
        }
        if (s.inputTypeClass == FieldSignal.CLASS_NUMBER && s.inputTypeVariation == FieldSignal.NUMBER_VARIATION_PASSWORD) return FieldKind.PASSWORD

        // 4. Fall back to name/id keyword alone (for untyped text fields).
        if (!negativeName && NAME_POSITIVE_PASS.any { it in nameId }) return FieldKind.PASSWORD
        if (!negativeName && NAME_POSITIVE_USER.any { it in nameId }) return FieldKind.USERNAME
        return FieldKind.NONE
    }
}
