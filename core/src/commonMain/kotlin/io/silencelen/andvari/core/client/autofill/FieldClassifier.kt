package io.silencelen.andvari.core.client.autofill

/**
 * Autofill field classification — pure, vector-tested, mirrored in web. Sees only field
 * SIGNALS (autofill hints, InputType, HTML tag/attrs), never field values. Priority:
 * autofill hints → CSC demotion → the FULL legacy (0.6.x) login classifier → whole-token-run
 * card keywords. Card keywords run ONLY when the legacy verdict is NONE — every field the
 * 0.6.x classifier decided keeps its verdict, so login verdicts on card-free forms are
 * bit-identical to pre-0.7.0 — pinned by urimatch.json (classify + classifyCardFreeRegression).
 */
enum class FieldKind { USERNAME, PASSWORD, NONE, CC_NUMBER, CC_EXP_MONTH, CC_EXP_YEAR, CC_EXP, CC_NAME, CC_CSC, CC_TYPE, CC_POSTAL }

/** Signals extracted at the Android boundary; InputType constants are stable AOSP values. */
data class FieldSignal(
    val hints: List<String> = emptyList(),
    val inputTypeClass: Int = 0,       // InputType.TYPE_MASK_CLASS
    val inputTypeVariation: Int = 0,   // InputType.TYPE_MASK_VARIATION
    val htmlTag: String? = null,
    val htmlType: String? = null,      // <input type="...">
    val htmlNameOrId: String? = null,
    // Consumed by CardForm.refine only — classify() never reads them.
    val maxLength: Int? = null,        // declared max length; null when undeclared (DOM reports -1 → map to null)
    val inputMode: String? = null,     // HTML inputmode attr, or a platform equivalent the caller maps in
    val frameDomain: String? = null,   // owning frame's webDomain; null = native app / undeclared frame
    // The html `id` attr when a `name` attr ALSO exists (else the id already rode htmlNameOrId —
    // never feed it twice). Appended LAST with a null default so every pre-0.19.x construction
    // and vector stays bit-identical; unlike its neighbors above, classify() DOES read it
    // (steps 2 + 4 — card path + CSC demotion only, the login steps never see it).
    val htmlId: String? = null,
    // ONE label string (Android: ViewNode.hint — the platform has no multi-source label list;
    // the extension classifies its label sources per-string on its own side). Appended LAST,
    // null default (construction sites are named-arg). The WEAKEST signal: consulted only in
    // the step-4 card gap, after the name and id passes both produced nothing — never by the
    // login steps or the CSC demotion. DELIBERATELY UN-BOUNDED here: the extension caps its
    // label sources at 60 chars / 8 tokens ([U6], a defense against form-sized wrapping <label>
    // over-match), but a ViewNode.hint is a short single control hint, not scraped page text —
    // there is no long-sentence hazard to bound, and the whole-token-run matcher already refuses
    // partial-token hits. Revisit only if a real over-matching hint surfaces.
    val labelText: String? = null,
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
    // "onetimecode" = the normalized W3C "one-time-code" / Android "oneTimeCode" token (hints are
    // lowercased + "_"/"-"-stripped at classify() step 0, so both collapse to this exact form before
    // the set check) — andvari's OWN Welcome TOTP box is the canonical one-time-code field, and a
    // PASSWORD must never be offered into it even though it carries htmlType=password (the negative
    // hint fires in step 1, ahead of the legacy htmlType=="password"→PASSWORD rule).
    private val NEGATIVE_HINTS = setOf("smsotpcode", "otpcode", "postalcode", "onetimecode")
    // Android AUTOFILL_HINT_CREDIT_CARD_* + W3C cc-* (normalized). cardnumber/creditcardnumber/
    // creditcardsecuritycode graduated out of NEGATIVE_HINTS in 0.7.0 — still never
    // USERNAME/PASSWORD by construction; checked before the password/username hint sets so an
    // explicit card hint beats a stray "password" hint on the same field.
    private val CARD_HINTS = mapOf(
        "cardnumber" to FieldKind.CC_NUMBER, "creditcardnumber" to FieldKind.CC_NUMBER, "ccnumber" to FieldKind.CC_NUMBER,
        "creditcardsecuritycode" to FieldKind.CC_CSC, "cccsc" to FieldKind.CC_CSC,
        "creditcardexpirationmonth" to FieldKind.CC_EXP_MONTH, "ccexpmonth" to FieldKind.CC_EXP_MONTH,
        "creditcardexpirationyear" to FieldKind.CC_EXP_YEAR, "ccexpyear" to FieldKind.CC_EXP_YEAR,
        "creditcardexpirationdate" to FieldKind.CC_EXP, "ccexp" to FieldKind.CC_EXP,
        "ccname" to FieldKind.CC_NAME,
        "cctype" to FieldKind.CC_TYPE,
    )
    private val NAME_POSITIVE_USER = listOf("user", "email", "login", "account", "userid")
    private val NAME_POSITIVE_PASS = listOf("pass", "pwd", "passwd")
    private val NAME_NEGATIVE = listOf("search", "otp", "captcha", "code", "query", "phone")
    // Card keywords — whole-token-run matched against the tokenized name/id/label (see
    // tokenMatch), never substring. "pan" is deliberately absent (hazard exceeds its value);
    // no bare "exp"/"expires" ([U4]: session_expires); no "cid" ([U3]: run-match makes it
    // c_id) and no "securitynumber"/"verificationnumber" ([U2]: SSN/OTP fields). Group order
    // matters: exp-month/-year before the generic exp group ("cc_exp_month" also
    // whole-run-matches "ccexp"; "expiration_month" also whole-run-matches "expiration"),
    // and bare "creditcard" rides a TRAILING cc-number group consulted after every other
    // kind ([U1]: credit_card_cvv/_expiry/_type must keep their specific verdicts — only a
    // bare credit_card collapses to the PAN). The NORMATIVE ordered copy is cardfill.json
    // tables.keywords; CardFillVectorTest asserts SEQUENCE equality (kinds AND order AND
    // contents) and the extension asserts the same file — lockstep by construction.
    // G3 [X3-A1] the cc-postal vocabulary — single-sourced into CARD_NAME_KINDS below AND
    // [postalKind]. Declared BEFORE CARD_NAME_KINDS (object-property init order). Bare `postalcode`
    // fires ONLY in the anchored gap (it also stays a login NEGATIVE_HINT for the autofill-hint
    // path, [X3-A2]); prefixed billing*/card* forms win.
    internal val CC_POSTAL_KEYWORDS = listOf("billingzip", "billingpostal", "cardpostal", "cardzip", "avszip", "postalcode")
    internal val CARD_NAME_KINDS = listOf(
        listOf("cardnumber", "ccnumber", "ccnum", "cardno", "cardnum", "ccno", "kartennummer", "kreditkartennummer", "numerocarte", "numerotarjeta", "numerocartao") to FieldKind.CC_NUMBER,
        listOf("expmonth", "expmm", "expirationmonth", "expirymonth", "cardmonth") to FieldKind.CC_EXP_MONTH,
        listOf("expyear", "expyy", "expirationyear", "expiryyear", "cardyear") to FieldKind.CC_EXP_YEAR,
        listOf("expiry", "expdate", "ccexp", "expiration", "expirationdate", "expiredate", "expirydate", "validthru", "validthrough", "goodthru", "goodthrough", "validuntil", "ablaufdatum", "gueltigbis", "dateexpiration", "vencimiento") to FieldKind.CC_EXP,
        listOf("cvv", "cvc", "csc", "securitycode", "cvn", "cardcode", "xcardcode", "verificationvalue", "cardverificationcode", "cardverificationvalue", "cryptogramme", "pruefnummer", "kartenpruefnummer", "codigoseguridad") to FieldKind.CC_CSC,
        listOf("cardholder", "nameoncard", "ccname", "holdername", "cardholdername", "cardholdersname", "titulaire", "titular", "karteninhaber") to FieldKind.CC_NAME,
        listOf("cardtype", "cctype", "cardbrand", "ccbrand", "cbtype") to FieldKind.CC_TYPE,
        // G3 [X3-A1] cc-postal group — placed AFTER cc-type and BEFORE the trailing bare-creditcard
        // [U1] group so no cross-kind run overlaps. It rides CARD_NAME_KINDS for the cardfill.json
        // sequence pin + the fill leg, but is ANCHOR-GATED: cardKeywordPass SKIPS it so classify()
        // never surfaces CC_POSTAL (login-inert bare — urimatch standalone pins NONE); CardForm.refine
        // re-derives it inside a CC_NUMBER-anchored cluster via [postalKind].
        CC_POSTAL_KEYWORDS to FieldKind.CC_POSTAL,
        listOf("creditcard") to FieldKind.CC_NUMBER,
    )
    // G3 [X3-A1](i) shipping-suppressor ([T10] gift-guard shape, per-string, terminal): a would-be
    // cc-postal string whose SAME token list also whole-run-matches a shipping token is a delivery
    // zip, never billing — suppressed to NONE so billing postal never fills/overwrites a shipping
    // zip on a mixed single-form checkout. i18n runs with the vocab (lieferung/livraison/…).
    private val SHIPPING_SUPPRESSORS = listOf("ship", "shipping", "delivery", "deliver", "recipient", "lieferung", "liefer", "livraison", "envio", "spedizione")
    // Gift/store-value suppressors ([T10]): a CC_NUMBER verdict from the name/id token path is
    // killed when one of these matches THE SAME token list that produced the verdict — a gift
    // number must never anchor a card form (and a killed anchor is terminal for the field: the
    // other string never resurrects it). Suppress-only: no other kind is touched, and the
    // autocomplete-hint path is deliberately unguarded (an explicit cc-number hint is the
    // site's own claim — Chromium parity).
    // i18n suppressors ride with the i18n number vocab: numeroCarteCadeau / Geschenkkarte /
    // tarjetaRegalo must never anchor a card form any more than giftCardNumber does.
    private val GIFT_SUPPRESSORS = listOf("gift", "egift", "voucher", "loyalty", "coupon", "cadeau", "geschenk", "regalo")
    // Whole-run-matchable forms only: "cardverification" covers cardVerificationValue
    // ([card,verification,value] — the run card+verification) — the old "cardverif" prefix hack
    // is gone with prefix-span matching.
    private val CSC_DEMOTION = listOf("cvv", "cvc", "csc", "securitycode", "cardverification")
    // Card keywords never classify a password type (only the CSC demotion may) and never fire
    // from bare CLASS_NUMBER InputType — the keyword, not the numeric-ness, is the card signal.
    private val CARD_FALLBACK_HTML_TYPES = setOf(null, "", "text", "tel", "number")

    // [W3] shared explicit char→STRING ASCII fold — NOT Char lowercasing + NFD: NFD leaves
    // ß/ø/æ/œ/ł/đ/ð/þ undecomposed and emits ü→u (unreachable for the shipped German ue/oe/ae
    // vocab), so the digraphs are decided EXPLICITLY and both engines compile the SAME table
    // (parity by construction). Uppercase forms fold identically; unmapped chars pass through.
    // NORMATIVE copy = cardfill.json tables.asciiFold (CardFillVectorTest asserts equality).
    internal val ASCII_FOLD: Map<Char, String> = mapOf(
        // German digraphs (gueltigbis / pruefnummer / kartenpruefnummer).
        'ß' to "ss", 'ä' to "ae", 'Ä' to "ae", 'ö' to "oe", 'Ö' to "oe", 'ü' to "ue", 'Ü' to "ue",
        // Non-decomposable Latin — decided explicitly, never left to NFD (the parity pins).
        'æ' to "ae", 'Æ' to "ae", 'œ' to "oe", 'Œ' to "oe", 'ø' to "o", 'Ø' to "o",
        'ð' to "d", 'Ð' to "d", 'þ' to "th", 'Þ' to "th", 'ł' to "l", 'Ł' to "l", 'đ' to "d", 'Đ' to "d",
        // Accented single letters.
        'à' to "a", 'À' to "a", 'â' to "a", 'Â' to "a", 'á' to "a", 'Á' to "a", 'ã' to "a", 'Ã' to "a",
        'å' to "a", 'Å' to "a", 'ā' to "a", 'Ā' to "a",
        'ç' to "c", 'Ç' to "c", 'ć' to "c", 'Ć' to "c", 'č' to "c", 'Č' to "c",
        'é' to "e", 'É' to "e", 'è' to "e", 'È' to "e", 'ê' to "e", 'Ê' to "e", 'ë' to "e", 'Ë' to "e",
        'ē' to "e", 'Ē' to "e",
        'í' to "i", 'Í' to "i", 'î' to "i", 'Î' to "i", 'ï' to "i", 'Ï' to "i", 'ì' to "i", 'Ì' to "i",
        'ī' to "i", 'Ī' to "i",
        'ñ' to "n", 'Ñ' to "n", 'ń' to "n", 'Ń' to "n",
        'ó' to "o", 'Ó' to "o", 'ô' to "o", 'Ô' to "o", 'õ' to "o", 'Õ' to "o", 'ò' to "o", 'Ò' to "o",
        'ō' to "o", 'Ō' to "o",
        'ú' to "u", 'Ú' to "u", 'û' to "u", 'Û' to "u", 'ù' to "u", 'Ù' to "u", 'ū' to "u", 'Ū' to "u",
        'ý' to "y", 'Ý' to "y", 'ÿ' to "y", 'Ÿ' to "y",
    )

    /** [W3] apply [ASCII_FOLD] over a string — card path only. Used inside [tokens] (whose every
     *  call site is a card step, so [legacyClassify]'s raw-`nameId` login verdicts stay
     *  bit-identical) and by CardFill's month-name select pass. Fast-paths the all-ASCII common case. */
    internal fun asciiFold(s: String): String {
        if (s.none { it in ASCII_FOLD }) return s
        val sb = StringBuilder(s.length)
        for (c in s) sb.append(ASCII_FOLD[c] ?: c.toString())
        return sb.toString()
    }

    fun classify(s: FieldSignal): FieldKind {
        val hints = s.hints.map { it.lowercase().replace("_", "").replace("-", "") }
        // 1. Autofill hints win.
        if (hints.any { it in NEGATIVE_HINTS }) return FieldKind.NONE
        hints.firstNotNullOfOrNull { CARD_HINTS[it] }?.let { return it }
        if (hints.any { it in PASSWORD_HINTS.map { p -> p.replace("-", "") } }) return FieldKind.PASSWORD
        if (hints.any { it in USERNAME_HINTS }) return FieldKind.USERNAME

        val nameId = s.htmlNameOrId?.lowercase() ?: ""
        val negativeName = NAME_NEGATIVE.any { it in nameId }
        val toks = tokens(s.htmlNameOrId ?: "")
        // htmlId only exists when a name attr shadowed the id (FieldSignal contract) — the card
        // path checks BOTH strings; the login steps stay htmlNameOrId-only (bit-identity gate).
        val idToks = tokens(s.htmlId ?: "")
        val htmlType = s.htmlType?.lowercase()

        // 2. CSC demotion: a password input NAMED like a card security code is the CVV, never the
        //    account password — filling the vault password here hands it to the merchant. Fires on
        //    name OR id ([T12]) — widening a SUPPRESSION is fail-safe, and without the id leg
        //    <input type=password name=field_7 id=cardCvc> would offer the vault password into
        //    the merchant's CVV box.
        if (htmlType == "password" && (CSC_DEMOTION.any { tokenMatch(toks, it) } || CSC_DEMOTION.any { tokenMatch(idToks, it) })) return FieldKind.CC_CSC

        // 3. The FULL legacy (0.6.x) classifier. Any verdict it produces STANDS — the bit-identity
        //    gate: adding card kinds can never flip a verdict 0.6.x already produced (passport_expiry
        //    stays PASSWORD; a native InputType-password field id'd securityCode stays PASSWORD).
        val legacyKind = legacyClassify(s, nameId, negativeName, htmlType)
        if (legacyKind != FieldKind.NONE) return legacyKind

        // 4. Card keyword fallback — fires ONLY in the legacy==NONE gap. This keeps the spirit of
        //    the one deliberate 0.7.0 reorder: fields the legacy tel/number→NONE early return gave
        //    up on (<input type="tel" name="cardNumber">) still classify, without a card keyword
        //    ever outranking a login verdict. Never on password types (only step 2 may demote).
        //    The name pass runs first; the id pass ONLY when the name produced nothing; the
        //    labelText pass (the weakest signal) ONLY when both attr strings produced nothing —
        //    so a verdict (or its gift suppression) always binds to the string that produced it,
        //    per-string terminality included ([U5]: token runs never span a source boundary).
        if (htmlType in CARD_FALLBACK_HTML_TYPES) {
            (cardKeywordPass(toks) ?: cardKeywordPass(idToks) ?: cardKeywordPass(tokens(s.labelText ?: "")))?.let { return it }
        }
        return FieldKind.NONE
    }

    /** One string's card-keyword verdict, or null when its tokens matched no group. NONE (not
     *  null) on a gift-suppressed CC_NUMBER — suppression must TERMINATE the fallback ([T10]:
     *  the guard binds to the verdict-producing string, and a suppressed anchor is a decided
     *  "this is a gift field", never an invitation to consult the other string). */
    private fun cardKeywordPass(toks: List<String>): FieldKind? {
        for ((kws, kind) in CARD_NAME_KINDS) {
            // [X3-A1] CC_POSTAL is anchor-gated: it rides CARD_NAME_KINDS for the sequence pin +
            // fill leg, but classify() must stay login-inert on it (urimatch standalone billingZip/
            // postalCode = NONE) — CardForm.refine promotes it via [postalKind] under a PAN anchor.
            if (kind == FieldKind.CC_POSTAL) continue
            if (kws.any { tokenMatch(toks, it) }) {
                if (kind == FieldKind.CC_NUMBER && GIFT_SUPPRESSORS.any { tokenMatch(toks, it) }) return FieldKind.NONE
                return kind
            }
        }
        return null
    }

    /** [X3-A1] Anchor-gated CC_POSTAL detection — [CardForm.refine] ONLY (classify() is login-inert
     *  bare per urimatch standalone). Per-string over name→id→label: the FIRST source whose tokens
     *  whole-run-match a cc-postal keyword binds (terminal, [U5]-shape), and the shipping-suppressor
     *  ([X3-A1](i)) is checked against THAT string — a shippingPostalCode (matches postalcode AND
     *  ship) is suppressed to NONE. No cc-postal hit on any source → NONE. */
    internal fun postalKind(s: FieldSignal): FieldKind {
        for (raw in listOf(s.htmlNameOrId, s.htmlId, s.labelText)) {
            val toks = tokens(raw ?: "")
            if (CC_POSTAL_KEYWORDS.any { tokenMatch(toks, it) }) {
                return if (SHIPPING_SUPPRESSORS.any { tokenMatch(toks, it) }) FieldKind.NONE else FieldKind.CC_POSTAL
            }
        }
        return FieldKind.NONE
    }

    /** The 0.6.x classifier, verbatim: HTML input type + name/id keywords → Android InputType
     *  variations → bare name/id keyword fallback (for untyped text fields). Its USERNAME/PASSWORD/
     *  NONE verdicts are frozen by the urimatch.json classify section — do not edit its logic. */
    private fun legacyClassify(s: FieldSignal, nameId: String, negativeName: Boolean, htmlType: String?): FieldKind {
        // HTML input type + name/id keyword.
        when (htmlType) {
            "password" -> return FieldKind.PASSWORD
            "email" -> if (!negativeName) return FieldKind.USERNAME
            "search", "tel", "number" -> return FieldKind.NONE
            "text", "" -> {
                if (!negativeName && NAME_POSITIVE_PASS.any { it in nameId }) return FieldKind.PASSWORD
                if (!negativeName && NAME_POSITIVE_USER.any { it in nameId }) return FieldKind.USERNAME
            }
        }

        // Android InputType variations.
        if (s.inputTypeClass == FieldSignal.CLASS_TEXT) {
            when (s.inputTypeVariation) {
                FieldSignal.VARIATION_PASSWORD, FieldSignal.VARIATION_WEB_PASSWORD, FieldSignal.VARIATION_VISIBLE_PASSWORD -> return FieldKind.PASSWORD
                FieldSignal.VARIATION_EMAIL_ADDRESS, FieldSignal.VARIATION_WEB_EMAIL_ADDRESS -> if (!negativeName) return FieldKind.USERNAME
            }
        }
        if (s.inputTypeClass == FieldSignal.CLASS_NUMBER && s.inputTypeVariation == FieldSignal.NUMBER_VARIATION_PASSWORD) return FieldKind.PASSWORD

        // Fall back to name/id keyword alone (for untyped text fields).
        if (!negativeName && NAME_POSITIVE_PASS.any { it in nameId }) return FieldKind.PASSWORD
        if (!negativeName && NAME_POSITIVE_USER.any { it in nameId }) return FieldKind.USERNAME
        return FieldKind.NONE
    }

    /** name/id/label → lowercase tokens: split on non-alphanumerics + camelCase boundaries +
     *  the letter↔digit boundary ("cardVerificationValue" → [card, verification, value];
     *  "CVVCode" → [cvv, code]; "cardNumber2" → [card, number, 2] — [U9] extension-tokenizer
     *  parity). Each token is then ASCII-FOLDED ([W3] "Prüfnummer" → "pruefnummer", the run
     *  "Gültig"+"bis" → "gueltig"+"bis"); every call site is the card path (steps 2 + 4), so the
     *  fold cannot move a login verdict. */
    private fun tokens(raw: String): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        fun flush() { if (sb.isNotEmpty()) { out.add(asciiFold(sb.toString().lowercase())); sb.clear() } }
        for ((i, c) in raw.withIndex()) {
            if (!c.isLetterOrDigit()) { flush(); continue }
            // sb non-empty ⇒ raw[i-1] was appended (separators flush), so it is the previous token char.
            if (sb.isNotEmpty()) {
                val prev = raw[i - 1]
                if (c.isDigit() != prev.isDigit()) {
                    flush() // [U9] letter↔digit boundary, both directions ("cvv2", "3dsecure")
                } else if (c.isUpperCase()) {
                    val nextLower = i + 1 < raw.length && raw[i + 1].isLowerCase()
                    if (prev.isLowerCase() || (prev.isUpperCase() && nextLower)) flush()
                }
            }
            sb.append(c)
        }
        flush()
        return out
    }

    /** WHOLE-TOKEN-RUN match: [kw] matches iff it EQUALS the concatenation of a contiguous run of
     *  one or more whole tokens — it can neither start nor END mid-token ("securitycode" matches
     *  security_code; "cardno" matches card_no but NOT card_note; "cvc" never matches cv_code or
     *  mycvv — the NOT-substring, NOT-prefix-span guarantee). */
    private fun tokenMatch(toks: List<String>, kw: String): Boolean {
        for (i in toks.indices) {
            val acc = StringBuilder()
            for (j in i until toks.size) {
                acc.append(toks[j])
                if (acc.length > kw.length) break
                if (acc.length == kw.length) {
                    if (acc.toString() == kw) return true
                    break
                }
            }
        }
        return false
    }
}
