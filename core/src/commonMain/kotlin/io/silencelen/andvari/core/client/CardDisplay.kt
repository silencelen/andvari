package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.autofill.CardNormalize

/**
 * Pure card DISPLAY helpers for the native clients — the Kotlin mirror of the display half
 * of web/src/vault/card.ts (`brandLabel`/`groupNumber`/`maskedLast4`/`cardSubtitle`/
 * `expiryLabel`/`isExpired` — web parity is the contract; CardDisplayTest pins it). The
 * canonical VALUE forms (digits-only number, "01".."12" month, 4-digit year) live in
 * [CardNormalize], which everything here delegates to for digits/brand/padMonth/yearTo4 —
 * no second parser, no second brand table.
 *
 * Display only: nothing here is a storage form, and the STORED `CardData.brand` is never
 * trusted — brand is always recomputed from the number, so a stale value written by
 * another client can never leak into a row.
 */
object CardDisplay {
    /**
     * Option A rollout gate (design 2026-07-09, "the one owner decision") for the NATIVE
     * clients: card CREATION was held dark until the fielded 0.2.x desktop MSI was retired —
     * that client rebuilds docs field-by-field, so any card it could touch became ghost
     * rows + denied writes. That trigger has now fired (0.2.x MSI retired; fleet manifest
     * windows=0.16.0), so this is flipped true and the create entry points are live;
     * everything else — render/edit/detail/history/trash of EXISTING cards — shipped live
     * regardless. Still test-pinned (now to true; like web's CARD_CREATE_ENABLED and the
     * extension's fv pin) so any change to card-create visibility stays deliberate.
     */
    const val CREATE_ENABLED: Boolean = true

    /** Human-readable brand ("Visa"), null for unknown/absent — callers pick their own fallback. */
    fun brandLabel(brand: String?): String? = when (brand) {
        "visa" -> "Visa"
        "mastercard" -> "Mastercard"
        "amex" -> "Amex"
        "discover" -> "Discover"
        else -> null
    }

    /**
     * Display grouping for a (digits-only) number: 4-4-4-… generally, Amex 4-6-5 — sliced
     * progressively so a partially typed number groups sanely too. Sanitizes via
     * [CardNormalize.digitsOnly], so it is safe on raw editor text; display only, never a
     * storage form.
     */
    fun groupNumber(digits: String): String {
        val d = CardNormalize.digitsOnly(digits)
        if (d.isEmpty()) return ""
        if (CardNormalize.brand(d) == "amex") {
            return listOf(d.take(4), d.drop(4).take(6), d.drop(10)).filter { it.isNotEmpty() }.joinToString(" ")
        }
        return d.chunked(4).joinToString(" ")
    }

    /** "••1234" — last (up to) four digits behind a mask (fewer than 4 digits → all of them);
     *  never more of the PAN than that. */
    fun maskedLast4(digits: String): String = "••" + CardNormalize.digitsOnly(digits).takeLast(4)

    /**
     * List-row subtitle: "Visa ••4242"; unknown IIN falls back to "Card ••4242"; no number
     * at all → "card" (mirrors the login row's "login" fallback; web `cardSubtitle`). Brand
     * is recomputed from the number here — never read from the stored field, which is
     * display-only and could be stale if another writer skipped the recompute.
     */
    fun subtitle(doc: ItemDoc): String {
        val d = CardNormalize.digitsOnly(doc.card?.number ?: "")
        if (d.isEmpty()) return "card"
        return "${brandLabel(CardNormalize.brand(d)) ?: "Card"} ${maskedLast4(d)}"
    }

    /** "MM/YYYY" for the detail view; a missing half renders as "—"; null when neither is set. */
    fun expiryLabel(card: CardData?): String? {
        val m = card?.expMonth
        val y = card?.expYear
        if (m.isNullOrEmpty() && y.isNullOrEmpty()) return null
        return "${if (m.isNullOrEmpty()) "—" else m}/${if (y.isNullOrEmpty()) "—" else y}"
    }

    /**
     * Expired = strictly AFTER the last moment of the expiry month (a card is good THROUGH
     * its printed month — web `isExpired`, minus the Date: [nowYear]/[nowMonth1] are the
     * caller's clock, 1-based month, so this stays pure and clock-free like the rest of
     * core). Missing or garbled fields → false: absent data must never scare the user with
     * a red chip. Tolerates 2-digit years via the same [CardNormalize.yearTo4] pivot as
     * everything else.
     */
    fun isExpired(expMonth: String?, expYear: String?, nowYear: Int, nowMonth1: Int): Boolean {
        val m = CardNormalize.padMonth(expMonth ?: "")?.toInt() ?: return false
        val y = CardNormalize.yearTo4(expYear ?: "")?.toInt() ?: return false
        return y < nowYear || (y == nowYear && m < nowMonth1)
    }
}
