package io.silencelen.andvari.core.client.autofill

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [W5] committed collision guard for the V2b localized month-name select pass (design
 * 2026-07-23-card-autofill-tier3 §V2b). AFTER the fold, a listed-locale full month name must
 * never equal a DIFFERENT month's full name — in ANY listed locale, its OWN locale, or the
 * Tier-1 en table (CardFill.MONTH_NAMES). If two names coincide they MUST be the same month
 * index (a same-month cognate like de/fr "mai" or it/es "marzo"); anything else would let
 * `monthNameMatches` fill the wrong month. Correctness-verified zero collisions today — this
 * test guards future locale edits (add a locale that collides → red here, not in production).
 */
class MonthNameCollisionTest {
    @Test
    fun noFoldedFullNameEqualsADifferentMonthAnywhere() {
        // The comparison universe: every listed locale's folded full names + BOTH en Tier-1 tables
        // (full names AND abbreviations — the matcher equality-checks abbreviations in the same
        // pass, so "mai" colliding with an en ABBREV for another month would be just as wrong;
        // review-fold widened this from names-only). Keys are only for the failure message.
        val enAbbrevs = CardFill.MONTH_ABBREVIATIONS.entries.map { (mm, abbrs) ->
            // "01"→["jan"] becomes index-aligned entries so the same-month check applies.
            (mm.toInt() - 1) to abbrs
        }
        val universe: Map<String, List<Pair<Int, String>>> =
            (CardFill.MONTH_NAMES_BY_LOCALE + ("en" to CardFill.MONTH_NAMES))
                .mapValues { (_, names) -> names.mapIndexed { i, n -> i to n } } +
                ("en-abbrev" to enAbbrevs.flatMap { (i, abbrs) -> abbrs.map { i to it } })
        for ((locale, names) in CardFill.MONTH_NAMES_BY_LOCALE) {
            names.forEachIndexed { month, name ->
                for ((otherLocale, entries) in universe) {
                    for ((otherMonth, other) in entries) {
                        if (name == other) {
                            assertEquals(
                                month, otherMonth,
                                "$locale month ${month + 1} ('$name') collides with $otherLocale month ${otherMonth + 1}",
                            )
                        }
                    }
                }
            }
        }
    }

    @Test
    fun everyAuthoredLocaleNameIsAFoldFixedPoint() {
        // The tables are authored in the FOLDED alphabet and the matcher folds the page option
        // with the same table — an entry that is not its own fold ("märz" instead of "maerz")
        // could NEVER match anything. Review-fold: pin the invariant, not the authoring habit.
        for ((locale, names) in CardFill.MONTH_NAMES_BY_LOCALE) {
            for (name in names) {
                assertEquals(
                    name, FieldClassifier.asciiFold(name),
                    "$locale '$name' is not fold-stable — it would never match a folded option",
                )
            }
        }
    }
}
