package io.silencelen.andvari.app.autofill

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [U20] the pure headroom rule (design 2026-07-23-card-autofill-tier2 §5). Framework
 * `Dataset`s can't be constructed in a JVM unit test, so [DatasetBuilder.loginDatasetCap]
 * is factored pure and pinned here — this is the lane's ONLY red-when-reverted coverage of
 * the reserve; the invariants below are the design's own words:
 *  - zero buildable cards → logins keep the full [DatasetBuilder.MAX_DATASETS] (never starved);
 *  - the reserve clamps at 3 (a 40-card vault must not shut logins out);
 *  - the reserve never trims below what cards consume (cards append under MAX_DATASETS
 *    after the capped logins, so ≥ min(builtCards, 3) slots always remain for them).
 */
class DatasetBuilderCapTest {

    @Test
    fun zeroCardsNeverCostALoginSlot() {
        assertEquals(DatasetBuilder.MAX_DATASETS, DatasetBuilder.loginDatasetCap(0))
    }

    @Test
    fun reserveGrowsWithCardsUpToThree() {
        assertEquals(DatasetBuilder.MAX_DATASETS - 1, DatasetBuilder.loginDatasetCap(1))
        assertEquals(DatasetBuilder.MAX_DATASETS - 2, DatasetBuilder.loginDatasetCap(2))
        assertEquals(DatasetBuilder.MAX_DATASETS - 3, DatasetBuilder.loginDatasetCap(3))
    }

    @Test
    fun reserveClampsAtThreeForCardHeavyVaults() {
        assertEquals(DatasetBuilder.MAX_DATASETS - 3, DatasetBuilder.loginDatasetCap(4))
        assertEquals(DatasetBuilder.MAX_DATASETS - 3, DatasetBuilder.loginDatasetCap(40))
    }

    @Test
    fun cardsAlwaysKeepAtLeastTheirReservedSlots() {
        for (builtCards in 0..12) {
            val remaining = DatasetBuilder.MAX_DATASETS - DatasetBuilder.loginDatasetCap(builtCards)
            assertEquals(minOf(builtCards, 3), remaining, "builtCards=$builtCards")
        }
    }
}
