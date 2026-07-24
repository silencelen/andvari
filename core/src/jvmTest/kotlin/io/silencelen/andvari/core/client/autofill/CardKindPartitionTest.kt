package io.silencelen.andvari.core.client.autofill

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [T14] the isCardKind PARTITION pin: every silent-skip inventory member (textFor /
 * listIndexFor / isCardKind — all `else`-defaulted, so a FieldKind added without deciding its
 * card-ness degrades SILENTLY at runtime) is guarded here instead: growing the enum without
 * updating this list — or updating isCardKind without this list — goes red at the gate.
 */
class CardKindPartitionTest {
    @Test
    fun isCardKindPartitionsTheEnum() {
        assertEquals(
            listOf(
                FieldKind.CC_NUMBER, FieldKind.CC_EXP_MONTH, FieldKind.CC_EXP_YEAR,
                FieldKind.CC_EXP, FieldKind.CC_NAME, FieldKind.CC_CSC, FieldKind.CC_TYPE,
            ),
            FieldKind.values().filter { it.isCardKind },
        )
        assertEquals(
            listOf(FieldKind.USERNAME, FieldKind.PASSWORD, FieldKind.NONE),
            FieldKind.values().filterNot { it.isCardKind },
        )
    }
}
