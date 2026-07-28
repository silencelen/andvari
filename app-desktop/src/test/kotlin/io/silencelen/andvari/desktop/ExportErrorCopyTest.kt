package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.HouseholdCopy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * #23 (polish audit 2026-07-27 ux-error--0/ux-copy--0): the spec 07 export paths' error slot.
 * [exportError] is android AndvariViewModel.exportError's twin — the ONLY sanctioned `.message`
 * pass-through on desktop, scoped to the export flow's own app-minted [IllegalStateException]
 * sentences (Backup verification, writeVerifiedAtomically's kept-temp move failure). Everything
 * else — an ApiException carrying the SERVER'S raw message, a ktor/IO exception's debug string —
 * routes through the shared HouseholdCopy canon, whose sentences core's HouseholdCopyTest pins.
 */
class ExportErrorCopyTest {
    // The carve-out: an app-minted IllegalStateException sentence surfaces verbatim.
    @Test
    fun appMintedIllegalStateSentencePassesThrough() {
        val minted = "backup verification failed — attachment \"tax.pdf\" does not round-trip"
        assertEquals(minted, exportError(IllegalStateException(minted)))
    }

    // A blank-message ISE has nothing curated to show — canon fallback, never an empty error bar.
    @Test
    fun blankIllegalStateFallsBackToCanon() {
        assertEquals(HouseholdCopy.SOMETHING_WENT_WRONG, exportError(IllegalStateException()))
        assertEquals(HouseholdCopy.SOMETHING_WENT_WRONG, exportError(IllegalStateException("")))
    }

    // The audited defect: a server 500's raw message must NEVER reach the error bar.
    @Test
    fun serverRawMessageNeverSurfaces() {
        val raw = "SQLITE_CONSTRAINT: UNIQUE constraint failed: sessions.id"
        val mapped = exportError(ApiException(500, "internal", raw))
        assertEquals(HouseholdCopy.SERVER_PROBLEM, mapped)
        assertFalse(mapped.contains("SQLITE"), "raw wire text leaked: $mapped")
    }

    // Transport failure during the pre-write fetch → the canon's unreachable sentence.
    @Test
    fun ioExceptionMapsToUnreachable() {
        assertEquals(HouseholdCopy.UNREACHABLE, exportError(java.io.IOException("Connection reset by peer")))
    }
}
