package io.silencelen.andvari.core.client.session

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** F8: a session written before sessions owned their origin gets one, or is dropped when that is unsafe. */
class SessionOriginBackfillTest {
    private val a = "https://a.example"
    private val b = "https://b.example"

    @Test
    fun withNoPendingSwitchTheSessionBelongsToTheBaseUrl() {
        assertEquals(a, sessionOriginForBackfill(a, pending = null))
    }

    @Test
    fun aPendingSwitchThatHasMovedTheBaseUrlLeavesTheSessionUnattributable() {
        // The base URL points at the marker's origin: the stored tokens could be either origin's.
        val marker = PendingServer(origin = b, previousOrigin = a, ts = 1)
        assertNull(sessionOriginForBackfill(b, marker))
        // The canonical compare decides, so a respelled URL is still the marker's origin.
        assertNull(sessionOriginForBackfill("https://B.example:443/", marker))
    }

    @Test
    fun aPendingSwitchThatHasNotMovedTheBaseUrlKeepsTheSessionWithIt() {
        // The marker is written first: a crash here never reached the origin change or the token
        // drop, so the session is still the current base URL's.
        val marker = PendingServer(origin = b, previousOrigin = a, ts = 1)
        assertEquals(a, sessionOriginForBackfill(a, marker))
    }
}
