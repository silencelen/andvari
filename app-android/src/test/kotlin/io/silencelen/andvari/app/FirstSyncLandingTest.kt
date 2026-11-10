package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.client.session.runBounded
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Audit H10, the post-bind half of sign-in, unlock, quick unlock and enroll: once a session is bound,
 * the first sync decides only what the landing screen also says, never whether the user lands.
 * `BoundedOpWiringTest` pins that every one of those ops lands after it.
 */
class FirstSyncLandingTest {
    @Test
    fun aSyncThatAnsweredLandsQuietly() {
        assertEquals(FirstSync.Done, firstSyncOutcome(null))
    }

    @Test
    fun anUnreachableServerLandsOffline() {
        assertEquals(FirstSync.Offline, firstSyncOutcome(java.io.IOException("connection refused")))
    }

    @Test
    fun aStalledServerHitsTheSyncsOwnBoundAndLandsOffline() {
        // The sync's own bound, outside any other: its timeout is an IOException, never a cancellation.
        val timedOut = runBlocking { runCatching { runBounded(20L) { delay(60_000L) } }.exceptionOrNull() }
        assertEquals(FirstSync.Offline, firstSyncOutcome(timedOut))
    }

    @Test
    fun aRefusalLandsWithTheSyncCanonsSentence() {
        val refused = ApiException(500, "server_error", "boom")
        assertEquals(FirstSync.Failed(HouseholdCopy.forSyncError(refused)), firstSyncOutcome(refused))
    }

    @Test
    fun anUpgradePinStillRaisesTheBlockingScreen() {
        assertEquals(FirstSync.UpgradeRequired, firstSyncOutcome(UpgradeRequiredException("upgrade_required", "update")))
    }

    @Test
    fun aCancelledScopeIsNotAVerdict() {
        assertFailsWith<CancellationException> { firstSyncOutcome(CancellationException("the screen went away")) }
    }
}
