package io.silencelen.andvari.core.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * One cause, one way out: every result of the journey that says one of the stops a thing kept here causes names one act,
 * the same for the same cause wherever it is said; and the lines said once a kit shown with a refusal is gone or typed
 * back never tell the person to save it.
 */
class KeptStopsTest {
    private val journeyResults: List<IntentResult> =
        ReplacePasswordResult.entries + KitRecoverResult.entries + KitScanResult.entries + SignInAnswer.entries +
            SignUpStartResult.entries + CreateAccountResult.entries + LinkPasswordResult.entries

    private fun named(vararg parts: String): List<IntentResult> = journeyResults.filter { r -> parts.any { it in (r as Enum<*>).name } }

    @Test
    fun aStopCausedByThisDevicesOwnCopyOffersItsRemovalEverywhere() {
        val own = named("SERVER_KEYS_NOT_KNOWN_HERE", "KEPT_COPY_DAMAGED")
        assertTrue(own.size >= 10, "found: $own")
        for (r in own) assertEquals(KeptWayOut.REMOVE_THIS_COPY, KeptStops.wayOut(r), "$r")
        for (e in listOf(LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE, LinkDeviceEnd.KEPT_COPY_DAMAGED)) {
            assertEquals(KeptWayOut.REMOVE_THIS_COPY, KeptStops.linkWayOut(e), "$e")
        }
    }

    @Test
    fun anotherAccountKeptOffersItsSignOutAndAHeldOperatorAccountItsRemoval() {
        for (r in named("ANOTHER_ACCOUNT_KEPT", "ANOTHER_SESSION_KEPT", "ACCOUNT_MADE_NOT_KEPT")) {
            assertEquals(KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, KeptStops.wayOut(r), "$r")
        }
        for (r in named("OPERATOR_ACCOUNT_HELD")) assertEquals(KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT, KeptStops.wayOut(r), "$r")
        assertEquals(KeptWayOut.SIGN_OUT_KEPT_ACCOUNT, KeptStops.linkWayOut(LinkDeviceEnd.ANOTHER_SESSION_KEPT))
        assertEquals(KeptWayOut.REMOVE_HELD_OPERATOR_ACCOUNT, KeptStops.linkWayOut(LinkDeviceEnd.OPERATOR_ACCOUNT_HELD))
    }

    @Test
    fun noWayOutIsOfferedWhereNothingKeptStandsInTheWay() {
        for (r in named("IDENTITY_FAULT", "NOT_THE_KEPT_ACCOUNT", "COMMITTED_NOT_KEPT", "COMMITTED_NOT_OPENED")) {
            assertNull(KeptStops.wayOut(r), "$r")
        }
        assertNull(KeptStops.linkWayOut(LinkDeviceEnd.IDENTITY_FAULT))
        assertNull(KeptStops.wayOut(ReplacePasswordResult.DONE))
    }

    @Test
    fun afterTheKitEachReasonHasALineOfItsOwnThatIsNotTheKitsLine() {
        val kitResults = listOf(
            ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, ReplacePasswordResult.IDENTITY_FAULT_COMMITTED,
            ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED, ReplacePasswordResult.COMMITTED_NOT_KEPT,
            ReplacePasswordResult.OPERATOR_ACCOUNT_HELD_COMMITTED, ReplacePasswordResult.KEPT_COPY_DAMAGED_COMMITTED,
            CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD, CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT,
        )
        val lines = kitResults.map { r ->
            val line = KeptStops.lineWithoutKit(r)!!
            assertTrue(line.name.startsWith("KIT_NOT_HERE_WHY_"), "$r: $line")
            assertNotEquals(KeeperReasons.kitLine(r), line, "$r")
            // The notice's line for the same kit is the same line, and its way out is the result's.
            val notice = KitWipedNotice.of(r is ReplacePasswordResult, "a@example.com", KeeperReasons.kitLine(r))
            assertEquals(line, notice.whyHere, "$r")
            assertEquals(KeptStops.wayOut(r), notice.wayOut, "$r")
            line
        }
        assertEquals(6, lines.toSet().size, "six reasons, six lines")
        // Results that bring no such kit have none.
        assertNull(KeptStops.lineWithoutKit(ReplacePasswordResult.STALE))
        assertNull(KeptStops.lineWithoutKit(ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE))
    }

    @Test
    fun aRecoveryThatWentThroughWhileAnotherAccountIsKeptNeverSaysNothingWasChanged() {
        val r = ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT
        assertEquals(CopyKey.RECOVERY_COMMITTED_ANOTHER_ACCOUNT_KEPT, r.sentence)
        assertNotEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED.sentence, r.sentence)
        assertEquals(CopyKey.KIT_RECOVERED_NOT_KEPT, KeeperReasons.kitLine(r), "the kit's own line stays")
    }
}
