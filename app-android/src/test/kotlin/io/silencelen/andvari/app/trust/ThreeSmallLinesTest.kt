package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Three small things from Android's evening report: "the copy on this device is kept" only where a copy is kept; a
 * two-step answer at its own card; a vault whose name this phone does not know has a neutral mark.
 */
class ThreeSmallLinesTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    @Test
    fun aDeletionNobodyCanTellSaysTheCopyIsKeptOnlyWhileItIs() {
        val (api, m) = at(FakeScene.DELETION)
        api.script.deletionAnswerLost = true
        api.script.deletionHappenedAnyway = true
        val deletion = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        m.runIn(DELETION_SECTION, { settings.deleteAccount(deletion, deletion.email, FakeScenes.PASSWORD, null) }, { deletionWords(it, 0) }) { m.deletionAnswered(it) }
        m.onSnapshot(api.snapshot)
        val unknown = assertNotNull(assertNotNull(api.snapshot.account).deletion)
        m.runIn(DELETION_SECTION, { settings.checkDeletion(unknown) }, { deletionCheckWords(it, 0) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertTrue(m.deletionCannotTell(api.snapshot))
        assertTrue(m.deletionCopyKept(api.snapshot), "the lock screen's session is stored: the copy is kept")

        // Signed in again from the lock screen: the first screen, with that account's copy kept.
        api.signInAgain(assertNotNull(api.snapshot.locked))
        m.onSnapshot(api.snapshot)
        val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        if (first.deletionOutcomeUnknown == null) {
            assertTrue(m.deletionCopyKept(api.snapshot))
            assertEquals(Placeholder.DELETION_CANNOT_TELL, assertIs<UiText.Ph>(assertNotNull(deletionUnknownLine(first, m.deletionCannotTell(api.snapshot), m.deletionCopyKept(api.snapshot))).text).placeholder)
        }

        // That copy signed out (twice confirmed): no copy is kept, and the line says so.
        val ask = m.signOutAsk()
        ask.open()
        ask.confirm()
        ask.confirm()
        m.onSnapshot(api.snapshot)
        assertNull(api.snapshot.keptSignedOut)
        val after = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        assertTrue(m.deletionCannotTell(api.snapshot), "still nobody can tell")
        assertEquals(false, m.deletionCopyKept(api.snapshot))
        if (after.deletionOutcomeUnknown == null) {
            val line = assertNotNull(deletionUnknownLine(after, m.deletionCannotTell(api.snapshot), m.deletionCopyKept(api.snapshot)))
            assertEquals(Placeholder.DELETION_CANNOT_TELL_NO_COPY, assertIs<UiText.Ph>(line.text).placeholder)
        }
        assertEquals(Placeholder.DELETION_CANNOT_TELL_NO_COPY, appDeletionLine(copyKept = false))
        assertEquals(Placeholder.DELETION_CANNOT_TELL, appDeletionLine(copyKept = true))
    }

    @Test
    fun aTwoStepAnswerIsSaidAtItsOwnCardNotAtTheTopOfSettings() {
        val (api, m) = at(FakeScene.VAULTS)
        m.runIn(TWO_STEP_SECTION, { settings.openTwoStep() })
        val ts = assertNotNull(assertNotNull(api.snapshot.account).twoStep)
        m.runIn(TWO_STEP_SECTION, { settings.startTwoStep(ts, "not the password") })
        assertNotNull(m.saidIn(api.snapshot, TWO_STEP_SECTION), "said at the card")
        assertEquals(TWO_STEP_SECTION, assertNotNull(m.saidOn(api.snapshot)).section, "and not under the top of the page")

        val card = File("src/main/kotlin/io/silencelen/andvari/app/trust/SettingsScreens.kt").readText()
            .substringAfter("internal fun TwoStepSection(").substringBefore("\n}\n")
        assertTrue(card.contains("SaidIn(model, s, TWO_STEP_SECTION)"))
        for (call in listOf("settings.openTwoStep()", "settings.confirmTwoStep(", "settings.turnOffTwoStepWithPassword(", "settings.replaceTwoStepKey(", "settings.startTwoStep(")) {
            assertTrue(card.contains("model.runIn(TWO_STEP_SECTION, { $call"), call)
        }
        assertTrue("model.run({" !in card && "model.runSaying(" !in card, "no answer of the card goes to the top")
    }

    @Test
    fun aVaultWhoseNameThisPhoneDoesNotKnowHasANeutralMark() {
        val (api, _) = at(FakeScene.VAULTS)
        api.script.strangerSharesVault("Mallory")
        val stranger = assertNotNull(api.snapshot.account).vaults.single { it.log == VaultLogState.CONNECT_FIRST }
        assertNull(stranger.name)
        assertEquals(NAMELESS_VAULT_MARK, vaultRowMark(stranger))
        assertNotEquals(vaultRowName(stranger).first().uppercase(), vaultRowMark(stranger), "never a letter of the words that stand in for the name")
        for (row in assertNotNull(api.snapshot.account).vaults.filter { !it.name.isNullOrBlank() }) {
            assertEquals(row.name!!.trim().first().uppercase(), vaultRowMark(row))
        }
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultScreens.kt").readText().contains("vaultRowMark(v), color = MaterialTheme.colorScheme.primary"))
    }
}
