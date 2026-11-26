package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.CsvImportView
import io.silencelen.andvari.core.app.EntryApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The shared code's results that are new since the last round, each drawn where it arrives (a registration whose session
 * this phone refused for a fault of the account's identity or for a held operator account, a recovery's commit that did
 * not open here, a move's kept deletions), an import kept to be sent later drawn as no failure, and the work a lock
 * overtook told apart from work the server's end of the session overtook.
 */
class LateResultsAndOvertakenTest {
    private val newPassword = "a brand new master password"

    private fun model(api: io.silencelen.andvari.core.app.AppApi): TrustModel =
        TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also { it.onSnapshot(api.snapshot) }

    private fun fake(scene: FakeScene): FakeAppApi = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)

    private fun typeBack(api: FakeAppApi, m: TrustModel) {
        val reveal = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        val doc = assertNotNull(api.kit.kitDocument(reveal))
        m.act { kit.proceedToConfirm(reveal) }
        m.onSnapshot(api.snapshot)
        val confirm = assertIs<EntryScreen.Kit>(api.snapshot.entry).kit
        m.run({ kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }) })
        m.onSnapshot(api.snapshot)
    }

    // ---- item 2: the new results ----

    @Test
    fun aRegistrationRefusedHereAfterTheAccountWasMadeShowsItsOwnSentenceWithTheKitThenOnTheFirstScreen() {
        val cases = listOf(
            "self_identity_mismatch" to CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT,
            "operator_account_held" to CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD,
        )
        for ((reason, expected) in cases) {
            val api = fake(FakeScene.CREATE_ACCOUNT)
            val m = model(api)
            api.script.refusedAfterCommit = reason
            val screen = assertIs<EntryScreen.CreateAccount>(api.snapshot.entry)
            m.run({ entry.createAccount(screen, NewAccountInput("", "Ada", newPassword, true)) })
            m.onSnapshot(api.snapshot)
            val kit = assertIs<EntryScreen.Kit>(api.snapshot.entry, reason).kit
            assertEquals(expected.sentence, kit.notKeptLine, "the kit's line is the result's own sentence")
            val refusal = assertNotNull(m.kitRefusal.value, "the result goes with the kit: $reason")
            assertEquals(expected, refusal.result)
            assertNull(refusal.text, "said once")
            assertEquals(
                listOf(UiText.of(assertNotNull(expected.sentence)).shown(), UiText.of(assertNotNull(kit.notKeptHoldsLine)).shown()),
                kitRefusalLines(kit, refusal).map { it.shown() },
            )
            assertNull(m.saidOn(api.snapshot), "no way out over the kit")
            typeBack(api, m)
            assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
            val said = assertNotNull(m.saidOn(api.snapshot), "the first screen says it again: $reason")
            assertEquals(expected, said.result)
        }
        assertNull(wayOutFor(CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT), "an identity fault offers no sign-out and no removal")
        assertEquals(WayOut.HELD_OPERATOR_REMOVAL, wayOutFor(CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD), "the held account's removal, never a sign-out")
    }

    /**
     * The fake has no road for it, so the engine's is played by hand: its commit went through, its answer did not open,
     * the journey went back to the first screen (`reset`), and the answer is COMMITTED_NOT_OPENED.
     */
    @Test
    fun aRecoverysCommitThatDidNotOpenHereIsSaidOnTheFirstScreenItLandsOn() {
        val inner = fake(FakeScene.REPLACE_PASSWORD)
        val api = EngineLike(inner)
        api.entryOverride = object : EntryApi by inner.entry {
            override suspend fun chooseReplacementPassword(screen: EntryScreen.ReplacePassword, password: String): ReplacePasswordResult {
                inner.entry.startOver()
                return ReplacePasswordResult.COMMITTED_NOT_OPENED
            }
        }
        val m = model(api)
        val screen = assertIs<EntryScreen.ReplacePassword>(api.snapshot.entry)
        m.run({ entry.chooseReplacementPassword(screen, newPassword) })
        m.onSnapshot(api.snapshot)
        assertIs<EntryScreen.FirstRun>(api.snapshot.entry, "not left on the password step")
        val said = assertNotNull(m.saidOn(api.snapshot), "said where the person lands")
        assertEquals(ReplacePasswordResult.COMMITTED_NOT_OPENED, said.result)
        assertEquals(UiText.of(CopyKey.RECOVERY_COMMITTED_NOT_OPENED).shown(), said.text.shown())
        assertNull(wayOutFor(ReplacePasswordResult.COMMITTED_NOT_OPENED))
    }

    /** The fake's notice never counts kept deletions: its notice is rebuilt with them, as the engine makes it. */
    @Test
    fun aMovesNoticeSaysTheDeletionsItKeptAndCarriedWhereTheSharedCodeGivesThem() {
        val api = fake(FakeScene.VAULTS)
        val family = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL]).vaults.first { it.name == "Family" }
        family.moveUnfinishedInto = "Work"
        family.moveDeleteWaiting = true
        api.script.changed()
        assertTrue(api.script.serverStoresMoveDeleteLater(added = 2, changed = 1))
        val plain = assertNotNull(api.snapshot.account).movesStoredOutside.single()
        assertEquals(listOf(UiText.of(plain.line).shown()), moveStoredLines(plain).map { it.shown() }, "nothing more where nothing was kept")
        val kept = StandIns.line(CopyKey.MOVE_STORED_DELETIONS_KEPT, "3", "Work")
        val carried = StandIns.line(CopyKey.MOVE_STORED_DELETIONS_CARRIED, "1", "Work")
        val withKept = StandIns.rebuilt(plain, "deletionsKept" to 3, "keptLine" to kept)
        assertEquals(listOf(UiText.of(plain.line).shown(), UiText.of(kept).shown()), moveStoredLines(withKept).map { it.shown() })
        val withBoth = StandIns.rebuilt(withKept, "deletionsCarried" to 1, "carriedLine" to carried)
        assertEquals(
            listOf(UiText.of(plain.line).shown(), UiText.of(carried).shown(), UiText.of(kept).shown()),
            moveStoredLines(withBoth).map { it.shown() },
        )
        val view = File("src/main/kotlin/io/silencelen/andvari/app/trust/AccountScreens.kt").readText()
            .substringAfter("internal fun MoveStoredOutsideNotice(").substringBefore("\n}\n")
        assertTrue("for (line in moveStoredLines(n)) Say(line)" in view, "drawn with the notice, as information")
    }

    // ---- item 3: an import kept to be sent later ----

    private fun importView(error: String?, retryable: Boolean, kept: Boolean) = CsvImportView(
        source = "Chrome or another Chromium browser", vaultId = "v1", vaultName = "Personal", vaultChoices = emptyList(),
        toImport = 3, counts = emptyList(), buckets = emptyList(), errors = emptyList(), note = null, progress = null,
        busy = false, error = error, retryable = retryable, done = null, kept = kept,
    )

    @Test
    fun anImportKeptToBeSentLaterIsNoFailureAndOffersNoSecondRun() {
        val kept = importView("Kept on this device; sent when the server answers.", retryable = true, kept = true)
        assertFalse(importStopIsFailure(kept), "drawn in the plain colour")
        assertFalse(importCanRun(kept), "no second run, whatever retryable says")
        val failed = importView("The server refused it.", retryable = true, kept = false)
        assertTrue(importStopIsFailure(failed))
        assertTrue(importCanRun(failed), "a stop that can be retried still offers Try again")
        val view = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultTransferScreens.kt").readText()
            .substringAfter("internal fun ImportView(").substringBefore("\n}\n")
        assertTrue("v.error?.let { Say(UiText.Plain(it), color = if (importStopIsFailure(v)) MaterialTheme.colorScheme.error else" in view)
    }

    // ---- item 4: "andvari locked before this was done" only where a lock did it ----

    private fun open(): Pair<FakeAppApi, TrustModel> {
        val api = fake(FakeScene.LOCKED)
        val m = model(api)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    private fun said(api: FakeAppApi, m: TrustModel): Placeholder =
        assertIs<UiText.Ph>(assertNotNull(m.saidOn(api.snapshot), "said on the screen on show").text).placeholder

    @Test
    fun workTheServersEndOfTheSessionOvertookIsNotSaidAsALock() {
        // The intent throws "the keys are gone" because the server ended the session meanwhile.
        open().let { (api, m) ->
            m.run<PlainResult>({ api.script.sessionEndedByServer(); throw KeysGoneException() })
            assertEquals(true, api.snapshot.locked?.signedOutByServer, "the lock screen of a session the server ended")
            assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, said(api, m))
        }
        // It answers STALE for the same reason.
        open().let { (api, m) ->
            m.run({ api.script.sessionEndedByServer(); PlainResult.STALE })
            assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, said(api, m))
        }
        // A plain intent that throws it.
        open().let { (api, m) ->
            m.act { api.script.sessionEndedByServer(); throw KeysGoneException() }
            assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, said(api, m))
        }
        // A lock is still the lock.
        open().let { (api, m) ->
            m.run<PlainResult>({ lock(); throw KeysGoneException() })
            assertEquals(false, api.snapshot.locked?.signedOutByServer)
            assertEquals(Placeholder.LOCK_OVERTOOK, said(api, m))
        }
        // The first screen has nothing to unlock: never "do it again once you've unlocked".
        val first = fake(FakeScene.FIRST_RUN)
        assertEquals(Placeholder.SESSION_ENDED_OVERTOOK, model(first).overtookWords(first.snapshot))
        // Every place that says it decides through the one rule.
        val src = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustModel.kt").readText()
        assertTrue("UiText.ph(overtookWords(now, personEndedSinceAsk))" in src)
        assertFalse("UiText.ph(Placeholder.LOCK_OVERTOOK)" in src, "said only through overtookWords")
        val autofill = File("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillUnlockActivity.kt").readText()
        assertFalse("Placeholder.LOCK_OVERTOOK" in autofill, "the unlock window never says it: the unlock is what to do again")
        assertTrue("unlockFaultWords(t, model.api.snapshot)" in autofill)
    }
}
