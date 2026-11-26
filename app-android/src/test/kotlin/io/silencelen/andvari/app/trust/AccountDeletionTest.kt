package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Settings › Delete account on the real calls, with every end. */
class AccountDeletionTest {
    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun FakeAppApi.deletion(): DeletionScreen = assertNotNull(assertNotNull(snapshot.account).deletion)

    /** As the section's button does it. */
    private fun TrustModel.delete(api: FakeAppApi, email: String, password: String, code: String? = null) {
        val screen = api.deletion()
        runIn(DELETION_SECTION, { settings.deleteAccount(screen, email, password, code) }, { deletionWords(it, 0) }) { deletionAnswered(it) }
        onSnapshot(api.snapshot)
    }

    private fun ph(m: TrustModel, api: FakeAppApi): Placeholder = (assertNotNull(m.saidIn(api.snapshot, DELETION_SECTION)).text as UiText.Ph).placeholder

    @Test
    fun thePlanNamesEachVaultAndAnUnreadableNameIsSaidToBeSo() {
        val (api, _) = at(FakeScene.DELETION)
        val plan = assertNotNull(api.deletion().plan)
        assertTrue(plan.deletedVaults.isNotEmpty())
        for (name in plan.deletedVaults) assertTrue(deletionGoesLine(name).shown().contains(name), name)
        assertEquals(Placeholder.DELETION_VAULT_GOES_UNREADABLE, (deletionGoesLine("") as UiText.Ph).placeholder)
        assertEquals(Placeholder.DELETION_VAULT_LEFT_UNREADABLE, (deletionLeftLine(" ") as UiText.Ph).placeholder)
        assertEquals(listOf("Family"), (deletionLeftLine("Family") as UiText.Ph).args)
        val section = File("src/main/kotlin/io/silencelen/andvari/app/trust/SettingsScreens.kt").readText()
            .substringAfter("internal fun DeleteAccountSection(").substringBefore("\n}\n")
        assertTrue(section.contains("for (name in plan.deletedVaults) Say(deletionGoesLine(name))"))
        assertTrue(section.contains("for (name in plan.leftVaults) Say(deletionLeftLine(name))"))
        assertTrue(section.contains("Placeholder.DELETION_CANNOT_UNDO"))
        assertFalse(section.contains("joinToString"), "one line per vault")
    }

    @Test
    fun eachBlockerSaysWhatToDoFirstAndNothingGoesPastIt() {
        val (api, _) = at(FakeScene.DELETION_BLOCKED)
        val screen = api.deletion()
        val plan = assertNotNull(screen.plan)
        assertFalse(plan.canProceed)
        // Each blocker's line and what to do first are named by their keys, so this holds whatever their words are.
        val lines = mapOf(
            io.silencelen.andvari.core.app.DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS to setOf(
                Placeholder.DELETION_BLOCKER_SHARED, Placeholder.DELETION_BLOCKER_SHARED_UNREADABLE,
                Placeholder.DELETION_BLOCKER_SHARED_ONE, Placeholder.DELETION_BLOCKER_SHARED_UNREADABLE_ONE,
            ),
            io.silencelen.andvari.core.app.DeletionBlockerKind.OPERATOR_ACCOUNT to setOf(Placeholder.DELETION_BLOCKER_OPERATOR),
            io.silencelen.andvari.core.app.DeletionBlockerKind.NOT_KNOWN to setOf(Placeholder.DELETION_BLOCKER_UNKNOWN),
        )
        val firsts = mapOf(
            io.silencelen.andvari.core.app.DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS to Placeholder.DELETION_BLOCKER_SHARED_DO,
            io.silencelen.andvari.core.app.DeletionBlockerKind.OPERATOR_ACCOUNT to Placeholder.DELETION_BLOCKER_OPERATOR_DO,
            io.silencelen.andvari.core.app.DeletionBlockerKind.NOT_KNOWN to Placeholder.DELETION_BLOCKER_UNKNOWN_DO,
        )
        for (b in plan.blockers) {
            assertTrue(assertIs<UiText.Ph>(deletionBlockerLine(b)).placeholder in assertNotNull(lines[b.kind]), b.kind.name)
            assertEquals(firsts[b.kind], assertIs<UiText.Ph>(deletionBlockerDo(b)).placeholder, b.kind.name)
            if (b.vaultName.isNullOrBlank() && b.kind == io.silencelen.andvari.core.app.DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS) {
                assertEquals(
                    if (b.others == 1) Placeholder.DELETION_BLOCKER_SHARED_UNREADABLE_ONE else Placeholder.DELETION_BLOCKER_SHARED_UNREADABLE,
                    (deletionBlockerLine(b) as UiText.Ph).placeholder,
                )
            }
        }
        assertFalse(deletionReady(screen, screen.email, FakeScenes.PASSWORD, "246810", codeAsked = true))
    }

    @Test
    fun theTypedAddressMustMatchAndEachRefusalHasItsLine() {
        val (api, m) = at(FakeScene.DELETION)
        val screen = api.deletion()
        assertTrue(typedEmailMatches(screen.email, "  " + screen.email.uppercase() + " "), "trimmed and case-folded")
        assertFalse(deletionReady(screen, "someone.else@example.com", FakeScenes.PASSWORD, ""), "the button waits for the address")
        assertTrue(deletionReady(screen, screen.email, FakeScenes.PASSWORD, ""))
        assertFalse(deletionReady(screen, screen.email, FakeScenes.PASSWORD, "", codeAsked = true), "a code once it is asked for")

        m.delete(api, "someone.else@example.com", FakeScenes.PASSWORD)
        assertEquals(Placeholder.DELETION_EMAIL_MISMATCH, ph(m, api))
        m.delete(api, screen.email, "wrong")
        assertEquals(Placeholder.DELETION_WRONG_PASSWORD, ph(m, api))
        api.script.deletionFarFutureHead = true
        m.delete(api, screen.email, FakeScenes.PASSWORD)
        assertEquals(CopyKey.DELETION_FAR_FUTURE.english, assertNotNull(m.saidIn(api.snapshot, DELETION_SECTION)).text.shown())
        api.script.deletionFarFutureHead = false
        api.script.deletionStaleRounds = 3
        m.delete(api, screen.email, FakeScenes.PASSWORD)
        assertEquals(Placeholder.DELETION_STILL_CHANGING, ph(m, api))
        assertFalse(api.deletion().retrying, "the retrying state ends with the run")
        api.script.forceNext(DeletionResult.BLOCKED)
        m.delete(api, screen.email, FakeScenes.PASSWORD)
        assertEquals(Placeholder.DELETION_BLOCKED, ph(m, api))
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNull(m.saidOn(api.snapshot)?.takeIf { it.section == null }, "said in the section only")

        // Every refusal of its own is told apart, and only DONE could ever read as deleted.
        val lines = DeletionResult.entries.mapNotNull { deletionWords(it, 0)?.shown() }
        assertEquals(lines.size, lines.toSet().size)
        assertNull(deletionWords(DeletionResult.DONE, 0))
        assertNull(deletionWords(DeletionResult.OUTCOME_UNKNOWN, 0), "the screen's state says it, never as done or failed")
    }

    @Test
    fun aDeletionThatIsDoneLandsOnTheFirstScreenWhichSaysSo() {
        val (api, m) = at(FakeScene.DELETION)
        m.delete(api, FakeScenes.EMAIL, FakeScenes.PASSWORD)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        // The shared code's notice, not the app's own flag: its line, named by its key, as the shared code fills it.
        val notice = assertNotNull(first.accountDeleted)
        assertEquals(FakeScenes.EMAIL, notice.email)
        // A confirmed deletion forgets the server too where no other account's copy is held there: the line says so.
        assertTrue(notice.serverForgotten)
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_FORGOTTEN, notice.line.key)
        val line = assertNotNull(accountDeletedLine(first))
        assertEquals(UiText.of(notice.line).shown(), line.shown())
        assertTrue(line.shown().contains(FakeScenes.EMAIL) && line.shown().contains(notice.instance.origin), line.shown())
        assertFalse(m.deletionCannotTell(api.snapshot))
        m.act { entry.dismissNotice(first) }
        assertNull(assertIs<EntryScreen.FirstRun>(api.snapshot.entry).accountDeleted, "once: the dismiss clears it")
        assertNull(accountDeletedLine(assertIs(api.snapshot.entry)))
        val screen = File("src/main/kotlin/io/silencelen/andvari/app/trust/EntryScreens.kt").readText()
        assertTrue(screen.contains("accountDeletedLine(screen)?.let { line ->"))
        assertTrue(screen.contains("{ model.act { entry.dismissNotice(screen) } }\n            Gap()\n        }\n        // An outcome nobody can tell yet"))
        assertFalse(screen.contains("Placeholder.ACCOUNT_DELETED"), "the app's own line is gone")
    }

    /**
     * A confirmed deletion where this phone keeps records of another account at the server (decided on 2026-11-19): only
     * the deleted account's records go, the server stays known, and the first screen's line says so, as the shared code's
     * fake plays the engine.
     */
    @Test
    fun aDeletionWhereAnotherAccountIsKnownAtTheServerKeepsTheServerAndSaysSo() {
        val (api, m) = at(FakeScene.DELETION)
        api.script.anotherAccountKnownAtServer = true
        m.delete(api, FakeScenes.EMAIL, FakeScenes.PASSWORD)
        val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        val notice = assertNotNull(first.accountDeleted)
        assertFalse(notice.serverForgotten, "the server stays known")
        assertEquals(CopyKey.ACCOUNT_DELETED_SERVER_KEPT, notice.line.key)
        val line = assertNotNull(accountDeletedLine(first))
        WalkPrint.draws("a1 the first screen's notice", listOf(line))
        assertEquals(UiText.of(notice.line).shown(), line.shown(), "drawn as handed")
        assertTrue(FakeScenes.EMAIL in notice.line.values && notice.instance.origin in notice.line.values, "the account and its server, named")

        // a1. Nothing said beside it: no answer in place, no other notice of the first screen.
        val beside = listOfNotNull(
            m.saidOn(api.snapshot)?.text,
            sessionNotConfirmedLine(first),
            deletionUnknownLine(first, m.deletionCannotTell(api.snapshot), m.deletionCopyKept(api.snapshot))?.text,
        )
        WalkPrint.draws("a1 said beside it", beside)
        assertEquals(emptyList(), beside.map { it.shown() }, "nothing said beside the notice")
        assertNull(first.notice)
        assertNull(first.lateRecovery)
        // Nothing offers to forget anything: no earlier account, no forgetting after a deletion of unknown outcome.
        assertNull(api.snapshot.earlierAccount, "no offer to forget an earlier account")
        assertNull(m.forgetUnknownCheck(), "no offer to forget after an unknown deletion")
        assertNull(first.deletionOutcomeUnknown)
        WalkPrint.note("a1 the first screen's buttons", firstRunChoices(first).map { it.label.shown() } + UiText.of(CopyKey.FIRST_SIGN_IN).shown() + UiText.ph(Placeholder.DISMISS).shown())

        // a2. The dismiss: the notice goes, and nothing is said.
        m.act { entry.dismissNotice(first) }
        m.onSnapshot(api.snapshot)
        val after = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        WalkPrint.draws("a2 after the dismiss", listOf(accountDeletedLine(after), m.saidOn(api.snapshot)?.text))
        assertNull(accountDeletedLine(after))
        assertNull(m.saidOn(api.snapshot))
        assertNull(api.snapshot.earlierAccount)
        assertNull(m.forgetUnknownCheck())

        // a3. Behind it: the sign-in, at that same server; nothing offers to forget there either.
        m.act { entry.openSignIn(after) }
        m.onSnapshot(api.snapshot)
        assertNull(api.snapshot.earlierAccount, "the sign-in's choice: no offer")
        m.act { entry.openPasswordSignIn(assertIs(snapshot.entry)) }
        var chosen: io.silencelen.andvari.core.app.IntentResult? = null
        runBlocking { m.run({ entry.choosePublicInstance(assertIs(snapshot.entry)) }) { chosen = it }.join() }
        m.onSnapshot(api.snapshot)
        assertEquals(io.silencelen.andvari.core.app.ServerResult.DONE, chosen)
        assertIs<EntryScreen.SignIn>(api.snapshot.entry)
        WalkPrint.draws("a3 the sign-in at that server, said", listOf(m.saidOn(api.snapshot)?.text))
        assertNull(m.saidOn(api.snapshot))
        assertNull(api.snapshot.earlierAccount, "the sign-in at that server: no offer")
        assertNull(m.forgetUnknownCheck())
    }

    /**
     * The deletion's answer is lost: the deletion's section offers to forget the account on this phone; its second step
     * says the shared code's confirmation and its count of changes not sent. A lock takes that step back and the step of
     * before the lock sends nothing; the lock screen offers a NEW check object, whose count is what this phone can tell
     * with the copy closed, and its second step draws that object's lines. The person's confirmation answers with the
     * first screen, which says nothing of its own.
     */
    @Test
    fun theOfferAfterADeletionOfUnknownOutcomeAcrossALockWithItsCountItsLinesAndItsAnswer() {
        val (api, m) = at(FakeScene.DELETION)
        api.script.deletionAnswerLost = true
        m.delete(api, FakeScenes.EMAIL, FakeScenes.PASSWORD)
        assertTrue(api.deletion().outcomeUnknown)

        // c1. The deletion's section: its own line, the offer; then the offer's second step.
        val open = assertNotNull(m.forgetUnknownCheck(), "the offer")
        assertEquals(CopyKey.DELETION_UNKNOWN_FORGET_OFFER, open.offerLine.key)
        WalkPrint.draws("c1 the deletion's section", listOf(UiText.ph(Placeholder.DELETION_OUTCOME_UNKNOWN), m.saidIn(api.snapshot, DELETION_SECTION)?.text, UiText.ph(Placeholder.DELETION_CHECK), UiText.of(open.offerLine)))
        assertNull(m.saidIn(api.snapshot, DELETION_SECTION), "the section's own state says it; nothing beside it")
        m.askToForgetUnknownDeletion()
        assertSame(open, m.forgetUnknownAsked.value)
        WalkPrint.note("c1 the count of changes not sent, the copy open", open.unsentChanges)
        val openLines = forgetUnknownLines(open, confirming = true)
        WalkPrint.draws("c1 the second step", openLines + listOf(UiText.ph(Placeholder.FORGET_UNKNOWN_DELETION_CONFIRM), UiText.of(CopyKey.CANCEL)))
        assertEquals(listOf(UiText.of(open.confirmLine).shown(), UiText.of(open.unsentLine).shown()), openLines.map { it.shown() })
        assertTrue(openLines.none { WalkPrint.isBare(it) })

        // c2. A lock: the second step goes back; its button, pressed from before the lock, sends nothing.
        m.act { lock() }
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertNull(m.forgetUnknownAsked.value, "the lock took the second step back")
        m.forgetUnknownDeletion()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the step of before the lock sent nothing")
        assertEquals(io.silencelen.andvari.core.app.PlainResult.STALE, runBlocking { api.forgetAfterUnknownDeletion(open) }, "the object of before the lock is not taken")
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        val locked = assertNotNull(api.snapshot.locked)
        assertTrue(locked.deletionOutcomeUnknown)
        val onLock = assertNotNull(m.forgetUnknownCheck(), "the lock screen's offer")
        assertTrue(onLock !== open, "a new check object")
        WalkPrint.draws("c2 the lock screen", listOf(lockDeletionLine(locked.deletionOutcomeUnknown, m.deletionCannotTell(api.snapshot)), m.saidOn(api.snapshot)?.text, UiText.of(onLock.offerLine)))
        WalkPrint.note("c2 the count of changes not sent, the copy closed", onLock.unsentChanges)
        assertNull(onLock.unsentChanges, "with the copy closed this phone cannot tell")
        assertNull(m.saidOn(api.snapshot))

        // c3. Its second step: the new object's confirmation and count.
        m.askToForgetUnknownDeletion()
        assertSame(onLock, m.forgetUnknownAsked.value)
        val lockLines = forgetUnknownLines(onLock, confirming = true)
        WalkPrint.draws("c3 the second step after the lock", lockLines + listOf(UiText.ph(Placeholder.FORGET_UNKNOWN_DELETION_CONFIRM), UiText.of(CopyKey.CANCEL)))
        assertEquals(listOf(CopyKey.DELETION_UNKNOWN_FORGET_CONFIRM, CopyKey.DELETION_UNKNOWN_FORGET_UNSENT_CANNOT_TELL), listOf(onLock.confirmLine.key, onLock.unsentLine.key))
        assertEquals(listOf(UiText.of(onLock.confirmLine).shown(), UiText.of(onLock.unsentLine).shown()), lockLines.map { it.shown() })
        assertTrue(FakeScenes.EMAIL in onLock.confirmLine.values, "the account named")
        assertTrue(lockLines.none { WalkPrint.isBare(it) })

        // c4. The person's confirmation: the first screen, the account gone from this phone; nothing said of its own.
        m.forgetUnknownDeletion()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        WalkPrint.draws("c4 the answer, the first screen", listOf(m.saidOn(api.snapshot)?.text, accountDeletedLine(first), deletionUnknownLine(first, m.deletionCannotTell(api.snapshot), m.deletionCopyKept(api.snapshot))?.text))
        assertNull(m.saidOn(api.snapshot))
        assertNull(api.snapshot.keptSignedOut, "the account is gone from this phone")
        assertNull(m.forgetUnknownCheck(), "no offer any more")
        assertNull(m.forgetUnknownAsked.value)
        assertNull(first.deletionOutcomeUnknown)
        assertNull(first.accountDeleted, "never \"deleted\"")
        // The person was told at the confirmation; this phone has forgotten the account and will never learn the outcome,
        // so "can't tell yet" is no longer so: nothing is said of it (decided on 21 November 2026).
        assertNull(deletionUnknownLine(first, m.deletionCannotTell(api.snapshot), m.deletionCopyKept(api.snapshot)), "nothing of \"can't tell yet\"")
        assertFalse(m.deletionCannotTell(api.snapshot))
    }

    /** The same forgetting from the deletion's own section, with the copy open: the first screen says nothing of it. */
    @Test
    fun afterForgettingFromTheDeletionsSectionTheFirstScreenSaysNothingOfCantTellYet() {
        val (api, m) = at(FakeScene.DELETION)
        api.script.deletionAnswerLost = true
        m.delete(api, FakeScenes.EMAIL, FakeScenes.PASSWORD)
        assertTrue(api.deletion().outcomeUnknown)
        m.askToForgetUnknownDeletion()
        assertNotNull(m.forgetUnknownAsked.value)
        m.forgetUnknownDeletion(DELETION_SECTION)
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        val first = assertIs<EntryScreen.FirstRun>(api.snapshot.entry)
        val line = deletionUnknownLine(first, m.deletionCannotTell(api.snapshot), m.deletionCopyKept(api.snapshot))
        WalkPrint.draws("the first screen after forgetting from the deletion's section", listOf(m.saidOn(api.snapshot)?.text, accountDeletedLine(first), line?.text))
        assertNull(line, "nothing of \"can't tell yet\"")
        assertNull(m.saidOn(api.snapshot))
        assertNull(accountDeletedLine(first), "never \"deleted\"")
        assertFalse(m.deletionCannotTell(api.snapshot))
        // Nor after the person goes to the sign-in and back.
        m.act { entry.openSignIn(first) }
        m.onSnapshot(api.snapshot)
        assertFalse(m.deletionCannotTell(api.snapshot))
    }

    @Test
    fun anUnknownOutcomeIsNeverDeletedAndTheCheckSaysTheAccountIsThere() {
        val (api, m) = at(FakeScene.DELETION)
        api.script.deletionAnswerLost = true
        m.delete(api, FakeScenes.EMAIL, FakeScenes.PASSWORD)
        assertTrue(api.deletion().outcomeUnknown)
        assertNull(m.saidIn(api.snapshot, DELETION_SECTION), "the screen's own state says it cannot tell")
        assertNull((api.snapshot.entry as? EntryScreen.FirstRun)?.accountDeleted)
        assertFalse(deletionReady(api.deletion(), FakeScenes.EMAIL, FakeScenes.PASSWORD, ""), "only the check is offered")

        val screen = api.deletion()
        m.runIn(DELETION_SECTION, { settings.checkDeletion(screen) }, { deletionCheckWords(it, 0) })
        m.onSnapshot(api.snapshot)
        assertFalse(api.deletion().outcomeUnknown)
        assertEquals(Placeholder.DELETION_CHECKED_STILL_THERE, ph(m, api))
        m.act { lock() }
        m.onSnapshot(api.snapshot)
        assertFalse(m.deletionCannotTell(api.snapshot), "the check said the account is there")
    }

    @Test
    fun anUnknownOutcomeWhoseCheckEndsTheSessionCannotTellOnTheLockScreen() {
        val (api, m) = at(FakeScene.DELETION)
        api.script.deletionAnswerLost = true
        api.script.deletionHappenedAnyway = true
        m.delete(api, FakeScenes.EMAIL, FakeScenes.PASSWORD)
        val screen = api.deletion()
        m.runIn(DELETION_SECTION, { settings.checkDeletion(screen) }, { deletionCheckWords(it, 0) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertTrue(assertNotNull(api.snapshot.locked).signedOutByServer)
        assertTrue(m.deletionCannotTell(api.snapshot), "the lock screen says andvari cannot tell yet")
        assertNull((api.snapshot.entry as? EntryScreen.FirstRun)?.accountDeleted, "never deleted")
        assertTrue(Placeholder.DELETION_CANNOT_TELL.gloss.contains("can't tell"))
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/trust/AccountScreens.kt").readText().contains("lockDeletionLine(locked.deletionOutcomeUnknown, model.deletionCannotTell(s))?.let { Say(it,"))
        assertEquals(Placeholder.DELETION_CANNOT_TELL, (lockDeletionLine(coreSaysUnknown = false, appCannotTell = true) as UiText.Ph).placeholder)
        // The first screen: the shared code's notice where it gives one, the app's own line only otherwise.
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/trust/EntryScreens.kt").readText().contains("deletionUnknownLine(screen, model.deletionCannotTell(s), model.deletionCopyKept(s))?.let { line ->"))
    }
}
