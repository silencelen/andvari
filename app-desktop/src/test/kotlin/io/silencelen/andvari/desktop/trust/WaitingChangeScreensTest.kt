package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.WaitingChange
import io.silencelen.andvari.core.app.WaitingChanges
import io.silencelen.andvari.core.app.WaitingKind
import io.silencelen.andvari.core.app.WaitingKnown
import io.silencelen.andvari.core.app.WaitingNotice
import io.silencelen.andvari.core.app.WaitingResult
import io.silencelen.andvari.core.app.WaitingUndo
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeScript
import io.silencelen.andvari.core.trust.MemberRole
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * A change to a shared vault that waits, on the Sharing page, over the stand-in: every state of the row, every result of
 * its two acts, every notice and its undo, and closing a move stopped on a frozen old vault. A result or an undo the
 * shared code adds later has no row here and turns this test red until it is drawn. And the four things a screen must
 * never do here: offer a button the row does not offer; draw a line of its own where the shared code hands one; say
 * anything for STALE; hand an act anything but the very object it drew.
 */
class WaitingChangeScreensTest {
    /** What is drawn in place after an act answered. */
    private enum class Answer { SENTENCE, NOTHING, TROUBLE }

    private val answers: Map<WaitingResult, Answer> = mapOf(
        WaitingResult.WITHDRAWN_NOT_MADE to Answer.SENTENCE,
        WaitingResult.WITHDRAWN_MAY_BE_MADE to Answer.SENTENCE,
        WaitingResult.KEPT_NOT_DELETED to Answer.SENTENCE,
        WaitingResult.KEPT_MAY_BE_DELETED to Answer.SENTENCE,
        WaitingResult.DELETED to Answer.SENTENCE,
        WaitingResult.DELETE_STILL_WAITING to Answer.SENTENCE,
        WaitingResult.DELETE_DID_NOT_HAPPEN to Answer.SENTENCE,
        WaitingResult.DELETE_REFUSED to Answer.SENTENCE,
        WaitingResult.DELETE_REFUSED_CANNOT_TELL to Answer.SENTENCE,
        WaitingResult.MOVE_IN_PROGRESS to Answer.SENTENCE,
        WaitingResult.DELETE_GIVEN_UP to Answer.SENTENCE,
        WaitingResult.STILL_SENDING to Answer.SENTENCE,
        WaitingResult.SERVER_SAYS_STORED to Answer.SENTENCE,
        WaitingResult.NOTHING_WAITING to Answer.SENTENCE,
        WaitingResult.NOT_OFFERED to Answer.SENTENCE,
        WaitingResult.RECORD_UNREADABLE to Answer.SENTENCE,
        WaitingResult.FROZEN to Answer.SENTENCE,
        WaitingResult.STALE to Answer.NOTHING,
        WaitingResult.UNREACHABLE to Answer.TROUBLE,
        WaitingResult.FAILED to Answer.TROUBLE,
    )

    /** The label of each undo a notice can offer: the ordinary act's own. */
    private val undoLabels: Map<WaitingUndo, Placeholder> = mapOf(
        WaitingUndo.REMOVE_MEMBER to Placeholder.VAULT_REMOVE_MEMBER,
        WaitingUndo.ADD_MEMBER to Placeholder.VAULT_ADD_THIS_PERSON,
        WaitingUndo.CHANGE_ROLE_BACK to Placeholder.WAITING_UNDO_ROLE_BACK,
        WaitingUndo.CANCEL_OFFER to Placeholder.VAULT_CANCEL_OFFER,
        WaitingUndo.RESTORE_VAULT to Placeholder.VAULT_RESTORE,
    )

    // ---- the scene ----

    private fun at(): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    private fun family(api: FakeDesktopAppApi): SharedVaultRow = assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }

    private fun waiting(api: FakeDesktopAppApi): WaitingChange = assertNotNull(family(api).waiting, "a change waits on Family")

    /** The account id of Family's member called [label] (a contact) or of the one the server names (null). */
    private fun memberId(api: FakeDesktopAppApi, m: TrustModel, label: String?): String {
        m.run({ vaults.openMembers(family(api)) })
        val members = assertNotNull(api.snapshot.account?.members).members
        return members.first { if (label == null) it.who is PersonName.Unverified else (it.who as? PersonName.Contact)?.label == label }.userId
    }

    private fun roleOf(api: FakeDesktopAppApi, m: TrustModel, id: String): RoleInVault? {
        m.run({ vaults.openMembers(family(api)) })
        return assertNotNull(api.snapshot.account?.members).members.firstOrNull { it.userId == id }?.role
    }

    private fun said(m: TrustModel): UiText? = m.said.value?.text

    private fun notices(api: FakeDesktopAppApi): List<WaitingNotice> = assertNotNull(api.snapshot.account).waitingNotices

    /** What the Sharing page drew in one frame: each row's waiting part, each notice, each move to close, with their taps. */
    private class Drawn : WaitingTaps {
        val rows = LinkedHashMap<String, Pair<WaitingDrawn, (WaitingAct) -> Unit>>()
        val rowObjects = LinkedHashMap<String, SharedVaultRow>()
        val notices = ArrayList<NoticeDrawn>()
        val moves = LinkedHashMap<String, Pair<UiText, () -> Unit>>()

        class NoticeDrawn(val notice: WaitingNotice, val lines: List<UiText>, val undo: UiText?, val act: () -> Unit, val dismiss: () -> Unit)

        override fun row(v: SharedVaultRow, drawn: WaitingDrawn, tap: (WaitingAct) -> Unit) {
            rows[v.name ?: v.vaultId] = drawn to tap
            rowObjects[v.name ?: v.vaultId] = v
        }

        override fun notice(n: WaitingNotice, lines: List<UiText>, undo: UiText?, act: () -> Unit, dismiss: () -> Unit) {
            notices += NoticeDrawn(n, lines, undo, act, dismiss)
        }

        override fun frozenMove(v: SharedVaultRow, line: UiText, close: () -> Unit) {
            moves[v.name ?: v.vaultId] = line to close
        }
    }

    /** The Sharing page's vaults and the notices, drawn once from the snapshot on show. */
    private fun draw(api: FakeDesktopAppApi, m: TrustModel): Drawn {
        val drawn = Drawn()
        m.onSnapshot(api.snapshot)
        val s = api.snapshot
        val account = assertNotNull(s.account)
        val scene = androidx.compose.ui.ImageComposeScene(700, 8000, androidx.compose.ui.unit.Density(1f)) {
            androidx.compose.runtime.CompositionLocalProvider(LocalWaitingTaps provides drawn) {
                androidx.compose.material3.MaterialTheme {
                    androidx.compose.foundation.layout.Column {
                        SharedVaultsSection(m, s, account)
                        for (n in account.waitingNotices) WaitingNoticeCard(m, s, n)
                    }
                }
            }
        }
        try {
            scene.render()
        } finally {
            scene.close()
        }
        return drawn
    }

    /** Records what each act was handed, then does as the stand-in does; [before] runs first (a lock, say). */
    private class Recording(private val inner: WaitingChanges, private val before: () -> Unit = {}) : WaitingChanges {
        val handed = ArrayList<Any>()

        override suspend fun withdrawWaiting(change: WaitingChange): WaitingResult {
            handed += change
            before()
            return inner.withdrawWaiting(change)
        }

        override suspend fun deleteWaitingNow(change: WaitingChange): WaitingResult {
            handed += change
            before()
            return inner.deleteWaitingNow(change)
        }

        override fun dismissWaitingNotice(notice: WaitingNotice) {
            handed += notice
            inner.dismissWaitingNotice(notice)
        }

        override fun closeFrozenMove(vault: SharedVaultRow): VaultActionResult {
            handed += vault
            return inner.closeFrozenMove(vault)
        }
    }

    private fun recording(api: FakeDesktopAppApi, m: TrustModel, before: () -> Unit = {}): Recording =
        Recording(api.vaults as WaitingChanges, before).also { r -> m.waitingActs = { r } }

    /** Asserts what is said in place for [r] after an act. */
    private fun assertAnswer(where: String, r: WaitingResult, text: UiText?) {
        when (assertNotNull(answers[r], "no row for ${r.name}")) {
            Answer.NOTHING -> assertNull(text, "$where, ${r.name}: nothing is said")
            Answer.SENTENCE -> {
                val line = assertNotNull(text, "$where, ${r.name}: its sentence is drawn, also where it means done")
                assertEquals(UiText.of(assertNotNull(r.sentence)).shown(), line.shown(), "$where, ${r.name}")
                assertFalse(line is UiText.Ph, "$where, ${r.name}: the shared code's sentence, never a line of the desktop's own")
            }
            Answer.TROUBLE -> {
                val trouble = assertNotNull(r.trouble)
                val expected = if (trouble == Trouble.UNREACHABLE) Placeholder.TROUBLE_UNREACHABLE else Placeholder.TROUBLE
                assertEquals(expected, assertIs<UiText.Ph>(text, "$where, ${r.name}").placeholder, "$where, ${r.name}")
            }
        }
    }

    // ---- every result ----

    @Test
    fun everyResultHasItsRowHereSoThatOneAddedLaterIsDrawnBeforeThisPasses() {
        assertEquals(WaitingResult.entries.toSet(), answers.keys, "a result of the shared code without a row here: draw it, then give it its row")
        for ((r, a) in answers) {
            if (a == Answer.SENTENCE) assertNotNull(r.sentence, "${r.name} has a sentence of its own")
        }
    }

    @Test
    fun everyResultOfWithdrawAndOfDeleteItNowIsDrawnByItsRow() {
        for (act in WaitingAct.entries) {
            for (r in WaitingResult.entries) {
                val (api, m) = at()
                assertTrue(api.script.changeWaits("Family", WaitingKind.DELETION))
                assertTrue(api.script.waitingDeletionLooked("Family"))
                val w = waiting(api)
                api.script.forceNext(r)
                m.actOnWaiting(w, act)
                val text = said(m)
                println("WAITING|${act.name}|${r.name}|${text?.shown() ?: "(nothing)"}")
                assertAnswer(act.name, r, text)
            }
        }
    }

    // ---- every state of the row, with the stand-in's own answers ----

    @Test
    fun aMembersChangeThatMayBeMadeIsDrawnWithItsMemberAndWithdrawnWithItsOwnSentenceAndANotice() {
        for ((kind, role) in listOf(WaitingKind.ADD to RoleInVault.READER, WaitingKind.REMOVE to null, WaitingKind.ROLE to RoleInVault.READER, WaitingKind.OFFER to null)) {
            val (api, m) = at()
            val bo = memberId(api, m, "Bo")
            assertTrue(api.script.changeWaits("Family", kind, WaitingKnown.CANNOT_TELL, bo, role))
            val w = waiting(api)
            assertEquals(CopyKey.WAITING_MAY_BE_MADE, w.line.key, kind.name)
            val drawn = draw(api, m)
            val (view, tap) = assertNotNull(drawn.rows["Family"], kind.name)
            assertEquals(UiText.of(w.line).shown(), view.lines[0].shown(), kind.name)
            assertEquals("Bo" + (role?.let { "  ·  " + it.name.lowercase() } ?: ""), view.lines[1].shown(), "${kind.name}: the member it names, with the role it gives")
            assertEquals(2, view.lines.size, "${kind.name}: nothing is being sent")
            assertNull(view.ask)
            assertEquals(listOf(WaitingAct.WITHDRAW), view.buttons.map { it.act }, kind.name)
            assertEquals(UiText.of(CopyKey.WAITING_WITHDRAW).shown(), view.buttons.single().label.shown())
            tap(WaitingAct.WITHDRAW)
            assertAnswer(kind.name, WaitingResult.WITHDRAWN_MAY_BE_MADE, said(m))
            assertNull(family(api).waiting, "${kind.name}: withdrawn")
            val notice = notices(api).single()
            assertEquals(CopyKey.WAITING_FOUND_NOT_MADE_YET, notice.line.key, "${kind.name}: the read that follows says what it found")
            assertNull(undoLabel(notice), "${kind.name}: no undo on a notice that offers none")
        }
    }

    @Test
    fun aChangeKnownNotMadeIsWithdrawnAsNotMadeAndOneTheServerSaysItStoredOffersNoButton() {
        val (api, m) = at()
        val bo = memberId(api, m, "Bo")
        api.script.changeWaits("Family", WaitingKind.REMOVE, WaitingKnown.NOT_STORED, bo)
        assertEquals(CopyKey.WAITING_NOT_MADE_YET, waiting(api).line.key)
        val (view, tap) = assertNotNull(draw(api, m).rows["Family"])
        assertEquals(UiText.of(waiting(api).line).shown(), view.lines[0].shown())
        assertEquals(listOf(WaitingAct.WITHDRAW), view.buttons.map { it.act })
        tap(WaitingAct.WITHDRAW)
        assertAnswer("not made", WaitingResult.WITHDRAWN_NOT_MADE, said(m))
        assertTrue(notices(api).isEmpty(), "a change known not made needs no read")

        val (api2, m2) = at()
        api2.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.SERVER_SAYS_STORED, memberId(api2, m2, "Bo"), RoleInVault.READER)
        val w2 = waiting(api2)
        assertEquals(CopyKey.WAITING_SERVER_SAYS_STORED, w2.line.key)
        assertFalse(w2.canWithdraw)
        val view2 = assertNotNull(draw(api2, m2).rows["Family"]).first
        assertEquals(UiText.of(w2.line).shown(), view2.lines[0].shown())
        assertTrue(view2.buttons.isEmpty(), "nothing offered, nothing drawn")
    }

    @Test
    fun aChangeBeingSentSaysSoAndOffersWhatTheRowOffers() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, memberId(api, m, "Bo"), RoleInVault.WRITER)
        api.script.waitingFirstRequestOut("Family")
        val w = waiting(api)
        val sending = assertNotNull(w.sendingLine)
        val view = assertNotNull(draw(api, m).rows["Family"]).first
        assertEquals(UiText.of(sending).shown(), view.lines.last().shown(), "the shared code's line that it is being sent")
        assertEquals(w.withdrawLabel != null, view.buttons.any { it.act == WaitingAct.WITHDRAW }, "withdraw only as the row offers it")
    }

    @Test
    fun anOtherEntryWaitsWithItsLineAndNoButton() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.OTHER)
        val w = waiting(api)
        val view = assertNotNull(draw(api, m).rows["Family"]).first
        assertEquals(UiText.of(w.line).shown(), view.lines.single().shown())
        assertTrue(view.buttons.isEmpty())
    }

    @Test
    fun aDeletionIsAskedAboutOnlyOnceTheRowAsksAndThenOffersKeepTheVaultFirstAndDeleteItNow() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.DELETION, WaitingKnown.CANNOT_TELL)
        val before = waiting(api)
        assertEquals(CopyKey.WAITING_DELETE, before.line.key)
        assertFalse(before.asksForWord)
        val first = assertNotNull(draw(api, m).rows["Family"]).first
        assertEquals(UiText.of(before.line).shown(), first.lines.single().shown())
        assertNull(first.ask, "before the look nothing is asked")
        assertTrue(first.buttons.isEmpty(), "before the look neither of the question's buttons is drawn")

        api.script.waitingDeletionLooked("Family")
        val asked = waiting(api)
        assertTrue(asked.asksForWord)
        val (view, tap) = assertNotNull(draw(api, m).rows["Family"])
        assertEquals(UiText.of(assertNotNull(asked.askLine)).shown(), assertNotNull(view.ask).shown())
        assertEquals(listOf(WaitingAct.WITHDRAW, WaitingAct.DELETE_NOW), view.buttons.map { it.act }, "the way out first")
        assertEquals(UiText.of(CopyKey.WAITING_KEEP_VAULT).shown(), view.buttons[0].label.shown())
        assertEquals(UiText.of(CopyKey.WAITING_DELETE_NOW).shown(), view.buttons[1].label.shown())
        tap(WaitingAct.DELETE_NOW)
        assertAnswer("delete now", WaitingResult.DELETED, said(m))
        assertTrue(family(api).deleted, "the row shows it deleted")
    }

    @Test
    fun keepTheVaultAnswersByWhatIsKnown() {
        for ((known, result) in listOf(WaitingKnown.CANNOT_TELL to WaitingResult.KEPT_MAY_BE_DELETED, WaitingKnown.NOT_STORED to WaitingResult.KEPT_NOT_DELETED)) {
            val (api, m) = at()
            api.script.changeWaits("Family", WaitingKind.DELETION, known)
            api.script.waitingDeletionLooked("Family")
            assertNotNull(draw(api, m).rows["Family"]).second(WaitingAct.WITHDRAW)
            assertAnswer("keep, ${known.name}", result, said(m))
            assertFalse(family(api).deleted)
        }
    }

    @Test
    fun aDeletionTheServerSaysItStoredAsksNothingAndOffersNothing() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.DELETION, WaitingKnown.SERVER_SAYS_STORED)
        api.script.waitingDeletionLooked("Family")
        val w = waiting(api)
        assertEquals(CopyKey.WAITING_DELETE_SERVER_SAYS_STORED, w.line.key)
        val view = assertNotNull(draw(api, m).rows["Family"]).first
        assertEquals(UiText.of(w.line).shown(), view.lines.single().shown())
        assertNull(view.ask)
        assertTrue(view.buttons.isEmpty())
    }

    @Test
    fun aDeleteNowWithoutAnAnswerSaysStillWaitingAndTheQuestionGoesUntilTheNextLook() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.DELETION)
        api.script.waitingDeletionLooked("Family")
        api.script.deleteNowGetsNoAnswer = true
        assertNotNull(draw(api, m).rows["Family"]).second(WaitingAct.DELETE_NOW)
        assertAnswer("no answer", WaitingResult.DELETE_STILL_WAITING, said(m))
        val view = assertNotNull(draw(api, m).rows["Family"]).first
        assertNull(view.ask)
        assertTrue(view.buttons.isEmpty())
    }

    @Test
    fun aQuestionAnsweredAfterTheDayIsGivenUpAndSaysSo() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.DELETION)
        api.script.waitingDeletionLooked("Family")
        val tap = assertNotNull(draw(api, m).rows["Family"]).second
        api.script.advance(24 * 3600 * 1000L)
        tap(WaitingAct.DELETE_NOW)
        assertAnswer("after the day", WaitingResult.DELETE_GIVEN_UP, said(m))
        assertFalse(family(api).deleted, "nothing was sent")
        assertEquals(CopyKey.WAITING_GIVEN_UP_CANNOT_TELL, notices(api).single().line.key)
    }

    @Test
    fun aFrozenVaultDrawsNoWaitingChangeAndAnActDrawnBeforeTheFreezeSaysFrozen() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, memberId(api, m, "Bo"), RoleInVault.READER)
        val tap = assertNotNull(draw(api, m).rows["Family"]).second
        api.script.waitingVaultFreezes("Family")
        assertNull(family(api).waiting)
        assertNull(draw(api, m).rows["Family"], "nothing waits on a frozen vault")
        tap(WaitingAct.WITHDRAW)
        assertAnswer("frozen", WaitingResult.FROZEN, said(m))
    }

    @Test
    fun aChangeSettledMeanwhileSaysNothingWaitsAndItsNoticeIsDrawn() {
        val (api, m) = at()
        val bo = memberId(api, m, "Bo")
        api.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, bo, RoleInVault.READER)
        val tap = assertNotNull(draw(api, m).rows["Family"]).second
        api.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.REMOVE_MEMBER)
        tap(WaitingAct.WITHDRAW)
        assertAnswer("settled", WaitingResult.NOTHING_WAITING, said(m))
        val drawn = draw(api, m)
        assertEquals(CopyKey.WAITING_FOUND_MADE_AFTER_ALL, drawn.notices.single().notice.line.key)
    }

    // ---- the notices ----

    private class NoticeCase(
        val key: CopyKey, val undo: WaitingUndo?, val kind: WaitingKind, val drawnKey: CopyKey, val drawnUndo: WaitingUndo?,
        val setUp: (FakeDesktopAppApi, TrustModel) -> Unit = { _, _ -> },
    )

    private val deleted: (FakeDesktopAppApi, TrustModel) -> Unit = { api, m -> m.run({ vaults.deleteVault(family(api)) }) }
    private val frozen: (FakeDesktopAppApi, TrustModel) -> Unit = { api, _ -> api.script.waitingVaultFreezes("Family") }

    private val noticeCases = listOf(
        NoticeCase(CopyKey.WAITING_FOUND_DELETED, WaitingUndo.RESTORE_VAULT, WaitingKind.DELETION, CopyKey.WAITING_FOUND_DELETED, WaitingUndo.RESTORE_VAULT, deleted),
        NoticeCase(CopyKey.WAITING_FOUND_DELETED_AFTER_ALL, WaitingUndo.RESTORE_VAULT, WaitingKind.DELETION, CopyKey.WAITING_FOUND_DELETED_AFTER_ALL, WaitingUndo.RESTORE_VAULT, deleted),
        NoticeCase(CopyKey.WAITING_FOUND_GIVEN_UP_DELETED_AFTER_ALL, WaitingUndo.RESTORE_VAULT, WaitingKind.DELETION, CopyKey.WAITING_FOUND_GIVEN_UP_DELETED_AFTER_ALL, WaitingUndo.RESTORE_VAULT, deleted),
        NoticeCase(CopyKey.WAITING_FOUND_HALF_MADE_DELETED, WaitingUndo.RESTORE_VAULT, WaitingKind.DELETION, CopyKey.WAITING_FOUND_HALF_MADE_DELETED, WaitingUndo.RESTORE_VAULT, deleted),
        NoticeCase(CopyKey.WAITING_FOUND_DELETED, WaitingUndo.RESTORE_VAULT, WaitingKind.DELETION, CopyKey.WAITING_FOUND_DELETED_RESTORED_SINCE, null),
        NoticeCase(CopyKey.WAITING_FOUND_DELETED, WaitingUndo.RESTORE_VAULT, WaitingKind.DELETION, CopyKey.WAITING_FOUND_DELETED_NO_RESTORE, null, frozen),
        NoticeCase(CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.REMOVE_MEMBER, WaitingKind.ADD, CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.REMOVE_MEMBER),
        NoticeCase(CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.ADD_MEMBER, WaitingKind.REMOVE, CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.ADD_MEMBER),
        NoticeCase(CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.CHANGE_ROLE_BACK, WaitingKind.ROLE, CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.CHANGE_ROLE_BACK),
        NoticeCase(CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.CANCEL_OFFER, WaitingKind.OFFER, CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.CANCEL_OFFER),
    ) + listOf(
        CopyKey.WAITING_FOUND_NOT_MADE, CopyKey.WAITING_FOUND_NOT_MADE_YET, CopyKey.WAITING_GIVEN_UP_NOT_MADE, CopyKey.WAITING_GIVEN_UP_ABSENT,
        CopyKey.WAITING_GIVEN_UP_CANNOT_TELL, CopyKey.WAITING_FOUND_REFUSED_CANNOT_TELL, CopyKey.WAITING_FOUND_PLACE_TAKEN, CopyKey.WAITING_FOUND_REFUSED,
        CopyKey.WAITING_FOUND_CONTACT_CHANGED, CopyKey.WAITING_FOUND_CONTACT_CHANGED_NOT_MADE,
    ).map { NoticeCase(it, null, WaitingKind.ADD, it, null) }

    @Test
    fun everyUndoHasItsLabelHereSoThatOneAddedLaterIsDrawnBeforeThisPasses() {
        assertEquals(WaitingUndo.entries.toSet(), undoLabels.keys, "an undo of the shared code without a label here")
        assertEquals(WaitingUndo.entries.toSet(), noticeCases.mapNotNull { it.drawnUndo }.toSet(), "every undo is drawn below")
    }

    @Test
    fun everyNoticeOfTheTableIsDrawnWithItsLineItsMemberItsUndoAndItsDismiss() {
        for (case in noticeCases) {
            val (api, m) = at()
            val bo = memberId(api, m, "Bo")
            val member = case.kind != WaitingKind.DELETION
            // First the vault's state (deleted, frozen): no other change of a vault is made while one waits there.
            case.setUp(api, m)
            api.script.changeWaits("Family", case.kind, WaitingKnown.CANNOT_TELL, if (member) bo else null, if (case.kind == WaitingKind.ROLE) RoleInVault.READER else null)
            assertTrue(api.script.waitingFound("Family", case.key, case.undo, case.kind))
            val n = notices(api).single()
            val where = "${case.key.name} -> ${case.drawnKey.name}"
            assertEquals(case.drawnKey, n.line.key, where)
            assertEquals(case.drawnUndo, n.undo, where)
            val drawn = draw(api, m).notices.single()
            assertSame(n, drawn.notice)
            assertEquals(UiText.of(n.line).shown(), drawn.lines[0].shown(), where)
            assertFalse(drawn.lines[0] is UiText.Ph, "$where: the shared code's line")
            if (n.names != null) assertEquals(personLine(assertNotNull(n.names)).shown(), drawn.lines[1].shown(), where)
            val label = drawn.undo
            if (case.drawnUndo == null) {
                assertNull(label, "$where: no undo")
            } else {
                assertEquals(undoLabels[case.drawnUndo], assertIs<UiText.Ph>(label, where).placeholder, where)
            }
            println("NOTICE|$where|${drawn.lines.joinToString(" / ") { it.shown() }}|${label?.shown() ?: "(no undo)"}")
            drawn.dismiss()
            assertTrue(notices(api).isEmpty(), "$where: dismissed")
        }
    }

    @Test
    fun aNoticeIsKeptAcrossALockUntilItIsDismissed() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, memberId(api, m, "Bo"), RoleInVault.READER)
        api.script.waitingFound("Family", CopyKey.WAITING_FOUND_NOT_MADE_YET)
        api.script.lock()
        api.script.unlock()
        val drawn = draw(api, m).notices.single()
        assertEquals(CopyKey.WAITING_FOUND_NOT_MADE_YET, drawn.notice.line.key)
        drawn.dismiss()
        assertTrue(draw(api, m).notices.isEmpty())
    }

    // ---- the undo acts on the member the notice names, by their account id ----

    @Test
    fun removingAMemberAgainActsOnTheMemberTheNoticeNames() {
        val (api, m) = at()
        val bo = memberId(api, m, "Bo")
        api.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, bo, RoleInVault.WRITER)
        api.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.REMOVE_MEMBER)
        val n = notices(api).single()
        assertEquals(bo, n.memberId)
        val dan = memberId(api, m, null)
        draw(api, m).notices.single().act()
        assertNull(roleOf(api, m, bo), "Bo was removed")
        assertNotNull(roleOf(api, m, dan), "the other member stays")
    }

    @Test
    fun anUndoForAMemberNoLongerListedCallsNothingAndSaysSo() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, "33333333-3333-4333-8333-333333333333", RoleInVault.READER)
        api.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.REMOVE_MEMBER)
        val bo = memberId(api, m, "Bo")
        val dan = memberId(api, m, null)
        draw(api, m).notices.single().act()
        assertEquals(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED, assertIs<UiText.Ph>(said(m)).placeholder)
        assertNotNull(roleOf(api, m, bo))
        assertNotNull(roleOf(api, m, dan))
    }

    @Test
    fun changingARoleBackGivesTheRoleTheNoticeNames() {
        val (api, m) = at()
        val bo = memberId(api, m, "Bo")
        assertEquals(RoleInVault.WRITER, roleOf(api, m, bo))
        api.script.changeWaits("Family", WaitingKind.ROLE, WaitingKnown.CANNOT_TELL, bo, RoleInVault.READER)
        api.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.CHANGE_ROLE_BACK)
        val n = notices(api).single()
        assertEquals(RoleInVault.WRITER, n.roleBack)
        // The change was made after all: Bo reads only now.
        m.run({ vaults.changeRole(assertNotNull(snapshot.account?.members).members.first { it.userId == bo }, MemberRole.READER) })
        assertEquals(RoleInVault.READER, roleOf(api, m, bo))
        val drawn = draw(api, m).notices.single()
        assertEquals(UiText.ph(Placeholder.WAITING_UNDO_ROLE_BACK, MemberRole.WRITER.literal).shown(), assertNotNull(drawn.undo).shown())
        drawn.act()
        assertEquals(RoleInVault.WRITER, roleOf(api, m, bo), "changed back to the role the notice names")
    }

    @Test
    fun sharingAVaultAgainAddsTheContactTheNoticeNames() {
        val (api, m) = at()
        val bo = memberId(api, m, "Bo")
        m.run({ vaults.removeMember(assertNotNull(snapshot.account?.members).members.first { it.userId == bo }) })
        assertNull(roleOf(api, m, bo))
        api.script.changeWaits("Family", WaitingKind.REMOVE, WaitingKnown.CANNOT_TELL, bo)
        api.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.ADD_MEMBER)
        assertEquals(bo, notices(api).single().memberId)
        draw(api, m).notices.single().act()
        assertEquals(RoleInVault.READER, roleOf(api, m, bo), "shared again with the contact of that account id, as a reader")
    }

    @Test
    fun restoringFromANoticeRestoresTheVaultItNames() {
        val (api, m) = at()
        deleted(api, m)
        api.script.changeWaits("Family", WaitingKind.DELETION)
        api.script.waitingFound("Family", CopyKey.WAITING_FOUND_DELETED, WaitingUndo.RESTORE_VAULT, WaitingKind.DELETION)
        assertTrue(family(api).deleted)
        draw(api, m).notices.single().act()
        assertFalse(family(api).deleted)
    }

    @Test
    fun theUndoFindsItsMemberByTheAccountIdAndNeverByAName() {
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/WaitingScreens.kt").readText()
        val body = src.substringAfter("internal suspend fun DesktopAppApi.undoNoticeAct(").substringBefore("\n}\n")
        assertTrue(body.contains("screen.members.firstOrNull { it.userId == id }"))
        assertTrue(body.contains("contacts?.contacts?.firstOrNull { it.userId == id }"))
        assertFalse(body.contains(".who") || body.contains(".label") || body.contains("names"), "no name is read to find whom the undo acts on")
        assertTrue(body.contains("givenRole(n.roleBack)"), "the role given back is the notice's")
    }

    @Test
    fun removingAMemberAgainAsksFirstWithTheRemoveDialogsWords() {
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/WaitingScreens.kt").readText()
        val card = src.substringAfter("internal fun WaitingNoticeCard(").substringBefore("\n}\n")
        assertTrue(card.contains("if (notice.undo == WaitingUndo.REMOVE_MEMBER) askingRemove = true else act()"))
        assertTrue(card.contains("Say(CopyKey.REMOVE_MEMBER_WARNING)"))
        val area = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/AccountScreens.kt").readText()
        assertTrue(area.contains("for (notice in account.waitingNotices) WaitingNoticeCard(model, s, notice)"), "every notice is drawn above every page")
    }

    // ---- closing a move stopped on a frozen old vault ----

    @Test
    fun aMoveStoppedOnAFrozenOldVaultIsClosedFromItsRowAndAStaleCloseSaysNothing() {
        val (api, m) = at()
        m.run({ vaults.openMembers(family(api)) })
        m.run({ vaults.openMoveEverythingRemoving(assertNotNull(snapshot.account?.members).members.first { it.who is PersonName.Unverified }) })
        api.script.moveDeleteUnanswered = true
        m.run({ vaults.moveEverything(assertNotNull(snapshot.account?.moving), "Family 2") })
        api.script.moveDeleteUnanswered = false
        api.script.nextMoveStop = FakeScript.MoveStopAt.OLD_VAULT_FROZEN
        m.run({ vaults.moveEverything(assertNotNull(snapshot.account?.moving), "ignored") })
        m.act { vaults.closeMoveEverything() }
        val row = family(api)
        val line = assertNotNull(row.frozenMoveClose)
        val rec = recording(api, m)
        val (drawnLine, close) = assertNotNull(draw(api, m).moves["Family"])
        assertEquals(UiText.of(line).shown(), drawnLine.shown())
        close()
        assertSame(row, rec.handed.single(), "the row on show, as it was drawn")
        assertNull(said(m), "DONE says nothing")
        assertNull(family(api).frozenMoveClose, "closed")
        m.closeFrozenMove(row)
        assertEquals(VaultActionResult.STALE, (api.vaults as WaitingChanges).closeFrozenMove(row))
        assertNull(said(m), "STALE says nothing")
        val view = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultScreens.kt").readText()
        assertTrue(view.contains("v.frozenMoveClose?.let { FrozenMoveClose(model, s, v, it) }"))
    }

    // ---- what a screen must never do ----

    /** Every row the stand-in can draw: each kind, each thing known, sent or not, looked at or not. */
    private fun everyRow(): List<Triple<String, WaitingChange, WaitingDrawn>> {
        val out = ArrayList<Triple<String, WaitingChange, WaitingDrawn>>()
        for (kind in WaitingKind.entries) for (known in WaitingKnown.entries) for (out1 in listOf(false, true)) for (looked in listOf(false, true)) {
            val (api, m) = at()
            val member = if (kind == WaitingKind.DELETION || kind == WaitingKind.OTHER) null else memberId(api, m, "Bo")
            api.script.changeWaits("Family", kind, known, member, if (kind == WaitingKind.ADD || kind == WaitingKind.ROLE) RoleInVault.READER else null)
            if (out1) api.script.waitingFirstRequestOut("Family")
            if (looked) api.script.waitingDeletionLooked("Family")
            val drawn = assertNotNull(draw(api, m).rows["Family"]).first
            out += Triple("${kind.name}/${known.name}/sent=$out1/looked=$looked", waiting(api), drawn)
        }
        return out
    }

    @Test
    fun neverAButtonTheRowDoesNotOffer() {
        for ((where, w, drawn) in everyRow()) {
            println("ROW|$where|${drawn.lines.joinToString(" / ") { it.shown() }}|${drawn.buttons.joinToString { it.act.name }}")
            val withdraw = drawn.buttons.filter { it.act == WaitingAct.WITHDRAW }
            val now = drawn.buttons.filter { it.act == WaitingAct.DELETE_NOW }
            if (withdraw.isNotEmpty()) {
                assertTrue(w.canWithdraw, "$where: withdraw only where offered")
                assertEquals(UiText.of(assertNotNull(w.withdrawLabel)).shown(), withdraw.single().label.shown(), where)
            }
            if (now.isNotEmpty()) assertTrue(w.asksForWord, "$where: delete it now only while the row asks")
            if (w.kind == WaitingKind.DELETION && !w.asksForWord) assertTrue(drawn.buttons.isEmpty(), "$where: a deletion not asked about has no button")
            if (w.kind != WaitingKind.DELETION) assertEquals(w.canWithdraw, withdraw.isNotEmpty(), "$where: withdraw exactly as the row offers it")
            assertTrue(drawn.buttons.size == drawn.buttons.map { it.act }.toSet().size, where)
        }
    }

    @Test
    fun neverALineOfTheDesktopsOwnWhereTheSharedCodeHandsOne() {
        for ((where, w, drawn) in everyRow()) {
            assertEquals(UiText.of(w.line).shown(), drawn.lines.first().shown(), where)
            assertFalse(drawn.lines.first() is UiText.Ph, where)
            w.sendingLine?.let { assertEquals(UiText.of(it).shown(), drawn.lines.last().shown(), where) }
            assertEquals(w.askLine?.let { UiText.of(it).shown() }, drawn.ask?.shown(), where)
            for (b in drawn.buttons) assertFalse(b.label is UiText.Ph, "$where: the button's label is the shared code's")
            val expected = 1 + (if (w.names != null) 1 else 0) + (if (w.sendingLine != null) 1 else 0)
            assertEquals(expected, drawn.lines.size, "$where: the shared code's lines and the member, nothing more")
        }
        for (r in WaitingResult.entries) {
            val text = waitingAnswer(r, 0)
            if (r.sentence != null) assertEquals(UiText.of(assertNotNull(r.sentence)).shown(), assertNotNull(text, r.name).shown(), r.name)
        }
    }

    @Test
    fun neverWordsForStaleAfterALockAndAnUnlockNorWhereALockCameBetween() {
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, memberId(api, m, "Bo"), RoleInVault.READER)
        val tap = assertNotNull(draw(api, m).rows["Family"]).second
        val old = waiting(api)
        api.script.lock()
        api.script.unlock()
        tap(WaitingAct.WITHDRAW)
        assertNull(said(m), "STALE says nothing")
        val fresh = waiting(api)
        assertFalse(fresh === old, "the row is drawn again from the snapshot")
        assertNotNull(draw(api, m).rows["Family"]).second(WaitingAct.WITHDRAW)
        assertAnswer("the row drawn again", WaitingResult.WITHDRAWN_MAY_BE_MADE, said(m))

        val (api2, m2) = at()
        api2.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, memberId(api2, m2, "Bo"), RoleInVault.READER)
        val rec = recording(api2, m2) { api2.script.lock() }
        assertNotNull(draw(api2, m2).rows["Family"]).second(WaitingAct.WITHDRAW)
        assertEquals(1, rec.handed.size)
        assertNull(said(m2), "a lock between the tap and the answer: still nothing said for STALE")
        val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/TrustModel.kt").readText()
        assertTrue(src.contains("if (r === io.silencelen.andvari.core.app.WaitingResult.STALE) {"))
    }

    @Test
    fun neverAnActCalledWithAnythingButTheObjectTheScreenDrew() {
        for (act in WaitingAct.entries) {
            val (api, m) = at()
            api.script.changeWaits("Family", WaitingKind.DELETION)
            api.script.waitingDeletionLooked("Family")
            val rec = recording(api, m)
            val drawn = draw(api, m)
            val shown = assertNotNull(drawn.rowObjects["Family"]?.waiting)
            assertSame(waiting(api), shown, "drawn from the snapshot on show")
            assertNotNull(drawn.rows["Family"]).second(act)
            assertSame(shown, rec.handed.single(), "${act.name}: handed the very object drawn")
        }
        val (api, m) = at()
        api.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, memberId(api, m, "Bo"), RoleInVault.READER)
        api.script.waitingFound("Family", CopyKey.WAITING_FOUND_NOT_MADE_YET)
        val rec = recording(api, m)
        val n = draw(api, m).notices.single()
        assertSame(notices(api).single(), n.notice)
        n.dismiss()
        assertSame(n.notice, rec.handed.single(), "the dismiss is handed the notice on show")
        val view = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/WaitingScreens.kt").readText()
            .substringAfter("internal fun WaitingOnRow(").substringBefore("\n}\n")
        assertTrue(view.contains("val w = v.waiting ?: return"))
        assertTrue(view.contains("model.actOnWaiting(w, act)"), "the act is handed the row's own object")
    }
}
