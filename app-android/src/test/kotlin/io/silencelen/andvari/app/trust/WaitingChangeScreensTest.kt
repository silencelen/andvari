package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.SharedVaultRow
import io.silencelen.andvari.core.app.SharedVaultsApi
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.WaitingChange
import io.silencelen.andvari.core.app.WaitingChanges
import io.silencelen.andvari.core.app.WaitingKind
import io.silencelen.andvari.core.app.WaitingKnown
import io.silencelen.andvari.core.app.WaitingNotice
import io.silencelen.andvari.core.app.WaitingResult
import io.silencelen.andvari.core.app.WaitingUndo
import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeScript
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * A change to a shared vault that waits, over the stand-in: every state a row can be in and what it draws and offers,
 * every result of the two acts and what is said for it, every notice with its undo and its dismiss, "close this move",
 * and a change refused because another waits. Each table here has a row for every value of the shared code's enum, so a
 * value added later turns the test red until it is given what the phone draws for it.
 */
class WaitingChangeScreensTest {
    private class Scene(val api: AppApi, val fake: FakeAppApi) {
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }).also { it.onSnapshot(api.snapshot) }
        val me: FakeAccount = assertNotNull(fake.script.publicInstance.accounts[FakeScenes.EMAIL])
        val vault = me.vaults.first { it.name == "Family" }
        val bo = vault.members.first { it.contact != null }
        val script: FakeScript get() = fake.script
        fun row(): SharedVaultRow = assertNotNull(api.snapshot.account).vaults.first { it.vaultId == vault.vaultId }
        fun waiting(): WaitingChange = assertNotNull(row().waiting)
        fun notices(): List<WaitingNotice> = assertNotNull(api.snapshot.account).waitingNotices
        fun said(): String? = m.saidOn(api.snapshot)?.text?.shown()
    }

    /** A day, as the stand-in's clock counts it (a waiting change is given up after one). */
    private val DAY = 24L * 60 * 60 * 1000

    private fun scene(): Scene = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS).let { Scene(it, it) }

    /** What is said after an act on a waiting change. */
    private enum class Said { SENTENCE, TROUBLE, NOTHING }

    /** Every result of [WaitingChanges.withdrawWaiting] and [WaitingChanges.deleteWaitingNow], with what the phone says. */
    private val saidFor: Map<WaitingResult, Said> = mapOf(
        WaitingResult.WITHDRAWN_NOT_MADE to Said.SENTENCE,
        WaitingResult.WITHDRAWN_MAY_BE_MADE to Said.SENTENCE,
        WaitingResult.KEPT_NOT_DELETED to Said.SENTENCE,
        WaitingResult.KEPT_MAY_BE_DELETED to Said.SENTENCE,
        WaitingResult.DELETED to Said.SENTENCE,
        WaitingResult.DELETE_STILL_WAITING to Said.SENTENCE,
        WaitingResult.DELETE_DID_NOT_HAPPEN to Said.SENTENCE,
        WaitingResult.DELETE_REFUSED to Said.SENTENCE,
        WaitingResult.DELETE_REFUSED_CANNOT_TELL to Said.SENTENCE,
        WaitingResult.MOVE_IN_PROGRESS to Said.SENTENCE,
        WaitingResult.DELETE_GIVEN_UP to Said.SENTENCE,
        WaitingResult.STILL_SENDING to Said.SENTENCE,
        WaitingResult.SERVER_SAYS_STORED to Said.SENTENCE,
        WaitingResult.NOTHING_WAITING to Said.SENTENCE,
        WaitingResult.NOT_OFFERED to Said.SENTENCE,
        WaitingResult.RECORD_UNREADABLE to Said.SENTENCE,
        WaitingResult.FROZEN to Said.SENTENCE,
        WaitingResult.STALE to Said.NOTHING,
        WaitingResult.UNREACHABLE to Said.TROUBLE,
        WaitingResult.FAILED to Said.TROUBLE,
    )

    @Test
    fun everyResultOfAnActOnAWaitingChangeHasItsRowHere() {
        assertEquals(WaitingResult.entries.toSet(), saidFor.keys, "a result of the shared code without a row here: give it what the phone says, then its row")
    }

    @Test
    fun everyResultIsSaidInItsOwnSentenceAfterBothActsAlsoWhereItIsDone() {
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.DELETION))
        assertTrue(sc.script.waitingDeletionLooked("Family"))
        for (act in listOf("withdraw", "delete now")) {
            for (r in WaitingResult.entries) {
                val w = sc.waiting()
                sc.m.clearSaid()
                sc.script.forceNext(r)
                if (act == "withdraw") withdrawWaiting(sc.m, w) else deleteWaitingNow(sc.m, w)
                val expected = when (assertNotNull(saidFor[r], "no row for ${r.name}")) {
                    Said.SENTENCE -> UiText.of(assertNotNull(r.sentence, "${r.name} has a sentence")).shown()
                    Said.TROUBLE -> OutcomeWords.trouble(assertNotNull(r.trouble), 0).shown()
                    Said.NOTHING -> null
                }
                assertEquals(expected, sc.said(), "$act, ${r.name}")
                assertEquals(expected, waitingResultWords(r, 0)?.shown(), "$act, ${r.name}")
            }
        }
    }

    // ---- every state of a row ----

    /** The shared code's line for each kind and what is known of it (the table's waiting lines). */
    private fun lineKey(kind: WaitingKind, known: WaitingKnown): CopyKey = when {
        kind == WaitingKind.DELETION && known == WaitingKnown.SERVER_SAYS_STORED -> CopyKey.WAITING_DELETE_SERVER_SAYS_STORED
        kind == WaitingKind.DELETION -> CopyKey.WAITING_DELETE
        known == WaitingKnown.SERVER_SAYS_STORED -> CopyKey.WAITING_SERVER_SAYS_STORED
        known == WaitingKnown.NOT_STORED -> CopyKey.WAITING_NOT_MADE_YET
        else -> CopyKey.WAITING_MAY_BE_MADE
    }

    /** The phone's own line of which change waits, by kind (null: the shared code's line says it). */
    private val kindLine: Map<WaitingKind, Placeholder?> = mapOf(
        WaitingKind.ADD to Placeholder.WAITING_KIND_ADD,
        WaitingKind.REMOVE to Placeholder.WAITING_KIND_REMOVE,
        WaitingKind.ROLE to Placeholder.WAITING_KIND_ROLE,
        WaitingKind.OFFER to Placeholder.WAITING_KIND_OFFER,
        WaitingKind.DELETION to null,
        WaitingKind.OTHER to null,
    )

    /** Every state of [WaitingKnown], each one played. */
    private val knownPlayed: Set<WaitingKnown> = setOf(WaitingKnown.SERVER_SAYS_STORED, WaitingKnown.NOT_STORED, WaitingKnown.CANNOT_TELL)

    @Test
    fun everyStateOfAWaitingChangeIsDrawnFromItsRowWithOnlyTheButtonsItOffers() {
        assertEquals(WaitingKind.entries.toSet(), kindLine.keys, "a kind without a row here")
        assertEquals(WaitingKnown.entries.toSet(), knownPlayed, "a state of what is known that is not played here")
        for (kind in WaitingKind.entries) for (known in WaitingKnown.entries) for (sending in listOf(false, true)) for (looked in listOf(false, true)) {
            if (looked && kind != WaitingKind.DELETION) continue
            val sc = scene()
            val member = sc.bo.userId.takeIf { kindLine[kind] != null }
            val role = when (kind) { WaitingKind.ADD, WaitingKind.ROLE -> RoleInVault.READER else -> null }
            assertTrue(sc.script.changeWaits("Family", kind, known, member, role))
            if (sending) sc.script.waitingFirstRequestOut("Family")
            if (looked) sc.script.waitingDeletionLooked("Family")
            val where = "$kind, $known, sending=$sending, looked=$looked"
            val w = sc.waiting()
            val stored = known == WaitingKnown.SERVER_SAYS_STORED
            val asks = kind == WaitingKind.DELETION && looked && !stored
            assertEquals(asks, w.asksForWord, where)
            // The lines: which change (the phone's own, naming the member and the role), the shared code's line, sending, the question.
            val expected = listOfNotNull(
                kindLine[kind]?.let { p ->
                    val who = personLine(assertNotNull(w.names, where)).shown()
                    when (kind) {
                        WaitingKind.ADD -> UiText.ph(p, who, roleWord(RoleInVault.READER))
                        WaitingKind.ROLE -> UiText.ph(p, who, roleWord(RoleInVault.WRITER), roleWord(RoleInVault.READER))
                        else -> UiText.ph(p, who)
                    }
                },
                UiText.of(lineKey(kind, known)),
                if (sending) UiText.of(CopyKey.WAITING_SENDING) else null,
                if (asks) UiText.of(assertNotNull(w.askLine, where)) else null,
            ).map { it.shown() }
            assertEquals(expected, waitingLines(w).map { it.shown() }, where)
            assertEquals(lineKey(kind, known), w.line.key, where)
            if (asks) assertEquals(CopyKey.WAITING_DELETE_ASK, w.askLine?.key, where)
            // The buttons: a deletion's two only once it asks; withdraw only where the row offers it.
            val withdraw = kind != WaitingKind.OTHER && !sending && !stored
            val acts = when {
                kind == WaitingKind.DELETION -> if (asks) listOfNotNull(WaitingAct.DELETE_NOW, WaitingAct.WITHDRAW.takeIf { withdraw }) else emptyList()
                else -> listOfNotNull(WaitingAct.WITHDRAW.takeIf { withdraw })
            }
            assertEquals(acts, waitingActs(w), where)
            assertEquals(withdraw, w.canWithdraw, where)
            for (act in waitingActs(w)) {
                assertTrue(if (act == WaitingAct.WITHDRAW) w.canWithdraw else w.asksForWord, "$where: $act only where the row offers it")
                val label = if (act == WaitingAct.DELETE_NOW) CopyKey.WAITING_DELETE_NOW else if (kind == WaitingKind.DELETION) CopyKey.WAITING_KEEP_VAULT else CopyKey.WAITING_WITHDRAW
                assertEquals(UiText.of(label).shown(), waitingActLabel(w, act).shown(), where)
            }
            assertEquals(member, w.memberId, where)
        }
    }

    @Test
    fun aRoleChangeWhoseRoleNowIsNotKnownSaysOnlyTheRoleItGives() {
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ROLE, memberId = "not-a-member", role = RoleInVault.READER))
        val w = sc.waiting()
        assertNull(w.roleBack)
        assertEquals(UiText.ph(Placeholder.WAITING_KIND_ROLE_TO, personLine(assertNotNull(w.names)).shown(), roleWord(RoleInVault.READER)).shown(), waitingKindLine(w)?.shown())
    }

    // ---- the results on their real roads ----

    @Test
    fun eachActOnItsOwnRoadSaysItsResultAndTheRowFollows() {
        fun road(kind: WaitingKind, known: WaitingKnown, looked: Boolean, act: WaitingAct, expected: WaitingResult, between: (Scene) -> Unit = {}): Scene {
            val sc = scene()
            assertTrue(sc.script.changeWaits("Family", kind, known, sc.bo.userId.takeIf { kind != WaitingKind.DELETION }, RoleInVault.READER.takeIf { kind == WaitingKind.ADD }))
            if (looked) sc.script.waitingDeletionLooked("Family")
            val w = sc.waiting()
            between(sc)
            if (act == WaitingAct.WITHDRAW) withdrawWaiting(sc.m, w) else deleteWaitingNow(sc.m, w)
            assertEquals(waitingResultWords(expected, 0)?.shown(), sc.said(), "$kind, $known: ${expected.name}")
            return sc
        }
        assertNull(road(WaitingKind.ADD, WaitingKnown.NOT_STORED, false, WaitingAct.WITHDRAW, WaitingResult.WITHDRAWN_NOT_MADE).row().waiting)
        road(WaitingKind.REMOVE, WaitingKnown.CANNOT_TELL, false, WaitingAct.WITHDRAW, WaitingResult.WITHDRAWN_MAY_BE_MADE).let { sc ->
            assertNull(sc.row().waiting)
            assertEquals(CopyKey.WAITING_FOUND_NOT_MADE_YET, sc.notices().single().line.key, "a notice follows")
        }
        road(WaitingKind.DELETION, WaitingKnown.NOT_STORED, true, WaitingAct.WITHDRAW, WaitingResult.KEPT_NOT_DELETED)
        road(WaitingKind.DELETION, WaitingKnown.CANNOT_TELL, true, WaitingAct.WITHDRAW, WaitingResult.KEPT_MAY_BE_DELETED)
        assertTrue(road(WaitingKind.DELETION, WaitingKnown.CANNOT_TELL, true, WaitingAct.DELETE_NOW, WaitingResult.DELETED).row().deleted)
        road(WaitingKind.DELETION, WaitingKnown.CANNOT_TELL, true, WaitingAct.DELETE_NOW, WaitingResult.DELETE_STILL_WAITING) { it.script.deleteNowGetsNoAnswer = true }.let { sc ->
            assertTrue(waitingActs(sc.waiting()).isEmpty(), "asked again only after a later look")
        }
        road(WaitingKind.DELETION, WaitingKnown.CANNOT_TELL, true, WaitingAct.DELETE_NOW, WaitingResult.DELETE_GIVEN_UP) { it.script.advance(DAY) }
        road(WaitingKind.ADD, WaitingKnown.CANNOT_TELL, false, WaitingAct.WITHDRAW, WaitingResult.STILL_SENDING) { it.script.waitingFirstRequestOut("Family") }
        road(WaitingKind.ADD, WaitingKnown.CANNOT_TELL, false, WaitingAct.WITHDRAW, WaitingResult.NOTHING_WAITING) {
            it.script.waitingFound("Family", CopyKey.WAITING_FOUND_NOT_MADE)
        }
        road(WaitingKind.ADD, WaitingKnown.CANNOT_TELL, false, WaitingAct.WITHDRAW, WaitingResult.FROZEN) { it.script.waitingVaultFreezes("Family") }
        road(WaitingKind.DELETION, WaitingKnown.CANNOT_TELL, true, WaitingAct.DELETE_NOW, WaitingResult.MOVE_IN_PROGRESS) {
            it.vault.moveDeleteWaiting = true
            it.script.changed()
        }
    }

    @Test
    fun staleSaysNothingAndTheRowIsDrawnAgainFromTheSnapshot() {
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, sc.bo.userId, RoleInVault.READER))
        val before = sc.waiting()
        sc.script.lock()
        sc.script.unlock()
        sc.m.onSnapshot(sc.api.snapshot)
        withdrawWaiting(sc.m, before)
        assertNull(sc.said(), "no words for STALE")
        assertNull(waitingResultWords(WaitingResult.STALE, 0))
        // Nothing was withdrawn: the row still draws the change, with its button, from the snapshot on show.
        val now = sc.waiting()
        assertEquals(WaitingKind.ADD, now.kind)
        assertEquals(listOf(WaitingAct.WITHDRAW), waitingActs(now))
    }

    @Test
    fun aChangeDrawnAgainAfterAnotherChangeIsActedOnAsTheNewObject() {
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, sc.bo.userId, RoleInVault.READER))
        val first = sc.waiting()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.REMOVE, WaitingKnown.CANNOT_TELL, sc.bo.userId))
        val second = sc.waiting()
        assertNotSame(first, second)
        withdrawWaiting(sc.m, first)
        assertNull(sc.said(), "the addition no longer waits: STALE, nothing said")
        assertSame(second, sc.waiting(), "the removal that waits is kept")
        withdrawWaiting(sc.m, second)
        assertEquals(UiText.of(CopyKey.WAITING_WITHDRAWN_MAY_BE_MADE).shown(), sc.said())
        assertNull(sc.row().waiting)
    }

    // ---- the notices ----

    /** Every notice line of the table: the kind of change and the undo the scene gives it (null: none). */
    private val noticeKeys: Map<CopyKey, Pair<WaitingKind, WaitingUndo?>> = mapOf(
        CopyKey.WAITING_FOUND_DELETED to (WaitingKind.DELETION to WaitingUndo.RESTORE_VAULT),
        CopyKey.WAITING_FOUND_DELETED_AFTER_ALL to (WaitingKind.DELETION to WaitingUndo.RESTORE_VAULT),
        CopyKey.WAITING_FOUND_GIVEN_UP_DELETED_AFTER_ALL to (WaitingKind.DELETION to WaitingUndo.RESTORE_VAULT),
        CopyKey.WAITING_FOUND_HALF_MADE_DELETED to (WaitingKind.DELETION to WaitingUndo.RESTORE_VAULT),
        CopyKey.WAITING_FOUND_DELETED_RESTORED_SINCE to (WaitingKind.DELETION to null),
        CopyKey.WAITING_FOUND_DELETED_NO_RESTORE to (WaitingKind.DELETION to null),
        CopyKey.WAITING_FOUND_MADE_AFTER_ALL to (WaitingKind.ADD to WaitingUndo.REMOVE_MEMBER),
        CopyKey.WAITING_FOUND_NOT_MADE to (WaitingKind.ADD to null),
        CopyKey.WAITING_FOUND_NOT_MADE_YET to (WaitingKind.ADD to null),
        CopyKey.WAITING_GIVEN_UP_NOT_MADE to (WaitingKind.ADD to null),
        CopyKey.WAITING_GIVEN_UP_ABSENT to (WaitingKind.ADD to null),
        CopyKey.WAITING_GIVEN_UP_CANNOT_TELL to (WaitingKind.ADD to null),
        CopyKey.WAITING_FOUND_REFUSED_CANNOT_TELL to (WaitingKind.ADD to null),
        CopyKey.WAITING_FOUND_PLACE_TAKEN to (WaitingKind.ADD to null),
        CopyKey.WAITING_FOUND_REFUSED to (WaitingKind.ADD to null),
        CopyKey.WAITING_FOUND_CONTACT_CHANGED to (WaitingKind.ADD to null),
        CopyKey.WAITING_FOUND_CONTACT_CHANGED_NOT_MADE to (WaitingKind.ADD to null),
    )

    @Test
    fun everyNoticeIsDrawnWithItsLineItsMemberItsUndoAndIsKeptUntilItsDismiss() {
        val all = CopyKey.entries.filter { it.name.startsWith("WAITING_FOUND_") || it.name.startsWith("WAITING_GIVEN_UP_") }.toSet()
        assertEquals(all, noticeKeys.keys, "a notice line of the shared code without a row here")
        for ((key, how) in noticeKeys) {
            val (kind, undo) = how
            val sc = scene()
            val member = sc.bo.userId.takeIf { kind != WaitingKind.DELETION }
            assertTrue(sc.script.changeWaits("Family", kind, WaitingKnown.CANNOT_TELL, member, RoleInVault.READER.takeIf { member != null }))
            if (undo == WaitingUndo.RESTORE_VAULT) sc.vault.purgeAtMs = sc.script.nowMs + 7 * DAY
            assertTrue(sc.script.waitingFound("Family", key, undo))
            val n = sc.notices().single()
            assertEquals(key, n.line.key, key.name)
            assertEquals(listOfNotNull(UiText.of(n.line), n.names?.let { personLine(it) }).map { it.shown() }, waitingNoticeLines(n).map { it.shown() }, key.name)
            assertEquals(member, n.memberId, key.name)
            assertEquals(undo, n.undo, key.name)
            assertEquals(undo, waitingUndoOf(n)?.undo, "${key.name}: the undo only where the notice offers it")
            // Kept across a lock.
            sc.script.lock()
            sc.script.unlock()
            val again = sc.notices().single()
            assertEquals(n.noticeId, again.noticeId, key.name)
            dismissWaitingNotice(sc.m, again)
            assertTrue(sc.notices().isEmpty(), "${key.name}: gone at the dismiss")
        }
    }

    /** Every undo: its button (the ordinary act's) and whether it asks the ordinary act's question first. */
    private val undoButtons: Map<WaitingUndo, Pair<Placeholder, Boolean>> = mapOf(
        WaitingUndo.REMOVE_MEMBER to (Placeholder.VAULT_REMOVE_MEMBER to true),
        WaitingUndo.ADD_MEMBER to (Placeholder.VAULT_ADD_THIS_PERSON to false),
        WaitingUndo.CHANGE_ROLE_BACK to (Placeholder.ROLE_CHANGE_CONFIRM to true),
        WaitingUndo.CANCEL_OFFER to (Placeholder.VAULT_CANCEL_OFFER to false),
        WaitingUndo.RESTORE_VAULT to (Placeholder.VAULT_RESTORE to false),
    )

    @Test
    fun everyUndoHasItsButtonAndTheOrdinaryActsQuestion() {
        assertEquals(WaitingUndo.entries.toSet(), undoButtons.keys, "an undo of the shared code without a row here")
        for ((undo, button) in undoButtons) {
            val u = WaitingUndoAsk("v", undo, "id", if (undo == WaitingUndo.CHANGE_ROLE_BACK) io.silencelen.andvari.core.trust.MemberRole.WRITER else null, null)
            assertEquals(button.first, (waitingUndoLabel(u) as UiText.Ph).placeholder, undo.name)
            assertEquals(button.second, u.asks, undo.name)
            assertEquals(button.second, waitingUndoQuestion(u).isNotEmpty(), undo.name)
        }
    }

    @Test
    fun theUndoRemovesTheMemberTheNoticeNamesByTheirIdNeverByAName() {
        val sc = scene()
        // Another member whom the server calls by the same name.
        val namesake = sc.vault.addMember("Bo", RoleInVault.READER, null)
        sc.script.changed()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, namesake.userId, RoleInVault.READER))
        assertTrue(sc.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.REMOVE_MEMBER))
        val u = assertNotNull(waitingUndoOf(sc.notices().single()))
        assertEquals(namesake.userId, u.memberId)
        undoWaiting(sc.m, u)
        assertTrue(sc.vault.members.none { it.userId == namesake.userId }, "the member the notice names is removed")
        assertTrue(sc.vault.members.any { it === sc.bo }, "the other one stays")
        assertNull(sc.api.snapshot.account?.members, "the members screen opened for it is closed again")
        assertEquals(1, sc.notices().size, "the notice stays until dismissed")
    }

    @Test
    fun theUndoChangesTheRoleBackToTheRoleTheNoticeNames() {
        val sc = scene()
        assertEquals(RoleInVault.WRITER, sc.bo.role)
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ROLE, WaitingKnown.CANNOT_TELL, sc.bo.userId, RoleInVault.READER))
        assertTrue(sc.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.CHANGE_ROLE_BACK))
        // The change was made after all.
        sc.bo.role = RoleInVault.READER
        sc.script.changed()
        val n = sc.notices().single()
        assertEquals(RoleInVault.WRITER, n.roleBack)
        val u = assertNotNull(waitingUndoOf(n))
        assertEquals(io.silencelen.andvari.core.trust.MemberRole.WRITER, u.roleBack)
        undoWaiting(sc.m, u)
        assertEquals(RoleInVault.WRITER, sc.bo.role)
    }

    @Test
    fun theUndoAddsTheContactTheNoticeNamesAgainAsAReader() {
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.REMOVE, WaitingKnown.CANNOT_TELL, sc.bo.userId))
        assertTrue(sc.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.ADD_MEMBER))
        val n = sc.notices().single()
        // The removal was made after all.
        sc.vault.members.removeAll { it === sc.bo }
        sc.script.changed()
        val u = assertNotNull(waitingUndoOf(n))
        undoWaiting(sc.m, u)
        assertEquals(RoleInVault.READER, sc.vault.members.single { it.userId == n.memberId }.role)
        assertNull(sc.api.snapshot.account?.members)
    }

    @Test
    fun anUndoForAMemberWhoIsNotListedNowChangesNothingAndSaysSo() {
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, sc.bo.userId, RoleInVault.READER))
        assertTrue(sc.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.REMOVE_MEMBER))
        sc.vault.members.removeAll { it === sc.bo }
        sc.script.changed()
        val before = sc.vault.members.map { it.userId }
        undoWaiting(sc.m, assertNotNull(waitingUndoOf(sc.notices().single())))
        assertEquals(before, sc.vault.members.map { it.userId })
        assertEquals(UiText.ph(Placeholder.WAITING_UNDO_MEMBER_NOT_LISTED).shown(), sc.said())
    }

    @Test
    fun theUndoRestoresADeletionFoundMadeWhileTheVaultReadsDeleted() {
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.DELETION))
        sc.vault.purgeAtMs = sc.script.nowMs + 7 * DAY
        assertTrue(sc.script.waitingFound("Family", CopyKey.WAITING_FOUND_DELETED, WaitingUndo.RESTORE_VAULT))
        undoWaiting(sc.m, assertNotNull(waitingUndoOf(sc.notices().single())))
        assertEquals(0L, sc.vault.purgeAtMs)
        assertNull(sc.said(), "done: the ordinary restore says nothing")
    }

    // ---- close this move, and a change refused because another waits ----

    @Test
    fun closeThisMoveSaysNothingWhereDoneOrStaleAndItsLineGoes() {
        val sc = scene()
        assertTrue(sc.script.waitingVaultFreezes("Family"))
        sc.vault.moveDeleteWaiting = true
        sc.vault.moveUnfinishedInto = "Family 2"
        sc.script.changed()
        val row = sc.row()
        assertEquals(CopyKey.MOVE_FROZEN_CLOSE, assertNotNull(row.frozenMoveClose).key)
        closeFrozenMove(sc.m, row)
        assertNull(sc.said())
        assertNull(sc.row().frozenMoveClose)
        closeFrozenMove(sc.m, row)
        assertNull(sc.said(), "STALE: nothing to close, nothing said")
        assertNull(frozenMoveCloseWords(VaultActionResult.STALE, 0))
        assertNull(frozenMoveCloseWords(VaultActionResult.DONE, 0))
    }

    @Test
    fun aChangeRefusedBecauseAnotherWaitsSaysTheSharedCodesSentenceNeverSent() {
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, sc.bo.userId, RoleInVault.READER))
        val row = sc.row()
        var result: VaultActionResult? = null
        sc.m.run({ vaults.deleteVault(row) }) { result = it }
        assertEquals(VaultActionResult.OTHER_CHANGE_WAITS, result)
        assertEquals(UiText.of(CopyKey.WAITING_OTHER_CHANGE_FIRST).shown(), sc.said())
        assertFalse(sc.said() == UiText.forResult(VaultActionResult.SENT_PENDING, 0)?.shown())
    }

    // ---- the nevers ----

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun neverAButtonTheRowDoesNotOffer() {
        val view = src("WaitingChangeScreens.kt").substringAfter("internal fun WaitingChangeView(").substringBefore("\n}\n")
        assertTrue("for (act in waitingActs(w))" in view, "the buttons come from the row's own offers only")
        assertFalse("WAITING_DELETE_NOW" in view || "WAITING_KEEP_VAULT" in view || "WAITING_WITHDRAW" in view, "no button of its own")
        // A deletion not looked at yet: drawn as waiting, nothing asked, no button.
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.DELETION))
        val w = sc.waiting()
        assertTrue(w.canWithdraw && !w.asksForWord)
        assertTrue(waitingActs(w).isEmpty())
        assertNull(w.askLine)
        // Where a notice names no member, an undo on a member has nothing to act on and no button.
        assertTrue(sc.script.waitingFound("Family", CopyKey.WAITING_FOUND_MADE_AFTER_ALL, WaitingUndo.REMOVE_MEMBER, WaitingKind.ADD))
        val n = sc.notices().single()
        assertNull(n.memberId)
        assertNull(waitingUndoOf(n))
    }

    @Test
    fun neverALineOfThePhonesOwnWhereTheSharedCodeHandsOne() {
        val screens = src("VaultScreens.kt").substringAfter("private fun VaultStateLines(").substringBefore("\n}\n")
        assertTrue("if (v.changeWaiting && v.waiting == null) Quiet(UiText.Plain(Approved.VAULT_CHANGE_WAITING_MARK))" in screens, "no mark beside a change the shared code draws")
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.REMOVE, WaitingKnown.CANNOT_TELL, sc.bo.userId))
        val w = sc.waiting()
        assertTrue(sc.row().changeWaiting)
        val drawn = waitingLines(w)
        assertTrue(drawn.any { it.shown() == UiText.of(w.line).shown() }, "the shared code's line, as handed")
        val own = drawn.filterIsInstance<UiText.Ph>().filter { it.placeholder != Placeholder.AWAITING_OWNER }.map { it.placeholder }
        assertEquals(listOf(Placeholder.WAITING_KIND_REMOVE), own, "only which change it is, for which the shared code hands no line")
        for (r in WaitingResult.entries) {
            r.sentence?.let { assertEquals(UiText.of(it).shown(), waitingResultWords(r, 0)?.shown(), r.name) }
        }
    }

    @Test
    fun neverWordsForStale() {
        assertNull(waitingResultWords(WaitingResult.STALE, 0))
        assertNull(frozenMoveCloseWords(VaultActionResult.STALE, 0))
        val sc = scene()
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, sc.bo.userId, RoleInVault.READER))
        sc.script.forceNext(WaitingResult.STALE)
        withdrawWaiting(sc.m, sc.waiting())
        assertNull(sc.said())
    }

    /** The stand-in behind a record of every object the phone hands to an act on a waiting change. */
    private class Handed(val inner: FakeAppApi) : AppApi by inner {
        val handed = ArrayList<Any>()
        private val waits = inner.vaults as WaitingChanges
        override val vaults: SharedVaultsApi = object : SharedVaultsApi by inner.vaults, WaitingChanges {
            override suspend fun withdrawWaiting(change: WaitingChange): WaitingResult { handed += change; return waits.withdrawWaiting(change) }
            override suspend fun deleteWaitingNow(change: WaitingChange): WaitingResult { handed += change; return waits.deleteWaitingNow(change) }
            override fun dismissWaitingNotice(notice: WaitingNotice) { handed += notice; waits.dismissWaitingNotice(notice) }
            override fun closeFrozenMove(vault: SharedVaultRow): VaultActionResult { handed += vault; return waits.closeFrozenMove(vault) }
        }
    }

    @Test
    fun neverAnActCalledWithAnythingButTheObjectTheScreenWasGiven() {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS)
        val api = Handed(fake)
        val sc = Scene(api, fake)
        assertTrue(sc.script.changeWaits("Family", WaitingKind.DELETION))
        assertTrue(sc.script.waitingDeletionLooked("Family"))
        val w = sc.waiting()
        deleteWaitingNow(sc.m, w)
        assertSame(w, api.handed.last())
        assertTrue(sc.script.changeWaits("Family", WaitingKind.ADD, WaitingKnown.CANNOT_TELL, sc.bo.userId, RoleInVault.READER))
        val add = sc.waiting()
        withdrawWaiting(sc.m, add)
        assertSame(add, api.handed.last())
        val n = sc.notices().first()
        dismissWaitingNotice(sc.m, n)
        assertSame(n, api.handed.last())
        assertTrue(sc.script.waitingVaultFreezes("Family"))
        sc.vault.moveDeleteWaiting = true
        sc.vault.moveUnfinishedInto = "Family 2"
        sc.script.changed()
        val row = sc.row()
        closeFrozenMove(sc.m, row)
        assertSame(row, api.handed.last())
        assertEquals(4, api.handed.size)
        // The screen reads the change from the row it draws, and the acts are called from one file only.
        val file = src("WaitingChangeScreens.kt")
        val view = file.substringAfter("internal fun WaitingChangeView(").substringBefore("\n}\n")
        assertTrue("val w = v.waiting ?: return" in view && "withdrawWaiting(model, w)" in view && "deleteWaitingNow(model, w)" in view)
        val sources = File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        fun usersOf(token: String) = sources.filter { f -> f.readLines().any { token in it.substringBefore("//") } }.map { it.name }.toSet()
        assertEquals(setOf("WaitingChangeScreens.kt"), usersOf(".withdrawWaiting("))
        assertEquals(setOf("WaitingChangeScreens.kt"), usersOf(".deleteWaitingNow("))
        assertEquals(setOf("WaitingChangeScreens.kt"), usersOf(".dismissWaitingNotice("))
        assertEquals(setOf("WaitingChangeScreens.kt"), usersOf(".closeFrozenMove("))
        assertTrue(sources.none { f -> f.readLines().any { "remember" in it && "WaitingChange" in it } }, "no waiting change is kept across a redraw")
        assertEquals(setOf("AccountScreens.kt"), usersOf("account.waitingNotices"), "read from the snapshot, never kept")
    }
}
