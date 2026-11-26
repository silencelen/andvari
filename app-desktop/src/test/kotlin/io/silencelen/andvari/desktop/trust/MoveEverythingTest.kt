package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.MoveKept
import io.silencelen.andvari.core.app.MoveStage
import io.silencelen.andvari.core.app.PersonName
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeVault
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * "Move everything to a new vault" on the desktop, on the shared code's rules of 2026-11-16 (§3.13): from the remove
 * dialog the member is named and never added; ticks only where core offers them; what moves and why the old vault is
 * kept, before the start; a stop and a second run into the same new vault; out of space. Asserted on the fake's own
 * state where it is about who holds what.
 */
class MoveEverythingTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
    }

    private val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/VaultScreens.kt").readText()
    private val view = src.substringAfter("private fun MoveEverythingView(").substringBefore("\n}\n")

    private fun me(api: FakeDesktopAppApi): FakeAccount = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
    private fun vault(api: FakeDesktopAppApi, name: String): FakeVault = me(api).vaults.single { it.name == name }

    /** Open the members of Family and, from [who]'s remove dialog, Move everything, as the dialog's button does. */
    private fun fromRemoveDialog(api: FakeDesktopAppApi, m: TrustModel, who: (PersonName) -> Boolean) {
        m.run({ vaults.openMembers(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        val member = assertNotNull(api.snapshot.account?.members).members.first { who(it.who) }
        m.run({ vaults.openMoveEverythingRemoving(member) })
    }

    private fun isDan(p: PersonName) = p is PersonName.Unverified
    private fun isBo(p: PersonName) = (p as? PersonName.Contact)?.label == "Bo"

    @Test
    fun fromTheRemoveDialogTheRemovedMemberIsNeverInTheNewVault() {
        val (api, m) = at(FakeScene.VAULTS)
        val dan = vault(api, "Family").members.single { it.contact == null && it.userId != me(api).userId }
        fromRemoveDialog(api, m, ::isDan)
        val screen = assertNotNull(api.snapshot.account?.moving)
        assertEquals(dan.userId, screen.removing?.userId)
        assertEquals(UiText.ph(Placeholder.MOVE_REMOVING, personLine(screen.removing!!.who).shown()).shown(), moveRemovingLine(screen)?.shown())
        assertTrue(screen.members.none { it.userId == dan.userId }, "not among the people added")
        assertNull(screen.oldVaultKept)

        m.run({ vaults.moveEverything(screen, "Family 2") })
        // The fake's own state: the new vault holds this account and Bo, never Dan; Dan is off the old log too.
        val made = vault(api, "Family 2")
        assertTrue(made.members.none { it.userId == dan.userId }, "the removed member is not in the new vault")
        assertEquals(setOf(me(api).userId, vault(api, "Family").members.first { it.contact?.label == "Bo" }.userId), made.members.map { it.userId }.toSet())
        assertTrue(vault(api, "Family").members.none { it.userId == dan.userId }, "removed on the old log first")
        assertTrue(vault(api, "Family").purgeAtMs > 0L, "the old vault is deleted last")
        assertNull(api.snapshot.account?.moving, "the screen closes when the old vault was deleted")

        // The dialog's button is this call, never the plain move of the vault.
        val dialog = src.substringAfter("removing?.let { m ->").substringBefore("confirmButton")
        assertTrue(dialog.contains("vaults.openMoveEverythingRemoving(m)"))
        assertFalse(dialog.contains("vaults.openMoveEverything(screen.vault)"))
    }

    @Test
    fun aVaultInGoodStandingHasNoTicksAndListsEveryoneWhoIsAddedAgain() {
        val (api, m) = at(FakeScene.VAULTS)
        fromRemoveDialog(api, m, ::isDan)
        val screen = assertNotNull(api.snapshot.account?.moving)
        assertFalse(screen.ticksOffered)
        assertFalse(screen.sourceStays)
        assertTrue(screen.members.all { it.ticked })
        // What moves is said before the start, in the shared code's words.
        assertEquals(UiText.of(CopyKey.MOVE_ONLY_LIVE_ITEMS).shown(), moveBeforeLines(screen).first().shown())
        // Tick boxes are drawn in the ticks branch only; the plain list says everyone is added again.
        val ticks = view.substringAfter("if (screen.ticksOffered) {").substringBefore("} else if")
        assertTrue(ticks.contains("Tick("))
        assertEquals(1, Regex("Tick\\(").findAll(view).count())
        assertTrue(view.substringAfter("} else if (screen.members.isNotEmpty()) {").contains("Placeholder.MOVE_ADDED_AGAIN"))
        assertFalse(src.contains("MOVE_SOURCE_STAYS"), "the desktop's own placeholder gave way to the shared key")
    }

    @Test
    fun aFrozenVaultOffersTicksWithNoneTickedAndTheWarning() {
        val (api, _) = at(FakeScene.MOVE_EVERYTHING_FROZEN)
        val screen = assertNotNull(api.snapshot.account?.moving)
        assertTrue(screen.ticksOffered)
        assertTrue(screen.sourceStays)
        assertTrue(screen.members.isNotEmpty() && screen.members.none { it.ticked }, "none ticked")
        assertTrue(view.contains("if (screen.sourceStays) Say(CopyKey.CHECK_WHAT_YOU_COPY"))
        val before = moveBeforeLines(screen).map { it.shown() }
        assertTrue(before.contains(UiText.of(CopyKey.MOVE_KEPT_SOURCE_STAYS).shown()))
        assertFalse(before.contains(UiText.of(CopyKey.MOVE_KEPT_NOT_ADDED).shown()), "the old vault stays anyway: one reason")
    }

    @Test
    fun aMemberWhoCannotBeAddedIsNamedBeforeTheStartAndTheOldVaultIsKept() {
        val (api, m) = at(FakeScene.MOVE_EVERYTHING)
        val screen = assertNotNull(api.snapshot.account?.moving)
        assertEquals(MoveKept.MEMBER_CANNOT_BE_ADDED, screen.oldVaultKept)
        val dan = screen.members.single { !it.canBeAdded }
        val before = moveBeforeLines(screen).map { it.shown() }
        assertTrue(before.contains(UiText.of(CopyKey.MOVE_KEPT_NOT_ADDED).shown()))
        assertTrue(before.contains("·  " + personLine(dan.who).shown()), "named before the start")

        m.run({ vaults.moveEverything(screen, "Family 2") })
        val finished = assertNotNull(api.snapshot.account?.moving, "a kept old vault leaves the screen open").finished
        assertNotNull(finished)
        assertEquals(0L, vault(api, "Family").purgeAtMs, "the old vault is kept")
        assertTrue(vault(api, "Family 2").members.none { it.userId == dan.userId })
        val lines = moveFinishedLines(assertNotNull(api.snapshot.account?.moving)).map { it.shown() }
        assertTrue(lines.contains(UiText.of(CopyKey.MOVE_KEPT_NOT_ADDED).shown()))
        assertTrue(lines.contains("·  " + personLine(dan.who).shown()))
        // A finished move shows its lines and a Close, and nothing to start again.
        val done = view.substringAfter("if (finished != null) {").substringBefore("return")
        assertTrue(done.contains("moveFinishedLines(screen)") && done.contains("vaults.closeMoveEverything()"))
        m.act { vaults.closeMoveEverything() }
        assertNull(api.snapshot.account?.moving)
    }

    @Test
    fun itemsThisComputerCannotReadAreCountedBeforeTheStart() {
        val (api, m) = at(FakeScene.VAULTS)
        vault(api, "Family").unreadable = 2
        api.script.changed()
        fromRemoveDialog(api, m, ::isDan)
        val screen = assertNotNull(api.snapshot.account?.moving)
        assertEquals(2, screen.unreadable)
        assertTrue(moveBeforeLines(screen).map { it.shown() }.contains(UiText.Awaiting(fillCopy(CopyKey.MOVE_KEPT_UNREADABLE, "2")).shown()))
    }

    @Test
    fun aStopSaysWhereAndASecondRunCarriesOnIntoTheSameNewVault() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.noSpaceForVaults = true
        fromRemoveDialog(api, m, ::isDan)
        m.run({ vaults.moveEverything(assertNotNull(api.snapshot.account?.moving), "Family 2") })
        val stopped = assertNotNull(api.snapshot.account?.moving)
        val stop = assertNotNull(stopped.stopped)
        // The check for space runs before anything is signed or sent, as the engine's: no vault is made, nothing copied.
        assertEquals(MoveStage.CREATE_VAULT, stop.stage)
        assertEquals(0, stop.copied)
        assertEquals(0, me(api).vaults.count { it.name == "Family 2" })
        val lines = moveStopLines(stopped, 0).map { it.shown() }
        assertEquals(UiText.ph(Placeholder.MOVE_STOPPED_CREATING).shown(), lines[0])
        assertEquals(UiText.Awaiting(fillCopy(CopyKey.MOVE_STOPPED, "Family 2", "Family", stop.copied.toString(), stop.total.toString())).shown(), lines[1])
        assertTrue(lines[1].contains("Family 2") && lines[1].contains("${stop.copied} of ${stop.total}"))
        // After a stop no name is asked: the run carries on into the vault it made.
        assertTrue(view.contains("if (!carriesOn) Field("))

        m.act { vaults.closeMoveEverything() }
        api.script.noSpaceForVaults = false
        m.run({ vaults.openMoveEverything(assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }) })
        val again = assertNotNull(api.snapshot.account?.moving)
        assertNotNull(again.stopped, "opened again, it says where it stopped")
        m.run({ vaults.moveEverything(again, "") })
        assertEquals(1, me(api).vaults.count { it.name == "Family 2" }, "the same new vault")
        assertEquals(3, vault(api, "Family 2").itemCount)
        assertTrue(vault(api, "Family 2").members.none { it.contact == null && it.userId != me(api).userId }, "Dan never added")
        assertTrue(vault(api, "Family").purgeAtMs > 0L)
    }

    @Test
    fun outOfSpaceStopsTheMoveInTheSharedCodesWordsAndLeavesTheOldVaultWhole() {
        val (api, m) = at(FakeScene.VAULTS)
        api.script.noSpaceForVaults = true
        fromRemoveDialog(api, m, ::isBo)
        m.run({ vaults.moveEverything(assertNotNull(api.snapshot.account?.moving), "Family 2") })
        val screen = assertNotNull(api.snapshot.account?.moving)
        assertEquals(VaultActionResult.OUT_OF_SPACE, screen.stopped?.result)
        assertEquals(CopyKey.OWNER_OUT_OF_SPACE.english, moveStopLines(screen, 0).last().shown())
        val old = vault(api, "Family")
        assertEquals(3, old.itemCount)
        assertEquals(0L, old.purgeAtMs)
        assertEquals(0, me(api).vaults.count { it.name == "Family 2" }, "no new vault is made while short of space")
    }
}
