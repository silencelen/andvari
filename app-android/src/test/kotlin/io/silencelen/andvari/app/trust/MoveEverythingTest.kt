package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.MemberRow
import io.silencelen.andvari.core.app.MoveEverythingScreen
import io.silencelen.andvari.core.app.MoveKept
import io.silencelen.andvari.core.app.MoveStage
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeVault
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
 * "Move everything to a new vault" on the rules of 2026-11-16 (design §3.13, as the shared code plays them),
 * over the fake. What reaches the new vault is read from the fake's own state, never from the screen.
 */
class MoveEverythingTest {
    private class At(val api: FakeAppApi, val m: TrustModel) {
        val me: FakeAccount get() = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
        val family: FakeVault get() = me.vaults.first { it.name == "Family" }
        fun vaultsNamed(name: String): List<FakeVault> = me.vaults.filter { it.name == name }
        val moving: MoveEverythingScreen get() = assertNotNull(assertNotNull(api.snapshot.account).moving, "the move's screen is open")
        fun memberRow(userId: String): MemberRow = assertNotNull(assertNotNull(api.snapshot.account).members).members.first { it.userId == userId }
    }

    private fun at(scene: FakeScene): At {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return At(api, TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }, { false }, {}))
    }

    /**
     * Family's members on the fake: the owner, Bo (a writer, a current contact) and Cy (a reader, a current contact whose
     * code was compared), every one of them addable from this phone. The scene's Dan, whom the server names and nobody
     * here can add, is kept only when [withDan].
     */
    private fun membersAllAddable(withDan: Boolean = false): At {
        val at = at(FakeScene.MEMBERS)
        val cy = at.me.contacts.first { it.label == "Cy" }
        cy.compared = true
        val dan = at.family.members.first { it.contact == null && it.userId != at.me.userId }
        if (withDan) dan.deletedByOperator = false else at.family.members -= dan
        at.family.addMember("Cy", RoleInVault.READER, cy)
        at.api.script.changed()
        return at
    }

    private fun bo(at: At): String = at.me.contacts.first { it.label == "Bo" }.userId

    private fun cy(at: At): String = at.me.contacts.first { it.label == "Cy" }.userId

    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    @Test
    fun fromTheRemoveDialogTheRemovedMemberIsRemovedFirstAndNeverAddedToTheNewVault() {
        val at = membersAllAddable()
        moveEverythingRemoving(at.m, at.memberRow(bo(at)))
        val screen = at.moving
        assertEquals(bo(at), assertNotNull(screen.removing, "the screen names who is being removed").userId)
        assertTrue(screen.members.none { it.userId == bo(at) }, "the member being removed is not among those added")
        assertNull(screen.oldVaultKept)
        startMove(at.m, screen, "Family 2")

        val made = at.vaultsNamed("Family 2").single()
        assertTrue(made.members.none { it.userId == bo(at) }, "the removed member is not in the new vault: ${made.members.map { it.serverName }}")
        assertTrue(made.members.any { it.userId == cy(at) }, "the remaining member is added again")
        assertEquals(RoleInVault.READER, made.members.first { it.userId == cy(at) }.role, "with the role they hold now")
        assertTrue(at.family.members.none { it.userId == bo(at) }, "their remove was signed on the old log")
        assertTrue(at.family.purgeAtMs > 0, "the old vault is deleted last, into its grace")
        assertEquals(3, made.itemCount)
        assertNull(assertNotNull(at.api.snapshot.account).moving, "a move that deleted the old vault closes")

        // The dialog calls the move the new way: from the remove dialog it names the member.
        val dialog = src("VaultScreens.kt").substringAfter("removing?.let { m ->").substringBefore("Quieter(UiText.ph(Placeholder.CLOSE)")
        assertTrue(dialog.contains("moveEverythingRemoving(model, m)"))
        assertFalse(dialog.contains("openMoveEverything("), "the old call would add the removed member to the new vault")
    }

    @Test
    fun aVaultInGoodStandingHasNoTicksAndAddsEveryRemainingMember() {
        val at = membersAllAddable()
        at.m.run({ vaults.openMoveEverything(at.api.snapshot.account!!.vaults.first { it.name == "Family" }) })
        var screen = at.moving
        assertFalse(screen.ticksOffered)
        assertEquals(setOf(bo(at), cy(at)), screen.members.map { it.userId }.toSet())
        // An untick does nothing on a vault in good standing.
        at.api.vaults.tickMember(screen, screen.members.first { it.userId == cy(at) }, false)
        screen = at.moving
        assertTrue(screen.members.all { it.ticked && it.canBeAdded })
        val lines = moveBeforeStartLines(screen).map { it.shown() }
        assertEquals(UiText.of(CopyKey.MOVE_ONLY_LIVE_ITEMS).shown(), lines.first(), "what moves is said before the start")
        assertEquals(1, lines.size, "nothing keeps the old vault: $lines")
        startMove(at.m, screen, "Family 2")
        val made = at.vaultsNamed("Family 2").single()
        assertEquals(setOf(at.me.userId, bo(at), cy(at)), made.members.map { it.userId }.toSet())
        assertTrue(at.family.purgeAtMs > 0)

        // Tick boxes are drawn only where the screen says ticks are offered.
        val view = src("VaultScreens.kt").substringAfter("private fun MoveEverythingView(")
        val ticks = view.substringAfter("if (screen.ticksOffered) {").substringBefore("} else {")
        assertTrue(ticks.contains("Checkbox("))
        assertEquals(1, Regex("Checkbox\\(").findAll(view).count(), "no other tick box on the move's screen")
    }

    @Test
    fun aFrozenVaultOffersTicksNoneTickedWithTheWarningAndKeepsTheOldVault() {
        val at = at(FakeScene.MOVE_EVERYTHING_FROZEN)
        val row = assertNotNull(at.api.snapshot.account).vaults.first { it.name == "Family" }
        assertEquals(VaultLogState.FROZEN, row.log)
        assertFalse(row.writable)
        assertTrue(moveEverythingOffered(row), "the way out of a frozen vault is offered on its row")
        var screen = at.moving
        assertTrue(screen.ticksOffered && screen.sourceStays)
        assertTrue(screen.members.isNotEmpty() && screen.members.none { it.ticked }, "none is ticked")
        assertEquals(MoveKept.SOURCE_STAYS, screen.oldVaultKept)
        val lines = moveBeforeStartLines(screen).map { it.shown() }
        assertTrue(UiText.of(CopyKey.MOVE_KEPT_SOURCE_STAYS).shown() in lines, "the shared code's key: $lines")
        assertTrue(Placeholder.entries.none { it.name == "MOVE_SOURCE_STAYS" }, "the app's own placeholder is gone")

        val bo = screen.members.first { it.canBeAdded }
        at.api.vaults.tickMember(screen, bo, true)
        screen = at.moving
        assertTrue(screen.members.first { it.userId == bo.userId }.ticked)
        val seqBefore = at.family.members.size
        startMove(at.m, screen, "Family, again")
        val made = at.vaultsNamed("Family, again").single()
        assertEquals(setOf(at.me.userId, bo.userId), made.members.map { it.userId }.toSet(), "only the ticked are added")
        assertEquals(0L, at.family.purgeAtMs, "the frozen vault stays where it is")
        assertEquals(seqBefore, at.family.members.size)
        screen = at.moving
        val finished = assertNotNull(screen.finished, "a move that kept the old vault stays on screen")
        assertEquals(MoveKept.SOURCE_STAYS, finished.oldKept)
        assertTrue(moveFinishedLines(screen).any { it.shown() == UiText.of(CopyKey.MOVE_KEPT_SOURCE_STAYS).shown() })
        at.m.act { vaults.closeMoveEverything() }
        assertNull(assertNotNull(at.api.snapshot.account).moving)
    }

    @Test
    fun aMemberWhoCannotBeAddedIsNamedBeforeTheStartAndTheOldVaultIsKept() {
        val at = membersAllAddable(withDan = true)
        val dan = at.family.members.first { it.contact == null && it.userId != at.me.userId }
        moveEverythingRemoving(at.m, at.memberRow(bo(at)))
        var screen = at.moving
        assertEquals(MoveKept.MEMBER_CANNOT_BE_ADDED, screen.oldVaultKept)
        val danRow = screen.members.first { it.userId == dan.userId }
        assertFalse(danRow.canBeAdded)
        val lines = moveBeforeStartLines(screen).map { it.shown() }
        val keptAt = lines.indexOf(UiText.of(CopyKey.MOVE_KEPT_NOT_ADDED).shown())
        assertTrue(keptAt > 0, "the reason is said before the start: $lines")
        assertEquals(personLine(danRow.who).shown(), lines[keptAt + 1], "and the person is named")

        startMove(at.m, screen, "Family 2")
        val made = at.vaultsNamed("Family 2").single()
        assertEquals(setOf(at.me.userId, cy(at)), made.members.map { it.userId }.toSet(), "the others are added; Bo, being removed, is not")
        assertEquals(0L, at.family.purgeAtMs, "the old vault is kept")
        assertTrue(at.family.members.any { it.userId == dan.userId }, "Dan keeps it")
        screen = at.moving
        val finished = assertNotNull(screen.finished)
        assertEquals(MoveKept.MEMBER_CANNOT_BE_ADDED, finished.oldKept)
        val done = moveFinishedLines(screen).map { it.shown() }
        assertTrue(UiText.of(CopyKey.MOVE_KEPT_NOT_ADDED).shown() in done && personLine(danRow.who).shown() in done, "$done")
        val into = moveFinishedLines(screen).first()
        assertEquals(Placeholder.MOVE_FINISHED_INTO, assertIs<UiText.Ph>(into).placeholder, "into which vault: $done")
        assertTrue(into.shown().contains("Family 2"), "into which vault: $done")
    }

    @Test
    fun outOfSpaceStopsSaysWhereAndASecondRunCarriesOnIntoTheSameNewVault() {
        val at = membersAllAddable()
        at.api.script.noSpaceForVaults = true
        moveEverythingRemoving(at.m, at.memberRow(bo(at)))
        startMove(at.m, at.moving, "Family 2")

        var screen = at.moving
        val stop = assertNotNull(screen.stopped)
        // The check for space runs before anything is signed or sent, as the engine's: no vault is made, nothing copied.
        assertEquals(MoveStage.CREATE_VAULT, stop.stage)
        assertEquals(VaultActionResult.OUT_OF_SPACE, stop.result)
        val lines = moveStopLines(screen).map { it.shown() }
        assertEquals(Placeholder.MOVE_STOPPED_MAKING_VAULT, (moveStopLines(screen)[0] as UiText.Ph).placeholder, "at which step, a sentence of its own")
        assertEquals(UiText.of(CopyKey.MOVE_STOPPED, "Family 2", "Family", "0", "3").shown(), lines[1])
        assertTrue(lines[1].contains("0 of 3") && lines[1].contains("Family 2") && !lines[1].contains("{"), lines[1])
        assertEquals(CopyKey.OWNER_OUT_OF_SPACE.english, lines[2], "the refusal for space, in the approved words")
        assertNull(at.m.saidOn(at.api.snapshot), "the stop is said once, by the move's own lines")
        assertTrue(at.vaultsNamed("Family 2").isEmpty(), "no vault is made")
        assertEquals(0L, at.family.purgeAtMs, "the old vault is untouched")

        // Space is made; the move is closed and opened again from the vault's row: it carries on.
        at.api.script.noSpaceForVaults = false
        at.m.act { vaults.closeMoveEverything() }
        val row = assertNotNull(at.api.snapshot.account).vaults.first { it.name == "Family" }
        assertTrue(moveEverythingOffered(row))
        at.m.run({ vaults.openMoveEverything(row) })
        screen = at.moving
        assertNotNull(screen.stopped, "the screen says where the last run stopped")
        startMove(at.m, screen, "")

        val made = at.vaultsNamed("Family 2").single()
        assertEquals(3, made.itemCount, "the same new vault, now with every item")
        assertTrue(made.members.none { it.userId == bo(at) })
        assertTrue(made.members.any { it.userId == cy(at) })
        assertTrue(at.family.purgeAtMs > 0)
        assertEquals(1, at.me.vaults.count { it.name.startsWith("Family ") }, "no second new vault")
    }

    @Test
    fun itemsThisPhoneCannotReadAreCountedBeforeTheStartAndKeepTheOldVault() {
        val at = membersAllAddable()
        at.family.unreadable = 2
        at.api.script.changed()
        at.m.run({ vaults.openMoveEverything(at.api.snapshot.account!!.vaults.first { it.name == "Family" }) })
        val screen = at.moving
        assertEquals(MoveKept.UNREADABLE_ITEMS, screen.oldVaultKept)
        assertTrue(UiText.of(CopyKey.MOVE_KEPT_UNREADABLE, "2").shown() in moveBeforeStartLines(screen).map { it.shown() })
        startMove(at.m, screen, "Family 2")
        assertEquals(1, at.vaultsNamed("Family 2").single().itemCount, "only what this phone can read is copied")
        assertEquals(0L, at.family.purgeAtMs, "the old vault is kept so nothing is lost")
        assertEquals(MoveKept.UNREADABLE_ITEMS, assertNotNull(at.moving.finished).oldKept)
    }

    @Test
    fun keysWithValuesAreFilledAndShownAsTheOwnersPlaceholders() {
        val stopped = UiText.of(CopyKey.MOVE_STOPPED, "New", "Old", "2", "5")
        // Shown as a placeholder exactly while the key awaits its words; filled either way.
        assertEquals(CopyKey.MOVE_STOPPED.awaitingOwner, stopped.isPlaceholder)
        val shown = stopped.shown()
        assertTrue(shown.contains("2 of 5") && shown.contains("New") && shown.contains("Old") && !shown.contains("{"), shown)
        assertEquals(if (stopped.isPlaceholder) 1 else 0, Regex("⟦").findAll(shown).count(), "no doubled brackets")
        val unreadable = UiText.of(CopyKey.MOVE_KEPT_UNREADABLE, "4").shown()
        assertTrue(unreadable.contains("4 items in this vault") && !unreadable.contains("{"), unreadable)
        assertEquals(CopyKey.OWNER_OUT_OF_SPACE.english, UiText.of(CopyKey.OWNER_OUT_OF_SPACE, "x").shown())
    }
}
