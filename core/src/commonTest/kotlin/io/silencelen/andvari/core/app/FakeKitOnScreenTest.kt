package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The fake plays what the engine does around a kit on the screen, so that the apps' walks over it prove the rules and
 * not a stand-in: the lock's wipe of a kit shown with a refusal and its notice, a commit that happened and could not be
 * opened, a move's kept deletions, every kit's idle limit, the line of a kit that replaces one shown and never confirmed,
 * and the unlock of a surface that only fills.
 */
class FakeKitOnScreenTest {
    private val newPassword = "a brand new master password"

    private fun lockedWithKitOwed(autoLockSeconds: Int = 300): Pair<FakeAppApi, io.silencelen.andvari.core.app.fake.FakeAccount> {
        val app = FakeAppApi()
        val account = app.script.publicInstance.addAccount(ADA, PW)
        account.kitSaved = false
        account.server.autoLockSeconds = autoLockSeconds
        app.script.storeSession(account)
        app.start()
        return app to account
    }

    @Test
    fun aLockWipesAKitShownWithARefusalAndOnlyTheDismissTakesTheNotice() {
        val app = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        app.script.refusedAfterCommit = io.silencelen.andvari.core.client.session.Establishing.IDENTITY_MISMATCH
        assertEquals(ReplacePasswordResult.IDENTITY_FAULT_COMMITTED, await { app.entry.chooseReplacementPassword(app.on(), newPassword) })
        val kit = app.on<EntryScreen.Kit>().kit
        val line = assertNotNull(kit.notKeptLine)
        assertEquals(300_000L, kit.idleLockAfterMs)
        assertEquals(CopyKey.KIT_IDLE_WARNING, kit.idleWarningLine)

        app.lock()
        val notice = assertNotNull(app.snapshot.kitWiped, "the lock wiped the kit and says so")
        assertEquals(CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE, notice.line)
        assertEquals(CopyKey.RECOVERY_COMMITTED_IDENTITY_FAULT, line)
        assertEquals(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT, notice.whyHere, "the reason without the kit")
        assertNull(notice.wayOut, "the identity fault has no sign-out or removal")
        assertFalse(app.snapshot.entry is EntryScreen.Kit, "nothing of the kit is on show")
        assertNull(app.kit.kitDocument(kit), "and nothing of it can be read")
        app.lock()
        assertSame(notice, app.snapshot.kitWiped, "a second lock keeps it")
        app.dismissKitWiped(io.silencelen.andvari.core.app.KitWipedNotice.of(true, notice.email, notice.whyHere))
        assertSame(notice, app.snapshot.kitWiped, "another notice's dismissal does not take it")
        app.dismissKitWiped(notice)
        assertNull(app.snapshot.kitWiped)
    }

    /**
     * As the engine: a kit that came on show while nothing of the app was on show ([AppApi.wentAway]) and was wiped by a
     * lock before the app came back was never seen, and its notice says so; where the app came back first, the kit was on
     * the screen and the line is the ordinary one.
     */
    @Test
    fun aKitWipedBeforeTheAppCameBackIsSaidAsNeverShown() {
        for (back in listOf(false, true)) {
            val app = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
            app.script.refusedAfterCommit = io.silencelen.andvari.core.client.session.Establishing.IDENTITY_MISMATCH
            app.wentAway()
            assertEquals(ReplacePasswordResult.IDENTITY_FAULT_COMMITTED, await { app.entry.chooseReplacementPassword(app.on(), newPassword) })
            app.on<EntryScreen.Kit>()
            if (back) app.returnedToForeground()
            app.lock()
            val notice = assertNotNull(app.snapshot.kitWiped, "back=$back")
            assertEquals(!back, notice.unseen, "back=$back")
            assertEquals(if (back) CopyKey.KIT_WIPED_AFTER_RECOVERY_NOT_HERE else CopyKey.KIT_WIPED_UNSEEN_AFTER_RECOVERY_NOT_HERE, notice.line, "back=$back")
            assertEquals(CopyKey.KIT_NOT_HERE_WHY_IDENTITY_FAULT, notice.whyHere, "back=$back")
        }
    }

    /**
     * As the engine ([io.silencelen.andvari.core.app.engine.EngineEntry.afterKitWiped]): where the first screen carried its
     * mark of a kept session this device could not confirm, and the journey went from there to a kit shown with a refusal,
     * a lock that wipes the kit comes back to a first screen that still carries the mark, beside the notice of the wiped
     * kit. Before: the first screen came back without the mark.
     */
    @Test
    fun aLockThatWipesAKitKeepsTheFirstScreensMarkOfASessionNotConfirmed() {
        val app = FakeAppApi()
        val kept = app.script.publicInstance.addAccount(ADA, PW)
        app.script.storeSession(kept)
        app.start()
        app.script.sessionNotConfirmed()
        val locked = assertNotNull(app.snapshot.locked)
        assertTrue(locked.sessionNotConfirmed)
        app.signInAgain(locked)
        assertTrue(app.on<EntryScreen.FirstRun>().sessionNotConfirmed, "the mark, before the journey")
        // From that first screen, a kit's recovery of the kept account (another address is refused beside a kept account),
        // whose commit the keeper refuses: its kit is shown with the refusal.
        val lost = kept
        app.entry.openSignIn(app.on())
        app.entry.openForgot(app.on())
        app.entry.openKitEntry(app.on())
        await { app.entry.submitKit(app.on(), app.script.kitOf(lost), PayloadSource.SCANNED) }
        await { app.entry.confirmKitRecovery(app.on()) }
        app.script.refusedAfterCommit = io.silencelen.andvari.core.client.session.Establishing.IDENTITY_MISMATCH
        assertEquals(ReplacePasswordResult.IDENTITY_FAULT_COMMITTED, await { app.entry.chooseReplacementPassword(app.on(), newPassword) })
        assertNotNull(app.on<EntryScreen.Kit>().kit.notKeptLine)

        app.lock()
        assertNotNull(app.snapshot.kitWiped, "the lock wiped the kit and says so")
        val first = app.on<EntryScreen.FirstRun>()
        assertTrue(first.sessionNotConfirmed, "the mark stands beside the notice of the wiped kit")
        assertEquals(CopyKey.SESSION_NOT_CONFIRMED_SIGN_OUT_FIRST, first.sessionNotConfirmedBesideSignOut)
    }

    @Test
    fun aRecoveryCommitThatCouldNotBeOpenedIsSaidAsThatOnTheFirstScreen() {
        val app = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        app.script.recoveryCommitNotOpened = true
        // Also when another session was refused meanwhile: never "stale", never the password step again.
        app.script.anotherAccountTakenDuringCommit = true
        val r = await { app.entry.chooseReplacementPassword(app.on(), newPassword) }
        assertEquals(ReplacePasswordResult.COMMITTED_NOT_OPENED, r)
        assertEquals(CopyKey.RECOVERY_COMMITTED_NOT_OPENED, r.sentence)
        app.on<EntryScreen.FirstRun>()
    }

    @Test
    fun aMovesKeptDeletionsAreCountedAndSaid() = kotlinx.coroutines.runBlocking<Unit> {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.script.moveDeleteUnanswered = true
        // From the remove dialog of the member who cannot be added here, so that the old vault is to be deleted.
        assertEquals(VaultActionResult.DONE, app.vaults.openMoveEverything(app.vault("Family")))
        val cannot = assertNotNull(app.account.moving).members.first { !it.canBeAdded }.userId
        app.vaults.closeMoveEverything()
        assertEquals(VaultActionResult.DONE, app.vaults.openMembers(app.vault("Family")))
        assertEquals(VaultActionResult.DONE, app.vaults.openMoveEverythingRemoving(assertNotNull(app.account.members).members.first { it.userId == cannot }))
        app.vaults.closeMembers()
        assertEquals(VaultActionResult.SENT_PENDING, app.vaults.moveEverything(assertNotNull(app.account.moving), "Family 2"))
        app.script.moveDeletionsKept = 2
        assertTrue(app.script.serverStoresMoveDeleteLater(added = 0, changed = 0))
        val notice = app.account.movesStoredOutside.single()
        assertEquals(2, notice.deletionsKept)
        assertEquals(CopyKey.MOVE_STORED_DELETIONS_KEPT, notice.keptLine?.key)
        assertEquals(0, notice.deletionsCarried)
        assertNull(notice.carriedLine)
    }

    @Test
    fun everyKitHasItsLimitAndAKitReplacingOneShownAndNeverConfirmedSaysSo() {
        val (app, _) = lockedWithKitOwed(autoLockSeconds = 60)
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        val first = app.on<EntryScreen.Kit>().kit
        assertEquals(KitReason.NEVER_SAVED, first.reason)
        assertEquals(60_000L, first.idleLockAfterMs)
        assertEquals(30_000L, first.idleWarnBeforeMs)
        assertEquals(CopyKey.KIT_IDLE_WARNING, first.idleWarningLine)
        assertNull(first.earlierKitVoidLine, "none was shown here before")

        app.lock()
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        val next = app.on<EntryScreen.Kit>().kit
        assertEquals(CopyKey.KIT_EARLIER_NOT_CONFIRMED_VOID, next.earlierKitVoidLine)
        app.kit.proceedToConfirm(next)
        assertNull(app.on<EntryScreen.Kit>().kit.earlierKitVoidLine, "only on the first step")
        app.kit.showKitAgain(app.on<EntryScreen.Kit>().kit)
        app.saveKit()
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)

        // Confirmed: a kit made in Settings replaces a confirmed one and says nothing of the kind; it has the policy's limit.
        assertEquals(RecoveryChangeResult.DONE, await { app.recovery.makeKit(PW) })
        val settings = assertNotNull(app.account.kit)
        assertNull(settings.earlierKitVoidLine)
        assertEquals(60_000L, settings.idleLockAfterMs)
        assertEquals(CopyKey.KIT_IDLE_WARNING, settings.idleWarningLine)
    }

    @Test
    fun anUnlockFromASurfaceThatOnlyFillsMakesNoKit() {
        val (app, account) = lockedWithKitOwed()
        val serial = account.kitSerial
        val fill: UnlockForFilling = app
        assertEquals(VaultUnlockResult.DONE, await { fill.unlockForFilling(assertNotNull(app.snapshot.locked), PW) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals(serial, account.kitSerial, "the server's kit was not replaced")
        assertNull(app.account.kit)
        assertTrue(app.account.kitDueAtOpening)
        app.lock()
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        assertEquals(KitReason.NEVER_SAVED, app.on<EntryScreen.Kit>().kit.reason)
        app.saveKit()
        assertFalse(app.account.kitDueAtOpening)
    }
}
