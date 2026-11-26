package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What the Android map's gaps asked of the API, walked through the fake: quick unlock (G3), two-step sign-in in
 * Settings (G6), the client policy (G7), a new kit after a followed move, and the operator account refused on a
 * phone however it arrives (§9.1).
 */
class AppApiSettingsTest {
    // ---- G3: quick unlock ----

    @Test
    fun quickUnlockOpensTheLockedVaultAndFallsBackToThePasswordWhenItMust() {
        val app = FakeScenes.at(FakeScene.LOCKED)
        val locked = assertNotNull(app.snapshot.locked)
        assertTrue(locked.quickUnlock, "set up on this device: the biometric button shows")
        app.script.biometricsCancelled = true
        assertEquals(QuickUnlockResult.CANCELLED, await { app.quickUnlock(locked) })
        app.script.biometricsRefused = true
        assertEquals(QuickUnlockResult.USE_PASSWORD, await { app.quickUnlock(locked) })
        assertTrue(locked === app.snapshot.locked, "neither changes the lock screen")
        assertEquals(QuickUnlockResult.DONE, await { app.quickUnlock(locked) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals(QuickUnlockResult.STALE, await { app.quickUnlock(locked) })
        assertEquals(QuickUnlockState.ON, app.account.quickUnlock.state)

        // The periodic full password: the lock screen asks for it, and one password unlock is enough.
        app.script.passwordDue = true
        app.lock()
        val due = assertNotNull(app.snapshot.locked)
        assertFalse(due.quickUnlock)
        assertEquals(QuickUnlockResult.USE_PASSWORD, await { app.quickUnlock(due) })
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(due, PW) })
        app.lock()
        assertTrue(assertNotNull(app.snapshot.locked).quickUnlock)

        // New biometrics invalidate the device's key: quick unlock turns off, and Settings offers it again.
        app.script.biometricsChanged = true
        assertEquals(QuickUnlockResult.TURNED_OFF, await { app.quickUnlock(assertNotNull(app.snapshot.locked)) })
        assertFalse(assertNotNull(app.snapshot.locked).quickUnlock)
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        assertEquals(QuickUnlockState.OFF, app.account.quickUnlock.state)
    }

    @Test
    fun underADamagedPinNoPromptIsShownAndUnderAForkItOpensReadOnly() {
        val damaged = FakeScenes.at(FakeScene.LOCKED)
        damaged.script.pinRecordDamaged(null)
        assertEquals(QuickUnlockResult.SERVER_BLOCKED, await { damaged.quickUnlock(assertNotNull(damaged.snapshot.locked)) })

        val stopped = FakeScenes.at(FakeScene.LOCKED_SERVER_STOPPED)
        assertEquals(QuickUnlockResult.DONE, await { stopped.quickUnlock(assertNotNull(stopped.snapshot.locked)) })
        assertTrue(stopped.account.serverStopped)
        assertFalse(stopped.account.quickUnlock.offerNow)
    }

    @Test
    fun quickUnlockIsTurnedOnFromTheOfferAndOffAgainAndGoesWithTheSession() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.script.quickUnlock = false
        app.lock()
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        val offer = app.account.quickUnlock
        assertEquals(QuickUnlockState.OFF, offer.state)
        assertTrue(offer.offerNow)
        app.script.biometricsCancelled = true
        assertEquals(QuickEnrolResult.CANCELLED, await { app.settings.turnOnQuickUnlock(offer) })
        assertTrue(offer === app.account.quickUnlock, "a cancelled prompt changes nothing")
        assertEquals(QuickEnrolResult.DONE, await { app.settings.turnOnQuickUnlock(offer) })
        val on = app.account.quickUnlock
        assertEquals(QuickUnlockState.ON, on.state)
        assertFalse(on.offerNow)
        assertEquals(QuickEnrolResult.STALE, await { app.settings.turnOnQuickUnlock(offer) })
        app.settings.turnOffQuickUnlock(on)
        assertEquals(QuickUnlockState.OFF, app.account.quickUnlock.state)
        assertEquals(QuickEnrolResult.DONE, await { app.settings.turnOnQuickUnlock(app.account.quickUnlock) })
        assertEquals(PlainResult.DONE, await { app.signOut() })
        assertFalse(app.script.quickUnlock, "it goes with the session")
    }

    @Test
    fun theOfferPutOffReturnsAfterThreePasswordUnlocksAndAtMostTwice() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.script.quickUnlock = false
        var cards = 0
        repeat(12) {
            val q = app.account.quickUnlock
            if (q.offerNow) {
                cards++
                app.settings.quickUnlockNotNow(q)
                assertFalse(app.account.quickUnlock.offerNow)
            }
            app.lock()
            assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        }
        assertEquals(3, cards)
    }

    @Test
    fun withoutABiometricOrUnderAForbiddingPolicyItCannotBeTurnedOn() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.script.quickUnlock = false
        app.script.biometricAvailable = false
        app.lock()
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        assertEquals(QuickUnlockState.UNAVAILABLE, app.account.quickUnlock.state)
        assertEquals(QuickEnrolResult.NOT_AVAILABLE, await { app.settings.turnOnQuickUnlock(app.account.quickUnlock) })
        app.script.biometricAvailable = true
        app.scriptServer(app.snapshot.instance!!.label.origin).offlineCacheAllowed = false
        app.lock()
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        assertEquals(QuickUnlockState.NOT_ALLOWED, app.account.quickUnlock.state)
        assertFalse(app.account.quickUnlock.offerNow)
    }

    // ---- G6: two-step sign-in in Settings ----

    @Test
    fun twoStepIsTurnedOnWithThePasswordAndAFirstCodeAndOffWithACode() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        assertNull(app.account.twoStep)
        assertEquals(PlainResult.DONE, await { app.settings.openTwoStep() })
        val off = assertNotNull(app.account.twoStep)
        assertFalse(off.enabled)
        assertNull(off.enrolment)
        assertEquals(TwoStepResult.WRONG_PASSWORD, await { app.settings.startTwoStep(off, "not the password") })
        assertEquals(TwoStepResult.DONE, await { app.settings.startTwoStep(off, PW) })
        val enrolment = assertNotNull(assertNotNull(app.account.twoStep).enrolment)
        val key = assertNotNull(app.settings.twoStepKey(enrolment))
        assertTrue(key.uri.startsWith("otpauth://totp/") && key.uri.contains(key.secret))
        assertEquals(TwoStepResult.WRONG_CODE, await { app.settings.confirmTwoStep(enrolment, "000000") })
        assertEquals(TwoStepResult.DONE, await { app.settings.confirmTwoStep(enrolment, app.script.authenticatorCode) })
        val on = assertNotNull(app.account.twoStep)
        assertTrue(on.enabled)
        assertNull(on.enrolment)
        assertNull(app.settings.twoStepKey(enrolment), "the key is readable only while its enrolment is on show")
        // A code alone no longer turns it off (decided on 2026-11-16): the fake answers as the engine does.
        assertEquals(TwoStepResult.PASSWORD_NEEDED, await { app.settings.turnOffTwoStep(on, app.script.authenticatorCode) })
        assertTrue(assertNotNull(app.account.twoStep).enabled)
        // A new key: the code and the password, in the server's order; the old key stays until the new one is confirmed.
        assertEquals(TwoStepResult.WRONG_PASSWORD, await { app.settings.replaceTwoStepKey(on, app.script.authenticatorCode, "not the password") })
        assertEquals(TwoStepResult.DONE, await { app.settings.replaceTwoStepKey(on, app.script.authenticatorCode, PW) })
        val replacing = assertNotNull(app.account.twoStep)
        assertTrue(replacing.enabled)
        assertEquals(TwoStepResult.DONE, await { app.settings.confirmTwoStep(assertNotNull(replacing.enrolment), app.script.authenticatorCode) })
        val again = assertNotNull(app.account.twoStep)
        assertEquals(TwoStepResult.WRONG_PASSWORD, await { app.settings.turnOffTwoStepWithPassword(again, "000000", "not the password") }, "the password first, whatever the code")
        app.script.twoStepTriesLocked = true
        assertEquals(TwoStepResult.TOO_MANY_TRIES, await { app.settings.turnOffTwoStepWithPassword(again, app.script.authenticatorCode, PW) })
        app.script.twoStepTriesLocked = false
        assertEquals(TwoStepResult.WRONG_CODE, await { app.settings.turnOffTwoStepWithPassword(again, "000000", PW) })
        assertEquals(TwoStepResult.DONE, await { app.settings.turnOffTwoStepWithPassword(again, app.script.authenticatorCode, PW) })
        assertFalse(assertNotNull(app.account.twoStep).enabled)
        app.settings.closeTwoStep()
        assertNull(app.account.twoStep)
    }

    // ---- "update required" as the session's server's state ----

    @Test
    fun updateRequiredIsAStateOfTheSessionsServerThatClosesNothingAndClearsByItself() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        assertFalse(app.snapshot.instance!!.updateRequired)
        val server = app.scriptServer(app.snapshot.instance!!.label.origin)
        val before = assertNotNull(app.content)
        assertFalse(before.state.serverStopped)
        server.tooNewForThisBuild = true
        assertEquals(VaultActionResult.UPDATE_REQUIRED, await { app.vaults.createVault("Family") })
        assertTrue(app.snapshot.instance!!.updateRequired)
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase, "the vault stays open")
        // As on the engine, the content is read-only while it stands (the fake stops the one it has).
        val halted = assertNotNull(app.content)
        assertTrue(halted.state.serverStopped)
        server.tooNewForThisBuild = false
        assertEquals(VaultActionResult.DONE, await { app.vaults.createVault("Family") })
        assertFalse(app.snapshot.instance!!.updateRequired)
        val after = assertNotNull(app.content)
        assertNotSame(halted, after, "composed again once it cleared")
        assertFalse(after.state.serverStopped)
    }

    // ---- G7: the client policy ----

    @Test
    fun thePolicyIsReadOnlyOnTheSnapshotAndClamped() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        val p = app.account.policy
        assertTrue(p.known)
        assertEquals(300, p.autoLockSeconds)
        assertEquals(30, p.clipboardClearSeconds)
        assertTrue(p.offlineCacheAllowed)
        assertTrue(p.attachmentMaxBytes > 0 && p.itemAttachmentsMaxBytes >= p.attachmentMaxBytes)
        // A server cannot turn the auto-lock off or keep a secret on the clipboard for hours.
        val server = app.scriptServer(app.snapshot.instance!!.label.origin)
        server.autoLockSeconds = 0
        server.clipboardClearSeconds = 86_400
        app.lock()
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        assertEquals(io.silencelen.andvari.core.client.ClientPolicyClamps.AUTO_LOCK_MAX_SECONDS, app.account.policy.autoLockSeconds)
        assertEquals(io.silencelen.andvari.core.client.ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS, app.account.policy.clipboardClearSeconds)
    }

    // ---- §4.4, R36: a new kit after a followed move ----

    @Test
    fun aFollowedMoveAsksForANewKitUntilOneIsMade() {
        val moved = FakeScenes.at(FakeScene.CARD_MOVED)
        assertNull(moved.account.kitAfterMove)
        val card = assertIs<InstanceCardState.Moved>(moved.snapshot.instance?.card)
        assertEquals(MoveResult.DONE, await { moved.instance.followMove(card) })
        val prompt = assertNotNull(moved.account.kitAfterMove)
        assertEquals("https://vault.newhome.example", prompt.instance.origin)
        moved.recovery.kitAfterMoveLater(prompt)
        assertNull(moved.account.kitAfterMove, "put off until the next unlock")
        moved.lock()
        assertEquals(VaultUnlockResult.DONE, await { moved.unlock(assertNotNull(moved.snapshot.locked), PW) })
        val again = assertNotNull(moved.account.kitAfterMove)
        assertEquals(RecoveryChangeResult.DONE, await { moved.recovery.makeKit(PW) })
        assertNull(moved.account.kitAfterMove)
        assertNotNull(moved.account.kit)
        assertTrue(again.instance.origin == prompt.instance.origin)
    }

    /** §4.4: a move whose data on this device did not move keeps the vault shut until it is finished. */
    @Test
    fun aMoveWhoseDataDidNotMoveKeepsTheVaultShutUntilItIsFinished() {
        val moved = FakeScenes.at(FakeScene.CARD_MOVED)
        moved.script.namespaceMoveFails = true
        val card = assertIs<InstanceCardState.Moved>(moved.snapshot.instance?.card)
        assertEquals(MoveResult.NOT_FINISHED, await { moved.instance.followMove(card) })
        assertEquals(AppPhase.LOCKED, moved.snapshot.phase, "an open vault locks")
        val instance = assertNotNull(moved.snapshot.instance)
        assertEquals("https://vault.newhome.example", instance.label.origin)
        assertIs<InstanceCardState.NotVerified>(instance.card)
        val unfinished = assertNotNull(instance.unfinishedMove)
        assertEquals(VaultUnlockResult.SERVER_BLOCKED, await { moved.unlock(assertNotNull(moved.snapshot.locked), PW) })
        assertEquals(MoveResult.NOT_FINISHED, await { moved.instance.finishMove(unfinished) })
        assertTrue(moved.snapshot.instance!!.unfinishedMove === unfinished, "nothing changed")
        moved.script.namespaceMoveFails = false
        assertEquals(MoveResult.DONE, await { moved.instance.finishMove(unfinished) })
        assertNull(moved.snapshot.instance!!.unfinishedMove)
        assertEquals(MoveResult.STALE, await { moved.instance.finishMove(unfinished) })
        assertEquals(VaultUnlockResult.DONE, await { moved.unlock(assertNotNull(moved.snapshot.locked), PW) })
        assertNotNull(moved.account.kitAfterMove, "a kit made before the move names the old address")
    }

    // ---- §9.1: the operator account is refused on a phone however it arrives ----

    @Test
    fun theOperatorAccountIsRefusedOnAPhoneThroughADeviceLink() {
        val app = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        app.script.publicInstance.accounts.values.forEach { it.isOperator = true }
        assertEquals(LinkPasswordResult.OPERATOR_NEEDS_COMPUTER, await { app.entry.submitLinkPassword(app.on(), PW) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        app.on<EntryScreen.FirstRun>()
        assertNull(app.snapshot.account)
    }

    @Test
    fun theOperatorAccountIsRefusedOnAPhoneThroughAKitBeforeAnythingChanges() {
        val app = FakeScenes.at(FakeScene.KIT_RECOVER)
        val account = assertNotNull(app.script.publicInstance.accounts.values.firstOrNull { it.email == ADA })
        account.isOperator = true
        assertEquals(KitRecoverResult.OPERATOR_NEEDS_COMPUTER, await { app.entry.confirmKitRecovery(app.on()) })
        app.on<EntryScreen.KitEntry>()
        assertEquals(PW, account.password, "nothing was changed")
    }

    @Test
    fun theOperatorAccountIsRefusedOnAPhoneAfterAnOperatorsHelpWithTheNewPasswordInForce() {
        val app = FakeScenes.at(FakeScene.REPLACE_PASSWORD_AFTER_HELP)
        val account = assertNotNull(app.scriptServer(FAMILY).accounts.values.firstOrNull { it.email == ADA })
        account.isOperator = true
        val replacement = "a brand new master password"
        assertEquals(ReplacePasswordResult.OPERATOR_NEEDS_COMPUTER, await { app.entry.chooseReplacementPassword(app.on(), replacement) })
        app.on<EntryScreen.FirstRun>()
        assertNull(app.snapshot.account)
        assertEquals(replacement, account.password, "the commit went through")
    }

    /** Engine-17 item 1, kept in step in the fake: live updates that do not connect are one quiet line on the open vault. */
    @Test
    fun liveUpdatesThatDoNotConnectAreOneQuietLineInTheFakeAsInTheEngine() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        val on = app.account.liveUpdates
        assertTrue(on.running && on.connected)
        assertNull(on.line)
        val server = assertNotNull(app.script.server(assertNotNull(app.snapshot.instance).label.origin))
        server.liveUpdatesConnect = false
        app.script.changed()
        val off = app.account.liveUpdates
        assertTrue(off.running && !off.connected)
        assertEquals(LiveUpdatesTrouble.NOT_OPENED, off.trouble)
        assertEquals(CopyKey.LIVE_UPDATES_NOT_CONNECTED, off.line?.key)
        server.liveUpdatesConnect = true
        app.script.changed()
        assertNull(app.account.liveUpdates.line)
    }
}
