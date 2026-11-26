package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeScript
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The fake plays what the engine now says on the roads other than a sign-in (spec 01 §7): a recovery with the kit, a
 * recovery with the operator's help and a device link, on a device that keeps the account whose server's keys are not
 * that account's as this device knows it; a link that this device does not take because it keeps another session; a link
 * over a copy sealed under another master password; and the mailbox value on "ask the operator for help".
 */
class AppApiKeptAccountRoadsTest {
    private val newPassword = "a brand new master password"

    @Test
    fun aKitWhoseKeyIsNotTheKeptAccountsHasTheSignInsAnswerAndCommitsNothing() {
        val app = FakeScenes.at(FakeScene.KIT_RECOVER)
        app.script.recoveredKeyNotKept = true
        val r = await { app.entry.confirmKitRecovery(app.on()) }
        assertEquals(KitRecoverResult.SERVER_KEYS_NOT_KNOWN_HERE, r, "never a general failure")
        assertEquals(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, r.sentence)
        assertFalse(r.done)
        assertTrue(app.snapshot.entry !is EntryScreen.ReplacePassword, "no new password is asked")

        // Found again just before the commit: nothing committed, the kit goes, the journey is back where it was handed in.
        val choose = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        choose.script.recoveredKeyNotKept = true
        val c = await { choose.entry.chooseReplacementPassword(choose.on(), newPassword) }
        assertEquals(ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE, c)
        assertEquals(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, c.sentence)
        assertTrue(choose.snapshot.entry !is EntryScreen.Kit && choose.snapshot.entry !is EntryScreen.ReplacePassword)
        assertEquals(AppPhase.ENTRY, choose.snapshot.phase)
    }

    /**
     * As the engine's keeper with a reason of its own (this device holds its server's operator account; its copy is
     * damaged): a sign-in, a kit's check, a recovery's commit, a device link and an operator's answer each say the reason,
     * never "another account is kept" or a general failure; nothing is committed and a request is kept.
     */
    @Test
    fun theKeepersOwnReasonsAreEachSaidAsWhatTheyAreOnEveryRoad() {
        val held = io.silencelen.andvari.core.client.session.Establishing.OPERATOR_ACCOUNT_HELD
        val damaged = io.silencelen.andvari.core.client.session.Establishing.KEPT_COPY_DAMAGED
        for ((reason, sentence) in listOf(held to CopyKey.OPERATOR_ACCOUNT_HELD_HERE, damaged to CopyKey.KEPT_COPY_DAMAGED)) {
            val signIn = FakeScenes.at(FakeScene.SIGN_IN)
            signIn.script.publicInstance.addAccount("ada@example.com", newPassword)
            signIn.script.keeperRefuses = reason
            val s = await { signIn.entry.submitSignIn(signIn.on(), "ada@example.com", newPassword) }
            assertEquals(if (reason == held) SignInAnswer.OPERATOR_ACCOUNT_HELD else SignInAnswer.KEPT_COPY_DAMAGED, s)
            assertEquals(sentence, s.sentence)
            assertTrue(signIn.snapshot.phase != AppPhase.UNLOCKED)

            val kit = FakeScenes.at(FakeScene.KIT_RECOVER)
            kit.script.keeperRefuses = reason
            val k = await { kit.entry.confirmKitRecovery(kit.on()) }
            assertEquals(if (reason == held) KitRecoverResult.OPERATOR_ACCOUNT_HELD else KitRecoverResult.KEPT_COPY_DAMAGED, k)
            assertEquals(sentence, k.sentence)

            val choose = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
            choose.script.keeperRefuses = reason
            val c = await { choose.entry.chooseReplacementPassword(choose.on(), newPassword) }
            assertEquals(if (reason == held) ReplacePasswordResult.OPERATOR_ACCOUNT_HELD else ReplacePasswordResult.KEPT_COPY_DAMAGED, c)
            assertEquals(sentence, c.sentence)
            assertTrue(choose.snapshot.entry !is EntryScreen.Kit, "nothing committed: no new kit")

            val link = FakeScenes.at(FakeScene.LINK_DEVICE_CODE)
            link.script.keeperRefuses = reason
            link.script.otherDeviceApproves()
            val ended = link.on<EntryScreen.LinkDeviceEnded>()
            assertEquals(if (reason == held) LinkDeviceEnd.OPERATOR_ACCOUNT_HELD else LinkDeviceEnd.KEPT_COPY_DAMAGED, ended.outcome)
            assertEquals(sentence, ended.outcome.sentence)

            val help = FakeScenes.at(FakeScene.OPERATOR_HELP_HOLDING)
            help.script.advance(7 * FakeScript.DAY)
            assertTrue(help.script.operatorAnswers(forged = false))
            val request = assertNotNull(help.helpRequest)
            help.script.keeperRefuses = reason
            assertEquals(ServerResult.DONE, await { help.entry.refreshOperatorHelp(help.on()) })
            val screen = help.on<EntryScreen.OperatorHelp>()
            assertEquals(sentence, if (reason == held) screen.operatorAccountHeld else screen.keptCopyDamaged)
            assertNull(screen.anotherAccountKept)
            assertTrue(help.helpRequest === request, "the request is kept")
        }
    }

    /** As the engine: an operator's answer naming another account than the one kept for the address keeps the request, with no sign-out. */
    @Test
    fun anOperatorsAnswerNamingAnotherAccountThanTheKeptOneKeepsTheRequestAndOffersNoSignOut() {
        val app = FakeScenes.at(FakeScene.OPERATOR_HELP_HOLDING)
        app.script.advance(7 * FakeScript.DAY)
        assertTrue(app.script.operatorAnswers(forged = false))
        val request = assertNotNull(app.helpRequest)
        request.namesAnotherAccount = true
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })
        val help = app.on<EntryScreen.OperatorHelp>()
        assertEquals(CopyKey.ASSIST_NOT_THE_KEPT_ACCOUNT, help.notTheKeptAccount)
        assertNull(help.anotherAccountKept)
        assertNull(help.identityFault)
        assertTrue(app.helpRequest === request, "the request is kept")
    }

    @Test
    fun anOperatorsAnswerWhoseKeyIsNotTheKeptAccountsKeepsTheRequestAndSaysSoAtEveryLook() {
        val app = FakeScenes.at(FakeScene.OPERATOR_HELP_HOLDING)
        app.script.advance(7 * FakeScript.DAY)
        assertTrue(app.script.operatorAnswers(forged = false))
        val request = assertNotNull(app.helpRequest)
        request.keyNotKept = true
        repeat(2) {
            assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })
            val help = app.on<EntryScreen.OperatorHelp>()
            assertEquals(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, help.keysNotKnownHere)
            assertTrue(app.helpRequest === request, "the request is kept")
        }

        // Asked again before the commit: nothing committed, back to the request's screen, which says so.
        val choose = FakeScenes.at(FakeScene.REPLACE_PASSWORD_AFTER_HELP)
        val kept = assertNotNull(choose.helpRequest)
        kept.keyNotKept = true
        val c = await { choose.entry.chooseReplacementPassword(choose.on(), newPassword) }
        assertEquals(ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE, c)
        assertEquals(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, choose.on<EntryScreen.OperatorHelp>().keysNotKnownHere)
        assertTrue(choose.helpRequest === kept, "the request is kept")
    }

    @Test
    fun aDeviceLinkEndsWithTheWayOutWhenTheKeysAreNotTheKeptAccountsOrAnotherSessionIsKept() {
        val keys = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        keys.script.linkKeysNotKnownHere = true
        val r = await { keys.entry.submitLinkPassword(keys.on(), FakeScenes.PASSWORD) }
        assertEquals(LinkPasswordResult.SERVER_KEYS_NOT_KNOWN_HERE, r)
        assertEquals(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, r.sentence)
        val ended = keys.on<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.SERVER_KEYS_NOT_KNOWN_HERE, ended.outcome)
        assertEquals(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, ended.outcome.sentence)
        assertEquals(AppPhase.ENTRY, keys.snapshot.phase)

        val other = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        other.script.linkAnotherSessionKept = true
        val o = await { other.entry.submitLinkPassword(other.on(), FakeScenes.PASSWORD) }
        assertEquals(LinkPasswordResult.ANOTHER_SESSION_KEPT, o)
        assertEquals(CopyKey.DEVICE_LINK_ANOTHER_SESSION_KEPT, o.sentence)
        assertEquals(LinkDeviceEnd.ANOTHER_SESSION_KEPT, other.on<EntryScreen.LinkDeviceEnded>().outcome)
        assertEquals(CopyKey.DEVICE_LINK_ANOTHER_SESSION_KEPT, LinkDeviceEnd.ANOTHER_SESSION_KEPT.sentence)
    }

    @Test
    fun aDeviceLinkOverACopySealedUnderAnotherPasswordSaysTheSignInsOneLine() {
        val app = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        app.script.signInOverOtherPasswordCopy = true
        assertEquals(LinkPasswordResult.DONE, await { app.entry.submitLinkPassword(app.on(), FakeScenes.PASSWORD) })
        assertEquals(CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER, assertNotNull(app.snapshot.account).signInNotice?.key)
        app.dismissSignInNotice()
        assertNull(assertNotNull(app.snapshot.account).signInNotice)

        val plain = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        assertEquals(LinkPasswordResult.DONE, await { plain.entry.submitLinkPassword(plain.on(), FakeScenes.PASSWORD) })
        assertNull(assertNotNull(plain.snapshot.account).signInNotice, "nothing to say when nothing changed")
    }

    @Test
    fun theMailboxValueOpensBehindItsLineIsCheckedBeforeAnythingIsSentAndChangesNothingTheScreenSays() {
        val app = FakeScenes.at(FakeScene.ASK_OPERATOR)
        val ask = app.on<EntryScreen.AskOperator>()
        assertFalse(ask.mailboxValueOpen)
        assertEquals(CopyKey.ASSIST_MAILBOX_VALUE_LINE, ask.mailboxValueLine)
        assertNull(ask.mailboxValueField, "the field is hidden until its line is opened")
        app.entry.openMailboxValue(ask)
        val open = app.on<EntryScreen.AskOperator>()
        assertTrue(open.mailboxValueOpen)
        assertEquals(CopyKey.ASSIST_MAILBOX_VALUE_FIELD, open.mailboxValueField)

        for (bad in listOf("ABCD", "ABCD EFGH JKMN PQRSI", "ABCD-EFGH-JKMN-PQR0", "ABCDEFGHJKMNPQRST")) {
            val r = await { app.entry.requestOperatorHelpWithValue(open, FakeScenes.EMAIL, bad) }
            assertEquals(AskOperatorResult.NOT_A_MAILBOX_VALUE, r, bad)
            assertEquals(CopyKey.ASSIST_NOT_A_MAILBOX_VALUE, r.sentence)
            assertTrue(app.on<EntryScreen.AskOperator>() === open, "the screen stays with its field")
            assertNull(app.helpRequest, "nothing was sent")
        }
        assertEquals(AskOperatorResult.DONE, await { app.entry.requestOperatorHelpWithValue(open, FakeScenes.EMAIL, "abcd-efgh jkmn PQRS") })
        assertEquals("ABCDEFGHJKMNPQRS", assertNotNull(app.helpRequest).mailboxValue)
        val with = app.on<EntryScreen.OperatorHelp>()

        val none = FakeScenes.at(FakeScene.ASK_OPERATOR)
        assertEquals(AskOperatorResult.DONE, await { none.entry.requestOperatorHelpWithValue(none.on(), FakeScenes.EMAIL, "  ") })
        assertNull(assertNotNull(none.helpRequest).mailboxValue, "blank is none")
        sameScreen(with, none.on())
    }

    /** As the engine's keeper at the kit's start: an account kept at another server; nothing is asked of the kit's server. */
    @Test
    fun aKitAtAnotherServerWhileAnAccountIsKeptSaysSo() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        app.script.addServer("https://other.example", "Other", ServerKind.PRIVATE_SERVER)
        app.script.sessionEndedByServer()
        app.signInAgain(app.snapshot.locked!!)
        app.entry.openSignIn(app.on())
        app.entry.openForgot(app.on())
        app.entry.openKitEntry(app.on())
        val r = await { app.entry.submitTypedKit(app.on(), "bea@example.com", "https://other.example", "a".repeat(43)) }
        assertEquals(KitScanResult.ANOTHER_ACCOUNT_KEPT, r)
        assertEquals(CopyKey.RECOVERY_ANOTHER_ACCOUNT_KEPT, r.sentence)
        app.on<EntryScreen.KitEntry>()
        assertNotNull(app.snapshot.keptSignedOut, "the way out: the kept account, to sign out")
    }

    /** As the engine's keeper before a recovery's commit: another account kept now, or the identity fault. Nothing is committed. */
    @Test
    fun aRecoveryStoppedBeforeItsCommitSaysWhyOnEitherRoad() {
        val kit = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        kit.script.anotherAccountTakenBeforeCommit = true
        val r = await { kit.entry.chooseReplacementPassword(kit.on(), newPassword) }
        assertEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED, r)
        assertEquals(CopyKey.RECOVERY_ANOTHER_ACCOUNT_KEPT, r.sentence)
        assertTrue(kit.snapshot.entry !is EntryScreen.Kit && kit.snapshot.entry !is EntryScreen.ReplacePassword, "nothing committed, no kit")

        val bound = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        bound.script.keeperIdentityFault = true
        val b = await { bound.entry.chooseReplacementPassword(bound.on(), newPassword) }
        assertEquals(ReplacePasswordResult.IDENTITY_FAULT, b)
        assertEquals(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, b.sentence)

        val help = FakeScenes.at(FakeScene.REPLACE_PASSWORD_AFTER_HELP)
        val kept = assertNotNull(help.helpRequest)
        help.script.anotherAccountTakenBeforeCommit = true
        assertEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT_NOT_COMMITTED, await { help.entry.chooseReplacementPassword(help.on(), newPassword) })
        assertEquals(CopyKey.ASSIST_ANOTHER_ACCOUNT_KEPT, help.on<EntryScreen.OperatorHelp>().anotherAccountKept)
        assertTrue(help.helpRequest === kept, "the request is kept")
    }

    /** As the engine's keeper at an answer's pick-up: an address bound here to another account; the request is kept. */
    @Test
    fun anOperatorsAnswerForAnAddressKnownHereUnderAnotherAccountIsTheIdentityFault() {
        val app = FakeScenes.at(FakeScene.OPERATOR_HELP_HOLDING)
        app.script.advance(7 * FakeScript.DAY)
        assertTrue(app.script.operatorAnswers(forged = false))
        val request = assertNotNull(app.helpRequest)
        request.boundElsewhere = true
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })
        val help = app.on<EntryScreen.OperatorHelp>()
        assertEquals(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, help.identityFault)
        assertNull(help.anotherAccountKept)
        assertTrue(app.helpRequest === request, "the request is kept")
    }

    /** As the engine's keeper once a link's approval names the account: the identity fault ends it before any password. */
    @Test
    fun aDeviceLinkForAnAddressKnownHereUnderAnotherAccountEndsWithTheIdentityFault() {
        val app = FakeScenes.at(FakeScene.LINK_DEVICE_CODE)
        app.script.keeperIdentityFault = true
        app.script.otherDeviceApproves()
        val ended = app.on<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT, ended.outcome)
        assertEquals(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, ended.outcome.sentence)
    }

    /**
     * As the engine where a link's approval stops on the identity check and this device cannot tell a remade account from a
     * substitution: the link ends with its own line (which points to the password sign-in), and nothing is offered.
     */
    @Test
    fun aDeviceLinkThatEndsWhereTheDeviceCannotTellIsPlayedWithItsOwnLineAndNoOffer() {
        val app = FakeScenes.at(FakeScene.LINK_DEVICE_CODE)
        app.script.earlierAccountKnown = true
        app.script.linkIdentityCannotTell = true
        app.script.otherDeviceApproves()
        val ended = app.on<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.IDENTITY_FAULT_CANNOT_TELL, ended.outcome)
        assertEquals(CopyKey.DEVICE_LINK_IDENTITY_CANNOT_TELL, ended.outcome.sentence)
        assertNull(app.snapshot.earlierAccount, "nothing is offered")
    }

    /**
     * A recovery's commit the server took, refused here for each of the keeper's reasons: each is its own result, said as a
     * committed change, with the new kit on show under that result's line; never "nothing was committed".
     */
    @Test
    fun aRecoveryCommittedAndRefusedHereSaysTheKeepersReasonAndThatTheCommitHappened() {
        val cases = listOf(
            io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT to ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT,
            io.silencelen.andvari.core.client.session.Establishing.IDENTITY_MISMATCH to ReplacePasswordResult.IDENTITY_FAULT_COMMITTED,
            io.silencelen.andvari.core.client.session.Establishing.SERVER_KEYS_NOT_KNOWN_HERE to ReplacePasswordResult.SERVER_KEYS_NOT_KNOWN_HERE_COMMITTED,
        )
        for ((reason, expected) in cases) {
            val app = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
            app.script.refusedAfterCommit = reason
            val r = await { app.entry.chooseReplacementPassword(app.on(), newPassword) }
            assertEquals(expected, r, reason)
            val kit = app.on<EntryScreen.Kit>().kit
            assertEquals(KitReason.AFTER_RECOVERY, kit.reason)
            assertEquals(if (expected == ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT) CopyKey.KIT_RECOVERED_NOT_KEPT else r.sentence, kit.notKeptLine)
            assertNotNull(app.kit.kitDocument(kit), "the new kit is on show")
        }
    }

    /**
     * A registration the server took whose session this device refused says the keeper's own reason: a device that came to
     * hold its server's operator account meanwhile is never told "another account is kept". Every kit shown with a refusal
     * says how long it holds (until the next sign-in, which shows a new kit).
     */
    @Test
    fun aRegistrationCommittedAndRefusedHereSaysTheKeepersReasonAndHowLongItsKitHolds() {
        val cases = listOf(
            io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT to CreateAccountResult.ACCOUNT_MADE_NOT_KEPT,
            io.silencelen.andvari.core.client.session.Establishing.OPERATOR_ACCOUNT_HELD to CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD,
            // The account was made: its own result and sentence, never IDENTITY_FAULT ("nothing is known to be made").
            io.silencelen.andvari.core.client.session.Establishing.IDENTITY_MISMATCH to CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT,
        )
        for ((reason, expected) in cases) {
            val reg = FakeScenes.at(FakeScene.CREATE_ACCOUNT)
            reg.script.refusedAfterCommit = reason
            val r = await { reg.entry.createAccount(reg.on(), NewAccountInput("", "Ada", newPassword, true)) }
            assertEquals(expected, r, reason)
            val kit = reg.on<EntryScreen.Kit>().kit
            assertEquals(KitReason.FIRST_KIT, kit.reason)
            assertNotNull(kit.notKeptLine, reason)
            assertEquals(CopyKey.KIT_NOT_KEPT_HOLDS_UNTIL_SIGN_IN, kit.notKeptHoldsLine, reason)
            if (expected == CreateAccountResult.ACCOUNT_MADE_OPERATOR_ACCOUNT_HELD) assertEquals(CopyKey.KIT_REGISTERED_OPERATOR_ACCOUNT_HELD, kit.notKeptLine)
            if (expected == CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT) {
                assertEquals(CopyKey.KIT_REGISTERED_IDENTITY_FAULT, r.sentence, "a sentence of its own")
                assertEquals(CopyKey.KIT_REGISTERED_IDENTITY_FAULT, kit.notKeptLine)
            }
        }
        val rec = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        rec.script.refusedAfterCommit = io.silencelen.andvari.core.client.session.Establishing.ANOTHER_SESSION_KEPT
        await { rec.entry.chooseReplacementPassword(rec.on(), newPassword) }
        assertEquals(CopyKey.KIT_NOT_KEPT_HOLDS_UNTIL_SIGN_IN, rec.on<EntryScreen.Kit>().kit.notKeptHoldsLine)
    }

    /** A recovery's commit the server took while this device refused its session: the new kit is shown and kept until confirmed. */
    @Test
    fun aKitTheServerTookWhileThisDeviceRefusedTheSessionIsShownUntilConfirmed() {
        val app = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        app.script.anotherAccountTakenDuringCommit = true
        assertEquals(ReplacePasswordResult.ANOTHER_ACCOUNT_KEPT, await { app.entry.chooseReplacementPassword(app.on(), newPassword) })
        val kit = app.on<EntryScreen.Kit>().kit
        assertEquals(KitReason.AFTER_RECOVERY, kit.reason)
        assertEquals(CopyKey.KIT_RECOVERED_NOT_KEPT, kit.notKeptLine)
        val doc = assertNotNull(app.kit.kitDocument(kit))
        app.kit.proceedToConfirm(kit)
        val confirm = app.on<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.MISMATCH, await { app.kit.confirmKit(confirm, listOf("x", "x", "x")) })
        assertNotNull(app.on<EntryScreen.Kit>(), "kept after a wrong confirm")
        val again = app.on<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, await { app.kit.confirmKit(again, again.groupsToType.map { doc.groups[it - 1] }) })
        assertTrue(app.snapshot.entry !is EntryScreen.Kit, "wiped once confirmed")
        assertEquals(AppPhase.ENTRY, app.snapshot.phase, "nothing of the account opens here")

        val reg = FakeScenes.at(FakeScene.CREATE_ACCOUNT)
        reg.script.anotherAccountTakenDuringCommit = true
        assertEquals(CreateAccountResult.ACCOUNT_MADE_NOT_KEPT, await { reg.entry.createAccount(reg.on(), NewAccountInput("", "Ada", newPassword, true)) })
        val first = reg.on<EntryScreen.Kit>().kit
        assertEquals(KitReason.FIRST_KIT, first.reason)
        assertEquals(CopyKey.KIT_REGISTERED_NOT_KEPT, first.notKeptLine)
    }

    private fun sameScreen(a: EntryScreen.OperatorHelp, b: EntryScreen.OperatorHelp) {
        assertEquals(a.stage, b.stage)
        assertEquals(a.email, b.email)
        assertEquals(a.requestCode.size, b.requestCode.size)
        assertEquals(a.holdEndsAtMs, b.holdEndsAtMs)
        assertEquals(a.answerReplaced, b.answerReplaced)
        assertEquals(a.keyChange == null, b.keyChange == null)
        assertEquals(a.requestUnknown, b.requestUnknown)
        assertEquals(a.keysNotKnownHere, b.keysNotKnownHere)
    }
}
