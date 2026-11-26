package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeLinkStep
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.pin.TrustGateWording
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * What the review of the app API asked for, flow by flow, against the fake: the lock screen through the interface,
 * the engine's outcomes that had no state, and the hooks the wording needs. (Its first finding, a screen that acts on
 * the server it names, is in [AppApiEntryTest].)
 */
class AppApiReviewTest {
    private val public = "https://vault.andvaripass.com"

    @Test
    fun theLockScreenNamesTheAccountAndItsServerAndOnlyThePasswordOpensIt() {
        val app = FakeScenes.at(FakeScene.LOCKED)
        val locked = assertNotNull(app.snapshot.locked)
        assertEquals("Master password for ada@example.com on andvari ($public)", locked.prompt.title?.english)
        assertEquals(InviteResult.STALE, await { app.openAppLink("https://andvaripass.com/l#v2.a.b.c") }, "a link is not acted on behind a lock")
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, await { app.unlock(locked, "not the password") })
        assertSame(locked, app.snapshot.locked)
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(locked, PW) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals(ADA, app.account.email)
        assertEquals(public, app.snapshot.instance?.label?.origin)
        assertFalse(app.account.serverStopped)
        assertEquals(VaultUnlockResult.STALE, await { app.unlock(locked, PW) })

        // Lock closes every screen of the account; sign-out ends the session and keeps the server's pin.
        assertEquals(PlainResult.DONE, await { app.contacts.openContacts() })
        app.lock()
        assertEquals(AppPhase.LOCKED, app.snapshot.phase)
        assertNull(app.snapshot.account)
        app.script.unlock()
        assertNull(app.account.contacts)
        assertEquals(PlainResult.DONE, await { app.signOut() })
        assertNull(app.on<EntryScreen.FirstRun>().notice)
        assertNull(app.snapshot.locked)
        assertTrue(app.pins.containsKey(public))
        assertEquals(PlainResult.STALE, await { app.signOut() })
    }

    @Test
    fun anUnlockThatFindsNoSavedKitShowsAFreshOneBeforeTheVaultOpens() {
        val app = FakeAppApi()
        val account = app.script.publicInstance.addAccount(ADA, PW)
        account.kitSaved = false
        app.script.storeSession(account)
        app.start()
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        assertEquals(KitReason.NEVER_SAVED, app.on<EntryScreen.Kit>().kit.reason)
        assertFalse(app.entry.back())
        app.saveKit()
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
    }

    @Test
    fun anOperatorAccountSignsInOnlyWhereTheOperatorViewsAre() {
        for (desktop in listOf(false, true)) {
            val app = if (desktop) FakeScenes.desktopAt(FakeScene.SIGN_IN_SERVER) else FakeScenes.at(FakeScene.SIGN_IN_SERVER)
            val family = app.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
            val operator = family.addAccount("operator@family.example", PW)
            operator.isOperator = true
            assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(app.on(), FAMILY) })
            assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(app.on()) })
            // A wrong password says nothing about whose account it is.
            assertEquals(SignInAnswer.WRONG, await { app.entry.submitSignIn(app.on(), "operator@family.example", "not the password") })
            val answer = await { app.entry.submitSignIn(app.on(), "operator@family.example", PW) }
            if (desktop) {
                assertEquals(SignInAnswer.DONE, answer)
                assertTrue(app.account.operatorAccount)
            } else {
                assertEquals(SignInAnswer.OPERATOR_NEEDS_COMPUTER, answer)
                assertEquals(AppPhase.ENTRY, app.snapshot.phase)
                app.on<EntryScreen.SignIn>()
                assertTrue(operator.devices.isEmpty(), "nothing of the account is kept on the phone")
            }
        }
    }

    @Test
    fun theFirstScreenNeverPresentsAnUnknownModeAsClosedAndABuildWithoutAPublicInstanceSaysSo() {
        val app = FakeScenes.at(FakeScene.FIRST_RUN_SIGNUP_NOT_KNOWN)
        val first = app.on<EntryScreen.FirstRun>()
        assertEquals(JoinMode.NOT_KNOWN, first.signup.mode)
        assertTrue(first.offersPublicInstance)
        assertFalse(first.signup.full)
        // The mode is resolved when "Create an account" is chosen.
        assertEquals(ServerResult.DONE, await { app.entry.createAccountOnAndvari(first) })
        app.on<EntryScreen.SignUpEmail>()

        val closed = FakeScenes.at(FakeScene.FIRST_RUN_SIGNUP_NOT_KNOWN)
        closed.script.publicInstance.mode = JoinMode.INVITATION_ONLY
        assertEquals(JoinMode.NOT_KNOWN, closed.on<EntryScreen.FirstRun>().signup.mode)
        assertEquals(ServerResult.NOT_TAKING_ACCOUNTS, await { closed.entry.createAccountOnAndvari(closed.on()) })
        assertEquals(JoinMode.INVITATION_ONLY, closed.on<EntryScreen.FirstRun>().signup.mode)

        val none = FakeScenes.at(FakeScene.FIRST_RUN_NO_PUBLIC_INSTANCE)
        assertFalse(none.on<EntryScreen.FirstRun>().offersPublicInstance)
        assertEquals(ServerResult.FAILED, await { none.entry.createAccountOnAndvari(none.on()) })
        none.entry.openSignIn(none.on())
        none.entry.openPasswordSignIn(none.on())
        assertFalse(none.on<EntryScreen.SignInServer>().offersPublicInstance)
        assertEquals(ServerResult.FAILED, await { none.entry.choosePublicInstance(none.on()) })
    }

    @Test
    fun aClaimedDeviceLinkIsLeftOnlyByGivingItUp() {
        val app = FakeScenes.at(FakeScene.LINK_DEVICE_WAITING)
        assertFalse(app.entry.back(), "no walking out of a claimed link")
        app.script.otherDeviceAnswers()
        assertFalse(app.entry.back())
        app.on<EntryScreen.LinkDeviceCode>()
        assertEquals(InviteResult.STALE, await { app.openAppLink(app.script.connectInvite(app.script.publicInstance, "Bo")) })
        app.entry.startOver()
        app.on<EntryScreen.FirstRun>()
        assertEquals(FakeLinkStep.CANCELLED, app.deviceLinks.values.single().step, "the other device sees it end")
    }

    @Test
    fun aKitIsProvedOnceAndAFailedProofLeavesNothingBehind() {
        val app = FakeScenes.at(FakeScene.KIT_RECOVER)
        val recover = app.on<EntryScreen.KitRecover>()
        assertTrue(app.pins.containsKey(public))
        app.script.failNext(Trouble.UNREACHABLE)
        assertEquals(KitRecoverResult.UNREACHABLE, await { app.entry.confirmKitRecovery(recover) })
        // The engine has wiped the kit: the journey is back where a kit is handed in, and the pin this recovery made is gone.
        app.on<EntryScreen.KitEntry>()
        assertEquals(KitRecoverResult.STALE, await { app.entry.confirmKitRecovery(recover) })
        assertFalse(app.pins.containsKey(public))
        assertNull(app.snapshot.instance)
    }

    @Test
    fun aKitFromBeforeAnIdentityResetPassesItsGateEvenWhereThisDeviceHoldsAPasswordPin() {
        val app = FakeScenes.at(FakeScene.KIT_ENTRY)
        val family = app.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
        val account = family.addAccount(ADA, PW)
        app.script.thisDevicePins(family)
        val kit = app.script.kitOf(account)
        app.script.kitPredatesReset(kit)
        assertEquals(KitScanResult.DONE, await { app.entry.submitKit(app.on(), kit, PayloadSource.SCANNED) })
        val gate = app.on<EntryScreen.TrustGate>()
        assertTrue(gate.prompt.kitIdentityChanged)
        assertFalse(gate.prompt.typedKit)
        assertEquals(CopyKey.GATE_KIT_IDENTITY_CHANGED, gate.prompt.lines.first().key)
        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(gate) })
        app.on<EntryScreen.KitRecover>()

        // A kit typed by hand carries no card hash: its gate says it is one, and a matching pin spares it.
        assertTrue(FakeScenes.at(FakeScene.GATE_TYPED_KIT).on<EntryScreen.TrustGate>().prompt.typedKit)
    }

    @Test
    fun theAccountCheckHasThreeAnswersAndTheNewPasswordScreenNamesOnlyTheTypedAddress() {
        val app = FakeScenes.at(FakeScene.OPERATOR_HELP_CHECK_ACCOUNT)
        // "Not now" keeps the request, which took seven days: the first screen offers it again.
        app.entry.recoveredAccountNotNow(app.on())
        val waiting = app.on<EntryScreen.FirstRun>()
        assertTrue(waiting.operatorHelpWaiting)
        assertNull(waiting.notice)
        assertEquals(ServerResult.DONE, await { app.entry.resumeOperatorHelp(waiting) })
        // "It's different" drops it for good, and the first screen says once that andvari stopped.
        app.entry.rejectRecoveredAccount(app.on<EntryScreen.CheckAccount>())
        val stopped = app.on<EntryScreen.FirstRun>()
        assertEquals(FirstRunNotice.RECOVERY_STOPPED, stopped.notice)
        assertFalse(stopped.operatorHelpWaiting)
        app.entry.dismissNotice(stopped)
        assertNull(app.on<EntryScreen.FirstRun>().notice)

        // The operator's answer carries no address: when it delivers another account, only the account ID can tell.
        val other = FakeScenes.at(FakeScene.OPERATOR_HELP_HOLDING)
        val mallory = other.scriptServer(FAMILY).addAccount("mallory@family.example", PW)
        other.script.advance(7 * DAY)
        assertTrue(other.script.operatorAnswersWithAnotherAccount(mallory))
        assertEquals(ServerResult.DONE, await { other.entry.refreshOperatorHelp(other.on()) })
        val check = other.on<EntryScreen.CheckAccount>()
        assertEquals(mallory.accountId, check.accountId)
        other.entry.acceptRecoveredAccount(check)
        assertEquals(ADA, other.on<EntryScreen.ReplacePassword>().email, "the address the person typed, never the delivered account's")
    }

    @Test
    fun aRegistrationWhoseAnswerDoesNotCarryTheIdentityBackOpensNothing() {
        val app = FakeScenes.at(FakeScene.CREATE_ACCOUNT)
        val form = app.on<EntryScreen.CreateAccount>()
        app.script.identityFault = true
        assertEquals(CreateAccountResult.IDENTITY_FAULT, await { app.entry.createAccount(form, NewAccountInput("", "Ada", PW, true)) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        assertSame(form, app.snapshot.entry)
        assertNull(app.snapshot.account)
    }

    @Test
    fun anAccountMadeToConnectSaysWhenTheConnectionWasNotMade() {
        val app = FakeScenes.at(FakeScene.PROMPT_CONNECTION_NOT_MADE)
        val prompt = app.prompt<AccountPrompt.ConnectionNotMade>()
        assertEquals("Bo", prompt.from)
        assertEquals(ConnectResult.UNREACHABLE, prompt.why)
        assertTrue(prompt.canRetry)
        assertEquals(PlainResult.DONE, await { app.contacts.openContacts() })
        assertTrue(assertNotNull(app.account.contacts).contacts.isEmpty(), "the account exists; the connection does not")
        assertEquals(ConnectResult.DONE, await { app.links.retryConnection(prompt) })
        assertFalse(app.hasPrompt<AccountPrompt.ConnectionNotMade>())
        assertEquals("Bo", app.contact("Bo").label)
        assertEquals(ConnectResult.STALE, await { app.links.retryConnection(prompt) })
    }

    @Test
    fun anEnrolLinkForAServerNothingVouchesForShowsItsGateBeforeItsName() {
        val app = FakeScenes.at(FakeScene.OPENED_TRUST_GATE)
        val gate = assertIs<OpenedInvite.TrustGate>(app.account.opened)
        assertEquals(TrustGateWording.ENROL_LINK, gate.gate.wording)
        assertEquals(FAMILY, gate.gate.origin)
        assertFalse(app.pins.containsKey(FAMILY), "nothing is pinned before the gate")
        assertEquals(ServerResult.DONE, await { app.links.confirmOpenedGate(gate) })
        val other = assertIs<OpenedInvite.OtherInstance>(app.account.opened)
        assertTrue(other.inviteInstance.selfNamed)
        assertEquals(ServerResult.STALE, await { app.links.confirmOpenedGate(gate) })
        app.links.dismissOpened()
        assertFalse(app.pins.containsKey(FAMILY), "the pin this invite made goes with it")

        // At the baked origin every kind of link pins through the baked root: no gate, signed in elsewhere or signed out.
        val family = FakeScenes.at(FakeScene.RECOVERY)
        assertEquals(InviteResult.DONE, await { family.links.openInvite(family.script.enrolLink(family.script.publicInstance, null), PayloadSource.SCANNED) })
        assertFalse(assertIs<OpenedInvite.OtherInstance>(family.account.opened).inviteInstance.selfNamed)
        assertIs<EntryScreen.CreateAccount>(FakeScenes.at(FakeScene.CREATE_ACCOUNT_ENROLLED).snapshot.entry)
        val invited = FakeScenes.at(FakeScene.JOIN_INVITE)
        assertEquals(ServerResult.DONE, await { invited.entry.signInFromInvite(invited.on()) })
        invited.on<EntryScreen.SignIn>()

        // An invite for another pinned server that moved since: the card on show is that server's, not this app's own.
        val moved = FakeScenes.at(FakeScene.OPENED_SERVER_CHANGED)
        val changed = assertIs<OpenedInvite.ServerChanged>(moved.account.opened)
        assertEquals(FAMILY, changed.instance.label.origin)
        assertEquals(public, moved.snapshot.instance?.label?.origin)
        assertEquals(MoveResult.DONE, await { moved.instance.followMove(assertIs(changed.instance.card)) })
        assertNull(moved.account.opened)
        assertEquals(public, moved.snapshot.instance?.label?.origin, "this app stays signed in where it was")
        assertTrue(moved.pins.containsKey("https://family.example"))
    }

    @Test
    fun aMoveToAnAddressThisDeviceAlreadyPinsHasAWayOnAndTheSessionMovesWithItsServer() {
        val app = FakeScenes.at(FakeScene.CARD_MOVE_ALREADY_PINNED)
        val card = assertIs<InstanceCardState.Moved>(app.snapshot.instance?.card)
        assertTrue(card.alreadyPinnedThere)
        assertEquals(MoveResult.ALREADY_PINNED_THERE, await { app.instance.followMove(card) })
        assertSame(card, app.snapshot.instance?.card, "nothing moved, and the prompt stays")
        // The way on is to forget one of the two servers: here, the one this device knows at the new address.
        assertEquals(PlainResult.DONE, await { app.instance.forgetServerAtNewAddress(card) })
        val free = assertIs<InstanceCardState.Moved>(app.snapshot.instance?.card)
        assertFalse(free.alreadyPinnedThere)
        assertEquals(PlainResult.STALE, await { app.instance.forgetServerAtNewAddress(free) })
        assertEquals(MoveResult.DONE, await { app.instance.followMove(free) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals("https://vault.newhome.example", app.snapshot.instance?.label?.origin)
        assertIs<InstanceCardState.Ok>(app.snapshot.instance?.card)
        assertEquals(VaultActionResult.DONE, await { app.vaults.createVault("Still mine") })
    }

    @Test
    fun aKindChangeCanBePutOffUntilTheNextUnlock() {
        val app = FakeScenes.at(FakeScene.CARD_KIND_CHANGED)
        val card = assertIs<InstanceCardState.KindChanged>(app.snapshot.instance?.card)
        assertFalse(card.putOff)
        val kind = assertNotNull(app.snapshot.instance).label.kind
        app.instance.kindChangeNotNow(card)
        val later = assertIs<InstanceCardState.KindChanged>(app.snapshot.instance?.card)
        assertTrue(later.putOff)
        assertEquals(kind, app.snapshot.instance?.label?.kind, "the old kind stays in force")
        app.script.lock()
        app.script.unlock()
        val again = assertIs<InstanceCardState.KindChanged>(app.snapshot.instance?.card)
        assertFalse(again.putOff)
        assertEquals(PlainResult.DONE, await { app.instance.acceptKindChange(again) })
        assertIs<InstanceCardState.Ok>(app.snapshot.instance?.card)
        assertNotSame(kind, app.snapshot.instance?.label?.kind)
    }

    @Test
    fun aTypedCodeIsComparedAsTextAndAWrongOneLetsThePersonTypeAgain() {
        val app = FakeScenes.at(FakeScene.COMPARE_READY)
        val ready = assertIs<CompareScreen.Ready>(app.account.comparing)
        val theirs = assertNotNull(app.script.codeTheyReadOut(ready.userId))
        for (wrong in listOf(ready.code, theirs.drop(1), "x$theirs", theirs + "0", "")) {
            if (wrong == theirs) continue
            assertEquals(ComparisonResult.MISMATCH, await { app.contacts.submitComparison(ready, wrong) }, wrong)
            assertSame(ready, app.account.comparing, "a wrong code ends nothing: the same screen takes the next try")
        }
        // The right digits whose record could not be written: nothing is compared yet, and typing again retries.
        app.script.comparisonNotSaved = true
        assertEquals(ComparisonResult.NOT_SAVED, await { app.contacts.submitComparison(ready, theirs) })
        assertFalse(app.contact(ready.label).compared)
        // Shown as two groups of three, and typed that way: every ASCII space is removed, nothing else is.
        assertEquals(ComparisonResult.DONE, await { app.contacts.submitComparison(ready, " ${theirs.take(3)} ${theirs.drop(3)} ") })
        assertIs<CompareScreen.Matched>(app.account.comparing)
    }

    @Test
    fun anAnsweredLinkNamesItsContactAndAWaitingChangeMarksItsVault() {
        val app = FakeScenes.at(FakeScene.LINKS)
        val links = assertNotNull(app.account.links)
        val answered = links.answered.single()
        assertEquals("Fay", answered.contact.label)
        assertFalse(answered.keyChanged)
        assertTrue(links.links.none { it.linkId == answered.linkId }, "an answered link is no longer open")
        // In person: straight on to the codes with the contact the answer made.
        assertEquals(PlainResult.DONE, await { app.contacts.openCompare(answered.contact) })
        val ready = assertIs<CompareScreen.Ready>(app.account.comparing)
        assertEquals(ComparisonResult.DONE, await { app.contacts.submitComparison(ready, assertNotNull(app.script.codeTheyReadOut(ready.userId))) })
        assertTrue(assertNotNull(app.account.links).answered.isEmpty(), "compared, the row has done its job")

        assertFalse(app.vault("Family").changeWaiting)
        app.script.appendGetsNoAnswer = true
        assertEquals(VaultActionResult.SENT_PENDING, await { app.vaults.deleteVault(app.vault("Family")) })
        assertTrue(app.vault("Family").changeWaiting)
        assertIs<PersonName.You>(app.vault("Family").owner)

        // The owner renames a vault; a member does not.
        assertEquals(VaultActionResult.NOT_OWNER, await { app.vaults.renameVault(app.vault("Work"), "Mine now") })
        assertEquals(VaultActionResult.DONE, await { app.vaults.createVault("Trips") })
        assertEquals(VaultActionResult.DONE, await { app.vaults.renameVault(app.vault("Trips"), "Holidays") })
        assertEquals("Holidays", app.vault("Holidays").named())
    }

    @Test
    fun aDesktopOperatorIsOfferedToFinishTheSetupAtUnlockOutsideTheConsoleToo() {
        val app = FakeScenes.desktopAt(FakeScene.OPERATOR_SETUP_UNFINISHED)
        app.operatorApi.closeConsole()
        val prompt = app.prompt<AccountPrompt.FinishServerSetup>()
        assertEquals(FAMILY, prompt.origin)
        assertEquals(CopyKey.FINISH_SERVER_SETUP, prompt.label)
        assertEquals(OperatorResult.DONE, await { app.operatorApi.finishServerSetup(PW) })
        assertFalse(app.hasPrompt<AccountPrompt.FinishServerSetup>())
    }

    @Test
    fun theScreensTheDesignGivesNoWordingHaveTheirKeysReservedAndNoSentenceYet() {
        val invitationOnly = FakeScenes.at(FakeScene.SERVER_INVITATION_ONLY).on<EntryScreen.Server>()
        assertEquals(CopyKey.SERVER_INVITATION_ONLY, invitationOnly.notTaking)
        assertNull(invitationOnly.notTakingWhy)
        assertNull(FakeScenes.at(FakeScene.SERVER).on<EntryScreen.Server>().notTaking)
        val required = FakeScenes.at(FakeScene.LINK_REQUIRED).on<EntryScreen.LinkRequired>()
        assertEquals(CopyKey.LINK_REQUIRED_TITLE, required.title)
        assertEquals(CopyKey.LINK_REQUIRED_BODY, required.body.key)
        assertEquals(listOf(ADA, "andvari", public), required.body.values)
        // The owner approved these sentences (copy page 2026-11-15, entries 3, 4, 5 and 14): core carries them, no key is
        // reserved any more, and the words are the approved ones exactly.
        assertEquals(emptySet(), CopyKey.entries.filter { it.reserved }.toSet())
        assertEquals("Create an account here", CopyKey.SERVER_CREATE_ACCOUNT.english)
        assertEquals("Sign in", CopyKey.SERVER_SIGN_IN.english)
        assertEquals("This server isn't taking new accounts right now.", CopyKey.SERVER_NOT_TAKING_ACCOUNTS.english)
        assertEquals("This device needs to be linked", CopyKey.LINK_REQUIRED_TITLE.english)
        assertTrue(required.body.english.startsWith("$ADA on andvari ($public) has “New devices must be linked” turned on"), required.body.english)
        assertTrue(required.body.english.endsWith("which sets a new master password and turns this setting off."))
    }


    /**
     * The lines the owner's next wording page is to word exist as keys, on the screens that show them, and are marked
     * as placeholders: a gloss in ⟦…⟧, never wording a person could take as final.
     */
    @Test
    fun theLinesAwaitingTheOwnersWordingAreKeysMarkedAsPlaceholders() {
        // Which keys await the owner is read from the code (and shown on his wording page); no list of them is kept by
        // hand here. Key by key: marked as awaiting exactly when its text holds a gloss in ⟦…⟧ (the whole line, or a clause
        // still to be worded inside the owner's words), never reserved, never an empty gloss, and every mark closed.
        val gloss = Regex("⟦([^⟦⟧]*)⟧")
        for (key in CopyKey.entries) {
            val glosses = gloss.findAll(key.english).map { it.groupValues[1] }.toList()
            assertEquals(key.awaitingOwner, glosses.isNotEmpty(), "$key")
            assertFalse(gloss.replace(key.english, "").let { '⟦' in it || '⟧' in it }, "$key: every mark is closed, none nested")
            if (key.awaitingOwner) {
                assertFalse(key.reserved, "$key")
                assertTrue(glosses.all { it.isNotBlank() }, "$key")
            }
        }
        assertEquals(CopyKey.DEVICES_REVOKE_DOES_NOT_WIPE, DevicesScreen(emptyList(), false).revokeLine.key)
        val code = FakeScenes.at(FakeScene.SIGN_UP_CODE).on<EntryScreen.SignUpCode>()
        assertEquals(CopyKey.SIGN_UP_CODE_LINE, code.codeLine.key)
        assertEquals(listOf(code.email), code.codeLine.values)
        val recover = FakeScenes.at(FakeScene.KIT_RECOVER).on<EntryScreen.KitRecover>()
        assertEquals(CopyKey.KIT_RECOVER_SETS_PASSWORD, recover.setsPasswordLine.key)
        assertEquals(listOf(recover.email), recover.setsPasswordLine.values)
    }

    /** Approved entry 9: the Trust Gate a typed kit raises has its own title, body and "It's the same". */
    @Test
    fun theTrustGateOfATypedKitSaysToCompareTheAddressOnTheKit() {
        fun gate(typedKit: Boolean, kitChanged: Boolean = false) = TrustGatePrompt(
            TrustGateWording.TYPED_ADDRESS, "https://vault.example", "Family vault", "0".repeat(32), switching = false,
            punycodeCaution = false, httpCaution = false, kitIdentityChanged = kitChanged, typedKit = typedKit, claimedKind = null,
        )
        val kit = gate(typedKit = true)
        assertEquals("Is this the server on your kit?", kit.title?.english)
        assertEquals(
            listOf("https://vault.example calls itself “Family vault”. This device hasn't used it before. Your recovery kit shows your server's address: continue only if it is exactly the same."),
            kit.lines.map { it.english },
        )
        assertEquals(CopyKey.GATE_ITS_THE_SAME, kit.confirmLabel)
        assertEquals(CopyKey.GATE_KIT_IDENTITY_CHANGED, gate(typedKit = true, kitChanged = true).lines.first().key)
        // A typed address that is not a kit keeps its own wording.
        val typed = gate(typedKit = false)
        assertEquals(CopyKey.GATE_TITLE_CONNECT, typed.title?.key)
        assertEquals(listOf(CopyKey.GATE_BASELINE, CopyKey.GATE_CALLS_ITSELF), typed.lines.map { it.key })
        assertNull(typed.confirmLabel)
    }
}
