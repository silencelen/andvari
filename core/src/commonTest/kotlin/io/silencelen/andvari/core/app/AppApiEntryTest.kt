package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeServer
import io.silencelen.andvari.core.client.pin.TrustGateWording
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The signed-out journey of IF-3, walked through the fake: first run, sign-up, registration through each link, sign-in
 * and the password rule, linking this device, and both recoveries. Each test names the rule of the design it pins.
 */
class AppApiEntryTest {
    private fun fresh(): FakeAppApi = FakeScenes.at(FakeScene.FIRST_RUN)

    // ---- §12.4, §12.1: the first launch and the first screen ----

    @Test
    fun theFirstLaunchDeletesEveryOldStoreOnceBeforeTheFirstScreen() {
        val deleted = ArrayList<PreCutoverStore>()
        val app = FakeAppApi(AppPlatform.IOS, object : PreCutoverStores {
            override fun wipe(store: PreCutoverStore): Boolean {
                deleted += store
                return true
            }
        })
        assertEquals(AppPhase.STARTING, app.snapshot.phase)
        assertNull(app.snapshot.entry, "nothing is on screen before the wipe")
        app.start()
        assertEquals(PreCutoverStore.entries.toList(), deleted)
        assertEquals(deleted, app.wiped)
        app.on<EntryScreen.FirstRun>()
        assertNull(app.snapshot.oldData, "every store went: there is nothing to say")

        // Keyed by the format marker: a later start of the same install deletes nothing.
        val again = FakeAppApi()
        again.script.wipeAlreadyDone()
        again.start()
        assertTrue(again.wiped.isEmpty())
        again.on<EntryScreen.FirstRun>()
    }

    @Test
    fun anOldStoreThatCannotBeDeletedDoesNotStopTheStartIsToldOnceAndIsTriedAgain() {
        val app = FakeScenes.at(FakeScene.OLD_DATA_LEFT)
        // The app carries on: new builds never open the old stores.
        app.on<EntryScreen.FirstRun>()
        val notice = assertNotNull(app.snapshot.oldData)
        assertEquals(listOf(PreCutoverStore.OFFLINE_CACHE), notice.stores)
        assertTrue(notice.tellNow)
        assertSame(notice, app.also { it.entry.openSignIn(it.on()) }.snapshot.oldData, "unchanged, it is the same object in the next snapshot")

        // Told once; afterwards it is a line in Settings with "Try again".
        app.acknowledgeOldData(notice)
        val told = assertNotNull(app.snapshot.oldData)
        assertFalse(told.tellNow)
        app.acknowledgeOldData(notice)
        assertSame(told, app.snapshot.oldData, "a notice that is no longer on show is not taken")

        // Only the store that stayed is tried again, and it stays until it can be deleted.
        val before = app.wiped.size
        assertFalse(app.retryOldDataRemoval(told))
        assertEquals(listOf(PreCutoverStore.OFFLINE_CACHE), app.wiped.drop(before))
        app.script.oldStoresThatStay.clear()
        assertTrue(app.retryOldDataRemoval(assertNotNull(app.snapshot.oldData)))
        assertNull(app.snapshot.oldData)
    }

    @Test
    fun theFirstScreenCarriesTheSignupStateOfThePublicInstance() {
        val app = fresh()
        val server = app.script.publicInstance
        val first = app.on<EntryScreen.FirstRun>()
        assertTrue(first.signup.takingAccounts)
        assertFalse(first.takesSetupLinks, "a phone takes no setup link")
        assertFalse(first.operatorHelpWaiting)
        assertTrue(FakeScenes.desktopAt(FakeScene.FIRST_RUN).on<EntryScreen.FirstRun>().takesSetupLinks)

        server.full = true
        app.script.changed()
        val full = app.on<EntryScreen.FirstRun>()
        assertTrue(full.signup.full)
        assertEquals("Sign-up is full right now", CopyKey.FIRST_SIGNUP_FULL.english)
        // The screen that was on show before is stale, and nothing happens for it.
        assertEquals(ServerResult.STALE, await { app.entry.createAccountOnAndvari(first) })
        assertEquals(ServerResult.NOT_TAKING_ACCOUNTS, await { app.entry.createAccountOnAndvari(full) })

        server.full = false
        for ((mode, expected) in listOf(JoinMode.INVITATION_ONLY to JoinMode.INVITATION_ONLY, JoinMode.CLOSED to JoinMode.CLOSED)) {
            server.mode = mode
            app.script.changed()
            assertEquals(expected, app.on<EntryScreen.FirstRun>().signup.mode)
            assertEquals(ServerResult.NOT_TAKING_ACCOUNTS, await { app.entry.createAccountOnAndvari(app.on()) })
        }
        server.reachable = false
        app.script.changed()
        assertEquals(JoinMode.NOT_KNOWN, app.on<EntryScreen.FirstRun>().signup.mode)
        assertEquals(ServerResult.UNREACHABLE, await { app.entry.createAccountOnAndvari(app.on()) })
        server.reachable = true
        server.tooNewForThisBuild = true
        app.script.changed()
        assertEquals(ServerResult.UPDATE_REQUIRED, await { app.entry.createAccountOnAndvari(app.on()) })
    }

    // ---- §7.2, §7.3, §10: sign-up, the form, the kit ----

    @Test
    fun signUpWalksAddressCodeFormAndKitBeforeTheVaultOpens(): Unit = runBlocking {
        val app = fresh()
        val script = app.script
        val server = script.publicInstance
        server.powBits = 20
        server.blockedDomains += "spam.example"
        assertEquals(ServerResult.DONE, app.entry.createAccountOnAndvari(app.on()))
        val email = app.on<EntryScreen.SignUpEmail>()
        assertTrue(email.ageConfirmRequired)
        assertNull(email.connectWith)

        assertEquals(SignUpStartResult.INVALID_EMAIL, app.entry.startSignUp(email, "not an address", true))
        assertEquals(SignUpStartResult.EMAIL_DOMAIN_NOT_ACCEPTED, app.entry.startSignUp(email, "x@spam.example", true))
        assertEquals(SignUpStartResult.AGE_CONFIRMATION_NEEDED, app.entry.startSignUp(email, ADA, false))
        server.mailStalled = true
        assertEquals(SignUpStartResult.MAIL_UNAVAILABLE, app.entry.startSignUp(email, ADA, true))
        assertEquals("We can't send email right now. Try again in a while.", SignUpStartResult.MAIL_UNAVAILABLE.sentence?.english)
        server.mailStalled = false
        assertSame(email, app.snapshot.entry, "a refusal leaves the screen where it was")

        // The proof of work runs with a progress note; the code is asked for only after it.
        script.holdProofOfWork = true
        val start = async { app.entry.startSignUp(email, " Ada@Example.com ", true) }
        yield()
        assertTrue(app.on<EntryScreen.SignUpEmail>().provingWork)
        script.setWorkProgress(55)
        assertEquals(55, app.on<EntryScreen.SignUpEmail>().workPercent)
        script.finishWork()
        assertEquals(SignUpStartResult.DONE, start.await())

        val code = app.on<EntryScreen.SignUpCode>()
        assertEquals("Ada@Example.com", code.email)
        assertEquals(CodeResult.WRONG_CODE, app.entry.verifySignUpCode(code, "000000"))
        assertEquals(CodeResult.DONE, app.entry.verifySignUpCode(code, script.emailCode))

        val form = app.on<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.EMAIL_CODE, form.via)
        assertEquals(ADA, form.fixedEmail, "the verified address, normalised")
        // Variant R: a public instance offers no choice, only the kit.
        assertNull(form.recovery)
        assertEquals(WhoCanRecover.ONLY_ME, form.whoCanRecover)
        app.entry.reviewOperatorRecovery(form)
        assertSame(form, app.snapshot.entry, "there is no warning to review, so no way to the operator choice")

        assertEquals(CreateAccountResult.WEAK_PASSWORD, app.entry.createAccount(form, NewAccountInput("", "Ada", "short", true)))
        app.script.escrowWrongForm = true
        assertEquals(CreateAccountResult.ESCROW_WRONG_FORM, app.entry.createAccount(form, NewAccountInput("", "Ada", PW, true)), "as the engine: no account")
        assertEquals(CreateAccountResult.DONE, app.entry.createAccount(form, NewAccountInput("", "Ada", PW, true)))

        // The account exists; the vault does not open before the kit is saved, and there is no way around it.
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        val reveal = app.on<EntryScreen.Kit>().kit
        assertEquals(KitReason.FIRST_KIT, reveal.reason)
        assertEquals(KitStep.REVEAL, reveal.step)
        assertFalse(app.entry.back())
        app.entry.startOver()
        assertSame(reveal, app.kitOnShow())

        val document = assertNotNull(app.kit.kitDocument(reveal))
        assertEquals(11, document.groups.size)
        assertEquals(listOf(4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3), document.groups.map { it.length })
        assertTrue(document.qrPayload.startsWith("andvari-kit:2:"))
        assertEquals(32, document.accountId.length)
        assertEquals("Your account ID: ${document.accountId}", document.accountIdLine.english)
        assertEquals(ADA, document.email)

        app.kit.proceedToConfirm(reveal)
        val confirm = app.kitOnShow()
        assertEquals(listOf(2, 7, 10), confirm.groupsToType)
        assertEquals("Type groups 2, 7 and 10", confirm.confirmLine?.english)
        // The secret is readable only while it is being revealed.
        assertNull(app.kit.kitDocument(confirm))
        assertNull(app.kit.kitDocument(reveal), "nor through the screen that is no longer on show")

        // Three wrong entries show the kit again.
        assertEquals(KitConfirmResult.MISMATCH, app.kit.confirmKit(app.kitOnShow(), listOf("a", "b", "c")))
        assertEquals(1, app.kitOnShow().failedTries)
        assertEquals(KitConfirmResult.MISMATCH, app.kit.confirmKit(app.kitOnShow(), listOf("a", "b", "c")))
        assertEquals(KitConfirmResult.MISMATCH, app.kit.confirmKit(app.kitOnShow(), listOf("a", "b", "c")))
        assertEquals(KitStep.REVEAL, app.kitOnShow().step)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)

        app.saveKit()
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertNull(app.snapshot.entry)
        assertEquals(ADA, app.account.email)
        assertEquals(document.accountId, app.account.accountId)
        assertFalse(app.account.operatorAccount)
        assertTrue(app.account.prompts.isEmpty())
        assertEquals("andvari", app.snapshot.instance?.label?.name)
        assertFalse(assertNotNull(app.snapshot.instance).label.selfNamed, "the baked instance is vouched for by the build")
    }

    @Test
    fun signUpAnswersTheSameWhetherOrNotTheAddressHasAnAccount() {
        val app = FakeScenes.at(FakeScene.SIGN_UP_EMAIL)
        app.script.publicInstance.addAccount("taken@example.com", PW)
        // G6: "sent", for every address alike. The code then simply never verifies.
        assertEquals(SignUpStartResult.DONE, await { app.entry.startSignUp(app.on(), "taken@example.com", true) })
        val code = app.on<EntryScreen.SignUpCode>()
        assertEquals("If no email arrives in a few minutes, check spam or try again.", CopyKey.EMAIL_CHECK_SPAM.english)
        assertEquals(CodeResult.WRONG_CODE, await { app.entry.verifySignUpCode(code, app.script.emailCode) })
        assertSame(code, app.snapshot.entry)
    }

    @Test
    fun aCodeDiesAfterFiveWrongTriesOrFifteenMinutesAndTheVerifiedAddressAfterThirty() {
        val app = FakeScenes.at(FakeScene.SIGN_UP_CODE)
        val code = app.on<EntryScreen.SignUpCode>()
        repeat(5) { assertEquals(CodeResult.WRONG_CODE, await { app.entry.verifySignUpCode(code, "999999") }) }
        assertEquals(CodeResult.WRONG_CODE, await { app.entry.verifySignUpCode(code, app.script.emailCode) }, "the code is dead")
        assertEquals(SignUpStartResult.DONE, await { app.entry.resendSignUpCode(code) })
        app.script.advance(16 * MINUTE)
        assertEquals(CodeResult.WRONG_CODE, await { app.entry.verifySignUpCode(code, app.script.emailCode) }, "expired")
        assertEquals(SignUpStartResult.DONE, await { app.entry.resendSignUpCode(code) })
        assertEquals(CodeResult.DONE, await { app.entry.verifySignUpCode(code, app.script.emailCode) })

        app.script.advance(31 * MINUTE)
        val form = app.on<EntryScreen.CreateAccount>()
        assertEquals(CreateAccountResult.VERIFICATION_EXPIRED, await { app.entry.createAccount(form, NewAccountInput("", "Ada", PW, true)) })
    }

    @Test
    fun theServersRefusalsOfARegistrationAreEachTheirOwnAnswer() {
        fun form(): Pair<FakeAppApi, EntryScreen.CreateAccount> = FakeScenes.at(FakeScene.CREATE_ACCOUNT).let { it to it.on() }
        val input = NewAccountInput("", "Ada", PW, true)
        form().let { (app, f) ->
            app.script.publicInstance.full = true
            assertEquals(CreateAccountResult.SIGNUP_FULL, await { app.entry.createAccount(f, input) })
        }
        form().let { (app, f) ->
            app.script.publicInstance.dailyLimitReached = true
            assertEquals(CreateAccountResult.DAILY_LIMIT, await { app.entry.createAccount(f, input) })
        }
        form().let { (app, f) ->
            app.script.publicInstance.mode = JoinMode.CLOSED
            assertEquals(CreateAccountResult.SIGNUP_CLOSED, await { app.entry.createAccount(f, input) })
        }
        form().let { (app, f) ->
            app.script.publicInstance.addAccount(ADA, PW)
            assertEquals(CreateAccountResult.EMAIL_TAKEN, await { app.entry.createAccount(f, input) })
        }
        form().let { (app, f) ->
            app.script.publicInstance.hasCard = false
            assertEquals(CreateAccountResult.SERVER_NOT_SET_UP, await { app.entry.createAccount(f, input) })
        }
        form().let { (app, f) ->
            // No answer: the account may exist, and the screen offers to sign in rather than claiming either way.
            app.script.forceNext(CreateAccountResult.MAY_EXIST)
            assertEquals(CreateAccountResult.MAY_EXIST, await { app.entry.createAccount(f, input) })
            assertSame(f, app.snapshot.entry)
        }
    }

    // ---- §6.7, §6.8, §12.1: invites ----

    @Test
    fun theInviteScreenTakesInvitesOnlyAndStartsNothingForAnythingElse() {
        val app = FakeScenes.at(FakeScene.INVITE_ENTRY)
        val script = app.script
        val screen = app.on<EntryScreen.InviteEntry>()
        val account = script.publicInstance.addAccount(ADA, PW)

        // Three scanners, three jobs (FS-B1): a device link and a kit are refused here, each with its own sentence.
        val deviceLink = await { app.entry.submitInvite(screen, script.deviceLinkFrom(account, "MacBook"), PayloadSource.SCANNED) }
        assertEquals(InviteResult.DEVICE_LINK_NOT_HERE, deviceLink)
        assertEquals("To add this device to your account, open Sign in → Link from your other device and scan the code there.", deviceLink.sentence?.english)
        val kit = await { app.entry.submitInvite(screen, script.kitOf(account), PayloadSource.PASTED) }
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, kit)
        // No directions on purpose: it must not walk someone handed a kit as an "invite" to the recovery screen (FC-9).
        assertEquals("This is a recovery kit, not an invite.", kit.sentence?.english)
        assertEquals(InviteResult.NOT_AN_INVITE, await { app.entry.submitInvite(screen, "hello", PayloadSource.PASTED) })
        assertEquals(InviteResult.NOT_FOUND, await { app.entry.submitInvite(screen, "https://andvaripass.com/l#v2.a.b.c", PayloadSource.PASTED) })

        val expired = script.connectInvite(script.publicInstance, "Bo").also(script::expire)
        val used = script.connectInvite(script.publicInstance, "Bo").also(script::useUp)
        val revoked = script.connectInvite(script.publicInstance, "Bo").also(script::revoke)
        val damaged = script.connectInvite(script.publicInstance, "Bo").also(script::damage)
        assertEquals(InviteResult.EXPIRED, await { app.entry.submitInvite(screen, expired, PayloadSource.SCANNED) })
        assertEquals(InviteResult.ALREADY_USED, await { app.entry.submitInvite(screen, used, PayloadSource.SCANNED) })
        assertEquals(InviteResult.NOT_FOUND, await { app.entry.submitInvite(screen, revoked, PayloadSource.SCANNED) })
        assertEquals(InviteResult.DOES_NOT_CHECK_OUT, await { app.entry.submitInvite(screen, damaged, PayloadSource.SCANNED) })
        val old = script.connectInvite(script.publicInstance, "Bo")
        script.advance(8 * DAY)
        assertEquals(InviteResult.EXPIRED, await { app.entry.submitInvite(screen, old, PayloadSource.SCANNED) })

        // A phone shows where a setup link belongs, and does nothing else (§9.5).
        val setup = await { app.entry.submitInvite(screen, script.setupLink(script.addServer("https://vault.new.example", "New", ServerKind.PRIVATE_SERVER)), PayloadSource.SCANNED) }
        assertEquals(InviteResult.SETUP_NEEDS_COMPUTER, setup)
        assertEquals("This link sets up a server's operator account. Open it in the andvari desktop app, or with andvari-cli operator enrol.", setup.sentence?.english)

        assertSame(screen, app.snapshot.entry, "every refusal left the screen where it was")
        assertNull(app.snapshot.instance, "and connected the app to nothing")

        // Chat apps wrap lines, and a link may arrive as its fragment alone (§6.1).
        val wrapped = script.connectInvite(script.publicInstance, "Bo").replace("#", "#\n ")
        assertEquals(InviteResult.DONE, await { app.entry.submitInvite(screen, wrapped, PayloadSource.PASTED) })
        app.on<EntryScreen.JoinInvite>()
    }

    @Test
    fun aConnectLinkWithoutAnAccountLeadsThroughSignUpToAnUncomparedContact() {
        val app = FakeScenes.at(FakeScene.JOIN_INVITE)
        val join = app.on<EntryScreen.JoinInvite>()
        assertEquals("Create an account on andvari to connect with Bo", join.headline.english)
        assertEquals("Bo", join.from)

        assertEquals(ServerResult.DONE, await { app.entry.joinFromInvite(join) })
        val email = app.on<EntryScreen.SignUpEmail>()
        assertEquals("Bo", email.connectWith)
        assertEquals(SignUpStartResult.DONE, await { app.entry.startSignUp(email, ADA, true) })
        assertEquals(CodeResult.DONE, await { app.entry.verifySignUpCode(app.on(), app.script.emailCode) })
        val form = app.on<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.CONNECT_LINK, form.via)
        assertEquals("Bo", form.invitedBy)
        assertEquals(CreateAccountResult.DONE, await { app.entry.createAccount(form, NewAccountInput("", "Ada", PW, true)) })
        app.saveKit()

        // The answer was posted right after the registration: Bo is a contact, and not yet compared (T-B2, T12).
        val bo = app.contact("Bo")
        assertFalse(bo.compared)
        assertTrue(bo.currentHere)
        assertFalse(bo.codesReady, "no code before the creator's reveal")
    }

    @Test
    fun aConnectLinkToAServerThatTakesNoAccountsIsADeadEndThatSaysWhy() {
        fun deadEnd(setUp: (FakeServer) -> Unit): EntryScreen.NotTakingAccounts {
            val app = FakeScenes.at(FakeScene.INVITE_ENTRY)
            val server = app.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
            setUp(server)
            assertEquals(InviteResult.DONE, await { app.entry.submitInvite(app.on(), app.script.connectInvite(server, "Bo"), PayloadSource.SCANNED) })
            return app.on()
        }
        val invitationOnly = deadEnd {}
        assertEquals("Bo invited you to connect on Family, but that server isn't taking new accounts right now.", invitationOnly.headline.english)
        assertEquals("It is invitation-only: ask Bo for an invitation link.", invitationOnly.whyNot?.english)
        assertEquals("It is closed.", deadEnd { it.mode = JoinMode.CLOSED }.whyNot?.english)
        assertEquals(
            "It is full.",
            deadEnd {
                it.mode = JoinMode.ANYONE
                it.full = true
            }.whyNot?.english,
        )

        // The person may already have an account there; signing in through a link's pin shows the Trust Gate first.
        val app = FakeScenes.at(FakeScene.NOT_TAKING_ACCOUNTS)
        assertEquals(ServerResult.DONE, await { app.entry.signInWhereInvited(app.on()) })
        assertEquals(TrustGateWording.LINK_OFFER_SIGN_IN, app.on<EntryScreen.TrustGate>().prompt.wording)
    }

    @Test
    fun aRegisterLinkNeedsNoCodeAndPinsTheInviterAndOffersTheFamilyRecoveryChoice() {
        val app = FakeScenes.at(FakeScene.CREATE_ACCOUNT_RECOVERY_CHOICE)
        var form = app.on<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.INVITATION_LINK, form.via)
        assertNull(form.fixedEmail)
        assertEquals("Bo", form.invitedBy)
        assertEquals("Family", form.instance.name)
        assertEquals(ServerKind.PRIVATE_SERVER, form.instance.kind)
        assertFalse(form.instance.selfNamed, "the link's offer vouches for the card")

        // §7.7: the family wording, "Only me" selected, and the operator posture only behind the warning and its checkbox.
        val question = assertNotNull(form.recovery)
        assertEquals("How should this account be recovered if you forget your master password?", question.question.english)
        assertEquals("Me, or the person who runs Family", question.meOrOperator.english)
        assertFalse(question.unsignedChange)
        assertNull(question.takeoverTitle)
        assertEquals(WhoCanRecover.ONLY_ME, form.whoCanRecover)

        app.entry.reviewOperatorRecovery(form)
        val warning = app.on<EntryScreen.RecoveryWarning>()
        assertEquals("Let the person who runs Family (https://vault.family.example) restore your account?", warning.warning.title.english)
        assertEquals(1, warning.warning.paragraphs.size)
        assertEquals("I understand that the person who runs this server could open my vault and act as me.", warning.warning.understand.english)
        assertFalse(app.entry.acceptOperatorRecovery(warning, understood = false))
        assertSame(warning, app.snapshot.entry)
        assertTrue(app.entry.acceptOperatorRecovery(warning, understood = true))
        form = app.on()
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, form.whoCanRecover)
        app.entry.chooseOnlyMe(form)
        form = app.on()
        assertEquals(WhoCanRecover.ONLY_ME, form.whoCanRecover)
        app.entry.reviewOperatorRecovery(form)
        app.entry.keepRecoveryPrivate(app.on())
        form = app.on()
        assertEquals(WhoCanRecover.ONLY_ME, form.whoCanRecover)
        app.entry.reviewOperatorRecovery(form)
        assertTrue(app.entry.acceptOperatorRecovery(app.on(), understood = true))

        assertEquals(CreateAccountResult.INVALID_EMAIL, await { app.entry.createAccount(app.on(), NewAccountInput("nope", "Ada", PW, false)) })
        assertEquals(CreateAccountResult.DONE, await { app.entry.createAccount(app.on(), NewAccountInput("ada@family.example", "Ada", PW, false)) })
        app.saveKit()
        assertEquals("ada@family.example", app.account.email)
        assertFalse(app.contact("Bo").compared)
        assertEquals(PlainResult.DONE, await { app.recovery.openRecovery() })
        assertEquals(WhoCanRecover.ME_OR_OPERATOR, assertNotNull(app.account.recovery).whoCanRecover)
        // The choice was made on this device, so it holds its own record of it and is not asked again (T2-R-e).
        assertFalse(app.hasPrompt<AccountPrompt.KeepOperatorRecovery>())
    }

    @Test
    fun thePublicWordingOfTheRecoveryChoiceNamesTheInstanceAndItsOrigin() {
        // The wording follows the pinned card's kind; a public card with a recovery key exists only under variant K.
        val warning = OperatorRecoveryWarning(InstanceLabel("andvari", "https://vault.andvaripass.com", ServerKind.PUBLIC_SERVER, false), unsignedChange = true)
        assertEquals("Let the operator of andvari (https://vault.andvaripass.com) restore your account?", warning.title.english)
        assertEquals(3, warning.paragraphs.size)
        assertTrue(warning.paragraphs[0].english.startsWith("With operator recovery on, the people who run andvari hold a key"))
        assertEquals("I understand that the operator could open my vault and act as me.", warning.understand.english)
        assertEquals("The recovery key for andvari (https://vault.andvaripass.com) changed without the old key's signature.", warning.takeoverTitle?.english)
        val question = RecoveryQuestion(warning.instance, unsignedChange = false)
        assertEquals("Me, or the operator of andvari", question.meOrOperator.english)
        assertEquals("Only me", question.onlyMe.english)
    }

    @Test
    fun anEnrolLinkPassesTheTypedAddressGateAndLeavesAPinThatIsNotAPasswordPin() {
        val app = FakeScenes.at(FakeScene.GATE_ENROL_LINK)
        val gate = app.on<EntryScreen.TrustGate>().prompt
        assertEquals(TrustGateWording.ENROL_LINK, gate.wording)
        assertEquals("Connect to this server?", gate.title?.english)
        assertEquals(FAMILY, gate.origin)
        assertEquals(
            listOf(
                "This server will store your encrypted vault and see your account activity (email, sign-ins, item counts). Only continue if you trust it.",
                "It calls itself “Family” — nobody you know has vouched for it",
            ),
            gate.lines.map { it.english },
        )
        assertNull(app.snapshot.instance, "nothing is pinned or connected before the gate is confirmed")

        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(app.on()) })
        val form = app.on<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.ENROLMENT_LINK, form.via)
        assertEquals("ada@family.example", form.fixedEmail)
        assertNull(form.invitedBy, "an enrol link pins nobody")
        assertTrue(form.instance.selfNamed, "only the server vouches for its name")
        assertEquals("(as the server names itself)", CopyKey.AS_THE_SERVER_NAMES_ITSELF.english)
        assertEquals(CreateAccountResult.DONE, await { app.entry.createAccount(form, NewAccountInput("someone@else.example", "Ada", PW, false)) })
        app.saveKit()
        assertEquals("ada@family.example", app.account.email, "the link's address, whatever was typed")
        assertEquals(PlainResult.DONE, await { app.contacts.openContacts() })
        assertTrue(assertNotNull(app.account.contacts).contacts.isEmpty())

        // FI-B8: that pin created an account; it does not let another one sign in without the gate. (Signed out by the
        // person: a session the server ends keeps its account here, and another account waits until it is signed out.)
        assertEquals(PlainResult.DONE, await { app.signOut() })
        app.entry.openSignIn(app.on())
        app.entry.openPasswordSignIn(app.on())
        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(app.on(), FAMILY) })
        val again = app.on<EntryScreen.TrustGate>().prompt
        assertEquals(TrustGateWording.LINK_OFFER_SIGN_IN, again.wording)
        assertEquals("You're about to enter your master password for this server.", again.lines.last().english)
    }

    @Test
    fun anEnrolLinkForThePublicInstanceNeedsNoGate() {
        val app = FakeScenes.at(FakeScene.CREATE_ACCOUNT_ENROLLED)
        val form = app.on<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.ENROLMENT_LINK, form.via)
        assertEquals(ADA, form.fixedEmail)
        assertFalse(form.instance.selfNamed)
    }

    @Test
    fun aTappedInviteOpensFromAnyScreenAndATappedDeviceLinkStartsNothing() {
        val app = FakeScenes.at(FakeScene.SIGN_IN_CHOICE)
        val account = app.script.publicInstance.addAccount(ADA, PW)
        val before = app.snapshot.entry
        assertEquals(InviteResult.DEVICE_LINK_NOT_HERE, await { app.openAppLink(app.script.deviceLinkFrom(account, "MacBook")) })
        assertEquals(InviteResult.KIT_NOT_AN_INVITE, await { app.openAppLink(app.script.kitOf(account)) })
        assertSame(before, app.snapshot.entry)
        assertEquals(InviteResult.DONE, await { app.openAppLink(app.script.invitation(app.script.publicInstance, "Bo")) })
        assertEquals(RegistrationVia.INVITATION_LINK, app.on<EntryScreen.CreateAccount>().via)
        // A locked app is not a place to open links from.
        assertEquals(InviteResult.STALE, await { FakeScenes.at(FakeScene.LOCKED).openAppLink("https://andvaripass.com/l#v2.a.b.c") })
    }

    // ---- §12.1, §4.4, §8.7: sign-in and the password rule ----

    @Test
    fun signingInToThePublicInstanceNeedsNoGateAndNamesTheAccountInstanceAndOrigin() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        val account = app.script.publicInstance.addAccount(ADA, PW)
        val screen = app.on<EntryScreen.SignIn>()
        assertNull(screen.prompt.email, "the person types the address")
        assertNull(screen.prompt.title)
        assertEquals("Master password for ada@example.com on andvari (https://vault.andvaripass.com)", screen.prompt.titleFor(ADA).english)

        // One answer for a wrong address and a wrong password.
        assertEquals(SignInAnswer.WRONG, await { app.entry.submitSignIn(screen, "nobody@example.com", PW) })
        assertEquals(SignInAnswer.WRONG, await { app.entry.submitSignIn(screen, ADA, "not the password") })
        account.disabled = true
        assertEquals(SignInAnswer.WRONG, await { app.entry.submitSignIn(screen, ADA, PW) })
        account.disabled = false
        app.script.identityFault = true
        assertEquals(SignInAnswer.IDENTITY_FAULT, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)

        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(screen, " ADA@example.com", PW) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals(PlainResult.DONE, await { app.devices.openDevices() })
        val here = assertNotNull(app.account.devices).devices.first()
        assertTrue(here.current)
        assertEquals(HowDeviceJoined.PASSWORD, here.how)
    }

    /** The fake keeps the engine's results that say what is so (spec 01 §7; a proof the server refuses is never a wrong password). */
    @Test
    fun theFakeSaysWhatIsSoForAKeptCopyARecoveryFormAndARefusedProof() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW)
        val screen = app.on<EntryScreen.SignIn>()
        app.script.signInServerKeysNotKnown = true
        assertEquals(SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        app.script.signInOverOtherPasswordCopy = true
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertEquals(CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER, assertNotNull(app.snapshot.account).signInNotice?.key)
        app.dismissSignInNotice()
        assertNull(assertNotNull(app.snapshot.account).signInNotice)

        app.script.serverRefusesProof = true
        assertEquals(PasswordChangeResult.PROOF_REFUSED, await { app.settings.changeMasterPassword(PW, "a whole new Master password 9") })
        app.script.serverKeysNotKnownHere = true
        assertEquals(PasswordChangeResult.KEYS_NOT_KNOWN_HERE, await { app.settings.changeMasterPassword(PW, "a whole new Master password 9") })
    }

    @Test
    fun aTypedServerIsCheckedAgainstTheGrammarThenShownInTheTrustGate() {
        val app = FakeScenes.at(FakeScene.SIGN_IN_SERVER)
        val family = app.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
        family.addAccount(ADA, PW)
        val choice = app.on<EntryScreen.SignInServer>()
        assertEquals(ServerPurpose.SIGN_IN, choice.purpose)
        assertTrue(choice.offersPublicInstance)

        // §2.2: refused before the gate opens, with the one sentence for every such address.
        val refused = listOf(
            "http://vault.family.example", "https://localhost", "https://10.0.0.7", "https://vault.family.example:443",
            "https://vault.family.example/app", "https://VAULT.family.example", "vault.family.example", "https://family",
        )
        for (address in refused) {
            val result = await { app.entry.chooseOwnServer(choice, address) }
            assertEquals(ServerResult.NOT_AN_ADDRESS, result, address)
            assertEquals("andvari needs an https address with a domain name for this server.", result.sentence?.english)
        }
        assertEquals(ServerResult.UNREACHABLE, await { app.entry.chooseOwnServer(choice, "https://nobody.home.example") })
        family.hasCard = false
        assertEquals(ServerResult.NOT_SET_UP_YET, await { app.entry.chooseOwnServer(choice, FAMILY) })
        family.hasCard = true
        assertSame(choice, app.snapshot.entry)

        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(choice, FAMILY) })
        val gate = app.on<EntryScreen.TrustGate>()
        assertEquals(TrustGateWording.TYPED_ADDRESS, gate.prompt.wording)
        assertEquals("Connect to this server?", gate.prompt.title?.english)
        assertEquals("Family", gate.prompt.name)
        assertEquals(32, gate.prompt.operatorKeyShort.length)
        assertFalse(gate.prompt.switching)
        assertFalse(gate.prompt.kitIdentityChanged)

        // Declining ends the flow: nothing was pinned, so the gate comes up again.
        app.entry.declineTrustGate(gate)
        assertSame(choice, app.snapshot.entry)
        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(choice, FAMILY) })
        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(app.on()) })
        val screen = app.on<EntryScreen.SignIn>()
        assertTrue(screen.prompt.instance.selfNamed)
        assertEquals("Master password for ada@example.com on Family (https://vault.family.example)", screen.prompt.titleFor(ADA).english)
        // The gate is not a place to come back to.
        assertTrue(app.entry.back())
        assertSame(choice, app.snapshot.entry)
        // The pin the gate made is a password pin: the same address needs no gate again.
        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(choice, FAMILY) })
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(app.on(), ADA, PW) })
        assertEquals(FAMILY, app.snapshot.instance?.label?.origin)
    }

    @Test
    fun twoStepSignInAsksForTheCodeOnlyAfterTheRightPassword() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        app.script.publicInstance.addAccount(ADA, PW).twoStepCode = "654321"
        val screen = app.on<EntryScreen.SignIn>()
        assertFalse(screen.codeNeeded)
        assertEquals(SignInAnswer.WRONG, await { app.entry.submitSignIn(screen, ADA, "wrong") })
        assertSame(screen, app.snapshot.entry)
        assertEquals(SignInAnswer.CODE_NEEDED, await { app.entry.submitSignIn(screen, ADA, PW) })
        val withCode = app.on<EntryScreen.SignIn>()
        assertTrue(withCode.codeNeeded)
        // A code the server did not take is said as that (as the engine does), never as a wrong password.
        assertEquals(SignInAnswer.REFUSED_AFTER_CODE, await { app.entry.submitSignInCode(withCode, "000000") })
        // A wrong code drops the keys derived from the password (as the engine does): the password again.
        val again = app.on<EntryScreen.SignIn>()
        assertFalse(again.codeNeeded)
        assertEquals(SignInAnswer.STALE, await { app.entry.submitSignInCode(again, "654321") }, "a screen that asks for no code takes none")
        assertEquals(SignInAnswer.CODE_NEEDED, await { app.entry.submitSignIn(again, ADA, PW) })
        // The code alone: the password is not sent again.
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignInCode(app.on(), "654321") })
    }

    @Test
    fun anAccountThatRequiresLinkingSaysSoOnlyAfterTheRightPasswordAndCode() {
        val app = FakeScenes.at(FakeScene.SIGN_IN)
        val account = app.script.publicInstance.addAccount(ADA, PW)
        account.requireLink = true
        account.twoStepCode = "654321"
        val screen = app.on<EntryScreen.SignIn>()

        // FC-8: a wrong password is the uniform answer, and never tells that the account has the setting on.
        assertEquals(SignInAnswer.WRONG, await { app.entry.submitSignIn(screen, ADA, "wrong") })
        assertSame(screen, app.snapshot.entry)
        assertEquals(SignInAnswer.CODE_NEEDED, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertEquals(SignInAnswer.REFUSED_AFTER_CODE, await { app.entry.submitSignInCode(app.on(), "111111") })
        assertIs<EntryScreen.SignIn>(app.snapshot.entry)
        assertEquals(SignInAnswer.CODE_NEEDED, await { app.entry.submitSignIn(app.on(), ADA, PW) })

        assertEquals(SignInAnswer.LINK_REQUIRED, await { app.entry.submitSignInCode(app.on(), "654321") })
        val required = app.on<EntryScreen.LinkRequired>()
        assertEquals(ADA, required.email)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        app.entry.linkInstead(required)
        app.on<EntryScreen.LinkDeviceEntry>()

        // A device the account knows (its id and secret both match a live device) signs in with the password.
        val known = FakeScenes.at(FakeScene.SIGN_IN)
        val same = known.script.publicInstance.addAccount(ADA, PW)
        same.requireLink = true
        known.script.thisDeviceIsKnownTo(same)
        assertEquals(SignInAnswer.DONE, await { known.entry.submitSignIn(known.on(), ADA, PW) })
    }

    @Test
    fun aSignInThroughALinksPinShowsTheGateFirstAndSoDoesOneWhosePinWentAway() {
        val app = FakeScenes.at(FakeScene.GATE_SIGN_IN_AFTER_INVITE)
        val gate = app.on<EntryScreen.TrustGate>().prompt
        assertEquals(TrustGateWording.LINK_OFFER_SIGN_IN, gate.wording)
        assertEquals("You're about to enter your master password for this server.", gate.lines.last().english)
        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(app.on()) })
        val screen = app.on<EntryScreen.SignIn>()

        // The rule is checked again when the password is sent: without a password pin, the gate, and nothing sent.
        app.script.dropPins(app.scriptServer(FAMILY))
        assertEquals(SignInAnswer.TRUST_GATE_FIRST, await { app.entry.submitSignIn(screen, ADA, PW) })
        assertEquals(TrustGateWording.LINK_OFFER_SIGN_IN, app.on<EntryScreen.TrustGate>().prompt.wording)
    }

    @Test
    fun aServerThatServesAnotherServersCardIsPinnedByNoRoot() {
        // §2.4 `origin_mismatch`: cards are public, so a look-alike address can serve the real server's genuine chain.
        val app = fresh()
        val script = app.script
        val lookalike = script.addServer("https://vau1t.family.example", "Family", ServerKind.PRIVATE_SERVER)
        lookalike.servesAnotherServersCard = true
        lookalike.cardNamesOrigin = FAMILY
        val account = lookalike.addAccount(ADA, PW)

        // A typed address: refused before any Trust Gate could show the borrowed name and key. The screen says both addresses.
        app.entry.openOwnServer(app.on())
        assertEquals(ServerResult.OTHER_ADDRESS, await { app.entry.submitServerAddress(app.on(), "https://vau1t.family.example") })
        val typed = app.on<EntryScreen.AddressMismatch>()
        assertEquals("https://vau1t.family.example", typed.dialed)
        assertEquals(FAMILY, typed.cardNames)
        assertEquals(AddressMismatchFor.TYPED_ADDRESS, typed.opening)
        assertFalse(typed.canRecoverThere)
        assertNull(typed.sentence)
        assertEquals(KitScanResult.STALE, await { app.entry.recoverAtNamedAddress(typed) }, "only a kit is taken to the address its server's card names")
        assertTrue(app.entry.back())
        app.on<EntryScreen.OwnServer>()
        app.entry.startOver()

        // A link, a device link and a kit: none of them makes a pin from it, and nothing is sent to it.
        app.entry.openInviteEntry(app.on())
        assertEquals(InviteResult.OTHER_ADDRESS, await { app.entry.submitInvite(app.on(), script.connectInvite(lookalike, "Bo"), PayloadSource.SCANNED) })
        // Both addresses show; an invite is never redirected.
        val invited = app.on<EntryScreen.AddressMismatch>()
        assertEquals(AddressMismatchFor.INVITE, invited.opening)
        assertEquals("https://vau1t.family.example", invited.dialed)
        assertEquals(FAMILY, invited.cardNames)
        assertFalse(invited.canRecoverThere)
        assertTrue(app.entry.back())
        app.on<EntryScreen.InviteEntry>()
        app.entry.startOver()
        app.entry.openSignIn(app.on())
        app.entry.openLinkDevice(app.on())
        assertEquals(DeviceLinkScanResult.OTHER_ADDRESS, await { app.entry.submitDeviceLink(app.on(), script.deviceLinkFrom(account, "MacBook"), PayloadSource.SCANNED) })
        // A device link is never redirected: the person starts again from the other device.
        assertFalse(app.on<EntryScreen.AddressMismatch>().canRecoverThere)
        assertTrue(app.entry.back())
        app.on<EntryScreen.LinkDeviceEntry>()
        app.entry.startOver()
        app.entry.openSignIn(app.on())
        app.entry.openForgot(app.on())
        app.entry.openKitEntry(app.on())
        assertEquals(KitScanResult.OTHER_ADDRESS, await { app.entry.submitKit(app.on(), script.kitOf(account), PayloadSource.SCANNED) })
        assertEquals(AddressMismatchFor.KIT, app.on<EntryScreen.AddressMismatch>().opening)
        assertTrue(app.pins.isEmpty(), "nothing was pinned")
        assertNull(app.snapshot.instance)

        // The baked instance is held to the same rule; there only an update of the app helps.
        script.publicInstance.servesAnotherServersCard = true
        app.entry.startOver()
        assertEquals(ServerResult.OTHER_ADDRESS, await { app.entry.createAccountOnAndvari(app.on()) })
        val baked = app.on<EntryScreen.AddressMismatch>()
        assertTrue(baked.publicInstance)
        assertEquals(CopyKey.CARD_MOVED_UPDATE, baked.sentence)
        assertTrue(app.pins.isEmpty())
    }

    @Test
    fun aKitFromBeforeItsServerMovedIsOfferedTheAddressTheCardNamesWhereEveryCheckRunsAgain() {
        val app = FakeScenes.at(FakeScene.KIT_ENTRY)
        val script = app.script
        val family = script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
        val account = family.addAccount(ADA, PW)
        val kit = script.kitFromBeforeMove(account, "https://old.family.example")

        // The old address serves the real server's chain, whose newest card names the new address: no dead end.
        assertEquals(KitScanResult.OTHER_ADDRESS, await { app.entry.submitKit(app.on(), kit, PayloadSource.SCANNED) })
        val mismatch = app.on<EntryScreen.AddressMismatch>()
        assertEquals("https://old.family.example", mismatch.dialed)
        assertEquals(FAMILY, mismatch.cardNames)
        assertTrue(mismatch.canRecoverThere)
        assertTrue(app.pins.isEmpty(), "nothing is pinned for the address the kit named")

        assertEquals(KitScanResult.DONE, await { app.entry.recoverAtNamedAddress(mismatch) })
        val recover = app.on<EntryScreen.KitRecover>()
        assertEquals("Recover ada@example.com on Family (https://vault.family.example)", recover.title.english)
        assertEquals(KitScanResult.STALE, await { app.entry.recoverAtNamedAddress(mismatch) })
        // The mismatch is not a place to come back to.
        assertTrue(app.entry.back())
        app.on<EntryScreen.KitEntry>()
        assertTrue(app.pins.isEmpty(), "the kit pin this recovery made went with it")
    }

    @Test
    fun aServerWhoseIdentityNoLongerContinuesThePinIsNotSignedInTo() {
        val app = FakeScenes.at(FakeScene.SIGN_IN_SERVER)
        val family = app.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(app.on(), FAMILY) })
        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(app.on()) })
        assertTrue(app.entry.back())
        // An operator reset, or something worse: the chain no longer contains the card this device pinned (§4.4, §4.6).
        family.identityChanged = true
        assertEquals(ServerResult.IDENTITY_CONFLICT, await { app.entry.chooseOwnServer(app.on(), FAMILY) })
        // The journey shows the stopped server itself: the card and "Forget this server" belong to the server the screen names.
        val stopped = app.on<EntryScreen.ServerChanged>()
        assertSame(stopped.instance, app.snapshot.instance)
        assertEquals(FAMILY, stopped.instance.label.origin)
        assertIs<InstanceCardState.Stopped>(stopped.instance.card)
        assertEquals("This server's identity changed in a way andvari can't verify. Don't continue. If you trust the operator, ask them what happened.", CopyKey.CARD_FORK.english)
        // The only way on.
        assertEquals(PlainResult.DONE, await { app.instance.forgetServer(stopped.instance) })
        assertNull(app.snapshot.instance)
        app.on<EntryScreen.FirstRun>()
        assertEquals(PlainResult.STALE, await { app.instance.forgetServer(stopped.instance) })
    }

    /** A screen's intents act on the server the screen names, whatever was opened in between. */
    @Test
    fun aSignInScreenSignsInToTheServerItNamesAfterAnInviteForAnotherWasTappedAndLeft() {
        val app = FakeScenes.at(FakeScene.SIGN_IN_SERVER)
        val script = app.script
        val family = script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
        val familyAda = family.addAccount(ADA, PW)
        // The same address and the same password exist on the public instance: only the server tells the two apart.
        val publicAda = script.publicInstance.addAccount(ADA, PW)
        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(app.on(), FAMILY) })
        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(app.on()) })
        val signIn = app.on<EntryScreen.SignIn>()
        assertEquals("Family", signIn.prompt.instance.name)
        assertEquals(FAMILY, app.snapshot.instance?.label?.origin)

        // An invite to the public instance is tapped: it starts a journey of its own, at its own server.
        assertEquals(InviteResult.DONE, await { app.openAppLink(script.connectInvite(script.publicInstance, "Bo")) })
        val join = app.on<EntryScreen.JoinInvite>()
        assertEquals("andvari", join.instance.name)
        assertEquals("https://vault.andvaripass.com", app.snapshot.instance?.label?.origin, "the instance on show is the screen's own")

        // Back: the very screen that names Family, and it still acts on Family.
        assertTrue(app.entry.back())
        assertSame(signIn, app.snapshot.entry)
        assertEquals(FAMILY, app.snapshot.instance?.label?.origin)
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(signIn, ADA, PW) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals(FAMILY, app.snapshot.instance?.label?.origin)
        assertTrue(familyAda.devices.any { it.live }, "the password went to the server the screen named")
        assertTrue(publicAda.devices.isEmpty(), "and nothing of it reached the public instance")
        assertEquals(familyAda.accountId, app.account.accountId)

        // The other way round, with two typed servers: each screen keeps its own.
        val two = FakeScenes.at(FakeScene.OWN_SERVER)
        val one = two.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
        val other = two.script.addServer("https://vault.other.example", "Other", ServerKind.PRIVATE_SERVER)
        one.addAccount(ADA, PW)
        val wrong = other.addAccount(ADA, "another password entirely")
        assertEquals(ServerResult.DONE, await { two.entry.submitServerAddress(two.on(), FAMILY) })
        assertEquals(ServerResult.DONE, await { two.entry.confirmTrustGate(two.on()) })
        val familyScreen = two.on<EntryScreen.Server>()
        assertTrue(two.entry.back())
        assertEquals(ServerResult.DONE, await { two.entry.submitServerAddress(two.on(), "https://vault.other.example") })
        assertEquals(ServerResult.DONE, await { two.entry.confirmTrustGate(two.on()) })
        val otherScreen = two.on<EntryScreen.Server>()
        assertEquals("Other", otherScreen.instance.name)
        // The first server's screen is no longer on show: it is stale, and does not act on the second.
        assertEquals(ServerResult.STALE, await { two.entry.signInHere(familyScreen) })
        assertEquals(ServerResult.DONE, await { two.entry.signInHere(otherScreen) })
        assertEquals(SignInAnswer.WRONG, await { two.entry.submitSignIn(two.on(), ADA, PW) }, "Family's password is not Other's")
        assertTrue(wrong.devices.isEmpty())
    }

    @Test
    fun aSignInThatFindsTheKitWasNeverSavedShowsOneBeforeTheVaultOpens() {
        val app = FakeScenes.at(FakeScene.KIT_NOT_MADE)
        val failed = app.kitOnShow()
        assertEquals(KitReason.NEVER_SAVED, failed.reason)
        assertEquals(KitStep.NOT_MADE, failed.step)
        assertNull(app.kit.kitDocument(failed))
        app.script.kitCommitFails = true
        assertEquals(KitConfirmResult.UNREACHABLE, await { app.kit.retryKit(failed, PW) })
        // Making a kit re-authenticates: the master password, every time.
        assertEquals(KitConfirmResult.WRONG_PASSWORD, await { app.kit.retryKit(app.kitOnShow(), "not the password") })
        assertEquals(KitStep.NOT_MADE, app.kitOnShow().step)
        assertEquals(KitConfirmResult.DONE, await { app.kit.retryKit(app.kitOnShow(), PW) })
        assertEquals(KitStep.REVEAL, app.kitOnShow().step)

        // Another device makes a newer kit while this one is being confirmed: this one is void, and a fresh one needs the password.
        val first = assertNotNull(app.kit.kitDocument(app.kitOnShow())).groups
        app.kit.proceedToConfirm(app.kitOnShow())
        app.script.kitReplacedElsewhere = true
        val confirm = app.kitOnShow()
        assertEquals(KitConfirmResult.REPLACED, await { app.kit.confirmKit(confirm, confirm.groupsToType.map { first[it - 1] }) })
        assertEquals(KitReason.REPLACED_ELSEWHERE, app.kitOnShow().reason)
        assertEquals(KitStep.NOT_MADE, app.kitOnShow().step)
        assertNull(app.kit.kitDocument(app.kitOnShow()))
        assertEquals(KitConfirmResult.DONE, await { app.kit.retryKit(app.kitOnShow(), PW) })
        assertEquals(KitStep.REVEAL, app.kitOnShow().step)
        assertFalse(first == assertNotNull(app.kit.kitDocument(app.kitOnShow())).groups)
        app.kit.proceedToConfirm(app.kitOnShow())
        app.kit.showKitAgain(app.kitOnShow())
        assertEquals(KitStep.REVEAL, app.kitOnShow().step)
        app.saveKit()
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)

        // A commit that has not landed yet is its own step.
        val making = FakeScenes.at(FakeScene.KIT_MAKING)
        assertEquals(KitStep.MAKING, making.kitOnShow().step)
        making.script.finishKitCommit()
        assertEquals(KitStep.REVEAL, making.kitOnShow().step)
    }

    // ---- §8.2: linking this device ----

    /**
     * As the engine, at a link's password: a former password that still opens this device's copy of the account is a
     * refused proof (never "wrong password"), and the link and its screen stay; a two-step code the server did not take
     * leaves the link open too, back at the password.
     */
    @Test
    fun theFakePlaysARefusedProofAndARefusedCodeAtALinkAsTheEngineDoes() {
        val app = FakeAppApi()
        val script = app.script
        val account = script.publicInstance.addAccount(ADA, PW)
        account.twoStepCode = "123456"
        script.storeSession(account)
        app.start()
        app.endedByServer()
        app.signInAgain(assertNotNull(app.snapshot.locked))
        app.previousPasswordHere = "a former master password"
        app.entry.openSignIn(app.on())
        app.entry.openLinkDevice(app.on())
        assertEquals(DeviceLinkScanResult.DONE, await { app.entry.submitDeviceLink(app.on(), script.deviceLinkFrom(account, "MacBook"), PayloadSource.SCANNED) })
        script.otherDeviceApproves()
        script.otherDeviceAnswers()
        script.otherDeviceApproves()
        val pw = app.on<EntryScreen.LinkDevicePassword>()
        val refused = await { app.entry.submitLinkPassword(pw, "a former master password") }
        assertEquals(LinkPasswordResult.PROOF_REFUSED, refused)
        assertEquals(CopyKey.LINK_PROOF_REFUSED_TYPE_CURRENT, refused.sentence)
        assertSame(pw, app.snapshot.entry, "the link and its screen stay")
        assertEquals(LinkPasswordResult.WRONG, await { app.entry.submitLinkPassword(pw, "not it at all") })
        assertEquals(LinkPasswordResult.CODE_NEEDED, await { app.entry.submitLinkPassword(pw, PW) })
        val code = app.on<EntryScreen.LinkDevicePassword>()
        assertTrue(code.codeNeeded)
        assertEquals(LinkPasswordResult.CODE_REFUSED_LINK_STAYS, await { app.entry.submitLinkCode(code, "000000") })
        assertFalse(app.on<EntryScreen.LinkDevicePassword>().codeNeeded, "back at the password, the link open")
        assertEquals(LinkPasswordResult.CODE_NEEDED, await { app.entry.submitLinkPassword(app.on(), PW) })
        assertEquals(LinkPasswordResult.DONE, await { app.entry.submitLinkCode(app.on(), "123456") })
    }

    @Test
    fun theNewDeviceShowsNoCodeBeforeItsCommitmentAndAsksNoPasswordBeforeTheApproval() {
        val app = FakeScenes.at(FakeScene.LINK_DEVICE_ENTRY)
        val script = app.script
        val account = script.publicInstance.addAccount(ADA, PW)
        account.addContact("Bo", compared = true)
        val entry = app.on<EntryScreen.LinkDeviceEntry>()

        // "The only place a device link is accepted" also accepts nothing else.
        assertEquals(DeviceLinkScanResult.NOT_A_DEVICE_LINK, await { app.entry.submitDeviceLink(entry, script.connectInvite(script.publicInstance, "Bo"), PayloadSource.SCANNED) })
        assertEquals(DeviceLinkScanResult.NOT_A_DEVICE_LINK, await { app.entry.submitDeviceLink(entry, script.kitOf(account), PayloadSource.PASTED) })
        assertSame(entry, app.snapshot.entry)

        // The baked instance is already a password pin: the claim goes out with this device's commitment.
        assertEquals(DeviceLinkScanResult.DONE, await { app.entry.submitDeviceLink(entry, script.deviceLinkFrom(account, "MacBook"), PayloadSource.SCANNED) })
        val waiting = app.on<EntryScreen.LinkDeviceWaiting>()
        assertEquals("andvari", waiting.instance.name)

        // Nothing but the other device's nonce produces a code, and nothing but its approval a password screen.
        script.otherDeviceApproves()
        assertSame(waiting, app.snapshot.entry)
        script.otherDeviceAnswers()
        val code = app.on<EntryScreen.LinkDeviceCode>()
        assertEquals(6, code.code.length)
        assertTrue(code.code.all { it in '0'..'9' })
        script.otherDeviceAnswers()
        assertSame(code, app.snapshot.entry, "the code is computed once")

        script.otherDeviceApproves()
        val password = app.on<EntryScreen.LinkDevicePassword>()
        assertEquals("Master password for ada@example.com on andvari (https://vault.andvaripass.com)", password.prompt.title?.english)
        assertEquals(LinkPasswordResult.WRONG, await { app.entry.submitLinkPassword(password, "wrong") })
        assertSame(password, app.snapshot.entry)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase, "no session without the master password")
        assertEquals(LinkPasswordResult.DONE, await { app.entry.submitLinkPassword(password, PW) })

        // Linked: the account's contacts count here at once, with no second ceremony (G3).
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertTrue(app.account.prompts.isEmpty())
        assertTrue(app.contact("Bo").currentHere)
        assertEquals(PlainResult.DONE, await { app.devices.openDevices() })
        val here = assertNotNull(app.account.devices).devices.first { it.current }
        assertEquals(HowDeviceJoined.LINKED, here.how)
        assertEquals("MacBook", here.linkedFrom)
    }

    @Test
    fun aDeviceLinkToAnUnpinnedServerPinsItThroughItsOwnGateBeforeAnythingIsSent() {
        val app = FakeScenes.at(FakeScene.GATE_DEVICE_LINK)
        val gate = app.on<EntryScreen.TrustGate>()
        assertEquals(TrustGateWording.DEVICE_LINK, gate.prompt.wording)
        assertEquals("Is this your server?", gate.prompt.title?.english)
        assertEquals(
            "https://vault.family.example — it calls itself “Family”. This device hasn't used it before. " +
                "Your other device shows the address it links to: continue only if it is exactly the same.",
            gate.prompt.lines.single().english,
        )
        assertEquals("It's the same", gate.prompt.confirmLabel?.english)

        // Declining ends the flow; nothing was claimed and nothing pinned.
        app.entry.declineTrustGate(gate)
        app.on<EntryScreen.LinkDeviceEntry>()
        assertNull(app.snapshot.instance)

        val again = FakeScenes.at(FakeScene.GATE_DEVICE_LINK)
        assertEquals(ServerResult.DONE, await { again.entry.confirmTrustGate(again.on()) })
        again.on<EntryScreen.LinkDeviceWaiting>()
    }

    @Test
    fun aBundleThatDisagreesWithThePinSignsTheDeviceOutAndDropsThePin() {
        val app = FakeScenes.at(FakeScene.GATE_DEVICE_LINK)
        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(app.on()) })
        app.script.otherDeviceAnswers()
        app.script.otherDeviceApproves()
        app.script.bundleDisagreesWithPin = true
        assertEquals(LinkPasswordResult.ENDED, await { app.entry.submitLinkPassword(app.on(), PW) })
        val ended = app.on<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.WRONG_SERVER, ended.outcome)
        assertEquals("This isn't the server your other device uses. Nothing was linked.", ended.outcome.sentence?.english)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        assertNull(app.snapshot.account)
        assertNull(app.snapshot.instance, "the pin made for the link is gone")

        // So the next link to that address meets the gate again.
        app.entry.dismissLinkDevice(ended)
        val other = app.scriptServer(FAMILY).accounts.values.first()
        assertEquals(DeviceLinkScanResult.DONE, await { app.entry.submitDeviceLink(app.on(), app.script.deviceLinkFrom(other, "MacBook"), PayloadSource.SCANNED) })
        assertEquals(TrustGateWording.DEVICE_LINK, app.on<EntryScreen.TrustGate>().prompt.wording)

        val unopenable = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        unopenable.script.bundleDoesNotOpen = true
        assertEquals(LinkPasswordResult.ENDED, await { unopenable.entry.submitLinkPassword(unopenable.on(), PW) })
        assertEquals(LinkDeviceEnd.DID_NOT_CHECK_OUT, unopenable.on<EntryScreen.LinkDeviceEnded>().outcome)
        assertEquals(AppPhase.ENTRY, unopenable.snapshot.phase)
    }

    @Test
    fun aDeviceLinkEndsWhenItIsCancelledClaimedByAnotherOrOutOfTime() {
        val cancelled = FakeScenes.at(FakeScene.LINK_DEVICE_CODE)
        cancelled.script.otherDeviceCancels()
        val ended = cancelled.on<EntryScreen.LinkDeviceEnded>()
        assertEquals(LinkDeviceEnd.CANCELLED, ended.outcome)
        assertEquals("Linking was cancelled", ended.outcome.sentence?.english)
        cancelled.entry.dismissLinkDevice(ended)
        cancelled.on<EntryScreen.LinkDeviceEntry>()

        val anomaly = FakeScenes.at(FakeScene.LINK_DEVICE_WAITING)
        anomaly.script.linkFailsItsChecks()
        assertEquals(LinkDeviceEnd.DID_NOT_CHECK_OUT, anomaly.on<EntryScreen.LinkDeviceEnded>().outcome)

        // Each step of a link has five minutes.
        val slow = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        slow.script.advance(6 * MINUTE)
        assertEquals(LinkDeviceEnd.EXPIRED, slow.on<EntryScreen.LinkDeviceEnded>().outcome)

        // T12: whoever read the QR first claimed it. The real device sees that, rather than a wait that never ends.
        val raced = FakeScenes.at(FakeScene.LINK_DEVICE_ENTRY)
        val account = raced.script.publicInstance.addAccount(ADA, PW)
        val link = raced.script.deviceLinkFrom(account, "MacBook")
        raced.script.someoneElseClaims(link)
        assertEquals(DeviceLinkScanResult.DONE, await { raced.entry.submitDeviceLink(raced.on(), link, PayloadSource.SCANNED) })
        assertEquals(LinkDeviceEnd.ALREADY_CLAIMED, raced.on<EntryScreen.LinkDeviceEnded>().outcome)

        val gone = FakeScenes.at(FakeScene.LINK_DEVICE_ENTRY)
        val replaced = gone.script.deviceLinkFrom(gone.script.publicInstance.addAccount(ADA, PW), "MacBook")
        gone.script.cancelDeviceLink(replaced)
        assertEquals(DeviceLinkScanResult.DONE, await { gone.entry.submitDeviceLink(gone.on(), replaced, PayloadSource.PASTED) })
        assertEquals(LinkDeviceEnd.CANCELLED, gone.on<EntryScreen.LinkDeviceEnded>().outcome)

        val twoStep = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        twoStep.scriptServer("https://vault.andvaripass.com").accounts.values.first().twoStepCode = "654321"
        assertEquals(LinkPasswordResult.CODE_NEEDED, await { twoStep.entry.submitLinkPassword(twoStep.on(), PW) })
        assertTrue(twoStep.on<EntryScreen.LinkDevicePassword>().codeNeeded)
        // As the engine: within the link's time a code the server did not take leaves the link open, said as that, back
        // at the password.
        assertEquals(LinkPasswordResult.CODE_REFUSED_LINK_STAYS, await { twoStep.entry.submitLinkCode(twoStep.on(), "000000") })
        assertFalse(twoStep.on<EntryScreen.LinkDevicePassword>().codeNeeded)

        val rightCode = FakeScenes.at(FakeScene.LINK_DEVICE_PASSWORD)
        rightCode.scriptServer("https://vault.andvaripass.com").accounts.values.first().twoStepCode = "654321"
        assertEquals(LinkPasswordResult.CODE_NEEDED, await { rightCode.entry.submitLinkPassword(rightCode.on(), PW) })
        assertEquals(LinkPasswordResult.DONE, await { rightCode.entry.submitLinkCode(rightCode.on(), "654321") })
    }

    @Test
    fun aServerThatMovedUnderItsPinIsShownAsAMoveFirstAndTheFlowStartsAgainAfterIt() {
        val app = FakeScenes.at(FakeScene.SERVER_CHANGED)
        val changed = app.on<EntryScreen.ServerChanged>()
        assertEquals("https://vault.family.example", changed.instance.label.origin)
        val card = assertIs<InstanceCardState.Moved>(changed.instance.card)
        assertEquals("https://family.example", card.toOrigin)
        assertEquals(MoveResult.DONE, await { app.instance.followMove(card) })
        // Back where the flow began; opening the server again now finds it at its new address.
        val server = app.on<EntryScreen.SignInServer>()
        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(server, "https://family.example") })
        assertIs<EntryScreen.SignIn>(app.snapshot.entry)
    }

    @Test
    fun aRecoveryCommitWithNoAnswerMayHaveWorkedAndLeadsToSignIn() {
        val app = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        app.script.recoveryCommitUnanswered = true
        assertEquals(ReplacePasswordResult.MAY_HAVE_WORKED, await { app.entry.chooseReplacementPassword(app.on(), "a brand new master password") })
        val signIn = app.on<EntryScreen.SignIn>()
        assertEquals(SignInAnswer.DONE, await { app.entry.submitSignIn(signIn, FakeScenes.EMAIL, "a brand new master password") })
    }

    // ---- §10: recovery with the kit ----

    @Test
    fun aKitIsTakenOnlyOnItsOwnScreenAndTheRecoveryNamesTheAccountAndTheServerFirst() {
        val app = FakeScenes.at(FakeScene.KIT_ENTRY)
        val script = app.script
        val account = script.publicInstance.addAccount(ADA, PW)
        account.twoStepCode = "654321"
        account.requireLink = true
        val kit = script.kitOf(account)
        val entry = app.on<EntryScreen.KitEntry>()

        assertEquals(KitScanResult.NOT_A_KIT, await { app.entry.submitKit(entry, script.connectInvite(script.publicInstance, "Bo"), PayloadSource.SCANNED) })
        assertEquals(KitScanResult.NOT_A_KIT, await { app.entry.submitKit(entry, script.deviceLinkFrom(account, "MacBook"), PayloadSource.SCANNED) })
        assertEquals(KitScanResult.NOT_A_KIT, await { app.entry.submitKit(entry, "andvari-kit:2:nothing", PayloadSource.PASTED) })
        assertSame(entry, app.snapshot.entry)

        assertEquals(KitScanResult.DONE, await { app.entry.submitKit(entry, kit, PayloadSource.SCANNED) })
        val target = app.on<EntryScreen.KitRecover>()
        assertEquals("Recover ada@example.com on andvari (https://vault.andvaripass.com)", target.title.english)
        assertEquals(KitRecoverResult.DONE, await { app.entry.confirmKitRecovery(target) })
        val replace = app.on<EntryScreen.ReplacePassword>()
        assertEquals(RecoveryRoute.KIT, replace.after)
        assertEquals(ReplacePasswordResult.WEAK_PASSWORD, await { app.entry.chooseReplacementPassword(replace, "short") })
        assertEquals(ReplacePasswordResult.DONE, await { app.entry.chooseReplacementPassword(replace, "a brand new master password") })

        // FS-B1: the commit replaced the kit, so the new one is forced before the vault opens.
        val forced = app.kitOnShow()
        assertEquals(KitReason.AFTER_RECOVERY, forced.reason)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        assertFalse(app.entry.back())
        // §8.7: someone who lost every device would otherwise be locked out.
        assertNull(account.twoStepCode)
        assertFalse(account.requireLink)
        app.saveKit()
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertEquals(PlainResult.DONE, await { app.devices.openDevices() })
        assertEquals(HowDeviceJoined.RECOVERED, assertNotNull(app.account.devices).devices.first { it.current }.how)

        // The scanned kit stopped working with the commit.
        val later = FakeScenes.at(FakeScene.KIT_ENTRY)
        val same = later.script.publicInstance.addAccount(ADA, PW)
        val old = later.script.kitOf(same)
        same.kitSerial++
        assertEquals(KitScanResult.DONE, await { later.entry.submitKit(later.on(), old, PayloadSource.SCANNED) })
        val refused = later.on<EntryScreen.KitRecover>()
        assertEquals(KitRecoverResult.KIT_NOT_ACCEPTED, await { later.entry.confirmKitRecovery(refused) })
        // A kit is proved once: the engine has wiped it, so the same screen cannot be tried again.
        later.on<EntryScreen.KitEntry>()
        assertEquals(KitRecoverResult.STALE, await { later.entry.confirmKitRecovery(refused) })
    }

    @Test
    fun aKitTypedByHandVouchesForNoServerSoTheGateOpensFirst() {
        fun typing(): Triple<FakeAppApi, EntryScreen.KitEntry, String> {
            val app = FakeScenes.at(FakeScene.KIT_ENTRY)
            val family = app.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
            return Triple(app, app.on(), app.script.kitGroupsOf(family.addAccount(ADA, PW)))
        }
        val (app, screen, groups) = typing()
        assertEquals(11, groups.split(' ').size)

        // What the form itself can refuse: nothing was sent for any of these.
        assertEquals(KitScanResult.INVALID_EMAIL, await { app.entry.submitTypedKit(screen, "nope", FAMILY, groups) })
        val address = await { app.entry.submitTypedKit(screen, ADA, "vault.family.example", groups) }
        assertEquals(KitScanResult.NOT_AN_ADDRESS, address)
        assertEquals(CopyKey.ADDRESS_NEEDS_HTTPS_DOMAIN, address.sentence)
        assertEquals(KitScanResult.NOT_A_KIT, await { app.entry.submitTypedKit(screen, ADA, FAMILY, groups.dropLast(1)) })
        assertEquals(KitScanResult.NOT_A_KIT, await { app.entry.submitTypedKit(screen, ADA, FAMILY, groups.replace(' ', '\t')) }, "a tab is not ignored")
        app.on<EntryScreen.KitEntry>()
        assertTrue(app.pins.isEmpty())

        // No card hash was typed, so nothing but the person vouches for the server: the Trust Gate, without the
        // "identity changed since your kit" warning, which only a scanned kit can raise.
        assertEquals(KitScanResult.DONE, await { app.entry.submitTypedKit(screen, " Ada@Example.com ", FAMILY, groups.replace(" ", "\n")) })
        val gate = app.on<EntryScreen.TrustGate>()
        assertEquals(TrustGateWording.TYPED_ADDRESS, gate.prompt.wording)
        assertFalse(gate.prompt.kitIdentityChanged)
        assertEquals(FAMILY, gate.prompt.origin)
        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(gate) })
        val recover = app.on<EntryScreen.KitRecover>()
        assertEquals(ADA, recover.email)
        assertEquals(FAMILY, recover.instance.origin)
        assertEquals(KitRecoverResult.DONE, await { app.entry.confirmKitRecovery(recover) })
        assertEquals(RecoveryRoute.KIT, app.on<EntryScreen.ReplacePassword>().after)

        // Declining the gate ends it there, and nothing was pinned.
        val (declining, form, typed) = typing()
        assertEquals(KitScanResult.DONE, await { declining.entry.submitTypedKit(form, ADA, FAMILY, typed) })
        declining.entry.declineTrustGate(declining.on())
        declining.on<EntryScreen.KitEntry>()
        assertTrue(declining.pins.isEmpty())

        // Wrong groups, or an address with no account there: the app cannot tell either from a right kit. The
        // server's one answer does, and it is the same for both.
        val (wrong, wrongForm, right) = typing()
        val other = (if (right[0] == 'A') "B" else "A") + right.drop(1)
        assertEquals(KitScanResult.DONE, await { wrong.entry.submitTypedKit(wrongForm, ADA, FAMILY, other) })
        assertEquals(ServerResult.DONE, await { wrong.entry.confirmTrustGate(wrong.on()) })
        assertEquals(KitRecoverResult.KIT_NOT_ACCEPTED, await { wrong.entry.confirmKitRecovery(wrong.on()) })
        val (nobody, nobodyForm, real) = typing()
        assertEquals(KitScanResult.DONE, await { nobody.entry.submitTypedKit(nobodyForm, "nobody@example.com", FAMILY, real) })
        assertEquals(ServerResult.DONE, await { nobody.entry.confirmTrustGate(nobody.on()) })
        assertEquals("nobody@example.com", nobody.on<EntryScreen.KitRecover>().email)
        assertEquals(KitRecoverResult.KIT_NOT_ACCEPTED, await { nobody.entry.confirmKitRecovery(nobody.on()) })

        // The public instance is pinned from the baked root, typed kit or not: no gate.
        val public = FakeScenes.at(FakeScene.KIT_ENTRY)
        val mine = public.script.publicInstance.addAccount(ADA, PW)
        assertEquals(KitScanResult.DONE, await { public.entry.submitTypedKit(public.on(), ADA, "https://vault.andvaripass.com", public.script.kitGroupsOf(mine)) })
        assertEquals(KitRecoverResult.DONE, await { public.entry.confirmKitRecovery(public.on()) })

        // A pasted kit text counts as a scan: the kit's own card hash pins the server, with no gate.
        val pasted = FakeScenes.at(FakeScene.KIT_ENTRY)
        val theirs = pasted.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER).addAccount(ADA, PW)
        assertEquals(KitScanResult.DONE, await { pasted.entry.submitKit(pasted.on(), pasted.script.kitOf(theirs), PayloadSource.PASTED) })
        pasted.on<EntryScreen.KitRecover>()
    }

    @Test
    fun aKitFromBeforeAnIdentityResetFallsBackToTheGateWithItsWarning() {
        val app = FakeScenes.at(FakeScene.GATE_KIT_IDENTITY_CHANGED)
        val gate = app.on<EntryScreen.TrustGate>().prompt
        assertTrue(gate.kitIdentityChanged)
        assertEquals("This server's identity changed since your kit was made. Continue only if you know why", gate.lines.first().english)
        assertEquals(3, gate.lines.size)
        assertEquals(ServerResult.DONE, await { app.entry.confirmTrustGate(app.on()) })
        assertEquals("Recover ada@example.com on Family (https://vault.family.example)", app.on<EntryScreen.KitRecover>().title.english)
    }

    @Test
    fun aKitsPinCountsForItsOwnRecoveryAndNotForSigningInToAnotherAccount() {
        val app = FakeScenes.at(FakeScene.KIT_ENTRY)
        val family = app.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
        val lost = family.addAccount(ADA, PW)
        family.addAccount("bo@family.example", PW)
        // The kit's own card hash anchors the pin: no gate, although this device never saw the server.
        assertEquals(KitScanResult.DONE, await { app.entry.submitKit(app.on(), app.script.kitOf(lost), PayloadSource.SCANNED) })
        val target = app.on<EntryScreen.KitRecover>()
        assertFalse(target.instance.selfNamed)
        // The recovery goes through; its kit pin stays with the account it recovered.
        assertEquals(KitRecoverResult.DONE, await { app.entry.confirmKitRecovery(target) })
        assertEquals(ReplacePasswordResult.DONE, await { app.entry.chooseReplacementPassword(app.on(), "a brand new master password") })
        app.saveKit()
        assertEquals(PlainResult.DONE, await { app.signOut() })

        // FS-B1: without this, a kit shown as an "invite" would have passed later sign-ins on an attacker's server.
        app.entry.openSignIn(app.on())
        app.entry.openPasswordSignIn(app.on())
        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(app.on(), FAMILY) })
        assertEquals(TrustGateWording.LINK_OFFER_SIGN_IN, app.on<EntryScreen.TrustGate>().prompt.wording)

        val disabled = FakeScenes.at(FakeScene.REPLACE_PASSWORD)
        disabled.scriptServer("https://vault.andvaripass.com").accounts.values.first().disabled = true
        assertEquals(ReplacePasswordResult.ACCOUNT_DISABLED, await { disabled.entry.chooseReplacementPassword(disabled.on(), "a brand new master password") })
    }

    // ---- §9.3: the operator's help ----

    @Test
    fun thePublicInstanceOffersNoOperatorHelpWhateverItsCardSays() {
        val app = FakeScenes.at(FakeScene.FORGOT)
        // Variant R is compiled into the client: a public card that names a recovery key changes nothing.
        app.script.publicInstance.recoveryKey = true
        app.entry.openAskOperator(app.on())
        val choice = app.on<EntryScreen.SignInServer>()
        assertEquals(ServerPurpose.ASK_OPERATOR, choice.purpose)
        assertEquals(ServerResult.NO_OPERATOR_RECOVERY, await { app.entry.choosePublicInstance(choice) })
        assertSame(choice, app.snapshot.entry)

        // A private server without a recovery key offers none either, and says so after its gate.
        val plain = app.script.addServer(FAMILY, "Family", ServerKind.PRIVATE_SERVER)
        assertFalse(plain.recoveryKey)
        assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(choice, FAMILY) })
        assertEquals(ServerResult.NO_OPERATOR_RECOVERY, await { app.entry.confirmTrustGate(app.on()) })
        assertSame(choice, app.snapshot.entry)
    }

    @Test
    fun aRequestForHelpWaitsOutItsHoldAndEndsInANewPasswordAndAForcedKit() {
        val app = FakeScenes.at(FakeScene.ASK_OPERATOR)
        val script = app.script
        val account = app.scriptServer(FAMILY).accounts.values.first()
        account.twoStepCode = "654321"
        val ask = app.on<EntryScreen.AskOperator>()
        assertEquals("Anyone who gets into your email can ask too. The operator waits 7 days and checks with you, and your other devices can cancel.", CopyKey.ASK_OPERATOR_WHO_CAN.english)

        assertEquals(AskOperatorResult.INVALID_EMAIL, await { app.entry.requestOperatorHelp(ask, "nope") })
        app.scriptServer(FAMILY).mailStalled = true
        assertEquals(AskOperatorResult.MAIL_UNAVAILABLE, await { app.entry.requestOperatorHelp(ask, ADA) })
        app.scriptServer(FAMILY).mailStalled = false
        assertEquals(AskOperatorResult.DONE, await { app.entry.requestOperatorHelp(ask, ADA) })

        var help = app.on<EntryScreen.OperatorHelp>()
        assertEquals(OperatorHelpStage.CODE_NEEDED, help.stage)
        assertEquals(6, help.requestCode.size)
        assertTrue(help.requestCode.all { it.length == 4 })
        assertEquals("Read this to the operator when they contact you.", CopyKey.REQUEST_CODE_READ_OUT.english)
        assertEquals(CodeResult.WRONG_CODE, await { app.entry.verifyOperatorHelp(help, "000000") })
        assertEquals(CodeResult.DONE, await { app.entry.verifyOperatorHelp(help, script.emailCode) })

        help = app.on()
        assertEquals(OperatorHelpStage.HOLDING, help.stage)
        assertEquals(script.nowMs + 7 * DAY, help.holdEndsAtMs)
        // The server refuses the operator's answer before the hold has passed.
        assertFalse(script.operatorAnswers(forged = false))
        // The request survives leaving the journey: the first screen offers it again.
        app.entry.startOver()
        val first = app.on<EntryScreen.FirstRun>()
        assertTrue(first.operatorHelpWaiting)
        assertEquals(ServerResult.DONE, await { app.entry.resumeOperatorHelp(first) })
        assertEquals(OperatorHelpStage.HOLDING, app.on<EntryScreen.OperatorHelp>().stage)

        script.advance(7 * DAY)
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })
        assertEquals(OperatorHelpStage.AWAITING_OPERATOR, app.on<EntryScreen.OperatorHelp>().stage)
        assertTrue(script.operatorAnswers(forged = false))
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })

        // §9.3 step 4: before any new password, the delivered account's ID, for the person to check.
        val check = app.on<EntryScreen.CheckAccount>()
        assertEquals(account.accountId, check.accountId)
        assertEquals(32, check.accountId.length)
        assertEquals(ADA, check.email)
        assertEquals("Family", check.instance.name)
        assertEquals("Check this against the account ID in an earlier andvari email to you. If it is different, stop", CopyKey.RECOVERY_CHECK_ACCOUNT_ID.english)
        assertEquals(PW, account.password, "nothing was changed by looking")
        app.entry.acceptRecoveredAccount(check)

        val replace = app.on<EntryScreen.ReplacePassword>()
        assertEquals(RecoveryRoute.OPERATOR_HELP, replace.after)
        assertEquals(ReplacePasswordResult.DONE, await { app.entry.chooseReplacementPassword(replace, "a brand new master password") })
        assertEquals(KitReason.AFTER_RECOVERY, app.kitOnShow().reason)
        assertNull(account.twoStepCode)
        app.saveKit()
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertTrue(account.helpRequests.isEmpty())
    }

    /**
     * The fake in step with the engine for what assisted recovery publishes now: an unsigned change
     * of the recovery key stops the request with the warning (kept); a signed one is said up to the account check; a
     * request the server no longer knows is said and kept; an answer the server replaced keeps the request; a recovery
     * left before its answer is said on the first screen until dismissed.
     */
    @Test
    fun theFakesSwitchesForAssistedRecoveryMatchTheEngine() {
        val app = FakeScenes.at(FakeScene.OPERATOR_HELP_HOLDING)
        val script = app.script
        script.advance(7 * DAY)
        assertTrue(script.operatorAnswers(forged = false))
        // Unsigned: the warning, the request kept, nothing opened.
        assertTrue(script.recoveryKeyChangesWhileRequestOpen(byOldKey = false))
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })
        val warned = app.on<EntryScreen.OperatorHelp>()
        assertFalse(assertNotNull(warned.keyChange).byOldKey)
        assertEquals(CopyKey.ASSIST_RECOVERY_KEY_CHANGED_BODY, warned.keyChange?.warningBody)
        // Signed later: the request goes on, and the check says so.
        assertTrue(script.recoveryKeyChangeSignedLater())
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(warned) })
        val check = app.on<EntryScreen.CheckAccount>()
        assertTrue(assertNotNull(check.keyChange).byOldKey)
        assertEquals(CopyKey.ASSIST_RECOVERY_KEY_ROTATED, check.keyChange?.line)
        app.entry.acceptRecoveredAccount(check)
        // The answer on the server was replaced: the request is kept, and the operator uploads again.
        assertTrue(script.operatorAnswerReplaced())
        val replaced = await { app.entry.chooseReplacementPassword(app.on(), "a brand new master password") }
        assertEquals(ReplacePasswordResult.ANSWER_REPLACED, replaced)
        assertEquals(CopyKey.ASSIST_ANSWER_REPLACED, app.on<EntryScreen.OperatorHelp>().answerReplaced)
        // Unknown to the server: said and kept, at the look and at the commit.
        assertTrue(script.serverForgetsRequest())
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })
        assertEquals(CopyKey.ASSIST_REQUEST_UNKNOWN, app.on<EntryScreen.OperatorHelp>().requestUnknown)
        assertTrue(script.serverForgetsRequest(known = true))
        assertTrue(script.operatorAnswers(forged = false))
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })
        app.entry.acceptRecoveredAccount(app.on())
        assertTrue(script.serverForgetsRequest())
        assertEquals(ReplacePasswordResult.REQUEST_UNKNOWN, await { app.entry.chooseReplacementPassword(app.on(), "a brand new master password") })
        assertEquals(CopyKey.ASSIST_REQUEST_UNKNOWN, app.on<EntryScreen.OperatorHelp>().requestUnknown)
        // A recovery left before its answer: said on the first screen until dismissed.
        app.entry.startOver()
        assertTrue(script.leftRecoveryAnswered(LateRecoveryResult.UNKNOWN))
        val first = app.on<EntryScreen.FirstRun>()
        assertEquals(CopyKey.LATE_RECOVERY_UNKNOWN, first.lateRecovery?.line?.key)
        app.entry.dismissNotice(first)
        assertNull(app.on<EntryScreen.FirstRun>().lateRecovery)
    }

    @Test
    fun anAnswerThatDeliversAnotherAccountIsCaughtByTheAccountIdAndStoppedThere() {
        // A member working with the server pointed their own request at this device's request key: the answer is
        // genuine in every check the app can make, and it would hand this person that member's account.
        val app = FakeScenes.at(FakeScene.OPERATOR_HELP_HOLDING)
        val server = app.scriptServer(FAMILY)
        val mine = assertNotNull(server.accounts[ADA])
        val theirs = server.addAccount("mallory@family.example", "their own password, which they keep")
        theirs.whoCanRecover = WhoCanRecover.ME_OR_OPERATOR
        app.script.advance(7 * DAY)
        assertTrue(app.script.operatorAnswersWithAnotherAccount(theirs))
        assertEquals(ServerResult.DONE, await { app.entry.refreshOperatorHelp(app.on()) })

        val check = app.on<EntryScreen.CheckAccount>()
        assertEquals(theirs.accountId, check.accountId)
        assertFalse(check.accountId == mine.accountId, "the one thing that tells the person")
        assertEquals(ADA, check.email)
        // The check cannot be passed over: no intent takes this screen but the two that answer it.
        assertEquals(ReplacePasswordResult.STALE, await { app.entry.chooseReplacementPassword(FakeScenes.at(FakeScene.REPLACE_PASSWORD_AFTER_HELP).on(), "a brand new master password") })

        app.entry.rejectRecoveredAccount(check)
        val first = app.on<EntryScreen.FirstRun>()
        assertFalse(first.operatorHelpWaiting, "the request is dropped from this device")
        assertEquals(PW, mine.password)
        assertEquals("their own password, which they keep", theirs.password)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)
        app.entry.rejectRecoveredAccount(check)
        app.entry.acceptRecoveredAccount(check)
        app.on<EntryScreen.FirstRun>()

        // The answer waits on the device like the request did: leaving and coming back shows the same check.
        val later = FakeScenes.at(FakeScene.OPERATOR_HELP_CHECK_ACCOUNT)
        later.entry.startOver()
        assertEquals(ServerResult.DONE, await { later.entry.resumeOperatorHelp(later.on()) })
        later.on<EntryScreen.CheckAccount>()
        // And going back from the new-password screen returns to the check, not past it.
        later.entry.acceptRecoveredAccount(later.on())
        later.on<EntryScreen.ReplacePassword>()
        assertTrue(later.entry.back())
        later.on<EntryScreen.CheckAccount>()
    }

    @Test
    fun aRequestForHelpCanBeVetoedExpireOrFailItsChecks() {
        val vetoed = FakeScenes.at(FakeScene.OPERATOR_HELP_VETOED)
        assertEquals(OperatorHelpStage.VETOED, vetoed.on<EntryScreen.OperatorHelp>().stage)
        vetoed.entry.abandonOperatorHelp(vetoed.on())
        assertFalse(vetoed.on<EntryScreen.FirstRun>().operatorHelpWaiting)

        // The answer must be signed by the recovery key the pinned card names: a server alone cannot fake it.
        val forged = FakeScenes.at(FakeScene.OPERATOR_HELP_NOT_GENUINE)
        assertEquals(OperatorHelpStage.DID_NOT_CHECK_OUT, forged.on<EntryScreen.OperatorHelp>().stage)
        assertEquals(AppPhase.ENTRY, forged.snapshot.phase)

        // An address without operator recovery gets the same "sent", and no code ever verifies.
        val unknown = FakeScenes.at(FakeScene.ASK_OPERATOR)
        assertEquals(AskOperatorResult.DONE, await { unknown.entry.requestOperatorHelp(unknown.on(), "nobody@family.example") })
        assertEquals(CodeResult.WRONG_CODE, await { unknown.entry.verifyOperatorHelp(unknown.on(), unknown.script.emailCode) })
        assertEquals(OperatorHelpStage.CODE_NEEDED, unknown.on<EntryScreen.OperatorHelp>().stage)
        unknown.script.advance(DAY + MINUTE)
        assertEquals(ServerResult.DONE, await { unknown.entry.refreshOperatorHelp(unknown.on()) })
        assertEquals(OperatorHelpStage.EXPIRED, unknown.on<EntryScreen.OperatorHelp>().stage)

        // A verified request nobody acts on lapses thirty days after its hold.
        val stale = FakeScenes.at(FakeScene.OPERATOR_HELP_AWAITING)
        assertEquals(OperatorHelpStage.AWAITING_OPERATOR, stale.on<EntryScreen.OperatorHelp>().stage)
        stale.script.advance(31 * DAY)
        assertEquals(ServerResult.DONE, await { stale.entry.refreshOperatorHelp(stale.on()) })
        assertEquals(OperatorHelpStage.EXPIRED, stale.on<EntryScreen.OperatorHelp>().stage)
    }

    // ---- staleness and locking ----

    @Test
    fun anIntentActsOnlyOnTheScreenThatIsOnShow() {
        val app = fresh()
        val first = app.on<EntryScreen.FirstRun>()
        app.entry.openSignIn(first)
        val choice = app.on<EntryScreen.SignInChoice>()
        // The first screen is no longer on show: its intents do nothing.
        app.entry.openInviteEntry(first)
        assertSame(choice, app.snapshot.entry)
        assertEquals(ServerResult.STALE, await { app.entry.createAccountOnAndvari(first) })
        assertTrue(app.entry.back())
        assertSame(first, app.snapshot.entry)
        assertFalse(app.entry.back())

        val locked = FakeScenes.at(FakeScene.LOCKED)
        assertEquals(AppPhase.LOCKED, locked.snapshot.phase)
        assertNull(locked.snapshot.entry)
        assertNull(locked.snapshot.account)
        assertEquals("andvari", locked.snapshot.instance?.label?.name)
        assertEquals(PlainResult.STALE, await { locked.contacts.openContacts() })
        locked.script.unlock()
        assertEquals(AppPhase.UNLOCKED, locked.snapshot.phase)
        locked.script.lock()
        assertNull(locked.snapshot.account)
    }
}

/** The fake's server at [origin]. */
internal fun FakeAppApi.scriptServer(origin: String): FakeServer = assertNotNull(script.server(origin), "no server at $origin")
