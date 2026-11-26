package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.fake.FakeAccount
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeHelpRequest
import io.silencelen.andvari.core.app.fake.FakeMember
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.app.fake.FakeServer
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What only the desktop app has (§9.1, §9.2, §6.7 setup link): the first operator's setup and the operator views.
 * A phone app is handed an [AppApi], which has neither.
 */
class AppApiOperatorTest {
    private fun desktop(): FakeDesktopAppApi = FakeScenes.desktopAt(FakeScene.FIRST_RUN)

    private fun console(): FakeDesktopAppApi = FakeScenes.desktopAt(FakeScene.OPERATOR_CONSOLE)

    private fun FakeDesktopAppApi.shown(): OperatorConsole = assertNotNull(operatorApi.console, "the console is not open")

    private fun FakeDesktopAppApi.family(): FakeServer = scriptServer(FAMILY)

    private fun FakeDesktopAppApi.member(name: String): FakeAccount = assertNotNull(family().accounts["$name@family.example"])

    private fun FakeDesktopAppApi.listed(name: String) = shown().accounts.first { it.email == "$name@family.example" }

    private fun FakeDesktopAppApi.newServer(): FakeServer =
        script.addServer("https://vault.newfamily.example", "New family", ServerKind.PRIVATE_SERVER)

    /** A desktop app on the form a setup link opens. */
    private fun setupForm(): Pair<FakeDesktopAppApi, FakeServer> {
        val app = desktop()
        val server = app.newServer()
        app.entry.openOwnServer(app.on())
        assertTrue(app.on<EntryScreen.OwnServer>().takesSetupLinks)
        assertEquals(ServerResult.DONE, await { app.entry.submitServerAddress(app.on(), app.script.setupLink(server)) })
        return app to server
    }

    private fun FakeDesktopAppApi.registerOperator() {
        // Card 0 is signed inside the registration and the kit names it, so the setup comes first and the kit after it.
        assertEquals(CreateAccountResult.DONE, await { entry.createAccount(on(), NewAccountInput("operator@newfamily.example", "Operator", PW, false)) })
        on<EntryScreen.ServerSetup>()
    }

    // ---- §9.1: who has the operator views ----

    @Test
    fun onlyADesktopAppHasTheOperatorViewsAndOnlyTheOperatorOpensThem() {
        // A phone app is an AppApi and nothing more: there is no member of it that leads to an operator route.
        for (platform in listOf(AppPlatform.IOS, AppPlatform.ANDROID)) {
            val phone: AppApi = FakeScenes.onPlatform(platform, FakeScene.VAULTS)
            assertFalse(phone is DesktopAppApi, platform.name)
        }
        // A desktop app has them, and the server refuses everyone but its operator.
        val member = FakeScenes.desktopAt(FakeScene.VAULTS)
        assertFalse(member.account.operatorAccount)
        assertEquals(OperatorResult.NOT_THE_OPERATOR, await { member.operatorApi.openConsole() })
        assertNull(member.operatorApi.console)
        assertEquals(OperatorResult.NOT_THE_OPERATOR, await { member.operatorApi.renameInstance("Mine now", PW) })
        assertEquals("andvari", member.snapshot.instance?.label?.name)

        // Signed out there is no console either.
        val signedOut = desktop()
        assertEquals(OperatorResult.STALE, await { signedOut.operatorApi.openConsole() })
        assertNull(signedOut.operatorApi.console)
    }

    // ---- §6.7 setup link ----

    @Test
    fun aSetupLinkMakesTheFirstOperatorWhoseAppSignsAndPinsCard0() {
        val (app, server) = setupForm()
        val form = app.on<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.SETUP_LINK, form.via)
        assertEquals("New family", form.instance.name)
        assertEquals("https://vault.newfamily.example", form.instance.origin)
        assertNull(form.recovery, "the first operator is offered no operator recovery")
        assertEquals(WhoCanRecover.ONLY_ME, form.whoCanRecover)
        assertFalse(form.ageConfirmRequired)
        assertFalse(server.hasCard)

        // The account and card 0, signed here, uploaded and pinned; then the kit, which names card 0.
        app.script.holdCardUpload = true
        app.registerOperator()
        val signing = app.on<EntryScreen.ServerSetup>()
        assertEquals(ServerSetupStep.SIGNING, signing.step)
        assertNull(signing.details)
        assertTrue(server.operatorExists)
        assertFalse(server.hasCard)
        // The step cannot be left by going back, and it does not open the vault.
        app.entry.back()
        app.entry.finishServerSetup(signing)
        assertEquals(ServerSetupStep.SIGNING, app.on<EntryScreen.ServerSetup>().step)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase)

        app.script.finishCardUpload()
        val finished = app.on<EntryScreen.ServerSetup>()
        assertEquals(ServerSetupStep.FINISHED, finished.step)
        assertTrue(server.hasCard)
        val details = assertNotNull(finished.details)
        assertEquals(64, details.card0Hash.length, "the card 0 hash a store build would bake (§14.1)")
        assertEquals(server.operatorKeyShort, details.operatorKeyShort)

        app.entry.finishServerSetup(finished)
        assertEquals(KitReason.FIRST_KIT, app.on<EntryScreen.Kit>().kit.reason)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase, "the vault opens only once the kit is saved")
        app.saveKit()
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertTrue(app.account.operatorAccount)
        assertEquals("New family", app.snapshot.instance?.label?.name)
        assertIs<InstanceCardState.Ok>(app.snapshot.instance?.card)
        assertEquals(OperatorResult.DONE, await { app.operatorApi.openConsole() })
        assertFalse(app.shown().setupUnfinished)
        assertEquals(listOf("operator@newfamily.example"), app.shown().accounts.map { it.email })
        assertEquals("operator", app.shown().accounts.single().role)
    }

    @Test
    fun aCardThatCouldNotBeUploadedIsRetriedThere() {
        val (app, server) = setupForm()
        app.script.cardUploadFails = true
        app.registerOperator()
        val failed = app.on<EntryScreen.ServerSetup>()
        assertEquals(ServerSetupStep.NOT_UPLOADED, failed.step)
        assertFalse(server.hasCard)
        app.entry.finishServerSetup(failed)
        assertEquals(AppPhase.ENTRY, app.snapshot.phase, "an unfinished setup does not open the vault from here")

        server.reachable = false
        assertEquals(ServerResult.UNREACHABLE, await { app.entry.retryServerSetup(failed, PW) })
        server.reachable = true
        // The upload re-authenticates: the operator's master password.
        assertEquals(ServerResult.WRONG_PASSWORD, await { app.entry.retryServerSetup(app.on(), "not the password") })
        assertFalse(server.hasCard)
        assertEquals(ServerResult.DONE, await { app.entry.retryServerSetup(app.on(), PW) })
        val finished = app.on<EntryScreen.ServerSetup>()
        assertEquals(ServerSetupStep.FINISHED, finished.step)
        assertEquals(ServerResult.STALE, await { app.entry.retryServerSetup(finished, PW) })
        assertEquals(ServerResult.STALE, await { app.entry.retryServerSetup(failed, PW) }, "the screen as it was is not the one on show")
        assertTrue(server.hasCard)
    }

    @Test
    fun anOperatorWhoseServerHasNoCardIsOfferedToFinishAtTheNextUnlock() {
        // §6.7 Resume: the operator exists, card 0 was never uploaded, and this device signs in again.
        val app = FakeScenes.desktopAt(FakeScene.OPERATOR_SETUP_UNFINISHED)
        assertTrue(app.shown().setupUnfinished)
        assertEquals("", app.shown().details.card0Hash)
        assertEquals("Finish setting up this server", CopyKey.FINISH_SERVER_SETUP.english)

        assertEquals(OperatorResult.WRONG_PASSWORD, await { app.operatorApi.finishServerSetup("wrong") })
        assertFalse(app.family().hasCard)
        assertEquals(OperatorResult.DONE, await { app.operatorApi.finishServerSetup(PW) })
        assertTrue(app.family().hasCard)
        assertFalse(app.shown().setupUnfinished)
        assertEquals(64, app.shown().details.card0Hash.length)
        assertEquals(OperatorResult.SETUP_ALREADY_DONE, await { app.operatorApi.finishServerSetup(PW) })
    }

    @Test
    fun aSetupLinkIsTakenOnlyWhereItBelongsAndOnlyWhileItIsGood() {
        // A used one: the server has its operator.
        val used = desktop()
        val done = used.newServer()
        val link = used.script.setupLink(done)
        done.operatorExists = true
        used.entry.openOwnServer(used.on())
        assertEquals(ServerResult.SETUP_ALREADY_DONE, await { used.entry.submitServerAddress(used.on(), link) })
        used.on<EntryScreen.OwnServer>()

        // An expired one (24 hours), and one the server does not know.
        val late = desktop()
        val expired = late.script.setupLink(late.newServer())
        late.script.advance(25 * 60 * MINUTE)
        late.entry.openOwnServer(late.on())
        assertEquals(ServerResult.SETUP_LINK_NOT_USABLE, await { late.entry.submitServerAddress(late.on(), expired) })
        val revoked = late.script.setupLink(late.newServer())
        late.script.revoke(revoked)
        assertEquals(ServerResult.SETUP_LINK_NOT_USABLE, await { late.entry.submitServerAddress(late.on(), revoked) })

        // "Use your own server" takes an address or a setup link: no other link is acted on there.
        val other = desktop()
        other.entry.openOwnServer(other.on())
        val invite = other.script.connectInvite(other.script.publicInstance, "Bo")
        assertEquals(ServerResult.NOT_AN_ADDRESS, await { other.entry.submitServerAddress(other.on(), invite) })
        other.on<EntryScreen.OwnServer>()

        // The form is refused too when someone else finished the setup meanwhile.
        val (raced, server) = setupForm()
        server.operatorExists = true
        assertEquals(CreateAccountResult.SETUP_ALREADY_DONE, await { raced.entry.createAccount(raced.on(), NewAccountInput("operator@newfamily.example", "Operator", PW, false)) })
        assertTrue(server.accounts.isEmpty())

        // A phone takes none, and says where it belongs in both places (here, and on "Scan an invite": AppApiEntryTest).
        val phone = FakeScenes.at(FakeScene.OWN_SERVER)
        assertFalse(phone.on<EntryScreen.OwnServer>().takesSetupLinks)
        val onPhone = phone.script.setupLink(phone.script.addServer("https://vault.new.example", "New", ServerKind.PRIVATE_SERVER))
        val refused = await { phone.entry.submitServerAddress(phone.on(), onPhone) }
        assertEquals(ServerResult.SETUP_NEEDS_COMPUTER, refused)
        assertEquals(CopyKey.SETUP_LINK_NEEDS_COMPUTER, refused.sentence)
        phone.on<EntryScreen.OwnServer>()

        // On the desktop it is taken in "Paste an invite link" as well.
        val pasted = desktop()
        pasted.entry.openInviteEntry(pasted.on())
        assertEquals(InviteResult.DONE, await { pasted.entry.submitInvite(pasted.on(), pasted.script.setupLink(pasted.newServer()), PayloadSource.PASTED) })
        assertEquals(RegistrationVia.SETUP_LINK, pasted.on<EntryScreen.CreateAccount>().via)
    }

    @Test
    fun aSetupPinServesOnlyTheOperatorAccountItEnrolled() {
        // §4.4, FS-B1: this device signed card 0, so it may sign in to the operator account there, and to no other.
        fun signedOutAfterSetup(): FakeDesktopAppApi {
            val app = FakeScenes.desktopAt(FakeScene.SERVER_SETUP_FINISHED)
            app.scriptServer("https://vault.newfamily.example").addAccount("bo@newfamily.example", PW)
            app.entry.finishServerSetup(app.on())
            app.saveKit()
            assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
            // Signed out by the person (a session the server ends keeps its account here, design §4.4).
            assertEquals(PlainResult.DONE, await { app.signOut() })
            app.entry.openSignIn(app.on())
            app.entry.openPasswordSignIn(app.on())
            // No gate at the server choice: the pin can serve an account, and which one is typed on the next screen.
            assertEquals(ServerResult.DONE, await { app.entry.chooseOwnServer(app.on(), "https://vault.newfamily.example") })
            app.on<EntryScreen.SignIn>()
            return app
        }

        val own = signedOutAfterSetup()
        assertEquals(SignInAnswer.DONE, await { own.entry.submitSignIn(own.on(), "operator@newfamily.example", PW) })
        assertEquals(AppPhase.UNLOCKED, own.snapshot.phase)
        assertTrue(own.account.operatorAccount)

        // Another account there: the gate first, with nothing sent, and after it the pin is a password pin.
        val other = signedOutAfterSetup()
        assertEquals(SignInAnswer.TRUST_GATE_FIRST, await { other.entry.submitSignIn(other.on(), "bo@newfamily.example", PW) })
        val gate = other.on<EntryScreen.TrustGate>()
        assertEquals(TrustGateWording.LINK_OFFER_SIGN_IN, gate.prompt.wording)
        assertEquals(ServerResult.DONE, await { other.entry.confirmTrustGate(gate) })
        assertEquals(SignInAnswer.DONE, await { other.entry.submitSignIn(other.on(), "bo@newfamily.example", PW) })
        assertFalse(other.account.operatorAccount)
    }

    // ---- §9.2: the console ----

    @Test
    fun theConsoleShowsTheServersOwnWordUnderThePinnedName() {
        val app = console()
        val shown = app.shown()
        assertEquals("Family", shown.instance.name)
        assertEquals(FAMILY, shown.instance.origin)
        assertFalse(shown.setupUnfinished)
        assertEquals(listOf("operator@family.example", "bo@family.example", "cy@family.example"), shown.accounts.map { it.email })
        assertEquals("disabled", app.listed("cy").status)
        assertEquals("operator", app.listed("bo").recovery)
        val status = assertNotNull(shown.status)
        assertEquals("private", status.instanceKind)
        assertTrue(status.mail.stalled, "the banner of §11.4")
        assertEquals("links", status.signup.mode)
        assertNull(shown.devicesOfUserId)
        assertTrue(shown.devices.isEmpty())

        // One account's devices, on request.
        val bo = app.member("bo")
        assertEquals(OperatorResult.DONE, await { app.operatorApi.openAccountDevices(bo.userId) })
        assertEquals(bo.userId, app.shown().devicesOfUserId)
        assertEquals(listOf("Bo's iPhone"), app.shown().devices.map { it.name })
        assertEquals(OperatorResult.NO_SUCH_ACCOUNT, await { app.operatorApi.openAccountDevices("nobody") })
        app.operatorApi.closeAccountDevices()
        assertNull(app.shown().devicesOfUserId)

        // The console follows the world, and closes with the session.
        var seen = 0
        val watching = app.operatorApi.observeConsole { seen++ }
        assertEquals(1, seen, "the current console first")
        app.family().mailStalled = false
        assertEquals(OperatorResult.DONE, await { app.operatorApi.refreshConsole() })
        assertFalse(assertNotNull(app.shown().status).mail.stalled)
        assertTrue(seen > 1)
        assertEquals(app.operatorApi.console, app.operatorApi.consoles.value)
        watching.close()
        app.operatorApi.closeConsole()
        assertNull(app.operatorApi.console)
        assertEquals(OperatorResult.STALE, await { app.operatorApi.refreshConsole() })
        assertEquals(OperatorResult.DONE, await { app.operatorApi.openConsole() })
        app.script.lock()
        assertNull(app.operatorApi.console, "nothing of the console outlives the unlocked session")
    }

    /** The desktop's ask: a server whose own count and own list disagree is set on the fake, not built by reflection. */
    @Test
    fun theFakeServersCountCanDisagreeWithItsList() {
        val app = console()
        assertFalse(app.shown().countsDisagree)
        app.family().userCountOffBy = 2
        app.script.changed()
        val shown = app.shown()
        assertTrue(shown.countsDisagree)
        assertEquals(shown.accounts.size + 2L, assertNotNull(shown.status).userCount)
        app.family().userCountOffBy = 0
        assertEquals(OperatorResult.DONE, await { app.operatorApi.refreshConsole() })
        assertFalse(app.shown().countsDisagree)
    }

    @Test
    fun everyRouteThatChangesSomethingNeedsTheOperatorsPasswordAgain() {
        val app = console()
        val bo = app.member("bo")
        val device = bo.devices.single()
        val policy = assertNotNull(app.shown().policy)
        val wrong = "not the password"
        val refused = listOf(
            await { app.operatorApi.disableAccount(bo.userId, DisableWhy.ABUSE, wrong) },
            await { app.operatorApi.enableAccount(app.member("cy").userId, wrong) },
            await { app.operatorApi.deleteAccount(app.member("cy").userId, wrong) },
            await { app.operatorApi.revokeAccountDevice(device.deviceId, wrong) },
            await { app.operatorApi.setAccountQuota(bo.userId, QuotaLimits(1L, null, null, null), wrong) },
            await { app.operatorApi.savePolicy(policy.copy(signup = AdminSignupPolicy("closed", null)), wrong) },
            await { app.operatorApi.downloadEscrow(bo.userId, wrong) },
            await { app.operatorApi.fulfilRecovery("request-1", "sealed", wrong) },
            await { app.operatorApi.renameInstance("Other", wrong) },
            await { app.operatorApi.moveInstance("https://vault.elsewhere.example", wrong) },
            await { app.operatorApi.changeRecoveryKey("f00d", null, wrong) },
            await { app.operatorApi.removeRecoveryKey(wrong) },
        )
        assertEquals(List(refused.size) { OperatorResult.WRONG_PASSWORD }, refused)
        // Nothing happened, and a wrong password is never taken for an ended session (S3-K1).
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
        assertFalse(bo.disabled)
        assertTrue(app.member("cy").disabled)
        assertTrue(device.live)
        assertEquals("Family", app.shown().instance.name)
        assertEquals(FAMILY, app.shown().instance.origin)
        assertTrue(app.family().recoveryKey)
        assertTrue(app.account.operatorAccount)
        assertNull(app.operatorApi.takeEscrow())
        assertEquals("links", assertNotNull(app.shown().status).signup.mode)
    }

    @Test
    fun anAccountIsDisabledEnabledAndDeletedOnlyAfterThirtyDaysDisabled() {
        val app = console()
        val bo = app.member("bo")
        val cy = app.member("cy")

        assertEquals(OperatorResult.DONE, await { app.operatorApi.disableAccount(bo.userId, DisableWhy.REQUEST, PW) })
        assertEquals("disabled", app.listed("bo").status)
        assertEquals(0L, app.listed("bo").liveDeviceCount, "its sessions ended")
        assertEquals(OperatorResult.NOT_DISABLED_LONG_ENOUGH, await { app.operatorApi.deleteAccount(bo.userId, PW) })
        assertEquals(OperatorResult.DONE, await { app.operatorApi.enableAccount(bo.userId, PW) })
        assertEquals("active", app.listed("bo").status)

        assertEquals(OperatorResult.CANNOT_TARGET_SELF, await { app.operatorApi.disableAccount(app.listed("operator").userId, DisableWhy.OTHER, PW) })
        assertEquals(OperatorResult.CANNOT_TARGET_SELF, await { app.operatorApi.deleteAccount(app.listed("operator").userId, PW) })
        assertEquals(OperatorResult.NO_SUCH_ACCOUNT, await { app.operatorApi.disableAccount("nobody", DisableWhy.ABUSE, PW) })
        assertEquals(OperatorResult.NO_SUCH_ACCOUNT, await { app.operatorApi.enableAccount("nobody", PW) })
        assertEquals(OperatorResult.NO_SUCH_ACCOUNT, await { app.operatorApi.deleteAccount("nobody", PW) })

        // Disabled for forty days, but it owns a vault others hold: the operator cannot delete that away.
        val shared = cy.addVault("Cy's vault", RoleInVault.OWNER)
        shared.addMember("Bo", RoleInVault.READER, null)
        assertEquals(OperatorResult.BLOCKED_BY_SHARED_VAULT, await { app.operatorApi.deleteAccount(cy.userId, PW) })
        cy.vaults.clear()
        // Where it was only a member, it stays in the history: nobody is there to sign a leave (§3.11).
        val bosVault = bo.addVault("Bo's vault", RoleInVault.OWNER)
        val asMember = FakeMember(cy.userId, "Cy", RoleInVault.READER, null)
        bosVault.members += asMember
        val listed = app.shown().accounts.size
        assertEquals(OperatorResult.DONE, await { app.operatorApi.deleteAccount(cy.userId, PW) })
        assertEquals(listed - 1, app.shown().accounts.size)
        assertNull(app.family().accounts["cy@family.example"])
        assertTrue(asMember.deletedByOperator, "Bo's list shows it, with \"Remove from the list\"")

        assertEquals(OperatorResult.DONE, await { app.operatorApi.revokeAccountDevice(bo.devices.single().deviceId, PW) })
        assertFalse(bo.devices.single().live)
        assertFalse(bo.devices.single().deviceId in bo.knownDevices, "a revoked device is unknown from then on (FC-8)")
        assertEquals(OperatorResult.NO_SUCH_DEVICE, await { app.operatorApi.revokeAccountDevice("device-nowhere", PW) })
        assertEquals(OperatorResult.DONE, await { app.operatorApi.setAccountQuota(bo.userId, QuotaLimits(1_073_741_824L, null, null, null), PW) })
        assertEquals(OperatorResult.NO_SUCH_ACCOUNT, await { app.operatorApi.setAccountQuota("nobody", QuotaLimits(null, null, null, null), PW) })

        // What was done is in the audit rows, by type and by account.
        assertEquals(OperatorResult.DONE, await { app.operatorApi.loadAudit(0L, null, null) })
        val types = app.shown().audit.map { it.type }
        assertEquals(listOf("operator_disable", "operator_enable", "operator_delete", "operator_device_revoke", "operator_quota"), types)
        assertEquals(OperatorResult.DONE, await { app.operatorApi.loadAudit(0L, "operator_disable", bo.userId) })
        assertEquals(1, app.shown().audit.size)
        assertEquals(OperatorResult.DONE, await { app.operatorApi.loadAudit(app.script.nowMs + 1, null, null) })
        assertTrue(app.shown().audit.isEmpty())
    }

    @Test
    fun thePanelCanOnlyTightenSignUp() {
        val app = console()
        val policy = assertNotNull(app.shown().policy)
        // The family's server takes invitations only: opening it is done on the host, never here (R7).
        assertEquals(OperatorResult.NOT_TIGHTER, await { app.operatorApi.savePolicy(policy.copy(signup = AdminSignupPolicy("open", null)), PW) })
        assertEquals(OperatorResult.NOT_TIGHTER, await { app.operatorApi.savePolicy(policy.copy(signup = AdminSignupPolicy(null, 500L)), PW) })
        assertEquals(JoinMode.INVITATION_ONLY, app.family().mode)
        assertEquals(OperatorResult.BAD_POLICY, await { app.operatorApi.savePolicy(policy.copy(kdfParams = policy.kdfParams.copy(memBytes = 1000L)), PW) })

        assertEquals(OperatorResult.DONE, await { app.operatorApi.savePolicy(policy.copy(signup = AdminSignupPolicy("closed", 50L), autoLockSeconds = 60), PW) })
        assertEquals(JoinMode.CLOSED, app.family().mode)
        assertEquals("closed", assertNotNull(app.shown().status).signup.mode)
        assertEquals(60L, assertNotNull(app.shown().policy).autoLockSeconds)
        // A null leaves the stored value as it is.
        assertEquals(OperatorResult.DONE, await { app.operatorApi.savePolicy(policy.copy(signup = AdminSignupPolicy(null, null)), PW) })
        assertEquals(JoinMode.CLOSED, app.family().mode)
    }

    @Test
    fun aRecoveryCopyIsHandedOverOnceAndARequestIsAnsweredOnlyAfterItsHold() {
        val app = console()
        val bo = app.member("bo")
        assertNull(app.operatorApi.takeEscrow())
        assertEquals(OperatorResult.DONE, await { app.operatorApi.downloadEscrow(bo.userId, PW) })
        assertEquals(bo.userId, assertNotNull(app.operatorApi.takeEscrow()).userId)
        assertNull(app.operatorApi.takeEscrow(), "the file is handed over once")
        // An account that kept recovery private has no copy to download.
        assertEquals(OperatorResult.NO_ESCROW, await { app.operatorApi.downloadEscrow(app.member("cy").userId, PW) })
        assertEquals(OperatorResult.NO_SUCH_ACCOUNT, await { app.operatorApi.downloadEscrow("nobody", PW) })

        // Bo forgot the master password and asked: the verified request is listed, without its code.
        val request = FakeHelpRequest("request-bo", app.family(), bo.email, app.script.nowMs, codeMailed = true, platform = AppPlatform.IOS)
        request.stage = OperatorHelpStage.HOLDING
        request.verifiedAtMs = app.script.nowMs
        request.holdEndsAtMs = app.script.nowMs + 7 * DAY
        bo.helpRequests += request
        app.script.changed()
        val row = app.shown().recoveryRequests.single()
        // The fake lists its request in the wire's grammar (spec 03 §18.6), as the shared reader of an answer needs.
        assertTrue(io.silencelen.andvari.core.trust.TrustGrammar.isB64_16(row.requestId) && io.silencelen.andvari.core.trust.TrustGrammar.isB64_32(row.rPub), row.toString())
        assertEquals(bo.email, row.email)
        assertEquals(request.holdEndsAtMs, row.holdEndsAt)
        assertEquals("ios", row.platform)
        // The token recovery-cli assist prints for this request (the fake never opens the seal).
        val token = io.silencelen.andvari.core.trust.AnswerToken.format(row.requestId, row.rPub, "ab".repeat(32),
            ByteArray(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes(row.email)) { 7 })

        // In step with the engine, the text is read first: a bare answer is refused as such, before the password.
        assertEquals(OperatorResult.ANSWER_BARE, await { app.operatorApi.fulfilRecovery(row.requestId, token.substringAfterLast(':'), "not the password") })
        // During the hold the server refuses the answer; after it, it takes one; a vetoed request takes none.
        assertEquals(OperatorResult.REQUEST_NOT_READY, await { app.operatorApi.fulfilRecovery(row.requestId, token, PW) })
        request.stage = OperatorHelpStage.AWAITING_OPERATOR
        assertEquals(OperatorResult.DONE, await { app.operatorApi.fulfilRecovery(row.requestId, token, PW) })
        assertTrue(request.fulfilled)
        request.stage = OperatorHelpStage.VETOED
        assertEquals(OperatorResult.REQUEST_NOT_READY, await { app.operatorApi.fulfilRecovery(row.requestId, token, PW) })
        assertTrue(app.shown().recoveryRequests.isEmpty())
        assertEquals(OperatorResult.REQUEST_NOT_READY, await { app.operatorApi.fulfilRecovery("request-nowhere", "sealed", PW) })
    }

    // ---- §4.3: card changes ----

    @Test
    fun theOperatorRenamesAndMovesTheInstanceByNewCards() {
        val app = console()
        assertEquals(OperatorResult.DONE, await { app.operatorApi.renameInstance("The Family", PW) })
        assertEquals("The Family", app.shown().instance.name)
        assertEquals("The Family", app.snapshot.instance?.label?.name)

        val bad = await { app.operatorApi.moveInstance("vault.newhome.example", PW) }
        assertEquals(OperatorResult.NOT_AN_ADDRESS, bad)
        assertEquals("andvari needs an https address with a domain name for this server.", bad.sentence?.english)
        assertEquals(OperatorResult.DONE, await { app.operatorApi.moveInstance("https://vault.newhome.example", PW) })
        assertEquals("https://vault.newhome.example", app.shown().instance.origin)
        assertEquals("https://vault.newhome.example", app.snapshot.instance?.label?.origin)
        assertIs<InstanceCardState.Ok>(app.snapshot.instance?.card, "the device that signed the move needs no prompt to follow it")
        assertNull(app.script.server(FAMILY))
    }

    @Test
    fun aRecoveryKeyChangeWithoutTheOldKeysStatementAsksEveryAccountThatChoseOperatorRecovery() {
        val signed = console()
        assertEquals(OperatorResult.ROTATION_REFUSED, await { signed.operatorApi.changeRecoveryKey("f00d", "not a statement", PW) })
        assertEquals(OperatorResult.DONE, await { signed.operatorApi.changeRecoveryKey("f00d", "rotation:signed-by-the-old-key", PW) })
        assertFalse(signed.member("bo").recoveryKeyChangedUnsigned)
        assertFalse(signed.family().unsignedRecoveryKeyChange)

        val unsigned = console()
        assertEquals(OperatorResult.DONE, await { unsigned.operatorApi.changeRecoveryKey("f00d", null, PW) })
        assertTrue(unsigned.family().unsignedRecoveryKeyChange)
        assertTrue(unsigned.member("bo").recoveryKeyChangedUnsigned, "Bo is asked, with turning it off as the default (§4.5)")
        assertFalse(unsigned.member("cy").recoveryKeyChangedUnsigned, "Cy never chose operator recovery")

        assertEquals(OperatorResult.DONE, await { unsigned.operatorApi.removeRecoveryKey(PW) })
        assertFalse(unsigned.family().recoveryKey)
        assertEquals(OperatorResult.NO_ESCROW, await { unsigned.operatorApi.downloadEscrow(unsigned.member("bo").userId, PW) })

        // A public instance's card never names a recovery key (variant R): the server refuses the card.
        val public = desktop()
        val operator = public.script.publicInstance.addAccount("operator@andvaripass.com", PW)
        operator.isOperator = true
        public.script.signedInAs(operator)
        assertEquals(OperatorResult.DONE, await { public.operatorApi.openConsole() })
        assertEquals("public", assertNotNull(public.shown().status).instanceKind)
        assertEquals(OperatorResult.CARD_REFUSED, await { public.operatorApi.changeRecoveryKey("f00d", null, PW) })
    }

    /** The role changes hands with the command-line tool; when it has, this account is an ordinary member here. */
    @Test
    fun anAccountThatIsNoLongerTheOperatorLosesTheConsole() {
        val app = console()
        app.member("bo").isOperator = true
        app.member("operator").isOperator = false
        app.script.changed()
        assertFalse(app.account.operatorAccount)
        assertNull(app.operatorApi.console, "the console closes with the role")
        assertEquals(OperatorResult.NOT_THE_OPERATOR, await { app.operatorApi.openConsole() })
        assertEquals(OperatorResult.NOT_THE_OPERATOR, await { app.operatorApi.renameInstance("Mine again", PW) })
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase, "it is an ordinary member from here on")
    }

    @Test
    fun theOperatorRoutesFailLikeAnyOther() {
        val app = console()
        app.script.failNext(Trouble.UNREACHABLE)
        assertEquals(OperatorResult.UNREACHABLE, await { app.operatorApi.refreshConsole() })
        app.script.rateLimitNext(30)
        assertEquals(OperatorResult.RATE_LIMITED, await { app.operatorApi.renameInstance("Later", PW) })
        assertEquals(30, app.retryAfterSeconds())
        assertEquals("Family", app.shown().instance.name)
        app.script.forceNext(OperatorResult.CARD_MOVED_ON)
        assertEquals(OperatorResult.CARD_MOVED_ON, await { app.operatorApi.renameInstance("Later", PW) })
        app.family().reachable = false
        assertEquals(OperatorResult.UNREACHABLE, await { app.operatorApi.renameInstance("Later", PW) })
    }
}
