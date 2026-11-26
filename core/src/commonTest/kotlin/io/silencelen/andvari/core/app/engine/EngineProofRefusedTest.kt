package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.TwoStepResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The server's refusal of a password proof on the app interface. A wrong password typed here is caught on this device
 * and sent nowhere. A refusal of the right password's proof is a wrong password only while nothing says otherwise; once
 * the session knows that the account's keys on the server are not the ones this device knows, every action that proves
 * the password says that, and that the person should sign in again here. Before, each of these answered FAILED.
 */
class EngineProofRefusedTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private fun app(server: FakeInstance): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
            { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also { it.start() }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun open(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    private val proofRoutes = listOf(WireRoute.ACCOUNT_DELETE, WireRoute.PASSWORD_CHANGE, WireRoute.REQUIRE_LINK, WireRoute.TOTP_SETUP)

    /** Every proof route of this test refuses the proof, as a server holding other keys for the account would. */
    private fun FakeInstance.refuseProofs() {
        for (r in proofRoutes) override[r] = WireResult.Refused(403, WireError("reauth_failed", "x"))
        override[WireRoute.ACCOUNT_DELETE_PREVIEW] = WireResult.Ok("""{"blockers":[],"deletedVaults":[],"leftVaults":[],"memberships":[],"totpRequired":false}""", 200)
        override[WireRoute.TOTP_STATUS] = WireResult.Ok("""{"enrolled":false,"pendingSetup":false}""", 200)
    }

    private data class Results(val deletion: DeletionResult, val change: PasswordChangeResult, val requireLink: ProofResult, val twoStep: TwoStepResult)

    private suspend fun EngineAppApi.proveEach(password: String): Results {
        assertEquals(PlainResult.DONE, settings.openDeletion())
        val deletion = settings.deleteAccount(assertNotNull(snapshot.account!!.deletion), "alice@example.com", password, null)
        settings.closeDeletion()
        val change = settings.changeMasterPassword(password, "a newer Battery 7 horse staple")
        assertEquals(PlainResult.DONE, devices.openDevices())
        val requireLink = devices.setRequireLink(true, password)
        devices.closeDevices()
        assertEquals(PlainResult.DONE, settings.openTwoStep())
        val twoStep = settings.startTwoStep(assertNotNull(snapshot.account!!.twoStep), password)
        settings.closeTwoStep()
        return Results(deletion, change, requireLink, twoStep)
    }

    @Test fun aRefusedProofIsSaidAsKeysNotKnownHereOnlyWhileTheSessionKnowsIt() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server)
        open(a)
        server.refuseProofs()

        // Nothing says the server's keys differ: a refusal of the right password's proof is the server's refusal of a proof
        // made here, never a wrong password (decided on 2026-11-17; it read as a wrong password before).
        assertFalse(a.keeper.session!!.serverKeysNotKnownHere)
        assertEquals(Results(DeletionResult.PROOF_REFUSED, PasswordChangeResult.PROOF_REFUSED, ProofResult.PROOF_REFUSED, TwoStepResult.PROOF_REFUSED), a.proveEach(strong))

        // The server serves a wrap another password made: the next opening with the password marks the session.
        val account = server.accounts.values.single()
        val salt = crypto.randomBytes(KdfParams.SALT_BYTES)
        val keys = assertNotNull(PasswordKeys.derive(crypto, "a different master password 5 Q".toCharArray(), salt, KdfParams.DEFAULT, served = false))
        account.wrappedUvk = Envelope.sealB64(crypto, keys.wrapKey, crypto.randomBytes(32), Ad.uvk(account.userId))
        account.kdfSalt = Bytes.toB64(salt)
        keys.wipe()
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertTrue(a.keeper.session!!.serverKeysNotKnownHere, "the opening found the server's keys are not this device's")

        // A wrong password typed here: caught here, and nothing is sent.
        val sent = server.calls.count { it in proofRoutes }
        val wrong = a.proveEach("not the password at all 1")
        assertEquals(Results(DeletionResult.WRONG_PASSWORD, PasswordChangeResult.WRONG_PASSWORD, ProofResult.WRONG_PASSWORD, TwoStepResult.WRONG_PASSWORD), wrong)
        assertEquals(sent, server.calls.count { it in proofRoutes }, "a wrong password typed here sends nothing")

        // The right password, whose proof the server refuses: said as what it is, with its sentence.
        val r = a.proveEach(strong)
        assertEquals(Results(DeletionResult.KEYS_NOT_KNOWN_HERE, PasswordChangeResult.KEYS_NOT_KNOWN_HERE, ProofResult.KEYS_NOT_KNOWN_HERE, TwoStepResult.KEYS_NOT_KNOWN_HERE), r)
        for (s in listOf(r.deletion.sentence, r.change.sentence, r.requireLink.sentence, r.twoStep.sentence)) assertEquals(CopyKey.KEYS_NOT_KNOWN_HERE, s)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase, "the session stays as it was")
    }

    /** The fake's switch answers the same way: a wrong password stays wrong, the right one is refused as not known here. */
    @Test fun theFakesSwitchRefusesTheRightPasswordsProofAsKeysNotKnownHere() = runBlocking<Unit> {
        val fake = io.silencelen.andvari.core.app.fake.FakeScenes.at(io.silencelen.andvari.core.app.fake.FakeScene.VAULTS)
        val pw = io.silencelen.andvari.core.app.fake.FakeScenes.PASSWORD
        assertEquals(ProofResult.DONE, fake.devices.setRequireLink(true, pw))
        fake.script.serverKeysNotKnownHere = true
        assertEquals(ProofResult.WRONG_PASSWORD, fake.devices.setRequireLink(false, "not the password at all 2"))
        assertEquals(ProofResult.KEYS_NOT_KNOWN_HERE, fake.devices.setRequireLink(false, pw))
        assertEquals(PasswordChangeResult.KEYS_NOT_KNOWN_HERE, fake.settings.changeMasterPassword(pw, "a newer Battery 7 horse staple"))
        fake.script.serverKeysNotKnownHere = false
        assertEquals(ProofResult.DONE, fake.devices.setRequireLink(false, pw))
    }
}
