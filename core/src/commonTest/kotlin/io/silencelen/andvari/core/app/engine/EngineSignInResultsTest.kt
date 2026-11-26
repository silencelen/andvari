package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.items.copyOut
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
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Results that say what is so (spec 01 §7; decided on 2026-11-17 for proofs the server refuses): a sign-in over a copy this
 * device keeps, whose server's keys are not this account's; a sign-in over a copy sealed under another master password; a
 * registration whose form of recovery copy the server no longer takes; and a proof the server refuses although the
 * password opened the account here. Each used to read as a general failure or as a wrong password.
 */
class EngineSignInResultsTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val second = "a whole Other master password 7"
    private val email = "alice@example.com"

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private fun app(server: FakeInstance, state: MemoryDeviceState = MemoryDeviceState(), secure: MemoryDeviceState = MemoryDeviceState()): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), state, secure, crypto,
            { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also {
        it.linkPollMs = Long.MAX_VALUE
        it.start()
    }

    /** Sign-up at h.example up to the form's answer. */
    private suspend fun createAccount(a: EngineAppApi): CreateAccountResult {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), email, true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        return a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true))
    }

    /** Sign-up through the kit: the vault is open. */
    private suspend fun signUp(a: EngineAppApi) {
        assertEquals(CreateAccountResult.DONE, createAccount(a))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /** The server serves [key] for the account, wrapped under [password] at a fresh salt, with that password's verifier. */
    private fun FakeInstance.serves(key: ByteArray, password: String) {
        val account = accounts.values.single()
        val salt = crypto.randomBytes(KdfParams.SALT_BYTES)
        val keys = assertNotNull(PasswordKeys.derive(crypto, password.toCharArray(), salt, KdfParams.DEFAULT, served = false))
        try {
            account.kdfSalt = Bytes.toB64(salt)
            account.kdfParams = KdfParams.DEFAULT
            account.wrappedUvk = Envelope.sealB64(crypto, keys.wrapKey, key, Ad.uvk(account.userId))
            account.authKey = keys.authKeyB64
        } finally {
            keys.wipe()
        }
    }

    /** The server signs this device out (its copy stays, §4.4); the person signs in again from the first screen. */
    private suspend fun signInAgain(a: EngineAppApi, server: FakeInstance): EntryScreen.SignIn {
        a.keeper.endedByServer(server.origin)
        a.signInAgain(assertNotNull(a.snapshot.locked))
        a.entry.openSignIn(a.at())
        a.entry.openPasswordSignIn(a.at())
        assertEquals(ServerResult.DONE, a.entry.chooseOwnServer(a.at(), server.origin))
        (a.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(it)) }
        return a.at()
    }

    @Test fun aSignInWhoseServerOpensAnotherKeyForTheKeptAccountHasItsOwnAnswerAndOpensNothing() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server)
        signUp(a)
        val userId = a.keeper.session!!.userId
        // A wrap the typed password opens, for this account's id, around another key.
        server.serves(crypto.randomBytes(32), strong)
        val form = signInAgain(a, server)
        val r = a.entry.submitSignIn(form, email, strong)
        assertEquals(SignInAnswer.SERVER_KEYS_NOT_KNOWN_HERE, r, "never a general failure")
        assertEquals(CopyKey.SIGN_IN_SERVER_KEYS_NOT_KNOWN_HERE, r.sentence)
        assertNotEquals(AppPhase.UNLOCKED, a.snapshot.phase, "nothing was opened")
        val kept = assertNotNull(a.keeper.session, "the kept account is still kept")
        assertEquals(userId, kept.userId)
        assertTrue(kept.endedByServer, "as its server signed it out")
    }

    @Test fun aSignInOverACopySealedUnderAnotherPasswordSaysInOneLineThatItFollowsTheServer() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server)
        signUp(a)
        // Another device changed the password: the server holds this account's own key under the new one.
        val uvk = assertNotNull(a.keeper.established).account.uvk.copyOut()
        try {
            server.serves(uvk, second)
        } finally {
            uvk.fill(0)
        }
        val form = signInAgain(a, server)
        assertEquals(SignInAnswer.DONE, a.entry.submitSignIn(form, email, second))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertEquals(CopyKey.SIGNED_IN_COPY_FOLLOWS_SERVER, assertNotNull(a.snapshot.account).signInNotice?.key)
        a.dismissSignInNotice()
        assertNull(assertNotNull(a.snapshot.account).signInNotice)

        // A sign-in with nothing changed says nothing.
        val again = signInAgain(a, server)
        assertEquals(SignInAnswer.DONE, a.entry.submitSignIn(again, email, second))
        assertNull(assertNotNull(a.snapshot.account).signInNotice)
    }

    /**
     * The sign-in's own comparison holds (the kept wrap opens to the same key) over a kept copy whose sealed identity seed
     * is damaged: the keeper takes the session on that proof and writes the copy again from it, so the sign-in opens the
     * account and nothing is refused (the rule of 17 November for a damaged copy; before it, the keeper refused such a
     * sign-in and every road was a dead end). Never "another account is kept".
     */
    @Test fun aSignInWhoseOwnComparisonHeldIsTakenOverADamagedCopyAndRepairsIt() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val a = app(server, state, secure)
        signUp(a)
        val userId = a.keeper.session!!.userId
        a.lock()
        // The kept copy's sealed seed no longer opens under the account's key.
        val seed = server.accounts.values.single().encryptedIdentitySeed
        val (store, key) = listOf(secure, state).firstNotNullOf { s -> s.keys().firstOrNull { s.get(it)?.contains(seed) == true }?.let { s to it } }
        val other = Envelope.sealB64(crypto, crypto.randomBytes(32), crypto.randomBytes(32), Ad.idkey(userId))
        store.set(key, assertNotNull(store.get(key)).replace(seed, other))
        val b = app(server, state, secure)
        val form = signInAgain(b, server)
        val refusedBefore = b.keeper.refusals
        val r = b.entry.submitSignIn(form, email, strong)
        assertEquals(refusedBefore, b.keeper.refusals, "nothing refused")
        assertEquals(SignInAnswer.DONE, r, "never \"another account is kept\"")
        assertEquals(AppPhase.UNLOCKED, b.snapshot.phase)
        assertEquals(userId, assertNotNull(b.keeper.session).userId, "the same account")
        // The copy was written again from the session: the next unlock opens it.
        b.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, b.unlock(assertNotNull(b.snapshot.locked), strong))
    }

    @Test fun aRegistrationWhoseRecoveryCopyFormTheServerNoLongerTakesHasItsOwnAnswer() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        server.override[WireRoute.REGISTER] = WireResult.Refused(400, WireError(WireErrors.ESCROW_WRONG_FORM, "this recovery copy form is no longer stored"))
        val a = app(server)
        val r = createAccount(a)
        assertEquals(CreateAccountResult.ESCROW_WRONG_FORM, r, "never a general failure")
        assertEquals(CopyKey.REGISTER_ESCROW_WRONG_FORM, r.sentence)
        assertNull(a.keeper.session, "no account was kept")
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
    }

    @Test fun aProofTheServerRefusesWhileThisDeviceDoesNotKnowItsKeysDifferIsNeverAWrongPassword() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server)
        signUp(a)
        assertEquals(PasswordChangeResult.WRONG_PASSWORD, a.settings.changeMasterPassword("not the password at all 1", second), "a wrong password is found here")
        server.override[WireRoute.PASSWORD_CHANGE] = WireResult.Refused(403, WireError(Reauthed.PROOF_REFUSED, "refused"))
        val r = a.settings.changeMasterPassword(strong, second)
        assertEquals(PasswordChangeResult.PROOF_REFUSED, r)
        assertEquals(CopyKey.SERVER_REFUSED_PROOF, r.sentence)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }
}
