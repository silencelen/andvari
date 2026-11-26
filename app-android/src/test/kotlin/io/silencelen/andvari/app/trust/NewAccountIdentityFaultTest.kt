package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * The identity fault at a new account's making ([CreateAccountResult.IDENTITY_FAULT], which the shared code hands with no
 * sentence), walked over the stand-in: said in the identity fault's own line, as at a sign-in and a kit's check, where
 * the address is known on this phone as another account (the forgetting is offered under it, as the shared code hands
 * it) and where the server's answer does not carry back the identity this phone registered. Never "the server's answer
 * did not match what this device sent", which is not so where the address is known as another account.
 */
class NewAccountIdentityFaultTest {
    private val strong = "a brand new master password"

    private fun at(): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.CREATE_ACCOUNT)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L })
        m.onSnapshot(api.snapshot)
        return api to m
    }

    /** The making, as the form's button runs it; its answer. */
    private fun TrustModel.make(api: FakeAppApi): IntentResult {
        val form = assertIs<EntryScreen.CreateAccount>(api.snapshot.entry)
        var r: IntentResult? = null
        runBlocking { run({ entry.createAccount(form, NewAccountInput("", "Ada", strong, true)) }) { r = it }.join() }
        onSnapshot(api.snapshot)
        return assertNotNull(r)
    }

    private val identityFaultLine get() = UiText.of(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN).shown()

    @Test
    fun aNewAccountRefusedBecauseTheAddressIsKnownAsAnotherAccountSaysTheIdentityFaultsLineWithTheOfferUnderIt() {
        val (api, m) = at()
        api.script.earlierAccountKnown = true
        assertEquals(CreateAccountResult.IDENTITY_FAULT, m.make(api))
        val said = assertNotNull(m.saidOn(api.snapshot), "said where the person is: ${api.snapshot.entry}")
        val offer = api.snapshot.earlierAccount
        WalkPrint.draws("the new account refused, the address known as another account", listOf(said.text) + (offer?.let { earlierAccountLines(it) } ?: emptyList()))
        assertEquals(identityFaultLine, said.text.shown(), "the identity fault's own line")
        assertFalse(WalkPrint.isBare(said.text))
        assertNotNull(offer, "the forgetting is offered under it, as the shared code hands it (a new account is never the earlier one)")
        assertNotEquals(AppPhase.UNLOCKED, api.snapshot.phase, "nothing opened")
    }

    @Test
    fun aNewAccountWhoseAnswerDidNotCarryBackItsIdentitySaysTheIdentityFaultsLineWithNoOffer() {
        val (api, m) = at()
        api.script.identityFault = true
        assertEquals(CreateAccountResult.IDENTITY_FAULT, m.make(api))
        val said = assertNotNull(m.saidOn(api.snapshot), "said where the person is: ${api.snapshot.entry}")
        WalkPrint.draws("the new account refused, the answer without its identity", listOf(said.text))
        assertEquals(identityFaultLine, said.text.shown(), "the identity fault's own line")
        assertFalse(WalkPrint.isBare(said.text))
        assertNull(api.snapshot.earlierAccount, "a fault of the server's answer offers nothing")
        assertNotEquals(AppPhase.UNLOCKED, api.snapshot.phase, "nothing opened")
    }
}
