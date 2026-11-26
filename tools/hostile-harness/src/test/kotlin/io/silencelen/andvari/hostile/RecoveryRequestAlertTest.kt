package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineAppApi
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Design §9.3 step 2 against the REAL server: someone asks the operator to
 * reset Alice's account from a fresh install and proves her inbox. Her phone, signed in through the app interface,
 * shows the request at its next sync (the sync's count, then the account's list), cancels it with a statement signed by
 * the account's key, and the request can no longer be answered. Before, only the test fake raised this prompt.
 */
class RecoveryRequestAlertTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val recoveryPub = crypto.boxKeypairFromSeed(seed).publicKey

    private fun World.phone(tag: String): EngineAppApi {
        val state = MemoryDeviceState()
        val engine = AppEngine(AppPlatform.ANDROID, "Phone", dialingTransport(state, server.httpFor(proxy.dial(tag)), AppPlatform.ANDROID), state, MemoryDeviceState(),
            crypto, server::now, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.IO)
        return EngineAppApi(engine).also {
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun World.signIn(app: EngineAppApi, email: String) {
        app.entry.openSignIn(app.at())
        app.entry.openPasswordSignIn(app.at())
        assertEquals(ServerResult.DONE, app.entry.chooseOwnServer(app.at(), origin))
        (app.snapshot.entry as? EntryScreen.TrustGate)?.let { assertEquals(ServerResult.DONE, app.entry.confirmTrustGate(it)) }
        assertEquals(SignInAnswer.DONE, app.entry.submitSignIn(app.at(), email, Steps.PASSWORD), "the server's answers: ${proxy.tail()}")
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase)
    }

    private fun EngineAppApi.alert(): AccountPrompt.RecoveryRequest? =
        snapshot.account?.prompts?.filterIsInstance<AccountPrompt.RecoveryRequest>()?.singleOrNull()

    @Test fun aRequestForAnAccountIsShownOnItsSignedInPhoneWhichCancelsItAndItCanNoLongerBeAnswered() =
        world(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(recoveryPub))) {
            operator()
            val ah = member("alice")
            // Alice opts in to operator recovery, so a request in her name is a real one.
            val settings = ah.recoverySettings(ah.session(origin)!!)
            // The offer is null for any of five reasons and does not say which (no pin, a pin that offers nothing, a card
            // read that did not come back Ok, the served chain unreadable, the recovery key's fetch). It failed once under
            // load right after the registration and never alone: wait for the offer itself, a bounded number of tries,
            // and if it never comes say which of the reasons holds.
            var offer = settings.operatorOffer()
            for (i in 0 until 20) {
                if (offer != null) break
                kotlinx.coroutines.delay(250)
                offer = settings.operatorOffer()
            }
            assertNotNull(offer, "no offer: pin ${ah.trust.pinFor(origin)?.let { it.kind + "/" + it.recoveryFp + "/" + it.seq }}, refresh ${ah.trust.refresh(origin)}, " +
                "instance reads ${proxy.requests(WireRoute.INSTANCE, "alice", 0).size} (last ${proxy.last(WireRoute.INSTANCE, "alice")}), " +
                "key reads ${proxy.requests(WireRoute.RECOVERY_PUBKEY, "alice", 0).size} (last ${proxy.last(WireRoute.RECOVERY_PUBKEY, "alice")}); ${proxy.tail()}")
            assertIs<Reauthed.Done<*>>(settings.setPosture(RecoveryChoiceKind.OPERATOR, offer, understood = true, password = Steps.PASSWORD.toCharArray()))

            val phone = phone("phone")
            signIn(phone, "alice@example.org")
            assertNull(phone.alert(), "no request yet")

            // Someone asks the operator in her name from a fresh install, and proves the inbox.
            val x = device("x")
            val target = assertIs<AssistedStep.ConfirmTarget>(x.assisted.start("alice@example.org", origin))
            val requested = assertIs<AssistedStep.Requested>(x.assisted.request(target))
            val code = Steps.awaitCode(server, "alice@example.org", "recovery_request_code")
            val waiting = assertIs<AssistedStep.Waiting>(x.assisted.verifyCode(requested, code))

            // Her phone's next sync: the count names it, the list is read, the prompt is raised.
            assertNotNull(phone.content).syncQuietly()
            // The list is read in the vault's own scope, after the sync: give it its moment.
            for (i in 0 until 200) {
                if (phone.alert() != null) break
                kotlinx.coroutines.delay(50)
            }
            val alert = assertNotNull(phone.alert(), "raised at the next sync; list reads: " +
                proxy.requests(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "phone", 0).size + ", last: " +
                proxy.last(WireRoute.ACCOUNT_RECOVERY_REQUESTS, "phone")?.upstream?.text?.take(400) + "; syncs: " +
                proxy.requests(WireRoute.SYNC, "phone", 0).size + ", last count: " + proxy.last(WireRoute.SYNC, "phone")?.upstream?.json?.get("recoveryRequests"))
            val row = alert.requests.single()
            assertEquals(io.silencelen.andvari.core.app.OperatorHelpStage.HOLDING, row.stage)
            assertTrue(row.holdEndsAtMs >= row.verifiedAtMs + 7 * 86_400_000L - 1000, "the full seven days")
            assertTrue(!row.holdCutShort && !row.answered)

            // She cancels it from the prompt: the server takes the statement, the prompt goes.
            assertEquals(PlainResult.DONE, phone.recovery.cancelRecoveryRequest(row), "the server's answers: ${proxy.tail()}")
            assertEquals(1, proxy.requests(WireRoute.RECOVERY_REQUEST_VETO, "phone", 0).size)
            assertNull(phone.alert())

            // The request can no longer be answered: the requester's poll says it was cancelled.
            val after = x.assisted.poll(waiting)
            assertEquals(RecoveryRequestState.VETOED, assertIs<AssistedStep.Stopped>(after, "$after").reason)
        }
}
