package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AccountPrompt
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.KitReason
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.RegistrationVia
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ServerSetupStep
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.link.LinkServer
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.InstanceCardPutResponse
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.LinkOffer
import io.silencelen.andvari.core.trust.LinkUrl
import io.silencelen.andvari.core.trust.Links
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.trust.SetupOfferFields
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Finishing a server's setup from the desktop (design §6.7 setup link and Resume, §9.5, §12.1):
 * the setup link typed under "Use your own server" or pasted as an invite, the first operator's registration through
 * it, the server setup screen, its retry, the kit behind it, and "Finish setting up this server" at a later unlock.
 * And what a lying server can make it do: nothing signed for another server, nothing pinned but the card 0 this
 * device signed, and nothing taken for finished that the server's answer does not name.
 */
class EngineServerSetupTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val hour = 3_600_000L
    private val email = "op@example.com"

    private class World(val server: LinkServer, val app: EngineAppApi, val state: MemoryDeviceState, val url: String) {
        val origin: String get() = server.instance.origin
    }

    /**
     * A server that serves no card yet, with one setup link whose offer names [offerOrigin] (its own address unless
     * given); a desktop app (a phone with [platform]). [cardPut] stands in front of the card upload when given.
     */
    private fun world(
        platform: AppPlatform = AppPlatform.LINUX, offerOrigin: String? = null,
        cardPut: (suspend (String, suspend () -> WireResult<Any?>) -> WireResult<Any?>)? = null,
        onInstance: suspend () -> Unit = {},
    ): World {
        val server = LinkServer(crypto, FakeInstance(crypto, withCard = false))
        val secret = ByteArray(32) { 4 }
        val keys = Links.deriveKeys(crypto, secret)
        val offer = LinkOffer.encodeSetup(SetupOfferFields(keys.linkId, offerOrigin ?: server.instance.origin, server.instance.instanceId, "Family",
            InstanceKind.PRIVATE, null, server.instance.now + hour))
        server.rows[keys.linkId] = LinkServer.Row(keys.linkId, "setup", Bytes.toB64(LinkOffer.seal(crypto, keys, offer)), server.instance.now + hour, null, null, null)
        val url = LinkUrl.compose(server.instance.origin, secret, null)!!
        val state = MemoryDeviceState()
        var self: EngineAppApi? = null
        val asApp = object : WireClient {
            override val origin: String = server.instance.origin

            @Suppress("UNCHECKED_CAST")
            override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
                val inner: suspend () -> WireResult<T> = { server.client(self?.keeper?.session?.userId).call(route, pathParams, query, bodyJson, authenticated, decode) }
                if (route == WireRoute.INSTANCE) onInstance()
                val put = cardPut
                if (route == WireRoute.INSTANCE_CARD_PUT && put != null) return put(bodyJson!!) { inner() as WireResult<Any?> } as WireResult<T>
                return inner()
            }
        }
        // A session route without a bearer is refused as the real server refuses it (the setup's card 0 upload
        // went without one, and this scripted world, which ignored bearers, never saw it).
        val transport = BearerTransport(mapOf(server.instance.origin to asApp)).also { it.sessionRoutesNeedBearer = true }
        val engine = AppEngine(platform, "Desk", transport, state, MemoryDeviceState(), crypto,
            { server.instance.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined)
        val app = if (platform == AppPlatform.LINUX) EngineDesktopAppApi(engine) else EngineAppApi(engine)
        self = app
        app.start()
        return World(server, app, state, url)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** "Use your own server", the setup link typed into its address field. */
    private suspend fun World.typeTheLink(): ServerResult {
        app.entry.openOwnServer(app.at())
        val own = app.at<EntryScreen.OwnServer>()
        assertTrue(own.takesSetupLinks || app !is EngineDesktopAppApi)
        return app.entry.submitServerAddress(own, url)
    }

    private suspend fun World.register(): EntryScreen.ServerSetup {
        val form = app.at<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.SETUP_LINK, form.via)
        assertEquals("Family", form.instance.name)
        assertEquals(origin, form.instance.origin)
        assertTrue(form.instance.selfNamed, "no card vouches for the name yet")
        assertEquals(CreateAccountResult.DONE, app.entry.createAccount(form, NewAccountInput(email, "Operator", strong, true)))
        return app.at()
    }

    private suspend fun World.confirmKit(reason: KitReason): String {
        val kit = app.at<EntryScreen.Kit>()
        assertEquals(reason, kit.kit.reason)
        val doc = assertNotNull(app.kit.kitDocument(kit.kit))
        app.kit.proceedToConfirm(kit.kit)
        val confirm = app.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, app.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        return doc.qrPayload
    }

    private fun World.setupKept(): Boolean = state.keys().any { it.startsWith("ovh.setup|") }

    @Test fun aSetupLinkTypedOnTheDesktopMakesTheOperatorSignsCardZeroAndThenShowsTheKit() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        assertEquals(ServerResult.DONE, w.typeTheLink())
        val setup = w.register()
        assertEquals(ServerSetupStep.FINISHED, setup.step)
        val card0 = w.server.instance.card0Hash
        assertEquals(card0, assertNotNull(setup.details).card0Hash, "the hash for the store builds, from this signing device")
        assertEquals(w.server.instance.operatorUserId, a.keeper.session!!.userId, "this account is the operator")
        val pin = assertNotNull(a.trust.pinFor(w.origin))
        assertEquals(PinRoot.SETUP, pin.root)
        assertEquals(card0, pin.card0Hash)
        assertTrue(!w.setupKept(), "card 0 is accepted: the kept offer has done its job")
        // The kit waits behind the setup screen; nothing gets past either.
        assertEquals(AppPhase.ENTRY, a.snapshot.phase)
        assertEquals(false, a.entry.back())
        a.entry.finishServerSetup(setup)
        val qr = w.confirmKit(KitReason.FIRST_KIT)
        assertEquals(card0, assertNotNull(RecoveryKit.parseQr(qr)).card0Hash, "the kit names the card 0 the server holds")
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        assertTrue(a.snapshot.account!!.prompts.none { it is AccountPrompt.FinishServerSetup })
    }

    @Test fun aSetupLinkPastedAsAnInviteOnTheDesktopGoesTheSameWay() = runBlocking<Unit> {
        val w = world()
        val a = w.app
        a.entry.openInviteEntry(a.at())
        assertEquals(InviteResult.DONE, a.entry.submitInvite(a.at(), w.url, PayloadSource.PASTED))
        assertEquals(ServerSetupStep.FINISHED, w.register().step)
    }

    /** A phone takes no setup link, typed or scanned: nothing is fetched, nothing kept. */
    @Test fun aPhoneSaysWhereASetupLinkBelongsAndSendsNothing() = runBlocking<Unit> {
        val w = world(platform = AppPlatform.ANDROID)
        assertEquals(ServerResult.SETUP_NEEDS_COMPUTER, w.typeTheLink())
        assertTrue(w.server.calls.isEmpty(), "nothing sent: ${w.server.calls}")
        w.app.entry.back()
        w.app.entry.openInviteEntry(w.app.at())
        assertEquals(InviteResult.SETUP_NEEDS_COMPUTER, w.app.entry.submitInvite(w.app.at(), w.url, PayloadSource.SCANNED))
        assertTrue(w.server.calls.none { it == WireRoute.REGISTER })
        assertTrue(!w.setupKept())
    }

    /** Lie: a setup link whose offer names another server than the link's. Nothing is pinned, kept or registered. */
    @Test fun aSetupLinkForAnotherServerIsRefusedWithNothingPinnedKeptOrSent() = runBlocking<Unit> {
        val w = world(offerOrigin = "https://other.example.org")
        assertEquals(ServerResult.OTHER_ADDRESS, w.typeTheLink())
        w.app.at<EntryScreen.OwnServer>()
        assertEquals(PinState.None, w.app.trust.pinState(w.origin))
        assertTrue(!w.setupKept())
        assertTrue(w.server.calls.none { it == WireRoute.REGISTER || it == WireRoute.INSTANCE_CARD_PUT })
    }

    /** "Use your own server" takes no other link: a link that is not a setup link starts nothing there. */
    @Test fun anotherLinkTypedAsAnAddressStartsNothing() = runBlocking<Unit> {
        val w = world()
        w.server.rows.values.single().let { w.server.rows[it.linkId] = LinkServer.Row(it.linkId, "enrol", it.offer, it.expiresAt, null, null, null) }
        val r = w.typeTheLink()
        assertTrue(r == ServerResult.NOT_AN_ADDRESS || r == ServerResult.SETUP_LINK_NOT_USABLE, "$r")
        w.app.at<EntryScreen.OwnServer>()
        assertTrue(w.server.calls.none { it == WireRoute.REGISTER })
    }

    /**
     * Lie: the card upload is answered "stored" with another card's hash, and nothing is stored. The setup is not taken
     * for finished: NOT_UPLOADED, nothing pinned, the kit held back. A wrong password at the retry sends nothing; the
     * retry against an honest answer finishes, and the kit then names the card 0 the server actually holds.
     */
    @Test fun aCardUploadAnsweredWithAnotherCardIsNotFinishedAndTheRetryNamesTheCardTheServerHolds() = runBlocking<Unit> {
        var lie = true
        val w = world(cardPut = { _, honest ->
            if (lie) WireResult.Ok(InstanceCardPutResponse(0, "ab".repeat(32)), 200) else honest()
        })
        val a = w.app
        assertEquals(ServerResult.DONE, w.typeTheLink())
        val setup = w.register()
        assertEquals(ServerSetupStep.NOT_UPLOADED, setup.step)
        assertNull(setup.details)
        assertEquals(PinState.None, a.trust.pinState(w.origin), "nothing pinned")
        assertTrue(w.server.instance.cards.isEmpty())
        a.entry.finishServerSetup(setup)
        assertIs<EntryScreen.ServerSetup>(a.snapshot.entry, "the kit stays behind an unfinished setup")

        val puts = w.server.calls.count { it == WireRoute.INSTANCE_CARD_PUT }
        assertEquals(ServerResult.WRONG_PASSWORD, a.entry.retryServerSetup(setup, "not the password at all 3"))
        assertEquals(puts, w.server.calls.count { it == WireRoute.INSTANCE_CARD_PUT }, "a wrong password sends no card")
        assertEquals(ServerResult.CARD_NOT_ACCEPTED, a.entry.retryServerSetup(a.at(), strong), "the lie again: not finished")
        assertEquals(PinState.None, a.trust.pinState(w.origin))

        lie = false
        assertEquals(ServerResult.DONE, a.entry.retryServerSetup(a.at(), strong))
        val done = a.at<EntryScreen.ServerSetup>()
        assertEquals(ServerSetupStep.FINISHED, done.step)
        val card0 = w.server.instance.card0Hash
        assertEquals(card0, assertNotNull(done.details).card0Hash)
        assertEquals(card0, assertNotNull(a.trust.pinFor(w.origin)).card0Hash)
        a.entry.finishServerSetup(done)
        val qr = w.confirmKit(KitReason.FIRST_KIT)
        assertEquals(card0, assertNotNull(RecoveryKit.parseQr(qr)).card0Hash, "the kit names the card 0 now accepted, not the first one signed")
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /**
     * Lie: by the retry the server serves a card 0 that names another operator. Nothing is signed or pinned; the setup
     * is not this device's to finish (SETUP_ALREADY_DONE).
     */
    @Test fun aCardThatNamesAnotherOperatorIsNeverPinnedAtTheRetry() = runBlocking<Unit> {
        var lie = true
        val w = world(cardPut = { _, honest -> if (lie) WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT) else honest() })
        val a = w.app
        assertEquals(ServerResult.DONE, w.typeTheLink())
        val setup = w.register()
        assertEquals(ServerSetupStep.NOT_UPLOADED, setup.step)
        lie = false
        w.server.instance.cards += FakeInstance(crypto).cards[0]
        val puts = w.server.calls.count { it == WireRoute.INSTANCE_CARD_PUT }
        assertEquals(ServerResult.SETUP_ALREADY_DONE, a.entry.retryServerSetup(setup, strong))
        assertEquals(puts, w.server.calls.count { it == WireRoute.INSTANCE_CARD_PUT }, "nothing signed or sent")
        assertEquals(PinState.None, a.trust.pinState(w.origin), "another operator's card is never pinned here")
    }

    /**
     * A lock on the server setup screen wipes the kit held there; the account stays kept. At the next unlock the vault
     * of the server's operator offers "Finish setting up this server" (desktop only); finishing it signs, uploads and
     * pins card 0, and the prompt goes. The next unlock then makes the kit that was never shown.
     */
    @Test fun aSetupThatALockLeftUnfinishedIsFinishedFromTheVaultAndTheNextUnlockMakesTheKit() = runBlocking<Unit> {
        var lie = true
        val w = world(cardPut = { _, honest -> if (lie) WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT) else honest() })
        val a = w.app as EngineDesktopAppApi
        assertEquals(ServerResult.DONE, w.typeTheLink())
        assertEquals(ServerSetupStep.NOT_UPLOADED, w.register().step)
        a.lock()
        assertEquals(AppPhase.LOCKED, a.snapshot.phase)
        lie = false
        assertEquals(VaultUnlockResult.DONE, a.unlock(assertNotNull(a.snapshot.locked), strong))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
        val prompt = a.snapshot.account!!.prompts.filterIsInstance<AccountPrompt.FinishServerSetup>().single()
        assertEquals(w.origin, prompt.origin)
        assertEquals(OperatorResult.WRONG_PASSWORD, a.operatorApi.finishServerSetup("not the password at all 3"))
        assertEquals(OperatorResult.DONE, a.operatorApi.finishServerSetup(strong))
        assertEquals(w.server.instance.card0Hash, assertNotNull(a.trust.pinFor(w.origin)).card0Hash)
        assertTrue(a.snapshot.account!!.prompts.none { it is AccountPrompt.FinishServerSetup })
        assertEquals(OperatorResult.SETUP_ALREADY_DONE, a.operatorApi.finishServerSetup(strong), "nothing left to finish")
        a.lock()
        assertEquals(VaultUnlockResult.DONE, a.unlock(assertNotNull(a.snapshot.locked), strong))
        w.confirmKit(KitReason.NEVER_SAVED)
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    /**
     * The key rule (spec 01, "Keys in memory and the lock", rules 3 and 5): a lock that comes while "Finish setting up
     * this server" waits on the server's instance read (before card 0 is signed) answers STALE, and no card is signed
     * or sent after it.
     */
    @Test fun aLockWhileTheFinishWaitsIsStaleAndNoCardIsSignedOrSent() = runBlocking<Unit> {
        var lie = true
        var hold: kotlinx.coroutines.CompletableDeferred<Unit>? = null
        val reached = kotlinx.coroutines.CompletableDeferred<Unit>()
        val w = world(cardPut = { _, honest -> if (lie) WireResult.NoAnswer(io.silencelen.andvari.core.client.net.NoAnswerKind.TRANSPORT) else honest() }, onInstance = {
            hold?.let {
                reached.complete(Unit)
                it.await()
            }
        })
        val a = w.app as EngineDesktopAppApi
        assertEquals(ServerResult.DONE, w.typeTheLink())
        assertEquals(ServerSetupStep.NOT_UPLOADED, w.register().step)
        a.lock()
        lie = false
        assertEquals(VaultUnlockResult.DONE, a.unlock(assertNotNull(a.snapshot.locked), strong))
        hold = kotlinx.coroutines.CompletableDeferred()
        var result: OperatorResult? = null
        val job = launch { result = a.operatorApi.finishServerSetup(strong) }
        reached.await()
        a.lock()
        val puts = w.server.calls.count { it == WireRoute.INSTANCE_CARD_PUT }
        hold!!.complete(Unit)
        job.join()
        assertEquals(OperatorResult.STALE, result)
        assertEquals(puts, w.server.calls.count { it == WireRoute.INSTANCE_CARD_PUT }, "no card sent after the lock")
        assertTrue(w.server.instance.cards.isEmpty())
        assertEquals(PinState.None, a.trust.pinState(w.origin))
    }
}
