package io.silencelen.andvari.core.app

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.EnrollLink
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.session.BiometricHost
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.session.FakeClocks
import io.silencelen.andvari.core.client.session.FakeNamespaces
import io.silencelen.andvari.core.client.session.FakeQuickKeys
import io.silencelen.andvari.core.client.session.FakeSessionPersistence
import io.silencelen.andvari.core.client.session.HttpClients
import io.silencelen.andvari.core.client.session.QuickGate
import io.silencelen.andvari.core.client.session.QuickRecover
import io.silencelen.andvari.core.client.session.SessionPersistence
import io.silencelen.andvari.core.client.session.StoredSession
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.RecoveryCommitRequest
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SessionResponse
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlinx.io.IOException
import kotlinx.serialization.json.Json
import kotlin.coroutines.ContinuationInterceptor
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The controller a native UI drives, against in-memory seams and a mock server, on one thread (the test's own
 * event loop stands in for the main thread). It composes flows that have their own tests; these pin what the
 * controller itself decides: the screen, the rules Android's view model follows, and that nothing throws.
 * The iOS tests run it again over the persistence the app uses ([newStore]).
 */
open class SessionControllerTest {
    private companion object {
        val crypto = createCryptoProvider()
        const val PASSWORD = "correct horse battery staple 42!"
        const val EMAIL = "u@example.com"
        const val HOME = "https://home.example"

        /** What a vault with no row in the cache is called in a list of saves. */
        const val PERSONAL = "a vault this device cannot name"
        const val DAY = 86_400_000L
        const val MINUTE = 60_000L
        const val DEVICE = "00000000-0000-4000-8000-000000000001"
        const val EMPTY_SYNC = """{"rev":1,"full":false,"vaults":[],"grants":[],"items":[],"removedGrants":[]}"""
        val json = Json { encodeDefaults = true; ignoreUnknownKeys = true }

        /** One enrolled account, at the minimum KDF cost: the offline password unlock derives under its cached keys. */
        val enrolled by lazy {
            val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
            Account.enroll("invite", EMAIL, "u", PASSWORD, KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "device", crypto)
        }
        val reg: RegisterRequest get() = enrolled.request

        /** The keys an earlier online unlock cached, with the personal wrap (the personal vault opens from it). */
        val cached: AccountKeys by lazy {
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk, encryptedIdentitySeed = reg.encryptedIdentitySeed,
                identityPub = reg.identityPub, escrowFingerprint = reg.escrow!!.fingerprint, recoveryConfirmed = true, personalWrap = reg.personalWrap,
            )
        }

        val item = ItemDoc(type = "login", name = "Example", login = LoginData(username = "fam", password = "hunter2", uris = listOf("https://login.example.com/x", "androidapp://com.foo.app"), totp = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"))
        const val ITEM_ID = "00000000-0000-4000-8000-0000000000c1"
        const val CARD_ID = "00000000-0000-4000-8000-0000000000c2"
        const val NOTE_ID = "00000000-0000-4000-8000-0000000000c3"

        /** The item sealed under the personal vault's key, as a cache holds it. */
        val sealed: WireItem by lazy {
            val upload = enrolled.account.encryptItem(reg.personalVault.vaultId, ITEM_ID, item)
            WireItem(ITEM_ID, reg.personalVault.vaultId, 1, 1_000, 2_000, false, false, upload.formatVersion, emptyList(), upload.blob)
        }
    }

    private val homeKey = OriginCanon.originKey(HOME)

    /** The persistence under test, pointed at [origin]. */
    protected open fun newStore(origin: String?): SessionPersistence = FakeSessionPersistence(origin)
    private val headers = headersOf(HttpHeaders.ContentType, "application/json")

    /** Everything one test drives, built on the test's event loop. */
    private inner class Rig(ui: CoroutineContext, origin: String?) {
        val clocks = FakeClocks(wall = 100 * DAY, mono = 5 * DAY, boot = "7")
        val store = newStore(origin)
        val namespaces = FakeNamespaces()
        val quickKeys = FakeQuickKeys()
        val calls = mutableListOf<String>()
        val seen = mutableListOf<AppState>()
        val shared = mutableListOf<String?>()
        val snapshots = InMemoryFillSnapshots()
        val queue = InMemorySaveQueue()
        val appliedLog = InMemoryFillSnapshots()

        /** Route answers by path suffix; a test swaps them. The account keys are offline by default (cached keys open). */
        val routes = mutableMapOf<String, suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData>(
            "/client-policy" to { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy()), HttpStatusCode.OK, headers) },
            "/account/keys" to { throw IOException("unreachable") },
            "/sync" to { throw IOException("unreachable") },
            "/auth/refresh" to { respond("""{"error":"unauthorized","message":"refused"}""", HttpStatusCode.Unauthorized, headers) },
            "/auth/logout" to { respond("{}", HttpStatusCode.OK, headers) },
            "/recovery/self/confirm" to { respond("{}", HttpStatusCode.OK, headers) },
        )

        val http = object : HttpClients {
            override fun create() = HttpClient(
                MockEngine { request ->
                    val path = request.url.encodedPath
                    calls += path
                    val route = routes.entries.firstOrNull { path.endsWith(it.key) }?.value
                        ?: prefixRoutes.entries.firstOrNull { path.startsWith(it.key) }?.value
                    route?.invoke(this, request) ?: respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, headers)
                },
            )
            override val wirePlatform = "test"
            override val deviceName = "test device"
        }

        /** Route answers by path prefix (an attachment's path names it), tried after [routes]. */
        val prefixRoutes = mutableMapOf<String, suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData>()

        val moveMemoLog = InMemoryFillSnapshots()
        val pendingLog = InMemoryFillSnapshots()
        val pendingFiles = InMemoryBlobs()
        val controller = SessionController(
            store, namespaces, http, quickKeys, clocks, setOf("127.0.0.1"), ui, { BiometricHost.None }, 0, { shared += it }, snapshots, queue, appliedLog, moveMemoLog,
            pendingLog, pendingFiles,
        )

        /** What an extension does with a captured login: seal it to the published key and queue it (under [id], here). */
        fun capture(id: String, site: String, username: String, password: String) = SaveQueue.enqueue(queue, crypto, site, username, password, clocks.wall, "safari") { id }

        /** The id of the listed automatic save for [host]. */
        fun appliedId(host: String): String = controller.state.appliedSaves.single { it.host == host }.id

        /** The AutoFill extension's view of the same shared state: its own vault object, as in another process. */
        fun autofill() = AutofillVault(store, snapshots, quickKeys, clocks, http)

        /** Let the work a landing started on the UI loop finish, until [done]. */
        suspend fun settle(done: () -> Boolean) = withTimeout(10_000) {
            while (!done()) delay(5)
        }

        init {
            controller.observe { seen += it }
        }

        /** A session saved by an earlier sign-in, its cached keys, and the item its cache holds. */
        fun seedSession() {
            store.save(StoredSession(HOME, reg.userId, EMAIL, "a1", "r1"))
            store.origin(homeKey).saveAccountKeys(reg.userId, cached)
            namespaces.caches["$homeKey/${reg.userId}"] = InMemoryVaultCache().apply { upsertItem(sealed, null) }
        }

        /**
         * [unlocked], on a device that has confirmed its personal vault (the wrap it remembers) and whose cache
         * survives the process, as the app's does: an offline save is honestly queued, and a new login has a home.
         */
        suspend fun unlockedWithAPersonalVault() {
            seedSession()
            val key = "$homeKey/${reg.userId}"
            val seeded = namespaces.caches.getValue(key)
            namespaces.caches[key] = object : io.silencelen.andvari.core.client.VaultCache by seeded {
                override val durable = true
            }
            namespaces.devices.getOrPut(key) { io.silencelen.andvari.core.client.MemoryDeviceState() }
                .set("personal.wrap", json.encodeToString(io.silencelen.andvari.core.model.PersonalWrap.serializer(), assertNotNull(reg.personalWrap)))
            routes["/sync/push"] = { throw IOException("unreachable") }
            controller.startAndLand()
            assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
            settle { queue.key != null } // the unlocked app has published the key the extensions seal to
        }

        suspend fun unlocked() {
            seedSession()
            controller.startAndLand()
            assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
            assertEquals(AppScreen.VAULT, controller.state.screen)
        }
    }

    private fun test(origin: String? = HOME, body: suspend Rig.() -> Unit) = runBlocking<Unit> {
        val rig = Rig(coroutineContext[ContinuationInterceptor]!!, origin)
        yield() // the subscriber registered in the rig receives the first state
        try {
            rig.body()
        } finally {
            rig.controller.close()
        }
    }

    // ---- choosing a server ----

    @Test
    fun theFirstLaunchAsksForAServerAndProbesNothing() = test(origin = null) {
        controller.startAndLand()
        assertEquals(AppScreen.CHOOSE_SERVER, controller.state.screen)
        assertTrue(calls.isEmpty(), "no default server, no probe")
        assertEquals(AppScreen.LOADING, seen.first().screen, "the subscriber saw the first state at once")
    }

    @Test
    fun theConfirmedServerIsSharedWithTheExtensions() = test(origin = null) {
        controller.startAndLand()
        assertEquals(listOf<String?>(null), shared, "no server yet: the extensions are told there is none")
        controller.chooseServer("https://home.example")
        controller.cancelTrustGate()
        assertEquals(listOf<String?>(null), shared, "a server only typed is never shared")
        controller.chooseServer("https://home.example")
        assertEquals(ActionResult.Ok, controller.confirmTrustGate())
        assertEquals(HOME, shared.last())
        controller.chooseServer("https://HOME.example/")
        assertEquals(HOME, shared.last(), "a re-spelling shares the same origin")
    }

    @Test
    fun aServerIsChosenThroughTheTrustGate() = test(origin = null) {
        controller.startAndLand()
        assertIs<ServerChoice.Invalid>(controller.chooseServer("https://real.example@evil.example"))
        val gate = assertIs<ServerChoice.NeedsGate>(controller.chooseServer("https://HOME.example/")).gate
        assertEquals(HOME, gate.origin)
        assertEquals(AppScreen.TRUST_GATE, controller.state.screen)
        assertEquals(gate, controller.state.trustGate)
        assertEquals(ActionResult.Ok, controller.confirmTrustGate())
        assertEquals(AppScreen.WELCOME, controller.state.screen)
        assertEquals(HOME, controller.state.server)
        assertNotNull(controller.state.policy, "the new server's policy was probed")
        assertNull(controller.state.trustGate)
    }

    @Test
    fun plainHttpToAnotherHostIsRefusedBeforeAnythingIsSent() = test(origin = null) {
        controller.startAndLand()
        val gate = assertIs<ServerChoice.NeedsGate>(controller.chooseServer("http://192.168.1.9:8080")).gate
        assertTrue(gate.cleartextBlocked)
        assertIs<ActionResult.Failed>(controller.confirmTrustGate())
        assertTrue(calls.isEmpty())
        assertNull(controller.state.server)
        controller.cancelTrustGate()
        assertEquals(AppScreen.CHOOSE_SERVER, controller.state.screen)
    }

    @Test
    fun anUnreachableServerChangesNothing() = test(origin = null) {
        controller.startAndLand()
        routes["/client-policy"] = { throw IOException("unreachable") }
        controller.chooseServer("https://other.example")
        assertIs<ActionResult.Failed>(controller.confirmTrustGate())
        assertNull(controller.state.server, "the probe failed, so the switch never committed")
        assertFalse(controller.state.busy)
    }

    // ---- unlock, the vault and its reads ----

    @Test
    fun aStoredSessionLandsOnUnlockAndThePasswordOpensTheVault() = test {
        seedSession()
        controller.startAndLand()
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        assertEquals(EMAIL, controller.state.accountEmail)
        assertIs<ActionResult.Failed>(controller.unlock("not the password"))
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(AppScreen.VAULT, controller.state.screen)
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
        assertEquals("login.example.com", controller.state.items.single().host)
        assertTrue(controller.state.items.single().hasTotp)
        assertNotNull(controller.state.notice, "the first sync could not run: the vault says it shows cached data")
    }

    @Test
    fun theVaultsReadsGiveSecretsOnlyWhenAsked() = test {
        unlocked()
        controller.setQuery("LOGIN.example")
        assertEquals(1, controller.state.items.size, "a web address matches")
        controller.setQuery("nothing like it")
        assertTrue(controller.state.items.isEmpty())
        controller.setQuery("")
        val detail = assertNotNull(controller.itemDetail(ITEM_ID))
        assertEquals("fam", detail.username)
        assertTrue(detail.hasPassword && detail.hasTotp && detail.editable)
        assertFalse(controller.state.toString().contains("hunter2"), "no secret in the state")
        assertEquals("hunter2", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        val code = assertNotNull(controller.oneTimeCode(ITEM_ID))
        assertEquals(6, code.code.length)
        assertTrue(code.secondsRemaining in 1..30)
        assertNull(controller.itemDetail("no such item"))
    }

    @Test
    fun theIdleWindowLocksAndSaysWhy() = test {
        unlocked()
        clocks.mono += 16 * MINUTE
        controller.tick()
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        assertEquals("Locked after inactivity.", controller.state.lockReason)
        assertTrue(controller.state.items.isEmpty())
        assertNull(controller.revealSecret(ITEM_ID, SecretField.PASSWORD), "nothing is readable once locked")
    }

    @Test
    fun leavingTheAppLocks() = test {
        unlocked()
        controller.onBackground()
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        assertEquals("Locked when you left the app.", controller.state.lockReason)
    }

    @Test
    fun aRejectionHeardMidSessionEndsItOnTheSignInSurface() = test {
        unlocked()
        routes["/sync"] = { respond("""{"error":"unauthorized","message":"expired"}""", HttpStatusCode.Unauthorized, headers) }
        assertIs<ActionResult.Failed>(controller.refresh())
        yield() // the coordinator's report lands on the next turn of the UI loop
        assertEquals(AppScreen.WELCOME, controller.state.screen)
        assertEquals("Your session ended — sign in again.", controller.state.lockReason)
        assertNull(store.load(), "the session is gone")
    }

    @Test
    fun aSignedInSessionHasAFreshPolicyAfterAMissedLaunchProbe() = policyIsFreshOnceInTheVault()

    /**
     * A4: the launch probe failed, so the origin's policy was never seen and quick unlock cannot be turned on (and says
     * why). Landing in the vault probes again, and the switch becomes available.
     */
    protected fun policyIsFreshOnceInTheVault() = test {
        seedSession()
        routes["/client-policy"] = { throw IOException("unreachable") }
        controller.startAndLand()
        assertEquals(0L, store.origin(homeKey).policyFetchedAt)
        assertFalse(controller.state.quickUnlock.available)
        assertEquals(QuickGate.POLICY, controller.state.quickUnlock.refusal)
        assertNotNull(controller.state.quickUnlock.reason)
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy()), HttpStatusCode.OK, headers) }
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.quickUnlock.available }
        assertEquals(clocks.wall, store.origin(homeKey).policyFetchedAt)
        assertEquals(QuickGate.NOT_ENROLLED, controller.state.quickUnlock.refusal)
        assertNull(controller.state.quickUnlock.reason, "turned off is not a problem to explain")
    }

    // ---- the AutoFill extension's snapshot ----

    @Test
    fun theExtensionFillsFromTheSnapshotWithTheQuickUnlockKeyAndNoNetwork() = test {
        unlocked()
        val fill = autofill()
        assertEquals(FillAvailability.OpenApp(AutofillVault.NOT_ENROLLED), fill.availability(), "quick unlock is off: the extension cannot unlock")
        assertEquals(ActionResult.Ok, controller.enableQuickUnlock(null))
        controller.onBackground() // the app is locked and suspended while the extension runs
        assertEquals(FillAvailability.Ready(EMAIL), fill.availability())
        assertTrue(fill.logins(listOf("login.example.com")).isEmpty(), "nothing is readable before the prompt")

        quickKeys.next = { QuickRecover.Fallback(null) }
        assertEquals(FillUnlock.Cancelled, fill.unlock(BiometricHost.None))
        assertNull(fill.credential(ITEM_ID))

        calls.clear()
        quickKeys.next = { QuickRecover.Ok(enrolled.account.uvkCopyForPlatformWrap()) }
        assertEquals(FillUnlock.Unlocked, fill.unlock(BiometricHost.None))
        val login = fill.logins(listOf("https://login.example.com/sign-in")).single()
        assertTrue(login.matches)
        assertEquals("fam", login.username)
        assertEquals(listOf("https://login.example.com/x"), login.uris, "web addresses only")
        assertFalse(fill.logins(listOf("evil.example.net")).single().matches, "listed, but not as a match for another site")
        assertEquals(FillCredential("fam", "hunter2"), fill.credential(ITEM_ID))
        assertEquals(6, fill.oneTimeCode(ITEM_ID)?.length)
        assertTrue(calls.isEmpty(), "the extension never contacts the server")
        fill.close()
        assertNull(fill.credential(ITEM_ID), "closed: the keys are gone")
    }

    @Test
    fun aSuggestionsRecordIsFilledOnlyForItsOwnSiteAndNeverOverPlainHttp() = test {
        unlocked()
        controller.enableQuickUnlock(null)
        val fill = autofill()
        quickKeys.next = { QuickRecover.Ok(enrolled.account.uvkCopyForPlatformWrap()) }
        assertEquals(FillUnlock.Unlocked, fill.unlock(BiometricHost.None))
        assertTrue(fill.matches(ITEM_ID, listOf("login.example.com")))
        assertTrue(fill.matches(ITEM_ID, listOf("https://login.example.com/sign-in")))
        assertFalse(fill.matches(ITEM_ID, listOf("evil.example.net")), "a record offered for another site is not filled there")
        assertFalse(fill.matches(ITEM_ID, listOf("com.foo.app")), "an Android app address is not a web domain")
        assertFalse(fill.matches(ITEM_ID, listOf("http://login.example.com/sign-in")), "saved for https: not for the cleartext page")
        assertFalse(fill.logins(listOf("http://login.example.com/")).single().matches)
        assertFalse(fill.matches("no-such-item", listOf("login.example.com")))
    }

    @Test
    fun theSnapshotHoldsOnlyWhatTheAppShows() = test {
        seedSession()
        // A row the app's engine cannot open (a vault it holds no key for): the app lists nothing for it.
        val cache = namespaces.caches.getValue("$homeKey/${reg.userId}")
        cache.upsertItem(sealed.copy(itemId = "00000000-0000-4000-8000-0000000000c2", vaultId = "00000000-0000-4000-8000-0000000000ff"), null)
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
        val snap = assertNotNull(FillSnapshot.decode(assertNotNull(snapshots.bytes)))
        assertEquals(listOf(ITEM_ID), snap.items.map { it.itemId }, "a row the app does not show is not handed to the extension")
        assertTrue(snap.vaults.all { it.vaultId == reg.personalVault.vaultId } && snap.grants.all { it.vaultId == reg.personalVault.vaultId })
    }

    @Test
    fun anUnlockThatFinishesAfterTheFillWasClosedKeepsNothing() = test {
        unlocked()
        controller.enableQuickUnlock(null)
        val fill = autofill()
        quickKeys.next = {
            fill.close() // the sheet went away while Face ID was up
            QuickRecover.Ok(enrolled.account.uvkCopyForPlatformWrap())
        }
        assertEquals(FillUnlock.Cancelled, fill.unlock(BiometricHost.None))
        assertNull(fill.credential(ITEM_ID))
        assertTrue(fill.logins(listOf("login.example.com")).isEmpty())
    }

    @Test
    fun theExtensionFillsOnlyForTheAccountThatIsSignedInNow() = test {
        unlocked()
        controller.enableQuickUnlock(null)
        val fill = autofill()
        assertEquals(FillAvailability.Ready(EMAIL), fill.availability())
        // The session changed hands (or ended) and a snapshot was left behind.
        store.save(StoredSession(HOME, "someone-else", "other@example.com", "a2", "r2"))
        assertEquals(FillAvailability.OpenApp(AutofillVault.NO_SNAPSHOT), fill.availability())
        val prompts = quickKeys.prompts
        assertEquals(FillUnlock.OpenApp(AutofillVault.NO_SNAPSHOT), fill.unlock(BiometricHost.None))
        assertEquals(prompts, quickKeys.prompts, "no prompt for an account that is not signed in")
    }

    @Test
    fun aKeyThatDoesNotOpenTheSnapshotFailsTheFillAndWipesNothing() = test {
        unlocked()
        controller.enableQuickUnlock(null)
        val fill = autofill()
        quickKeys.next = { QuickRecover.Ok(crypto.randomBytes(32)) } // a stale or foreign UVK
        assertEquals(FillUnlock.OpenApp(AutofillVault.USE_APP), fill.unlock(BiometricHost.None))
        assertFalse("$homeKey/${reg.userId}" in quickKeys.wiped, "the snapshot is a file anything in the group can replace: it never costs the enrollment")
        assertNull(fill.credential(ITEM_ID))
    }

    @Test
    fun aSnapshotThatCannotBeReplacedIsRemovedAndSignOutAlwaysRemovesIt() = test {
        unlocked()
        assertNotNull(snapshots.bytes)
        snapshots.refuse = true
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD)) // every landing rewrites the snapshot
        assertNull(snapshots.bytes, "a stale snapshot does not outlive a failed write")
        snapshots.refuse = false
        snapshots.bytes = "left behind".encodeToByteArray()
        store.clear() // the stored session is already gone when sign-out runs
        controller.signOut()
        assertNull(snapshots.bytes)
    }

    @Test
    fun aCardIsListedMaskedAndReleasedOneFieldAtATime() = test {
        seedSession()
        val cardId = "00000000-0000-4000-8000-0000000000ca"
        val card = ItemDoc(type = "card", name = "Everyday", card = io.silencelen.andvari.core.client.CardData(cardholderName = "F AM", number = "4242424242424242", expMonth = "07", expYear = "2031", securityCode = "123"))
        val upload = enrolled.account.encryptItem(reg.personalVault.vaultId, cardId, card)
        namespaces.caches.getValue("$homeKey/${reg.userId}").upsertItem(WireItem(cardId, reg.personalVault.vaultId, 1, 1_000, 2_000, false, false, upload.formatVersion, emptyList(), upload.blob), null)
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        controller.enableQuickUnlock(null)
        val text = assertNotNull(snapshots.bytes).decodeToString()
        for (secret in listOf("4242424242424242", "Everyday", "F AM")) assertFalse(text.contains(secret), "at rest: $secret")
        val fill = autofill()
        assertTrue(fill.cards().isEmpty(), "nothing before the prompt")
        quickKeys.next = { QuickRecover.Ok(enrolled.account.uvkCopyForPlatformWrap()) }
        assertEquals(FillUnlock.Unlocked, fill.unlock(BiometricHost.None))
        val listed = fill.cards().single()
        assertEquals("Everyday", listed.name)
        assertTrue(listed.subtitle.endsWith("4242") && !listed.subtitle.contains("42424242"), listed.subtitle)
        assertTrue(listed.hasNumber && listed.hasExpiry && listed.hasCvv && listed.hasName)
        assertEquals("4242424242424242", fill.cardField(cardId, "number"))
        assertEquals("07", fill.cardField(cardId, "expMonth"))
        assertEquals("123", fill.cardField(cardId, "cvv"))
        assertNull(fill.cardField(cardId, "postal"), "a field the card does not have")
        assertNull(fill.cardField(cardId, "everything"))
        assertNull(fill.cardField(ITEM_ID, "number"), "a login is not a card")
        assertNull(fill.credential(cardId), "a card is not a login")
        assertEquals(listOf(ITEM_ID), fill.logins(emptyList()).map { it.itemId }, "cards are not listed among the logins")
        assertEquals(listOf(ITEM_ID), controller.credentialIdentities().map { it.itemId }, "nor suggested to the system")
        fill.close()
        assertNull(fill.cardField(cardId, "number"))
    }

    @Test
    fun theSnapshotHoldsNoPlaintextAndNoToken() = test {
        unlocked()
        val text = assertNotNull(snapshots.bytes).decodeToString()
        for (secret in listOf("hunter2", "JBSWY3DPEHPK3PXP", "Example", "\"a1\"", "\"r1\"", "accessToken", "refreshToken", PASSWORD)) assertFalse(text.contains(secret), secret)
        val snap = assertNotNull(FillSnapshot.decode(snapshots.bytes!!))
        assertEquals(HOME, snap.origin)
        assertEquals(listOf(ITEM_ID), snap.items.map { it.itemId })
    }

    @Test
    fun theExtensionsGatesAreTheAppsGates() = test {
        unlocked()
        controller.enableQuickUnlock(null)
        val fill = autofill()
        clocks.wall += 8 * DAY // the policy was last seen over 7 days ago
        clocks.mono += 8 * DAY
        assertEquals(FillAvailability.OpenApp(AutofillVault.POLICY_UNSEEN), fill.availability())
        quickKeys.next = { QuickRecover.Ok(enrolled.account.uvkCopyForPlatformWrap()) }
        val prompts = quickKeys.prompts
        assertEquals(FillUnlock.OpenApp(AutofillVault.POLICY_UNSEEN), fill.unlock(BiometricHost.None))
        assertEquals(prompts, quickKeys.prompts, "refused before any prompt")
    }

    @Test
    fun aForbiddingPolicyLeavesNoSnapshotAndSignOutRemovesIt() = test {
        seedSession()
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(offlineCacheAllowed = false)), HttpStatusCode.OK, headers) }
        controller.startAndLand()
        controller.unlock(PASSWORD)
        assertNull(snapshots.bytes, "no offline cache, so no snapshot")
        assertTrue(controller.credentialIdentities().isEmpty())
    }

    @Test
    fun signOutRemovesTheSnapshotAndTheSuggestions() = test {
        unlocked()
        assertEquals(listOf(CredentialIdentity(ITEM_ID, "login.example.com", "fam", true)), controller.credentialIdentities())
        assertNotNull(snapshots.bytes)
        controller.signOut()
        assertNull(snapshots.bytes)
        assertTrue(controller.credentialIdentities().isEmpty())
        assertEquals(FillAvailability.OpenApp(AutofillVault.NO_SNAPSHOT), autofill().availability())
    }

    // ---- cards ----

    @Test
    fun aCardIsAddedNormalizedShownMaskedEditedAndItsSecretsReadOnRequest() = test {
        unlockedWithAPersonalVault()
        fun input(name: String = "Everyday", number: String = "4242 4242 4242 4242", month: String = "7", year: String = "31", code: String = "123") =
            CardInput(name, " F AM ", number, month, year, code, " SW1A 1AA ", "", false)
        assertIs<ActionResult.Failed>(controller.saveCard(null, input(name = " ")))
        assertIs<ActionResult.Failed>(controller.saveCard(null, input(month = "13")), "an expiry that cannot be read is refused, never guessed")
        assertIs<ActionResult.Failed>(controller.saveCard(ITEM_ID, input()), "a login is not edited as a card")
        assertEquals(ActionResult.Ok, controller.saveCard(null, input()))
        val row = controller.state.items.single { it.name == "Everyday" }
        assertEquals("card", row.type)
        val detail = assertNotNull(controller.itemDetail(row.itemId))
        val card = assertNotNull(detail.card)
        assertTrue(card.summary.endsWith("4242") && !card.summary.contains("42424242"), card.summary)
        assertEquals("F AM", card.cardholder)
        assertEquals("07/2031", card.expiry)
        assertEquals("SW1A 1AA", card.postalCode)
        assertTrue(card.hasNumber && card.hasCode && detail.editable)
        assertEquals("4242424242424242", controller.revealSecret(row.itemId, SecretField.CARD_NUMBER), "digits only")
        assertEquals("123", controller.revealSecret(row.itemId, SecretField.CARD_CODE))
        assertNull(controller.revealSecret(ITEM_ID, SecretField.CARD_NUMBER), "a login has no card number")
        assertNull(assertNotNull(controller.itemDetail(ITEM_ID)).card)
        // An edit keeps the item and changes the fields; a whole expiry typed into the month is split.
        assertEquals(ActionResult.Ok, controller.saveCard(row.itemId, input(name = "Travel", number = "5555555555554444", month = "08/32", year = "", code = "")))
        val edited = assertNotNull(controller.itemDetail(row.itemId))
        assertEquals("Travel", edited.name)
        assertEquals("08/2032", edited.card?.expiry)
        assertFalse(assertNotNull(edited.card).hasCode)
        assertEquals(2, controller.state.items.size, "edited, not duplicated")
        // A card is not a login: it is not offered to the system's AutoFill, and it is in the extensions' snapshot.
        assertTrue(controller.credentialIdentities().none { it.itemId == row.itemId })
        assertEquals(ActionResult.Ok, controller.deleteItem(row.itemId))
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
    }

    @Test
    fun aCardWithAYearAndNoMonthGoesBackToTheEditorAsItIsAndSavesAgain() = test {
        unlockedWithAPersonalVault()
        assertEquals(ActionResult.Ok, controller.saveCard(null, CardInput("Year only", "", "4242424242424242", "", "31", "", "", "", false)))
        val itemId = controller.state.items.single { it.name == "Year only" }.itemId
        val card = assertNotNull(controller.itemDetail(itemId)?.card)
        assertNull(card.expMonth)
        assertEquals("2031", card.expYear, "each half as stored, never re-split from the label")
        // What an editor loads from the detail saves again unchanged.
        assertEquals(ActionResult.Ok, controller.saveCard(itemId, CardInput("Year only", "", "4242424242424242", card.expMonth.orEmpty(), card.expYear.orEmpty(), "", "", "", false)))
        assertEquals("2031", controller.itemDetail(itemId)?.card?.expYear)
        assertNull(controller.itemDetail(ITEM_ID)?.card)
    }

    @Test
    fun aCardNumberHasAtMostNineteenDigitsAndAnUnusualOneIsOnlyWarnedAbout() = test {
        unlockedWithAPersonalVault()
        val long = "4".repeat(20)
        val tooLong = assertNotNull(controller.cardNumberWarning(long))
        assertEquals(ActionResult.Failed(tooLong), controller.saveCard(null, CardInput("Long", "", long, "", "", "", "", "", false)))
        assertTrue(controller.state.items.none { it.name == "Long" })
        // A number that fails the usual check is warned about and still saved.
        val odd = "4242 4242 4242 4241"
        val warning = assertNotNull(controller.cardNumberWarning(odd))
        assertTrue(warning != tooLong)
        assertEquals(ActionResult.Ok, controller.saveCard(null, CardInput("Odd", "", odd, "", "", "", "", "", false)))
        assertNull(controller.cardNumberWarning("4242 4242 4242 4242"))
        assertNull(controller.cardNumberWarning("4242"), "a partial number while typing is not warned about")
        assertEquals(ActionResult.Ok, controller.saveCard(null, CardInput("Last four", "", "4242", "", "", "", "", "", false)), "and a short one is saved")
    }

    @Test
    fun aStoredNumberLongerThanTheBoundDoesNotStopAnEditOfTheRestOfTheCard() = test {
        unlockedWithAPersonalVault()
        // A card another client stored with a longer number than any real card has.
        val long = "1".repeat(24)
        val upload = enrolled.account.encryptItem(reg.personalVault.vaultId, CARD_ID, ItemDoc(type = "card", name = "Imported", card = io.silencelen.andvari.core.client.CardData(number = long)))
        namespaces.caches.getValue("$homeKey/${reg.userId}").upsertItem(WireItem(CARD_ID, reg.personalVault.vaultId, 1, 1_000, 2_000, false, false, upload.formatVersion, emptyList(), upload.blob), null)
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(ActionResult.Ok, controller.saveCard(CARD_ID, CardInput("Renamed", "", long, "", "", "", "", "", false)))
        assertEquals("Renamed", controller.itemDetail(CARD_ID)?.name)
        assertEquals(long, controller.revealSecret(CARD_ID, SecretField.CARD_NUMBER))
        assertIs<ActionResult.Failed>(controller.saveCard(CARD_ID, CardInput("Renamed", "", long + "1", "", "", "", "", "", false)), "but a new number is held to it")
    }

    // ---- secure notes ----

    @Test
    fun aNoteIsAddedToThePersonalVaultEditedAndItsTextReadOnRequest() = test {
        unlockedWithAPersonalVault()
        assertEquals(ActionResult.Failed("Give the note a name."), controller.saveNote(null, NoteInput(" ", "text", false)))
        assertEquals(ActionResult.Ok, controller.saveNote(null, NoteInput(" Wi-Fi ", "network: home\npassword: correct horse", true)))
        val row = controller.state.items.single { it.name == "Wi-Fi" }
        assertEquals("note", row.type)
        assertTrue(row.favorite)
        assertNull(row.username)
        val detail = assertNotNull(controller.itemDetail(row.itemId))
        assertEquals(reg.personalVault.vaultId, detail.vaultId, "in the personal vault")
        assertTrue(detail.hasNotes && detail.editable && detail.card == null && !detail.hasPassword)
        assertEquals("network: home\npassword: correct horse", controller.revealSecret(row.itemId, SecretField.NOTES), "the text as typed")
        assertFalse(controller.state.toString().contains("correct horse"), "the text is never in the state")
        // An edit keeps the item; an emptied note is still a note.
        assertEquals(ActionResult.Ok, controller.saveNote(row.itemId, NoteInput("Wi-Fi at home", "", false)))
        val edited = assertNotNull(controller.itemDetail(row.itemId))
        assertEquals("Wi-Fi at home", edited.name)
        assertFalse(edited.hasNotes)
        assertNull(controller.revealSecret(row.itemId, SecretField.NOTES))
        assertEquals(2, controller.state.items.size, "edited, not duplicated")
        // A login is not edited as a note, and a note is not filled anywhere.
        assertIs<ActionResult.Failed>(controller.saveNote(ITEM_ID, NoteInput("Example", "x", false)))
        assertEquals("hunter2", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertTrue(controller.credentialIdentities().none { it.itemId == row.itemId })
        assertEquals(ActionResult.Ok, controller.deleteItem(row.itemId))
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
    }

    @Test
    fun aNoteEditKeepsWhatThisAppDoesNotShow() = test {
        unlockedWithAPersonalVault()
        // A note another client wrote with an attachment reference and a field this client does not know.
        val doc = ItemDoc(type = "note", name = "Lease", notes = "flat 3", attachments = listOf(io.silencelen.andvari.core.client.AttachmentRef("a1", "lease.pdf", 1024, "k")), dupeAck = "sig")
        val upload = enrolled.account.encryptItem(reg.personalVault.vaultId, NOTE_ID, doc)
        namespaces.caches.getValue("$homeKey/${reg.userId}").upsertItem(WireItem(NOTE_ID, reg.personalVault.vaultId, 1, 1_000, 2_000, false, false, upload.formatVersion, emptyList(), upload.blob), null)
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        onlineServer()
        assertEquals(ActionResult.Ok, controller.saveNote(NOTE_ID, NoteInput("Lease 2027", "flat 3, renewed", false)))
        assertEquals(ActionResult.Ok, controller.refresh())
        val saved = namespaces.caches.getValue("$homeKey/${reg.userId}").getItem(NOTE_ID)!!.doc
        assertEquals("Lease 2027", saved.name)
        assertEquals(listOf("a1"), saved.attachments.map { it.id }, "the attachment stays")
        assertEquals("sig", saved.dupeAck)
    }

    // ---- shared vaults ----

    /** Another account the server knows: its identity key pair, and its code as its own screen shows it. */
    private class Person(val userId: String, val email: String, val name: String, val pub: ByteArray, val priv: ByteArray) {
        val pubB64: String get() = Bytes.toB64(pub)
        val code: String get() = io.silencelen.andvari.core.crypto.SharedGrant.shortFingerprint(crypto, pub)
        val qr: String get() = io.silencelen.andvari.core.client.IdentityQr.compose(crypto, userId, pub)
        val served get() = io.silencelen.andvari.core.model.UserLookupResponse(userId, name, pubB64)

        fun row(role: String) = io.silencelen.andvari.core.model.VaultMemberSummary(userId, email, name, role, pubB64, 2_000)
    }

    /** A server that keeps vault rows and grants: creates, renames, deletes and restores what this account asks. */
    private inner class VaultServer(private val rig: Rig) {
        val vaults = LinkedHashMap<String, WireVault>()
        val grants = LinkedHashMap<String, io.silencelen.andvari.core.model.WireGrant>()
        val removed = mutableListOf<String>()
        val deleted = mutableListOf<io.silencelen.andvari.core.model.DeletedVaultSummary>()
        var rev = 100L

        /** Who each address looks up to (`/users/lookup`), and each account's served identity (`/users/{id}/identity`). */
        val accounts = HashMap<String, io.silencelen.andvari.core.model.UserLookupResponse>()
        val identities = HashMap<String, io.silencelen.andvari.core.model.UserLookupResponse>()

        /** Each shared vault's members as the server lists them; and what the owner asked of it. */
        val members = HashMap<String, MutableList<io.silencelen.andvari.core.model.VaultMemberSummary>>()
        val adds = mutableListOf<Pair<String, io.silencelen.andvari.core.model.VaultMemberAdd>>()
        val roles = mutableListOf<Triple<String, String, String>>()
        val removals = mutableListOf<Triple<String, String, io.silencelen.andvari.core.model.VaultMemberRemoveRequest>>()

        /** Grants an owner signed again for a member on the older kind of sharing (`PUT /vaults/{id}/members/{userId}/grant`). */
        val reissues = mutableListOf<Triple<String, String, io.silencelen.andvari.core.model.GrantReissueRequest>>()

        /** Ownership offers made (`POST /vaults/{id}/transfer`), offers taken back or declined (`DELETE`), and accepts. */
        val offers = mutableListOf<Pair<String, io.silencelen.andvari.core.model.TransferOfferRequest>>()
        val withdrawn = mutableListOf<String>()
        val accepts = mutableListOf<Pair<String, io.silencelen.andvari.core.model.TransferAcceptRequest>>()

        /** Another account, known to the server by [email]. */
        fun person(email: String, name: String, id: String = "00000000-0000-4000-8000-0000000000e${accounts.size + 1}"): Person {
            val keys = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
            val p = Person(id, email, name, keys.publicKey, keys.privateKey)
            accounts[email] = p.served
            identities[id] = p.served
            return p
        }

        init {
            vaults[reg.personalVault.vaultId] = WireVault(reg.personalVault.vaultId, "personal", 1, reg.personalVault.metaBlob, 1_000)
            with(rig) {
                routes["/users/lookup"] = { request ->
                    val email = json.decodeFromString(io.silencelen.andvari.core.model.UserLookupRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString()).email
                    val u = accounts[email]
                    if (u == null) respond("""{"error":"no_such_user","message":"no"}""", HttpStatusCode.NotFound, headers)
                    else respond(json.encodeToString(io.silencelen.andvari.core.model.UserLookupResponse.serializer(), u), HttpStatusCode.OK, headers)
                }
                routes["/identity"] = { request ->
                    val u = identities[request.url.encodedPath.removeSuffix("/identity").substringAfterLast('/')]
                    if (u == null) respond("""{"error":"no_such_user","message":"no"}""", HttpStatusCode.NotFound, headers)
                    else respond(json.encodeToString(io.silencelen.andvari.core.model.UserLookupResponse.serializer(), u), HttpStatusCode.OK, headers)
                }
                routes["/members"] = { request ->
                    val vaultId = request.url.encodedPath.removeSuffix("/members").substringAfterLast('/')
                    if (request.method == io.ktor.http.HttpMethod.Post) {
                        val add = json.decodeFromString(io.silencelen.andvari.core.model.VaultMemberAdd.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
                        adds += vaultId to add
                        val who = identities.getValue(add.userId)
                        members.getOrPut(vaultId) { mutableListOf() } += io.silencelen.andvari.core.model.VaultMemberSummary(add.userId, accounts.entries.first { it.value.userId == add.userId }.key, who.displayName, add.role, who.identityPub, 3_000)
                        respond("""{"rev":${++rev}}""", HttpStatusCode.Created, headers)
                    } else {
                        respond(json.encodeToString(kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.model.VaultMemberSummary.serializer()), members[vaultId].orEmpty()), HttpStatusCode.OK, headers)
                    }
                }
                prefixRoutes["/api/v1/vaults/"] = { request ->
                    // /api/v1/vaults/{vaultId}/members/{userId}: a role (PUT) or a removal (DELETE); /grant after it, a re-issue.
                    val parts = request.url.encodedPath.removePrefix("/api/v1/vaults/").split('/')
                    if (parts.size == 4 && parts[1] == "members" && parts[3] == "grant") {
                        val (vaultId, _, userId) = parts
                        val body = (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString()
                        reissues += Triple(vaultId, userId, json.decodeFromString(io.silencelen.andvari.core.model.GrantReissueRequest.serializer(), body))
                        val rows = members.getValue(vaultId)
                        for (i in rows.indices) if (rows[i].userId == userId) rows[i] = rows[i].copy(legacyGrant = false)
                        respond("""{"rev":${++rev}}""", HttpStatusCode.OK, headers)
                    } else if (parts.size != 3 || parts[1] != "members") {
                        respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, headers)
                    } else {
                        val (vaultId, _, userId) = parts
                        val body = (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString()
                        val rows = members.getValue(vaultId)
                        if (request.method == io.ktor.http.HttpMethod.Put) {
                            val role = json.decodeFromString(io.silencelen.andvari.core.model.VaultMemberRole.serializer(), body).role
                            roles += Triple(vaultId, userId, role)
                            for (i in rows.indices) if (rows[i].userId == userId) rows[i] = rows[i].copy(role = role)
                        } else {
                            removals += Triple(vaultId, userId, json.decodeFromString(io.silencelen.andvari.core.model.VaultMemberRemoveRequest.serializer(), body))
                            rows.removeAll { it.userId == userId }
                        }
                        respond("""{"rev":${++rev}}""", HttpStatusCode.OK, headers)
                    }
                }
                routes["/transfer"] = { request ->
                    val vaultId = request.url.encodedPath.removeSuffix("/transfer").substringAfterLast('/')
                    val v = vaults.getValue(vaultId)
                    if (request.method == io.ktor.http.HttpMethod.Post) {
                        val req = json.decodeFromString(io.silencelen.andvari.core.model.TransferOfferRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
                        offers += vaultId to req
                        val seq = (v.lastTransfer?.seq ?: 0L) + 1
                        vaults[vaultId] = v.copy(rev = ++rev, pendingTransfer = io.silencelen.andvari.core.model.PendingTransfer(req.toUserId, req.offerId, req.proof, req.expiresAt, seq))
                        respond("""{"rev":$rev,"expiresAt":${req.expiresAt}}""", HttpStatusCode.Created, headers)
                    } else {
                        withdrawn += vaultId
                        vaults[vaultId] = v.copy(rev = ++rev, pendingTransfer = null)
                        respond("""{"rev":$rev}""", HttpStatusCode.OK, headers)
                    }
                }
                routes["/transfer/accept"] = { request ->
                    val vaultId = request.url.encodedPath.removeSuffix("/transfer/accept").substringAfterLast('/')
                    val req = json.decodeFromString(io.silencelen.andvari.core.model.TransferAcceptRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
                    accepts += vaultId to req
                    val v = vaults.getValue(vaultId)
                    val pt = v.pendingTransfer!!
                    val wrapHash = Bytes.toHexLower(crypto.sha256(req.wrappedVk.encodeToByteArray()))
                    vaults[vaultId] = v.copy(rev = ++rev, pendingTransfer = null, lastTransfer = io.silencelen.andvari.core.model.TransferRecord(pt.offerId, pt.toUserId, req.proof, pt.seq, wrapHash))
                    grants[vaultId] = io.silencelen.andvari.core.model.WireGrant(vaultId, pt.toUserId, "owner", req.wrappedVk, rev)
                    members[vaultId]?.let { rows ->
                        for (i in rows.indices) {
                            if (rows[i].userId == pt.toUserId) rows[i] = rows[i].copy(role = "owner") else if (rows[i].role == "owner") rows[i] = rows[i].copy(role = "writer")
                        }
                    }
                    respond("""{"rev":$rev}""", HttpStatusCode.OK, headers)
                }
                routes["/account/state"] = { respond("""{"sealedState":null,"seq":0}""", HttpStatusCode.OK, headers) }
                routes["/sync/push"] = { respond(json.encodeToString(io.silencelen.andvari.core.model.PushResponse.serializer(), io.silencelen.andvari.core.model.PushResponse(rev, emptyList())), HttpStatusCode.OK, headers) }
                routes["/sync"] = { request ->
                    // A delta (re-sent rows are idempotent); a removal is told once.
                    val since = request.url.parameters["since"]?.toLongOrNull() ?: 0L
                    val body = io.silencelen.andvari.core.model.SyncResponse(++rev, since == 0L, vaults.values.toList(), grants.values.toList(), emptyList(), removed.toList())
                    removed.clear()
                    respond(json.encodeToString(io.silencelen.andvari.core.model.SyncResponse.serializer(), body), HttpStatusCode.OK, headers)
                }
                routes["/vaults/deleted"] = {
                    respond(json.encodeToString(kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.model.DeletedVaultSummary.serializer()), deleted.toList()), HttpStatusCode.OK, headers)
                }
                routes["/api/v1/vaults"] = { request ->
                    val req = json.decodeFromString(io.silencelen.andvari.core.model.CreateVaultRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
                    vaults[req.vaultId] = WireVault(req.vaultId, "shared", ++rev, req.metaBlob, 2_000)
                    grants[req.vaultId] = io.silencelen.andvari.core.model.WireGrant(req.vaultId, reg.userId, "owner", req.wrappedVk, rev)
                    members[req.vaultId] = mutableListOf(io.silencelen.andvari.core.model.VaultMemberSummary(reg.userId, EMAIL, "u", "owner", reg.identityPub, 2_000))
                    respond("""{"rev":$rev}""", HttpStatusCode.OK, headers)
                }
                routes["/meta"] = { request ->
                    val vaultId = request.url.encodedPath.removeSuffix("/meta").substringAfterLast('/')
                    val req = json.decodeFromString(io.silencelen.andvari.core.model.VaultMetaUpdateRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
                    vaults[vaultId] = vaults.getValue(vaultId).copy(metaBlob = req.metaBlob, rev = ++rev)
                    respond("""{"rev":$rev}""", HttpStatusCode.OK, headers)
                }
                routes["/delete"] = { request ->
                    val vaultId = request.url.encodedPath.removeSuffix("/delete").substringAfterLast('/')
                    val req = json.decodeFromString(io.silencelen.andvari.core.model.VaultDeleteRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
                    val v = vaults.remove(vaultId)!!
                    val g = grants.remove(vaultId)!!
                    removed += vaultId
                    deleted += io.silencelen.andvari.core.model.DeletedVaultSummary(vaultId, v.metaBlob, g.wrappedVk, 3_000, 3_000 + 7 * DAY, req.deleteId)
                    respond("""{"rev":${++rev},"purgeAt":${3_000 + 7 * DAY}}""", HttpStatusCode.OK, headers)
                }
                routes["/restore"] = { request ->
                    val vaultId = request.url.encodedPath.removeSuffix("/restore").substringAfterLast('/')
                    val d = deleted.single { it.vaultId == vaultId }
                    deleted.remove(d)
                    vaults[vaultId] = WireVault(vaultId, "shared", ++rev, d.metaBlob, 2_000)
                    grants[vaultId] = io.silencelen.andvari.core.model.WireGrant(vaultId, reg.userId, "owner", d.wrappedVk, rev)
                    respond("""{"rev":$rev}""", HttpStatusCode.OK, headers)
                }
            }
        }
    }

    @Test
    fun aSharedVaultIsCreatedRenamedDeletedAndRestored() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.openSharing())
        val start = assertNotNull(controller.state.sharing)
        assertEquals(listOf(true), start.vaults.map { it.personal }, "the personal vault, and nothing shared yet")
        assertTrue(start.deleted.isEmpty())

        assertEquals(ActionResult.Failed(SharingCopy.NAME_REQUIRED), controller.createSharedVault("  "))
        assertEquals(ActionResult.Ok, controller.createSharedVault(" Family "))
        val family = assertNotNull(controller.state.sharing).vaults.single { !it.personal }
        assertEquals("Family", family.name)
        assertEquals("owner", family.role)
        assertTrue(family.ownershipConfirmed, "created here: this account's own record says it owns it")
        assertTrue(controller.vaultsForNewItems().any { it.vaultId == family.vaultId && !it.personal }, "and a new item can go there")

        assertEquals(ActionResult.Ok, controller.renameSharedVault(family.vaultId, "Household"))
        assertEquals("Household", controller.state.sharing?.vaults?.single { !it.personal }?.name)
        assertEquals(ActionResult.Failed(SharingCopy.OWNER_CANNOT_LEAVE), controller.leaveSharedVault(family.vaultId))

        assertEquals(ActionResult.Failed(SharingCopy.TYPE_THE_NAME), controller.deleteSharedVault(family.vaultId, "household"))
        assertTrue(server.vaults.containsKey(family.vaultId), "nothing was sent")
        assertEquals(ActionResult.Ok, controller.deleteSharedVault(family.vaultId, "Household"))
        val after = assertNotNull(controller.state.sharing)
        assertTrue(after.vaults.none { it.vaultId == family.vaultId }, "gone from the vaults")
        assertEquals(listOf("Household"), after.deleted.map { it.name }, "and restorable")
        assertTrue(after.removed.none { it.vaultId == family.vaultId }, "listed once, under Recently deleted")
        assertTrue(controller.state.notice!!.contains("You can restore it until"))

        assertEquals(ActionResult.Ok, controller.restoreDeletedVault(family.vaultId))
        val back = assertNotNull(controller.state.sharing)
        assertEquals("Household", back.vaults.single { !it.personal }.name)
        assertTrue(back.deleted.isEmpty())
        controller.closeSharing()
        assertNull(controller.state.sharing)
    }

    @Test
    fun onlyAnOwnerRenamesOrDeletesAndNothingHappensToAVaultThatIsNotThere() = test {
        unlockedWithAPersonalVault()
        VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        val elsewhere = "00000000-0000-4000-8000-0000000000f1"
        assertEquals(ActionResult.Failed(SharingCopy.OWNER_ONLY), controller.renameSharedVault(reg.personalVault.vaultId, "Mine"), "the personal vault is not a shared one")
        assertEquals(ActionResult.Failed(SharingCopy.OWNER_ONLY), controller.deleteSharedVault(reg.personalVault.vaultId, "Personal"))
        assertEquals(ActionResult.Failed(SharingCopy.VAULT_GONE), controller.deleteSharedVault(elsewhere, "x"))
        assertEquals(ActionResult.Failed(SharingCopy.VAULT_GONE), controller.leaveSharedVault(elsewhere))
        assertEquals(ActionResult.Failed(SharingCopy.VAULT_GONE), controller.restoreDeletedVault(elsewhere))
    }

    // ---- members (root cause A §1.5, §1.6, §7.2) ----

    /** A shared vault "Family" this account created here, so its own record says it owns it. */
    private suspend fun Rig.familyVault(): Pair<VaultServer, String> {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.createSharedVault("Family"))
        return server to server.vaults.values.single { it.type == "shared" }.vaultId
    }

    /**
     * Adding someone: the address typed is looked up, the server's answer is not trusted, and nothing is sent until the
     * person compared codes with them. The add then seals the vault's key to the key verified, as the role chosen.
     */
    @Test
    fun anOwnerAddsSomeoneOnlyAfterComparingCodesWithThem() = test {
        val (server, family) = familyVault()
        val bea = server.person("bea@example.com", "Bea")
        assertEquals(ActionResult.Ok, controller.openMembers(family))
        val open = assertNotNull(controller.state.members)
        assertTrue(open.owner && open.canAdd, "created here: this account's own record says it owns it")
        assertEquals("Family", open.vaultName)
        val me = assertNotNull(open.members).single()
        assertTrue(me.you)
        assertNull(me.check)

        assertEquals(ActionResult.Failed(MembersCopy.EMAIL_REQUIRED), controller.findNewMember(" "))
        assertEquals(ActionResult.Failed(MembersCopy.NO_SUCH_USER), controller.findNewMember("nobody@example.com"))
        server.accounts[EMAIL] = io.silencelen.andvari.core.model.UserLookupResponse(reg.userId, "u", reg.identityPub)
        assertEquals(ActionResult.Failed(MembersCopy.THATS_YOU), controller.findNewMember(EMAIL))
        assertEquals(ActionResult.Ok, controller.findNewMember(" bea@example.com "))
        val adding = assertNotNull(controller.state.members?.adding)
        assertEquals(NewMemberStep.VERIFY, adding.step)
        assertEquals("Bea", adding.serverName)
        assertNull(adding.verified)
        assertEquals(ActionResult.Failed(MembersCopy.VERIFY_FIRST), controller.addNewMember("writer"))
        assertTrue(server.adds.isEmpty(), "nothing is sent before the codes are compared")

        assertEquals(ActionResult.Ok, controller.verifyNewMember())
        val ceremony = assertNotNull(controller.state.verifying)
        assertEquals("bea@example.com", ceremony.email)
        assertFalse(ceremony.invitation)
        assertEquals(enrolled.account.identityFingerprintShort(), ceremony.myCode, "this account's own code, from its own key")
        assertEquals(io.silencelen.andvari.core.client.IdentityQr.compose(crypto, reg.userId, Bytes.fromB64(reg.identityPub)), ceremony.myQr)
        assertFalse(controller.state.toString().contains(bea.code), "their code is never shown before it is typed")
        assertEquals(ActionResult.Failed(MembersCopy.CODE_LENGTH), controller.verifyWithCode(bea.code.take(16)))
        assertEquals(ActionResult.Failed(MembersCopy.CODE_MISMATCH), controller.verifyWithCode("0".repeat(32)))
        assertEquals(NewMemberStep.VERIFY, controller.state.members?.adding?.step, "a mismatch records nothing")
        assertNotNull(controller.state.verifying, "and the comparison stays open for another try")
        // As read from their screen: spaces and case do not matter.
        assertEquals(ActionResult.Ok, controller.verifyWithCode(bea.code.uppercase().chunked(4).joinToString(" ")))
        assertNull(controller.state.verifying)
        val ready = assertNotNull(controller.state.members?.adding)
        assertEquals(NewMemberStep.READY, ready.step)
        val verified = assertNotNull(ready.verified)
        assertEquals("bea@example.com", verified.email)
        assertEquals("Bea", verified.label)
        assertEquals(bea.code, verified.code)

        assertEquals(ActionResult.Failed(MembersCopy.BAD_ROLE), controller.addNewMember("owner"))
        assertEquals(ActionResult.Ok, controller.addNewMember("reader"))
        val (vaultId, add) = server.adds.single()
        assertEquals(family, vaultId)
        assertEquals(bea.userId, add.userId)
        assertEquals("reader", add.role)
        assertNotNull(add.signedGrant, "a signed grant")
        // The vault's key is sealed to the key verified: Bea's own key opens it.
        io.silencelen.andvari.core.crypto.SharedGrant.open(crypto, bea.pub, bea.priv, family, Bytes.fromB64(add.sealedVk))
        val after = assertNotNull(controller.state.members)
        assertNull(after.adding)
        val row = assertNotNull(after.members).single { it.userId == bea.userId }
        assertEquals("reader", row.role)
        assertEquals(MemberCheck.VERIFIED, row.check)
        assertTrue(assertNotNull(controller.state.notice).startsWith("Added bea@example.com to “Family” as a reader."))
        assertEquals(ActionResult.Failed(MembersCopy.LOOK_UP_AGAIN), controller.addNewMember("reader"), "added once")
        assertEquals(ActionResult.Failed(MembersCopy.ALREADY_MEMBER), controller.findNewMember("bea@example.com"))
    }

    /** An owner makes a member a reader or a writer, and removes them with the removal proof; the owner's row stays. */
    @Test
    fun anOwnerChangesARoleAndRemovesAMemberButNotTheOwner() = test {
        val (server, family) = familyVault()
        val bea = server.person("bea@example.com", "Bea")
        server.members.getValue(family) += bea.row("writer")
        assertEquals(ActionResult.Ok, controller.openMembers(family))
        assertEquals(MemberCheck.NOT_VERIFIED, controller.state.members?.members?.single { it.userId == bea.userId }?.check)
        assertEquals(ActionResult.Failed(MembersCopy.BAD_ROLE), controller.setMemberRole(bea.userId, "owner"))
        assertEquals(ActionResult.Failed(MembersCopy.OWNER_STAYS), controller.setMemberRole(reg.userId, "reader"))
        assertEquals(ActionResult.Failed(MembersCopy.MEMBER_GONE), controller.setMemberRole("00000000-0000-4000-8000-0000000000ff", "reader"))
        assertEquals(ActionResult.Ok, controller.setMemberRole(bea.userId, "writer"))
        assertTrue(server.roles.isEmpty(), "a writer already: nothing to send")
        assertEquals(ActionResult.Ok, controller.setMemberRole(bea.userId, "reader"))
        assertEquals(listOf(Triple(family, bea.userId, "reader")), server.roles)
        assertEquals("reader", controller.state.members?.members?.single { it.userId == bea.userId }?.role)
        assertEquals("Bea is now a reader.", controller.state.notice)

        assertEquals(ActionResult.Failed(MembersCopy.OWNER_STAYS), controller.removeMember(reg.userId))
        assertEquals(ActionResult.Ok, controller.removeMember(bea.userId))
        val (vaultId, userId, removal) = server.removals.single()
        assertEquals(family to bea.userId, vaultId to userId)
        assertEquals(2, removal.proofV)
        assertNotNull(removal.proof, "the proof Bea's devices check")
        assertNotNull(removal.nonce)
        assertTrue(assertNotNull(controller.state.members?.members).none { it.userId == bea.userId })
        assertTrue(assertNotNull(controller.state.notice).startsWith("Removed Bea from “Family”."))
        assertEquals(ActionResult.Failed(MembersCopy.MEMBER_GONE), controller.removeMember(bea.userId))
    }

    /**
     * A listed member is verified by their identity QR code: it must name them and match the key served for them at full
     * length (a machine's value is never compared by a prefix). When the server later serves another key, the list says so.
     */
    @Test
    fun aListedMemberIsVerifiedByTheirQrCodeAndAChangedKeyShows() = test {
        val (server, family) = familyVault()
        val bea = server.person("bea@example.com", "Bea")
        val cy = server.person("cy@example.com", "Cy")
        server.members.getValue(family) += bea.row("writer")
        assertEquals(ActionResult.Ok, controller.openMembers(family))
        assertEquals(ActionResult.Failed(MembersCopy.THATS_YOU), controller.verifyListedMember(reg.userId))
        assertEquals(ActionResult.Ok, controller.verifyListedMember(bea.userId))
        assertNull(assertNotNull(controller.state.verifying).email, "found from the list, not by an address typed")
        assertEquals(ActionResult.Failed(MembersCopy.QR_NOT_IDENTITY), controller.verifyWithQr("https://example.com"))
        assertEquals(
            ActionResult.Failed(MembersCopy.QR_NOT_IDENTITY), controller.verifyWithQr(io.silencelen.andvari.core.client.IdentityQr.PREFIX + bea.userId + ":" + bea.code),
            "a short code from a machine is not enough",
        )
        assertEquals(ActionResult.Failed(MembersCopy.QR_NOT_IDENTITY), controller.verifyWithQr(bea.qr + "\n"))
        assertEquals(ActionResult.Failed(MembersCopy.QR_OTHER_ACCOUNT), controller.verifyWithQr(cy.qr))
        val other = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        assertEquals(ActionResult.Failed(MembersCopy.QR_MISMATCH), controller.verifyWithQr(io.silencelen.andvari.core.client.IdentityQr.compose(crypto, bea.userId, other)))
        assertEquals(MemberCheck.NOT_VERIFIED, controller.state.members?.members?.single { it.userId == bea.userId }?.check)
        assertEquals(ActionResult.Ok, controller.verifyWithQr(bea.qr))
        assertNull(controller.state.verifying)
        assertEquals(MemberCheck.VERIFIED, controller.state.members?.members?.single { it.userId == bea.userId }?.check)
        assertEquals("Verified Bea on this device.", controller.state.notice)

        // The server serves another key for Bea now: the list says so.
        val rows = server.members.getValue(family)
        for (i in rows.indices) if (rows[i].userId == bea.userId) rows[i] = rows[i].copy(identityPub = Bytes.toB64(other))
        controller.closeMembers()
        assertNull(controller.state.members)
        assertEquals(ActionResult.Ok, controller.openMembers(family))
        assertEquals(MemberCheck.KEY_CHANGED, controller.state.members?.members?.single { it.userId == bea.userId }?.check)
    }

    /**
     * A11: an add names who was verified for the address typed, never the look-up's answer. When the server answers that
     * address with an account verified as someone else, nothing is added; when it serves another key, the person has to
     * compare codes again, and the code from the real person's screen does not match the key served.
     */
    @Test
    fun anAddTheVerificationsContradictIsRefused() = test {
        val (server, family) = familyVault()
        val bea = server.person("bea@example.com", "Bea")
        val cy = server.person("cy@example.com", "Cy")
        assertEquals(ActionResult.Ok, controller.openMembers(family))
        assertEquals(ActionResult.Ok, controller.findNewMember("bea@example.com"))
        assertEquals(ActionResult.Ok, controller.verifyNewMember())
        assertEquals(ActionResult.Ok, controller.verifyWithCode(bea.code))
        assertEquals(NewMemberStep.READY, controller.state.members?.adding?.step)
        controller.cancelNewMember()
        assertNull(controller.state.members?.adding)

        // The server answers Bea's address with Cy's account.
        server.accounts["bea@example.com"] = cy.served
        assertEquals(ActionResult.Ok, controller.findNewMember("bea@example.com"))
        val refused = assertNotNull(controller.state.members?.adding)
        assertEquals(NewMemberStep.REFUSED, refused.step)
        assertTrue(assertNotNull(refused.reason).contains("Don't add them"), refused.reason)
        assertIs<ActionResult.Failed>(controller.verifyNewMember(), "comparing codes would not change it")
        assertIs<ActionResult.Failed>(controller.addNewMember("writer"))

        // The server serves another key for Bea.
        val other = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        server.accounts["bea@example.com"] = bea.served.copy(identityPub = Bytes.toB64(other))
        assertEquals(ActionResult.Ok, controller.findNewMember("bea@example.com"))
        val changed = assertNotNull(controller.state.members?.adding)
        assertEquals(NewMemberStep.VERIFY_AGAIN, changed.step)
        assertTrue(assertNotNull(changed.reason).contains("different identity key"), changed.reason)
        assertIs<ActionResult.Failed>(controller.addNewMember("writer"))
        assertEquals(ActionResult.Ok, controller.verifyNewMember())
        assertEquals(ActionResult.Failed(MembersCopy.CODE_MISMATCH), controller.verifyWithCode(bea.code), "her own screen shows her real key's code")
        assertTrue(server.adds.isEmpty())
    }

    /**
     * Root cause A §1.6: a shared vault from someone this device has not verified is an invitation. It stays closed, its
     * name unshown, until the person compares codes with the sender; a wrong code opens nothing. Declining hides one.
     */
    @Test
    fun anInvitationOpensItsVaultOnlyOnceTheSenderIsVerified() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        val me = io.silencelen.andvari.core.client.Contact(reg.userId, reg.identityPub, "u", 1_000, io.silencelen.andvari.core.client.Contact.METHOD_TYPED, EMAIL)
        fun sender(email: String, name: String): io.silencelen.andvari.core.client.EnrollResult {
            val e = Account.enroll("invite", email, name, PASSWORD, KdfParams(ops = 1, memBytes = 8192), null, null, "device", crypto)
            server.identities[e.request.userId] = io.silencelen.andvari.core.model.UserLookupResponse(e.request.userId, name, e.request.identityPub)
            return e
        }
        fun share(from: io.silencelen.andvari.core.client.EnrollResult, name: String): String {
            val shared = from.account.buildCreateSharedVault(name)
            server.vaults[shared.vaultId] = WireVault(shared.vaultId, "shared", ++server.rev, shared.request.metaBlob, 2_000)
            server.grants[shared.vaultId] = io.silencelen.andvari.core.model.WireGrant(shared.vaultId, reg.userId, "writer", "", server.rev, null, from.account.buildSignedGrant(shared.vaultId, me))
            server.members[shared.vaultId] = mutableListOf(
                io.silencelen.andvari.core.model.VaultMemberSummary(from.request.userId, from.request.email, from.request.displayName, "owner", from.request.identityPub, 1_000),
                io.silencelen.andvari.core.model.VaultMemberSummary(reg.userId, EMAIL, "u", "writer", reg.identityPub, 2_000),
            )
            return shared.vaultId
        }
        val olga = sender("olga@example.com", "Olga")
        val cabin = share(olga, "Cabin")
        assertEquals(ActionResult.Ok, controller.refresh())
        val invitation = controller.state.invitations.single()
        settle { controller.state.invitations.single().from == "Olga" } // the sender's name, asked for in the background
        assertTrue(controller.vaultsForNewItems().none { it.vaultId == cabin }, "closed until the sender is verified")
        assertFalse(controller.state.toString().contains("Cabin"), "its name is not shown")

        assertEquals(ActionResult.Ok, controller.verifyInvitation(invitation.id))
        val ceremony = assertNotNull(controller.state.verifying)
        assertTrue(ceremony.invitation)
        assertEquals("Olga", ceremony.serverName)
        assertNull(ceremony.email)
        assertEquals(ActionResult.Failed(MembersCopy.INVITATION_MISMATCH), controller.verifyWithCode("0".repeat(32)))
        assertEquals(1, controller.state.invitations.size, "a wrong code opens nothing")
        assertEquals(ActionResult.Ok, controller.verifyWithCode(olga.account.identityFingerprintShort()))
        assertNull(controller.state.verifying)
        assertTrue(controller.state.invitations.isEmpty())
        assertEquals("Verified Olga. “Cabin” is open now.", controller.state.notice)
        assertTrue(controller.vaultsForNewItems().any { it.vaultId == cabin }, "a writer can put items in it now")

        // A member, not the owner: the members are listed read only, and Olga shows as verified.
        assertEquals(ActionResult.Ok, controller.openMembers(cabin))
        val members = assertNotNull(controller.state.members)
        assertFalse(members.owner || members.canAdd)
        assertEquals(MemberCheck.VERIFIED, members.members?.single { it.userId == olga.request.userId }?.check)
        assertEquals(ActionResult.Failed(SharingCopy.OWNER_ONLY), controller.findNewMember("x@example.com"))
        assertEquals(ActionResult.Failed(SharingCopy.OWNER_ONLY), controller.setMemberRole(reg.userId, "reader"))
        assertEquals(ActionResult.Failed(SharingCopy.OWNER_ONLY), controller.removeMember(olga.request.userId))
        controller.closeMembers()

        // An invitation from someone else, declined: hidden on this device, and its vault stays closed.
        val boat = share(sender("pat@example.com", "Pat"), "Boat")
        assertEquals(ActionResult.Ok, controller.refresh())
        controller.declineInvitation(controller.state.invitations.single().id)
        assertTrue(controller.state.invitations.isEmpty())
        assertTrue(controller.vaultsForNewItems().none { it.vaultId == boat })
    }

    /**
     * Handing a vault over (spec 03 §11): the owner offers it to a member, signed under the vault's key, and can take the
     * offer back until it is accepted. Only a listed, active member who is not the owner can be offered it.
     */
    @Test
    fun anOwnerOffersTheVaultToAMemberAndCanTakeTheOfferBack() = test {
        val (server, family) = familyVault()
        val bea = server.person("bea@example.com", "Bea")
        val cy = server.person("cy@example.com", "Cy")
        server.members.getValue(family) += bea.row("writer")
        server.members.getValue(family) += cy.row("reader").copy(status = "disabled")
        assertEquals(ActionResult.Ok, controller.openMembers(family))
        assertNull(controller.state.members?.offer)

        assertEquals(ActionResult.Failed(MembersCopy.OWNER_ALREADY), controller.offerOwnership(reg.userId))
        assertEquals(ActionResult.Failed(MembersCopy.MEMBER_GONE), controller.offerOwnership("00000000-0000-4000-8000-0000000000ff"))
        assertEquals(ActionResult.Failed(MembersCopy.DISABLED_CANNOT_OWN), controller.offerOwnership(cy.userId))
        // Sharing review 2026-11 (item 4): only someone verified on this device can be made the owner.
        assertEquals(MemberCheck.NOT_VERIFIED, controller.state.members?.members?.single { it.userId == bea.userId }?.check)
        assertEquals(ActionResult.Failed(MembersCopy.VERIFY_BEFORE_HANDOVER), controller.offerOwnership(bea.userId))
        assertTrue(server.offers.isEmpty())
        assertEquals(ActionResult.Ok, controller.verifyListedMember(bea.userId))
        assertEquals(ActionResult.Ok, controller.verifyWithCode(bea.code))
        val verifiedBea = controller.state.members?.members?.single { it.userId == bea.userId }
        assertEquals(MemberCheck.VERIFIED, verifiedBea?.check)
        assertEquals("Bea", verifiedBea?.verifiedName, "named as recorded when verified")

        assertEquals(ActionResult.Ok, controller.offerOwnership(bea.userId))
        val (vaultId, offer) = server.offers.single()
        assertEquals(family, vaultId)
        assertEquals(bea.userId, offer.toUserId)
        // Signed under the vault's key (a member's devices check it before they show it: the next test), for 14 days.
        assertTrue(offer.proof.isNotEmpty())
        val left = offer.expiresAt - kotlinx.datetime.Clock.System.now().toEpochMilliseconds()
        assertTrue(left in 13 * DAY..14 * DAY, "$left")
        val shown = assertNotNull(controller.state.members?.offer)
        assertEquals(OwnerOfferView(bea.userId, "Bea", offer.expiresAt, mine = true), shown, "this account's own offer")
        assertTrue(assertNotNull(controller.state.notice).startsWith("Asked Bea to take over “Family”."))
        assertEquals(ActionResult.Failed(MembersCopy.OFFER_PENDING), controller.offerOwnership(bea.userId), "one offer at a time")

        assertEquals(ActionResult.Ok, controller.cancelOwnershipOffer())
        assertEquals(listOf(family), server.withdrawn)
        assertNull(controller.state.members?.offer)
        assertEquals(MembersCopy.OFFER_CANCELLED, controller.state.notice)
        assertEquals("owner", controller.state.members?.members?.single { it.you }?.role, "nothing changed")

        // Item 5: an offer the server lists after it was cancelled is only the server's word, never "You asked".
        server.vaults[family] = server.vaults.getValue(family).copy(
            rev = ++server.rev, pendingTransfer = io.silencelen.andvari.core.model.PendingTransfer(bea.userId, offer.offerId, offer.proof, offer.expiresAt, 1),
        )
        assertEquals(ActionResult.Ok, controller.refresh())
        controller.closeMembers()
        assertEquals(ActionResult.Ok, controller.openMembers(family))
        assertEquals(OwnerOfferView(bea.userId, "Bea", offer.expiresAt, mine = false), controller.state.members?.offer)
    }

    /**
     * An offer to make this account a vault's owner is listed only once it verifies under that vault's key: one the
     * server made up is not. Accepting seals the vault's key to this account as its owner; declining leaves it as it was.
     */
    @Test
    fun anOfferToTakeAVaultOverIsListedOnlyWhenItVerifiesAndAcceptingMakesThisAccountItsOwner() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        val me = io.silencelen.andvari.core.client.Contact(reg.userId, reg.identityPub, "u", 1_000, io.silencelen.andvari.core.client.Contact.METHOD_TYPED, EMAIL)
        val olga = Account.enroll("invite", "olga@example.com", "Olga", PASSWORD, KdfParams(ops = 1, memBytes = 8192), null, null, "device", crypto)
        server.identities[olga.request.userId] = io.silencelen.andvari.core.model.UserLookupResponse(olga.request.userId, "Olga", olga.request.identityPub)
        fun share(name: String): String {
            val shared = olga.account.buildCreateSharedVault(name)
            server.vaults[shared.vaultId] = WireVault(shared.vaultId, "shared", ++server.rev, shared.request.metaBlob, 2_000)
            server.grants[shared.vaultId] = io.silencelen.andvari.core.model.WireGrant(shared.vaultId, reg.userId, "writer", "", server.rev, null, olga.account.buildSignedGrant(shared.vaultId, me))
            server.members[shared.vaultId] = mutableListOf(
                io.silencelen.andvari.core.model.VaultMemberSummary(olga.request.userId, "olga@example.com", "Olga", "owner", olga.request.identityPub, 1_000),
                io.silencelen.andvari.core.model.VaultMemberSummary(reg.userId, EMAIL, "u", "writer", reg.identityPub, 2_000),
            )
            return shared.vaultId
        }
        fun offerTo(vaultId: String, proof: String? = null): io.silencelen.andvari.core.model.PendingTransfer {
            val offerId = enrolled.account.newItemId()
            val expiresAt = 4_000_000_000_000L
            val signed = io.silencelen.andvari.core.crypto.LifecycleProof.offer(crypto, olga.account.lifecycleKeyFor(vaultId), vaultId, offerId, reg.userId, expiresAt, 1)
            val pt = io.silencelen.andvari.core.model.PendingTransfer(reg.userId, offerId, proof ?: signed, expiresAt, 1)
            server.vaults[vaultId] = server.vaults.getValue(vaultId).copy(rev = ++server.rev, pendingTransfer = pt)
            return pt
        }
        val cabin = share("Cabin")
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.verifyInvitation(controller.state.invitations.single().id))
        assertEquals(ActionResult.Ok, controller.verifyWithCode(olga.account.identityFingerprintShort()))

        // One the server made up (its proof is not the vault key's) is never listed.
        offerTo(cabin, proof = Bytes.toB64(ByteArray(32)))
        assertEquals(ActionResult.Ok, controller.refresh())
        assertTrue(controller.state.ownershipOffers.isEmpty(), "an offer that does not verify is not shown")
        assertIs<ActionResult.Failed>(controller.acceptOwnership(cabin))
        assertTrue(server.accepts.isEmpty())

        offerTo(cabin)
        assertEquals(ActionResult.Ok, controller.refresh())
        val listed = controller.state.ownershipOffers.single()
        assertEquals(cabin, listed.vaultId)
        assertEquals("Cabin", listed.vaultName)
        settle { controller.state.ownershipOffers.single().from == "Olga" } // the owner's name, asked for in the background

        assertEquals(ActionResult.Ok, controller.acceptOwnership(cabin))
        val (vaultId, accept) = server.accepts.single()
        assertEquals(cabin, vaultId)
        // The vault's key, wrapped under this account's own key as its owner, and the accept proof over that wrap.
        val key = olga.account.lifecycleKeyFor(cabin)
        assertEquals(io.silencelen.andvari.core.crypto.LifecycleProof.accept(crypto, key, cabin, accept.offerId, reg.userId, 1, accept.wrappedVk), accept.proof)
        assertTrue(controller.state.ownershipOffers.isEmpty())
        assertEquals("You own “Cabin” now: you manage its members, and only you can rename, hand over or delete it.", controller.state.notice)
        assertEquals(ActionResult.Ok, controller.openMembers(cabin))
        assertTrue(assertNotNull(controller.state.members).owner, "this account owns it now")
        controller.closeMembers()

        // Another, declined: the vault stays with its owner. (Olga is verified on this device now: Boat opens at once.)
        val boat = share("Boat")
        assertEquals(ActionResult.Ok, controller.refresh())
        assertTrue(controller.state.invitations.isEmpty())
        offerTo(boat)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(listOf(boat), controller.state.ownershipOffers.map { it.vaultId })
        assertEquals(ActionResult.Ok, controller.declineOwnership(boat))
        assertEquals(listOf(boat), server.withdrawn)
        assertTrue(controller.state.ownershipOffers.isEmpty())
        assertEquals("Declined. “Boat” stays with its owner.", controller.state.notice)
        assertEquals(1, server.accepts.size)

        // A lock forgets the offers; the next unlock lists them again from what it verifies.
        offerTo(boat)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(1, controller.state.ownershipOffers.size)
        controller.lock()
        assertTrue(controller.state.ownershipOffers.isEmpty())
    }

    /**
     * The people this account verified (Android's "Household members you've verified"): listed from the account's own
     * record, verified by looking someone up and comparing codes with them, and taken off again. Nothing is recorded on a
     * mismatch, and a lock forgets the open list.
     */
    @Test
    fun thePeopleThisAccountVerifiedAreListedVerifiedAndRemoved() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        val bea = server.person("bea@example.com", "Bea")
        assertEquals(ActionResult.Ok, controller.openHousehold())
        val empty = assertNotNull(controller.state.household)
        assertTrue(empty.contacts.isEmpty())
        assertNull(empty.warning)

        assertEquals(ActionResult.Failed(MembersCopy.EMAIL_REQUIRED), controller.findHouseholdMember(" "))
        assertEquals(ActionResult.Failed(MembersCopy.NO_SUCH_USER), controller.findHouseholdMember("nobody@example.com"))
        server.accounts[EMAIL] = io.silencelen.andvari.core.model.UserLookupResponse(reg.userId, "u", reg.identityPub)
        assertEquals(ActionResult.Failed(MembersCopy.THATS_YOU), controller.findHouseholdMember(EMAIL))
        assertEquals(ActionResult.Ok, controller.findHouseholdMember(" bea@example.com "))
        val ceremony = assertNotNull(controller.state.verifying)
        assertEquals("bea@example.com", ceremony.email)
        assertFalse(ceremony.invitation)
        assertEquals(ActionResult.Failed(MembersCopy.CODE_MISMATCH), controller.verifyWithCode("0".repeat(32)))
        assertTrue(assertNotNull(controller.state.household).contacts.isEmpty(), "a mismatch records nothing")
        assertEquals(ActionResult.Ok, controller.verifyWithCode(bea.code))
        assertNull(controller.state.verifying)
        val listed = assertNotNull(controller.state.household).contacts.single()
        assertEquals(bea.userId, listed.userId)
        assertEquals("bea@example.com", listed.email, "the address typed to find her")
        assertEquals("Bea", listed.label)
        assertEquals(io.silencelen.andvari.core.client.Contact.METHOD_TYPED, listed.method)
        assertTrue(listed.confirmedHere, "verified on this device")
        assertEquals("Verified Bea on this device.", controller.state.notice)

        assertEquals(ActionResult.Ok, controller.removeContact(bea.userId))
        assertTrue(assertNotNull(controller.state.household).contacts.isEmpty())
        assertTrue(assertNotNull(controller.state.notice).startsWith("Removed bea@example.com from the people you verified."))
        assertEquals(ActionResult.Failed(MembersCopy.CONTACT_GONE), controller.removeContact(bea.userId))

        // Verified by her QR code this time; a lock forgets the open list.
        assertEquals(ActionResult.Ok, controller.findHouseholdMember("bea@example.com"))
        assertEquals(ActionResult.Ok, controller.verifyWithQr(bea.qr))
        assertEquals("qr", assertNotNull(controller.state.household).contacts.single().method)
        controller.lock()
        assertNull(controller.state.household)
        assertNull(controller.state.verifying)
    }

    /**
     * A vault shared the older way (a v1 seal nobody signed, root cause A §8.2): readable but read only, listed for review
     * with the owner the server names, on the vault screen and under Shared vaults. Accepting it (trust on first use) makes
     * it writable and stores this account's own wrap of its key; leaving another one ends it.
     */
    @Test
    fun aVaultSharedTheOlderWayIsReadOnlyUntilItIsAcceptedOrLeft() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        val wraps = mutableListOf<String>()
        routes["/grant/self-wrap"] = { request ->
            wraps += request.url.encodedPath.removeSuffix("/grant/self-wrap").substringAfterLast('/')
            respond("""{"rev":${++server.rev}}""", HttpStatusCode.OK, headers)
        }
        routes["/leave"] = { request ->
            val vaultId = request.url.encodedPath.removeSuffix("/leave").substringAfterLast('/')
            server.vaults.remove(vaultId)
            server.grants.remove(vaultId)
            server.removed += vaultId
            respond("""{"rev":${++server.rev}}""", HttpStatusCode.OK, headers)
        }
        fun owner(email: String, name: String): io.silencelen.andvari.core.client.EnrollResult {
            val e = Account.enroll("invite", email, name, PASSWORD, KdfParams(ops = 1, memBytes = 8192), null, null, "device", crypto)
            server.identities[e.request.userId] = io.silencelen.andvari.core.model.UserLookupResponse(e.request.userId, name, e.request.identityPub)
            return e
        }
        fun shareTheOlderWay(from: io.silencelen.andvari.core.client.EnrollResult, name: String): String {
            val shared = from.account.buildCreateSharedVault(name)
            val seal = from.account.wrapVkForMember(Bytes.fromB64(reg.identityPub), shared.vaultId)
            server.vaults[shared.vaultId] = WireVault(shared.vaultId, "shared", ++server.rev, shared.request.metaBlob, 2_000)
            server.grants[shared.vaultId] = io.silencelen.andvari.core.model.WireGrant(shared.vaultId, reg.userId, "writer", "", server.rev, seal, null)
            server.members[shared.vaultId] = mutableListOf(
                io.silencelen.andvari.core.model.VaultMemberSummary(from.request.userId, from.request.email, from.request.displayName, "owner", from.request.identityPub, 1_000),
                io.silencelen.andvari.core.model.VaultMemberSummary(reg.userId, EMAIL, "u", "writer", reg.identityPub, 2_000),
            )
            return shared.vaultId
        }
        val olga = owner("olga@example.com", "Olga")
        val cabin = shareTheOlderWay(olga, "Cabin")
        val boat = shareTheOlderWay(owner("pat@example.com", "Pat"), "Boat")
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(listOf("Boat", "Cabin"), controller.state.legacyReviews.map { it.name }, "readable, so named; listed for review")
        settle { controller.state.legacyReviews.all { it.owner != null } } // the owners the server names, asked for in the background
        assertEquals("Olga", controller.state.legacyReviews.single { it.vaultId == cabin }.owner)
        assertTrue(controller.vaultsForNewItems().none { it.vaultId == cabin || it.vaultId == boat }, "nothing is saved into them yet")
        assertTrue(wraps.isEmpty(), "no wrap of a key nobody vouched for")
        assertEquals(ActionResult.Ok, controller.openSharing())
        assertEquals(setOf(cabin, boat), assertNotNull(controller.state.sharing).vaults.filter { it.awaitingReview }.map { it.vaultId }.toSet())

        assertEquals(ActionResult.Failed(MembersCopy.REVIEW_GONE), controller.acceptLegacyVault(reg.personalVault.vaultId))
        assertEquals(ActionResult.Ok, controller.acceptLegacyVault(cabin))
        assertEquals(MembersCopy.reviewAccepted("Cabin"), controller.state.notice)
        assertEquals(listOf(boat), controller.state.legacyReviews.map { it.vaultId })
        assertTrue(controller.vaultsForNewItems().any { it.vaultId == cabin }, "a writer can put items in it now")
        assertEquals(listOf(cabin), wraps, "this account's own wrap of the key it vouched for")
        assertFalse(assertNotNull(controller.state.sharing).vaults.single { it.vaultId == cabin }.awaitingReview)
        assertEquals(ActionResult.Failed(MembersCopy.REVIEW_GONE), controller.acceptLegacyVault(cabin), "accepted once")

        assertEquals(ActionResult.Ok, controller.leaveSharedVault(boat))
        assertTrue(controller.state.legacyReviews.isEmpty())
        assertTrue(assertNotNull(controller.state.sharing).vaults.none { it.vaultId == boat })

        // Sharing review 2026-11 (item 8): the server's owner label never keeps this account in a vault awaiting review.
        val raft = shareTheOlderWay(owner("ray@example.com", "Ray"), "Raft")
        server.grants[raft] = server.grants.getValue(raft).copy(role = "owner")
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(listOf(raft), controller.state.legacyReviews.map { it.vaultId })
        assertEquals(ActionResult.Ok, controller.leaveSharedVault(raft))
        assertNull(server.vaults[raft], "the leave was sent")
        assertTrue(controller.state.legacyReviews.isEmpty(), "and it is no longer awaiting review here")
        controller.lock()
        assertTrue(controller.state.legacyReviews.isEmpty(), "after the lock")
    }

    /**
     * A vault the server says this account owns, made before andvari kept its own record of that (A6b): nothing is added
     * or signed until the person confirms "You own <vault>?" with their master password, after seeing what the server
     * reports. Then the members still on the older kind of sharing can be shared with again, each only once verified here,
     * signed by this account.
     */
    @Test
    fun anOwnerConfirmsOwnershipWithTheMasterPasswordThenSharesAgainUnderTheSignedKind() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        twoStepServer() // the account's keys as the server serves them, at the KDF floor: what the password is checked against
        val bea = server.person("bea@example.com", "Bea")
        val made = enrolled.account.buildCreateSharedVault("Garage")
        val garage = made.vaultId
        server.vaults[garage] = WireVault(garage, "shared", ++server.rev, made.request.metaBlob, 2_000)
        server.grants[garage] = io.silencelen.andvari.core.model.WireGrant(garage, reg.userId, "owner", made.request.wrappedVk, server.rev)
        server.members[garage] = mutableListOf(
            io.silencelen.andvari.core.model.VaultMemberSummary(reg.userId, EMAIL, "u", "owner", reg.identityPub, 2_000),
            bea.row("writer").copy(legacyGrant = true),
        )
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.openSharing())
        val listed = assertNotNull(controller.state.sharing).vaults.single { it.vaultId == garage }
        assertEquals("owner", listed.role)
        assertFalse(listed.ownershipConfirmed, "the server's word only")

        assertEquals(ActionResult.Ok, controller.openMembers(garage))
        val before = assertNotNull(controller.state.members)
        assertTrue(before.owner)
        assertFalse(before.canAdd)
        assertTrue(before.legacy.isEmpty(), "nothing offered for re-sharing while ownership is unconfirmed")
        assertEquals(ActionResult.Failed(MembersCopy.OWNERSHIP_UNCONFIRMED), controller.reshareWithMember(bea.userId))

        assertEquals(ActionResult.NotDone(null), controller.confirmOwnership(PASSWORD, false), "nothing described yet")
        assertEquals(ActionResult.Ok, controller.describeOwnership(garage))
        val claim = assertNotNull(controller.state.ownershipClaim)
        assertEquals("Garage", claim.vaultName)
        assertFalse(claim.receivedAsMember)
        assertEquals(
            listOf("Created by u ($EMAIL); never handed over (as the server reports it).", "Also in this vault: Bea (bea@example.com), writer (as the server reports it)."),
            claim.lines,
        )
        controller.cancelOwnershipClaim()
        assertNull(controller.state.ownershipClaim)
        assertEquals(ActionResult.NotDone(null), controller.confirmOwnership(PASSWORD, false), "cancelled")

        assertEquals(ActionResult.Ok, controller.describeOwnership(garage))
        assertEquals(ActionResult.Failed(MembersCopy.PASSWORD_REQUIRED), controller.confirmOwnership("", false))
        assertEquals(ActionResult.Failed(HouseholdCopy.REAUTH_FAILED), controller.confirmOwnership("not it", false))
        assertNotNull(controller.state.ownershipClaim, "still open after a wrong password")
        assertFalse(assertNotNull(controller.state.sharing).vaults.single { it.vaultId == garage }.ownershipConfirmed)
        assertEquals(ActionResult.Ok, controller.confirmOwnership(PASSWORD, false))
        assertNull(controller.state.ownershipClaim)
        assertEquals(MembersCopy.ownershipConfirmed("Garage"), controller.state.notice)
        assertTrue(assertNotNull(controller.state.sharing).vaults.single { it.vaultId == garage }.ownershipConfirmed)
        val owned = assertNotNull(controller.state.members)
        assertTrue(owned.canAdd)

        // The members still on the older kind of sharing: Bea, not verified on this device yet.
        val row = owned.legacy.single()
        assertEquals(bea.userId, row.userId)
        assertEquals(MemberCheck.NOT_VERIFIED, row.check)
        assertNull(row.verifiedLabel)
        assertEquals(ActionResult.Failed(MembersCopy.VERIFY_FIRST), controller.reshareWithMember(bea.userId))
        assertTrue(server.reissues.isEmpty())
        assertEquals(ActionResult.Ok, controller.verifyListedMember(bea.userId))
        assertEquals(ActionResult.Ok, controller.verifyWithCode(bea.code))
        val verified = assertNotNull(controller.state.members).legacy.single()
        assertEquals(MemberCheck.VERIFIED, verified.check)
        assertEquals("Bea", verified.verifiedLabel)

        assertEquals(ActionResult.Ok, controller.reshareWithMember(bea.userId))
        val (vaultId, userId, request) = server.reissues.single()
        assertEquals(garage to bea.userId, vaultId to userId)
        assertTrue(request.signedGrant.isNotEmpty())
        assertTrue(assertNotNull(controller.state.members).legacy.isEmpty(), "shared again: off the list")
        assertEquals(MembersCopy.reshared("Garage", "Bea"), controller.state.notice)
        assertEquals(ActionResult.Failed(MembersCopy.MEMBER_GONE), controller.reshareWithMember(bea.userId), "once")
        controller.closeMembers()
    }

    /** Nothing the members screen or a comparison of codes held outlives a lock, or a screen closed while its read was out. */
    @Test
    fun aLockOrAClosedScreenForgetsTheMembersAndAnOpenComparison() = test {
        val (server, family) = familyVault()
        val bea = server.person("bea@example.com", "Bea")
        assertEquals(ActionResult.Ok, controller.openMembers(family))
        assertEquals(ActionResult.Ok, controller.findNewMember("bea@example.com"))
        assertEquals(ActionResult.Ok, controller.verifyNewMember())
        controller.lock()
        assertNull(controller.state.members)
        assertNull(controller.state.verifying)
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(ActionResult.NotDone(null), controller.verifyWithCode(bea.code), "no comparison is open")
        assertEquals(ActionResult.Failed(MembersCopy.LOOK_UP_AGAIN), controller.addNewMember("writer"))
        assertEquals(ActionResult.Failed(MembersCopy.MEMBER_GONE), controller.verifyListedMember(bea.userId))
        assertTrue(server.adds.isEmpty())

        kotlinx.coroutines.coroutineScope {
            val gate = CompletableDeferred<Unit>()
            val answer = routes.getValue("/members")
            routes["/members"] = { request ->
                gate.await()
                answer(request)
            }
            val opening = async { controller.openMembers(family) }
            settle { controller.state.busy }
            controller.closeMembers()
            gate.complete(Unit)
            assertEquals(ActionResult.NotDone(null), opening.await())
            assertNull(controller.state.members, "the closed screen does not come back")
            assertFalse(controller.state.busy)
        }
    }

    // ---- two-step sign-in ----

    @Test
    fun twoStepSignInIsReadAndTurnedOffWithACodeAndThePasswordAndNothingOutlivesTheScreen() = test {
        unlocked()
        // The account's keys at the KDF floor, so a password proof can be derived for the disable.
        twoStepServer()
        var enrolled = true
        var disabledWith: io.silencelen.andvari.core.model.wire.TotpDisableRequest? = null
        routes["/account/totp"] = {
            respond(json.encodeToString(io.silencelen.andvari.core.model.TotpStatus.serializer(), io.silencelen.andvari.core.model.TotpStatus(enrolled, false)), HttpStatusCode.OK, headers)
        }
        routes["/account/totp/disable"] = { request ->
            disabledWith = json.decodeFromString(io.silencelen.andvari.core.model.wire.TotpDisableRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            enrolled = false
            respond(json.encodeToString(io.silencelen.andvari.core.model.TotpStatus.serializer(), io.silencelen.andvari.core.model.TotpStatus(false, false)), HttpStatusCode.OK, headers)
        }
        assertNull(controller.state.twoStep)
        assertEquals(ActionResult.Ok, controller.loadTwoStep())
        assertEquals(TwoStepView(enrolled = true, settingUp = false), controller.state.twoStep)
        assertEquals(ActionResult.NotDone(null), controller.confirmTwoStep("123456"), "nothing is being set up")
        // The code alone (decided on 2026-11-16): nothing is sent, and the answer says the password is needed.
        assertEquals(ActionResult.NotDone(ItemCopy.TWO_STEP_PASSWORD_NEEDED), controller.disableTwoStep(" 123456 "))
        assertNull(disabledWith, "nothing was sent")
        assertEquals(ActionResult.Ok, controller.disableTwoStep(" 123456 ", PASSWORD))
        assertEquals("123456", disabledWith?.code)
        assertTrue(disabledWith?.currentAuthKey.orEmpty().isNotEmpty(), "the password's proof beside the code")
        assertFalse(disabledWith?.currentAuthKey.orEmpty().contains(PASSWORD), "never the password itself")
        assertEquals(TwoStepView(enrolled = false, settingUp = false), controller.state.twoStep)
        assertEquals(ItemCopy.TWO_STEP_OFF, controller.state.notice)
        controller.closeTwoStep()
        assertNull(controller.state.twoStep)
        assertNull(controller.twoStepSetup())
    }

    /**
     * The server answers for a setup, with the account's keys re-wrapped under the KDF floor (the fixture's own are below
     * it, and a password proof is only derived at or above it), so Turn on gets as far as a new key.
     */
    private fun Rig.twoStepServer(confirmed: () -> Unit = {}) {
        val floor = io.silencelen.andvari.core.crypto.KdfParams(ops = 3, memBytes = io.silencelen.andvari.core.client.KdfUpgrade.MIN_MEM_BYTES)
        val mk = io.silencelen.andvari.core.crypto.Keys.masterKey(crypto, PASSWORD, Bytes.fromB64(cached.kdfSalt), floor)
        val wrap = io.silencelen.andvari.core.crypto.Keys.wrapKey(crypto, mk)
        val uvk = enrolled.account.uvkCopyForPlatformWrap()
        val wrapped = io.silencelen.andvari.core.crypto.Envelope.sealB64(crypto, wrap, uvk, io.silencelen.andvari.core.crypto.Ad.uvk(reg.userId))
        routes["/account/keys"] = { respond(json.encodeToString(AccountKeys.serializer(), cached.copy(kdfParams = floor, wrappedUvk = wrapped)), HttpStatusCode.OK, headers) }
        routes["/account/totp"] = { respond("""{"enrolled":false,"pendingSetup":false}""", HttpStatusCode.OK, headers) }
        routes["/account/totp/setup"] = {
            respond("""{"secretBase32":"JBSWY3DPEHPK3PXP","otpauthUri":"otpauth://totp/andvari:${EMAIL}?secret=JBSWY3DPEHPK3PXP&issuer=andvari&digits=8"}""", HttpStatusCode.OK, headers)
        }
        routes["/account/totp/confirm"] = {
            confirmed()
            respond("""{"enrolled":true,"pendingSetup":false}""", HttpStatusCode.OK, headers)
        }
    }

    @Test
    fun theAuthenticatorLinkNamesTheServerNotTheEmail() {
        assertEquals("otpauth://totp/andvari:vault.example?secret=JBSWY3DPEHPK3PXP&issuer=andvari", authenticatorLink("JBSWY3DPEHPK3PXP", "otpauth://totp/andvari:me%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=andvari", "vault.example"))
        assertEquals(
            "otpauth://totp/andvari:vault.example?secret=JBSWY3DPEHPK3PXP&issuer=andvari&algorithm=SHA256&digits=8&period=60",
            authenticatorLink("JBSWY3DPEHPK3PXP", "otpauth://totp/x:me@example.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60", "vault.example"),
            "the server's own algorithm, digits and period are kept",
        )
        assertEquals("otpauth://totp/andvari:%5B%3A%3A1%5D?secret=AB%3D%3D&issuer=andvari", authenticatorLink("AB==", "not a link", "[::1]"))
    }

    /**
     * Round-6 review L4: setting up two-step sign-in sends the person to an authenticator, which locks the app. The key
     * being set up stays (for ten minutes from when it was minted), the screen comes back on its confirm step after the
     * unlock, and the code from it confirms. The link names the server, never the email.
     */
    @Test
    fun aKeyBeingSetUpOutlivesTheTripToTheAuthenticatorAndIsConfirmedAfterTheUnlock() = test {
        unlocked()
        var confirms = 0
        twoStepServer { confirms++ }
        assertEquals(ActionResult.Ok, controller.loadTwoStep())
        assertEquals(ActionResult.Ok, controller.beginTwoStep(PASSWORD))
        val setup = assertNotNull(controller.twoStepSetup())
        assertEquals("JBSWY3DPEHPK3PXP", setup.secret)
        assertEquals("otpauth://totp/andvari:home.example?secret=JBSWY3DPEHPK3PXP&issuer=andvari&digits=8", setup.uri)
        assertFalse(setup.uri.contains(EMAIL) || setup.uri.contains("%40") || setup.uri.contains("example.com"), "never the email")
        // Open in authenticator: the app leaves the foreground and locks; the screen goes with the lock.
        controller.lock()
        controller.closeTwoStep()
        assertNull(controller.state.twoStep)
        assertNull(controller.twoStepSetup(), "nothing is shown while locked")
        clocks.mono += 4 * MINUTE
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(TwoStepView(enrolled = false, settingUp = true, resumed = true), controller.state.twoStep, "back on the confirm step")
        assertEquals(setup.secret, controller.twoStepSetup()?.secret, "the same key, not a new one")
        assertEquals(ActionResult.Ok, controller.loadTwoStep())
        assertEquals(TwoStepView(enrolled = false, settingUp = true), controller.state.twoStep)
        assertEquals(ActionResult.Ok, controller.confirmTwoStep("123456"))
        assertEquals(1, confirms)
        assertEquals(ItemCopy.TWO_STEP_ON, controller.state.notice)
        assertNull(controller.twoStepSetup())
        assertEquals(1, calls.count { it.endsWith("/account/totp/setup") }, "one key was minted")
    }

    @Test
    fun aKeyBeingSetUpGoesAfterTenMinutesWhenTheScreenIsClosedOrOnSignOut() = test {
        unlocked()
        twoStepServer()
        // Past its time while locked: not shown again, and nothing to confirm.
        assertEquals(ActionResult.Ok, controller.beginTwoStep(PASSWORD))
        controller.lock()
        controller.closeTwoStep()
        clocks.mono += 11 * MINUTE
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertNull(controller.state.twoStep)
        assertNull(controller.twoStepSetup())
        assertEquals(ActionResult.NotDone(null), controller.confirmTwoStep("123456"))
        // Closed by the person while unlocked: gone.
        assertEquals(ActionResult.Ok, controller.beginTwoStep(PASSWORD))
        controller.closeTwoStep()
        assertNull(controller.twoStepSetup())
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertNull(controller.state.twoStep)
        // A sign-out drops it, though the app was only locked when it ran.
        assertEquals(ActionResult.Ok, controller.beginTwoStep(PASSWORD))
        controller.lock()
        assertEquals(ActionResult.Ok, controller.signOut())
        seedSession()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertNull(controller.state.twoStep)
        assertNull(controller.twoStepSetup())
    }

    /** Round-7 review L4: a key past its time goes at the lock, and a session revoked at the next unlock takes it with it. */
    @Test
    fun aKeyBeingSetUpGoesAtALockPastItsTimeAndWithASessionRevokedAtUnlock() = test {
        unlocked()
        twoStepServer()
        assertEquals(ActionResult.Ok, controller.beginTwoStep(PASSWORD))
        clocks.mono += 11 * MINUTE
        controller.lock()
        assertFalse(controller.holdsTwoStepKey(), "past its time: not kept while locked")
        // In time at the lock, then the server says the session is dead at the next unlock.
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(ActionResult.Ok, controller.beginTwoStep(PASSWORD))
        controller.lock()
        assertTrue(controller.holdsTwoStepKey(), "an ordinary lock keeps it for the trip")
        routes["/account/keys"] = { respond("""{"error":"unauthorized","message":"revoked"}""", HttpStatusCode.Unauthorized, headers) }
        routes["/auth/refresh"] = { respond("""{"error":"unauthorized","message":"revoked"}""", HttpStatusCode.Unauthorized, headers) }
        assertIs<ActionResult.Failed>(controller.unlock(PASSWORD))
        assertEquals("Your session ended — sign in again.", controller.state.lockReason)
        assertFalse(controller.holdsTwoStepKey(), "the revoked session takes it with it")
    }

    /** Round-8 review L: a key being set up goes when its time is up, whether the app is locked or not; not at every lock. */
    @Test
    fun aKeyBeingSetUpGoesWhenItsTimeIsUpLockedOrNot() = test {
        unlocked()
        twoStepServer()
        // Locked in time, then its time runs out while still locked: gone then, not at the next unlock.
        assertEquals(ActionResult.Ok, controller.beginTwoStep(PASSWORD))
        controller.lock()
        assertTrue(controller.holdsTwoStepKey(), "a lock in time keeps it for the trip")
        clocks.mono += 10 * MINUTE - 1
        controller.tick()
        assertTrue(controller.holdsTwoStepKey(), "not before its time")
        clocks.mono += 1
        controller.tick()
        assertFalse(controller.holdsTwoStepKey(), "at its time, while locked")
        // Unlocked with the setup screen open: the key goes at its time and the screen goes back to its start.
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(ActionResult.Ok, controller.beginTwoStep(PASSWORD))
        assertEquals(true, controller.state.twoStep?.settingUp)
        repeat(10) {
            clocks.mono += MINUTE
            controller.userActivity() // the person is there: no idle lock
            controller.tick()
        }
        assertEquals(AppScreen.VAULT, controller.state.screen)
        assertNull(controller.twoStepSetup())
        assertEquals(false, controller.state.twoStep?.settingUp)
        assertEquals(ActionResult.NotDone(null), controller.confirmTwoStep("123456"))
    }

    @Test
    fun aRefusedCodeOrAWeakServerSaysWhyAndChangesNothing() = test {
        unlocked()
        twoStepServer()
        routes["/account/totp"] = { respond("""{"enrolled":true,"pendingSetup":false}""", HttpStatusCode.OK, headers) }
        routes["/account/totp/disable"] = { respond("""{"error":"bad_totp_code","message":"no"}""", HttpStatusCode.BadRequest, headers) }
        assertEquals(ActionResult.Ok, controller.loadTwoStep())
        assertIs<ActionResult.Failed>(controller.disableTwoStep("000000", PASSWORD))
        assertEquals(TwoStepView(enrolled = true, settingUp = false), controller.state.twoStep, "still on")
        // Setting up needs the master password proven under the account's own key settings: this fixture's are below the
        // floor any server may send, so the proof is refused before anything is sent, and nothing is set up.
        routes["/account/keys"] = { respond(json.encodeToString(AccountKeys.serializer(), cached), HttpStatusCode.OK, headers) }
        assertIs<ActionResult.Failed>(controller.beginTwoStep(PASSWORD))
        assertNull(controller.twoStepSetup())
        assertFalse(calls.any { it.endsWith("/account/totp/setup") }, "no setup request left the device")
    }

    // ---- attachments (owner decision 2026-11-12) ----

    /** What the attachment routes saw and hold: by id, the item a file was sent for and its bytes as they went up. */
    private class FileServer {
        val stored = LinkedHashMap<String, Pair<String, ByteArray>>()
        val uploads = mutableListOf<String>()

        /** Each put pushed: the item and the revision it was sent from. */
        val pushedBases = mutableListOf<Pair<String, Long>>()

        /** While set, an upload waits for it; [started] is completed as one arrives. */
        var gate: CompletableDeferred<Unit>? = null
        var started: CompletableDeferred<Unit>? = null

        /** The server cannot be reached for uploads. */
        var fail = false
    }

    /** [onlineServer], with the attachment routes of the real one: an upload of the same bytes for the same item is taken again. */
    private fun Rig.fileServer(): FileServer {
        onlineServer()
        val files = FileServer()
        val push = routes.getValue("/sync/push")
        routes["/sync/push"] = { request ->
            val body = json.decodeFromString(io.silencelen.andvari.core.model.PushRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            body.mutations.forEach { files.pushedBases += it.itemId to it.baseItemRev }
            push(request)
        }
        prefixRoutes["/api/v1/attachments/"] = { request ->
            val id = request.url.encodedPath.substringAfterLast('/')
            if (request.method == io.ktor.http.HttpMethod.Post) {
                files.uploads += id
                files.started?.complete(Unit)
                files.gate?.await()
                if (files.fail) throw IOException("unreachable")
                val itemId = assertNotNull(request.url.parameters["itemId"])
                val vaultId = assertNotNull(request.url.parameters["vaultId"])
                // A copy, as a server holds what came over the wire: the client zeroes its own array once the upload is done.
                val bytes = (request.body as OutgoingContent.ByteArrayContent).bytes().copyOf()
                val held = files.stored[id]
                if (held != null && (held.first != itemId || !held.second.contentEquals(bytes))) {
                    respond("""{"error":"attachment_id_taken","message":"taken"}""", HttpStatusCode.BadRequest, headers)
                } else {
                    files.stored[id] = itemId to bytes
                    val meta = io.silencelen.andvari.core.model.AttachmentMeta(id, itemId, vaultId, bytes.size.toLong(), "sha")
                    respond(json.encodeToString(io.silencelen.andvari.core.model.AttachmentMeta.serializer(), meta), HttpStatusCode.OK, headers)
                }
            } else {
                val held = files.stored[id]
                if (held == null) respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, headers)
                else respond(held.second, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/octet-stream"))
            }
        }
        clocks.wall = System_now() // the device's clock and the server's agree, as on a phone
        return files
    }

    private fun Rig.kept(): List<PendingSave> = PendingSaves(pendingLog, pendingFiles) { true }.load(enrolled.account)

    @Test
    fun aNewItemsFileGoesUpBeforeTheItemAndOpensFromMemory() = test {
        unlockedWithAPersonalVault()
        val files = fileServer()
        controller.openAttachmentDraft(null)
        val plain = ByteArray(200_000) { (it % 251).toByte() }
        val given = plain.copyOf()
        assertEquals(ActionResult.Ok, controller.addAttachment("/private/var/mobile/tmp/Lease.pdf", given))
        assertTrue(given.all { it == 0.toByte() }, "the plaintext handed over is zeroed")
        val draft = assertNotNull(controller.state.attachmentDraft)
        assertEquals(listOf("Lease.pdf"), draft.added.map { it.name }, "called by the last part of its path")
        assertEquals(200_000L, draft.totalBytes)
        val setAside = assertNotNull(pendingFiles.get(draft.added.single().id))
        assertEquals(io.silencelen.andvari.core.crypto.Attachments.wireLength(200_000), setAside.size.toLong(), "set aside encrypted, as it goes up")
        assertFalse(setAside.copyOfRange(24, 1_024).contentEquals(plain.copyOfRange(0, 1_000)))
        assertEquals(ActionResult.Ok, controller.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.example"), "", "", false)))
        val upload = calls.indexOfFirst { it.startsWith("/api/v1/attachments/") }
        assertTrue(upload >= 0 && upload < calls.indexOfLast { it.endsWith("/sync/push") }, "the file went up before the item that names it")
        val row = controller.state.items.single { it.name == "Bank" }
        val detail = assertNotNull(controller.itemDetail(row.itemId))
        assertEquals(listOf(AttachmentView(draft.added.single().id, "Lease.pdf", 200_000)), detail.attachments)
        assertEquals(row.itemId, files.stored.values.single().first, "sent for the item it is in")
        val opened = controller.readAttachment(row.itemId, detail.attachments.single().id)
        assertNull(opened.error)
        assertContentEquals(plain, opened.bytes, "opened in memory")
        assertNull(pendingLog.bytes, "nothing is kept once the save is done")
        assertTrue(pendingFiles.ids().isEmpty())
        assertNull(controller.state.upload)
        controller.closeAttachmentDraft()
        assertNull(controller.state.attachmentDraft)
        assertEquals(1, controller.state.items.count { it.name == "Bank" })
    }

    @Test
    fun aFileIsHeldToThePolicysLimitsBeforeItIsSetAside() = test {
        routes["/client-policy"] = {
            respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(attachmentMaxBytes = 1_000, itemAttachmentsMaxBytes = 2_000)), HttpStatusCode.OK, headers)
        }
        unlockedWithAPersonalVault()
        assertEquals(AttachmentLimitsView(1_000, 2_000), controller.attachmentLimits())
        assertEquals(ActionResult.NotDone(null), controller.addAttachment("a.txt", ByteArray(10)), "no editor is open")
        controller.openAttachmentDraft(null)
        assertEquals(AttachmentLimitsView(1_000, 2_000), controller.state.attachmentDraft?.limits)
        assertEquals(ActionResult.Failed("This file is empty."), controller.addAttachment("a.txt", ByteArray(0)))
        assertEquals(ActionResult.Failed("This file is larger than 1 KB, the most one file can be here."), controller.addAttachment("a.txt", ByteArray(1_001)))
        assertEquals(ActionResult.Ok, controller.addAttachment("a.txt", ByteArray(800) { 1 }))
        assertEquals(ActionResult.Ok, controller.addAttachment("b.txt", ByteArray(800) { 2 }))
        assertEquals(
            ActionResult.Failed("This item's files would come to more than 2 KB, the most one item can hold."),
            controller.addAttachment("c.txt", ByteArray(800) { 3 }),
        )
        assertEquals(1_600L, controller.state.attachmentDraft?.totalBytes)
        assertEquals(2, pendingFiles.ids().size)
        controller.removeAttachment(assertNotNull(controller.state.attachmentDraft).added.first().id)
        assertEquals(listOf("b.txt"), controller.state.attachmentDraft?.added?.map { it.name })
        assertEquals(1, pendingFiles.ids().size, "a file taken off goes at once")
        controller.closeAttachmentDraft()
        assertTrue(pendingFiles.ids().isEmpty(), "closing the editor takes what it added away")
        assertNull(controller.state.attachmentDraft)
        assertNull(pendingLog.bytes)
    }

    @Test
    fun theLimitsAreTheServersHeldToWhatThisAppReadsIntoMemory() {
        assertEquals(AttachmentLimitsView(25L shl 20, 100L shl 20), AttachmentRules.limits(null, null))
        assertEquals(AttachmentLimitsView(50L shl 20, 200L shl 20), AttachmentRules.limits(1L shl 30, 10L shl 30), "a server never raises them past the app's")
        assertEquals(AttachmentLimitsView(5L shl 20, 8L shl 20), AttachmentRules.limits(5L shl 20, 8L shl 20), "and lowers them as it likes")
        assertEquals(AttachmentLimitsView(1, 1), AttachmentRules.limits(0, -5))
        assertEquals("25 MB", AttachmentRules.size(25L shl 20))
        assertEquals("500 KB", AttachmentRules.size(500L * 1024))
    }

    @Test
    fun aSaveWithFilesALockCutShortIsFinishedAfterTheNextUnlockUnderTheSameIds() = test {
        unlockedWithAPersonalVault()
        val files = fileServer()
        controller.openAttachmentDraft(null)
        val plain = ByteArray(70_000) { 3 }
        assertEquals(ActionResult.Ok, controller.addAttachment("scan.pdf", plain.copyOf()))
        val fileId = assertNotNull(controller.state.attachmentDraft).added.single().id
        val pushes = calls.count { it.endsWith("/sync/push") }
        files.gate = CompletableDeferred()
        files.started = CompletableDeferred()
        kotlinx.coroutines.coroutineScope {
            val save = async { controller.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.example"), "", "", false)) }
            withTimeout(10_000) { assertNotNull(files.started).await() }
            assertEquals(UploadView(0, 1), controller.state.upload)
            val again = controller.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.example"), "", "", false))
            assertEquals(ActionResult.NotDone(null), again, "a second Save while the first runs does nothing, never a save without its files")
            assertTrue(controller.state.busy, "and the first save is still running")
            controller.lock() // an explicit lock is immediate, upload or not
            assertEquals(AppScreen.UNLOCK, controller.state.screen)
            assertNull(controller.state.upload)
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.NotDone(null), save.await())
        }
        files.gate = null
        assertEquals(pushes, calls.count { it.endsWith("/sync/push") }, "the item was not sent")
        val sealed = assertNotNull(pendingLog.bytes, "the save is kept")
        assertFalse(sealed.decodeToString().contains("Bank"), "sealed to the account")
        assertEquals(listOf(fileId), pendingFiles.ids(), "with its file, encrypted")
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { pendingLog.bytes == null && controller.state.upload == null }
        val bank = controller.state.items.filter { it.name == "Bank" }
        assertEquals(1, bank.size, "made once")
        assertEquals(listOf(fileId), controller.itemDetail(bank.single().itemId)?.attachments?.map { it.id }, "under the id it was given")
        assertEquals(setOf(fileId), files.stored.keys)
        assertEquals(bank.single().itemId, files.stored.getValue(fileId).first, "and the item's id from its first try")
        assertEquals(AttachmentCopy.KEPT_SAVE_DONE, controller.state.notice)
        assertTrue(pendingFiles.ids().isEmpty())
        assertContentEquals(plain, controller.readAttachment(bank.single().itemId, fileId).bytes)
    }

    @Test
    fun leavingTheAppDuringAnUploadLocksWhenItEndsOrWhenTheGraceRunsOut() = test {
        unlockedWithAPersonalVault()
        val files = fileServer()

        suspend fun savingBlocked(name: String, then: suspend (kotlinx.coroutines.Deferred<ActionResult>) -> Unit) = kotlinx.coroutines.coroutineScope {
            controller.openAttachmentDraft(null)
            assertEquals(ActionResult.Ok, controller.addAttachment("$name.pdf", ByteArray(1_000) { 5 }))
            files.gate = CompletableDeferred()
            files.started = CompletableDeferred()
            val save = async { controller.saveLogin(null, LoginInput(name, "me", "pw", emptyList(), "", "", false)) }
            withTimeout(10_000) { assertNotNull(files.started).await() }
            then(save)
        }

        // The upload ends within the grace: the save is done, and the vault locks the moment it is.
        savingBlocked("First") { save ->
            assertTrue(controller.onBackground(), "the lock waits for the upload")
            clocks.mono += AttachmentRules.BACKGROUND_GRACE_MS - 1
            controller.tick()
            assertEquals(AppScreen.VAULT, controller.state.screen, "within the grace")
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.Ok, save.await())
            assertEquals(AppScreen.UNLOCK, controller.state.screen, "locked the moment it finished")
            assertEquals("Locked when you left the app.", controller.state.lockReason)
        }
        assertNull(pendingLog.bytes)
        files.gate = null
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertTrue(controller.state.items.any { it.name == "First" })

        // The grace runs out first: the vault locks then, and the save is finished after the next unlock.
        savingBlocked("Second") { save ->
            assertTrue(controller.onBackground())
            clocks.mono += AttachmentRules.BACKGROUND_GRACE_MS
            controller.tick()
            assertEquals(AppScreen.UNLOCK, controller.state.screen, "the grace ran out")
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.NotDone(null), save.await())
        }
        assertNotNull(pendingLog.bytes)
        files.gate = null
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { pendingLog.bytes == null && controller.state.items.any { it.name == "Second" } }

        // The system's time runs out first: the same.
        savingBlocked("Third") { save ->
            assertTrue(controller.onBackground())
            controller.backgroundTimeEnded()
            assertEquals(AppScreen.UNLOCK, controller.state.screen)
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.NotDone(null), save.await())
        }
        files.gate = null
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { pendingLog.bytes == null && controller.state.items.any { it.name == "Third" } }

        // Away past the grace while suspended (no ticker runs): coming back lands the lock, never voids it (round-9 review 6).
        savingBlocked("Fifth") { save ->
            assertTrue(controller.onBackground())
            clocks.mono += AttachmentRules.BACKGROUND_GRACE_MS
            controller.onForeground()
            assertEquals(AppScreen.UNLOCK, controller.state.screen)
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.NotDone(null), save.await())
        }
        files.gate = null
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { pendingLog.bytes == null && controller.state.items.any { it.name == "Fifth" } }

        // Back within the grace: nothing locks, and the save goes on.
        savingBlocked("Fourth") { save ->
            assertTrue(controller.onBackground())
            controller.onForeground()
            clocks.mono += AttachmentRules.BACKGROUND_GRACE_MS
            controller.tick()
            assertEquals(AppScreen.VAULT, controller.state.screen)
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.Ok, save.await())
            assertEquals(AppScreen.VAULT, controller.state.screen)
        }
        files.gate = null
        assertEquals(listOf(1, 1, 1, 1), listOf("First", "Second", "Third", "Fourth").map { n -> controller.state.items.count { it.name == n } }, "each made once")
        // Nothing running: leaving locks at once.
        assertFalse(controller.onBackground())
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
    }

    @Test
    fun aSecondTryOfTheSameEditorReplacesItsKeptSaveAndClosingTheEditorTakesItBack() = test {
        unlockedWithAPersonalVault()
        val files = fileServer()
        controller.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, controller.addAttachment("a.pdf", ByteArray(1_000) { 1 }))
        files.fail = true
        val input = LoginInput("Bank", "me", "pw", emptyList(), "", "", false)
        assertIs<ActionResult.Failed>(controller.saveLogin(null, input))
        assertIs<ActionResult.Failed>(controller.saveLogin(null, input))
        assertEquals(1, kept().size, "one kept save, however many tries")
        files.fail = false
        assertEquals(ActionResult.Ok, controller.saveLogin(null, input))
        assertEquals(1, controller.state.items.count { it.name == "Bank" })
        assertNull(pendingLog.bytes)
        controller.closeAttachmentDraft()

        // A save that failed, whose editor is then closed, is not tried again.
        controller.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, controller.addAttachment("b.pdf", ByteArray(1_000) { 2 }))
        files.fail = true
        assertIs<ActionResult.Failed>(controller.saveLogin(null, LoginInput("Scan", "", "", emptyList(), "", "", false)))
        assertEquals(1, kept().size)
        controller.closeAttachmentDraft()
        assertNull(pendingLog.bytes)
        assertTrue(pendingFiles.ids().isEmpty())
        files.fail = false
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        delay(100)
        assertTrue(controller.state.items.none { it.name == "Scan" })
    }

    @Test
    fun anEditTakesAFileOffKeepsTheOthersAndIsSentFromTheRevisionItWasEditedFrom() = test {
        unlockedWithAPersonalVault()
        val files = fileServer()
        controller.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, controller.addAttachment("one.pdf", ByteArray(500) { 1 }))
        assertEquals(ActionResult.Ok, controller.addAttachment("two.pdf", ByteArray(600) { 2 }))
        assertEquals(ActionResult.Ok, controller.saveNote(null, NoteInput("Lease", "flat 3", false)))
        controller.closeAttachmentDraft()
        val note = controller.state.items.single { it.name == "Lease" }.itemId
        val (one, two) = assertNotNull(controller.itemDetail(note)).attachments
        controller.openAttachmentDraft(note)
        assertEquals(listOf(one, two), controller.state.attachmentDraft?.kept)
        controller.removeAttachment(one.id)
        assertEquals(ActionResult.Ok, controller.addAttachment("three.pdf", ByteArray(700) { 3 }))
        assertEquals(listOf(two), controller.state.attachmentDraft?.kept)
        assertEquals(1_300L, controller.state.attachmentDraft?.totalBytes)
        val rev = assertNotNull(namespaces.caches.getValue("$homeKey/${reg.userId}").getItem(note)).rev
        assertEquals(ActionResult.Ok, controller.saveNote(note, NoteInput("Lease", "flat 3, renewed", false)))
        assertEquals(listOf("two.pdf", "three.pdf"), assertNotNull(controller.itemDetail(note)).attachments.map { it.name })
        assertEquals(note to rev, files.pushedBases.last(), "sent from the revision it was edited from")
        assertEquals("flat 3, renewed", controller.revealSecret(note, SecretField.NOTES))
    }

    @Test
    fun aKeptSaveWhoseItemTheServerAlreadyHasIsLetGoAndNotSentAgain() = test {
        unlockedWithAPersonalVault()
        fileServer()
        controller.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, controller.addAttachment("a.pdf", ByteArray(500) { 1 }))
        assertEquals(ActionResult.Ok, controller.saveNote(null, NoteInput("Lease", "", false)))
        controller.closeAttachmentDraft()
        val note = controller.state.items.single { it.name == "Lease" }.itemId
        val doc = assertNotNull(namespaces.caches.getValue("$homeKey/${reg.userId}").getItem(note)).doc
        // A lock fell after the item was saved and before its kept save was let go.
        assertTrue(PendingSaves(pendingLog, pendingFiles) { true }.keep(enrolled.account, PendingSave("p-1", null, note, reg.personalVault.vaultId, 0, doc, doc.attachments.map { it.id })))
        controller.lock()
        val pushes = calls.count { it.endsWith("/sync/push") }
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { pendingLog.bytes == null }
        assertEquals(pushes, calls.count { it.endsWith("/sync/push") }, "nothing was sent")
        assertEquals(listOf("Lease"), controller.state.items.map { it.name }.filter { it.startsWith("Lease") }, "and no copy was made")
    }

    @Test
    fun aFileLargerThanThisAppOpensIsNotDownloaded() = test {
        unlockedWithAPersonalVault()
        val big = io.silencelen.andvari.core.client.AttachmentRef("00000000-0000-4000-8000-0000000000f1", "video.mov", AttachmentRules.MAX_FILE_BYTES + 1, "k")
        val doc = ItemDoc(type = "note", name = "Video", attachments = listOf(big))
        val upload = enrolled.account.encryptItem(reg.personalVault.vaultId, NOTE_ID, doc)
        namespaces.caches.getValue("$homeKey/${reg.userId}").upsertItem(WireItem(NOTE_ID, reg.personalVault.vaultId, 1, 1_000, 2_000, false, false, upload.formatVersion, emptyList(), upload.blob), null)
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(listOf(AttachmentView(big.id, "video.mov", big.size)), controller.itemDetail(NOTE_ID)?.attachments)
        val read = controller.readAttachment(NOTE_ID, big.id)
        assertNull(read.bytes)
        assertEquals(AttachmentCopy.FILE_TOO_LARGE_TO_OPEN, read.error)
        assertTrue(calls.none { it.contains("/attachments/") }, "nothing was downloaded")
        assertEquals(AttachmentCopy.FILE_GONE, controller.readAttachment(NOTE_ID, "00000000-0000-4000-8000-0000000000f2").error)
        controller.lock()
        val locked = controller.readAttachment(NOTE_ID, big.id)
        assertTrue(locked.bytes == null && locked.error == null, "locked: nothing, and nothing to say")
    }

    @Test
    fun keptSavesFollowThePolicyAndGoWithTheAccount() = test {
        var durable = true
        val log = InMemoryFillSnapshots()
        val blobs = InMemoryBlobs()
        val saves = PendingSaves(log, blobs) { durable }
        val doc = ItemDoc(type = "note", name = "Lease")
        assertTrue(saves.keep(enrolled.account, PendingSave("p-1", null, "n-1", "v", 0, doc, listOf("f-1"))))
        assertTrue(saves.putBlob("f-1", byteArrayOf(1, 2, 3)))
        assertNotNull(log.bytes, "on disk while the policy allows an offline cache")
        durable = false
        assertTrue(saves.keep(enrolled.account, PendingSave("p-2", null, "n-2", "v", 0, doc, listOf("f-2"))))
        assertTrue(saves.putBlob("f-2", byteArrayOf(4)))
        assertEquals(listOf("p-1", "p-2"), saves.load(enrolled.account).map { it.id }, "only in memory otherwise; one kept before stays found")
        assertContentEquals(byteArrayOf(1, 2, 3), saves.blob("f-1"), "with its file, wherever the policy put it (round-9 review 8)")
        assertEquals(listOf("f-1"), blobs.ids())
        // An open editor's file, set aside while the policy allowed it, named by no kept save yet.
        durable = true
        assertTrue(saves.putBlob("f-draft", byteArrayOf(7, 7)))
        durable = false
        // The policy forbids it: what was on disk moves into memory, files and all (the editor's too: round-11 review),
        // and the disk is emptied.
        assertEquals(1, saves.leaveDisk(enrolled.account))
        assertNull(log.bytes)
        assertTrue(blobs.ids().isEmpty())
        assertContentEquals(byteArrayOf(7, 7), saves.blob("f-draft"), "an open editor's file is moved, not dropped")
        assertEquals(setOf("p-1", "p-2"), saves.load(enrolled.account).map { it.id }.toSet(), "what is in memory stays while the account does")
        assertContentEquals(byteArrayOf(1, 2, 3), saves.blob("f-1"))
        saves.forget(enrolled.account, "p-1")
        saves.forget(enrolled.account, "p-2")
        assertNull(saves.blob("f-2"), "a save let go takes its files")
        assertTrue(saves.keep(enrolled.account, PendingSave("p-3", null, "n-3", "v", 0, doc, listOf("f-3"))))
        saves.dropAll()
        assertTrue(saves.load(enrolled.account).isEmpty())
        // The rig's sign-out takes them all.
        unlockedWithAPersonalVault()
        fileServer().fail = true
        controller.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, controller.addAttachment("a.pdf", ByteArray(500) { 1 }))
        assertIs<ActionResult.Failed>(controller.saveNote(null, NoteInput("Lease", "", false)))
        assertNotNull(pendingLog.bytes)
        assertEquals(ActionResult.Ok, controller.signOut())
        assertNull(pendingLog.bytes, "a sign-out takes what was kept")
        assertTrue(pendingFiles.ids().isEmpty())
    }

    /**
     * Round-9 review 3: a kept save finished after an edit made since (offline, still waiting to be sent, or already
     * synced) only adds its files to the item as it is now: the newer password survives, nothing becomes a conflict copy.
     */
    @Test
    fun aKeptSaveFinishedAfterANewerEditAddsOnlyItsFiles() = test {
        unlockedWithAPersonalVault()
        val files = fileServer()
        controller.openAttachmentDraft(ITEM_ID)
        assertEquals(ActionResult.Ok, controller.addAttachment("scan.pdf", ByteArray(900) { 7 }))
        val fileId = assertNotNull(controller.state.attachmentDraft).added.single().id
        files.gate = CompletableDeferred()
        files.started = CompletableDeferred()
        kotlinx.coroutines.coroutineScope {
            val save = async { controller.saveLogin(ITEM_ID, LoginInput("Example", "fam", "pw-in-the-kept-save", listOf("https://login.example.com/x"), "", "", false)) }
            withTimeout(10_000) { assertNotNull(files.started).await() }
            controller.lock()
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.NotDone(null), save.await())
        }
        files.gate = null
        assertNotNull(pendingLog.bytes, "the save with its file is kept")
        // Offline at the next unlock: the kept save cannot go, and the person edits the login meanwhile.
        files.fail = true
        val online = routes.getValue("/sync/push")
        routes["/sync/push"] = { throw IOException("unreachable") }
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.notice?.contains("has not been saved with its files yet") == true }
        assertEquals(ActionResult.Ok, controller.saveLogin(ITEM_ID, LoginInput("Example", "fam", "pw-newer", listOf("https://login.example.com/x"), "", "", false)))
        assertEquals(HouseholdCopy.SAVE_OFFLINE, controller.state.notice, "queued, to be sent later")
        // Back online: the next unlock finishes the kept save.
        files.fail = false
        routes["/sync/push"] = online
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { pendingLog.bytes == null && controller.state.upload == null }
        assertEquals("pw-newer", controller.revealSecret(ITEM_ID, SecretField.PASSWORD), "the newer edit stands")
        assertEquals(listOf(fileId), controller.itemDetail(ITEM_ID)?.attachments?.map { it.id }, "and the file is on it")
        assertTrue(controller.state.items.none { it.name.contains("conflict") }, "no conflict copy")
        assertEquals(AttachmentCopy.filesOnly("Example"), controller.state.notice)
    }

    /**
     * Round-10 review 5: a kept save is judged against the item as the server has it after a pull, not a cache an offline
     * unlock left as it was. Here the unlock's own pull fails, the kept save's pull then brings another device's newer
     * edit, and only the save's new file goes onto it: the file the save took off stays, as the notice says.
     */
    @Test
    fun aKeptSaveIsJudgedAfterAPullAndKeepsTheFilesItTookOffWhenOnlyItsFilesGo() = test {
        unlockedWithAPersonalVault()
        val files = fileServer()
        controller.openAttachmentDraft(ITEM_ID)
        assertEquals(ActionResult.Ok, controller.addAttachment("old.pdf", ByteArray(300) { 1 }))
        assertEquals(ActionResult.Ok, controller.saveLogin(ITEM_ID, LoginInput("Example", "fam", "hunter2", listOf("https://login.example.com/x"), "", "", false)))
        controller.closeAttachmentDraft()
        val old = assertNotNull(controller.itemDetail(ITEM_ID)).attachments.single().id
        // Another item is saved after it, so the server's counter is past the revision the other device's edit gets below.
        assertEquals(ActionResult.Ok, controller.saveNote(null, NoteInput("Other", "", false)))
        // An edit takes that file off and adds another; a lock cuts its save short.
        controller.openAttachmentDraft(ITEM_ID)
        controller.removeAttachment(old)
        assertEquals(ActionResult.Ok, controller.addAttachment("new.pdf", ByteArray(400) { 2 }))
        val new = assertNotNull(controller.state.attachmentDraft).added.single().id
        files.gate = CompletableDeferred()
        files.started = CompletableDeferred()
        kotlinx.coroutines.coroutineScope {
            val save = async { controller.saveLogin(ITEM_ID, LoginInput("Example", "fam", "pw-in-the-kept-save", listOf("https://login.example.com/x"), "", "", false)) }
            withTimeout(10_000) { assertNotNull(files.started).await() }
            controller.lock()
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.NotDone(null), save.await())
        }
        files.gate = null
        // Another device changed the login meanwhile. The unlock's own pull fails; the next one brings that edit.
        val cached = assertNotNull(namespaces.caches.getValue("$homeKey/${reg.userId}").getItem(ITEM_ID))
        val elsewhere = cached.doc.copy(login = cached.doc.login!!.copy(password = "pw-elsewhere"))
        val sealedElsewhere = enrolled.account.encryptItem(reg.personalVault.vaultId, ITEM_ID, elsewhere)
        val newer = WireItem(ITEM_ID, reg.personalVault.vaultId, cached.rev + 1, 1_000, 9_000, false, false, sealedElsewhere.formatVersion, listOf(old), sealedElsewhere.blob)
        val sync = routes.getValue("/sync")
        var pulls = 0
        routes["/sync"] = { request ->
            when (++pulls) {
                1 -> throw IOException("unreachable")
                2 -> {
                    val body = io.silencelen.andvari.core.model.SyncResponse(newer.rev, false, emptyList(), emptyList(), listOf(newer), emptyList())
                    respond(json.encodeToString(io.silencelen.andvari.core.model.SyncResponse.serializer(), body), HttpStatusCode.OK, headers)
                }
                else -> sync(request)
            }
        }
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { pendingLog.bytes == null && controller.state.upload == null }
        assertTrue(pulls >= 2, "the kept save pulled before it decided")
        assertEquals("pw-elsewhere", controller.revealSecret(ITEM_ID, SecretField.PASSWORD), "the newer edit stands")
        assertEquals(listOf(old, new), controller.itemDetail(ITEM_ID)?.attachments?.map { it.id }, "the new file is added; the one the save took off stays")
        assertEquals(AttachmentCopy.filesOnly("Example", removalsNotKept = true), controller.state.notice)
        assertTrue(assertNotNull(controller.state.notice).endsWith("the files it took off are still in the item."))
    }

    /**
     * Round-10 review 2, round-11 review: a policy that forbids keeping data, seen while locked (the probe at launch or on
     * the way back), cannot open the kept saves, so nothing moves yet: the sealed record and the files stay on disk until
     * the next unlock, which moves them into memory and says so. A copy in memory only would be lost if the system ended
     * the process first; a copy is taken only as a cache, used should the disk's be gone by the unlock. Nothing is swept
     * or deleted unseen.
     */
    @Test
    fun aForbiddingPolicySeenWhileLockedKeepsKeptSavesOnDiskUntilTheUnlockMovesThem() = test {
        var durable = true
        val log = InMemoryFillSnapshots()
        val blobs = InMemoryBlobs()
        val saves = PendingSaves(log, blobs) { durable }
        val doc = ItemDoc(type = "note", name = "Lease")
        assertTrue(saves.keep(enrolled.account, PendingSave("p-1", null, "n-1", "v", 0, doc, listOf("f-1"))))
        assertTrue(saves.putBlob("f-1", byteArrayOf(1, 2, 3)))
        assertTrue(saves.putBlob("f-orphan", byteArrayOf(9)))
        durable = false
        assertEquals(0, saves.leaveDisk(null), "locked: nothing can be opened, so nothing is counted yet")
        assertNotNull(log.bytes, "the record stays on disk until the unlock")
        assertEquals(setOf("f-1", "f-orphan"), blobs.ids().toSet(), "and so do the files")
        assertContentEquals(byteArrayOf(1, 2, 3), saves.blob("f-1"))

        // The system ends the process before the unlock: the next one finds everything on disk, and its own probe and
        // unlock move it.
        val next = PendingSaves(log, blobs) { durable }
        assertEquals(0, next.leaveDisk(null))
        next.sweep(enrolled.account, emptySet())
        assertNotNull(next.blob("f-orphan"), "nothing is swept before the unlock opens the record that names them")
        val found = next.unlocked(enrolled.account)
        assertEquals(1, found.movedToMemory)
        assertEquals(0, found.unreadable)
        assertNull(log.bytes, "moved at the unlock")
        assertTrue(blobs.ids().isEmpty())
        assertEquals(listOf("p-1"), next.load(enrolled.account).map { it.id })
        next.sweep(enrolled.account, emptySet())
        assertNull(next.blob("f-orphan"), "an orphan goes once the record is open")
        assertContentEquals(byteArrayOf(1, 2, 3), next.blob("f-1"))
        assertEquals(0, next.unlocked(enrolled.account).movedToMemory, "said once")

        // Should the disk's record be gone by the unlock, the copy taken while locked is what is opened.
        durable = true
        val log3 = InMemoryFillSnapshots()
        val blobs3 = InMemoryBlobs()
        val again = PendingSaves(log3, blobs3) { durable }
        assertTrue(again.keep(enrolled.account, PendingSave("p-3", null, "n-3", "v", 0, doc, listOf("f-3"))))
        assertTrue(again.putBlob("f-3", byteArrayOf(3)))
        durable = false
        again.leaveDisk(null)
        log3.delete()
        assertEquals(1, again.unlocked(enrolled.account).movedToMemory)
        assertEquals(listOf("p-3"), again.load(enrolled.account).map { it.id })
        assertContentEquals(byteArrayOf(3), again.blob("f-3"))

        // The policy allows keeping data again by the unlock: what is on disk stays there.
        durable = true
        val log4 = InMemoryFillSnapshots()
        val stays = PendingSaves(log4, InMemoryBlobs()) { durable }
        assertTrue(stays.keep(enrolled.account, PendingSave("p-4", null, "n-4", "v", 0, doc, emptyList())))
        stays.leaveDisk(null)
        assertEquals(0, stays.unlocked(enrolled.account).movedToMemory)
        assertNotNull(log4.bytes)

        // A sign-out takes everything, the copies too.
        durable = false
        stays.leaveDisk(null)
        stays.dropAll()
        assertNull(log4.bytes)
        assertEquals(0, stays.unlocked(enrolled.account).movedToMemory)
    }

    /** The same through the app: the probe on the way back finds the policy forbidding, and the unlock says what it kept. */
    @Test
    fun aKeptSaveOutlivesAForbiddingPolicySeenWhileLockedAndTheUnlockSaysSo() = test {
        unlockedWithAPersonalVault()
        val files = fileServer()
        controller.openAttachmentDraft(null)
        assertEquals(ActionResult.Ok, controller.addAttachment("scan.pdf", ByteArray(5_000) { 3 }))
        val fileId = assertNotNull(controller.state.attachmentDraft).added.single().id
        files.gate = CompletableDeferred()
        files.started = CompletableDeferred()
        kotlinx.coroutines.coroutineScope {
            val save = async { controller.saveLogin(null, LoginInput("Bank", "me", "pw", listOf("https://bank.example"), "", "", false)) }
            withTimeout(10_000) { assertNotNull(files.started).await() }
            controller.lock()
            assertNotNull(files.gate).complete(Unit)
            assertEquals(ActionResult.NotDone(null), save.await())
        }
        files.gate = null
        assertNotNull(pendingLog.bytes)
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(offlineCacheAllowed = false)), HttpStatusCode.OK, headers) }
        clocks.wall += 2 * 60 * MINUTE // the policy read last is stale
        controller.onForeground()
        settle { controller.state.policy?.offlineCacheAllowed == false } // the probe found the policy forbidding
        assertNotNull(pendingLog.bytes, "locked: the kept save stays on disk until the unlock moves it (round-11 review)")
        assertFalse(pendingFiles.ids().isEmpty(), "with its file")
        // The forbidding policy took the cached keys with it: they come from the server now.
        twoStepServer()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.items.any { it.name == "Bank" } && controller.state.upload == null && pendingFiles.ids().isEmpty() && pendingLog.bytes == null }
        assertTrue(seen.any { it.notice == AttachmentCopy.KEPT_IN_MEMORY }, "the unlock said the save is kept only in memory now")
        val bank = controller.state.items.single { it.name == "Bank" }
        assertEquals(listOf(fileId), controller.itemDetail(bank.itemId)?.attachments?.map { it.id }, "finished, with its file, under its id")
    }

    /**
     * Round-10 review 3: what an earlier version kept on this device, in records without this version's MAC, is not
     * dropped unsaid: one notice counts it (two saves with files, an entry of the list of automatic saves, and a kept
     * move that cannot be read at all).
     */
    @Test
    fun whatAnEarlierVersionKeptIsCountedInOneNoticeAtTheUnlock() = test {
        seedSession()
        fun earlier(plain: String) = crypto.sealTo(enrolled.account.identityPub, plain.encodeToByteArray())
        val doc = ItemDoc(type = "note", name = "Lease")
        val two = listOf(PendingSave("p-1", null, "n-1", "v", 0, doc, emptyList()), PendingSave("p-2", null, "n-2", "v", 0, doc, emptyList()))
        pendingLog.write(earlier(json.encodeToString(kotlinx.serialization.builtins.ListSerializer(PendingSave.serializer()), two)))
        appliedLog.write("[\"${Bytes.toB64(earlier("{}"))}\"]".encodeToByteArray())
        moveMemoLog.write(byteArrayOf(1, 2, 3))
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.notice == AttachmentCopy.earlierRecords(4) }
        assertNull(pendingLog.bytes, "removed, and said")
        assertNull(appliedLog.bytes)
        assertNull(moveMemoLog.bytes)
        assertTrue(assertNotNull(controller.state.notice).startsWith("4 things an earlier version of andvari kept on this device"))
        // Said once: the next unlock finds nothing more.
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        delay(100)
        assertNotEquals(AttachmentCopy.earlierRecords(4), controller.state.notice)
    }

    /** Round-9 review 1: a file is listed and opened under a name that is safe to show and to offer to Files. */
    @Test
    fun aFilesNameFromAnotherClientIsMadeSafeEverywhereItIsShown() = test {
        unlockedWithAPersonalVault()
        val evil = io.silencelen.andvari.core.client.AttachmentRef("00000000-0000-4000-8000-0000000000f3", "../../Library/Preferences/x\u202Egpj.plist", 10, "k")
        val doc = ItemDoc(type = "note", name = "Shared", attachments = listOf(evil))
        val upload = enrolled.account.encryptItem(reg.personalVault.vaultId, NOTE_ID, doc)
        namespaces.caches.getValue("$homeKey/${reg.userId}").upsertItem(WireItem(NOTE_ID, reg.personalVault.vaultId, 1, 1_000, 2_000, false, false, upload.formatVersion, emptyList(), upload.blob), null)
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(listOf("xgpj.plist"), controller.itemDetail(NOTE_ID)?.attachments?.map { it.name }, "the detail")
        controller.openAttachmentDraft(NOTE_ID)
        assertEquals(listOf("xgpj.plist"), controller.state.attachmentDraft?.kept?.map { it.name }, "the editor")
        assertEquals("xgpj.plist", controller.readAttachment(NOTE_ID, evil.id).name, "and what a preview and Save to Files get")
    }

    // ---- lifecycle notices ----

    @Test
    fun aChangeTheServerRefusedIsToldOnTheVaultScreenUntilDismissed() = test {
        unlockedWithAPersonalVault()
        // Saved offline; the server later refuses it for good.
        assertEquals(ActionResult.Ok, controller.saveLogin(null, LoginInput("Queued", "me", "pw", listOf("https://queued.example"), "", "", false)))
        assertTrue(controller.state.vaultNotices.isEmpty())
        routes["/sync/push"] = { request ->
            val body = json.decodeFromString(io.silencelen.andvari.core.model.PushRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            val results = body.mutations.map { io.silencelen.andvari.core.model.MutationResult(it.mutationId, "rejected", reason = "body_too_large") }
            respond(json.encodeToString(io.silencelen.andvari.core.model.PushResponse.serializer(), io.silencelen.andvari.core.model.PushResponse(5, results)), HttpStatusCode.OK, headers)
        }
        routes["/sync"] = { respond(EMPTY_SYNC, HttpStatusCode.OK, headers) }
        routes["/account/state"] = { respond("""{"sealedState":null,"seq":0}""", HttpStatusCode.OK, headers) }
        controller.refresh()
        val notice = controller.state.vaultNotices.singleOrNull()
        assertNotNull(notice, "the refusal is said on the vault screen")
        assertTrue(notice.warning)
        assertEquals(io.silencelen.andvari.core.client.HouseholdCopy.writeRejectedNotice(1, notice.text.substringAfter("“").substringBefore("”"), "body_too_large"), notice.text, "Android's sentence, word for word")
        controller.dismissVaultNotice(notice.id)
        assertTrue(controller.state.vaultNotices.isEmpty())
    }

    // ---- deleting the account ----

    /**
     * Settings › Delete account (spec 03 §13): what goes and what stands in the way, from the server's preview, with a
     * kind this version does not know listed rather than dropped; the address and the master password checked here first
     * (a wrong one is never sent); a refusal for blockers shows the server's; an answer that says nothing is never taken
     * for "deleted" or "not deleted"; and once the server deleted the account, this device keeps nothing of it.
     */
    @Test
    fun deletingTheAccountShowsWhatGoesThenLeavesNothingOfItOnThisDevice() = test {
        unlockedWithAPersonalVault()
        twoStepServer() // the account's keys as the server serves them: what the master password is proved against
        var blockers = listOf(io.silencelen.andvari.core.model.AccountDeleteBlocker("shared_vault", "00000000-0000-4000-8000-0000000000f1", 2), io.silencelen.andvari.core.model.AccountDeleteBlocker("future_kind"))
        var fail502 = false
        val sent = mutableListOf<io.silencelen.andvari.core.model.AccountDeleteRequest>()
        routes["/account/delete/preview"] = {
            val p = io.silencelen.andvari.core.model.AccountDeletePreview(blockers, deletedVaults = listOf(reg.personalVault.vaultId), leftVaults = listOf("00000000-0000-4000-8000-0000000000f2"), totpRequired = true)
            respond(json.encodeToString(io.silencelen.andvari.core.model.AccountDeletePreview.serializer(), p), HttpStatusCode.OK, headers)
        }
        routes["/account/delete"] = { request ->
            val req = json.decodeFromString(io.silencelen.andvari.core.model.AccountDeleteRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            sent += req
            when {
                fail502 -> respond("bad gateway", HttpStatusCode.BadGateway, headersOf(HttpHeaders.ContentType, "text/plain"))
                blockers.isNotEmpty() -> respond(
                    json.encodeToString(io.silencelen.andvari.core.model.AccountDeleteBlockedError.serializer(), io.silencelen.andvari.core.model.AccountDeleteBlockedError("account_delete_blocked", "blocked", blockers)),
                    HttpStatusCode.Conflict, headers,
                )
                req.totp != "123456" -> respond("""{"error":"bad_totp_code","message":"no"}""", HttpStatusCode.BadRequest, headers)
                else -> respond("""{"deletedAt":5000}""", HttpStatusCode.OK, headers)
            }
        }
        assertEquals(ActionResult.Ok, controller.openAccountDeletion())
        val open = assertNotNull(controller.state.accountDeletion)
        assertEquals(EMAIL, open.email)
        val preview = assertNotNull(open.preview)
        assertTrue(preview.totpRequired)
        assertEquals(listOf(DeletionCopy.blocker("shared_vault", null, 2), DeletionCopy.blocker("future_kind", null, 0)), preview.blockers, "an unknown kind is listed, never dropped")
        assertTrue(preview.deleted.any { it.startsWith("Your Personal vault") })
        assertEquals(DeletionCopy.leaves(listOf(null)), preview.left)

        // Checked here first, and nothing sent: the address, the code the account needs, the master password.
        assertEquals(ActionResult.Failed(DeletionCopy.EMAIL_MISMATCH), controller.deleteAccount("someone@example.com", PASSWORD, "123456"))
        assertEquals(ActionResult.Failed(DeletionCopy.CODE_REQUIRED), controller.deleteAccount(EMAIL, PASSWORD, " "))
        assertEquals(ActionResult.Failed(HouseholdCopy.REAUTH_FAILED), controller.deleteAccount(EMAIL, "not it", "123456"))
        assertTrue(sent.isEmpty(), "a wrong password never leaves this device")

        // Refused for blockers: the server's show, and nothing was deleted.
        assertEquals(ActionResult.Failed(DeletionCopy.BLOCKED), controller.deleteAccount(" $EMAIL ", PASSWORD, "123 456"))
        assertEquals(EMAIL, sent.single().confirmEmail)
        assertEquals("123456", sent.single().totp)
        assertEquals(AppScreen.VAULT, controller.state.screen)

        // No answer that says what happened: never "deleted" or "not deleted"; a check finds the account still here.
        fail502 = true
        assertEquals(ActionResult.Failed(DeletionCopy.OUTCOME_UNKNOWN), controller.deleteAccount(EMAIL, PASSWORD, "123456"))
        assertTrue(assertNotNull(controller.state.accountDeletion).outcomeUnknown)
        assertEquals(ActionResult.Ok, controller.checkAccountDeletion())
        assertFalse(assertNotNull(controller.state.accountDeletion).outcomeUnknown)
        assertEquals(DeletionCopy.NOT_DELETED_AFTER_CHECK, controller.state.notice)
        fail502 = false

        // The blockers resolved: a wrong code is refused, the right one deletes the account.
        blockers = emptyList()
        assertEquals(ActionResult.Failed(DeletionCopy.BAD_CODE), controller.deleteAccount(EMAIL, PASSWORD, "000000"))
        val namespace = "$homeKey/${reg.userId}"
        assertTrue(namespaces.devices.containsKey(namespace))
        assertNotNull(queue.key, "the save key the extensions seal to")
        assertEquals(ActionResult.Ok, controller.deleteAccount(EMAIL, PASSWORD, "123456"))
        assertEquals(AppScreen.CHOOSE_SERVER, controller.state.screen)
        assertEquals(DeletionCopy.deleted(EMAIL), controller.state.notice)
        assertNull(controller.state.accountDeletion)
        assertNull(store.load(), "no session and no tokens")
        assertTrue(namespace in namespaces.deleted, "the vault cache")
        assertFalse(namespaces.devices.containsKey(namespace), "the device state")
        assertTrue(quickKeys.wiped.isNotEmpty(), "quick unlock")
        assertNull(queue.key, "the save queue and its key")
        assertNull(store.origin(homeKey).loadAccountKeys(reg.userId), "the account's keys")
    }

    /** A server that previews and deletes the account without blockers; [during] runs while the delete request is out. */
    private fun Rig.deletingServer(during: () -> Unit = {}) {
        routes["/account/delete/preview"] = {
            val p = io.silencelen.andvari.core.model.AccountDeletePreview(emptyList(), deletedVaults = listOf(reg.personalVault.vaultId), leftVaults = emptyList(), totpRequired = true)
            respond(json.encodeToString(io.silencelen.andvari.core.model.AccountDeletePreview.serializer(), p), HttpStatusCode.OK, headers)
        }
        routes["/account/delete"] = {
            during()
            respond("""{"deletedAt":5000}""", HttpStatusCode.OK, headers)
        }
    }

    /**
     * A deletion the server confirmed forgets the account's identity records here too (the user-id-keyed one, and the
     * address's binding that names it), so the same address can register again on this device. Before, the binding
     * stayed, and the next account under the address was held to the deleted one's key at its first unlock.
     */
    @Test
    fun aConfirmedDeletionForgetsTheAccountsIdentityRecordsSoItsAddressCanRegisterAgain() = test {
        unlockedWithAPersonalVault()
        twoStepServer()
        deletingServer()
        val remade = "00000000-0000-4000-8000-0000000000ab"
        assertNotNull(store.origin(homeKey).identityPins().pinFor(EMAIL, reg.userId), "recorded at the unlock")
        kotlin.test.assertFailsWith<io.silencelen.andvari.core.crypto.CryptoException>("the address is held to the deleted account") {
            store.origin(homeKey).identityPins().pinFor(EMAIL, remade)
        }
        assertEquals(ActionResult.Ok, controller.openAccountDeletion())
        assertEquals(ActionResult.Ok, controller.deleteAccount(EMAIL, PASSWORD, "123456"))
        assertNull(store.origin(homeKey).identityPins().pinFor(EMAIL, remade), "a remade account under the address is not held to the deleted one")
        assertNull(store.origin(homeKey).identityPins().pinFor(EMAIL, reg.userId))
    }

    /**
     * A deletion the server confirmed while something else ended the session here (a lock, a rejection heard by another
     * request) still leaves nothing of the account on this device. Before, the answer was dropped and everything of the
     * deleted account stayed.
     */
    @Test
    fun aConfirmedDeletionWipesTheAccountAlsoWhenTheSessionEndedWhileTheRequestWasOut() = test {
        unlockedWithAPersonalVault()
        twoStepServer()
        deletingServer(during = { controller.lock() })
        val namespace = "$homeKey/${reg.userId}"
        assertTrue(namespaces.devices.containsKey(namespace))
        assertEquals(ActionResult.Ok, controller.openAccountDeletion())
        assertEquals(ActionResult.Ok, controller.deleteAccount(EMAIL, PASSWORD, "123456"))
        assertEquals(AppScreen.CHOOSE_SERVER, controller.state.screen)
        assertEquals(DeletionCopy.deleted(EMAIL), controller.state.notice)
        assertNull(store.load(), "no session and no tokens")
        assertTrue(namespace in namespaces.deleted, "the vault cache")
        assertFalse(namespaces.devices.containsKey(namespace), "the device state")
        assertNull(store.origin(homeKey).loadAccountKeys(reg.userId), "the account's keys")
        assertNull(store.origin(homeKey).identityPins().pinFor(EMAIL, "00000000-0000-4000-8000-0000000000ab"))
    }

    /**
     * After a confirmed deletion the device is as new for the deleted account's server: the store forgets the server it
     * dials (its address goes with the session), so the next launch starts at the first screen. Before, only the session
     * was cleared and the address stayed.
     */
    @Test
    fun aConfirmedDeletionLeavesTheDeviceAsNewForItsServer() = test {
        unlockedWithAPersonalVault()
        twoStepServer()
        deletingServer()
        assertEquals(ActionResult.Ok, controller.openAccountDeletion())
        assertEquals(ActionResult.Ok, controller.deleteAccount(EMAIL, PASSWORD, "123456"))
        assertNull(store.baseUrl, "the server's address went")
        assertNull(store.load())
        assertEquals(AppScreen.CHOOSE_SERVER, controller.state.screen)
    }

    /**
     * The wipe after a confirmed deletion works under the session's own origin, also where the origin the store dials
     * differs from it by then: the deleted account's records under its own server go, and nothing is wiped under the
     * other one. Before, the wipe read the store's origin and worked under the other server's key.
     */
    @Test
    fun aConfirmedDeletionWipesUnderTheSessionsOwnOriginWhereTheStoreDialsAnother() = test {
        unlockedWithAPersonalVault()
        twoStepServer()
        val other = "https://other.example"
        deletingServer(during = { store.moveOrigin(other) })
        val namespace = "$homeKey/${reg.userId}"
        val otherKey = OriginCanon.originKey(other)
        assertTrue(namespaces.devices.containsKey(namespace))
        assertEquals(ActionResult.Ok, controller.openAccountDeletion())
        assertEquals(ActionResult.Ok, controller.deleteAccount(EMAIL, PASSWORD, "123456"))
        assertEquals(other, store.baseUrl, "the store dials the other origin")
        assertTrue(namespace in namespaces.deleted, "the vault cache under the session's own origin")
        assertFalse(namespaces.devices.containsKey(namespace), "the device state")
        assertNull(store.origin(homeKey).loadAccountKeys(reg.userId), "the account's keys")
        assertNull(store.origin(homeKey).identityPins().pinFor(EMAIL, "00000000-0000-4000-8000-0000000000ab"), "the identity records")
        assertTrue(namespaces.deleted.none { it.startsWith("$otherKey/") }, "nothing under the other origin")
    }

    // ---- vault health ----

    /**
     * Vault health (the Android app's screen, core's rules): weak and reused passwords; a breach check that sends only
     * 5-character hash prefixes, one request per range, and keeps no verdict for a range that failed or a login changed
     * since; copies merged, or one kept with the other's password in its history; and a check run that writes only the
     * verdict a person gives, offering the trash for a login that is gone. A lock forgets it all.
     */
    @Test
    fun vaultHealthChecksBreachesByPrefixCleansUpCopiesAndRecordsOnlyWhatThePersonSays() = test {
        unlockedWithAPersonalVault()
        onlineServer()
        for (input in listOf(
            LoginInput("Bank", "me", "Brisk-Otter-Lamp-41", listOf("https://bank.example"), "", "", false),
            LoginInput("Bank again", "me", "Brisk-Otter-Lamp-41", listOf("https://bank.example/login"), "", "", false),
            LoginInput("Shop", "sam", "Quiet-Maple-Door-73", listOf("https://shop.example"), "", "", false),
            LoginInput("Shop old", "sam", "Older-Pine-Gate-19", listOf("https://shop.example"), "", "", false),
            LoginInput("Forum", "fam", "hunter2", listOf("https://forum.example"), "", "", false),
        )) assertEquals(ActionResult.Ok, controller.saveLogin(null, input))
        val hibp = io.silencelen.andvari.core.crypto.Hibp
        val breached = hibp.sha1UpperHex(crypto, "hunter2")
        val unreachable = hibp.prefix(hibp.sha1UpperHex(crypto, "Quiet-Maple-Door-73"))
        val asked = mutableListOf<String>()
        prefixRoutes["/api/v1/hibp/range/"] = { request ->
            val prefix = request.url.encodedPath.substringAfterLast('/')
            asked += prefix
            if (prefix == unreachable) throw IOException("unreachable")
            val body = if (prefix == hibp.prefix(breached)) "${hibp.suffix(breached)}:4200\r\n00000000000000000000000000000000000:3" else "00000000000000000000000000000000000:1"
            respond(body, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "text/plain"))
        }

        controller.openHealth()
        val opened = assertNotNull(controller.state.health)
        assertEquals(6, opened.tiles.logins, "the five saved here and the one the cache held")
        assertNull(opened.tiles.breached, "never checked is not none")
        assertEquals(HealthCopy.RUN_A_SCAN, opened.tiles.breachedHint)
        val forum = opened.passwords.single { it.name == "Forum" }
        assertTrue(forum.weak)
        assertEquals(1, forum.reused, "the cached login has the same password")
        assertNull(forum.breaches)
        val exact = opened.duplicates.single { it.exact }
        val differs = opened.duplicates.single { !it.exact }
        assertEquals(setOf("Bank", "Bank again"), exact.members.map { it.name }.toSet())
        assertNotNull(exact.mergeConfirm)
        assertNull(exact.mergeRefusal)
        assertEquals(setOf("Shop", "Shop old"), differs.members.map { it.name }.toSet())
        assertEquals(6, opened.tiles.unchecked)
        assertTrue(opened.staleness.all { it.neverChecked })

        assertEquals(ActionResult.Ok, controller.checkBreaches())
        val checked = assertNotNull(controller.state.health)
        assertNull(checked.scan)
        assertTrue(checked.scanned)
        assertEquals(HealthCopy.SCAN_INCOMPLETE, checked.message)
        assertTrue(asked.isNotEmpty() && asked.all { it.length == 5 }, "only 5 hex characters of a hash leave the device")
        assertEquals(asked.size, asked.toSet().size, "each range is asked for once")
        assertTrue(asked.size <= 4, "one request per range, for 4 distinct passwords")
        assertEquals(4200L, checked.passwords.single { it.name == "Forum" }.breaches)
        assertEquals(4200L, checked.passwords.single { it.name == "Example" }.breaches)
        assertEquals(0L, checked.passwords.single { it.name == "Bank" }.breaches)
        assertNull(checked.passwords.single { it.name == "Shop" }.breaches, "its range failed: no verdict, never none")
        assertEquals(2, checked.tiles.breached)
        assertEquals(HealthCopy.INCOMPLETE, checked.tiles.breachedHint)

        // Copies with the same password merge into one; the survivor changed, so its verdict is retired.
        assertEquals(ActionResult.Ok, controller.mergeDuplicates(exact.signature))
        val merged = assertNotNull(controller.state.health)
        assertEquals(HealthCopy.merged(1), merged.message)
        assertTrue(merged.duplicates.none { it.exact })
        val survivor = controller.state.items.single { it.name.startsWith("Bank") }
        assertNull(merged.passwords.single { it.itemId == survivor.itemId }.breaches, "changed since the check")
        assertEquals(ActionResult.Failed(HealthCopy.GROUP_CHANGED), controller.mergeDuplicates(exact.signature), "the group is gone")

        // Copies with different passwords: one is kept, and the other's password goes into its history first.
        val shop = differs.members.single { it.name == "Shop" }
        assertNull(shop.keepRefusal)
        assertNotNull(shop.keepConfirm)
        assertEquals(ActionResult.Ok, controller.keepDuplicate(differs.signature, shop.itemId))
        assertEquals(HealthCopy.kept(1), controller.state.health?.message)
        assertTrue(controller.state.items.none { it.name == "Shop old" })
        assertEquals(1, assertNotNull(controller.itemDetail(shop.itemId)).previousPasswords)

        // The check run: a person signs in themselves and says what happened; only that verdict is written.
        controller.startCheckRun(neverCheckedOnly = true)
        val first = assertNotNull(controller.state.health?.run)
        assertEquals(1, first.position)
        assertEquals(4, first.total, "the never-checked logins left")
        assertEquals(ActionResult.Failed(HealthCopy.CHOOSE_RESULT), controller.recordCheck(first.itemId, "maybe"))
        assertEquals(first.itemId, controller.state.health?.run?.itemId, "a refusal keeps the run where it is")
        assertEquals(ActionResult.Ok, controller.recordCheck(first.itemId, "ok"))
        assertNull(controller.state.health?.message)
        assertEquals(2, controller.state.health?.run?.position)
        controller.skipCheck()
        val third = assertNotNull(controller.state.health?.run)
        assertEquals(3, third.position)
        assertEquals(ActionResult.Ok, controller.recordCheck(third.itemId, "gone"))
        assertEquals(third.itemId, controller.state.health?.offerDelete?.itemId, "gone offers the trash")
        assertEquals(ActionResult.Ok, controller.trashGoneLogin())
        assertEquals(HealthCopy.TRASHED, controller.state.health?.message)
        assertNull(controller.state.health?.offerDelete)
        assertTrue(controller.state.items.none { it.itemId == third.itemId })
        val fourth = assertNotNull(controller.state.health?.run)
        assertEquals(ActionResult.Ok, controller.recordCheck(fourth.itemId, "blocked"))
        assertNull(controller.state.health?.run)
        assertEquals(HealthCopy.RUN_FINISHED, controller.state.health?.message)
        val after = assertNotNull(controller.state.health)
        assertTrue(after.staleness.none { it.itemId == fourth.itemId }, "couldn't finish: snoozed, off the list")
        assertEquals("Checked recently: it worked", after.staleness.single { it.itemId == first.itemId }.state)
        controller.setHealthShowSnoozed(true)
        assertTrue(assertNotNull(controller.state.health).staleness.single { it.itemId == fourth.itemId }.snoozed)
        assertEquals(ActionResult.Ok, controller.unsnoozeLogin(fourth.itemId))
        assertEquals(HealthCopy.BACK_ON_THE_LIST, controller.state.health?.message)
        assertFalse(assertNotNull(controller.state.health).staleness.single { it.itemId == fourth.itemId }.snoozed)

        controller.lock()
        assertNull(controller.state.health)
    }

    // ---- importing a CSV export ----

    /**
     * A CSV export is parsed and planned on this device against the items already in the vault (a login already there is
     * skipped, a duplicate in the file merged, a row that can't be read named); nothing is sent until Import, and an
     * interrupted import is finished by Retry with the same items under the same ids. The file's bytes are zeroed once read.
     */
    @Test
    fun aCsvExportIsPlannedAgainstTheVaultThenImportedIntoItOnce() = test {
        unlockedWithAPersonalVault()
        // A server holding the personal vault's row, as a synced device sees it, and the items pushed to it.
        val server = VaultServer(this)
        val rows = mutableListOf<WireItem>()
        val sent = mutableListOf<List<String>>()
        val applying: suspend MockRequestHandleScope.(HttpRequestData) -> HttpResponseData = { request ->
            val body = json.decodeFromString(io.silencelen.andvari.core.model.PushRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            sent += body.mutations.map { it.itemId }
            val results = body.mutations.map { m ->
                val rev = ++server.rev
                rows.removeAll { it.itemId == m.itemId }
                val up = m.item
                rows += WireItem(m.itemId, m.vaultId, rev, 3_000, 3_000, deleted = up == null, conflict = false, formatVersion = up?.formatVersion ?: 1, attachmentIds = up?.attachmentIds.orEmpty(), blob = up?.blob)
                io.silencelen.andvari.core.model.MutationResult(m.mutationId, "applied", newItemRev = rev)
            }
            respond(json.encodeToString(io.silencelen.andvari.core.model.PushResponse.serializer(), io.silencelen.andvari.core.model.PushResponse(server.rev, results)), HttpStatusCode.OK, headers)
        }
        routes["/sync/push"] = applying
        routes["/sync"] = { request ->
            val since = request.url.parameters["since"]?.toLongOrNull() ?: 0L
            val body = io.silencelen.andvari.core.model.SyncResponse(++server.rev, since == 0L, server.vaults.values.toList(), server.grants.values.toList(), rows.filter { it.rev > since }, emptyList())
            respond(json.encodeToString(io.silencelen.andvari.core.model.SyncResponse.serializer(), body), HttpStatusCode.OK, headers)
        }
        assertEquals(ActionResult.Ok, controller.refresh())
        val unrecognized = "hello,world\n1,2\n".encodeToByteArray()
        assertEquals(ActionResult.Failed(ImportCopy.UNRECOGNIZED), controller.importCsv(unrecognized))
        assertNull(controller.state.csvImport)

        val file = (
            "name,url,username,password,note\n" +
                "Example,https://login.example.com/x,fam,hunter2,\n" +
                "Bank,https://bank.example,me,Brisk-Otter-Lamp-41,\n" +
                "Bank,https://bank.example,me,Brisk-Otter-Lamp-41,\n" +
                "Mail,https://mail.example,me@mail,Quiet-Maple-Door-73,\n" +
                ",,,,\n" +
                "Broken,https://broken.example,me\n"
            ).encodeToByteArray()
        val pushes = calls.count { it.endsWith("/sync/push") }
        assertEquals(ActionResult.Ok, controller.importCsv(file))
        assertTrue(file.all { it == 0.toByte() }, "the file's bytes are zeroed once read")
        val preview = assertNotNull(controller.state.csvImport)
        assertEquals("Chrome or another Chromium browser", preview.source)
        assertEquals(reg.personalVault.vaultId, preview.vaultId)
        assertEquals(2, preview.toImport, "Bank once, and Mail")
        assertEquals(listOf("Example"), preview.buckets.single { it.title == ImportCopy.ALREADY }.names)
        assertTrue(ImportCopy.collapsed(1) in preview.counts)
        assertTrue(preview.errors.single().endsWith(": the wrong number of fields"))
        assertNull(preview.done)
        assertEquals(pushes, calls.count { it.endsWith("/sync/push") }, "nothing is sent before Import")

        // Interrupted: the items stay planned, and Retry sends the same ones again.
        routes["/sync/push"] = { throw IOException("unreachable") }
        assertEquals(ActionResult.Ok, controller.confirmImport())
        val interrupted = assertNotNull(controller.state.csvImport)
        assertEquals(ImportCopy.INTERRUPTED, interrupted.error)
        assertTrue(interrupted.retryable)
        assertNull(interrupted.done)
        routes["/sync/push"] = applying
        assertEquals(ActionResult.Ok, controller.confirmImport())
        val done = assertNotNull(controller.state.csvImport)
        assertNull(done.error)
        assertTrue(assertNotNull(done.done).startsWith("Added 2 items to “"))
        assertEquals(2, sent.flatten().toSet().size, "two items, each sent under its planned id")
        assertEquals(1, controller.state.items.count { it.name == "Bank" })
        assertEquals(1, controller.state.items.count { it.name == "Mail" })
        assertEquals(ActionResult.NotDone(null), controller.confirmImport(), "imported once")

        controller.closeImport()
        assertNull(controller.state.csvImport)
    }

    // ---- export and backup (spec 07) ----

    /** A server holding the personal vault's row and every item pushed to it, as a synced device sees them. */
    private fun Rig.syncedVaultServer(): VaultServer {
        val server = VaultServer(this)
        val rows = mutableListOf<WireItem>()
        routes["/sync/push"] = { request ->
            val body = json.decodeFromString(io.silencelen.andvari.core.model.PushRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            val results = body.mutations.map { m ->
                val rev = ++server.rev
                rows.removeAll { it.itemId == m.itemId }
                val up = m.item
                rows += WireItem(m.itemId, m.vaultId, rev, 3_000, 3_000, deleted = up == null, conflict = false, formatVersion = up?.formatVersion ?: 1, attachmentIds = up?.attachmentIds.orEmpty(), blob = up?.blob)
                io.silencelen.andvari.core.model.MutationResult(m.mutationId, "applied", newItemRev = rev)
            }
            respond(json.encodeToString(io.silencelen.andvari.core.model.PushResponse.serializer(), io.silencelen.andvari.core.model.PushResponse(server.rev, results)), HttpStatusCode.OK, headers)
        }
        routes["/sync"] = { request ->
            val since = request.url.parameters["since"]?.toLongOrNull() ?: 0L
            val body = io.silencelen.andvari.core.model.SyncResponse(++server.rev, since == 0L, server.vaults.values.toList(), server.grants.values.toList(), rows.filter { it.rev > since }, emptyList())
            respond(json.encodeToString(io.silencelen.andvari.core.model.SyncResponse.serializer(), body), HttpStatusCode.OK, headers)
        }
        return server
    }

    /**
     * Export for another password manager: a sync first, then what the CSV would hold, with what it leaves out named; a
     * cell a spreadsheet would run as a formula holds the file back until it is acknowledged, and the file is made only
     * for the folder chosen, as exactly the logins the screen counted.
     */
    @Test
    fun aCsvExportNamesWhatItLeavesOutAndIsMadeOnlyOnceTheFormulaCellsAreAcknowledged() = test {
        unlockedWithAPersonalVault()
        syncedVaultServer()
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.saveLogin(null, LoginInput("Sheet", "me", "=HYPERLINK(1)", listOf("https://sheet.example"), "", "", false)))
        assertEquals(ActionResult.Ok, controller.saveNote(null, NoteInput("Shopping", "milk", false)))
        assertEquals(ActionResult.Ok, controller.openExport(ExportKind.CSV))
        val screen = assertNotNull(controller.state.exporting)
        assertEquals(ExportKind.CSV, screen.kind)
        assertNull(screen.offlineNote, "the sync reached the server")
        assertTrue(screen.vaults.single().personal && screen.vaults.single().included)
        assertEquals(2, screen.count, "Example and Sheet")
        assertEquals(listOf("Shopping"), screen.warnings.single { it.title == ExportCopy.NOTES_LEFT_OUT }.names)
        assertEquals(listOf("Password of \u201CSheet\u201D"), screen.formulaCells)

        assertNull(controller.csvFile(acknowledged = false), "not without the tick")
        assertEquals(ExportCopy.FORMULA_ACK_NEEDED, controller.state.exporting?.error)
        val file = assertNotNull(controller.csvFile(acknowledged = true))
        assertTrue(Regex("andvari-export-\\d{4}-\\d{2}-\\d{2}\\.csv").matches(file.fileName), file.fileName)
        val text = file.bytes.decodeToString()
        assertTrue(text.startsWith(io.silencelen.andvari.core.client.ExportCsv.HEADER + "\r\n"))
        assertTrue(text.contains("Sheet,https://sheet.example,me,=HYPERLINK(1),"), "written as is, never mangled")
        assertFalse(text.contains("Shopping"))
        controller.exportSaved(file.fileName, "On My iPhone")
        assertEquals(ExportCopy.csvSaved(file.fileName, "On My iPhone", 2), controller.state.exporting?.done)

        // A vault that changed after the tick: nothing is made, and the screen lists the cells again.
        assertEquals(ActionResult.Ok, controller.saveLogin(null, LoginInput("Sum", "+SUM(A1)", "pw", emptyList(), "", "", false)))
        assertNull(controller.csvFile(acknowledged = true))
        val again = assertNotNull(controller.state.exporting)
        assertEquals(ExportCopy.VAULT_CHANGED, again.error)
        assertEquals(2, again.formulaCells.size)
        assertNotNull(controller.csvFile(acknowledged = true), "acknowledged again, for the cells now listed")
        controller.exportNotSaved(written = true)
        assertEquals(ExportCopy.READ_BACK_FAILED, controller.state.exporting?.error)

        controller.lock()
        assertNull(controller.state.exporting, "a lock closes the export screen")
    }

    /**
     * A backup is made in memory under a passphrase typed twice and at least "good", opened again before it is handed
     * over, and holds the vault's items; offline, the screen says it holds the vault as of the last sync.
     */
    @Test
    fun aBackupIsMadeUnderAGoodPassphraseAndOpensAgain() = test {
        unlockedWithAPersonalVault()
        syncedVaultServer()
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.saveNote(null, NoteInput("Shopping", "milk", false)))
        routes["/sync"] = { throw IOException("unreachable") }
        assertEquals(ActionResult.Ok, controller.openExport(ExportKind.BACKUP))
        val screen = assertNotNull(controller.state.exporting)
        assertNotNull(screen.offlineNote, "offline: the vault as of the last sync")
        assertEquals(2, screen.count, "Example and Shopping")

        val good = "Brisk-Otter-Lamp-41-Quiet-Maple"
        assertNull(controller.backupFile("", ""))
        assertEquals(ExportCopy.PASSPHRASE_REQUIRED, controller.state.exporting?.error)
        assertNull(controller.backupFile(good, good + "x"))
        assertEquals(ExportCopy.PASSPHRASES_DIFFER, controller.state.exporting?.error)
        assertNull(controller.backupFile("password", "password"))
        assertEquals(ExportCopy.PASSPHRASE_WEAK, controller.state.exporting?.error)

        val file = assertNotNull(controller.backupFile(good, good))
        assertTrue(file.fileName.startsWith("andvari-backup-") && file.fileName.endsWith(".andvari"))
        val opened = io.silencelen.andvari.core.client.Backup.open(crypto, good, file.bytes)
        assertEquals(setOf("Example", "Shopping"), opened.payload.items.map { it.doc.name }.toSet())
        assertEquals(reg.userId, opened.payload.userId)
        assertTrue(runCatching { io.silencelen.andvari.core.client.Backup.open(crypto, "Another-Passphrase-99-Long", file.bytes) }.isFailure, "only under its passphrase")
        controller.exportSaved(file.fileName, "iCloud Drive")
        assertEquals(ExportCopy.backupSaved(file.fileName, "iCloud Drive", 2, 1, 0), controller.state.exporting?.done)
        controller.closeExport()
        assertNull(controller.state.exporting)
    }

    // ---- vaults: where a new item goes, moving and copying ----

    @Test
    fun aNewItemGoesOnlyToAVaultThisAccountCanWriteAndAnEditStaysWhereItIs() = test {
        unlockedWithAPersonalVault()
        // The personal vault's row, as a sync delivers it (the rig's cache starts with items only).
        namespaces.caches.getValue("$homeKey/${reg.userId}").upsertVault(WireVault(reg.personalVault.vaultId, "personal", 1, reg.personalVault.metaBlob, 1_000))
        val vaults = controller.vaultsForNewItems()
        assertEquals(listOf(reg.personalVault.vaultId), vaults.map { it.vaultId })
        assertTrue(vaults.single().personal, "the personal vault, first, is the default")
        val elsewhere = "00000000-0000-4000-8000-0000000000e9"
        assertEquals(ActionResult.Failed(ItemCopy.VAULT_NOT_WRITABLE), controller.saveLogin(null, LoginInput("New", "me", "pw", listOf("https://new.example"), "", "", false), elsewhere))
        assertEquals(ActionResult.Failed(ItemCopy.VAULT_NOT_WRITABLE), controller.saveNote(null, NoteInput("Note", "text", false), elsewhere))
        assertTrue(controller.state.items.none { it.name == "New" || it.name == "Note" }, "nothing went anywhere")
        assertEquals(ActionResult.Ok, controller.saveNote(null, NoteInput("Note", "text", false), reg.personalVault.vaultId))
        assertEquals(reg.personalVault.vaultId, controller.itemDetail(controller.state.items.single { it.name == "Note" }.itemId)?.vaultId)
        // An edit never changes vault, whatever it names.
        assertEquals(ActionResult.Ok, controller.saveLogin(ITEM_ID, LoginInput("Example", "fam", "hunter2", listOf("https://login.example.com/x"), "", "", false), elsewhere))
        assertEquals(reg.personalVault.vaultId, controller.itemDetail(ITEM_ID)?.vaultId)
        // With no other vault there is nowhere to move or copy to, and nothing is attempted.
        assertTrue(controller.moveTargets(ITEM_ID).isEmpty())
        assertEquals(ActionResult.Failed(ItemCopy.VAULT_NOT_WRITABLE), controller.moveOrCopyItem(ITEM_ID, reg.personalVault.vaultId, move = false), "not into its own vault")
        assertEquals(ActionResult.Failed(ItemCopy.VAULT_NOT_WRITABLE), controller.moveOrCopyItem(ITEM_ID, elsewhere, move = true), "not into a vault this account cannot write")
        assertEquals(1, controller.state.items.count { it.itemId == ITEM_ID })
    }

    /**
     * A move's push legs as the server answers them: the copy ([put]) and the delete of the original ([delete]); every
     * mutation seen is kept in [pushed].
     */
    private fun Rig.moveServer(server: VaultServer, delete: String, pushed: MutableList<io.silencelen.andvari.core.model.Mutation>) {
        routes["/sync/push"] = { request ->
            val body = json.decodeFromString(io.silencelen.andvari.core.model.PushRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            pushed += body.mutations
            val results = body.mutations.map { io.silencelen.andvari.core.model.MutationResult(it.mutationId, if (it.op == "put") "applied" else delete, newItemRev = if (it.op == "put") ++server.rev else null) }
            respond(json.encodeToString(io.silencelen.andvari.core.model.PushResponse.serializer(), io.silencelen.andvari.core.model.PushResponse(++server.rev, results)), HttpStatusCode.OK, headers)
        }
    }

    /**
     * Round-6 review L5: a move whose copy was made but whose original could not be removed says so, naming the copy and
     * where it went; the unfinished try is kept, sealed, across a lock, so another try replays the same ids instead of a
     * second copy; Cancel lets it go.
     */
    @Test
    fun aMoveWhoseOriginalCouldNotBeRemovedSaysBothAreThereAndATryAfterALockMakesNoSecondCopy() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.createSharedVault("Family"))
        val family = controller.moveTargets(ITEM_ID).single()
        assertEquals("Family", family.name)
        assertTrue(controller.canMoveOut(ITEM_ID))
        val pushed = mutableListOf<io.silencelen.andvari.core.model.Mutation>()
        moveServer(server, delete = "denied", pushed)
        val expected = "Copied “Example” to “Family”, but the original couldn't be removed from “Personal” (your access there may have changed). It is in both vaults now."
        assertEquals(ActionResult.Failed(expected), controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        val copy = pushed.first { it.op == "put" }
        assertTrue(controller.state.items.any { it.itemId == copy.itemId }, "the copy is listed")
        assertTrue(controller.state.items.any { it.itemId == ITEM_ID }, "and so is the original")
        assertNotNull(moveMemoLog.bytes, "the unfinished try is kept, sealed")
        assertFalse(moveMemoLog.bytes!!.decodeToString().contains(copy.itemId), "sealed at rest")
        // A lock, then another try: the same gesture, so the same copy, never a second one.
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(ActionResult.Failed(expected), controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        assertEquals(setOf(copy.itemId), pushed.filter { it.op == "put" }.map { it.itemId }.toSet(), "one copy, whatever the tries")
        assertEquals(setOf(copy.mutationId), pushed.filter { it.op == "put" }.map { it.mutationId }.toSet(), "replayed under the same mutation id")
        // Cancel lets the try go: what it kept is removed.
        controller.cancelMove(ITEM_ID)
        assertNull(moveMemoLog.bytes)
    }

    /**
     * Round-7 review M3: after a move whose original could not be removed, the copy is deleted (here, or on another
     * device). Another try must not replay the kept gesture, whose copy leg the server would answer from its journal
     * without making the copy again, and then delete the only original: it finds the copy gone and mints a new one.
     */
    @Test
    fun aKeptMoveWhoseCopyWasDeletedSinceMakesANewCopyBeforeAnyDelete() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.createSharedVault("Family"))
        val family = controller.moveTargets(ITEM_ID).single()
        val pushed = mutableListOf<io.silencelen.andvari.core.model.Mutation>()
        moveServer(server, delete = "denied", pushed)
        assertIs<ActionResult.Failed>(controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        val firstCopy = pushed.single { it.op == "put" }.itemId
        controller.lock()
        // The copy is deleted meanwhile: the next sync no longer has it.
        namespaces.caches.getValue("$homeKey/${reg.userId}").deleteItem(firstCopy)
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        moveServer(server, delete = "applied", pushed)
        assertEquals(ActionResult.Ok, controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        val puts = pushed.filter { it.op == "put" }.map { it.itemId }
        assertEquals(2, puts.size)
        assertNotEquals(firstCopy, puts.last(), "a new copy, not the replayed one")
        val deletes = pushed.filter { it.op == "delete" }
        assertTrue(pushed.indexOfLast { it.op == "put" } < pushed.indexOf(deletes.last()), "the new copy is made before the original goes")
        assertTrue(controller.state.items.any { it.itemId == puts.last() }, "and it is there")
    }

    /**
     * Round-8 review M: a try whose delete leg timed out after the copy leg (TRANSIENT, as the app being stopped there is)
     * kept its gesture without knowing what became of the copy. When the copy is deleted before the next try, that try
     * syncs, finds it gone, and makes a new copy before the original goes: never a replay the server would answer from
     * its journal with no copy made.
     */
    @Test
    fun aMoveWhoseDeleteLegTimedOutIsReplayedOnlyWhileItsCopyIsThere() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.createSharedVault("Family"))
        val family = controller.moveTargets(ITEM_ID).single()
        val pushed = mutableListOf<io.silencelen.andvari.core.model.Mutation>()
        moveServer(server, delete = "applied", pushed)
        val copyLeg = routes.getValue("/sync/push")
        routes["/sync/push"] = { request ->
            val body = json.decodeFromString(io.silencelen.andvari.core.model.PushRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            if (body.mutations.any { it.op == "delete" }) {
                pushed += body.mutations
                throw IOException("timed out")
            }
            copyLeg(request)
        }
        assertEquals(ActionResult.Failed(ItemCopy.MOVE_RETRY), controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        val firstCopy = pushed.single { it.op == "put" }.itemId
        assertNotNull(moveMemoLog.bytes, "the try is kept")
        controller.lock()
        // The copy is deleted meanwhile: the next sync no longer has it.
        namespaces.caches.getValue("$homeKey/${reg.userId}").deleteItem(firstCopy)
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        moveServer(server, delete = "applied", pushed)
        assertEquals(ActionResult.Ok, controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        val puts = pushed.filter { it.op == "put" }.map { it.itemId }
        assertEquals(2, puts.size)
        assertNotEquals(firstCopy, puts.last(), "a new copy, never a replay of the one that is gone")
        assertTrue(pushed.indexOfLast { it.op == "put" } < pushed.indexOfLast { it.op == "delete" }, "made before the original goes")
        assertTrue(controller.state.items.any { it.itemId == puts.last() }, "and it is there")
        assertNull(moveMemoLog.bytes, "the move is done")
    }

    /** The same timeout with the copy still there: the next try replays the same ids, so no second copy is made. */
    @Test
    fun aMoveWhoseDeleteLegTimedOutReplaysTheSameIdsWhileItsCopyIsThere() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.createSharedVault("Family"))
        val family = controller.moveTargets(ITEM_ID).single()
        val pushed = mutableListOf<io.silencelen.andvari.core.model.Mutation>()
        moveServer(server, delete = "applied", pushed)
        val copyLeg = routes.getValue("/sync/push")
        routes["/sync/push"] = { request ->
            val body = json.decodeFromString(io.silencelen.andvari.core.model.PushRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            if (body.mutations.any { it.op == "delete" }) throw IOException("timed out")
            copyLeg(request)
        }
        assertEquals(ActionResult.Failed(ItemCopy.MOVE_RETRY), controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        moveServer(server, delete = "applied", pushed)
        assertEquals(ActionResult.Ok, controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        assertEquals(1, pushed.filter { it.op == "put" }.map { it.itemId }.toSet().size, "one copy, replayed")
        assertEquals(1, pushed.filter { it.op == "put" }.map { it.mutationId }.toSet().size, "under the same mutation id")
    }

    @Test
    fun aMovedItemThatChangedMeanwhileIsKeptAndNoSecondCopyIsMinted() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.createSharedVault("Family"))
        val family = controller.moveTargets(ITEM_ID).single()
        val pushed = mutableListOf<io.silencelen.andvari.core.model.Mutation>()
        moveServer(server, delete = "conflict", pushed)
        assertEquals(
            ActionResult.Failed("Copied “Example” to “Family”, but it changed in “Personal” meanwhile, so the original was kept there. It is in both vaults now: review them and delete the one you don't need."),
            controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true),
        )
        // The original changes (another device's edit, pulled by a sync): another try would copy a different item, and
        // the earlier copy is there.
        val changed = enrolled.account.encryptItem(reg.personalVault.vaultId, ITEM_ID, item.copy(login = item.login!!.copy(password = "changed-elsewhere")))
        server.rev += 50
        val row = WireItem(ITEM_ID, reg.personalVault.vaultId, server.rev, 1_000, 9_000, false, false, changed.formatVersion, changed.attachmentIds, changed.blob)
        val sync = routes.getValue("/sync")
        routes["/sync"] = {
            // The server's counter only moves forward: the next ordinary sync answers above this one.
            val body = io.silencelen.andvari.core.model.SyncResponse(++server.rev, false, server.vaults.values.toList(), server.grants.values.toList(), listOf(row), emptyList())
            respond(json.encodeToString(io.silencelen.andvari.core.model.SyncResponse.serializer(), body), HttpStatusCode.OK, headers)
        }
        assertEquals(ActionResult.Ok, controller.refresh())
        routes["/sync"] = sync
        assertEquals("changed-elsewhere", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        moveServer(server, delete = "applied", pushed)
        val copies = { pushed.count { it.op == "put" && it.itemId != ITEM_ID } }
        assertEquals(
            ActionResult.Failed("An earlier try already copied “Example” to “Family”, and it has changed since, so nothing more was done. Cancel to start over, or delete the copy you don't need."),
            controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true),
        )
        assertEquals(1, copies(), "no second copy")
        // After Cancel, a new move is the person's own choice: it goes ahead.
        controller.cancelMove(ITEM_ID)
        assertEquals(ActionResult.Ok, controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        assertEquals(2, copies())
    }

    /**
     * Round-10 review 3: a move an earlier version kept (its record has no MAC, so anyone who could write the file could
     * have written it) is never replayed. While its copy is in the target, no second copy is made and the person is told;
     * Cancel starts over. The record is carried over in this version's form, marked.
     */
    @Test
    fun aMoveAnEarlierVersionKeptIsNeverReplayedAndMakesNoSecondCopy() = test {
        unlockedWithAPersonalVault()
        val server = VaultServer(this)
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(ActionResult.Ok, controller.createSharedVault("Family"))
        val family = controller.moveTargets(ITEM_ID).single()
        val pushed = mutableListOf<io.silencelen.andvari.core.model.Mutation>()
        moveServer(server, delete = "denied", pushed)
        assertIs<ActionResult.Failed>(controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true))
        val copy = pushed.single { it.op == "put" }.itemId
        // The same kept move, as an earlier version wrote it: a sealed box without the MAC.
        val plain = assertNotNull(enrolled.account.openLocalRecord("move-memos", assertNotNull(moveMemoLog.bytes)))
        moveMemoLog.write(crypto.sealTo(enrolled.account.identityPub, plain))
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertNotNull(enrolled.account.openLocalRecord("move-memos", assertNotNull(moveMemoLog.bytes)), "carried over in this version's form")
        moveServer(server, delete = "applied", pushed)
        val before = pushed.size
        assertEquals(
            ActionResult.Failed("An earlier try already copied “Example” to “Family”, so nothing more was done. Delete the copy you don't need, or Cancel to start over."),
            controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true),
        )
        assertEquals(before, pushed.size, "nothing replayed: no second copy, and the original stays")
        assertTrue(controller.state.items.any { it.itemId == ITEM_ID } && controller.state.items.any { it.itemId == copy })
        controller.cancelMove(ITEM_ID)
        assertEquals(ActionResult.Ok, controller.moveOrCopyItem(ITEM_ID, family.vaultId, move = true), "a new move is the person's own choice")
    }

    /**
     * Round-6 review L6, the rules both apps now share (VaultMoves): an item in a vault this account only reads can be
     * copied out but not moved, and a vault whose key this device does not hold is never a target.
     */
    @Test
    fun aReadersItemIsCopiedOutNotMovedAndAVaultWithoutItsKeyIsNoTarget() = test {
        val readOnly = io.silencelen.andvari.core.client.VaultInfo("00000000-0000-4000-8000-0000000000b1", "shared", "Shared, read only", "reader")
        val vaults = listOf(
            io.silencelen.andvari.core.client.VaultInfo(reg.personalVault.vaultId, "personal", "Personal", null),
            readOnly,
            io.silencelen.andvari.core.client.VaultInfo("v-writer-nokey", "shared", "Family", "writer"),
            io.silencelen.andvari.core.client.VaultInfo("v-owner", "shared", "Work", "owner"),
        )
        val holds = setOf(reg.personalVault.vaultId, readOnly.vaultId, "v-owner")
        assertEquals(listOf(reg.personalVault.vaultId, "v-owner"), VaultMoves.writableVaults(vaults) { it in holds }.map { it.vaultId }, "no reader's vault, no vault without its key")
        assertEquals(listOf(reg.personalVault.vaultId, "v-owner"), VaultMoves.targets(readOnly.vaultId, vaults) { it in holds }.map { it.vaultId }, "a reader's item can be copied out")
        assertEquals(listOf("v-owner"), VaultMoves.targets(reg.personalVault.vaultId, vaults) { it in holds }.map { it.vaultId })
        assertFalse(VaultMoves.canTakeOut(readOnly.vaultId, vaults), "but not moved: its original cannot be deleted")
        assertTrue(VaultMoves.canTakeOut(reg.personalVault.vaultId, vaults))
        assertTrue(VaultMoves.canTakeOut("v-writer-nokey", vaults))
        assertFalse(VaultMoves.canTakeOut("v-unknown", vaults))
    }

    // ---- trash and history ----

    /** [doc] as the server keeps an archived version of [itemId] in the personal vault. */
    private fun archived(itemId: String, rev: Long, doc: ItemDoc, archivedAt: Long): io.silencelen.andvari.core.model.ItemVersion {
        val upload = enrolled.account.encryptItem(reg.personalVault.vaultId, itemId, doc)
        return io.silencelen.andvari.core.model.ItemVersion(rev, upload.blob, upload.formatVersion, archivedAt)
    }

    private fun Rig.versionsAnswer(byItem: Map<String, List<io.silencelen.andvari.core.model.ItemVersion>>) {
        routes["/versions"] = { request ->
            val itemId = request.url.encodedPath.removeSuffix("/versions").substringAfterLast('/')
            val body = io.silencelen.andvari.core.model.ItemVersionsResponse(itemId, byItem[itemId].orEmpty())
            respond(json.encodeToString(io.silencelen.andvari.core.model.ItemVersionsResponse.serializer(), body), HttpStatusCode.OK, headers)
        }
    }

    @Test
    fun theTrashNamesDeletedItemsRestoresOneAndDeletesAnotherForGood() = test {
        unlockedWithAPersonalVault()
        val restorable = "00000000-0000-4000-8000-0000000000d1"
        val unreadable = "00000000-0000-4000-8000-0000000000d2"
        val vault = reg.personalVault.vaultId
        routes["/items/deleted"] = {
            val items = listOf(io.silencelen.andvari.core.model.DeletedItem(restorable, vault, 5_000), io.silencelen.andvari.core.model.DeletedItem(unreadable, vault, 9_000))
            respond(json.encodeToString(io.silencelen.andvari.core.model.DeletedItemsResponse.serializer(), io.silencelen.andvari.core.model.DeletedItemsResponse(items)), HttpStatusCode.OK, headers)
        }
        val old = ItemDoc(type = "login", name = "Old bank", login = LoginData(username = "me", password = "pw-old", uris = listOf("https://bank.example")), attachments = listOf(io.silencelen.andvari.core.client.AttachmentRef("a1", "statement.pdf", 10, "k")))
        versionsAnswer(mapOf(restorable to listOf(archived(restorable, 7, old, 4_000))))
        assertEquals(ActionResult.Ok, controller.openTrash())
        val trash = assertNotNull(controller.state.trash)
        assertEquals(listOf(unreadable, restorable), trash.map { it.itemId }, "newest deletion first")
        val readable = trash.single { it.itemId == restorable }
        assertEquals("Old bank", readable.name)
        assertEquals("me", readable.detail)
        assertTrue(readable.canRestore && readable.canPurge)
        val lost = trash.single { it.itemId == unreadable }
        assertNull(lost.name)
        assertFalse(lost.canRestore, "no readable version: it can only be deleted for good")
        assertTrue(lost.canPurge)
        assertFalse(controller.state.toString().contains("pw-old"), "no secret is in the state")
        assertEquals(ActionResult.Failed(ItemCopy.TRASH_UNREADABLE), controller.restoreFromTrash(unreadable))

        // Restore: the version is sealed again for its vault, without the attachments the deletion removed.
        var restored: io.silencelen.andvari.core.model.ItemUpload? = null
        routes["/restore"] = { request ->
            restored = json.decodeFromString(io.silencelen.andvari.core.model.ItemUpload.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            respond("""{"rev":20}""", HttpStatusCode.OK, headers)
        }
        routes["/sync"] = {
            val up = assertNotNull(restored)
            val row = WireItem(restorable, vault, 20, 6_000, 6_000, false, false, up.formatVersion, up.attachmentIds, up.blob)
            respond(json.encodeToString(io.silencelen.andvari.core.model.SyncResponse.serializer(), io.silencelen.andvari.core.model.SyncResponse(20, false, emptyList(), emptyList(), listOf(row), emptyList())), HttpStatusCode.OK, headers)
        }
        assertEquals(ActionResult.Ok, controller.restoreFromTrash(restorable))
        val back = enrolled.account.decryptItem(WireItem(restorable, vault, 20, 0, 0, false, false, restored!!.formatVersion, emptyList(), restored!!.blob))
        assertEquals("pw-old", back.login?.password)
        assertTrue(back.attachments.isEmpty(), "attachments do not come back")
        assertTrue(controller.state.items.any { it.itemId == restorable && it.name == "Old bank" }, "in the vault again")
        assertEquals(listOf(unreadable), controller.state.trash?.map { it.itemId })

        // Delete forever.
        var purged: String? = null
        routes["/purge"] = { request ->
            purged = request.url.encodedPath
            respond("""{"rev":21}""", HttpStatusCode.OK, headers)
        }
        assertEquals(ActionResult.Ok, controller.purgeFromTrash(unreadable))
        assertTrue(purged!!.contains(unreadable))
        assertEquals(emptyList(), controller.state.trash)
        // Closing it, or a lock, forgets what was read.
        controller.closeTrash()
        assertNull(controller.state.trash)
        assertIs<ActionResult.Failed>(controller.restoreFromTrash(restorable))
    }

    /**
     * Round-6 review L8: a screen that reads from the server as it opens, closed before the read came back, gets
     * nothing when it does: not the trash, an item's history, the shared vaults, or two-step sign-in. A reopen in
     * between keeps only the newest read.
     */
    @Test
    fun aScreenClosedWhileItsReadIsOutAssignsNothingWhenTheReadComesBack() = test {
        unlockedWithAPersonalVault()
        kotlinx.coroutines.coroutineScope {
            val vault = reg.personalVault.vaultId
            val deletedId = "00000000-0000-4000-8000-0000000000d1"
            var gate = CompletableDeferred<Unit>()
            routes["/items/deleted"] = {
                gate.await()
                val items = listOf(io.silencelen.andvari.core.model.DeletedItem(deletedId, vault, 5_000))
                respond(json.encodeToString(io.silencelen.andvari.core.model.DeletedItemsResponse.serializer(), io.silencelen.andvari.core.model.DeletedItemsResponse(items)), HttpStatusCode.OK, headers)
            }
            val versions = mapOf(deletedId to listOf(archived(deletedId, 7, item, 4_000)), ITEM_ID to listOf(archived(ITEM_ID, 9, item.copy(login = item.login!!.copy(password = "hunter1")), 3_000)))
            routes["/versions"] = { request ->
                gate.await()
                val itemId = request.url.encodedPath.removeSuffix("/versions").substringAfterLast('/')
                val body = io.silencelen.andvari.core.model.ItemVersionsResponse(itemId, versions[itemId].orEmpty())
                respond(json.encodeToString(io.silencelen.andvari.core.model.ItemVersionsResponse.serializer(), body), HttpStatusCode.OK, headers)
            }

            val trash = async { controller.openTrash() }
            settle { controller.state.busy }
            controller.closeTrash()
            gate.complete(Unit)
            assertEquals(ActionResult.NotDone(null), trash.await())
            assertNull(controller.state.trash, "the closed trash does not come back")
            assertFalse(controller.state.busy)
            assertEquals(ActionResult.Failed(ItemCopy.TRASH_GONE), controller.restoreFromTrash(deletedId), "nothing it read is held")

            gate = CompletableDeferred()
            val history = async { controller.openItemHistory(ITEM_ID) }
            settle { controller.state.busy }
            controller.closeItemHistory()
            gate.complete(Unit)
            assertEquals(ActionResult.NotDone(null), history.await())
            assertNull(controller.state.history)
            assertNull(controller.historyPassword(ITEM_ID, 9), "no version is held")

            // Reopened while the first read is out: the first one assigns nothing, the second one does.
            gate = CompletableDeferred()
            val first = async { controller.openTrash() }
            settle { controller.state.busy }
            controller.closeTrash()
            val second = async { controller.openTrash() }
            gate.complete(Unit)
            assertEquals(ActionResult.NotDone(null), first.await())
            assertEquals(ActionResult.Ok, second.await())
            assertEquals(listOf(deletedId), controller.state.trash?.map { it.itemId })
            controller.closeTrash()

            // The shared vaults screen: what is restorable, read after it closed, is not kept.
            gate = CompletableDeferred()
            routes["/vaults/deleted"] = {
                gate.await()
                respond("[]", HttpStatusCode.OK, headers)
            }
            val sharing = async { controller.openSharing() }
            settle { controller.state.busy }
            controller.closeSharing()
            gate.complete(Unit)
            assertEquals(ActionResult.NotDone(null), sharing.await())
            assertNull(controller.state.sharing, "the closed screen does not come back")

            // Two-step sign-in: the status read after its screen closed does not bring the screen back.
            gate = CompletableDeferred()
            routes["/account/totp"] = {
                gate.await()
                respond("""{"enrolled":true,"pendingSetup":false}""", HttpStatusCode.OK, headers)
            }
            val twoStep = async { controller.loadTwoStep() }
            settle { controller.state.busy }
            controller.closeTwoStep()
            gate.complete(Unit)
            assertEquals(ActionResult.NotDone(null), twoStep.await())
            assertNull(controller.state.twoStep)
        }
    }

    @Test
    fun anItemsHistoryShowsEarlierVersionsAndRestoresOne() = test {
        unlockedWithAPersonalVault()
        versionsAnswer(
            mapOf(
                ITEM_ID to listOf(
                    archived(ITEM_ID, 9, item.copy(login = item.login!!.copy(password = "hunter1")), 3_000),
                    archived(ITEM_ID, 8, item.copy(name = "Example (old)", login = item.login!!.copy(password = null)), 2_000),
                ),
            ),
        )
        assertNull(controller.historyPassword(ITEM_ID, 9), "nothing before the history is open")
        assertEquals(ActionResult.Ok, controller.openItemHistory(ITEM_ID))
        val history = assertNotNull(controller.state.history)
        assertEquals(ITEM_ID, history.itemId)
        assertEquals(listOf(9L, 8L), history.versions.map { it.rev })
        assertEquals(listOf(true, false), history.versions.map { it.hasPassword })
        assertEquals("Example (old)", history.versions[1].name)
        assertEquals("fam", history.versions[0].detail)
        assertTrue(history.canRestore)
        assertFalse(controller.state.toString().contains("hunter1"), "no secret is in the state")
        assertEquals("hunter1", controller.historyPassword(ITEM_ID, 9))
        assertNull(controller.historyPassword(ITEM_ID, 8))
        // Restore puts that version back over the item.
        assertEquals(ActionResult.Ok, controller.restoreItemVersion(ITEM_ID, 9))
        assertEquals("hunter1", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals(1, controller.state.items.count { it.itemId == ITEM_ID }, "the same item, not a copy")
        assertEquals(ActionResult.Failed(ItemCopy.HISTORY_GONE), controller.restoreItemVersion(ITEM_ID, 77))
        // A lock forgets the versions.
        controller.lock()
        assertNull(controller.state.history)
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertNull(controller.historyPassword(ITEM_ID, 9))
        assertEquals(ActionResult.Failed(ItemCopy.HISTORY_GONE), controller.restoreItemVersion(ITEM_ID, 9))
    }

    // ---- the personal vault ----

    /** The members of the personal vault as the server reports them: this account alone. */
    private fun Rig.membersAnswer(vararg others: String) {
        val me = io.silencelen.andvari.core.model.VaultMemberSummary(reg.userId, EMAIL, "u", "owner", reg.identityPub, 1)
        val rest = others.map { io.silencelen.andvari.core.model.VaultMemberSummary("00000000-0000-4000-8000-0000000000b$it", "$it@example.com", "Other $it", "writer", reg.identityPub, 1) }
        routes["/members"] = { respond(json.encodeToString(kotlinx.serialization.builtins.ListSerializer(io.silencelen.andvari.core.model.VaultMemberSummary.serializer()), listOf(me) + rest), HttpStatusCode.OK, headers) }
    }

    @Test
    fun aPersonalVaultLookupThatAnswersAfterTheSessionEndedShowsNothing() = test {
        seedSession()
        membersAnswer("1")
        val answer = routes.getValue("/members")
        val asked = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        routes["/members"] = { request ->
            asked.complete(Unit)
            release.await()
            answer(request)
        }
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        withTimeout(10_000) { asked.await() } // the lookup of who else holds the served vault is in flight
        assertEquals(ActionResult.Ok, controller.signOut())
        assertNull(controller.state.personalVault)
        release.complete(Unit)
        delay(200)
        assertNull(controller.state.personalVault, "neither the answer nor its failure draws a notice on the sign-in screen")
        assertEquals(AppScreen.WELCOME, controller.state.screen)
    }

    @Test
    fun aRaisedPersonalVaultProposalDoesNotSurviveASignOut() = test {
        seedSession()
        membersAnswer("1")
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.personalVault?.servedDetail != null }
        assertEquals(ActionResult.Ok, controller.proposePersonalVault(reg.personalVault.vaultId))
        assertTrue(assertNotNull(controller.state.personalVault?.proposal?.warning).contains("1@example.com"), "the confirmation names who else can read the vault")
        assertEquals(ActionResult.Ok, controller.signOut())
        assertNull(controller.state.personalVault)
        // The next session on this device starts with no confirmation raised and nobody named.
        routes["/members"] = { throw IOException("unreachable") }
        seedSession()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.personalVault?.lookupFailed == true }
        val notice = assertNotNull(controller.state.personalVault)
        assertNull(notice.proposal)
        assertNull(notice.servedDetail)
        assertNull(notice.useServedLabel, "\"Use\" waits for a lookup made in this session")
    }

    @Test
    fun aDeviceThatNeverConfirmedItsPersonalVaultAsksOnceAndThenSavesWhatWasWaiting() = test {
        // This account was created elsewhere: the server names a personal vault, and nothing on this device vouches for it.
        seedSession()
        val key = "$homeKey/${reg.userId}"
        val seeded = namespaces.caches.getValue(key)
        namespaces.caches[key] = object : io.silencelen.andvari.core.client.VaultCache by seeded {
            override val durable = true
        }
        routes["/sync/push"] = { throw IOException("unreachable") }
        membersAnswer("1")
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { queue.key != null && controller.state.personalVault?.servedDetail != null }
        val notice = assertNotNull(controller.state.personalVault)
        assertEquals(PersonalVaultState.PROPOSED, notice.state)
        assertTrue(notice.title.startsWith("The server says your personal vault is"), notice.title)
        assertNull(notice.keepLabel, "the account designates no other vault to keep")
        assertNull(notice.keepDetail)
        assertTrue(assertNotNull(notice.servedDetail).contains("1 item · last changed 1970-01-01 · id ending ${reg.personalVault.vaultId.takeLast(6)}"), "what tells this vault from another of the same name: ${notice.servedDetail}")
        assertTrue(assertNotNull(notice.servedDetail).contains("Other 1 (writer)"), "who else can read it is named before it can be used: ${notice.servedDetail}")
        assertNotNull(notice.useServedLabel)

        // A capture made meanwhile has nowhere to go, and says so.
        controller.lock()
        capture("a", "https://shop.example/login", "me", "pw")
        controller.unlock(PASSWORD)
        settle { controller.state.pendingSaves.singleOrNull()?.reason != null && controller.state.personalVault?.useServedLabel != null }
        assertEquals(SaveImporter.PERSONAL_UNCONFIRMED, controller.state.pendingSaves.single().reason)
        assertIs<ActionResult.Failed>(controller.saveLogin(null, LoginInput("New", "me", "pw", listOf("https://new.example"), "", "", false)))

        // The person confirms; the notice goes, a new login has a home, and what waited is saved with no further tap.
        assertEquals(ActionResult.Ok, controller.usePersonalVaultServed())
        assertNull(controller.state.personalVault)
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf("shop.example"), controller.state.appliedSaves.map { it.host })
        assertTrue(controller.state.pendingSaves.isEmpty())
        assertEquals(ActionResult.Ok, controller.saveLogin(null, LoginInput("New", "me", "pw", listOf("https://new.example"), "", "", false)))
        // The confirmation is remembered on the device: the next unlock does not ask again.
        controller.lock()
        controller.unlock(PASSWORD)
        assertNull(controller.state.personalVault)
    }

    @Test
    fun whenTheAccountsRecordAndTheServerNameTheSameVaultTheNoticeSaysSoAndOffersNoFalseChoice() = test {
        // The account's own record names the vault (this device confirmed it once), and then the device forgets: the
        // state of a long-established account on a newly signed-in device. One vault, no conflict, one question.
        seedSession()
        membersAnswer()
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.personalVault?.useServedLabel != null }
        assertEquals(ActionResult.Ok, controller.usePersonalVaultServed())
        controller.lock()
        namespaces.devices.getValue("$homeKey/${reg.userId}").apply {
            set("personal.wrap", null)
            set("personal.last", null)
        }
        namespaces.caches.getValue("$homeKey/${reg.userId}").apply {
            setClientState("personal.wrap", null) // the cache mirrors the device's memory
            setClientState("personal.last", null)
        }
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.personalVault?.useServedLabel != null }
        val notice = assertNotNull(controller.state.personalVault)
        assertEquals(PersonalVaultState.PROPOSED, notice.state)
        assertTrue(notice.title.startsWith("Confirm your personal vault on this device"), notice.title)
        assertTrue(notice.body.contains("name the same vault (id ending ${reg.personalVault.vaultId.takeLast(6)})"), notice.body)
        assertNull(notice.keepLabel, "nothing to keep instead: it is the same vault")
        assertTrue(notice.otherChoices.none { it.vaultId == reg.personalVault.vaultId }, "and it is not offered again as another vault")
        assertEquals(ActionResult.Ok, controller.usePersonalVaultServed())
        assertNull(controller.state.personalVault)
    }

    /**
     * A device's first sign-in to an account whose record already names the served vault (another device confirmed it):
     * the device holds the proposal at hydrate, before any account state is read, and the notice must still say it is
     * the same vault once the record is read, not "the server says your personal vault is X".
     */
    @Test
    fun aFirstSignInWhoseAccountRecordNamesTheServedVaultSaysItIsTheSameVault() = test {
        // The server keeps the account state it is given.
        var stored: String? = null
        var seq = 0L
        routes["/account/state"] = { request ->
            if (request.method.value == "PUT") {
                val put = json.decodeFromString(io.silencelen.andvari.core.model.AccountStatePut.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
                if (put.baseSeq != seq) {
                    respond("""{"error":"stale_state","message":"stale"}""", HttpStatusCode.Conflict, headers)
                } else {
                    stored = put.sealedState
                    seq++
                    respond(json.encodeToString(io.silencelen.andvari.core.model.AccountStateResponse.serializer(), io.silencelen.andvari.core.model.AccountStateResponse(stored, seq)), HttpStatusCode.OK, headers)
                }
            } else {
                respond(json.encodeToString(io.silencelen.andvari.core.model.AccountStateResponse.serializer(), io.silencelen.andvari.core.model.AccountStateResponse(stored, seq)), HttpStatusCode.OK, headers)
            }
        }
        routes["/sync"] = { respond(EMPTY_SYNC, HttpStatusCode.OK, headers) }
        // Another device confirmed the personal vault: the account's record names it.
        seedSession()
        membersAnswer()
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.personalVault?.useServedLabel != null }
        assertEquals(ActionResult.Ok, controller.usePersonalVaultServed())
        controller.refresh()
        settle { stored != null }
        controller.lock()
        // This device, as on its first sign-in: no personal wrap of its own and no account state read yet.
        for (state in listOf(namespaces.devices.getValue("$homeKey/${reg.userId}"))) {
            for (k in listOf("personal.wrap", "personal.last", "acctstate.copy", "acctstate.hw")) state.set(k, null)
        }
        namespaces.caches.getValue("$homeKey/${reg.userId}").apply {
            for (k in listOf("personal.wrap", "personal.last", "acctstate.copy", "acctstate.hw")) setClientState(k, null)
        }
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.personalVault?.useServedLabel != null && controller.state.personalVault?.title?.startsWith("Confirm") == true }
        val notice = assertNotNull(controller.state.personalVault)
        assertEquals(PersonalVaultState.PROPOSED, notice.state, "still asked once on this device")
        assertTrue(notice.title.startsWith("Confirm your personal vault on this device"), notice.title)
        assertNull(notice.keepLabel, "nothing to keep instead: it is the same vault")
    }

    @Test
    fun usingTheServedPersonalVaultIsNotOfferedUntilItsCoHoldersWereLoaded() = test {
        unlocked() // the members lookup is unreachable in this rig
        settle { controller.state.personalVault?.lookupFailed == true }
        val notice = assertNotNull(controller.state.personalVault)
        assertEquals(PersonalVaultState.PROPOSED, notice.state)
        assertNull(notice.useServedLabel)
        assertNull(notice.servedDetail)
        assertEquals(ActionResult.NotDone(null), controller.usePersonalVaultServed(), "the core refuses, whatever a UI shows")
        assertNotNull(controller.state.personalVault?.error)
        // Once the server answers, a retry loads them and the offer appears.
        membersAnswer()
        assertEquals(ActionResult.Ok, controller.retryPersonalVaultDetails())
        assertFalse(assertNotNull(controller.state.personalVault).lookupFailed)
        assertTrue(assertNotNull(controller.state.personalVault?.servedDetail).contains("nobody else"))
        assertEquals(ActionResult.Ok, controller.usePersonalVaultServed())
        assertNull(controller.state.personalVault)
    }

    @Test
    fun choosingAnotherVaultInsteadTakesTheConfirmationAndTheMasterPassword() = test {
        seedSession()
        namespaces.caches.getValue("$homeKey/${reg.userId}").upsertVault(io.silencelen.andvari.core.model.WireVault(reg.personalVault.vaultId, "personal", 1, reg.personalVault.metaBlob, 1))
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        membersAnswer("1")
        assertEquals(ActionResult.Ok, controller.retryPersonalVaultDetails())
        val other = assertNotNull(controller.state.personalVault).otherChoices
        assertEquals(1, other.size, "every vault of this account's own may be chosen instead")
        assertEquals(ActionResult.Ok, controller.proposePersonalVault(other.single().vaultId))
        val proposal = assertNotNull(controller.state.personalVault?.proposal)
        assertTrue(proposal.needsPassword, "it replaces the record the server holds")
        assertTrue(assertNotNull(proposal.warning).contains("Other 1"), "the confirmation names everyone who can read the vault")
        assertEquals(ActionResult.NotDone(null), controller.confirmPersonalVault(null))
        assertEquals("Enter your master password to confirm.", controller.state.personalVault?.error)
        controller.cancelPersonalVaultProposal()
        assertNull(controller.state.personalVault?.proposal)
        assertEquals(PersonalVaultState.PROPOSED, controller.state.personalVault?.state, "cancelled: nothing was chosen")
    }

    @Test
    fun whileThePersonalVaultQuestionIsOpenNothingIsSavedByItselfEvenWhereTheDeviceHasAVaultToUse() = test {
        // The device remembers a personal vault, but the server sent no record this time (WITHHELD): the device keeps
        // using its own for what the person does by hand, and build 103 also auto-saved into it. A save the person
        // did not make by hand now waits until the question is settled.
        seedSession()
        val key = "$homeKey/${reg.userId}"
        val seeded = namespaces.caches.getValue(key)
        namespaces.caches[key] = object : io.silencelen.andvari.core.client.VaultCache by seeded {
            override val durable = true
        }
        namespaces.devices.getOrPut(key) { io.silencelen.andvari.core.client.MemoryDeviceState() }
            .set("personal.wrap", json.encodeToString(io.silencelen.andvari.core.model.PersonalWrap.serializer(), assertNotNull(reg.personalWrap)))
        store.origin(homeKey).saveAccountKeys(reg.userId, cached.copy(personalWrap = null))
        routes["/sync/push"] = { throw IOException("unreachable") }
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { queue.key != null }
        assertEquals(PersonalVaultState.WITHHELD, controller.state.personalVault?.state)
        controller.lock()
        capture("new", "https://shop.example/", "me", "pw")
        capture("change", "https://login.example.com/x", "fam", "hunter3")
        controller.unlock(PASSWORD)
        settle { controller.state.pendingSaves.size == 2 && controller.state.pendingSaves.all { it.reason != null } }
        // The notice for this state offers nothing to confirm, so the reason does not say "confirm above".
        assertEquals(setOf(SaveImporter.PERSONAL_RECORD_MISSING), controller.state.pendingSaves.map { it.reason }.toSet())
        assertTrue(controller.state.appliedSaves.isEmpty())
        assertEquals(listOf("Example"), controller.state.items.map { it.name }, "nothing was written")
        assertEquals("hunter2", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        // By hand it still works, into the vault this device has: that is the person's own decision.
        assertEquals(ActionResult.Ok, controller.confirmPendingSave("new"))
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name })
    }

    @Test
    fun aLockTakesThePersonalVaultNoticeAway() = test {
        unlocked()
        settle { controller.state.personalVault != null }
        controller.lock()
        assertNull(controller.state.personalVault)
    }

    /**
     * A server that keeps what is pushed and serves it back, as the real one does: an online save is applied, and the
     * reconcile pull returns the row. The rig's default is an unreachable server.
     */
    private fun Rig.onlineServer() {
        val rows = mutableListOf<WireItem>()
        var rev = 10L
        val real = System_now()
        // (The key fetch stays unreachable: the fixture's account keys are below the KDF floor a server may send.)
        routes["/account/state"] = { respond("""{"sealedState":null,"seq":0}""", HttpStatusCode.OK, headers) }
        routes["/sync/push"] = { request ->
            val body = json.decodeFromString(io.silencelen.andvari.core.model.PushRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            val results = body.mutations.map { m ->
                rev++
                rows.removeAll { it.itemId == m.itemId }
                val up = m.item
                rows += WireItem(m.itemId, m.vaultId, rev, real, real, deleted = up == null, conflict = false, formatVersion = up?.formatVersion ?: 1, attachmentIds = up?.attachmentIds.orEmpty(), blob = up?.blob)
                io.silencelen.andvari.core.model.MutationResult(m.mutationId, "applied", newItemRev = rev)
            }
            respond(json.encodeToString(io.silencelen.andvari.core.model.PushResponse.serializer(), io.silencelen.andvari.core.model.PushResponse(rev, results)), HttpStatusCode.OK, headers)
        }
        routes["/sync"] = { request ->
            val since = request.url.parameters["since"]?.toLongOrNull() ?: 0L
            val resp = io.silencelen.andvari.core.model.SyncResponse(rev, false, emptyList(), emptyList(), rows.filter { it.rev > since }, emptyList())
            respond(json.encodeToString(io.silencelen.andvari.core.model.SyncResponse.serializer(), resp), HttpStatusCode.OK, headers)
        }
    }

    private fun System_now(): Long = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()

    @Test
    fun anAutoSavedLoginIsInTheVaultListOnTheSqliteCacheTheAppUses() = test {
        seedSession()
        val key = "$homeKey/${reg.userId}"
        val sqlite = io.silencelen.andvari.core.client.sqliteVaultCache(":memory:", reg.userId).apply { upsertItem(sealed, null) }
        namespaces.caches[key] = object : io.silencelen.andvari.core.client.VaultCache by sqlite {
            override fun close() {} // one in-memory database for the whole test, across locks
        }
        namespaces.devices.getOrPut(key) { io.silencelen.andvari.core.client.MemoryDeviceState() }
            .set("personal.wrap", json.encodeToString(io.silencelen.andvari.core.model.PersonalWrap.serializer(), assertNotNull(reg.personalWrap)))
        onlineServer()
        clocks.wall = System_now()
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { queue.key != null }
        controller.lock()
        assertEquals(SaveQueued.QUEUED, capture("a", "https://shop.example/login", "me", "s3cret-pw"))
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name })
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name }, "still there after the next unlock")
    }

    @Test
    fun anAutoSavedLoginIsInTheVaultListItsSearchAndTheSnapshotAndStaysThere() = test {
        unlockedWithAPersonalVault()
        onlineServer()
        clocks.wall = System_now() // the device's clock and the server's agree, as on a phone
        controller.lock()
        assertEquals(SaveQueued.QUEUED, capture("a", "shop.example", "me", "s3cret-pw")) // the system's save names a domain
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name }, "in the list the vault screen shows")
        controller.setQuery("shop")
        assertEquals(listOf("shop.example"), controller.state.items.map { it.name }, "found by the search")
        controller.setQuery("")
        val added = controller.state.items.single { it.name == "shop.example" }
        assertEquals("s3cret-pw", controller.revealSecret(added.itemId, SecretField.PASSWORD))
        assertEquals(reg.personalVault.vaultId, controller.itemDetail(added.itemId)?.vaultId, "in the personal vault")
        assertNotNull(controller.state.appliedSaves.single().vault, "and the list of saves says which vault it is in")
        assertTrue(added.itemId in assertNotNull(FillSnapshot.decode(assertNotNull(snapshots.bytes))).items.map { it.itemId }, "in the AutoFill snapshot")
        assertTrue(controller.credentialIdentities().any { it.itemId == added.itemId && it.host == "shop.example" }, "suggested to the system")
        // It is still there after a sync and after the next unlock.
        assertEquals(ActionResult.Ok, controller.refresh())
        assertEquals(2, controller.state.items.size)
        controller.lock()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name })
    }

    @Test
    fun aSavedLoginDeletedOnAnotherDeviceIsNeverWrittenAgain() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("elsewhere", "https://shop.example/", "me", "pw-1")
        capture("here", "https://other.example/", "me", "pw-2")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size == 2 }
        val cache = namespaces.caches.getValue("$homeKey/${reg.userId}")
        val remote = controller.state.items.single { it.name == "shop.example" }.itemId
        val local = controller.state.items.single { it.name == "other.example" }.itemId
        assertEquals(ActionResult.Ok, controller.deleteItem(local))
        controller.lock()
        // What a sync leaves of a login deleted on another device, or from the web's trash: no row, nothing queued.
        cache.pending().filter { it.itemId == remote }.forEach { cache.dequeue(it.mutationId) }
        cache.deleteItem(remote)
        repeat(2) {
            controller.unlock(PASSWORD)
            settle { appliedLog.bytes == null } // the queue's sync has run: the records are gone
            controller.onForeground() // and again, as on every return to the app
            delay(100)
            assertEquals(listOf("Example"), controller.state.items.map { it.name }, "neither login comes back")
            assertTrue(controller.state.appliedSaves.isEmpty(), "and neither is listed: there is nothing left to undo")
            controller.lock()
        }
        assertNull(appliedLog.bytes)
        assertTrue(cache.pending().none { it.itemId == remote }, "nothing was queued for it either")
    }

    /** A record as the importer stores it, sealed to the account ([queueId] null: as a build before record ids stored it). */
    private fun Rig.storedSaveRecord(id: String, site: String, itemId: String, password: String, intent: Boolean, queueId: String? = null) {
        val entry = queueId?.let { ""","queueId":"$it"""" } ?: ""
        val record = """{"id":"$id","site":"$site","username":"me","itemId":"$itemId","replacedName":null,"password":"$password","keptOld":false,"appliedAtMs":${clocks.wall},"intent":$intent$entry}"""
        // As the app itself writes it: sealed to the account, with the MAC only it can make (round-9 review 2).
        val sealedRecord = Bytes.toB64(enrolled.account.sealLocalRecord(SaveImporter.APPLIED_RECORD, record.encodeToByteArray()))
        appliedLog.write("""["$sealedRecord"]""".encodeToByteArray())
    }

    @Test
    fun aSaveCutShortBeforeItsWriteIsJudgedAgainFromTheQueueAndWrittenOnce() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("a", "https://shop.example/", "me", "pw-1")
        // The lock fell between storing the intent and writing: the entry is still queued, and the vault has no such login.
        storedSaveRecord("a", "https://shop.example/", "00000000-0000-4000-8000-0000000000aa", "pw-1", intent = true)
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name }, "written once")
        assertEquals(listOf("shop.example"), controller.state.appliedSaves.map { it.host })
        assertTrue(queue.map.isEmpty())
        assertEquals(ActionResult.Ok, controller.undoAppliedSave(appliedId("shop.example")))
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
    }

    @Test
    fun aSaveCutShortAfterItsWriteIsListedWithItsUndoAndNotWrittenTwice() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("a", "https://shop.example/", "me", "pw-1")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        val written = controller.state.items.single { it.name == "shop.example" }.itemId
        controller.lock()
        // The lock fell between the write and the bookkeeping: the entry is still queued and the record is still an intent.
        capture("a", "https://shop.example/", "me", "pw-1")
        storedSaveRecord("r-1", "https://shop.example/", written, "pw-1", intent = true, queueId = "a")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name })
        assertTrue(queue.map.isEmpty(), "the entry it came from is gone")
        assertEquals(listOf("r-1"), controller.state.appliedSaves.map { it.id }, "listed under its own id")
        assertEquals(ActionResult.Ok, controller.undoAppliedSave("r-1"), "nothing was written that the list does not show")
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
    }

    @Test
    fun anIntentWithNothingBehindItIsDroppedAndWritesNothing() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        // No queue entry and no login: a restored container, or an undo whose bookkeeping a lock cut short.
        storedSaveRecord("a", "https://shop.example/", "00000000-0000-4000-8000-0000000000aa", "pw-1", intent = true)
        controller.unlock(PASSWORD)
        settle { appliedLog.bytes == null }
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
        assertTrue(controller.state.appliedSaves.isEmpty())
        // The same for a finished record whose login is no longer there.
        controller.lock()
        storedSaveRecord("b", "https://shop.example/", "00000000-0000-4000-8000-0000000000bb", "pw-1", intent = false)
        controller.unlock(PASSWORD)
        settle { appliedLog.bytes == null }
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
    }

    // ---- the extensions' save queue ----

    @Test
    fun aCapturedLoginIsSealedQueuedAndSavedAtUnlockWithNoSecondTap() = test {
        assertEquals(SaveQueued.NO_ACCOUNT, capture("a", "https://shop.example/login", "me", "s3cret-pw"), "nobody is signed in: no key to seal to")
        unlockedWithAPersonalVault()
        controller.onBackground() // the extension runs while the app is locked
        assertEquals(SaveQueued.QUEUED, capture("a", "https://shop.example/login", "me", "s3cret-pw"))
        val kept = queue.map.getValue("a").decodeToString()
        for (secret in listOf("s3cret-pw", "shop.example", "\"me\"")) assertFalse(kept.contains(secret), "at rest: $secret")
        assertTrue(controller.state.pendingSaves.isEmpty() && controller.state.appliedSaves.isEmpty(), "a locked app shows nothing")

        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.appliedSaves.isNotEmpty() }
        val applied = controller.state.appliedSaves.single()
        assertEquals(AppliedSaveView(applied.id, "shop.example", "me", null, false, clocks.wall, PERSONAL), applied)
        assertNotEquals("a", applied.id, "the list names its own record, never the queue entry")
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name })
        assertTrue(queue.map.isEmpty())
        // The record of it is kept sealed, in app-private storage, and survives a lock: the list is there after the next unlock.
        val log = assertNotNull(appliedLog.bytes).decodeToString()
        for (secret in listOf("s3cret-pw", "shop.example")) assertFalse(log.contains(secret), "the applied list at rest: $secret")
        controller.lock()
        assertTrue(controller.state.appliedSaves.isEmpty())
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf(applied), controller.state.appliedSaves)
        // Undo, a lock later, removes exactly the login it added.
        assertEquals(ActionResult.Ok, controller.undoAppliedSave(applied.id))
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
        assertTrue(controller.state.appliedSaves.isEmpty())
        assertNull(appliedLog.bytes)
    }

    @Test
    fun aNewPasswordReplacesThePersonalLoginKeepsTheOldOneAndCanBeUndone() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("same", "https://login.example.com/x", "fam", "hunter2") // already in the vault
        capture("new", "https://login.example.com/reset", "fam", "hunter3")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf(AppliedSaveView(appliedId("login.example.com"), "login.example.com", "fam", "Example", false, clocks.wall, PERSONAL)), controller.state.appliedSaves)
        assertEquals("hunter3", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals(1, controller.state.items.size, "updated, not duplicated")
        assertTrue(controller.state.pendingSaves.isEmpty())
        assertTrue(queue.map.isEmpty(), "the identical capture was dropped, the applied one left the queue")
        assertEquals(1, controller.itemDetail(ITEM_ID)?.previousPasswords, "the password it replaced is kept in the login's history")
        assertEquals(listOf(clocks.wall), controller.passwordHistory(ITEM_ID), "when it was retired, newest first")
        assertEquals("hunter2", controller.previousPassword(ITEM_ID, 0), "read one at a time, on request")
        assertNull(controller.previousPassword(ITEM_ID, 1))
        assertEquals(ActionResult.Ok, controller.undoAppliedSave(appliedId("login.example.com")))
        assertEquals("hunter2", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals(0, controller.itemDetail(ITEM_ID)?.previousPasswords, "the history entry is taken out again")
        assertTrue(controller.state.appliedSaves.isEmpty())
    }

    @Test
    fun anotherSchemeOrPortIsAnotherLoginNeverAReplacement() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("h", "http://login.example.com/reset", "fam", "from-cleartext")
        capture("p", "https://login.example.com:8443/", "fam", "other-port")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size == 2 }
        assertEquals("hunter2", controller.revealSecret(ITEM_ID, SecretField.PASSWORD), "the https login on the default port is untouched")
        assertEquals(setOf(null), controller.state.appliedSaves.map { it.replaced }.toSet(), "both were added as logins of their own")
        assertEquals(listOf(false, true), controller.state.appliedSaves.map { it.plainHttp }.sorted(), "one of them is the http login")
        assertEquals(3, controller.state.items.size)
    }

    @Test
    fun aCaptureWithNoSchemeIsNotAppliedOverALoginByItself() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("d", "login.example.com", "fam", "hunter3") // the system named only the domain
        controller.unlock(PASSWORD)
        settle { controller.state.pendingSaves.singleOrNull()?.reason != null }
        val row = controller.state.pendingSaves.single()
        assertEquals(SaveImporter.SCHEME_UNKNOWN, row.reason)
        assertEquals("Example", row.replaces)
        assertTrue(row.detail.contains("domain only"), row.detail)
        assertEquals("hunter2", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        // The person decides: a Save by hand writes what the row named.
        assertEquals(ActionResult.Ok, controller.confirmPendingSave("d"))
        assertEquals("hunter3", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertTrue(controller.state.pendingSaves.isEmpty())
        assertEquals(listOf("login.example.com"), controller.state.appliedSaves.map { it.host }, "a save by hand is listed and can be undone too")
    }

    @Test
    fun aStaleOrFutureCaptureDoesNotRollAPasswordBack() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("early", "https://login.example.com/x", "fam", "an-older-password")
        clocks.wall += DAY
        clocks.mono += DAY
        // The login is changed after that capture was made.
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        controller.dismissAppliedSaves()
        assertEquals(ActionResult.Ok, controller.saveLogin(ITEM_ID, LoginInput("Example", "fam", "the-current-one", listOf("https://login.example.com/x"), "", "", false)))
        controller.lock()
        clocks.wall -= DAY / 2 // a replayed entry: captured before the login's last change
        capture("replayed", "https://login.example.com/x", "fam", "an-older-password")
        clocks.wall += DAY / 2 + 10 * MINUTE
        capture("future", "https://login.example.com/y", "fam", "from-the-future")
        clocks.wall -= 10 * MINUTE
        controller.unlock(PASSWORD)
        settle { controller.state.pendingSaves.isNotEmpty() && controller.state.pendingSaves.all { it.reason != null } }
        assertEquals("the-current-one", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals(mapOf("future" to SaveImporter.FROM_THE_FUTURE), controller.state.pendingSaves.associate { it.id to it.reason }, "the older capture for the same login was dropped for the newer one, which is refused")
    }

    @Test
    fun theNewestCaptureOfALoginWinsWhateverItsId() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("z-first", "https://login.example.com/x", "fam", "first-attempt")
        clocks.wall += MINUTE
        capture("a-second", "https://login.example.com/x", "fam", "corrected")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(1, controller.state.appliedSaves.size)
        assertEquals("corrected", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertTrue(queue.map.isEmpty() && controller.state.pendingSaves.isEmpty(), "the older capture is dropped, not offered")
        // A further change to the same login in this unlock is not applied by itself.
        clocks.wall = System_now() + MINUTE // after the login's last change, which the vault stamps with the real time
        capture("third", "https://login.example.com/x", "fam", "yet-another")
        controller.onForeground()
        settle { controller.state.pendingSaves.singleOrNull()?.reason != null }
        assertEquals(SaveImporter.ALREADY_REPLACED, controller.state.pendingSaves.single().reason)
        assertEquals("corrected", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        // Nor in the next unlock, or any after it, while the first replace is still listed.
        repeat(2) {
            controller.lock()
            controller.unlock(PASSWORD)
            settle { controller.state.pendingSaves.singleOrNull()?.reason != null }
            assertEquals(SaveImporter.ALREADY_REPLACED, controller.state.pendingSaves.single().reason)
            assertEquals("corrected", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        }
        // Once the person has read and dismissed that record, the login can be updated by a save again.
        controller.dismissAppliedSaves()
        controller.lock()
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals("yet-another", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
    }

    @Test
    fun whatTheCapHeldBackIsNeverSavedByItselfLater() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        repeat(7) { capture("e$it", "https://shop$it.example/", "me", "pw$it") }
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size + controller.state.pendingSaves.count { it.reason != null } == 7 }
        val heldBack = controller.state.pendingSaves.map { it.id }
        assertEquals(2, heldBack.size)
        // Fifty forged entries are five automatic saves, not five at every unlock.
        repeat(2) {
            controller.lock()
            controller.unlock(PASSWORD)
            settle { controller.state.pendingSaves.size == 2 && controller.state.pendingSaves.all { it.reason != null } }
            controller.onForeground()
            delay(100)
            assertEquals(heldBack, controller.state.pendingSaves.map { it.id })
            assertEquals(listOf(SaveImporter.TOO_MANY, SaveImporter.TOO_MANY), controller.state.pendingSaves.map { it.reason })
            assertEquals(6, controller.state.items.size)
        }
        // Dismissing the list of what was saved does not release them either.
        controller.dismissAppliedSaves()
        controller.lock()
        controller.unlock(PASSWORD)
        settle { controller.state.pendingSaves.size == 2 && controller.state.pendingSaves.all { it.reason != null } }
        assertEquals(6, controller.state.items.size)
        // By hand they are saved or discarded as before, and the hold goes with the entry.
        assertEquals(ActionResult.Ok, controller.confirmPendingSave(heldBack[0]))
        controller.discardPendingSave(heldBack[1])
        assertEquals(7, controller.state.items.size)
        assertTrue(controller.state.pendingSaves.isEmpty())
        controller.dismissAppliedSaves()
        assertNull(appliedLog.bytes, "nothing is kept once nothing is listed or held")
    }

    @Test
    fun aLockDuringAnAutomaticSaveKeepsTheListTheHoldsAndTheIntent() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        repeat(7) { capture("e$it", "https://shop$it.example/", "me", "pw$it") }
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size + controller.state.pendingSaves.count { it.reason != null } == 7 }
        val listed = controller.state.appliedSaves.map { it.id }.toSet()
        val heldBack = controller.state.pendingSaves.map { it.id }.toSet()
        assertEquals(5, listed.size)
        controller.lock()
        capture("late", "https://late.example/", "me", "pw-late")
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        // The automatic save of the new capture is in flight (its push waits) when the app leaves the foreground.
        val pushing = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        routes["/sync/push"] = {
            pushing.complete(Unit)
            release.await()
            throw IOException("unreachable")
        }
        withTimeout(10_000) { pushing.await() }
        val before = assertNotNull(appliedLog.bytes).decodeToString()
        controller.onBackground() // an automatic save holds no busy: the lock lands at once
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        release.complete(Unit)
        delay(300) // the write that was cut short finishes failing
        val after = assertNotNull(appliedLog.bytes, "the lock persisted nothing, and the failed write deleted nothing").decodeToString()
        assertEquals(before, after, "nothing was written for the session that ended")
        // The next unlock finds the list, the holds and the intent, and settles the intent.
        routes["/sync/push"] = { throw IOException("unreachable") }
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        settle { controller.state.appliedSaves.size >= 5 && controller.state.pendingSaves.count { it.reason == SaveImporter.TOO_MANY } == 2 }
        assertTrue(controller.state.appliedSaves.map { it.id }.containsAll(listed), "the list survived the lock")
        assertEquals(heldBack, controller.state.pendingSaves.filter { it.reason == SaveImporter.TOO_MANY }.map { it.id }.toSet(), "the holds too")
        settle { "late.example" in controller.state.appliedSaves.map { it.host } }
        assertEquals(1, controller.state.items.count { it.name == "late.example" }, "the cut-short save is listed once, never written twice")
        assertTrue(queue.map.keys.none { it == "late" })
    }

    @Test
    fun anUndoDoesNotRemoveAnAddedLoginThatWasEditedInAnyField() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("added", "https://shop.example/", "me", "pw")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        val added = controller.state.items.single { it.name == "shop.example" }.itemId
        // The same username and password, but a note and a code were added since: that is the person's work.
        assertEquals(ActionResult.Ok, controller.saveLogin(added, LoginInput("shop.example", "me", "pw", listOf("https://shop.example"), "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "the recovery codes are in the safe", false)))
        val record = appliedId("shop.example")
        assertEquals(ActionResult.Failed(SaveImporter.UNDO_EDITED), controller.undoAppliedSave(record))
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name })
        assertEquals(listOf(record), controller.state.appliedSaves.map { it.id }, "the record stays, with the reason said")
    }

    @Test
    fun aNewerCaptureIsNotDroppedBecauseAnOlderOneWasAppliedLater() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("first", "https://shop.example/", "me", "pw-1")
        clocks.wall += 10 * MINUTE
        controller.unlock(PASSWORD) // applied ten minutes after it was captured
        settle { controller.state.appliedSaves.isNotEmpty() }
        controller.lock()
        // A capture made after the first one, though before the first was applied: it is the newer password.
        clocks.wall -= 5 * MINUTE
        capture("second", "https://shop.example/", "me", "pw-2")
        clocks.wall += 6 * MINUTE
        controller.unlock(PASSWORD)
        settle { controller.state.pendingSaves.singleOrNull()?.reason != null }
        assertEquals("second", controller.state.pendingSaves.single().id, "listed for the person to decide, not dropped unread")
    }

    @Test
    fun atMostFiveAreSavedByThemselvesAndAllCanBeUndoneAtOnce() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        repeat(7) { capture("e$it", "https://shop$it.example/", "me", "pw$it") }
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size + controller.state.pendingSaves.count { it.reason != null } == 7 }
        assertEquals(SaveImporter.MAX_AUTO_PER_RUN, controller.state.appliedSaves.size)
        assertEquals(listOf(SaveImporter.TOO_MANY, SaveImporter.TOO_MANY), controller.state.pendingSaves.map { it.reason })
        assertEquals(6, controller.state.items.size)
        // The rest are saved by hand, one at a time.
        assertEquals(ActionResult.Ok, controller.confirmPendingSave(controller.state.pendingSaves.first().id))
        assertEquals(7, controller.state.items.size)
        // Undo all takes back every one of them, and leaves the login that was there before.
        assertEquals(ActionResult.Ok, controller.undoAllAppliedSaves())
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
        assertTrue(controller.state.appliedSaves.isEmpty())
        assertEquals(1, controller.state.pendingSaves.size, "what was never saved is still listed")
    }

    @Test
    fun anUndoNeverOverwritesALaterChange() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("new", "https://login.example.com/reset", "fam", "hunter3")
        capture("added", "https://shop.example/", "me", "pw")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size == 2 }
        // The person changes both again before reaching for Undo.
        assertEquals(ActionResult.Ok, controller.saveLogin(ITEM_ID, LoginInput("Example", "fam", "edited-since", listOf("https://login.example.com/x"), "", "", false)))
        val added = controller.state.items.single { it.name == "shop.example" }.itemId
        assertEquals(ActionResult.Ok, controller.saveLogin(added, LoginInput("shop.example", "me", "edited-too", listOf("https://shop.example"), "", "", false)))
        val replaced = appliedId("login.example.com")
        assertIs<ActionResult.Failed>(controller.undoAppliedSave(replaced))
        assertIs<ActionResult.Failed>(controller.undoAppliedSave(appliedId("shop.example")))
        assertIs<ActionResult.Failed>(controller.undoAllAppliedSaves())
        assertEquals("edited-since", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals("edited-too", controller.revealSecret(added, SecretField.PASSWORD), "a login changed since it was added is not deleted")
        assertFalse(controller.state.busy)
        controller.dismissAppliedSaves()
        assertTrue(controller.state.appliedSaves.isEmpty())
        assertNull(appliedLog.bytes)
        assertEquals(ActionResult.NotDone(null), controller.undoAppliedSave(replaced), "dismissed: nothing left to undo from here")
    }

    /**
     * Two saves whose queue entries had the same id (the entry of the first was gone once it was applied, and the next
     * capture reused its name: an extension that names entries badly, or a forged entry). Each is listed under an id
     * the importer minted, and each keeps its own Undo: a later record never replaces an earlier one.
     */
    @Test
    fun twoSavesWhoseEntriesSharedAnIdAreBothListedEachWithItsOwnUndo() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("s-1", "https://login.example.com/reset", "fam", "hunter3") // alice's changed password
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size == 1 }
        controller.lock()
        capture("s-1", "https://shop.example/", "me", "pw") // the next save, under the same entry id
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size == 2 }
        assertEquals(setOf("login.example.com", "shop.example"), controller.state.appliedSaves.map { it.host }.toSet())
        assertTrue(controller.state.appliedSaves.none { it.id == "s-1" })
        // Both survive a lock.
        controller.lock()
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size == 2 }
        // The first one's Undo still puts the replaced password back.
        assertEquals(ActionResult.Ok, controller.undoAppliedSave(appliedId("login.example.com")))
        assertEquals("hunter2", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals(ActionResult.Ok, controller.undoAppliedSave(appliedId("shop.example")))
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
        assertTrue(controller.state.appliedSaves.isEmpty())
    }

    @Test
    fun undoAllTakesBackBothSavesWhoseEntriesSharedAnId() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("s-1", "https://login.example.com/reset", "fam", "hunter3")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size == 1 }
        controller.lock()
        capture("s-1", "https://shop.example/", "me", "pw")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.size == 2 }
        assertEquals(ActionResult.Ok, controller.undoAllAppliedSaves())
        assertEquals("hunter2", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
        assertTrue(controller.state.appliedSaves.isEmpty())
        assertNull(appliedLog.bytes)
    }

    @Test
    fun aCaptureThatCannotBeSavedStaysListedWithItsReason() = test {
        // This rig's vault has no personal vault confirmed on the device, so a new login has nowhere to go.
        unlocked()
        settle { queue.key != null }
        controller.lock()
        capture("a", "https://shop.example/login", "me", "s3cret-pw")
        controller.unlock(PASSWORD)
        settle { controller.state.pendingSaves.singleOrNull()?.reason != null }
        val row = controller.state.pendingSaves.single()
        assertEquals(SaveImporter.PERSONAL_UNCONFIRMED, row.reason)
        assertEquals("s3cret-pw", controller.pendingSavePassword("a"))
        assertEquals(listOf("Example"), controller.state.items.map { it.name })
        assertIs<ActionResult.Failed>(controller.confirmPendingSave("a"))
        assertEquals(setOf("a"), queue.map.keys, "a failed save keeps the capture")
        assertFalse(controller.state.busy)
        controller.discardPendingSave("a")
        assertTrue(controller.state.pendingSaves.isEmpty())
        assertTrue(queue.map.isEmpty())
        assertEquals(1, controller.state.items.size)
    }

    @Test
    fun anOldCaptureAndAForeignKeyAreDealtWithAtUnlock() = test {
        unlocked()
        settle { queue.key != null }
        controller.lock()
        capture("old", "shop.example", "me", "pw")
        clocks.wall += SaveQueue.MAX_AGE_MS
        clocks.mono += SaveQueue.MAX_AGE_MS
        // Something replaced the published key: what is sealed to it cannot be read by this account.
        val other = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        queue.key = json.encodeToString(SaveKeyPublication.serializer(), SaveKeyPublication(origin = HOME, userId = reg.userId, identityPub = io.silencelen.andvari.core.crypto.Bytes.toB64(other.publicKey))).encodeToByteArray()
        capture("lost", "shop.example", "me", "pw")
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy()), HttpStatusCode.OK, headers) }
        controller.startAndLand()
        controller.unlock(PASSWORD)
        settle { queue.map.isEmpty() && controller.state.notice != null }
        assertTrue(controller.state.pendingSaves.isEmpty(), "the stale capture and the unreadable one are gone")
        assertEquals("Some logins captured for saving could not be read and were removed. Sign in on that site again to capture them.", controller.state.notice)
        assertEquals(enrolled.account.identityPub.toList(), io.silencelen.andvari.core.crypto.Bytes.fromB64(assertNotNull(SaveQueue.decodePublication(queue.key)).identityPub).toList(), "the key is this account's again")
    }

    @Test
    fun theQueueIsBoundedAndRefusesWhatItCannotKeep() = test {
        unlocked()
        settle { queue.key != null }
        controller.lock()
        assertEquals(SaveQueued.REFUSED, capture("a", "shop.example", "me", ""), "no password, nothing to save")
        assertEquals(SaveQueued.REFUSED, capture("a", "shop.example", "me", "x".repeat(SaveQueue.MAX_FIELD_CHARS + 1)))
        assertEquals(SaveQueued.REFUSED, capture("a", "shop.example", "u".repeat(SaveQueue.MAX_FIELD_CHARS + 1), "pw"))
        assertEquals(SaveQueued.REFUSED, capture("a", "s".repeat(SaveQueue.MAX_SITE_CHARS + 1), "me", "pw"))
        assertEquals(SaveQueued.REFUSED, capture("../escape", "shop.example", "me", "pw"), "an id is a file name")
        repeat(SaveQueue.MAX_ENTRIES) { assertEquals(SaveQueued.QUEUED, capture("e$it", "shop$it.example", "me", "pw")) }
        assertEquals(SaveQueued.REFUSED, capture("one-more", "shop.example", "me", "pw"), "full")
        assertTrue(queue.map.values.all { it.size <= SaveQueue.MAX_ENTRY_BYTES })
    }

    @Test
    fun anEntryIsNeverReplacedAndATakenIdIsTriedAgainUnderANewOne() = test {
        unlocked()
        settle { queue.key != null }
        controller.lock()
        assertEquals(SaveQueued.QUEUED, capture("e0", "shop.example", "me", "pw"))
        val first = queue.map.getValue("e0").copyOf()
        assertEquals(SaveQueued.REFUSED, capture("e0", "shop.example", "me", "pw2"), "every id it is given is taken")
        assertContentEquals(first, queue.map.getValue("e0"), "the entry is untouched")
        val ids = ArrayDeque(listOf("e0", "e1"))
        assertEquals(SaveQueued.QUEUED, SaveQueue.enqueue(queue, crypto, "shop.example", "me", "pw3", clocks.wall, "autofill") { ids.removeFirst() })
        assertEquals(setOf("e0", "e1"), queue.map.keys)
        assertContentEquals(first, queue.map.getValue("e0"))
        // Ids minted for the capture: 128 random bits each, never the same twice.
        val minted = (1..20).map { SaveQueue.newId(crypto) }
        assertTrue(minted.all { SaveQueue.validId(it) && it.matches(Regex("s-[0-9a-f]{32}")) })
        assertEquals(minted.size, minted.toSet().size)
    }

    /**
     * The AutoFill extension's saves while the app is closed: each is a new extension process, whose save request
     * says sessionID "1" every time. Every one reaches the next unlock: none replaces another.
     */
    @Test
    fun severalSavesMadeBeforeTheAppIsOpenedAllReachTheNextUnlock() = test {
        unlocked()
        settle { queue.key != null }
        controller.lock()
        // As IosAutofill.queueSave does it: the id is minted here, whatever the request called itself.
        for ((site, password) in listOf("https://login.example.com/x" to "changed-1", "https://shop.example/" to "pw", "https://other.example/" to "pw-2")) {
            assertEquals(SaveQueued.QUEUED, SaveQueue.enqueue(queue, crypto, site, if (site.contains("login.")) "fam" else "me", password, clocks.wall, "autofill"))
        }
        assertEquals(3, queue.map.size, "three saves, three entries")
        controller.unlock(PASSWORD)
        settle { controller.state.pendingSaves.size + controller.state.appliedSaves.size == 3 }
        val hosts = (controller.state.pendingSaves.map { it.host } + controller.state.appliedSaves.map { it.host }).toSet()
        assertEquals(setOf("login.example.com", "shop.example", "other.example"), hosts)
    }

    @Test
    fun aTamperedForeignOrOversizedEntryIsRemovedNotShown() = test {
        unlocked()
        settle { queue.key != null }
        controller.lock()
        capture("good", "shop.example", "me", "pw")
        val good = queue.map.getValue("good")
        // A flipped byte in the seal.
        val entry = json.decodeFromString(QueuedSave.serializer(), good.decodeToString())
        val sealed = io.silencelen.andvari.core.crypto.Bytes.fromB64(entry.sealed).also { it[40] = (it[40].toInt() xor 1).toByte() }
        queue.map["tampered"] = json.encodeToString(QueuedSave.serializer(), entry.copy(sealed = io.silencelen.andvari.core.crypto.Bytes.toB64(sealed))).encodeToByteArray()
        // Another account's entry, and one relabelled as this account's (its inside still names the other).
        val other = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val inside = json.encodeToString(CapturedLogin.serializer(), CapturedLogin(origin = HOME, userId = "someone-else", site = "shop.example", username = "me", password = "pw", capturedAtMs = clocks.wall, source = "safari"))
        val forOther = io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.sealTo(other.publicKey, inside.encodeToByteArray()))
        queue.map["foreign"] = json.encodeToString(QueuedSave.serializer(), QueuedSave(origin = HOME, userId = "someone-else", sealed = forOther)).encodeToByteArray()
        val relabelled = io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.sealTo(enrolled.account.identityPub, inside.encodeToByteArray()))
        queue.map["relabelled"] = json.encodeToString(QueuedSave.serializer(), QueuedSave(origin = HOME, userId = reg.userId, sealed = relabelled)).encodeToByteArray()
        queue.map["elsewhere"] = json.encodeToString(QueuedSave.serializer(), entry.copy(origin = "https://other.example")).encodeToByteArray()
        queue.map["garbage"] = "not json".encodeToByteArray()
        queue.map["huge"] = ByteArray(SaveQueue.MAX_ENTRY_BYTES + 1) { 'a'.code.toByte() }

        controller.unlock(PASSWORD)
        settle { queue.map.keys == setOf("good") && controller.state.pendingSaves.isNotEmpty() }
        assertEquals(listOf("good"), controller.state.pendingSaves.map { it.id })
    }

    @Test
    fun signOutEmptiesTheQueueTheKeyAndTheAppliedList() = test {
        unlockedWithAPersonalVault()
        settle { queue.key != null }
        controller.lock()
        capture("a", "https://shop.example/", "me", "pw")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertNotNull(appliedLog.bytes)
        assertEquals(SaveQueued.QUEUED, capture("b", "https://other.example/", "me", "pw"))
        controller.signOut()
        assertNull(queue.key)
        assertTrue(queue.map.isEmpty())
        assertNull(appliedLog.bytes, "the list of what was saved goes with the account")
        assertTrue(controller.state.appliedSaves.isEmpty())
        assertEquals(SaveQueued.NO_ACCOUNT, capture("c", "shop.example", "me", "pw"))
    }

    @Test
    fun aForbiddingPolicyPublishesNoKeyAndKeepsNoQueue() = test {
        seedSession()
        queue.map["stale"] = "x".encodeToByteArray()
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(offlineCacheAllowed = false)), HttpStatusCode.OK, headers) }
        controller.startAndLand()
        controller.unlock(PASSWORD)
        settle { queue.map.isEmpty() }
        assertNull(queue.key)
        assertTrue(controller.state.pendingSaves.isEmpty())
    }

    @Test
    fun aServerSwitchEmptiesTheQueue() = test {
        unlocked()
        settle { queue.key != null }
        capture("a", "shop.example", "me", "pw")
        controller.lock()
        assertNotNull(queue.key, "a lock keeps the key: the extension captures while the app is locked")
        controller.changeServer()
        controller.chooseServer("https://other.example")
        assertEquals(ActionResult.Ok, controller.confirmTrustGate())
        assertNull(queue.key)
        assertTrue(queue.map.isEmpty())
    }

    @Test
    fun aDeviceWithNoBiometricSaysSo() = test {
        quickKeys.biometric = false
        unlocked()
        assertFalse(controller.state.quickUnlock.available)
        assertEquals(QuickGate.NO_BIOMETRIC, controller.state.quickUnlock.refusal)
        assertEquals("Set up Face ID or Touch ID on this iPhone first.", controller.state.quickUnlock.reason)
    }

    @Test
    fun quickUnlockTurnsOnUnlocksAndTurnsOff() = test {
        unlocked()
        assertTrue(controller.state.quickUnlock.available)
        assertEquals(ActionResult.Ok, controller.enableQuickUnlock(null))
        assertTrue(controller.state.quickUnlock.enrolled)
        controller.lock()
        assertTrue(controller.state.quickUnlock.usable, "the Face ID button shows on the lock screen")
        quickKeys.next = { QuickRecover.Ok(enrolled.account.uvkCopyForPlatformWrap()) }
        assertEquals(ActionResult.Ok, controller.unlockWithBiometrics(null))
        assertEquals(AppScreen.VAULT, controller.state.screen)
        controller.disableQuickUnlock()
        assertFalse(controller.state.quickUnlock.enrolled)
    }

    @Test
    fun aCancelledPromptLeavesTheLockScreen() = test {
        unlocked()
        controller.enableQuickUnlock(null)
        controller.lock()
        quickKeys.next = { QuickRecover.Fallback(null) }
        assertEquals(ActionResult.NotDone(null), controller.unlockWithBiometrics("Unlock"))
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        assertFalse(controller.state.busy)
    }

    @Test
    fun aSaveIsValidatedAndAFailedOneIsSaidNotThrown() = test {
        unlocked()
        fun input(name: String = "New", totp: String = "") = LoginInput(name, "me", "pw", listOf("https://new.example"), "", totp, false)
        assertIs<ActionResult.Failed>(controller.saveLogin(null, input(name = " ")))
        assertIs<ActionResult.Failed>(controller.saveLogin(null, input(totp = "not base32 !")))
        assertIs<ActionResult.Failed>(controller.saveLogin("no such item", input()))
        // Offline, on a cache that is not durable, the engine cannot queue it: a sentence, not a crash.
        assertIs<ActionResult.Failed>(controller.saveLogin(null, input()))
        assertFalse(controller.state.busy)
    }

    @Test
    fun signOutEndsTheSessionAtTheServerAndDeletesThisAccountsData() = test {
        unlocked()
        controller.enableQuickUnlock(null)
        assertEquals(ActionResult.Ok, controller.signOut())
        assertTrue(calls.any { it.endsWith("/auth/logout") })
        assertTrue("$homeKey/${reg.userId}" in namespaces.deleted)
        assertTrue("$homeKey/${reg.userId}" in quickKeys.wiped)
        assertNull(store.load())
        assertEquals(AppScreen.WELCOME, controller.state.screen)
        assertNull(store.origin(homeKey).passwordStamp(reg.userId))
    }

    @Test
    fun nothingThrowsAcrossTheBoundary() = test {
        controller.startAndLand()
        assertEquals(ActionResult.NotDone(null), controller.unlock(PASSWORD), "no stored session")
        assertEquals(ActionResult.NotDone(null), controller.saveLogin(null, LoginInput("x", "", "", emptyList(), "", "", false)))
        assertNull(controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertNull(controller.oneTimeCode(ITEM_ID))
        assertNull(controller.recoveryPhrase())
        assertTrue(controller.generatePassword(GeneratorSettings(16, false, false, false, false, false)).isNotEmpty(), "impossible settings still give a password")
        assertEquals(20, controller.generatePassword(GeneratorSettings.standard).length)
    }

    // ---- sign-in and enroll ----

    @Test
    fun aSignInThatNeedsAnAuthenticatorCodeAsksForIt() = test {
        controller.startAndLand()
        routes["/auth/prelogin"] = { respond("""{"kdfSalt":"${reg.kdfSalt}","kdfParams":{"v":1,"alg":"argon2id13","ops":3,"memBytes":67108864}}""", HttpStatusCode.OK, headers) }
        routes["/auth/login"] = { respond("""{"error":"totp_required","message":"code"}""", HttpStatusCode.Forbidden, headers) }
        assertEquals(ActionResult.NeedsCode(wrongCode = false), controller.signIn(EMAIL, PASSWORD, null))
        assertTrue(controller.state.totpRequired)
        assertNull(store.load())
    }

    @Test
    fun anInviteForAnotherServerGoesThroughTheTrustGateFirst() = test {
        controller.startAndLand()
        val link = assertNotNull(EnrollLink.compose("https://other.example", "tok", "new@example.com"))
        assertEquals(ActionResult.OtherServer("https://other.example"), controller.enroll(EnrollForm(link, "", "", PASSWORD, false, "")))
        assertFalse(calls.any { it.endsWith("/auth/register") })
    }

    @Test
    fun anEnrollRevealsThePhraseOnceAndConfirmsIt() = test {
        controller.startAndLand()
        routes["/auth/register"] = { request ->
            val req = json.decodeFromString(RegisterRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            val keys = AccountKeys(req.kdfSalt, req.kdfParams, req.wrappedUvk, req.encryptedIdentitySeed, req.identityPub, "", personalWrap = req.personalWrap)
            respond(json.encodeToString(SessionResponse.serializer(), SessionResponse(req.userId, DEVICE, "a1", "r1", keys, false, recoveryPieceId = "piece-1")), HttpStatusCode.OK, headers)
        }
        routes["/sync"] = { respond(EMPTY_SYNC, HttpStatusCode.OK, headers) }
        assertEquals(ActionResult.Ok, controller.enroll(EnrollForm("tok", "new@example.com", "", PASSWORD, false, "")))
        assertEquals(AppScreen.RECOVERY_REVEAL, controller.state.screen)
        assertTrue(controller.state.recoveryWaived)
        val phrase = assertNotNull(controller.recoveryPhrase())
        assertEquals(ActionResult.Mismatch, controller.confirmRecoveryPhrase("not the phrase"))
        val confirmed = CompletableDeferred<Unit>()
        routes["/recovery/self/confirm"] = { confirmed.complete(Unit); respond("{}", HttpStatusCode.OK, headers) }
        assertEquals(ActionResult.Ok, controller.confirmRecoveryPhrase(phrase))
        assertEquals(AppScreen.VAULT, controller.state.screen, "the vault opens without waiting on the confirm")
        assertNull(controller.recoveryPhrase(), "shown once")
        withTimeout(10_000) { confirmed.await() } // the enroll path's confirm still reaches the server
    }

    // ---- change server, identity code, clipboard policy ----

    @Test
    fun changingServerCanBeCancelledBackToWhereItCameFrom() = test {
        seedSession()
        controller.startAndLand()
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        controller.changeServer()
        assertEquals(AppScreen.CHOOSE_SERVER, controller.state.screen)
        controller.cancelChangeServer()
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        assertEquals(HOME, controller.state.server)
    }

    @Test
    fun withNoServerChosenThereIsNothingToCancelTo() = test(origin = null) {
        controller.startAndLand()
        assertEquals(AppScreen.CHOOSE_SERVER, controller.state.screen)
        controller.cancelChangeServer()
        assertEquals(AppScreen.CHOOSE_SERVER, controller.state.screen)
    }

    @Test
    fun theIdentityCodeIsThisDevicesKeyAndOnlyWhileUnlocked() = test {
        seedSession()
        controller.startAndLand()
        assertNull(controller.identityCode())
        assertNull(controller.identityCodeFull())
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        assertEquals(enrolled.account.identityFingerprintShort(), controller.identityCode())
        assertEquals(enrolled.account.identityFingerprintFull(), controller.identityCodeFull())
        controller.lock()
        assertNull(controller.identityCode())
    }

    @Test
    fun theClipboardLifetimeIsTheServersClamped() = test {
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(clipboardClearSeconds = 86_400)), HttpStatusCode.OK, headers) }
        controller.startAndLand()
        settle { controller.state.policy != null }
        assertEquals(300, controller.state.policy?.clipboardClearSeconds)
    }

    @Test
    fun aZeroClipboardLifetimeStillClears() = test {
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(clipboardClearSeconds = 0)), HttpStatusCode.OK, headers) }
        controller.startAndLand()
        settle { controller.state.policy != null }
        assertEquals(1, controller.state.policy?.clipboardClearSeconds)
    }

    // ---- forgot the master password ----

    private val phrase get() = MemberRecovery.displayForm(enrolled.recoverySecret)
    private val serverPolicy = ClientPolicy()

    /** A server that verifies [EMAIL] with the enrolled phrase and takes a commit; what it was sent lands in [commits]. */
    private fun Rig.recoveryServer(commits: MutableList<RecoveryCommitRequest>) {
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), serverPolicy), HttpStatusCode.OK, headers) }
        val piece = reg.memberRecovery!!
        routes["/recovery/self/verify"] = { request ->
            val body = (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString()
            if (body.contains(MemberRecovery.deriveAuthKey(crypto, enrolled.recoverySecret)) && body.contains(EMAIL)) {
                respond(json.encodeToString(RecoveryVerifyResponse.serializer(), RecoveryVerifyResponse(reg.userId, "ticket-1", piece.recoveryWrappedUvk, reg.encryptedIdentitySeed, reg.identityPub)), HttpStatusCode.OK, headers)
            } else {
                respond("""{"error":"unauthorized","message":"no"}""", HttpStatusCode.Unauthorized, headers)
            }
        }
        routes["/recovery/self/commit"] = { request ->
            commits += json.decodeFromString(RecoveryCommitRequest.serializer(), (request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString())
            respond("{}", HttpStatusCode.OK, headers)
        }
    }

    @Test
    fun recoveryResetsThePasswordOverTheSameKeysAndEndsThisDevicesSession() = test {
        val commits = mutableListOf<RecoveryCommitRequest>()
        recoveryServer(commits)
        seedSession()
        controller.startAndLand()
        controller.openRecover()
        assertEquals(AppScreen.RECOVER, controller.state.screen)
        assertFalse(controller.state.recoverVerified)
        assertEquals(ActionResult.Ok, controller.recoverVerify(" $EMAIL ", phrase.chunked(4).joinToString(" ")))
        assertTrue(controller.state.recoverVerified)
        assertEquals(ActionResult.Failed(RecoverCopy.WEAK_PASSWORD), controller.recoverCommit("short"))
        assertTrue(commits.isEmpty())
        val fresh = "a brand new master password 77!"
        assertEquals(ActionResult.Ok, controller.recoverCommit(fresh))
        val sent = commits.single()
        assertEquals("ticket-1", sent.recoveryTicket)
        assertEquals(serverPolicy.kdfParams, sent.newKdfParams, "the server policy's parameters, not a default")
        // The same UVK under the new password: the commit's wrap opens the account the enrolment made.
        val keys = cached.copy(kdfSalt = sent.newKdfSalt, kdfParams = sent.newKdfParams, wrappedUvk = sent.newWrappedUvk)
        assertEquals(enrolled.account.identityFingerprintFull(), Account.unlock(reg.userId, fresh, keys, crypto).identityFingerprintFull())
        // Every session of the account is revoked server-side: this device forgets its own.
        assertNull(store.load())
        assertEquals(AppScreen.WELCOME, controller.state.screen)
        assertEquals(RecoverCopy.DONE, controller.state.notice)
        assertFalse(controller.state.recoverVerified)
        assertNull(snapshots.read(), "nothing shared with the extensions outlives the session")
    }

    @Test
    fun aRefusedPhraseSaysOneThingWhicheverPartWasWrong() = test {
        recoveryServer(mutableListOf())
        controller.startAndLand()
        controller.openRecover()
        val wrong = MemberRecovery.displayForm(crypto.randomBytes(32))
        val refusal = ActionResult.Failed("We couldn't verify that email and recovery phrase.")
        assertEquals(refusal, controller.recoverVerify(EMAIL, wrong))
        assertEquals(refusal, controller.recoverVerify("other@example.com", phrase))
        assertFalse(controller.state.recoverVerified)
        assertEquals(ActionResult.Failed(RecoverCopy.NOT_A_PHRASE), controller.recoverVerify(EMAIL, "not a phrase !!"))
        assertEquals(ActionResult.Failed(RecoverCopy.EXPIRED), controller.recoverCommit("a brand new master password 77!"))
    }

    @Test
    fun cancellingRecoveryForgetsWhatWasVerified() = test {
        val commits = mutableListOf<RecoveryCommitRequest>()
        recoveryServer(commits)
        seedSession()
        controller.startAndLand()
        controller.openRecover()
        assertEquals(ActionResult.Ok, controller.recoverVerify(EMAIL, phrase))
        controller.cancelRecover()
        assertEquals(AppScreen.UNLOCK, controller.state.screen)
        assertEquals(ActionResult.NotDone(null), controller.recoverCommit("a brand new master password 77!"))
        controller.openRecover()
        assertFalse(controller.state.recoverVerified, "a fresh entry starts at the first step")
        assertEquals(ActionResult.Failed(RecoverCopy.EXPIRED), controller.recoverCommit("a brand new master password 77!"))
        assertTrue(commits.isEmpty())
        assertNotNull(store.load(), "nothing was reset, so nothing is forgotten")
    }

    @Test
    fun theNewPasswordStepDoesNotOutliveIdleOrTheBackground() = test {
        val commits = mutableListOf<RecoveryCommitRequest>()
        recoveryServer(commits)
        controller.startAndLand()
        controller.openRecover()
        assertEquals(ActionResult.Ok, controller.recoverVerify(EMAIL, phrase))
        clocks.mono += RecoverCopy.IDLE_MS - 1
        controller.tick()
        assertEquals(AppScreen.RECOVER, controller.state.screen)
        clocks.mono += 1
        controller.tick()
        assertEquals(AppScreen.WELCOME, controller.state.screen)
        assertEquals(RecoverCopy.TIMEOUT, controller.state.notice)

        controller.openRecover()
        controller.onBackground()
        assertEquals(AppScreen.WELCOME, controller.state.screen, "the first step does not survive the background either")
        controller.openRecover()
        assertEquals(ActionResult.Ok, controller.recoverVerify(EMAIL, phrase))
        controller.onBackground()
        assertEquals(AppScreen.WELCOME, controller.state.screen)
        assertEquals(ActionResult.NotDone(null), controller.recoverCommit("a brand new master password 77!"))
        assertTrue(commits.isEmpty())
    }

    @Test
    fun aVerifyInFlightWhenTheAppLeavesTheForegroundLandsNowhere() = test {
        recoveryServer(mutableListOf())
        val asked = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val verify = routes.getValue("/recovery/self/verify")
        routes["/recovery/self/verify"] = { request ->
            asked.complete(Unit)
            release.await()
            verify(request)
        }
        controller.startAndLand()
        controller.openRecover()
        kotlinx.coroutines.coroutineScope {
            val result = async { controller.recoverVerify(EMAIL, phrase) }
            withTimeout(10_000) { asked.await() }
            controller.onBackground()
            assertEquals(AppScreen.WELCOME, controller.state.screen)
            release.complete(Unit)
            assertEquals(ActionResult.NotDone(null), result.await())
        }
        assertFalse(controller.state.recoverVerified, "the answer of a verify the person left is not kept")
        assertEquals(AppScreen.WELCOME, controller.state.screen)
    }

    @Test
    fun aResetThatLandsAfterTheAppLeftTheForegroundSaysItIsDone() = test {
        val commits = mutableListOf<RecoveryCommitRequest>()
        recoveryServer(commits)
        val committing = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val commit = routes.getValue("/recovery/self/commit")
        routes["/recovery/self/commit"] = { request ->
            committing.complete(Unit)
            release.await()
            commit(request)
        }
        seedSession()
        controller.startAndLand()
        controller.openRecover()
        assertEquals(ActionResult.Ok, controller.recoverVerify(EMAIL, phrase))
        kotlinx.coroutines.coroutineScope {
            val result = async { controller.recoverCommit("a brand new master password 77!") }
            withTimeout(10_000) { committing.await() }
            controller.onBackground()
            assertEquals(RecoverCopy.TIMEOUT, controller.state.notice)
            release.complete(Unit)
            result.await()
        }
        assertEquals(1, commits.size, "the server took the reset")
        assertEquals(RecoverCopy.DONE, controller.state.notice, "so the person is told it is done, not that it timed out")
        assertNull(store.load(), "and this device's session, revoked by the reset, is gone")
        assertEquals(AppScreen.WELCOME, controller.state.screen)
    }

    @Test
    fun aFailedCommitKeepsTheVerifiedStepForARetry() = test {
        val commits = mutableListOf<RecoveryCommitRequest>()
        recoveryServer(commits)
        controller.startAndLand()
        controller.openRecover()
        assertEquals(ActionResult.Ok, controller.recoverVerify(EMAIL, phrase))
        routes["/recovery/self/commit"] = { throw IOException("unreachable") }
        assertEquals(ActionResult.Failed(HouseholdCopy.UNREACHABLE), controller.recoverCommit("a brand new master password 77!"))
        assertTrue(controller.state.recoverVerified)
        recoveryServer(commits)
        assertEquals(ActionResult.Ok, controller.recoverCommit("a brand new master password 77!"))
        assertEquals(1, commits.size)
    }

    @Test
    fun aSubstitutedIdentityKeyStopsTheResetBeforeAnythingIsSent() = test {
        val commits = mutableListOf<RecoveryCommitRequest>()
        recoveryServer(commits)
        val piece = reg.memberRecovery!!
        val other = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        routes["/recovery/self/verify"] = {
            respond(json.encodeToString(RecoveryVerifyResponse.serializer(), RecoveryVerifyResponse(reg.userId, "ticket-1", piece.recoveryWrappedUvk, reg.encryptedIdentitySeed, Bytes.toB64(other.publicKey))), HttpStatusCode.OK, headers)
        }
        controller.startAndLand()
        controller.openRecover()
        assertEquals(ActionResult.Ok, controller.recoverVerify(EMAIL, phrase))
        assertEquals(ActionResult.Failed(HouseholdCopy.IDENTITY_MISMATCH), controller.recoverCommit("a brand new master password 77!"))
        assertTrue(commits.isEmpty())
    }

    @Test
    fun aServerOfferingWeakenedKeyDerivationCannotTakeTheReset() = test {
        val commits = mutableListOf<RecoveryCommitRequest>()
        recoveryServer(commits)
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(kdfParams = KdfParams(ops = 1, memBytes = 8192))), HttpStatusCode.OK, headers) }
        controller.startAndLand()
        controller.openRecover()
        assertEquals(ActionResult.Ok, controller.recoverVerify(EMAIL, phrase))
        assertEquals(ActionResult.Failed(HouseholdCopy.WEAK_KDF_ACTION), controller.recoverCommit("a brand new master password 77!"))
        assertTrue(commits.isEmpty())
    }

    @Test
    fun recoveryOpensOnlyFromTheSignedOutScreens() = test {
        unlocked()
        controller.openRecover()
        assertEquals(AppScreen.VAULT, controller.state.screen)
        assertEquals(ActionResult.NotDone(null), controller.recoverVerify(EMAIL, phrase))
    }
}
