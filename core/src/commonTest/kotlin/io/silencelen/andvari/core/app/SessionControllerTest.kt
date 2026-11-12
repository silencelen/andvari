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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlinx.io.IOException
import kotlinx.serialization.json.Json
import kotlin.coroutines.ContinuationInterceptor
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
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
                    route?.invoke(this, request) ?: respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, headers)
                },
            )
            override val wirePlatform = "test"
            override val deviceName = "test device"
        }

        val controller = SessionController(store, namespaces, http, quickKeys, clocks, setOf("127.0.0.1"), ui, { BiometricHost.None }, 0, { shared += it }, snapshots, queue, appliedLog)

        /** What an extension does with a captured login: seal it to the published key and queue it. */
        fun capture(id: String, site: String, username: String, password: String) = SaveQueue.enqueue(queue, crypto, id, site, username, password, clocks.wall, "safari")

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
        assertEquals(listOf("a"), controller.state.appliedSaves.map { it.id })
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

    /** A record as the importer stores it, sealed to the account. */
    private fun Rig.storedSaveRecord(id: String, site: String, itemId: String, password: String, intent: Boolean) {
        val record = """{"id":"$id","site":"$site","username":"me","itemId":"$itemId","replacedName":null,"password":"$password","keptOld":false,"appliedAtMs":${clocks.wall},"intent":$intent}"""
        val sealedRecord = Bytes.toB64(crypto.sealTo(enrolled.account.identityPub, record.encodeToByteArray()))
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
        assertEquals(listOf("a"), controller.state.appliedSaves.map { it.id })
        assertTrue(queue.map.isEmpty())
        assertEquals(ActionResult.Ok, controller.undoAppliedSave("a"))
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
        storedSaveRecord("a", "https://shop.example/", written, "pw-1", intent = true)
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name })
        assertTrue(queue.map.isEmpty(), "the entry it came from is gone")
        assertEquals(ActionResult.Ok, controller.undoAppliedSave("a"), "nothing was written that the list does not show")
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
        assertEquals(AppliedSaveView("a", "shop.example", "me", null, false, clocks.wall, PERSONAL), applied)
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
        assertEquals(ActionResult.Ok, controller.undoAppliedSave("a"))
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
        assertEquals(listOf(AppliedSaveView("new", "login.example.com", "fam", "Example", false, clocks.wall, PERSONAL)), controller.state.appliedSaves)
        assertEquals("hunter3", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals(1, controller.state.items.size, "updated, not duplicated")
        assertTrue(controller.state.pendingSaves.isEmpty())
        assertTrue(queue.map.isEmpty(), "the identical capture was dropped, the applied one left the queue")
        assertEquals(1, controller.itemDetail(ITEM_ID)?.previousPasswords, "the password it replaced is kept in the login's history")
        assertEquals(listOf(clocks.wall), controller.passwordHistory(ITEM_ID), "when it was retired, newest first")
        assertEquals("hunter2", controller.previousPassword(ITEM_ID, 0), "read one at a time, on request")
        assertNull(controller.previousPassword(ITEM_ID, 1))
        assertEquals(ActionResult.Ok, controller.undoAppliedSave("new"))
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
        assertEquals(listOf(true, false), controller.state.appliedSaves.sortedBy { it.id }.map { it.plainHttp })
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
        assertEquals(listOf("d"), controller.state.appliedSaves.map { it.id }, "a save by hand is listed and can be undone too")
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
        assertEquals(listOf("a-second"), controller.state.appliedSaves.map { it.id })
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
    fun anUndoDoesNotRemoveAnAddedLoginThatWasEditedInAnyField() = test {
        unlockedWithAPersonalVault()
        controller.lock()
        capture("added", "https://shop.example/", "me", "pw")
        controller.unlock(PASSWORD)
        settle { controller.state.appliedSaves.isNotEmpty() }
        val added = controller.state.items.single { it.name == "shop.example" }.itemId
        // The same username and password, but a note and a code were added since: that is the person's work.
        assertEquals(ActionResult.Ok, controller.saveLogin(added, LoginInput("shop.example", "me", "pw", listOf("https://shop.example"), "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP", "the recovery codes are in the safe", false)))
        assertEquals(ActionResult.Failed(SaveImporter.UNDO_EDITED), controller.undoAppliedSave("added"))
        assertEquals(listOf("Example", "shop.example"), controller.state.items.map { it.name })
        assertEquals(listOf("added"), controller.state.appliedSaves.map { it.id }, "the record stays, with the reason said")
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
        assertIs<ActionResult.Failed>(controller.undoAppliedSave("new"))
        assertIs<ActionResult.Failed>(controller.undoAppliedSave("added"))
        assertIs<ActionResult.Failed>(controller.undoAllAppliedSaves())
        assertEquals("edited-since", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals("edited-too", controller.revealSecret(added, SecretField.PASSWORD), "a login changed since it was added is not deleted")
        assertFalse(controller.state.busy)
        controller.dismissAppliedSaves()
        assertTrue(controller.state.appliedSaves.isEmpty())
        assertNull(appliedLog.bytes)
        assertEquals(ActionResult.NotDone(null), controller.undoAppliedSave("new"), "dismissed: nothing left to undo from here")
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
        assertEquals(SaveQueued.QUEUED, capture("e0", "shop0.example", "me", "pw2"), "the same form's later capture replaces its entry")
        assertTrue(queue.map.values.all { it.size <= SaveQueue.MAX_ENTRY_BYTES })
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
        assertEquals(AppScreen.RECOVER, controller.state.screen, "the first step holds nothing, so it stays")
        assertEquals(ActionResult.Ok, controller.recoverVerify(EMAIL, phrase))
        controller.onBackground()
        assertEquals(AppScreen.WELCOME, controller.state.screen)
        assertEquals(ActionResult.NotDone(null), controller.recoverCommit("a brand new master password 77!"))
        assertTrue(commits.isEmpty())
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
