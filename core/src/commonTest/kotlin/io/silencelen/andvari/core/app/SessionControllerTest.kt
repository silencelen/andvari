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
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
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

        val controller = SessionController(store, namespaces, http, quickKeys, clocks, setOf("127.0.0.1"), ui, { BiometricHost.None }, 0, { shared += it }, snapshots, queue)

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
    fun aKeyThatNoLongerOpensTheAccountIsWipedByTheExtensionToo() = test {
        unlocked()
        controller.enableQuickUnlock(null)
        val fill = autofill()
        quickKeys.next = { QuickRecover.Ok(crypto.randomBytes(32)) } // a stale or foreign UVK
        assertEquals(FillUnlock.OpenApp(AutofillVault.USE_APP), fill.unlock(BiometricHost.None))
        assertTrue("$homeKey/${reg.userId}" in quickKeys.wiped, "the next unlock is the password's, in the app")
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

    // ---- the extensions' save queue ----

    @Test
    fun aCapturedLoginIsSealedQueuedShownAndSavedOnlyOnConfirm() = test {
        assertEquals(SaveQueued.NO_ACCOUNT, capture("a", "https://shop.example/login", "me", "s3cret-pw"), "nobody is signed in: no key to seal to")
        unlocked()
        routes["/sync/push"] = { throw IOException("unreachable") }
        controller.onBackground() // the extension runs while the app is locked
        assertEquals(SaveQueued.QUEUED, capture("a", "https://shop.example/login", "me", "s3cret-pw"))
        val kept = queue.map.getValue("a").decodeToString()
        for (secret in listOf("s3cret-pw", "shop.example", "\"me\"")) assertFalse(kept.contains(secret), "at rest: $secret")
        assertTrue(controller.state.pendingSaves.isEmpty(), "a locked app shows nothing")

        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        val pending = controller.state.pendingSaves.single()
        assertEquals(PendingSaveView("a", "shop.example", "me", null), pending)
        assertEquals("s3cret-pw", controller.pendingSavePassword("a"))
        assertEquals(listOf("Example"), controller.state.items.map { it.name }, "nothing is written before the person confirms")

        // This rig's vault cannot take a new login offline (as [aSaveIsValidatedAndAFailedOneIsSaidNotThrown]): the
        // failure is a sentence, and the capture stays queued for the next try.
        assertIs<ActionResult.Failed>(controller.confirmPendingSave("a"))
        assertEquals(listOf("a"), controller.state.pendingSaves.map { it.id })
        assertEquals(setOf("a"), queue.map.keys)
        assertFalse(controller.state.busy)
    }

    @Test
    fun aCaptureForAKnownLoginOffersItsNewPasswordAndAnIdenticalOneIsDropped() = test {
        seedSession()
        // A cache that survives the process, as the app's is: an offline save is honestly queued.
        val seeded = namespaces.caches.getValue("$homeKey/${reg.userId}")
        namespaces.caches["$homeKey/${reg.userId}"] = object : io.silencelen.andvari.core.client.VaultCache by seeded {
            override val durable = true
        }
        routes["/sync/push"] = { throw IOException("unreachable") }
        controller.startAndLand()
        assertEquals(ActionResult.Ok, controller.unlock(PASSWORD))
        controller.lock()
        capture("same", "login.example.com", "fam", "hunter2") // already in the vault
        capture("new", "https://login.example.com/reset", "fam", "hunter3")
        controller.unlock(PASSWORD)
        assertEquals(listOf(PendingSaveView("new", "login.example.com", "fam", "Example")), controller.state.pendingSaves)
        assertEquals(setOf("new"), queue.map.keys)
        assertEquals(ActionResult.Ok, controller.confirmPendingSave("new"))
        assertEquals("hunter3", controller.revealSecret(ITEM_ID, SecretField.PASSWORD))
        assertEquals(1, controller.state.items.size, "updated, not duplicated")
        assertTrue(controller.state.pendingSaves.isEmpty())
        assertTrue(queue.map.isEmpty())
        assertNull(controller.pendingSavePassword("new"))
    }

    @Test
    fun aDiscardedSaveWritesNothing() = test {
        unlocked()
        controller.lock()
        capture("a", "shop.example", "me", "pw")
        controller.unlock(PASSWORD)
        controller.discardPendingSave("a")
        assertTrue(controller.state.pendingSaves.isEmpty())
        assertTrue(queue.map.isEmpty())
        assertEquals(1, controller.state.items.size)
    }

    @Test
    fun theQueueIsBoundedAndRefusesWhatItCannotKeep() = test {
        unlocked()
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
        controller.lock()
        capture("good", "shop.example", "me", "pw")
        val good = queue.map.getValue("good")
        // A flipped byte in the seal.
        val entry = json.decodeFromString(QueuedSave.serializer(), good.decodeToString())
        val sealed = io.silencelen.andvari.core.crypto.Bytes.fromB64(entry.sealed).also { it[40] = (it[40].toInt() xor 1).toByte() }
        queue.map["tampered"] = json.encodeToString(QueuedSave.serializer(), entry.copy(sealed = io.silencelen.andvari.core.crypto.Bytes.toB64(sealed))).encodeToByteArray()
        // Another account's entry, and one relabelled as this account's (its inside still names the other).
        val other = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val inside = json.encodeToString(CapturedLogin.serializer(), CapturedLogin(origin = HOME, userId = "someone-else", site = "shop.example", username = "me", password = "pw", capturedAtMs = 1, source = "safari"))
        val forOther = io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.sealTo(other.publicKey, inside.encodeToByteArray()))
        queue.map["foreign"] = json.encodeToString(QueuedSave.serializer(), QueuedSave(origin = HOME, userId = "someone-else", sealed = forOther)).encodeToByteArray()
        val relabelled = io.silencelen.andvari.core.crypto.Bytes.toB64(crypto.sealTo(enrolled.account.identityPub, inside.encodeToByteArray()))
        queue.map["relabelled"] = json.encodeToString(QueuedSave.serializer(), QueuedSave(origin = HOME, userId = reg.userId, sealed = relabelled)).encodeToByteArray()
        queue.map["elsewhere"] = json.encodeToString(QueuedSave.serializer(), entry.copy(origin = "https://other.example")).encodeToByteArray()
        queue.map["garbage"] = "not json".encodeToByteArray()
        queue.map["huge"] = ByteArray(SaveQueue.MAX_ENTRY_BYTES + 1) { 'a'.code.toByte() }

        controller.unlock(PASSWORD)
        assertEquals(listOf("good"), controller.state.pendingSaves.map { it.id })
        assertEquals(setOf("good"), queue.map.keys, "everything else is removed")
    }

    @Test
    fun signOutAServerSwitchAndAForbiddingPolicyEmptyTheQueue() = test {
        unlocked()
        assertNotNull(queue.key, "the unlocked app publishes the key")
        assertEquals(SaveQueued.QUEUED, capture("a", "shop.example", "me", "pw"))
        controller.signOut()
        assertNull(queue.key)
        assertTrue(queue.map.isEmpty())
        assertEquals(SaveQueued.NO_ACCOUNT, capture("b", "shop.example", "me", "pw"))
    }

    @Test
    fun aForbiddingPolicyPublishesNoKeyAndKeepsNoQueue() = test {
        seedSession()
        queue.map["stale"] = "x".encodeToByteArray()
        routes["/client-policy"] = { respond(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(offlineCacheAllowed = false)), HttpStatusCode.OK, headers) }
        controller.startAndLand()
        controller.unlock(PASSWORD)
        assertNull(queue.key)
        assertTrue(queue.map.isEmpty())
        assertTrue(controller.state.pendingSaves.isEmpty())
    }

    @Test
    fun aServerSwitchEmptiesTheQueue() = test {
        unlocked()
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
}
