package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.OriginProbeFence
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.RegisterRequest
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Step 6: the one unlock ladder, against in-memory seams and a mock server. Survey gap 6: the quick-unlock
 * gates hold in the ladder, before any prompt. Survey gap 7: a recovered UVK is zeroed on every path where no
 * account took it, and an account that was built and never bound is wiped.
 */
class UnlockLadderTest {
    private val home = "https://home.example"
    private val homeKey = OriginCanon.originKey(home)
    private val hour = 60L * 60 * 1000
    private val day = 24 * hour

    private val clocks = FakeClocks(wall = 100 * day, mono = 5 * day, boot = "7")
    private val store = FakeSessionPersistence(home)
    private val session = VaultSession(clocks)
    private val artifacts = RecordingArtifacts()
    private val coordinator = PolicyCoordinator(store, artifacts, session, clocks, OriginProbeFence())
    private val namespaces = FakeNamespaces()
    private val quickKeys = FakeQuickKeys()

    private val json = Json { encodeDefaults = true }
    private val headers = headersOf(HttpHeaders.ContentType, "application/json")
    private fun ok(body: String): suspend MockRequestHandleScope.() -> HttpResponseData = { respond(body, HttpStatusCode.OK, headers) }
    private val refused: suspend MockRequestHandleScope.() -> HttpResponseData =
        { respond("""{"error":"unauthorized","message":"refused"}""", HttpStatusCode.Unauthorized, headers) }
    private val unreachable: suspend MockRequestHandleScope.() -> HttpResponseData = { throw IOException("unreachable") }

    /** What the server answers, per route; a test swaps them. */
    private var keysAnswer = ok(json.encodeToString(AccountKeys.serializer(), served))
    private var syncAnswer = ok(EMPTY_SYNC)
    private var policyAnswer = ok(json.encodeToString(ClientPolicy.serializer(), ClientPolicy()))
    private var refreshAnswer = refused
    private val calls = mutableListOf<String>()

    private val http = object : HttpClients {
        override fun create() = HttpClient(
            MockEngine { request ->
                val path = request.url.encodedPath
                calls += path
                when {
                    path.endsWith("/account/keys") -> keysAnswer()
                    path.endsWith("/sync") -> syncAnswer()
                    path.endsWith("/client-policy") -> policyAnswer()
                    path.endsWith("/auth/refresh") -> refreshAnswer()
                    else -> respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, headers)
                }
            },
        )
        override val wirePlatform = "test"
        override val deviceName = "test device"
    }
    private val clients = SessionClients(http, store, coordinator)
    private val binder = SessionBinder(store, session, coordinator, namespaces, clocks)
    private val ladder = UnlockLadder(store, session, coordinator, clients, binder, quickKeys, clocks)

    private companion object {
        val crypto = createCryptoProvider()
        const val PASSWORD = "correct horse battery staple"
        const val EMAIL = "u@example.com"
        const val EMPTY_SYNC = """{"rev":1,"full":false,"vaults":[],"grants":[],"items":[],"removedGrants":[]}"""

        /** Enrolled once, at the minimum KDF cost: the password path derives under the cached keys' params. */
        val enrolled by lazy {
            val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
            val fp = Escrow.fingerprint(crypto, recovery.publicKey)
            Account.enroll("invite", EMAIL, "u", PASSWORD, KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, fp, "device", crypto)
        }
        val reg: RegisterRequest get() = enrolled.request

        /** The keys as an earlier online unlock cached them. */
        val cached: AccountKeys by lazy {
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint,
            )
        }

        /** The keys the server serves: params at the floor its fence demands. The quick path never derives under them. */
        val served: AccountKeys by lazy { cached.copy(kdfParams = KdfParams(ops = 3, memBytes = 67_108_864)) }
    }

    private val stored = StoredSession(home, reg.userId, EMAIL, "a1", "r1").also { store.save(it) }

    /** A fresh UVK copy, as the platform's prompt would release it; the test keeps the reference. */
    private fun releasedUvk(): ByteArray = enrolled.account.uvkCopyForPlatformWrap()

    /** Every quick-unlock gate open: a recent policy that permits it, a biometric, an enrollment, a fresh stamp. */
    private fun readyForQuick() {
        store.origin(homeKey).policyFetchedAt = clocks.wall - hour
        quickKeys.enrolled += "$homeKey/${reg.userId}"
        binder.stampPasswordUnlock(homeKey, reg.userId)
        clocks.wall += hour
        clocks.mono += hour
    }

    private fun ByteArray.isZero() = all { it == 0.toByte() }

    // ---- gap 6: the gates hold in the ladder ----

    @Test
    fun aQuickUnlockTheOrgForbidsNeverPrompts() = runBlocking<Unit> {
        readyForQuick()
        store.origin(homeKey).cacheAllowed = false
        assertEquals(UnlockResult.QuickUnavailable(QuickGate.POLICY), ladder.unlockWithQuick(stored, BiometricHost.None))
        assertEquals(0, quickKeys.prompts)
        assertTrue(calls.isEmpty(), "and nothing reached the server")
    }

    @Test
    fun aPolicyNotSeenForSevenDaysRefusesQuickUnlock() = runBlocking<Unit> {
        readyForQuick()
        store.origin(homeKey).policyFetchedAt = clocks.wall - QuickUnlockRules.POLICY_STALE_MS
        assertEquals(UnlockResult.QuickUnavailable(QuickGate.POLICY), ladder.unlockWithQuick(stored, BiometricHost.None))
        assertEquals(0, quickKeys.prompts)
    }

    @Test
    fun noBiometricNoEnrollmentAndAnExpiredWindowEachRefuseBeforeThePrompt() = runBlocking<Unit> {
        readyForQuick()
        quickKeys.biometric = false
        assertEquals(UnlockResult.QuickUnavailable(QuickGate.NO_BIOMETRIC), ladder.unlockWithQuick(stored, BiometricHost.None))
        quickKeys.biometric = true
        quickKeys.enrolled.clear()
        assertEquals(UnlockResult.QuickUnavailable(QuickGate.NOT_ENROLLED), ladder.unlockWithQuick(stored, BiometricHost.None))
        quickKeys.enrolled += "$homeKey/${reg.userId}"
        clocks.wall += 30 * day
        clocks.mono += 30 * day
        store.origin(homeKey).policyFetchedAt = clocks.wall - hour
        assertEquals(UnlockResult.QuickUnavailable(QuickGate.EXPIRED), ladder.unlockWithQuick(stored, BiometricHost.None))
        assertEquals(0, quickKeys.prompts)
    }

    @Test
    fun withNoFullPasswordStampTheWindowIsClosed() {
        store.origin(homeKey).policyFetchedAt = clocks.wall - hour
        quickKeys.enrolled += "$homeKey/${reg.userId}"
        val q = ladder.quickStatus(reg.userId)
        assertTrue(q.eligible && q.enrolled)
        assertFalse(q.fresh)
        assertEquals(QuickGate.EXPIRED, q.refusal)
    }

    @Test
    fun theStatusTheUiReadsIsTheOneTheLadderEnforces() {
        readyForQuick()
        val q = ladder.quickStatus(reg.userId)
        assertEquals(QuickStatus(eligible = true, enrolled = true, fresh = true, refusal = null), q)
        assertTrue(q.usable)
        assertEquals(clocks.wall, store.highWaterWallMs, "a freshness read advances the high-water clock")
        assertNull(ladder.quickStatus(null).takeIf { it.enrolled }, "no session, nothing enrolled")
    }

    // ---- gap 7: a recovered UVK is zeroed wherever no account took it ----

    @Test
    fun aQuickUnlockThatAdoptsAWinnerZeroesItsKey() = runBlocking<Unit> {
        readyForQuick()
        val winner = AndvariApi(home, HttpClient(MockEngine { respond("{}", HttpStatusCode.OK) }), Tokens("a1", "r1"))
        val other = Account.unlockWithUvk(reg.userId, releasedUvk(), cached, crypto)
        session.bind(winner, other, SyncEngine(winner, other, InMemoryVaultCache()))
        val uvk = releasedUvk()
        quickKeys.next = { QuickRecover.Ok(uvk) }
        val r = assertIs<UnlockResult.Adopted>(ladder.unlockWithQuick(stored, BiometricHost.None))
        assertSame(winner, r.unlocked.api)
        assertTrue(uvk.isZero(), "another unlock won: the key it released is zeroed")
        assertFalse(calls.any { it.endsWith("/account/keys") }, "and no second token-holder was built")
    }

    @Test
    fun anUnreachableServerWithNoCachedKeysZeroesTheKey() = runBlocking<Unit> {
        readyForQuick()
        val uvk = releasedUvk()
        quickKeys.next = { QuickRecover.Ok(uvk) }
        keysAnswer = unreachable
        val r = assertIs<UnlockResult.Failed>(ladder.unlockWithQuick(stored, BiometricHost.None))
        assertIs<IOException>(r.cause)
        assertTrue(uvk.isZero())
        assertNull(session.get())
        assertTrue(quickKeys.wiped.isEmpty(), "being offline is no reason to drop the enrollment")
    }

    @Test
    fun aRefusedSessionIsPurgedAndTheKeyZeroed() = runBlocking<Unit> {
        readyForQuick()
        val uvk = releasedUvk()
        quickKeys.next = { QuickRecover.Ok(uvk) }
        keysAnswer = refused
        val r = assertIs<UnlockResult.Revoked>(ladder.unlockWithQuick(stored, BiometricHost.None))
        assertEquals(401, r.cause.status)
        assertTrue(uvk.isZero())
        assertNull(store.stored, "the dead session is gone")
        assertTrue("cache:$homeKey/${reg.userId}" in artifacts.events && "blob:$homeKey/${reg.userId}" in artifacts.events, "and this origin's namespace with it")
    }

    @Test
    fun aKeyThatDoesNotOpenTheAccountIsWipedAndZeroed() = runBlocking<Unit> {
        readyForQuick()
        val foreign = crypto.randomBytes(32)
        quickKeys.next = { QuickRecover.Ok(foreign) }
        val r = assertIs<UnlockResult.Failed>(ladder.unlockWithQuick(stored, BiometricHost.None))
        assertIs<CryptoException>(r.cause)
        assertTrue(foreign.isZero())
        assertEquals(listOf("$homeKey/${reg.userId}"), quickKeys.wiped, "a stale or foreign key goes, so the next attempt asks for the password")
        assertNull(session.get())
    }

    @Test
    fun anIdentityMismatchKeepsTheEnrollmentAsEvidence() = runBlocking<Unit> {
        readyForQuick()
        val stranger = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        keysAnswer = ok(json.encodeToString(AccountKeys.serializer(), served.copy(identityPub = io.silencelen.andvari.core.crypto.Bytes.toB64(stranger))))
        val uvk = releasedUvk()
        quickKeys.next = { QuickRecover.Ok(uvk) }
        val r = assertIs<UnlockResult.Failed>(ladder.unlockWithQuick(stored, BiometricHost.None))
        assertTrue(r.cause.message!!.contains("identity key mismatch"))
        assertTrue(quickKeys.wiped.isEmpty())
        assertTrue(uvk.isZero())
    }

    @Test
    fun anAccountThatFailsToBindIsWiped() = runBlocking<Unit> {
        readyForQuick()
        val uvk = releasedUvk()
        quickKeys.next = { QuickRecover.Ok(uvk) }
        namespaces.failOpen = IllegalStateException("corrupt cache file")
        val r = assertIs<UnlockResult.Failed>(ladder.unlockWithQuick(stored, BiometricHost.None))
        assertEquals("corrupt cache file", r.cause.message)
        assertTrue(uvk.isZero(), "the account took the key, and its wipe zeroed it")
        assertNull(session.get())
        assertTrue(quickKeys.wiped.isEmpty(), "a damaged cache says nothing about the key")
    }

    @Test
    fun aQuickUnlockBindsWithoutStampingAndTheLockWipesItsKeys() = runBlocking<Unit> {
        readyForQuick()
        val stampBefore = store.origin(homeKey).stamps[reg.userId]
        val uvk = releasedUvk()
        var keyed = 0
        quickKeys.next = { QuickRecover.Ok(uvk) }
        val r = assertIs<UnlockResult.Unlocked>(ladder.unlockWithQuick(stored, BiometricHost.None, UnlockOptions(onQuickKey = { keyed++ })))
        assertEquals(1, keyed)
        assertTrue(r.online)
        assertEquals(FirstSync.Done, r.firstSync)
        assertSame(r.unlocked, session.get())
        assertEquals(VaultSession.UnlockProvenance.QUICK, r.unlocked.provenance)
        assertEquals(stampBefore, store.origin(homeKey).stamps[reg.userId], "a quick unlock is never a full-password unlock (A1)")
        assertEquals(served, store.origin(homeKey).accountKeys, "the fresh keys are kept for offline unlock")
        assertEquals(listOf("$homeKey/${reg.userId}"), namespaces.opened, "a durable cache, in this origin's namespace")
        assertFalse(uvk.isZero(), "the account holds the key while the session lives")
        session.lock()
        assertTrue(uvk.isZero(), "and the lock zeroes it")
        assertTrue(r.unlocked.account.isWiped)
    }

    // ---- the password rung ----

    @Test
    fun anOfflinePasswordUnlockOpensOnTheCachedKeysAndStampsTheWindow() = runBlocking<Unit> {
        store.origin(homeKey).accountKeys = cached
        keysAnswer = unreachable
        syncAnswer = unreachable
        val r = assertIs<UnlockResult.Unlocked>(ladder.unlockWithPassword(stored, PASSWORD))
        assertFalse(r.online)
        assertEquals(cached, r.keys)
        assertEquals(FirstSync.Offline, r.firstSync, "the first sync could not run, and the user lands anyway")
        assertSame(r.unlocked, session.get())
        assertEquals(VaultSession.UnlockProvenance.PASSWORD, r.unlocked.provenance)
        assertEquals(PasswordStamp(clocks.wall, clocks.mono, clocks.wall - clocks.mono, "7"), store.origin(homeKey).stamps[reg.userId], "A1: every full-password unlock stamps, offline too")
        assertNotNull(store.origin(homeKey).identityPins().pinFor(EMAIL, reg.userId), "the identity pin is recorded at the first unlock that passed")
    }

    @Test
    fun aWrongPasswordBuildsNothing() = runBlocking<Unit> {
        store.origin(homeKey).accountKeys = cached
        keysAnswer = unreachable
        val r = assertIs<UnlockResult.Failed>(ladder.unlockWithPassword(stored, "not the password"))
        assertIs<CryptoException>(r.cause)
        assertNull(session.get())
        assertTrue(store.origin(homeKey).stamps.isEmpty())
    }

    @Test
    fun aStoredSessionOfAnotherOriginIsRefusedBeforeAnythingIsSent() = runBlocking<Unit> {
        val elsewhere = stored.copy(baseUrl = "https://other.example")
        assertEquals(UnlockResult.Elsewhere("https://other.example"), ladder.unlockWithPassword(elsewhere, PASSWORD))
        readyForQuick()
        assertEquals(UnlockResult.Elsewhere("https://other.example"), ladder.unlockWithQuick(elsewhere, BiometricHost.None))
        assertEquals(0, quickKeys.prompts, "not even the prompt")
        assertTrue(calls.isEmpty())
    }

    @Test
    fun aSessionRejectedDuringItsFirstSyncLandsNowhere() = runBlocking<Unit> {
        readyForQuick()
        quickKeys.next = { QuickRecover.Ok(releasedUvk()) }
        syncAnswer = refused // the 401 survives the refresh, which is refused too
        assertEquals(UnlockResult.EndedBeforeLanding, ladder.unlockWithQuick(stored, BiometricHost.None))
        assertNull(session.get())
        assertTrue(session.takeRejected(), "the rejection is there for the screen to report")
    }

    // ---- the overlay's options ----

    @Test
    fun anEntryPointWithoutAPolicyReadOfItsOwnReadsItAndAForbiddingOnePurges() = runBlocking<Unit> {
        readyForQuick()
        quickKeys.next = { QuickRecover.Ok(releasedUvk()) }
        policyAnswer = ok(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(offlineCacheAllowed = false)))
        val r = assertIs<UnlockResult.Unlocked>(ladder.unlockWithQuick(stored, BiometricHost.None, UnlockOptions(refreshPolicy = true)))
        assertEquals(false, r.policy?.offlineCacheAllowed)
        assertFalse(store.origin(homeKey).cacheAllowed, "the mirror is written")
        assertEquals(clocks.wall, store.origin(homeKey).policyFetchedAt, "and A4's timestamp")
        assertTrue("blob:$homeKey/${reg.userId}" in artifacts.events, "the forbidding policy takes the quick-unlock key")
        assertTrue(namespaces.opened.isEmpty(), "the session runs on an in-memory cache")
        assertNull(store.origin(homeKey).accountKeys, "and keeps no offline keys")
    }

    @Test
    fun onlyAFreshWinnerIsAdoptedWhenTheEntryPointHasNoIdleTicker() = runBlocking<Unit> {
        store.origin(homeKey).accountKeys = cached
        keysAnswer = unreachable
        session.setAutoLockSeconds(300)
        val first = assertIs<UnlockResult.Unlocked>(ladder.unlockWithPassword(stored, PASSWORD))
        clocks.mono += 10 * 60 * 1000 // idle past the window
        val second = assertIs<UnlockResult.Unlocked>(ladder.unlockWithPassword(stored, PASSWORD, UnlockOptions(adoptOnlyFresh = true)))
        assertTrue(first.unlocked.account.isWiped, "the stale session was locked, and its keys went with it")
        assertSame(second.unlocked, session.get())
        clocks.mono += 10 * 60 * 1000
        val adopted = assertIs<UnlockResult.Adopted>(ladder.unlockWithPassword(stored, PASSWORD))
        assertSame(second.unlocked, adopted.unlocked, "the main app's ticker locks a stale session itself")
    }
}
