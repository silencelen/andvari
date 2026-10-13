package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.PersonalWrap
import io.silencelen.andvari.core.model.PersonalWrapPut
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TransferRecord
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A, branch A5b (follow-up to A5; A5 re-review M-1, M-2, L-1, L-2).
 *
 *  - M-1: the cached personal wrap must outlive a non-durable offline cache (desktop's in-memory default, an
 *    org-forbid policy, a revocation purge), so a withheld wrap stays WITHHELD after a restart.
 *  - M-2: a first designation never mints without an explicit confirmation naming the vault and its
 *    co-holders; the choice lists say who else holds each vault and whether this account created it or
 *    received it by transfer; a served wrap naming a DIFFERENT vault than this device's raises a notice
 *    instead of switching silently (this also covers the replay of an older wrap, L-2).
 *  - L-1: a served wrap that is present but does not open must not discard a valid cached wrap.
 */
class PersonalChoiceHardeningTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(tag: String): Enrolled {
        val email = "$tag-${crypto.randomBytes(4).joinToString("") { (it.toInt() and 0xff).toString(16) }}@example.com"
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, fp, "dev", crypto)
        return Enrolled(
            reg, account,
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint,
            ),
        )
    }

    /** A scripted server: the sync feed, the member lists, and capture of every personal-wrap PUT. */
    private class FakeServer(val feed: SyncResponse, val members: Map<String, List<VaultMemberSummary>> = emptyMap(), val failMembers: Boolean = false) {
        val personalWrapPuts = mutableListOf<String>()
        val memberFetches = mutableListOf<String>()
    }

    private fun api(server: FakeServer): AndvariApi {
        val json = this.json
        val engine = MockEngine { req ->
            val path = req.url.encodedPath
            val ct = headersOf(HttpHeaders.ContentType, "application/json")
            val members = Regex("^/api/v1/vaults/([^/]+)/members$").find(path)
            when {
                path == "/api/v1/sync" -> respond(json.encodeToString(SyncResponse.serializer(), server.feed), HttpStatusCode.OK, ct)
                path == "/api/v1/account/personal-wrap" && req.method == HttpMethod.Put -> {
                    server.personalWrapPuts.add((req.body as TextContent).text)
                    respond("ok", HttpStatusCode.OK)
                }
                members != null && req.method == HttpMethod.Get && server.failMembers ->
                    respond("""{"error":"unavailable","message":"no"}""", HttpStatusCode.ServiceUnavailable, ct)
                members != null && req.method == HttpMethod.Get -> {
                    val id = members.groupValues[1]
                    server.memberFetches.add(id)
                    respond(json.encodeToString(ListSerializer(VaultMemberSummary.serializer()), server.members[id].orEmpty()), HttpStatusCode.OK, ct)
                }
                else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
    }

    private fun member(e: Enrolled, role: String, name: String) =
        VaultMemberSummary(e.reg.userId, "${name.lowercase()}@example.com", name, role, e.reg.identityPub, 0)

    private fun personalRow(e: Enrolled) = WireVault(e.reg.personalVault.vaultId, "personal", 2, e.reg.personalVault.metaBlob, 0)
    private fun personalGrant(e: Enrolled) = WireGrant(e.reg.personalVault.vaultId, e.reg.userId, "owner", e.reg.personalVault.wrappedVk, 2, null)

    /** The victim's real personal vault plus an owned shared vault "Household" (a second genuine wrap target). */
    private class Household(val victim: Enrolled, val mate: Enrolled, val sharedId: String, val sharedWrap: PersonalWrap, val feed: SyncResponse)

    private fun household(): Household {
        val victim = enroll("a5b")
        val mate = enroll("a5b-mate")
        val shared = victim.account.buildCreateSharedVault("Household")
        val feed = SyncResponse(
            rev = 9, full = true,
            vaults = listOf(personalRow(victim), WireVault(shared.vaultId, "shared", 3, shared.request.metaBlob, 0)),
            grants = listOf(personalGrant(victim), WireGrant(shared.vaultId, victim.reg.userId, "owner", shared.request.wrappedVk, 3, null)),
            items = emptyList(), removedGrants = emptyList(),
        )
        // A genuine personal wrap for the shared vault: what a (mistaken, or older) designation elsewhere minted.
        return Household(victim, mate, shared.vaultId, victim.account.buildPersonalWrap(shared.vaultId), feed)
    }

    private fun unlock(e: Enrolled, wrap: PersonalWrap?) = Account.unlock(e.reg.userId, password, e.keys.copy(personalWrap = wrap), crypto)

    /** A9 (M-2): a first device with no designation on record confirms the served wrap once; from then on it is established. */
    private suspend fun establish(engine: SyncEngine) {
        engine.sync()
        engine.describePersonalChange()
        engine.acceptPersonalChange()
    }

    // ---- M-1: durable cached wrap ----

    @Test
    fun m1_aWithheldWrapStaysWithheldAfterARestartWithANonDurableCache() = runBlocking<Unit> {
        val h = household()
        val device = MemoryDeviceState()
        // Session 1: the wrap is served. The offline cache is IN MEMORY (desktop default, org-forbid policy).
        val first = unlock(h.victim, h.victim.reg.personalWrap)
        establish(SyncEngine(api(FakeServer(h.feed)), first, InMemoryVaultCache(), deviceState = device))
        assertEquals(h.victim.reg.personalVault.vaultId, first.personalVaultId)

        // Restart: the in-memory cache is gone (or a revocation purge wiped the durable one). Server withholds.
        val again = unlock(h.victim, null)
        val server = FakeServer(h.feed)
        val engine = SyncEngine(api(server), again, InMemoryVaultCache(), deviceState = device)
        engine.hydrate()
        engine.sync()
        assertEquals(Account.PersonalStatus.WITHHELD, again.personalStatus, "a withheld wrap after a restart is still the anomaly, not a fresh question")
        assertEquals(h.victim.reg.personalVault.vaultId, again.personalVaultId)
        assertNull(engine.personalVaultChoices)
        assertTrue(server.personalWrapPuts.isEmpty())
    }

    @Test
    fun m1_theFileDeviceStateSurvivesANewInstance() {
        val dir = Files.createTempDirectory("andvari-device-state").toFile()
        try {
            FileDeviceState(dir).set("personal.last", "v1")
            assertEquals("v1", FileDeviceState(dir).get("personal.last"))
            FileDeviceState(dir).set("personal.last", null)
            assertNull(FileDeviceState(dir).get("personal.last"))
        } finally {
            dir.deleteRecursively()
        }
    }

    // ---- M-2: confirmed, informed first designation ----

    @Test
    fun m2_aFirstDesignationDoesNotMintWithoutConfirmation() = runBlocking<Unit> {
        val h = household()
        val server = FakeServer(h.feed, mapOf(h.sharedId to listOf(member(h.victim, "owner", "Victim"), member(h.mate, "writer", "Mate"))))
        val account = unlock(h.victim, null)
        val engine = SyncEngine(api(server), account, InMemoryVaultCache(), deviceState = MemoryDeviceState())
        engine.sync()
        assertEquals(Account.PersonalStatus.ABSENT, account.personalStatus)

        val proposal = engine.proposePersonalVault(h.sharedId)
        assertTrue(server.personalWrapPuts.isEmpty(), "proposing is not designating: nothing is minted or sent")
        assertEquals("", account.personalVaultId)
        assertEquals("Household", proposal.name)
        assertEquals(listOf(h.mate.reg.userId), proposal.coHolders.map { it.userId }, "the confirmation names who else holds the vault")

        // A proposal that is no longer the pending one (another vault was proposed since) cannot mint.
        val other = engine.proposePersonalVault(h.victim.reg.personalVault.vaultId)
        assertFailsWith<IllegalStateException> { engine.confirmPersonalVault(proposal, null) }
        assertTrue(server.personalWrapPuts.isEmpty())
        // Nor can a proposal from another engine.
        val stranger = SyncEngine(api(server), account, InMemoryVaultCache()).also { it.sync() }
        val foreign = stranger.proposePersonalVault(h.sharedId)
        assertFailsWith<IllegalStateException> { engine.confirmPersonalVault(foreign, null) }
        assertTrue(server.personalWrapPuts.isEmpty())

        // Only the confirmed proposal mints, once.
        engine.confirmPersonalVault(other, null)
        assertEquals(1, server.personalWrapPuts.size)
        assertEquals(h.victim.reg.personalVault.vaultId, json.decodeFromString(PersonalWrapPut.serializer(), server.personalWrapPuts.single()).vaultId)
        assertEquals(Account.PersonalStatus.CONFIRMED, account.personalStatus)
        assertFailsWith<IllegalStateException> { engine.confirmPersonalVault(other, null) } // single use
        assertEquals(1, server.personalWrapPuts.size)
    }

    @Test
    fun m2_theChoiceListShowsCoHoldersAndTheCreatedOrReceivedOrigin() = runBlocking<Unit> {
        val h = household()
        val received = h.mate.account.buildCreateSharedVault("Taxes")
        // The mate created "Taxes" and transferred it to the victim: the victim's row is an owner UVK wrap.
        val receivedWrap = io.silencelen.andvari.core.crypto.Envelope.sealB64(
            crypto, h.victim.account.uvkCopyForPlatformWrap(),
            io.silencelen.andvari.core.crypto.Envelope.openB64(crypto, h.mate.account.uvkCopyForPlatformWrap(), received.request.wrappedVk, io.silencelen.andvari.core.crypto.Ad.vk(received.vaultId, h.mate.reg.userId)),
            io.silencelen.andvari.core.crypto.Ad.vk(received.vaultId, h.victim.reg.userId),
        )
        val feed = h.feed.copy(
            vaults = h.feed.vaults + WireVault(received.vaultId, "shared", 5, received.request.metaBlob, 0, lastTransfer = TransferRecord("offer-1", h.victim.reg.userId, "proof", 1, "hash")),
            grants = h.feed.grants + WireGrant(received.vaultId, h.victim.reg.userId, "owner", receivedWrap, 5, null),
        )
        val server = FakeServer(
            feed,
            mapOf(
                h.sharedId to listOf(member(h.victim, "owner", "Victim"), member(h.mate, "reader", "Mate")),
                received.vaultId to listOf(member(h.victim, "owner", "Victim"), member(h.mate, "writer", "Mate")),
                h.victim.reg.personalVault.vaultId to listOf(member(h.victim, "owner", "Victim")),
            ),
        )
        val account = unlock(h.victim, null)
        val engine = SyncEngine(api(server), account, InMemoryVaultCache(), deviceState = MemoryDeviceState())
        engine.sync()
        val choices = engine.personalVaultChoices!!.map { it.vaultId }.toSet()
        assertEquals(setOf(h.victim.reg.personalVault.vaultId, h.sharedId, received.vaultId), choices)

        engine.refreshPersonalChoiceDetails(choices)
        val personal = engine.personalChoiceInfo(h.victim.reg.personalVault.vaultId)
        assertEquals(emptyList(), personal.coHolders)
        assertEquals(PersonalChoiceInfo.Origin.CREATED, personal.origin)
        val shared = engine.personalChoiceInfo(h.sharedId)
        assertEquals(listOf("Mate"), shared.coHolders!!.map { it.displayName })
        assertEquals(PersonalChoiceInfo.Origin.CREATED, shared.origin)
        val taxes = engine.personalChoiceInfo(received.vaultId)
        assertEquals(listOf("Mate"), taxes.coHolders!!.map { it.displayName })
        assertEquals(PersonalChoiceInfo.Origin.RECEIVED_BY_TRANSFER, taxes.origin)
        assertEquals("Taxes", taxes.name)

        // The Settings re-designation list carries the same detail.
        assertEquals(choices, engine.redesignationChoices().map { it.vaultId }.toSet())
        assertNotNull(engine.personalChoiceInfo(h.sharedId).coHolders)
    }

    @Test
    fun m2_aServedWrapNamingADifferentVaultRaisesTheChangeNoticeInsteadOfSwitching() = runBlocking<Unit> {
        val h = household()
        val device = MemoryDeviceState()
        // This device knows the real personal vault.
        val first = unlock(h.victim, h.victim.reg.personalWrap)
        establish(SyncEngine(api(FakeServer(h.feed)), first, InMemoryVaultCache(), deviceState = device))

        // The server now serves a GENUINE wrap for the shared vault (a designation on another device, or a
        // replay of an older wrap). The device must not switch silently.
        val again = unlock(h.victim, h.sharedWrap)
        val server = FakeServer(h.feed)
        val engine = SyncEngine(api(server), again, InMemoryVaultCache(), deviceState = device)
        engine.hydrate()
        engine.sync()
        assertEquals(Account.PersonalStatus.CHANGED, again.personalStatus)
        assertEquals(h.victim.reg.personalVault.vaultId, again.personalVaultId, "the device keeps the vault it had until the human confirms")
        val change = assertNotNull(engine.personalChange())
        assertEquals(h.victim.reg.personalVault.vaultId, change.currentVaultId)
        assertEquals(h.sharedId, change.servedVaultId)
        assertEquals("personal", engine.vaultInfos().single { it.vaultId == h.victim.reg.personalVault.vaultId }.type)
        assertTrue(server.personalWrapPuts.isEmpty())
        assertTrue(device.get("personal.wrap")!!.contains(h.victim.reg.personalVault.vaultId), "the cache is not overwritten by the unconfirmed wrap")

        // The human confirms the change: now (and only now) the served wrap is in force and cached. "Use new" is
        // offered only once the new vault's co-holders loaded (A5b review LOW-1).
        assertNotNull(engine.describePersonalChange())
        engine.acceptPersonalChange()
        assertEquals(Account.PersonalStatus.CONFIRMED, again.personalStatus)
        assertEquals(h.sharedId, again.personalVaultId)
        assertNull(engine.personalChange())
        assertTrue(device.get("personal.wrap")!!.contains(h.sharedId))
        assertTrue(server.personalWrapPuts.isEmpty(), "accepting a served wrap mints nothing")

        // L-2: the server replays the OLDER wrap. That is a change too, and it asks again.
        val replay = unlock(h.victim, h.victim.reg.personalWrap)
        val e3 = SyncEngine(api(FakeServer(h.feed)), replay, InMemoryVaultCache(), deviceState = device)
        e3.hydrate()
        assertEquals(Account.PersonalStatus.CHANGED, replay.personalStatus)
        assertEquals(h.sharedId, replay.personalVaultId)
    }

    @Test
    fun m2_keepingTheCurrentVaultOverAChangeIsAReauthRedesignation() = runBlocking<Unit> {
        val h = household()
        val device = MemoryDeviceState()
        val first = unlock(h.victim, h.victim.reg.personalWrap)
        establish(SyncEngine(api(FakeServer(h.feed)), first, InMemoryVaultCache(), deviceState = device))
        val again = unlock(h.victim, h.sharedWrap)
        val server = FakeServer(h.feed, mapOf(h.victim.reg.personalVault.vaultId to listOf(member(h.victim, "owner", "Victim"))))
        val engine = SyncEngine(api(server), again, InMemoryVaultCache(), deviceState = device)
        engine.sync()
        assertEquals(Account.PersonalStatus.CHANGED, again.personalStatus)
        val keep = engine.proposePersonalVault(h.victim.reg.personalVault.vaultId)
        engine.confirmPersonalVault(keep, "fresh-auth-key")
        assertEquals(Account.PersonalStatus.CONFIRMED, again.personalStatus)
        assertEquals(h.victim.reg.personalVault.vaultId, again.personalVaultId)
        assertEquals("fresh-auth-key", json.decodeFromString(PersonalWrapPut.serializer(), server.personalWrapPuts.single()).currentAuthKey)
    }

    // ---- A5b review LOW-1 / LOW-2 (carried into A6) ----

    @Test
    fun low1_useNewIsRefusedUntilTheNewVaultsCoHoldersLoaded() = runBlocking<Unit> {
        val h = household()
        val device = MemoryDeviceState()
        val first = unlock(h.victim, h.victim.reg.personalWrap)
        establish(SyncEngine(api(FakeServer(h.feed)), first, InMemoryVaultCache(), deviceState = device))

        val again = unlock(h.victim, h.sharedWrap)
        // The member lookup for the NEW vault fails (the server withholds it).
        val failing = FakeServer(h.feed, failMembers = true)
        val engine = SyncEngine(api(failing), again, InMemoryVaultCache(), deviceState = device)
        engine.sync()
        assertEquals(Account.PersonalStatus.CHANGED, again.personalStatus)
        assertFailsWith<Exception> { engine.describePersonalChange() }
        assertFailsWith<IllegalStateException>("no co-holder list, no \"Use new\"") { engine.acceptPersonalChange() }
        assertEquals(h.victim.reg.personalVault.vaultId, again.personalVaultId)

        // Once the lookup succeeds, the details name the co-holders (server-reported) and "Use new" works.
        val ok = FakeServer(h.feed, mapOf(h.sharedId to listOf(member(h.mate, "writer", "Mate"))))
        val e2 = SyncEngine(api(ok), again, InMemoryVaultCache(), deviceState = device)
        val details = e2.describePersonalChange()
        assertEquals(h.sharedId, details.servedVaultId)
        assertEquals(listOf("Mate"), details.servedCoHolders.map { it.displayName })
        assertEquals(h.victim.reg.personalVault.vaultId, details.currentVaultId)
        e2.acceptPersonalChange()
        assertEquals(h.sharedId, again.personalVaultId)
    }

    // ---- L-1: a junk served wrap keeps the valid cached one ----

    @Test
    fun l1_aJunkServedWrapKeepsTheValidCachedWrap() = runBlocking<Unit> {
        val h = household()
        val device = MemoryDeviceState()
        val first = unlock(h.victim, h.victim.reg.personalWrap)
        establish(SyncEngine(api(FakeServer(h.feed)), first, InMemoryVaultCache(), deviceState = device))

        // The server serves the OWNER wrap where the personal wrap belongs: present, but it never opens.
        val junk = PersonalWrap(h.victim.reg.personalVault.vaultId, h.victim.reg.personalVault.wrappedVk)
        val again = unlock(h.victim, junk)
        assertEquals(Account.PersonalStatus.UNREADABLE, again.personalStatus)
        val server = FakeServer(h.feed)
        val engine = SyncEngine(api(server), again, InMemoryVaultCache(), deviceState = device)
        engine.hydrate()
        engine.sync()
        assertEquals(Account.PersonalStatus.UNREADABLE_CACHED, again.personalStatus, "an anomaly, flagged")
        assertEquals(h.victim.reg.personalVault.vaultId, again.personalVaultId, "the valid cached wrap stays in force")
        assertTrue(device.get("personal.wrap")!!.contains(h.victim.reg.personalVault.vaultId), "the cached wrap is not discarded")
        assertTrue(server.personalWrapPuts.isEmpty())
        // The re-designation list marks the vault this device already had.
        assertTrue(engine.personalChoiceInfo(h.victim.reg.personalVault.vaultId).onThisDevice)
        assertFalse(engine.personalChoiceInfo(h.sharedId).onThisDevice)
    }
}
