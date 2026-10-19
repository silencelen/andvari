package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.GrantOutcome
import io.silencelen.andvari.core.crypto.GrantPin
import io.silencelen.andvari.core.crypto.SignedGrant
import io.silencelen.andvari.core.crypto.Statement
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.AccountStateResponse
import io.silencelen.andvari.core.model.GrantReissueRequest
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.RemovedGrantInfo
import io.silencelen.andvari.core.model.SelfWrapRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Signed vault grants on the path a real client takes (security review 2026-10, root cause A §1.4–§1.6, §3.2,
 * §8.2, branch A6). The invariant: a member never adopts a VK, and never mints a self-wrap, for a key the server
 * or an unpinned party chose.
 *
 *  - a verified grant from a PINNED, current contact is adopted, named, and self-wrapped once;
 *  - a grant that names the owner but is signed by another pinned member, or whose signer is not the pinned key
 *    of the named sender, is refused (an anomaly) and never falls back to the v1 seal on the same row;
 *  - an unpinned sender is a pending invitation; accepting runs the verification ceremony, then §1.4 again;
 *  - a key only a v1 seal vouches for is legacy-read-only and is self-wrapped only after the human confirms it,
 *    or with pre-upgrade evidence on this device (the §8.2 freeze);
 *  - a pin a fresh device learned from an older account-state blob cannot skip verification (A5 review L-3);
 *  - the owner grants only to a pinned member, sealed to the PIN key, and re-issues legacy grants (§8.2 step 4).
 */
class SignedGrantEngineTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val doc = ItemDoc(type = "login", name = "Shared login", login = LoginData(username = "fam", password = "hunter2"))

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys) {
        val userId get() = reg.userId
    }

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
                escrowFingerprint = reg.escrow!!.fingerprint, personalWrap = reg.personalWrap,
            ),
        )
    }

    private fun unlock(e: Enrolled) = Account.unlock(e.userId, password, e.keys, crypto)

    /** A scripted hostile-capable server. */
    private class FakeServer(var feed: SyncResponse) {
        val selfWraps = mutableListOf<Pair<String, String>>()
        val adds = mutableListOf<Pair<String, VaultMemberAdd>>()
        val reissues = mutableListOf<Triple<String, String, String>>() // vaultId, userId, signedGrant
        val identities = HashMap<String, UserLookupResponse>()
        val members = HashMap<String, List<VaultMemberSummary>>()
        var accountState: String? = null
        var accountSeq: Long = 0
        /** A7 review: answer the next delta pull with 410, forcing a since=0 resync. */
        var resyncOnce = false
        val leaves = mutableListOf<String>()
    }

    private fun body(req: io.ktor.client.request.HttpRequestData): String = when (val b = req.body) {
        is TextContent -> b.text
        is OutgoingContent.ByteArrayContent -> b.bytes().decodeToString()
        else -> error("unexpected body")
    }

    private fun api(server: FakeServer): AndvariApi {
        val engine = MockEngine { req ->
            val path = req.url.encodedPath
            val ct = headersOf(HttpHeaders.ContentType, "application/json")
            val members = Regex("^/api/v1/vaults/([^/]+)/members$").find(path)
            val reissue = Regex("^/api/v1/vaults/([^/]+)/members/([^/]+)/grant$").find(path)
            val identity = Regex("^/api/v1/users/([^/]+)/identity$").find(path)
            when {
                path == "/api/v1/sync" && server.resyncOnce && (req.url.parameters["since"]?.toLongOrNull() ?: 0L) > 0L -> {
                    server.resyncOnce = false
                    respond("""{"error":"resync_required","message":"gone"}""", HttpStatusCode.Gone, ct)
                }
                path.endsWith("/leave") -> {
                    server.leaves.add(path)
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                }
                path == "/api/v1/sync" -> {
                    val since = req.url.parameters["since"]?.toLongOrNull() ?: 0L
                    val resp = when {
                        since == 0L -> server.feed
                        since < server.feed.rev -> server.feed.copy(full = false)
                        else -> SyncResponse(server.feed.rev, false, emptyList(), emptyList(), emptyList(), emptyList())
                    }
                    respond(json.encodeToString(SyncResponse.serializer(), resp), HttpStatusCode.OK, ct)
                }
                path == "/api/v1/account/state" && req.method == HttpMethod.Get ->
                    respond(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(server.accountState, server.accountSeq)), HttpStatusCode.OK, ct)
                path == "/api/v1/account/state" && req.method == HttpMethod.Put -> {
                    val put = json.decodeFromString(AccountStatePut.serializer(), body(req))
                    if (put.baseSeq != server.accountSeq) {
                        respond("""{"error":"stale_state","message":"stale"}""", HttpStatusCode.Conflict, ct)
                    } else {
                        server.accountState = put.sealedState
                        server.accountSeq += 1
                        respond(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(put.sealedState, server.accountSeq)), HttpStatusCode.OK, ct)
                    }
                }
                identity != null -> {
                    val u = server.identities[identity.groupValues[1]]
                    if (u == null) respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, ct)
                    else respond(json.encodeToString(UserLookupResponse.serializer(), u), HttpStatusCode.OK, ct)
                }
                members != null && req.method == HttpMethod.Get ->
                    respond(json.encodeToString(ListSerializer(VaultMemberSummary.serializer()), server.members[members.groupValues[1]].orEmpty()), HttpStatusCode.OK, ct)
                members != null && req.method == HttpMethod.Post -> {
                    server.adds.add(members.groupValues[1] to json.decodeFromString(VaultMemberAdd.serializer(), body(req)))
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.Created, ct)
                }
                reissue != null && req.method == HttpMethod.Put -> {
                    val r = json.decodeFromString(GrantReissueRequest.serializer(), body(req))
                    server.reissues.add(Triple(reissue.groupValues[1], reissue.groupValues[2], r.signedGrant))
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                }
                req.method == HttpMethod.Put && path.endsWith("/grant/self-wrap") -> {
                    val vaultId = path.removePrefix("/api/v1/vaults/").removeSuffix("/grant/self-wrap")
                    server.selfWraps.add(vaultId to json.decodeFromString(SelfWrapRequest.serializer(), body(req)).wrappedVk)
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                }
                else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
    }

    private fun served(e: Enrolled, name: String) = UserLookupResponse(e.userId, name, e.reg.identityPub)
    private fun pinOf(e: Enrolled, label: String) = Contact(e.userId, e.reg.identityPub, label, 1_000, Contact.METHOD_TYPED, email = "${label.lowercase()}@example.com") // A11: the ceremony records the typed email
    private fun personalRow(e: Enrolled) = WireVault(e.reg.personalVault.vaultId, "personal", 2, e.reg.personalVault.metaBlob, 0)
    private fun personalGrant(e: Enrolled) = WireGrant(e.reg.personalVault.vaultId, e.userId, "owner", e.reg.personalVault.wrappedVk, 2, null)

    /** An owner, a member, and a shared vault "Household" the owner created. */
    private class World(val owner: Enrolled, val member: Enrolled, val vaultId: String, val metaBlob: String, val vk: ByteArray)

    private fun world(): World {
        val owner = enroll("a6-owner")
        val member = enroll("a6-member")
        val shared = owner.account.buildCreateSharedVault("Household")
        val vk = Envelope.openB64(crypto, ownerUvk(owner), shared.request.wrappedVk, Ad.vk(shared.vaultId, owner.userId))
        return World(owner, member, shared.vaultId, shared.request.metaBlob, vk)
    }

    // The owner's VK, recovered only to fabricate fixtures the way a real owner client would hold it.
    private fun ownerUvk(e: Enrolled): ByteArray {
        val mk = Keys.masterKey(crypto, password, Bytes.fromB64(e.keys.kdfSalt), e.keys.kdfParams)
        return Envelope.openB64(crypto, Keys.wrapKey(crypto, mk), e.keys.wrappedUvk, Ad.uvk(e.userId))
    }

    private fun feed(w: World, rev: Long, grant: WireGrant?, items: List<WireItem> = emptyList()) = SyncResponse(
        rev = rev, full = true,
        vaults = listOfNotNull(personalRow(w.member), if (grant != null) WireVault(w.vaultId, "shared", 3, w.metaBlob, 0) else null),
        grants = listOfNotNull(personalGrant(w.member), grant),
        items = items, removedGrants = emptyList(),
    )

    private fun v1Seal(w: World, to: ByteArray = Bytes.fromB64(w.member.reg.identityPub)) =
        Bytes.toB64(SharedGrant.seal(crypto, to, w.vaultId, w.vk))

    /** A v2 grant built by the owner's own client, to its pin for the member. */
    private fun ownerSignedGrant(w: World): String = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"))

    private fun memberRow(w: World, rev: Long, sealedVk: String?, signedGrant: String?) =
        WireGrant(w.vaultId, w.member.userId, "writer", "", rev, sealedVk, signedGrant)

    private fun opensTo(member: Enrolled, wrap: String, vaultId: String): ByteArray =
        Envelope.openB64(crypto, ownerUvk(member), wrap, Ad.vk(vaultId, member.userId))

    // ---- §1.4: verified, pinned, current ----

    @Test
    fun aVerifiedGrantFromAPinnedOwnerIsAdoptedNamedAndSelfWrappedOnce() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        assertNotNull(engine.verifyMemberTyped(served(w.owner, "Owner"), w.owner.account.identityFingerprintShort()))

        server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSignedGrant(w)))
        engine.sync()
        assertTrue(device.hasVault(w.vaultId))
        assertEquals(Account.KeySource.SIGNED_GRANT, device.keySource(w.vaultId))
        assertFalse(device.isLegacyReadOnly(w.vaultId))
        val added = engine.notices().single { it.vaultId == w.vaultId }
        assertEquals("added", added.kind)
        assertEquals("Household", added.vaultName)
        assertEquals("Owner", added.byLabel, "the notice names the PINNED contact's label")
        assertEquals(1, server.selfWraps.size, "a verified grant is self-wrapped (§3.2)")
        assertContentEquals(w.vk, opensTo(w.member, server.selfWraps.single().second, w.vaultId))
        engine.sync()
        assertEquals(1, server.selfWraps.size, "posted once")
    }

    // ---- §1.4 step 8: the pin is chosen by contacts[from] ----

    @Test
    fun aGrantNamingTheOwnerButSignedByAnotherPinnedMemberIsRefused() = runBlocking<Unit> {
        val w = world()
        // Mallory is another household member this account ALSO pinned (and who colludes with the server).
        val mallorySeed = crypto.randomBytes(32)
        val malloryBox = crypto.boxKeypairFromSeed(mallorySeed)
        val mallorySign = crypto.signKeypairFromSeed(mallorySeed)
        val malloryId = "33333333-3333-4333-8333-333333333333"
        val server = FakeServer(feed(w, 5, null))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        engine.accountState.pin(pinOf(w.owner, "Owner"))
        engine.accountState.pin(Contact(malloryId, Bytes.toB64(malloryBox.publicKey), "Mallory", 1_000, Contact.METHOD_TYPED))

        val serverVk = crypto.randomBytes(32)
        val forged = SignedGrant.buildFrame(
            crypto, mallorySign,
            Statement.VaultGrant(w.owner.userId, w.member.userId, Bytes.fromB64(w.member.reg.identityPub), w.vaultId, crypto.randomBytes(16), 1_791_590_400_000, serverVk),
        )
        val sealed = Bytes.toB64(crypto.sealTo(Bytes.fromB64(w.member.reg.identityPub), forged))
        val v1Forged = Bytes.toB64(SharedGrant.seal(crypto, Bytes.fromB64(w.member.reg.identityPub), w.vaultId, serverVk))
        server.feed = feed(w, 9, memberRow(w, 9, v1Forged, sealed))
        engine.sync()
        assertFalse(device.hasVault(w.vaultId), "refused, and the v1 seal on the same row is not a fallback")
        assertEquals("signer_not_pinned_key", engine.notices().single { it.vaultId == w.vaultId && it.kind == "grant-anomaly" }.reason)
        assertTrue(engine.pendingInvitations().isEmpty())
        assertTrue(server.selfWraps.isEmpty())
    }

    @Test
    fun aGrantWhoseSignerIsNotThePinnedKeyOfTheNamedSenderIsRefused() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        // The member pinned "the owner" with a key the server substituted at verification time... except a human
        // compared it, so model the honest version: the pin holds ANOTHER key for the owner's userId.
        val other = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        engine.accountState.pin(Contact(w.owner.userId, Bytes.toB64(other.publicKey), "Owner", 1_000, Contact.METHOD_TYPED))
        server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSignedGrant(w)))
        engine.sync()
        assertFalse(device.hasVault(w.vaultId))
        assertEquals("signer_not_pinned_key", engine.notices().single { it.kind == "grant-anomaly" }.reason)
        assertTrue(server.selfWraps.isEmpty())
    }

    // ---- §1.6: unpinned sender → pending invitation ----

    @Test
    fun anUnpinnedSenderIsAPendingInvitationAndAcceptingRunsTheCeremony() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSignedGrant(w))))
        server.identities[w.owner.userId] = served(w.owner, "Owner (server)")
        val device = unlock(w.member)
        val cache = InMemoryVaultCache()
        val engine = SyncEngine(api(server), device, cache)
        engine.sync()
        assertFalse(device.hasVault(w.vaultId), "not adopted, and the dual-sent v1 seal is not used instead")
        assertTrue(engine.vaultInfos().none { it.vaultId == w.vaultId })
        val inv = engine.pendingInvitations().single()
        assertEquals(w.vaultId, inv.vaultId)
        assertEquals(w.owner.userId, inv.fromUserId)
        assertTrue(server.selfWraps.isEmpty())

        // A wrong code pins nothing and adopts nothing.
        assertFalse(engine.acceptInvitation(inv, "0000 0000 0000 0000 0000 0000 0000 0000"))
        assertFalse(device.hasVault(w.vaultId))
        // The right code (read from the owner's screen) pins the owner and re-runs §1.4.
        assertTrue(engine.acceptInvitation(inv, w.owner.account.identityFingerprintShort()))
        assertTrue(device.hasVault(w.vaultId))
        assertEquals(Account.KeySource.SIGNED_GRANT, device.keySource(w.vaultId))
        assertTrue(engine.pendingInvitations().isEmpty())
        engine.sync()
        assertEquals(1, server.selfWraps.size)
    }

    @Test
    fun aDeclinedInvitationStaysHiddenAcrossARestart() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, null, ownerSignedGrant(w))))
        val cache = InMemoryVaultCache()
        val engine = SyncEngine(api(server), unlock(w.member), cache)
        engine.sync()
        engine.declineInvitation(engine.pendingInvitations().single())
        assertTrue(engine.pendingInvitations().isEmpty())
        val again = SyncEngine(api(server), unlock(w.member), cache)
        again.hydrate()
        again.sync()
        assertTrue(again.pendingInvitations().isEmpty())
    }

    // ---- §8.2: v1-only keys ----

    @Test
    fun aV1OnlyKeyIsReadOnlyAndSelfWrappedOnlyAfterTheHumanConfirms() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.hydrate()
        engine.sync()
        engine.sync()
        assertTrue(device.hasVault(w.vaultId), "in-window: readable")
        assertEquals(Account.KeySource.LEGACY_SEAL, device.keySource(w.vaultId))
        assertTrue(device.isLegacyReadOnly(w.vaultId))
        assertEquals("reader", device.roleFor(w.vaultId), "INV-WRITE-KEY: every write path treats it as read-only")
        assertFailsWith<VaultKeyNotVerifiedException> { device.encryptItem(w.vaultId, device.newItemId(), doc) }
        assertTrue(server.selfWraps.isEmpty(), "never minted for an unconfirmed v1-seal key")
        val review = engine.legacyReviewVaults().single()
        assertEquals(w.vaultId, review.vaultId)
        assertEquals("Household", review.name)

        engine.acceptLegacyVault(w.vaultId)
        assertEquals(1, server.selfWraps.size, "Accept (trust on first use) mints the self-wrap")
        assertFalse(device.isLegacyReadOnly(w.vaultId))
        assertTrue(engine.legacyReviewVaults().isEmpty())
    }

    /** A vouch (Accept or freeze) covers the EXACT key it was given for: if the self-wrap never reached the row and
     *  the server later serves a different v1 key for the same vaultId, that key is read-only again. */
    @Test
    fun aVouchCoversOnlyTheKeyItWasGivenFor() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val cache = InMemoryVaultCache()
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, cache)
        engine.sync()
        engine.acceptLegacyVault(w.vaultId)
        assertFalse(device.isLegacyReadOnly(w.vaultId))

        // Same device state (the vouch is persisted), a fresh cache: the server now serves ANOTHER key for the vault.
        val forgedVk = crypto.randomBytes(32)
        val forged = Bytes.toB64(SharedGrant.seal(crypto, Bytes.fromB64(w.member.reg.identityPub), w.vaultId, forgedVk))
        val cache2 = InMemoryVaultCache()
        cache2.setClientState("grant.legacy.authorized", cache.clientState("grant.legacy.authorized"))
        cache2.setClientState("grant.freeze.done", "1")
        val server2 = FakeServer(feed(w, 10, memberRow(w, 10, forged, null)))
        val again = unlock(w.member)
        val e2 = SyncEngine(api(server2), again, cache2)
        e2.hydrate()
        e2.sync()
        // Round 3 (the vouch gate): the swapped-in key is not even held read-only; it is refused as vk_mismatch.
        assertFalse(again.hasVault(w.vaultId), "the vouch does not carry over to a key the server swapped in")
        assertEquals(io.silencelen.andvari.core.crypto.GrantVerdict.VK_MISMATCH, again.grantAnomalies()[w.vaultId])
        assertTrue(server2.selfWraps.isEmpty())
    }

    @Test
    fun preUpgradeEvidenceFreezesTheKeyButALaterV1GrantDoesNot() = runBlocking<Unit> {
        val w = world()
        val item = w.owner.account.let { o ->
            val itemId = o.newItemId()
            val up = o.encryptItem(w.vaultId, itemId, doc)
            WireItem(itemId, w.vaultId, 4, 1, 1, false, false, up.formatVersion, emptyList(), up.blob)
        }
        // The cache a pre-A6 client left behind: the v1 row and an item that decrypted under it.
        val cache = InMemoryVaultCache()
        val row = memberRow(w, 4, v1Seal(w), null)
        cache.upsertGrant(row)
        cache.upsertVault(WireVault(w.vaultId, "shared", 3, w.metaBlob, 0))
        cache.upsertVault(personalRow(w.member))
        cache.upsertGrant(personalGrant(w.member))
        cache.upsertItem(item, null)
        cache.setCursor(4)

        // A second shared vault that a v1 grant delivers only AFTER the upgrade.
        val later = w.owner.account.buildCreateSharedVault("Later")
        val laterVk = Envelope.openB64(crypto, ownerUvk(w.owner), later.request.wrappedVk, Ad.vk(later.vaultId, w.owner.userId))
        val laterRow = WireGrant(later.vaultId, w.member.userId, "writer", "", 8,
            Bytes.toB64(SharedGrant.seal(crypto, Bytes.fromB64(w.member.reg.identityPub), later.vaultId, laterVk)), null)
        val server = FakeServer(
            SyncResponse(8, false, listOf(WireVault(later.vaultId, "shared", 8, later.request.metaBlob, 0)), listOf(laterRow), emptyList(), emptyList()),
        )
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, cache)
        engine.hydrate()
        engine.sync()
        assertEquals(listOf(w.vaultId), server.selfWraps.map { it.first }, "only the vault with pre-upgrade evidence is frozen")
        assertFalse(device.isLegacyReadOnly(w.vaultId))
        assertTrue(device.isLegacyReadOnly(later.vaultId))
        assertEquals(listOf(later.vaultId), engine.legacyReviewVaults().map { it.vaultId })
    }

    // ---- A5 review L-3: a pin must be current to skip verification ----

    @Test
    fun aPinAFreshDeviceLearnedFromAnOlderBlobCannotSkipVerification() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        // Device A pins the owner, then removes the pin; the server keeps the OLDER blob (seq with the pin).
        val a = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        a.sync()
        a.accountState.pin(pinOf(w.owner, "Owner"))
        val olderBlob = server.accountState
        val olderSeq = server.accountSeq
        a.accountState.unpin(w.owner.userId)
        server.accountState = olderBlob
        server.accountSeq = olderSeq

        // A fresh device B (no high-water mark) reads the older blob: the pin is there, but not current.
        server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSignedGrant(w)))
        val bAccount = unlock(w.member)
        val b = SyncEngine(api(server), bAccount, InMemoryVaultCache())
        b.sync()
        assertNotNull(b.accountState.doc.contact(w.owner.userId), "the stale pin is in the blob")
        assertNull(b.accountState.currentPin(w.owner.userId), "but it may not skip verification on this device")
        assertFalse(bAccount.hasVault(w.vaultId), "so the grant is NOT auto-adopted")
        assertEquals(w.owner.userId, b.pendingInvitations().single().fromUserId)
        assertEquals(SyncEngine.MemberPinState.NEEDS_VERIFICATION, b.memberPinState(served(w.owner, "Owner")),
            "and it cannot skip the add-member check either")
        b.sync()
        assertFalse(bAccount.hasVault(w.vaultId), "a later read on the same device does not promote it")

        // Re-verifying on THIS device makes it current.
        assertNotNull(b.verifyMemberTyped(served(w.owner, "Owner"), w.owner.account.identityFingerprintShort()))
        b.sync()
        assertTrue(bAccount.hasVault(w.vaultId))
    }

    /**
     * A6 review MED-1: the earlier high-water rule could be stepped up by a server serving OLDER authentic blobs in
     * ascending order (each above the last mark), so a later-tombstoned pin became "current". The rule now: a pin
     * is current on a device only when a human made or re-confirmed it ON THAT DEVICE.
     */
    @Test
    fun anAscendingReplayOfOlderBlobsNeverMakesAPinCurrent() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val a = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        a.sync()
        a.accountState.pin(Contact("44444444-4444-4444-8444-444444444444", Bytes.toB64(crypto.randomBytes(32)), "Other", 1, Contact.METHOD_TYPED))
        val blob1 = server.accountState to server.accountSeq
        a.accountState.pin(pinOf(w.owner, "Owner"))
        val blob2 = server.accountState to server.accountSeq
        a.accountState.unpin(w.owner.userId) // the genuine latest state: the owner's pin is tombstoned

        val bAccount = unlock(w.member)
        val b = SyncEngine(api(server), bAccount, InMemoryVaultCache())
        server.accountState = blob1.first; server.accountSeq = blob1.second
        b.sync() // establishes a mark on the older blob
        server.accountState = blob2.first; server.accountSeq = blob2.second
        server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSignedGrant(w)))
        b.sync() // a higher (but still stale) seq: the stale pin reappears
        assertNotNull(b.accountState.doc.contact(w.owner.userId))
        assertNull(b.accountState.currentPin(w.owner.userId), "never confirmed on this device: not current")
        assertFalse(bAccount.hasVault(w.vaultId))
        assertEquals(w.owner.userId, b.pendingInvitations().single().fromUserId)
    }

    @Test
    fun aPinAddedOnAnotherDeviceIsNotCurrentHereUntilVerifiedHere() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val bAccount = unlock(w.member)
        val b = SyncEngine(api(server), bAccount, InMemoryVaultCache())
        b.sync()
        b.accountState.pin(Contact("44444444-4444-4444-8444-444444444444", Bytes.toB64(crypto.randomBytes(32)), "Someone", 1, Contact.METHOD_TYPED))
        val a = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        a.sync()
        a.accountState.pin(pinOf(w.owner, "Owner"))
        assertNotNull(a.accountState.currentPin(w.owner.userId), "made by a human on device A: current there")
        b.sync()
        assertNotNull(b.accountState.doc.contact(w.owner.userId))
        assertNull(b.accountState.currentPin(w.owner.userId), "synced, not confirmed here")
        assertEquals(SyncEngine.MemberPinState.NEEDS_VERIFICATION, b.memberPinState(served(w.owner, "Owner")))
        assertNotNull(b.verifyMemberTyped(served(w.owner, "Owner"), w.owner.account.identityFingerprintShort()))
        assertNotNull(b.accountState.currentPin(w.owner.userId), "re-confirmed on this device")
    }

    @Test
    fun aConfirmationForAnotherIdentityKeyDoesNotCount() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val cache = InMemoryVaultCache()
        val b = SyncEngine(api(server), unlock(w.member), cache)
        b.sync()
        // This device confirmed the owner's userId with ANOTHER key once (e.g. before a re-enrolment).
        val oldKey = Bytes.toB64(crypto.randomBytes(32))
        b.accountState.pin(Contact(w.owner.userId, oldKey, "Owner", 1_000, Contact.METHOD_TYPED))
        // Another device later pins the owner's real key; it syncs here.
        val a = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        a.sync()
        a.accountState.pin(pinOf(w.owner, "Owner").copy(verifiedAt = 2_000))
        b.sync()
        assertEquals(w.owner.reg.identityPub, b.accountState.doc.contact(w.owner.userId)!!.identityPub)
        assertNull(b.accountState.currentPin(w.owner.userId), "the local confirmation was for a different key")
    }

    @Test
    fun aTombstoneStillWinsOverALocalConfirmation() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val b = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        b.sync()
        b.accountState.pin(pinOf(w.owner, "Owner"))
        val a = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        a.sync()
        a.accountState.unpin(w.owner.userId)
        b.sync()
        assertNull(b.accountState.currentPin(w.owner.userId))
    }

    // ---- A6 review MED-2: a v2 grant never silently replaces a legacy-held key ----

    @Test
    fun aDifferentKeyV2GrantBesideAVouchedLegacyKeyIsAnAnomalyAndTheHeldKeyStays() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        engine.acceptLegacyVault(w.vaultId)
        engine.accountState.pin(pinOf(w.owner, "Owner"))
        // A pinned contact (the owner, or anyone this account pinned) signs a grant carrying ANOTHER key.
        val otherVk = crypto.randomBytes(32)
        val forged = forgeSigned(w, w.owner, otherVk)
        server.feed = feed(w, 12, memberRow(w, 12, v1Seal(w), forged))
        engine.sync()
        assertEquals("vk_mismatch", engine.notices().single { it.kind == "grant-anomaly" }.reason)
        assertEquals(Account.KeySource.LEGACY_SEAL, device.keySource(w.vaultId), "no silent switch")
        assertFalse(device.isLegacyReadOnly(w.vaultId), "the vouched key stays in force")
        assertEquals("Household", device.decryptVaultName(w.vaultId, w.metaBlob), "the held key is the original")
    }

    @Test
    fun aDifferentKeyV2GrantBesideAnUnvouchedLegacyKeyIsAnAnomalyAndStaysReadOnly() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        engine.accountState.pin(pinOf(w.owner, "Owner"))
        server.feed = feed(w, 12, memberRow(w, 12, v1Seal(w), forgeSigned(w, w.owner, crypto.randomBytes(32))))
        engine.sync()
        assertEquals("vk_mismatch", engine.notices().single { it.kind == "grant-anomaly" }.reason)
        assertEquals(Account.KeySource.LEGACY_SEAL, device.keySource(w.vaultId))
        assertTrue(device.isLegacyReadOnly(w.vaultId))
        assertEquals("Household", device.decryptVaultName(w.vaultId, w.metaBlob))
        assertTrue(server.selfWraps.isEmpty())
    }

    /** Cold start: the vouched v1 key wins over a verified v2 grant naming a different key (anomaly). */
    @Test
    fun onColdStartAVouchedLegacyKeyIsNotReplacedByADifferentV2Key() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val cache = InMemoryVaultCache()
        val first = SyncEngine(api(server), unlock(w.member), cache)
        first.sync()
        first.acceptLegacyVault(w.vaultId)
        first.accountState.pin(pinOf(w.owner, "Owner"))
        val restartCache = InMemoryVaultCache()
        for (k in listOf("grant.legacy.authorized", "grant.freeze.done", "acctstate.copy", "acctstate.hw", "pins.confirmed")) {
            restartCache.setClientState(k, cache.clientState(k))
        }
        server.feed = feed(w, 12, memberRow(w, 12, v1Seal(w), forgeSigned(w, w.owner, crypto.randomBytes(32))))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, restartCache)
        engine.hydrate()
        engine.sync()
        assertEquals(Account.KeySource.LEGACY_SEAL, device.keySource(w.vaultId))
        assertEquals("Household", device.decryptVaultName(w.vaultId, w.metaBlob))
        assertTrue(engine.notices().any { it.kind == "grant-anomaly" && it.reason == "vk_mismatch" })
    }

    // ---- A6 re-review round 2 ----

    private suspend fun vouchedThenRestart(w: World, row: WireGrant): Pair<Account, Pair<SyncEngine, FakeServer>> {
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val cache = InMemoryVaultCache()
        val first = SyncEngine(api(server), unlock(w.member), cache)
        first.sync()
        first.acceptLegacyVault(w.vaultId)
        first.accountState.pin(pinOf(w.owner, "Owner"))
        val restartCache = InMemoryVaultCache()
        for (k in listOf("grant.legacy.authorized", "grant.freeze.done", "acctstate.copy", "acctstate.hw", "pins.confirmed")) {
            restartCache.setClientState(k, cache.clientState(k))
        }
        server.selfWraps.clear() // the Accept above posted one; only what the restarted device posts matters here
        server.feed = feed(w, 12, row)
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, restartCache)
        engine.hydrate()
        engine.sync()
        return device to (engine to server)
    }

    /** MEDIUM-A: the vouch is decided from the device-local tag, not from whether the server kept the v1 seal. */
    @Test
    fun aVouchWithAStrippedSealRefusesADifferentKeyV2Grant() = runBlocking<Unit> {
        val w = world()
        val (device, es) = vouchedThenRestart(w, memberRow(w, 12, null, forgeSigned(w, w.owner, crypto.randomBytes(32))))
        val (engine, server) = es
        assertFalse(device.hasVault(w.vaultId), "K' is never adopted")
        assertEquals("vk_mismatch", engine.notices().single { it.kind == "grant-anomaly" }.reason)
        assertTrue(server.selfWraps.isEmpty())
    }

    @Test
    fun aVouchWithAStrippedSealAdoptsASameKeyV2GrantNormally() = runBlocking<Unit> {
        val w = world()
        val (device, es) = vouchedThenRestart(w, memberRow(w, 12, null, forgeSigned(w, w.owner, w.vk)))
        assertEquals(Account.KeySource.SIGNED_GRANT, device.keySource(w.vaultId))
        assertTrue(es.first.notices().none { it.kind == "grant-anomaly" })
    }

    /** LOW-A parity (core already replaced the user's earlier confirmation; pinned here for the web twin). */
    @Test
    fun reConfirmingAUserReplacesThisDevicesEarlierConfirmation() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val b = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        b.sync()
        val oldKey = Bytes.toB64(crypto.randomBytes(32))
        b.accountState.pin(Contact(w.owner.userId, oldKey, "Owner", 1_000, Contact.METHOD_TYPED))
        b.accountState.pin(pinOf(w.owner, "Owner").copy(verifiedAt = 2_000))
        val a = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        a.sync()
        a.accountState.pin(Contact(w.owner.userId, oldKey, "Owner", 3_000, Contact.METHOD_TYPED))
        b.sync()
        assertEquals(oldKey, b.accountState.doc.contact(w.owner.userId)!!.identityPub)
        assertNull(b.accountState.currentPin(w.owner.userId))
    }

    /** LOW-D: an import (or any write's reconcile) that pulls before any sync/hydrate must not leave the freeze to
     *  run later over rows this release pulled. */
    @Test
    fun anImportBeforeTheFirstSyncCannotLaterCountAsPreUpgradeEvidence() = runBlocking<Unit> {
        val w = world()
        val item = w.owner.account.let { o ->
            val id = o.newItemId(); val up = o.encryptItem(w.vaultId, id, doc)
            WireItem(id, w.vaultId, 4, 1, 1, false, false, up.formatVersion, emptyList(), up.blob)
        }
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null), listOf(item)))
        val cache = InMemoryVaultCache()
        val first = SyncEngine(api(server), unlock(w.member), cache)
        first.importAll(emptyList()) // pulls the post-upgrade rows; no sync(), no hydrate()
        assertNotNull(cache.clientState("grant.freeze.done"), "the pull itself marks the freeze as done")
        val again = unlock(w.member)
        val e2 = SyncEngine(api(server), again, cache)
        e2.hydrate()
        assertTrue(again.isLegacyReadOnly(w.vaultId), "rows pulled by this release are never pre-upgrade evidence")
    }

    // ---- A6 re-review round 3: ONE vouch gate on every key-source path ----

    /** A device that vouched for the real key K (Accept), restarted, then served [rows] in order (warm pulls). */
    private suspend fun vouchedThenServe(w: World, rows: List<WireGrant?>): Triple<Account, SyncEngine, FakeServer> {
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val cache = InMemoryVaultCache()
        val first = SyncEngine(api(server), unlock(w.member), cache)
        first.sync()
        first.acceptLegacyVault(w.vaultId)
        first.accountState.pin(pinOf(w.owner, "Owner"))
        val restartCache = InMemoryVaultCache()
        for (k in listOf("grant.legacy.authorized", "grant.freeze.done", "acctstate.copy", "acctstate.hw", "pins.confirmed")) {
            restartCache.setClientState(k, cache.clientState(k))
        }
        server.selfWraps.clear()
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, restartCache)
        engine.hydrate()
        var rev = 12L
        for (row in rows) {
            server.feed = feed(w, rev, row?.copy(rev = rev))
            engine.sync()
            rev += 3
        }
        return Triple(device, engine, server)
    }

    private fun sealOf(w: World, vk: ByteArray) = Bytes.toB64(SharedGrant.seal(crypto, Bytes.fromB64(w.member.reg.identityPub), w.vaultId, vk))
    private fun wrapOf(w: World, vk: ByteArray) = Envelope.sealB64(crypto, ownerUvk(w.member), vk, Ad.vk(w.vaultId, w.member.userId))
    private fun tag(vk: ByteArray) = Bytes.toHexLower(crypto.sha256(vk))

    /** The invariant: K' (≠ the vouched K) is never writable, never self-wrapped, never offered for Accept, never
     *  owner-wrapped; only under rule 2 (our own UVK wrap) is it used, and then it is flagged vk_mismatch. */
    private suspend fun assertVouchHolds(w: World, kPrime: ByteArray, device: Account, engine: SyncEngine, server: FakeServer, ruleTwo: Boolean, label: String) {
        val heldIsKPrime = device.hasVault(w.vaultId) && device.legacyKeyTag(w.vaultId) == tag(kPrime)
        if (ruleTwo) {
            assertTrue(heldIsKPrime, "$label: the UVK wrap is canonical (A1) and is used")
            assertEquals(io.silencelen.andvari.core.crypto.GrantVerdict.VK_MISMATCH, device.grantAnomalies()[w.vaultId], "$label: flagged")
        } else {
            assertFalse(heldIsKPrime && !device.isLegacyReadOnly(w.vaultId), "$label: K' never writable")
            assertFalse(heldIsKPrime, "$label: K' never held at all")
        }
        if (heldIsKPrime) {
            assertFalse(device.selfWrapAuthorized(w.vaultId), "$label: K' never self-wrapped")
            assertFailsWith<VaultKeyNotVerifiedException>("$label: K' never owner-wrapped") { device.buildOwnerWrap(w.vaultId) }
            // A6 final review LOW-G: nor signed onward to anyone.
            assertFailsWith<VaultKeyNotVerifiedException>("$label: K' never signed onward") { device.buildSignedGrant(w.vaultId, pinOf(w.owner, "Owner")) }
        }
        for ((_, wrap) in server.selfWraps) {
            assertFalse(Bytes.ctEquals(kPrime, Envelope.openB64(crypto, ownerUvk(w.member), wrap, Ad.vk(w.vaultId, w.member.userId))), "$label: no self-wrap of K'")
        }
        assertTrue(engine.legacyReviewVaults().none { it.vaultId == w.vaultId }, "$label: not offered for Accept")
        assertTrue(runCatching { engine.acceptLegacyVault(w.vaultId) }.isFailure, "$label: Accept refuses")
    }

    @Test
    fun theVouchGateHoldsForEveryRowShapeInEveryOrder() = runBlocking<Unit> {
        val third = enroll("a6-unpinned-sender")
        val shapes: List<Pair<String, (World, ByteArray) -> WireGrant?>> = listOf(
            "wrap" to { w, k -> memberRow(w, 0, null, null).copy(wrappedVk = wrapOf(w, k)) },
            "v2" to { w, k -> memberRow(w, 0, null, forgeSigned(w, w.owner, k)) },
            "v2+seal" to { w, k -> memberRow(w, 0, sealOf(w, k), forgeSigned(w, w.owner, k)) },
            "seal" to { w, k -> memberRow(w, 0, sealOf(w, k), null) },
            "pending+seal" to { w, k -> memberRow(w, 0, sealOf(w, k), forgeSigned(w, third, k)) },
            "broken+seal" to { w, k -> memberRow(w, 0, sealOf(w, k), Bytes.toB64(crypto.randomBytes(200))) },
            "absent" to { _, _ -> null },
            // A6 final review LOW-G: the seal IS the vouched key K and the v2 grant carries K'.
            "seal(K)+v2(K')" to { w, k -> memberRow(w, 0, sealOf(w, w.vk), forgeSigned(w, w.owner, k)) },
        )
        for ((name, shape) in shapes) {
            for (twoPull in listOf(false, true)) {
                val w = world()
                val kPrime = crypto.randomBytes(32)
                val rows = if (twoPull) listOf(memberRow(w, 0, sealOf(w, kPrime), null), shape(w, kPrime)) else listOf(shape(w, kPrime))
                val (device, engine, server) = vouchedThenServe(w, rows)
                assertVouchHolds(w, kPrime, device, engine, server, ruleTwo = name == "wrap", label = "$name/${if (twoPull) "two-pull" else "single"}")
            }
        }
    }

    /** A6 final review LOW-G: the same table on a WARM session — rows served to the very engine that vouched, with
     *  no restart in between (the held branch of addGrant, not the cold path). */
    @Test
    fun theVouchGateHoldsOnAWarmSessionToo() = runBlocking<Unit> {
        val third = enroll("a7-unpinned-sender")
        val shapes: List<Pair<String, (World, ByteArray) -> WireGrant?>> = listOf(
            "wrap" to { w, k -> memberRow(w, 0, null, null).copy(wrappedVk = wrapOf(w, k)) },
            "v2" to { w, k -> memberRow(w, 0, null, forgeSigned(w, w.owner, k)) },
            "v2+seal" to { w, k -> memberRow(w, 0, sealOf(w, k), forgeSigned(w, w.owner, k)) },
            "seal" to { w, k -> memberRow(w, 0, sealOf(w, k), null) },
            "pending+seal" to { w, k -> memberRow(w, 0, sealOf(w, k), forgeSigned(w, third, k)) },
            "broken+seal" to { w, k -> memberRow(w, 0, sealOf(w, k), Bytes.toB64(crypto.randomBytes(200))) },
            "seal(K)+v2(K')" to { w, k -> memberRow(w, 0, sealOf(w, w.vk), forgeSigned(w, w.owner, k)) },
        )
        for ((name, shape) in shapes) {
            val w = world()
            val kPrime = crypto.randomBytes(32)
            val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
            val device = unlock(w.member)
            val engine = SyncEngine(api(server), device, InMemoryVaultCache())
            engine.sync()
            engine.acceptLegacyVault(w.vaultId)
            engine.accountState.pin(pinOf(w.owner, "Owner"))
            server.selfWraps.clear()
            var rev = 12L
            for (row in listOf(memberRow(w, 0, sealOf(w, kPrime), null), shape(w, kPrime))) {
                server.feed = feed(w, rev, row?.copy(rev = rev))
                engine.sync()
                rev += 3
            }
            // Warm: the vouched key K is still the one held, whatever the rows carried.
            assertEquals(tag(w.vk), device.legacyKeyTag(w.vaultId), "warm/$name: K stays held")
            assertVouchHolds(w, kPrime, device, engine, server, ruleTwo = false, label = "warm/$name")
        }
    }

    /** A6 final review LOW-G: a held LEGACY_SEAL key whose vouch (seeded directly) names ANOTHER key is never promoted,
     *  even by a verified v2 grant carrying the held key itself. Removing the held-branch gate reds this test. */
    @Test
    fun aHeldLegacyKeyWithAMismatchingVouchIsNeverPromoted() {
        val w = world()
        val device = unlock(w.member)
        device.grantPins = { uid -> if (uid == w.owner.userId) GrantPin(Bytes.fromB64(w.owner.reg.identityPub), true) else null }
        val ks = crypto.randomBytes(32)
        device.addGrant(memberRow(w, 9, sealOf(w, ks), null))
        assertEquals(Account.KeySource.LEGACY_SEAL, device.keySource(w.vaultId))
        device.authorizeLegacyKey(w.vaultId, tag(w.vk), frozen = false) // the vouch is for K, the held key is K_s
        device.addGrant(memberRow(w, 12, sealOf(w, ks), forgeSigned(w, w.owner, ks)))
        assertEquals(Account.KeySource.LEGACY_SEAL, device.keySource(w.vaultId), "never promoted to SIGNED_GRANT")
        assertEquals(io.silencelen.andvari.core.crypto.GrantVerdict.VK_MISMATCH, device.grantAnomalies()[w.vaultId])
        assertFalse(device.selfWrapAuthorized(w.vaultId))
        assertFailsWith<VaultKeyNotVerifiedException> { device.buildSignedGrant(w.vaultId, pinOf(w.owner, "Owner")) }
    }

    /** A6 final review LOW-H: rule 2 meeting a mismatching vouch also raises the "vault key mismatch" flag. */
    @Test
    fun ruleTwoAgainstTheVouchAlsoFlagsVkMismatch() = runBlocking<Unit> {
        val w = world()
        val kPrime = crypto.randomBytes(32)
        val (device, engine, _) = vouchedThenServe(w, listOf(memberRow(w, 0, null, null).copy(wrappedVk = wrapOf(w, kPrime))))
        assertTrue(device.vkMismatch(w.vaultId), "vkMismatchVaults carries it")
        assertTrue(engine.notices().any { it.kind == "vk-mismatch" && it.vaultId == w.vaultId })
    }

    // ---- branch A7: per-vault held-key memory (closes R15(g) on a device that held the vault) ----

    /** A vault adopted from a verified v2 grant and self-wrapped; the server then strips the wrap and serves a grant
     *  for K' signed by a pinned contact. Warm: flagged, K kept. After a restart: refused, never adopted. */
    @Test
    fun aV2AdoptedVaultServedWithAnotherKeyIsFlaggedWarmAndRefusedAfterARestart() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val cache = InMemoryVaultCache()
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, cache)
        engine.sync()
        assertNotNull(engine.verifyMemberTyped(served(w.owner, "Owner"), w.owner.account.identityFingerprintShort()))
        server.feed = feed(w, 9, memberRow(w, 9, null, ownerSignedGrant(w)))
        engine.sync()
        assertEquals(Account.KeySource.SIGNED_GRANT, device.keySource(w.vaultId))
        assertEquals(1, server.selfWraps.size)
        val kPrime = crypto.randomBytes(32)
        server.feed = feed(w, 12, memberRow(w, 12, null, forgeSigned(w, w.owner, kPrime)))
        engine.sync()
        assertEquals(tag(w.vk), device.legacyKeyTag(w.vaultId), "warm: K stays")
        assertTrue(device.vkMismatch(w.vaultId), "warm: flagged")
        // Restart over the same cache: the cached row now carries only the v2 grant for K'.
        val again = unlock(w.member)
        val restarted = SyncEngine(api(server), again, cache)
        restarted.hydrate()
        restarted.sync()
        assertFalse(again.legacyKeyTag(w.vaultId) == tag(kPrime), "K' is never adopted")
        assertFalse(again.hasVault(w.vaultId), "the row is refused with no key")
        assertEquals(io.silencelen.andvari.core.crypto.GrantVerdict.VK_MISMATCH, again.grantAnomalies()[w.vaultId])
        assertEquals(1, server.selfWraps.size, "and nothing is wrapped for K'")
    }

    /** A vault held from our own UVK wrap; the server strips it and serves a v1 seal or a v2 grant for K'. */
    @Test
    fun aWrapAdoptedVaultServedWithAnotherKeyIsRefusedAfterARestart() = runBlocking<Unit> {
        for (shape in listOf("seal", "v2")) {
            val w = world()
            val server = FakeServer(feed(w, 5, null))
            val cache = InMemoryVaultCache()
            val device = unlock(w.member)
            val engine = SyncEngine(api(server), device, cache)
            engine.sync()
            engine.accountState.pin(pinOf(w.owner, "Owner"))
            server.feed = feed(w, 9, memberRow(w, 9, null, null).copy(wrappedVk = wrapOf(w, w.vk)))
            engine.sync()
            assertEquals(Account.KeySource.UVK_WRAP, device.keySource(w.vaultId))
            val kPrime = crypto.randomBytes(32)
            val swapped = if (shape == "seal") memberRow(w, 12, sealOf(w, kPrime), null) else memberRow(w, 12, null, forgeSigned(w, w.owner, kPrime))
            server.feed = feed(w, 12, swapped)
            engine.sync()
            assertEquals(tag(w.vk), device.legacyKeyTag(w.vaultId), "$shape warm: K stays")
            assertTrue(device.vkMismatch(w.vaultId), "$shape warm: flagged")
            val again = unlock(w.member)
            val restarted = SyncEngine(api(server), again, cache)
            restarted.hydrate()
            restarted.sync()
            assertFalse(again.hasVault(w.vaultId), "$shape: K' is refused after a restart, never adopted")
            assertTrue(restarted.legacyReviewVaults().none { it.vaultId == w.vaultId }, "$shape: never offered for Accept")
        }
    }

    /** A7 review MEDIUM-1: the memory survives a server-driven removal (only the user's own leave clears it). */
    @Test
    fun theHeldKeyMemorySurvivesAServerDrivenRemoval() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val cache = InMemoryVaultCache()
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, cache)
        engine.sync()
        server.feed = feed(w, 9, memberRow(w, 9, null, null).copy(wrappedVk = wrapOf(w, w.vk)))
        engine.sync()
        assertTrue(cache.clientState(SyncEngine.HELD_KEYS_KEY).orEmpty().contains(w.vaultId))
        server.feed = feed(w, 12, null).copy(removedGrants = listOf(w.vaultId))
        engine.sync()
        assertFalse(device.hasVault(w.vaultId))
        assertTrue(cache.clientState(SyncEngine.HELD_KEYS_KEY).orEmpty().contains(w.vaultId))
        assertTrue(device.heldKeyTagsSnapshot()[w.vaultId] != null)
    }

    /** MEDIUM-B, named: pull 1 holds K_s from a seal (≠ vouched K); pull 2 brings a verified v2 for K_s. */
    @Test
    fun aTwoPullSealThenSameKeyV2NeverPromotesAKeyAgainstTheVouch() = runBlocking<Unit> {
        val w = world()
        val ks = crypto.randomBytes(32)
        val (device, engine, server) = vouchedThenServe(w, listOf(memberRow(w, 0, sealOf(w, ks), null), memberRow(w, 0, sealOf(w, ks), forgeSigned(w, w.owner, ks))))
        assertFalse(device.keySource(w.vaultId) == Account.KeySource.SIGNED_GRANT, "never promoted")
        assertTrue(engine.notices().any { it.kind == "grant-anomaly" && it.reason == "vk_mismatch" })
        assertVouchHolds(w, ks, device, engine, server, ruleTwo = false, label = "MEDIUM-B")
    }

    /** LOW-E: a v1 seal for another key than the vouch is vk_mismatch, never a review card, Accept refuses. */
    @Test
    fun aSealForAnotherKeyThanTheVouchIsAMismatchNotAnAcceptOffer() = runBlocking<Unit> {
        val w = world()
        val kPrime = crypto.randomBytes(32)
        val (device, engine, server) = vouchedThenServe(w, listOf(memberRow(w, 0, sealOf(w, kPrime), null)))
        assertTrue(engine.notices().any { it.kind == "grant-anomaly" && it.reason == "vk_mismatch" })
        assertVouchHolds(w, kPrime, device, engine, server, ruleTwo = false, label = "LOW-E")
    }

    /** LOW-F: another device's self-wrap (rule 2) is used, but flagged when it differs from this device's vouch. */
    @Test
    fun aUvkWrapForAnotherKeyThanTheVouchIsUsedButFlagged() = runBlocking<Unit> {
        val w = world()
        val kPrime = crypto.randomBytes(32)
        val (device, engine, server) = vouchedThenServe(w, listOf(memberRow(w, 0, null, null).copy(wrappedVk = wrapOf(w, kPrime))))
        assertEquals(Account.KeySource.UVK_WRAP, device.keySource(w.vaultId))
        assertTrue(engine.notices().any { it.kind == "grant-anomaly" && it.reason == "vk_mismatch" })
        assertVouchHolds(w, kPrime, device, engine, server, ruleTwo = true, label = "LOW-F")
    }

    // ---- A6 review LOW-2: a present-but-broken v2 field is never an "Accept anyway" ----

    @Test
    fun aGarbageSignedGrantBesideAV1SealIsAnAnomalyNotAReviewCard() = runBlocking<Unit> {
        val w = world()
        val garbage = Bytes.toB64(crypto.sealTo(Bytes.fromB64(w.member.reg.identityPub), "not a frame".encodeToByteArray()))
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), garbage)))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        assertFalse(device.hasVault(w.vaultId), "no v1 fallback")
        assertTrue(engine.legacyReviewVaults().isEmpty())
        assertEquals("bad_frame", engine.notices().single { it.kind == "grant-anomaly" }.reason)
        assertFailsWith<IllegalStateException> { engine.acceptLegacyVault(w.vaultId) }
    }

    @Test
    fun anUndecodableSignedGrantIsAnAnomalyToo() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), "!!not-base64!!")))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        assertFalse(device.hasVault(w.vaultId))
        assertEquals("unopenable", engine.notices().single { it.kind == "grant-anomaly" }.reason)
    }

    /** A held, unvouched legacy vault whose row now carries a v2 grant from an UNPINNED sender is an invitation
     *  (verify to confirm), not a review card and not stuck on neither (web parity). */
    @Test
    fun aHeldLegacyVaultWithAPendingV2GrantIsAnInvitationNotAReviewCard() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        server.feed = feed(w, 12, memberRow(w, 12, v1Seal(w), ownerSignedGrant(w)))
        engine.sync()
        assertTrue(device.isLegacyReadOnly(w.vaultId))
        assertTrue(engine.legacyReviewVaults().isEmpty())
        assertEquals(listOf(w.vaultId), engine.pendingInvitations().map { it.vaultId })
    }

    private fun forgeSigned(w: World, signer: Enrolled, vk: ByteArray): String {
        val sign = crypto.signKeypairFromSeed(seedOf(signer))
        val frame = SignedGrant.buildFrame(
            crypto, sign,
            Statement.VaultGrant(signer.userId, w.member.userId, Bytes.fromB64(w.member.reg.identityPub), w.vaultId, crypto.randomBytes(16), 1_791_590_400_000, vk),
        )
        return Bytes.toB64(crypto.sealTo(Bytes.fromB64(w.member.reg.identityPub), frame))
    }

    // ---- §1.5: owner side ----

    @Test
    fun theOwnerGrantsOnlyToAPinnedMemberSealedToThePinKey() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(
            SyncResponse(5, true, listOf(personalRow(w.owner), WireVault(w.vaultId, "shared", 3, w.metaBlob, 0)),
                listOf(personalGrant(w.owner), WireGrant(w.vaultId, w.owner.userId, "owner", ownerRowWrap(w), 3, null)), emptyList(), emptyList()),
        )
        val ownerDevice = unlock(w.owner)
        val engine = SyncEngine(api(server), ownerDevice, InMemoryVaultCache())
        engine.sync()
        // A6b: the owner's own evidence of ownership (here seeded directly; in the app it is the creation record,
        // a transfer accept, or the password-reauthed "You own <vault>?").
        assertFailsWith<OwnershipNotConfirmedException> { engine.addVaultMember(w.vaultId, w.member.userId, "writer", "member@example.com") }
        engine.accountState.update { AccountState.withOwned(it, w.vaultId, 1) }
        assertFailsWith<MemberNotVerifiedException> { engine.addVaultMember(w.vaultId, w.member.userId, "writer", "member@example.com") }
        assertTrue(server.adds.isEmpty())

        engine.accountState.pin(pinOf(w.member, "Member"))
        assertEquals(SyncEngine.MemberPinState.PINNED, engine.memberPinState(served(w.member, "Member")), "no fingerprint step")
        // A served key that differs from the pin is refused outright.
        val substituted = UserLookupResponse(w.member.userId, "Member", Bytes.toB64(crypto.randomBytes(32)))
        assertEquals(SyncEngine.MemberPinState.KEY_CHANGED, engine.memberPinState(substituted))

        engine.addVaultMember(w.vaultId, w.member.userId, "writer", "member@example.com")
        val (vaultId, add) = server.adds.single()
        assertEquals(w.vaultId, vaultId)
        val me = crypto.boxKeypairFromSeed(seedOf(w.member))
        // The v2 grant is addressed to the PIN key and verifies under the owner's pinned identity.
        val opened = SignedGrant.open(
            crypto, w.member.userId, me.publicKey, me.privateKey, w.vaultId, Bytes.fromB64(add.signedGrant!!),
            pinFor = { if (it == w.owner.userId) GrantPin(Bytes.fromB64(w.owner.reg.identityPub), true) else null },
            heldVk = null,
        )
        assertContentEquals(w.vk, (opened as GrantOutcome.Adopted).vk)
        // In-window dual-send: the v1 seal for older clients, also sealed to the pin key.
        assertContentEquals(w.vk, SharedGrant.open(crypto, me.publicKey, me.privateKey, w.vaultId, Bytes.fromB64(add.sealedVk)))
    }

    @Test
    fun theOwnerReissuesLegacyGrantsOnlyOnConfirmationAndListsTheRest() = runBlocking<Unit> {
        val w = world()
        val unpinned = enroll("a6-unpinned")
        val server = FakeServer(
            SyncResponse(5, true, listOf(personalRow(w.owner), WireVault(w.vaultId, "shared", 3, w.metaBlob, 0)),
                listOf(personalGrant(w.owner), WireGrant(w.vaultId, w.owner.userId, "owner", ownerRowWrap(w), 3, null)), emptyList(), emptyList()),
        )
        server.members[w.vaultId] = listOf(
            VaultMemberSummary(w.owner.userId, "o@example.com", "Owner", "owner", w.owner.reg.identityPub, 0),
            VaultMemberSummary(w.member.userId, "m@example.com", "Member", "writer", w.member.reg.identityPub, 0, legacyGrant = true),
            VaultMemberSummary(unpinned.userId, "u@example.com", "Unpinned", "reader", unpinned.reg.identityPub, 0, legacyGrant = true),
        )
        val engine = SyncEngine(api(server), unlock(w.owner), InMemoryVaultCache())
        engine.sync()
        engine.accountState.update { AccountState.withOwned(it, w.vaultId, 1) } // A6b: ownership evidence (see above)
        engine.accountState.pin(pinOf(w.member, "Member"))
        engine.sync()
        assertTrue(server.reissues.isEmpty(), "A6b: sync() never re-issues")
        val rows = engine.loadLegacyGrants(w.vaultId)
        assertEquals(listOf(w.member.userId, unpinned.userId).sorted(), rows.map { it.userId }.sorted())
        assertTrue(server.reissues.isEmpty(), "listing signs nothing for an unrecorded pair")
        assertFailsWith<MemberNotVerifiedException> { engine.confirmReissue(rows.single { it.userId == unpinned.userId }) }
        engine.confirmReissue(rows.single { it.userId == w.member.userId })
        val (vaultId, userId, signed) = server.reissues.single()
        assertEquals(w.vaultId to w.member.userId, vaultId to userId)
        val me = crypto.boxKeypairFromSeed(seedOf(w.member))
        val opened = SignedGrant.open(
            crypto, w.member.userId, me.publicKey, me.privateKey, w.vaultId, Bytes.fromB64(signed),
            pinFor = { if (it == w.owner.userId) GrantPin(Bytes.fromB64(w.owner.reg.identityPub), true) else null },
            heldVk = w.vk,
        )
        assertTrue(opened is GrantOutcome.Adopted, "the SAME VK, re-issued")
        val legacy = engine.legacyGrantRows(w.vaultId)
        assertEquals(listOf(unpinned.userId), legacy.map { it.userId }, "only the unpinned member still needs securing")
        assertEquals(SyncEngine.MemberPinState.NEEDS_VERIFICATION, legacy.single().pinState)
        engine.sync()
        assertEquals(1, server.reissues.size, "sync() adds nothing")
    }

    private fun ownerRowWrap(w: World): String = Envelope.sealB64(crypto, ownerUvk(w.owner), w.vk, Ad.vk(w.vaultId, w.owner.userId))

    private fun seedOf(e: Enrolled): ByteArray = Envelope.openB64(crypto, ownerUvk(e), e.keys.encryptedIdentitySeed, Ad.idkey(e.userId))

    // ---- A7 review MEDIUM-1: a server-driven drop never resets the held-key memory or the vouch ----

    /** A member holding K from a verified v2 grant (pinned owner), self-wrapped. */
    private suspend fun adoptedV2(w: World): Triple<Account, SyncEngine, FakeServer> {
        val server = FakeServer(feed(w, 5, null))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        engine.accountState.pin(pinOf(w.owner, "Owner"))
        server.feed = feed(w, 9, memberRow(w, 9, null, forgeSigned(w, w.owner, w.vk)))
        engine.sync()
        assertEquals(Account.KeySource.SIGNED_GRANT, device.keySource(w.vaultId))
        return Triple(device, engine, server)
    }

    private fun removalFeed(w: World, rev: Long, info: RemovedGrantInfo?) =
        feed(w, rev, null).copy(full = false, removedGrants = listOf(w.vaultId), removedGrantsInfo = listOfNotNull(info))

    private fun validRemoval(w: World, nonce: String = LifecycleProof.newNonce(crypto)): RemovedGrantInfo {
        val at = System.currentTimeMillis()
        val key = w.owner.account.lifecycleKeyFor(w.vaultId)
        return RemovedGrantInfo(w.vaultId, "removed", removeProof = LifecycleProof.removeV2(crypto, key, w.vaultId, w.member.userId, nonce, at), removeNonce = nonce, proofV = 2, issuedAt = at)
    }

    /** After the drop, the server re-adds the vault under K' (a pinned contact signs it): never adopted. */
    private suspend fun assertReAddWithKPrimeRefused(w: World, device: Account, engine: SyncEngine, server: FakeServer, rev: Long, label: String) {
        val kPrime = crypto.randomBytes(32)
        server.selfWraps.clear()
        server.feed = feed(w, rev, memberRow(w, rev, sealOf(w, kPrime), forgeSigned(w, w.owner, kPrime)))
        engine.sync()
        assertFalse(device.hasVault(w.vaultId) && device.legacyKeyTag(w.vaultId) == tag(kPrime), "$label: K' never adopted")
        assertEquals(io.silencelen.andvari.core.crypto.GrantVerdict.VK_MISMATCH, device.grantAnomalies()[w.vaultId], "$label: vk_mismatch")
        assertTrue(server.selfWraps.isEmpty(), "$label: never self-wrapped")
        assertTrue(runCatching { device.buildOwnerWrap(w.vaultId) }.isFailure, "$label: never owner-wrapped")
    }

    @Test
    fun anAnomalyRemovalThenAReAddWithAnotherKeyIsRefused() = runBlocking<Unit> {
        val w = world()
        val (device, engine, server) = adoptedV2(w)
        server.feed = removalFeed(w, 12, null) // bare revocation: anomaly
        engine.sync()
        assertEquals("anomaly", engine.notices().last { it.vaultId == w.vaultId }.kind)
        assertReAddWithKPrimeRefused(w, device, engine, server, 15, "anomaly")
    }

    @Test
    fun aReplayDeniedRemovalThenAReAddWithAnotherKeyIsRefused() = runBlocking<Unit> {
        val w = world()
        val (device, engine, server) = adoptedV2(w)
        val info = validRemoval(w)
        server.feed = removalFeed(w, 12, info)
        engine.sync()
        server.feed = feed(w, 15, memberRow(w, 15, null, forgeSigned(w, w.owner, w.vk))) // re-add, same K
        engine.sync()
        assertTrue(device.hasVault(w.vaultId))
        server.feed = removalFeed(w, 18, info) // the same proof again
        engine.sync()
        assertEquals("replay-denied", engine.notices().last { it.vaultId == w.vaultId }.kind)
        assertReAddWithKPrimeRefused(w, device, engine, server, 21, "replay-denied")
    }

    @Test
    fun aResyncDropThenAReAddWithAnotherKeyIsRefused() = runBlocking<Unit> {
        val w = world()
        val (device, engine, server) = adoptedV2(w)
        server.feed = feed(w, 12, null) // the snapshot no longer carries the vault
        server.feed = server.feed.copy(removedGrants = listOf(w.vaultId))
        server.resyncOnce = true
        engine.sync()
        assertFalse(device.hasVault(w.vaultId), "the silent resync drop ran")
        assertReAddWithKPrimeRefused(w, device, engine, server, 15, "resync")
    }

    @Test
    fun aValidRemovalThenAReAddWithTheSameKeyWorksNormally() = runBlocking<Unit> {
        val w = world()
        val (device, engine, server) = adoptedV2(w)
        server.feed = removalFeed(w, 12, validRemoval(w))
        engine.sync()
        assertEquals("removed", engine.notices().last { it.vaultId == w.vaultId }.kind)
        server.selfWraps.clear()
        server.feed = feed(w, 15, memberRow(w, 15, null, forgeSigned(w, w.owner, w.vk)))
        engine.sync()
        assertEquals(Account.KeySource.SIGNED_GRANT, device.keySource(w.vaultId))
        assertTrue(device.selfWrapAuthorized(w.vaultId), "self-wrap allowed again")
        assertTrue(device.grantAnomalies()[w.vaultId] == null)
    }

    @Test
    fun aSelfInitiatedLeaveThenAReAddWithANewKeyIsAdopted() = runBlocking<Unit> {
        val w = world()
        val (device, engine, server) = adoptedV2(w)
        server.feed = removalFeed(w, 12, RemovedGrantInfo(w.vaultId, "left"))
        engine.leaveSharedVault(w.vaultId)
        assertEquals(1, server.leaves.size)
        assertFalse(device.hasVault(w.vaultId))
        val k2 = crypto.randomBytes(32)
        server.feed = feed(w, 15, memberRow(w, 15, null, forgeSigned(w, w.owner, k2)))
        engine.sync()
        assertEquals(tag(k2), device.legacyKeyTag(w.vaultId), "the user's own leave cleared the memory: the new key is adopted")
        assertEquals(Account.KeySource.SIGNED_GRANT, device.keySource(w.vaultId))
    }

    // ---- A7 review LOW-1: only trusted sources record a held-key tag ----

    @Test
    fun aServerChosenFirstSealDoesNotBlockTheGenuineKey() = runBlocking<Unit> {
        val w = world()
        val ks = crypto.randomBytes(32)
        val server = FakeServer(feed(w, 9, memberRow(w, 9, sealOf(w, ks), null)))
        val cache = InMemoryVaultCache()
        val first = SyncEngine(api(server), unlock(w.member), cache)
        first.sync()
        first.accountState.pin(pinOf(w.owner, "Owner"))
        assertFalse(cache.clientState(SyncEngine.HELD_KEYS_KEY).orEmpty().contains(w.vaultId), "an unvouched seal records no tag")
        // The genuine v2 grant for K replaces the row; the next cold start adopts K.
        server.feed = feed(w, 12, memberRow(w, 12, null, forgeSigned(w, w.owner, w.vk)))
        first.sync()
        val again = unlock(w.member)
        val restarted = SyncEngine(api(server), again, cache)
        restarted.hydrate()
        restarted.sync()
        assertEquals(tag(w.vk), again.legacyKeyTag(w.vaultId), "K is adopted")
        assertEquals(Account.KeySource.SIGNED_GRANT, again.keySource(w.vaultId))
    }

    @Test
    fun aVouchRecordsTheHeldKeyTag() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 9, memberRow(w, 9, v1Seal(w), null)))
        val cache = InMemoryVaultCache()
        val engine = SyncEngine(api(server), unlock(w.member), cache)
        engine.sync()
        assertFalse(cache.clientState(SyncEngine.HELD_KEYS_KEY).orEmpty().contains(w.vaultId))
        engine.acceptLegacyVault(w.vaultId)
        engine.sync()
        // A10: the held-key memory is a JSON record (no delimiter-joined lines).
        assertEquals(listOf(TrustRecords.HeldKey(w.vaultId, tag(w.vk))), TrustRecords.decodeHeldKeys(cache.clientState(SyncEngine.HELD_KEYS_KEY)).rows)
    }

    // ---- security review 2026-10, plugin scan (branch A10): wire-boundary ids + structured trust records ----

    /** A second shared vault of the owner's, sealed v1 to the member with key [vk]. */
    private fun targetVault(w: World, name: String): Triple<String, String, ByteArray> {
        val shared = w.owner.account.buildCreateSharedVault(name)
        val vk = Envelope.openB64(crypto, ownerUvk(w.owner), shared.request.wrappedVk, Ad.vk(shared.vaultId, w.owner.userId))
        return Triple(shared.vaultId, shared.request.metaBlob, vk)
    }

    @Test
    fun aLegacyVouchRecordWithAForgedLineIsIgnoredOnMigration_andTheGenuineVouchSurvives() = runBlocking<Unit> {
        val w = world()
        val (targetId, targetMeta, targetVk) = targetVault(w, "Target")
        val decoy = "44444444-4444-4444-8444-444444444444"
        val cache = InMemoryVaultCache()
        // A pre-A10 line record: the human's genuine Accept of "Household", and the line the scan's decoy wrote (its
        // vaultId carried a line break and a forged `TARGET|sha256(Z)|confirmed` for the vault the server wants).
        cache.setClientState(
            SyncEngine.LEGACY_AUTHORIZED_KEY,
            listOf("${w.vaultId}|${tag(w.vk)}|confirmed", "$decoy\n$targetId|${tag(targetVk)}|confirmed|${"c".repeat(64)}|confirmed").joinToString("\n"),
        )
        cache.setClientState(SyncEngine.HELD_KEYS_KEY, "${w.vaultId}|${tag(w.vk)}\n$decoy\n$targetId|${tag(targetVk)}|x")
        val server = FakeServer(
            SyncResponse(
                rev = 9, full = true,
                vaults = listOf(personalRow(w.member), WireVault(w.vaultId, "shared", 3, w.metaBlob, 0), WireVault(targetId, "shared", 3, targetMeta, 0)),
                grants = listOf(personalGrant(w.member), memberRow(w, 9, v1Seal(w), null), WireGrant(targetId, w.member.userId, "writer", "", 9, Bytes.toB64(SharedGrant.seal(crypto, Bytes.fromB64(w.member.reg.identityPub), targetId, targetVk)), null)),
                items = emptyList(), removedGrants = emptyList(),
            ),
        )
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, cache)
        // Migration happened at construction: JSON, only the well-formed line.
        val migrated = cache.clientState(SyncEngine.LEGACY_AUTHORIZED_KEY)!!
        assertTrue(migrated.startsWith("["), migrated)
        assertEquals(listOf(TrustRecords.Vouch(w.vaultId, tag(w.vk), "confirmed")), TrustRecords.decodeVouches(migrated).rows)
        assertEquals(listOf(TrustRecords.HeldKey(w.vaultId, tag(w.vk))), TrustRecords.decodeHeldKeys(cache.clientState(SyncEngine.HELD_KEYS_KEY)).rows)
        engine.sync()
        assertFalse(device.isLegacyReadOnly(w.vaultId), "the genuine vouch survives the migration")
        assertTrue(device.isLegacyReadOnly(targetId), "the forged line vouched for nothing")
        assertEquals(listOf(w.vaultId), server.selfWraps.map { it.first }, "no self-wrap for the vault the server chose a key for")
        assertEquals(listOf(targetId), engine.legacyReviewVaults().map { it.vaultId })
    }

    @Test
    fun aDecoyVaultWhoseIdCarriesALineBreakIsRefusedAtTheWire_andAcceptWritesNothingForOtherVaults() = runBlocking<Unit> {
        val w = world()
        val (targetId, targetMeta, targetVk) = targetVault(w, "Target")
        // The decoy: a vault id that is a UUID, a line break, then a forged vouch line for TARGET. Its grant is v1-sealed
        // to the member under a key the server knows, with the SAME string as the sealed payload's vaultId.
        val decoyKey = crypto.randomBytes(32)
        val decoyId = "44444444-4444-4444-8444-444444444444\n$targetId|${tag(targetVk)}|confirmed"
        val server = FakeServer(
            SyncResponse(
                rev = 9, full = true,
                vaults = listOf(personalRow(w.member), WireVault(decoyId, "shared", 3, w.metaBlob, 0), WireVault(targetId, "shared", 3, targetMeta, 0)),
                grants = listOf(
                    personalGrant(w.member),
                    WireGrant(decoyId, w.member.userId, "writer", "", 9, Bytes.toB64(SharedGrant.seal(crypto, Bytes.fromB64(w.member.reg.identityPub), decoyId, decoyKey)), null),
                    WireGrant(targetId, w.member.userId, "writer", "", 9, Bytes.toB64(SharedGrant.seal(crypto, Bytes.fromB64(w.member.reg.identityPub), targetId, targetVk)), null),
                ),
                items = emptyList(), removedGrants = emptyList(),
            ),
        )
        val cache = InMemoryVaultCache()
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, cache)
        engine.sync()
        assertFalse(device.hasVault(decoyId), "the decoy row never reached the account")
        assertTrue(engine.vaultInfos().none { it.vaultId == decoyId })
        assertEquals(listOf(targetId), engine.legacyReviewVaults().map { it.vaultId }, "only the genuine legacy vault is offered for review")
        val notice = engine.notices().single { it.kind == "bad-id" }
        assertEquals("sync", notice.reason)
        // The human accepts TARGET (the only card): the record holds exactly that vouch, as JSON, and nothing else.
        engine.acceptLegacyVault(targetId)
        assertEquals(listOf(TrustRecords.Vouch(targetId, tag(targetVk), "confirmed")), TrustRecords.decodeVouches(cache.clientState(SyncEngine.LEGACY_AUTHORIZED_KEY)).rows)
        assertEquals(listOf(targetId), server.selfWraps.map { it.first })
    }

    // ---- security review 2026-10, branch A11 (q56): the "added" notice is decided by key provenance, not the label ----

    @Test
    fun a11_aVerifiedGrantOnARowLabelledOwner_stillAnnouncesItself() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        assertNotNull(engine.verifyMemberTyped(served(w.owner, "Owner"), w.owner.account.identityFingerprintShort()))
        server.feed = feed(w, 9, memberRow(w, 9, v1Seal(w), ownerSignedGrant(w)).copy(role = "owner"))
        engine.sync()
        assertEquals(Account.KeySource.SIGNED_GRANT, device.keySource(w.vaultId))
        assertEquals(listOf("added"), engine.notices().filter { it.vaultId == w.vaultId }.map { it.kind })
    }

    @Test
    fun a11_thisAccountsOwnVaultOnItsSecondDevice_staysQuiet_whateverTheLabel() = runBlocking<Unit> {
        for (role in listOf("owner", "writer")) {
            val owner = enroll("a11-owner-$role")
            val shared = owner.account.buildCreateSharedVault("Mine")
            fun feedOf(rev: Long, withShared: Boolean) = SyncResponse(
                rev = rev, full = true,
                vaults = listOfNotNull(personalRow(owner), if (withShared) WireVault(shared.vaultId, "shared", 3, shared.request.metaBlob, 0) else null),
                grants = listOfNotNull(personalGrant(owner), if (withShared) WireGrant(shared.vaultId, owner.userId, role, shared.request.wrappedVk, rev, null) else null),
                items = emptyList(), removedGrants = emptyList(),
            )
            val server = FakeServer(feedOf(5, false))
            val device = unlock(owner)
            val engine = SyncEngine(api(server), device, InMemoryVaultCache())
            engine.sync()
            server.feed = feedOf(9, true)
            engine.sync()
            assertTrue(device.hasVault(shared.vaultId), role)
            assertEquals(emptyList(), engine.notices().filter { it.vaultId == shared.vaultId && it.kind == "added" }, role)
        }
    }
}

