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
    private fun pinOf(e: Enrolled, label: String) = Contact(e.userId, e.reg.identityPub, label, 1_000, Contact.METHOD_TYPED)
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
        assertTrue(again.isLegacyReadOnly(w.vaultId), "the vouch does not carry over to a key the server swapped in")
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

    @Test
    fun aPinAddedElsewhereAfterThisDeviceEstablishedItsMarkIsCurrent() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(feed(w, 5, null))
        val bAccount = unlock(w.member)
        val b = SyncEngine(api(server), bAccount, InMemoryVaultCache())
        b.sync()
        b.accountState.pin(Contact("44444444-4444-4444-8444-444444444444", Bytes.toB64(crypto.randomBytes(32)), "Someone", 1, Contact.METHOD_TYPED))
        // Another device of this account pins the owner later.
        val a = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        a.sync()
        a.accountState.pin(pinOf(w.owner, "Owner"))
        b.sync()
        assertNotNull(b.accountState.currentPin(w.owner.userId))
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
        assertFailsWith<MemberNotVerifiedException> { engine.addVaultMember(w.vaultId, w.member.userId, "writer") }
        assertTrue(server.adds.isEmpty())

        engine.accountState.pin(pinOf(w.member, "Member"))
        assertEquals(SyncEngine.MemberPinState.PINNED, engine.memberPinState(served(w.member, "Member")), "no fingerprint step")
        // A served key that differs from the pin is refused outright.
        val substituted = UserLookupResponse(w.member.userId, "Member", Bytes.toB64(crypto.randomBytes(32)))
        assertEquals(SyncEngine.MemberPinState.KEY_CHANGED, engine.memberPinState(substituted))

        engine.addVaultMember(w.vaultId, w.member.userId, "writer")
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
    fun theOwnerReissuesLegacyGrantsToPinnedMembersAndListsTheRest() = runBlocking<Unit> {
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
        engine.accountState.pin(pinOf(w.member, "Member"))
        engine.sync()
        val (vaultId, userId, signed) = server.reissues.single()
        assertEquals(w.vaultId to w.member.userId, vaultId to userId)
        val me = crypto.boxKeypairFromSeed(seedOf(w.member))
        val opened = SignedGrant.open(
            crypto, w.member.userId, me.publicKey, me.privateKey, w.vaultId, Bytes.fromB64(signed),
            pinFor = { if (it == w.owner.userId) GrantPin(Bytes.fromB64(w.owner.reg.identityPub), true) else null },
            heldVk = w.vk,
        )
        assertTrue(opened is GrantOutcome.Adopted, "the SAME VK, re-issued")
        val legacy = engine.legacyGrantMembers(w.vaultId)
        assertEquals(listOf(unpinned.userId), legacy.map { it.userId }, "only the unpinned member still needs securing")
        engine.sync()
        assertEquals(1, server.reissues.size, "once per session")
    }

    private fun ownerRowWrap(w: World): String = Envelope.sealB64(crypto, ownerUvk(w.owner), w.vk, Ad.vk(w.vaultId, w.owner.userId))

    private fun seedOf(e: Enrolled): ByteArray = Envelope.openB64(crypto, ownerUvk(e), e.keys.encryptedIdentitySeed, Ad.idkey(e.userId))
}
