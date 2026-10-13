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
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.AccountStateResponse
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.TransferRecord
import io.silencelen.andvari.core.crypto.GrantOutcome
import io.silencelen.andvari.core.crypto.GrantPin
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.crypto.SignedGrant
import io.silencelen.andvari.core.model.GrantReissueRequest
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TransferOfferRequest
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Grant re-issue authority (security review 2026-10, root cause A, branch A6b; closes the API-review HIGH
 * "automatic legacy re-issue gives a vault key to a member the owner never granted it to").
 *
 * The invariant: this account's client never signs or seals a vault key to a user unless (a) a human on this
 * device confirmed that (vault, user) pair now, or (b) the pair is in this account's UVK-authenticated
 * issued-grants record for the same identity key; and it never takes an owner-only signing action on a vault on
 * the strength of the server's `role=owner` label alone.
 */
class ReissueAuthorityTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys) {
        val userId get() = reg.userId
    }

    private fun enroll(tag: String, params: KdfParams = kdf): Enrolled {
        val email = "$tag-${crypto.randomBytes(4).joinToString("") { (it.toInt() and 0xff).toString(16) }}@example.com"
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, params, recovery.publicKey, fp, "dev", crypto)
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
    private class FakeServer(var feed: SyncResponse, val keys: AccountKeys? = null, val selfUserId: String? = null) {
        val adds = mutableListOf<Pair<String, VaultMemberAdd>>()
        val reissues = mutableListOf<Triple<String, String, String>>() // vaultId, userId, signedGrant
        val offers = mutableListOf<Pair<String, TransferOfferRequest>>()
        val removals = mutableListOf<Pair<String, String>>()
        val members = HashMap<String, List<VaultMemberSummary>>()
        var accountState: String? = null
        var accountSeq: Long = 0
    }

    private fun body(req: io.ktor.client.request.HttpRequestData): String = when (val b = req.body) {
        is TextContent -> b.text
        is OutgoingContent.ByteArrayContent -> b.bytes().decodeToString()
        else -> ""
    }

    private fun api(server: FakeServer): AndvariApi {
        val engine = MockEngine { req ->
            val path = req.url.encodedPath
            val ct = headersOf(HttpHeaders.ContentType, "application/json")
            val members = Regex("^/api/v1/vaults/([^/]+)/members$").find(path)
            val member = Regex("^/api/v1/vaults/([^/]+)/members/([^/]+)$").find(path)
            val reissue = Regex("^/api/v1/vaults/([^/]+)/members/([^/]+)/grant$").find(path)
            val transfer = Regex("^/api/v1/vaults/([^/]+)/transfer$").find(path)
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
                path == "/api/v1/account/keys" && server.keys != null ->
                    respond(json.encodeToString(AccountKeys.serializer(), server.keys), HttpStatusCode.OK, ct)
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
                path == "/api/v1/vaults" && req.method == HttpMethod.Post -> {
                    // The created vault joins the creator's feed, with the creator's own UVK-wrapped owner row.
                    val cv = json.decodeFromString(CreateVaultRequest.serializer(), body(req))
                    val rev = server.feed.rev + 1
                    server.feed = server.feed.copy(
                        rev = rev,
                        vaults = server.feed.vaults + WireVault(cv.vaultId, "shared", rev, cv.metaBlob, 0),
                        grants = server.feed.grants + WireGrant(cv.vaultId, server.selfUserId!!, "owner", cv.wrappedVk, rev, null),
                    )
                    respond("""{"rev":$rev}""", HttpStatusCode.Created, ct)
                }
                members != null && req.method == HttpMethod.Get ->
                    respond(json.encodeToString(ListSerializer(VaultMemberSummary.serializer()), server.members[members.groupValues[1]].orEmpty()), HttpStatusCode.OK, ct)
                members != null && req.method == HttpMethod.Post -> {
                    server.adds.add(members.groupValues[1] to json.decodeFromString(VaultMemberAdd.serializer(), body(req)))
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.Created, ct)
                }
                member != null && req.method == HttpMethod.Delete -> {
                    server.removals.add(member.groupValues[1] to member.groupValues[2])
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                }
                reissue != null && req.method == HttpMethod.Put -> {
                    val r = json.decodeFromString(GrantReissueRequest.serializer(), body(req))
                    server.reissues.add(Triple(reissue.groupValues[1], reissue.groupValues[2], r.signedGrant))
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                }
                transfer != null && req.method == HttpMethod.Post -> {
                    server.offers.add(transfer.groupValues[1] to json.decodeFromString(TransferOfferRequest.serializer(), body(req)))
                    respond("""{"rev":${server.feed.rev + 1},"expiresAt":0}""", HttpStatusCode.OK, ct)
                }
                req.method == HttpMethod.Put && path.endsWith("/grant/self-wrap") ->
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
    }

    private fun pinOf(e: Enrolled, label: String) = Contact(e.userId, e.reg.identityPub, label, 1_000, Contact.METHOD_TYPED)
    private fun personalRow(e: Enrolled) = WireVault(e.reg.personalVault.vaultId, "personal", 2, e.reg.personalVault.metaBlob, 0)
    private fun personalGrant(e: Enrolled) = WireGrant(e.reg.personalVault.vaultId, e.userId, "owner", e.reg.personalVault.wrappedVk, 2, null)
    private fun summary(e: Enrolled, name: String, role: String, legacy: Boolean = false) =
        VaultMemberSummary(e.userId, "$name@example.com", name, role, e.reg.identityPub, 0, legacyGrant = legacy.takeIf { it })

    private fun uvkOf(e: Enrolled): ByteArray {
        val mk = Keys.masterKey(crypto, password, Bytes.fromB64(e.keys.kdfSalt), e.keys.kdfParams)
        return Envelope.openB64(crypto, Keys.wrapKey(crypto, mk), e.keys.wrappedUvk, Ad.uvk(e.userId))
    }

    /** An owner, a member, a shared vault "Household" the owner created ON ANOTHER DEVICE before this branch. */
    private class World(val owner: Enrolled, val member: Enrolled, val vaultId: String, val metaBlob: String, val ownerWrap: String)

    private fun world(ownerParams: KdfParams = kdf, memberParams: KdfParams = kdf): World {
        val owner = enroll("a6b-owner", ownerParams)
        val member = enroll("a6b-member", memberParams)
        val shared = owner.account.buildCreateSharedVault("Household")
        return World(owner, member, shared.vaultId, shared.request.metaBlob, shared.request.wrappedVk)
    }

    /** The owner's own feed: personal vault + the shared vault, owner row wrapped under the owner's UVK. */
    private fun ownerFeed(w: World, rev: Long = 5) = SyncResponse(
        rev, true, listOf(personalRow(w.owner), WireVault(w.vaultId, "shared", 3, w.metaBlob, 0)),
        listOf(personalGrant(w.owner), WireGrant(w.vaultId, w.owner.userId, "owner", w.ownerWrap, 3, null)), emptyList(), emptyList(),
    )

    // ---- the HIGH: no automatic re-issue ----

    @Test
    fun aServerListedPinnedMemberOnAHeldVaultIsNotReissuedWithoutConfirmation() = runBlocking<Unit> {
        val w = world()
        val server = FakeServer(ownerFeed(w))
        server.members[w.vaultId] = listOf(summary(w.owner, "Owner", "owner"), summary(w.member, "Member", "writer", legacy = true))
        val engine = SyncEngine(api(server), unlock(w.owner), InMemoryVaultCache())
        engine.sync()
        engine.accountState.pin(pinOf(w.member, "Member"))
        engine.sync()
        engine.sync()
        assertTrue(server.reissues.isEmpty(), "sync() never signs a grant: the member list and the role are the server's")
    }

    @Test
    fun aServerOwnerRelabelOnAVaultThisAccountNeverCreatedOrAcceptedUnlocksNoSigningAction() = runBlocking<Unit> {
        // The member holds the vault through a verified grant from its pinned owner. The server relabels the
        // member's own row `owner` and lists a colluding household member (pinned here) as a legacy member.
        val w = world()
        val colluder = enroll("a6b-colluder")
        val server = FakeServer(
            SyncResponse(5, true, listOf(personalRow(w.member)), listOf(personalGrant(w.member)), emptyList(), emptyList()),
        )
        val device = unlock(w.member)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache())
        engine.sync()
        engine.accountState.pin(pinOf(w.owner, "Owner"))
        engine.accountState.pin(pinOf(colluder, "Colluder"))
        val signed = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"))
        server.feed = SyncResponse(
            9, true, listOf(personalRow(w.member), WireVault(w.vaultId, "shared", 9, w.metaBlob, 0)),
            listOf(personalGrant(w.member), WireGrant(w.vaultId, w.member.userId, "owner", "", 9, null, signed)), emptyList(), emptyList(),
        )
        server.members[w.vaultId] = listOf(summary(w.member, "Member", "owner"), summary(colluder, "Colluder", "writer", legacy = true))
        engine.sync()
        assertTrue(device.hasVault(w.vaultId))
        assertEquals("owner", device.serverRoleFor(w.vaultId), "the label is still shown as the server reports it")
        engine.sync()
        assertTrue(server.reissues.isEmpty(), "no automatic re-issue on a relabelled vault")
        assertFalse(engine.ownsVault(w.vaultId), "the label is not evidence")
        assertTrue(engine.ownershipNeedsConfirmation(w.vaultId), "the owner UI asks 'You own <vault>?' first")
        assertFailsWith<OwnershipNotConfirmedException>("add member refused") { engine.addVaultMember(w.vaultId, colluder.userId, "writer") }
        assertFailsWith<OwnershipNotConfirmedException>("transfer offer refused") { engine.offerTransfer(w.vaultId, colluder.userId) }
        assertFailsWith<OwnershipNotConfirmedException>("silent re-issue refused") { engine.reissueGrant(w.vaultId, colluder.userId) }
        // The list may SHOW the row (the server listed it), but its confirmation refuses without ownership evidence.
        val row = engine.loadLegacyGrants(w.vaultId).single()
        assertFalse(row.ownershipConfirmed)
        assertFailsWith<OwnershipNotConfirmedException>("confirmed re-issue refused") { engine.confirmReissue(row) }
        // Nor can the member claim it: its key came from a grant, not from its own UVK wrap.
        assertFailsWith<VaultKeyNotVerifiedException> { engine.describeOwnership(w.vaultId) }
        assertTrue(server.adds.isEmpty() && server.offers.isEmpty() && server.reissues.isEmpty(), "nothing was signed or sealed")
    }

    // ---- rule (a): the owner confirms the (vault, member) pair ----

    /** The owner's device, with a vault it CREATED through the engine (its own evidence of ownership). */
    private suspend fun ownerWithCreatedVault(owner: Enrolled, deviceState: DeviceState? = null, cache: VaultCache = InMemoryVaultCache()):
        Triple<SyncEngine, FakeServer, String> {
        val server = FakeServer(
            SyncResponse(5, true, listOf(personalRow(owner)), listOf(personalGrant(owner)), emptyList(), emptyList()),
            selfUserId = owner.userId,
        )
        val engine = SyncEngine(api(server), unlock(owner), cache, deviceState = deviceState)
        engine.sync()
        val vaultId = engine.createSharedVault("Family")
        assertTrue(engine.ownsVault(vaultId), "creating the vault records ownership")
        return Triple(engine, server, vaultId)
    }

    private fun seedOf(e: Enrolled): ByteArray = Envelope.openB64(crypto, uvkOf(e), e.keys.encryptedIdentitySeed, Ad.idkey(e.userId))

    private fun opensForMember(member: Enrolled, owner: Enrolled, vaultId: String, signed: String): ByteArray {
        val me = crypto.boxKeypairFromSeed(seedOf(member))
        val opened = SignedGrant.open(
            crypto, member.userId, me.publicKey, me.privateKey, vaultId, Bytes.fromB64(signed),
            pinFor = { if (it == owner.userId) GrantPin(Bytes.fromB64(owner.reg.identityPub), true) else null },
            heldVk = null,
        )
        return (opened as GrantOutcome.Adopted).vk
    }

    @Test
    fun aConfirmedReissueWorks() = runBlocking<Unit> {
        val owner = enroll("a6b-owner")
        val member = enroll("a6b-member")
        val (engine, server, vaultId) = ownerWithCreatedVault(owner)
        server.members[vaultId] = listOf(summary(owner, "Owner", "owner"), summary(member, "Member (server)", "writer", legacy = true))
        engine.accountState.pin(pinOf(member, "Member"))
        engine.sync()
        assertTrue(server.reissues.isEmpty())

        val row = engine.loadLegacyGrants(vaultId).single()
        assertEquals("Family", row.vaultName, "the row names the vault")
        assertEquals("Member", row.verifiedLabel, "and the member by the label this device verified")
        assertEquals("Member (server)", row.displayName)
        assertTrue(row.ownershipConfirmed)
        assertTrue(server.reissues.isEmpty(), "loading the list signs nothing for an unrecorded pair")
        // Only the row this engine offered is accepted: a look-alike built elsewhere is refused.
        assertFailsWith<IllegalStateException> { engine.confirmReissue(row.copy()) }
        assertTrue(server.reissues.isEmpty())

        engine.confirmReissue(row)
        val (v, u, signed) = server.reissues.single()
        assertEquals(vaultId to member.userId, v to u)
        assertEquals(32, opensForMember(member, owner, vaultId, signed).size, "a verifiable v2 grant from the owner")
        assertNotNull(engine.accountState.issued(vaultId, member.userId), "the confirmed pair is now recorded")
        assertTrue(engine.legacyGrantRows(vaultId).isEmpty())
        assertFailsWith<IllegalStateException>("a row is confirmed once") { engine.confirmReissue(row) }
        assertEquals(1, server.reissues.size)
        engine.sync()
        assertEquals(1, server.reissues.size, "sync() adds nothing")
    }

    // ---- rule (b): the issued-grants record, bound to the identity key ----

    @Test
    fun aRecordedPairReissuesSilentlyAndTheSamePairWithAnotherKeyDoesNot() = runBlocking<Unit> {
        val owner = enroll("a6b-owner")
        val member = enroll("a6b-member")
        val (engine, server, vaultId) = ownerWithCreatedVault(owner)
        engine.accountState.pin(pinOf(member, "Member"))
        engine.addVaultMember(vaultId, member.userId, "writer")
        val rec = assertNotNull(engine.accountState.issued(vaultId, member.userId), "an add records the pair")
        assertEquals(Bytes.toHexLower(crypto.sha256(Bytes.fromB64(member.reg.identityPub))), rec.keyHash)

        // The server now lists the member as legacy (e.g. after a key-format migration): re-issued without a prompt.
        server.members[vaultId] = listOf(summary(owner, "Owner", "owner"), summary(member, "Member", "writer", legacy = true))
        assertTrue(engine.loadLegacyGrants(vaultId).isEmpty(), "nothing to confirm")
        val (v, u, signed) = server.reissues.single()
        assertEquals(vaultId to member.userId, v to u)
        assertEquals(32, opensForMember(member, owner, vaultId, signed).size)

        // The member's identity key changes and the owner re-verifies the NEW key: same pair, another key.
        val newKey = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        val repinned = Contact(member.userId, Bytes.toB64(newKey), "Member", 2_000, Contact.METHOD_TYPED)
        engine.accountState.pin(repinned)
        server.members[vaultId] = listOf(
            summary(owner, "Owner", "owner"),
            VaultMemberSummary(member.userId, "m@example.com", "Member", "writer", Bytes.toB64(newKey), 0, legacyGrant = true),
        )
        assertFailsWith<ReissueNotAuthorizedException> { engine.reissueGrant(vaultId, member.userId) }
        val row = engine.loadLegacyGrants(vaultId).single()
        assertEquals(member.userId, row.userId)
        assertEquals(1, server.reissues.size, "a different identity key is never re-issued silently")
        engine.confirmReissue(row)
        assertEquals(2, server.reissues.size, "only the owner's confirmation re-issues to the new key")
        assertEquals(Bytes.toHexLower(crypto.sha256(newKey)), engine.accountState.issued(vaultId, member.userId)!!.keyHash)
    }

    @Test
    fun theIssuedGrantsRecordSurvivesARestartAndIsNeverShrunkByServedState() = runBlocking<Unit> {
        val owner = enroll("a6b-owner")
        val member = enroll("a6b-member")
        val deviceState = MemoryDeviceState() // the host's durable per-(origin, user) store
        val (engine, server, vaultId) = ownerWithCreatedVault(owner, deviceState)
        val beforeAdd = server.accountState to server.accountSeq
        engine.accountState.pin(pinOf(member, "Member"))
        engine.addVaultMember(vaultId, member.userId, "writer")
        assertNotNull(engine.accountState.issued(vaultId, member.userId))

        // Restart on a memory-only cache (wiped), and the server replays the OLDER blob that lacks the record.
        server.accountState = beforeAdd.first
        server.accountSeq += 1
        val restarted = SyncEngine(api(server), unlock(owner), InMemoryVaultCache(), deviceState = deviceState)
        restarted.sync()
        assertNotNull(restarted.accountState.issued(vaultId, member.userId), "the record survived the restart and the replay")
        assertTrue(restarted.ownsVault(vaultId))
        val written = unlock(owner).openAccountState(server.accountState!!)
        assertNotNull(written.issued(vaultId, member.userId), "the local copy won and was written back")

        // Withheld entirely: still there.
        server.accountState = null
        restarted.sync()
        assertNotNull(restarted.accountState.issued(vaultId, member.userId))

        // Another device of the owner learns it from the (authentic) served blob.
        val other = SyncEngine(api(server), unlock(owner), InMemoryVaultCache())
        other.sync()
        assertNotNull(other.accountState.issued(vaultId, member.userId), "every device of the owner shares the record")

        // A removal tombstones it, and the tombstone too survives a replay of the older blob.
        val withRecord = server.accountState to server.accountSeq
        engine.sync()
        engine.removeVaultMember(vaultId, member.userId)
        assertNull(engine.accountState.issued(vaultId, member.userId), "removing the member drops the pair")
        server.accountState = withRecord.first
        server.accountSeq += 1
        engine.sync()
        assertNull(engine.accountState.issued(vaultId, member.userId), "an older blob cannot bring it back")
    }

    // ---- ownership evidence ----

    @Test
    fun theYouOwnConfirmationRequiresAReauth() = runBlocking<Unit> {
        // Real KDF floor: the reauth reads the account keys through the client's KDF fence.
        val w = world(KdfParams(ops = KdfUpgrade.MIN_OPS, memBytes = KdfUpgrade.MIN_MEM_BYTES))
        val server = FakeServer(ownerFeed(w), keys = w.owner.keys)
        val engine = SyncEngine(api(server), unlock(w.owner), InMemoryVaultCache())
        engine.sync()
        engine.accountState.pin(pinOf(w.member, "Member"))
        assertTrue(engine.ownershipNeedsConfirmation(w.vaultId), "a vault created before A6b has no ownership record")
        assertFailsWith<OwnershipNotConfirmedException> { engine.addVaultMember(w.vaultId, w.member.userId, "writer") }

        val claim = engine.describeOwnership(w.vaultId)
        assertFalse(claim.receivedAsMember, "a vault this account created needs only the single confirm")
        assertEquals(PersonalChoiceInfo.Origin.CREATED, claim.origin)
        assertEquals("Household", claim.vaultName)
        assertFailsWith<ReauthFailedException> { engine.confirmOwnership(claim, "not the password") }
        assertFalse(engine.ownsVault(w.vaultId), "a wrong password records nothing")
        assertTrue(server.adds.isEmpty())
        // Only the claim this engine described is accepted.
        assertFailsWith<IllegalStateException> { engine.confirmOwnership(claim.copy(), password) }

        engine.confirmOwnership(claim, password)
        assertTrue(engine.ownsVault(w.vaultId))
        assertFalse(engine.ownershipNeedsConfirmation(w.vaultId), "asked once")
        engine.addVaultMember(w.vaultId, w.member.userId, "writer")
        assertEquals(1, server.adds.size)
        // The confirmation is UVK-authenticated account state: it reached the server sealed, for every device.
        assertTrue(unlock(w.owner).openAccountState(server.accountState!!).owns(w.vaultId))
    }

    @Test
    fun aVerifiedTransferAwayEndsTheOwnershipRecord() = runBlocking<Unit> {
        val owner = enroll("a6b-owner")
        val member = enroll("a6b-member")
        val (engine, server, vaultId) = ownerWithCreatedVault(owner)
        // The member accepted an offer; every member verifies the accept proof under the held key.
        val wrapHash = Bytes.toHexLower(crypto.sha256("member-wrap".encodeToByteArray()))
        val offerId = "11111111-1111-4111-8111-111111111111"
        val lifecycle = engineLifecycleKey(engine, vaultId)
        val proof = LifecycleProof.acceptFromHash(crypto, lifecycle, vaultId, offerId, member.userId, 1, wrapHash)
        val rev = server.feed.rev + 1
        server.feed = server.feed.copy(
            rev = rev, full = true,
            vaults = server.feed.vaults.map { if (it.vaultId == vaultId) it.copy(rev = rev, lastTransfer = TransferRecord(offerId, member.userId, proof, 1, wrapHash)) else it },
        )
        engine.sync()
        assertFalse(engine.ownsVault(vaultId), "a verified transfer to someone else ends this account's ownership evidence")
        assertFailsWith<OwnershipNotConfirmedException> { engine.offerTransfer(vaultId, member.userId) }
    }

    private fun engineLifecycleKey(engine: SyncEngine, vaultId: String): ByteArray {
        val f = SyncEngine::class.java.getDeclaredField("account").apply { isAccessible = true }
        return (f.get(engine) as Account).lifecycleKeyFor(vaultId)
    }

    // ---- A6b review MEDIUM-1: a vault this device received as a member is not claimed by one confirm ----

    private val floor = KdfParams(ops = KdfUpgrade.MIN_OPS, memBytes = KdfUpgrade.MIN_MEM_BYTES)

    /** The member's device holding the vault through a verified grant from its pinned owner AND its own self-wrap,
     *  with the server relabelling the member's row `owner`. */
    private suspend fun memberHoldingRelabelled(w: World): Pair<SyncEngine, FakeServer> {
        val vk = Envelope.openB64(crypto, uvkOf(w.owner), w.ownerWrap, Ad.vk(w.vaultId, w.owner.userId))
        val selfWrap = Envelope.sealB64(crypto, uvkOf(w.member), vk, Ad.vk(w.vaultId, w.member.userId))
        val signed = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"))
        val server = FakeServer(
            SyncResponse(
                9, true, listOf(personalRow(w.member), WireVault(w.vaultId, "shared", 9, w.metaBlob, 0)),
                listOf(personalGrant(w.member), WireGrant(w.vaultId, w.member.userId, "owner", selfWrap, 9, null, signed)), emptyList(), emptyList(),
            ),
            keys = w.member.keys,
        )
        server.members[w.vaultId] = listOf(summary(w.member, "Member", "owner"), summary(w.owner, "Owner", "writer"))
        val engine = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache())
        engine.sync()
        return engine to server
    }

    @Test
    fun aMemberGrantedVaultIsNotClaimedByASingleConfirm() = runBlocking<Unit> {
        val w = world(memberParams = floor)
        val (engine, _) = memberHoldingRelabelled(w)
        assertTrue(engine.ownershipNeedsConfirmation(w.vaultId))
        val claim = engine.describeOwnership(w.vaultId)
        // The dialog data, as the server reports it, and this device's own record of how it got the key.
        assertTrue(claim.receivedAsMember)
        assertEquals(w.member.userId, claim.reportedOwner?.userId, "the server's owner label, shown as reported")
        assertEquals(listOf(w.owner.userId), claim.coHolders.map { it.userId }, "the co-holders are named")
        assertEquals(PersonalChoiceInfo.Origin.CREATED, claim.origin, "no transfer reported")
        assertNull(claim.lastTransferTo)
        assertFailsWith<OwnershipTransferAckRequiredException>("one confirm does not claim a vault received as a member") {
            engine.confirmOwnership(claim, password)
        }
        assertFalse(engine.ownsVault(w.vaultId))
        // The explicit second acknowledgement ("This vault's owner transferred it to me") is what a genuine
        // pre-A6b transfer recipient gives; it is not refused outright.
        engine.confirmOwnership(claim, password, transferredToMe = true)
        assertTrue(engine.ownsVault(w.vaultId))
    }

    // ---- A6b review LOW-3: the reauth runs only on keys this session can vouch for ----

    @Test
    fun theReauthRefusesAReplayedOlderSaltAndAWeakenedKdf() {
        val owner = enroll("a6b-owner", floor)
        val device = unlock(owner)
        val uvk = uvkOf(owner)
        // An OLDER AccountKeys (before a password change): another salt, the same UVK under the OLD password.
        val oldSalt = crypto.randomBytes(16)
        val oldWrap = Envelope.sealB64(crypto, Keys.wrapKey(crypto, Keys.masterKey(crypto, "the old password", oldSalt, floor)), uvk, Ad.uvk(owner.userId))
        val replayed = owner.keys.copy(kdfSalt = Bytes.toB64(oldSalt), wrappedUvk = oldWrap)
        assertFalse(runCatching { device.verifyPassword("the old password", replayed) }.getOrDefault(false), "a replayed older salt never passes")
        // The current salt, but weakened KDF parameters the server chose.
        val weak = KdfParams(ops = 1, memBytes = 8192)
        val weakWrap = Envelope.sealB64(crypto, Keys.wrapKey(crypto, Keys.masterKey(crypto, password, Bytes.fromB64(owner.keys.kdfSalt), weak)), uvk, Ad.uvk(owner.userId))
        val weakened = owner.keys.copy(kdfParams = weak, wrappedUvk = weakWrap)
        assertFalse(runCatching { device.verifyPassword(password, weakened) }.getOrDefault(false), "a weakened KDF never passes")
        assertTrue(device.verifyPassword(password, owner.keys), "the real keys still pass")
    }

    @Test
    fun theMemberProvenanceSurvivesARestartWhoseServedRowLooksLikeAnOwnerRow() = runBlocking<Unit> {
        // The server later strips the grant from the relabelled row: a restarted engine sees a plain owner-shaped row,
        // but the device's durable record still says the key first arrived as a member.
        val w = world(memberParams = floor)
        val vk = Envelope.openB64(crypto, uvkOf(w.owner), w.ownerWrap, Ad.vk(w.vaultId, w.owner.userId))
        val selfWrap = Envelope.sealB64(crypto, uvkOf(w.member), vk, Ad.vk(w.vaultId, w.member.userId))
        val signed = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"))
        val server = FakeServer(
            SyncResponse(9, true, listOf(personalRow(w.member), WireVault(w.vaultId, "shared", 9, w.metaBlob, 0)),
                listOf(personalGrant(w.member), WireGrant(w.vaultId, w.member.userId, "writer", selfWrap, 9, null, signed)), emptyList(), emptyList()),
            keys = w.member.keys,
        )
        server.members[w.vaultId] = listOf(summary(w.member, "Member", "owner"))
        val cache = InMemoryVaultCache()
        val ds = MemoryDeviceState()
        SyncEngine(api(server), unlock(w.member), cache, deviceState = ds).sync()
        server.feed = SyncResponse(12, true, listOf(personalRow(w.member), WireVault(w.vaultId, "shared", 12, w.metaBlob, 0)),
            listOf(personalGrant(w.member), WireGrant(w.vaultId, w.member.userId, "owner", selfWrap, 12, null)), emptyList(), emptyList())
        val restarted = SyncEngine(api(server), unlock(w.member), cache, deviceState = ds)
        restarted.hydrate()
        restarted.sync()
        val claim = restarted.describeOwnership(w.vaultId)
        assertTrue(claim.receivedAsMember, "the durable provenance outlives the served row")
        assertFailsWith<OwnershipTransferAckRequiredException> { restarted.confirmOwnership(claim, password) }
    }

    /**
     * A6b carry-forward LOW-R (branch A1b): the "received as a member" provenance also rides account state (UVK-sealed,
     * union-merged, add-only), so a fresh device of the member whose FIRST served row is owner-shaped still needs the
     * transfer acknowledgement when another device of the same account recorded member provenance.
     */
    @Test
    fun aFreshDeviceStillNeedsTheTransferAckWhenAnotherDeviceRecordedMemberProvenance() = runBlocking<Unit> {
        val w = world(memberParams = floor)
        val vk = Envelope.openB64(crypto, uvkOf(w.owner), w.ownerWrap, Ad.vk(w.vaultId, w.owner.userId))
        val selfWrap = Envelope.sealB64(crypto, uvkOf(w.member), vk, Ad.vk(w.vaultId, w.member.userId))
        val signed = w.owner.account.buildSignedGrant(w.vaultId, pinOf(w.member, "Member"))
        val server = FakeServer(
            SyncResponse(9, true, listOf(personalRow(w.member), WireVault(w.vaultId, "shared", 9, w.metaBlob, 0)),
                listOf(personalGrant(w.member), WireGrant(w.vaultId, w.member.userId, "writer", selfWrap, 9, null, signed)), emptyList(), emptyList()),
            keys = w.member.keys,
        )
        server.members[w.vaultId] = listOf(summary(w.member, "Member", "owner"))
        SyncEngine(api(server), unlock(w.member), InMemoryVaultCache(), deviceState = MemoryDeviceState()).sync()
        // Another device of the same member: nothing local, and its FIRST served row is owner-shaped.
        server.feed = SyncResponse(12, true, listOf(personalRow(w.member), WireVault(w.vaultId, "shared", 12, w.metaBlob, 0)),
            listOf(personalGrant(w.member), WireGrant(w.vaultId, w.member.userId, "owner", selfWrap, 12, null)), emptyList(), emptyList())
        val fresh = SyncEngine(api(server), unlock(w.member), InMemoryVaultCache(), deviceState = MemoryDeviceState())
        fresh.sync()
        val claim = fresh.describeOwnership(w.vaultId)
        assertTrue(claim.receivedAsMember, "the account-state record reaches a device that never saw the member row")
        assertFailsWith<OwnershipTransferAckRequiredException> { fresh.confirmOwnership(claim, password) }
    }

    /**
     * A6b carry-forward (copy, branch A1b): after a password change or a KDF upgrade the session's salt is stale, so the
     * reauth fails closed. It must say how to recover ("Lock and unlock andvari, then try again"), not blame the
     * password. Byte-identical with web (`ReauthStaleSessionError`).
     */
    @Test
    fun aReauthAgainstAStaleSessionSaltSaysLockAndUnlock() = runBlocking<Unit> {
        val params = KdfParams(ops = KdfUpgrade.MIN_OPS, memBytes = KdfUpgrade.MIN_MEM_BYTES)
        val w = world(params)
        val newSalt = crypto.randomBytes(16)
        val newWrap = Envelope.sealB64(crypto, Keys.wrapKey(crypto, Keys.masterKey(crypto, "the new password", newSalt, params)), uvkOf(w.owner), Ad.uvk(w.owner.userId))
        val server = FakeServer(ownerFeed(w), keys = w.owner.keys.copy(kdfSalt = Bytes.toB64(newSalt), wrappedUvk = newWrap))
        val engine = SyncEngine(api(server), unlock(w.owner), InMemoryVaultCache())
        engine.sync()
        val claim = engine.describeOwnership(w.vaultId)
        val e = assertFailsWith<Exception> { engine.confirmOwnership(claim, "the new password") }
        assertEquals("Lock and unlock andvari, then try again.", e.message)
        assertFalse(engine.ownsVault(w.vaultId))
    }
}
