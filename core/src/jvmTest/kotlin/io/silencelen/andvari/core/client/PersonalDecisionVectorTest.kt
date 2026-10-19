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
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.AccountStateResponse
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PersonalWrap
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, branch A11 (core runner of `personalwrap.json` `decision`; web
 * `personaldecision.vectors.test.ts` twin). c00: a withheld or unopenable served wrap no longer puts the cached wrap in
 * force against the account's designation. c01: a designation that moves away from the cached vault is a CHANGED notice,
 * never a silent switch. Also c19 (a second apply keeps a proposal a proposal) and c04 (copy-all-to-Personal refuses
 * with no personal vault in force). Every row drives the REAL Account + SyncEngine against a scripted server.
 */
class PersonalDecisionVectorTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val vectors = Json.parseToJsonElement(
        File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"), "personalwrap.json").readText(),
    ).jsonObject
    private val stateSeq = 3L

    private class World(
        val account: Account, val keys: AccountKeys, val userId: String, val a: String, val c: String,
        val wraps: Map<String, PersonalWrap>, val feed: SyncResponse,
    )

    private fun world(): World {
        val email = "a11-${crypto.randomBytes(4).joinToString("") { (it.toInt() and 0xff).toString(16) }}@example.com"
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val r = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "dev", crypto)
        val reg = r.request
        val keys = AccountKeys(
            kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
            encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
            escrowFingerprint = reg.escrow!!.fingerprint, personalWrap = reg.personalWrap,
        )
        val shared = r.account.buildCreateSharedVault("Household")
        val a = reg.personalVault.vaultId
        val c = shared.vaultId
        val feed = SyncResponse(
            5, true,
            listOf(WireVault(a, "personal", 2, reg.personalVault.metaBlob, 0), WireVault(c, "shared", 3, shared.request.metaBlob, 0)),
            listOf(WireGrant(a, reg.userId, "owner", reg.personalVault.wrappedVk, 2, null), WireGrant(c, reg.userId, "owner", shared.request.wrappedVk, 3, null)),
            emptyList(), emptyList(),
        )
        val wraps = mapOf(
            "A" to reg.personalWrap!!,
            "C" to r.account.buildPersonalWrap(c),
            "junk" to PersonalWrap(c, shared.request.wrappedVk), // an owner wrap (Ad.vk): never opens as a personal wrap
        )
        return World(r.account, keys, reg.userId, a, c, wraps, feed)
    }

    private class Server(val feed: SyncResponse, var keys: AccountKeys) {
        var accountState: String? = null
        var accountSeq = 0L
        val pushed = mutableListOf<io.silencelen.andvari.core.model.Mutation>()
    }

    private fun body(req: io.ktor.client.request.HttpRequestData): String = when (val b = req.body) {
        is TextContent -> b.text
        is OutgoingContent.ByteArrayContent -> b.bytes().decodeToString()
        else -> ""
    }

    private fun api(server: Server): AndvariApi {
        val engine = MockEngine { req ->
            val path = req.url.encodedPath
            val ct = headersOf(HttpHeaders.ContentType, "application/json")
            when {
                path == "/api/v1/sync" -> {
                    val since = req.url.parameters["since"]?.toLongOrNull() ?: 0L
                    val resp = if (since == 0L) server.feed else SyncResponse(server.feed.rev, false, emptyList(), emptyList(), emptyList(), emptyList())
                    respond(json.encodeToString(SyncResponse.serializer(), resp), HttpStatusCode.OK, ct)
                }
                path == "/api/v1/sync/push" -> {
                    val b = json.decodeFromString(PushRequest.serializer(), body(req))
                    server.pushed += b.mutations
                    val rev = server.feed.rev + server.pushed.size
                    respond(json.encodeToString(PushResponse.serializer(), PushResponse(rev, b.mutations.map { MutationResult(it.mutationId, "applied", newItemRev = rev) })), HttpStatusCode.OK, ct)
                }
                path == "/api/v1/account/keys" -> respond(json.encodeToString(AccountKeys.serializer(), server.keys), HttpStatusCode.OK, ct)
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
                Regex("^/api/v1/vaults/([^/]+)/members$").matches(path) && req.method == HttpMethod.Get ->
                    respond(json.encodeToString(ListSerializer(VaultMemberSummary.serializer()), emptyList()), HttpStatusCode.OK, ct)
                else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
    }

    private class Run(val device: Account, val engine: SyncEngine, val server: Server, val state: MemoryDeviceState)

    private fun run(w: World, served: String, cached: String, designation: String?, mergedStateBefore: Boolean): Run = runBlocking {
        val server = Server(w.feed, w.keys.copy(personalWrap = if (served == "none") null else w.wraps.getValue(served)))
        val state = MemoryDeviceState()
        if (cached != "none") state.set("personal.wrap", json.encodeToString(PersonalWrap.serializer(), w.wraps.getValue(cached)))
        if (designation != null) {
            val doc = AccountState.withPersonal(AccountState.empty(w.userId), if (designation == "A") w.a else w.c, 1_000).copy(seq = stateSeq)
            server.accountState = w.account.sealAccountState(doc)
            server.accountSeq = stateSeq
        }
        if (mergedStateBefore) state.set("acctstate.hw", stateSeq.toString())
        val device = Account.unlock(w.userId, password, server.keys, crypto)
        val engine = SyncEngine(api(server), device, InMemoryVaultCache(), deviceState = state)
        engine.sync()
        Run(device, engine, server, state)
    }

    private fun status(s: Account.PersonalStatus) = s.name.lowercase().replace('_', '-')

    @Test
    fun decisionRows() {
        val rows = vectors.getValue("decision").jsonArray
        assertTrue(rows.size >= 15, "the decision table is present")
        for (el in rows) {
            val row = el.jsonObject
            val name = row.getValue("name").jsonPrimitive.content
            val exp = row.getValue("expected").jsonObject
            val w = world()
            val sym = { id: String? -> when (id) { null -> null; w.a -> "A"; w.c -> "C"; else -> id } }
            val desig = row.getValue("designation").let { if (it is JsonNull) null else it.jsonPrimitive.content }
            val r = run(
                w, row.getValue("served").jsonPrimitive.content, row.getValue("cached").jsonPrimitive.content, desig,
                row.getValue("mergedStateBefore").jsonPrimitive.boolean,
            )
            assertEquals(exp.getValue("status").jsonPrimitive.content, status(r.device.personalStatus), "$name: status")
            assertEquals(exp.getValue("inForce").jsonPrimitive.content, sym(r.device.personalVaultId), "$name: in force")
            val pending = if (r.device.personalStatus == Account.PersonalStatus.CHANGED || r.device.personalStatus == Account.PersonalStatus.PROPOSED) {
                sym(r.device.pendingPersonalChange?.vaultId)
            } else null
            val expPending = exp.getValue("pending").let { if (it is JsonNull) null else it.jsonPrimitive.content }
            assertEquals(expPending, pending, "$name: pending")
        }
    }

    @Test
    fun c00_theHeldCachedWrapIsResolvedOnlyByTheHuman() = runBlocking<Unit> {
        val w = world()
        val r = run(w, "none", "A", "C", true)
        assertEquals(PersonalChange(w.c, w.a), r.engine.personalChange())
        assertNull(r.engine.personalVaultChoices)
        val doc = ItemDoc(type = "login", name = "Bank", login = LoginData(username = "me", password = "pw"))
        assertFailsWith<NoPersonalVaultException> { r.engine.save(null, doc) }
        r.engine.sync()
        assertEquals(Account.PersonalStatus.PROPOSED, r.device.personalStatus, "a later sync never confirms it for the human")
        r.engine.describePersonalChange()
        r.engine.acceptPersonalChange()
        assertEquals(Account.PersonalStatus.CONFIRMED, r.device.personalStatus)
        assertEquals(w.a, r.device.personalVaultId)
        assertEquals(w.a, r.engine.designatedPersonalVaultId())
    }

    @Test
    fun c19_aSecondApplyWhileProposedKeepsTheProposal() {
        val w = world()
        val device = Account.unlock(w.userId, password, w.keys.copy(personalWrap = w.wraps.getValue("A")), crypto)
        assertEquals(Account.PersonalStatus.CONFIRMED, device.personalStatus)
        assertTrue(device.holdPersonalProposal(w.c))
        device.applyPersonalWrap(w.wraps.getValue("A"))
        assertEquals(Account.PersonalStatus.PROPOSED, device.personalStatus)
        assertEquals("", device.personalVaultId)
        assertEquals(w.a, device.pendingPersonalChange?.vaultId)
        assertEquals(w.c, device.proposedAgainstDesignation)
        device.applyPersonalWrap(w.wraps.getValue("C"))
        assertEquals(Account.PersonalStatus.PROPOSED, device.personalStatus)
        assertEquals("", device.personalVaultId)
        assertEquals(w.a, device.pendingPersonalChange?.vaultId)
    }

    @Test
    fun c04_copyAllToPersonalWithNoPersonalVaultRefusesBeforeSealing() = runBlocking<Unit> {
        val w = world()
        val r = run(w, "A", "none", null, false)
        assertEquals("", r.device.personalVaultId)
        r.engine.save(null, ItemDoc(type = "login", name = "Shared", login = LoginData(username = "u", password = "p")), vaultId = w.c)
        val before = r.server.pushed.size
        assertFailsWith<NoPersonalVaultException> { r.engine.copyAllToPersonal(w.c) }
        assertEquals(before, r.server.pushed.size, "nothing was sealed under vault \"\"")
    }
}
