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
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.LifecycleProof
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AccountStatePut
import io.silencelen.andvari.core.model.AccountStateResponse
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.GrantReissueRequest
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PersonalWrap
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.PersonalWrapPut
import io.silencelen.andvari.core.model.RecoveryVerifyResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.TransferRecord
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberSummary
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, branch A9 (the second API-review round over A6b/A1b/A5c): three MEDIUM and the LOW items.
 *
 *  - M-1: every password-derived upload goes through ONE fenced derivation ([Account.reauthAuthKey]): the unlock KDF
 *    floor/ceiling, and only the salt this session unlocked with. The re-designation reauth had neither.
 *  - M-2: the account's own personal-vault designation rides account state (`personal`, newest wins). A served wrap
 *    agreeing with it is confirmed on any device; one disagreeing with it, or served to a device with no cache and no
 *    designation, is a PROPOSAL the human confirms — never a silent adoption on a fresh device.
 *  - M-3: nothing re-issues a vault key without a per-row human confirmation; the issued-grants record only annotates
 *    the row ("you shared this on …"), and the removing device keeps its own durable tombstone.
 *  - L-1: an item's home is recorded only from a row this device actually applied; a tombstone or an unheld-vault row
 *    served first never homes the item.
 *  - L-2: the member-granted bit is set only when the key was adopted through a seal or a verified grant.
 *  - LOWs: a failed ownership-release write is retried; a rename refuses a key contradicting the vouch; recover() wipes
 *    the probe account's identity and signing secrets.
 */
class ApiReview2Test {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val floor = KdfParams(ops = KdfUpgrade.MIN_OPS, memBytes = KdfUpgrade.MIN_MEM_BYTES)
    private val weak = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys, val recoverySecret: ByteArray) {
        val userId get() = reg.userId
        val personalId get() = reg.personalVault.vaultId
    }

    private fun enroll(tag: String, params: KdfParams = kdf): Enrolled {
        val email = "$tag-${crypto.randomBytes(4).joinToString("") { (it.toInt() and 0xff).toString(16) }}@example.com"
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val r = Account.enroll("inv", email, email, password, params, recovery.publicKey, fp, "dev", crypto)
        val reg = r.request
        return Enrolled(
            reg, r.account,
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint, personalWrap = reg.personalWrap,
            ),
            r.recoverySecret,
        )
    }

    /** A fresh device of [e]: the wrap the server serves it is [wrap] (default: the one enrolment minted). */
    private fun unlock(e: Enrolled, wrap: PersonalWrap? = e.reg.personalWrap) = Account.unlock(e.userId, password, e.keys.copy(personalWrap = wrap), crypto)

    private fun uvkOf(e: Enrolled): ByteArray {
        val mk = Keys.masterKey(crypto, password, Bytes.fromB64(e.keys.kdfSalt), e.keys.kdfParams)
        return Envelope.openB64(crypto, Keys.wrapKey(crypto, mk), e.keys.wrappedUvk, Ad.uvk(e.userId))
    }

    private fun expectedAuthKey(e: Enrolled): String =
        Bytes.toB64(Keys.authKey(crypto, Keys.masterKey(crypto, password, Bytes.fromB64(e.keys.kdfSalt), e.keys.kdfParams)))

    /** A scripted hostile-capable server. */
    private class FakeServer(var feed: SyncResponse, var keys: AccountKeys? = null, val selfUserId: String? = null) {
        val adds = mutableListOf<Pair<String, VaultMemberAdd>>()
        val reissues = mutableListOf<Triple<String, String, String>>()
        val removals = mutableListOf<Pair<String, String>>()
        val personalWrapPuts = mutableListOf<PersonalWrapPut>()
        val pushed = mutableListOf<io.silencelen.andvari.core.model.Mutation>()
        val members = HashMap<String, List<VaultMemberSummary>>()
        var accountState: String? = null
        var accountSeq: Long = 0
        /** GET /account/state answers "nothing stored" (the server withholds it). */
        var withholdState = false
        /** Every PUT /account/state fails with 500 while set. */
        var failStatePut = false
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
                path == "/api/v1/sync/push" -> {
                    val body = json.decodeFromString(PushRequest.serializer(), body(req))
                    server.pushed += body.mutations
                    val rev = server.feed.rev + server.pushed.size
                    respond(json.encodeToString(PushResponse.serializer(), PushResponse(rev, body.mutations.map { MutationResult(it.mutationId, "applied", newItemRev = rev) })), HttpStatusCode.OK, ct)
                }
                path == "/api/v1/account/keys" && server.keys != null ->
                    respond(json.encodeToString(AccountKeys.serializer(), server.keys!!), HttpStatusCode.OK, ct)
                path == "/api/v1/account/personal-wrap" && req.method == HttpMethod.Put -> {
                    server.personalWrapPuts.add(json.decodeFromString(PersonalWrapPut.serializer(), body(req)))
                    respond("ok", HttpStatusCode.OK)
                }
                path == "/api/v1/account/state" && req.method == HttpMethod.Get -> {
                    val blob = if (server.withholdState) null else server.accountState
                    respond(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(blob, if (server.withholdState) 0 else server.accountSeq)), HttpStatusCode.OK, ct)
                }
                path == "/api/v1/account/state" && req.method == HttpMethod.Put -> {
                    val put = json.decodeFromString(AccountStatePut.serializer(), body(req))
                    when {
                        server.failStatePut -> respond("""{"error":"internal","message":"no"}""", HttpStatusCode.InternalServerError, ct)
                        put.baseSeq != server.accountSeq -> respond("""{"error":"stale_state","message":"stale"}""", HttpStatusCode.Conflict, ct)
                        else -> {
                            server.accountState = put.sealedState
                            server.accountSeq += 1
                            respond(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(put.sealedState, server.accountSeq)), HttpStatusCode.OK, ct)
                        }
                    }
                }
                path == "/api/v1/vaults" && req.method == HttpMethod.Post -> {
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
                req.method == HttpMethod.Put && path.endsWith("/grant/self-wrap") ->
                    respond("""{"rev":${server.feed.rev + 1}}""", HttpStatusCode.OK, ct)
                else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
    }

    private fun pinOf(e: Enrolled, label: String) = Contact(e.userId, e.reg.identityPub, label, 1_000, Contact.METHOD_TYPED)
    private fun personalRow(e: Enrolled) = WireVault(e.personalId, "personal", 2, e.reg.personalVault.metaBlob, 0)
    private fun personalGrant(e: Enrolled) = WireGrant(e.personalId, e.userId, "owner", e.reg.personalVault.wrappedVk, 2, null)
    private fun summary(e: Enrolled, name: String, role: String, legacy: Boolean = false) =
        VaultMemberSummary(e.userId, "$name@example.com", name, role, e.reg.identityPub, 0, legacyGrant = legacy.takeIf { it })

    /** The owner's own feed: the personal vault plus a shared vault "Household" the owner created (own UVK wrap). */
    private class World(val owner: Enrolled, val sharedId: String, val metaBlob: String, val ownerWrap: String, val feed: SyncResponse)

    private fun world(params: KdfParams = kdf): World {
        val owner = enroll("a9", params)
        val shared = owner.account.buildCreateSharedVault("Household")
        val feed = SyncResponse(
            5, true, listOf(personalRow(owner), WireVault(shared.vaultId, "shared", 3, shared.request.metaBlob, 0)),
            listOf(personalGrant(owner), WireGrant(shared.vaultId, owner.userId, "owner", shared.request.wrappedVk, 3, null)), emptyList(), emptyList(),
        )
        return World(owner, shared.vaultId, shared.request.metaBlob, shared.request.wrappedVk, feed)
    }

    private fun serverOf(w: World, keys: AccountKeys? = w.owner.keys) = FakeServer(w.feed, keys, w.owner.userId).also {
        it.members[w.sharedId] = listOf(summary(w.owner, "Owner", "owner"))
        it.members[w.owner.personalId] = listOf(summary(w.owner, "Owner", "owner"))
    }

    private fun designationOn(server: FakeServer, e: Enrolled): String? =
        server.accountState?.let { unlock(e).openAccountState(it).personal?.vaultId }

    // ---- M-1: the re-designation reauth derives only through the fence ----

    @Test
    fun m1_theRedesignationReauthRefusesWeakenedParamsAndAReplayedSalt() = runBlocking<Unit> {
        val w = world(floor)
        val server = serverOf(w)
        val engine = SyncEngine(api(server), unlock(w.owner), InMemoryVaultCache(), deviceState = MemoryDeviceState())
        engine.sync()
        val proposal = engine.proposePersonalVault(w.sharedId)

        // The server answers GET /account/keys with its own, weakened KDF parameters on the real salt.
        server.keys = w.owner.keys.copy(kdfParams = weak)
        assertFailsWith<KdfPolicyViolationException> { engine.redesignatePersonalVault(proposal, password) }
        assertTrue(server.personalWrapPuts.isEmpty(), "nothing derived from weakened params ever leaves the device")

        // The server replays an older AccountKeys: another salt (before a password change). Nothing is derived.
        server.keys = w.owner.keys.copy(kdfSalt = Bytes.toB64(crypto.randomBytes(16)))
        assertFailsWith<ReauthStaleSessionException> { engine.redesignatePersonalVault(proposal, password) }
        assertTrue(server.personalWrapPuts.isEmpty(), "a salt this session did not unlock with derives nothing")

        // The real keys pass, and the uploaded proof is the login authKey under the session's salt and params.
        server.keys = w.owner.keys
        engine.redesignatePersonalVault(proposal, password)
        assertEquals(expectedAuthKey(w.owner), server.personalWrapPuts.single().currentAuthKey)
        assertEquals(w.sharedId, server.personalWrapPuts.single().vaultId)
    }

    @Test
    fun m1_reauthAuthKeyIsTheOneFencedDerivation() {
        val owner = enroll("a9-fence", floor)
        val device = unlock(owner)
        assertFailsWith<KdfPolicyViolationException> { device.reauthAuthKey(password, owner.keys.copy(kdfParams = weak)) }
        assertFailsWith<ReauthStaleSessionException> { device.reauthAuthKey(password, owner.keys.copy(kdfSalt = Bytes.toB64(crypto.randomBytes(16)))) }
        assertEquals(expectedAuthKey(owner), device.reauthAuthKey(password, owner.keys))
        // The pre-session derivation (sign-in after prelogin, where no session salt exists yet) is fenced on the params too.
        assertFailsWith<KdfPolicyViolationException> { Account.deriveAuthKey(password, owner.keys.kdfSalt, weak, crypto) }
        assertEquals(expectedAuthKey(owner), Account.deriveAuthKey(password, owner.keys.kdfSalt, owner.keys.kdfParams, crypto))
    }

    private val repo = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set")).absoluteFile.parentFile.parentFile

    private fun productSources(): List<File> = listOf(
        "core/src/commonMain", "core/src/jvmShared", "core/src/jvmMain", "core/src/androidMain",
        "app-android/src/main", "app-desktop/src/main", "tools",
    ).map { File(repo, it) }.filter { it.exists() }.flatMap { root ->
        root.walkTopDown().filter { it.isFile && it.extension == "kt" && "/src/test/" !in it.path && "/build/" !in it.path }.toList()
    }

    /**
     * Tripwire: product code derives a master-password credential for an upload ONLY through the fence. The raw KDF
     * ([Keys.masterKey]) is called only inside Account (every caller fenced), the backup KDF (its own window, spec 07 §2.3)
     * and the KDF re-key (fenced by [KdfUpgrade.shouldUpgrade]); the pre-session [Account.deriveAuthKey] appears only
     * at the two sign-in sites, over the prelogin values (fenced at the API boundary, and no session salt exists yet).
     */
    @Test
    fun m1_tripwire_productCodeDerivesPasswordCredentialsOnlyThroughTheFence() {
        val files = productSources()
        assertTrue(files.size > 50, "the scan found the product sources (${files.size} files under $repo)")
        val masterKeyAllowed = setOf(
            "core/src/commonMain/kotlin/io/silencelen/andvari/core/client/Account.kt",
            "core/src/commonMain/kotlin/io/silencelen/andvari/core/client/Export.kt",
            "core/src/jvmShared/kotlin/io/silencelen/andvari/core/client/KdfReKeyCore.kt",
            // Admin tooling, not a client: the recovery CLI mints the recovered member's temporary password offline under
            // params of its own choosing, and the vector generator authors the cross-engine KDF vectors (below the floor).
            "tools/recovery-cli/src/main/kotlin/io/silencelen/andvari/recovery/Main.kt",
            "tools/vector-gen/src/main/kotlin/io/silencelen/andvari/tools/vectorgen/Main.kt",
        )
        val rawKdf = files.filter { f -> f.readLines().any { Regex("""Keys\.masterKey\(""").containsMatchIn(it.substringBefore("//")) } }
            .map { it.relativeTo(repo).path }.filterNot { it in masterKeyAllowed }
        assertEquals(emptyList(), rawKdf, "Keys.masterKey is called outside Account / the backup KDF / the fenced re-key")
        val loginDerivations = files.flatMap { f ->
            f.readLines().mapIndexedNotNull { i, line ->
                val code = line.substringBefore("//")
                if (Regex("""Account\.deriveAuthKey\(""").containsMatchIn(code)) Triple(f.relativeTo(repo).path, i + 1, code.trim()) else null
            }
        }
        val offenders = loginDerivations.filterNot { (path, _, code) ->
            (path.endsWith("AndvariViewModel.kt") || path.endsWith("DesktopState.kt")) && "pre.kdfSalt" in code && "pre.kdfParams" in code
        }
        assertEquals(emptyList(), offenders.map { "${it.first}:${it.second}: ${it.third}" }, "derive an in-session password proof through Account.reauthAuthKey(password, keys)")
        assertEquals(2, loginDerivations.size, "exactly the two sign-in sites derive the pre-session login authKey")
    }

    // ---- M-2: the designation in account state; a fresh device never adopts a served wrap silently ----

    @Test
    fun m2_registrationDesignatesThePersonalVaultOnTheFirstSync() = runBlocking<Unit> {
        val w = world()
        val server = serverOf(w)
        val device = MemoryDeviceState()
        // The REGISTERING device: the account enrolment just built (it minted the wrap itself).
        val engine = SyncEngine(api(server), w.owner.account, InMemoryVaultCache(), deviceState = device)
        engine.sync()
        assertEquals(Account.PersonalStatus.CONFIRMED, w.owner.account.personalStatus)
        assertEquals(w.owner.personalId, w.owner.account.personalVaultId)
        assertEquals(w.owner.personalId, designationOn(server, w.owner), "the designation is written on register")
        assertEquals(w.owner.personalId, engine.designatedPersonalVaultId())
        assertTrue(device.get("personal.wrap")!!.contains(w.owner.personalId), "and cached on this device")

        // A9 review LOW-4: a fresh device (no cached wrap, no high-water mark of its own) confirms the served wrap ONCE,
        // even when the designation names it: on a fresh device the designation is as replayable as the wrap.
        val freshAccount = unlock(w.owner)
        val dsFresh = MemoryDeviceState()
        val fresh = SyncEngine(api(server), freshAccount, InMemoryVaultCache(), deviceState = dsFresh)
        fresh.sync()
        assertEquals(Account.PersonalStatus.PROPOSED, freshAccount.personalStatus, "a fresh device asks once, designation or not")
        assertEquals(PersonalChange(w.owner.personalId, w.owner.personalId), fresh.personalChange(), "the designation and the served wrap agree")
        fresh.sync()
        assertEquals(Account.PersonalStatus.PROPOSED, freshAccount.personalStatus, "a second sync does not confirm it for the human")
        fresh.describePersonalChange()
        fresh.acceptPersonalChange()
        assertEquals(Account.PersonalStatus.CONFIRMED, freshAccount.personalStatus)
        assertEquals(w.owner.personalId, freshAccount.personalVaultId)
        assertNull(fresh.personalChange())
        // From then on the device is established: a restart with the cached wrap is confirmed silently.
        val restarted = unlock(w.owner)
        SyncEngine(api(server), restarted, InMemoryVaultCache(), deviceState = dsFresh).sync()
        assertEquals(Account.PersonalStatus.CONFIRMED, restarted.personalStatus, "exactly once")
        assertEquals("personal", fresh.vaultInfos().single { it.vaultId == w.owner.personalId }.type)
    }

    @Test
    fun m2_aFreshDeviceServedASupersededWrapAgainstTheDesignationAsksInsteadOfAdopting() = runBlocking<Unit> {
        val w = world(floor)
        val server = serverOf(w)
        // Device A registers (designation = the personal vault), then re-designates the co-held "Household".
        val a = SyncEngine(api(server), w.owner.account, InMemoryVaultCache(), deviceState = MemoryDeviceState())
        a.sync()
        a.redesignatePersonalVault(a.proposePersonalVault(w.sharedId), password)
        assertEquals(w.sharedId, designationOn(server, w.owner), "the re-designation is the newest designation")
        assertEquals(1, server.personalWrapPuts.size)
        a.sync()
        assertEquals(Account.PersonalStatus.CONFIRMED, w.owner.account.personalStatus, "the established device is unchanged")
        assertEquals(w.sharedId, w.owner.account.personalVaultId)

        // Device B is fresh (no cache, no device state). The server serves it the SUPERSEDED wrap for the personal vault.
        val b = unlock(w.owner, w.owner.reg.personalWrap)
        val dsB = MemoryDeviceState()
        val engineB = SyncEngine(api(server), b, InMemoryVaultCache(), deviceState = dsB)
        engineB.sync()
        assertEquals(Account.PersonalStatus.PROPOSED, b.personalStatus, "a served wrap disagreeing with the designation is never adopted")
        assertEquals("", b.personalVaultId, "nothing is in force: no default destination")
        assertEquals(PersonalChange(w.sharedId, w.owner.personalId), engineB.personalChange(), "the ask names the designation and the served vault")
        assertNull(dsB.get("personal.wrap"), "the unconfirmed wrap is not cached")
        assertTrue(engineB.vaultInfos().none { it.type == "personal" })
        assertEquals(1, server.personalWrapPuts.size, "nothing minted")
        assertEquals(w.sharedId, designationOn(server, w.owner), "the designation is untouched")

        // The human confirms the served vault after seeing its co-holders: it is in force, cached and designated.
        assertNotNull(engineB.describePersonalChange())
        engineB.acceptPersonalChange()
        assertEquals(Account.PersonalStatus.CONFIRMED, b.personalStatus)
        assertEquals(w.owner.personalId, b.personalVaultId)
        assertTrue(dsB.get("personal.wrap")!!.contains(w.owner.personalId))
        engineB.sync()
        assertEquals(w.owner.personalId, designationOn(server, w.owner), "accepting a change writes the newest designation")
        assertEquals(1, server.personalWrapPuts.size, "accepting a served wrap mints nothing")
    }

    @Test
    fun m2_aFreshDeviceWithAccountStateWithheldTreatsTheServedWrapAsAProposal() = runBlocking<Unit> {
        val w = world()
        val server = serverOf(w)
        server.withholdState = true
        val b = unlock(w.owner)
        val engine = SyncEngine(api(server), b, InMemoryVaultCache(), deviceState = MemoryDeviceState())
        engine.sync()
        assertEquals(Account.PersonalStatus.PROPOSED, b.personalStatus, "no designation anywhere: the served wrap is a proposal, not a fact")
        assertEquals("", b.personalVaultId)
        assertEquals(PersonalChange("", w.owner.personalId), engine.personalChange())
        assertNull(engine.personalVaultChoices, "not the migration question: there IS a served wrap, it just needs the human")
        assertTrue(engine.vaultInfos().none { it.type == "personal" }, "nothing seals under the served vault by default")
        assertTrue(server.personalWrapPuts.isEmpty())
        // "Use it" is offered only once the vault's co-holders loaded (A5b review LOW-1 holds for the proposal too).
        assertFailsWith<IllegalStateException> { engine.acceptPersonalChange() }
        val details = engine.describePersonalChange()
        assertEquals("", details.currentVaultId)
        assertEquals(w.owner.personalId, details.servedVaultId)
        engine.acceptPersonalChange()
        assertEquals(Account.PersonalStatus.CONFIRMED, b.personalStatus)
        assertEquals(w.owner.personalId, b.personalVaultId)
        assertEquals("personal", engine.vaultInfos().single { it.vaultId == w.owner.personalId }.type)
        // The account state comes back: the human's confirmation is now the designation.
        server.withholdState = false
        engine.sync()
        assertEquals(w.owner.personalId, designationOn(server, w.owner))
    }

    @Test
    fun m2_aSecondApplyWhileChangedOrWithheldNeverSwitches() {
        val w = world()
        val sharedWrap = w.owner.account.buildPersonalWrap(w.sharedId)
        // CONFIRMED on the personal vault; a keys refresh then serves a wrap for ANOTHER vault.
        val device = unlock(w.owner)
        assertEquals(Account.PersonalStatus.CONFIRMED, device.personalStatus)
        device.applyPersonalWrap(sharedWrap)
        assertEquals(Account.PersonalStatus.CHANGED, device.personalStatus, "a second apply for another vault is a notice, never a switch")
        assertEquals(w.owner.personalId, device.personalVaultId)
        assertEquals(w.sharedId, device.pendingPersonalChange?.vaultId)
        // The current vault re-served withdraws the change.
        device.applyPersonalWrap(w.owner.reg.personalWrap!!)
        assertEquals(Account.PersonalStatus.CONFIRMED, device.personalStatus)
        assertNull(device.pendingPersonalChange)
        // WITHHELD (the cached wrap in force) and then a wrap for another vault: the same.
        val withheld = unlock(w.owner, null)
        withheld.applyCachedPersonalWrap(w.owner.reg.personalWrap!!)
        assertEquals(Account.PersonalStatus.WITHHELD, withheld.personalStatus)
        withheld.applyPersonalWrap(sharedWrap)
        assertEquals(Account.PersonalStatus.CHANGED, withheld.personalStatus)
        assertEquals(w.owner.personalId, withheld.personalVaultId)
        // A wrap that does not open, applied while one is in force, keeps it (the A5b L-1 posture).
        val junked = unlock(w.owner)
        junked.applyPersonalWrap(PersonalWrap(w.sharedId, w.ownerWrap))
        assertEquals(Account.PersonalStatus.UNREADABLE_CACHED, junked.personalStatus)
        assertEquals(w.owner.personalId, junked.personalVaultId)
    }

    @Test
    fun m2_withPersonalAlwaysOutranksTheDesignationItReplaces() {
        val doc = AccountState.withPersonal(AccountState.empty("33333333-3333-4333-8333-333333333333"), "11111111-1111-4111-8111-111111111111", 100)
        assertEquals(PersonalDesignation("11111111-1111-4111-8111-111111111111", 100), doc.personal)
        val next = AccountState.withPersonal(doc, "22222222-2222-4222-8222-222222222222", 5) // a clock behind the other device's
        assertEquals("22222222-2222-4222-8222-222222222222", next.personal!!.vaultId)
        assertTrue(next.personal!!.at > 100, "a new designation is pushed past the one it replaces, whatever this clock says")
        assertFalse(next.isBlank())
        // A document without the key reads it as absent (older clients' documents).
        assertNull(AccountState.decode(doc.userId, AccountState.encode(AccountState.empty(doc.userId))).personal)
    }

    // ---- M-3: no silent re-issue; the record only annotates ----

    private suspend fun ownerWithCreatedVault(owner: Enrolled, deviceState: DeviceState? = null, cache: VaultCache = InMemoryVaultCache()): Triple<SyncEngine, FakeServer, String> {
        val server = FakeServer(SyncResponse(5, true, listOf(personalRow(owner)), listOf(personalGrant(owner)), emptyList(), emptyList()), keys = owner.keys, selfUserId = owner.userId)
        val engine = SyncEngine(api(server), owner.account, cache, deviceState = deviceState)
        engine.sync()
        val vaultId = engine.createSharedVault("Family")
        assertTrue(engine.ownsVault(vaultId))
        return Triple(engine, server, vaultId)
    }

    @Test
    fun m3_aRecordedPairIsNotReissuedWithoutAConfirmationAndOnlyAnnotatesTheRow() = runBlocking<Unit> {
        val owner = enroll("a9-owner")
        val member = enroll("a9-member")
        val (engine, server, vaultId) = ownerWithCreatedVault(owner)
        engine.accountState.pin(pinOf(member, "Member"))
        engine.addVaultMember(vaultId, member.userId, "writer", "member@example.com", legacyPinConfirmed = true)
        val rec = assertNotNull(engine.accountState.issued(vaultId, member.userId))

        // The server lists the member as legacy (a key-format migration). Nothing is signed without a tap.
        server.members[vaultId] = listOf(summary(owner, "Owner", "owner"), summary(member, "Member", "writer", legacy = true))
        val row = engine.loadLegacyGrants(vaultId).single()
        assertTrue(server.reissues.isEmpty(), "a recorded pair is NOT re-issued without the owner's confirmation")
        assertEquals(rec.at, row.previouslySharedAt, "the record only annotates: 'you shared this vault with them on …'")
        assertTrue(row.ownershipConfirmed)
        engine.sync()
        assertTrue(server.reissues.isEmpty(), "sync() signs nothing either")

        // The owner's tap re-issues.
        engine.confirmReissue(row)
        assertEquals(vaultId to member.userId, server.reissues.single().let { it.first to it.second })
        assertTrue(engine.legacyGrantRows(vaultId).isEmpty())
    }

    @Test
    fun m3_aWithheldTombstoneWithAStaleBlobNeverReissuesAndTheRemovingDeviceForgetsThePair() = runBlocking<Unit> {
        val owner = enroll("a9-owner")
        val member = enroll("a9-member")
        val dsA = MemoryDeviceState()
        val (a, server, vaultId) = ownerWithCreatedVault(owner, dsA)
        a.accountState.pin(pinOf(member, "Member"))
        a.addVaultMember(vaultId, member.userId, "writer", "member@example.com", legacyPinConfirmed = true)
        val withRecord = server.accountState to server.accountSeq
        a.removeVaultMember(vaultId, member.userId)
        assertEquals(1, server.removals.size)
        assertNull(a.accountState.issued(vaultId, member.userId))

        // The server withholds the tombstone: it replays the authentic PRE-removal blob (seq moved on, so no rollback
        // is detectable by a device that never saw the tombstone) and lists the removed member as legacy.
        server.accountState = withRecord.first
        server.accountSeq += 1
        server.members[vaultId] = listOf(summary(owner, "Owner", "owner"), summary(member, "Member", "writer", legacy = true))

        // Another device of the owner, fresh, pins the member here (a human ceremony) and opens the Legacy grants list.
        val c = SyncEngine(api(server), unlock(owner), InMemoryVaultCache(), deviceState = MemoryDeviceState())
        c.sync()
        c.accountState.pin(pinOf(member, "Member"))
        assertNotNull(c.accountState.issued(vaultId, member.userId), "the stale record is in force on the device that never saw the tombstone")
        val rowC = c.loadLegacyGrants(vaultId).single()
        assertTrue(server.reissues.isEmpty(), "the withheld tombstone buys the server nothing: no re-issue without a human")
        assertEquals(member.userId, rowC.userId)

        // The REMOVING device, restarted with its account-state memory lost but its own durable tombstone intact.
        dsA.set("acctstate.copy", null)
        dsA.set("acctstate.hw", null)
        val a2 = SyncEngine(api(server), unlock(owner), InMemoryVaultCache(), deviceState = dsA)
        a2.sync()
        assertNotNull(a2.accountState.issued(vaultId, member.userId), "the stale blob merged in (this device has no newer copy)")
        a2.accountState.pin(pinOf(member, "Member"))
        val rowA = a2.loadLegacyGrants(vaultId).single()
        assertNull(rowA.previouslySharedAt, "the removing device never offers the removed pair as previously shared")
        assertTrue(server.reissues.isEmpty())
    }

    // ---- L-2: the member-granted bit only from an actual adoption through a seal or a verified grant ----

    @Test
    fun l2_aJunkSealBesideTheOwnersOwnWrapDoesNotMarkTheVaultMemberGranted() = runBlocking<Unit> {
        val w = world(floor)
        // The server attaches a seal (to a key it made up) to the owner's own UVK-wrapped row. The wrap opens; the seal is junk.
        val junk = Bytes.toB64(SharedGrant.seal(crypto, crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey, w.sharedId, crypto.randomBytes(32)))
        val feed = w.feed.copy(grants = w.feed.grants.map { if (it.vaultId == w.sharedId) it.copy(sealedVk = junk) else it })
        val server = serverOf(w).also { it.feed = feed }
        val cache = InMemoryVaultCache()
        val ds = MemoryDeviceState()
        SyncEngine(api(server), unlock(w.owner), cache, deviceState = ds).sync()
        // Cold start: the cached row is replayed through addGrant (the moment the bit is decided).
        val engine = SyncEngine(api(server), unlock(w.owner), cache, deviceState = ds)
        engine.hydrate()
        engine.sync()
        assertFalse(engine.receivedAsMember(w.sharedId), "a junk seal beside an opened UVK wrap is not an adoption through a seal")
        assertNull(cache.clientState(SyncEngine.MEMBER_GRANTED_KEY), "nothing durable was written from the row's shape")
        val claim = engine.describeOwnership(w.sharedId)
        assertFalse(claim.receivedAsMember)
        engine.confirmOwnership(claim, password) // no transfer acknowledgement demanded of the genuine creator
        assertTrue(engine.ownsVault(w.sharedId))
        assertTrue(unlock(w.owner).openAccountState(server.accountState!!).memberReceived.isEmpty(), "account state carries no member-received evidence")

        // A relabelled role on an own-UVK-wrapped row sets nothing either.
        val relabelled = serverOf(w).also { s -> s.feed = w.feed.copy(grants = w.feed.grants.map { if (it.vaultId == w.sharedId) it.copy(role = "writer") else it }) }
        val e2 = SyncEngine(api(relabelled), unlock(w.owner), InMemoryVaultCache(), deviceState = MemoryDeviceState())
        e2.sync()
        assertFalse(e2.receivedAsMember(w.sharedId), "a label is not provenance")
    }

    // ---- L-1: a home is recorded only from a row this device applied ----

    @Test
    fun l1_aTombstoneOrAnUnheldRowServedFirstNeverHomesTheItem() = runBlocking<Unit> {
        for (tombstoneFirst in listOf(true, false)) {
            val victim = enroll("a9-victim")
            val p = victim.personalId
            val x = victim.account.newItemId()
            val doc = ItemDoc(type = "login", name = "Bank", login = LoginData(username = "me", password = "P-SECRET-0001"))
            val genuine = victim.account.encryptItem(p, x, doc).let { WireItem(x, p, 4, 1, 1, false, false, it.formatVersion, it.attachmentIds, it.blob) }
            // S: a vault this device holds NO key for (the server's, or a colluding co-member's).
            val s = victim.account.newItemId()
            val vkS = crypto.randomBytes(32)
            val sRow = WireVault(s, "shared", 7, Envelope.sealB64(crypto, vkS, """{"name":"Server"}""".encodeToByteArray(), Ad.vaultMeta(s)), 0)
            val first = if (tombstoneFirst) WireItem(x, s, 3, 1, 1, true, false, 1, emptyList(), null)
            else WireItem(x, s, 3, 1, 1, false, false, 1, emptyList(), Envelope.sealB64(crypto, vkS, """{"type":"login","name":"bait"}""".encodeToByteArray(), Ad.item(s, x, 1)))
            val feed = SyncResponse(9, true, listOf(personalRow(victim), sRow), listOf(personalGrant(victim)), listOf(first, genuine), emptyList())
            val server = FakeServer(feed, victim.keys, victim.userId)
            val cache = InMemoryVaultCache()
            val engine = SyncEngine(api(server), unlock(victim), cache, deviceState = MemoryDeviceState())
            engine.sync()
            val label = if (tombstoneFirst) "tombstone first" else "unheld row first"
            assertEquals(p, cache.itemHome(x), "$label: the home is the vault of the row this device APPLIED")
            assertEquals(doc, engine.items().single { it.itemId == x }.doc, "$label: the genuine row is in the working set")
            assertEquals(p, engine.items().single { it.itemId == x }.vaultId)
            assertTrue(engine.quarantinedItems().isEmpty(), "$label: nothing was quarantined")
            // Cold start replays the cached rows: still homed to P.
            val cold = SyncEngine(api(server), unlock(victim), cache, deviceState = MemoryDeviceState())
            cold.hydrate()
            assertEquals(p, cold.items().single { it.itemId == x }.vaultId, "$label: the home survives a hydrate")
        }
    }

    // ---- LOW items ----

    @Test
    fun low_aVerifiedTransferAwayIsReleasedEvenWhenTheFirstAccountStateWriteFails() = runBlocking<Unit> {
        val owner = enroll("a9-owner")
        val member = enroll("a9-member")
        val (engine, server, vaultId) = ownerWithCreatedVault(owner)
        val wrapHash = Bytes.toHexLower(crypto.sha256("member-wrap".encodeToByteArray()))
        val offerId = "11111111-1111-4111-8111-111111111111"
        val lifecycle = owner.account.lifecycleKeyFor(vaultId)
        val proof = LifecycleProof.acceptFromHash(crypto, lifecycle, vaultId, offerId, member.userId, 1, wrapHash)
        val rev = server.feed.rev + 1
        server.feed = server.feed.copy(
            rev = rev, full = true,
            vaults = server.feed.vaults.map { if (it.vaultId == vaultId) it.copy(rev = rev, lastTransfer = TransferRecord(offerId, member.userId, proof, 1, wrapHash)) else it },
        )
        server.failStatePut = true
        engine.sync()
        assertFalse(engine.ownsVault(vaultId), "the release is in force on this device at once")
        assertTrue(unlock(owner).openAccountState(server.accountState!!).owns(vaultId), "the server still holds the old record (the write failed)")
        server.failStatePut = false
        engine.sync()
        assertFalse(unlock(owner).openAccountState(server.accountState!!).owns(vaultId), "the release is retried, not dropped")
    }

    @Test
    fun low_aRenameRefusesAKeyThatContradictsTheVouch() {
        val w = world()
        val device = unlock(w.owner)
        device.rememberHeldKey(w.sharedId, "ab".repeat(32)) // this device remembers ANOTHER key for the vault
        device.addGrant(WireGrant(w.sharedId, w.owner.userId, "owner", w.ownerWrap, 3, null))
        assertTrue(device.hasVault(w.sharedId) && device.heldKeyContradictsVouch(w.sharedId), "the own wrap is used but flagged")
        assertFailsWith<VaultKeyNotVerifiedException>("INV-WRITE-KEY holds for the vault name too") { device.buildRenameMeta(w.sharedId, w.metaBlob, "Renamed") }
    }

    // ---- A9 review round (MERGE AFTER FIXES) ----

    /** LOW-4: a fresh device served an OLDER authentic account-state blob together with the matching older wrap. */
    @Test
    fun review_low4_aFreshDeviceServedAReplayedOlderStateAndWrapPairStaysProposed() = runBlocking<Unit> {
        val w = world(floor)
        val server = serverOf(w)
        val a = SyncEngine(api(server), w.owner.account, InMemoryVaultCache(), deviceState = MemoryDeviceState())
        a.sync()
        val olderState = server.accountState to server.accountSeq // designation = the personal vault, wrap = the personal wrap
        a.redesignatePersonalVault(a.proposePersonalVault(w.sharedId), password)
        assertEquals(w.sharedId, designationOn(server, w.owner))
        // The server replays the older pair to a fresh device: the blob is authentic and its designation names the wrap.
        server.accountState = olderState.first
        server.accountSeq = olderState.second + 5
        val b = unlock(w.owner, w.owner.reg.personalWrap)
        val engineB = SyncEngine(api(server), b, InMemoryVaultCache(), deviceState = MemoryDeviceState())
        engineB.sync()
        assertEquals(Account.PersonalStatus.PROPOSED, b.personalStatus, "a matching designation does not auto-confirm on a device with no high-water mark of its own")
        assertEquals("", b.personalVaultId)
        assertTrue(server.personalWrapPuts.size == 1 && engineB.vaultInfos().none { it.type == "personal" })
    }

    /** LOW-1: the reauth derivation PROVES the password against the session UVK, so a quick-unlock session whose served salt
     *  the server chose derives nothing for it. */
    @Test
    fun review_low1_theReauthProvesThePasswordAgainstTheSessionUvk() {
        val owner = enroll("a9-qu", floor)
        val uvk = uvkOf(owner)
        // A biometric/PIN unlock: the UVK comes from the platform, and the server serves the AccountKeys at that moment —
        // here a salt and a wrap of its own choosing (it cannot wrap OUR UVK under a salt we never derived for).
        val serverSalt = Bytes.toB64(crypto.randomBytes(16))
        val junkWrap = Envelope.sealB64(crypto, crypto.randomBytes(32), uvk, Ad.uvk(owner.userId))
        val chosen = owner.keys.copy(kdfSalt = serverSalt, wrappedUvk = junkWrap)
        val quick = Account.unlockWithUvk(owner.userId, uvk.copyOf(), chosen, crypto)
        assertFailsWith<ReauthFailedException>("the served salt is the session's, but the password proves nothing under it") { quick.reauthAuthKey(password, chosen) }
        // The same quick-unlock session with the REAL keys served passes (biometric users can still reauth)...
        val quickReal = Account.unlockWithUvk(owner.userId, uvk.copyOf(), owner.keys, crypto)
        assertEquals(expectedAuthKey(owner), quickReal.reauthAuthKey(password, owner.keys))
        // ...and a wrong password derives nothing for the server either (proved locally, never sent to find out).
        assertFailsWith<ReauthFailedException> { quickReal.reauthAuthKey("not the password", owner.keys) }
        // A password-unlock session with the real keys passes, as before.
        assertEquals(expectedAuthKey(owner), unlock(owner).reauthAuthKey(password, owner.keys))
    }

    /** LOW-2: a default save while no personal vault is in force is refused with "Choose a vault for this item.", never
     *  reaching the seal with an empty vault id (which surfaced as "wrong master password"). */
    @Test
    fun review_low2_aDefaultSaveWhileProposedIsRefusedWithChooseAVault() = runBlocking<Unit> {
        val w = world()
        val server = serverOf(w)
        server.withholdState = true
        val b = unlock(w.owner)
        val engine = SyncEngine(api(server), b, InMemoryVaultCache(), deviceState = MemoryDeviceState())
        engine.sync()
        assertEquals(Account.PersonalStatus.PROPOSED, b.personalStatus)
        val doc = ItemDoc(type = "login", name = "Bank", login = LoginData(username = "me", password = "pw"))
        val e = assertFailsWith<NoPersonalVaultException> { engine.save(null, doc) }
        assertEquals(HouseholdCopy.NO_PERSONAL_VAULT, e.message)
        assertEquals(HouseholdCopy.NO_PERSONAL_VAULT, HouseholdCopy.forSaveError(e))
        assertFailsWith<NoPersonalVaultException> { engine.importAll(emptyList()) }
        assertFailsWith<NoPersonalVaultException> { engine.importProjections() }
        assertTrue(engine.items().isEmpty() && server.pushed.isEmpty(), "nothing was sealed anywhere")
        // An explicit destination still works.
        engine.save(null, doc, vaultId = w.sharedId)
        assertEquals(w.sharedId, server.pushed.single().vaultId)
    }

    /** Captures every private key a keypair derivation hands out (the probe Account's identity and signing secrets). */
    private class RecordingKeys(private val d: CryptoProvider) : CryptoProvider by d {
        val privates = ArrayList<Pair<ByteArray, ByteArray>>() // (live, snapshot)
        override fun boxKeypairFromSeed(seed: ByteArray): KeyPairBytes = d.boxKeypairFromSeed(seed).also { privates += it.privateKey to it.privateKey.copyOf() }
        override fun signKeypairFromSeed(seed: ByteArray): KeyPairBytes = d.signKeypairFromSeed(seed).also { privates += it.privateKey to it.privateKey.copyOf() }
    }

    @Test
    fun low_recoverWipesTheProbeAccountsIdentityAndSigningSecrets() {
        val r = enroll("a9-recover")
        val verify = RecoveryVerifyResponse(
            userId = r.userId, recoveryTicket = "opaque-ticket",
            recoveryWrappedUvk = r.reg.memberRecovery!!.recoveryWrappedUvk,
            encryptedIdentitySeed = r.reg.encryptedIdentitySeed, identityPub = r.reg.identityPub,
        )
        val rec = RecordingKeys(crypto)
        val commit = Account.recover(r.recoverySecret, verify, "a brand new master password", kdf, rec)
        assertTrue(commit.newWrappedUvk.isNotEmpty())
        assertEquals(2, rec.privates.size, "the probe derives one identity keypair and one signing keypair")
        for ((live, at) in rec.privates) {
            assertTrue(at.any { it != 0.toByte() }, "captured non-zero")
            assertTrue(live.all { it == 0.toByte() }, "the probe account's secret key was not wiped")
        }
    }
}
