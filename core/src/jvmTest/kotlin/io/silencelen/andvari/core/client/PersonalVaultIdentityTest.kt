package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.PersonalWrap
import io.silencelen.andvari.core.model.PersonalWrapPut
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A §4 / §8.5 (branch A5): "personal" is a client-held, UVK-authenticated
 * property (`AccountKeys.personalWrap`), never a server `type` label or `role`.
 *
 * The A1 residue this closes: a hostile server that strips a vault's seal and relabels `role=owner`, or (the
 * simplest form) relabels an OWNER-created shared vault `type=personal`, used to make that vault the
 * default save destination, the import target and the usage-ledger key, all readable by co-members.
 */
class PersonalVaultIdentityTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(email: String): Enrolled {
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

    /** A scripted server: the sync feed, plus capture of every personal-wrap PUT. */
    private class FakeServer(val feed: SyncResponse) {
        val personalWrapPuts = mutableListOf<String>()
        var personalWrapStatus = HttpStatusCode.OK
    }

    private fun api(server: FakeServer): AndvariApi {
        val json = this.json
        val engine = MockEngine { req ->
            val path = req.url.encodedPath
            val ct = headersOf(HttpHeaders.ContentType, "application/json")
            when {
                path == "/api/v1/sync" -> respond(json.encodeToString(SyncResponse.serializer(), server.feed), HttpStatusCode.OK, ct)
                path == "/api/v1/account/personal-wrap" && req.method == HttpMethod.Put -> {
                    server.personalWrapPuts.add((req.body as TextContent).text)
                    if (server.personalWrapStatus == HttpStatusCode.OK) respond("ok", HttpStatusCode.OK)
                    else respond("""{"error":"personal_wrap_exists","message":"conflict"}""", server.personalWrapStatus, ct)
                }
                else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
            }
        }
        return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
    }

    private fun personalRow(e: Enrolled, type: String = "personal") =
        WireVault(e.reg.personalVault.vaultId, type, 2, e.reg.personalVault.metaBlob, 0)

    private fun personalGrant(e: Enrolled) =
        WireGrant(e.reg.personalVault.vaultId, e.reg.userId, "owner", e.reg.personalVault.wrappedVk, 2, null)

    /**
     * THE A1 RESIDUE, in its simplest form: the victim OWNS a shared vault (its grant is a bare UVK wrap on
     * an owner row, exactly like the personal one), the server relabels it `personal` and withholds the
     * real personal row. Before A5 that vault became the personal vault. Now there is no personal wrap
     * and the §8.5 rule does not auto-pick a vault not named "Personal": no personal vault, fail closed.
     */
    @Test
    fun aRelabelledOwnerSharedVaultIsNotPersonal_onSyncOrHydrate() = runBlocking<Unit> {
        val victim = enroll("owner-relabel@example.com")
        val shared = victim.account.buildCreateSharedVault("Household")
        val feed = SyncResponse(
            rev = 9, full = true,
            vaults = listOf(WireVault(shared.vaultId, "personal", 4, shared.request.metaBlob, 0)),
            grants = listOf(WireGrant(shared.vaultId, victim.reg.userId, "owner", shared.request.wrappedVk, 4, null)),
            items = emptyList(), removedGrants = emptyList(),
        )
        val server = FakeServer(feed)
        val cache = InMemoryVaultCache()

        val fresh = Account.unlock(victim.reg.userId, password, victim.keys, crypto)
        SyncEngine(api(server), fresh, cache).sync()
        assertTrue(fresh.hasVault(shared.vaultId))
        assertNotEquals(shared.vaultId, fresh.personalVaultId, "a server label must never make an owned shared vault personal")
        assertEquals("", fresh.personalVaultId)
        assertTrue(runCatching { fresh.sealUsage("{}".encodeToByteArray()) }.isFailure, "no personal vault ⇒ no ledger under a shared VK")

        val restarted = Account.unlock(victim.reg.userId, password, victim.keys, crypto)
        SyncEngine(api(server), restarted, cache).hydrate()
        assertNotEquals(shared.vaultId, restarted.personalVaultId, "hydrate() must refuse the same relabel")
    }

    /** With the personal wrap in AccountKeys, the server's labels are irrelevant: it can swap them both. */
    @Test
    fun thePersonalWrapDecidesEvenWhenTheServerSwapsLabels() = runBlocking<Unit> {
        val victim = enroll("wrap-decides@example.com")
        val housemate = enroll("wrap-mate@example.com")
        val owned = victim.account.buildCreateSharedVault("Personal") // even NAMED Personal
        val memberVault = housemate.account.buildCreateSharedVault("Household")
        // The A1 residue proper: a member self-wrap (bare UVK wrap of OURS) whose seal the server stripped
        // and whose role it relabelled owner.
        val selfWrap = Envelope.sealB64(crypto, victim.account.uvkCopyForPlatformWrap(), crypto.randomBytes(32), Ad.vk(memberVault.vaultId, victim.reg.userId))
        val feed = SyncResponse(
            rev = 9, full = true,
            vaults = listOf(
                personalRow(victim, type = "shared"),
                WireVault(owned.vaultId, "personal", 4, owned.request.metaBlob, 0),
                WireVault(memberVault.vaultId, "personal", 5, memberVault.request.metaBlob, 0),
            ),
            grants = listOf(
                personalGrant(victim),
                WireGrant(owned.vaultId, victim.reg.userId, "owner", owned.request.wrappedVk, 4, null),
                WireGrant(memberVault.vaultId, victim.reg.userId, "owner", selfWrap, 5, null),
            ),
            items = emptyList(), removedGrants = emptyList(),
        )
        val keys = victim.keys.copy(personalWrap = victim.reg.personalWrap)
        val account = Account.unlock(victim.reg.userId, password, keys, crypto)
        assertEquals(Account.PersonalStatus.CONFIRMED, account.personalStatus)
        val engine = SyncEngine(api(FakeServer(feed)), account, InMemoryVaultCache())
        engine.sync()
        assertEquals(victim.reg.personalVault.vaultId, account.personalVaultId)
        val types = engine.vaultInfos().associate { it.vaultId to it.type }
        assertEquals("personal", types[victim.reg.personalVault.vaultId], "type is derived from the wrap, not the label")
        assertEquals("shared", types[owned.vaultId])
        assertEquals("shared", types[memberVault.vaultId])
        assertNull(engine.personalVaultChoices)
    }

    /** A served personal wrap that does not open is an anomaly: no personal vault, no label fallback, and no
     *  migration auto-pick papering over it (only a re-designation with a password reauth replaces it). */
    @Test
    fun anUnreadablePersonalWrapFailsClosed() = runBlocking<Unit> {
        val victim = enroll("unreadable@example.com")
        // The server re-serves the OWNER wrap (Ad.vk) as the personal wrap: it never opens under vk-personal.
        val forged = PersonalWrap(victim.reg.personalVault.vaultId, victim.reg.personalVault.wrappedVk)
        val account = Account.unlock(victim.reg.userId, password, victim.keys.copy(personalWrap = forged), crypto)
        assertEquals(Account.PersonalStatus.UNREADABLE, account.personalStatus)
        val server = FakeServer(SyncResponse(9, true, listOf(personalRow(victim)), listOf(personalGrant(victim)), emptyList(), emptyList()))
        SyncEngine(api(server), account, InMemoryVaultCache()).sync()
        assertEquals("", account.personalVaultId)
        assertTrue(server.personalWrapPuts.isEmpty(), "no automatic re-mint over an unreadable wrap")
    }

    /** §8.5 honest migration: one vault labelled personal, our own bare UVK wrap, named "Personal" → minted
     *  automatically, stored, and the stored wrap opens under vk-personal to that vault's key. */
    @Test
    fun theMigrationPicksTheRightVaultAndStoresItsWrap() = runBlocking<Unit> {
        val victim = enroll("migrate@example.com")
        val other = victim.account.buildCreateSharedVault("Household")
        val server = FakeServer(
            SyncResponse(
                9, true,
                listOf(personalRow(victim), WireVault(other.vaultId, "shared", 3, other.request.metaBlob, 0)),
                listOf(personalGrant(victim), WireGrant(other.vaultId, victim.reg.userId, "owner", other.request.wrappedVk, 3, null)),
                emptyList(), emptyList(),
            ),
        )
        val account = Account.unlock(victim.reg.userId, password, victim.keys, crypto) // pre-A5 account: no wrap
        assertEquals(Account.PersonalStatus.ABSENT, account.personalStatus)
        val stored = mutableListOf<PersonalWrap>()
        val engine = SyncEngine(api(server), account, InMemoryVaultCache()).also { it.onPersonalWrapStored = { w -> stored.add(w) } }
        engine.sync()
        assertEquals(victim.reg.personalVault.vaultId, account.personalVaultId)
        assertEquals(Account.PersonalStatus.CONFIRMED, account.personalStatus)
        val put = json.decodeFromString(PersonalWrapPut.serializer(), server.personalWrapPuts.single())
        assertEquals(victim.reg.personalVault.vaultId, put.vaultId)
        assertNull(put.currentAuthKey, "a first set needs no reauth")
        val vk = Envelope.openB64(crypto, victim.account.uvkCopyForPlatformWrap(), put.wrappedVk, Ad.vkPersonal(put.vaultId, victim.reg.userId))
        val ownerVk = Envelope.openB64(crypto, victim.account.uvkCopyForPlatformWrap(), victim.reg.personalVault.wrappedVk, Ad.vk(put.vaultId, victim.reg.userId))
        assertTrue(vk.contentEquals(ownerVk))
        assertEquals(1, stored.size)
    }

    /** Ambiguity asks; the answer and a later re-designation (Q9) only accept a vault keyed from our own UVK
     *  wrap, and a re-designation carries the fresh password proof. */
    @Test
    fun ambiguityAsksAndReDesignationIsAllowedWithReauth() = runBlocking<Unit> {
        val victim = enroll("ask@example.com")
        val housemate = enroll("ask-mate@example.com")
        val owned = victim.account.buildCreateSharedVault("Personal")
        val sealedVault = housemate.account.buildCreateSharedVault("Personal")
        val sealedVk = housemate.account.wrapVkForMember(victim.account.identityPub, sealedVault.vaultId)
        val server = FakeServer(
            SyncResponse(
                9, true,
                listOf(personalRow(victim), WireVault(owned.vaultId, "personal", 3, owned.request.metaBlob, 0), WireVault(sealedVault.vaultId, "personal", 4, sealedVault.request.metaBlob, 0)),
                listOf(
                    personalGrant(victim),
                    WireGrant(owned.vaultId, victim.reg.userId, "owner", owned.request.wrappedVk, 3, null),
                    WireGrant(sealedVault.vaultId, victim.reg.userId, "writer", "", 4, sealedVk),
                ),
                emptyList(), emptyList(),
            ),
        )
        val account = Account.unlock(victim.reg.userId, password, victim.keys, crypto)
        val engine = SyncEngine(api(server), account, InMemoryVaultCache())
        engine.sync()
        assertEquals("", account.personalVaultId, "two candidates: no automatic pick, no default destination")
        assertEquals(setOf(victim.reg.personalVault.vaultId, owned.vaultId), engine.personalVaultChoices!!.map { it.vaultId }.toSet(), "the seal-delivered vault is never offered")
        assertTrue(server.personalWrapPuts.isEmpty())
        assertFailsWith<Exception> { engine.designatePersonalVault(sealedVault.vaultId, null) }

        engine.designatePersonalVault(victim.reg.personalVault.vaultId, null)
        assertEquals(victim.reg.personalVault.vaultId, account.personalVaultId)
        assertNull(engine.personalVaultChoices)

        // Q9: a wrong pick is not permanent. The re-designation sends the fresh reauth proof.
        assertEquals(setOf(victim.reg.personalVault.vaultId, owned.vaultId), engine.redesignationChoices().map { it.vaultId }.toSet())
        engine.designatePersonalVault(owned.vaultId, "fresh-auth-key")
        assertEquals(owned.vaultId, account.personalVaultId)
        assertEquals("fresh-auth-key", json.decodeFromString(PersonalWrapPut.serializer(), server.personalWrapPuts.last()).currentAuthKey)
    }

    /** Enrolment sends the wrap with the register, and it opens under vk-personal for the new account. */
    @Test
    fun enrolmentSendsThePersonalWrap() {
        val e = enroll("enrol-wrap@example.com")
        val pw = e.reg.personalWrap!!
        assertEquals(e.reg.personalVault.vaultId, pw.vaultId)
        val account = Account.unlock(e.reg.userId, password, e.keys.copy(personalWrap = pw), crypto)
        assertEquals(Account.PersonalStatus.CONFIRMED, account.personalStatus)
        assertEquals(pw.vaultId, account.personalVaultId)
        assertEquals(Account.PersonalStatus.CONFIRMED, e.account.personalStatus)
    }
}
