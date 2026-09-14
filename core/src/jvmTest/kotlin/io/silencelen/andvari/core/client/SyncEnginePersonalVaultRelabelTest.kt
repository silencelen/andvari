package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Audit H64, engine leg: the refusal must hold on the path a real client actually takes — a full
 * `sync()` and then a cold-start `hydrate()` off the durable cache — not only when
 * [Account.setPersonalVault] is called directly. Both call sites read the server's plaintext
 * `Vault.type`, which is bound into no AD, so the feed below is exactly what a T1 server can
 * serve today: the victim's real personal row withheld, and the household's SHARED vault (whose
 * key reached the victim as a `sealedVk` member grant) relabelled `type="personal"`.
 *
 * If either site adopted it, `usageKey = HKDF(VK, "andvari/v1|usage")` would be a key every other
 * member of that vault holds, and the victim's usage ledger — itemId → {lastUsedAt, useCount} for
 * every login they touch — would be readable by a colluding housemate (spec 02 §8.2).
 * [UsagePersonalVaultProvenanceTest] pins the crypto consequence; this pins the wiring.
 */
class SyncEnginePersonalVaultRelabelTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192) // test-speed argon2id
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

    @Test
    fun aServerRelabelledMemberVaultIsNotAdoptedByEitherSyncOrHydrate() = runBlocking<Unit> {
        val victim = enroll("relabel-victim@example.com")
        val housemate = enroll("relabel-mate@example.com")
        val shared = housemate.account.buildCreateSharedVault("Household")
        val sealedVk = housemate.account.wrapVkForMember(victim.account.identityPub, shared.vaultId)

        val feed = SyncResponse(
            rev = 9, full = true,
            // THE LIE: the victim's real personal row is absent and the shared vault claims its place.
            vaults = listOf(WireVault(shared.vaultId, "personal", 4, shared.request.metaBlob, 0)),
            grants = listOf(WireGrant(shared.vaultId, victim.reg.userId, "writer", "", 4, sealedVk)),
            items = emptyList(), removedGrants = emptyList(),
        )
        val engine = MockEngine { req ->
            if (req.url.encodedPath == "/api/v1/sync") {
                respond(json.encodeToString(SyncResponse.serializer(), feed), HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json"))
            } else {
                respond("""{"error":"not_found","message":"unexpected ${req.url.encodedPath}"}""", HttpStatusCode.NotFound, headersOf(HttpHeaders.ContentType, "application/json"))
            }
        }
        val api = AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
        val cache = InMemoryVaultCache()

        // Leg 1 — the live pull.
        val fresh = Account.unlock(victim.reg.userId, password, victim.keys, crypto)
        SyncEngine(api, fresh, cache).sync()
        assertTrue(fresh.hasVault(shared.vaultId), "the member grant still opens the vault — this is a refusal to ADOPT, not to join")
        assertEquals("", fresh.personalVaultId, "sync() must not adopt a member-granted vault the server labels personal")
        assertTrue(runCatching { fresh.sealUsage("{}".encodeToByteArray()) }.isFailure, "no personal vault ⇒ no ledger (render '—'), never a ledger under the household VK")

        // Leg 2 — cold start off the same durable cache, where the rows are replayed from disk and
        // the provenance has to be rebuilt from the persisted grant before the vault row is read.
        val restarted = Account.unlock(victim.reg.userId, password, victim.keys, crypto)
        SyncEngine(api, restarted, cache).hydrate()
        assertTrue(restarted.keyArrivedByMemberGrant(shared.vaultId), "hydrate replays grants before vaults, so provenance is known in time")
        assertEquals("", restarted.personalVaultId, "hydrate() must refuse the same relabel")
    }
}
