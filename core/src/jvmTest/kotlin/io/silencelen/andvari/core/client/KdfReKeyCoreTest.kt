package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.PasswordChangeRequest
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The shared F61 re-key (audit H85). This suite is the whole reason the hoist was worth doing:
 * before it, the ~40-line routine existed twice — Android's `KdfReKey` and an inline copy in the
 * desktop's `DesktopState` — and NEITHER copy had a single test. A silent re-key of the master key
 * that nothing exercises is the worst possible combination: when it breaks, it breaks at the next
 * unlock, on a device that is now the only place the old params are written down, and it reads to
 * the household as "I forgot my password".
 *
 * What is pinned here is the CONTRACT both natives now inherit, not an implementation detail:
 *  - the request the server sees (old authKey proves possession; new salt/params/wrappedUvk),
 *  - the invariant that the UVK is re-WRAPPED and never re-derived (spec 01 §4/§7),
 *  - that the keys handed to [KdfReKeyCore.maybeUpgrade]'s `persist` actually unlock the account
 *    offline afterwards — the design §4 step 3 rule, stated as a real `Account.unlock`,
 *  - that persist happens ONLY after the server accepted,
 *  - that the [KdfUpgrade.shouldUpgrade] fence is consulted (a weakening policy re-keys nothing),
 *  - that every failure is swallowed (best-effort: the unlock already succeeded),
 *  - and that the new MK, the new wrapKey and the UVK egress copy are zeroed (H80).
 *
 * The account is enrolled at deliberately cheap Argon2id params (the test-speed convention in
 * AccountZeroizationTest); the POLICY has to be a real one because the fence refuses anything
 * below 64 MiB / t=3, so each re-keying case pays two honest derivations.
 */
class KdfReKeyCoreTest {

    private val real = createCryptoProvider()
    private val password = "correct horse battery staple"
    private val cheap = KdfParams(ops = 1, memBytes = 8192) // account's OLD params — test-speed
    private val policyParams = KdfParams.DEFAULT           // 64 MiB / t=3 — the fence floor, inclusive
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val enrolled = Account.enroll("inv", "a@x.com", "a", password, cheap, null, null, "dev", real)
    private val userId = enrolled.request.userId
    private val account = enrolled.account
    private val keys = AccountKeys(
        kdfSalt = enrolled.request.kdfSalt,
        kdfParams = enrolled.request.kdfParams,
        wrappedUvk = enrolled.request.wrappedUvk,
        encryptedIdentitySeed = enrolled.request.encryptedIdentitySeed,
        identityPub = enrolled.request.identityPub,
        escrowFingerprint = "",
    )

    /** Captures what the client actually PUT, and answers with [status]. */
    private class Server(val status: HttpStatusCode = HttpStatusCode.NoContent) {
        var puts = 0
        var lastPath: String? = null
        var lastBody: String? = null
    }

    private fun apiFor(server: Server): AndvariApi {
        val engine = MockEngine { request ->
            server.puts++
            server.lastPath = request.url.encodedPath
            server.lastBody = request.body.toByteArray().decodeToString()
            respond("", server.status, headersOf(HttpHeaders.ContentType, "application/json"))
        }
        return AndvariApi("http://fake", HttpClient(engine))
    }

    private fun policy(p: KdfParams) = ClientPolicy(kdfParams = p)

    private fun rekey(
        server: Server,
        policyKdf: KdfParams = policyParams,
        crypto: CryptoProvider? = null,
        accountKeys: AccountKeys = keys,
        persist: (AccountKeys) -> Unit,
    ) = runBlocking {
        KdfReKeyCore.maybeUpgrade(
            api = apiFor(server),
            userId = userId,
            password = password,
            keys = accountKeys,
            policy = policy(policyKdf),
            account = account,
            crypto = crypto,
            persist = persist,
        )
    }

    // ---- the happy path ----

    @Test
    fun rekeyReWrapsTheSameUvkAndTellsTheCacheParamsThatStillUnlock() {
        val server = Server()
        var persisted: AccountKeys? = null
        rekey(server) { persisted = it }

        assertEquals(1, server.puts, "exactly one write — the re-key is a single PUT")
        assertEquals("/api/v1/account/password", server.lastPath)
        val req = json.decodeFromString(PasswordChangeRequest.serializer(), server.lastBody!!)

        // Possession of the CURRENT password is proved with the CURRENT salt/params — a re-key is
        // an authenticated change, not a takeover the server has to take on trust.
        assertEquals(Account.deriveAuthKey(password, keys.kdfSalt, keys.kdfParams, real), req.currentAuthKey)

        // The move is to the policy's params under a FRESH salt (reusing the old salt would leave
        // the pre-upgrade authKey derivable from a captured MK).
        assertEquals(policyParams, req.newKdfParams)
        assertNotEquals(keys.kdfSalt, req.newKdfSalt, "a re-key must mint a new salt")
        assertEquals(KdfParams.SALT_BYTES, Bytes.fromB64(req.newKdfSalt).size)

        // The new authKey is exactly what the new password/salt/params derive — i.e. the server can
        // authenticate the next sign-in against it.
        assertEquals(
            Account.deriveAuthKey(password, req.newKdfSalt, req.newKdfParams, real),
            req.newAuthKey,
        )

        // spec 01 §4/§7: the UVK is RE-WRAPPED, never re-derived — every sealed grant and vault key
        // hangs off it. Open the new envelope under the new wrapKey and compare to the live UVK.
        val mkNew = Keys.masterKey(real, password, Bytes.fromB64(req.newKdfSalt), req.newKdfParams)
        val unwrapped = Envelope.openB64(real, Keys.wrapKey(real, mkNew), req.newWrappedUvk, Ad.uvk(userId))
        assertContentEquals(account.uvkCopyForPlatformWrap(), unwrapped, "the UVK must survive a KDF upgrade unchanged")

        // design §4 step 3, as a fact rather than a comment: the row handed to persist is the one
        // an OFFLINE unlock will derive from, so it must open the account with the same password.
        val p = persisted ?: error("persist must be called after the server accepts")
        assertEquals(req.newKdfSalt, p.kdfSalt)
        assertEquals(req.newKdfParams, p.kdfParams)
        assertEquals(req.newWrappedUvk, p.wrappedUvk)
        assertEquals(keys.encryptedIdentitySeed, p.encryptedIdentitySeed, "only the KDF-derived fields move")
        assertEquals(keys.identityPub, p.identityPub)
        val reopened = Account.unlock(userId, password, p, real)
        assertContentEquals(
            account.uvkCopyForPlatformWrap(),
            reopened.uvkCopyForPlatformWrap(),
            "the persisted keys must unlock the SAME account — this is what a stale cache breaks",
        )
    }

    // ---- the gate ----

    @Test
    fun aPolicyThatIsNotAnUpgradeRekeysNothing() {
        // Two legs, and R45 made the second one real: the loop used to iterate
        // `KdfParams(ops = 1, memBytes = 8192)` and `keys.kdfParams`, which are THE SAME VALUE
        // (the account is enrolled at `cheap` for test speed). Both passes were therefore the
        // below-the-floor refusal, and the "equal-params no-op" the comment claimed — the leg
        // that matters for an account already AT policy, i.e. every account after the first
        // upgrade — was never driven at all.
        //
        // Leg 1: below the sanity floor (spec 05 T1 — a hostile server proposing weaker Argon2id).
        // Leg 2: params EQUAL to the account's and inside the fence. `shouldUpgrade` demands a
        // strict increase on at least one axis, so equal is a no-op, not an upgrade. Driven by
        // handing the routine an account row already at DEFAULT — no Argon2id runs, because the
        // gate refuses before any key derivation, which is exactly the property under test.
        val legs = listOf(
            KdfParams(ops = 1, memBytes = 8192) to keys,
            KdfParams.DEFAULT to keys.copy(kdfParams = KdfParams.DEFAULT),
        )
        for ((p, k) in legs) {
            val server = Server()
            var persisted: AccountKeys? = null
            rekey(server, policyKdf = p, accountKeys = k) { persisted = it }
            assertEquals(0, server.puts, "no upgrade must mean no request (policy=$p, account=${k.kdfParams})")
            assertNull(persisted, "no upgrade must mean no cache write (policy=$p, account=${k.kdfParams})")
        }
    }

    // ---- best-effort ----

    @Test
    fun aServerRefusalIsSwallowedAndTheCacheKeepsTheOldParams() {
        val server = Server(HttpStatusCode.Conflict)
        var persisted: AccountKeys? = null
        rekey(server) { persisted = it } // must NOT throw — the unlock already succeeded
        assertEquals(1, server.puts)
        assertNull(
            persisted,
            "caching params the server refused would break the NEXT offline unlock — persist is " +
                "strictly after the accept",
        )
    }

    @Test
    fun aPersistThatThrowsIsSwallowedToo() {
        val server = Server()
        rekey(server) { throw IllegalStateException("disk full") }
        assertEquals(1, server.puts, "the server change stands; a local cache failure is not the user's problem")
    }

    // ---- H80 zeroization ----

    @Test
    fun theNewMasterKeyWrapKeyAndUvkCopyAreZeroed() {
        val rec = Recording(real)
        val server = Server()
        rekey(server, crypto = rec) { }
        assertEquals(1, server.puts, "guard: the zeroization claim is only meaningful if the re-key ran")

        // Two derivations: the NEW master key, and the one deriveAuthKey makes to prove possession.
        assertEquals(2, rec.argon.size)
        rec.argon.forEachIndexed { i, s -> assertWiped(s, "master key #$i") }
        // The wrapKey is the AEAD key of the UVK seal; the UVK egress copy is its plaintext.
        val seal = rec.seals.single { it.ad.contentEquals(Ad.uvk(userId)) }
        assertWiped(seal.key, "new wrapKey")
        assertWiped(seal.plaintext, "UVK egress copy")
        // ...and the session's own UVK is untouched: the wipe is targeted, not blanket.
        assertTrue(account.uvkCopyForPlatformWrap().any { it != 0.toByte() }, "the live UVK must survive")
    }

    private class Seen(val live: ByteArray, val at: ByteArray)
    private class Seal(val ad: ByteArray, val key: Seen, val plaintext: Seen)

    /** Delegates every primitive to the real provider; captures REFERENCES (plus a snapshot of the
     *  bytes at that moment), because zeroization of a local is invisible from outside. Same idiom
     *  as AccountZeroizationTest, whose copy is private to that class. */
    private class Recording(private val d: CryptoProvider) : CryptoProvider by d {
        val argon = ArrayList<Seen>()
        val seals = ArrayList<Seal>()

        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray =
            d.argon2id(password, salt, outLen, opsLimit, memLimitBytes).also { argon += Seen(it, it.copyOf()) }

        override fun aeadEncrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, ad: ByteArray): ByteArray {
            seals += Seal(ad.copyOf(), Seen(key, key.copyOf()), Seen(plaintext, plaintext.copyOf()))
            return d.aeadEncrypt(key, nonce, plaintext, ad)
        }
    }

    private fun assertWiped(s: Seen, what: String) {
        assertTrue(s.at.any { it != 0.toByte() }, "$what was already all-zero when captured — nothing to prove")
        assertFalse(s.live.any { it != 0.toByte() }, "$what was not zeroed after use")
    }
}
