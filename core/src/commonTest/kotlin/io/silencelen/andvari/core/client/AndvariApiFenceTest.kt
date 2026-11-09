package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.LoginRequest
import io.silencelen.andvari.core.model.PreloginResponse
import io.silencelen.andvari.core.model.SessionResponse
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * H1 (spec 05 T1 / spec 01 §9): the client rejects SERVER-SUPPLIED KDF params outside the sanity
 * fence at every ingestion boundary (prelogin / client-policy / login+register session / account
 * keys), so a hostile or misconfigured server can neither WEAKEN the master-password KDF (which
 * would make the transmitted authKey offline-crackable) nor inflate it into a per-unlock DoS. The
 * fence lives at AndvariApi, NOT in Keys.masterKey — the cross-impl vectors legitimately derive
 * below this floor. Pins the fence numbers to the web (keys.ts) + extension (crypto.ts) copies.
 */
class AndvariApiFenceTest {
    private val json = Json { encodeDefaults = true }
    private val weak = KdfParams(ops = 1, memBytes = 8192) // libsodium minimum
    private val ceiling = KdfParams(ops = 3, memBytes = 2L * 1024 * 1024 * 1024) // 2 GiB > the 1 GiB ceiling
    private val floor = KdfParams.DEFAULT // 64 MiB / t=3 — the at-floor DEFAULT must PASS (inclusive)

    private fun apiWith(body: String): AndvariApi {
        val engine = MockEngine { respond(body, HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) }
        return AndvariApi("http://fake", HttpClient(engine))
    }

    private fun keys(p: KdfParams) = AccountKeys("AA", p, "AA", "AA", "AA", "AA")
    private fun sessionBody(p: KdfParams) = json.encodeToString(SessionResponse.serializer(), SessionResponse("u", "d", "at", "rt", keys(p), false))
    private fun preloginBody(p: KdfParams) = json.encodeToString(PreloginResponse.serializer(), PreloginResponse("AA", p))
    private fun policyBody(p: KdfParams) = json.encodeToString(ClientPolicy.serializer(), ClientPolicy(kdfParams = p))
    private fun keysBody(p: KdfParams) = json.encodeToString(AccountKeys.serializer(), keys(p))

    @Test
    fun fenceConstantsPinnedToWebAndExtension() {
        // These four numbers are duplicated verbatim in web/src/crypto/keys.ts and
        // extension/src/crypto.ts — a change here is a deliberate three-file edit.
        assertEquals(67_108_864L, KdfUpgrade.MIN_MEM_BYTES)
        assertEquals(3L, KdfUpgrade.MIN_OPS)
        assertEquals(1_073_741_824L, KdfUpgrade.MAX_MEM_BYTES)
        assertEquals(10L, KdfUpgrade.MAX_OPS)
    }

    @Test
    fun weakPreloginRejectedBelowFloor() = runBlocking {
        val api = apiWith(preloginBody(weak))
        val e = assertFailsWith<KdfPolicyViolationException> { api.prelogin("a@b.c") }
        assertEquals("kdf_below_floor", e.reason)
        api.close()
    }

    @Test
    fun weakClientPolicyRejected() = runBlocking {
        val api = apiWith(policyBody(weak))
        assertFailsWith<KdfPolicyViolationException> { api.clientPolicy() }
        api.close()
    }

    @Test
    fun weakLoginSessionRejectedBeforeSetTokens() = runBlocking {
        val api = apiWith(sessionBody(weak))
        // The fence runs BEFORE setTokens, so a weakened login never installs a session.
        assertFailsWith<KdfPolicyViolationException> {
            api.login(LoginRequest("a@b.c", "authkey", DeviceInfo("web", "test")))
        }
        api.close()
    }

    @Test
    fun weakAccountKeysRejected() = runBlocking {
        val api = apiWith(keysBody(weak))
        assertFailsWith<KdfPolicyViolationException> { api.accountKeys() }
        api.close()
    }

    @Test
    fun overCeilingRejected() = runBlocking {
        val api = apiWith(preloginBody(ceiling))
        val e = assertFailsWith<KdfPolicyViolationException> { api.prelogin("a@b.c") }
        assertEquals("kdf_above_ceiling", e.reason)
        api.close()
    }

    @Test
    fun atFloorDefaultPasses() = runBlocking {
        // The honest server default (64 MiB / t=3) must not trip the inclusive fence.
        val api = apiWith(preloginBody(floor))
        val r = api.prelogin("a@b.c")
        assertEquals(floor.memBytes, r.kdfParams.memBytes)
        api.close()
    }
}
