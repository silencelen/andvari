package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.UsagePut
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNull

/** The usage ledger on the new session: its key follows the genesis personal vault and nothing else (spec 02 §8.2). */
class ItemUsageTest {
    private val crypto = createCryptoProvider()
    private val me = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val personal = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val other = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

    private class Server : WireClient {
        override val origin = "https://h.example"
        var stored: String? = null
        var calls = 0
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls++
            if (route == WireRoute.USAGE_PUT) stored = WireJson.json.decodeFromString(UsagePut.serializer(), bodyJson!!).sealedUsage
            return WireResult.Ok(decode(if (route == WireRoute.USAGE_GET) """{"sealedUsage":${stored?.let { "\"$it\"" } ?: "null"},"updatedAt":0}""" else "ok"), 200)
        }
    }

    @Test
    fun theLedgerRoundTripsUnderThePersonalVaultKey_andUnderNoOther() = runBlocking<Unit> {
        val server = Server()
        val keys = FakeKeys(personal).also { it.put(personal, ByteArray(32) { 1 }); it.put(other, ByteArray(32) { 2 }, "writer") }
        val usage = SessionUsage(server, keys, crypto, me)
        assertNull(usage.fetchSealed(), "an account that never wrote a ledger has none")
        val plain = """{"v":1}""".encodeToByteArray()
        usage.put(usage.seal(plain))
        val sealed = usage.fetchSealed()!!
        assertContentEquals(plain, usage.open(sealed))

        // Another account's slot, and another vault standing in as "personal", open nothing.
        assertFails { SessionUsage(server, keys, crypto, other).open(sealed) }
        keys.personalVaultId = other
        assertFails { usage.open(sealed) }
        // No personal vault in force: no ledger at all, never an empty one.
        keys.personalVaultId = null
        assertFails { usage.open(sealed) }
        assertFails { usage.seal(plain) }
    }

    @Test
    fun halted_theLedgerIsNeitherFetchedNorStored() = runBlocking<Unit> {
        val server = Server()
        val usage = SessionUsage(server, FakeKeys(personal).also { it.put(personal, ByteArray(32) { 1 }) }, crypto, me, halted = { true })
        assertFails { usage.fetchSealed() }
        assertFails { usage.put("x") }
        assertEquals(0, server.calls)
    }
}
