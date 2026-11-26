package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.state.AccountDocument
import io.silencelen.andvari.core.client.state.AccountStateRead
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.client.state.AccountStateWrite
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.model.wire.SyncGrant
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * An engine that could not read the store when it began holds no mark that the account's records stand. It never takes
 * one later: were it to take whatever it finds at its first write, an account forgotten meanwhile would get a new mark
 * and a forgotten account's record. It writes nothing, sends no write, and says so as the store's fault.
 */
class LiveMarkStoreFaultTest {
    private val crypto = createCryptoProvider()
    private val me = "11111111-1111-4111-8111-111111111111"

    /** [inner], failing every read and write while [failing]. */
    private class Flaky(val inner: MemoryDeviceState) : DeviceState {
        var failing = false
        override fun get(key: String): String? = if (failing) throw IllegalStateException("storage locked") else inner.get(key)
        override fun set(key: String, value: String?) = if (failing) throw IllegalStateException("storage locked") else inner.set(key, value)
        override fun keys(): Set<String>? = inner.keys()
    }

    private class Account : AccountStateStore {
        var writes = 0
        override fun local() = AccountDocument.EMPTY
        override suspend fun read(): AccountStateRead = AccountStateRead.Ok(AccountDocument.EMPTY, emptyList())
        override suspend fun update(change: (AccountDocument) -> AccountDocument): AccountStateWrite {
            writes++
            return AccountStateWrite.Written(change(AccountDocument.EMPTY))
        }
    }

    private class Client : WireClient {
        var calls = 0
        override val origin = "https://h.example"
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            calls++
            return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        }
    }

    private object Host : VaultLogHost {
        override fun grantRow(vaultId: String): SyncGrant? = null
        override fun isCurrentContact(userId: String, identityPub: String) = false
        override fun currentContact(userId: String): Pair<String, Boolean>? = null
        override fun labelFor(userId: String, identityPub: String): String? = null
        override fun vaultName(vaultId: String, vk: ByteArray): String? = null
        override fun sealMeta(vaultId: String, vk: ByteArray, name: String) = "meta"
        override fun serverOwnerName(vaultId: String): String? = null
    }

    private fun engine(state: DeviceState, account: AccountStateStore, client: WireClient) = StoredVaultLogs(
        me, crypto.signKeypairFromSeed(ByteArray(32) { 3 }), crypto.boxKeypairFromSeed(ByteArray(32) { 3 }), ByteArray(32) { 4 },
        client, crypto, state, account, Host, { 1_763_164_800_000L }, { null },
    )

    @Test fun anEngineThatCouldNotReadTheStoreAtItsStartWritesNothingAfterAForgetting() = runBlocking<Unit> {
        val device = MemoryDeviceState()
        engine(device, Account(), Client())
        val mine = "ovh.log|$me|"
        assertTrue(device.keys().any { it.startsWith(mine) }, "an engine that began over a working store keeps its mark")

        val flaky = Flaky(device)
        flaky.failing = true
        val account = Account()
        val client = Client()
        val old = engine(flaky, account, client)
        assertTrue(StoredVaultLogs.forgetAccount(device, me))
        flaky.failing = false

        val made = runCatching { old.append(null, LogAction.Create("Two")) }
        assertEquals(emptyList(), device.keys().filter { it.startsWith(mine) }, "nothing of the forgotten account is written")
        assertEquals(0, account.writes, "no write of the account's state is sent")
        assertEquals(0, client.calls, "nothing is sent")
        val fault = assertNotNull(made.exceptionOrNull(), "$made")
        assertFalse(fault is KeysGoneException, "the store's fault, never said as forgotten: $fault")
        assertTrue(fault is LogStoreFaultException, "$fault")
    }
}
