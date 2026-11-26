package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A lock wipes every vault key the log engine holds (engine item 20). The fake server has no vault logs, so the keys
 * are placed in the engine's own maps by reflection: what is checked is that the lock zeroes and drops them.
 */
class EngineLockWipesKeysTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private fun app(): EngineAppApi {
        val server = FakeInstance(crypto)
        val transport = BearerTransport(mapOf(server.origin to server))
        return EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", transport, MemoryDeviceState(), MemoryDeviceState(), crypto,
                { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun open(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    @Suppress("UNCHECKED_CAST")
    private fun map(logs: StoredVaultLogs, field: String): HashMap<String, ByteArray> =
        StoredVaultLogs::class.java.getDeclaredField(field).also { it.isAccessible = true }.get(logs) as HashMap<String, ByteArray>

    /** Puts one adopted and one held key into the open vault's log engine; answers both arrays. */
    private fun plant(a: EngineAppApi): Pair<StoredVaultLogs, List<ByteArray>> {
        val logs = assertNotNull(a.vault).logs
        val adopted = ByteArray(32) { 7 }
        val held = ByteArray(32) { 9 }
        map(logs, "keys")["11111111-1111-4111-8111-111111111111"] = adopted
        map(logs, "heldKeys")["22222222-2222-4222-8222-222222222222"] = held
        return logs to listOf(adopted, held)
    }

    private fun assertWiped(logs: StoredVaultLogs, arrays: List<ByteArray>) {
        assertTrue(map(logs, "keys").isEmpty() && map(logs, "heldKeys").isEmpty(), "no key is held after the vault closes")
        for (k in arrays) assertTrue(k.all { it == 0.toByte() }, "every key is zeroed")
    }

    @Test fun aLockWipesTheVaultKeysTheLogEngineHolds() = runBlocking<Unit> {
        val a = app()
        open(a)
        val (logs, arrays) = plant(a)
        a.lock()
        assertWiped(logs, arrays)
    }

    @Test fun signingOutWipesThemToo() = runBlocking<Unit> {
        val a = app()
        open(a)
        val (logs, arrays) = plant(a)
        assertEquals(PlainResult.DONE, a.signOut())
        assertWiped(logs, arrays)
    }
}
