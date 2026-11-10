package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Survey gap 7, the holder's half: a session's account is wiped when the session ends, not left to the collector. */
class SessionWipeTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))

    private fun account(): Account =
        Account.enroll("inv", "w@example.com", "w", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "dev", crypto).account

    private fun api() = AndvariApi("https://home.example", HttpClient(MockEngine { respond("{}", HttpStatusCode.OK) }), Tokens("a", "r"))

    /** Holds the end-of-session flush open, the way a platform's bounded usage flush does. */
    private class HeldFlush : SessionEndHook {
        var closeTransport: (() -> Unit)? = null
        var sawWiped: Boolean? = null

        override fun flush(session: VaultSession.Unlocked, closeTransport: () -> Unit) {
            sawWiped = session.account.isWiped
            this.closeTransport = closeTransport
        }

        override fun clear() {}
    }

    @Test
    fun theLockWipesTheAccountOnceItsTransportHasClosed() {
        val hook = HeldFlush()
        val session = VaultSession(FakeClocks(), hook)
        val a = account()
        val api = api()
        session.bind(api, a, SyncEngine(api, a, InMemoryVaultCache()))
        session.lock()
        assertEquals(false, hook.sawWiped, "the flush still seals with the live keys")
        assertFalse(a.isWiped, "nothing is wiped while the flush holds the transport")
        assertNotNull(hook.closeTransport).invoke()
        assertTrue(a.isWiped, "the keys go as the transport closes")
    }

    @Test
    fun withNoFlushTheLockWipesAtOnce() {
        val session = VaultSession(FakeClocks())
        val a = account()
        val api = api()
        session.bind(api, a, SyncEngine(api, a, InMemoryVaultCache()))
        session.lock()
        assertTrue(a.isWiped)
    }

    @Test
    fun aReplacedAccountIsWipedButARebindOfTheSameOneIsNot() {
        val session = VaultSession(FakeClocks())
        val first = account()
        val api = api()
        session.bind(api, first, SyncEngine(api, first, InMemoryVaultCache()))
        session.bind(api, first, SyncEngine(api, first, InMemoryVaultCache())) // a new engine, the same account
        assertFalse(first.isWiped)
        val second = account()
        val other = api()
        session.bind(other, second, SyncEngine(other, second, InMemoryVaultCache()))
        assertTrue(first.isWiped, "the account the session no longer holds")
        assertFalse(second.isWiped)
    }
}
