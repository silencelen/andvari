package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.KtorWireClient
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/**
 * The check's p6, kept: the session keeper takes the transport's word "never left" as it is, and the transport gives it
 * only for a failure of the connect itself with no earlier attempt attached. Each of the five such failures costs a
 * refresh nothing (the record that a refresh is out stands as it was); a failure with a sent attempt attached, a secure
 * setup that failed and a plain socket failure (the JVM's "network is unreachable") keep the record.
 */
class KeeperNeverLeftTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"

    private fun connect() = java.net.ConnectException("Failed to connect to /192.0.2.1:443").apply { initCause(java.net.ConnectException("Connection refused")) }

    private val costsNothing: Map<String, Throwable> = mapOf(
        "connection refused" to connect(),
        "no route to host" to java.net.NoRouteToHostException("No route to host"),
        "a name not resolved" to java.net.UnknownHostException("h.example"),
        "an address not resolved" to java.nio.channels.UnresolvedAddressException(),
        "a connect that timed out" to io.ktor.client.network.sockets.ConnectTimeoutException("Connect timeout has expired", null),
    )

    private val keepsTheRecord: Map<String, Throwable> = mapOf(
        "a refused second try of a sent attempt" to connect().apply { addSuppressed(java.io.IOException("unexpected end of stream")) },
        "a secure setup that failed" to javax.net.ssl.SSLHandshakeException("handshake failed"),
        "a plain socket failure" to java.net.SocketException("Network is unreachable"),
    )

    /** One refresh lost to [failure], as the transport words it; true when the record that a refresh is out was kept. */
    private suspend fun recordKeptAfter(failure: Throwable): Boolean {
        val server = FakeInstance(crypto)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val transport = BearerTransport(mapOf(server.origin to server))
        transport.clock = { server.now }
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(transport, secure, state, trust, crypto, clock = { server.now })
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, crypto), keeper, crypto, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form))
        val dev = assertNotNull(keeper.session).deviceId
        transport.refreshAnswer = {
            transport.refreshAnswer = null
            WireResult.NoAnswer(NoAnswerKind.TRANSPORT, KtorWireClient.neverLeft(failure))
        }
        transport.expired += "at-$dev"
        keeper.clientFor(server.origin).call(WireRoute.ACCOUNT_STATE_GET, authenticated = true) { it }
        return assertNotNull(secure.get(SessionKeeper.KEY)).contains("refreshLostAt")
    }

    @Test fun eachFailureOfTheConnectItselfCostsARefreshNothing() = runBlocking<Unit> {
        for ((what, failure) in costsNothing) assertEquals(false, recordKeptAfter(failure), "$what: never left, the record stands as it was")
    }

    @Test fun aFailureThatMayComeAfterBytesWereWrittenKeepsTheRecord() = runBlocking<Unit> {
        for ((what, failure) in keepsTheRecord) assertEquals(true, recordKeptAfter(failure), "$what: may have left, the record stays")
    }
}
