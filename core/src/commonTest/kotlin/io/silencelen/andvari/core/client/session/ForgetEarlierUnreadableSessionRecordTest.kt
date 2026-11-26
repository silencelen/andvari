package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * The keeper's forgetting of an earlier account refuses, removing nothing, while the secure store holds a session record
 * it cannot read now: whether the read throws or the store answers "nothing" and says so ([SessionRecordReadability]).
 * That record may be the very account the address is tied to. Before, the forgetting removed the address's record and the
 * account's identity record (and, with a throwing read, then failed).
 */
class ForgetEarlierUnreadableSessionRecordTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val alice = "alice@example.com"

    /** A secure store that can throw at the read of the session record ([throws]) or hand nothing for it and say so ([hides]). */
    private class SessionStore(val inner: MemoryDeviceState) : DeviceState, SessionRecordReadability {
        var throws = false
        var hides = false
        override val sessionRecordUnreadable: Boolean get() = hides && inner.get(SessionKeeper.KEY) != null
        override fun get(key: String): String? {
            if (key == SessionKeeper.KEY && throws) throw IllegalStateException("the session record cannot be read now")
            if (key == SessionKeeper.KEY && hides) return null
            return inner.get(key)
        }
        override fun keys(): Set<String> = inner.keys()
        override fun set(key: String, value: String?) = inner.set(key, value)
    }

    @Test fun theForgettingRefusesWhileTheSessionRecordCannotBeReadNow() = runBlocking<Unit> {
        for (how in listOf("the read throws", "the store hands nothing and says so")) {
            val server = FakeInstance(crypto)
            val state = MemoryDeviceState()
            val trust = server.pinnedTrust(state)
            val transport = BearerTransport(mapOf(server.origin to server))
            val secure = SessionStore(MemoryDeviceState())
            val first = SessionKeeper(transport, secure, state, trust, crypto)
            val o = WireOnboarding(server.origin, first.clientFor(server.origin), trust, KnownDevices(state, crypto), first, crypto, state, "android", "Pixel",
                { server.now }, knownIdentity = first::knownIdentity, work = Dispatchers.Unconfined)
            o.signupStart(alice, true)
            val t = assertIs<SignupVerify.Ticket>(o.signupVerify(alice, "482915"))
            val userId = assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t),
                RegistrationForm(alice, "Someone", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android"))).userId
            first.lock()
            // A start at which the platform cannot read the record: the keeper loads nothing.
            secure.hides = true
            val keeper = SessionKeeper(transport, secure, state, trust, crypto)
            assertNull(keeper.session, how)
            if (how == "the read throws") {
                secure.hides = false
                secure.throws = true
            }
            val before = state.keys().associateWith { state.get(it) }
            val secureBefore = secure.inner.keys().associateWith { secure.inner.get(it) }
            val r = runCatching { keeper.forgetEarlierAccount(server.origin, alice, userId) }
            assertEquals(before, state.keys().associateWith { state.get(it) }, "$how: the address's record and the identity record of $userId stay")
            assertEquals(secureBefore, secure.inner.keys().associateWith { secure.inner.get(it) }, "$how: the session record stays")
            assertEquals(ForgetEarlier.OpenForThatAccount, r.getOrThrow(), how)
        }
    }
}
