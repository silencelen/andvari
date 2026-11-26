package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.client.onboard.EstablishedSession
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.onboard.KnownDevices
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountKeys
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Spec 01 §7, the pending-record rule, offered to a host that holds its session itself (the command-line tool):
 * [EstablishedSession.settleServed] takes the account's keys a server serves and the password this opening verified, runs
 * the whole fence first, opens the served wrap, compares its key with the session's own in constant time, and makes the
 * served wrap the session's own only when they are the same key. Before, the tool compared through a probe of its own,
 * sealed under one key and opened under the other.
 */
class SettleServedTest {
    private val plain = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val up = KdfParams(ops = 4, memBytes = 64L * 1024 * 1024)
    private val mib = 1024L * 1024

    /** The crypto the session is handed, counting every Argon2id derivation it runs (and the cost of each). */
    private class Counting(private val inner: CryptoProvider) : CryptoProvider by inner {
        val costs = ArrayList<Pair<Long, Long>>()
        override fun argon2id(password: ByteArray, salt: ByteArray, outLen: Int, opsLimit: Long, memLimitBytes: Long): ByteArray {
            costs += opsLimit to memLimitBytes
            return inner.argon2id(password, salt, outLen, opsLimit, memLimitBytes)
        }
    }

    private class Env(val server: FakeInstance, val session: EstablishedSession, val crypto: Counting) {
        val account get() = server.accounts.values.single()
        val userId get() = account.userId
    }

    private suspend fun registered(): Env {
        val server = FakeInstance(plain)
        val state = MemoryDeviceState()
        val secure = MemoryDeviceState()
        val trust = server.pinnedTrust(state)
        val keeper = SessionKeeper(BearerTransport(mapOf(server.origin to server)), secure, state, trust, plain)
        val o = WireOnboarding(server.origin, keeper.clientFor(server.origin), trust, KnownDevices(state, plain), keeper, plain, state, "android", "Pixel",
            { server.now }, knownIdentity = keeper::knownIdentity, work = Dispatchers.Unconfined)
        o.signupStart("alice@example.com", true)
        val t = assertIs<SignupVerify.Ticket>(o.signupVerify("alice@example.com", "482915"))
        val form = RegistrationForm("alice@example.com", "Alice", strong.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "Pixel", "android")
        assertIs<Registration.Registered>(o.register(RegistrationAuth.Ticket(t), form))
        return Env(server, assertNotNull(keeper.established), Counting(plain))
    }

    private fun pw() = strong.toCharArray()

    /** A wrap made with [password] under a fresh salt at [params], sealing [key] for the account [adUser]. */
    private fun wrapOf(key: ByteArray, adUser: String, params: KdfParams = KdfParams.DEFAULT, password: String = strong): Pair<String, String> {
        val salt = plain.randomBytes(KdfParams.SALT_BYTES)
        val keys = assertNotNull(PasswordKeys.derive(plain, password.toCharArray(), salt, params, served = false))
        try {
            return Bytes.toB64(salt) to Envelope.sealB64(plain, keys.wrapKey, key, Ad.uvk(adUser))
        } finally {
            keys.wipe()
        }
    }

    private fun Env.served(salt: String, params: KdfParams, wrapped: String): AccountKeys =
        session.accountKeys.copy(kdfSalt = salt, kdfParams = params, wrappedUvk = wrapped)

    /** The session's proof now: the auth key it derives, and the cost it derived at. */
    private fun Env.proof(): Pair<String, List<Pair<Long, Long>>> {
        crypto.costs.clear()
        val k = assertIs<ReauthKey.Key>(session.proveAuthKey(crypto, pw())).currentAuthKey
        return k to crypto.costs.toList()
    }

    /** The session still proves against its own wrap: the server's verifier takes it, at the session's own cost. */
    private fun Env.unchanged(what: String) {
        val (key, costs) = proof()
        assertEquals(account.authKey, key, "the session's own wrap still proves: $what")
        assertEquals(listOf(KdfParams.DEFAULT.ops to KdfParams.DEFAULT.memBytes), costs, what)
    }

    private fun Env.settle(keys: AccountKeys): Pair<ServedWrap, List<Pair<Long, Long>>> {
        crypto.costs.clear()
        val password = pw()
        val r = session.settleServed(crypto, keys, password)
        assertTrue(password.all { it == '\u0000' }, "the password is wiped")
        return r to crypto.costs.toList()
    }

    @Test fun aServedWrapThatOpensToAnotherKeyIsNotAdoptedAndNothingOfTheSessionChanges() = runBlocking<Unit> {
        val e = registered()
        // Made with the person's own password, for this account, around another key: it opens, to the wrong key.
        val other = wrapOf(plain.randomBytes(32), e.userId)
        val (r, costs) = e.settle(e.served(other.first, KdfParams.DEFAULT, other.second))
        assertEquals(ServedWrap.NOT_THIS_DEVICES, r)
        assertEquals(listOf(KdfParams.DEFAULT.ops to KdfParams.DEFAULT.memBytes), costs, "tried once, at the served cost")
        e.unchanged("another key")
    }

    @Test fun aServedCostOutsideTheFenceDerivesNothing() = runBlocking<Unit> {
        val e = registered()
        val uvk = e.session.account.uvk.copyOut()
        // A ragged cost passes the floor and the ceiling, and this wrap really opens with the password at that cost.
        val ragged = KdfParams(ops = 3, memBytes = 64 * mib + 1)
        val raggedWrap = wrapOf(uvk, e.userId, ragged)
        uvk.fill(0)
        val rows = listOf(
            ragged to raggedWrap,
            KdfParams(ops = 11, memBytes = 64 * mib) to wrapOf(plain.randomBytes(32), e.userId),
            KdfParams(ops = 3, memBytes = 32 * mib) to wrapOf(plain.randomBytes(32), e.userId),
            KdfParams(ops = 3, memBytes = 2048 * mib) to wrapOf(plain.randomBytes(32), e.userId),
        )
        for ((params, wrap) in rows) {
            val (r, costs) = e.settle(e.served(wrap.first, params, wrap.second))
            assertEquals(ServedWrap.NOT_THIS_DEVICES, r, "$params")
            assertEquals(emptyList(), costs, "no derivation ran for $params")
            e.unchanged("$params")
        }
    }

    @Test fun aServedWrapThatDoesNotOpenChangesNothing() = runBlocking<Unit> {
        val e = registered()
        val cases = mapOf(
            "another password's wrap" to wrapOf(plain.randomBytes(32), e.userId, password = "a different master password 5 Q"),
            "another account's wrap" to wrapOf(plain.randomBytes(32), "00000000-0000-4000-8000-000000000042"),
        )
        for ((what, wrap) in cases) {
            val (r, costs) = e.settle(e.served(wrap.first, KdfParams.DEFAULT, wrap.second))
            assertEquals(ServedWrap.NOT_THIS_DEVICES, r, what)
            assertEquals(listOf(KdfParams.DEFAULT.ops to KdfParams.DEFAULT.memBytes), costs, what)
            e.unchanged(what)
        }
    }

    /** "Known" is the salt, the cost and the wrapped key together: the own wrap's bytes at another salt or cost are not. */
    @Test fun theOwnWrapsBytesAtAnotherSaltOrCostAreNotKnown() = runBlocking<Unit> {
        val e = registered()
        val own = e.session.accountKeys
        for ((what, keys) in listOf(
            "another salt" to own.copy(kdfSalt = Bytes.toB64(plain.randomBytes(KdfParams.SALT_BYTES))),
            "another cost" to own.copy(kdfParams = up),
        )) {
            val (r, costs) = e.settle(keys)
            assertEquals(ServedWrap.NOT_THIS_DEVICES, r, what)
            assertEquals(listOf(keys.kdfParams.ops to keys.kdfParams.memBytes), costs, "tried once, at the served cost: $what")
            e.unchanged(what)
        }
    }

    @Test fun theSameKeyAtANewCostIsAdoptedAndTheSessionProvesAgainstIt() = runBlocking<Unit> {
        val e = registered()
        // The session's own wrap, as it was opened: known, and nothing is derived.
        val (own, ownCosts) = e.settle(e.session.accountKeys)
        assertEquals(ServedWrap.KNOWN, own)
        assertEquals(emptyList(), ownCosts)

        val uvk = e.session.account.uvk.copyOut()
        val raised = wrapOf(uvk, e.userId, up)
        uvk.fill(0)
        val (r, costs) = e.settle(e.served(raised.first, up, raised.second))
        assertEquals(ServedWrap.ADOPTED, r)
        assertEquals(listOf(up.ops to up.memBytes), costs, "one derivation, at the served cost")

        // The session proves against the adopted wrap: its salt and its cost.
        val expected = assertNotNull(PasswordKeys.derive(plain, pw(), Bytes.fromB64(raised.first), up, served = false))
        val want = try { expected.authKeyB64 } finally { expected.wipe() }
        val (key, proofCosts) = e.proof()
        assertEquals(want, key)
        assertEquals(listOf(up.ops to up.memBytes), proofCosts)

        // Served again: known now, with nothing derived.
        val (again, againCosts) = e.settle(e.served(raised.first, up, raised.second))
        assertEquals(ServedWrap.KNOWN, again)
        assertEquals(emptyList(), againCosts)
    }
}
