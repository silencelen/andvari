package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Security review 2026-10, branch A11 (q08): the §2.4 self-identity pin was keyed ONLY by the userId the server
 * returned at login. A server that answers the same typed email with a NEW userId got a pin miss, the backstop was
 * skipped, and the server's identity became the new pin. The pin is now also bound to the email the user TYPED
 * (device-chosen) together with the (userId, identityPub) this device saw at its first passing unlock: a changed
 * userId for the same email is a security fault, not a fresh pin.
 */
class SelfIdentityEmailBindingTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse battery staple"
    private val u1 = "11111111-1111-4111-8111-111111111111"
    private val u2 = "22222222-2222-4222-8222-222222222222"

    private fun account(): Account {
        val r = Account.enroll("inv", "m@x.com", "m", password, KdfParams(ops = 1, memBytes = 8192), null, null, "dev", crypto)
        val keys = AccountKeys(r.request.kdfSalt, r.request.kdfParams, r.request.wrappedUvk, r.request.encryptedIdentitySeed, r.request.identityPub, "")
        return Account.unlock(r.request.userId, password, keys, crypto)
    }

    @Test
    fun emailIsNormalisedTheWayTheUserMightRetypeIt() {
        assertEquals("ann@example.com", SelfIdentityPin.normalizeEmail("  Ann@Example.COM "))
    }

    @Test
    fun aBindingRoundTripsAndMalformedRecordsReadAsAbsent() {
        val a = account()
        val b = SelfIdentityPin.decodeBinding(SelfIdentityPin.encodeBinding(a.userId, a))!!
        assertEquals(a.userId, b.userId)
        assertContentEquals(a.identityPub, b.identityPub)
        assertNull(SelfIdentityPin.decodeBinding(null))
        assertNull(SelfIdentityPin.decodeBinding("garbage"))
        assertNull(SelfIdentityPin.decodeBinding("not-a-uuid\n" + Bytes.toB64(a.identityPub)))
        assertNull(SelfIdentityPin.decodeBinding(a.userId + "\n" + Bytes.toB64(ByteArray(31))))
    }

    @Test
    fun aChangedUserIdForTheSameEmailIsASecurityFaultNotAFreshPin() {
        val pub = account().identityPub
        val e = assertFailsWith<CryptoException> {
            SelfIdentityPin.resolve(SelfIdentityPin.Binding(u1, pub), userId = u2, legacy = null)
        }
        assertTrue(e.message!!.contains("identity key mismatch"), "the hosts map it to the §5 security-fault copy")
    }

    @Test
    fun theBoundUserIdGetsTheBoundKeyAndNoBindingFallsBackToTheLegacyPin() {
        val pub = account().identityPub
        assertContentEquals(pub, SelfIdentityPin.resolve(SelfIdentityPin.Binding(u1, pub), userId = u1, legacy = null))
        assertContentEquals(pub, SelfIdentityPin.resolve(SelfIdentityPin.Binding(u1, pub), userId = u1, legacy = pub))
        assertContentEquals(pub, SelfIdentityPin.resolve(null, userId = u1, legacy = pub))
        assertNull(SelfIdentityPin.resolve(null, userId = u1, legacy = null), "a device that never unlocked: first pin")
    }

    @Test
    fun aLegacyPinThatContradictsTheBindingIsRefused() {
        val pub = account().identityPub
        val other = account().identityPub
        assertFailsWith<CryptoException> { SelfIdentityPin.resolve(SelfIdentityPin.Binding(u1, pub), userId = u1, legacy = other) }
    }
}

/** The key-value form the Android prefs store uses (A11, q08): the same rules over one origin's namespace. */
class SelfIdentityKeyValueStoreTest {
    private val crypto = createCryptoProvider()
    private val forged = "99999999-9999-4999-8999-999999999999"

    private fun account(): Account {
        val r = Account.enroll("inv", "m@x.com", "m", "correct horse battery staple", KdfParams(ops = 1, memBytes = 8192), null, null, "dev", crypto)
        val keys = AccountKeys(r.request.kdfSalt, r.request.kdfParams, r.request.wrappedUvk, r.request.encryptedIdentitySeed, r.request.identityPub, "")
        return Account.unlock(r.request.userId, "correct horse battery staple", keys, crypto)
    }

    @Test
    fun aChangedUserIdForTheSameEmailIsRefused() {
        val m = mutableMapOf<String, String>()
        val s = SelfIdentityPin.KeyValueStore({ m[it] }, { k, v -> m[k] = v })
        val a = account()
        assertNull(s.pinFor("ann@example.com", a.userId))
        s.record(a.userId, "ann@example.com", a)
        assertFailsWith<CryptoException> { s.pinFor("ANN@example.com ", forged) }
        assertContentEquals(a.identityPub, s.pinFor("ann@example.com", a.userId))
        assertNull(s.pinFor("bob@example.com", forged), "another email is independent")
    }

    @Test
    fun aPreA11PinIsBoundToTheSessionEmailAndKeptAsIs() {
        val a = account()
        val m = mutableMapOf("selfIdentityPub.${a.userId}" to Bytes.toB64(a.identityPub)) // the pre-A11 prefs key
        val s = SelfIdentityPin.KeyValueStore({ m[it] }, { k, v -> m[k] = v })
        s.bindLegacy(a.userId, "ann@example.com")
        assertFailsWith<CryptoException> { s.pinFor("ann@example.com", forged) }
        assertContentEquals(a.identityPub, s.pinFor("ann@example.com", a.userId))
        assertEquals(Bytes.toB64(a.identityPub), m["selfIdentityPub.${a.userId}"], "the legacy pin is not rewritten")
    }
}
