package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Security review 2026-10, branch A11 (q08): the desktop §2.4 self-identity pin was keyed by the server-chosen
 * login userId alone, so a server answering the same email with a new userId met a pin miss and became the new
 * pin. The pin is now bound to the email the user typed as well; a changed userId for that email is refused with
 * the security-fault copy. Existing userId-keyed pins are kept and bound to the session's email.
 */
class SelfIdentityEmailPinTest {
    private val root = Files.createTempDirectory("andvari-desktop-a11-q08").toFile()
    private val crypto = createCryptoProvider()
    private val password = "correct horse battery staple"
    private val origin = "https://vault.example.net"
    private val key = originKey(origin)
    private val forged = "99999999-9999-4999-8999-999999999999"

    @AfterTest
    fun cleanup() { root.deleteRecursively() }

    private fun account(email: String): Account {
        val r = Account.enroll("inv", email, "m", password, KdfParams(ops = 1, memBytes = 8192), null, null, "dev", crypto)
        val keys = AccountKeys(r.request.kdfSalt, r.request.kdfParams, r.request.wrappedUvk, r.request.encryptedIdentitySeed, r.request.identityPub, "")
        return Account.unlock(r.request.userId, password, keys, crypto)
    }

    @Test
    fun aNewUserIdForTheSameTypedEmailIsRefusedNotPinnedAfresh() {
        val store = DesktopSessionStore(root)
        val a = account("ann@example.com")
        assertNull(store.selfIdentityPubFor(key, "ann@example.com", a.userId), "first unlock on this device")
        store.recordSelfIdentityPub(key, a.userId, "ann@example.com", a)
        // A later sign-in: the server answers the same email (retyped with different case) with a new userId.
        assertFailsWith<CryptoException> { store.selfIdentityPubFor(key, " Ann@Example.com", forged) }
        // The genuine userId still gets its pin.
        assertContentEquals(a.identityPub, store.selfIdentityPubFor(key, "ann@example.com", a.userId))
        // A restart (a new store over the same directory) keeps the binding.
        assertFailsWith<CryptoException> { DesktopSessionStore(root).selfIdentityPubFor(key, "ann@example.com", forged) }
    }

    @Test
    fun theBindingIsWrittenOnceAndNeverOverwritten() {
        val store = DesktopSessionStore(root)
        val a = account("ann@example.com")
        store.recordSelfIdentityPub(key, a.userId, "ann@example.com", a)
        val b = account("ann@example.com")
        store.recordSelfIdentityPub(key, b.userId, "ann@example.com", b) // never reached in product (unlock refuses first)
        assertFailsWith<CryptoException> { store.selfIdentityPubFor(key, "ann@example.com", b.userId) }
    }

    @Test
    fun aPreA11UserIdKeyedPinIsBoundToTheSessionEmailAtStartup() {
        val a = account("ann@example.com")
        // The pre-A11 layout: only ns/<origin>/<userId>/self-identity-pub, plus the saved session.
        val nsDir = DesktopSessionStore(root).nsDir(key, a.userId).also { it.mkdirs() }
        File(nsDir, "self-identity-pub").writeText(Bytes.toB64(a.identityPub))
        DesktopSessionStore(root).save(DesktopSession(origin, a.userId, "ann@example.com", "at", "rt"))

        val store = DesktopSessionStore(root)
        store.bindLegacySelfIdentity()
        // A revocation then clears the session; the server later answers the email with another userId.
        store.clear()
        assertFailsWith<CryptoException> { store.selfIdentityPubFor(key, "ann@example.com", forged) }
        assertContentEquals(a.identityPub, store.selfIdentityPubFor(key, "ann@example.com", a.userId))
    }

    @Test
    fun aLegacyPinIsAlsoBoundLazilyWhileTheSessionStillExists() {
        val a = account("ann@example.com")
        val store = DesktopSessionStore(root)
        File(store.nsDir(key, a.userId).also { it.mkdirs() }, "self-identity-pub").writeText(Bytes.toB64(a.identityPub))
        store.save(DesktopSession(origin, a.userId, "ann@example.com", "at", "rt"))
        assertFailsWith<CryptoException> { store.selfIdentityPubFor(key, "ann@example.com", forged) }
    }

    @Test
    fun anotherEmailOrAnotherOriginIsIndependent() {
        val store = DesktopSessionStore(root)
        val a = account("ann@example.com")
        store.recordSelfIdentityPub(key, a.userId, "ann@example.com", a)
        assertNull(store.selfIdentityPubFor(key, "bob@example.com", forged))
        assertNull(store.selfIdentityPubFor(originKey("https://other.example.org"), "ann@example.com", forged))
    }
}
