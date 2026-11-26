package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Proves the escrow ceremony end-to-end using the same :core primitives recovery-cli
 * uses (keygen → seal UVK → canary → open the escrow offline). What `assist` does with the
 * opened UVK is covered by AssistRotateTest; no temporary password exists (spec 04 §7).
 */
class RecoveryCeremonyTest {
    private val crypto = createCryptoProvider()

    @Test
    fun canaryMakeAndVerifyRoundTrip() {
        val seed = crypto.randomBytes(32)
        val kp = crypto.boxKeypairFromSeed(seed)
        val sealed = Escrow.sealCanary(crypto, kp.publicKey)
        // Verify from a freshly-reconstructed keypair (simulating typing the printed seed).
        val fromSheet = crypto.boxKeypairFromSeed(seed)
        Escrow.openCanary(crypto, fromSheet, sealed) // throws unless it is exactly the fixed canary
    }

    @Test
    fun escrowOpensOffline_toTheAccountsOwnUvk() {
        // Enrollment: a real enrolment (escrow v2 since security review 2026-10, root cause A).
        val recoverySeed = crypto.randomBytes(32)
        val recovery = crypto.boxKeypairFromSeed(recoverySeed)
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val r = Account.enroll("inv", "m@x.com", "m", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, fp, "dev", crypto)
        val userId = r.request.userId
        val uvk = r.account.uvkCopyForPlatformWrap()
        val sealed = Bytes.fromB64(r.request.escrow!!.sealed)

        // Unseal offline, bound to the named account, its anchor and its identity file.
        val opened = Escrow.open(
            crypto, recovery, sealed, userId, Escrow.fingerprint(crypto, r.account.identityPub).take(32),
            IdentityCheck(r.request.encryptedIdentitySeed, r.request.identityPub),
        )
        assertEquals(userId, opened.userId)
        assertContentEquals(uvk, opened.uvk, "the escrow opens to the account's own UVK")
    }

    @Test
    fun wrongSheetCannotRecover() {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val sealed = Escrow.sealCanary(crypto, recovery.publicKey)
        val wrong = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        assertFailsWith<Exception> { Escrow.openCanary(crypto, wrong, sealed) }
    }

    @Test
    fun noNetworkClassesOnClasspath() {
        // The offline guarantee (spec 04 §5): no HTTP client must be reachable.
        for (cls in listOf(
            "io.ktor.client.HttpClient",
            "java.net.http.HttpClient",
            "okhttp3.OkHttpClient",
        )) {
            // java.net.http is in the JDK, so only assert the 3rd-party HTTP stacks are absent.
            if (cls.startsWith("java.")) continue
            val present = runCatching { Class.forName(cls) }.isSuccess
            assertTrue(!present, "$cls must NOT be on the recovery-cli classpath (offline tool)")
        }
    }

    @Test
    fun theTemporaryPasswordCommandIsGone() {
        // Spec 04 §7: no temporary password at any point. The command, its bundle and its writer are deleted.
        val main = Class.forName("io.silencelen.andvari.recovery.MainKt")
        val names = main.declaredMethods.map { it.name }
        for (gone in listOf("recover", "recoveryBundle", "writeBundleOwnerOnly", "humanTempPassword")) {
            assertTrue(names.none { it == gone || it.startsWith("$gone\$") }, "$gone must not exist: $names")
        }
    }
}
