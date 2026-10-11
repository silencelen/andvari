package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.RecoveryUpload
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Proves the escrow ceremony end-to-end using the same :core primitives recovery-cli
 * uses (keygen → seal UVK → canary → recover → re-wrap under temp password → unlock).
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
    fun fullRecoveryReWrapUnlocks() {
        // Enrollment: a real enrolment (escrow v2 since security review 2026-10, root cause A).
        val recoverySeed = crypto.randomBytes(32)
        val recovery = crypto.boxKeypairFromSeed(recoverySeed)
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val r = Account.enroll("inv", "m@x.com", "m", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, fp, "dev", crypto)
        val userId = r.request.userId
        val uvk = r.account.uvkCopyForPlatformWrap()
        val sealed = Bytes.fromB64(r.request.escrow!!.sealed)

        // Recover: unseal offline, bound to the named account, its anchor and its identity file.
        val opened = Escrow.open(
            crypto, recovery, sealed, userId, Escrow.fingerprint(crypto, r.account.identityPub).take(32),
            IdentityCheck(r.request.encryptedIdentitySeed, r.request.identityPub),
        )
        assertEquals(userId, opened.userId)
        val recoveredUvk = opened.uvk
        assertContentEquals(uvk, recoveredUvk)

        // Re-wrap under a temp password.
        val tempPassword = "temp horse battery 99"
        val tempSalt = crypto.randomBytes(KdfParams.SALT_BYTES)
        val params = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024)
        val mk = Keys.masterKey(crypto, tempPassword, tempSalt, params)
        val tempWrappedUvk = Envelope.seal(crypto, Keys.wrapKey(crypto, mk), recoveredUvk, Ad.uvk(userId))

        // User logs in with the temp password on a fresh device → unwraps the SAME uvk.
        val mk2 = Keys.masterKey(crypto, tempPassword, tempSalt, params)
        val unwrapped = Envelope.open(crypto, Keys.wrapKey(crypto, mk2), tempWrappedUvk, Ad.uvk(userId))
        assertContentEquals(uvk, unwrapped, "recovered account unlocks the original UVK")
    }

    @Test
    fun wrongSheetCannotRecover() {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val sealed = Escrow.sealCanary(crypto, recovery.publicKey)
        val wrong = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        assertFailsWith<Exception> { Escrow.openCanary(crypto, wrong, sealed) }
    }

    @Test
    fun recoveryBundleRoundTripsThroughServerType() {
        // PRC-1 regression guard. The bundle `recover()` emits must decode into the server's
        // exact RecoveryUpload; the old hand-built JsonObject wrote tempKdfParams as a JSON
        // STRING and 400'd the admin upload. Cover BOTH default params (serialize to `{}`) and
        // non-default params (must carry their values), each round-tripping losslessly.
        val cliJson = Json { prettyPrint = true } // MUST match Main.kt's `json` instance
        // The server's decoder is non-lenient beyond ignoreUnknownKeys (Repo.kt) — no
        // string→object coercion, so this decode is exactly what App.kt's receive() does.
        val serverJson = Json { ignoreUnknownKeys = true; encodeDefaults = true }
        for (params in listOf(KdfParams.DEFAULT, KdfParams(ops = 5, memBytes = 128L * 1024 * 1024))) {
            val bundle = recoveryBundle(
                userId = "abcdef01-2345-4678-8abc-def012345678",
                tempAuthKey = crypto.randomBytes(32),
                tempWrappedUvk = crypto.randomBytes(80),
                tempKdfSalt = crypto.randomBytes(KdfParams.SALT_BYTES),
                params = params,
            )
            val text = cliJson.encodeToString(RecoveryUpload.serializer(), bundle)
            // tempKdfParams MUST be a nested object, never a JSON string — the PRC-1 bug.
            val field = Json.parseToJsonElement(text).jsonObject["tempKdfParams"]
            assertTrue(field is JsonObject, "tempKdfParams must serialize as an object, got: $field")
            // And the server's decoder accepts the emitted bundle and reconstructs it exactly.
            val decoded = serverJson.decodeFromString(RecoveryUpload.serializer(), text)
            assertEquals(bundle, decoded, "recovery bundle must round-trip through RecoveryUpload")
            assertEquals(params, decoded.tempKdfParams, "KDF params must survive the round-trip")
        }
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
}
