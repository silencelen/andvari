package io.silencelen.andvari.app.crypto

import androidx.test.platform.app.InstrumentationRegistry
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.UsageKey
import io.silencelen.andvari.core.crypto.createCryptoProvider
import org.json.JSONObject
import org.junit.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H94 — the phone's crypto, graded against `spec/test-vectors` **on the phone**.
 *
 * ## Why this exists
 *
 * The Android target links `com.goterl:lazysodium-android`, which ships its OWN bundled libsodium
 * `.so`; every vector suite in the tree (core `jvmTest`, web's vitest, the extension's node run)
 * grades a DIFFERENT native binary — `lazysodium-java` over the host libsodium, plus `@noble` in
 * TypeScript. Byte-identity is expected by construction, both being libsodium, but "expected by
 * construction" is exactly the claim the corpus exists to stop anyone from making: a loader or ABI
 * mismatch, a stale `.so`, or a future `lazysodium-android` bump would have been caught only by a
 * member's phone failing to open a vault the web client sealed — which is precisely how the 0.26.3
 * desktop libsodium loader defect surfaced. The artifact users install had no tripwire of its own.
 *
 * Nothing here is new logic. It is the [io.silencelen.andvari.core.crypto.createCryptoProvider]
 * seam driven over the same files core's `VectorsTest` and `UsageKeyVectorTest` read, so a
 * divergence reports as "the phone's libsodium disagrees with the corpus" instead of as a support
 * ticket. Add cases; never edit a frozen vector (`spec/test-vectors/README.md`).
 *
 * ## How to run it
 *
 * It CANNOT run on a build host — instrumentation needs a device or an emulator:
 *
 * ```
 * ./gradlew :app-android:connectedDebugAndroidTest        # device/emulator attached over adb
 * ./gradlew :app-android:compileDebugAndroidTestKotlin     # host-side: proves it still compiles
 * ```
 *
 * **Use an arm64 device or an arm64 emulator image.** The APK carries `arm64-v8a` only (the
 * `abiFilters` in `build.gradle.kts`), and that is deliberate here rather than incidental: an
 * x86_64 emulator would grade a native binary no phone ever loads, re-creating by proxy the exact
 * gap this test closes. It belongs on the release checklist, not the PR gate, for the same
 * reason — the answer is only worth having off the real ABI.
 *
 * The corpus is mounted as this test APK's assets straight out of `spec/test-vectors` (see the
 * `sourceSets` block), so there is no second copy to drift.
 */
class AndroidCryptoVectorsTest {

    private val crypto = createCryptoProvider()

    private fun load(name: String): JSONObject {
        // getInstrumentation().context is the TEST apk (where the vectors are), not the app under
        // test — targetContext would look in the wrong assets and fail with a bare FileNotFound.
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        return JSONObject(assets.open(name).bufferedReader().use { it.readText() })
    }

    private fun JSONObject.s(key: String): String = getString(key)
    private fun JSONObject.b(key: String): ByteArray = Bytes.fromB64(getString(key))
    private fun JSONObject.arr(key: String): List<JSONObject> {
        val a = getJSONArray(key)
        return (0 until a.length()).map { a.getJSONObject(it) }
    }
    private fun JSONObject.params(key: String): KdfParams {
        val p = getJSONObject(key)
        return KdfParams(v = p.getInt("v"), alg = p.getString("alg"), ops = p.getLong("ops"), memBytes = p.getLong("memBytes"))
    }

    /** kdf.json — argon2id, HKDF and the master-key chain, on the phone's own libsodium. */
    @Test
    fun kdf() {
        val v = load("kdf.json")
        for (case in v.arr("argon2id")) {
            assertContentEquals(
                case.b("outB64"),
                crypto.argon2id(
                    case.s("passwordUtf8").encodeToByteArray(),
                    case.b("saltB64"),
                    case.getInt("outLen"),
                    case.getLong("ops"),
                    case.getLong("memBytes"),
                ),
                "argon2id ${case.s("passwordUtf8")}",
            )
        }
        for (case in v.arr("hkdf")) {
            assertContentEquals(
                case.b("okmB64"),
                Hkdf.sha256(crypto, case.b("ikmB64"), ByteArray(0), case.s("infoUtf8").encodeToByteArray(), case.getInt("len")),
                "hkdf ${case.s("infoUtf8")}",
            )
        }
        for (case in v.arr("chain")) {
            val mk = Keys.masterKey(crypto, case.s("passwordUtf8"), case.b("saltB64"), case.params("kdfParams"))
            assertContentEquals(case.b("mkB64"), mk, "masterKey")
            assertContentEquals(case.b("authKeyB64"), Keys.authKey(crypto, mk), "authKey")
            assertContentEquals(case.b("wrapKeyB64"), Keys.wrapKey(crypto, mk), "wrapKey")
        }
        // spec 01 §1 (H16): a memBytes that is not a KiB multiple floors to KiB inside every
        // engine. The phone's libsodium must floor it the same way, so the corpus has to keep
        // carrying such a case here too — otherwise the loop above grades nobody on it.
        assertTrue(v.arr("chain").any { it.params("kdfParams").memBytes % 1024 != 0L }, "a non-KiB-multiple chain case")
    }

    /** envelope.json — the AEAD every blob in the vault is sealed with, both directions. */
    @Test
    fun aead() {
        val v = load("envelope.json")
        for (case in v.arr("seal")) {
            val ad = case.s("adUtf8").encodeToByteArray()
            assertContentEquals(
                case.b("envelopeB64"),
                Envelope.sealWithNonce(crypto, case.b("keyB64"), case.b("nonceB64"), case.b("plaintextB64"), ad),
                "seal ${case.s("name")}",
            )
            assertContentEquals(case.b("plaintextB64"), Envelope.open(crypto, case.b("keyB64"), case.b("envelopeB64"), ad))
        }
        // The rejects matter more than the accepts on a native seam: a provider that "opens"
        // a tampered envelope is worse than one that cannot open anything.
        for (case in v.arr("reject")) {
            assertFailsWith<CryptoException>("reject ${case.s("reason")}") {
                Envelope.open(crypto, case.b("keyB64"), case.b("envelopeB64"), case.s("adUtf8").encodeToByteArray())
            }
        }
    }

    /** seal.json — crypto_box_seal + the escrow payload the recovery key opens. */
    @Test
    fun sealedBox() {
        val v = load("seal.json")
        val kp = crypto.boxKeypairFromSeed(v.b("recoverySeedB64"))
        assertContentEquals(v.b("recoveryPubB64"), kp.publicKey)
        assertContentEquals(v.b("recoveryPrivB64"), kp.privateKey)
        assertEquals(v.s("fingerprint"), Escrow.fingerprint(crypto, kp.publicKey))
        assertEquals(v.s("shortFingerprint"), Escrow.shortFingerprint(crypto, kp.publicKey))

        for (case in v.arr("open")) {
            assertContentEquals(case.b("plaintextB64"), crypto.sealOpen(kp.publicKey, kp.privateKey, case.b("sealedB64")))
        }
        val escrow = v.getJSONObject("escrowUvk")
        val payload = Escrow.open(crypto, kp.publicKey, kp.privateKey, escrow.b("sealedB64"))
        assertEquals(escrow.s("userId"), payload.userId)
        assertEquals(Escrow.KEY_TYPE_UVK, payload.keyType)
        assertContentEquals(escrow.b("uvkB64"), Bytes.fromB64(payload.key))

        val reject = v.getJSONObject("rejectWrongKey")
        val wrong = crypto.boxKeypairFromSeed(reject.b("wrongSeedB64"))
        assertFailsWith<CryptoException> { crypto.sealOpen(wrong.publicKey, wrong.privateKey, reject.b("sealedB64")) }
    }

    /** sharedgrant.json — the shared-vault key handoff, including the three refusals. */
    @Test
    fun sharedGrant() {
        val v = load("sharedgrant.json")
        val kp = crypto.boxKeypairFromSeed(v.b("memberSeedB64"))
        assertContentEquals(v.b("memberIdentityPubB64"), kp.publicKey)
        assertEquals(v.s("fingerprint"), SharedGrant.fingerprint(crypto, kp.publicKey))
        assertEquals(v.s("shortFingerprint"), SharedGrant.shortFingerprint(crypto, kp.publicKey))

        val vaultId = v.s("vaultId")
        assertContentEquals(v.s("payloadUtf8").encodeToByteArray(), SharedGrant.canonicalPayload(vaultId, v.b("vkB64")))
        assertContentEquals(v.b("vkB64"), SharedGrant.open(crypto, kp.publicKey, kp.privateKey, vaultId, v.b("sealedB64")))

        val reject = v.getJSONObject("rejectVaultMismatch")
        assertFailsWith<CryptoException> {
            SharedGrant.open(crypto, kp.publicKey, kp.privateKey, reject.s("expectedVaultId"), reject.b("sealedB64"))
        }
        val shortVk = v.getJSONObject("rejectVkLength")
        assertNotEquals(32, shortVk.getInt("vkLen"))
        val e = assertFailsWith<CryptoException> {
            SharedGrant.open(crypto, kp.publicKey, kp.privateKey, shortVk.s("expectedVaultId"), shortVk.b("sealedB64"))
        }
        assertTrue(e.message!!.contains("32 bytes"), e.message)
        val badVersion = v.getJSONObject("rejectVersion")
        assertNotEquals(1, badVersion.getInt("v"))
        val ev = assertFailsWith<CryptoException> {
            SharedGrant.open(crypto, kp.publicKey, kp.privateKey, badVersion.s("expectedVaultId"), badVersion.b("sealedB64"))
        }
        assertTrue(ev.message!!.contains("version"), ev.message)
        // …and this device's OWN (nondeterministic) seal round-trips through the same open.
        val ownSeal = SharedGrant.seal(crypto, kp.publicKey, vaultId, v.b("vkB64"))
        assertContentEquals(v.b("vkB64"), SharedGrant.open(crypto, kp.publicKey, kp.privateKey, vaultId, ownSeal))
    }

    /**
     * usagekey.json — the usage-ledger key and its AD. A divergence here fails in the most
     * misleading way available: each client seals and opens its own ledger perfectly while being
     * unable to read the other's, so the phone simply looks as though it "never records anything"
     * (spec 02 §8.2). The expected value came from an INDEPENDENT third implementation, so this
     * pins "the phone is correct", not "the phone agrees with core".
     */
    @Test
    fun usageKey() {
        val v = load("usagekey.json")
        assertEquals(v.s("usageKeyB64"), Bytes.toB64(UsageKey.usageKey(crypto, v.b("vkB64"))))
        assertEquals(v.s("adUtf8"), Ad.usage(v.s("adUserId")).decodeToString())
    }
}
