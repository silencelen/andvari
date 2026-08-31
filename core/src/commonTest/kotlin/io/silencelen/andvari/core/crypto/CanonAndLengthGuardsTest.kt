package io.silencelen.andvari.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Audit F32 + F33 — the two hardening rules that guard the sealed/escrow paths, pinned so a
 * later refactor cannot quietly drop either.
 *
 * F32 (length preconditions): every array these functions hand to libsodium is read at its
 * FIXED length by native code through JNA, regardless of how long the Kotlin array is. The
 * encrypt side already asserted that; the decrypt side and the whole sealed-box pair did not,
 * so a short key reaching them was an out-of-bounds native read rather than the clean
 * [CryptoException] every caller's error handling is written against. Production always passes
 * 32 bytes today — these tests exist so it stays true when it isn't obvious.
 *
 * F33 (canonical-JSON composition): the escrow and shared-grant payloads are hand-composed
 * string templates (they must be byte-identical to the web twins, which an encoder can't
 * guarantee), and every id they interpolate is SERVER-SUPPLIED. Without a precondition a hostile
 * server picks the JSON structure of the blob the client seals.
 */
class CanonAndLengthGuardsTest {
    private val crypto = createCryptoProvider()

    private val userId = "44444444-4444-4444-8444-444444444444"
    private val vaultId = "55555555-5555-4555-8555-555555555555"

    // ---- F33: a server-supplied id can never break out of its JSON string ----

    @Test
    fun escrowPayloadRefusesAnIdThatWouldRewriteTheStructure() {
        // The exact shape a hostile server would return to turn a `uvk` blob into a `canary`
        // one: the id closes its own string and opens a new key.
        assertFailsWith<IllegalArgumentException> {
            Escrow.canonicalPayload("x\",\"keyType\":\"canary", Escrow.KEY_TYPE_UVK, ByteArray(32), crypto)
        }
        // A backslash is the other escape into the string grammar.
        assertFailsWith<IllegalArgumentException> {
            Escrow.canonicalPayload("x\\", Escrow.KEY_TYPE_UVK, ByteArray(32), crypto)
        }
        assertFailsWith<IllegalArgumentException> {
            Escrow.canonicalPayload(userId, "uvk\",\"key\":\"", ByteArray(32), crypto)
        }
    }

    @Test
    fun sharedGrantPayloadRefusesAnIdThatWouldRewriteTheStructure() {
        assertFailsWith<IllegalArgumentException> {
            SharedGrant.canonicalPayload("v\",\"vk\":\"", ByteArray(32))
        }
        assertFailsWith<IllegalArgumentException> {
            SharedGrant.canonicalPayload("v\\", ByteArray(32))
        }
    }

    /** The guard must not change the bytes for a conforming (lowercase-UUID) id — these
     *  payloads are sealed and re-parsed by the web twin and by recovery-cli. */
    @Test
    fun conformingIdsStillProduceTheExactCanonicalBytes() {
        assertEquals(
            """{"v":1,"userId":"$userId","keyType":"uvk","key":"${Bytes.toB64(ByteArray(32))}","sha256":"${Bytes.toB64(crypto.sha256(ByteArray(32)))}"}""",
            Escrow.canonicalPayload(userId, Escrow.KEY_TYPE_UVK, ByteArray(32), crypto).decodeToString(),
        )
        assertEquals(
            """{"v":1,"vaultId":"$vaultId","vk":"${Bytes.toB64(ByteArray(32))}"}""",
            SharedGrant.canonicalPayload(vaultId, ByteArray(32)).decodeToString(),
        )
    }

    // ---- F32: length preconditions on every path into native code ----

    /**
     * Note the exception type: [CryptoException], not the `require` the encrypt side uses. A
     * short key on the DECRYPT side is a legitimate runtime verdict — it is precisely what
     * quick-unlock sees when the platform-wrapped UVK it was handed is truncated or foreign, and
     * AccountUnlockWithUvkTest pins that as a bad-secret failure, not an app bug. Reclassifying
     * it would turn "wrong master password" into "couldn't unlock" for a whole failure class.
     */
    @Test
    fun aeadDecryptGuardsKeyAndNonceLikeEncryptAlreadyDid() {
        val key = crypto.randomBytes(32)
        val nonce = crypto.randomBytes(24)
        val ct = crypto.aeadEncrypt(key, nonce, "hello".encodeToByteArray(), ByteArray(0))
        // The happy path is unchanged.
        assertContentEquals("hello".encodeToByteArray(), crypto.aeadDecrypt(key, nonce, ct, ByteArray(0)))
        assertFailsWith<CryptoException> { crypto.aeadDecrypt(ByteArray(31), nonce, ct, ByteArray(0)) }
        assertFailsWith<CryptoException> { crypto.aeadDecrypt(ByteArray(33), nonce, ct, ByteArray(0)) }
        assertFailsWith<CryptoException> { crypto.aeadDecrypt(key, ByteArray(23), ct, ByteArray(0)) }
    }

    /** G52 (the F32 residue): the secretstream key/header arrive attacker-authored — a backup
     *  manifest's `fileKey` (Export.readAttachment) or a co-member item doc's attachment ref
     *  (SyncEngine) — and init_pull reads fixed lengths through JNA like every neighbour. */
    @Test
    fun secretstreamDecryptGuardsKeyAndHeaderLikeEncryptAlreadyDid() {
        val key = crypto.randomBytes(32)
        val enc = crypto.secretstreamEncrypt(key, listOf("hello".encodeToByteArray()))
        // The happy path is unchanged.
        assertContentEquals(
            "hello".encodeToByteArray(),
            crypto.secretstreamDecrypt(key, enc.header, enc.chunks).single(),
        )
        assertFailsWith<CryptoException> { crypto.secretstreamDecrypt(ByteArray(31), enc.header, enc.chunks) }
        assertFailsWith<CryptoException> { crypto.secretstreamDecrypt(ByteArray(33), enc.header, enc.chunks) }
        assertFailsWith<CryptoException> { crypto.secretstreamDecrypt(key, ByteArray(23), enc.chunks) }
    }

    @Test
    fun sealedBoxGuardsItsKeysAsCryptoExceptions() {
        val kp = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val sealed = crypto.sealTo(kp.publicKey, "hello".encodeToByteArray())
        assertContentEquals("hello".encodeToByteArray(), crypto.sealOpen(kp.publicKey, kp.privateKey, sealed))
        // CryptoException, not IllegalArgumentException: the sealed-box family reports every
        // structural refusal that way, so these ride the callers' existing fail-closed paths.
        assertFailsWith<CryptoException> { crypto.sealTo(ByteArray(31), "hello".encodeToByteArray()) }
        assertFailsWith<CryptoException> { crypto.sealOpen(ByteArray(31), kp.privateKey, sealed) }
        assertFailsWith<CryptoException> { crypto.sealOpen(kp.publicKey, ByteArray(31), sealed) }
    }

    /**
     * The sha256 self-check inside [Escrow.open] passes for a key of ANY length — it only proves
     * the blob is internally consistent. recovery-cli's `recover` re-wraps whatever comes back as
     * the victim's temporary wrappedUvk, so a short key would reach libsodium at their next
     * unlock; the length assertion belongs in the shared helper, not in one CLI subcommand.
     */
    @Test
    fun escrowOpenRejectsAShortUvkEvenWhenItsSelfCheckPasses() {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val shortKey = ByteArray(16) { 7 }
        // Built exactly as a buggy/hostile enrolling client would: consistent, just too short.
        val sealed = crypto.sealTo(
            recovery.publicKey,
            Escrow.canonicalPayload(userId, Escrow.KEY_TYPE_UVK, shortKey, crypto),
        )
        val e = assertFailsWith<CryptoException> {
            Escrow.open(crypto, recovery.publicKey, recovery.privateKey, sealed)
        }
        assertTrue(e.message!!.contains("not 32 bytes"), "expected a length refusal, got: ${e.message}")
        // A well-formed blob still opens — the guard adds a rule, it doesn't change the format.
        val good = Escrow.sealUvk(crypto, recovery.publicKey, userId, crypto.randomBytes(32))
        assertEquals(Escrow.KEY_TYPE_UVK, Escrow.open(crypto, recovery.publicKey, recovery.privateKey, good).keyType)
    }
}
