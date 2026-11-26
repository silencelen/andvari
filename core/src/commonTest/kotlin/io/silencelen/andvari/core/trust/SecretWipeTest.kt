package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Key material is zeroed where it can be. A grant frame
 * holds the vault key and an assisted-recovery frame the account's UVK, both in the clear, and HKDF's
 * pseudorandom key is as good as its input key.
 *
 * The provider is wrapped so that the test holds the very arrays the code under test was given: what
 * `sealOpen` returned (the opened frame) and what `hmacSha256` returned and was fed (the PRK, the blocks,
 * the block inputs). A `String` cannot be wiped, so the other half of the fix is that the key never
 * becomes one: it is written into a statement and read out of it as bytes.
 */
class SecretWipeTest {
    private val crypto = createCryptoProvider()
    private val alice = Party(crypto, Ids.ALICE, 1)
    private val bob = Party(crypto, Ids.BOB, 2)
    private val grantId = Ids.id16(1)

    private class Recording(private val real: CryptoProvider) : CryptoProvider by real {
        val opened = ArrayList<ByteArray>()
        val macs = ArrayList<ByteArray>()
        val macInputs = ArrayList<ByteArray>()

        override fun sealOpen(publicKey: ByteArray, privateKey: ByteArray, sealed: ByteArray): ByteArray =
            real.sealOpen(publicKey, privateKey, sealed).also { opened += it }

        override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
            real.hmacSha256(key, data).also {
                macs += it
                macInputs += data
            }
    }

    private fun isZero(bytes: ByteArray) = bytes.all { it == 0.toByte() }

    // ---- base64url on bytes ----------------------------------------------------------------------------

    @Test
    fun base64OnBytes_agreesWithTheStringCodec_andRefusesWhatItRefuses() {
        for (n in 0..70) {
            val bytes = crypto.randomBytes(n)
            val text = Bytes.toB64Bytes(bytes)
            assertEquals(Bytes.toB64(bytes), text.decodeToString(), "length $n")
            assertContentEquals(bytes, Bytes.fromB64Bytes(text), "length $n")
        }
        // Every byte value in every position of a short text: the two decoders accept and refuse alike.
        for (base in listOf("AAAA", "AAA", "AA", "QUJD", "-_-_", "AAAAAA", "AAAAAAA")) {
            for (at in base.indices) {
                for (c in 0..255) {
                    val mutated = base.encodeToByteArray().also { it[at] = c.toByte() }
                    val viaString = if (c < 128) Bytes.fromB64Canonical(mutated.decodeToString()) else null
                    assertContentEquals(viaString, Bytes.fromB64Bytes(mutated), "$base[$at] = $c")
                }
            }
        }
        assertNull(Bytes.fromB64Bytes("A".encodeToByteArray()), "one character carries no byte")
        assertNull(Bytes.fromB64Bytes("AAAAA".encodeToByteArray()))
        assertNull(Bytes.fromB64Bytes("AB".encodeToByteArray()), "unused trailing bits must be zero")
        assertNull(Bytes.fromB64Bytes("AA==".encodeToByteArray()), "no padding")
        assertContentEquals(ByteArray(3), Bytes.fromB64Bytes("xxAAAAyy".encodeToByteArray(), 2, 6))
        assertNull(Bytes.fromB64Bytes("AAAA".encodeToByteArray(), 2, 9))
        assertNull(Bytes.fromB64Bytes("AAAA".encodeToByteArray(), -1, 3))
    }

    // ---- a secret field ---------------------------------------------------------------------------------

    private val grantFields = mapOf(
        "from" to Ids.ALICE, "to" to Ids.BOB, "toKey" to bob.key, "vaultId" to Ids.VAULT, "grantId" to grantId, "issuedAt" to Ids.T0.toString(),
    )

    @Test
    fun aSecretField_isWrittenFromBytes_readBackAsBytes_andAbsentFromTheValues() {
        val vk = crypto.randomBytes(32)
        val statement = StatementCodec.encode(TrustPurpose.VAULT_GRANT, grantFields, secrets = mapOf("vk" to vk))
        assertTrue(statement.decodeToString().endsWith(",\"vk\":\"${Bytes.toB64(vk)}\"}"))

        val frame = SignedFrame.sign(crypto, alice.sign, TrustPurpose.VAULT_GRANT, statement)
        val parsed = assertIs<Checked.Ok<ParsedFrame>>(StatementCodec.parseFrame(frame, TrustPurpose.VAULT_GRANT)).value
        assertEquals(setOf("v", "purpose", "from", "to", "toKey", "vaultId", "grantId", "issuedAt"), parsed.raw.values.keys)
        assertContentEquals(vk, parsed.raw.secret("vk"))
        assertFailsWith<IllegalStateException> { parsed.raw.secret("toKey") } // a plain field is not read this way
        assertFailsWith<NoSuchElementException> { parsed.raw.str("vk") }

        // Wiping the parts wipes what the parser worked on, and nothing is left to read.
        parsed.parts.wipe()
        assertTrue(isZero(parsed.parts.statement) && isZero(parsed.parts.signature) && isZero(parsed.parts.signerPub))
        assertFailsWith<IllegalStateException> { parsed.raw.secret("vk") }
    }

    @Test
    fun aSecretField_isRefusedAsText_withTheWrongLength_andOutsideItsGrammar() {
        val vk = crypto.randomBytes(32)
        val asText = Bytes.toB64(vk)
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_GRANT, grantFields + ("vk" to asText)) }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_GRANT, grantFields + ("vk" to asText), secrets = mapOf("vk" to vk)) }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_GRANT, grantFields, secrets = mapOf("vk" to vk.copyOf(31))) }
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.VAULT_GRANT, grantFields) }
        // A template without a secret takes none.
        val veto = mapOf("requestId" to grantId, "userId" to Ids.ALICE, "issuedAt" to Ids.T0.toString())
        assertFailsWith<IllegalArgumentException> { StatementCodec.encode(TrustPurpose.RECOVERY_VETO, veto, secrets = mapOf("vk" to vk)) }

        // The b64_32 grammar holds for the key where it stands: 43 characters, canonical.
        val text = StatementCodec.encode(TrustPurpose.VAULT_GRANT, grantFields, secrets = mapOf("vk" to ByteArray(32))).decodeToString()
        fun withVk(value: String): String =
            StatementCodec.parse(TrustPurpose.VAULT_GRANT, text.replace("\"vk\":\"${"A".repeat(43)}\"", "\"vk\":\"$value\"").encodeToByteArray()).verdictOrNull()?.code ?: "ok"
        assertEquals("ok", withVk("A".repeat(43)))
        assertEquals("non_canonical", withVk("A".repeat(42)))
        assertEquals("non_canonical", withVk("A".repeat(44)))
        assertEquals("non_canonical", withVk("A".repeat(42) + "B"), "non-zero trailing bits")
        assertEquals("non_canonical", withVk("A".repeat(42) + "+"), "the standard alphabet")
        assertEquals("non_canonical", withVk("A".repeat(42) + "="))
    }

    // ---- what an opener leaves behind --------------------------------------------------------------------

    @Test
    fun openingAGrant_zeroesTheOpenedFrame_onSuccessAndOnEveryRefusalAfterTheSeal() {
        val log = LogBuilder(crypto).also {
            it.genesis(alice)
            it.add(alice, bob, grantId)
        }
        fun sealedGrant(vk: ByteArray = log.vk, vaultId: String = Ids.VAULT, signer: Party = alice, id: String = grantId): ByteArray {
            val fields = GrantFields(Ids.ALICE, Ids.BOB, bob.key, vaultId, id, Ids.T0 + 5, vk)
            val frame = VaultGrant.sign(crypto, signer.sign, fields)
            fields.wipe()
            return VaultGrant.seal(crypto, bob.box.publicKey, frame).also { frame.fill(0) }
        }
        fun open(sealed: ByteArray, state: VaultState? = log.state): Pair<Checked<OpenedGrant, VaultGrantVerdict>, ByteArray> {
            val recording = Recording(crypto)
            val result = VaultGrant.open(recording, Ids.BOB, bob.box.publicKey, bob.box.privateKey, Ids.VAULT, sealed, state)
            return result to recording.opened.single()
        }

        val (ok, frame) = open(sealedGrant())
        val opened = assertIs<Checked.Ok<OpenedGrant>>(ok).value
        assertTrue(isZero(frame), "the opened frame")
        assertContentEquals(log.vk, opened.vk)
        opened.wipe()
        assertTrue(isZero(opened.vk))

        val refusals = listOf(
            VaultGrantVerdict.NON_CANONICAL to crypto.sealTo(bob.box.publicKey, SignedFrame.MAGIC + byteArrayOf(0x01) + ByteArray(96) + "{}".encodeToByteArray()),
            VaultGrantVerdict.VAULT_MISMATCH to sealedGrant(vaultId = Ids.OTHER_VAULT),
            VaultGrantVerdict.NO_ADD_ENTRY to sealedGrant(id = Ids.id16(2)),
            VaultGrantVerdict.NOT_AUTHORIZED to sealedGrant(signer = bob),
            VaultGrantVerdict.VK_COMMIT_MISMATCH to sealedGrant(vk = ByteArray(32) { 9 }),
        )
        for ((expected, sealed) in refusals) {
            val (result, openedFrame) = open(sealed)
            assertEquals(expected, result.verdictOrNull())
            assertTrue(isZero(openedFrame), "the opened frame after $expected")
        }
        val (noLog, openedFrame) = open(sealedGrant(), state = null)
        assertEquals(VaultGrantVerdict.NO_ADD_ENTRY, noLog.verdictOrNull())
        assertTrue(isZero(openedFrame))
    }

    @Test
    fun openingAnAssistedRecovery_zeroesTheOpenedFrame_onSuccessAndOnRefusal() {
        val recoverySeed = ByteArray(32) { (0x51 + it).toByte() }
        val recoverySigner = crypto.signKeypairFromSeed(recoverySeed)
        val recoveryFp = Bytes.toHexLower(crypto.sha256(crypto.boxKeypairFromSeed(recoverySeed).publicKey))
        val request = crypto.boxKeypairFromSeed(ByteArray(32) { 0x33 })
        val requestId = Ids.id16(4)
        val uvk = ByteArray(32) { (0x70 + it).toByte() }
        val identity = IdentityCheck(Envelope.sealB64(crypto, uvk, alice.seed, Ad.idkey(Ids.ALICE)), alice.key)

        val payload = AssistedRecoveryFields(Ids.INSTANCE, Ids.ALICE, requestId, Bytes.toB64(request.publicKey), uvk, Ids.T0)
        val frame = AssistedRecovery.sign(crypto, recoverySigner, payload)
        payload.wipe()
        assertTrue(isZero(payload.uvk))
        val sealed = AssistedRecovery.seal(crypto, request.publicKey, frame)

        fun open(instanceId: String): Pair<Checked<OpenedAssistedRecovery, RecoveryVerdict>, ByteArray> {
            val recording = Recording(crypto)
            val result = AssistedRecovery.open(recording, request.publicKey, request.privateKey, sealed, recoveryFp, instanceId, requestId, identity, null)
            return result to recording.opened.single()
        }
        val (ok, openedFrame) = open(Ids.INSTANCE)
        val opened = assertIs<Checked.Ok<OpenedAssistedRecovery>>(ok).value
        assertTrue(isZero(openedFrame), "the opened frame")
        assertContentEquals(uvk, opened.uvk)
        opened.wipe()
        assertTrue(isZero(opened.uvk))

        val (refused, refusedFrame) = open(Ids.OTHER_INSTANCE)
        assertEquals(RecoveryVerdict.REQUEST_MISMATCH, refused.verdictOrNull())
        assertTrue(isZero(refusedFrame), "the opened frame after a refusal")
    }

    @Test
    fun hkdf_zeroesThePseudorandomKey_everyBlock_andEveryBlockInput() {
        val recording = Recording(crypto)
        val ikm = crypto.randomBytes(32)
        val info = "andvari/v2|test".encodeToByteArray()
        val out = Hkdf.sha256(recording, ikm, ByteArray(0), info, 80)
        assertContentEquals(Hkdf.sha256(crypto, ikm, ByteArray(0), info, 80), out)
        assertEquals(4, recording.macs.size, "the PRK, then T(1), T(2), T(3)")
        for (mac in recording.macs) assertTrue(isZero(mac))
        assertSame(ikm, recording.macInputs[0], "the caller's key is the caller's")
        assertTrue(!isZero(ikm))
        for (input in recording.macInputs.drop(1)) assertTrue(isZero(input))
    }
}
