package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The account genesis record (design 2026-11-15 §5; verdicts and order of §2.4, VR-13), graded off
 * `accountgenesis.json` from the independent oracle. Every row is one unlock of the same account: the
 * signing and identity keys are derived from the seed (never taken from the server), and the genesis is
 * checked against them (the signer byte for byte against the Ed25519 key, §2.4 row 0x05), the session's
 * `userId`, the pinned card's `instanceId` and the served personal wrap.
 *
 * `expect.extensionVerdict` is the extension's reading. Since every client binds the signer the same way,
 * it must equal `expect.verdict` on every row, and this suite checks that it does.
 */
class AccountGenesisVectorTest {
    private val crypto = createCryptoProvider()
    private val v = vector("accountgenesis.json")
    private val account = v.o("account")
    private val identityPub = crypto.boxKeypairFromSeed(account.b64("seedB64")).publicKey
    private val signPub = crypto.signKeypairFromSeed(account.b64("seedB64")).publicKey

    /** §5.3: a served wrap that names the genesis's personal vault AND opens under the UVK with the personal AD is in force. */
    private fun personalVaultInForce(wrap: JsonObject?, genesis: VerifiedGenesis): Boolean {
        if (wrap == null || wrap.s("vaultId") != genesis.fields.personalVaultId) return false
        return try {
            Envelope.open(crypto, account.b64("uvkB64"), wrap.b64("wrappedVkB64"), Ad.vkPersonal(wrap.s("vaultId"), genesis.fields.userId))
            true
        } catch (e: CryptoException) {
            false
        }
    }

    @Test
    fun theFileHasTheSectionsThisSuiteGrades_andNoOther() {
        assertSections(v, "_about", "account", "instanceId", "personalVaultId", "personalVkB64", "rows")
    }

    @Test
    fun rows_everyUnlockGetsItsExactVerdict() {
        assertContentEquals(account.b64("identityPubB64"), identityPub)
        assertContentEquals(account.b64("signPubB64"), signPub)
        val seen = HashSet<String>()
        gradeEvery("accountgenesis.rows", v.rows("rows")) { r ->
            val name = r.s("name")
            val expect = r.o("expect")
            val wrap = r.oOrNull("personalWrap")
            assertEquals(expect.s("verdict"), expect.s("extensionVerdict"), "$name: every client binds the signer the same way")
            val okKeys = if (expect.s("verdict") == "ok") setOf("personalVaultInForce") else emptySet()
            assertExpectGraded(expect, setOf("verdict", "extensionVerdict") + okKeys, name)
            val result = AccountGenesis.verify(
                crypto, r.b64("genesisB64"), signPub, identityPub, r.s("sessionUserId"), r.s("pinnedInstanceId"), wrap?.s("vaultId"),
            )
            when (result) {
                is Checked.Refused -> assertEquals(expect.s("verdict"), result.verdict.code, "$name: ${r.s("why")}")
                is Checked.Ok -> {
                    assertEquals(expect.s("verdict"), "ok", "$name: ${r.s("why")}")
                    val genesis = result.value
                    assertEquals(SignedFrame.hash(crypto, r.b64("genesisB64")), genesis.hash, name)
                    assertEquals(account.s("userId"), genesis.fields.userId, name)
                    assertEquals(account.s("identityPubB64"), genesis.fields.identityKey, name)
                    assertEquals(v.s("instanceId"), genesis.fields.instanceId, name)
                    assertEquals(v.s("personalVaultId"), genesis.fields.personalVaultId, name)
                    assertEquals(expect.bool("personalVaultInForce"), personalVaultInForce(wrap, genesis), name)
                }
            }
            seen += expect.s("verdict")
        }
        val named = listOf(
            "ok", "bad_frame", "unknown_format", "non_canonical", "bad_statement", "signer_not_pinned_key", "bad_signature",
            "identity_mismatch", "user_mismatch", "instance_mismatch", "personal_vault_mismatch",
        )
        for (verdict in named) assertTrue(verdict in seen, "no row for $verdict")
    }

    @Test
    fun theValidRow_signsToTheSameBytes() {
        val valid = v.rows("rows").first { it.s("name") == "valid" }
        val genesis = Bytes.fromB64(valid.s("genesisB64"))
        val verified = AccountGenesis.verify(crypto, genesis, signPub, identityPub, account.s("userId"), v.s("instanceId"), v.s("personalVaultId"))
        val fields = (verified as Checked.Ok).value.fields
        assertContentEquals(genesis, AccountGenesis.sign(crypto, crypto.signKeypairFromSeed(account.b64("seedB64")), fields))
        assertEquals(valid.s("statementUtf8"), (SignedFrame.split(genesis) as Checked.Ok).value.statement.decodeToString())
    }
}
