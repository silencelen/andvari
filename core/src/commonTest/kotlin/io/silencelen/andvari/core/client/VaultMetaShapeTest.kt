package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Security review 2026-10, branch A11 (q55, LOW; web vaultmeta-shape.test.ts twin): the vault meta plaintext is authored
 * by ANY holder of the vault key. A non-object document (`null`, a string, an array, a number) made `decryptVaultMeta`
 * throw a generic IllegalArgumentException and crashed the owner's rename. Now the read refuses it with
 * [MalformedVaultMetaException], and a rename over it writes a clean meta (the new name, the counter restarted).
 */
class VaultMetaShapeTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)

    private fun enroll(email: String): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        return Account.enroll("test-invite", email, email, "pw $email", kdf, recovery.publicKey, fp, "test-device", crypto).account
    }

    @Test
    fun aNonObjectMeta_isRefusedOnRead_andReplacedCleanlyOnRename() {
        val owner = enroll("owner@example.com")
        val vaultId = owner.buildCreateSharedVault("Family").vaultId
        val kp = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val vk = SharedGrant.open(crypto, kp.publicKey, kp.privateKey, vaultId, Bytes.fromB64(owner.wrapVkForMember(kp.publicKey, vaultId)))
        for (junk in listOf("null", "\"abc\"", "[1,2,3]", "7", "true", "not json")) {
            val blob = Envelope.sealB64(crypto, vk, junk.encodeToByteArray(), Ad.vaultMeta(vaultId))
            assertFailsWith<MalformedVaultMetaException>(junk) { owner.decryptVaultMeta(vaultId, blob) }
            val renamed = owner.buildRenameMeta(vaultId, blob, "Clean")
            assertEquals(buildJsonObject { put("name", "Clean"); put("metaV", 1L) }, owner.decryptVaultMeta(vaultId, renamed), junk)
        }
        // A genuine object still round-trips its unknown fields.
        val blob = Envelope.sealB64(crypto, vk, """{"name":"X","metaV":3,"extra":"kept"}""".encodeToByteArray(), Ad.vaultMeta(vaultId))
        val meta = owner.decryptVaultMeta(vaultId, owner.buildRenameMeta(vaultId, blob, "Y"))
        assertEquals(JsonPrimitive("kept"), meta["extra"])
        assertEquals(JsonPrimitive(4L), meta["metaV"])
    }
}
