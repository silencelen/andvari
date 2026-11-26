package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * The personal wrap opened at every session open ([AccountOpen.check], design §5.3) takes no vault key of zeros out
 * (spec 01, "Keys in memory and the lock", rule 4): such a wrap does not open, so no personal vault is in force, as for
 * any wrap that does not open. Before, the zeros were held as the personal vault's key, and every later open under it
 * was refused by the key floor as though the account were locked. Only someone holding the account's key can make it.
 */
class AccountOpenZeroPersonalWrapTest {
    private val crypto = createCryptoProvider()

    private fun str(o: JsonObject, k: String): String? = o[k]?.takeIf { it !is JsonNull }?.jsonPrimitive?.contentOrNull

    private val doc by lazy { Json.parseToJsonElement(readVector("accountgenesis.json")).jsonObject }
    private val account by lazy { doc.getValue("account").jsonObject }
    private val valid by lazy { doc.getValue("rows").jsonArray.map { it.jsonObject }.first { str(it, "name") == "valid" } }
    private val userId by lazy { str(valid, "sessionUserId")!! }
    private val vaultId by lazy { str(doc, "personalVaultId")!! }
    private val uvk by lazy { Bytes.fromB64(str(account, "uvkB64")!!) }

    private fun open(wrap: PersonalWrap): OpenedAccount {
        val seed = Bytes.fromB64(str(account, "seedB64")!!)
        return assertIs<AccountOpenResult.Opened>(AccountOpen.check(
            crypto, userId, uvk.copyOf(), crypto.boxKeypairFromSeed(seed), crypto.signKeypairFromSeed(seed),
            str(account, "identityPubB64")!!, str(valid, "genesisB64")!!, wrap, str(valid, "pinnedInstanceId")!!, null,
        )).account
    }

    /**
     * The test plays a party that holds the account's key: a personal wrap whose plaintext is 32 zero bytes, built at the
     * provider because the shared envelope refuses to wrap a wiped key. The only function here that puts zeros through it.
     */
    private fun wrapOfZeros(key: ByteArray, ad: ByteArray): String {
        val nonce = crypto.randomBytes(Envelope.NONCE_BYTES)
        val ct = crypto.aeadEncrypt(key, nonce, ByteArray(32), ad)
        return Bytes.toB64(byteArrayOf(Envelope.VERSION, Envelope.ALG_XCHACHA20POLY1305_IETF) + nonce + ct)
    }

    // Building the hostile wrap seals 32 zero bytes at the provider, which the zero-key tripwire counts: [wrapOfZeros] is
    // the one place it lists as expected for this class. The open itself happens outside it and records nothing. Fails on
    // the code before the check (the personal vault was in force under a key of zeros).
    @Test fun aPersonalWrapOfAZeroVaultKeyDoesNotOpenAndNoPersonalVaultIsInForce() {
        val opened = open(PersonalWrap(vaultId, wrapOfZeros(uvk, Ad.vkPersonal(vaultId, userId))))
        assertNull(opened.personalVaultId)
        assertNull(opened.personalVk)
        opened.wipe()
    }

    @Test fun aVaultKeyWithOneNonZeroByteStillOpens() {
        val near = ByteArray(32).also { it[31] = 1 }
        val opened = open(PersonalWrap(vaultId, Envelope.sealB64(crypto, uvk, near, Ad.vkPersonal(vaultId, userId))))
        assertEquals(vaultId, opened.personalVaultId)
        opened.wipe()
    }
}
