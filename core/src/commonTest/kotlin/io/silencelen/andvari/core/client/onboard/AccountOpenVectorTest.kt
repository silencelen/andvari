package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.client.items.copyOut
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.readVector
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Grades the engine's unlock checks ([AccountOpen.check]) on `spec/test-vectors/accountgenesis.json`: every row's
 * first failing verdict, and on `ok` rows whether the personal vault is in force (design §5.2, §5.3).
 */
class AccountOpenVectorTest {
    private val crypto = createCryptoProvider()

    private fun str(o: JsonObject, k: String): String? = o[k]?.takeIf { it !is JsonNull }?.jsonPrimitive?.contentOrNull

    @Test fun everyRow() {
        val doc = Json.parseToJsonElement(readVector("accountgenesis.json")).jsonObject
        val account = doc.getValue("account").jsonObject
        val seed = Bytes.fromB64(str(account, "seedB64")!!)
        val uvk = Bytes.fromB64(str(account, "uvkB64")!!)
        val rows = doc.getValue("rows").jsonArray.map { it.jsonObject }
        assertTrue(rows.size >= 28)
        for (r in rows) {
            val name = str(r, "name")!!
            val wrap = (r["personalWrap"] as? JsonObject)?.let { PersonalWrap(str(it, "vaultId")!!, str(it, "wrappedVkB64")!!) }
            val got = AccountOpen.check(
                crypto, str(r, "sessionUserId")!!, uvk.copyOf(), crypto.boxKeypairFromSeed(seed), crypto.signKeypairFromSeed(seed),
                str(account, "identityPubB64")!!, str(r, "genesisB64")!!, wrap, str(r, "pinnedInstanceId")!!, null,
            )
            val expect = r.getValue("expect").jsonObject
            val verdict = str(expect, "verdict")!!
            if (verdict == "ok") {
                val opened = assertIs<AccountOpenResult.Opened>(got, name).account
                val inForce = expect.getValue("personalVaultInForce").jsonPrimitive.boolean
                assertEquals(inForce, opened.personalVaultId != null, name)
                if (inForce) assertEquals(str(doc, "personalVaultId"), opened.personalVaultId, name)
                if (inForce) assertEquals(str(doc, "personalVkB64"), Bytes.toB64(opened.personalVk!!.copyOut()), name)
            } else {
                assertEquals(verdict, assertIs<AccountOpenResult.IdentityFault>(got, name).reason, name)
            }
        }
    }

    @Test fun theSeedAndServedKeyChecksComeFirst() {
        val doc = Json.parseToJsonElement(readVector("accountgenesis.json")).jsonObject
        val account = doc.getValue("account").jsonObject
        val seed = Bytes.fromB64(str(account, "seedB64")!!)
        val valid = doc.getValue("rows").jsonArray.map { it.jsonObject }.first { str(it, "name") == "valid" }
        val uvk = ByteArray(32) { 5 }
        fun check(identityPub: String, genesis: String?, known: ByteArray? = null) = AccountOpen.check(
            crypto, str(valid, "sessionUserId")!!, uvk.copyOf(), crypto.boxKeypairFromSeed(seed), crypto.signKeypairFromSeed(seed),
            identityPub, genesis, null, str(valid, "pinnedInstanceId")!!, known,
        )
        assertEquals("identity_mismatch", (check(Bytes.toB64(ByteArray(32)), str(valid, "genesisB64")) as AccountOpenResult.IdentityFault).reason)
        assertEquals("no_genesis", (check(str(account, "identityPubB64")!!, null) as AccountOpenResult.IdentityFault).reason)
        assertEquals("self_identity_mismatch", (check(str(account, "identityPubB64")!!, str(valid, "genesisB64"), ByteArray(32) { 1 }) as AccountOpenResult.IdentityFault).reason)
        assertIs<AccountOpenResult.Opened>(check(str(account, "identityPubB64")!!, str(valid, "genesisB64"), Bytes.fromB64(str(account, "identityPubB64")!!)))
    }
}
