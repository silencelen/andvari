package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.GrantPin
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.Keys
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.SignedGrant
import io.silencelen.andvari.core.crypto.Statement
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.WireGrant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Consumes spec/test-vectors/keyprecedence.json (security review 2026-10, root cause A §3.1 as it stands after A6/A7;
 * branch A1b) — the SAME file web `vault/keyprecedence.vectors.test.ts` grades. Every row is built into real crypto
 * (UVK wraps, v1 seals, v2 frames signed by real joint keys) and run through the functions production calls:
 * [Account.addGrant] for the precedence, and [Account.sealItem] for INV-WRITE-KEY.
 */
class KeyPrecedenceVectorTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys) {
        val userId: String get() = reg.userId
    }

    private fun enroll(email: String): Enrolled {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "dev", crypto)
        return Enrolled(
            reg, account,
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint, personalWrap = reg.personalWrap,
            ),
        )
    }

    private val owner by lazy { enroll("kp-owner@example.com") }
    private val member by lazy { enroll("kp-member@example.com") }
    private val stranger by lazy { enroll("kp-stranger@example.com") }

    private fun uvkOf(e: Enrolled): ByteArray =
        Envelope.openB64(crypto, Keys.wrapKey(crypto, Keys.masterKey(crypto, password, Bytes.fromB64(e.keys.kdfSalt), e.keys.kdfParams)), e.keys.wrappedUvk, Ad.uvk(e.userId))

    private fun seedOf(e: Enrolled): ByteArray = Envelope.openB64(crypto, uvkOf(e), e.keys.encryptedIdentitySeed, Ad.idkey(e.userId))

    private fun tag(k: ByteArray): String = Bytes.toHexLower(crypto.sha256(k))

    private fun tamper(b64: String): String {
        val raw = Bytes.fromB64(b64)
        raw[raw.size - 1] = (raw[raw.size - 1].toInt() xor 0x01).toByte()
        return Bytes.toB64(raw)
    }

    private val vectors: JsonObject by lazy {
        val dir = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set"))
        Json.parseToJsonElement(File(dir, "keyprecedence.json").readText()).jsonObject
    }

    private fun JsonElement?.str(): String? = if (this == null || this is JsonNull) null else jsonPrimitive.contentOrNull

    @Test
    fun everyRowMatchesTheDecisionTable() {
        val cases = vectors["cases"]!!.jsonArray
        assertTrue(cases.size >= 20, "the table is populated")
        val uvkM = uvkOf(member)
        for (c in cases) {
            val case = c.jsonObject
            val name = case["name"].str()!!
            val personal = case["vault"].str() == "personal"
            val vaultId = if (personal) member.reg.personalVault.vaultId else member.account.newItemId()
            val keyA = if (personal) Envelope.openB64(crypto, uvkM, member.reg.personalVault.wrappedVk, Ad.vk(vaultId, member.userId)) else crypto.randomBytes(32)
            val keyB = crypto.randomBytes(32)
            fun key(sym: String) = when (sym) { "A" -> keyA; "B" -> keyB; else -> error("unknown key $sym") }

            val device = Account.unlock(member.userId, password, member.keys, crypto)
            device.grantPins = { uid -> if (uid == owner.userId) GrantPin(Bytes.fromB64(owner.reg.identityPub), true) else null }
            (case["held"] as? JsonObject)?.let { h ->
                h["vouch"].str()?.let { device.authorizeLegacyKey(vaultId, tag(key(it)), frozen = h["kind"].str() == "frozen") }
                h["heldTag"].str()?.let { device.rememberHeldKey(vaultId, tag(key(it))) }
            }
            for ((i, r) in case["rows"]!!.jsonArray.withIndex()) {
                val row = r.jsonObject
                val wrapped = when (val w = row["wrappedVk"].str()) {
                    null -> ""
                    "damaged" -> tamper(Envelope.sealB64(crypto, uvkM, keyA, Ad.vk(vaultId, member.userId)))
                    else -> Envelope.sealB64(crypto, uvkM, key(w), Ad.vk(vaultId, member.userId))
                }
                val sealed = when (val s = row["sealedVk"].str()) {
                    null -> null
                    "foreign" -> Bytes.toB64(SharedGrant.seal(crypto, crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey, vaultId, keyA))
                    else -> Bytes.toB64(SharedGrant.seal(crypto, Bytes.fromB64(member.reg.identityPub), vaultId, key(s)))
                }
                val signed = (row["signedGrant"] as? JsonObject)?.let { sg ->
                    val (signerSeed, from) = when (sg["by"].str()) {
                        "owner" -> seedOf(owner) to owner.userId
                        "unpinned" -> seedOf(stranger) to stranger.userId
                        "impostor" -> crypto.randomBytes(32) to owner.userId
                        else -> error("unknown signer")
                    }
                    val frame = SignedGrant.buildFrame(
                        crypto, crypto.signKeypairFromSeed(signerSeed),
                        Statement.VaultGrant(from, member.userId, Bytes.fromB64(member.reg.identityPub), vaultId, crypto.randomBytes(16), 1_791_590_400_000, key(sg["vk"].str()!!)),
                    )
                    Bytes.toB64(crypto.sealTo(Bytes.fromB64(member.reg.identityPub), frame))
                }
                val grant = WireGrant(vaultId, member.userId, row["role"].str()!!, wrapped, 3L + i, sealed, signed)
                runCatching { device.addGrant(grant) }
            }

            val e = case["expect"]!!.jsonObject
            val heldTag = if (device.hasVault(vaultId)) device.legacyKeyTag(vaultId) else null
            val gotKey = when (heldTag) { null -> null; tag(keyA) -> "A"; tag(keyB) -> "B"; else -> "?" }
            val gotSource = if (device.hasVault(vaultId)) when (device.keySource(vaultId)) {
                Account.KeySource.PERSONAL_WRAP -> "personal_wrap"
                Account.KeySource.UVK_WRAP -> "uvk_wrap"
                Account.KeySource.SIGNED_GRANT -> "signed_grant"
                Account.KeySource.LEGACY_SEAL -> "legacy_seal"
                null -> null
            } else null
            val writable = runCatching { device.sealItem(SealProvenance.Chosen(vaultId), device.newItemId(), ItemDoc(type = "login", name = "probe")) }.isSuccess
            assertEquals(e["key"].str(), gotKey, "$name: key")
            assertEquals(e["source"].str(), gotSource, "$name: source")
            assertEquals(e["vkMismatch"]!!.jsonPrimitive.boolean, device.vkMismatch(vaultId), "$name: vkMismatch")
            assertEquals(e["keyUnreadable"]!!.jsonPrimitive.boolean, device.keyUnreadable(vaultId), "$name: keyUnreadable")
            assertEquals(e["pending"]!!.jsonPrimitive.boolean, device.pendingGrants().any { it.vaultId == vaultId }, "$name: pending")
            assertEquals(e["anomaly"].str(), device.grantAnomalies()[vaultId]?.code, "$name: anomaly")
            assertEquals(e["legacyReadOnly"]!!.jsonPrimitive.boolean, device.isLegacyReadOnly(vaultId), "$name: legacyReadOnly")
            assertEquals(e["writable"]!!.jsonPrimitive.boolean, writable, "$name: writable (INV-WRITE-KEY)")
        }
    }
}
