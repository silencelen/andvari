package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/**
 * Fleet escrow canary (spec 04): unseal EVERY escrowed blob with the printed recovery
 * seed and prove each account is actually recoverable — the check the server can never
 * perform (crypto_box_seal blobs open only with the offline secret key; the server-side
 * gate is structural only, see server requireEscrowBlob). OFFLINE like everything here:
 * input is a sqlite dump file + the seed file, no network, nothing written.
 */

/** One row of the server escrow-table dump: `sqlite3 -json <db> "SELECT ... FROM escrow"`. */
@Serializable
data class EscrowDumpRow(
    val userId: String,
    val sealed: String,
    val fingerprint: String? = null,
    val updatedAt: Long? = null,
)

data class EscrowVerifyResult(val userId: String, val pass: Boolean, val detail: String)

object EscrowVerify {
    private val json = Json { ignoreUnknownKeys = true }

    fun parseDump(text: String): List<EscrowDumpRow> =
        json.decodeFromString(ListSerializer(EscrowDumpRow.serializer()), text)

    /**
     * Validate each blob exactly the way `recover` would consume it: unseal with the
     * seed's keypair (Escrow.open also enforces v==1 + the sha256 self-check), then
     * check keyType, the payload↔row userId binding, and the 32-byte key length.
     * A canary row (fixed userId, spec 04 §4) is validated against its fixed payload.
     */
    fun verify(crypto: CryptoProvider, seed: ByteArray, rows: List<EscrowDumpRow>): List<EscrowVerifyResult> {
        val kp = crypto.boxKeypairFromSeed(seed)
        val fp = Escrow.fingerprint(crypto, kp.publicKey)
        return rows.map { row ->
            try {
                if (row.fingerprint != null && row.fingerprint != fp) {
                    return@map EscrowVerifyResult(row.userId, false, "row fingerprint != this key ($fp) — sealed to a different recovery key")
                }
                val payload = Escrow.open(crypto, kp.publicKey, kp.privateKey, Bytes.fromB64(row.sealed))
                when {
                    payload.userId != row.userId ->
                        EscrowVerifyResult(row.userId, false, "payload userId=${payload.userId} does not match row")
                    payload.keyType == Escrow.KEY_TYPE_CANARY ->
                        if (row.userId == Escrow.CANARY_USER_ID && Bytes.fromB64(payload.key).contentEquals(Escrow.CANARY_KEY)) {
                            EscrowVerifyResult(row.userId, true, "canary ok")
                        } else {
                            EscrowVerifyResult(row.userId, false, "canary payload mismatch")
                        }
                    payload.keyType != Escrow.KEY_TYPE_UVK ->
                        EscrowVerifyResult(row.userId, false, "unexpected keyType=${payload.keyType}")
                    Bytes.fromB64(payload.key).size != 32 ->
                        EscrowVerifyResult(row.userId, false, "escrowed key is not 32 bytes")
                    else -> EscrowVerifyResult(row.userId, true, "uvk ok")
                }
            } catch (e: Exception) {
                EscrowVerifyResult(row.userId, false, "unseal failed: ${e.message}")
            }
        }
    }
}
