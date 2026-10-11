package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowFormat
import io.silencelen.andvari.core.crypto.EscrowOpenException
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.model.EscrowDrillPass
import io.silencelen.andvari.core.model.EscrowDrillReceipt
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

/**
 * One row of the server escrow dump. Since escrow v2 (security review 2026-10, root cause A) the drill
 * goes through the same [Escrow.open] as `recover`, which REQUIRES the account's identity file, so the
 * dump joins the users table:
 *
 * ```
 * sqlite3 -json <db> "SELECT e.userId, e.sealed, e.fingerprint, e.updatedAt, u.encryptedIdentitySeed, u.identityPub
 *                     FROM escrow e LEFT JOIN users u ON u.userId = e.userId"
 * ```
 *
 * A row without the two identity columns FAILS: a drill PASS has to mean `recover` would succeed.
 */
@Serializable
data class EscrowDumpRow(
    val userId: String,
    val sealed: String,
    val fingerprint: String? = null,
    val updatedAt: Long? = null,
    val encryptedIdentitySeed: String? = null,
    val identityPub: String? = null,
)

data class EscrowVerifyResult(
    val userId: String,
    val pass: Boolean,
    val detail: String,
    /** hex SHA-256 of the drilled blob bytes, for the drill receipt (§8.4 drill hook); null on FAIL or canary. */
    val sealedSha256: String? = null,
)

object EscrowVerify {
    private val json = Json { ignoreUnknownKeys = true }
    private val receiptJson = Json { prettyPrint = true }

    /** The dump query the drill expects (printed when a dump lacks the identity columns). */
    const val DUMP_SQL =
        "SELECT e.userId, e.sealed, e.fingerprint, e.updatedAt, u.encryptedIdentitySeed, u.identityPub FROM escrow e LEFT JOIN users u ON u.userId = e.userId"

    fun parseDump(text: String): List<EscrowDumpRow> =
        json.decodeFromString(ListSerializer(EscrowDumpRow.serializer()), text)

    /**
     * Validate each blob exactly the way `recover` would consume it: [Escrow.open] with the row's
     * userId as `expectedUserId` and the row's identity columns as the identity check. The drill has
     * no per-member human anchor, so it opens in the acknowledged UNANCHORED mode and prints each
     * account's identity fingerprint for the admin to compare with their pins; a PASS still proves the
     * blob names its row's account, is sealed to this sheet, carries a valid signature by that identity
     * (v2), and opens that account's identity seed (both formats). The canary row has its own opener.
     */
    fun verify(crypto: CryptoProvider, seed: ByteArray, rows: List<EscrowDumpRow>): List<EscrowVerifyResult> {
        val kp = crypto.boxKeypairFromSeed(seed)
        val fp = Escrow.fingerprint(crypto, kp.publicKey)
        return rows.map { row ->
            try {
                if (row.fingerprint != null && row.fingerprint != fp) {
                    return@map EscrowVerifyResult(row.userId, false, "row fingerprint != this key ($fp) — sealed to a different recovery key")
                }
                val sealed = Bytes.fromB64(row.sealed)
                if (row.userId == Escrow.CANARY_USER_ID) {
                    return@map try {
                        Escrow.openCanary(crypto, kp, sealed)
                        EscrowVerifyResult(row.userId, true, "canary ok")
                    } catch (e: Exception) {
                        EscrowVerifyResult(row.userId, false, "canary payload mismatch: ${e.message}")
                    }
                }
                if (row.encryptedIdentitySeed == null || row.identityPub == null) {
                    return@map EscrowVerifyResult(row.userId, false, "dump lacks the identity columns — re-export with: $DUMP_SQL")
                }
                val opened = Escrow.open(
                    crypto, kp, sealed, row.userId, null,
                    IdentityCheck(row.encryptedIdentitySeed, row.identityPub), Escrow.UNANCHORED_ACK,
                )
                opened.wipe()
                val idFp = Fingerprint.shortForm(Escrow.fingerprint(crypto, opened.identityKey))
                val what = if (opened.format == EscrowFormat.V2) "v2 ok" else "v1 legacy ok (re-seal pending)"
                EscrowVerifyResult(row.userId, true, "$what, identity $idFp", Bytes.toHexLower(crypto.sha256(sealed)))
            } catch (e: EscrowOpenException) {
                EscrowVerifyResult(row.userId, false, "refused: ${e.verdict.code}")
            } catch (e: Exception) {
                EscrowVerifyResult(row.userId, false, "unseal failed: ${e.message}")
            }
        }
    }

    /**
     * The drill receipt (§8.4 drill hook) for `POST /api/v1/admin/escrow/drill`: one entry per PASSED
     * member row with the drilled blob's hash, so the server drops the retained legacy blob only for an
     * account whose CURRENT blob is the one this drill opened.
     */
    fun receipt(results: List<EscrowVerifyResult>): String = receiptJson.encodeToString(
        EscrowDrillReceipt.serializer(),
        EscrowDrillReceipt(results.filter { it.pass && it.sealedSha256 != null }.map { EscrowDrillPass(it.userId, it.sealedSha256!!) }),
    )
}
