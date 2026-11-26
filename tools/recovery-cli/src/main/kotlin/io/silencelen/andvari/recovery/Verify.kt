package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.client.TerminalText
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowOpenException
import io.silencelen.andvari.core.crypto.EscrowVerdict
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.IdentityCheck
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

/** What the key a row's copy is sealed to is (spec 04 §4, "Which key each copy is sealed to"). */
enum class KeyStanding(val word: String) {
    /** The newest card's key (without `--instance-file`: the sheet's own). */
    CURRENT("current"),

    /** A key the card chain replaced and the signed rotations connect to the current one. */
    OUTGOING("outgoing"),

    /** A key nothing given to the tool proves: not the current key and not one the rotations lead from. */
    UNPROVEN("unproven"),

    /** The row names no key, and its copy did not open with the sheet. */
    UNKNOWN("unknown"),
}

/**
 * One row's result. [pass]: opened and checked with a sheet given; [skipped]: sealed (by the dump's word) to the current
 * key or an outgoing key the rotations prove, whose sheet was not given, so NOT CHECKED here: neither a PASS nor a FAIL,
 * and never counted as recoverable. [keyFp] is the key the copy is sealed to: proven when [pass] (the copy's own signed
 * statement names it), otherwise the dump's column, the server's word ([keyProven] false). [address] is the address the
 * opened copy names, null when it was not opened.
 */
data class EscrowVerifyResult(
    val userId: String,
    val pass: Boolean,
    val detail: String,
    val skipped: Boolean = false,
    val keyFp: String? = null,
    val keyStanding: KeyStanding = KeyStanding.UNKNOWN,
    val keyProven: Boolean = false,
    val address: String? = null,
)

object EscrowVerify {
    private val json = Json { ignoreUnknownKeys = true }

    /** The dump query the drill expects (printed when a dump lacks the identity columns). */
    const val DUMP_SQL =
        "SELECT e.userId, e.sealed, e.fingerprint, e.updatedAt, u.encryptedIdentitySeed, u.identityPub FROM escrow e LEFT JOIN users u ON u.userId = e.userId"

    private val HEX64 = Regex("^[0-9a-f]{64}$")

    /** A file's bytes as strict UTF-8: a byte sequence that is not UTF-8 throws, nothing is replaced. */
    fun strictText(bytes: ByteArray): String = bytes.decodeToString(throwOnInvalidSequence = true)

    fun parseDump(text: String): List<EscrowDumpRow> =
        json.decodeFromString(ListSerializer(EscrowDumpRow.serializer()), text)

    /**
     * Validate each blob exactly the way `recover` would consume it: [Escrow.open] with the row's
     * userId as `expectedUserId` and the row's identity columns as the identity check. The drill has
     * no per-member human anchor, so it opens in the acknowledged UNANCHORED mode and prints each
     * account's identity fingerprint for the admin to compare with their pins; a PASS still proves the
     * blob names its row's account, is sealed to this sheet, carries a valid signature by that identity
     * (v2), and opens that account's identity seed (both formats). The canary row has its own opener.
     *
     * One row, in this order (spec 04 §4, "Annual drill"): the `fingerprint` column against the keys of the sheets given
     * (the seed file's, and with [outgoing] each outgoing sheet the operator pasted): a column naming one of them picks the
     * sheet that opens the copy; a column naming an outgoing key whose sheet the operator said is no longer held is
     * `outgoing_sheet_gone`; with [history], a column naming the current key or an outgoing key the rotations prove, whose
     * sheet was not given, is a SKIP, NOT CHECKED; any other column is `recovery_fp_mismatch`. Then the copy's grammar
     * (`bad_copy`); the canary row (`canary_failed`); the identity columns (`identity_check_required`); then §4 steps 0 to 7.
     *
     * [outgoing]: null when the operator did not give `--outgoing-sheets`; otherwise each outgoing key's fingerprint to the
     * seed of its sheet, or to null when the operator said they no longer hold it. Every key derived here is wiped.
     */
    internal fun verify(
        crypto: CryptoProvider,
        seed: ByteArray,
        rows: List<EscrowDumpRow>,
        history: KeyHistory? = null,
        outgoing: Map<String, ByteArray?>? = null,
    ): List<EscrowVerifyResult> {
        val kp = crypto.boxKeypairFromSeed(seed)
        val fp = Escrow.fingerprint(crypto, kp.publicKey)
        val sheets = LinkedHashMap<String, io.silencelen.andvari.core.crypto.KeyPairBytes>()
        sheets[fp] = kp
        val gone = HashSet<String>()
        outgoing?.forEach { (k, s) -> if (s == null) gone += k else sheets.getOrPut(k) { crypto.boxKeypairFromSeed(s) } }
        val current = history?.current ?: fp
        fun standing(key: String?): KeyStanding = when {
            key == null -> KeyStanding.UNKNOWN
            key == current -> KeyStanding.CURRENT
            history?.outgoing?.any { it.fp == key } == true -> KeyStanding.OUTGOING
            else -> KeyStanding.UNPROVEN
        }
        try {
            return rows.map { row ->
                // The column is the server's word until the copy opens; anything not a hex64 names no key.
                val column = row.fingerprint?.takeIf { HEX64.matches(it) }
                val claimed = EscrowVerifyResult(row.userId, false, "", keyFp = column ?: row.fingerprint, keyStanding = if (row.fingerprint == null) KeyStanding.UNKNOWN else standing(column))
                try {
                    // A row that names no key is opened with the seed file's sheet, as it always was.
                    val openerFp = if (row.fingerprint == null) fp else row.fingerprint
                    val opener = sheets[openerFp] ?: run {
                        if (column != null && column in gone) {
                            return@map claimed.copy(
                                detail = "refused: outgoing_sheet_gone (sealed to the outgoing key ${KeyHistory.short(column)} by the server's word, and you said you no " +
                                    "longer hold that sheet: no sheet you hold opens this copy, so this account is NOT recoverable)",
                            )
                        }
                        if (claimed.keyStanding == KeyStanding.CURRENT || claimed.keyStanding == KeyStanding.OUTGOING) {
                            return@map claimed.copy(
                                skipped = true,
                                detail = "NOT CHECKED: sealed to the ${claimed.keyStanding.word} key by the server's word, and that sheet was not given; " +
                                    "this copy was not opened, so nothing proves it recoverable. Run again with that sheet" +
                                    (if (claimed.keyStanding == KeyStanding.OUTGOING) " (add --outgoing-sheets)" else "") + " to check it",
                            )
                        }
                        return@map claimed.copy(detail = "refused: ${EscrowVerdict.RECOVERY_FP_MISMATCH.code} (row fingerprint != this key ($fp) — sealed to a different recovery key)")
                    }
                    val sheet = standing(openerFp)
                    val sealed = Bytes.fromB64Canonical(row.sealed)?.takeIf { it.isNotEmpty() }
                        ?: return@map claimed.copy(detail = "refused: bad_copy (${RecoverCommand.BAD_COPY_SENTENCE})")
                    if (row.userId == Escrow.CANARY_USER_ID) {
                        return@map try {
                            Escrow.openCanary(crypto, opener, sealed)
                            claimed.copy(pass = true, detail = "canary ok", keyFp = openerFp, keyStanding = sheet, keyProven = true)
                        } catch (e: Exception) {
                            claimed.copy(detail = "refused: canary_failed (the canary does not open to its fixed payload with this sheet: ${e::class.simpleName})")
                        }
                    }
                    if (row.encryptedIdentitySeed == null || row.identityPub == null) {
                        // spec 04 §4 step 0.3: the identity file is absent, by its name.
                        return@map claimed.copy(detail = "refused: ${EscrowVerdict.IDENTITY_CHECK_REQUIRED.code} (the dump lacks the identity columns — re-export with: $DUMP_SQL)")
                    }
                    // spec 04 §4 steps 0 to 7: unanchored by design, nothing asked; nothing without the
                    // magic is read; a copy that does not say whose it is (version 2) cannot be used by assist. The opener
                    // requires the copy's own statement to name this sheet's key, so the key is proven from here on.
                    val opened = Escrow.openForFleet(crypto, opener, sealed, row.userId, IdentityCheck(row.encryptedIdentitySeed, row.identityPub))
                    opened.wipe()
                    val idFp = Fingerprint.shortForm(Escrow.fingerprint(crypto, opened.identityKey))
                    claimed.copy(
                        pass = true, detail = "v3 ok (unanchored: compare the identity with your pins), identity $idFp",
                        keyFp = openerFp, keyStanding = sheet, keyProven = true, address = opened.email,
                    )
                } catch (e: EscrowOpenException) {
                    claimed.copy(detail = "refused: ${e.verdict.code}" + when (e.verdict) {
                        EscrowVerdict.NO_ADDRESS -> " (${RecoverCommand.NO_ADDRESS_SENTENCE})"
                        EscrowVerdict.UNKNOWN_FORMAT -> " (${RecoverCommand.UNKNOWN_FORMAT_SENTENCE})"
                        else -> ""
                    })
                } catch (e: Throwable) {
                    // Never a stack trace and never an exception's message: the kind of fault only.
                    claimed.copy(detail = "refused: unexpected_fault (${e::class.simpleName})")
                }
            }
        } finally {
            sheets.values.forEach { it.privateKey.fill(0) }
        }
    }

    /** The key column: the first 32 hex of the fingerprint and what that key is; `(server)` when only the dump says so. */
    private fun keyColumn(r: EscrowVerifyResult): String = when (val k = r.keyFp) {
        null -> "-"
        else -> "${Fingerprint.shortForm(k)} ${r.keyStanding.word}${if (r.keyProven) "" else " (server)"}"
    }

    /**
     * The printed result table (A14, F12): header + one line per row. The userId, the key column and the address are the
     * server's dump data or come from it, and the detail can quote exception text, so every cell goes through
     * [TerminalText.escape]: a hostile row must not move the cursor over another row's FAIL.
     */
    fun tableLines(results: List<EscrowVerifyResult>, note: String = ""): List<String> =
        listOf("%-38s %-6s %-50s %-30s %s".format("userId", "result", "sealed to", "address", "detail")) +
            results.map {
                "%-38s %-6s %-50s %-30s %s".format(
                    TerminalText.escape(it.userId), if (it.pass) "PASS" else if (it.skipped) "SKIP" else "FAIL",
                    TerminalText.escape(keyColumn(it)), TerminalText.escape(it.address ?: "-"), TerminalText.escape(it.detail) + note,
                )
            }

    /**
     * The one line the operator reads before destroying an outgoing sheet (spec 04 §5): how many accounts still have a copy
     * sealed to an outgoing key, and which sheets they need. It says that an outgoing sheet is no longer needed only when
     * none is on one and every row opened with the current sheet here.
     */
    internal fun outgoingLine(results: List<EscrowVerifyResult>, history: KeyHistory?): String {
        if (history == null) {
            return "Accounts still on an outgoing key: not known (without --instance-file the tool cannot tell an outgoing key from a wrong one)."
        }
        val on = results.filter { it.keyStanding == KeyStanding.OUTGOING }
        if (on.isNotEmpty()) {
            val sheets = on.mapNotNull { it.keyFp }.distinct().joinToString(", ") { KeyHistory.short(it) }
            return "Accounts still on an outgoing key: ${on.size}. Keep the outgoing sheet ($sheets) until this line says 0.${history.note}"
        }
        val allCurrent = results.all { it.pass && it.keyStanding == KeyStanding.CURRENT }
        return if (allCurrent) {
            // What this rests on (spec 04 §4): the accounts in this download. One the server left out of it is not covered.
            "Accounts still on an outgoing key: 0. Every copy in this download (${results.size}) opened with the current sheet, so none of these accounts " +
                "needs an outgoing sheet any more. That rests on the download: an account the server left out of it is not covered. Before you " +
                "destroy an outgoing sheet, check that ${results.size} is the number of accounts you know have operator recovery on.${history.note}"
        } else {
            "Accounts still on an outgoing key: 0 shown, but not every copy opened with the current sheet here: do not destroy an outgoing sheet yet.${history.note}"
        }
    }

    /**
     * How the fleet check ends (spec 04 §4, "Which key each copy is sealed to"): [EXIT_ALL_GOOD] when every copy in the
     * download was opened and checked and none failed; [EXIT_FAILED] when any failed; [EXIT_NOT_ALL_CHECKED] when none
     * failed but some were not checked. A refusal before any row is checked is [EXIT_FAILED] too, as for every command.
     */
    internal fun exitStatus(results: List<EscrowVerifyResult>): Int = when {
        results.any { !it.pass && !it.skipped } -> EXIT_FAILED
        results.any { it.skipped } -> EXIT_NOT_ALL_CHECKED
        else -> EXIT_ALL_GOOD
    }

    const val EXIT_ALL_GOOD = 0
    const val EXIT_FAILED = 1
    const val EXIT_NOT_ALL_CHECKED = 2

    /**
     * Everything `verify` prints after its header: the table, the PASS count, what was not checked and why, the line on
     * outgoing keys, and the verdict. The verification is offline and complete in itself; there is no receipt to upload,
     * because the server has no route that takes one (`/admin/escrow/drill` does not exist). A copy that
     * was not opened (SKIP) is never counted as recoverable: the verdict names how many were not checked, and never says
     * "all" when any was not ([exitStatus] tells the three outcomes apart).
     */
    internal fun reportLines(results: List<EscrowVerifyResult>, history: KeyHistory? = null): List<String> {
        val fails = results.count { !it.pass && !it.skipped }
        val skipped = results.filter { it.skipped }
        val skips = skipped.size
        val passes = results.size - fails - skips
        val sheets = if (results.mapNotNull { r -> r.keyFp.takeIf { r.pass } }.distinct().size > 1) "these sheets" else "this sheet"
        val notChecked = if (skips == 0) emptyList() else {
            val why = skipped.groupBy { it.keyStanding to it.keyFp }.entries.joinToString("; ") { (k, rows) ->
                "${rows.size} sealed, by the server's word, to the ${k.first.word} key ${k.second?.let { KeyHistory.short(it) } ?: "-"}, whose sheet was not given"
            }
            listOf(
                "$skips NOT CHECKED (SKIP): $why. A copy that was not opened is not proven recoverable: run again with the sheet each names" +
                    (if (skipped.any { it.keyStanding == KeyStanding.OUTGOING }) " (an outgoing sheet: add --outgoing-sheets)" else "") + "." +
                    (history?.note ?: ""),
            )
        }
        val verdict = when {
                fails > 0 ->
                    "$fails escrow blob(s) FAILED — those accounts are NOT recoverable with this key (spec 04 §4: P1 incident, re-ceremony + re-escrow)" +
                        (if (skips > 0) "; and $skips more NOT CHECKED" else "")
                skips > 0 ->
                    "NOT ALL CHECKED: $skips of the ${results.size} copies in this download were not opened here, so not every account is proven " +
                        "recoverable; the $passes that were opened are recoverable with $sheets."
                else -> "All escrowed accounts in this download (${results.size}) are recoverable with $sheets."
            } + (history?.note ?: "")
        return tableLines(results, history?.note ?: "") + "" + "$passes/${results.size} PASS" + notChecked + outgoingLine(results, history) + verdict
    }
}
