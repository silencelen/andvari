package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowFormat
import io.silencelen.andvari.core.crypto.EscrowOpenException
import io.silencelen.andvari.core.crypto.EscrowOpened
import io.silencelen.andvari.core.crypto.EscrowVerdict
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.IdentityCheck
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.model.AdminEscrowDownload
import kotlinx.serialization.json.Json

/**
 * `recover` (security review 2026-10, root cause A §2.3; spec 04 §4). New command shape:
 *
 * ```
 * recover --user <uuid> --identity-fp <>=32 hex> --identity-file <escrow-download.json> [<sealedBlobB64>]
 * recover --user <uuid> --no-identity-anchor --identity-file <escrow-download.json> [<sealedBlobB64>]
 * ```
 *
 * `--identity-file` is the admin escrow download (`GET /admin/users/{id}/escrow`): `{sealed,
 * encryptedIdentitySeed, identityPub, legacySealed?}`. It is server-supplied and is used ONLY as
 * something to check against. The blob defaults to its `sealed`; pass `--legacy` to recover from the
 * retained pre-migration blob instead, or give a blob explicitly.
 */
internal class RecoverOptions(
    val userId: String,
    /** Normalised lowercase hex (>= 32 digits), or null with [unanchored]. */
    val identityFpPrefix: String?,
    val unanchored: Boolean,
    val identityFile: String,
    val sealedB64: String?,
    val useLegacy: Boolean,
)

internal class RecoverRefused(message: String) : Exception(message)

internal object RecoverCommand {
    private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private val json = Json { ignoreUnknownKeys = true }

    const val USAGE =
        "usage: recover --user <uuid> (--identity-fp <32+ hex> | --no-identity-anchor) --identity-file <escrow-download.json> [--legacy] [<sealedBlobB64>]"

    /** Step 0: refuse to start without `--user`, and without `--identity-fp` unless `--no-identity-anchor` (Q2). */
    fun parse(args: List<String>): RecoverOptions {
        var user: String? = null
        var fp: String? = null
        var noAnchor = false
        var identityFile: String? = null
        var legacy = false
        var blob: String? = null
        var i = 0
        while (i < args.size) {
            when (val a = args[i]) {
                "--user" -> user = args.getOrNull(++i) ?: throw RecoverRefused("--user needs a value")
                "--identity-fp" -> fp = args.getOrNull(++i) ?: throw RecoverRefused("--identity-fp needs a value")
                "--identity-file" -> identityFile = args.getOrNull(++i) ?: throw RecoverRefused("--identity-file needs a value")
                "--no-identity-anchor" -> noAnchor = true
                "--legacy" -> legacy = true
                else -> {
                    if (a.startsWith("--")) throw RecoverRefused("unknown option $a\n$USAGE")
                    if (blob != null) throw RecoverRefused("more than one blob given\n$USAGE")
                    blob = a
                }
            }
            i++
        }
        if (user == null || (fp == null && !noAnchor)) {
            throw RecoverRefused("recovery must name the account and its identity fingerprint (--user and --identity-fp, or --no-identity-anchor)\n$USAGE")
        }
        if (!UUID_RE.matches(user)) throw RecoverRefused("--user must be the account's lowercase uuid")
        if (fp != null && noAnchor) throw RecoverRefused("give either --identity-fp or --no-identity-anchor, not both")
        val normFp = fp?.lowercase()?.filter { it != ' ' && it != '-' && it != '\t' }
        if (normFp != null && (normFp.length !in Fingerprint.SHORT_HEX_LEN..64 || normFp.any { it !in "0123456789abcdef" })) {
            throw RecoverRefused("--identity-fp must be at least ${Fingerprint.SHORT_HEX_LEN} hex digits of the member's identity fingerprint (spaces and dashes are fine)")
        }
        if (identityFile == null) throw RecoverRefused("--identity-file is required: the admin escrow download for this account\n$USAGE")
        if (legacy && blob != null) throw RecoverRefused("give either --legacy or an explicit blob, not both")
        return RecoverOptions(user, normFp, noAnchor, identityFile, blob, legacy)
    }

    fun readIdentityFile(text: String, opts: RecoverOptions): Pair<IdentityCheck, String> {
        val dl = try {
            json.decodeFromString(AdminEscrowDownload.serializer(), text)
        } catch (e: Exception) {
            throw RecoverRefused("--identity-file is not an admin escrow download (expected {sealed, encryptedIdentitySeed, identityPub})")
        }
        // The file's own userId is server-supplied and only a hint; a mismatch is still worth a hard stop
        // because it means the admin carried the wrong file.
        if (dl.userId != opts.userId) throw RecoverRefused("--identity-file is for account ${dl.userId}, not ${opts.userId}")
        val sealed = when {
            opts.sealedB64 != null -> opts.sealedB64
            opts.useLegacy -> dl.legacySealed ?: throw RecoverRefused("--legacy: the download carries no retained legacy blob")
            else -> dl.sealed
        }
        return IdentityCheck(dl.encryptedIdentitySeed, dl.identityPub) to sealed
    }

    /** Human-readable abort for each [EscrowVerdict] (design §2.3 table, abridged messages). */
    fun abortMessage(v: EscrowVerdict, opts: RecoverOptions, detail: String?): String = when (v) {
        EscrowVerdict.UNOPENABLE -> "not sealed to this household recovery key"
        EscrowVerdict.UNKNOWN_FORMAT -> "unknown backstop key format"
        EscrowVerdict.BAD_FRAME, EscrowVerdict.NON_CANONICAL, EscrowVerdict.BAD_STATEMENT,
        EscrowVerdict.V1_MALFORMED, EscrowVerdict.V1_SELF_CHECK_FAILED,
        -> "malformed backstop key (${v.code})"
        EscrowVerdict.USER_MISMATCH -> "this backstop key belongs to another account, not ${opts.userId}: the server substituted it"
        EscrowVerdict.RECOVERY_FP_MISMATCH -> "sealed for a different recovery key"
        EscrowVerdict.IDENTITY_FP_MISMATCH -> "identity does not match the fingerprint you were given: possible server substitution"
        EscrowVerdict.SIGNER_NOT_PINNED_KEY -> "signature key does not belong to this identity"
        EscrowVerdict.BAD_SIGNATURE -> "backstop key signature invalid"
        EscrowVerdict.IDENTITY_MISMATCH -> "the backstop key names a different identity than the one you anchored: possible server substitution"
        EscrowVerdict.IDENTITY_CHECK_FAILED -> "the escrowed key does not open this account's identity"
        EscrowVerdict.IDENTITY_CHECK_REQUIRED -> "a backstop key can only be recovered with the identity check (--identity-file)"
        EscrowVerdict.UNANCHORED_NOT_ACKNOWLEDGED -> "unanchored recovery was not acknowledged"
        EscrowVerdict.BAD_ANCHOR -> "--identity-fp must be at least 32 hex digits"
        EscrowVerdict.BAD_USER_ID -> "--user must be the account's lowercase uuid"
    } + (detail?.let { " [$it]" } ?: "")

    /**
     * Steps 1–12 against an already-read sheet seed. [readLine] supplies the admin's typed lines (the
     * unanchored acknowledgment, then the `RECOVER <first 8>` confirmation); [out] receives the
     * operator display. Returns the opened escrow ONLY after the confirmation was typed — nothing is
     * generated or written before that (step 13 is the caller's).
     */
    fun openAndConfirm(
        crypto: CryptoProvider,
        org: KeyPairBytes,
        opts: RecoverOptions,
        identityCheck: IdentityCheck,
        sealedB64: String,
        readLine: () -> String?,
        out: (String) -> Unit,
    ): EscrowOpened {
        // Step 1: print the org key the sheet opens, grouped, so the admin sees which household key this is.
        out("Recovery key (from the sheet): ${Fingerprint.groupedShort(Escrow.fingerprint(crypto, org.publicKey)).replace("\n", " / ")}")
        var ack: String? = null
        if (opts.unanchored) {
            out("")
            out("WARNING: --no-identity-anchor. Without the member's identity fingerprint this recovery cannot tell")
            out("a genuine backstop key from one the SERVER minted with a matching forged identity (design §2.3, Q2).")
            out("It still refuses a key swapped in from another member. Type exactly:")
            out("    ${Escrow.UNANCHORED_ACK}")
            ack = readLine()?.trim()
        }
        val sealed = try {
            Bytes.fromB64(sealedB64.trim())
        } catch (e: Exception) {
            throw RecoverRefused("the backstop key is not base64url")
        }
        val opened = try {
            Escrow.open(crypto, org, sealed, opts.userId, opts.identityFpPrefix, identityCheck, ack)
        } catch (e: EscrowOpenException) {
            throw RecoverRefused("REFUSED: " + abortMessage(e.verdict, opts, null))
        }
        // Step 12: show what was proven and require the typed confirmation.
        val idFp = Escrow.fingerprint(crypto, opened.identityKey)
        out("")
        out("account:  ${opened.userId}")
        out("identity: ${Fingerprint.groupedShort(idFp).replace("\n", " / ")}")
        out("format:   ${if (opened.format == EscrowFormat.V2) "v2 (signed)" else "v1 (legacy, identity-checked)"}")
        out("anchored: ${if (opened.anchored) "yes" else "NO — UNANCHORED"}")
        val expect = "RECOVER ${opened.userId.take(8)}"
        out("Type '$expect' to generate the temporary password and the bundle:")
        if (readLine()?.trim() != expect) {
            opened.wipe()
            throw RecoverRefused("confirmation not typed — nothing generated")
        }
        return opened
    }
}
