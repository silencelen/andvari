package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.client.TerminalText
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
import kotlinx.serialization.json.Json

/**
 * Opening ONE named member's escrow (security review 2026-10, root cause A §2.3; spec 04 §4), the part
 * of `assist` that names the account and its anchor:
 *
 * ```
 * --user <uuid> --identity-fp <>=32 hex> --identity-file <escrow-download.json>
 * --user <uuid> --no-identity-anchor --identity-file <escrow-download.json>
 * ```
 *
 * `--identity-file` is the operator's escrow download (`POST /admin/accounts/{userId}/escrow`): `{userId,
 * sealed, encryptedIdentitySeed, identityPub}`. It is server-supplied and is used ONLY as something to
 * check against. The blob defaults to its `sealed`.
 *
 * The old `recover` command (a temporary password and an upload bundle for a route that no longer
 * exists) is gone: no temporary password exists at any point (spec 04 §7).
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

    private val OPTIONS = setOf("--user", "--identity-fp", "--identity-file", "--no-identity-anchor", "--legacy")

    /** Step 0: refuse to start without `--user`, and without `--identity-fp` unless `--no-identity-anchor` (Q2). */
    fun parse(args: List<String>): RecoverOptions {
        var user: String? = null
        var fp: String? = null
        var noAnchor = false
        var identityFile: String? = null
        var legacy = false
        var blob: String? = null
        var i = 0
        val given = HashSet<String>()
        while (i < args.size) {
            if (args[i] in OPTIONS && !given.add(args[i])) throw RecoverRefused(repeatedOption(args[i], USAGE))
            when (val a = args[i]) {
                // A flag given last, with no value, is an absent argument: its own check below names it, in step 0's order.
                "--user" -> user = args.getOrNull(++i)
                "--identity-fp" -> fp = args.getOrNull(++i)
                "--identity-file" -> identityFile = args.getOrNull(++i)
                "--no-identity-anchor" -> noAnchor = true
                "--legacy" -> legacy = true
                else -> {
                    if (a.startsWith("--")) throw RecoverRefused("REFUSED (unknown_option): unknown option ${TerminalText.escape(a)}\n$USAGE")
                    if (blob != null) throw RecoverRefused("REFUSED (more_than_one_copy): more than one recovery copy given\n$USAGE")
                    blob = a
                }
            }
            i++
        }
        // spec 04 §4 step 0, in its one order: --user, the anchor, --identity-file.
        if (user == null || !UUID_RE.matches(user)) {
            throw RecoverRefused(
                "REFUSED (bad_user_id): recovery must name the account and its identity fingerprint (--user and --identity-fp, or --no-identity-anchor); " +
                    "--user is the account's lowercase uuid\n$USAGE",
            )
        }
        if (fp == null && !noAnchor) {
            throw RecoverRefused("REFUSED (bad_anchor): recovery must name the account and its identity fingerprint (--identity-fp, or --no-identity-anchor)\n$USAGE")
        }
        if (fp != null && noAnchor) throw RecoverRefused("REFUSED (bad_anchor): give either --identity-fp or --no-identity-anchor, not both")
        // The tool removes the separators a printed fingerprint is grouped with; it keeps case.
        val normFp = fp?.filter { it != ' ' && it != '-' && it != '\t' }
        if (normFp != null && (normFp.length !in Fingerprint.SHORT_HEX_LEN..64 || normFp.any { it !in "0123456789abcdef" })) {
            throw RecoverRefused(
                "REFUSED (bad_anchor): --identity-fp must be at least ${Fingerprint.SHORT_HEX_LEN} lowercase hex digits of the member's identity fingerprint (spaces and dashes are fine)",
            )
        }
        if (identityFile == null) throw RecoverRefused("REFUSED (identity_check_required): --identity-file is required: the admin escrow download for this account\n$USAGE")
        if (legacy && blob != null) throw RecoverRefused("REFUSED (legacy_refused): give either --legacy or an explicit blob, not both")
        return RecoverOptions(user, normFp, noAnchor, identityFile, blob, legacy)
    }

    /**
     * The identity file's bytes as the tool reads them (spec 04 §4 "Reading the identity file"): strict UTF-8, nothing
     * replaced, then [readIdentityFile]. Bytes that are not UTF-8 are `bad_identity_file`.
     */
    fun readIdentityFileBytes(bytes: ByteArray, opts: RecoverOptions): Pair<IdentityCheck, String> {
        if (bytes.size > ToolInput.IDENTITY_FILE_MAX) {
            throw RecoverRefused("REFUSED (bad_identity_file): --identity-file is larger than ${ToolInput.size(ToolInput.IDENTITY_FILE_MAX)}, so it is not a recovery-copy download")
        }
        val text = try {
            bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (e: CharacterCodingException) {
            throw RecoverRefused("REFUSED (bad_identity_file): --identity-file is not UTF-8 text, so it is not a recovery-copy download")
        }
        return readIdentityFile(text, opts)
    }

    /** The download's fields as read: each a JSON string, or null when absent or not a string. */
    private class Download(val userId: String, val sealed: String?, val encryptedIdentitySeed: String, val identityPub: String, val legacySealed: String?)

    fun readIdentityFile(text: String, opts: RecoverOptions): Pair<IdentityCheck, String> {
        val notADownload = "REFUSED (bad_identity_file): --identity-file is not a recovery-copy download (expected {userId, sealed, encryptedIdentitySeed, identityPub})"
        // A download is the four fields the server sends; other fields beside them are ignored. Its own `sealed` is read
        // only when no copy is given in its place (spec 04 §4, "Reading the identity file"). A key given twice, or nesting
        // deeper than the limit, is refused before the parser would keep the last value silently.
        ToolInput.jsonProblem(text)?.let { throw RecoverRefused("REFUSED (bad_identity_file): --identity-file is not a recovery-copy download: $it") }
        val obj = try {
            json.parseToJsonElement(text) as? kotlinx.serialization.json.JsonObject
        } catch (e: Throwable) {
            null
        } ?: throw RecoverRefused(notADownload)
        fun str(name: String): String? = (obj[name] as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { it.isString }?.content
        val dl = Download(
            str("userId") ?: throw RecoverRefused(notADownload),
            str("sealed"),
            str("encryptedIdentitySeed") ?: throw RecoverRefused(notADownload),
            str("identityPub") ?: throw RecoverRefused(notADownload),
            str("legacySealed"),
        )
        if (opts.sealedB64 == null && !opts.useLegacy && dl.sealed == null) throw RecoverRefused(notADownload)
        // Every field the server wrote is checked against its grammar before it is used or shown,
        // and none is ever printed. The file's own userId is server-supplied and only a hint; a mismatch is still worth a
        // hard stop because it means the admin carried the wrong file.
        if (!UUID_RE.matches(dl.userId)) throw RecoverRefused("REFUSED (bad_identity_file): --identity-file's userId is not an account id")
        if (Bytes.fromB64Canonical(dl.encryptedIdentitySeed).let { it == null || it.isEmpty() }) {
            throw RecoverRefused("REFUSED (bad_identity_file): --identity-file's encryptedIdentitySeed is not base64url")
        }
        if (dl.userId != opts.userId) throw RecoverRefused("REFUSED (identity_file_mismatch): --identity-file is for another account, not ${opts.userId}")
        // The identity file's key, before the seed is asked for (the shared opener checks it again at its step 0).
        if (Bytes.fromB64Exact(dl.identityPub, 32) == null) {
            throw RecoverRefused("REFUSED (${EscrowVerdict.IDENTITY_CHECK_FAILED.code}): --identity-file's identityPub is not a 32-byte key")
        }
        val sealed = when {
            opts.sealedB64 != null -> opts.sealedB64
            opts.useLegacy -> dl.legacySealed ?: throw RecoverRefused("REFUSED (legacy_refused): --legacy: the download carries no retained legacy blob")
            else -> dl.sealed!!
        }
        // The copy as it will be opened: exactly as given, canonical base64url, decided before the seed is asked for.
        if (Bytes.fromB64Canonical(sealed).let { it == null || it.isEmpty() }) throw RecoverRefused("REFUSED (bad_copy): $BAD_COPY_SENTENCE")
        return IdentityCheck(dl.encryptedIdentitySeed, dl.identityPub) to sealed
    }

    /**
     * A typed confirmation as the tool reads it (spec 04 §4 step 2): space and tab removed from both ends,
     * nothing else (not the platform's wider white space); the shared opener then compares it exactly.
     */
    fun typedLine(line: String): String = line.trim { it == ' ' || it == '\t' }

    /** What the tool says for a copy that is not canonical unpadded base64url exactly as given. */
    const val BAD_COPY_SENTENCE = "the recovery copy is not base64url (exactly as given, with nothing around it)"

    /** Human-readable abort for each [EscrowVerdict] (design §2.3 table, abridged messages). */
    fun abortMessage(v: EscrowVerdict, opts: RecoverOptions, detail: String?): String = when (v) {
        EscrowVerdict.UNOPENABLE -> "not sealed to this household recovery key"
        EscrowVerdict.UNKNOWN_FORMAT -> UNKNOWN_FORMAT_SENTENCE
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
        EscrowVerdict.BAD_EMAIL -> "--email is not an address. Type the address of the person you are helping"
        // spec 04 §4 step 7: the sentence the specification gives.
        EscrowVerdict.NO_ADDRESS -> NO_ADDRESS_SENTENCE
        EscrowVerdict.EMAIL_MISMATCH -> "this recovery copy is another account's, not that of the address you typed. Do not continue: the server gave you another account's copy"
    } + (detail?.let { " [$it]" } ?: "")

    /** What both sentences below end with. */
    private const val ONLY_A_SIGNED_IN_PERSON =
        "If the person can still sign in on some device, they can seal a new copy there by turning operator recovery off and on again, " +
            "and you download the copy again. If they cannot sign in anywhere, the operator cannot recover this account."

    /** spec 04 §4 step 4: what `assist` and `verify` say for a copy without the magic. */
    const val UNKNOWN_FORMAT_SENTENCE =
        "This recovery copy is damaged, or was sealed before recovery copies were signed, and cannot be used. " + ONLY_A_SIGNED_IN_PERSON

    /**
     * spec 04 §4 step 7: what the tool says for a copy of the old form. Turning operator
     * recovery off and on needs the master password, which a locked-out person has lost, so the sentence says the truth.
     */
    const val NO_ADDRESS_SENTENCE =
        "This recovery copy does not say whose it is, so it cannot be checked against the person you are helping and cannot be used. " +
            ONLY_A_SIGNED_IN_PERSON

    /** spec 04 §4 step 8: whose copy it is, in the account's own signed words. Both addresses are `emailNorm`s, so plain ASCII. */
    fun emailMismatchSentence(copyEmail: String, typed: String): String =
        "This recovery copy is ${TerminalText.escape(copyEmail)}'s, not ${TerminalText.escape(typed)}'s. Do not continue: the server gave you another account's copy."

    /**
     * Steps 1–12 against an already-read sheet seed. [readLine] supplies the operator's typed lines (the
     * unanchored acknowledgment, then the `RECOVER <first 8>` confirmation); [out] receives the
     * operator display; [produces] names what the typed confirmation generates (`assist`: the signed
     * answer). Returns the opened escrow ONLY after the confirmation was typed — nothing is generated
     * before that.
     */
    fun openAndConfirm(
        crypto: CryptoProvider,
        org: KeyPairBytes,
        opts: RecoverOptions,
        /** The `emailNorm` of the address the operator typed (`--email`): the copy must name it (spec 04 §4 steps 7 and 8). */
        typedEmail: String,
        identityCheck: IdentityCheck,
        sealedB64: String,
        produces: String,
        readLine: () -> String?,
        /** A line said after the sheet's key, when another sheet signs the answer (spec 04 §5: a copy sealed to an outgoing key). */
        signedWith: String? = null,
        /** What is added to `unopenable`'s sentence: why the copy may be sealed to another key, and what to do. */
        unopenableHint: String? = null,
        out: (String) -> Unit,
    ): EscrowOpened {
        // Step 1: print the org key the sheet opens, grouped, so the admin sees which household key this is.
        out("Recovery key (from the sheet): ${Fingerprint.groupedShort(Escrow.fingerprint(crypto, org.publicKey)).replace("\n", " / ")}")
        signedWith?.let(out)
        var ack: String? = null
        if (opts.unanchored) {
            out("")
            out("WARNING: --no-identity-anchor. Without the member's identity fingerprint this recovery cannot tell")
            out("a genuine backstop key from one the SERVER minted with a matching forged identity (design §2.3, Q2).")
            out("It still refuses a key swapped in from another member. Type exactly:")
            out("    ${Escrow.UNANCHORED_ACK}")
            ack = readLine()?.let { typedLine(it) }
        }
        val sealed = Bytes.fromB64Canonical(sealedB64)?.takeIf { it.isNotEmpty() } ?: throw RecoverRefused("REFUSED (bad_copy): $BAD_COPY_SENTENCE")
        val opened = try {
            Escrow.openForAssist(crypto, org, sealed, opts.userId, typedEmail, opts.identityFpPrefix, identityCheck, ack)
        } catch (e: EscrowOpenException) {
            val copyEmail = e.copyEmail
            if (e.verdict == EscrowVerdict.EMAIL_MISMATCH && copyEmail != null) {
                throw RecoverRefused("REFUSED (${e.verdict.code}): " + emailMismatchSentence(copyEmail, typedEmail))
            }
            val hint = if (e.verdict == EscrowVerdict.UNOPENABLE && unopenableHint != null) " $unopenableHint" else ""
            throw RecoverRefused("REFUSED (${e.verdict.code}): " + abortMessage(e.verdict, opts, null) + hint)
        }
        // Step 9: show what was proven, whose copy it is in the account's own signed words, and require the typed confirmation.
        val idFp = Escrow.fingerprint(crypto, opened.identityKey)
        out("")
        out("account:  ${opened.userId}")
        out("address:  ${TerminalText.escape(opened.email ?: "")} (named by the copy, signed by the account; the address you typed)")
        out("identity: ${Fingerprint.groupedShort(idFp).replace("\n", " / ")}")
        out("format:   ${opened.format.code} (signed, names its address)")
        out("anchored: ${if (opened.anchored) "yes" else "NO — UNANCHORED"}")
        val expect = "RECOVER ${opened.userId.take(8)}"
        out("Type '$expect' to generate $produces:")
        if (readLine()?.let { typedLine(it) } != expect) {
            opened.wipe()
            throw RecoverRefused("REFUSED (not_confirmed): confirmation not typed — nothing generated")
        }
        return opened
    }
}
