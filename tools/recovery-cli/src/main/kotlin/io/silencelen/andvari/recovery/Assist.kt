package io.silencelen.andvari.recovery

import io.silencelen.andvari.core.client.TerminalText
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowVerdict
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RotationFields

private val UUID_RE = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

/**
 * [s] exactly as given is canonical unpadded base64url of [n] bytes (V4-C2, V4-C3: nothing is trimmed, so the value
 * checked is the value used; an id or a key with white space around it is refused by its name).
 */
private fun b64Exact(s: String, n: Int): ByteArray? = Bytes.fromB64Exact(s, n)

/** An option given twice (every command): refused by this name, never taken as its last value. */
internal fun repeatedOption(option: String, usage: String): String =
    "REFUSED (repeated_option): ${TerminalText.escape(option)} is given more than once; give each option once\n$usage"

/**
 * `assist`'s options: `recover`'s account, anchor and identity file, plus the request it answers and [email], the
 * `emailNorm` of the address the operator TYPED for the person they are helping (spec 04 §4 step 0, §7 step 3).
 */
internal class AssistOptions(
    val recover: RecoverOptions,
    val requestId: String,
    val requestKey: ByteArray,
    val instanceId: String,
    val email: String,
    /**
     * `--instance-file`: the server's `GET /api/v1/instance` answer, saved by the operator, for a copy sealed to a key the
     * server has since replaced ([KeyHistory], spec 04 §5). Null: the one-sheet assist, as before.
     */
    val instanceFile: String? = null,
    /**
     * `--card0-hash`: the hash of the server's first card, which the operator holds; [instanceFile] is checked from it.
     * Null with an [instanceFile] only when the operator gave `--instance-file-unchecked`.
     */
    val card0Hash: String? = null,
)

/**
 * What `assist` produced (spec 04 §7 step 3): the sealed version-3 answer and the hash of its commit value. The commit
 * value itself was zeroed once sealed: only the person's device, which opens the answer, can present it.
 */
internal class AssistAnswer(val sealed: ByteArray, val commitHash: String)

/**
 * `recovery-cli assist` (spec 04 §7 step 3, design §9.3): answer one operator-assisted recovery request,
 * offline.
 *
 * ```
 * assist --instance <uuid> --request <requestId> --request-key <rPub> --request-code <typed> --email <address>
 *        --user <uuid> --identity-file <escrow-download.json> (--identity-fp <32+ hex> | --no-identity-anchor)
 * ```
 *
 * In order (spec 04 §7 step 3): every argument's grammar, `--email` included (the address of the person the operator
 * is helping, typed from the operator's own knowledge); the typed request code must be
 * the one computed from `--request-key` (so a server that swapped `rPub` is caught before the seed is even asked
 * for); the copy is opened through spec 04 §4's steps ([RecoverCommand.openAndConfirm]: it must be the version-3 form
 * and name the typed address, and the operator types `RECOVER <first 8>` having seen it); then the version-3 0x09
 * statement `{instanceId, userId, email, requestId, requestKey, commit, uvk, issuedAt}` with a fresh commit value is
 * signed by the recovery seed's Ed25519 key and sealed to `rPub`. The last line printed is the answer token the
 * operator uploads ([io.silencelen.andvari.core.trust.AnswerToken]). No temporary password exists.
 *
 * `--instance` is not in spec 04 §7's command line, but the 0x09 statement names the instance and the CLI
 * is offline: the operator copies it from the instance card (or `andvari admin status`).
 */
internal object AssistCommand {
    const val USAGE =
        "usage: assist --instance <uuid> --request <requestId> --request-key <rPub> --request-code <code> --email <their address> " +
            "--user <uuid> (--identity-fp <32+ hex> | --no-identity-anchor) --identity-file <escrow-download.json> " +
            "[--instance-file <the server's GET /api/v1/instance answer> (--card0-hash <64 hex> | --instance-file-unchecked)]"

    /** Every option `assist` has; each may be given once. */
    private val ASSIST_OPTIONS = setOf(
        "--request", "--request-key", "--request-code", "--instance", "--email", "--instance-file", "--card0-hash", "--instance-file-unchecked",
        "--user", "--identity-fp", "--identity-file", "--no-identity-anchor", "--legacy",
    )

    /** The smallest and the first too-large time with 13 decimal digits: the answer's size assumes them (spec 04 §7 step 3). */
    private const val CLOCK_FROM = 1_000_000_000_000L
    private const val CLOCK_UNTIL = 10_000_000_000_000L

    /**
     * The tool's clock, checked with the arguments, before the identity file is read or the seed asked for
     * ("refuses to run" means before anything is read); [answer] checks the same value again and signs it.
     */
    fun checkClock(now: Long) {
        if (now !in CLOCK_FROM until CLOCK_UNTIL) throw RecoverRefused("REFUSED (bad_clock): this machine's clock is wrong (it reads $now ms): set it and run again")
    }

    fun parse(crypto: CryptoProvider, args: List<String>): AssistOptions {
        var request: String? = null
        var key: String? = null
        var code: String? = null
        var instance: String? = null
        var email: String? = null
        var instanceFile: String? = null
        var card0Hash: String? = null
        var unchecked = false
        val rest = ArrayList<String>()
        var copies = 0
        var i = 0
        // The command line itself, before any value is checked (every refusal has a name). A flag given last,
        // with no value, is an absent argument: its own check below names it, in its order.
        val given = HashSet<String>()
        while (i < args.size) {
            val a0 = args[i]
            // An option given twice is refused by its own name, never taken as its last value.
            if (a0 in ASSIST_OPTIONS && !given.add(a0)) throw RecoverRefused(repeatedOption(a0, USAGE))
            when (val a = a0) {
                "--request" -> request = args.getOrNull(++i)
                "--request-key" -> key = args.getOrNull(++i)
                "--request-code" -> code = args.getOrNull(++i)
                "--instance" -> instance = args.getOrNull(++i)
                "--email" -> email = args.getOrNull(++i)
                "--instance-file" -> instanceFile = args.getOrNull(++i)
                "--card0-hash" -> card0Hash = args.getOrNull(++i) ?: ""
                "--instance-file-unchecked" -> unchecked = true
                "--user", "--identity-fp", "--identity-file" -> args.getOrNull(++i)?.let { rest += a; rest += it }
                "--no-identity-anchor" -> rest += a
                "--legacy" -> throw RecoverRefused("REFUSED (legacy_refused): assist opens the account's current recovery copy only; --legacy is gone\n$USAGE")
                else -> {
                    if (a.startsWith("--")) throw RecoverRefused("REFUSED (unknown_option): unknown option ${TerminalText.escape(a)}\n$USAGE")
                    if (++copies > 1) throw RecoverRefused("REFUSED (more_than_one_copy): more than one recovery copy given\n$USAGE")
                    rest += a
                }
            }
            i++
        }
        // spec 04 §7 step 3.1: assist's own three request arguments, in this order; then §4 step 0; then the code (3.2).
        if (instance == null || !UUID_RE.matches(instance)) throw RecoverRefused("REFUSED (bad_instance): --instance must be the instance's lowercase uuid\n$USAGE")
        if (request == null || b64Exact(request, 16) == null) throw RecoverRefused("REFUSED (bad_request_id): --request must be the request id (22 base64url characters)\n$USAGE")
        val rPub = key?.let { b64Exact(it, 32) } ?: throw RecoverRefused("REFUSED (bad_request_key): --request-key must be the request's 32-byte key in base64url\n$USAGE")
        // A low-order point would make the seal's shared secret a constant anyone can compute: refuse it here,
        // before the seed is asked for and the escrow opened (seal refuses it too, but only after both).
        if (!AssistedRecovery.requestKeyUsable(rPub)) {
            throw RecoverRefused("REFUSED (low_order_request_key): the request key is not a usable key (a low-order point); nothing may be sealed to it. Do not continue.")
        }
        val recover = try {
            RecoverCommand.parse(rest)
        } catch (e: RecoverRefused) {
            throw RecoverRefused((e.message ?: "").replace(RecoverCommand.USAGE, USAGE))
        }
        if (email == null) {
            throw RecoverRefused(
                "REFUSED (${EscrowVerdict.BAD_EMAIL.code}): assist needs --email: the address of the person you are helping, typed from what " +
                    "you know of them (not copied from the console). The recovery copy must name it.\n$USAGE",
            )
        }
        val emailNorm = TrustGrammar.emailNorm(email)
            ?: throw RecoverRefused("REFUSED (${EscrowVerdict.BAD_EMAIL.code}): --email is not an address. Type the address of the person you are helping.")
        // A copy given on the command line in place of the download's: exactly as given, canonical base64url.
        recover.sealedB64?.let { if (Bytes.fromB64Canonical(it).let { b -> b == null || b.isEmpty() }) throw RecoverRefused("REFUSED (bad_copy): ${RecoverCommand.BAD_COPY_SENTENCE}") }
        // The check that stops a server which swapped rPub: the person read this code from their own app.
        if (code == null || !AssistedRecovery.requestCodeMatches(crypto, code, rPub)) {
            throw RecoverRefused(
                "REFUSED (request_code_mismatch): the request code does not match this request key. Do not continue: the key the server showed " +
                    "is not the one on the person's device.",
            )
        }
        // spec 04 §5: the instance file is checked from the hash of the first card the operator holds, or it is unchecked by
        // the operator's explicit word; decided here, before any file is read or any seed asked for.
        val anchor = KeyHistory.anchorOptions(instanceFile, card0Hash, unchecked, USAGE)
        return AssistOptions(recover, request, rPub, instance, emailNorm, instanceFile, anchor)
    }

    /**
     * The sealed version-3 0x09 answer (spec 04 §7 step 3): [uvk] (wiped here) and a fresh commit value, with [copyEmail]
     * (the opened copy's own address, which the opener proved is the typed one), signed by the recovery seed's signing
     * key and sealed to the request key; and the commit value's hash. [seed] is the sheet's recovery seed; the caller
     * wipes it. Refuses a clock whose milliseconds do not have 13 digits, because the answer's one size assumes them.
     */
    fun answer(crypto: CryptoProvider, seed: ByteArray, opts: AssistOptions, copyEmail: String, uvk: ByteArray, issuedAt: Long): AssistAnswer {
        val commit = crypto.randomBytes(32)
        try {
            checkClock(issuedAt)
            if (copyEmail != opts.email) throw RecoverRefused("REFUSED: the copy names another address than the one you typed")
            val signer = crypto.signKeypairFromSeed(seed)
            try {
                val fields = AssistedRecoveryFields(
                    opts.instanceId, opts.recover.userId, opts.requestId, Bytes.toB64(opts.requestKey), uvk, issuedAt, email = copyEmail, commit = commit,
                )
                val frame = AssistedRecovery.sign(crypto, signer, fields)
                fields.wipe()
                try {
                    return AssistAnswer(AssistedRecovery.seal(crypto, opts.requestKey, frame), AssistedRecovery.commitHash(crypto, commit))
                } finally {
                    frame.fill(0)
                }
            } finally {
                signer.privateKey.fill(0)
            }
        } finally {
            uvk.fill(0)
            commit.fill(0)
        }
    }
}

/**
 * `recovery-cli rotate` (spec 04 §5): the 0x08 statement that moves every opted-in person's consent from the
 * OUTGOING recovery key (the seed read from its sheet) to the new public key.
 *
 * ```
 * rotate --instance <uuid> --to <newPubB64>
 * ```
 *
 * The output is the frame the operator stores with `PUT /instance/rotation` before signing the card that
 * names the new `recoveryFp`.
 */
internal object RotateCommand {
    const val USAGE = "usage: rotate --instance <uuid> --to <new recovery public key, base64url>"

    class Options(val instanceId: String, val toPub: ByteArray)

    fun parse(args: List<String>): Options {
        var instance: String? = null
        var to: String? = null
        var i = 0
        val given = HashSet<String>()
        // The command line first, as assist reads its own: an unknown option, an option given twice; a flag given last with
        // no value is an absent argument, named by its own check below.
        while (i < args.size) {
            val a = args[i]
            if ((a == "--instance" || a == "--to") && !given.add(a)) throw RecoverRefused(repeatedOption(a, USAGE))
            when (a) {
                "--instance" -> instance = args.getOrNull(++i)
                "--to" -> to = args.getOrNull(++i)
                else -> throw RecoverRefused("REFUSED (unknown_option): unknown option ${TerminalText.escape(a)}\n$USAGE")
            }
            i++
        }
        if (instance == null || !UUID_RE.matches(instance)) throw RecoverRefused("REFUSED (bad_instance): --instance must be the instance's lowercase uuid\n$USAGE")
        val pub = to?.let { b64Exact(it, 32) }
            ?: throw RecoverRefused("REFUSED (bad_key): --to must be the new recovery public key: 32 bytes in base64url, exactly as given\n$USAGE")
        return Options(instance, pub)
    }

    /** The signed rotation and its fields. [outgoingSeed] is the outgoing sheet's seed; the caller wipes it. */
    fun statement(crypto: CryptoProvider, outgoingSeed: ByteArray, opts: Options, issuedAt: Long): Pair<ByteArray, RotationFields> {
        val fromFp = Escrow.fingerprint(crypto, crypto.boxKeypairFromSeed(outgoingSeed).publicKey)
        val toFp = Escrow.fingerprint(crypto, opts.toPub)
        if (fromFp == toFp) throw RecoverRefused("REFUSED (same_key): the new key is the outgoing key: nothing to rotate. Nothing was produced.")
        val fields = RotationFields(opts.instanceId, fromFp, toFp, issuedAt)
        val signer = crypto.signKeypairFromSeed(outgoingSeed)
        try {
            return RecoveryRotation.sign(crypto, signer, fields) to fields
        } finally {
            signer.privateKey.fill(0)
        }
    }
}
