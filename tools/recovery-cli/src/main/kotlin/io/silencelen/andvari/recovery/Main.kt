package io.silencelen.andvari.recovery

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.EscrowVerdict
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.trust.RecoveryRotation
import java.time.LocalDate

/**
 * andvari recovery-cli — OFFLINE escrow ceremony and the operator's half of assisted recovery (spec 04).
 * Runs on an air-gapped machine. No network I/O anywhere (verified by test:
 * no HTTP classes on the classpath), and a server-URL argument anywhere on the
 * command line is refused outright (spec 04 §5). The org recovery private seed
 * lives only in memory during a command and on the printed sheet / USB — never
 * on disk here, never on the server, never in git/PBS/B2.
 *
 * There is no temporary password at any point (spec 04 §7): the person sets their own new master
 * password on their own device, after the app opens the signed answer `assist` produces.
 *
 * Commands:
 *   keygen                              generate the org recovery keypair + printable sheet
 *   fingerprint <pubkeyB64>             show the fingerprint of a public key
 *   canary make <pubkeyB64>             seal the fixed canary blob (store server-side)
 *   canary verify <sealedB64>           open the canary with the printed seed (proves the sheet works)
 *   verify <seedFile> <dumpJson>        fleet canary: unseal EVERY escrow blob from a sqlite dump,
 *                                       PASS/FAIL per user, exit 1 on any FAIL (the drill is
 *                                       docs/drills/escrow-canary-drill.md — recorded elsewhere)
 *   assist …                            open ONE named member's escrow (spec 04 §4) and emit the 0x09
 *                                       answer for an assisted-recovery request (spec 04 §7 step 3)
 *   rotate --instance <uuid> --to <pub> sign a 0x08 rotation with the outgoing seed (spec 04 §5)
 */

private val crypto = createCryptoProvider()

fun main(args: Array<String>) {
    // spec 04 §5: this tool is OFFLINE — no command takes a server address, so a server
    // URL among the args means a confused (or hostile) invocation. Refuse before dispatch.
    serverUrlArg(args)?.let {
        die("REFUSED (server_url_refused): argument '$it' looks like an andvari server URL — recovery-cli is offline-only and never contacts a server (spec 04 §5)")
    }
    try {
        when (args.getOrNull(0)) {
            "keygen" -> keygen()
            "fingerprint" -> fingerprint(args.getOrNull(1) ?: "")
            "canary" -> when (args.getOrNull(1)) {
                "make" -> canaryMake(args.getOrNull(2) ?: "")
                "verify" -> canaryVerify(args.getOrNull(2) ?: "")
                else -> die("REFUSED (unknown_option): $CANARY_USAGE")
            }
            "verify" -> verifyDump(args.drop(1))
            "assist" -> assist(args.drop(1))
            "rotate" -> rotate(args.drop(1))
            else -> die(
                """
                andvari recovery-cli (OFFLINE — run air-gapped)
                  keygen
                  fingerprint <pubkeyB64>
                  canary make <pubkeyB64>
                  canary verify <sealedB64>
                  verify <seedFile> <escrowDumpJson> [--instance-file <file> [--outgoing-sheets]]
                  assist --instance <uuid> --request <requestId> --request-key <rPub> --request-code <code> --email <their address> --user <uuid> (--identity-fp <32+ hex> | --no-identity-anchor) --identity-file <escrow-download.json>
                  rotate --instance <uuid> --to <newRecoveryPubB64>
                """.trimIndent(),
            )
        }
    } catch (e: RecoverRefused) {
        die(e.message ?: "refused")
    } catch (e: Throwable) {
        // Never a stack trace: the kind of fault, no message.
        die("REFUSED (unexpected_fault): an unexpected fault (${e::class.simpleName ?: "unknown"}). Nothing was produced.")
    }
}

/**
 * spec 04 §5 guard: any URL-ish argument — a scheme (`https://…`, `wss://…`), or a bare
 * server-host shape — marks the invocation as confused/hostile. HOST-AGNOSTIC by design
 * (2026-07-15 §5.5): andvari is self-hostable, so ANY origin must be refused as loudly as the
 * reference instance's — no hardcoded hostnames. A bare host is: dotted DNS labels with at
 * least three labels (`andvari.monahanhosting.com`, any `*.ts.net` tailnet name, an IPv4), or
 * any dotted name carrying a `:port` (`myvault.net:8443`). Legitimate arguments are
 * subcommands, base64url blobs, and local file paths — none contain "://", and anything with a
 * path separator is never host-shaped, so a multi-dotted FILENAME that trips the guard can
 * always be passed as `./name`.
 */
internal fun serverUrlArg(args: Array<String>): String? = args.firstOrNull { arg ->
    val a = arg.lowercase()
    "://" in a || BARE_HOST.matches(a)
}

private const val HOST_LABEL = """[a-z0-9]([a-z0-9-]*[a-z0-9])?"""
private val BARE_HOST = Regex("""$HOST_LABEL(\.$HOST_LABEL){2,}(:\d{1,5})?|$HOST_LABEL(\.$HOST_LABEL)+:\d{1,5}""")

private fun keygen() {
    print(keygenSheet(crypto.randomBytes(32)))
}

/**
 * The printable recovery sheet (spec 04 §1): seed (base64url + QR), pubkey, fingerprints,
 * generation date, env snippet, and next steps including the assisted-recovery one-liner. A pure
 * text builder so tests can pin the sheet's required fields without capturing stdout.
 */
internal fun keygenSheet(seed: ByteArray, generatedOn: LocalDate = LocalDate.now()): String = buildString {
    val kp = crypto.boxKeypairFromSeed(seed)
    val fp = Escrow.fingerprint(crypto, kp.publicKey)
    // Security review 2026-10, root cause A (A5): the human short form is 32 hex (128 bits), never the
    // legacy 16-hex id, and every machine compare (the in-person QR rfp included) is the full value above.
    val short = Fingerprint.groupedShort(fp).replace("\n", " ")

    appendLine("=".repeat(64))
    appendLine("  andvari ORG RECOVERY KEY — PRINT THIS SHEET x2, COPY SEED TO USB")
    appendLine("  The private seed below can decrypt EVERY escrowed vault.")
    appendLine("  Store the two sheets + USB in separate secure places. Never photograph")
    appendLine("  to a networked device, never type into the server or any online machine.")
    appendLine("=".repeat(64))
    appendLine()
    appendLine("Generated: $generatedOn") // spec 04 §1: the sheet carries its generation date
    appendLine()
    appendLine("Recovery seed (base64url) — SECRET:")
    appendLine("    ${Bytes.toB64(seed)}")
    appendLine()
    appendLine("Public key (base64url) — pin in server config ANDVARI_RECOVERY_PUBKEY:")
    appendLine("    ${Bytes.toB64(kp.publicKey)}")
    appendLine()
    appendLine("Fingerprint (ANDVARI_RECOVERY_FINGERPRINT):")
    appendLine("    $fp")
    appendLine("Short fingerprint (the first 32 characters: type these when confirming at enrollment or an invite):")
    appendLine("    $short")
    appendLine()
    appendLine("Seed QR (scan back to verify the print is readable):")
    appendLine(qr(Bytes.toB64(seed)))
    appendLine()
    appendLine("Config snippet for /etc/andvari/andvari.env:")
    appendLine("    ANDVARI_RECOVERY_PUBKEY=${Bytes.toB64(kp.publicKey)}")
    appendLine("    ANDVARI_RECOVERY_FINGERPRINT=$fp")
    appendLine()
    appendLine("Next: (1) pin the pubkey+fingerprint in server config, (2) run")
    appendLine("      'canary make <pubkey>' and store the sealed blob server-side, then")
    appendLine("      'canary verify <sealed>' FROM THE PRINTED SEED before any real account.")
    appendLine()
    appendLine("Assisted recovery (a member lost both the master password and the kit, and asked for help):")
    appendLine("      after the 7-day hold, check the request code with them over a channel you already had, then run")
    appendLine("      'recovery-cli assist --instance <instance id> --request <request id> --request-key <rPub>")
    appendLine("      --request-code <the code they read to you> --email <their address, as YOU know it> --user <their id>")
    appendLine("      --identity-fp <32+ hex> --identity-file <escrow download>' and upload its last line with fulfil.")
    appendLine("      The identity fingerprint comes from YOUR pin of them or their own kit, never from the console.")
    appendLine("      No temporary password exists at any point.")
}

private fun fingerprint(pubB64: String) {
    val pub = keyArg(pubB64, "the public key")
    println("fingerprint: ${Escrow.fingerprint(crypto, pub)}")
    println("short:       ${Fingerprint.groupedShort(Escrow.fingerprint(crypto, pub)).replace("\n", " ")}")
}

private fun canaryMake(pubB64: String) {
    val pub = keyArg(pubB64, "the public key")
    val sealed = Escrow.sealCanary(crypto, pub)
    println("Canary sealed blob (store server-side as the ceremony canary):")
    println(Bytes.toB64(sealed))
}

private fun canaryVerify(sealedB64: String) {
    canaryCheck(crypto, sealedB64) { readSecret("Paste the recovery seed from the PRINTED SHEET (base64url): ") }.forEach { println(printable(it)) }
}

internal const val CANARY_USAGE = "usage: canary make <pubkeyB64> | canary verify <sealedB64>"

/**
 * `canary verify` (spec 04 §4, genesis step 3): [sealedB64] exactly as given (`bad_copy`), then the seed [readSeedText]
 * gives (`bad_seed`), then the canary must open to its fixed payload with it (`canary_failed`). The lines to print on
 * success; a [RecoverRefused] with its name otherwise. The seed and its key are wiped.
 */
internal fun canaryCheck(crypto: io.silencelen.andvari.core.crypto.CryptoProvider, sealedB64: String, readSeedText: () -> String?): List<String> {
    val canary = blobArg(sealedB64, "the sealed canary")
    val seed = readSeedText()?.let { readSeed(it) } ?: throw RecoverRefused("REFUSED (bad_seed): $BAD_SEED_SENTENCE")
    val kp = crypto.boxKeypairFromSeed(seed)
    try {
        try {
            Escrow.openCanary(crypto, kp, canary)
        } catch (e: Exception) {
            throw RecoverRefused("REFUSED (canary_failed): the canary does not open to its fixed payload with this sheet (${e::class.simpleName}). Nothing proves this sheet can open the copies.")
        }
        return listOf("CANARY VERIFIED ✓  print → restore → unseal works end-to-end.", "Fingerprint of the sheet's key: ${Escrow.fingerprint(crypto, kp.publicKey)}")
    } finally {
        kp.privateKey.fill(0)
        seed.fill(0)
    }
}

/**
 * Fleet escrow canary (spec 04; the drill procedure is docs/drills/escrow-canary-drill.md,
 * which is RECORDED ELSEWHERE — `docs/drills/` was never in this repository, it is the
 * reference instance's private, out-of-tree operational area; the same note stands at the
 * top of CHANGELOG.md, and it is repeated here because a stranger reading this public file
 * would otherwise see a dangling path): open every escrowed
 * blob with the printed seed and prove the accounts are recoverable. The seed comes from
 * a FILE (typed/scanned from the sheet onto the air-gapped box, or the USB copy) so the
 * drill is scriptable; the dump is `sqlite3 -json` output of the server's escrow table.
 */
private fun verifyDump(args: List<String>) {
    val status = runVerify(crypto, args, AssistIo.terminal())
    if (status != 0) kotlin.system.exitProcess(status)
}

/**
 * The fleet check from its arguments (after `verify`) to its verdict, against [terminal]; returns the exit status
 * ([EscrowVerify.exitStatus]; 1 for a refusal). In this order, every refusal before any sheet is read or asked for: the
 * command line; `--instance-file`, read and checked; the dump; then the seed file (the sheet), and only after it, with
 * `--outgoing-sheets`, each outgoing sheet at a prompt, newest first (spec 04 §4, "Which key each copy is sealed to").
 */
internal fun runVerify(crypto: io.silencelen.andvari.core.crypto.CryptoProvider, args: List<String>, terminal: AssistIo): Int {
    val io = AssistIo(
        terminal.readFile, terminal.readSecret, terminal.readLine,
        out = { terminal.out(printable(it)) }, err = { terminal.err(printable(it)) }, clock = terminal.clock,
    )
    var seed: ByteArray? = null
    val outgoing = LinkedHashMap<String, ByteArray?>()
    try {
        val seedFile = args.getOrNull(0) ?: throw RecoverRefused("REFUSED (missing_argument): seedFile is missing\n$VERIFY_USAGE")
        val dumpFile = args.getOrNull(1) ?: throw RecoverRefused("REFUSED (missing_argument): escrowDumpJson is missing\n$VERIFY_USAGE")
        val opts = verifyOptions(args.drop(2))
        val history = opts.instanceFile?.let { path ->
            val bytes = try {
                io.read(path, ToolInput.INSTANCE_FILE_MAX)
            } catch (e: ToolInput.TooLarge) {
                throw tooLarge("bad_instance_file", "--instance-file", e.cap, "the server's GET /api/v1/instance answer")
            } catch (e: Exception) {
                throw RecoverRefused("REFUSED (bad_instance_file): --instance-file cannot be read (${e::class.simpleName})")
            }
            KeyHistory.read(crypto, bytes, null, opts.card0Hash)
        }
        val note = history?.note ?: ""
        val dumpText = try {
            EscrowVerify.strictText(io.read(dumpFile, ToolInput.DUMP_MAX))
        } catch (e: ToolInput.TooLarge) {
            throw tooLarge("bad_dump", dumpFile, e.cap, "a dump the tool reads")
        } catch (e: Exception) {
            null
        }
        val rows = try {
            ToolInput.jsonProblem(dumpText!!)?.let { throw RecoverRefused("REFUSED (bad_dump): $dumpFile is not a dump the tool reads: $it") }
            EscrowVerify.parseDump(dumpText)
        } catch (e: RecoverRefused) {
            throw e
        } catch (e: Exception) {
            throw RecoverRefused("REFUSED (bad_dump): $dumpFile is not UTF-8 sqlite3 -json output of: ${EscrowVerify.DUMP_SQL}")
        }
        if (rows.isEmpty()) throw RecoverRefused("REFUSED (bad_dump): no escrow rows in $dumpFile — export with: sqlite3 -json <db> \"${EscrowVerify.DUMP_SQL}\"")

        // The sheets, only now: first the seed file's, then the outgoing ones at prompts.
        val s = try {
            readSeedFile(EscrowVerify.strictText(io.read(seedFile, ToolInput.SEED_FILE_MAX)))
        } catch (e: ToolInput.TooLarge) {
            throw tooLarge("bad_seed", "the seed file", e.cap, "one line with the 32-byte seed")
        } catch (e: Exception) {
            null
        } ?: throw RecoverRefused("REFUSED (bad_seed): the seed file must contain the 32-byte seed in base64url, as UTF-8 text")
        seed = s
        val kp = crypto.boxKeypairFromSeed(s)
        val sheetFp = Escrow.fingerprint(crypto, kp.publicKey)
        kp.privateKey.fill(0)
        if (opts.outgoingSheets && sheetFp != history!!.current) throw RecoverRefused(wrongSheet(sheetFp, "the CURRENT sheet", history.current).replace("Nothing was produced.", "Nothing was checked.") + note)
        io.out("Escrow fleet verify — recovery key ${Fingerprint.shortForm(sheetFp)} (${rows.size} blob(s))\n")
        history?.sayItFirst(forAssist = false)?.forEach { io.out("$it\n") }
        if (opts.outgoingSheets) {
            val h = history!!
            if (h.outgoing.isEmpty()) {
                io.out("--outgoing-sheets: the key has no outgoing key, so no other sheet is asked for.$note\n")
            } else {
                io.out("--outgoing-sheets: the tool now asks for each OUTGOING sheet, newest first, and opens the copies sealed to it. An empty line says you no longer hold that sheet: its copies then FAIL, as not recoverable.$note\n")
            }
            for (k in h.outgoing) {
                val text = io.readSecret("Paste the recovery seed from the OUTGOING sheet (${KeyHistory.short(k.fp)}, outgoing since ${KeyHistory.date(k.since)})$note (base64url), or an empty line if you no longer hold it: ")
                    ?: throw RecoverRefused("REFUSED (bad_seed): no recovery seed was given for the outgoing sheet. Nothing was checked.")
                if (text.trim { it == ' ' || it == '\t' }.isEmpty()) {
                    outgoing[k.fp] = null
                    continue
                }
                val o = readSeed(text) ?: throw RecoverRefused("REFUSED (bad_seed): the recovery seed is not the 32-byte seed in base64url printed on the sheet. Nothing was checked.")
                outgoing[k.fp] = o
                val okp = crypto.boxKeypairFromSeed(o)
                val got = Escrow.fingerprint(crypto, okp.publicKey)
                okp.privateKey.fill(0)
                if (got != k.fp) throw RecoverRefused(wrongSheet(got, "the OUTGOING sheet", k.fp).replace("Nothing was produced.", "Nothing was checked.") + note)
            }
        }
        io.out("\n")
        val results = EscrowVerify.verify(crypto, s, rows, history, outgoing.takeIf { opts.outgoingSheets })
        val lines = EscrowVerify.reportLines(results, history) // A14 (F12): every cell escaped
        val status = EscrowVerify.exitStatus(results)
        lines.dropLast(1).forEach { io.out("$it\n") }
        if (status == EscrowVerify.EXIT_ALL_GOOD) io.out(lines.last() + "\n") else io.err(lines.last())
        return status
    } catch (e: RecoverRefused) {
        io.err(e.message ?: VERIFY_USAGE)
        return 1
    } catch (e: Throwable) {
        io.err("REFUSED (unexpected_fault): an unexpected fault (${e::class.simpleName ?: "unknown"}) during the fleet check. Nothing was checked.")
        return 1
    } finally {
        seed?.fill(0)
        outgoing.values.forEach { it?.fill(0) }
    }
}

/** The fleet check's options after its two files. */
internal class VerifyOptions(val instanceFile: String?, val outgoingSheets: Boolean, val card0Hash: String? = null)

/**
 * The fleet check's options after its two files, each at most once: `--instance-file <file>` with exactly one of
 * `--card0-hash <64 hex>` and `--instance-file-unchecked` (spec 04 §5, as for `assist`), and `--outgoing-sheets`, which
 * needs the file (`instance_file_missing`): the outgoing sheets are never given on the command line, the tool asks for
 * them after the seed file.
 */
internal fun verifyOptions(options: List<String>): VerifyOptions {
    var instanceFile: String? = null
    var outgoingSheets = false
    var card0Hash: String? = null
    var unchecked = false
    val given = HashSet<String>()
    var i = 0
    while (i < options.size) {
        val a = options[i]
        if (a in VERIFY_OPTIONS && !given.add(a)) throw RecoverRefused(repeatedOption(a, VERIFY_USAGE))
        when (a) {
            "--instance-file" -> instanceFile = options.getOrNull(++i) ?: throw RecoverRefused("REFUSED (bad_instance_file): --instance-file needs the file\n$VERIFY_USAGE")
            "--card0-hash" -> card0Hash = options.getOrNull(++i) ?: ""
            "--instance-file-unchecked" -> unchecked = true
            "--outgoing-sheets" -> outgoingSheets = true
            else -> throw RecoverRefused("REFUSED (unknown_option): unknown option ${io.silencelen.andvari.core.client.TerminalText.escape(a)}\n$VERIFY_USAGE")
        }
        i++
    }
    if (outgoingSheets && instanceFile == null) {
        throw RecoverRefused("REFUSED (instance_file_missing): --outgoing-sheets needs --instance-file: only the server's checked card chain and rotations say which keys are outgoing\n$VERIFY_USAGE")
    }
    val anchor = KeyHistory.anchorOptions(instanceFile, card0Hash, unchecked, VERIFY_USAGE)
    return VerifyOptions(instanceFile, outgoingSheets, anchor)
}

private val VERIFY_OPTIONS = setOf("--instance-file", "--card0-hash", "--instance-file-unchecked", "--outgoing-sheets")

internal const val VERIFY_USAGE =
    "usage: verify <seedFile> <escrowDumpJson> [--instance-file <the server's GET /api/v1/instance answer> " +
        "(--card0-hash <64 hex> | --instance-file-unchecked) [--outgoing-sheets]]"

/** `assist` (spec 04 §7 step 3): see [AssistCommand]. Prints the sealed answer the operator uploads with `fulfil`. */
private fun assist(args: List<String>) {
    val status = runAssist(crypto, args, AssistIo.terminal())
    if (status != 0) kotlin.system.exitProcess(status)
}

/**
 * What `assist` reads and writes: its one file, the operator's typed lines, the two output streams and the clock. The
 * command line gives the terminal's ([terminal]); a test gives its own, and so sees what was read, asked and produced.
 */
internal class AssistIo(
    /** A file by its path, read up to the limit given and never further ([ToolInput.readFile]); see [read]. */
    val readFile: (String, Int) -> ByteArray,
    /** The recovery seed, typed or piped without echo; null when there is no input. */
    val readSecret: (String) -> String?,
    val readLine: () -> String?,
    /** Standard output: the answer, and the line before the identity file is read. */
    val out: (String) -> Unit,
    /** Standard error: every prompt, the copy's display and every refusal, one line each. */
    val err: (String) -> Unit,
    val clock: () -> Long,
) {
    companion object {
        fun terminal() = AssistIo(
            readFile = { path, cap -> ToolInput.readFile(path, cap) },
            readSecret = { readSecret(it) },
            readLine = { ToolInput.stdinLine() },
            out = { print(it); System.out.flush() },
            err = { System.err.println(it) },
            clock = { System.currentTimeMillis() },
        )
    }

    /** The file at [path], at most [cap] bytes ([ToolInput.TooLarge] otherwise), whoever [readFile] is. */
    fun read(path: String, cap: Int): ByteArray = ToolInput.within(readFile(path, cap), cap)
}

/** The sentence for a file over its limit: what it is, and what it therefore is not. */
private fun tooLarge(name: String, option: String, cap: Int, isNot: String): RecoverRefused =
    RecoverRefused("REFUSED ($name): $option is larger than ${ToolInput.size(cap)}, so it is not $isNot; it was not read whole")

/** `assist` from its arguments to its answer, against [io]. Returns the exit status: 0 with the answer printed, 1 with nothing produced. */
internal fun runAssist(
    crypto: io.silencelen.andvari.core.crypto.CryptoProvider,
    args: List<String>,
    terminal: AssistIo,
    /** Called at the start of each stage after the seed is read; a test throws from it on purpose. */
    fault: (AssistStage) -> Unit = {},
): Int {
    // Everything assist prints goes through the one escaping function, on every path.
    val io = AssistIo(
        terminal.readFile, terminal.readSecret, terminal.readLine,
        out = { terminal.out(printable(it)) }, err = { terminal.err(printable(it)) }, clock = terminal.clock,
    )
    val opts = try {
        AssistCommand.parse(crypto, args)
    } catch (e: RecoverRefused) {
        io.err(e.message ?: AssistCommand.USAGE)
        return 1
    }
    // The clock is checked with the arguments, and the value checked is the one the answer signs.
    val now = io.clock()
    try {
        AssistCommand.checkClock(now)
    } catch (e: RecoverRefused) {
        io.err(e.message ?: "bad clock")
        return 1
    }
    io.out("Request code matches the request key.\n")
    val (identityCheck, sealedB64) = try {
        val bytes = try {
            io.read(opts.recover.identityFile, ToolInput.IDENTITY_FILE_MAX)
        } catch (e: ToolInput.TooLarge) {
            throw tooLarge("bad_identity_file", "--identity-file", e.cap, "a recovery-copy download")
        } catch (e: Exception) {
            throw RecoverRefused("REFUSED (bad_identity_file): --identity-file cannot be read (${e::class.simpleName})")
        }
        RecoverCommand.readIdentityFileBytes(bytes, opts.recover)
    } catch (e: RecoverRefused) {
        io.err(e.message ?: "bad --identity-file")
        return 1
    }
    // spec 04 §5: a copy sealed to a key the server has since replaced. The server's own card chain and signed rotations,
    // checked here, say which sheet signs the answer and which keys it replaced; all of it before any seed is asked for.
    val history = opts.instanceFile?.let { path ->
        try {
            val bytes = try {
                io.read(path, ToolInput.INSTANCE_FILE_MAX)
            } catch (e: ToolInput.TooLarge) {
                throw tooLarge("bad_instance_file", "--instance-file", e.cap, "the server's GET /api/v1/instance answer")
            } catch (e: Exception) {
                throw RecoverRefused("REFUSED (bad_instance_file): --instance-file cannot be read (${e::class.simpleName})")
            }
            KeyHistory.read(crypto, bytes, opts.instanceId, opts.card0Hash)
        } catch (e: RecoverRefused) {
            io.err(e.message ?: "bad --instance-file")
            return 1
        }
    }
    history?.sayItFirst()?.forEach(io.err)
    val note = history?.note ?: ""
    val currentPrompt = if (history == null) {
        "Paste the recovery seed from the PRINTED SHEET (base64url): "
    } else {
        "Paste the recovery seed from the CURRENT sheet (${KeyHistory.short(history.current)})$note (base64url): "
    }
    val seedText = io.readSecret(currentPrompt) ?: run {
        io.err("REFUSED (bad_seed): no recovery seed was given. Nothing was produced.")
        return 1
    }
    // From here on the seed is in memory: whatever happens ends as one line that names its kind and no secret, with
    // nothing produced, and the seed and its keys are wiped.
    var stage = AssistStage.SEED
    val seed = readSeed(seedText) ?: run {
        io.err("REFUSED (bad_seed): $BAD_SEED_SENTENCE")
        return 1
    }
    var kp: io.silencelen.andvari.core.crypto.KeyPairBytes? = null
    var opened: io.silencelen.andvari.core.crypto.EscrowOpened? = null
    var outgoingSeed: ByteArray? = null
    var outgoingKp: io.silencelen.andvari.core.crypto.KeyPairBytes? = null
    try {
        fault(stage)
        stage = AssistStage.KEYS
        fault(stage)
        val keys = crypto.boxKeypairFromSeed(seed).also { kp = it }
        if (history != null) {
            val got = Escrow.fingerprint(crypto, keys.publicKey)
            if (got != history.current) throw RecoverRefused(wrongSheet(got, "the CURRENT sheet", history.current) + note)
        }
        stage = AssistStage.OPEN
        fault(stage)
        // Which sheet opens the copy: the current one, or else the outgoing ones the rotations name, newest first. The
        // copy's own signed statement then names the key it was sealed to, and the opener requires it to be that sheet's.
        var opener = keys
        var outgoing: OutgoingKey? = null
        if (history != null && history.outgoing.isNotEmpty()) {
            val sealedBytes = Bytes.fromB64Canonical(sealedB64) ?: throw RecoverRefused("REFUSED (bad_copy): ${RecoverCommand.BAD_COPY_SENTENCE}")
            if (opensWith(crypto, keys, sealedBytes)) {
                io.err("This copy opens with the CURRENT sheet: the account sealed it after the change. The outgoing sheet is not needed.$note")
            } else {
                for (k in history.outgoing) {
                    io.err("This copy does not open with ${if (outgoing == null) "the CURRENT sheet" else "the OUTGOING sheet ${KeyHistory.short(outgoing.fp)}"}: it was sealed before ${KeyHistory.date(k.since)}.$note")
                    val text = io.readSecret("Paste the recovery seed from the OUTGOING sheet (${KeyHistory.short(k.fp)}, outgoing since ${KeyHistory.date(k.since)})$note (base64url): ")
                        ?: throw RecoverRefused("REFUSED (bad_seed): no recovery seed was given for the outgoing sheet. Nothing was produced.")
                    outgoingKp?.privateKey?.fill(0)
                    outgoingSeed?.fill(0)
                    val s = readSeed(text) ?: throw RecoverRefused("REFUSED (bad_seed): $BAD_SEED_SENTENCE")
                    outgoingSeed = s
                    val okp = crypto.boxKeypairFromSeed(s).also { outgoingKp = it }
                    val got = Escrow.fingerprint(crypto, okp.publicKey)
                    if (got != k.fp) throw RecoverRefused(wrongSheet(got, "the OUTGOING sheet", k.fp) + note)
                    outgoing = k
                    if (opensWith(crypto, okp, sealedBytes)) {
                        opener = okp
                        break
                    }
                }
                if (opener === keys) {
                    throw RecoverRefused(
                        "REFUSED (${EscrowVerdict.UNOPENABLE.code}): this copy opens with neither the current sheet nor any outgoing sheet the rotations name. " +
                            "It is not sealed to any recovery key of this server's history: the server may have given you another copy. Nothing was produced.$note",
                    )
                }
            }
        }
        val o = RecoverCommand.openAndConfirm(
            crypto, opener, opts.recover, opts.email, identityCheck, sealedB64, "the signed answer for request ${opts.requestId}",
            io.readLine,
            signedWith = if (opener === keys) null else "The copy names that OUTGOING key as the one it is sealed to; the answer is signed with the CURRENT sheet, ${KeyHistory.short(history!!.current)}.$note",
            unopenableHint = if (history == null) UNOPENABLE_HINT else null,
        ) { line -> io.err(line) }.also { opened = it }
        // The outgoing sheet's work is done: it opened the copy, which named its key. The chain from that key to the one that
        // signs is checked once more, link by link, as a device would follow it; then the outgoing seed is wiped.
        outgoing?.takeIf { opener !== keys }?.let { k ->
            RecoveryRotation.verifyChain(crypto, k.chain, opts.instanceId, k.fp, history!!.current)?.let {
                throw RecoverRefused("REFUSED (rotation_chain_broken): the rotations from ${KeyHistory.short(k.fp)} to ${KeyHistory.short(history.current)} do not verify (${it.code}). Nothing was produced.$note")
            }
        }
        outgoingKp?.privateKey?.fill(0)
        outgoingSeed?.fill(0)
        val copyEmail = o.email ?: throw RecoverRefused("REFUSED (${EscrowVerdict.NO_ADDRESS.code}): ${RecoverCommand.NO_ADDRESS_SENTENCE}")
        stage = AssistStage.ANSWER
        fault(stage)
        val uvk = o.uvk
        o.wipe()
        val answer = AssistCommand.answer(crypto, seed, opts, copyEmail, uvk, now)
        stage = AssistStage.OUTPUT
        // The whole output is made before any of it is written: a fault leaves nothing behind.
        val text = answerOutput(opts, answer)
        fault(stage)
        io.out(text)
        return 0
    } catch (e: RecoverRefused) {
        io.err(e.message ?: "refused")
        return 1
    } catch (e: Throwable) {
        io.err(unexpectedFault(stage, e))
        return 1
    } finally {
        opened?.wipe()
        kp?.privateKey?.fill(0)
        seed.fill(0)
        outgoingKp?.privateKey?.fill(0)
        outgoingSeed?.fill(0)
    }
}

/**
 * A typed seed as the tool reads it (spec 04 §4 step 1), like everything else a person types: space and tab removed from
 * both ends and nothing else, then exactly 32 bytes in canonical unpadded base64url. Null when it is not one (`bad_seed`):
 * padding, the other base64 alphabet, a no-break space or any other character around it.
 */
internal fun readSeed(text: String): ByteArray? = Bytes.fromB64Exact(text.trim { it == ' ' || it == '\t' }, 32)

/** A seed file (the fleet check's) is one line: its line ending, LF or CR LF, is removed, then [readSeed]. */
internal fun readSeedFile(text: String): ByteArray? =
    readSeed(if (text.endsWith("\r\n")) text.dropLast(2) else text.removeSuffix("\n"))

/** Whether [sealed] opens with [keys]; what it opens to is wiped at once, unread (the opener reads it, in its order). */
private fun opensWith(crypto: io.silencelen.andvari.core.crypto.CryptoProvider, keys: io.silencelen.andvari.core.crypto.KeyPairBytes, sealed: ByteArray): Boolean =
    try {
        crypto.sealOpen(keys.publicKey, keys.privateKey, sealed).fill(0)
        true
    } catch (e: io.silencelen.andvari.core.crypto.CryptoException) {
        false
    }

/** spec 04 §5: the seed pasted is another sheet's than the one asked for. */
internal fun wrongSheet(got: String, which: String, want: String): String =
    "REFUSED (wrong_sheet): the seed you pasted is the sheet ${KeyHistory.short(got)}, not $which, ${KeyHistory.short(want)}. Nothing was produced."

/** What `unopenable` adds when `assist` was run without `--instance-file` (spec 04 §5). */
internal const val UNOPENABLE_HINT =
    "If the server's recovery key was replaced since this account sealed its copy, the copy is sealed to the outgoing key: save the server's " +
        "GET /api/v1/instance answer to a file, run again with --instance-file <that file> and --card0-hash <the server's card 0 hash, 64 hex digits, " +
        "as `andvari-cli card show` prints it>, and have both the current and the outgoing sheet at hand."

/** Where `assist` was after the seed was read, for the one line an unexpected fault ends in. */
internal enum class AssistStage(val words: String) {
    SEED("reading the recovery seed"),
    KEYS("deriving the recovery key from the seed"),
    OPEN("opening the recovery copy"),
    ANSWER("making the answer"),
    OUTPUT("printing the answer"),
}

/** spec 04 §7 step 3: the seed typed or piped is not 32 bytes of base64url. */
internal const val BAD_SEED_SENTENCE = "the recovery seed is not the 32-byte seed in base64url printed on the sheet. Nothing was produced."

/**
 * The one line an unexpected fault ends in: its name, the kind of fault (the exception's class, never its
 * message, which could quote what it was working on) and the stage, and that nothing was produced.
 */
internal fun unexpectedFault(stage: AssistStage, e: Throwable): String =
    "REFUSED (unexpected_fault): an unexpected fault (${e::class.simpleName ?: "unknown"}) while ${stage.words}. Nothing was produced: " +
        "no answer was printed and nothing was written. Run the command again; if it happens again, report this line."

/**
 * The one escaping function every printed line of the tool goes through: each line of [text] with
 * its control characters, separators and direction overrides made visible ([io.silencelen.andvari.core.client.TerminalText.escape]);
 * the tool's own line breaks are kept.
 */
internal fun printable(text: String): String = text.split('\n').joinToString("\n") { io.silencelen.andvari.core.client.TerminalText.escape(it) }

/** A key given on the command line (`fingerprint`, `canary make`): exactly as given, 32 bytes of canonical base64url. */
internal fun keyArg(text: String, name: String): ByteArray =
    Bytes.fromB64Exact(text, 32) ?: throw RecoverRefused("REFUSED (bad_key): $name must be a 32-byte public key in base64url, exactly as given")

/** A sealed blob given on the command line (`canary verify`): exactly as given, canonical base64url. */
internal fun blobArg(text: String, name: String): ByteArray =
    Bytes.fromB64Canonical(text)?.takeIf { it.isNotEmpty() } ?: throw RecoverRefused("REFUSED (bad_copy): $name must be base64url, exactly as given")

/**
 * What `assist` prints on standard output once the answer is made (spec 04 §7 step 3, item 6): who it is for, and as
 * the LAST line, with nothing after it, the answer token the console and `andvari-cli operator fulfil` read.
 */
internal fun answerOutput(opts: AssistOptions, answer: AssistAnswer): String = buildString {
    appendLine()
    appendLine("ANSWER for request ${opts.requestId} (account ${opts.recover.userId}, address ${opts.email}${if (opts.recover.unanchored) ", UNANCHORED" else ""}):")
    appendLine("It is signed by the recovery key and sealed to the person's device; only that device can open it, and only")
    appendLine("that device can then finish: the server takes the new password only with the value inside the answer.")
    appendLine("Give the console, or andvari-cli operator fulfil, the whole last line below (the console also takes this whole output):")
    appendLine()
    appendLine(io.silencelen.andvari.core.trust.AnswerToken.format(opts.requestId, Bytes.toB64(opts.requestKey), answer.commitHash, answer.sealed))
}

/** `rotate` (spec 04 §5): see [RotateCommand]. Prints the 0x08 statement to store with `PUT /instance/rotation`. */
private fun rotate(args: List<String>) {
    val opts = try {
        RotateCommand.parse(args)
    } catch (e: RecoverRefused) {
        die(e.message ?: RotateCommand.USAGE)
    }
    val seed = readSeed(readSecret("Paste the OUTGOING recovery seed from its printed sheet (base64url): ")) ?: die("REFUSED (bad_seed): $BAD_SEED_SENTENCE")
    val (frame, fields) = try {
        RotateCommand.statement(crypto, seed, opts, System.currentTimeMillis())
    } catch (e: RecoverRefused) {
        die(e.message ?: "refused")
    } catch (e: Throwable) {
        die("REFUSED (unexpected_fault): an unexpected fault (${e::class.simpleName ?: "unknown"}) while signing the rotation. Nothing was produced.")
    } finally {
        seed.fill(0)
    }
    println("Rotation for instance ${fields.instanceId}")
    println("  from ${Fingerprint.groupedShort(fields.fromFp).replace("\n", " ")}")
    println("  to   ${Fingerprint.groupedShort(fields.toFp).replace("\n", " ")}")
    println("Store it with PUT /api/v1/instance/rotation {statement, currentAuthKey}, THEN sign the card with recoveryFp = ${fields.toFp}:")
    println()
    println(Bytes.toB64(frame))
}

private fun qr(text: String): String {
    val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0)
    val sb = StringBuilder()
    // Two rows per printed line using half-block chars keeps the QR roughly square.
    var y = 0
    while (y < matrix.height) {
        for (x in 0 until matrix.width) {
            val top = matrix.get(x, y)
            val bottom = if (y + 1 < matrix.height) matrix.get(x, y + 1) else false
            sb.append(if (top && bottom) '█' else if (top) '▀' else if (bottom) '▄' else ' ')
        }
        sb.append('\n')
        y += 2
    }
    return sb.toString()
}

/**
 * No-echo read of a SECRET — here the org recovery seed, which can decrypt EVERY escrowed
 * UVK and lives only in offline/printed-sheet custody (ER-1). No-echo via the console when a
 * real terminal is attached to BOTH stdin and stdout (the char[] is zeroed after copying it
 * out); otherwise a plaintext line from stdin for piped drills/scripts, with the prompt on
 * stderr so a redirected stdout (`assist ... > answer.txt`) never captures the prompt.
 * PT-L10 caveat (JDK 17): `System.console()` is null when EITHER stream is not a tty — so
 * TYPING the seed while stdout is redirected takes this fallback and the TERMINAL echoes it to
 * scrollback. We warn loudly on stderr; the fully-safe paths are: pipe the seed via stdin, or
 * don't redirect stdout. Mirrors backup-cli's readPassphrase.
 */
internal fun readSecret(message: String): String {
    System.console()?.let { console ->
        val chars = console.readPassword(message) ?: die(NO_SEED)
        return String(chars).also { chars.fill(' ') }
    }
    System.err.println(
        "WARNING: no secure console (stdout is redirected or not a terminal). If you TYPE the " +
            "seed here it WILL appear in your terminal scrollback. Pipe it via stdin instead, or " +
            "re-run without redirecting stdout.",
    )
    System.err.print(message)
    System.err.flush()
    // Bounded (spec 04 §4, "The tool's inputs are hostile"): an overlong line is never held whole and fails as bad_seed.
    return ToolInput.stdinLine() ?: die(NO_SEED)
}

private const val NO_SEED = "REFUSED (bad_seed): no recovery seed was given. Nothing was produced."

private fun die(message: String): Nothing {
    System.err.println(printable(message))
    kotlin.system.exitProcess(1)
}
