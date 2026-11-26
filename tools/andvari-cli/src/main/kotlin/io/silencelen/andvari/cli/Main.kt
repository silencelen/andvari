package io.silencelen.andvari.cli

import kotlinx.coroutines.runBlocking
import java.io.File
import java.io.PrintStream
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    useOwnLogging()
    exitProcess(Cli.run(args.toList()))
}

/** The logging configuration that keeps standard output for the command alone (`andvari-cli-logback.xml`), unless the caller chose one. */
fun useOwnLogging() {
    if (System.getProperty(LOGBACK_CONFIGURATION) == null) System.setProperty(LOGBACK_CONFIGURATION, "andvari-cli-logback.xml")
}

private const val LOGBACK_CONFIGURATION = "logback.configurationFile"

/** Parsed `--flag value` / `--flag=value` / `--switch` arguments, as `andvari setup` parses them. */
class Args(argv: List<String>) {
    val flags = HashMap<String, MutableList<String>>()
    val switches = HashSet<String>()
    val positional = ArrayList<String>()

    init {
        var i = 0
        while (i < argv.size) {
            val a = argv[i]
            if (a.startsWith("--") && a.length > 2) {
                val eq = a.indexOf('=')
                when {
                    eq > 0 -> flags.getOrPut(a.substring(2, eq)) { ArrayList() } += a.substring(eq + 1)
                    a.substring(2) in SWITCHES -> switches += a.substring(2)
                    i + 1 < argv.size -> { flags.getOrPut(a.substring(2)) { ArrayList() } += argv[i + 1]; i++ }
                    else -> throw CliError("$a needs a value", 2)
                }
            } else positional += a
            i++
        }
        for (k in flags.keys) if (k in SECRET_FLAGS) throw CliError("--$k: secrets are never taken on the command line; use --$k-file or the environment", 2)
    }

    fun opt(name: String): String? = flags[name]?.lastOrNull()
    fun all(name: String): List<String> = flags[name] ?: emptyList()
    fun has(name: String): Boolean = name in switches
    fun pos(i: Int, what: String): String = positional.getOrNull(i) ?: throw CliError("missing $what", 2)
    val single: Map<String, String> get() = flags.mapValues { it.value.last() }

    companion object {
        val SWITCHES = setOf("json", "yes", "help", "accept", "decline", "uncompared", "age-confirm", "operator-recovery", "i-understand", "dry-run", "cancel", "under-minimum-age", "check", "all")
        /** Flags that would put a secret in the process list or the shell history (design §12). */
        val SECRET_FLAGS = setOf("password", "new-password", "passphrase", "backup-passphrase", "totp", "kit", "seed", "code-secret", "mailbox-value")
    }
}

/**
 * `andvari-cli`: the headless client (design §9.5, §12, §14.1). Global options, before or after the command:
 *   --home DIR             this device's state (default $ANDVARI_CLI_HOME or ~/.andvari-cli)
 *   --origin URL           the instance (its identity: card checks, links, the Host header)
 *   --connect URL          accepted only when it is the origin's own address (R11; any other address is refused)
 *   --email E              the account (default: the one this device last used at the origin)
 *   --trust-card HASH      the Trust Gate for scripts: the card 0 hash you expect (never a silent first trust)
 *   --link-file PATH / -   a link from a file or standard input, never the process list (a positional link still works)
 *   --password-file PATH / $ANDVARI_PASSWORD   the master password (never an argument)
 */
object Cli {
    val HELP = """
        |usage: andvari-cli [global options] <command> ...
        |
        |  operator enrol <setup-link> --email E [--name N] [--kit-out FILE]   the operator account; signs card 0
        |  enrol <link> --email E [--name N] [--kit-out FILE]                  register through an enrol or register link
        |
        |  Every <link> (operator enrol, enrol, link open, link-device) may be given as --link-file PATH (preferred), or as -
        |  to read it from standard input. A link typed as an argument is visible to every user of this host in the process
        |  list while the command runs. Without --origin, a command that takes a link uses the origin the link names.
        |
        |  --connect URL is accepted only when it is the origin's own address. This tool cannot name the origin on a
        |  connection to another address (the server would be told the wrong name), so any other --connect is refused and
        |  nothing is sent. Connect by the origin's own name instead, or add a hosts entry that points the origin's host
        |  name at the loopback address where the origin is served.
        |
        |  sign-up --email E [--name N] [--age-confirm] [--kit-out FILE]        public sign-up (the emailed code: --code-file / ${'$'}ANDVARI_SIGNUP_CODE / prompt)
        |  sign-in | sign-out | whoami | sync
        |  recover kit --kit-file FILE|- [--email E] --kit-out NEW-KIT          a lost master password: the kit (never an argument), a new password, a new kit
        |  recover assist --email E [--trust-card H]                             ask the operator for help (prints the request code; the emailed code: --code-file / ${'$'}ANDVARI_RECOVERY_CODE)
        |                 [--mailbox-value-file F]                               a value from a mail about a request you did not make (or ${'$'}ANDVARI_MAILBOX_VALUE; asked at a terminal)
        |  recover assist [--account-id ID] [--kit-out NEW-KIT] | --cancel     later runs: where it stands; then confirm the account, a new password, a new kit
        |  recovery-requests [veto ID] | recovery [show|operator --i-understand|private]   a signed-in account: cancel a request; its recovery posture
        |  account password                                                     a new master password (the new one: --new-password-file / ${'$'}ANDVARI_NEW_PASSWORD / prompt)
        |  account kit [--kit-out NEW-KIT]                                      a new recovery kit; the old one stops working
        |  account devices | account revoke-device ID                           your devices; revoke any but this one
        |  account require-link on|off                                          "new devices must be linked"
        |  account quota                                                        used and limit of each meter, from a fresh sync
        |  account delete [--confirm-email E] | account delete --check          the plan and blockers first, then the typed address
        |                                                                       (--confirm-email without a terminal); --check after "cannot tell yet"
        |  forget-server --yes                                            the only way on after a fork: deletes everything kept for the server
        |  forget-earlier-account --email E [--yes]                       after a refusal of a remade account: says what goes; --yes forgets it
        |  card show | card sign --name N | --move-to ORIGIN | --recovery-fp HEX     one change per card, as the desktop signs it
        |  card sign --recovery-fp none [--confirm "REMOVE RECOVERY KEY"]       removes the recovery key; said first, typed confirmation
        |  card rotation --file F [--recovery-fp HEX]                           a change of recovery key: recovery-cli rotate's statement,
        |                                                                       checked before the password, then uploaded with its card
        |  card follow [--yes]                                                  follow a move the operator signed (records and session move)
        |  link create [--kind connect|register] [--hours H] [--share VAULT[:ROLE]]... [--name N] | link list | link revoke ID
        |  link open <url> [--name N] | link answers | link code CONTACT | link compare CONTACT [--code DIGITS] | contacts
        |    --name N: the name your account goes by in its links, kept on this device; needed where the account was not
        |    made here (the server does not keep it), asked for at a terminal
        |  vault list | create NAME | add V CONTACT [--role writer|reader] [--uncompared] | role V M ROLE | remove V M
        |        leave V | delete V | restore V | offer V TO [--days N] | cancel V | accept V | incoming V --accept|--decline
        |        send-deletion V | keep V                                      a vault's deletion that got no answer waits: send it now, or keep the vault
        |  share V CONTACT [--role R]                                            the same as vault add
        |  item list V [--json] | item get V ID | item put V [--id ID] [--file F] (JSON on stdin) | item delete V ID
        |  link-device show [--code DIGITS] | link-device <url>                 the device-link flow, both roles
        |  restore --backup FILE [--vaults personal|all] [--dry-run]            spec 07 §3 (passphrase: --backup-passphrase-file / ${'$'}ANDVARI_BACKUP_PASSPHRASE)
        |                                                                       checks the account's space first: short, it does not start
        |                                                                       (exit 4, [account_short_of_space]; --json: {error, short})
        |  operator accounts | status | audit [--type T] [--user E] [--since MS] [--after ID] [--all] | policy [set --file F] (JSON both ways)
        |           (audit: one page of the newest 500 rows; when older rows exist it says so and gives --after <id>;
        |           --all follows the pages, at most 20 of them)
        |           recovery-requests | disable E [--reason R] | enable E | delete E [--under-minimum-age]
        |           (delete: an account disabled for 30 days; --under-minimum-age lifts the 30 days for a disabled account,
        |           and the server's audit row records reason=under_minimum_age)
        |           devices E | revoke-device ID | quota E [--bytes N] [--items N] [--vaults N] [--links N]
        |           escrow E --out FILE | fulfil REQUEST --sealed-file FILE
        |           hand-over --to-user ID --to-key KEY [--confirm "HAND OVER <first 8 of ID>"]
        |           (the next card names that account as the operator; ID and KEY from `account signing-key` on its own device)
        |  account signing-key                                                  this account's user id and signing key, for a hand-over
        |  seed [--items N] | check [--items N]                                  the demo accounts (design §9.5 R11)
        |
        |  --json: the command's list or state as ONE JSON document on standard output, nothing else there; every other
        |  line on standard error; the exit codes as without it (0 done, 1 refused, 2 usage, 3 the server's answer: too
        |  large, a row this device will not show, or a password-hashing cost it will not derive at [server_kdf_refused];
        |  4 short of space; 5 too many wrong passwords for the account: wait the time the message names, then try again,
        |  [too_many_wrong_passwords], or two-step codes where one was sent [too_many_wrong_codes]; the tool never tries
        |  again by itself; 6 the account's keys on the server are not the
        |  ones this run knows, so no proof of the password was made or sent: run the command again
        |  [server_keys_not_known_here]; 7 the server refused a proof the password made here [proof_refused_by_server];
        |  8 another andvari-cli command was running in this home for the whole wait, 10 seconds unless
        |  ${'$'}ANDVARI_CLI_LOCK_WAIT_MS names another (at most 60000): nothing was sent or changed, run it again [home_busy]).
        |  One command at a time changes a home: every command holds it while it runs, and a lock left by a process
        |  that died does not block.
        |  On a failure standard output is empty. A list is an array, a state an object; absent values are null:
        |    whoami          {origin, account, server: {name, kind, cardSeq, pinnedThrough} | null, state}
        |    card show       {origin, name, kind, instanceId, card0Hash, cardSeq, cardHash, operator, operatorKey, recoveryFp, pinnedVia}
        |    sync            {vaults}
        |    contacts        [{userId, label, compared, code}]          (code: the comparison code, null when not current here)
        |    vault list      [{vaultId, name, kind: personal|shared, log, owner, members, headSeq}]
        |    item list V     [{itemId, doc}]                             (the items themselves, secrets included: that is its purpose)
        |    link list       [{linkId, kind, shares}]                    (never a link: a link is a capability)
        |    link answers    [{outcome: connected|key_changed|deferred|ignored, userId, label, code, linkId, reason}]
        |    account delete --check   {origin, account, state: exists}    (cannot tell: nothing on standard output, exit 1)
        |    recovery-requests veto ID   {requestId, state: vetoed}
        |    recovery-requests   {offered, requests: [{requestId, state, createdAt, verifiedAt, holdEndsAt, platform}]}
        |    recovery show   {posture, recorded, fp, operatorOffered}
        |    account devices, operator devices E   [{deviceId, platform, name, clientVersion, createdAt, lastSeenAt, live, how, linkedFrom?, current}]
        |    operator accounts | status     the server's own JSON rows
        |    operator audit  {rows: [the server's own rows], more, after}   (more: older rows exist; after: the --after for them, else null)
        |    operator recovery-requests   [{requestId, userId, email, rPub, platform, createdAt, verifiedAt, holdEndsAt,
        |                                   state: holding|awaiting_operator|ready|null}]
        |                    (never a request code, never the server's account ID: what you check comes from the person)
        |  (The rows marked as the server's own may leave out a field at its default, as linkedFrom?.)
        |    restore         {exportedAt, origin, vaults: [{vaultId, name, type, items, chosen}], attachments, attachmentsOverCap,
        |                     undecryptable, restored: {items, vaults, refused, attachmentsCarried, attachmentsStripped} | null}
        |                    (restored: null on --dry-run; the preview's lines go to standard error)
        |    operator policy     always JSON, with or without --json
        """.trimMargin()

    /** [clock] is the wall clock; a test passes its server's test clock. */
    fun run(
        argv: List<String>, out: PrintStream = Term.standardOutput(), env: (String) -> String? = System::getenv, stdin: () -> String? = { readlnOrNull() },
        clock: () -> Long = System::currentTimeMillis,
    ): Int = runWith(argv, out, env, stdin, clock, http = null)

    /** [run] over the HTTP client [http] makes instead of the tool's own: a test that dials a listener of its own. */
    internal fun runWith(
        argv: List<String>, out: PrintStream, env: (String) -> String?, stdin: () -> String?, clock: () -> Long,
        http: (() -> io.ktor.client.HttpClient)?,
        crypto: ((io.silencelen.andvari.core.crypto.CryptoProvider) -> io.silencelen.andvari.core.crypto.CryptoProvider)? = null,
    ): Int {
        var ctx: Ctx? = null
        // An answer the engine refused as too large in this run: whatever the command made of it, that is the fault.
        fun tooLarge(): CliError? = ctx?.hostIfBuilt?.answersTooLarge?.firstOrNull()?.let { (origin, route) -> serverAnswerError(origin, route) }
        // An answer naming a hashing cost outside the fence, which the engine never saw: whatever the command made of it.
        fun costRefused(): CliError? = ctx?.hostIfBuilt?.servedCostsRefused?.firstOrNull()?.let { (origin, p) -> servedCostError(origin, p) }
        val debug = env("ANDVARI_CLI_DEBUG") == "1"
        // Held from before the command reads anything of its home until it ends, whatever way it ends ([HomeLock]).
        var lock: HomeLock? = null
        return try {
            val a = Args(argv)
            if (a.has("help") || a.positional.isEmpty()) {
                HELP.lines().forEach(Term(out)::say); if (a.positional.isEmpty() && !a.has("help")) 2 else 0
            } else {
                val home = CliHome(File(a.opt("home") ?: env("ANDVARI_CLI_HOME") ?: (System.getProperty("user.home") + "/.andvari-cli")))
                val wait = HomeLock.waitMs(env)
                lock = HomeLock.take(home.dir, wait) ?: throw homeBusyError(home.dir, wait)
                val c = Ctx(a, home, out, env, stdin, clock, http, crypto).also { ctx = it }
                val code = runBlocking { Commands(c).dispatch() }
                // A proof of the password this run refused because the server's keys are not the ones it knows: the
                // command did not do what it was asked, whatever it made of that.
                // A cost outside the fence in this run's answers keeps its own words and code ahead of it.
                ctx?.hostIfBuilt?.proofFault()?.let { val f = tooLarge() ?: costRefused() ?: it; report(f); return f.code }
                // The command finished without what it was sent; say so, without failing it.
                (tooLarge() ?: costRefused())?.let { Term.note("andvari-cli: note [${it.key}]: the command finished, but ${it.message}") }
                // A refresh in this run that got no answer, or was not sent: said, without failing a command that finished.
                ctx?.hostIfBuilt?.refreshFault()?.let { Term.note("andvari-cli: note [${it.key}]: the command finished, but ${it.message}") }
                code
            }
        } catch (e: CliError) {
            // Spec 01 §7: a proof refused here for keys this run does not know is said as what it is. (A proof the server
            // refused is the engine's own result, and the command says it.) A cost outside the fence in this run's answers
            // (the keys read again included) is the server's answer at fault, and keeps its own code ahead of it.
            // A refresh in this run that got no answer, or that was not sent because no try was left, is why a request failed.
            val fault = tooLarge() ?: costRefused() ?: ctx?.hostIfBuilt?.proofFault() ?: ctx?.hostIfBuilt?.refreshFault()
            if (fault != null) {
                report(fault)
                if (debug) Term.note("andvari-cli: (what the command said: ${e.message})")
                fault.code
            } else {
                report(e)
                e.code
            }
        } catch (e: Exception) {
            val fault = tooLarge() ?: costRefused() ?: ctx?.hostIfBuilt?.refreshFault()
            if (fault != null) report(fault)
            // Never a stack trace for the person: what stopped, and where the details are.
            else Term.note("andvari-cli: the command stopped on an unexpected error (${e::class.simpleName}: ${e.message}). " +
                "Run it again with ANDVARI_CLI_DEBUG=1 to see the details")
            if (debug) Term.trace(e)
            fault?.code ?: 1
        } finally {
            lock?.close()
        }
    }

    /** A stopped command on standard error: `andvari-cli: <message>`, with the message key when it has one. */
    private fun report(e: CliError) {
        Term.note("andvari-cli${e.key?.let { " [$it]" } ?: ""}: ${e.lines.firstOrNull() ?: e.message}")
        e.lines.drop(1).forEach(Term::note)
    }
}
