package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.deletion.DeletionOutcome
import io.silencelen.andvari.core.client.devicelink.DeviceLinkStop
import io.silencelen.andvari.core.client.devicelink.ExistingStep
import io.silencelen.andvari.core.client.devicelink.NewStep
import io.silencelen.andvari.core.client.link.CompareResult
import io.silencelen.andvari.core.client.link.CreateOutcome
import io.silencelen.andvari.core.client.link.CreatorStep
import io.silencelen.andvari.core.client.link.LinkShare
import io.silencelen.andvari.core.client.link.RecipientStep
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.FoundKind
import io.silencelen.andvari.core.client.log.HeldKind
import io.silencelen.andvari.core.client.log.HeldKnown
import io.silencelen.andvari.core.client.log.HeldLook
import io.silencelen.andvari.core.client.log.HeldRepost
import io.silencelen.andvari.core.client.log.HeldWithdrawal
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.net.ORIGIN_STOPPED
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.net.originStopped
import io.silencelen.andvari.core.client.onboard.KitConfirm
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.Registration
import io.silencelen.andvari.core.client.onboard.RegistrationAuth
import io.silencelen.andvari.core.client.onboard.RegistrationForm
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.onboard.SignupStart
import io.silencelen.andvari.core.client.onboard.SignupVerify
import io.silencelen.andvari.core.client.onboard.WireOnboarding
import io.silencelen.andvari.core.client.session.Establishing
import io.silencelen.andvari.core.client.pin.CardStatus
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.GateDecision
import io.silencelen.andvari.core.client.pin.GateEntry
import io.silencelen.andvari.core.client.pin.GateInput
import io.silencelen.andvari.core.client.pin.GatePurpose
import io.silencelen.andvari.core.client.pin.OriginAccess
import io.silencelen.andvari.core.client.pin.PasswordGate
import io.silencelen.andvari.core.client.pin.ServerForgotten
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.crypto.Fingerprint
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.client.account.OperatorDelete
import io.silencelen.andvari.core.model.wire.OperatorDeleteReason
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.DeviceLinkUrl
import io.silencelen.andvari.core.trust.LinkUrl
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.client.recovery.KitRecoveryStep
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.KeptAssistRequests
import io.silencelen.andvari.core.client.recovery.LiveRecoveryRequests
import io.silencelen.andvari.core.client.recovery.VetoOutcome
import io.silencelen.andvari.core.client.recovery.WireAssistedRecovery
import io.silencelen.andvari.core.trust.TrustGrammar
import io.silencelen.andvari.core.model.wire.Device
import kotlinx.coroutines.delay
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import java.io.File
import java.io.PrintStream

/** One invocation: its arguments, this device's home, where output goes, and where secrets come from. */
/** [http], when given, replaces the client the tool builds for itself (a test that dials somewhere else; never `--connect`). */
class Ctx(
    val a: Args, val home: CliHome, val out: PrintStream, val env: (String) -> String?, val stdin: () -> String?, val clock: () -> Long = System::currentTimeMillis,
    internal val http: (() -> io.ktor.client.HttpClient)? = null,
    /** A test's view of the host's crypto provider (it counts the password derivations); null in the tool itself. */
    internal val crypto: ((io.silencelen.andvari.core.crypto.CryptoProvider) -> io.silencelen.andvari.core.crypto.CryptoProvider)? = null,
) {
    val state = home.deviceState()
    val secrets = Secrets(a.single, env, stdin)

    /** Where this run's result goes: every line through [Shown.text]. */
    val term = Term(out)

    /** The origin the link of this command names ([originFromLink]); null when the command takes no link. */
    private var linkOrigin: String? = null

    /**
     * A command that takes a link uses the origin the link names when no `--origin` is given. An
     * `--origin` that disagrees is refused here, before anything is sent. Called before [origin] is first read; a link
     * that does not parse ([linkOrigin] null) is left to the engine, which says why.
     */
    fun originFromLink(origin: String?) {
        if (origin == null) return
        a.opt("origin")?.let { given ->
            if (given != origin) throw CliError("the link is for $origin, not --origin $given: nothing was sent", 2)
        }
        linkOrigin = origin
    }

    /** The instance: `--origin`, else the one a link names, else the one this device last used. */
    val origin: String by lazy {
        val o = a.opt("origin") ?: linkOrigin ?: state.get(K_ORIGIN) ?: throw CliError("no instance: pass --origin https://your.server", 2)
        if (!TrustGrammar.isOrigin(o)) throw CliError("--origin must be an https address with a domain name (or http://127.0.0.1 / localhost for tests)", 2)
        o
    }

    val host: Host get() = hostOnce.value

    /** The host when this run built one (it dialled or read the device's trust), else null. */
    val hostIfBuilt: Host? get() = if (hostOnce.isInitialized()) hostOnce.value else null

    private val hostOnce: Lazy<Host> = lazy {
        a.opt("connect")?.let { connect ->
            if (!Host.isLoopback(connect)) throw CliError("--connect is accepted only for a loopback address (http://127.0.0.1:<port>)", 2)
            if (!Host.connectsAsOrigin(origin, connect)) throw CliError(connectRefused(origin, connect), 2)
        }
        // A device name given here is checked with the shared code's own test before anything is sent,
        // and the sentence says which kind of character it refuses.
        val given = a.opt("device-name")?.also { n -> nameRefusal(n)?.let { throw CliError("--device-name is not a name andvari can use: it $it. Nothing was sent; choose a name of visible characters and spaces, at most ${TrustGrammar.TEXT_MAX_CHARS}", 2) } }
        val http = this.http?.invoke() ?: Host.defaultHttp()
        val provider = io.silencelen.andvari.core.crypto.createCryptoProvider().let { p -> crypto?.invoke(p) ?: p }
        Host(state, home.secureState(), clock, http, provider, deviceName = given ?: defaultDeviceName()).also { h ->
            h.onSession = { saved.save(it) }
            // The server ended the session: its saved tokens go, and nothing else (design §4.4).
            h.onEnded = { saved.forget(it.origin, it.emailNorm) }
            // The saved session a sign-in names as the one it replaces.
            h.savedToken = { at, norm -> saved.token(at, norm) }
            h.onNewAccountRemembered = { at, norm -> Term.note(fill(NEW_ACCOUNT_REMEMBERED, at, norm)) }
            h.originNow = { runCatching { origin }.getOrNull() }
            // A forgetting of an earlier account that a stopped run began is finished before anything else.
            h.settleForgettings()
            // What this home keeps per server: the saved sessions, and the address remembered as the account there (also
            // one whose session its server ended, which keeps only that).
            h.keptAt = { at ->
                saved.accounts(at)?.let { kept ->
                    val remembered = try { state.get("$K_EMAIL|$at") } catch (e: Exception) { null }
                    kept + listOfNotNull(remembered?.takeIf { r -> kept.none { it.emailNorm == r } }?.let { KeptHere(it, null, null) })
                }
            }
        }
    }

    /**
     * Why `--connect` to an address that is not the origin's own is refused, and what to do instead (design §9.5 R11; the
     * library that could name the origin was declined, see [Host.connectsAsOrigin]).
     */
    private fun connectRefused(origin: String, connect: String): String {
        val host = io.ktor.http.Url(origin).host
        val byName = !Host.isLoopback(origin)
        return "--connect $connect is refused for $origin: this tool cannot name $host on a connection to another address, " +
            "so the server would be told the wrong name. Nothing was sent. Leave out --connect and connect by the origin's own address" +
            (if (byName) ", or add a hosts entry that points $host at the loopback address where $origin is served" else "")
    }

    /** Sessions kept between invocations (tokens and ids only; reopening takes the password). */
    val saved: SavedSessions by lazy { SavedSessions(home.secureState()) }

    fun email(): String = a.opt("email") ?: a.opt("account") ?: state.get("$K_EMAIL|$origin") ?: throw CliError("no account: pass --email", 2)

    fun remember(email: String) {
        state.set(K_ORIGIN, origin)
        state.set("$K_EMAIL|$origin", TrustGrammar.emailNorm(email) ?: email)
    }

    fun password(email: String): CharArray {
        val name = host.trust.pinFor(origin)?.name ?: ""
        return secrets.read("password", "ANDVARI_PASSWORD", "Master password for $email on $name ($origin): ")
    }

    companion object {
        const val K_ORIGIN = "cli.origin"
        const val K_EMAIL = "cli.email"
        /** "andvari-cli on <host name>": a host name's characters that a name refuses are dropped. */
        fun defaultDeviceName(): String = runCatching { java.net.InetAddress.getLocalHost().hostName }.getOrNull()
            ?.let(::droppingRefused)?.take(40)?.takeIf { it.isNotBlank() }?.let { "andvari-cli on $it" } ?: "andvari-cli"

        private fun droppingRefused(s: String): String = buildString {
            s.codePoints().forEach { cp -> if (cp !in 0xD800..0xDFFF && !TrustGrammar.isRefusedNameCodePoint(cp)) appendCodePoint(cp) }
        }
    }
}

/** The commands. Exit codes: 0 done, 1 refused (the message says why), 2 usage. */
class Commands(private val c: Ctx) {
    private val a get() = c.a

    /**
     * One line of the result, and one line on standard error: both through [Term], which escapes whatever a terminal
     * would act on. A value the person may paste into a command is also given as [Shown.arg].
     */
    private fun say(line: String) = c.term.say(line)
    private fun note(line: String) = Term.note(line)
    private fun flush() = c.term.flush()
    private fun arg(value: String) = Shown.arg(value)

    /**
     * `--json`: the command's list or state as ONE JSON document on standard output and nothing else there; every other
     * word goes to standard error, and the exit codes are as without it. The shapes are in [Cli.HELP] and the README.
     */
    private val asJson get() = a.has("json")

    private fun emit(e: JsonElement) = c.term.json(e.toString())

    /** A wire value as the JSON the server itself writes for it. */
    private fun <T> wire(ser: KSerializer<T>, v: T): JsonElement = WireJson.json.encodeToJsonElement(ser, v)
    private val host get() = c.host
    private val origin get() = c.origin

    suspend fun dispatch(): Int {
        val p = a.positional
        when (p[0]) {
            "operator" -> if (p.getOrNull(1) == "enrol") enrol(linkArg(2, "the setup link"), setup = true) else operator(p.getOrNull(1))
            "enrol" -> enrol(linkArg(1, "the link"), setup = false)
            "sign-up" -> signUp()
            "sign-in" -> signedIn { s -> say("signed in: ${s.held.emailNorm} (${s.held.session.role}) on $origin") }
            "sign-out" -> signOut()
            "whoami" -> whoami()
            "forget-server" -> forgetServer()
            "forget-earlier-account" -> forgetEarlierAccount()
            "sync" -> signedIn { s ->
                when (val r = s.sync()) {
                    is SyncOutcome.Synced -> if (asJson) emit(buildJsonObject { put("vaults", JsonPrimitive(s.vaultIds().size)) })
                        else say("synced: ${s.vaultIds().size} vaults")
                    is SyncOutcome.Refused -> throw CliError(refusal("the sync was refused", r.code))
                    SyncOutcome.Unreachable -> throw CliError("the server did not answer; nothing was synced")
                }
            }
            "card" -> card(a.pos(1, "card show|sign|rotation"))
            "link" -> link(a.pos(1, "link create|list|revoke|open|answers|code|compare"))
            "contacts" -> signedIn { s ->
                s.readAccountStateOnce()
                val list = s.contacts.list()
                if (asJson) emit(JsonArray(list.map {
                    buildJsonObject {
                        put("userId", JsonPrimitive(it.record.userId)); put("label", JsonPrimitive(it.labelText))
                        put("compared", JsonPrimitive(it.record.compared)); put("code", JsonPrimitive(it.current?.code))
                    }
                }))
                else list.forEach { say("${arg(it.record.userId)}  ${it.labelText}  ${if (it.record.compared) "compared" else "not compared"}  ${it.current?.code ?: "not current here"}") }
            }
            "vault" -> vault(a.pos(1, "vault list|create|add|…"))
            "share" -> signedIn { s -> s.sync(); append(s, vaultArg(s, 1), LogAction.Add(contactArg(s, 2), a.opt("role") ?: "writer", a.has("uncompared"))) }
            "item" -> item(a.pos(1, "item list|get|put|delete"))
            "link-device" -> linkDevice()
            "recover" -> when (a.pos(1, "recover kit|assist")) {
                "kit" -> recoverWithKit()
                "assist" -> recoverWithOperator()
                else -> throw CliError("recover kit|assist", 2)
            }
            "recovery" -> recoveryPosture()
            "recovery-requests" -> recoveryRequests()
            "account" -> account(a.pos(1, "account password|kit|devices|revoke-device|require-link|delete"))
            // The restore's own status: 1 when it ended with items the server refused.
            "restore" -> return signedIn { s -> Restore(c, s).run() }
            "seed" -> signedIn { s -> Demo(c, s).seed(a.opt("items")?.toIntOrNull() ?: 5) }
            "check" -> signedIn { s -> Demo(c, s).check(a.opt("items")?.toIntOrNull() ?: 5) }
            else -> throw CliError("unknown command '${p[0]}' (andvari-cli --help)", 2)
        }
        return 0
    }

    /**
     * The link a command takes: a link is a capability, and a positional argument is visible to every
     * user of the host in the process list. In order of preference: `--link-file PATH` (its first non-blank line), `-` in
     * the link's place (or `--link-file -`) for one line of standard input, then the positional form, kept for scripts.
     */
    private fun linkArg(i: Int, what: String): String {
        val file = a.opt("link-file")
        val pos = a.positional.getOrNull(i)
        if (file != null && pos != null) throw CliError("give the link once: --link-file or the argument, not both", 2)
        val text = when {
            file == "-" || (file == null && pos == "-") -> c.stdin() ?: throw CliError("no link on standard input", 2)
            file != null -> {
                val f = File(file)
                if (!f.isFile) throw CliError("--link-file: $file is not a readable file", 2)
                f.readLines().firstOrNull { it.isNotBlank() } ?: throw CliError("--link-file: $file holds no link", 2)
            }
            else -> pos ?: throw CliError("missing $what (--link-file PATH, or - to read it from standard input)", 2)
        }
        return text.trim()
    }

    // ---------------------------------------------------------------------------------------------
    // The Trust Gate in a terminal (design §4.4, §12): the printed origin, name and operator key with a confirmation,
    // or --trust-card <card0Hash> for scripts. Never a silent trust on first use.
    // ---------------------------------------------------------------------------------------------

    /**
     * The operator key as every Trust Gate shows it ("Connect to this server?" in the apps, [passGate] here): the engine's
     * [io.silencelen.andvari.core.client.pin.CardTrust.operatorShortFp] over the key's X25519 image, never a hash of the
     * Ed25519 key itself, so the value an operator reads out from `card show` is the one people compare.
     */
    private fun trustGateKey(operatorSignKeyB64: String): String =
        host.trust.operatorShortFp(operatorSignKeyB64)?.let(::grouped) ?: "(none: the card's operator key has no identity image)"

    private fun grouped(shortFp: String): String = Fingerprint.groupedShort(shortFp).replace("\n", " ")

    private fun passGate(g: FirstPin.NeedsTrustGate): Boolean {
        val card0 = g.confirm.card0Hash
        note("Server:       ${g.origin}")
        note("It calls itself “${g.name}” — nobody you know has vouched for it.")
        note("Operator key: ${grouped(g.operatorShortFp)}")
        note("Card 0:       $card0")
        a.opt("trust-card")?.let { expected ->
            if (expected.trim().lowercase() != card0) throw CliError("the server's card 0 is $card0, not the --trust-card you gave: nothing was trusted or sent")
            return true
        }
        val console = Term.console() ?: throw CliError("the Trust Gate needs --trust-card <card0Hash> when no terminal is attached")
        val typed = Term.readLine(console, "Type the server's address to trust it (anything else stops): ")?.trim()
        if (typed != g.origin) throw CliError("not trusted: nothing was sent")
        return true
    }

    /** Make sure this device holds a pin for the origin that a sign-in may use; runs the Trust Gate when it does not. */
    private suspend fun passwordPin(emailNorm: String) {
        val d = PasswordGate.decide(GateInput(GatePurpose.SIGN_IN, GateEntry.SERVER_CHOICE, null, origin, emailNorm, host.trust.gatePins()))
        if (d == GateDecision.PROCEED && host.trust.pinFor(origin) != null) return
        if (d == GateDecision.REFUSE_ENTRY) throw CliError("this server is blocked on this device (its identity changed in a way andvari can't verify)")
        when (val g = host.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS)) {
            is FirstPin.NeedsTrustGate -> if (passGate(g)) host.trust.confirmTrustGate(g.confirm).let { if (it !is FirstPin.Pinned) throw CliError("the server could not be pinned: $it") }
            is FirstPin.Pinned -> {}
            is FirstPin.Refused -> throw CliError("the server's identity card does not verify: ${g.reason}")
            is FirstPin.OriginMismatch -> throw CliError("the server at ${g.dialedOrigin} presents the card of ${g.cardOrigin}: ${g.verdict}")
            is FirstPin.Blocked -> throw CliError("this server is blocked on this device: ${g.verdict}")
            else -> throw CliError("the server could not be pinned: $g")
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Sessions
    // ---------------------------------------------------------------------------------------------

    /** Open the account (the saved session when there is one, else a sign-in), run [block], and keep the session. */
    private suspend fun <T> signedIn(block: suspend (AccountSession) -> T): T {
        val s = signIn()
        try {
            val v = block(s)
            // The server ended the session during the command: say so, even when what the command needed got through.
            host.endedByServer(origin)?.let { throw endedError(s.held.emailNorm, it.code) }
            return v
        } catch (e: Exception) {
            host.endedByServer(origin)?.let { throw endedError(s.held.emailNorm, it.code) }
            throw e
        } finally {
            // What this device found about a change it held is said once, at the signed-in run that finds it or the next.
            runCatching { showFindings(s) }
            host.session(origin)?.let { c.saved.save(it) }
            host.dropSession(origin)
        }
    }

    /** Each finding the engine keeps about a held change ([io.silencelen.andvari.core.client.log.HeldFinding]) said on a line of its own, then marked shown. */
    private fun showFindings(s: AccountSession) {
        for (f in s.logs.heldFindings()) {
            note(findingLine(f))
            s.logs.findingShown(f.id)
        }
    }

    private fun findingLine(f: io.silencelen.andvari.core.client.log.HeldFinding): String {
        val v = f.vaultId
        val what = changeWord(f.change)
        return when (f.what) {
            FoundKind.MADE -> fill(FOUND_MADE, v)
            FoundKind.MADE_AFTER_ALL -> if (f.change == HeldKind.DELETE) fill(FOUND_DELETION_MADE_AFTER_ALL, v)
                else fill(FOUND_MADE_AFTER_ALL, v, what)
            FoundKind.NOT_MADE -> fill(if (f.final) FOUND_NOT_MADE_FINAL else FOUND_NOT_MADE, v, what)
            FoundKind.GIVEN_UP -> fill(when {
                f.final -> FOUND_GIVEN_UP_NOT_MADE
                f.code != null -> FOUND_GIVEN_UP_REFUSED
                f.absentAtRead -> FOUND_GIVEN_UP_ABSENT
                else -> FOUND_GIVEN_UP_CANNOT_TELL
            }, v, what, f.code ?: "")
            FoundKind.PLACE_TAKEN -> fill(FOUND_PLACE_TAKEN, v, what)
            FoundKind.REFUSED -> fill(FOUND_REFUSED, v, what, f.code ?: "")
            FoundKind.CONTACT_CHANGED -> fill(if (f.final) FOUND_CONTACT_CHANGED_NOT_MADE else FOUND_CONTACT_CHANGED, v, what)
        }
    }

    /** The change a finding is about, as it starts a sentence. */
    private fun changeWord(k: HeldKind): String = when (k) {
        HeldKind.CREATE -> "The making of"
        HeldKind.ADD -> "The addition of a member to"
        HeldKind.ROLE -> "The change of a member's role in"
        HeldKind.REMOVE -> "The removal of a member from"
        HeldKind.LEAVE -> "Your leaving of"
        HeldKind.OFFER -> "The offer of the ownership of"
        HeldKind.CANCEL -> "The withdrawal of the offer of the ownership of"
        HeldKind.ACCEPT -> "Your acceptance of the ownership of"
        HeldKind.DELETE -> "The deletion of"
        HeldKind.RESTORE -> "The restoring of"
        HeldKind.OTHER -> "A change to"
    }

    /**
     * A refusal as the person reads it: [what] and the server's [code]. A request this device stopped before sending it
     * (`origin_stopped`: a fork, a damaged pin, an unfinished move, or no pin in force at all, design §4.4 "No credential
     * goes to an origin without a pin in force") is said in words, with what to do, never as the bare code.
     */
    private fun refusal(what: String, code: String): String =
        if (code == ORIGIN_STOPPED) stoppedError(origin, host.access(origin), host.trust.pinFor(origin) != null).message!! else "$what: $code"

    /**
     * Design §4.4 "A session the server ends does not delete the device's copy": the server refused the session's
     * refresh. Only its tokens were deleted; the next sign-in continues.
     */
    private fun endedError(email: String, code: String): CliError = SessionEnded(endedText(origin, email, code))

    /** [endedError]'s type, so a command that must read a session end differently (the deletion check) can tell it apart. */
    private class SessionEnded(message: String) : CliError(message)

    private suspend fun signIn(): AccountSession {
        host.access(origin).let { if (it != OriginAccess.OPEN) throw stoppedError(origin, it) }
        val email = c.email()
        val emailNorm = TrustGrammar.emailNorm(email) ?: throw CliError("not an email address: $email", 2)
        // Design §4.4: a kept session whose origin holds no pin record is a blocked server that can be forgotten. It does
        // not open (no password is asked) and dials nothing; the Trust Gate is not offered over it.
        if (host.trust.pinFor(origin) == null && c.saved.has(origin, emailNorm)) throw CliError(keptWithoutPin(origin, email))
        // The tool keeps one account per server on a home: a sign-in of another account where one is kept stops here,
        // before the password is asked and before anything is sent. A home that keeps a session of this address goes on.
        if (!c.saved.has(origin, emailNorm)) host.keptRefusal(origin, emailNorm, null)?.let { code -> keeperStop(code, origin, emailNorm, ACT_SIGN_IN)?.let { throw it } }
        val password = c.password(email)
        if (host.trust.pinFor(origin) != null) {
            when (val r = c.saved.reopen(host, origin, emailNorm, password.copyOf())) {
                SavedSessions.Reopen.Reopened -> {
                    password.fill('\u0000')
                    return host.account(origin)!!
                }
                // `sign-in` is the person signing in again: it goes on; every other command stops and says so.
                is SavedSessions.Reopen.Ended -> if (a.positional[0] == "sign-in") {
                    note("The server had ended this device's previous session (${r.code}); signing in again.")
                } else {
                    password.fill('\u0000')
                    throw endedError(emailNorm, r.code)
                }
                SavedSessions.Reopen.Unusable -> if (a.positional[0] == "sign-in") {
                    note("This device's saved session of $email on $origin is unusable; signing in again.")
                } else {
                    password.fill('\u0000')
                    throw CliError(unusableText(origin, email))
                }
                // A refresh got no answer: the token kept may be one the server replaced. `sign-in` goes on and names that
                // session, so the server ends it with the sign-in; every other command stops, having sent nothing.
                // Past the window (or tried once more already) nothing was sent with the token; with a try left, a command
                // run again within the window sends it once more.
                SavedSessions.Reopen.RefreshUnanswered, SavedSessions.Reopen.RefreshLost -> if (a.positional[0] == "sign-in") {
                    note(fill(REFRESH_UNANSWERED_SIGN_IN, origin, email))
                } else {
                    password.fill('\u0000')
                    throw if (r == SavedSessions.Reopen.RefreshLost) refreshLostError(origin, email) else refreshUnansweredError(origin, email)
                }
                SavedSessions.Reopen.None -> {}
            }
        }
        // Spec 01 §7, "KDF upgrade": the sign-in wipes [password]; the quiet re-key after it has its own copy, wiped on every path.
        val forReKey = password.copyOf()
        try {
            passwordPin(emailNorm)
            val mark = host.answersMark()
            var r = host.onboarding(origin).signIn(email, password)
            val codeSent = r is SignIn.TotpRequired
            if (r is SignIn.TotpRequired) r = host.onboarding(origin).signInCode(r, String(c.secrets.read("totp", "ANDVARI_TOTP", "Two-step code: ")))
            when (r) {
                is SignIn.SignedIn -> {}
                // After the code step the server's refusal is the one it gives a wrong password too (spec 03 §2).
                SignIn.InvalidCredentials -> throw CliError(if (codeSent) fill(WRONG_CODE_AT_SIGN_IN, origin) else "wrong email or master password")
                SignIn.LinkRequired -> throw CliError("new devices must be linked from one of yours: run `andvari-cli link-device <link>` with a link from your other device")
                SignIn.TrustGateFirst -> throw CliError("the Trust Gate is needed first")
                is SignIn.IdentityFault -> {
                    // A known account under another key: never offered for forgetting ([Host.earlierOffer]).
                    if (r.reason == io.silencelen.andvari.core.client.onboard.AccountOpen.SELF_IDENTITY_MISMATCH) {
                        runCatching { c.state.set("${Host.CLI_EARLIER}$origin|$emailNorm", "key ?") }
                        throw CliError(fill(IDENTITY_KEY_REFUSED_OPEN, origin, ACT_SIGN_IN), 1, IDENTITY_KEY_NOT_KNOWN)
                    }
                    throw CliError("SECURITY: the server's answer did not open as this account (${r.reason}); nothing was used")
                }
                is SignIn.Refused -> throw when (r.code) {
                    RATE_LIMITED -> tooManySignIns()
                    // The shared step's refusal after the code step: the server's one answer for a wrong code and a wrong
                    // password, given after it had asked for a code with this password (spec 03 §2).
                    WireOnboarding.REFUSED_AFTER_CODE -> CliError(fill(WRONG_CODE_AT_SIGN_IN, origin))
                    // The address is recorded on this home as another account ([Host.CLI_ADDRESS]): the session the server
                    // opened was ended there, nothing of it was kept, and the forgetting is offered.
                    EARLIER_ACCOUNT_KNOWN -> CliError(fill(EARLIER_ACCOUNT_REFUSED_OPENED, origin, emailNorm, ACT_SIGN_IN), 1, EARLIER_ACCOUNT_KNOWN)
                    else -> CliError(refusal("sign-in refused", r.code))
                }
                // The shared step's one word for no answer and for an answer it could not use (a server error, a body
                // that is not a sign-in's answer): told apart from what came back.
                SignIn.Unreachable -> throw CliError(
                    if (host.answersSince(mark).lastOrNull()?.third.let { it != null && (it !is Answered.NotUsable || it.reached) })
                        fill(SIGN_IN_UNUSABLE, origin) else "the server did not answer",
                )
                is SignIn.TotpRequired -> throw CliError("two-step code refused")
            }
            c.remember(email)
            host.session(origin)?.let { host.reKeyAfterOpening(it, forReKey) }
            return host.account(origin)!!
        } finally {
            password.fill('\u0000')
            forReKey.fill('\u0000')
        }
    }

    private suspend fun signOut() {
        val email = c.email()
        var told = "no session of it was kept here"
        TrustGrammar.emailNorm(email)?.let { norm ->
            // Through the dialer: a stopped origin (a fork, a damaged pin, no pin in force) is sent nothing, not even the
            // logout; the device ends the session anyway (design §4.4).
            c.saved.accessToken(origin, norm)?.let { token ->
                val r = host.withToken(origin, token).call(WireRoute.LOGOUT, decode = { })
                told = when {
                    r is WireResult.Ok -> "the server ended the session too"
                    r.originStopped -> "the server was not told: nothing is sent to it from this device"
                    r is WireResult.NoAnswer -> "the server did not answer, so it was not told"
                    else -> "the server had already ended the session"
                }
            }
            c.saved.forget(origin, norm)
            host.devices.forget(origin, norm)
        }
        host.signedOut(origin)
        c.state.set("${Ctx.K_EMAIL}|$origin", null)
        val pin = if (host.trust.pinFor(origin) != null) "its pin of the server is kept" else "it holds no pin of the server"
        say("signed out: this device forgot $email on $origin; $told ($pin)")
    }

    /**
     * "Forget this server" (design §4.4, §12.3): the only way on after a fork or a damaged pin. Local only, nothing is
     * sent: everything this device keeps for the origin goes ([Host.forgetServer]): the pin with its marks, the saved
     * sessions, the accounts' records and the tool's own. Next time the address is typed again and passes the Trust Gate.
     */
    private fun forgetServer() {
        if (!a.has("yes")) throw CliError(
            "forget-server deletes everything this device keeps for $origin: its pin of the server, the saved session and this " +
                "device's copy of the account's records. Nothing is sent to the server. Add --yes", 2,
        )
        val was = try { host.access(origin).code } catch (e: Exception) { "unreadable" }
        val remembered = try { c.state.get("${Ctx.K_EMAIL}|$origin") } catch (e: Exception) { null }
        val r = host.forgetServer(origin, c.saved, remembered)
        val said = forgotten(origin, was, r, c.home.dir.path)
        if (r is ServerForgotten.Partly) throw CliError(said)
        say(said)
    }

    /**
     * "Forget the earlier account on this device" (decided on 2026-11-17), offered by a refusal of another account under an
     * address this home ties to an earlier one ([EARLIER_ACCOUNT_REFUSED]). Local only, nothing is sent. Without `--yes` it
     * says exactly what would go and changes nothing; with it, the earlier account's records go ([Host.forgetEarlier]) and
     * its identity key, the pin and every other account stay. A forgetting a stopped run began is finished first.
     */
    private fun forgetEarlierAccount() {
        val email = a.opt("email") ?: throw CliError("--email E: the address whose earlier account this device would forget", 2)
        val norm = TrustGrammar.emailNorm(email) ?: throw CliError("not an email address: $email", 2)
        if (host.finishForgetting(origin, norm) != null) return say(fill(EARLIER_FORGOTTEN, origin, norm))
        val earlier = when (val o = host.earlierOffer(origin, norm, c.saved)) {
            is Host.EarlierOffer.Account -> o.userId
            Host.EarlierOffer.Key -> throw CliError(fill(EARLIER_KEY_NOT_OFFERED, origin, norm), 1, KEY_EARLIER_NOT_OFFERED)
            null -> throw CliError(fill(EARLIER_NOT_OFFERED, origin, norm), 1, KEY_EARLIER_NOT_OFFERED)
        }
        val records = host.earlierRecords(origin, norm, earlier) ?: throw CliError("this device could not list what it keeps in ${c.home.dir}: nothing was changed")
        val request = "${Host.KEPT_ASSIST}$origin" in records
        if (!a.has("yes")) {
            // One record to a line, on standard error (an error's own text is one line), then the plan's sentence.
            records.forEach { note("  $it") }
            throw CliError.lines(listOfNotNull(fill(EARLIER_FORGET_PLAN, origin, norm, earlier, records.size),
                fill(EARLIER_PLAN_REQUEST, origin, norm).takeIf { request }), 2, KEY_EARLIER_FORGET_PLAN)
        }
        host.forgetEarlier(origin, norm, earlier)
        say(fill(EARLIER_FORGOTTEN, origin, norm))
        if (request) say(fill(EARLIER_REQUEST_FORGOTTEN, origin, norm))
    }

    private fun whoami() {
        val pin = host.trust.pinFor(origin)
        if (asJson) {
            val access = host.access(origin)
            val account = c.state.get("${Ctx.K_EMAIL}|$origin")
            val blocked = access == OriginAccess.OPEN && pin == null && account?.let { c.saved.has(origin, it) } == true
            return emit(buildJsonObject {
                put("origin", JsonPrimitive(origin))
                put("account", JsonPrimitive(account))
                put("server", pin?.let { p ->
                    buildJsonObject {
                        put("name", JsonPrimitive(p.name)); put("kind", JsonPrimitive(p.kind)); put("cardSeq", JsonPrimitive(p.seq))
                        put("pinnedThrough", JsonPrimitive(p.root.code))
                    }
                } ?: JsonNull)
                put("state", JsonPrimitive(if (access != OriginAccess.OPEN) access.code else if (blocked) "blocked" else "open"))
            })
        }
        say("origin:  $origin")
        say("account: ${c.state.get("${Ctx.K_EMAIL}|$origin") ?: "(none)"}")
        say("server:  ${pin?.let { "${it.name}, ${it.kind}, card ${it.seq}, pinned through ${it.root.code}" } ?: "not pinned on this device"}")
        val access = host.access(origin)
        if (access != OriginAccess.OPEN) say("state:   stopped (${access.code}): nothing is sent to it")
        else if (pin == null && c.state.get("${Ctx.K_EMAIL}|$origin")?.let { c.saved.has(origin, it) } == true) {
            say("state:   blocked: a session is kept but no pin; `forget-server --yes` or `sign-out`")
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Registration: the setup link, enrol and register links, public sign-up (design §6.7, §7.2, §7.3, §9.5)
    // ---------------------------------------------------------------------------------------------

    private fun form(email: String, password: CharArray): RegistrationForm = RegistrationForm(
        email, a.opt("name") ?: email.substringBefore('@'), password, a.has("age-confirm") || a.opt("age-confirm") != null,
        RecoveryChoiceKind.PRIVATE, host.deviceName, host.platform,
    )

    private fun newPassword(email: String): CharArray {
        val pw = c.secrets.read("password", "ANDVARI_PASSWORD", "New master password for $email: ")
        if (a.opt("password-file") == null && c.env("ANDVARI_PASSWORD").isNullOrEmpty() && Term.console() != null) {
            val again = c.secrets.read("password", "ANDVARI_PASSWORD", "Again: ")
            if (!pw.contentEquals(again)) throw CliError("the two passwords differ")
            again.fill('\u0000')
        }
        return pw
    }

    /**
     * The kit's capture gate must be passable before anything is sent: the server records a new kit with the account (or
     * with the recovery), so a kit that cannot be captured afterwards would leave an account whose kit nobody saw.
     * Without a terminal that means `--kit-out FILE`, to a file that does not exist yet.
     */
    private fun kitCapturable() {
        val file = a.opt("kit-out")?.let(::File)
        if (file == null && Term.console() == null) {
            throw CliError("the recovery kit must be captured: pass --kit-out FILE when no terminal is attached. Nothing was sent", 2)
        }
        if (file != null && file.exists()) throw CliError("--kit-out $file exists; it is never overwritten. Nothing was sent", 2)
    }

    private suspend fun enrol(link: String, setup: Boolean) {
        val email = a.opt("email") ?: throw CliError("--email is required", 2)
        kitCapturable()
        c.originFromLink(LinkUrl.parse(link)?.let { p -> p.origin.also { p.wipe() } })
        var step = host.links.open(link, GateEntry.PASTE_INVITE)
        if (step is RecipientStep.TrustGate) {
            passGate(step.gate)
            step = host.links.proceed(step)
        }
        val confirm = when (step) {
            is RecipientStep.Confirm -> step
            is RecipientStep.Stopped -> throw CliError("the link stopped: ${step.reason.code}${step.cardVerdict?.let { " ($it)" } ?: ""}")
            is RecipientStep.NotTakingAccounts -> throw CliError("${step.offer.origin} is not taking new accounts (${step.mode}${if (step.full) ", full" else ""})")
            else -> throw CliError("the link cannot be used here: $step")
        }
        if (setup != (confirm.offer.kind == "setup")) throw CliError(if (setup) "that is not a setup link" else "that is a setup link: use `andvari-cli operator enrol <link>`")
        if (confirm.offer.origin != origin) throw CliError("the link is for ${confirm.offer.origin}, not $origin")
        val linkOrigin = confirm.offer.origin
        note("${if (setup) "Set up the operator account of" else "Create an account on"} “${confirm.offer.instanceName}” ($linkOrigin) for $email")
        val auth = when (confirm.offer.kind) {
            "setup" -> RegistrationAuth.SetupLink(confirm)
            "enrol" -> RegistrationAuth.EnrolLink(confirm)
            else -> RegistrationAuth.RegisterLink(confirm)
        }
        val o = host.onboarding(linkOrigin)
        val reg = registered(o.register(auth, form(email, newPassword(email))), linkOrigin, TrustGrammar.emailNorm(email))
        host.rememberName(linkOrigin, reg.userId, a.opt("name") ?: email.substringBefore('@'))
        c.state.set(Ctx.K_ORIGIN, linkOrigin)
        c.state.set("${Ctx.K_EMAIL}|$linkOrigin", TrustGrammar.emailNorm(email))
        captureKit(o, reg.kit)
        if (setup) {
            val pin = host.trust.pinFor(linkOrigin)
            if (reg.cardPending || pin == null) say("card 0 is not stored yet: run `andvari-cli card sign` to finish setting up this server")
            else say("Instance ready: ${pin.name}. Card 0 $pin.card0Hash".replace("\$pin.card0Hash", pin.card0Hash))
        }
        say("registered: $email (${reg.userId}) on $linkOrigin")
    }

    /** [r] when an account was made; else what stopped it, said. [at] and [emailNorm]: where and for whom. */
    private fun registered(r: Registration, at: String, emailNorm: String?): Registration.Registered = when (r) {
        // Made at the server, but this home did not keep its session (what it keeps changed meanwhile): the kit is kept.
        is Registration.Registered -> r.notKept?.let { reason ->
            val where = keepKitUnconfirmed(r.kit)
            throw CliError(fill(REGISTRATION_COMMITTED_NOT_KEPT, at, emailNorm ?: "the account", where, notKeptWhy(reason, at, emailNorm)), 1, KEY_COMMITTED_NOT_KEPT)
        } ?: r
        Registration.PasswordTooWeak -> throw CliError("that master password is too weak")
        is Registration.Refused -> throw keeperStop(r.code, at, emailNorm, ACT_REGISTRATION) ?: CliError(refusal("registration refused", r.code))
        is Registration.IdentityFault -> throw CliError("SECURITY: the server's answer is not the account this device registered (${r.reason})")
        Registration.Unknown -> throw CliError("no answer from the server: the account may exist; try `andvari-cli sign-in`")
    }

    private suspend fun signUp() {
        val email = a.opt("email") ?: throw CliError("--email is required", 2)
        val emailNorm = TrustGrammar.emailNorm(email) ?: throw CliError("not an email address", 2)
        kitCapturable()
        passwordPin(emailNorm)
        val o = host.onboarding(origin)
        when (val s = o.signupStart(email, a.has("age-confirm")) { }) {
            SignupStart.Sent -> note("If no email arrives, check the address, or sign in if you already have an account.")
            SignupStart.MailUnavailable -> throw CliError("the server can't send email right now")
            SignupStart.Unreachable -> throw CliError("the server did not answer")
            is SignupStart.Refused -> throw CliError(refusal("sign-up refused", s.code))
        }
        val code = String(c.secrets.read("code", "ANDVARI_SIGNUP_CODE", "The 6-digit code from the email: ")).trim()
        val ticket = when (val v = o.signupVerify(email, code)) {
            is SignupVerify.Ticket -> v
            SignupVerify.BadCode -> throw CliError("that code is wrong or expired")
            is SignupVerify.Refused -> throw CliError(refusal("the code was refused", v.code))
            SignupVerify.Unreachable -> throw CliError("the server did not answer")
        }
        val reg = registered(o.register(RegistrationAuth.Ticket(ticket), form(email, newPassword(email))), origin, emailNorm)
        host.rememberName(origin, reg.userId, a.opt("name") ?: email.substringBefore('@'))
        c.remember(email)
        captureKit(o, reg.kit)
        say("registered: $email (${reg.userId}) on $origin")
    }

    /**
     * The kit's capture gate (design §10): with `--kit-out FILE` the kit is written there (owner-only) and the three
     * groups are confirmed from it; otherwise it is shown on the terminal and the person types the groups back.
     */
    private fun kitText(kit: RevealedKit): String = buildString {
        appendLine("andvari recovery kit for account ${kit.accountId}")
        kit.groups.forEachIndexed { i, g -> appendLine("${i + 1}. $g") }
        appendLine(kit.qr)
    }

    /**
     * A kit the server made the account's own while this home did not keep the account's session (the engine's `notKept`):
     * written to `--kit-out`, else shown on the terminal, else printed, and never confirmed (that needs a session). Answers
     * where it went, as [COMMITTED_KIT_WRITTEN] or [COMMITTED_KIT_SHOWN] say it.
     */
    private fun keepKitUnconfirmed(kit: RevealedKit): String {
        val file = a.opt("kit-out")?.let(::File)
        if (file != null && !file.exists()) {
            OwnerOnlyFile(file).replace(kitText(kit))
            return fill(COMMITTED_KIT_WRITTEN, file.path)
        }
        val console = Term.console()
        if (console != null) {
            Term.console(console, "YOUR RECOVERY KIT (account ${kit.accountId}). Write it down now:")
            kit.groups.forEachIndexed { i, g -> Term.console(console, "  ${(i + 1).toString().padStart(2)}. $g") }
        } else {
            // The account's only kit: it is never lost for want of a terminal.
            kitText(kit).lines().filter { it.isNotEmpty() }.forEach(::say)
        }
        return COMMITTED_KIT_SHOWN
    }

    /** Why this home did not keep the session after a commit ([Host.sink]'s take), in words. */
    private fun notKeptWhy(reason: String, at: String, emailNorm: String?): String = when (reason) {
        Establishing.ANOTHER_SESSION_KEPT -> fill(NOT_KEPT_ANOTHER, host.keptAt(at)?.firstOrNull { it.emailNorm != emailNorm }?.emailNorm ?: "another account")
        Establishing.OPERATOR_ACCOUNT_HELD -> NOT_KEPT_OPERATOR
        Establishing.KEPT_COPY_DAMAGED -> NOT_KEPT_DAMAGED
        KEPT_UNREADABLE -> NOT_KEPT_UNREADABLE
        EARLIER_ACCOUNT_KNOWN -> fill(NOT_KEPT_EARLIER, emailNorm ?: "the address")
        else -> fill(NOT_KEPT_OTHER, reason)
    }

    /** A recovery the server committed whose session this home did not keep: the kit kept, and the commit said. */
    private fun recoveryNotKept(kit: RevealedKit, at: String, email: String, reason: String, assisted: Boolean): CliError {
        val where = keepKitUnconfirmed(kit)
        val text = fill(RECOVERY_COMMITTED_NOT_KEPT, at, email, where, notKeptWhy(reason, at, TrustGrammar.emailNorm(email))) +
            (if (assisted) " $ASSISTED_REQUEST_USED" else "")
        return CliError(text, 1, KEY_COMMITTED_NOT_KEPT)
    }

    private suspend fun captureKit(o: WireOnboarding, kit: RevealedKit) {
        val file = a.opt("kit-out")?.let(::File)
        if (file != null) {
            if (file.exists()) throw CliError("--kit-out $file exists; it is never overwritten")
            OwnerOnlyFile(file).replace(kitText(kit))
            val typed = o.kitChallenge(kit).associateWith { kit.groups[it - 1] }
            confirmed(o.confirmKit(kit, typed))
            note("Recovery kit written to $file. Print it and keep it offline.")
            return
        }
        val console = Term.console() ?: throw CliError("the recovery kit must be captured: pass --kit-out FILE when no terminal is attached")
        Term.console(console, "YOUR RECOVERY KIT (account ${kit.accountId}). Write it down now:")
        fun groups() = kit.groups.forEachIndexed { i, g -> Term.console(console, "  ${(i + 1).toString().padStart(2)}. $g") }
        groups()
        while (true) {
            val asked = o.kitChallenge(kit)
            val typed = asked.associateWith { Term.readLine(console, "Group $it: ")?.trim() ?: "" }
            when (val r = o.confirmKit(kit, typed)) {
                KitConfirm.Confirmed -> return
                KitConfirm.Wrong -> Term.console(console, "That doesn't match. Try again.")
                KitConfirm.ShowAgain -> groups()
                is KitConfirm.Unrecorded -> throw CliError("the server did not record the kit confirmation (${r.code}); sign in to confirm it again")
            }
        }
    }

    private fun confirmed(r: KitConfirm) {
        if (r != KitConfirm.Confirmed) throw CliError("the kit confirmation was not recorded: $r")
    }

    // ---------------------------------------------------------------------------------------------
    // The instance card (design §4.2, §14.1)
    // ---------------------------------------------------------------------------------------------

    private suspend fun card(sub: String) {
        when (sub) {
            "show" -> {
                // From this device's pin, never a fetch (T-R10): take card0Hash from the device that signed.
                val pin = host.trust.pinFor(origin) ?: throw CliError("this device holds no pin for $origin")
                if (asJson) return emit(buildJsonObject {
                    put("origin", JsonPrimitive(pin.origin)); put("name", JsonPrimitive(pin.name)); put("kind", JsonPrimitive(pin.kind))
                    put("instanceId", JsonPrimitive(pin.instanceId)); put("card0Hash", JsonPrimitive(pin.card0Hash))
                    put("cardSeq", JsonPrimitive(pin.seq)); put("cardHash", JsonPrimitive(pin.hash)); put("operator", JsonPrimitive(pin.operator))
                    put("operatorKey", JsonPrimitive(trustGateKey(pin.operatorSignKey))); put("recoveryFp", JsonPrimitive(pin.recoveryFp))
                    put("pinnedVia", JsonPrimitive(pin.root.code))
                })
                say("origin:      ${pin.origin}")
                say("name:        ${pin.name}")
                say("kind:        ${pin.kind}")
                say("instanceId:  ${pin.instanceId}")
                say("card0Hash:   ${pin.card0Hash}")
                say("card:        seq ${pin.seq}, ${pin.hash}")
                say("operator:    ${pin.operator}")
                say("operatorKey: ${trustGateKey(pin.operatorSignKey)}   (as the Trust Gate shows it: compare this)")
                say("recoveryFp:  ${pin.recoveryFp}")
                say("pinned via:  ${pin.root.code}")
            }
            "sign" -> cardSign()
            "rotation" -> cardRotation()
            "follow" -> followMove()
            else -> throw CliError("card show|sign|rotation|follow", 2)
        }
    }

    /**
     * `card sign --name N | --move-to ORIGIN | --recovery-fp HEX|none`: ONE change per card, through the shared code's path
     * ([CardChanges], [Host.operatorCards]). A recovery key is named only where the card names none (a change of key is
     * `card rotation`, with its signed statement); removing it (`none`) is said first, in words, and needs the typed
     * [CardChanges.REMOVE_PHRASE], at the terminal or as `--confirm`. Everything is checked before the password is asked.
     */
    private suspend fun cardSign() {
        val changes = listOfNotNull(a.opt("name")?.let { "name" }, a.opt("move-to")?.let { "move-to" }, a.opt("recovery-fp")?.let { "recovery-fp" })
        if (changes.size > 1) throw CliError("one change per card: give one of --name, --move-to and --recovery-fp (not ${changes.joinToString(" and ") { "--$it" }}). Nothing was sent", 2)
        val fp = a.opt("recovery-fp")?.let(CardChanges::typedFp)
        if (fp != null && fp != io.silencelen.andvari.core.trust.TrustGrammar.NONE && !io.silencelen.andvari.core.trust.TrustGrammar.isHex64(fp)) {
            throw CliError("--recovery-fp must be the 64 hex digits recovery-cli keygen printed, or none: nothing was sent", 2)
        }
        if (fp == io.silencelen.andvari.core.trust.TrustGrammar.NONE) confirmRecoveryKeyRemoval()
        signedIn { s ->
            if (changes.isEmpty()) throw CliError("say what the next card changes: --name N, --move-to ORIGIN or --recovery-fp HEX|none. Nothing was sent", 2)
            cardSigner(s)
            val cards = host.operatorCards(s.held)
            val before = host.trust.pinFor(origin)
            val pw = c.password(s.held.emailNorm)
            val r = when {
                a.opt("name") != null -> cards.rename(a.opt("name")!!, pw)
                a.opt("move-to") != null -> cards.move(a.opt("move-to")!!.trim().trimEnd('/'), pw)
                fp == io.silencelen.andvari.core.trust.TrustGrammar.NONE -> cards.removeRecoveryKey(pw)
                else -> cards.setRecoveryKey(fp!!, pw)
            }
            say(CardChanges.outcome(r, origin, before))
            if (fp != null && fp != io.silencelen.andvari.core.trust.TrustGrammar.NONE) {
                say("The card now names a recovery key it did not name before, with no signed rotation: members who opt in to operator recovery see that change named")
            }
        }
    }

    /**
     * What removing the recovery key does, said before anything is asked, and the typed confirmation
     * (as the desktop asks it): `--confirm "REMOVE RECOVERY KEY"`, or typed at the terminal.
     */
    private fun confirmRecoveryKeyRemoval() {
        val name = host.trust.pinFor(origin)?.name?.let { "“$it” ($origin)" } ?: origin
        note("Removing the recovery key from the card of $name turns operator recovery off on this server:")
        note("  - no request for help can be answered any more, also for the people who chose operator recovery;")
        note("  - a card that names no key can never be covered by a signed rotation later: if you name a key again, every member")
        note("    who opts in afterwards is warned that the server's identity may have been taken over.")
        val typed = a.opt("confirm") ?: run {
            val console = Term.console() ?: throw CliError("type the confirmation: give --confirm \"${CardChanges.REMOVE_PHRASE}\" when no terminal is attached. Nothing was sent", 2)
            Term.readLine(console, "Type ${CardChanges.REMOVE_PHRASE} to remove it (anything else stops): ")?.trim()
        }
        if (typed != CardChanges.REMOVE_PHRASE) throw CliError("not confirmed: the recovery key stays on the card. Nothing was sent")
    }

    /**
     * `card rotation --file F [--recovery-fp HEX]`: the statements `recovery-cli rotate` made offline, checked against this
     * device's pin BEFORE the master password is asked (each signed by the key the card names, for this instance, leading
     * to a new key, and to `--recovery-fp` when it is given); then the shared code's path checks them again on the
     * refreshed pin, uploads them and the card that names the new key, in that order.
     */
    private suspend fun cardRotation() {
        val path = a.opt("file") ?: throw CliError("--file <the output of recovery-cli rotate>", 2)
        val f = File(path)
        if (!f.isFile) throw CliError("--file: $path is not a readable file", 2)
        if (f.length() > CardChanges.ROTATION_FILE_MAX) throw CliError("--file holds more than a rotation file does: nothing was asked or sent", 2)
        val frames = CardChanges.statements(f.readText())
        val typed = a.opt("recovery-fp")?.let(CardChanges::typedFp)
        // Against this device's pin, before any password: no pin here leaves the refusal to the sign-in below.
        host.trust.pinFor(origin)?.let { pin -> CardChanges.leadsTo(host.crypto, pin, frames, typed) }
        signedIn { s ->
            cardSigner(s)
            val cards = host.operatorCards(s.held)
            val pin = (host.trust.refresh(origin) as? io.silencelen.andvari.core.client.pin.CardStatus.Ok)?.pin
                ?: throw CliError("this device's pin of $origin is not at the server's newest card: nothing was asked or sent")
            val to = CardChanges.leadsTo(host.crypto, pin, frames, typed)
            val r = cards.rotateRecoveryKey(frames, c.password(s.held.emailNorm))
            say(CardChanges.outcome(r, origin, pin))
            say("The card names the recovery key $to, and its signed rotation is served with it")
        }
    }

    /**
     * A move (design §4.4 "A move"): the newest verified card names another origin. It is shown, and followed only on the
     * person's word (`--yes`), with no Trust Gate; the pin, every per-origin record (the tool's own names and remembered
     * account included) and the saved session move to the new address. A move this device followed but could not finish
     * (`MOVING`) is finished by the same command at the new address. No credential is sent for any of it.
     */
    private suspend fun followMove() {
        val st = if (host.access(origin) == OriginAccess.MOVING) host.trust.finishMove(origin) else {
            when (val now = host.trust.refresh(origin)) {
                is CardStatus.Moved -> {
                    if (now.storeBuildMustUpdate) throw CliError("this server says it moved. Update andvari-cli")
                    note("“${now.pinned.name}” (${now.pinned.origin}) moved to ${now.newest.origin}, signed by its operator.")
                    if (!a.has("yes")) throw CliError("pass --yes to follow the move to ${now.newest.origin}", 2)
                    host.trust.followMove(now)
                }
                is CardStatus.Ok -> { say("no move: the card of ${now.pin.name} ($origin) names this address"); return }
                else -> now
            }
        }
        when (st) {
            is CardStatus.Ok -> {
                c.state.set(Ctx.K_ORIGIN, st.pin.origin)
                say("followed: this device now uses ${st.pin.name} at ${st.pin.origin}; its records and saved session moved with it")
                if (st.newKitDue) say("Your recovery kit names the old address: make a new one")
            }
            is CardStatus.PinConflict -> throw CliError(
                "this device already keeps something for ${st.newest.origin}, so the move was not followed and nothing changed. " +
                    "If that is an old copy, run `andvari-cli forget-server --yes --origin ${arg(st.newest.origin)}` and then `card follow --yes` again",
            )
            is CardStatus.Refused -> throw CliError(
                when (st.verdict) {
                    "no_pin" -> "this device holds no pin of $origin, so there is no move of it to follow: nothing was sent. " +
                        "Sign in with `andvari-cli sign-in --origin <the server's address>` first"
                    io.silencelen.andvari.core.client.pin.MOVE_UNFINISHED ->
                        "the move was followed but this device could not move its saved session yet; nothing is sent to the new address. " +
                            "Run `andvari-cli card follow --origin ${arg(st.pinned?.origin ?: origin)}` again"
                    else -> "the move was not followed: ${st.verdict}; nothing changed"
                },
            )
            is CardStatus.Fork -> throw stoppedError(origin, OriginAccess.FORKED)
            CardStatus.Unreachable -> throw CliError("the server did not answer; nothing changed")
            else -> throw CliError("the move was not followed (${st::class.simpleName}); nothing changed")
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Links and contacts (design §6)
    // ---------------------------------------------------------------------------------------------

    private suspend fun link(sub: String) {
        when (sub) {
            "create" -> signedIn { s ->
                linkName(s)
                s.sync()
                val shares = a.all("share").map { val (v, r) = (it.split(':') + "writer").let { p -> p[0] to p[1] }; LinkShare(vaultOf(s, v), r) }
                val hours = a.opt("hours")?.toLongOrNull() ?: 24
                when (val r = host.links.create(a.opt("kind") ?: "connect", hours * 3_600_000L, shares)) {
                    is CreateOutcome.Created -> say(r.link.url)
                    is CreateOutcome.Unknown -> say(r.link.url).also { note("(no answer from the server: the link may not exist)") }
                    is CreateOutcome.Refused -> throw CliError(refusal("link refused", r.code))
                }
            }
            "list" -> signedIn {
                val links = host.links.createdLinks()
                // Never the link itself: it is a capability (the ids, kinds and how many shares only).
                if (asJson) emit(JsonArray(links.map { l ->
                    buildJsonObject { put("linkId", JsonPrimitive(l.linkId)); put("kind", JsonPrimitive(l.kind)); put("shares", JsonPrimitive(l.shares.size)) }
                }))
                else links.forEach { l -> say("${arg(l.linkId)}  ${l.kind}  ${l.shares.size} shares") }
            }
            "revoke" -> signedIn { if (!host.links.revoke(a.pos(2, "the link id"))) throw CliError("the server did not confirm the revocation") }
            "open" -> signedIn { s ->
                linkName(s)
                var step = host.links.open(linkArg(2, "the link"), GateEntry.PASTE_INVITE)
                if (step is RecipientStep.KeyChanged) {
                    note("WARNING: you already have a contact “${step.existingLabel}” with a different key. Only matching codes will replace it.")
                    if (!a.has("yes")) throw CliError("pass --yes to continue with the key change")
                    step = host.links.proceed(step)
                }
                val confirm = step as? RecipientStep.Confirm ?: throw CliError("the link cannot be used here: ${(step as? RecipientStep.Stopped)?.reason?.code ?: step}")
                if (confirm.needsAccount) throw CliError("that link registers an account: use `andvari-cli enrol <link> --email …`")
                note("Connect with “${confirm.offer.creatorName}” (as they call themselves) on ${confirm.offer.origin}")
                val answered = host.links.confirm(confirm) as? RecipientStep.Answered ?: throw CliError("the answer was not posted")
                say("answered: contact ${arg(answered.contactUserId)}. When they have processed it, run `andvari-cli link code ${arg(answered.contactUserId)}`")
            }
            "answers" -> signedIn {
                val steps = host.links.processAnswers()
                // One row per answer, in the order processed; absent values are null (the form of every --json list).
                if (asJson) return@signedIn emit(JsonArray(steps.map { st ->
                    fun row(outcome: String, userId: String?, label: String?, code: String?, linkId: String, reason: String?) = buildJsonObject {
                        put("outcome", JsonPrimitive(outcome)); put("userId", userId?.let(::JsonPrimitive) ?: JsonNull)
                        put("label", label?.let(::JsonPrimitive) ?: JsonNull); put("code", code?.let(::JsonPrimitive) ?: JsonNull)
                        put("linkId", JsonPrimitive(linkId)); put("reason", reason?.let(::JsonPrimitive) ?: JsonNull)
                    }
                    when (st) {
                        is CreatorStep.Processed -> row("connected", st.contactUserId, st.label, host.links.code(st.contactUserId), st.linkId, null)
                        is CreatorStep.KeyChanged -> row("key_changed", st.answererUserId, st.existingLabel, null, st.linkId, null)
                        is CreatorStep.Deferred -> row("deferred", null, null, null, st.linkId, st.reason)
                        is CreatorStep.Ignored -> row("ignored", null, null, null, st.linkId, st.reason)
                    }
                }))
                for (st in steps) when (st) {
                    is CreatorStep.Processed -> say("connected: ${st.contactUserId} “${st.label}”  your code ${host.links.code(st.contactUserId) ?: "(not ready)"}")
                    is CreatorStep.KeyChanged -> say("key changed: ${st.answererUserId} (was “${st.existingLabel}”): compare codes to replace it")
                    is CreatorStep.Deferred -> say("deferred: ${st.linkId} (${st.reason})")
                    is CreatorStep.Ignored -> say("ignored: ${st.linkId} (${st.reason})")
                }
            }
            "code" -> signedIn { s ->
                val contact = contactArg(s, 2)
                if (host.links.code(contact) == null) host.links.refreshReveal(contact)
                val code = host.links.code(contact) ?: throw CliError("no code yet: the other side has not processed the link")
                say("Your code: $code   Read it to them; type theirs with `andvari-cli link compare ${arg(contact)}`")
            }
            "compare" -> signedIn { s ->
                val contact = contactArg(s, 2)
                val digits = a.opt("code") ?: String(c.secrets.read("code", "ANDVARI_CONTACT_CODE", "The code shown on THEIR screen: "))
                when (host.links.typeCode(contact, digits.filter { it.isDigit() })) {
                    CompareResult.Matched -> say("codes match: $contact is compared")
                    CompareResult.Mismatch -> throw CliError("The codes don't match. Don't share anything with this person until you've talked.")
                    CompareResult.Failed -> throw CliError("this link is failed: no code can be compared; make a new link")
                    CompareResult.Unsaved -> throw CliError("the codes match, but the account state was not saved yet: run the command again")
                }
            }
            else -> throw CliError("link create|list|revoke|open|answers|code|compare", 2)
        }
    }

    /**
     * The name [s]'s account goes by in its links, made sure of before anything of a link is sent ([LinkName]): `--name`
     * when given (kept for the account on this home, replacing what was kept), else the one kept here, else asked at a
     * terminal and kept. Without one and without a terminal, exit 2 and nothing of the link is sent. The address's first
     * part is never taken in its place here: only a registration on this home did that.
     */
    private fun linkName(s: AccountSession) {
        val given = a.opt("name")
        if (given == null && host.ownName(origin, s.userId) != null) return
        val name = LinkName.read(given, Term.console()?.let { k -> { q: String -> Term.readLine(k, q) } }, s.held.emailNorm)
            ?: throw CliError(fill(LinkName.NEEDED, s.held.emailNorm), 2, LinkName.KEY_NEEDED)
        if (!LinkName.isName(name)) throw CliError(LinkName.NOT_A_NAME, 2)
        host.rememberName(origin, s.userId, name)
    }

    /** A contact given as its userId or its label. */
    private suspend fun contactArg(s: AccountSession, i: Int): String {
        s.readAccountStateOnce()
        val v = a.pos(i, "the contact")
        val list = s.contacts.list()
        list.firstOrNull { it.record.userId == v }?.let { return it.record.userId }
        val byLabel = list.filter { it.labelText == v }
        if (byLabel.size == 1) return byLabel[0].record.userId
        if (TrustGrammar.isUuid(v)) return v
        throw CliError(if (byLabel.isEmpty()) "no contact '$v'" else "'$v' names ${byLabel.size} contacts: use the userId")
    }

    // ---------------------------------------------------------------------------------------------
    // Vaults (design §3) and items (spec 02 §3)
    // ---------------------------------------------------------------------------------------------

    /** A vault given as its id, its name, or `personal`. */
    private fun vaultOf(s: AccountSession, v: String): String {
        if (v == "personal") return s.personalVaultId ?: throw CliError("this account has no personal vault in force")
        if (s.vault(v) != null) return v
        val byName = s.vaultIds().filter { s.vaultName(it) == v }
        if (byName.size == 1) return byName[0]
        throw CliError(if (byName.isEmpty()) "no vault '$v'" else "'$v' names ${byName.size} vaults: use the id")
    }

    private fun vaultArg(s: AccountSession, i: Int) = vaultOf(s, a.pos(i, "the vault"))

    private suspend fun append(s: AccountSession, vaultId: String?, action: LogAction): String {
        var tries = 0
        while (true) {
            when (val r = s.logs.append(vaultId, action)) {
                is AppendOutcome.Appended -> { say("${arg(r.state.vaultId)}  seq ${r.state.headSeq}"); return r.state.vaultId }
                is AppendOutcome.Refused -> {
                    val wait = r.retryAfterSeconds
                    if (r.code == "rate_limited" && wait != null && tries++ < 3) {
                        note("rate limited: waiting $wait s"); delay(wait * 1000); continue
                    }
                    throw CliError(refusal("refused", r.code))
                }
                // A change this device holds for the vault waits: nothing new is signed for it meanwhile.
                is AppendOutcome.NotAllowed -> throw if (r.reason == io.silencelen.andvari.core.client.log.StoredVaultLogs.APPEND_PENDING && vaultId != null)
                    heldError(s, vaultId) else CliError("not allowed: ${r.reason}")
                AppendOutcome.VaultReadOnly -> throw CliError("this vault is read-only on this device (its history doesn't check out, or the server withheld it)")
                AppendOutcome.HeadMoved -> if (tries++ < 3) { s.sync(); continue } else throw CliError("the vault changed meanwhile: try again")
                AppendOutcome.ClockAhead -> throw CliError("your device's clock is ahead")
                AppendOutcome.Pending -> throw if (vaultId == null) CliError(NEW_VAULT_WAITS, 1, KEY_CHANGE_WAITS) else heldError(s, vaultId)
            }
        }
    }

    /**
     * What is so of the change this device holds for [vaultId] (the engine's own rule, design §3.7): a vault's deletion is
     * never sent again by itself and waits for the person's word ([deletionWord]); any other change is sent again, unchanged,
     * only before the next change made to that vault from this device, and not after a day.
     */
    private fun heldError(s: AccountSession, vaultId: String): CliError {
        val held = s.logs.heldChange(vaultId)
        if (held?.waitsForWord == true) return CliError(fill(DELETION_WAITS, vaultId), 1, KEY_DELETION_WAITS)
        // What is said reads the change's own state: one the server's answer called stored is never given up after a day.
        return CliError(when (held?.known) {
            HeldKnown.STORED_BY_SERVERS_WORD -> CHANGE_WAITS_STORED
            HeldKnown.NOT_STORED -> CHANGE_WAITS_NOT_STORED
            else -> CHANGE_WAITS
        }, 1, KEY_CHANGE_WAITS)
    }

    /**
     * `vault send-deletion V` and `vault keep V`: the person's word on a vault's deletion that waits ([DELETION_WAITS]).
     * Sending reads the vault's log first, with nothing sent ([io.silencelen.andvari.core.client.log.VaultLogEngine.lookHeld]),
     * and sends the deletion as it was signed only where the read reached the server and the vault does not hold it; keeping
     * withdraws it, and it is never sent again from here.
     */
    private suspend fun deletionWord(s: AccountSession, v: String, send: Boolean) {
        // A vault already gone from the list is still named by its id: the sync that ran first may have found it deleted.
        val id = runCatching { vaultOf(s, v) }.getOrNull() ?: v
        val held = s.logs.heldChange(id)?.takeIf { it.waitsForWord }
        if (held == null) {
            // The sync that runs first found the deletion in the vault's log: the engine's finding says so, and is shown here.
            if (madeShown(s, id)) {
                if (send) return say(fill(DELETION_MADE, id))
                throw CliError(fill(DELETION_MADE_NOT_KEPT, id), 1, KEY_DELETION_WAITS)
            }
            vaultOf(s, v)
            throw CliError(fill(NO_DELETION_WAITS, id), 1, KEY_DELETION_WAITS)
        }
        if (!send) return when (val w = s.logs.withdraw(id, held.hash)) {
            is HeldWithdrawal.Withdrawn -> say(fill(if (w.known == HeldKnown.NOT_STORED) DELETION_KEPT_NOT_MADE else DELETION_KEPT_MAYBE_MADE, id))
            // "Try again" only where trying again can help: the deletion's first request is still out.
            is HeldWithdrawal.Kept -> throw CliError(when (w.reason) {
                HeldWithdrawal.FIRST_REQUEST_OUT -> fill(DELETION_NOT_WITHDRAWN, id, w.reason)
                HeldWithdrawal.STORED_BY_SERVERS_WORD -> fill(DELETION_STORED_NOT_WITHDRAWN, id)
                HeldWithdrawal.RECORD_UNREADABLE -> fill(DELETION_UNREADABLE_NOT_WITHDRAWN, id)
                else -> fill(DELETION_NEVER_WITHDRAWN, id, w.reason)
            }, 1, KEY_DELETION_WAITS)
        }
        // What this command says of the deletion is said once: the engine's finding about it is marked shown, not said again.
        try { sendHeldDeletion(s, id, held.vaultId) } finally { deletionFindings(s, id).forEach { s.logs.findingShown(it.id) } }
    }

    /** The deletion findings the engine keeps for vault [id]. */
    private fun deletionFindings(s: AccountSession, id: String) = s.logs.heldFindings().filter { it.vaultId == id && it.change == HeldKind.DELETE }

    /** Whether the engine found the deletion of vault [id] made; such findings are marked shown (the caller says it). */
    private fun madeShown(s: AccountSession, id: String): Boolean {
        val made = deletionFindings(s, id).filter { it.what == FoundKind.MADE || it.what == FoundKind.MADE_AFTER_ALL }
        made.forEach { s.logs.findingShown(it.id) }
        return made.isNotEmpty()
    }

    private suspend fun sendHeldDeletion(s: AccountSession, id: String, vaultId: String) {
        when (val look = s.logs.lookHeld(vaultId)) {
            is HeldLook.Made -> say(fill(DELETION_MADE, id))
            is HeldLook.StillHeld -> if (!look.readReached) throw CliError(fill(DELETION_NOT_READ, id), 1, KEY_DELETION_WAITS)
                else when (val r = s.logs.repostHeld(id, look.change.hash)) {
                    is HeldRepost.Stored -> say(fill(DELETION_MADE, id))
                    is HeldRepost.Refused -> throw CliError(refusal(fill(DELETION_REFUSED, id), r.code))
                    HeldRepost.Dropped -> throw CliError(fill(DELETION_PLACE_TAKEN, id))
                    else -> throw CliError(fill(DELETION_WAITS, id), 1, KEY_DELETION_WAITS)
                }
            is HeldLook.PlaceTaken -> throw CliError(fill(DELETION_PLACE_TAKEN, id))
            else -> throw CliError(fill(DELETION_NOT_READ, id), 1, KEY_DELETION_WAITS)
        }
    }

    private suspend fun vault(sub: String) = signedIn { s ->
        s.sync()
        when (sub) {
            "list" -> if (asJson) emit(JsonArray(s.vaultIds().map { id ->
                val st = s.logs.status(id)
                val verified = (st as? VaultLogStatus.Verified)?.state
                buildJsonObject {
                    put("vaultId", JsonPrimitive(id)); put("name", JsonPrimitive(s.vaultName(id)))
                    put("kind", JsonPrimitive(if (id == s.personalVaultId) "personal" else "shared"))
                    put("log", JsonPrimitive(if (id == s.personalVaultId) null else st::class.simpleName?.lowercase()))
                    put("owner", JsonPrimitive(verified?.owner)); put("members", JsonPrimitive(verified?.members?.size)); put("headSeq", JsonPrimitive(verified?.headSeq))
                }
            })) else for (id in s.vaultIds()) {
                val st = s.logs.status(id)
                val what = when {
                    id == s.personalVaultId -> "personal"
                    st is VaultLogStatus.Verified -> "shared, owner ${st.state.owner}, ${st.state.members.size} members, seq ${st.state.headSeq}"
                    else -> st::class.simpleName?.lowercase() ?: "?"
                }
                say("${arg(id)}  ${s.vaultName(id) ?: "(not open here)"}  $what")
            }
            "create" -> append(s, null, LogAction.Create(a.pos(2, "the name")))
            "add" -> append(s, vaultArg(s, 2), LogAction.Add(contactArg(s, 3), a.opt("role") ?: "writer", a.has("uncompared")))
            "role" -> append(s, vaultArg(s, 2), LogAction.Role(contactArg(s, 3), a.pos(4, "the role")))
            "remove" -> append(s, vaultArg(s, 2), LogAction.Remove(contactArg(s, 3)))
            "leave" -> append(s, vaultArg(s, 2), LogAction.Leave)
            "delete" -> append(s, vaultArg(s, 2), LogAction.Delete)
            "send-deletion" -> deletionWord(s, a.pos(2, "the vault"), send = true)
            "keep" -> deletionWord(s, a.pos(2, "the vault"), send = false)
            "restore" -> append(s, a.pos(2, "the vault id"), LogAction.Restore)
            "offer" -> append(s, vaultArg(s, 2), LogAction.Offer(contactArg(s, 3), (a.opt("days")?.toLongOrNull() ?: 7) * 86_400_000L))
            "cancel" -> append(s, vaultArg(s, 2), LogAction.Cancel)
            "accept" -> append(s, vaultArg(s, 2), LogAction.Accept)
            "incoming" -> {
                val id = a.pos(2, "the vault id")
                when (val ad = s.logs.adoption(id)) {
                    is Adoption.AskAccept -> {
                        say("“${ad.vaultName}” from ${ad.ownerLabel.ifEmpty { ad.owner }}")
                        if (!a.has("accept") && !a.has("decline")) throw CliError("pass --accept or --decline", 2)
                        say("${s.logs.answerIncoming(ad, accept = a.has("accept"))}")
                    }
                    is Adoption.ConnectFirst -> throw CliError("connect with the person who added you first")
                    else -> say("$ad")
                }
            }
            else -> throw CliError("vault list|create|add|role|remove|leave|delete|restore|offer|cancel|accept|incoming", 2)
        }
    }

    private val itemJson = Json { prettyPrint = false }

    private suspend fun item(sub: String) = signedIn { s ->
        s.sync()
        val v = vaultArg(s, 2)
        when (sub) {
            "list" -> {
                val items = s.items(v)
                if (a.has("json")) emit(JsonArray(items.map { buildJsonObject { put("itemId", JsonPrimitive(it.itemId)); put("doc", it.doc) } }))
                else items.forEach { say("${arg(it.itemId)}  ${(it.doc["name"] as? JsonPrimitive)?.content ?: ""}") }
            }
            "get" -> emit(s.items(v).firstOrNull { it.itemId == a.pos(3, "the item id") }?.doc ?: throw CliError("no such item"))
            "put" -> {
                val text = a.opt("file")?.let { File(it).readText() } ?: generateSequence(c.stdin).joinToString("\n")
                val doc = runCatching { itemJson.parseToJsonElement(text).jsonObject }.getOrElse { throw CliError("the item is not a JSON object") }
                if ((doc["type"] as? JsonPrimitive)?.content !in setOf("login", "note", "card")) throw CliError("the item needs a type: login, note or card")
                val (saved, err) = s.putItem(v, JsonObject(doc - "logHead"), a.opt("id"))
                if (err != null) throw CliError(refusal("not stored", err))
                say("stored ${saved!!.itemId} (${saved.outcome.name.lowercase()})")
            }
            "delete" -> {
                val id = a.pos(3, "the item id")
                if (s.items(v).none { it.itemId == id }) throw CliError("no such item")
                val (done, err) = s.deleteItem(id)
                if (err != null) throw CliError(refusal("refused", err))
                say(done!!.name.lowercase())
            }
            else -> throw CliError("item list|get|put|delete", 2)
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Device links (design §8): `link-device show` on the signed-in device, `link-device <url>` on the new one
    // ---------------------------------------------------------------------------------------------

    private suspend fun linkDevice() {
        if (a.positional.getOrNull(1) == "show") return signedIn { showDeviceLink() }
        val arg = linkArg(1, "show, or the link from your other device")
        c.originFromLink(DeviceLinkUrl.parse(arg)?.let { p -> p.origin.also { p.wipe() } })
        var n = host.deviceLinks.start(arg, GateEntry.CLI_LINK_DEVICE)
        if (n is NewStep.TrustGate) { passGate(n.gate); n = host.deviceLinks.afterTrustGate(n, confirmed = true) }
        val deadline = System.currentTimeMillis() + 10 * 60_000L
        // The costs this run had refused before the latest pickup step: what that step refused is what follows.
        var refusedBefore = host.servedCostsRefused.size
        // What came back since the latest pickup step: the shared step's one word for several answers is told apart here.
        var answersBefore = host.answersMark()
        // Whether a two-step code went with the pickup: a refusal after it is said as what it most likely is.
        var codeSent = false
        // The link's account and server name, from the step that asked for the password: asked again after a refused code.
        var email = ""
        var instanceName = ""
        // The code the server refused last, and how many codes it refused: the same code is never sent again (a code given
        // in a file or the environment would only be refused again), and after [CODES_AT_LINK] the run stops.
        var refusedCode: String? = null
        var codesRefused = 0
        // How many proofs of a password this device knows the server refused in this link (the engine's `proofRefused`).
        var proofsRefused = 0
        val waits = LinkWaits(host.answersMark(), shown = false)
        while (System.currentTimeMillis() < deadline) {
            when (n) {
                is NewStep.Claimed -> { delay(2000); n = host.deviceLinks.advance(n).also(waits::tell) }
                is NewStep.ShowCode -> {
                    say("Type this code on your other device: ${n.code}"); flush()
                    var next = host.deviceLinks.advance(n).also(waits::tell)
                    while (next is NewStep.ShowCode && System.currentTimeMillis() < deadline) { delay(2000); next = host.deviceLinks.advance(next).also(waits::tell) }
                    n = next
                }
                is NewStep.PasswordNeeded -> {
                    email = n.email
                    instanceName = n.instanceName
                    refusedBefore = host.servedCostsRefused.size
                    answersBefore = host.answersMark()
                    n = host.deviceLinks.pickup(n, c.secrets.read("password", "ANDVARI_PASSWORD", "Master password for $email on $instanceName ($origin): "))
                    if (n is NewStep.Linked) c.remember(email)
                }
                is NewStep.TotpNeeded -> {
                    answersBefore = host.answersMark()
                    codeSent = true
                    val code = String(c.secrets.read("totp", "ANDVARI_TOTP", "Two-step code: "))
                    refusedCode = code
                    n = host.deviceLinks.pickup(n, CharArray(0), code)
                }
                // The server refused a password that opens this device's copy of the account (a former one, most often): never
                // a wrong password. The engine keeps the link within its time, so the current password is asked for; after
                // [CODES_AT_LINK] such refusals the run stops with the same words, as after the link's time.
                // (Not reached from this tool today: its home keeps no copy of the account to compare with.)
                is NewStep.WrongPassword -> if (n.proofRefused) {
                    if (++proofsRefused >= CODES_AT_LINK) throw linkProofRefusedError(origin)
                    note(fill(LINK_PROOF_REFUSED_ASK_AGAIN, origin)); flush()
                    refusedBefore = host.servedCostsRefused.size
                    answersBefore = host.answersMark()
                    n = host.deviceLinks.pickup(n, c.secrets.read("password", "ANDVARI_PASSWORD", "Master password for $email on $instanceName ($origin): "))
                    if (n is NewStep.Linked) c.remember(email)
                // No code was asked for: the password was wrong.
                } else if (!n.afterCode && !codeSent) throw CliError("wrong master password") else {
                    // After the code step the server's refusal is the one it gives a wrong password too (spec 03 §2: one
                    // `invalid_credentials`); the tool claims no more than that the code was most likely wrong. The server
                    // keeps the link approved within its time, so the link stays and the password and the code are asked
                    // for again; a code that is the one just refused is not sent again.
                    if (!n.afterCode || ++codesRefused >= CODES_AT_LINK) throw CliError(fill(WRONG_CODE_AT_LINK, origin))
                    note(fill(WRONG_CODE_LINK_STAYS, origin)); flush()
                    val password = c.secrets.read("password", "ANDVARI_PASSWORD", "Master password for $email on $instanceName ($origin): ")
                    val code = try {
                        String(c.secrets.read("totp", "ANDVARI_TOTP", "Two-step code: "))
                    } catch (e: Throwable) {
                        password.fill('\u0000')
                        throw e
                    }
                    if (code == refusedCode) {
                        password.fill('\u0000')
                        throw CliError(fill(WRONG_CODE_AT_LINK, origin))
                    }
                    refusedCode = code
                    refusedBefore = host.servedCostsRefused.size
                    answersBefore = host.answersMark()
                    n = host.deviceLinks.pickup(n, password, code)
                    if (n is NewStep.Linked) c.remember(email)
                }
                is NewStep.Linked -> {
                    say("linked: this device is ${n.deviceId} of account ${n.userId}")
                    return
                }
                is NewStep.Stopped -> throw when (n.reason) {
                    // The shared step's word for a first exchange it could not use. It says so for a cost outside the limits and
                    // for an answer that does not decode alike, so the tool goes by its own record: a cost this run refused in
                    // that exchange is the server's cost (exit 3); with none, what came back says the rest.
                    DeviceLinkStop.KDF_REFUSED ->
                        host.servedCostsRefused.drop(refusedBefore).firstOrNull()?.let { (o, p) -> servedCostError(o, p) }
                            ?: pickupStopped(host.answersSince(answersBefore))
                    // The shared step's word for no answer and for every refusal it has no stop of its own for: the pickup
                    // refused by the address's sign-in back-off is that back-off, said as a sign-in's is; the rest is told
                    // from what came back.
                    DeviceLinkStop.UNREACHABLE -> answersBefore.let { mark ->
                        if (pickupBackOff(host.answersSince(mark))) tooManySignIns()
                        // A check of the link refused as too many from this address: the server answered, and said so.
                        else linkTooMany(host.answersSince(mark))?.let { linkTooManyError(origin, it) } ?: pickupStopped(host.answersSince(mark))
                    }
                    // A step that cannot wait (the claim, the pickup's first exchange, the pickup) refused as too many: the
                    // pickup refused by the address's sign-in back-off is that back-off, said as a sign-in's is ("at least
                    // a minute", whatever wait it named); the others with the wait the server named.
                    DeviceLinkStop.TOO_MANY ->
                        if (pickupBackOff(host.answersSince(answersBefore))) tooManySignIns() else linkTooManyError(origin, n.retryAfterSeconds)
                    // A step that can wait was refused for longer than the link has left: the link ran out waiting.
                    DeviceLinkStop.EXPIRED -> waits.lastTooMany()?.let { linkTooManyError(origin, it) } ?: CliError("the device link stopped: ${n.reason.code}")
                    // The shared step's stop after the code step past the link's own time: the server's one answer for a
                    // wrong code and a wrong password, given after it had asked for a code with this password.
                    DeviceLinkStop.REFUSED_AFTER_CODE -> CliError(fill(WRONG_CODE_AT_LINK, origin))
                    // The server refused a password that opens this device's copy of the account: never a wrong password.
                    DeviceLinkStop.PROOF_REFUSED -> linkProofRefusedError(origin)
                    // What this home keeps (the tool's sink): stopped before the pickup, so nothing was linked; or after it (what
                    // this home keeps changed while the pickup was out), when the server had already added this device.
                    // The tool's own reasons come through as the keeper's, unchanged ([NewStep.Stopped.keeperReason]).
                    DeviceLinkStop.ANOTHER_SESSION_KEPT, DeviceLinkStop.OPERATOR_ACCOUNT_HELD, DeviceLinkStop.KEPT_COPY_DAMAGED, DeviceLinkStop.KEEPER_REFUSED ->
                        host.refusedAfterCommit?.takeIf { it.first == origin }?.let { (_, device) ->
                            val kept = host.keptAt(origin)?.firstOrNull { it.emailNorm != email }?.emailNorm ?: "another account"
                            CliError(fill(LINK_ADDED_NOT_KEPT, origin, email ?: "the account", device, kept), 1, KEY_LINK_ADDED_NOT_KEPT)
                        } ?: keeperStop(n.keeperReason ?: n.reason.code, origin, null, ACT_LINK)
                        ?: CliError("the device link stopped: ${n.keeperReason ?: n.reason.code}")
                    else -> CliError("the device link stopped: ${n.reason.code}${n.pinVerdict?.let { " ($it)" } ?: ""}")
                }
                else -> throw CliError("the device link cannot continue here: $n")
            }
        }
        throw CliError("the device link timed out")
    }

    /**
     * The answer that stopped a device link when it is a refusal as too many (`429 rate_limited`) of one of the link's
     * own requests (a check, the reveal, the view, the nonce, the approval), or null: the shared step ends the link on it
     * and calls it unreachable, but the server answered, so the tool says what it answered. The pickup's is the sign-in
     * back-off's ([pickupBackOff]).
     */
    private fun linkTooMany(since: List<Triple<String, WireRoute, Answered>>): Answered.Refusal? {
        val (_, route, a) = since.lastOrNull() ?: return null
        return (a as? Answered.Refusal)?.takeIf { it.code == RATE_LIMITED && route != WireRoute.DEVICE_LINK_PICKUP && route.name.startsWith("DEVICE_LINK") }
    }

    /**
     * A device link's waits, from [start] on: the shared step waits out a refusal as too many at a step that can wait (a
     * check, the reveal, the view) within the link's time, and hands back the same step. [tell] says each such wait once,
     * with the time the server named ([LINK_WAITS]); [lastTooMany] is the refusal a link that ran out waiting ended on.
     */
    private inner class LinkWaits(private val start: Int, private val shown: Boolean) {
        private var mark = start

        fun tell(step: Any) {
            val since = host.answersSince(mark)
            mark += since.size
            if (step is NewStep.Stopped || step is ExistingStep.Stopped) return
            since.lastOrNull { (_, route, a) -> route.name.startsWith("DEVICE_LINK") && a is Answered.Refusal && a.code == RATE_LIMITED }
                ?.let { note(linkWaitsLine(origin, it.third as Answered.Refusal)); flush() }
        }

        fun lastTooMany(): Answered.Refusal? =
            host.answersSince(start).lastOrNull { it.second != WireRoute.DEVICE_LINK_CANCEL }
                ?.takeIf { (_, route, a) -> route.name.startsWith("DEVICE_LINK") && a is Answered.Refusal && a.code == RATE_LIMITED }
                ?.third as? Answered.Refusal
    }

    /** Whether [since] holds the pickup refused by the sign-in back-off (`429 rate_limited`, spec 03 §16.6, §8). */
    private fun pickupBackOff(since: List<Triple<String, WireRoute, Answered>>): Boolean = since.any { (_, route, a) ->
        route == WireRoute.DEVICE_LINK_PICKUP && a is Answered.Refusal && a.code == RATE_LIMITED
    }

    /**
     * The pickup stopped with no usable answer, told from what came back since its step began ([since]): whether it got as
     * far as the pickup itself (before it, only the first exchange went: nothing was derived from the password, nothing sent
     * with it), and whether the server was reached at the step that stopped it ("cannot be reached" only when it was not).
     */
    private fun pickupStopped(since: List<Triple<String, WireRoute, Answered>>): CliError {
        val pickedUp = since.any { it.second == WireRoute.DEVICE_LINK_PICKUP }
        val last = since.lastOrNull { it.second == WireRoute.DEVICE_LINK_PICKUP || it.second == WireRoute.PRELOGIN }?.third
        val reached = last != null && (last !is Answered.NotUsable || last.reached)
        return when {
            !pickedUp && reached -> CliError(fill(FIRST_STEP_UNUSABLE, origin))
            !pickedUp -> CliError(fill(FIRST_STEP_NOT_REACHED, origin))
            reached -> CliError(fill(LATER_STEP_UNUSABLE, origin))
            else -> CliError(fill(LATER_STEP_NOT_REACHED, origin))
        }
    }

    private suspend fun showDeviceLink() {
        val mark = host.answersMark()
        var e = host.deviceLinks.create()
        (e as? ExistingStep.Stopped)?.takeIf { it.reason == DeviceLinkStop.TOO_MANY }?.let { throw linkTooManyError(origin, it.retryAfterSeconds, shown = true) }
        val shown = e as? ExistingStep.Shown ?: throw CliError("no device link: ${(e as? ExistingStep.Stopped)?.reason?.code ?: e}")
        val waits = LinkWaits(host.answersMark(), shown = true)
        say(shown.url); flush()
        note("On the new device: andvari-cli link-device '<the link above>' (or Sign in → Link from your other device)")
        val deadline = System.currentTimeMillis() + 10 * 60_000L
        var toldOf: String? = null
        while (System.currentTimeMillis() < deadline) {
            e = when (e) {
                is ExistingStep.Shown -> { delay(2000); host.deviceLinks.advance(e).also(waits::tell) }
                // The claim is fixed and this device's nonce sent; the new device reveals its own at its next check. Until
                // then each step answers the same, so it is asked at the same pace as the view above: asked at once, again
                // and again, it spent this device's views of a minute in a second or two, and the server refused the rest.
                is ExistingStep.ClaimFixed -> {
                    if (e.name != toldOf) note("A device “${e.name}” (${e.platform}, as it calls itself) wants to join.")
                    toldOf = e.name
                    delay(2000)
                    host.deviceLinks.advance(e).also(waits::tell)
                }
                is ExistingStep.TypeDigits -> {
                    val digits = a.opt("code") ?: String(c.secrets.read("code", "ANDVARI_DEVICE_CODE", "The code the new device shows: "))
                    host.deviceLinks.typeDigits(e, digits.filter { it.isDigit() })
                }
                // The approval's view waits out a refusal as too many as the checks above do; the step stays until then.
                is ExistingStep.Approvable -> { host.deviceLinks.approve(e).also(waits::tell).also { if (it === e) delay(2000) } }
                is ExistingStep.Approved -> { say("approved: “${e.name}” can now finish with the master password"); return }
                is ExistingStep.Stopped -> throw when (e.reason) {
                    // A step that cannot wait (the nonce, the approval) refused as too many, with the wait the server named.
                    DeviceLinkStop.TOO_MANY -> linkTooManyError(origin, e.retryAfterSeconds, shown = true)
                    // A wait for longer than the link has left: the link ran out waiting.
                    DeviceLinkStop.EXPIRED -> waits.lastTooMany()?.let { linkTooManyError(origin, it.retryAfterSeconds, shown = true) }
                    DeviceLinkStop.UNREACHABLE -> linkTooMany(host.answersSince(mark))?.let { linkTooManyError(origin, it.retryAfterSeconds, shown = true) }
                    else -> null
                } ?: CliError("the device link stopped: ${e.reason.code}")
            }
        }
        throw CliError("the device link timed out")
    }

    // ---------------------------------------------------------------------------------------------
    // Kit recovery (design §10; §12.1 "Forgot your master password? → Scan your recovery kit")
    // ---------------------------------------------------------------------------------------------

    /**
     * `recover kit --kit-file F`. The file is the one `--kit-out` wrote, or any file with the kit's `andvari-kit:2:` line:
     * that counts as a scan and pins the server from the kit's card 0. A file with only the typed groups needs `--email`
     * and `--origin` and goes through the Trust Gate. The kit is a secret and never an argument (`--kit-file -` reads it
     * from standard input). The new master password comes as every password does, and the NEW kit must be capturable
     * (`--kit-out FILE` without a terminal), which is checked before anything is sent: the recovery replaces the kit.
     */
    private suspend fun recoverWithKit() {
        kitCapturable()
        val path = a.opt("kit-file") ?: throw CliError("--kit-file FILE (the kit file, or - for standard input): a kit is never an argument", 2)
        val lines = if (path == "-") generateSequence(c.stdin).toList()
            else File(path).takeIf { it.isFile }?.readLines() ?: throw CliError("--kit-file: $path is not a readable file", 2)
        val qr = lines.map { it.trim() }.firstOrNull { it.startsWith("andvari-kit:") }
        val scanned = qr?.let { RecoveryKit.parseQr(it) ?: throw CliError("the kit's andvari-kit: line does not read: nothing was sent") }
        // Another account kept here at the kit's server stops the recovery before anything is sent (its kit stays good).
        try {
            if (scanned != null) anotherAccountKept(scanned.origin, scanned.emailNorm)
            else a.opt("email")?.let(TrustGrammar::emailNorm)?.let { anotherAccountKept(origin, it) }
        } catch (e: CliError) {
            scanned?.wipe()
            throw e
        }
        scanned?.let { c.originFromLink(it.origin) }
        val k = host.kitRecovery
        val step = if (scanned != null) {
            val kit = scanned
            a.opt("email")?.let { e ->
                if (TrustGrammar.emailNorm(e) != kit.emailNorm) { kit.wipe(); throw CliError("the kit is for ${kit.emailNorm}, not --email $e: nothing was sent", 2) }
            }
            try { k.start(kit, GateEntry.KIT_RECOVERY_SCREEN) } finally { kit.wipe() }
        } else {
            val email = a.opt("email") ?: throw CliError("a kit typed as its groups needs --email and --origin", 2)
            val groups = lines.map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("andvari recovery kit") }
                .joinToString(" ") { it.replace(Regex("^[0-9]+\\.\\s*"), "") }
            k.startTyped(email, origin, groups, GateEntry.KIT_RECOVERY_SCREEN)
        }
        // Whatever stops this run before the recovery is committed, the flow is cancelled: the pin a scanned kit made goes
        // with its secrets (`WireKitRecovery.cancel`), so a stopped recovery leaves this device as it found it.
        var live: KitRecoveryStep? = step
        try {
            recoverFrom(k, step) { live = it }
            live = null
        } finally {
            live?.let { k.cancel(it) }
        }
    }

    /** [recoverWithKit] from its first step; [holding] is told each step the flow holds secrets (and maybe a pin) for. */
    private suspend fun recoverFrom(
        k: io.silencelen.andvari.core.client.recovery.WireKitRecovery, first: KitRecoveryStep, holding: (KitRecoveryStep?) -> Unit,
    ) {
        var step = first
        if (step is KitRecoveryStep.OriginMismatch) {
            val m = step.mismatch
            if (!a.has("yes")) throw CliError("the server at ${m.dialedOrigin} presents the card of ${m.cardOrigin}: nothing was sent. Add --yes to recover at ${m.cardOrigin}", 2)
            step = k.retargetOrigin(step)
            holding(step)
        }
        val target = when (step) {
            is KitRecoveryStep.ConfirmTarget -> step
            is KitRecoveryStep.PinChanged -> throw CliError("this server moved or changed its kind since this device pinned it: run `andvari-cli card follow` first. Nothing was sent")
            is KitRecoveryStep.Stopped -> throw keeperStop(step.reason, origin, null, ACT_RECOVERY)
                ?: CliError(refusal("kit recovery stopped, nothing changed", step.reason))
            KitRecoveryStep.Rejected -> throw CliError(KIT_REJECTED)
            else -> throw CliError("kit recovery cannot continue here: $step")
        }
        val asked = TrustGrammar.emailNorm(target.email)
        // The record of the account's key is looked up at the kit's server, which may not be the command's.
        host.flowOrigin = target.origin
        // A kit whose server answered from another address: the same check at the address the recovery goes on at.
        TrustGrammar.emailNorm(target.email)?.let { anotherAccountKept(target.origin, it) }
        note("Recover ${target.email} on “${target.instanceName}” (${target.origin})")
        if (target.kitAnchorMismatch) note("WARNING: this server's identity changed since your kit was made. Continue only if you expected this.")
        target.gate?.let { passGate(it) }
        val chosen = when (val v = k.verify(target)) {
            is KitRecoveryStep.ChoosePassword -> v.also(holding)
            KitRecoveryStep.Rejected -> throw CliError(KIT_REJECTED)
            is KitRecoveryStep.Stopped -> throw keeperStop(v.reason, target.origin, asked, ACT_RECOVERY)
                ?: CliError(refusal("kit recovery stopped, nothing changed", v.reason))
            else -> throw CliError("kit recovery cannot continue here: $v")
        }
        when (val r = k.commit(chosen, newPassword(target.email))) {
            is KitRecoveryStep.Recovered -> {
                // Committed: the pin stays with the recovered account, whatever happens next.
                holding(null)
                r.notKept?.let { throw recoveryNotKept(r.newKit, target.origin, target.email, it, assisted = false) }
                c.state.set(Ctx.K_ORIGIN, target.origin)
                c.state.set("${Ctx.K_EMAIL}|${target.origin}", TrustGrammar.emailNorm(target.email))
                captureKit(host.onboarding(target.origin), r.newKit)
                say("recovered: ${target.email} (${r.userId}) on ${target.origin}. The old kit no longer works; two-step sign-in and " +
                    "\"new devices must be linked\" are off")
            }
            KitRecoveryStep.Rejected -> throw CliError(KIT_REJECTED)
            is KitRecoveryStep.Stopped -> throw keeperStop(r.reason, target.origin, asked, ACT_RECOVERY) ?: CliError(refusal("kit recovery stopped", r.reason))
            else -> throw CliError("kit recovery cannot continue here: $r")
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Operator-assisted recovery (design §9.3), the person's side and the signed-in devices' side; the recovery posture (§7.7)
    // ---------------------------------------------------------------------------------------------

    /**
     * `recover assist`, on a device with no account: the request kept in this device's secure store survives between runs
     * (`rSec` and `pollSecret`, design §9.3 N11), so each run takes the next step.
     * - With `--email E` and no request kept: "Ask the operator for help": the Trust Gate when needed, the request, the
     *   request code to read to the operator, and the 6-digit code the email holds (`--code-file`, `$ANDVARI_RECOVERY_CODE`
     *   or standard input) in the same run.
     * - Later, with no `--email`: where the request stands; once the operator answered, the delivered account's ID, which
     *   the person confirms by giving it as `--account-id` (from the kit, the better source: the server sent the emails);
     *   then the new password and the new kit (`--kit-out`, checked before anything is sent). An ID that differs keeps the
     *   request and says so ([KEY_ACCOUNT_ID_DIFFERS]): a typing slip is not a decision, and stopping is `--cancel`.
     * - `--cancel` drops the kept request; nothing is sent.
     */
    private suspend fun recoverWithOperator() {
        val r = host.assisted
        val email = a.opt("email")
        val kept = r.keptOrigins().contains(origin)
        if (a.has("cancel")) {
            if (!kept) throw CliError("this device keeps no assisted-recovery request for $origin")
            // Local only: the request's rSec and pollSecret go, and nothing is polled or sent.
            KeptAssistRequests.forget(host.secure, origin, null)
            say("cancelled: this device dropped its request to $origin; nothing was sent")
            return
        }
        if (!kept) {
            val e = email ?: throw CliError("no request is kept for $origin on this device: start one with --email", 2)
            TrustGrammar.emailNorm(e)?.let { anotherAccountKept(origin, it) }
            // A value given in a file or the environment is checked before anything is dialed; one typed at a terminal
            // is asked for after the notes below. Either way it goes with the request, and nothing here can tell whether
            // it was right.
            var mailbox = c.secrets.given(MailboxValue.NAME, MailboxValue.ENV)?.let(::mailboxValue)
            val target = when (val st = r.start(e, origin)) {
                is AssistedStep.ConfirmTarget -> st
                is AssistedStep.Stopped -> throw CliError(refusal("operator recovery cannot be asked for here", st.reason))
                else -> throw CliError("operator recovery cannot start here: $st")
            }
            note("Ask the operator of “${target.instanceName}” (${target.origin}) to reset ${target.email}.")
            note("Anyone who gets into your email can ask too. The operator waits 7 days and checks with you, and your other devices can cancel.")
            if (mailbox == null) Term.console()?.let { k ->
                mailbox = MailboxValue.read(null, { q -> Term.readLine(k, q) }, { p -> Term.readPassword(k, p) })?.let(::mailboxValue)
            }
            target.gate?.let { passGate(it) }
            // The value goes in the shared step's own field (spec 03 §18.1, `mailboxValue`), which the step puts in this
            // one request and nowhere else. It was checked above with the step's own rule, so the step's refusal of a value
            // that is not one cannot come here; were it to, it is said in the same words.
            val requested = when (val st = r.request(target, mailbox)) {
                is AssistedStep.Requested -> st
                is AssistedStep.Stopped -> throw if (st.reason == WireAssistedRecovery.BAD_MAILBOX_VALUE) CliError(MailboxValue.NOT_A_VALUE, 2)
                    else CliError(refusal("the request was refused", st.reason))
                else -> throw CliError("the request cannot continue here: $st")
            }
            say("request code: ${requested.requestCode}   Read this to the operator when they contact you.")
            if (mailbox != null) note(MailboxValue.SENT)
            flush()
            val code = String(c.secrets.read("code", "ANDVARI_RECOVERY_CODE", "The 6-digit code from the email: ")).trim()
            return when (val st = r.verifyCode(requested, code)) {
                is AssistedStep.Waiting -> say(waiting(st))
                is AssistedStep.Stopped -> throw CliError(
                    if (st.reason == "bad_code") "that code is wrong or expired; the request is kept, but its code can only be typed in the run that made it: " +
                        "run `andvari-cli recover assist --cancel` and ask again" else refusal("the code was refused", st.reason),
                )
                else -> throw CliError("the request cannot continue here: $st")
            }
        }
        if (email != null && TrustGrammar.emailNorm(email) == null) throw CliError("not an email address: $email", 2)
        when (val st = r.resume(origin) ?: throw CliError("this device keeps no assisted-recovery request for $origin")) {
            is AssistedStep.Waiting, is AssistedStep.Requested -> say(if (st is AssistedStep.Waiting) waiting(st) else "the request is not verified yet")
            is AssistedStep.CheckAccount -> {
                say("The operator answered. The account delivered is account ID ${st.accountId} (${st.email} on “${st.instanceName}”).")
                val expected = a.opt("account-id")?.lowercase()?.filter { it.isLetterOrDigit() }
                    ?: throw CliError("check this against the account ID on your recovery kit (or in an andvari email that reached you before you " +
                        "asked for help; this server sent the emails, so the kit is the better source). If it is the same, run again " +
                        "with --account-id <that ID>; if it is different, stop and run `andvari-cli recover assist --cancel`", 2)
                // A mistyped ID is not a decision: the request is kept, and stopping is the
                // person's own step (`--cancel`), never this tool's guess.
                if (expected != st.accountId.lowercase()) throw CliError(
                    "the account ID you gave (${arg(a.opt("account-id").orEmpty())}) differs from the account delivered (${st.accountId}). " +
                        "Nothing was changed, and this device keeps the request. If you mistyped, run again with --account-id <the ID on your kit>; " +
                        "if the IDs truly differ, stop: run `andvari-cli recover assist --cancel`",
                    1, KEY_ACCOUNT_ID_DIFFERS,
                )
                // Nothing is committed for an account while this device keeps another at the same server: the shared flow
                // asked the tool's sink at the pick-up, before this account was shown, and asks again before the commit.
                kitCapturable()
                val choose = r.confirmAccount(st, same = true) as? AssistedStep.ChoosePassword ?: throw CliError("the account could not be confirmed")
                when (val done = r.commit(choose, newPassword(st.email))) {
                    is AssistedStep.Recovered -> {
                        done.notKept?.let { throw recoveryNotKept(done.newKit, origin, st.email, it, assisted = true) }
                        c.state.set(Ctx.K_ORIGIN, origin)
                        c.state.set("${Ctx.K_EMAIL}|$origin", TrustGrammar.emailNorm(st.email))
                        captureKit(host.onboarding(origin), done.newKit)
                        say("recovered: ${st.email} (${done.userId}) on $origin with the operator's help. The old kit no longer works")
                    }
                    is AssistedStep.Stopped -> throw keeperStop(done.reason, origin, TrustGrammar.emailNorm(st.email), ACT_RECOVERY)
                        ?: CliError(refusal("the new password was not set", done.reason))
                    else -> throw CliError("the recovery cannot continue here: $done")
                }
            }
            // A stop at the pick-up for what this home keeps: the request is kept, and the sentence says why.
            is AssistedStep.Stopped -> throw keeperStop(st.reason, origin, email?.let(TrustGrammar::emailNorm), ACT_RECOVERY)
                ?: CliError(refusal("the request stopped", st.reason))
            else -> throw CliError("the request cannot continue here: $st")
        }
    }

    /**
     * A recovery of [emailNorm] at [at] stops here, before anything is sent, when this home keeps another account at that
     * server ([Host.keptRefusal], the same rule the shared flows ask through the tool's sink). The flows ask it only once
     * the server has answered (a kit's check, the operator's answer); the tool knows the address before it dials, so it
     * asks first where nothing has been sent yet: before a kit recovery starts, and before a request for help is made.
     */
    private fun anotherAccountKept(at: String, emailNorm: String) {
        host.keptRefusal(at, emailNorm, null)?.let { throw keeperStop(it, at, emailNorm, ACT_RECOVERY)!! }
    }

    /**
     * A stop the shared flows hand up for this home's keeping (the tool's sink, [Host.keptRefusal], or the flows' own
     * checks of what is kept) as its own sentence, with its exit code and key: [code] at [at], for [asked] (the address
     * asked for, where known), of [act]. Null for any other code.
     */
    private fun keeperStop(code: String, at: String, asked: String?, act: String): CliError? = when {
        // A device link hands the tool's own reasons up as `another_session_kept`: the refusal this run made says which.
        code == EARLIER_ACCOUNT_KNOWN || (code == Establishing.ANOTHER_SESSION_KEPT && host.earlierRefused?.first == at) ->
            CliError(fill(when (act) { ACT_REGISTRATION -> EARLIER_ACCOUNT_REFUSED_NEW; ACT_LINK -> EARLIER_ACCOUNT_REFUSED_LINK; else -> EARLIER_ACCOUNT_REFUSED }, at,
                host.earlierRefused?.second ?: asked ?: "this address", act), 1, EARLIER_ACCOUNT_KNOWN)
        code == IDENTITY_KEY_NOT_KNOWN -> CliError(fill(IDENTITY_KEY_REFUSED, at, act), 1, IDENTITY_KEY_NOT_KNOWN)
        // A recovery's check compared with this home's record of the key (the shared flow's own word for it).
        code == io.silencelen.andvari.core.client.recovery.WireKitRecovery.IDENTITY_MISMATCH && act == ACT_RECOVERY && host.recoveryKeyKnown -> {
            keyMark(at, asked)
            CliError(fill(IDENTITY_KEY_REFUSED, at, act), 1, IDENTITY_KEY_NOT_KNOWN)
        }
        // The session a recovery's commit opened, under another key than the record: after the server took the commit.
        code == io.silencelen.andvari.core.client.onboard.AccountOpen.SELF_IDENTITY_MISMATCH && act == ACT_RECOVERY -> {
            keyMark(at, asked)
            CliError.lines(listOf(fill(RECOVERY_KEY_REFUSED_AFTER_COMMIT, at, asked ?: "the account"), fill(RECOVERY_REFUSED_NEXT, at)), 1, KEY_RECOVERY_KEY_REFUSED)
        }
        else -> keptStop(code, at, asked, act)
    }

    /** The mark that the server showed the account known under [asked] at [at] under another key: nothing is offered for it. */
    private fun keyMark(at: String, asked: String?) {
        asked?.let { runCatching { c.state.set("${Host.CLI_EARLIER}$at|$it", "key ?") } }
    }

    private fun keptStop(code: String, at: String, asked: String?, act: String): CliError? = when (code) {
        Establishing.ANOTHER_SESSION_KEPT, Establishing.OPERATOR_ACCOUNT_HELD, KEPT_UNREADABLE -> {
            val kept = host.keptAt(at)
            // The account kept that is not the one asked for (or, for the same address, the one kept under it).
            val other = kept?.let { k -> k.firstOrNull { it.emailNorm != asked } ?: k.firstOrNull() }
            when {
                kept == null || code == KEPT_UNREADABLE -> CliError(fill(KEPT_ACCOUNTS_UNREADABLE, at, act), 1, KEY_ANOTHER_ACCOUNT_KEPT)
                code == Establishing.OPERATOR_ACCOUNT_HELD && other != null ->
                    CliError(fill(OPERATOR_ACCOUNT_HELD, at, other.emailNorm, act), 1, KEY_OPERATOR_ACCOUNT_HELD)
                else -> CliError(fill(ANOTHER_ACCOUNT_KEPT, at, other?.emailNorm ?: "an account", act), 1, KEY_ANOTHER_ACCOUNT_KEPT)
            }
        }
        Establishing.KEPT_COPY_DAMAGED -> CliError(fill(KEPT_COPY_DAMAGED, at, act), 1, KEY_KEPT_COPY_DAMAGED)
        WireAssistedRecovery.NOT_THE_KEPT_ACCOUNT -> CliError(fill(NOT_THE_KEPT_ACCOUNT, at, asked ?: "your request's address"), 1, KEY_NOT_THE_KEPT_ACCOUNT)
        else -> null
    }

    /** [typed] (wiped) as the server takes it ([MailboxValue.normal]); one that cannot be a value stops here, exit 2, nothing sent. */
    private fun mailboxValue(typed: CharArray): String = try {
        MailboxValue.normal(typed) ?: throw CliError(MailboxValue.NOT_A_VALUE, 2)
    } finally {
        typed.fill('\u0000')
    }

    private fun waiting(w: AssistedStep.Waiting): String =
        "request kept: ${w.state}${w.holdEndsAt?.let { ", the hold ends at $it" } ?: ""}. Request code: ${w.requestCode} (read it to the operator). " +
            "Run `andvari-cli recover assist` again later"

    /** `recovery-requests [veto ID]`: the account's live assisted-recovery requests, and the veto (design §9.3 step 2). */
    private suspend fun recoveryRequests() = signedIn { s ->
        val rr = host.recoveryRequests(s.held)
        when (a.positional.getOrNull(1)) {
            null, "list" -> when (val l = rr.live()) {
                is LiveRecoveryRequests.Listed -> if (asJson) emit(buildJsonObject {
                    put("offered", JsonPrimitive(true))
                    put("requests", wire(ListSerializer(io.silencelen.andvari.core.model.wire.RecoveryRequestSummary.serializer()), l.requests))
                }) else {
                    if (l.requests.isEmpty()) say("no live recovery requests")
                    l.requests.forEach { say("${arg(it.requestId)}  ${it.state}  verified ${it.verifiedAt}  hold ends ${it.holdEndsAt}  ${it.platform} (as it says)") }
                }
                LiveRecoveryRequests.NotOffered -> if (asJson) emit(buildJsonObject { put("offered", JsonPrimitive(false)); put("requests", JsonArray(emptyList())) })
                    else say("this server offers no operator recovery")
                LiveRecoveryRequests.Unreachable -> throw CliError("the server did not answer")
                is LiveRecoveryRequests.Refused -> throw CliError(refusal("refused", l.code))
            }
            "veto" -> when (val v = rr.veto(a.pos(2, "the request id"))) {
                VetoOutcome.Vetoed -> if (asJson) emit(buildJsonObject { put("requestId", JsonPrimitive(a.pos(2, "the request id"))); put("state", JsonPrimitive("vetoed")) })
                    else say("cancelled: the request is dead and the cancellation is emailed")
                VetoOutcome.NotOffered -> throw CliError("this server offers no operator recovery")
                VetoOutcome.Unknown -> throw CliError("no answer: the cancellation may have landed; list the requests to check")
                is VetoOutcome.Refused -> throw CliError(refusal("the cancellation was refused", v.code))
                else -> throw CliError("the cancellation did not go through: $v")
            }
            else -> throw CliError("recovery-requests [list] | recovery-requests veto ID", 2)
        }
    }

    /** `recovery [show] | recovery operator --i-understand | recovery private`: the account's recovery posture (design §7.7). */
    private suspend fun recoveryPosture() = signedIn { s ->
        val rs = host.recoverySettings(s.held)
        when (a.positional.getOrNull(1)) {
            null, "show" -> {
                val p = fetched(rs.posture())
                if (asJson) return@signedIn emit(buildJsonObject {
                    put("posture", JsonPrimitive(p.record?.posture ?: "private")); put("recorded", JsonPrimitive(p.record != null))
                    put("fp", JsonPrimitive(p.record?.fp)); put("operatorOffered", JsonPrimitive(p.operatorOffered))
                })
                say("posture:  ${p.record?.posture ?: "private (none recorded)"}${p.record?.fp?.let { ", key $it" } ?: ""}")
                say("operator recovery offered here: ${if (p.operatorOffered) "yes" else "no"}")
            }
            "operator" -> {
                val offer = rs.operatorOffer() ?: throw CliError("this server offers no operator recovery (a public server, or no recovery key)")
                if (offer.unsignedChange) note("WARNING: this server's recovery key changed without a signed rotation since you first trusted it.")
                if (!a.has("i-understand")) throw CliError(
                    "with operator recovery, the operator of “${offer.instanceName}” (${offer.origin}) can open your account with the offline recovery key, " +
                        "read your vaults and act as you. Add --i-understand to choose it", 2,
                )
                say("recovery: ${done(rs.setPosture(RecoveryChoiceKind.OPERATOR, offer, understood = true, password = c.password(s.held.emailNorm))).posture}")
            }
            "private" -> say("recovery: ${done(rs.setPosture(RecoveryChoiceKind.PRIVATE, null, understood = false, password = c.password(s.held.emailNorm))).posture}")
            else -> throw CliError("recovery [show] | recovery operator --i-understand | recovery private", 2)
        }
    }

    // ---------------------------------------------------------------------------------------------
    // The person's own account (design §8.6, §8.7, §10, §3.11 and the account-deletion design): the master password, a
    // new kit, the devices, "new devices must be linked", and deleting the account
    // ---------------------------------------------------------------------------------------------

    private suspend fun account(sub: String) {
        when (sub) {
            "password" -> signedIn { s -> changePassword(s) }
            "kit" -> {
                // The new kit must be capturable before anything is sent: the server replaces the old one when it answers.
                kitCapturable()
                signedIn { s -> newKit(s) }
            }
            "devices" -> signedIn { s ->
                val list = fetched(host.settings(s.held).list())
                if (asJson) emit(wire(ListSerializer(Device.serializer()), list))
                else for (d in list) say(deviceLine(d, s.held.session.deviceId))
            }
            "revoke-device" -> signedIn { s -> revokeDevice(s, a.pos(2, "the device id")) }
            "require-link" -> {
                val on = when (a.pos(2, "on or off")) { "on" -> true; "off" -> false; else -> throw CliError("account require-link on|off", 2) }
                signedIn { s ->
                    done(host.settings(s.held).setRequireLink(on, c.password(s.held.emailNorm)))
                    say(
                        if (on) "new devices must be linked: on. A password sign-in on a device this account has not used is refused; link it from one of yours"
                        else "new devices must be linked: off. A new device can sign in with the master password again",
                    )
                }
            }
            "delete" -> if (a.has("check")) deletionCheck() else deleteAccount()
            "quota" -> signedIn { s ->
                // The meters of a fresh sync (spec 03 §14.4): used and limit for each, or unknown when the server gave none.
                when (val r = s.sync()) {
                    is SyncOutcome.Synced -> {}
                    is SyncOutcome.Refused -> throw CliError(refusal("the sync was refused", r.code))
                    SyncOutcome.Unreachable -> throw CliError("the server did not answer; nothing was read")
                }
                val q = s.quota()
                if (asJson) emit(buildJsonObject { put("quota", Quotas.json(q)) })
                else Quotas.lines(q).forEach { say(it) }
            }
            "signing-key" -> signedIn { s ->
                // From this device's own opened account, never from the server: what a hand-over names (design §4.1, §9.1).
                val key = s.held.session.account.signingKeyB64()
                val short = host.trust.operatorShortFp(key)?.let(::grouped)
                if (asJson) return@signedIn emit(buildJsonObject {
                    put("userId", JsonPrimitive(s.userId)); put("signingKey", JsonPrimitive(key)); put("shortForm", JsonPrimitive(short))
                })
                say("user id:     ${s.userId}")
                say("signing key: $key")
                say("short form:  ${short ?: "(none)"}   (as the Trust Gate shows an operator key)")
                say("These come from this device's own copy of ${s.held.emailNorm}, not from the server. To be handed $origin, give the first two to its operator")
                say("(`andvari-cli operator hand-over --to-user <user id> --to-key <signing key>`), and read the short form to them to compare.")
            }
            else -> throw CliError("account password|kit|devices|revoke-device ID|require-link on|off|delete|quota|signing-key", 2)
        }
    }

    /**
     * `account password`: the current password and the new one each from a file (`--password-file`,
     * `--new-password-file`), the environment (`ANDVARI_PASSWORD`, `ANDVARI_NEW_PASSWORD`) or the terminal, never an
     * argument. The UVK is re-wrapped; the kit, the items and the other devices' sessions stay.
     */
    private suspend fun changePassword(s: AccountSession) {
        val email = s.held.emailNorm
        val current = c.secrets.read("password", "ANDVARI_PASSWORD", "Current master password for $email: ")
        val next = c.secrets.read("new-password", "ANDVARI_NEW_PASSWORD", "New master password for $email: ")
        if (a.opt("new-password-file") == null && c.env(a.opt("new-password-env") ?: "ANDVARI_NEW_PASSWORD").isNullOrEmpty() && Term.console() != null) {
            val again = c.secrets.read("new-password", "ANDVARI_NEW_PASSWORD", "Again: ")
            val same = next.contentEquals(again)
            again.fill('\u0000')
            if (!same) { next.fill('\u0000'); current.fill('\u0000'); throw CliError("the two new passwords differ; nothing was sent") }
        }
        val r = try { host.changePassword(s.held, current, next) } finally { current.fill('\u0000'); next.fill('\u0000') }
        when (r) {
            // The server signs every other session of the account out at a password change: the words say so.
            is Reauthed.Done -> say(fill(PASSWORD_CHANGED, email, origin))
            Reauthed.WrongPassword -> throw CliError("the current master password is wrong: nothing was sent, nothing changed")
            Reauthed.PasswordTooWeak -> throw CliError("the new master password is too weak: nothing was sent. Choose a longer one")
            Reauthed.NoSession -> throw CliError("this device may not send the password to $origin now (no session for $email here): nothing was sent")
            is Reauthed.Refused -> throw when (r.code) {
                RATE_LIMITED -> tooManyPasswords(r.retryAfterSeconds, "Nothing changed")
                // The engine's word: the proof was made here and sent, and the server refused it. Never a wrong password.
                Reauthed.PROOF_REFUSED -> proofRefusedError(origin)
                "credential_changed" -> CliError("the account's password changed elsewhere meanwhile: nothing changed here. Sign in again with the password now in force")
                else -> CliError(refusal("the password change was refused, nothing changed", r.code))
            }
            Reauthed.Unknown -> throw CliError(
                "cannot tell yet whether the password changed: the server's answer did not arrive. Run `andvari-cli whoami` " +
                    "and then a command such as `andvari-cli sync` with the new password; if that is refused, the old one is still in force",
                1, "outcome_unknown",
            )
        }
    }

    /** `account kit`: a new kit (`PUT /recovery/self-setup`), captured as at registration; the old kit stops working. */
    private suspend fun newKit(s: AccountSession) {
        val kit = when (val r = host.settings(s.held).rotateKit(c.password(s.held.emailNorm))) {
            is Reauthed.Done -> r.value
            Reauthed.Unknown -> throw CliError(
                "cannot tell yet whether the server replaced your kit: its answer did not arrive, so the old kit may no longer work. " +
                    "Run `andvari-cli account kit` again to make one you hold",
                1, "outcome_unknown",
            )
            else -> { done(r); return }
        }
        captureKit(host.onboarding(origin), kit)
        say("new recovery kit made for ${s.held.emailNorm} on $origin: the old kit no longer works")
    }

    private fun deviceLine(d: io.silencelen.andvari.core.model.wire.Device, thisDevice: String): String =
        "${arg(d.deviceId)}  “${d.name}” (${d.platform}, as it says)  ${d.how}${d.linkedFrom?.let { " from $it" } ?: ""}  " +
            "added ${d.createdAt}  last seen ${d.lastSeenAt ?: "never"}  ${if (d.live) "signed in" else "not signed in"}" +
            if (d.current || d.deviceId == thisDevice) "  (this device)" else ""

    /**
     * `account revoke-device ID`: any of the account's devices but this one, signed in or not. This device is refused
     * before anything is sent (`sign-out` ends it here); so is an id the account's list does not hold.
     */
    private suspend fun revokeDevice(s: AccountSession, id: String) {
        val st = host.settings(s.held)
        val list = fetched(st.list())
        val d = list.firstOrNull { it.deviceId == id } ?: throw CliError("no device $id in this account's list (`andvari-cli account devices`): nothing was sent")
        if (d.current || d.deviceId == s.held.session.deviceId) {
            throw CliError("$id is this device: to end it here, run `andvari-cli sign-out`. Nothing was sent")
        }
        done(st.revoke(id, c.password(s.held.emailNorm)))
        say("revoked: “${d.name}” ($id) is signed out and no longer a known device of this account; to use it again, link it or sign in there")
    }

    /**
     * `account delete` (the account-deletion design §3, §11; design §3.11): the plan and the blockers first; then the
     * typed confirmation of the account's address, at the terminal, or without one as `--confirm-email <address>` (the
     * request's own `confirmEmail` field); then the code when the account has two-step sign-in, and the password. A lost
     * answer is "cannot tell yet", never "deleted". Deleted, nothing of the account is left in this device's home.
     */
    private suspend fun deleteAccount() {
        var gone: Triple<String, String, String>? = null
        signedIn { s ->
            s.sync()
            val email = s.held.emailNorm
            val del = s.deletion { }
            val p = del.preview() ?: throw CliError("the server did not answer, so there is no plan to show: nothing was deleted")
            val name = host.trust.pinFor(origin)?.name ?: origin
            fun vaults(ids: List<String>) = if (ids.isEmpty()) "none" else ids.joinToString { id -> s.vaultName(id)?.let { "“$it” ($id)" } ?: id }
            say("Deleting $email on “$name” ($origin) removes, for good:")
            say("  - the account, its personal vault and everything in it")
            say("  - the vaults only it holds: ${vaults(p.deletedVaults.filter { it != s.personalVaultId })}")
            say("  - every device signed in to it, its recovery kit and its links nobody used")
            say("It leaves these shared vaults (what it saved there stays with the others): ${vaults(p.leftVaults)}")
            say("This can't be undone.")
            flush()
            if (p.blockers.isNotEmpty()) {
                throw CliError.lines(listOf("the account cannot be deleted yet:") + p.blockers.map { "  - " + blockerText(s, it) } + "Nothing was deleted")
            }
            val typed = a.opt("confirm-email") ?: run {
                val console = Term.console() ?: throw CliError(
                    "account delete asks you to type the account's email address to confirm, and no terminal is attached: " +
                        "give it as --confirm-email <the address>. Nothing was sent", 2,
                )
                Term.readLine(console, "Type this account's email address to delete it permanently: ")?.trim() ?: ""
            }
            if (TrustGrammar.emailNorm(typed) != email) throw CliError("the address typed is not this account's: nothing was sent")
            val totp = if (p.totpRequired) String(c.secrets.read("totp", "ANDVARI_TOTP", "Two-step code: ")).trim() else null
            val password = c.password(email)
            var outcome: DeletionOutcome
            try {
                var rounds = 0
                while (true) {
                    // The engine wipes the password it is handed: each round has its own copy.
                    outcome = del.delete(typed, password.copyOf(), totp)
                    if (outcome !is DeletionOutcome.LogStale || ++rounds >= 3) break
                }
            } finally {
                password.fill('\u0000')
            }
            when (val o = outcome) {
                is DeletionOutcome.Deleted -> {
                    gone = Triple(email, s.userId, s.held.session.deviceId)
                    say("deleted: $email on $origin at ${o.deletedAt}. Members of the shared vaults it was in see it leave")
                }
                else -> throw deletionRefused(s, o, codeSent = totp != null)
            }
        }
        // After signedIn, which saves the held session back: nothing of the account stays in the home.
        gone?.let { (email, userId, deviceId) -> say(forgetDeletedAccount(email, userId, deviceId)) }
    }

    private fun blockerText(s: AccountSession, b: io.silencelen.andvari.core.model.wire.AccountDeleteBlocker): String = when (b.kind) {
        io.silencelen.andvari.core.model.wire.DeleteBlockerKind.SHARED_VAULT -> {
            val v = b.vaultId?.let { id -> s.vaultName(id)?.let { "“$it” ($id)" } ?: id } ?: "a shared vault"
            "it owns $v, which has ${b.others} other member${if (b.others == 1) "" else "s"}: hand it over (`vault offer`), remove them (`vault remove`) or delete the vault (`vault delete`) first"
        }
        io.silencelen.andvari.core.model.wire.DeleteBlockerKind.OPERATOR ->
            "it is this server's operator account, which cannot be deleted while it is the operator: hand the operator role over first"
        else -> "a reason this version of andvari-cli cannot explain (${b.kind}): update andvari-cli, or ask whoever runs your server"
    }

    /** [codeSent]: a two-step code went with the deletion, so a back-off that refused it is the codes' ([tooManyCodes]). */
    private fun deletionRefused(s: AccountSession, o: DeletionOutcome, codeSent: Boolean = false): CliError {
        return when (o) {
            is DeletionOutcome.Blocked ->
                CliError.lines(listOf("the account cannot be deleted yet:") + o.blockers.map { "  - " + blockerText(s, it) } + "Nothing was deleted")
            is DeletionOutcome.LogStale ->
                CliError("your shared vaults kept changing while the deletion was being signed: nothing was deleted. Try again")
            DeletionOutcome.FutureHead -> CliError("One of your shared vaults reports a time far in the future. Try again later. Nothing was signed or sent")
            DeletionOutcome.ClockAhead -> CliError("your device's clock is ahead of the server's: set it right and try again. Nothing was deleted")
            DeletionOutcome.TotpNeeded -> CliError("this account has two-step sign-in: give the current code (--totp-file or \$ANDVARI_TOTP). Nothing was deleted")
            DeletionOutcome.BadTotp -> CliError("that two-step code is wrong or was already used: nothing was deleted")
            DeletionOutcome.WrongPassword -> CliError("wrong master password: nothing was sent, nothing was deleted")
            DeletionOutcome.EmailMismatch -> CliError("the address typed is not this account's: nothing was sent")
            DeletionOutcome.Unreachable -> CliError("the server did not answer before anything was sent: nothing was deleted")
            DeletionOutcome.ReauthRefused -> CliError("this device may not send the password to $origin now: nothing was sent")
            DeletionOutcome.Unknown -> CliError(
                "cannot tell yet whether ${s.held.emailNorm} was deleted: the server's answer did not arrive, and it may have deleted the account. " +
                    "This device kept everything. Check with `andvari-cli account delete --check`",
                1, KEY_DELETION_UNKNOWN,
            )
            is DeletionOutcome.Refused -> when (o.code) {
                RATE_LIMITED -> if (codeSent) tooManyCodes(o.retryAfterSeconds, "Nothing was deleted") else tooManyPasswords(o.retryAfterSeconds, "Nothing was deleted")
                Reauthed.PROOF_REFUSED -> proofRefusedError(origin)
                "credential_changed" -> CliError("the account's password changed, or this session was ended, meanwhile: nothing was deleted")
                else -> CliError(refusal("the deletion was refused, nothing was deleted", o.code))
            }
            is DeletionOutcome.Deleted -> CliError("deleted")
        }
    }

    /**
     * `account delete --check`, after "cannot tell yet": the preview answers only while the account exists. A session the
     * server no longer accepts cannot be told from a revocation, a disable or a reset elsewhere, so that is said as such.
     */
    private suspend fun deletionCheck() {
        try {
            signedIn { s ->
                if (s.deletion { }.preview() == null) throw CliError("the server did not answer: cannot tell yet. Run the check again later", 1, KEY_DELETION_UNKNOWN)
                if (asJson) emit(buildJsonObject {
                    put("origin", JsonPrimitive(origin)); put("account", JsonPrimitive(s.held.emailNorm)); put("state", JsonPrimitive("exists"))
                })
                else say("not deleted: ${s.held.emailNorm} still exists on $origin")
            }
        } catch (e: SessionEnded) {
            throw CliError(
                "cannot tell: the server no longer accepts this device's session. A deletion ends it, and so do a revocation, a disable " +
                    "or a password reset elsewhere. If a sign-in with your password is refused too, the account is most likely gone; " +
                    "`andvari-cli sign-out` then forgets it on this device",
                1, KEY_DELETION_UNKNOWN,
            )
        }
    }

    /**
     * The account is deleted: everything this device's home keeps for it goes. The held session, the saved one, the known
     * device record, every record keyed by the account's user id, and every record of this server keyed by its email or
     * device id (the engine's account records, the identity record included, as the apps forget it on a deletion; the
     * tool's names), and the remembered account; nothing of another server, whatever address it keeps there. Then
     * (decided on 2026-11-19) the server goes too, its pin and every record of it ([Host.forgetServer]), only where this
     * home keeps nothing of another account there ([Host.otherAccountKept]); otherwise the server and the other account's
     * records stay. Answers what is said.
     */
    private fun forgetDeletedAccount(email: String, userId: String, deviceId: String): String {
        host.signedOut(origin)
        c.saved.forget(origin, email)
        host.devices.forget(origin, email)
        // The address and the device's id are matched only in records of this server: the same address at another server
        // is another server's account, and its saved session, device record and address record stay as they are. The
        // account's id is this server's own and is matched in every record except one that names another server, which
        // that server's word alone put there (a server can hand out an id another server gave).
        for (store in listOf(c.state, host.secure)) {
            val keys = store.keys() ?: throw CliError("deleted on the server, but this device could not list what it keeps in ${c.home.dir}: delete that directory's records by hand")
            for (k in keys) {
                val parts = k.split('|')
                val ofThisServer = origin in parts && (email in parts || deviceId in parts)
                if (ofThisServer || (userId in parts && !Host.namesAnotherServer(k, origin))) store.set(k, null)
            }
        }
        if (c.state.get("${Ctx.K_EMAIL}|$origin") == email) c.state.set("${Ctx.K_EMAIL}|$origin", null)
        // A request for the operator's help made for the deleted address goes with it; one for another address stays.
        host.secure.get("${Host.KEPT_ASSIST}$origin")?.let { if (host.requestAddress(it) == email) KeptAssistRequests.forget(host.secure, origin, null) }
        host.otherAccountKept(origin, userId, email)?.let { return fill(DELETED_SERVER_KEPT, origin, it) }
        val r = host.forgetServer(origin, c.saved, null)
        if (r is ServerForgotten.Partly) throw CliError(forgotten(origin, OriginAccess.OPEN.code, r, c.home.dir.path))
        return fill(DELETED_SERVER_FORGOTTEN, origin)
    }

    // ---------------------------------------------------------------------------------------------
    // Operator (design §9.2): every route, for the operator account's own session
    // ---------------------------------------------------------------------------------------------

    /**
     * Whether this account runs [origin], on the pinned card's word (design §12.2 rule 7; spec 03 §17.2), never the
     * session's: the served chain's newest card is taken in first ([io.silencelen.andvari.core.client.pin.CardTrust.refresh]),
     * then the shared code's [cardNamesOperator][io.silencelen.andvari.core.client.pin.InstanceTrust.cardNamesOperator]
     * answers. So the command after a hand-over is served or refused as the new card says, on both accounts, with no
     * sign-in again. Refused here, with nothing sent, when the card names another account or no pin can be read.
     */
    private suspend fun operatorByCard(s: AccountSession) {
        host.trust.refresh(origin)
        when (host.trust.cardNamesOperator(origin, s.userId)) {
            true -> {}
            false -> throw CliError(
                "the server's card names another account as the operator of $origin: this account is an ordinary member there " +
                    "(after a hand-over, only the new operator runs the server). Nothing was sent", 1, KEY_NOT_THE_OPERATOR,
            )
            null -> throw CliError("this device holds no readable pin of $origin, so it cannot tell who runs it: nothing was sent", 1, KEY_NOT_THE_OPERATOR)
        }
    }

    /**
     * The card commands' own check on top of [operatorByCard]: the shared code's card path goes by the session's role
     * ([io.silencelen.andvari.core.client.account.WireOperatorCards]), which a hand-over does not change in a session
     * opened before it. Said before the password is asked, with what to do.
     */
    private suspend fun cardSigner(s: AccountSession) {
        operatorByCard(s)
        if (s.held.session.role != io.silencelen.andvari.core.model.wire.AccountRole.OPERATOR) throw CliError(
            "the server's card names this account as the operator of $origin (a hand-over), but this device's session was opened " +
                "before it, and signing a card goes by the role the session was opened with: run `andvari-cli sign-out`, then " +
                "`andvari-cli sign-in`, and sign again. Nothing was sent", 1, KEY_SESSION_ROLE_STALE,
        )
    }

    private suspend fun operator(sub: String?) = signedIn { s ->
        operatorByCard(s)
        val op = host.operator(s.held, io.silencelen.andvari.core.model.wire.AccountRole.OPERATOR)
        suspend fun userOf(email: String): String {
            if (TrustGrammar.isUuid(email)) return email
            val list = fetched(op.accounts())
            return list.firstOrNull { it.email == TrustGrammar.emailNorm(email) }?.userId ?: throw CliError("no account $email")
        }
        fun pw() = c.password(s.held.emailNorm)
        when (sub) {
            "accounts" -> fetched(op.accounts()).let { list ->
                if (asJson) emit(wire(ListSerializer(AccountSummary.serializer()), list))
                // An address may hold a backtick, `$`, `|` or `&`: each id and address is one shell word.
                else list.forEach { u: AccountSummary -> say("${arg(u.userId)}  ${arg(u.email)}  ${u.role}  ${u.status}  ${Quotas.short(u.quota)}") }
            }
            "status" -> fetched(op.status()).let { st ->
                if (asJson) emit(wire(io.silencelen.andvari.core.model.wire.AdminStatus.serializer(), st)) else say("$st")
            }
            "audit" -> audit(s, op)
            "policy" -> when (a.positional.getOrNull(2)) {
                // JSON both ways: what `operator policy` prints, edited, is what `operator policy set --file` takes.
                null, "show" -> c.term.json(WireJson.json.encodeToString(AdminPolicy.serializer(), fetched(op.policy())))
                "set" -> {
                    val f = File(a.opt("file") ?: throw CliError("--file FILE (the JSON `operator policy` prints, edited)", 2))
                    if (!f.isFile) throw CliError("--file: $f is not a readable file", 2)
                    val p = runCatching { WireJson.json.decodeFromString(AdminPolicy.serializer(), f.readText()) }
                        .getOrElse { throw CliError("--file: $f is not a policy as `operator policy` prints it (${it.message}); nothing was sent", 2) }
                    c.term.json(WireJson.json.encodeToString(AdminPolicy.serializer(), done(op.setPolicy(p, pw()))))
                }
                else -> throw CliError("operator policy [show] | operator policy set --file FILE", 2)
            }
            "recovery-requests" -> recoveryRequestsListing(fetched(op.recoveryRequests()))
            "disable" -> done(op.disable(userOf(a.pos(2, "the account")), a.opt("reason") ?: "other", pw()))
            "enable" -> done(op.enable(userOf(a.pos(2, "the account")), pw()))
            "delete" -> {
                // The one reason the server takes (owner policy 2026-11-15) is a switch, so no other value can be given.
                if (a.opt("under-minimum-age") != null) throw CliError("--under-minimum-age is a switch and takes no value; nothing was sent", 2)
                if (a.opt("reason") != null) throw CliError(
                    "operator delete takes no --reason: the only reason the server records is --under-minimum-age; nothing was sent", 2,
                )
                val underAge = a.has("under-minimum-age")
                val target = userOf(a.pos(2, "the account"))
                // What the server will record, said before the password is asked.
                if (underAge) note(
                    "Deleting ${a.pos(2, "the account")} as under the minimum age: the 30 days after the disable are lifted, nothing else is. " +
                        "The server records this deletion in its audit log as operator_delete with reason=${OperatorDeleteReason.UNDER_MINIMUM_AGE}, " +
                        "and that row outlives the account",
                )
                deleteOutcome(op.deleteChecked(target, pw(), if (underAge) OperatorDeleteReason.UNDER_MINIMUM_AGE else null), underAge)
            }
            "devices" -> fetched(op.accountDevices(userOf(a.pos(2, "the account")))).let { list ->
                if (asJson) emit(wire(ListSerializer(Device.serializer()), list)) else list.forEach { say(deviceLine(it, "")) }
            }
            "revoke-device" -> done(op.revokeDevice(a.pos(2, "the device id"), pw()))
            "quota" -> say("${done(op.setQuota(userOf(a.pos(2, "the account")), a.opt("bytes")?.toLong(), a.opt("items")?.toLong(), a.opt("vaults")?.toLong(), a.opt("links")?.toLong(), pw()))}")
            "escrow" -> {
                val f = File(a.opt("out") ?: throw CliError("--out FILE (the identity file for recovery-cli assist)", 2))
                val e = done(op.escrow(userOf(a.pos(2, "the account")), pw()))
                OwnerOnlyFile(f).replace(WireJson.json.encodeToString(AdminEscrowResponse.serializer(), e))
                say("escrow written to $f: carry it to the offline machine for recovery-cli assist --identity-file ${arg(f.path)}")
                say("It is the copy the server handed out. What you check it against comes from the person, never from this server: " +
                    "the account ID on their recovery kit, which they read to you. Delete the file when the recovery is done")
            }
            "hand-over" -> handOver(s)
            "fulfil" -> {
                // spec 04 §7 step 3: the file is read by the one shared reader, against the
                // listed request, before the password is asked; a refusal sends nothing.
                val requestId = a.pos(2, "the request id")
                val f = File(a.opt("sealed-file") ?: throw CliError("--sealed-file FILE (recovery-cli assist's output, or its last line)", 2))
                if (!f.isFile || f.length() > ANSWER_FILE_MAX) throw CliError("--sealed-file: $f is not an answer from recovery-cli assist; nothing was sent", 2)
                val row = fetched(op.recoveryRequests()).firstOrNull { it.requestId == requestId }
                    ?: throw CliError("operator fulfil: no listed request has that id (it is still in its hold, was cancelled, or is gone); nothing was sent", 1)
                val emailNorm = io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(row.email)
                    ?: throw CliError("operator fulfil: the server's row for that request names no address; nothing was sent", 1)
                // The file's bytes as UTF-8; bytes that are not UTF-8 are no answer (spec 04 §7 step 3).
                val answer = when (val r = io.silencelen.andvari.core.trust.AnswerToken.readFile(f.readBytes(), requestId, row.rPub, emailNorm)) {
                    is io.silencelen.andvari.core.trust.AnswerRead.Ok -> r
                    is io.silencelen.andvari.core.trust.AnswerRead.Refused -> throw CliError("operator fulfil: ${answerRefusal(r)}; nothing was sent", 2)
                }
                done(op.fulfil(requestId, answer, pw()))
                say("fulfilled: the person's device can now finish (until it does, you can upload a corrected answer the same way)")
            }
            else -> throw CliError("operator enrol|accounts|status|audit|policy|recovery-requests|disable|enable|delete|devices|revoke-device|quota|escrow|fulfil|hand-over", 2)
        }
    }

    /**
     * `operator audit [--type T] [--user E] [--since MS] [--after ID] [--all]` (design §9.2; spec 03 §7.3).
     * The server answers one page of at most [AUDIT_PAGE_ROWS] rows, newest first; a full page means older rows
     * may exist, and the command says so with the `--after` that reads them. `--all` follows the pages, at most
     * [AUDIT_MAX_PAGES], and says so when it stops at that cap with more left. Every page is read and checked by the shared
     * code's two calls (`auditPage`, `nextAuditPage`) before anything of it is shown: at most a page of rows, ids strictly
     * descending, each below the cursor, and each row inside the filters asked for. A page that fails stops the command
     * ([EXIT_SERVER_ANSWER], [KEY_SERVER_ROW_REFUSED]), with nothing printed on standard output.
     */
    private suspend fun audit(s: AccountSession, op: io.silencelen.andvari.core.client.account.WireOperatorRoutes) {
        val since = a.opt("since")?.let { it.toLongOrNull()?.takeIf { v -> v >= 0 } ?: throw CliError("--since takes a time in milliseconds", 2) }
        val type = a.opt("type")
        val user = a.opt("user")?.let { u ->
            if (TrustGrammar.isUuid(u)) u else fetched(op.accounts()).firstOrNull { it.email == TrustGrammar.emailNorm(u) }?.userId ?: throw CliError("no account $u")
        }
        val start = a.opt("after")?.let { it.toLongOrNull()?.takeIf { v -> v > 0 } ?: throw CliError("--after takes the id of a row (a whole number above 0), as the last line of a page shows it", 2) }
        if (type != null && !AUDIT_TYPE.matches(type)) throw CliError(refusal("refused", "bad_type"))
        // Spec 03 §7.3: a server whose status names the kinds of audit row it writes is asked only for one of them; the
        // tool keeps no list of its own, so a kind it has never seen is asked for, and shown, as the server serves it.
        if (type != null) (op.status() as? Fetched.Ok)?.value?.auditKinds?.let { kinds ->
            if (type !in kinds) throw CliError(fill(AUDIT_KIND_NOT_KEPT, origin, type, kinds.joinToString(", ").ifEmpty { "none" }), 2)
        }
        val all = a.has("all")
        val rows = ArrayList<io.silencelen.andvari.core.model.wire.AuditRow>()
        var pages = 0
        // The shared code's two calls: the first page (after --after when given), then the next one with the same filters.
        // Each page is checked there (at most a page, newest first and each once, older than the cursor, inside the
        // filters); one that fails is AUDIT_PAGE_LIES, said here as the server's fault, never shown as a short list.
        fun page(f: Fetched<io.silencelen.andvari.core.client.account.AuditPage>): io.silencelen.andvari.core.client.account.AuditPage {
            if (f is Fetched.Refused && f.code == io.silencelen.andvari.core.client.account.WireOperatorRoutes.AUDIT_PAGE_LIES) throw CliError(
                "the server at $origin sent a page of its audit log that this device will not show (more than a page of rows, rows not " +
                    "newest first, a row not older than the page before, or one outside the filters asked for): nothing of it was shown. " +
                    "That is a fault of the server's answer; tell whoever runs the server's host",
                EXIT_SERVER_ANSWER, KEY_SERVER_ROW_REFUSED,
            )
            return fetched(f)
        }
        var last = page(op.auditPage(since, type, user, start))
        while (true) {
            rows += last.rows
            pages++
            if (!last.full || !all || pages >= AUDIT_MAX_PAGES) break
            last = page(op.nextAuditPage(last) ?: break)
        }
        val more = last.full
        val after = if (more) rows.last().id else null
        if (asJson) return emit(buildJsonObject {
            put("rows", wire(ListSerializer(io.silencelen.andvari.core.model.wire.AuditRow.serializer()), rows))
            put("more", JsonPrimitive(more))
            put("after", after?.let(::JsonPrimitive) ?: JsonNull)
        })
        // at, type, the acting account, the row's meta (ids and fixed values only, never an email, §9.4), then its id.
        rows.forEach { say("${it.at}  ${it.type}  ${it.userId?.let(::arg) ?: "-"}${it.meta?.let { m -> "  $m" } ?: ""}  id ${it.id}") }
        if (after != null) note(
            (if (all) "Stopped after $AUDIT_MAX_PAGES pages (${rows.size} rows), the most --all reads in one run: older rows exist. "
            else "This is one page of the newest ${rows.size} rows: older rows exist. ") +
                "Read them with the same filters and --after $after${if (all) "" else ", or follow every page with --all (at most $AUDIT_MAX_PAGES pages)"}",
        )
    }

    /**
     * `operator recovery-requests` (design §9.3). Never a request code (T2-R-c), and never the
     * server's account ID: what the operator checks comes from the person, and the listing says so in its own words. Each
     * row is shown only after every field was checked ([ServedRows.request]); a row that fails is left out and the command
     * then fails with [KEY_SERVER_ROW_REFUSED] (with `--json`, nothing is printed at all).
     */
    private fun recoveryRequestsListing(rows: List<io.silencelen.andvari.core.model.wire.AdminRecoveryRequest>) {
        val shown = rows.mapNotNull { ServedRows.request(it) }
        val refused = rows.size - shown.size
        if (asJson) {
            if (refused == 0) emit(JsonArray(shown.map { it.json() }))
        } else if (shown.isEmpty()) {
            if (refused == 0) say("no live recovery request (none verified and not yet finished, cancelled or expired)")
        } else {
            // The heading claims nothing a row may contradict
            // (each row says its own state), and the guidance names every argument recovery-cli assist requires.
            val instance = host.trust.pinFor(origin)?.instanceId
            say("Live recovery requests, each with its own state. Answer only one that is waiting for the operator (or answered, to correct it).")
            say("What you check comes from the person, never from this list: the request code they read out from their own device,")
            say("their address as you know it, and the account ID on their recovery kit.")
            say("This list shows no account ID, and nothing in it is a value to check against. recovery-cli assist, offline, requires:")
            say("  --instance ${instance ?: "<the instance id on this server's card: andvari-cli card show>"}${if (instance != null) " (from this device's pin of the server's card)" else ""}")
            say("  --request and --request-key: the row's request id and request key; --user: the row's user id")
            say("  --request-code: the code the person reads to you from their own device")
            say("  --email: the person's address, typed from your own knowledge of the person, never copied from this list")
            say("  --identity-fp: the account ID on their recovery kit, which they read to you (--no-identity-anchor only when they have no kit)")
            say("  --identity-file: the file `andvari-cli operator escrow <account> --out FILE` writes")
            val recoveryFp = host.trust.pinFor(origin)?.recoveryFp
            for (r in shown) {
                say("${r.requestId}  for ${arg(r.email)}  request key ${r.requestKey}  user ${r.userId}  ${r.stateWords()}  from a ${r.platform} device (as it says)")
                r.outgoingKeyLine(recoveryFp)?.let { say("  $it") }
            }
        }
        if (refused > 0) throw ServedRows.refused(origin, if (refused == 1) "a recovery request" else "recovery requests", refused)
    }

    /**
     * `operator hand-over --to-user UUID --to-key KEY [--confirm "HAND OVER <first 8 of UUID>"]` (design §4.2, §4.3, §9.1;
     * spec 03 §17.2): the next card names another account and its Ed25519 signing key as the operator, through the shared
     * code's path ([io.silencelen.andvari.core.client.account.WireOperatorCards.handOver]). The new operator is named by
     * what the person can check: the user id and key `account signing-key` prints on the new operator's own device,
     * never a value from this server's lists; when this account compared codes with them, the key must also map to that
     * contact's identity key. What this account can and cannot do afterwards is said before the typed confirmation, and
     * the master password is proven on this device before anything is sent.
     */
    private suspend fun handOver(s: AccountSession) {
        val toUser = a.opt("to-user")?.trim()?.lowercase() ?: throw CliError("--to-user <the new operator's user id, from their own device>", 2)
        val toKey = a.opt("to-key")?.trim() ?: throw CliError("--to-key <the new operator's signing key, from their own device>", 2)
        if (!TrustGrammar.isUuid(toUser)) throw CliError("--to-user must be a user id (a uuid) as `andvari-cli account signing-key` prints it: nothing was sent", 2)
        if (!TrustGrammar.isB64_32(toKey)) throw CliError("--to-key must be a signing key (43 characters of base64url) as `andvari-cli account signing-key` prints it: nothing was sent", 2)
        if (toUser == s.userId) throw CliError("that is this account: it is the operator already. Nothing was sent", 2)
        cardSigner(s)
        val short = host.trust.operatorShortFp(toKey)?.let(::grouped)
            ?: throw CliError("--to-key is not a signing key an operator can have (it has no identity image): nothing was sent", 2)
        s.readAccountStateOnce()
        val contact = s.store.local().contacts[toUser]
        val name = host.trust.pinFor(origin)?.name?.let { "“$it” ($origin)" } ?: origin
        note("Hand $name over to the account $toUser, whose signing key's short form is $short.")
        note("Both must come from the new operator's own device (`andvari-cli account signing-key` there), never from this server's lists.")
        note(
            if (contact != null) "This account ${if (contact.compared) "compared codes with" else "is connected to"} that account: the key is also checked against that contact's key."
            else "This account holds no contact for that account: the key is checked only by your reading it from their device.",
        )
        note("After the hand-over, this account (${s.held.emailNorm}) is an ordinary member of the server:")
        note("  - it can no longer sign the server's card, nor use any operator command (accounts, disable, enable, delete, devices, quotas,")
        note("    policy, the audit log, recovery copies and requests), and it can be deleted like any account;")
        note("  - it keeps its own account and its personal vault, and only a card signed by the new operator can change the server's card again;")
        note("  - what it holds offline stays with whoever holds it: the instance recovery sheet still opens the recovery copies sealed to its key")
        note("    until the new operator rotates the key with that sheet's seed (recovery-cli rotate). Hand the sheet over, or rotate.")
        note("The new operator's account becomes operator-only: its sessions in the web app, the browser extension and phones sign out.")
        val phrase = "HAND OVER ${toUser.take(8)}"
        val typed = a.opt("confirm") ?: run {
            val console = Term.console() ?: throw CliError("type the confirmation: give --confirm \"$phrase\" when no terminal is attached. Nothing was sent", 2)
            Term.readLine(console, "Type $phrase to hand the server over (anything else stops): ")?.trim()
        }
        if (typed != phrase) throw CliError("not confirmed: this account stays the operator. Nothing was sent")
        val before = host.trust.pinFor(origin)
        val r = host.operatorCards(s.held).handOver(toUser, toKey, contact?.identityPub, c.password(s.held.emailNorm))
        say(CardChanges.outcome(r, origin, before))
        say("handed over: $toUser is the operator of $origin, and this account is an ordinary member. The new operator's operator commands " +
            "follow the card from their next command; to sign a card, a session they opened before now must sign in again first " +
            "(`andvari-cli sign-out`, then `andvari-cli sign-in` on their device)")
    }

    /** The operator's delete as the person reads it; [underAge] when it carried the one reason. */
    private fun deleteOutcome(d: OperatorDelete, underAge: Boolean) {
        when (d) {
            is OperatorDelete.Deleted -> say("deleted at ${d.deletedAt}" + if (underAge) " (recorded with reason=${OperatorDeleteReason.UNDER_MINIMUM_AGE})" else "")
            is OperatorDelete.NotDisabledLongEnough -> throw CliError(
                if (underAge) {
                    "an account under the minimum age is deleted only once it is disabled (the disable emails the person first); " +
                        (d.disabledAt?.let { "this one was disabled at $it, and the server still refused" } ?: "this one is not disabled: run `operator disable` first") +
                        ". Nothing was deleted"
                } else {
                    "only an account disabled for at least 30 days can be deleted; " +
                        (d.disabledAt?.let { "this one was disabled at $it" } ?: "this one is not disabled (run `operator disable` first)") + ". Nothing was deleted"
                },
            )
            is OperatorDelete.Blocked -> throw CliError("the account owns shared vaults with other members, so it cannot be deleted: " +
                "${d.blockers.joinToString { it.toString() }}. Nothing was deleted")
            is OperatorDelete.Other -> done(d.result).let { }
        }
    }

    private fun <T> fetched(f: Fetched<T>): T = when (f) {
        is Fetched.Ok -> f.value
        is Fetched.Refused -> throw CliError(refusal("refused", f.code))
        Fetched.Unreachable -> throw CliError("the server did not answer")
    }

    private fun <T> done(r: Reauthed<T>): T = when (r) {
        is Reauthed.Done -> r.value
        Reauthed.WrongPassword -> throw CliError("wrong master password: nothing was sent")
        Reauthed.NoSession -> throw CliError("this device may not send the password to $origin now: nothing was sent")
        Reauthed.PasswordTooWeak -> throw CliError("that password is too weak")
        is Reauthed.Refused -> throw when (r.code) {
            RATE_LIMITED -> tooManyPasswords(r.retryAfterSeconds, "Nothing changed")
            // The engine's word: the proof was made here and sent, and the server refused it. Never a wrong password.
            Reauthed.PROOF_REFUSED -> proofRefusedError(origin)
            else -> CliError(refusal("refused", r.code))
        }
        Reauthed.Unknown -> throw CliError("no answer: the change may have landed; check before retrying")
    }

    @Suppress("unused")
    private fun unusedResult(r: WireResult<*>) = r

    companion object {
        /** The message key of a deletion whose outcome this device cannot tell yet (`account delete`, `account delete --check`). */
        const val KEY_DELETION_UNKNOWN = "deletion_outcome_unknown"

        /** The uniform kit refusal (design §10): it does not say which of the three it was. */
        const val KIT_REJECTED = "the kit was not accepted (a wrong kit, another account's, or no kit on record for this address): nothing changed"

        /** A kept session at an origin with no pin record (design §4.4): blocked, and what to do. */
        fun keptWithoutPin(origin: String, email: String): String =
            "SECURITY: this device keeps a session for $email at $origin but no pin of that server (a move that stopped half-way, " +
                "or a record that was lost). The server is blocked here: the session does not open and nothing is sent to it. " +
                "Run `andvari-cli forget-server --yes` to delete what this device keeps for the server, or `andvari-cli sign-out` " +
                "to end the session on this device only (the server is not told)"

        /** What the person reads when the saved session cannot be rebuilt ([SavedSessions.Reopen.Unusable]). */
        fun unusableText(origin: String, email: String): String =
            "this device's saved session of $email on $origin is unusable: what it kept cannot be made into a session again, so it " +
                "was not used and nothing was changed. Run `andvari-cli sign-in` to sign in again and continue"

        /** What the person reads when the server ended the session ([code]: why it refused the refresh). */
        fun endedText(origin: String, email: String, code: String): String =
            "the server at $origin ended this device's session for $email ($code: the session was revoked, this device was removed, " +
                "the master password was changed or its key settings were raised on another of your devices, " +
                "or the session expired there). This device deleted only that session's tokens; everything else it keeps for the " +
                "account stays. Run `andvari-cli sign-in` to sign in again and continue"

        /** What `forget-server` tells the person: done, or partly done with what to do next. [was] is the pin's access code. */
        fun forgotten(origin: String, was: String, r: ServerForgotten, home: String): String = when (r) {
            ServerForgotten.Done ->
                "forgot $origin on this device (it was $was): its pin, the saved session and everything kept for its accounts are deleted, " +
                    "and nothing was sent. The next sign-in shows the Trust Gate again"
            is ServerForgotten.Partly ->
                "forgot $origin only in part: the pin is gone and nothing was sent, so this device trusts nothing from that address, but " +
                    "some of what it keeps for the server could not be ${if (r.reason == ServerForgotten.CANNOT_LIST) "listed" else "deleted"}. " +
                    "Run `andvari-cli forget-server --yes` again to finish; if it stops here again, check that $home is writable and its files are intact"
        }
    }
}

/** An answer file larger than this is not read (the tool's whole output is under 2 KiB). */
private const val ANSWER_FILE_MAX = 64L * 1024

/**
 * Why [name] is not a name the server takes, as words that say which kind of character is refused ("holds a control
 * character (U+0009)"), or null when the shared code's own test ([TrustGrammar.isText]) passes it. The kind is read from
 * the first character the shared list ([TrustGrammar.isRefusedNameCodePoint]) refuses; the list itself is never copied.
 */
internal fun nameRefusal(name: String): String? {
    if (TrustGrammar.isText(name)) return null
    if (name.isEmpty()) return "is empty"
    if (name.length > TrustGrammar.TEXT_MAX_CHARS) return "is longer than ${TrustGrammar.TEXT_MAX_CHARS} characters"
    var i = 0
    while (i < name.length) {
        val ch = name[i]
        val cp = when {
            ch.isHighSurrogate() && i + 1 < name.length && name[i + 1].isLowSurrogate() -> Character.toCodePoint(ch, name[++i])
            ch.isSurrogate() -> return "holds a broken character (half of a pair, U+%04X)".format(ch.code)
            else -> ch.code
        }
        if (TrustGrammar.isRefusedNameCodePoint(cp)) {
            val kind = when (cp) {
                in 0x00..0x1F, in 0x7F..0x9F -> "a control character (such as a line break or a tab)"
                0x061C, 0x200E, 0x200F, in 0x202A..0x202E, in 0x2066..0x2069 -> "a character that changes the direction of text"
                0x2028, 0x2029 -> "a line or paragraph separator"
                in 0xFFF9..0xFFFB -> "an interlinear annotation character"
                else -> "an invisible character (zero-width, a soft hyphen, a byte-order mark or an invisible operator)"
            }
            return "holds $kind (U+%04X)".format(cp)
        }
        i++
    }
    return "is not a name the server takes"
}

/**
 * How many two-step codes a device link's pickup sends before the run stops: the link stays at the server after each
 * refused one (within its time), and the server counts the codes on its own back-off, so a run keeps well below it.
 */
const val CODES_AT_LINK = 3

/** The most rows one page of the audit log holds (spec 03 §7.3): a page this full means older rows may exist. */
const val AUDIT_PAGE_ROWS = 500

/** The most pages `operator audit --all` reads in one run (10 000 rows). */
const val AUDIT_MAX_PAGES = 20

/** An audit type name as the server takes it (the shared code's own grammar for it). */
private val AUDIT_TYPE = Regex("^[a-z][a-z0-9_]{0,63}$")

/** The message key of an operator command refused because the pinned card names another account (or none can be read). */
const val KEY_NOT_THE_OPERATOR = "not_the_operator"

/** The message key of a card command in a session opened before a hand-over named this account (sign out and in). */
const val KEY_SESSION_ROLE_STALE = "session_role_stale"

/** The message key of `recover assist --account-id` given an ID that differs from the account delivered (the request is kept). */
const val KEY_ACCOUNT_ID_DIFFERS = "account_id_differs"

/** What `operator fulfil` says for each refusal of the shared reader of an answer (spec 04 §7 step 3). */
private fun answerRefusal(r: io.silencelen.andvari.core.trust.AnswerRead.Refused): String = when (r.refusal) {
    io.silencelen.andvari.core.trust.AnswerRefusal.EMPTY -> "the file holds no answer"
    io.silencelen.andvari.core.trust.AnswerRefusal.IS_THE_COPY -> "this is the recovery copy, which recovery-cli assist reads, not the answer it writes"
    io.silencelen.andvari.core.trust.AnswerRefusal.NOT_AN_ANSWER ->
        "this is not an answer from recovery-cli assist (give its whole output, or only the last line it printed)"
    io.silencelen.andvari.core.trust.AnswerRefusal.BARE ->
        "this is a sealed answer without its request: give the whole last line recovery-cli assist printed (it starts andvari-answer:)"
    io.silencelen.andvari.core.trust.AnswerRefusal.OTHER_REQUEST ->
        "recovery-cli assist made this answer for another request, ${r.namedRequest.orEmpty()}" // a b64_16 by the reader's grammar: nothing to escape
    io.silencelen.andvari.core.trust.AnswerRefusal.OTHER_REQUEST_KEY -> "this answer was made for another request key than this request's"
    io.silencelen.andvari.core.trust.AnswerRefusal.CUT_SHORT ->
        "this answer is shorter than recovery-cli assist makes one for this request's address: it is cut or damaged, or it was made for another address"
    io.silencelen.andvari.core.trust.AnswerRefusal.TOO_LONG ->
        "this answer is longer than recovery-cli assist makes one for this request's address: it is damaged, or it was made for another address"
}
