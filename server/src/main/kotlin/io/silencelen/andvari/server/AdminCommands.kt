package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.SignupMode
import java.io.File
import java.io.PrintStream

/**
 * The `andvari admin` commands (spec 03 §7.4, design §9.5). Host-trusted: they act on the database and
 * the env file directly and are audited like the operator's own actions, with no session.
 */
class AdminCommands(private val s: Services, private val envFile: File, private val out: PrintStream) {

    fun run(cmd: String, a: HostCli.Args) {
        when (cmd) {
            "status" -> status()
            "accounts" -> accounts()
            "operator" -> operator()
            "audit" -> audit(a)
            "signup" -> signup(a)
            "quota" -> quota(a)
            "enrol-link" -> enrolLinks(a)
            "setup-link" -> setupLink()
            "reset-instance-identity" -> resetIdentity(a)
            "disable", "enable" -> setStatus(cmd, a)
            else -> throw HostCli.Usage("unknown admin command '$cmd'")
        }
    }

    private fun status() = s.db.read { c ->
        val setup = s.instance.setupOn(c)
        val head = s.instance.head(c)
        val p = s.policy.load(c)
        out.println("instance ${setup?.instanceId} (${s.config.instanceKind}) at ${s.config.canonicalOrigin}")
        out.println("card: ${head?.let { "seq ${it.seq}, ${it.hash}" } ?: "none (setup not finished)"}")
        out.println("sign-up: ${s.policy.effectiveMode(p)}, cap ${s.policy.effectiveCap(p)}, active members ${s.policy.activeMembers(c)}")
        out.println("accounts: ${c.count("SELECT COUNT(*) FROM users")}")
        // The record of the last `andvari admin restored` (served by no route): shown here only.
        c.queryOne("SELECT value FROM meta WHERE key=?", RestoredStart.RECORD_KEY) { it.getString(1) }?.let { out.println("last restored start: $it") }
    }

    private fun accounts() = s.db.read { c ->
        c.queryAll("SELECT userId,email,role,status FROM users ORDER BY createdAt") { "${it.getString(1)}  ${it.getString(2)}  ${it.getString(3)}  ${it.getString(4)}" }
            .forEach { out.println(it) }
    }

    private fun operator() = s.db.read { c ->
        out.println(c.queryOne("SELECT userId,email FROM users WHERE role='operator'") { "${it.getString(1)}  ${it.getString(2)}" } ?: "no operator account")
    }

    private fun audit(a: HostCli.Args) = s.db.read { c ->
        val limit = a.opt("limit")?.toIntOrNull()?.coerceIn(1, 10_000) ?: 100
        s.audit.query(c, a.opt("since")?.toLongOrNull(), a.opt("type"), a.opt("user"), limit).forEach {
            out.println("${it.id} ${it.at} ${it.type} ${it.userId ?: "-"} ${it.deviceId ?: "-"} ${it.ip ?: "-"} ${it.meta ?: ""}")
        }
    }

    /**
     * `signup open|links|close|cap <n>` (spec 03 §7.2, design §7.1 R7/N8): edits `andvari.env`, clears the
     * database's tighter value for what it sets, and asks for a restart. The only way to raise the cap or
     * loosen the mode.
     */
    private fun signup(a: HostCli.Args) {
        val what = a.positional.getOrNull(1) ?: throw HostCli.Usage("andvari admin signup open|links|close|cap <n>")
        val (key, value) = when (what) {
            "open" -> "ANDVARI_SIGNUP_MODE" to SignupMode.OPEN
            "links" -> "ANDVARI_SIGNUP_MODE" to SignupMode.LINKS
            "close", "closed" -> "ANDVARI_SIGNUP_MODE" to SignupMode.CLOSED
            // The start's own bound for the cap, so that the settings file never gets a cap every start would refuse.
            "cap" -> Config.NUM_RANGES.getValue("ANDVARI_SIGNUP_CAP").let { range ->
                "ANDVARI_SIGNUP_CAP" to (a.positional.getOrNull(2)?.toLongOrNull()?.takeIf { it in range }?.toString()
                    ?: throw HostCli.Usage("andvari admin signup cap <n>, a whole number from ${range.first} to ${range.last}"))
            }
            else -> throw HostCli.Usage("andvari admin signup open|links|close|cap <n>")
        }
        if (value == SignupMode.OPEN && !s.config.mailConfigured) throw HostCli.Refused("open sign-up needs a mail transport")
        HostCli.editEnvFile(envFile, mapOf(key to value))
        s.db.tx { c ->
            val p = s.policy.load(c)
            val signup = if (key == "ANDVARI_SIGNUP_MODE") AdminSignupPolicy(null, p.signup.cap) else AdminSignupPolicy(p.signup.mode, null)
            s.policy.storeOn(c, p.copy(signup = signup))
            s.audit.on(c, "operator_policy", null, null, null, "host_signup=$what")
        }
        out.println("Set $key=$value in ${envFile.path} and cleared the panel's value. Restart the server to apply it.")
    }

    /** `quota --account <email> [--bytes N] [--items N] [--vaults N] [--links N]`; `default` returns a limit to the instance default. */
    private fun quota(a: HostCli.Args) {
        val email = a.opt("account")?.let { Grammar.emailOrNull(it) } ?: throw HostCli.Usage("andvari admin quota --account <email> [--bytes N] [--items N] [--vaults N] [--links N]")
        fun v(name: String): Pair<Boolean, Long?> = a.opt(name)?.let { if (it == "default") true to null else true to (it.toLongOrNull()?.takeIf { n -> n >= 0 } ?: throw HostCli.Usage("--$name <n>|default")) } ?: (false to null)
        s.db.tx { c ->
            val userId = c.queryOne("SELECT userId FROM users WHERE email=?", email) { it.getString(1) } ?: throw HostCli.Refused("no account with that address")
            for ((flag, col) in listOf("bytes" to "quotaAccountBytes", "items" to "quotaItems", "vaults" to "quotaOwnedSharedVaults", "links" to "quotaOpenLinks")) {
                val (set, value) = v(flag)
                if (set) c.exec("UPDATE users SET $col=? WHERE userId=?", value, userId)
            }
            s.audit.on(c, "operator_quota", null, null, null, "host target=$userId")
            val q = s.policy.quotaOf(c, userId)
            out.println("quota: accountBytes ${q.accountBytes}, items ${q.items}, ownedSharedVaults ${q.ownedSharedVaults}, openLinks ${q.openLinks}")
        }
    }

    /** `enrol-link [--email E] [--expires D] [--count N]` (spec 03 §15.1): refused until card 0 exists. */
    private fun enrolLinks(a: HostCli.Args) {
        val email = a.opt("email")?.let { Grammar.emailOrNull(it) ?: throw HostCli.Refused("not an email address") }
        val days = a.opt("expires")?.removeSuffix("d")?.toLongOrNull()?.takeIf { it in 1..90 } ?: 7
        val count = a.opt("count")?.toIntOrNull()?.takeIf { it in 1..100 } ?: 1
        val urls = s.db.tx { c ->
            val card0 = s.instance.card0Hash(c) ?: throw HostCli.Refused("card 0 is not signed yet; finish setup first")
            val instanceId = s.instance.instanceId(c)
            (1..count).map { HostLinks.mintEnrol(c, s.config, instanceId, card0, email, days * Clock.DAY_MS, s.clock.now()).url }
                .also { s.audit.on(c, "enrol_link_mint", null, null, null, "count=$count") }
        }
        urls.forEach { out.println(it) }
    }

    /** `setup-link`: only while no operator account exists (design FI-B9). */
    private fun setupLink() {
        val minted = s.db.tx { c ->
            if (c.queryOne("SELECT 1 FROM users WHERE role='operator'") { 1 } != null) throw HostCli.Refused("an operator account exists")
            HostLinks.mintSetup(c, s.config, s.instance.setupOn(c)!!, s.clock.now())
        }
        out.println(minted.url)
    }

    /** `reset-instance-identity` (spec 03 §17.5): typed confirmation of the instance id, then one transaction. */
    private fun resetIdentity(a: HostCli.Args) {
        val instanceId = s.db.read { c -> s.instance.instanceId(c) }
        if (a.opt("confirm") != instanceId) {
            throw HostCli.Refused(
                "this demotes the operator, deletes the card chain and mints a new setup link; every client and every store " +
                    "build must re-pin. Re-run with --confirm $instanceId",
            )
        }
        val minted = s.db.tx { c -> s.instance.resetIdentity(c, s.audit) }
        out.println("The old operator is now a member and the card chain is gone. New setup link:")
        out.println(minted.url)
    }

    /** `disable <email> [--reason abuse|request|other]`, `enable <email>`: as the panel (spec 03 §7.1). */
    private fun setStatus(cmd: String, a: HostCli.Args) {
        val email = a.positional.getOrNull(1)?.let { Grammar.emailOrNull(it) } ?: throw HostCli.Usage("andvari admin $cmd <email>")
        // The panel refuses any other reason (spec 03 §7.1); so does the command, since the reason reaches the person's mail.
        val reason = a.opt("reason") ?: "other"
        if (reason !in setOf("abuse", "request", "other")) throw HostCli.Usage("andvari admin disable <email> [--reason abuse|request|other]")
        val accounts = Accounts(s)
        s.db.tx { c ->
            val userId = c.queryOne("SELECT userId FROM users WHERE email=?", email) { it.getString(1) } ?: throw HostCli.Refused("no account with that address")
            if (cmd == "disable") {
                if (c.queryOne("SELECT 1 FROM users WHERE userId=? AND role='operator'", userId) { 1 } != null) throw HostCli.Refused("the operator account cannot be disabled")
                accounts.disable(c, userId, reason, null, null)
            } else {
                accounts.enable(c, userId, null, null)
            }
        }
        out.println("${cmd}d")
    }
}
