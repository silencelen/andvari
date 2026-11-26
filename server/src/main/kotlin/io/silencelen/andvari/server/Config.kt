package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.InstanceKind
import io.silencelen.andvari.core.model.wire.SignupMode
import io.silencelen.andvari.core.model.wire.WireGrammar
import java.io.File

/** A configuration the server refuses to start with. */
class ConfigError(message: String) : Exception(message)

/**
 * Server configuration from the environment (spec 03 §1.1, §14.4; design §7.1). The environment is the
 * source of truth for the instance's stance and is read at boot; the operator panel can only tighten
 * what it allows (spec 03 §7.2). `andvari setup` writes `andvari.env`; tests build a [Config] directly.
 *
 * The constructor enforces every boot rule ([check]): an instance that would contradict the spec does
 * not start, rather than starting half-armed.
 */
class Config(
    val host: String = "127.0.0.1",
    val port: Int = 8080,
    val dbPath: String,
    val blobDir: String,
    val webDir: String? = null,
    val downloadsDir: String? = null,
    /** `ANDVARI_CANONICAL_ORIGIN`: the instance's one origin (spec 03 preamble), in the `origin` grammar. */
    val canonicalOrigin: String,
    /** `ANDVARI_INSTANCE_KIND` (spec 03 §14.4). */
    val instanceKind: String = InstanceKind.PRIVATE,
    /** `ANDVARI_INSTANCE_NAME`: decorative only (§1.1); the signed name is the card's. */
    val instanceName: String? = null,
    val selfHostDocsUrl: String? = null,
    /** 32-byte X25519 recovery public key, or empty: `ANDVARI_RECOVERY_PUBKEY`. Never on a public instance. */
    val recoveryPublicKey: ByteArray = ByteArray(0),
    /** `ANDVARI_RECOVERY_FINGERPRINT`: hex SHA-256 of [recoveryPublicKey], or empty. */
    val recoveryFingerprint: String = "",
    /** `ANDVARI_ENUM_SECRET`: fake prelogin salts (spec 01 §3). */
    val enumSecret: ByteArray,
    /** `ANDVARI_SIGNUP_SECRET`: the 32-byte key of sign-up and recovery-request code MACs (§14.1). */
    val signupSecret: ByteArray? = null,
    val signupMode: String = SignupMode.LINKS,
    val signupCap: Long = 200,
    val signupDailyMax: Long = 25,
    val signupPowBits: Int = 0,
    /** Refused email domains (lowercase), from the `ANDVARI_SIGNUP_BLOCKLIST` file. */
    val signupBlocklist: Set<String> = emptySet(),
    val requireAgeConfirm: Boolean = false,
    /** `ANDVARI_REGISTER_LINKS`: `members` or `operator`; null takes the kind's default (§14.4). */
    registerLinks: String? = null,
    val totpRequired: Boolean = false,
    val offlineCacheAllowedFloor: Boolean = true,
    val forceHsts: Boolean = false,
    val loginRatePerMin: Int = 5,
    val pushRatePerMin: Int = 120,
    val itemMaxBytes: Long = 2L * 1024 * 1024,
    val quotaAccountBytes: Long = 104_857_600L,
    val quotaItems: Long = 5_000L,
    val quotaOwnedSharedVaults: Long = 50L,
    val quotaOpenLinks: Long = 20L,
    val vaultGraceDays: Int = 7,
    val janitorDryRun: Boolean = false,
    /** Production KDF floor (spec 01 §9); 0/0 = off, for fast-parameter tests. */
    val minKdfMemBytes: Long = 0,
    val minKdfOps: Long = 0,
    val trustedIpHeaders: List<String> = listOf("X-Forwarded-For"),
    val trustedProxyCidrs: List<String> = listOf("127.0.0.0/8", "::1/128"),
    val uploadMaxConcurrentPerUser: Int = 4,
    val requestReadTimeoutSeconds: Int = 0,
    val responseWriteTimeoutSeconds: Int = 0,
    // ---- mail transport (spec 03 §14.5) ----
    val smtpHost: String? = null,
    val smtpPort: Int = 587,
    val smtpUser: String? = null,
    val smtpPass: String? = null,
    val smtpFrom: String? = null,
    val graphTenantId: String? = null,
    val graphClientId: String? = null,
    val graphClientSecret: String? = null,
    val graphSender: String? = null,
    // ---- test mode (spec 03 §14.4) ----
    val testMode: Boolean = false,
    val mailSinkDir: String? = null,
    val testClockFile: String? = null,
    /**
     * Where the warnings about these settings go (the plain-http line): standard error, as the server's start and the
     * other host commands print them; `andvari admin backup` passes nothing, since a run of it that works prints nothing.
     */
    warn: (String) -> Unit = { System.err.println(it) },
) {
    /** Who may create register links (spec 03 §15.2): `members` only on a private instance that allows it. */
    val registerLinks: String = when {
        instanceKind == InstanceKind.PUBLIC -> "operator"
        registerLinks == null -> "members"
        else -> registerLinks
    }

    val isPublic: Boolean get() = instanceKind == InstanceKind.PUBLIC

    /**
     * The keyed hash of a typed address that the server's records keep ([ServerCrypto.addressHash]), keyed from
     * [enumSecret]. No setting of its own: the secret is the one `andvari host init` writes into the 0600 env file.
     */
    fun addressHash(emailNorm: String): String = ServerCrypto.addressHash(enumSecret, emailNorm)

    /**
     * The grace a `delete` starts (spec 03 §11.1, `ANDVARI_VAULT_GRACE_DAYS`): the one place its length is
     * computed. The append stores `purgeAt = deletedAt + vaultGraceMs`; every answer that tells a client the
     * grace's end reads that stored `purgeAt`, so they all agree and none recomputes it.
     */
    val vaultGraceMs: Long get() = vaultGraceDays * Clock.DAY_MS

    /** True when this instance offers operator recovery at all: private, with a recovery key. */
    val recoveryConfigured: Boolean get() = !isPublic && recoveryPublicKey.size == 32 && recoveryFingerprint.isNotEmpty()

    /** `recoveryFp` as card 0 must carry it (spec 03 §17.2): the fingerprint, or `none`. */
    val recoveryFpOrNone: String get() = if (recoveryConfigured) recoveryFingerprint else "none"

    val smtpConfigured: Boolean
        get() = !smtpHost.isNullOrBlank() && !smtpUser.isNullOrBlank() && !smtpPass.isNullOrBlank() && !smtpFrom.isNullOrBlank()
    val graphConfigured: Boolean
        get() = !graphTenantId.isNullOrBlank() && !graphClientId.isNullOrBlank() && !graphClientSecret.isNullOrBlank() && !graphSender.isNullOrBlank()

    /** A mail transport exists: Graph, SMTP, or (test mode only) the sink. */
    val mailConfigured: Boolean get() = graphConfigured || smtpConfigured || (testMode && mailSinkDir != null)

    init { check(warn) }

    /**
     * Every boot rule. Each one is a place where a running server would otherwise contradict the spec:
     *  - the origin must satisfy the `origin` grammar (spec 03 §1.1);
     *  - an https origin needs `ANDVARI_FORCE_HSTS=1` (§1.1: mandatory whenever the origin is https);
     *  - test mode only on a loopback http origin, and the sink and test clock only in test mode (§14.4);
     *  - `open` needs a mail transport and a sign-up secret (§14.4, §14.1);
     *  - a public instance never carries a recovery key: variant R can never be switched into operator
     *    recovery by configuration alone (§18.6);
     *  - the recovery fingerprint must be the key's own SHA-256 (spec 04 §1).
     */
    private fun check(warn: (String) -> Unit) {
        if (!WireGrammar.isOrigin(canonicalOrigin)) throw ConfigError("ANDVARI_CANONICAL_ORIGIN must be an https address with a domain name (got '$canonicalOrigin'): andvari needs an https address with a domain name for this server.")
        if (instanceKind != InstanceKind.PUBLIC && instanceKind != InstanceKind.PRIVATE) throw ConfigError("ANDVARI_INSTANCE_KIND must be public or private")
        if (signupMode !in setOf(SignupMode.OPEN, SignupMode.LINKS, SignupMode.CLOSED)) throw ConfigError("ANDVARI_SIGNUP_MODE must be open, links or closed")
        if (registerLinks !in setOf("members", "operator")) throw ConfigError("ANDVARI_REGISTER_LINKS must be members or operator")
        val loopbackOrigin = canonicalOrigin.startsWith("http://")
        if (canonicalOrigin.startsWith("https://") && !forceHsts) throw ConfigError("ANDVARI_FORCE_HSTS=1 is mandatory for an https origin")
        if (testMode && !loopbackOrigin) throw ConfigError("ANDVARI_TEST_MODE=1 is refused unless ANDVARI_CANONICAL_ORIGIN is http://localhost[:port] or http://127.0.0.1[:port]")
        if (!testMode && (mailSinkDir != null || testClockFile != null)) throw ConfigError("ANDVARI_MAIL_SINK and ANDVARI_TEST_CLOCK exist only in test mode")
        if (!testMode && loopbackOrigin) warn("[andvari] WARNING: a plain-http origin is for development only")
        if (signupMode == SignupMode.OPEN && !mailConfigured) throw ConfigError("ANDVARI_SIGNUP_MODE=open refuses to start without a mail transport")
        if (signupMode == SignupMode.OPEN && signupSecret == null) throw ConfigError("ANDVARI_SIGNUP_MODE=open needs ANDVARI_SIGNUP_SECRET (32 random bytes, base64url)")
        if (signupSecret != null && signupSecret.size != 32) throw ConfigError("ANDVARI_SIGNUP_SECRET must decode to exactly 32 bytes")
        if (enumSecret.size < 32) throw ConfigError("ANDVARI_ENUM_SECRET must decode to at least 32 bytes")
        if (signupPowBits !in 0..32) throw ConfigError("ANDVARI_SIGNUP_POW_BITS must be 0..32")
        if (recoveryPublicKey.isNotEmpty() && recoveryPublicKey.size != 32) throw ConfigError("ANDVARI_RECOVERY_PUBKEY must be a 32-byte X25519 public key")
        if (isPublic && (recoveryPublicKey.isNotEmpty() || recoveryFingerprint.isNotEmpty())) {
            throw ConfigError("a public instance has no operator recovery (variant R): unset ANDVARI_RECOVERY_PUBKEY and ANDVARI_RECOVERY_FINGERPRINT")
        }
        if (recoveryPublicKey.isNotEmpty() != recoveryFingerprint.isNotEmpty()) throw ConfigError("set both ANDVARI_RECOVERY_PUBKEY and ANDVARI_RECOVERY_FINGERPRINT, or neither")
        if (recoveryPublicKey.size == 32 && recoveryFingerprint != sha256Hex(recoveryPublicKey)) {
            throw ConfigError("ANDVARI_RECOVERY_FINGERPRINT is not the SHA-256 of ANDVARI_RECOVERY_PUBKEY")
        }
        if (quotaAccountBytes <= 0 || quotaItems <= 0 || quotaOwnedSharedVaults < 0 || quotaOpenLinks < 0) throw ConfigError("quota defaults must be positive")
        // A hashing-cost floor the server cannot apply stops the start (decided on 2026-11-17): the three limits are KdfLimits'.
        KdfLimits.problem("ANDVARI_MIN_KDF_OPS", minKdfOps, "passes")?.let { throw ConfigError(it) }
        KdfLimits.problem("ANDVARI_MIN_KDF_MEM", minKdfMemBytes, "bytes")?.let { throw ConfigError(it) }
        // Row 91 serves every regular file directly inside ANDVARI_DOWNLOADS_DIR to anyone. Pointed at the directory
        // that holds the database (with its -wal and -shm) or at the blob directory, it would hand out the whole
        // instance: emails, verifiers, two-step secrets, every ciphertext.
        downloadsDir?.let { d ->
            fun dir(p: String): File = File(p).absoluteFile.normalize().let { f -> runCatching { f.canonicalFile }.getOrDefault(f) }
            val served = dir(d)
            val dbDir = dir(dbPath).parentFile
            if (served == dbDir || served == dir(blobDir)) {
                throw ConfigError("ANDVARI_DOWNLOADS_DIR must be a directory of its own: everything directly in it is served to anyone, and $d holds the database or the blobs")
            }
        }
    }

    /** Parsed once: the operator-declared trusted proxies (spec 03 §8). [fromEnv] refuses a malformed entry; one in a [Config] built directly is dropped (fail closed). */
    internal val trustedProxyNets: List<CidrBlock> by lazy { trustedProxyCidrs.mapNotNull { CidrBlock.parse(it) } }

    companion object {
        /** Every `ANDVARI_*` variable the server reads; anything else is an env problem (spec 03 §1.1). */
        val KNOWN_ENV: Set<String> = setOf(
            "ANDVARI_HOST", "ANDVARI_PORT", "ANDVARI_DB", "ANDVARI_BLOB_DIR", "ANDVARI_WEB_DIR", "ANDVARI_DOWNLOADS_DIR",
            "ANDVARI_CANONICAL_ORIGIN", "ANDVARI_INSTANCE_KIND", "ANDVARI_INSTANCE_NAME", "ANDVARI_SELFHOST_DOCS_URL",
            "ANDVARI_RECOVERY_PUBKEY", "ANDVARI_RECOVERY_FINGERPRINT", "ANDVARI_ENUM_SECRET", "ANDVARI_SIGNUP_SECRET",
            "ANDVARI_SIGNUP_MODE", "ANDVARI_SIGNUP_CAP", "ANDVARI_SIGNUP_DAILY_MAX", "ANDVARI_SIGNUP_POW_BITS",
            "ANDVARI_SIGNUP_BLOCKLIST", "ANDVARI_REQUIRE_AGE_CONFIRM", "ANDVARI_REGISTER_LINKS", "ANDVARI_TOTP_REQUIRED",
            "ANDVARI_OFFLINE_CACHE_ALLOWED", "ANDVARI_FORCE_HSTS", "ANDVARI_LOGIN_RATE_PER_MIN", "ANDVARI_PUSH_RATE_PER_MIN",
            "ANDVARI_ITEM_MAX_BYTES", "ANDVARI_QUOTA_ACCOUNT_BYTES", "ANDVARI_QUOTA_ITEMS", "ANDVARI_QUOTA_OWNED_SHARED_VAULTS",
            "ANDVARI_QUOTA_OPEN_LINKS", "ANDVARI_VAULT_GRACE_DAYS", "ANDVARI_JANITOR_DRYRUN", "ANDVARI_MIN_KDF_MEM",
            "ANDVARI_MIN_KDF_OPS", "ANDVARI_TRUSTED_IP_HEADERS", "ANDVARI_TRUSTED_PROXY_CIDRS", "ANDVARI_UPLOAD_MAX_CONCURRENT",
            "ANDVARI_REQUEST_READ_TIMEOUT_S", "ANDVARI_RESPONSE_WRITE_TIMEOUT_S", "ANDVARI_SMTP_HOST", "ANDVARI_SMTP_PORT",
            "ANDVARI_SMTP_USER", "ANDVARI_SMTP_PASS", "ANDVARI_SMTP_FROM", "ANDVARI_GRAPH_TENANT", "ANDVARI_GRAPH_CLIENT_ID",
            "ANDVARI_GRAPH_CLIENT_SECRET", "ANDVARI_GRAPH_SENDER", "ANDVARI_TEST_MODE", "ANDVARI_MAIL_SINK",
            "ANDVARI_TEST_CLOCK", "ANDVARI_STRICT_ENV",
        )

        internal val NUM_RANGES: Map<String, LongRange> = mapOf(
            "ANDVARI_PORT" to 1L..65_535L,
            "ANDVARI_SMTP_PORT" to 1L..65_535L,
            "ANDVARI_SIGNUP_CAP" to 0L..10_000_000L,
            "ANDVARI_SIGNUP_DAILY_MAX" to 0L..10_000_000L,
            "ANDVARI_SIGNUP_POW_BITS" to 0L..32L,
            "ANDVARI_LOGIN_RATE_PER_MIN" to 1L..100_000L,
            "ANDVARI_PUSH_RATE_PER_MIN" to 1L..100_000L,
            "ANDVARI_ITEM_MAX_BYTES" to 1_024L..(8L * 1024 * 1024),
            "ANDVARI_QUOTA_ACCOUNT_BYTES" to 1L..(1L shl 44),
            "ANDVARI_QUOTA_ITEMS" to 1L..100_000_000L,
            "ANDVARI_QUOTA_OWNED_SHARED_VAULTS" to 0L..1_000_000L,
            "ANDVARI_QUOTA_OPEN_LINKS" to 0L..1_000_000L,
            "ANDVARI_VAULT_GRACE_DAYS" to 0L..3_650L,
            "ANDVARI_MIN_KDF_MEM" to KdfLimits.CONFIG_MEM_BYTES,
            "ANDVARI_MIN_KDF_OPS" to KdfLimits.CONFIG_OPS,
            "ANDVARI_UPLOAD_MAX_CONCURRENT" to 1L..1_024L,
            "ANDVARI_REQUEST_READ_TIMEOUT_S" to 0L..86_400L,
            "ANDVARI_RESPONSE_WRITE_TIMEOUT_S" to 0L..86_400L,
        )
        internal val BOOL_ENV = setOf(
            "ANDVARI_REQUIRE_AGE_CONFIRM", "ANDVARI_TOTP_REQUIRED", "ANDVARI_OFFLINE_CACHE_ALLOWED", "ANDVARI_FORCE_HSTS",
            "ANDVARI_JANITOR_DRYRUN", "ANDVARI_TEST_MODE", "ANDVARI_STRICT_ENV",
        )
        internal val ENUM_ENV: Map<String, Set<String>> = mapOf(
            "ANDVARI_SIGNUP_MODE" to setOf("open", "links", "closed"),
            "ANDVARI_INSTANCE_KIND" to setOf("public", "private"),
            "ANDVARI_REGISTER_LINKS" to setOf("members", "operator"),
        )

        fun parseBool(v: String?): Boolean? = when {
            v == null -> null
            v == "1" || v.equals("true", ignoreCase = true) -> true
            v == "0" || v.equals("false", ignoreCase = true) -> false
            else -> null
        }

        /** Unknown or invalid `ANDVARI_*` values (boot warns; `ANDVARI_STRICT_ENV=1` exits). Pure. */
        fun envLint(env: Map<String, String>): List<String> {
            val problems = mutableListOf<String>()
            for (name in env.keys.filter { it.startsWith("ANDVARI_") }.sorted()) {
                if (name !in KNOWN_ENV) problems += "unknown env var $name (typo? renamed?)"
            }
            for ((name, range) in NUM_RANGES) env[name]?.let { v ->
                val n = v.trim().toLongOrNull()
                if (n == null || n !in range) problems += "invalid $name: '$v' (want ${range.first}..${range.last})"
            }
            for (name in BOOL_ENV) env[name]?.let { if (parseBool(it) == null) problems += "invalid $name: '$it' (use 1/0)" }
            for ((name, values) in ENUM_ENV) env[name]?.let { if (it.trim() !in values) problems += "invalid $name: '$it' (one of ${values.joinToString("|")})" }
            env["ANDVARI_TRUSTED_PROXY_CIDRS"]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }?.forEach {
                if (CidrBlock.parse(it) == null) problems += "invalid ANDVARI_TRUSTED_PROXY_CIDRS entry '$it'"
            }
            return problems
        }

        /**
         * A number setting as the operator set it, never the default in its place (decided on 2026-11-17): unset or blank
         * is the default; a value that is not a whole number, or one outside the setting's range, stops the start with a
         * line that names the setting, the value and the range. Before, both quietly took the default, with a warning at
         * most: a sign-up cap meant lower could be raised, proof of work turned off.
         */
        private fun num(env: (String) -> String?, name: String, default: Long): Long {
            val raw = env(name)?.trim()?.takeIf { it.isNotEmpty() } ?: return default
            val range = NUM_RANGES.getValue(name)
            val n = raw.toLongOrNull()
                ?: throw ConfigError("$name='$raw' is not a whole number (the configuration accepts ${range.first}..${range.last}); the server will not take the default in its place")
            if (n !in range) throw ConfigError("$name=$n is outside the range the configuration accepts (${range.first}..${range.last}); the server will not take the default in its place")
            return n
        }

        /**
         * A switch as the operator set it (decided on 2026-11-17): unset or blank is the default; `1`, `true`, `0` or `false`
         * (any case, spaces around ignored) are read; anything else stops the start with a line that names it. Before,
         * anything else took the default: "yes" for `ANDVARI_TOTP_REQUIRED` turned required two-step sign-in OFF.
         */
        private fun bool(env: (String) -> String?, name: String, default: Boolean): Boolean {
            val raw = env(name)?.trim()?.takeIf { it.isNotEmpty() } ?: return default
            return parseBool(raw)
                ?: throw ConfigError("$name='$raw' is neither on nor off (use 1 or true, 0 or false); the server will not take the default in its place")
        }

        /** A setting with a closed list of values: unset or blank is the default; anything else must be on the list. */
        private fun choice(env: (String) -> String?, name: String, default: String?): String? {
            val raw = env(name)?.trim()?.takeIf { it.isNotEmpty() } ?: return default
            val values = ENUM_ENV.getValue(name)
            if (raw !in values) throw ConfigError("$name='$raw' is not one of ${values.joinToString(", ")}; the server will not take the default in its place")
            return raw
        }

        /** A text setting: unset or blank is null (the caller's default, if it has one); otherwise the value as written. */
        private fun text(env: (String) -> String?, name: String): String? = env(name)?.takeIf { it.isNotBlank() }

        /**
         * A comma-separated list: unset is [default]. A value that is present but blank (or only commas and spaces) is the
         * empty list, which for both lists the server reads means "none", as it always has (decided on 2026-11-17: a blank
         * value keeps the meaning it had): a blank `ANDVARI_TRUSTED_PROXY_CIDRS` trusts no proxy, and a blank
         * `ANDVARI_TRUSTED_IP_HEADERS` reads no forwarded header (docs/self-hosting.md). For a while a blank list took the
         * default instead, which trusted loopback proxies an operator had switched off.
         */
        private fun list(env: (String) -> String?, name: String, default: List<String>): List<String> {
            val raw = env(name) ?: return default
            return raw.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        }

        /**
         * The trusted proxies (spec 03 §8): every entry must be an address block. Before, an entry that was not one was
         * dropped, so a typo quietly trusted fewer proxies than the operator listed; now it stops the start, naming it.
         */
        private fun proxies(env: (String) -> String?): List<String> {
            val name = "ANDVARI_TRUSTED_PROXY_CIDRS"
            val entries = list(env, name, listOf("127.0.0.0/8", "::1/128"))
            entries.firstOrNull { CidrBlock.parse(it) == null }?.let {
                throw ConfigError("$name entry '$it' is not an address block (such as 10.0.0.0/8 or fd00::/8); the server will not drop it and go on")
            }
            return entries
        }

        /**
         * A hashing-cost floor as the operator set it, never the default in its place (decided on 2026-11-17): unset or
         * blank is the default; a value that is not a whole number stops the start here, and one outside [KdfLimits]'s
         * ranges stops it at [check], each with a line that names the value and the range. Before, both were replaced by
         * the default, which lowered the floor the operator meant to raise.
         */
        private fun floor(env: (String) -> String?, name: String, default: Long, unit: String): Long {
            val raw = env(name)?.trim()?.takeIf { it.isNotEmpty() } ?: return default
            val range = NUM_RANGES.getValue(name)
            return raw.toLongOrNull()
                ?: throw ConfigError("$name='$raw' is not a whole number (the configuration accepts ${range.first}..${range.last} $unit); the server will not take the default in its place")
        }

        /** Read the blocklist file: one domain per line, `#` comments, lowercase. A missing file is a boot error. */
        fun readBlocklist(path: String): Set<String> {
            val f = File(path)
            if (!f.isFile) throw ConfigError("ANDVARI_SIGNUP_BLOCKLIST names no file: $path")
            return f.readLines().map { it.substringBefore('#').trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
        }

        fun fromEnv(env: (String) -> String? = System::getenv): Config = fromEnv(env) { System.err.println(it) }

        /** [fromEnv] with the settings' warnings given to [warn] instead of standard error. */
        fun fromEnv(env: (String) -> String?, warn: (String) -> Unit): Config {
            fun b64(name: String): ByteArray? = env(name)?.trim()?.takeIf { it.isNotEmpty() }?.let {
                runCatching { Bytes.fromB64(it) }.getOrElse { throw ConfigError("$name is not base64url") }
            }
            val enumSecret = b64("ANDVARI_ENUM_SECRET") ?: throw ConfigError("ANDVARI_ENUM_SECRET must be set (32 random bytes, base64url)")
            val testMode = bool(env, "ANDVARI_TEST_MODE", false)
            // Read by the start before the configuration (Main), and checked here with every other switch.
            bool(env, "ANDVARI_STRICT_ENV", false)
            return Config(
                host = text(env, "ANDVARI_HOST") ?: "127.0.0.1",
                port = num(env, "ANDVARI_PORT", 8080).toInt(),
                dbPath = text(env, "ANDVARI_DB") ?: "andvari.db",
                blobDir = text(env, "ANDVARI_BLOB_DIR") ?: "blobs",
                webDir = text(env, "ANDVARI_WEB_DIR"),
                downloadsDir = text(env, "ANDVARI_DOWNLOADS_DIR"),
                canonicalOrigin = text(env, "ANDVARI_CANONICAL_ORIGIN") ?: throw ConfigError("ANDVARI_CANONICAL_ORIGIN must be set"),
                instanceKind = choice(env, "ANDVARI_INSTANCE_KIND", InstanceKind.PRIVATE)!!,
                instanceName = text(env, "ANDVARI_INSTANCE_NAME"),
                selfHostDocsUrl = text(env, "ANDVARI_SELFHOST_DOCS_URL"),
                recoveryPublicKey = b64("ANDVARI_RECOVERY_PUBKEY") ?: ByteArray(0),
                recoveryFingerprint = env("ANDVARI_RECOVERY_FINGERPRINT")?.trim() ?: "",
                enumSecret = enumSecret,
                signupSecret = b64("ANDVARI_SIGNUP_SECRET"),
                signupMode = choice(env, "ANDVARI_SIGNUP_MODE", SignupMode.LINKS)!!,
                signupCap = num(env, "ANDVARI_SIGNUP_CAP", 200),
                signupDailyMax = num(env, "ANDVARI_SIGNUP_DAILY_MAX", 25),
                signupPowBits = num(env, "ANDVARI_SIGNUP_POW_BITS", 0).toInt(),
                signupBlocklist = text(env, "ANDVARI_SIGNUP_BLOCKLIST")?.let { readBlocklist(it) } ?: emptySet(),
                requireAgeConfirm = bool(env, "ANDVARI_REQUIRE_AGE_CONFIRM", false),
                registerLinks = choice(env, "ANDVARI_REGISTER_LINKS", null),
                totpRequired = bool(env, "ANDVARI_TOTP_REQUIRED", false),
                offlineCacheAllowedFloor = bool(env, "ANDVARI_OFFLINE_CACHE_ALLOWED", true),
                forceHsts = bool(env, "ANDVARI_FORCE_HSTS", false),
                loginRatePerMin = num(env, "ANDVARI_LOGIN_RATE_PER_MIN", 5).toInt(),
                pushRatePerMin = num(env, "ANDVARI_PUSH_RATE_PER_MIN", 120).toInt(),
                itemMaxBytes = num(env, "ANDVARI_ITEM_MAX_BYTES", 2L * 1024 * 1024),
                quotaAccountBytes = num(env, "ANDVARI_QUOTA_ACCOUNT_BYTES", 104_857_600L),
                quotaItems = num(env, "ANDVARI_QUOTA_ITEMS", 5_000L),
                quotaOwnedSharedVaults = num(env, "ANDVARI_QUOTA_OWNED_SHARED_VAULTS", 50L),
                quotaOpenLinks = num(env, "ANDVARI_QUOTA_OPEN_LINKS", 20L),
                vaultGraceDays = num(env, "ANDVARI_VAULT_GRACE_DAYS", 7).toInt(),
                janitorDryRun = bool(env, "ANDVARI_JANITOR_DRYRUN", false),
                minKdfMemBytes = floor(env, "ANDVARI_MIN_KDF_MEM", 67_108_864L, "bytes"),
                minKdfOps = floor(env, "ANDVARI_MIN_KDF_OPS", 3L, "passes"),
                trustedIpHeaders = list(env, "ANDVARI_TRUSTED_IP_HEADERS", listOf("X-Forwarded-For")),
                trustedProxyCidrs = proxies(env),
                uploadMaxConcurrentPerUser = num(env, "ANDVARI_UPLOAD_MAX_CONCURRENT", 4).toInt(),
                requestReadTimeoutSeconds = num(env, "ANDVARI_REQUEST_READ_TIMEOUT_S", 0).toInt(),
                responseWriteTimeoutSeconds = num(env, "ANDVARI_RESPONSE_WRITE_TIMEOUT_S", 0).toInt(),
                smtpHost = text(env, "ANDVARI_SMTP_HOST"),
                smtpPort = num(env, "ANDVARI_SMTP_PORT", 587).toInt(),
                smtpUser = text(env, "ANDVARI_SMTP_USER"),
                smtpPass = text(env, "ANDVARI_SMTP_PASS"),
                smtpFrom = text(env, "ANDVARI_SMTP_FROM"),
                graphTenantId = text(env, "ANDVARI_GRAPH_TENANT"),
                graphClientId = text(env, "ANDVARI_GRAPH_CLIENT_ID"),
                graphClientSecret = text(env, "ANDVARI_GRAPH_CLIENT_SECRET"),
                graphSender = text(env, "ANDVARI_GRAPH_SENDER"),
                testMode = testMode,
                mailSinkDir = text(env, "ANDVARI_MAIL_SINK"),
                testClockFile = text(env, "ANDVARI_TEST_CLOCK"),
                warn = warn,
            )
        }
    }
}
