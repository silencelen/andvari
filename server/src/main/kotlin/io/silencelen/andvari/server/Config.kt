package io.silencelen.andvari.server

import io.silencelen.andvari.core.client.EnrollLink
import io.silencelen.andvari.core.crypto.Bytes

/**
 * Server config from environment (spec 04 §2: recovery pubkey/fingerprint pinned
 * here). ANDVARI_* env with dev defaults; production values live in the LXC's
 * /etc/andvari/andvari.env (systemd EnvironmentFile), never in git.
 */
class Config(
    val host: String,
    val port: Int,
    val dbPath: String,
    val blobDir: String,
    val webDir: String?,
    val downloadsDir: String? = null,
    val recoveryPublicKey: ByteArray,
    val recoveryFingerprint: String,
    val enumSecret: ByteArray,
    val publicHostname: String?,
    val bootstrapToken: String?,
    // Minimum Argon2id strength the server will PERSIST at enrollment / re-key (spec 01 §9,
    // spec 05 T8: "policy enforces minimum strength at enrollment"). Default 0/0 = off so
    // fast-param integration tests are unaffected; fromEnv() sets the production floor.
    val minKdfMemBytes: Long = 0,
    val minKdfOps: Long = 0,
    // Forwarded-IP headers trusted for rate keys + audit ip ONLY when the direct peer is
    // loopback (tailscale serve / cloudflared both terminate on 127.0.0.1); raw XFF from
    // a non-loopback peer is never trusted (spec 03 §8).
    val trustedIpHeaders: List<String> = DEFAULT_TRUSTED_IP_HEADERS,
    // Cap on concurrent streaming uploads per user; in-flight .part bytes also count
    // toward the user quota mid-stream (LOW-6).
    val uploadMaxConcurrentPerUser: Int = 4,
    // Netty request-read timeout, seconds (0 = off). Stays OFF until idle-WS survival
    // under the timeout is verified on the deployment (ping keepalive vs Netty reaper).
    val requestReadTimeoutSeconds: Int = 0,
    // Netty response-WRITE timeout, seconds (0 = off). Netty's built-in default is 10 s,
    // which severs any response that takes >10 s to flush to a SLOW client — truncating
    // large installer downloads (the .msi/.deb) proxied to DERP-relayed clients mid-body
    // ("ReverseProxy read error during body copy: unexpected EOF"). Default OFF so a slow
    // drain can't sever a legitimate large download; set the env to re-arm a finite reaper.
    val responseWriteTimeoutSeconds: Int = 0,
    // Vault lifecycle (spec 03 §11): soft-delete grace before the janitor purges, and
    // the ownership-transfer offer TTL. Env-tunable, not schema.
    val vaultGraceDays: Int = 7,
    val transferTtlDays: Int = 14,
    // Log-only janitor mode for the first armed week (design §14.1): sweeps run and log
    // what they WOULD purge/expire but destroy nothing.
    val janitorDryRun: Boolean = false,
    // cut 4 email-invite (all absent by default → the feature is inert). SMTP submission via a relay
    // (the household M365 tenant: smtp.office365.com:587). inviteBaseUrl is the DEPRECATED alias of
    // canonicalOrigin (multi-tenant design 2026-07-15 §3): the canonical origin the emailed enroll
    // link embeds; it MUST equal the browser's location.origin (no trailing slash / :443 / uppercase),
    // validated by canonicalOriginIssue().
    val smtpHost: String? = null,
    val smtpPort: Int = 587,
    val smtpUser: String? = null,
    val smtpPass: String? = null,
    val smtpFrom: String? = null,
    val inviteBaseUrl: String? = null,
    // cut 4 alt transport: Microsoft Graph app-only sendMail (client-credentials) — PREFERRED over
    // SMTP when set (no SMTP AUTH / no stored mailbox password). graphSender = the from-mailbox UPN.
    val graphTenantId: String? = null,
    val graphClientId: String? = null,
    val graphClientSecret: String? = null,
    val graphSender: String? = null,
    // ---- multi-tenant / endpoint-agnostic pivot (design 2026-07-15 §2.1) ----
    // Operator-declared instance stance, overlaid onto ClientPolicy by Service.policy() on every
    // read and STRIPPED on every admin write — env-owned, never admin-settable. All trailing +
    // defaulted so the ~15 positional test constructions compile unchanged, and the defaults
    // reproduce today's behavior exactly (deploy-inert until the operator sets the new env vars).
    val signupMode: String = "invite-only", // §2.1 enum: closed | invite-only | landing | open(reserved)
    val totpRequired: Boolean = false, // §2.6 per-instance login-factor stance
    val instanceName: String? = null, // decorative label — NEVER a verified identity (§2.3)
    // canonicalOrigin/selfHostDocsUrl are plain params (not vals): the public properties below
    // resolve the deprecated-alias fallback and the derived default ONCE at construction.
    canonicalOrigin: String? = null,
    selfHostDocsUrl: String? = null,
    // §2.2 tighten-only floor: env false forces offlineCacheAllowed=false in the declared policy;
    // env true (default) leaves the admin-stored knob in charge. The env can forbid, never force-allow.
    val offlineCacheAllowedFloor: Boolean = true,
    // §7.2: emit HSTS even off the break-glass origin (single-origin TLS instances; the reference
    // sets ANDVARI_FORCE_HSTS=1). Default off so plain-http LAN dev is never pinned to HTTPS.
    val forceHsts: Boolean = false,
    // §2.5 (B1-3): flat per-IP login bucket, decoupled from origin. Default 5 = the old PUBLIC
    // tightness; the old private-origin relaxation to 10/min is deliberately revoked.
    val loginRatePerMin: Int = 5,
) {
    /**
     * §3: the instance's canonical public origin — used as the invite-minting origin AND declared
     * (decoratively) in ClientPolicy. ANDVARI_CANONICAL_ORIGIN, with the deprecated
     * ANDVARI_INVITE_BASE_URL honored as a fallback alias ([envLint] emits the deprecation note at
     * boot). NB: the initializer reads the CONSTRUCTOR PARAMS (in scope here), not this property.
     */
    val canonicalOrigin: String? = canonicalOrigin ?: inviteBaseUrl

    /** §2.1: where /client-policy points strangers for self-hosting; defaults to
     *  `<canonicalOrigin>/selfhost` (the real route App.kt registers before the SPA fallback). */
    val selfHostDocsUrl: String? = selfHostDocsUrl ?: (canonicalOrigin ?: inviteBaseUrl)?.let { "$it/selfhost" }

    val escrowConfigured: Boolean get() = recoveryPublicKey.size == 32 && recoveryFingerprint.isNotEmpty()

    val smtpConfigured: Boolean
        get() = !smtpHost.isNullOrBlank() && !smtpUser.isNullOrBlank() && !smtpPass.isNullOrBlank() && !smtpFrom.isNullOrBlank()
    val graphConfigured: Boolean
        get() = !graphTenantId.isNullOrBlank() && !graphClientId.isNullOrBlank() && !graphClientSecret.isNullOrBlank() && !graphSender.isNullOrBlank()

    /** cut 4: email-invite is enabled ONLY when a transport (SMTP or Graph) is fully configured AND a
     *  usable canonical origin is present. Any gap ⇒ the Admin "email this invite" checkbox
     *  is disabled and a sendEmail request is a no-op — fail-safe, never a hard error (breaker NIT). */
    val emailConfigured: Boolean
        get() = (smtpConfigured || graphConfigured) && canonicalOriginIssue() == null

    /** null = the resolved [canonicalOrigin] is a usable canonical origin; else a human reason (logged
     *  at boot; a strict-env boot problem in [envLint]). Formerly inviteBaseUrlIssue() — renamed with
     *  the var (design 2026-07-15 §3); the checks are shared with [envLint] via [originIssue]. */
    fun canonicalOriginIssue(): String? = originIssue(canonicalOrigin, publicHostname)

    companion object {
        /**
         * §3: canonicalOrigin validation, shared by [canonicalOriginIssue] (runtime, resolved config)
         * and [envLint] (boot, raw env). Catches breaker B2 (a config typo → every emailed invite
         * dead-on-arrival), A5 (topology-conditional: only fires in the dual-origin break-glass
         * topology — never on single-origin instances, where publicHostname is unset), and the NEW
         * https-for-non-local rule (an emailed enroll link is a bearer credential; with private-origin
         * containment gone, transport secrecy is the remaining control — refuse http:// unless the
         * host is loopback/RFC1918/.local-class, keeping dev/LAN parity).
         */
        internal fun originIssue(base0: String?, publicHostname: String?): String? {
            val base = base0?.takeIf { it.isNotBlank() }
                ?: return "ANDVARI_CANONICAL_ORIGIN is unset (deprecated alias ANDVARI_INVITE_BASE_URL also unset)"
            // A default port a browser STRIPS from location.origin → the emailed link would never match.
            if (base.startsWith("https://") && base.endsWith(":443")) return "drop the default :443 (browsers strip it → dead-on-arrival)"
            if (base.startsWith("http://") && base.endsWith(":80")) return "drop the default :80 (browsers strip it → dead-on-arrival)"
            val host = base.substringAfter("://", "").substringBefore("/").substringBefore(":")
            // NEW (§3): https required for non-local hosts — enroll links are bearer credentials.
            if (base.startsWith("http://") && !isLocalClassHost(host))
                return "ANDVARI_CANONICAL_ORIGIN must be https:// for non-local hosts (an enroll link is a bearer credential); http:// is allowed only for loopback/RFC1918/.local dev hosts (got '$base')"
            // A5 (reworded per §3): emailed bearer links must not point at the emergency hatch, where
            // register is refused. Fires only when a break-glass twin origin is configured at all.
            if (!publicHostname.isNullOrBlank() && host.equals(publicHostname, ignoreCase = true))
                return "ANDVARI_CANONICAL_ORIGIN host matches the break-glass origin ($publicHostname) — emailed invites must point at the primary origin, not the break-glass origin"
            // B2: the emitted link must round-trip so the web enrollPrefillFor (payload.o === origin)
            // matches; parse also enforces the canonical-origin rule (lowercase, no trailing slash/path).
            val link = EnrollLink.compose(base, "selftest", "selftest@example.com") ?: return "the base URL couldn't be encoded as an enroll link"
            val parsed = EnrollLink.parse(link)
            if (parsed == null || parsed.o != base)
                return "ANDVARI_CANONICAL_ORIGIN must be a canonical origin — lowercase scheme+host[:non-default-port], no trailing slash or path (got '$base')"
            return null
        }

        /** Loopback / RFC1918 / `.local`-class hosts, where a plain-http canonical origin is tolerated
         *  (dev/LAN parity). Anything else must be https (see [originIssue]). */
        internal fun isLocalClassHost(host: String): Boolean {
            val h = host.lowercase()
            if (h == "localhost" || h == "::1" || h == "[::1]" || h.endsWith(".local")) return true
            // The private-IPv4 ranges must be dotted-decimal LITERALS — a routable DNS name like
            // "10.evil.com" / "192.168.evil.com" / "172.16.evil.com" is NOT local, so it must still be
            // https (review 2026-07-16 F2). isIpLiteral (Auth.kt, same package) rejects such names.
            if (!isIpLiteral(h)) return false
            if (h.startsWith("127.") || h.startsWith("10.") || h.startsWith("192.168.")) return true
            val second = Regex("""^172\.(\d{1,3})\.""").find(h)?.groupValues?.get(1)?.toIntOrNull()
            return second != null && second in 16..31
        }

        /** Strict bool env parse: 1/0/true/false (case-insensitive); anything else null (lint flags it). */
        internal fun parseBool(v: String?): Boolean? = when {
            v == null -> null
            v == "1" || v.equals("true", ignoreCase = true) -> true
            v == "0" || v.equals("false", ignoreCase = true) -> false
            else -> null
        }

        /**
         * §2.1/§7.3 signupMode env → effective mode. `open` is legal-but-RESERVED: it boot-coerces to
         * `landing` (never silently open an unwired door) — [envLint] emits the note. Unknown values
         * coerce to the conservative default `invite-only` (same rule the clients apply) — [envLint]
         * flags them as problems (strict boot refuses).
         */
        internal fun signupModeOf(raw: String?): String = when (val v = raw?.trim()?.lowercase().orEmpty()) {
            "" -> "invite-only"
            "closed", "invite-only", "landing" -> v
            "open" -> "landing"
            else -> "invite-only"
        }

        /** Every ANDVARI_* var the server reads — [envLint]'s unknown-var authority. Keep in lockstep
         *  with [fromEnv] (+ ANDVARI_STRICT_ENV, read by Main before fromEnv). */
        internal val KNOWN_ENV: Set<String> = setOf(
            "ANDVARI_HOST", "ANDVARI_PORT", "ANDVARI_DB", "ANDVARI_BLOB_DIR", "ANDVARI_WEB_DIR",
            "ANDVARI_DOWNLOADS_DIR", "ANDVARI_RECOVERY_PUBKEY", "ANDVARI_RECOVERY_FINGERPRINT",
            "ANDVARI_ENUM_SECRET", "ANDVARI_PUBLIC_HOSTNAME", "ANDVARI_BOOTSTRAP_TOKEN",
            "ANDVARI_MIN_KDF_MEM", "ANDVARI_MIN_KDF_OPS", "ANDVARI_TRUSTED_IP_HEADERS",
            "ANDVARI_UPLOAD_MAX_CONCURRENT", "ANDVARI_REQUEST_READ_TIMEOUT_S", "ANDVARI_RESPONSE_WRITE_TIMEOUT_S",
            "ANDVARI_VAULT_GRACE_DAYS", "ANDVARI_TRANSFER_TTL_DAYS", "ANDVARI_JANITOR_DRYRUN",
            "ANDVARI_SMTP_HOST", "ANDVARI_SMTP_PORT", "ANDVARI_SMTP_USER", "ANDVARI_SMTP_PASS", "ANDVARI_SMTP_FROM",
            "ANDVARI_INVITE_BASE_URL", "ANDVARI_GRAPH_TENANT", "ANDVARI_GRAPH_CLIENT_ID",
            "ANDVARI_GRAPH_CLIENT_SECRET", "ANDVARI_GRAPH_SENDER",
            "ANDVARI_SIGNUP_MODE", "ANDVARI_TOTP_REQUIRED", "ANDVARI_INSTANCE_NAME",
            "ANDVARI_CANONICAL_ORIGIN", "ANDVARI_SELFHOST_DOCS_URL", "ANDVARI_OFFLINE_CACHE_ALLOWED",
            "ANDVARI_FORCE_HSTS", "ANDVARI_LOGIN_RATE_PER_MIN", "ANDVARI_STRICT_ENV",
        )

        private val INT_ENV = setOf(
            "ANDVARI_PORT", "ANDVARI_SMTP_PORT", "ANDVARI_MIN_KDF_MEM", "ANDVARI_MIN_KDF_OPS",
            "ANDVARI_UPLOAD_MAX_CONCURRENT", "ANDVARI_REQUEST_READ_TIMEOUT_S", "ANDVARI_RESPONSE_WRITE_TIMEOUT_S",
            "ANDVARI_VAULT_GRACE_DAYS", "ANDVARI_TRANSFER_TTL_DAYS", "ANDVARI_LOGIN_RATE_PER_MIN",
        )
        private val BOOL_ENV = setOf(
            "ANDVARI_JANITOR_DRYRUN", "ANDVARI_TOTP_REQUIRED", "ANDVARI_OFFLINE_CACHE_ALLOWED",
            "ANDVARI_FORCE_HSTS", "ANDVARI_STRICT_ENV",
        )

        /** [envLint]'s verdict. [problems] = unknown/invalid ANDVARI_* (boot WARNs; ANDVARI_STRICT_ENV=1
         *  EXITS — bringup.sh sets strict so a typo'd/renamed var fails the healthz wait, B2-1).
         *  [notes] = defined-but-noteworthy states (deprecated alias in use, `open` coercion) — warned,
         *  never fatal. */
        data class EnvLint(val problems: List<String>, val notes: List<String>)

        /** Documented NON-server ANDVARI_* families (e2e.sh / migration-rehearsal.sh / drill
         *  harnesses set these around the server) — exempt from the unknown-var check so an
         *  exported harness var never noises up a drill boot. */
        private val HARNESS_ENV_PREFIXES = listOf("ANDVARI_E2E", "ANDVARI_REHEARSAL", "ANDVARI_DRILL")

        /** §2.1 env lint over the raw process environment. Pure — Main prints + decides the exit. */
        fun envLint(env: Map<String, String>): EnvLint {
            val problems = mutableListOf<String>()
            val notes = mutableListOf<String>()
            for (name in env.keys.filter { it.startsWith("ANDVARI_") }.sorted()) {
                if (name !in KNOWN_ENV && HARNESS_ENV_PREFIXES.none { name.startsWith(it) }) {
                    problems += "unknown env var $name (typo? renamed?)"
                }
            }
            for (name in INT_ENV) env[name]?.let { v ->
                if (v.trim().toLongOrNull() == null) problems += "invalid $name: '$v' is not a number"
            }
            for (name in BOOL_ENV) env[name]?.let { v ->
                if (parseBool(v) == null) problems += "invalid $name: '$v' is not a boolean (use 1/0/true/false)"
            }
            env["ANDVARI_SIGNUP_MODE"]?.let { raw ->
                when (raw.trim().lowercase()) {
                    "closed", "invite-only", "landing" -> {}
                    "open" -> notes += "ANDVARI_SIGNUP_MODE=open is reserved (§7.3) — coerced to 'landing' until open registration ships"
                    else -> problems += "invalid ANDVARI_SIGNUP_MODE: '$raw' is not one of closed|invite-only|landing|open"
                }
            }
            if (env["ANDVARI_CANONICAL_ORIGIN"] == null && env["ANDVARI_INVITE_BASE_URL"] != null) {
                notes += "ANDVARI_INVITE_BASE_URL is deprecated — set ANDVARI_CANONICAL_ORIGIN (the old var is honored as a fallback alias)"
            }
            (env["ANDVARI_CANONICAL_ORIGIN"] ?: env["ANDVARI_INVITE_BASE_URL"])?.let { base ->
                originIssue(base, env["ANDVARI_PUBLIC_HOSTNAME"])?.let { problems += it }
            }
            return EnvLint(problems, notes)
        }

        // M3: X-Forwarded-For ONLY — NOT CF-Connecting-Ip. Both front-ends terminate on loopback, so
        // any loopback-peer header is trusted; but only the genuine CF tunnel sets CF-Connecting-Ip,
        // while tailscale-serve (and LAN) leave it UNSET and pass a client-supplied one through —
        // making it forgeable there (a tailnet client rotates it to evade per-IP rate limits, spec 05
        // T11). Probed 2026-07-13: cloudflared AND tailscale-serve both set X-Forwarded-For to the
        // REAL client as the RIGHTMOST entry (tailscale OVERWRITES a client-sent XFF; CF appends the
        // edge-observed IP), and pickClientIp already takes the rightmost — so XFF is un-forgeable on
        // both paths while CF-Connecting-Ip is not. An all-CF deployment can re-add it via env.
        val DEFAULT_TRUSTED_IP_HEADERS = listOf("X-Forwarded-For")

        fun fromEnv(env: (String) -> String? = System::getenv): Config {
            val recoveryPub = env("ANDVARI_RECOVERY_PUBKEY")?.let { Bytes.fromB64(it) } ?: ByteArray(0)
            require(recoveryPub.isEmpty() || recoveryPub.size == 32) {
                "ANDVARI_RECOVERY_PUBKEY must be a 32-byte X25519 public key"
            }
            // Deterministic fake-prelogin salts (anti-enumeration, spec 01 §3) rest ENTIRELY
            // on this secret being unknown. A missing/blank var used to default to 32 zero
            // bytes silently, making fake salts computable. Fail closed instead.
            val enumSecret = env("ANDVARI_ENUM_SECRET")?.takeIf { it.isNotBlank() }?.let { Bytes.fromB64(it) }
                ?: error("ANDVARI_ENUM_SECRET must be set (>=32 random bytes, base64url) — refusing to start with a guessable enumeration secret")
            require(enumSecret.size >= 32) { "ANDVARI_ENUM_SECRET must decode to >=32 bytes" }
            return Config(
                host = env("ANDVARI_HOST") ?: "127.0.0.1",
                port = env("ANDVARI_PORT")?.toInt() ?: 8080,
                dbPath = env("ANDVARI_DB") ?: "andvari.db",
                blobDir = env("ANDVARI_BLOB_DIR") ?: "blobs",
                webDir = env("ANDVARI_WEB_DIR"),
                downloadsDir = env("ANDVARI_DOWNLOADS_DIR"),
                recoveryPublicKey = recoveryPub,
                recoveryFingerprint = env("ANDVARI_RECOVERY_FINGERPRINT") ?: "",
                enumSecret = enumSecret,
                publicHostname = env("ANDVARI_PUBLIC_HOSTNAME"),
                bootstrapToken = env("ANDVARI_BOOTSTRAP_TOKEN"),
                // Production KDF floor (spec 01 §9's hard rule: never below 64 MiB / ops 3).
                minKdfMemBytes = env("ANDVARI_MIN_KDF_MEM")?.toLong() ?: 67_108_864L,
                minKdfOps = env("ANDVARI_MIN_KDF_OPS")?.toLong() ?: 3L,
                trustedIpHeaders = env("ANDVARI_TRUSTED_IP_HEADERS")
                    ?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }
                    ?: DEFAULT_TRUSTED_IP_HEADERS,
                uploadMaxConcurrentPerUser = env("ANDVARI_UPLOAD_MAX_CONCURRENT")?.toInt() ?: 4,
                requestReadTimeoutSeconds = env("ANDVARI_REQUEST_READ_TIMEOUT_S")?.toInt() ?: 0,
                responseWriteTimeoutSeconds = env("ANDVARI_RESPONSE_WRITE_TIMEOUT_S")?.toInt() ?: 0,
                vaultGraceDays = env("ANDVARI_VAULT_GRACE_DAYS")?.toInt() ?: 7,
                transferTtlDays = env("ANDVARI_TRANSFER_TTL_DAYS")?.toInt() ?: 14,
                janitorDryRun = env("ANDVARI_JANITOR_DRYRUN")?.let { it == "1" || it.equals("true", ignoreCase = true) } ?: false,
                smtpHost = env("ANDVARI_SMTP_HOST"),
                smtpPort = env("ANDVARI_SMTP_PORT")?.toInt() ?: 587,
                smtpUser = env("ANDVARI_SMTP_USER"),
                smtpPass = env("ANDVARI_SMTP_PASS"),
                smtpFrom = env("ANDVARI_SMTP_FROM"),
                inviteBaseUrl = env("ANDVARI_INVITE_BASE_URL"),
                graphTenantId = env("ANDVARI_GRAPH_TENANT"),
                graphClientId = env("ANDVARI_GRAPH_CLIENT_ID"),
                graphClientSecret = env("ANDVARI_GRAPH_CLIENT_SECRET"),
                graphSender = env("ANDVARI_GRAPH_SENDER"),
                // §2.1 instance stance. All new vars use FORGIVING parses (bad value → default) so a
                // non-strict boot never crashes on them — envLint is the loud channel, and the
                // fallback direction is always today's behavior (deploy-inert).
                signupMode = signupModeOf(env("ANDVARI_SIGNUP_MODE")),
                totpRequired = parseBool(env("ANDVARI_TOTP_REQUIRED")) ?: false,
                instanceName = env("ANDVARI_INSTANCE_NAME"),
                canonicalOrigin = env("ANDVARI_CANONICAL_ORIGIN"), // deprecated-alias fallback happens at the property (inviteBaseUrl above)
                selfHostDocsUrl = env("ANDVARI_SELFHOST_DOCS_URL"),
                offlineCacheAllowedFloor = parseBool(env("ANDVARI_OFFLINE_CACHE_ALLOWED")) ?: true,
                forceHsts = parseBool(env("ANDVARI_FORCE_HSTS")) ?: false,
                loginRatePerMin = env("ANDVARI_LOGIN_RATE_PER_MIN")?.toIntOrNull()?.takeIf { it > 0 } ?: 5,
            )
        }
    }
}
