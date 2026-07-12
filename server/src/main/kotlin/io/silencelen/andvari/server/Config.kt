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
    // (the household M365 tenant: smtp.office365.com:587). inviteBaseUrl = the CANONICAL private
    // origin the emailed enroll link embeds; it MUST equal the browser's location.origin (no trailing
    // slash / :443 / uppercase), validated by inviteBaseUrlIssue().
    val smtpHost: String? = null,
    val smtpPort: Int = 587,
    val smtpUser: String? = null,
    val smtpPass: String? = null,
    val smtpFrom: String? = null,
    val inviteBaseUrl: String? = null,
) {
    val escrowConfigured: Boolean get() = recoveryPublicKey.size == 32 && recoveryFingerprint.isNotEmpty()

    /** cut 4: email-invite is enabled ONLY when all SMTP config + a usable canonical private base URL
     *  are present. Any gap ⇒ the Admin "email this invite" checkbox is disabled and a sendEmail
     *  request is a no-op — fail-safe, never a hard error that loses the invite (breaker NIT). */
    val emailConfigured: Boolean
        get() = !smtpHost.isNullOrBlank() && !smtpUser.isNullOrBlank() && !smtpPass.isNullOrBlank() &&
            !smtpFrom.isNullOrBlank() && inviteBaseUrlIssue() == null

    /** null = ANDVARI_INVITE_BASE_URL is a usable canonical private origin; else a human reason (logged
     *  at boot). Catches breaker B2 (a config typo → every emailed invite dead-on-arrival) + A5 (never
     *  email a bearer-token link pointing at the internet-facing public origin). */
    fun inviteBaseUrlIssue(): String? {
        val base = inviteBaseUrl?.takeIf { it.isNotBlank() } ?: return "ANDVARI_INVITE_BASE_URL is unset"
        // A default port a browser STRIPS from location.origin → the emailed link would never match.
        if (base.startsWith("https://") && base.endsWith(":443")) return "drop the default :443 (browsers strip it → dead-on-arrival)"
        if (base.startsWith("http://") && base.endsWith(":80")) return "drop the default :80 (browsers strip it → dead-on-arrival)"
        // A5: never email a link pointing at the internet-facing public origin.
        val host = base.substringAfter("://", "").substringBefore("/").substringBefore(":")
        if (!publicHostname.isNullOrBlank() && host.equals(publicHostname, ignoreCase = true))
            return "ANDVARI_INVITE_BASE_URL host matches the public origin ($publicHostname) — emailed invites must stay private-origin"
        // B2: the emitted link must round-trip so the web enrollPrefillFor (payload.o === origin)
        // matches; parse also enforces the canonical-origin rule (lowercase, no trailing slash/path).
        val link = EnrollLink.compose(base, "selftest", "selftest@example.com") ?: return "the base URL couldn't be encoded as an enroll link"
        val parsed = EnrollLink.parse(link)
        if (parsed == null || parsed.o != base)
            return "ANDVARI_INVITE_BASE_URL must be a canonical origin — lowercase scheme+host[:non-default-port], no trailing slash or path (got '$base')"
        return null
    }

    companion object {
        val DEFAULT_TRUSTED_IP_HEADERS = listOf("CF-Connecting-IP", "X-Forwarded-For")

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
            )
        }
    }
}
