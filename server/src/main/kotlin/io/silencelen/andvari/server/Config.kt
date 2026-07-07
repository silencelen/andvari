package io.silencelen.andvari.server

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
) {
    val escrowConfigured: Boolean get() = recoveryPublicKey.size == 32 && recoveryFingerprint.isNotEmpty()

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
            )
        }
    }
}
