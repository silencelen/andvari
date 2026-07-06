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
    val recoveryPublicKey: ByteArray,
    val recoveryFingerprint: String,
    val enumSecret: ByteArray,
    val publicHostname: String?,
    val bootstrapToken: String?,
) {
    val escrowConfigured: Boolean get() = recoveryPublicKey.size == 32 && recoveryFingerprint.isNotEmpty()

    companion object {
        fun fromEnv(env: (String) -> String? = System::getenv): Config {
            val recoveryPub = env("ANDVARI_RECOVERY_PUBKEY")?.let { Bytes.fromB64(it) } ?: ByteArray(0)
            require(recoveryPub.isEmpty() || recoveryPub.size == 32) {
                "ANDVARI_RECOVERY_PUBKEY must be a 32-byte X25519 public key"
            }
            return Config(
                host = env("ANDVARI_HOST") ?: "127.0.0.1",
                port = env("ANDVARI_PORT")?.toInt() ?: 8080,
                dbPath = env("ANDVARI_DB") ?: "andvari.db",
                blobDir = env("ANDVARI_BLOB_DIR") ?: "blobs",
                webDir = env("ANDVARI_WEB_DIR"),
                recoveryPublicKey = recoveryPub,
                recoveryFingerprint = env("ANDVARI_RECOVERY_FINGERPRINT") ?: "",
                // Deterministic fake-prelogin salts need a stable secret; prod MUST set one.
                enumSecret = env("ANDVARI_ENUM_SECRET")?.let { Bytes.fromB64(it) } ?: ByteArray(32),
                publicHostname = env("ANDVARI_PUBLIC_HOSTNAME"),
                bootstrapToken = env("ANDVARI_BOOTSTRAP_TOKEN"),
            )
        }
    }
}
