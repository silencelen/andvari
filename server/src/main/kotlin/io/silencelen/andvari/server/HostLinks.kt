package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Hkdf
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.LinkKind
import java.sql.Connection

/**
 * Host-minted links (spec 03 §15.1, §17.5; design §6.4, §9.5): the setup link that enrols the first
 * operator and the enrol links that register an ordinary member with no inviter. Written straight into
 * the database by `andvari setup` / `andvari admin`; there is no HTTP route that mints either kind.
 *
 * The secret `s` exists only here and in the printed URL: the server stores the link id, the offer
 * envelope and the token hash, never `s` or a key derived from it (spec 03 §15.8).
 */
object HostLinks {
    /** The product origin's join path (design §0.3). */
    const val LINK_BASE = "https://andvaripass.com/l"

    const val SETUP_TTL_MS = 24L * 3_600_000
    const val ENROL_DEFAULT_TTL_MS = 7L * 86_400_000

    private val crypto = createCryptoProvider()

    class Minted(val linkId: String, val url: String, val expiresAt: Long)

    private class Derived(val linkId: String, val offerKey: ByteArray, val registerToken: String)

    private fun derive(s: ByteArray): Derived {
        fun hkdf(info: String, n: Int) = Hkdf.sha256(crypto, s, ByteArray(0), info.encodeToByteArray(), n)
        return Derived(
            linkId = Bytes.toB64(hkdf("andvari/v2|link|id", 16)),
            offerKey = hkdf("andvari/v2|link|offer", 32),
            registerToken = Bytes.toB64(hkdf("andvari/v2|link|register", 32)),
        )
    }

    /** `https://andvaripass.com/l#v2.<O>.<S>.-` (spec 03 §15.1): a host-minted link has no creator fingerprint. */
    fun url(origin: String, s: ByteArray): String =
        "$LINK_BASE#v2.${Bytes.toB64(origin.encodeToByteArray())}.${Bytes.toB64(s)}.-"

    /**
     * Mint the setup link (spec 03 §17.5): kind `setup`, 24-hour expiry, the setup offer
     * `{"v":2,"purpose":"setup-offer","linkId","origin","instanceId","name","kind","recoveryFp","expiresAt"}`.
     * Every earlier open setup link is revoked first, so at most one is live.
     */
    fun mintSetup(c: Connection, config: Config, setup: InstanceSetupRow, nowMs: Long): Minted {
        c.exec("UPDATE links SET state='revoked', stateChangedAt=? WHERE kind='setup' AND state='open'", nowMs)
        val s = crypto.randomBytes(32)
        val d = derive(s)
        val expiresAt = nowMs + SETUP_TTL_MS
        val offer = "{\"v\":2,\"purpose\":\"setup-offer\",\"linkId\":\"${d.linkId}\",\"origin\":\"${config.canonicalOrigin}\"," +
            "\"instanceId\":\"${setup.instanceId}\",\"name\":\"${setup.name}\",\"kind\":\"${config.instanceKind}\"," +
            "\"recoveryFp\":\"${config.recoveryFpOrNone}\",\"expiresAt\":$expiresAt}"
        insert(c, d, LinkKind.SETUP, offer, expiresAt, null, nowMs)
        return Minted(d.linkId, url(config.canonicalOrigin, s), expiresAt)
    }

    /**
     * Mint one enrol link (spec 03 §15.1, design §9.5): the enrol offer
     * `{"v":2,"purpose":"enrol-offer","linkId","origin","instanceId","cardHash","email","expiresAt"}`, with
     * `email` the `email_b64n` of [boundEmailNorm] or `none`. Refused until card 0 exists ([cardHash]).
     */
    fun mintEnrol(c: Connection, config: Config, instanceId: String, cardHash: String, boundEmailNorm: String?, ttlMs: Long, nowMs: Long): Minted {
        val s = crypto.randomBytes(32)
        val d = derive(s)
        val expiresAt = nowMs + ttlMs
        val email = boundEmailNorm?.let { Bytes.toB64(it.encodeToByteArray()) } ?: "none"
        val offer = "{\"v\":2,\"purpose\":\"enrol-offer\",\"linkId\":\"${d.linkId}\",\"origin\":\"${config.canonicalOrigin}\"," +
            "\"instanceId\":\"$instanceId\",\"cardHash\":\"$cardHash\",\"email\":\"$email\",\"expiresAt\":$expiresAt}"
        insert(c, d, LinkKind.ENROL, offer, expiresAt, boundEmailNorm?.let { config.addressHash(it) }, nowMs)
        return Minted(d.linkId, url(config.canonicalOrigin, s), expiresAt)
    }

    private fun insert(c: Connection, d: Derived, kind: String, offerJson: String, expiresAt: Long, boundEmailHash: String?, nowMs: Long) {
        val envelope = Envelope.sealB64(crypto, d.offerKey, offerJson.encodeToByteArray(), "andvari/v2|link-offer|${d.linkId}".encodeToByteArray())
        c.exec(
            """INSERT INTO links(linkId,kind,creatorUserId,createdAt,expiresAt,offer,tokenHash,boundEmailHash,state)
               VALUES(?,?,NULL,?,?,?,?,?,'open')""",
            d.linkId, kind, nowMs, expiresAt, envelope, ServerCrypto.hashToken(d.registerToken), boundEmailHash,
        )
    }

    /** Test seam: the register token and offer key of a link minted from [s] (what a client derives). */
    fun clientView(s: ByteArray): Triple<String, ByteArray, String> = derive(s).let { Triple(it.linkId, it.offerKey, it.registerToken) }

    /** Parse the secret back out of a host-minted URL (tests and the CLI's printed QR). */
    fun secretOf(url: String): ByteArray? {
        val parts = url.substringAfter('#', "").split('.')
        if (parts.size != 4 || parts[0] != "v2") return null
        return runCatching { Bytes.fromB64(parts[2]) }.getOrNull()?.takeIf { it.size == 32 }
    }
}
