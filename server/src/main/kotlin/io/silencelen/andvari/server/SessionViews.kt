package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.PersonalWrap
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.model.wire.WireErrors
import java.sql.Connection

/** `AccountKeys` (spec 03 §3): the server always sends both `personalWrap` and `genesis`. */
fun accountKeys(c: Connection, userId: String): AccountKeys =
    c.queryOne(
        """SELECT u.kdfSalt,u.kdfParams,u.wrappedUvk,u.encryptedIdentitySeed,u.identityPub,u.recoveryConfirmed,u.genesis,
                  pw.vaultId AS pwVault, pw.wrappedVk AS pwWrap
           FROM users u LEFT JOIN personal_wrap pw ON pw.userId=u.userId WHERE u.userId=?""",
        userId,
    ) { rs ->
        AccountKeys(
            kdfSalt = rs.getString("kdfSalt"),
            kdfParams = decodeParams(rs.getString("kdfParams")),
            wrappedUvk = rs.getString("wrappedUvk"),
            encryptedIdentitySeed = rs.getString("encryptedIdentitySeed"),
            identityPub = rs.getString("identityPub"),
            recoveryConfirmed = rs.bool("recoveryConfirmed"),
            personalWrap = rs.getString("pwVault")?.let { PersonalWrap(it, rs.getString("pwWrap")) },
            genesis = rs.getString("genesis"),
        )
    } ?: unauthorized(WireErrors.INVALID_CREDENTIALS)

/** `SessionResponse` (spec 03 §2) for a session just minted. */
fun sessionResponse(c: Connection, config: Config, userId: String, issued: IssuedSession, recoveryPieceId: String? = null): SessionResponse {
    val (role, totp) = c.queryOne("SELECT role,totpSecret FROM users WHERE userId=?", userId) { it.getString(1) to (it.getString(2) != null) }
        ?: unauthorized()
    return SessionResponse(
        userId = userId,
        deviceId = issued.deviceId,
        accessToken = issued.accessToken,
        refreshToken = issued.refreshToken,
        accountKeys = accountKeys(c, userId),
        role = role,
        totpEnrolled = totp,
        mustEnrollTotp = config.totpRequired && !totp,
        recoveryPieceId = recoveryPieceId,
    )
}

/** hex SHA-256 of the decoded 32 bytes of a `deviceSecret` (spec 03 §0.3); null when it is not a `b64_32`. */
fun deviceSecretHash(deviceSecret: String): String? =
    Grammar.b64Bytes(deviceSecret, 32, 32)?.let { sha256Hex(it) }

/** Global rev (spec 03 §4): every create/update/delete of any object bumps it through `changes`. */
fun nextRev(c: Connection, kind: String, entityId: String, vaultId: String?, nowMs: Long): Long {
    c.exec("INSERT INTO changes(kind,entityId,vaultId,at) VALUES(?,?,?,?)", kind, entityId, vaultId, nowMs)
    return c.queryOne("SELECT last_insert_rowid()") { it.getLong(1) }!!
}

fun currentRev(c: Connection): Long = c.queryOne("SELECT COALESCE(MAX(rev),0) FROM changes") { it.getLong(1) } ?: 0L

/** The account ID of [userId] (the 32-hex short identity fingerprint) for notices. */
fun accountIdOf(c: Connection, userId: String): String? =
    c.queryOne("SELECT identityPub FROM users WHERE userId=?", userId) { Mail.accountId(it.getString(1)) }

