package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.AccountRole
import io.silencelen.andvari.core.model.wire.WirePlatform
import java.sql.Connection

/**
 * The authenticated caller (spec 03 §0.1), resolved from a bearer access token against live state.
 *
 * - [restricted]: a §2 restricted session (instance `totpRequired`, account not enrolled); every route
 *   but TOTP setup, confirm and logout answers `403 totp_enrollment_required`.
 * - [webSession]: minted by a request whose `X-Andvari-Client` platform was `web` (§1); every operator
 *   route refuses it (`403 operator_web_refused`).
 * - [passwordAt]: when a password login minted the session. Stored and carried over by a refresh; no rule reads it
 *   since 2026-11-17, when the ten-minute window in which a first two-step setup needed no password proof was removed.
 */
data class Principal(
    val userId: String,
    val deviceId: String,
    val sessionId: String,
    val role: String,
    val restricted: Boolean,
    val webSession: Boolean,
    val passwordAt: Long?,
) {
    val isOperator: Boolean get() = role == AccountRole.OPERATOR
}

/**
 * The refresh chains of sessions (spec 02 §5 `session_chains`, spec 03 §2): which chain a session a refresh made belongs to.
 * A session with no row is a chain of its own, named by its own id.
 */
internal object SessionChains {
    /** The chain of the session `s` in a query that joins `session_chains sc ON sc.sessionId=s.sessionId` (LEFT JOIN). */
    const val CHAIN_OF_S = "COALESCE(sc.chainId,s.sessionId)"

    /**
     * The start-up step for a database a development build of 2026-11-17 ran on, which kept the chain in a column of
     * `sessions` (`chainId`): before the catch-up step rebuilds `sessions` without that column ([Db.RETIRED_COLUMNS]), what
     * it held is carried into `session_chains`, created here when missing. A row whose chain is its own session needs no
     * row. Nothing when the column is not there. Inside the start-up's transaction.
     */
    fun carryFromRetiredColumn(c: Connection): List<String> {
        val hasColumn = c.queryAll("PRAGMA table_info(sessions)") { it.getString("name") }.contains("chainId")
        if (!hasColumn) return emptyList()
        val done = ArrayList<String>()
        if (c.queryOne("SELECT 1 FROM sqlite_master WHERE type='table' AND name='session_chains'") { 1 } == null) {
            val t = BaselineCatchUp.baselineTables.single { it.name == "session_chains" }
            c.createStatement().use { st ->
                st.executeUpdate(t.ddl)
                for ((_, ddl) in BaselineCatchUp.baselineIndexes[t.name].orEmpty()) st.executeUpdate(ddl)
            }
            done.add("created table session_chains")
        }
        val n = c.exec(
            "INSERT OR IGNORE INTO session_chains(sessionId,chainId) SELECT sessionId,chainId FROM sessions WHERE chainId IS NOT NULL AND chainId<>sessionId",
        )
        done.add("carried $n refresh chain link${if (n == 1) "" else "s"} from sessions.chainId into session_chains")
        return done
    }
}

/** A freshly minted session: its device and both bearer tokens (returned once, stored only as hashes). */
data class IssuedSession(val deviceId: String, val accessToken: String, val refreshToken: String, val sessionId: String)

/**
 * Sessions and devices (spec 03 §2, §16.7, §16.8). Tokens are 256-bit random, stored as SHA-256; access
 * lives [accessTtlMs], refresh [refreshTtlMs] and rotates single-use.
 */
class Sessions(private val config: Config, private val policy: PolicyStore, private val clock: Clock) {
    val accessTtlMs: Long get() = policy.get().sessionAccessTtlSeconds * 1000
    val refreshTtlMs: Long get() = policy.get().sessionRefreshTtlDays * Clock.DAY_MS

    /** The sixty-second grace for a refresh that is repeated (spec 03 §2, [RefreshGrace]). */
    val refreshGrace = RefreshGrace(clock)

    /**
     * Resolve [accessToken]. Null for an unknown, expired or revoked token, a revoked device, or an account
     * that is not `active` — all of which the route answers with the uniform `401 invalid_credentials`.
     *
     * A token that resolves was received by its client, so a repeat of the refresh that made it is no longer a lost
     * answer: its grace ends here ([RefreshGrace.accessUsed]).
     */
    fun authenticate(c: Connection, accessToken: String): Principal? {
        val nowMs = clock.now()
        val hash = ServerCrypto.hashToken(accessToken)
        return c.queryOne(
            """SELECT s.sessionId, s.userId, s.deviceId, s.clientPlatform, s.passwordAt, u.role, u.totpSecret
               FROM sessions s JOIN users u ON u.userId=s.userId JOIN devices d ON d.deviceId=s.deviceId
               WHERE s.accessHash=? AND s.revokedAt IS NULL AND s.accessExpiresAt>? AND d.revokedAt IS NULL AND u.status='active'""",
            hash, nowMs,
        ) { rs ->
            Principal(
                userId = rs.getString("userId"),
                deviceId = rs.getString("deviceId"),
                sessionId = rs.getString("sessionId"),
                role = rs.getString("role"),
                restricted = config.totpRequired && rs.getString("totpSecret") == null,
                webSession = rs.getString("clientPlatform") == WirePlatform.WEB,
                passwordAt = rs.longOrNull("passwordAt"),
            )
        }?.also { refreshGrace.accessUsed(hash) }
    }

    /** True while [sessionId] is unrevoked (the account-deletion and re-auth compare-and-swaps). */
    fun sessionLive(c: Connection, sessionId: String): Boolean =
        c.queryOne("SELECT 1 FROM sessions WHERE sessionId=? AND revokedAt IS NULL", sessionId) { true } ?: false

    /** True while [deviceId] has an unrevoked session of an active account (the WS re-check, §6). */
    fun deviceHasLiveSession(c: Connection, deviceId: String): Boolean =
        c.queryOne(
            """SELECT 1 FROM sessions s JOIN users u ON u.userId=s.userId JOIN devices d ON d.deviceId=s.deviceId
               WHERE s.deviceId=? AND s.revokedAt IS NULL AND u.status='active' AND d.revokedAt IS NULL LIMIT 1""",
            deviceId,
        ) { true } ?: false

    /**
     * Create a device row (spec 03 §16.8: every device-creating call stores the hash of its
     * `deviceSecret`) and return its id. [name] and [platform] are already checked by the caller.
     */
    fun createDevice(
        c: Connection, userId: String, platform: String, name: String, how: String,
        deviceSecretHash: String?, clientVersion: String?, linkedFrom: String? = null,
    ): String {
        val deviceId = uuid()
        val t = clock.now()
        c.exec(
            """INSERT INTO devices(deviceId,userId,platform,name,clientVersion,how,linkedFrom,deviceSecretHash,createdAt,lastSeenAt)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            deviceId, userId, platform, name, clientVersion, how, linkedFrom, deviceSecretHash, t, t,
        )
        return deviceId
    }

    /**
     * Mint a session on an existing device row. [clientPlatform] is the request header's platform (§1), which the row's
     * kind overrides when the row was made as `web` (see below). [chainId] is the
     * chain the session continues: a refresh passes its rotated-away session's chain; anything else starts a chain of its
     * own, named by the new session's id, which needs no row (spec 02 §5, `session_chains`).
     */
    fun issue(c: Connection, userId: String, deviceId: String, clientPlatform: String, passwordLogin: Boolean, chainId: String? = null): IssuedSession {
        val access = ServerCrypto.newToken()
        val refresh = ServerCrypto.newToken()
        val t = clock.now()
        val sessionId = uuid()
        // The kind of the device row decides, not the caller's word (decided on 2026-11-17), wherever a session is made: a
        // sign-in, a registration, both recoveries' commits, a link's pickup and a refresh. A session on a row made as `web`
        // is a web session, which every operator route refuses, whatever header the request carried; on any other row
        // the request's platform stands, so a `web` header there still gives a web session, which only restricts.
        val rowPlatform = c.queryOne("SELECT platform FROM devices WHERE deviceId=?", deviceId) { it.getString(1) }
        val platform = if (rowPlatform == WirePlatform.WEB) WirePlatform.WEB else clientPlatform
        c.exec(
            """INSERT INTO sessions(sessionId,deviceId,userId,accessHash,accessExpiresAt,refreshHash,refreshExpiresAt,clientPlatform,passwordAt,createdAt)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            sessionId, deviceId, userId, ServerCrypto.hashToken(access), t + accessTtlMs,
            ServerCrypto.hashToken(refresh), t + refreshTtlMs, platform, if (passwordLogin) t else null, t,
        )
        if (chainId != null) c.exec("INSERT INTO session_chains(sessionId,chainId) VALUES(?,?)", sessionId, chainId)
        return IssuedSession(deviceId, access, refresh, sessionId)
    }

    /** What [endNamed] ended: the chain's sessions that were still live, and whether the token named had been replaced. */
    class NamedEnd(val liveSessionIds: List<String>, val replaced: Boolean)

    /**
     * A sign-in on the known device [deviceId] of [userId] named the session it replaces by the refresh token the client
     * last held for it ([refreshHash], spec 03 §2 `replacesRefreshToken`): that session ends, as it stands now, in the
     * caller's transaction. "As it stands now" is the token's chain: the session the token was minted with and every one a
     * refresh rotated it into since (`session_chains`), so a token one refresh behind (a refresh whose answer was lost)
     * still names the session that refresh made. Every unrevoked row of the chain gets `revokedAt`.
     *
     * Null, and nothing changed, when the token names no unrevoked, unexpired session of that account on that device row:
     * another account's, another row's, an unknown, ended or expired one. A token the server had already replaced is NOT
     * the reuse signal here: the sign-in proved the password (and the code where one is required) and the device's own
     * secret, so it ends that one chain only, and [NamedEnd.replaced] says it for the record. The reuse rule for such a
     * token sent to `/auth/refresh` or `/auth/end-session` is unchanged.
     *
     * A session a refresh made where the chain was not recorded (before the chain was kept, or by a server that does not
     * keep it) has no row and counts as a chain of its own, so it is not reached through the session it was rotated from.
     */
    fun endNamed(c: Connection, userId: String, deviceId: String, refreshHash: String): NamedEnd? {
        val t = clock.now()
        val named = c.queryOne(
            "SELECT ${SessionChains.CHAIN_OF_S},s.refreshConsumedAt,s.refreshExpiresAt FROM sessions s LEFT JOIN session_chains sc ON sc.sessionId=s.sessionId " +
                "WHERE s.refreshHash=? AND s.userId=? AND s.deviceId=? AND s.revokedAt IS NULL",
            refreshHash, userId, deviceId,
        ) { rs -> Triple(rs.getString(1), rs.longOrNull("refreshConsumedAt"), rs.getLong(3)) } ?: return null
        val (chain, consumedAt, expiresAt) = named
        if (t >= expiresAt) return null
        // The chain's sessions: its first (named by the chain's id) and every one a row of `session_chains` names.
        val inChain = "s.deviceId=? AND (s.sessionId=? OR s.sessionId IN (SELECT sessionId FROM session_chains WHERE chainId=?))"
        val live = c.queryAll(
            "SELECT s.sessionId FROM sessions s WHERE $inChain AND s.revokedAt IS NULL AND s.refreshConsumedAt IS NULL AND s.refreshExpiresAt>?",
            deviceId, chain, chain, t,
        ) { it.getString(1) }
        c.exec("UPDATE sessions AS s SET revokedAt=? WHERE $inChain AND s.revokedAt IS NULL", t, deviceId, chain, chain)
        return NamedEnd(live, replaced = consumedAt != null)
    }

    /**
     * A sign-in on the known device [deviceId] is about to give it a new session (spec 03 §2): every earlier session of
     * the device row ends now, in the caller's transaction, as a logout ends them (`revokedAt`; the row and its secret
     * stay, so the device stays known). Returns how many of them were still live (not consumed by a refresh, not
     * expired), which is what the caller records as `session_end`; 0 when the device held none.
     *
     * A device has one live session (decided on 2026-11-17). Before, the client ended the session a sign-in replaced by
     * sending that session's refresh token; when an earlier refresh had been answered and the answer lost, the token it
     * sent was one the server had already replaced, which the server must take for the reuse of a stolen token, and so it
     * ended every session of the device, the new one included. Now every earlier session, the consumed links of its
     * chain included, is ended here, so an old token sent afterwards names a session that is already ended: the refresh
     * answers `session_revoked` and `/auth/end-session` does nothing, and neither reaches the new session. The reuse rule
     * itself is unchanged: a replaced token of a session that is still live revokes every session of its device.
     */
    fun endEarlierOf(c: Connection, deviceId: String): Int {
        val t = clock.now()
        val live = c.count("SELECT COUNT(*) FROM sessions WHERE deviceId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL AND refreshExpiresAt>?", deviceId, t)
        c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", t, deviceId)
        return live.toInt()
    }

    /** Revoke every session of [userId], optionally sparing [exceptSessionId]. */
    fun revokeAllOf(c: Connection, userId: String, exceptSessionId: String? = null) {
        c.exec(
            "UPDATE sessions SET revokedAt=? WHERE userId=? AND revokedAt IS NULL AND (? IS NULL OR sessionId<>?)",
            clock.now(), userId, exceptSessionId, exceptSessionId,
        )
    }

    /**
     * Revoke a device (spec 03 §16.7, §7.1): its sessions, its row, and **its deviceSecret hash**, so it is
     * never a known device again (§16.8). Every device link the device created or approved is cancelled
     * (deleted) with it, so a revoked device can never complete a pickup it started or approved.
     */
    fun revokeDevice(c: Connection, deviceId: String) {
        val t = clock.now()
        c.exec("UPDATE sessions SET revokedAt=? WHERE deviceId=? AND revokedAt IS NULL", t, deviceId)
        c.exec("UPDATE devices SET revokedAt=COALESCE(revokedAt,?), deviceSecretHash=NULL WHERE deviceId=?", t, deviceId)
        c.exec("DELETE FROM device_links WHERE deviceId=? OR approvedBy=?", deviceId, deviceId)
    }

    /** True when [deviceId] names an unrevoked device of [userId]. */
    fun deviceUnrevoked(c: Connection, userId: String, deviceId: String): Boolean =
        c.queryOne("SELECT 1 FROM devices WHERE deviceId=? AND userId=? AND revokedAt IS NULL", deviceId, userId) { true } ?: false
}
