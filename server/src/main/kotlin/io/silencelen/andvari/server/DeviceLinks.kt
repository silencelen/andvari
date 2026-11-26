package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.DeviceHow
import io.silencelen.andvari.core.model.wire.DeviceLinkApproveRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkClaim
import io.silencelen.andvari.core.model.wire.DeviceLinkCreateRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkNonceRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPickupRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPollRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkPollResponse
import io.silencelen.andvari.core.model.wire.DeviceLinkRevealRequest
import io.silencelen.andvari.core.model.wire.DeviceLinkState
import io.silencelen.andvari.core.model.wire.DeviceLinkView
import io.silencelen.andvari.core.model.wire.LinkCreatedResponse
import io.silencelen.andvari.core.model.wire.ReauthRequest
import io.silencelen.andvari.core.model.wire.RequireLinkPut
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireGrammar
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.TrustGrammar
import java.security.MessageDigest
import java.sql.Connection

/**
 * Device links (spec 03 §16, design §8.2): a state machine whose every state has its own server timer.
 * No device and no session exist before pickup, so a timeout leaves nothing to revoke. The server sees
 * the link id, both devices' names and platforms, `nPub`, timing and opaque blobs; without `s` it can
 * neither forge a claim nor an approval the new device accepts.
 */
object DeviceLinks {
    /** Each later state's timeout (§16.2): 5 minutes from entering it. The `open` timeout is stored. */
    const val STATE_TTL_MS = 5 * 60_000L
    /** `outer` (§16.6): a `sealed` of at most 1,400 characters. */
    const val OUTER_MAX = 1_400
    /** `inner`: an envelope of at most 64 KiB of plaintext, in base64url characters with envelope overhead. */
    const val INNER_MAX = ((64 * 1024 + 64) * 4 + 2) / 3

    class Row(
        val linkId: String, val userId: String, val deviceId: String, val state: String, val expiresAt: Long,
        val nPub: String?, val claimName: String?, val claimPlatform: String?, val commitN: String?, val claimMac: String?,
        val nonceE: String?, val nonceN: String?, val proofHash: String?, val outer: String?, val inner: String?, val approveMac: String?,
        val claimedAt: Long?, val revealedAt: Long?, val approvedAt: Long?, val approvedBy: String?,
    ) {
        /** The current state's deadline (§16.2). */
        val deadline: Long
            get() = when (state) {
                DeviceLinkState.OPEN -> expiresAt
                DeviceLinkState.CLAIMED -> claimedAt!! + STATE_TTL_MS
                DeviceLinkState.REVEALED -> revealedAt!! + STATE_TTL_MS
                else -> approvedAt!! + STATE_TTL_MS
            }
    }

    fun row(c: Connection, linkId: String): Row? = c.queryOne("SELECT * FROM device_links WHERE linkId=?", linkId) { rs ->
        Row(
            rs.getString("linkId"), rs.getString("userId"), rs.getString("deviceId"), rs.getString("state"), rs.getLong("expiresAt"),
            rs.getString("nPub"), rs.getString("claimName"), rs.getString("claimPlatform"), rs.getString("commitN"), rs.getString("claimMac"),
            rs.getString("nonceE"), rs.getString("nonceN"), rs.getString("proofHash"), rs.getString("outer"), rs.getString("inner"),
            rs.getString("approveMac"), rs.longOrNull("claimedAt"), rs.longOrNull("revealedAt"), rs.longOrNull("approvedAt"),
            rs.getString("approvedBy"),
        )
    }

    /** `404 link_unknown` for no row (or a malformed id), `410 link_expired` past the state's timeout. */
    fun live(c: Connection, linkId: String, nowMs: Long): Row {
        val r = row(c, linkId) ?: notFound(WireErrors.LINK_UNKNOWN)
        if (nowMs >= r.deadline) gone(WireErrors.LINK_EXPIRED)
        return r
    }

    /**
     * E's own link, for the device that created it only: another device of the same account sees no such
     * link, exactly as another account would (`404 link_unknown`; spec 03 §16.3, §16.5, §16.6).
     */
    fun own(c: Connection, linkId: String, userId: String, deviceId: String, nowMs: Long): Row {
        val r = row(c, linkId)?.takeIf { it.userId == userId && it.deviceId == deviceId } ?: notFound(WireErrors.LINK_UNKNOWN)
        if (nowMs >= r.deadline) gone(WireErrors.LINK_EXPIRED)
        return r
    }

    fun pathId(raw: String): String = raw.takeIf { WireGrammar.isB64_16(it) } ?: notFound(WireErrors.LINK_UNKNOWN)

    /** `proofHash = hexLower(SHA-256(ASCII(proof)))` (§16.1), over the 43-character proof string. */
    fun proofHash(proof: String): String = sha256Hex(proof)

    /** Once `proofHash` exists, any other proof is `403 bad_proof` (§16.5). */
    fun checkProof(r: Row, proof: String) {
        val h = r.proofHash ?: return
        if (!MessageDigest.isEqual(h.encodeToByteArray(), proofHash(proof).encodeToByteArray())) forbidden(WireErrors.BAD_PROOF)
    }
}

/**
 * One page of the devices list (spec 03 §16.7): at most this many rows. A row is at most about 1.1 KB (a name of
 * 256 characters of 3 UTF-8 bytes each, the longest `clientVersion`, every field set), so a page always fits the
 * 1 MiB a client reads (§0.4) however many rows the account holds. Rows are never pruned while known (§16.8).
 */
const val DEVICE_PAGE_ROWS = 500

/** The devices list's `?after=` (spec 03 §16.7): absent, or a `uuid`; anything else is `400 bad_request`. */
fun Req.devicePageAfter(): String? =
    query("after")?.also { if (!io.silencelen.andvari.core.model.wire.WireGrammar.isUuid(it)) badRequest(WireErrors.BAD_REQUEST) }

/**
 * `live` (spec 03 §7.1): not revoked AND a session neither revoked nor past its refresh expiry. Derived, never a column.
 * Rows come in `(createdAt, deviceId)` order. With a [limit], at most that many, starting after the row [after]
 * names (one of [userId]'s devices, else `400 bad_request`); without, every row (the operator's live count).
 */
fun deviceList(c: Connection, userId: String, nowMs: Long, currentDeviceId: String?, limit: Int? = null, after: String? = null): List<Device> {
    val afterAt: Long? = after?.let { id ->
        c.queryOne("SELECT createdAt FROM devices WHERE deviceId=? AND userId=?", id, userId) { it.getLong(1) } ?: badRequest(WireErrors.BAD_REQUEST)
    }
    return c.queryAll(
        """SELECT d.deviceId,d.platform,d.name,d.clientVersion,d.createdAt,d.lastSeenAt,d.how,d.linkedFrom,d.revokedAt,
                  EXISTS(SELECT 1 FROM sessions s WHERE s.deviceId=d.deviceId AND s.revokedAt IS NULL AND s.refreshExpiresAt>?) AS hasLive
           FROM devices d WHERE d.userId=? AND (? IS NULL OR d.createdAt>? OR (d.createdAt=? AND d.deviceId>?))
           ORDER BY d.createdAt, d.deviceId LIMIT ?""",
        nowMs, userId, afterAt, afterAt, afterAt, after, limit ?: -1,
    ) { rs ->
        Device(
            deviceId = rs.getString("deviceId"), platform = rs.getString("platform"), name = rs.getString("name"),
            clientVersion = rs.getString("clientVersion"), createdAt = rs.getLong("createdAt"), lastSeenAt = rs.longOrNull("lastSeenAt"),
            live = rs.longOrNull("revokedAt") == null && rs.getInt("hasLive") == 1, how = rs.getString("how"),
            linkedFrom = rs.getString("linkedFrom"), current = currentDeviceId != null && rs.getString("deviceId") == currentDeviceId,
        )
    }
}

fun Route.deviceRoutes(s: Services) {
    /**
     * `POST /device-links` (spec 03 §16.2): the server owns the expiry: it stores `min(expiresAt, now + 5 min)`
     * and refuses only `expiresAt <= now`. A known id is `409 link_id_taken`. An account has at most one live
     * device link: every other link of the account not yet picked up is deleted. Audited `device_link_create`.
     */
    api(WireRoute.DEVICE_LINK_CREATE, s, Bucket.devicePerHour("device_link_create", 10)) {
        val req = body<DeviceLinkCreateRequest>()
        val linkId = Grammar.requireB64_16(req.linkId, "linkId")
        val nowMs = now
        if (req.expiresAt <= nowMs) badRequest(WireErrors.BAD_EXPIRY)
        val stored = minOf(req.expiresAt, nowMs + DeviceLinks.STATE_TTL_MS)
        val principal = p
        s.db.tx { c ->
            if (c.queryOne("SELECT 1 FROM device_links WHERE linkId=?", linkId) { 1 } != null) conflict(WireErrors.LINK_ID_TAKEN)
            c.exec("DELETE FROM device_links WHERE userId=?", principal.userId)
            c.exec(
                "INSERT INTO device_links(linkId,userId,deviceId,state,expiresAt,createdAt) VALUES(?,?,?,'open',?,?)",
                linkId, principal.userId, principal.deviceId, stored, nowMs,
            )
            s.audit.on(c, "device_link_create", principal.userId, principal.deviceId, ip)
        }
        respond(LinkCreatedResponse(stored, stored - nowMs))
    }

    /** `GET /device-links/{linkId}` (spec 03 §16.3): E's view, each optional field once it exists. */
    api(WireRoute.DEVICE_LINK_VIEW, s) {
        val linkId = DeviceLinks.pathId(param("linkId"))
        val principal = p
        val r = s.db.read { c -> DeviceLinks.own(c, linkId, principal.userId, principal.deviceId, now) }
        val claim = r.nPub?.let { DeviceLinkClaim(it, r.claimName!!, r.claimPlatform!!, r.commitN!!, r.claimMac!!) }
        respond(DeviceLinkView(r.state, r.deadline, claim, r.nonceE, r.nonceN))
    }

    /**
     * `POST /device-links/{linkId}/claim` (spec 03 §16.4), unauthenticated: stored as sent (the server
     * cannot check `mac`). The first claim wins: a link not `open` is `409 link_claimed`. Audited.
     */
    api(WireRoute.DEVICE_LINK_CLAIM, s, Bucket.ipPerMinute("device_link_claim", 10)) {
        val linkId = DeviceLinks.pathId(param("linkId"))
        val req = body<DeviceLinkClaim>()
        Grammar.requireB64_32(req.nPub, "nPub")
        if (!TrustGrammar.isName(req.name)) badRequest(WireErrors.badField("name"))
        Grammar.requirePlatform(req.platform)
        Grammar.requireHex64(req.commitN, "commitN")
        Grammar.requireB64_32(req.mac, "mac")
        s.db.tx { c ->
            val r = DeviceLinks.live(c, linkId, now)
            if (r.state != DeviceLinkState.OPEN) conflict(WireErrors.LINK_CLAIMED)
            c.exec(
                "UPDATE device_links SET state='claimed', nPub=?, claimName=?, claimPlatform=?, commitN=?, claimMac=?, claimedAt=? WHERE linkId=? AND state='open'",
                req.nPub, req.name, req.platform, req.commitN, req.mac, now, linkId,
            )
            s.audit.on(c, "device_link_claim", r.userId, null, ip)
            bellUser(s, c, r.userId)
        }
        ok()
    }

    /** `POST /device-links/{linkId}/nonce` (spec 03 §16.5): E's nonce and `proofHash`, once, on a claimed link. */
    api(WireRoute.DEVICE_LINK_NONCE, s) {
        val linkId = DeviceLinks.pathId(param("linkId"))
        val req = body<DeviceLinkNonceRequest>()
        Grammar.requireB64_32(req.nonceE, "nonceE")
        Grammar.requireHex64(req.proofHash, "proofHash")
        val principal = p
        s.db.tx { c ->
            val r = DeviceLinks.own(c, linkId, principal.userId, principal.deviceId, now)
            if (r.state != DeviceLinkState.CLAIMED || r.nonceE != null) conflict(WireErrors.LINK_STATE)
            c.exec("UPDATE device_links SET nonceE=?, proofHash=? WHERE linkId=? AND nonceE IS NULL", req.nonceE, req.proofHash, linkId)
        }
        ok()
    }

    /**
     * `POST /device-links/{linkId}/poll` (spec 03 §16.5): N's view. `nonceE`, `outer` and `approveMac` only
     * against the right proof; once `proofHash` exists any other proof is `403 bad_proof`.
     */
    api(WireRoute.DEVICE_LINK_POLL, s, SharedBuckets.DEVICE_LINK_POLL) {
        val linkId = DeviceLinks.pathId(param("linkId"))
        val req = body<DeviceLinkPollRequest>()
        Grammar.requireB64_32(req.proof, "proof")
        val r = s.db.read { c -> DeviceLinks.live(c, linkId, now) }
        DeviceLinks.checkProof(r, req.proof)
        val resp = when {
            r.proofHash == null || r.nonceE == null -> DeviceLinkPollResponse(r.state)
            r.state == DeviceLinkState.APPROVED -> DeviceLinkPollResponse(r.state, r.nonceE, r.outer, r.approveMac)
            else -> DeviceLinkPollResponse(r.state, r.nonceE)
        }
        respond(resp)
    }

    /** `POST /device-links/{linkId}/reveal` (spec 03 §16.5): N's nonce, once, after E's; the state becomes `revealed`. */
    api(WireRoute.DEVICE_LINK_REVEAL, s, SharedBuckets.DEVICE_LINK_POLL) {
        val linkId = DeviceLinks.pathId(param("linkId"))
        val req = body<DeviceLinkRevealRequest>()
        Grammar.requireB64_32(req.nonceN, "nonceN")
        Grammar.requireB64_32(req.proof, "proof")
        s.db.tx { c ->
            val r = DeviceLinks.live(c, linkId, now)
            DeviceLinks.checkProof(r, req.proof)
            if (r.state != DeviceLinkState.CLAIMED || r.nonceE == null || r.nonceN != null) conflict(WireErrors.LINK_STATE)
            c.exec("UPDATE device_links SET state='revealed', nonceN=?, revealedAt=? WHERE linkId=? AND state='claimed'", req.nonceN, now, linkId)
            s.audit.on(c, "device_link_reveal", r.userId, null, ip)
            bellUser(s, c, r.userId)
        }
        ok()
    }

    /**
     * `POST /device-links/{linkId}/approve` (spec 03 §16.6): E's approval; no session is created here. Only
     * the device that created the link may approve: any other session, of this account or another, is
     * `404 link_unknown`. The approving device is recorded (`approvedBy`), so revoking it cancels the link
     * and the pickup re-checks it.
     */
    api(WireRoute.DEVICE_LINK_APPROVE, s) {
        val linkId = DeviceLinks.pathId(param("linkId"))
        val req = body<DeviceLinkApproveRequest>()
        Grammar.requireB64(req.outer, "outer", DeviceLinks.OUTER_MAX)
        Grammar.requireB64(req.inner, "inner", DeviceLinks.INNER_MAX)
        Grammar.requireB64_32(req.approveMac, "approveMac")
        val principal = p
        s.db.tx { c ->
            // Only the device that created the link approves (§16.6: E's session); another device of the
            // same account sees no such link, exactly as another account would.
            val r = DeviceLinks.own(c, linkId, principal.userId, principal.deviceId, now)
            if (r.state != DeviceLinkState.REVEALED) conflict(WireErrors.LINK_STATE)
            c.exec(
                "UPDATE device_links SET state='approved', outer=?, inner=?, approveMac=?, approvedAt=?, approvedBy=? WHERE linkId=? AND state='revealed'",
                req.outer, req.inner, req.approveMac, now, principal.deviceId, linkId,
            )
            s.audit.on(c, "device_link_approve", principal.userId, principal.deviceId, ip)
        }
        ok()
    }

    /**
     * `POST /device-links/{linkId}/pickup` (spec 03 §16.6), unauthenticated. Checks, in order: the per-IP
     * login bucket; the link (`404`, `410`); the email backoff; `proof` (`403 bad_proof`); `approved`
     * (`409 link_state`); `authKey` exactly like a login — the verifier, then the TOTP rules, a failure
     * the uniform `401` counted against the backoff (audited `device_link_pickup_denied`). `requireLink`
     * does not apply. Then one transaction re-checks what the gate checked outside it, exactly as login
     * does: the account is still `active` and its verifier is still the one the password matched (a password
     * change or recovery that committed in between makes this the uniform `401`), and the devices that created
     * and approved the link are still unrevoked (otherwise the link is gone: `404 link_unknown`). Only then it
     * creates the device (`how = linked`, `linkedFrom` E's device, name and platform from the claim) and its
     * session, deletes the link, and queues `new_device`.
     */
    api(WireRoute.DEVICE_LINK_PICKUP, s, SharedBuckets.login(s.config)) {
        val linkId = DeviceLinks.pathId(param("linkId"))
        val req = body<DeviceLinkPickupRequest>()
        Grammar.requireB64_32(req.proof, "proof")
        Grammar.requireB64(req.authKey, "authKey", Caps.AUTH_KEY)
        val secretHash = deviceSecretHash(req.device.deviceSecret) ?: badRequest(WireErrors.badField("device"))
        val r0 = s.db.read { c -> DeviceLinks.live(c, linkId, now) }
        val email = s.db.read { c -> c.queryOne("SELECT email FROM users WHERE userId=?", r0.userId) { it.getString(1) } } ?: notFound(WireErrors.LINK_UNKNOWN)
        // The sign-in's fixed 60 seconds, as at a sign-in (spec 03 §8): never the real wait of an address's lock.
        if (s.loginBackoff.blocked(email)) {
            recordLoginWait(s, email, r0.userId, ip, "pickup")
            rateLimited(60_000)
        }
        DeviceLinks.checkProof(r0, req.proof)
        if (r0.state != DeviceLinkState.APPROVED || r0.proofHash == null) conflict(WireErrors.LINK_STATE)
        val u = passwordGate(s, email, req.authKey, req.totp, ip, "device_link_pickup_denied")
        if (u.userId != r0.userId) {
            s.loginBackoff.fail(email)
            unauthorized()
        }
        val clientVersion = call.declaredClientVersion()
        s.raceHook?.invoke("pickup.afterGate")
        val result = s.db.tx { c ->
            val r = DeviceLinks.live(c, linkId, now)
            if (r.state != DeviceLinkState.APPROVED) conflict(WireErrors.LINK_STATE)
            if (r.userId != u.userId) notFound(WireErrors.LINK_UNKNOWN)
            val still = c.queryOne("SELECT verifier,status FROM users WHERE userId=?", u.userId) { it.getString(1) to it.getString(2) }
            if (still == null || still.second != "active" || still.first != u.verifier) {
                s.audit.on(c, "device_link_pickup_denied", u.userId, null, ip, "credential_changed")
                return@tx Result.failure(ApiException(401, WireErrors.INVALID_CREDENTIALS))
            }
            if (!s.sessions.deviceUnrevoked(c, r.userId, r.deviceId) || r.approvedBy == null || !s.sessions.deviceUnrevoked(c, r.userId, r.approvedBy)) {
                notFound(WireErrors.LINK_UNKNOWN)
            }
            // The claim route takes only a readable name, so the fallback is reached only through a row of an older or
            // restored database; the mail then shows the row without a name, never the server's own words as the device's.
            val claimed = TrustGrammar.decodeName(r.claimName!!)
            val name = claimed ?: "new device"
            val deviceId = s.sessions.createDevice(c, r.userId, r.claimPlatform!!, name, DeviceHow.LINKED, secretHash, clientVersion, linkedFrom = r.deviceId)
            val issued = s.sessions.issue(c, r.userId, deviceId, headerPlatform ?: r.claimPlatform, passwordLogin = true)
            c.exec("DELETE FROM device_links WHERE linkId=?", linkId)
            s.audit.on(c, "device_link_pickup", r.userId, deviceId, ip)
            // Both devices by the server's own words for them and their names in the narrow form a mail shows (MailDevices):
            // the new one's name is the claim's, sent by a device not yet signed in.
            val from = MailDevices.of(c, r.deviceId) ?: "your other device"
            notify(s, c, r.userId, "new_device", MailDevices.of(c, deviceId, isNew = true, ownName = claimed != null), mapOf("how" to "linked from $from"))
            // The session is a login's SessionResponse (spec 03 §16.6): role, two-step flags and account keys inside it.
            Result.success(io.silencelen.andvari.core.model.wire.DeviceLinkPickupResponse(r.inner!!, sessionResponse(c, s.config, r.userId, issued)))
        }
        val resp = result.getOrElse { e ->
            s.loginBackoff.fail(email)
            throw e
        }
        s.loginBackoff.success(email)
        respond(resp)
    }

    /** `DELETE /device-links/{linkId}` (spec 03 §16.2): E cancels in any state before pickup. */
    api(WireRoute.DEVICE_LINK_CANCEL, s) {
        val linkId = DeviceLinks.pathId(param("linkId"))
        val principal = p
        s.db.tx { c ->
            DeviceLinks.row(c, linkId)?.takeIf { it.userId == principal.userId } ?: notFound(WireErrors.LINK_UNKNOWN)
            c.exec("DELETE FROM device_links WHERE linkId=?", linkId)
        }
        ok()
    }

    // ---- your devices (spec 03 §16.7, §16.8) ----

    /** `GET /account/devices[?after=<deviceId>]`: one page of the account's devices, `live` derived, `current` the caller's. */
    api(WireRoute.DEVICES, s) {
        val principal = p
        val after = devicePageAfter()
        respondList(Device.serializer(), s.db.read { c -> deviceList(c, principal.userId, now, principal.deviceId, DEVICE_PAGE_ROWS, after) })
    }

    /**
     * `POST /account/devices/{deviceId}/revoke` (spec 03 §16.7), session†: another of the account's own
     * devices. The calling device is `400 cannot_target_self`; an unknown or foreign one `404 no_such_device`.
     * Its sessions are revoked, its `deviceSecret` hash cleared (never a known device again), its sockets
     * get `revoked`, and `device_removed` names the revoking device. Audited `account_device_revoke`.
     */
    api(WireRoute.DEVICE_REVOKE, s) {
        val req = body<ReauthRequest>()
        reauth(req.currentAuthKey)
        val target = param("deviceId").takeIf { WireGrammar.isUuid(it) } ?: notFound(WireErrors.NO_SUCH_DEVICE)
        val principal = p
        if (target == principal.deviceId) badRequest(WireErrors.CANNOT_TARGET_SELF)
        s.db.tx { c ->
            c.queryOne("SELECT 1 FROM devices WHERE deviceId=? AND userId=?", target, principal.userId) { true } ?: notFound(WireErrors.NO_SUCH_DEVICE)
            val removed = MailDevices.of(c, target) ?: "a device"
            s.sessions.revokeDevice(c, target)
            s.audit.on(c, "account_device_revoke", principal.userId, principal.deviceId, ip, "target=$target")
            notify(s, c, principal.userId, "device_removed", vars = mapOf("removed" to removed, "by" to "you, from ${MailDevices.of(c, principal.deviceId) ?: "another device"}"))
            afterCommit(c) {
                s.forgetDeviceCounters(listOf(target))
                s.notifier.notifyRevokedDevice(principal.userId, target)
            }
        }
        ok()
    }

    /** `PUT /account/require-link` (spec 03 §16.8), session†. Audited `require_link_set`. */
    api(WireRoute.REQUIRE_LINK, s) {
        val req = body<RequireLinkPut>()
        reauth(req.currentAuthKey)
        val principal = p
        s.db.tx { c ->
            c.exec("UPDATE users SET requireLink=? WHERE userId=?", req.enabled, principal.userId)
            s.audit.on(c, "require_link_set", principal.userId, principal.deviceId, ip, "enabled=${req.enabled}")
        }
        ok()
    }
}

/** A dirty bell for every socket of [userId] after commit (spec 03 §6), with a fresh rev. */
fun bellUser(s: Services, c: Connection, userId: String) {
    val rev = nextRev(c, "account", userId, null, s.clock.now())
    afterCommit(c) { s.notifier.notifyRev(listOf(userId), rev) }
}
