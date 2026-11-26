package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.model.wire.InstanceKind
import io.silencelen.andvari.core.model.wire.LinkAnswer
import io.silencelen.andvari.core.model.wire.LinkAnswerRequest
import io.silencelen.andvari.core.model.wire.LinkCreateRequest
import io.silencelen.andvari.core.model.wire.LinkCreatedResponse
import io.silencelen.andvari.core.model.wire.LinkFetchResponse
import io.silencelen.andvari.core.model.wire.LinkKind
import io.silencelen.andvari.core.model.wire.LinkRevealRequest
import io.silencelen.andvari.core.model.wire.LinkState
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireGrammar
import io.silencelen.andvari.core.model.wire.WireRoute
import java.sql.Connection

/** Links (spec 03 §15, design §6.6). The server sees ids, kinds, who and when, never `s` or an offer's contents. */
object LinkRules {
    const val CONNECT_MAX_MS = 7 * Clock.DAY_MS
    const val REGISTER_MAX_MS = 72 * Clock.HOUR_MS
    /** The slack a client-set expiry gets on its upper bound (design S3-Q6, SR-1). */
    const val SLACK_MS = 10 * 60_000L

    class Row(
        val linkId: String, val kind: String, val creatorUserId: String?, val expiresAt: Long, val offer: String,
        val state: String, val answererUserId: String?, val answeredAt: Long?, val deliveredAt: Long?, val reveal: String?,
    )

    fun row(c: Connection, linkId: String): Row? = c.queryOne(
        "SELECT linkId,kind,creatorUserId,expiresAt,offer,state,answererUserId,answeredAt,deliveredAt,reveal FROM links WHERE linkId=?", linkId,
    ) {
        Row(it.getString(1), it.getString(2), it.getString(3), it.getLong(4), it.getString(5), it.getString(6), it.getString(7),
            it.longOrNull("answeredAt"), it.longOrNull("deliveredAt"), it.getString(10))
    }

    /** A path `linkId` (`b64_16`); anything else names no link. */
    fun pathLinkId(raw: String): String = raw.takeIf { WireGrammar.isB64_16(it) } ?: notFound(WireErrors.LINK_UNKNOWN)

    /** The row [linkId] of [creator], or `404 link_unknown` (another account's link is unknown to the caller). */
    fun ownRow(c: Connection, linkId: String, creator: String): Row =
        row(c, linkId)?.takeIf { it.creatorUserId == creator } ?: notFound(WireErrors.LINK_UNKNOWN)

    /** Bump the global rev for a link event and ring [userIds] after commit (spec 03 §6). */
    fun bell(s: Services, c: Connection, linkId: String, userIds: List<String>, nowMs: Long) {
        val rev = nextRev(c, "link", linkId, null, nowMs)
        afterCommit(c) { s.notifier.notifyRev(userIds, rev) }
    }
}

fun Route.linkRoutes(s: Services) {
    /**
     * `POST /links` (spec 03 §15.2): `connect` or `register` only (`400 bad_kind`); the offer envelope;
     * `now < expiresAt <= now + max + 10 min` by the server's clock (`400 bad_expiry`); `tokenHash` for
     * `register` only (`400 bad_token_hash`); register links by members only on a private instance with
     * `ANDVARI_REGISTER_LINKS = members` (`403 not_operator`); at most `openLinks` open links
     * (`413 quota_exceeded {openLinks}`); 30 creations a day (the bucket); a known id is `409 link_id_taken`.
     * The expiry is stored as sent; the answer carries it and the milliseconds left. Audited `link_create`.
     */
    api(WireRoute.LINK_CREATE, s, Bucket.devicePerDay("link_create", 30)) {
        val req = body<LinkCreateRequest>()
        val linkId = Grammar.requireB64_16(req.linkId, "linkId")
        if (req.kind != LinkKind.CONNECT && req.kind != LinkKind.REGISTER) badRequest(WireErrors.BAD_KIND)
        Grammar.requireB64(req.offer, "offer", Caps.LINK_ENVELOPE)
        val max = if (req.kind == LinkKind.CONNECT) LinkRules.CONNECT_MAX_MS else LinkRules.REGISTER_MAX_MS
        val nowMs = now
        if (req.expiresAt <= nowMs || req.expiresAt > nowMs + max + LinkRules.SLACK_MS) badRequest(WireErrors.BAD_EXPIRY)
        val tokenHash = req.tokenHash
        if (req.kind == LinkKind.REGISTER) {
            if (tokenHash == null || tokenHash.length != 43 || !WireGrammar.isB64_32(tokenHash)) badRequest(WireErrors.BAD_TOKEN_HASH)
        } else if (tokenHash != null) badRequest(WireErrors.BAD_TOKEN_HASH)
        val principal = p
        if (req.kind == LinkKind.REGISTER) {
            val membersMay = s.config.instanceKind == InstanceKind.PRIVATE && s.config.registerLinks == "members"
            if (!membersMay && !principal.isOperator) forbidden(WireErrors.NOT_OPERATOR)
        }
        s.db.tx { c ->
            val quota = s.policy.quotaOf(c, principal.userId).openLinks
            val open = Quotas.openLinks(c, principal.userId, nowMs)
            if (open >= quota) quotaExceeded(QuotaName.OPEN_LINKS)
            if (c.queryOne("SELECT 1 FROM links WHERE linkId=?", linkId) { 1 } != null) conflict(WireErrors.LINK_ID_TAKEN)
            c.exec(
                "INSERT INTO links(linkId,kind,creatorUserId,createdAt,expiresAt,offer,tokenHash,state) VALUES(?,?,?,?,?,?,?,'open')",
                linkId, req.kind, principal.userId, nowMs, req.expiresAt, req.offer, tokenHash,
            )
            s.audit.on(c, "link_create", principal.userId, principal.deviceId, ip, "kind=${req.kind}")
        }
        respond(LinkCreatedResponse(req.expiresAt, req.expiresAt - nowMs))
    }

    /**
     * `GET /links/{linkId}` (spec 03 §15.3), unauthenticated: exactly two `200` shapes. Open and unexpired:
     * the offer with its creator (`creator*` null for host-minted links) and `reveal: null`; answered:
     * `{kind, state, reveal}` whatever its expiry. Open past expiry, or expired: `410 link_expired`;
     * revoked or unknown: `404 link_unknown`.
     */
    api(WireRoute.LINK_FETCH, s, Bucket.ipPerMinute("link_fetch", 30)) {
        val linkId = LinkRules.pathLinkId(param("linkId"))
        val nowMs = now
        val (row, creatorPub) = s.db.read { c ->
            val r = LinkRules.row(c, linkId)
            r to r?.creatorUserId?.let { id -> c.queryOne("SELECT identityPub FROM users WHERE userId=?", id) { it.getString(1) } }
        }
        val body = when {
            row == null || row.state == LinkState.REVOKED -> notFound(WireErrors.LINK_UNKNOWN)
            row.state == LinkState.ANSWERED -> LinkFetchResponse.answered(row.kind, row.reveal)
            row.state == LinkState.EXPIRED || row.expiresAt <= nowMs -> gone(WireErrors.LINK_EXPIRED)
            else -> LinkFetchResponse.open(row.kind, row.offer, row.expiresAt, row.creatorUserId, creatorPub?.takeIf { row.creatorUserId != null })
        }
        respondJsonText(body.toJsonObject().toString())
    }

    /**
     * `POST /links/{linkId}/answer` (spec 03 §15.4). Checks, in order: the row exists and is not revoked
     * (`404 link_unknown`); `connect` (`409 kind_mismatch`); unexpired (`410 link_expired`); `open`
     * (`409 link_used`: the first answer wins); not the creator (`400 cannot_target_self`). Then one
     * transaction stores the answer and writes the `connections` row. Rings the creator. Audited `link_answer`.
     */
    api(WireRoute.LINK_ANSWER, s) {
        val linkId = LinkRules.pathLinkId(param("linkId"))
        val req = body<LinkAnswerRequest>()
        Grammar.requireB64(req.answer, "answer", Caps.LINK_ENVELOPE)
        val principal = p
        val nowMs = now
        s.db.tx { c ->
            val row = LinkRules.row(c, linkId)
            if (row == null || row.state == LinkState.REVOKED) notFound(WireErrors.LINK_UNKNOWN)
            if (row.kind != LinkKind.CONNECT) conflict(WireErrors.KIND_MISMATCH)
            if (row.state == LinkState.EXPIRED || (row.state == LinkState.OPEN && row.expiresAt <= nowMs)) gone(WireErrors.LINK_EXPIRED)
            if (row.state != LinkState.OPEN) conflict(WireErrors.LINK_USED)
            if (row.creatorUserId == principal.userId) badRequest(WireErrors.CANNOT_TARGET_SELF)
            val changed = c.exec(
                "UPDATE links SET state='answered', stateChangedAt=?, answer=?, answererUserId=?, answeredAt=? WHERE linkId=? AND state='open'",
                nowMs, req.answer, principal.userId, nowMs, linkId,
            )
            if (changed != 1) conflict(WireErrors.LINK_USED)
            writeConnection(c, row.creatorUserId!!, principal.userId, nowMs)
            s.audit.on(c, "link_answer", principal.userId, principal.deviceId, ip)
            LinkRules.bell(s, c, linkId, listOf(row.creatorUserId), nowMs)
        }
        ok()
    }

    /**
     * `POST /links/{linkId}/reveal` (spec 03 §15.5): the creator's code nonce, stored once. A link the
     * caller did not create is `404 link_unknown`; one not answered, or already revealed, `409 link_state`.
     */
    api(WireRoute.LINK_REVEAL, s) {
        val linkId = LinkRules.pathLinkId(param("linkId"))
        val req = body<LinkRevealRequest>()
        Grammar.requireB64_32(req.nonce, "nonce")
        val principal = p
        s.db.tx { c ->
            val row = LinkRules.ownRow(c, linkId, principal.userId)
            if (row.state != LinkState.ANSWERED || row.reveal != null) conflict(WireErrors.LINK_STATE)
            if (c.exec("UPDATE links SET reveal=? WHERE linkId=? AND reveal IS NULL", req.nonce, linkId) != 1) conflict(WireErrors.LINK_STATE)
            row.answererUserId?.let { LinkRules.bell(s, c, linkId, listOf(it), now) }
        }
        ok()
    }

    /** `GET /links/answers` (spec 03 §15.6): the caller's answered, unacknowledged links. */
    api(WireRoute.LINK_ANSWERS, s) {
        val principal = p
        val rows = s.db.read { c ->
            c.queryAll(
                "SELECT linkId,answer,answererUserId,answeredAt FROM links WHERE creatorUserId=? AND state='answered' AND deliveredAt IS NULL AND answer IS NOT NULL ORDER BY answeredAt",
                principal.userId,
            ) { LinkAnswer(it.getString(1), it.getString(2), it.getString(3), it.getLong(4)) }
        }
        respondList(LinkAnswer.serializer(), rows)
    }

    /** `POST /links/{linkId}/ack` (spec 03 §15.6): sets `deliveredAt`; a repeat answers `ok` and changes nothing. */
    api(WireRoute.LINK_ACK, s) {
        val linkId = LinkRules.pathLinkId(param("linkId"))
        val principal = p
        s.db.tx { c ->
            val row = LinkRules.ownRow(c, linkId, principal.userId)
            if (row.state != LinkState.ANSWERED) conflict(WireErrors.LINK_STATE)
            c.exec("UPDATE links SET deliveredAt=? WHERE linkId=? AND deliveredAt IS NULL", now, linkId)
        }
        ok()
    }

    /** `DELETE /links/{linkId}` (spec 03 §15.7): the creator revokes an open link. Audited `link_revoke`. */
    api(WireRoute.LINK_REVOKE, s) {
        val linkId = LinkRules.pathLinkId(param("linkId"))
        val principal = p
        s.db.tx { c ->
            val row = LinkRules.ownRow(c, linkId, principal.userId)
            if (row.state != LinkState.OPEN) conflict(WireErrors.LINK_STATE)
            c.exec("UPDATE links SET state='revoked', stateChangedAt=? WHERE linkId=?", now, linkId)
            s.audit.on(c, "link_revoke", principal.userId, principal.deviceId, ip)
        }
        ok()
    }
}
