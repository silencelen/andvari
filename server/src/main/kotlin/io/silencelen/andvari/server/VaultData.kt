package io.silencelen.andvari.server

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.server.request.header
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respondOutputStream
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.websocket.webSocket
import io.ktor.websocket.CloseReason
import io.ktor.websocket.Frame
import io.ktor.websocket.close
import io.ktor.websocket.readText
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AccountStatePut
import io.silencelen.andvari.core.model.wire.AccountStateResponse
import io.silencelen.andvari.core.model.wire.AttachmentMeta
import io.silencelen.andvari.core.model.wire.DeletedItem
import io.silencelen.andvari.core.model.wire.DeletedItemsResponse
import io.silencelen.andvari.core.model.wire.EventsTicketResponse
import io.silencelen.andvari.core.model.wire.ItemUpload
import io.silencelen.andvari.core.model.wire.ItemVersion
import io.silencelen.andvari.core.model.wire.ItemVersionsResponse
import io.silencelen.andvari.core.model.wire.Mutation
import io.silencelen.andvari.core.model.wire.MutationStatus
import io.silencelen.andvari.core.model.wire.PushRequest
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.RemovedGrantInfo
import io.silencelen.andvari.core.model.wire.RevResponse
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncItem
import io.silencelen.andvari.core.model.wire.SyncLogHead
import io.silencelen.andvari.core.model.wire.SyncResponse
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.model.wire.UsagePut
import io.silencelen.andvari.core.model.wire.UsageResponse
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireGrammar
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.Serializable
import java.sql.Connection
import java.sql.ResultSet

/** Item rows, versions, pulls and pushes (spec 03 §4, §5, §5.1; spec 02 §7). */
object Items {
    const val BATCH_MAX = 200
    const val MUTATION_ID_MAX = 64
    const val ATTACHMENTS_MAX = 256
    const val VERSIONS_KEPT = 10
    const val ACCOUNT_STATE_SEALED_MAX = 1_048_576
    const val USAGE_SEALED_MAX = 512 * 1024

    fun item(rs: ResultSet) = SyncItem(
        itemId = rs.getString("itemId"), vaultId = rs.getString("vaultId"), rev = rs.getLong("rev"),
        createdAt = rs.getLong("createdAt"), updatedAt = rs.getLong("updatedAt"), deleted = rs.bool("deleted"),
        conflict = rs.bool("conflict"), formatVersion = rs.getInt("formatVersion"),
        attachmentIds = decodeIds(rs.getString("attachmentIds")), blob = rs.getString("blob"),
    )

    fun byId(c: Connection, itemId: String): SyncItem? = c.queryOne("SELECT * FROM items WHERE itemId=?", itemId) { item(it) }

    fun archive(c: Connection, it: SyncItem, nowMs: Long) {
        val blob = it.blob ?: return
        c.exec("INSERT OR REPLACE INTO item_versions(itemId,rev,blob,formatVersion,archivedAt) VALUES(?,?,?,?,?)", it.itemId, it.rev, blob, it.formatVersion, nowMs)
        c.exec(
            "DELETE FROM item_versions WHERE itemId=? AND rev NOT IN (SELECT rev FROM item_versions WHERE itemId=? ORDER BY rev DESC LIMIT ?)",
            it.itemId, it.itemId, VERSIONS_KEPT,
        )
    }

    fun members(c: Connection, vaultId: String): Set<String> =
        c.queryAll("SELECT userId FROM grants WHERE vaultId=? AND revokedAt IS NULL", vaultId) { it.getString(1) }.toSet()

    /** The shape of an `attachmentIds` list (spec 03 §5, F1), before its members are resolved. */
    fun attachmentListReason(ids: List<String>): String? = when {
        ids.size > ATTACHMENTS_MAX -> WireErrors.TOO_MANY_ATTACHMENTS
        ids.size != ids.toHashSet().size -> WireErrors.DUPLICATE_ATTACHMENT
        ids.any { !WireGrammar.isUuid(it) } -> WireErrors.BAD_ATTACHMENT_ID
        else -> null
    }

    /** Every reference exists, is bound to this item and vault, and fits the per-item ceiling (spec 03 §9). */
    fun attachmentRefReason(s: Services, c: Connection, itemId: String, vaultId: String, ids: List<String>): String? {
        var total = 0L
        for (aid in ids) {
            val row = s.attachments.rowById(c, aid) ?: return WireErrors.UNKNOWN_ATTACHMENT
            if (row.vaultId != vaultId) return WireErrors.UNKNOWN_ATTACHMENT
            if (row.itemId != itemId) return WireErrors.ATTACHMENT_MISMATCH
            total += row.size
        }
        if (total > s.attachments.maxCipherBytes(s.policy.get().itemAttachmentsMaxBytes)) return WireErrors.ITEM_ATTACHMENT_QUOTA
        return null
    }

    /**
     * The owner-quota ledger of one push batch (spec 03 §14.4): the owner's bytes and item count are read
     * once per owner, and the batch's own growth is added on top, so 200 puts cannot each see the
     * pre-batch total. A put that shrinks or keeps an item, and every delete, is never refused.
     */
    class Ledger(private val s: Services, private val c: Connection) {
        private val bytes = HashMap<String, Long>()
        private val items = HashMap<String, Long>()

        /** null when admitted, else the quota name that refuses it. */
        fun admit(vaultId: String, deltaBytes: Long, deltaItems: Long): String? {
            val owner = Quotas.ownerOf(c, vaultId) ?: return null
            val q = s.policy.quotaOf(c, owner)
            val b = bytes.getOrPut(owner) { Quotas.ownedBytes(c, owner) }
            val n = items.getOrPut(owner) { Quotas.ownedItems(c, owner) }
            if (deltaBytes > 0 && b + deltaBytes > q.accountBytes) return QuotaName.ACCOUNT_BYTES
            if (deltaItems > 0 && n + deltaItems > q.items) return QuotaName.ITEMS
            bytes[owner] = b + deltaBytes
            items[owner] = n + deltaItems
            return null
        }
    }

    /** A device's journal keeps its newest rows only (spec 03 §5: the dedup window). */
    const val JOURNAL_PER_DEVICE = 1000

    /** Drop [deviceId]'s journal rows beyond its newest [JOURNAL_PER_DEVICE]. */
    fun capJournal(c: Connection, deviceId: String) {
        c.exec(
            "DELETE FROM mutations WHERE deviceId=? AND rowid NOT IN (SELECT rowid FROM mutations WHERE deviceId=? ORDER BY rowid DESC LIMIT ?)",
            deviceId, deviceId, JOURNAL_PER_DEVICE,
        )
    }

    /**
     * The stored items one push answer carries (spec 03 §5): each stored item (an itemId at one rev) at most
     * once, and no more than [capBytes] of them in all, the push request's own body cap. A result past either
     * limit carries no item and says `serverItemOmitted: true` (the client pulls).
     */
    class Echo(private val capBytes: Long) {
        private val seen = HashSet<String>()
        private var used = 0L

        fun attach(r: PushResult, item: SyncItem?): PushResult {
            if (item == null) return r
            val cost = (item.blob?.length ?: 0).toLong() + 40L * item.attachmentIds.size + 256
            // A deletion's mark (a tombstone: no blob, no attachments) is never left out: it is how a put that brought a
            // deleted item back tells its client that the version it displaced was a deletion. At most one per result,
            // about 300 bytes each, so an answer grows by at most 60 KB past the cap.
            if (item.deleted) {
                used += cost
                return r.copy(serverItem = item)
            }
            if (!seen.add("${item.itemId}:${item.rev}") || used + cost > capBytes) return r.copy(serverItemOmitted = true)
            used += cost
            return r.copy(serverItem = item)
        }
    }

    /**
     * The displaced version of a replayed conflicting put, read at answer time from the history (spec 03 §5):
     * null once it has left the history (pruned past the ten kept, or purged with the item).
     */
    fun displaced(c: Connection, current: SyncItem, rev: Long, updatedAt: Long?): SyncItem? =
        c.queryOne("SELECT blob,formatVersion,archivedAt FROM item_versions WHERE itemId=? AND rev=?", current.itemId, rev) { rs ->
            SyncItem(
                itemId = current.itemId, vaultId = current.vaultId, rev = rev, createdAt = current.createdAt,
                updatedAt = updatedAt ?: rs.getLong("archivedAt"), deleted = false, conflict = false,
                formatVersion = rs.getInt("formatVersion"), attachmentIds = emptyList(), blob = rs.getString("blob"),
            )
        }

    /** `GET /sync` (spec 03 §4): one consistent snapshot. */
    fun pull(s: Services, c: Connection, userId: String, since: Long): SyncResponse {
        val rev = currentRev(c)
        val vaults = c.queryAll(
            """SELECT v.* FROM vaults v JOIN grants g ON g.vaultId=v.vaultId
               WHERE g.userId=? AND g.revokedAt IS NULL AND (v.rev>? OR g.rev>?)""",
            userId, since, since,
        ) { rs ->
            SyncVault(
                rs.getString("vaultId"), rs.getString("type"), rs.getLong("rev"), rs.getString("metaBlob"), rs.getLong("createdAt"),
                rs.longOrNull("logSeq")?.let { SyncLogHead(it, rs.getString("logHash")) },
            )
        }
        val grants = c.queryAll("SELECT * FROM grants WHERE userId=? AND revokedAt IS NULL AND rev>?", userId, since) { rs ->
            SyncGrant(rs.getString("vaultId"), rs.getString("userId"), rs.getString("role"), rs.getString("wrappedVk"), rs.getLong("rev"), rs.getString("signedGrant"))
        }
        val items = c.queryAll(
            """SELECT i.* FROM items i JOIN grants g ON g.vaultId=i.vaultId WHERE g.userId=? AND g.revokedAt IS NULL AND i.rev>?
               UNION ALL
               SELECT i.* FROM items i JOIN grants g ON g.vaultId=i.vaultId WHERE g.userId=? AND g.revokedAt IS NULL AND g.rev>? AND i.rev<=?""",
            userId, since, userId, since, since,
        ) { item(it) }
        val removed = c.queryAll(
            """SELECT g.vaultId, g.revokedReason, v.deletedAt, v.purgeAt FROM grants g JOIN vaults v ON v.vaultId=g.vaultId
               WHERE g.userId=? AND g.revokedAt IS NOT NULL AND g.rev>?""",
            userId, since,
        ) { rs ->
            when (rs.getString("revokedReason")) {
                "vault_delete" -> RemovedGrantInfo(rs.getString(1), "deleted", rs.longOrNull("deletedAt"), rs.longOrNull("purgeAt"))
                "member_leave" -> RemovedGrantInfo(rs.getString(1), "left")
                else -> RemovedGrantInfo(rs.getString(1), "removed")
            }
        }
        val linkAnswers = c.count("SELECT COUNT(*) FROM links WHERE creatorUserId=? AND state='answered' AND deliveredAt IS NULL AND answer IS NOT NULL", userId)
        // The same rows `GET /account/recovery-requests` lists (pending, `ready` included), so the two never disagree.
        val recoveryRequests = if (s.config.isPublic) 0L else Assisted.pendingOf(c, userId, s.clock.now()).size.toLong()
        return SyncResponse(rev, since == 0L, vaults, grants, items, removed.map { it.vaultId }, removed, linkAnswers.toInt(), recoveryRequests.toInt())
    }
}

fun Route.vaultDataRoutes(s: Services) {
    /** `GET /sync?since=<rev>` (spec 03 §4); `410 resync_required` for a cursor before retained history. */
    api(WireRoute.SYNC, s) {
        val since = query("since")?.let { parseInt(it) ?: badRequest(WireErrors.badField("since")) } ?: 0L
        val principal = p
        val nowMs = now
        val (pulled, stateSeq) = s.db.read { c ->
            val oldest = c.queryOne("SELECT value FROM meta WHERE key='oldestRetainedRev'") { it.getString(1).toLong() } ?: 0L
            if (since in 1 until oldest) gone(WireErrors.RESYNC_REQUIRED)
            // The caller's own meters ride every answer, full or delta, read in the same snapshot (spec 03 §4, §14.4),
            // and so does the account state's seq.
            (Items.pull(s, c, principal.userId, since) to QuotaUses.of(s, c, principal.userId, nowMs)) to accountState(c, principal.userId).seq
        }
        respondJsonText(syncWithStateSeq(QuotaUses.syncJson(pulled.first, pulled.second), stateSeq))
    }

    /**
     * `POST /sync/push` (spec 03 §5): up to 200 mutations, in order, in ONE transaction. Thrown validation
     * (`batch_too_large`, `bad_op`, `put_without_item`) rolls the whole batch back; `denied` and `rejected`
     * are per mutation. A replayed `mutationId` is answered from the journal's status and rev; the journal holds
     * no vault content (spec 02 §5), and the stored items one answer echoes are bounded by [Items.Echo].
     */
    api(WireRoute.PUSH, s, Bucket.devicePerMinute("sync_push", s.config.pushRatePerMin)) {
        val req = body<PushRequest>()
        if (req.mutations.size > Items.BATCH_MAX) badRequest(WireErrors.BATCH_TOO_LARGE)
        val principal = p
        val ring = HashSet<String>()
        val unlink = ArrayList<String>()
        val denied = ArrayList<String>()
        val results = try {
            s.db.tx { c ->
                val ledger = Items.Ledger(s, c)
                val echo = Items.Echo(BODY_CAP_PUSH)
                var journaled = false
                // Each stored item is attached (or omitted) as soon as its mutation is decided, so the answer
                // never holds more than the echo cap of item content at once.
                val out = req.mutations.map { m ->
                    val o = applyMutation(s, c, principal, m, ring, unlink, denied, ledger)
                    journaled = journaled || o.journaled
                    echo.attach(o.result, o.item)
                }
                if (journaled) Items.capJournal(c, principal.deviceId)
                out
            }
        } finally {
            if (denied.isNotEmpty()) s.db.tx { c -> denied.forEach { s.audit.on(c, "push_denied", principal.userId, principal.deviceId, ip, it) } }
        }
        s.attachments.unlinkOrphaned(unlink)
        val rev = s.db.read { currentRev(it) }
        if (ring.isNotEmpty()) s.notifier.notifyRev(ring, rev)
        respond(PushAnswer.serializer(), PushAnswer(rev, results))
    }

    /** `GET /items/{itemId}/versions` (spec 03 §4): grant-checked; unknown and foreign both `403 no_grant`. */
    api(WireRoute.ITEM_VERSIONS, s) {
        val itemId = param("itemId").takeIf { WireGrammar.isUuid(it) } ?: forbidden(WireErrors.NO_GRANT)
        val principal = p
        val resp = s.db.read { c ->
            val it0 = Items.byId(c, itemId) ?: forbidden(WireErrors.NO_GRANT)
            if (Quotas.role(c, principal.userId, it0.vaultId) == null) forbidden(WireErrors.NO_GRANT)
            ItemVersionsResponse(itemId, c.queryAll("SELECT rev,blob,formatVersion,archivedAt FROM item_versions WHERE itemId=? ORDER BY rev DESC", itemId) {
                ItemVersion(it.getLong(1), it.getString(2), it.getInt(3), it.getLong(4))
            })
        }
        respond(resp)
    }

    /**
     * `GET /items/deleted[?after=<deletedAt>:<itemId>]` (spec 03 §5.1): one page of at most [DELETED_PAGE_ROWS]
     * tombstones, newest first in `(deletedAt, itemId)` descending order, starting after the row the cursor names.
     */
    api(WireRoute.ITEMS_DELETED, s) {
        val principal = p
        val after = query("after")?.let { a ->
            val at = a.substringBefore(':', "").takeIf { it.length in 1..15 && it.all { ch -> ch in '0'..'9' } }?.toLong()
            val id = a.substringAfter(':', "").takeIf { WireGrammar.isUuid(it) }
            if (at == null || id == null) badRequest(WireErrors.BAD_REQUEST)
            at to id
        }
        val rows = s.db.read { c ->
            c.queryAll(
                """SELECT i.itemId,i.vaultId,i.updatedAt FROM items i JOIN grants g ON g.vaultId=i.vaultId
                   WHERE g.userId=? AND g.revokedAt IS NULL AND i.deleted=1
                     AND (? IS NULL OR i.updatedAt<? OR (i.updatedAt=? AND i.itemId<?))
                   ORDER BY i.updatedAt DESC, i.itemId DESC LIMIT ?""",
                principal.userId, after?.first, after?.first, after?.first, after?.second, DELETED_PAGE_ROWS,
            ) { DeletedItem(it.getString(1), it.getString(2), it.getLong(3)) }
        }
        respond(DeletedItemsResponse(rows))
    }

    /** `POST /items/{itemId}/restore` (spec 03 §5.1): push's checks, thrown; the owner's quota. */
    api(WireRoute.ITEM_RESTORE, s, Bucket.devicePerHour("item_recovery", 400)) {
        val itemId = param("itemId").takeIf { WireGrammar.isUuid(it) } ?: forbidden(WireErrors.NO_GRANT)
        val up = body<ItemUpload>()
        val principal = p
        var fvDenied = false
        val rev = s.db.tx { c ->
            val existing = Items.byId(c, itemId) ?: forbidden(WireErrors.NO_GRANT)
            val role = Quotas.role(c, principal.userId, existing.vaultId)
            if (role == null || role == "reader") forbidden(WireErrors.NO_GRANT)
            if (!existing.deleted) badRequest(WireErrors.ITEM_NOT_DELETED)
            if (up.formatVersion < existing.formatVersion) {
                s.audit.on(c, "push_denied", principal.userId, principal.deviceId, ip, "fv_downgrade:${existing.vaultId}:$itemId")
                fvDenied = true
                return@tx 0L
            }
            Items.attachmentListReason(up.attachmentIds)?.let { badRequest(it) }
            when (val r = Items.attachmentRefReason(s, c, itemId, existing.vaultId, up.attachmentIds)) {
                null -> {}
                WireErrors.ITEM_ATTACHMENT_QUOTA -> throw ApiException(413, r)
                else -> badRequest(r)
            }
            val size = up.blob.length.toLong()
            if (size > s.config.itemMaxBytes) throw ApiException(413, WireErrors.ITEM_TOO_LARGE)
            Items.Ledger(s, c).admit(existing.vaultId, size, 1)?.let { quotaExceeded(it) }
            val rev = nextRev(c, "item", itemId, existing.vaultId, now)
            c.exec(
                "UPDATE items SET rev=?, updatedAt=?, deleted=0, conflict=0, formatVersion=?, attachmentIds=?, blob=?, blobSize=? WHERE itemId=?",
                rev, now, up.formatVersion, encodeIds(up.attachmentIds), up.blob, size, itemId,
            )
            s.audit.on(c, "item_restore", principal.userId, principal.deviceId, ip, "${existing.vaultId}:$itemId")
            val ring = Items.members(c, existing.vaultId)
            afterCommit(c) { s.notifier.notifyRev(ring, rev) }
            rev
        }
        if (fvDenied) badRequest(WireErrors.FV_DOWNGRADE)
        respond(RevResponse(rev))
    }

    /** `POST /items/{itemId}/purge` (spec 03 §5.1): "Delete forever" a tombstoned item and its versions. */
    api(WireRoute.ITEM_PURGE, s, Bucket.devicePerHour("item_destructive", 200)) {
        val itemId = param("itemId").takeIf { WireGrammar.isUuid(it) } ?: forbidden(WireErrors.NO_GRANT)
        val principal = p
        s.db.tx { c ->
            val existing = Items.byId(c, itemId) ?: forbidden(WireErrors.NO_GRANT)
            val role = Quotas.role(c, principal.userId, existing.vaultId)
            if (role == null || role == "reader") forbidden(WireErrors.NO_GRANT)
            if (!existing.deleted) badRequest(WireErrors.ITEM_NOT_DELETED)
            c.exec("DELETE FROM item_versions WHERE itemId=?", itemId)
            c.exec("DELETE FROM items WHERE itemId=?", itemId)
            s.audit.on(c, "item_purge", principal.userId, principal.deviceId, ip, "${existing.vaultId}:$itemId")
        }
        respond(RevResponse(s.db.read { currentRev(it) }))
    }

    /** `POST /attachments/{attachmentId}?vaultId=&itemId=` (spec 03 §9): streamed, writer/owner only. */
    api(WireRoute.ATTACHMENT_UPLOAD, s, Bucket.devicePerHour("attachment_upload", 600)) {
        val aid = Grammar.requireUuid(param("attachmentId"), "attachmentId")
        val vaultId = Grammar.requireUuid(query("vaultId"), "vaultId")
        val itemId = Grammar.requireUuid(query("itemId"), "itemId")
        val principal = p
        s.db.read { c ->
            val role = Quotas.role(c, principal.userId, vaultId)
            if (role == null) forbidden(WireErrors.NO_GRANT)
            if (role == "reader") forbidden(WireErrors.NO_WRITE_GRANT)
        }
        val meta = s.attachments.store(principal.userId, aid, itemId, vaultId, call.receiveChannel())
        respond(AttachmentMeta.serializer(), meta)
    }

    /** `GET /attachments/{attachmentId}` (spec 03 §9): any grant on the owning vault; otherwise hidden-as-403. */
    api(WireRoute.ATTACHMENT_GET, s) {
        val aid = param("attachmentId").takeIf { WireGrammar.isUuid(it) } ?: forbidden(WireErrors.NO_GRANT)
        val principal = p
        val header = s.db.read { c ->
            val row = c.queryOne("SELECT vaultId,header FROM attachments WHERE attachmentId=?", aid) { it.getString(1) to it.getString(2) } ?: forbidden(WireErrors.NO_GRANT)
            if (Quotas.role(c, principal.userId, row.first) == null) forbidden(WireErrors.NO_GRANT)
            Bytes.fromB64(row.second)
        }
        val f = s.attachments.file(aid)
        if (!f.isFile) forbidden(WireErrors.NO_GRANT)
        call.respondOutputStream(ContentType.Application.OctetStream) {
            write(header)
            f.inputStream().use { it.copyTo(this) }
        }
    }

    /** `POST /events/ticket` (spec 03 §6): a single-use 30-second ticket, in memory only. */
    api(WireRoute.EVENTS_TICKET, s, Bucket.devicePerMinute("ws_ticket", 60)) {
        val principal = p
        respond(EventsTicketResponse(s.tickets.mint(principal.userId, principal.deviceId, principal.sessionId), 30))
    }

    /**
     * `GET /events` (spec 03 §6): `?ticket=` or a bearer (never a raw token in the query). The socket is
     * registered first and revocation re-checked after, so a concurrent revoke always tears it down.
     */
    webSocket(EVENTS_PATH) {
        val ticketAuth = call.request.queryParameters["ticket"]?.let { s.tickets.redeem(it) }
        val auth = ticketAuth
            ?: call.request.header(HttpHeaders.Authorization)?.removePrefix("Bearer ")?.trim()
                ?.let { t -> s.db.read { c -> s.sessions.authenticate(c, t) } }
                ?.takeIf { !it.restricted }
                ?.let { EventsTicketStore.Redeemed(it.userId, it.deviceId, it.sessionId) }
        if (auth == null) {
            close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "unauthorized"))
            return@webSocket
        }
        // The bearer upgrade draws on its own bucket, per device with its ceiling per account, as minting
        // a ticket does (`ws_ticket`); over it the socket is closed 1013 (try again later) before it is registered.
        if (ticketAuth == null && s.limiter.drawDevice(WS_BEARER_BUCKET, auth.userId, auth.deviceId) != null) {
            close(CloseReason(CloseReason.Codes.TRY_AGAIN_LATER, "rate_limited"))
            return@webSocket
        }
        s.notifier.register(auth.userId, auth.deviceId, auth.sessionId, this)
        var recheck: Job? = null
        try {
            if (!s.db.read { c -> s.sessions.deviceHasLiveSession(c, auth.deviceId) }) {
                close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "unauthorized"))
                return@webSocket
            }
            // Re-check the session on a timer, so a revoke made outside this process
            // (`andvari admin disable`) still ends with `revoked` and the close.
            recheck = launch {
                while (true) {
                    delay(s.notifier.recheckMs)
                    if (!s.db.read { c -> s.sessions.deviceHasLiveSession(c, auth.deviceId) }) {
                        runCatching { withTimeoutOrNull(2_000) { outgoing.send(Frame.Text(Notifier.REVOKED)) } }
                        runCatching { close(CloseReason(CloseReason.Codes.VIOLATED_POLICY, "revoked")) }
                        break
                    }
                }
            }
            for (frame in incoming) {
                if (frame is Frame.Text && frame.readText() == "ping") outgoing.send(Frame.Text("pong"))
            }
        } finally {
            recheck?.cancel()
            s.notifier.unregister(auth.userId, this)
        }
    }

    // ---- account state and usage (spec 03 §3) ----

    api(WireRoute.ACCOUNT_STATE_GET, s) {
        val principal = p
        respond(s.db.read { c -> accountState(c, principal.userId) })
    }

    /** `PUT /account/state` (spec 03 §3): compare-and-set on the served counter; `409 stale_state` otherwise. */
    api(WireRoute.ACCOUNT_STATE_PUT, s, Bucket.devicePerMinute("account_state", 60)) {
        val req = body<AccountStatePut>()
        checkSealedState(req.sealedState)
        val principal = p
        respond(s.db.tx { c -> putAccountState(c, principal.userId, req, now) })
    }

    api(WireRoute.USAGE_GET, s) {
        val principal = p
        val r = s.db.read { c ->
            c.queryOne("SELECT sealedUsage,updatedAt FROM usage_ledger WHERE userId=?", principal.userId) { UsageResponse(it.getString(1), it.getLong(2)) }
        } ?: UsageResponse(null, 0)
        respond(r)
    }

    /** `PUT /usage` (spec 03 §3): one opaque blob per account, last writer wins; not audited. */
    api(WireRoute.USAGE_PUT, s, Bucket.devicePerMinute("usage", 60)) {
        val req = body<UsagePut>()
        if (req.sealedUsage.isEmpty() || req.sealedUsage.length > Items.USAGE_SEALED_MAX) badRequest(WireErrors.BAD_USAGE_BLOB)
        val principal = p
        s.db.tx { c ->
            c.exec(
                "INSERT INTO usage_ledger(userId,sealedUsage,updatedAt) VALUES(?,?,?) ON CONFLICT(userId) DO UPDATE SET sealedUsage=excluded.sealedUsage, updatedAt=excluded.updatedAt",
                principal.userId, req.sealedUsage, now,
            )
        }
        ok()
    }

    /** `GET /hibp/range/{prefix}` (spec 03 §8): a stateless relay for item passwords. */
    api(WireRoute.HIBP_RANGE, s, Bucket.devicePerMinute("hibp", 600)) {
        val body = s.hibp.range(param("prefix"))
        call.respondText(body, ContentType.Text.Plain)
    }
}

fun checkSealedState(sealed: String) {
    if (sealed.isEmpty() || sealed.length > Items.ACCOUNT_STATE_SEALED_MAX) badRequest(WireErrors.BAD_ACCOUNT_STATE)
}

/**
 * The sync answer with `accountStateSeq` added (spec 03 §4; additive; for the app interface): the account
 * state's `seq`, the counter its compare-and-set write advances by one at every write (§3) and that nothing lowers, 0
 * before the first write. A device that holds the state at some `seq` learns from any sync, full or delta, that
 * another device of the account wrote it since, without reading the state at every sync.
 */
fun syncWithStateSeq(syncJson: String, seq: Long): String {
    val tree = WireJson.json.parseToJsonElement(syncJson) as kotlinx.serialization.json.JsonObject
    return kotlinx.serialization.json.JsonObject(tree + ("accountStateSeq" to kotlinx.serialization.json.JsonPrimitive(seq))).toString()
}

fun accountState(c: Connection, userId: String): AccountStateResponse =
    c.queryOne("SELECT sealedState,seq FROM account_state WHERE userId=?", userId) { AccountStateResponse(it.getString(1), it.getLong(2)) }
        ?: AccountStateResponse(null, 0)

/** The compare-and-set write of the account state (spec 03 §3, §3.1). */
fun putAccountState(c: Connection, userId: String, req: AccountStatePut, nowMs: Long): AccountStateResponse {
    val current = c.queryOne("SELECT seq FROM account_state WHERE userId=?", userId) { it.getLong(1) } ?: 0L
    if (req.baseSeq != current) conflict(WireErrors.STALE_STATE)
    val next = current + 1
    c.exec(
        "INSERT INTO account_state(userId,sealedState,seq,updatedAt) VALUES(?,?,?,?) ON CONFLICT(userId) DO UPDATE SET sealedState=excluded.sealedState, seq=excluded.seq, updatedAt=excluded.updatedAt",
        userId, req.sealedState, next, nowMs,
    )
    return AccountStateResponse(req.sealedState, next)
}

/**
 * One result of `POST /sync/push` (spec 03 §5): the wire `MutationResult` plus `serverItemOmitted`, true when
 * the result would have carried a stored item that the answer left out (the client pulls for it).
 */
@Serializable
data class PushResult(
    val mutationId: String,
    val status: String,
    val newItemRev: Long? = null,
    val serverItem: SyncItem? = null,
    val reason: String? = null,
    val serverItemOmitted: Boolean? = null,
)

/**
 * One page of the trash list (spec 03 §5.1). Every row is exactly 125 bytes or less (two `uuid`s and a 13-digit
 * millisecond time), so a page is at most 65,536 × 125 + 12 = 8,192,012 bytes, inside the 8 MiB a client reads
 * (§0.4), and a client that does not page yet still receives the whole trash of anyone with up to 65,536 tombstones.
 */
const val DELETED_PAGE_ROWS = 65_536

/** The answer of `POST /sync/push` (spec 03 §5). */
@Serializable
data class PushAnswer(val rev: Long, val results: List<PushResult>)

/**
 * A row of the push journal (spec 02 §5, spec 03 §5): the outcome's status, revs and reason, and the ids it
 * names, never vault content. A replayed conflict reads its stored item at answer time.
 */
@Serializable
internal data class JournalRow(
    val status: String,
    val newItemRev: Long? = null,
    val reason: String? = null,
    val op: String,
    val itemId: String,
    val vaultId: String,
    /** A conflicting put: the rev of the version it displaced (kept in `item_versions`) and its update time. */
    val displacedRev: Long? = null,
    val displacedAt: Long? = null,
    /**
     * A put that brought a deleted item back: the deletion's mark it displaced, as the first answer served it (ids, revs,
     * times and the format version; a tombstone holds no blob and no attachments). A replay serves it again, also after the
     * item has left the server. Absent on rows journaled before it existed.
     */
    val displacedTombstone: SyncItem? = null,
)

/** One mutation decided: its result without any item, the stored item it may carry, and whether it was journaled. */
private class Outcome(val result: PushResult, val item: SyncItem? = null, val journaled: Boolean = false)

private fun result(m: Mutation, status: String, rev: Long? = null, reason: String? = null) = PushResult(m.mutationId, status, rev, reason = reason)

/** One mutation of a push (spec 03 §5). */
private fun applyMutation(
    s: Services, c: Connection, p: Principal, m: Mutation, ring: MutableSet<String>, unlink: MutableList<String>,
    denied: MutableList<String>, ledger: Items.Ledger,
): Outcome {
    if (m.mutationId.isEmpty() || m.mutationId.length > Items.MUTATION_ID_MAX) {
        return Outcome(PushResult(m.mutationId.take(Items.MUTATION_ID_MAX), MutationStatus.REJECTED, reason = "bad_mutation_id"))
    }
    c.queryOne("SELECT resultJson FROM mutations WHERE deviceId=? AND mutationId=?", p.deviceId, m.mutationId) { it.getString(1) }
        ?.let { return replay(c, p, m, WireJson.json.decodeFromString(JournalRow.serializer(), it)) }
    if (!WireGrammar.isUuid(m.itemId) || !WireGrammar.isUuid(m.vaultId)) return Outcome(result(m, MutationStatus.REJECTED, reason = "bad_item_id"))
    if (m.op != "put" && m.op != "delete") badRequest(WireErrors.BAD_OP)
    val role = Quotas.role(c, p.userId, m.vaultId)
    val existing = if (role == null || role == "reader") null else Items.byId(c, m.itemId)
    val nowMs = s.clock.now()
    val decided = when {
        role == null || role == "reader" -> {
            denied += "${m.vaultId}:${m.itemId}"
            Decided(result(m, MutationStatus.DENIED))
        }
        existing != null && existing.vaultId != m.vaultId -> {
            denied += "vault_mismatch:${m.vaultId}:${m.itemId}"
            Decided(result(m, MutationStatus.DENIED))
        }
        m.op == "put" -> applyPut(s, c, m, existing, ring, denied, ledger, nowMs)
        else -> applyDelete(s, c, m, existing, ring, unlink, nowMs)
    }
    val r = decided.result
    // Journaled: an applied or conflicting outcome on an item that exists now or existed before; a delete of
    // an item that never existed changes nothing and is answered afresh on a replay.
    val journal = (r.status == MutationStatus.APPLIED || r.status == MutationStatus.CONFLICT) && (existing != null || m.op == "put")
    if (journal) {
        val row = JournalRow(
            r.status, r.newItemRev, r.reason, m.op, m.itemId, m.vaultId, decided.displaced?.rev, decided.displaced?.updatedAt,
            decided.displaced?.takeIf { it.deleted },
        )
        c.exec(
            "INSERT INTO mutations(deviceId,mutationId,resultJson,createdAt,userId) VALUES(?,?,?,?,?)",
            p.deviceId, m.mutationId, WireJson.json.encodeToString(JournalRow.serializer(), row), nowMs, p.userId,
        )
    }
    return Outcome(r, decided.item, journal)
}

/** A replayed `mutationId` (spec 03 §5): the journal's status and rev; a conflict's stored item read now. */
private fun replay(c: Connection, p: Principal, m: Mutation, row: JournalRow): Outcome {
    val r = PushResult(m.mutationId, row.status, row.newItemRev, reason = row.reason)
    if (row.status != MutationStatus.CONFLICT || Quotas.role(c, p.userId, row.vaultId) == null) return Outcome(r)
    // A put that brought a deleted item back: the deletion's mark, as the first answer served it (never in the history).
    if (row.op == "put") row.displacedTombstone?.let { return Outcome(r, it) }
    val current = Items.byId(c, row.itemId)?.takeIf { it.vaultId == row.vaultId } ?: return Outcome(r)
    val item = if (row.op == "put") row.displacedRev?.let { Items.displaced(c, current, it, row.displacedAt) } else current
    return Outcome(r, item)
}

/** What one put or delete decided: the result, the stored item it carries, and for a conflicting put the displaced version. */
private class Decided(val result: PushResult, val item: SyncItem? = null, val displaced: SyncItem? = null)

private fun applyPut(
    s: Services, c: Connection, m: Mutation, existing: SyncItem?, ring: MutableSet<String>, denied: MutableList<String>,
    ledger: Items.Ledger, nowMs: Long,
): Decided {
    val item = m.item ?: badRequest(WireErrors.PUT_WITHOUT_ITEM)
    val size = item.blob.length.toLong()
    fun reject(reason: String) = Decided(result(m, MutationStatus.REJECTED, reason = reason), existing)
    if (size > s.config.itemMaxBytes) return reject(WireErrors.ITEM_TOO_LARGE)
    Items.attachmentListReason(item.attachmentIds)?.let { return reject(it) }
    Items.attachmentRefReason(s, c, m.itemId, m.vaultId, item.attachmentIds)?.let { return reject(it) }
    if (existing == null) {
        if (ledger.admit(m.vaultId, size, 1) != null) return reject(WireErrors.QUOTA_EXCEEDED)
        ring += Items.members(c, m.vaultId)
        val rev = nextRev(c, "item", m.itemId, m.vaultId, nowMs)
        c.exec(
            "INSERT INTO items(itemId,vaultId,rev,createdAt,updatedAt,deleted,conflict,formatVersion,attachmentIds,blob,blobSize) VALUES(?,?,?,?,?,0,0,?,?,?,?)",
            m.itemId, m.vaultId, rev, nowMs, nowMs, item.formatVersion, encodeIds(item.attachmentIds), item.blob, size,
        )
        return Decided(result(m, MutationStatus.APPLIED, rev))
    }
    if (item.formatVersion < existing.formatVersion) {
        denied += "fv_downgrade:${m.vaultId}:${m.itemId}"
        return Decided(result(m, MutationStatus.DENIED))
    }
    val oldSize = existing.blob?.length?.toLong() ?: 0L
    if (ledger.admit(m.vaultId, size - oldSize, if (existing.deleted) 1 else 0) != null) return reject(WireErrors.QUOTA_EXCEEDED)
    ring += Items.members(c, m.vaultId)
    val conflict = m.baseItemRev < existing.rev || existing.deleted
    // The stored row's conflict mark asks a client to keep the displaced version as a copy. A deletion has no version to
    // keep, and a client that sees the mark copies the row's own (winning) value instead: a duplicate of the item. So a
    // put that brings a deleted item back is answered `conflict` (with the deletion's mark) and stored unmarked.
    val marked = conflict && !existing.deleted
    Items.archive(c, existing, nowMs)
    val rev = nextRev(c, "item", m.itemId, m.vaultId, nowMs)
    c.exec(
        "UPDATE items SET rev=?, updatedAt=?, deleted=0, conflict=?, formatVersion=?, attachmentIds=?, blob=?, blobSize=? WHERE itemId=?",
        rev, nowMs, marked, item.formatVersion, encodeIds(item.attachmentIds), item.blob, size, m.itemId,
    )
    return if (conflict) Decided(result(m, MutationStatus.CONFLICT, rev), existing, existing)
    else Decided(result(m, MutationStatus.APPLIED, rev))
}

private fun applyDelete(
    s: Services, c: Connection, m: Mutation, existing: SyncItem?, ring: MutableSet<String>, unlink: MutableList<String>, nowMs: Long,
): Decided {
    if (existing == null || existing.deleted) return Decided(result(m, MutationStatus.APPLIED))
    ring += Items.members(c, m.vaultId)
    if (m.baseItemRev < existing.rev) return Decided(result(m, MutationStatus.CONFLICT, existing.rev), existing)
    Items.archive(c, existing, nowMs)
    val rev = nextRev(c, "item", m.itemId, m.vaultId, nowMs)
    c.exec("UPDATE items SET rev=?, updatedAt=?, deleted=1, conflict=0, blob=NULL, blobSize=0, attachmentIds='[]' WHERE itemId=?", rev, nowMs, m.itemId)
    unlink += s.attachments.deleteRowsForItem(c, m.itemId)
    return Decided(result(m, MutationStatus.APPLIED, rev))
}
