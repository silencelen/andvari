package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.DeletedVaultSummary
import io.silencelen.andvari.core.model.wire.LogAppendRequest
import io.silencelen.andvari.core.model.wire.LogAppendResponse
import io.silencelen.andvari.core.model.wire.LogDeleted
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.LogPage
import io.silencelen.andvari.core.model.wire.LogPurged
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.RevResponse
import io.silencelen.andvari.core.model.wire.SelfWrapPut
import io.silencelen.andvari.core.model.wire.VaultMemberSummary
import io.silencelen.andvari.core.model.wire.VaultMetaPut
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireGrammar
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.LogSignerCheck
import io.silencelen.andvari.core.trust.UnverifiedLogEntry
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.core.trust.VaultLogVerdict
import io.silencelen.andvari.core.trust.VaultState
import java.sql.Connection

/**
 * The vault log on the server (spec 03 §10, §11; design §3.7, §3.8). Every membership, role, ownership
 * and lifecycle change of a shared vault is one signed entry appended through one route; the server runs
 * the SAME `core/trust` verifier every client runs and keeps no second implementation of its rules.
 */
object VaultLogs {
    private val crypto = createCryptoProvider()

    /** The `at` ceiling (spec 03 §10.3 step 8): the server's, outside the clock-free verifier. */
    const val AT_AHEAD_MS = 10 * 60_000L
    const val OFFER_MAX_MS = 14 * Clock.DAY_MS + 10 * 60_000L
    const val MEMBERSHIP_LIMIT = 500
    const val PAGE = 500
    const val ENTRY_MAX = 1_500
    const val GRANT_MAX = 2_100

    /** The rate bucket of each kind (spec 03 §10.5). */
    fun bucketOf(kind: String): Bucket = when (kind) {
        "genesis" -> Bucket.devicePerHour("vault_create", 10)
        "offer", "delete", "remove" -> SharedBuckets.VAULT_DESTRUCTIVE
        "add", "role" -> Bucket.devicePerHour("vault_membership", 60)
        else -> Bucket.devicePerHour("vault_recovery", 30)
    }

    class VaultRow(
        val vaultId: String, val type: String, val rev: Long, val logSeq: Long?, val logHash: String?, val logAt: Long?,
        val deletedAt: Long?, val purgeAt: Long?, val purgedAt: Long?, val pendingOfferId: String?, val pendingOwnerId: String?,
        val pendingOfferExpiresAt: Long?, val logState: String?, val metaBlob: String,
    )

    fun vault(c: Connection, vaultId: String): VaultRow? = c.queryOne("SELECT * FROM vaults WHERE vaultId=?", vaultId) { rs ->
        VaultRow(
            rs.getString("vaultId"), rs.getString("type"), rs.getLong("rev"), rs.longOrNull("logSeq"), rs.getString("logHash"), rs.longOrNull("logAt"),
            rs.longOrNull("deletedAt"), rs.longOrNull("purgeAt"), rs.longOrNull("purgedAt"), rs.getString("pendingOfferId"), rs.getString("pendingOwnerId"),
            rs.longOrNull("pendingOfferExpiresAt"), rs.getString("logState"), rs.getString("metaBlob"),
        )
    }

    class Grant(val role: String, val revokedAt: Long?, val revokedReason: String?)

    fun grant(c: Connection, userId: String, vaultId: String): Grant? =
        c.queryOne("SELECT role,revokedAt,revokedReason FROM grants WHERE userId=? AND vaultId=?", userId, vaultId) {
            Grant(it.getString(1), it.longOrNull("revokedAt"), it.getString(3))
        }

    fun frames(c: Connection, vaultId: String, afterSeq: Long = -1, uptoSeq: Long = Long.MAX_VALUE, limit: Int = Int.MAX_VALUE): List<Pair<Long, String>> =
        c.queryAll("SELECT seq,frame FROM vault_log WHERE vaultId=? AND seq>? AND seq<=? ORDER BY seq LIMIT ?", vaultId, afterSeq, uptoSeq, limit) { it.getLong(1) to it.getString(2) }

    /** The verified state after the stored head: the stored encoding, or a replay from the genesis. */
    fun state(c: Connection, v: VaultRow): VaultState? {
        v.logState?.let { VaultState.decode(it) }?.takeIf { it.head.seq == v.logSeq }?.let { return it }
        val all = frames(c, v.vaultId).map { Bytes.fromB64(it.second) }
        if (all.isEmpty()) return null
        // From the genesis; the server holds no hash of its own beside the stored chain it is replaying.
        val r = VaultLog.replay(crypto, v.vaultId, all, from = null, known = KnownHashes.NONE_HELD)
        check(r.verdict == null) { "stored log of ${v.vaultId} does not verify" }
        return r.state
    }

    /**
     * `deleted: {deletedAt, purgeAt}` (spec 03 §10.3, §10.6, §11.1): [v] is in its grace (deleted, not
     * purged), and the head the caller is given is the vault's current head, so the caller sees the
     * `delete`. An account cut off before the delete learns nothing of it. `purgeAt` is the stored end of the
     * grace, the same value `GET /vaults/deleted` gives.
     */
    fun graceOf(v: VaultRow, shownSeq: Long): LogDeleted? {
        val deletedAt = v.deletedAt ?: return null
        val purgeAt = v.purgeAt ?: return null
        return if (v.purgedAt == null && shownSeq == v.logSeq) LogDeleted(deletedAt, purgeAt) else null
    }

    fun headAt(c: Connection, vaultId: String, seq: Long): LogHead? =
        c.queryOne("SELECT seq,hash,at FROM vault_log WHERE vaultId=? AND seq=?", vaultId, seq) { LogHead(it.getLong(1), it.getString(2), it.getLong(3)) }

    /**
     * The last `seq` [userId] may read (spec 03 §10.6), or null for none: an active member, or an account
     * whose grant was revoked by the vault's `delete` (also after the purge), reads the whole log; an
     * account cut off by `remove` or `leave` reads up to and including that entry; anyone else nothing.
     */
    fun visibleUpto(c: Connection, userId: String, v: VaultRow): Long? {
        if (v.type != "shared" || v.logSeq == null) return null
        val g = grant(c, userId, v.vaultId) ?: return null
        if (g.revokedAt == null || g.revokedReason == "vault_delete") return v.logSeq
        // Cut off: the latest leave by the account, or remove of it.
        val leave = c.queryOne("SELECT MAX(seq) FROM vault_log WHERE vaultId=? AND kind='leave' AND actor=?", v.vaultId, userId) { it.longOrNull("MAX(seq)") }
        val removes = c.queryAll("SELECT seq,frame FROM vault_log WHERE vaultId=? AND kind='remove' ORDER BY seq DESC", v.vaultId) { it.getLong(1) to it.getString(2) }
        val remove = removes.firstOrNull { (_, f) ->
            (VaultLog.parse(crypto, Bytes.fromB64(f)).valueOrNull()?.entry as? LogEntry.Remove)?.member == userId
        }?.first
        return listOfNotNull(leave, remove).maxOrNull()
    }

    /** Is [userId] still connected to [other] (spec 03 §15.8)? */
    fun connected(c: Connection, userId: String, other: String): Boolean {
        val (a, b) = if (userId < other) userId to other else other to userId
        return c.queryOne("SELECT 1 FROM connections WHERE a=? AND b=?", a, b) { 1 } != null
    }

    /** Map a verifier verdict to the wire (spec 03 §10.4). */
    fun refuse(v: VaultLogVerdict, c: Connection, row: VaultRow?): Nothing = when (v) {
        VaultLogVerdict.BAD_FRAME, VaultLogVerdict.UNKNOWN_FORMAT -> badRequest(WireErrors.BAD_FRAME)
        VaultLogVerdict.NON_CANONICAL -> badRequest(WireErrors.NON_CANONICAL)
        VaultLogVerdict.BAD_STATEMENT -> badRequest(WireErrors.BAD_STATEMENT)
        VaultLogVerdict.WRONG_VAULT -> badRequest(WireErrors.WRONG_VAULT)
        VaultLogVerdict.BAD_SIGNATURE -> badRequest(WireErrors.BAD_SIGNATURE)
        VaultLogVerdict.NOT_AUTHORIZED -> forbidden(WireErrors.NOT_VAULT_OWNER)
        VaultLogVerdict.PRECONDITION -> badRequest(WireErrors.PRECONDITION)
        VaultLogVerdict.BAD_SEQ, VaultLogVerdict.BAD_PREV, VaultLogVerdict.FORK -> {
            val h = row?.logSeq?.let { headAt(c, row.vaultId, it) } ?: LogHead(-1, "0".repeat(64), 0)
            logHeadMoved(h.seq, h.hash, h.at)
        }
    }

    fun parse(frame: ByteArray): UnverifiedLogEntry = when (val r = VaultLog.parse(crypto, frame)) {
        is io.silencelen.andvari.core.trust.Checked.Ok -> r.value
        is io.silencelen.andvari.core.trust.Checked.Refused -> when (r.verdict) {
            VaultLogVerdict.NON_CANONICAL -> badRequest(WireErrors.NON_CANONICAL)
            VaultLogVerdict.BAD_STATEMENT -> badRequest(WireErrors.BAD_STATEMENT)
            else -> badRequest(WireErrors.BAD_FRAME)
        }
    }

    fun signedByCaller(entry: UnverifiedLogEntry, userId: String, identityPub: ByteArray) =
        VaultLog.signedByCaller(crypto, entry, userId, identityPub)

    fun verify(vaultId: String, prior: VaultState?, frame: ByteArray) = VaultLog.verify(crypto, vaultId, prior, frame, KnownHashes.NONE_HELD)

    /**
     * `409 vault_items_moved` (spec 03 §10.3): a `delete` that named its read point while an item of the vault changed after
     * it. Nothing is stored; the caller reads the vault again. (The shared code's `WireErrors` has no constant for it yet.)
     */
    const val VAULT_ITEMS_MOVED = "vault_items_moved"

    /**
     * The `delete`'s read point, `itemsAtMost` (spec 03 §10.3): unsigned, beside the signed entry, the sync `rev` up to which
     * the caller read the vault's items. Absent or `null`: none (taken as before the field existed). Anything but the `int`
     * grammar (a JSON number, `0` or `[1-9][0-9]*`, below 2^53) is `400 bad_items_at_most`.
     */
    fun itemsAtMostOf(tree: kotlinx.serialization.json.JsonObject): Long? {
        val v = tree["itemsAtMost"] ?: return null
        if (v is kotlinx.serialization.json.JsonNull) return null
        val prim = v as? kotlinx.serialization.json.JsonPrimitive
        if (prim == null || prim.isString) badRequest(WireErrors.badField("itemsAtMost"))
        return parseInt(prim.content) ?: badRequest(WireErrors.badField("itemsAtMost"))
    }

    /**
     * Has any item row of [vaultId] a `rev` above [point]? Every change of an item row takes the next global `rev`: a save
     * (create or edit, a conflicting one too), a move into the trash, a restore from it. A purge removes the row without a
     * new `rev` (the item was already in the trash, and only its deletion forever follows); an attachment counts through
     * the put of the item that names it.
     */
    fun itemsMovedPast(c: Connection, vaultId: String, point: Long): Boolean =
        c.queryOne("SELECT 1 FROM items WHERE vaultId=? AND rev>? LIMIT 1", vaultId, point) { 1 } != null

    /** Kinds that a grant revoked with reason `vault_delete` still allows (spec 03 §10.3 step 5). */
    private val DELETE_REVOKED_OK = setOf("restore", "delete", "leave")
    /** Kinds that need the owner role on the server (spec 03 §10.1). */
    private val OWNER_KINDS = setOf("add", "role", "remove", "offer", "delete", "restore")

    /**
     * One append, in the order of spec 03 §10.3 from step 3 on (the session and the body caps are the
     * route's). [exemptFromBuckets] is the account deletion's leaves (§13). Returns the new head, or null
     * for a byte-identical retry (which changes nothing). Runs inside [c]; side effects after commit.
     */
    fun append(
        s: Services, c: Connection, req: Req?, userId: String, deviceId: String?, ip: String?, vaultId: String,
        frameB64: String, grant: String?, wrappedVk: String?, metaBlob: String?, exemptFromBuckets: Boolean,
        itemsAtMost: Long? = null,
    ): LogHead? {
        val nowMs = s.clock.now()
        val frame = frameBytes(frameB64, WireErrors.BAD_FRAME)
        // ---- step 3: the strict parse and the vault; then the kind's bucket ----
        val parsed = parse(frame)
        val e = parsed.entry
        if (e.vaultId != vaultId) badRequest(WireErrors.WRONG_VAULT)
        val kind = e.kind.literal
        val allowed = io.silencelen.andvari.core.model.wire.LogAppendRequest.sideFieldsFor(kind)
        val present = buildSet { if (grant != null) add("grant"); if (wrappedVk != null) add("wrappedVk"); if (metaBlob != null) add("metaBlob") }
        if (!allowed.containsAll(present)) badRequest(WireErrors.BAD_REQUEST)
        // The read point rides a `delete` only; on any other kind it is refused like a side field the kind does not take.
        if (itemsAtMost != null && kind != "delete") badRequest(WireErrors.BAD_REQUEST)
        for (f in allowed) {
            when (f) {
                "grant" -> if (grant == null || grant.length > GRANT_MAX || Grammar.b64Bytes(grant, 1, GRANT_MAX) == null) badRequest(WireErrors.BAD_GRANT)
                "wrappedVk" -> if (wrappedVk == null || wrappedVk.length > Caps.KEY_ENVELOPE || Grammar.b64Bytes(wrappedVk, 1, Caps.KEY_ENVELOPE) == null) badRequest(WireErrors.BAD_WRAPPED_VK)
                "metaBlob" -> if (metaBlob == null || metaBlob.length > Caps.META_BLOB || Grammar.b64Bytes(metaBlob, 1, Caps.META_BLOB) == null) badRequest(WireErrors.BAD_META_BLOB)
            }
        }
        // Held, so that a refusal that decided nothing about the caller can give it back (the read point's, below).
        val draw = if (exemptFromBuckets) null else req?.takeHeld(bucketOf(kind))
        // ---- step 4: the signer ----
        val identityPub = c.queryOne("SELECT identityPub FROM users WHERE userId=?", userId) { Bytes.fromB64(it.getString(1)) } ?: unauthorized()
        when (signedByCaller(parsed, userId, identityPub)) {
            LogSignerCheck.OK -> {}
            LogSignerCheck.BAD_SIGNER -> badRequest(WireErrors.BAD_SIGNER)
            LogSignerCheck.BAD_SIGNATURE -> badRequest(WireErrors.BAD_SIGNATURE)
        }
        // ---- step 5: retry, then access ----
        if (c.queryOne("SELECT 1 FROM vault_log WHERE vaultId=? AND frame=? AND actor=?", vaultId, frameB64, userId) { 1 } != null) return null
        var row = vault(c, vaultId)
        if (kind == "genesis") {
            if (row != null) conflict(WireErrors.VAULT_ID_TAKEN)
        } else {
            val g = grant(c, userId, vaultId)
            // While the vault is deleted, a grant its `delete` revoked counts for `leave` (anyone's) and for
            // `restore` and `delete` (the owner's only); a non-owner's restore or delete is `no_grant`, decided
            // before the role check (as the test vectors' logappend.json grade it).
            val deleteRevokedCounts = g != null && g.revokedReason == "vault_delete" && kind in DELETE_REVOKED_OK && (kind == "leave" || g.role == "owner")
            val counts = g != null && (g.revokedAt == null || deleteRevokedCounts)
            // A purged vault is a tombstone: no entry of any kind is appended after the purge, so a `restore`
            // can never revive grants whose key material the purge blanked (nor a `leave` move the final head).
            if (row == null || !counts || row.purgedAt != null) forbidden(WireErrors.NO_GRANT)
            if (row.type != "shared") badRequest(WireErrors.NOT_SHARED_VAULT)
            if (kind in OWNER_KINDS && g!!.role != "owner") forbidden(WireErrors.NOT_VAULT_OWNER)
        }
        // ---- step 6: the position ----
        if (kind == "genesis") {
            if (e.seq != 0L) logHeadMoved(-1, "0".repeat(64), 0)
        } else if (e.seq != row!!.logSeq!! + 1 || e.prev != row.logHash) {
            val h = headAt(c, vaultId, row.logSeq!!)!!
            logHeadMoved(h.seq, h.hash, h.at)
        }
        // ---- step 7: the shared verifier ----
        val prior = row?.let { state(c, it) }
        val step = when (val r = verify(vaultId, prior, frame)) {
            is io.silencelen.andvari.core.trust.Checked.Ok -> r.value
            is io.silencelen.andvari.core.trust.Checked.Refused -> refuse(r.verdict, c, row)
        }
        // ---- step 8: the kind's checks ----
        if (e.at > nowMs + AT_AHEAD_MS) badRequest(WireErrors.AT_AHEAD)
        when (e) {
            is LogEntry.Add -> {
                val active = c.queryOne("SELECT status FROM users WHERE userId=?", e.member) { it.getString(1) } == "active"
                val memberships = c.count(
                    "SELECT COUNT(*) FROM grants g JOIN vaults v ON v.vaultId=g.vaultId WHERE g.userId=? AND v.type='shared' AND g.revokedAt IS NULL", e.member,
                )
                if (!active || memberships >= MEMBERSHIP_LIMIT) conflict(WireErrors.MEMBER_LIMIT)
                if (!connected(c, userId, e.member)) conflict(WireErrors.NOT_CONNECTED)
            }
            is LogEntry.Genesis -> {
                val q = s.policy.quotaOf(c, userId)
                if (Quotas.ownedSharedVaults(c, userId) >= q.ownedSharedVaults) quotaExceeded(QuotaName.OWNED_SHARED_VAULTS)
                if (Quotas.ownedBytes(c, userId) + (metaBlob?.length ?: 0) > q.accountBytes) quotaExceeded(QuotaName.ACCOUNT_BYTES)
            }
            is LogEntry.Offer -> if (e.expiresAt <= nowMs || e.expiresAt > nowMs + OFFER_MAX_MS) badRequest(WireErrors.BAD_EXPIRY)
            // The read point (spec 03 §10.3): any item row of the vault, live or in the trash, changed after the caller's
            // read refuses the delete, in this transaction, so no other writer's save can land between this check and the
            // append below (the database serves one transaction at a time).
            // The refusal gives the device's draw on `vault_destructive` back, with the rollback it causes: the caller did
            // nothing wrong and nothing is stored, so members who keep saving cannot spend a reading client's deletions
            // (decided on 2026-11-18). A stored deletion's draw is never given back, and a give-back is good for one use, so
            // no more deletions are stored in a window than the limit. The account's ceiling keeps the call ([DeviceDraw]).
            is LogEntry.Delete -> if (itemsAtMost != null && itemsMovedPast(c, vaultId, itemsAtMost)) {
                draw?.let { d -> onRollback(c) { d.giveBack() } }
                conflict(VAULT_ITEMS_MOVED)
            }
            is LogEntry.Accept -> {
                val exp = row!!.pendingOfferExpiresAt
                // Expiry is exclusive: the offer has expired at now = expiresAt.
                if (exp == null || nowMs >= exp) conflict(WireErrors.OFFER_EXPIRED)
                val q = s.policy.quotaOf(c, userId)
                if (Quotas.ownedSharedVaults(c, userId) + 1 > q.ownedSharedVaults) quotaExceeded(QuotaName.OWNED_SHARED_VAULTS)
                if (Quotas.ownedBytes(c, userId) + Quotas.vaultBytes(c, vaultId) > q.accountBytes) quotaExceeded(QuotaName.ACCOUNT_BYTES)
                if (Quotas.ownedItems(c, userId) + Quotas.vaultItems(c, vaultId) > q.items) quotaExceeded(QuotaName.ITEMS)
            }
            else -> {}
        }
        // ---- the effect, in this transaction ----
        val rev = nextRev(c, "vault", vaultId, vaultId, nowMs)
        val ring = HashSet<String>()
        c.queryAll("SELECT userId FROM grants WHERE vaultId=? AND (revokedAt IS NULL OR revokedReason='vault_delete')", vaultId) { it.getString(1) }.forEach { ring += it }
        fun clearPendingIf(target: String?) {
            if (target == null || row?.pendingOwnerId == target) {
                c.exec("UPDATE vaults SET pendingOfferId=NULL, pendingOwnerId=NULL, pendingOfferExpiresAt=NULL WHERE vaultId=?", vaultId)
            }
        }
        when (e) {
            is LogEntry.Genesis -> {
                c.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,?,?,?)", vaultId, "shared", rev, metaBlob, nowMs)
                c.exec("INSERT INTO grants(vaultId,userId,role,addedAt,wrappedVk,rev) VALUES(?,?,'owner',?,?,?)", vaultId, userId, nowMs, wrappedVk, rev)
                ring += userId
            }
            is LogEntry.Add -> {
                c.exec(
                    """INSERT INTO grants(vaultId,userId,role,addedAt,wrappedVk,signedGrant,rev) VALUES(?,?,?,?,'',?,?)
                       ON CONFLICT(vaultId,userId) DO UPDATE SET role=excluded.role, addedAt=excluded.addedAt, wrappedVk='',
                         signedGrant=excluded.signedGrant, rev=excluded.rev, revokedAt=NULL, revokedReason=NULL""",
                    vaultId, e.member, e.role.literal, nowMs, grant, rev,
                )
                ring += e.member
            }
            is LogEntry.Role -> {
                c.exec("UPDATE grants SET role=?, rev=? WHERE vaultId=? AND userId=?", e.role.literal, rev, vaultId, e.member)
                clearPendingIf(e.member)
            }
            is LogEntry.Remove -> {
                c.exec("UPDATE grants SET revokedAt=?, revokedReason='member_remove', rev=? WHERE vaultId=? AND userId=? AND revokedAt IS NULL", nowMs, rev, vaultId, e.member)
                clearPendingIf(e.member)
                ring += e.member
            }
            is LogEntry.Leave -> {
                c.exec(
                    "UPDATE grants SET revokedAt=COALESCE(revokedAt,?), revokedReason='member_leave', rev=? WHERE vaultId=? AND userId=? AND (revokedAt IS NULL OR revokedReason='vault_delete')",
                    nowMs, rev, vaultId, userId,
                )
                clearPendingIf(userId)
            }
            is LogEntry.Offer -> c.exec(
                "UPDATE vaults SET pendingOfferId=?, pendingOwnerId=?, pendingOfferExpiresAt=? WHERE vaultId=?", e.offerId, e.to, e.expiresAt, vaultId,
            )
            is LogEntry.Cancel -> clearPendingIf(null)
            is LogEntry.Accept -> {
                c.exec("UPDATE grants SET role='writer', rev=? WHERE vaultId=? AND role='owner'", rev, vaultId)
                c.exec("UPDATE grants SET role='owner', wrappedVk=?, rev=? WHERE vaultId=? AND userId=?", wrappedVk, rev, vaultId, userId)
                clearPendingIf(null)
            }
            is LogEntry.Delete -> {
                c.exec("UPDATE grants SET revokedAt=?, revokedReason='vault_delete', rev=? WHERE vaultId=? AND revokedAt IS NULL", nowMs, rev, vaultId)
                c.exec(
                    "UPDATE vaults SET deletedAt=?, purgeAt=?, deletedBy=?, deleteId=? WHERE vaultId=?",
                    nowMs, nowMs + s.config.vaultGraceMs, userId, e.deleteId, vaultId,
                )
                clearPendingIf(null)
            }
            is LogEntry.Restore -> {
                c.exec("UPDATE grants SET revokedAt=NULL, revokedReason=NULL, rev=? WHERE vaultId=? AND revokedReason='vault_delete'", rev, vaultId)
                c.exec("UPDATE vaults SET deletedAt=NULL, purgeAt=NULL, deletedBy=NULL, deleteId=NULL WHERE vaultId=?", vaultId)
            }
        }
        c.exec(
            "INSERT INTO vault_log(vaultId,seq,hash,frame,actor,kind,at,storedAt) VALUES(?,?,?,?,?,?,?,?)",
            vaultId, e.seq, step.hash, frameB64, userId, kind, e.at, nowMs,
        )
        c.exec("UPDATE vaults SET rev=?, logSeq=?, logHash=?, logAt=?, logState=? WHERE vaultId=?", rev, e.seq, step.hash, e.at, step.state.encode(), vaultId)
        s.audit.on(c, "vault_log_append", userId, deviceId, ip, "kind=$kind vault=$vaultId")
        afterCommit(c) { s.notifier.notifyRev(ring, rev) }
        return LogHead(e.seq, step.hash, e.at)
    }
}

fun Route.vaultLogRoutes(s: Services) {
    /**
     * `POST /vaults/{vaultId}/log` (spec 03 §10.3), the one route for every membership, role, ownership
     * and lifecycle change of a shared vault. The checks run in the spec's order (see [VaultLogs.append]);
     * a byte-identical stored frame signed by the caller answers `200` before any grant check.
     */
    api(WireRoute.LOG_APPEND, s, bucket = null) {
        val vaultId = Grammar.requireUuid(param("vaultId"), "vaultId")
        val tree = jsonBody() as? kotlinx.serialization.json.JsonObject ?: badRequest(WireErrors.BAD_REQUEST)
        val req = try {
            // The read point is taken from the tree by its own grammar below, never from the typed field: a value that
            // field cannot hold (`1.5`, a string) is refused as `bad_items_at_most`, not as a bad request.
            WireJson.json.decodeFromJsonElement(LogAppendRequest.serializer(), kotlinx.serialization.json.JsonObject(tree - "itemsAtMost"))
        } catch (_: Throwable) {
            badRequest(WireErrors.BAD_REQUEST)
        }
        val itemsAtMost = VaultLogs.itemsAtMostOf(tree)
        if (req.entry.length > VaultLogs.ENTRY_MAX) badRequest(WireErrors.BAD_FRAME)
        val principal = p
        val (head, grace) = s.db.tx { c ->
            val head = VaultLogs.append(s, c, this, principal.userId, principal.deviceId, ip, vaultId, req.entry, req.grant, req.wrappedVk, req.metaBlob, false, itemsAtMost)
                ?: run {
                    val v = VaultLogs.vault(c, vaultId)!!
                    val upto = VaultLogs.visibleUpto(c, principal.userId, v) ?: v.logSeq!!
                    VaultLogs.headAt(c, vaultId, upto)!!
                }
            head to VaultLogs.graceOf(VaultLogs.vault(c, vaultId)!!, head.seq)
        }
        respond(LogAppendResponse(s.db.read { currentRev(it) }, head, grace))
    }

    /**
     * `GET /vaults/{vaultId}/log?after=<seq>` (spec 03 §10.6): at most 500 entries per page with `seq > after`
     * (from the genesis without `after`), up to what the caller may see; `head` is the last entry it may
     * see; `purged` once the vault is purged. Anyone else is `403 no_grant`.
     */
    api(WireRoute.LOG_FETCH, s) {
        val vaultId = param("vaultId").takeIf { WireGrammar.isUuid(it) } ?: forbidden(WireErrors.NO_GRANT)
        val after = query("after")?.let { a -> parseInt(a) ?: badRequest(WireErrors.BAD_AFTER) } ?: -1L
        val principal = p
        val page = s.db.read { c ->
            val v = VaultLogs.vault(c, vaultId) ?: forbidden(WireErrors.NO_GRANT)
            val upto = VaultLogs.visibleUpto(c, principal.userId, v) ?: forbidden(WireErrors.NO_GRANT)
            val entries = VaultLogs.frames(c, vaultId, after, upto, VaultLogs.PAGE).map { it.second }
            // A tombstone past its year has no log rows left: nothing to serve.
            val head = VaultLogs.headAt(c, vaultId, upto) ?: forbidden(WireErrors.NO_GRANT)
            LogPage(entries, head, v.purgedAt?.let { LogPurged(it) }, VaultLogs.graceOf(v, head.seq))
        }
        respond(page)
    }

    /** `GET /vaults/{vaultId}/members` (spec 03 §10.7): the server's view of the active grants; members only. */
    api(WireRoute.VAULT_MEMBERS, s) {
        val vaultId = param("vaultId").takeIf { WireGrammar.isUuid(it) } ?: forbidden(WireErrors.NO_GRANT)
        val principal = p
        val rows = s.db.read { c ->
            if (Quotas.role(c, principal.userId, vaultId) == null) forbidden(WireErrors.NO_GRANT)
            c.queryAll(
                """SELECT g.userId,u.email,u.displayName,g.role,u.identityPub,g.addedAt,u.status FROM grants g JOIN users u ON u.userId=g.userId
                   WHERE g.vaultId=? AND g.revokedAt IS NULL ORDER BY g.addedAt""",
                vaultId,
            ) { VaultMemberSummary(it.getString(1), it.getString(2), it.getString(3), it.getString(4), it.getString(5), it.getLong(6), it.getString(7).takeIf { st -> st != "active" }) }
        }
        respondList(VaultMemberSummary.serializer(), rows)
    }

    /** `GET /vaults/deleted` (spec 03 §11.2): in-grace vaults the caller owned when they were deleted. */
    api(WireRoute.VAULTS_DELETED, s) {
        val principal = p
        val rows = s.db.read { c ->
            c.queryAll(
                """SELECT v.vaultId,v.metaBlob,g.wrappedVk,v.deletedAt,v.purgeAt,v.deleteId FROM vaults v JOIN grants g ON g.vaultId=v.vaultId
                   WHERE g.userId=? AND g.role='owner' AND g.revokedReason='vault_delete' AND v.deletedAt IS NOT NULL AND v.purgedAt IS NULL""",
                principal.userId,
            ) { DeletedVaultSummary(it.getString(1), it.getString(2), it.getString(3), it.getLong(4), it.getLong(5), it.getString(6)) }
        }
        respondList(DeletedVaultSummary.serializer(), rows)
    }

    /**
     * `PUT /vaults/{vaultId}/meta` (spec 03 §11.3): owner only (`403 not_vault_owner`, also a non-member),
     * shared only, not while deleted, `baseVaultRev` not stale (`409 stale_meta`). Not a log entry.
     */
    api(WireRoute.VAULT_META, s, SharedBuckets.VAULT_DESTRUCTIVE) {
        val vaultId = Grammar.requireUuid(param("vaultId"), "vaultId")
        val req = body<VaultMetaPut>()
        Grammar.requireB64(req.metaBlob, "metaBlob", Caps.META_BLOB)
        val principal = p
        val rev = s.db.tx { c ->
            val v = VaultLogs.vault(c, vaultId)
            // While the vault is deleted its owner's grant is revoked (reason `vault_delete`); that owner is still
            // the owner here, so it is told `vault_deleted`, not `not_vault_owner` (§11.3).
            val isOwner = v != null && (Quotas.role(c, principal.userId, vaultId) == "owner" ||
                (v.deletedAt != null && Quotas.ownerOf(c, vaultId) == principal.userId))
            if (!isOwner) forbidden(WireErrors.NOT_VAULT_OWNER)
            v!!
            if (v.type != "shared") badRequest(WireErrors.NOT_SHARED_VAULT)
            if (v.deletedAt != null) badRequest(WireErrors.VAULT_DELETED)
            req.baseVaultRev?.let { if (it < v.rev) conflict(WireErrors.STALE_META) }
            val rev = nextRev(c, "vault", vaultId, vaultId, now)
            c.exec("UPDATE vaults SET metaBlob=?, rev=? WHERE vaultId=?", req.metaBlob, rev, vaultId)
            s.audit.on(c, "vault_rename", principal.userId, principal.deviceId, ip, "vault=$vaultId")
            val ring = c.queryAll("SELECT userId FROM grants WHERE vaultId=? AND revokedAt IS NULL", vaultId) { it.getString(1) }
            afterCommit(c) { s.notifier.notifyRev(ring, rev) }
            rev
        }
        respond(RevResponse(rev))
    }

    /**
     * `PUT /vaults/{vaultId}/grant/self-wrap` (spec 03 §11.4): the caller's own active, non-owner grant
     * (`403 owner_wrap_immutable`, `403 no_grant`); bumps the grant rev so the account's other devices get
     * it; an identical re-post changes nothing.
     */
    api(WireRoute.VAULT_SELF_WRAP, s, Bucket.devicePerHour("vault_self_wrap", 60)) {
        val vaultId = param("vaultId").takeIf { WireGrammar.isUuid(it) } ?: forbidden(WireErrors.NO_GRANT)
        val req = body<SelfWrapPut>()
        Grammar.requireB64(req.wrappedVk, "wrappedVk", Caps.KEY_ENVELOPE)
        val principal = p
        val rev = s.db.tx { c ->
            val g = c.queryOne("SELECT role,wrappedVk,rev FROM grants WHERE vaultId=? AND userId=? AND revokedAt IS NULL", vaultId, principal.userId) {
                Triple(it.getString(1), it.getString(2), it.getLong(3))
            } ?: forbidden(WireErrors.NO_GRANT)
            if (g.first == "owner") forbidden(WireErrors.OWNER_WRAP_IMMUTABLE)
            if (g.second == req.wrappedVk) return@tx currentRev(c)
            val rev = nextRev(c, "grant", principal.userId, vaultId, now)
            c.exec("UPDATE grants SET wrappedVk=?, rev=? WHERE vaultId=? AND userId=?", req.wrappedVk, rev, vaultId, principal.userId)
            s.audit.on(c, "vault_grant_self_wrap", principal.userId, principal.deviceId, ip, "vault=$vaultId")
            afterCommit(c) { s.notifier.notifyRev(listOf(principal.userId), rev) }
            rev
        }
        respond(RevResponse(rev))
    }
}

/** The `int` grammar for a query parameter: `0` or `[1-9][0-9]*`, below 2^53. */
fun parseInt(a: String): Long? {
    if (a.isEmpty() || a.length > 16 || a.any { it !in '0'..'9' } || (a.length > 1 && a[0] == '0')) return null
    return a.toLong().takeIf { it < (1L shl 53) }
}
