package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.wire.AuditRow
import java.sql.Connection

/**
 * The audit table (spec 02 §5, spec 03 §7.3). Rows carry ids, the IP and coarse metadata only — never an
 * email, a name, a code, a token, a key or any decrypted content. Each row is also printed to the
 * `andvari.audit` logger (journald → Loki).
 */
class Audit(private val clock: Clock) {
    /**
     * Write one row inside [c]. A row naming a userId that no longer exists (a request racing an account
     * deletion, spec 03 §13) is stored without anything that names the account: userId, deviceId and ip
     * null, meta prefixed `deleted_account`.
     */
    fun on(c: Connection, type: String, userId: String?, deviceId: String?, ip: String?, meta: String? = null) {
        val gone = userId != null && c.queryOne("SELECT 1 FROM users WHERE userId=?", userId) { 1 } == null
        val uid = if (gone) null else userId
        val dev = if (gone) null else deviceId
        val addr = if (gone) null else ip
        val m = if (!gone) meta else if (meta == null) DELETED_ACCOUNT_META else "$DELETED_ACCOUNT_META:$meta"
        insert(c, type, uid, dev, addr, m)
    }

    /**
     * A row recording a refusal: written now, and written again on its own if the enclosing
     * transaction rolls back because the route then refuses, so a denied call always leaves its row.
     */
    fun denied(c: Connection, type: String, userId: String?, deviceId: String?, ip: String?, meta: String? = null) {
        on(c, type, userId, deviceId, ip, meta)
        Db.CURRENT.get()?.queueKeepOnRollback { c2 -> on(c2, type, userId, deviceId, ip, meta) }
    }

    /** The one writer of a row whose userId names no user: the deletion's own row under its pseudonym (§13). */
    fun pseudonymOn(c: Connection, type: String, pseudonym: String, deviceId: String?, ip: String?, meta: String?) =
        insert(c, type, pseudonym, deviceId, ip, meta)

    private fun insert(c: Connection, type: String, userId: String?, deviceId: String?, ip: String?, meta: String?) {
        c.exec("INSERT INTO audit(at,type,userId,deviceId,ip,meta) VALUES(?,?,?,?,?,?)", clock.now(), type, userId, deviceId, ip, meta)
        AuditLog.log(type, userId, deviceId, ip, meta)
    }

    /**
     * `GET /admin/audit` (spec 03 §7.3): newest first (by `id`, which only grows), filtered, at most [limit] rows,
     * and with [afterId] only the rows older than it (`id < afterId`): the next page after a page whose last row
     * had that id. The cursor is a position, so it stays valid when that row has been pruned in between.
     */
    fun query(c: Connection, sinceMs: Long?, type: String?, userId: String?, limit: Int, afterId: Long? = null): List<AuditRow> {
        val where = ArrayList<String>()
        val args = ArrayList<Any?>()
        if (afterId != null) { where += "id<?"; args += afterId }
        if (sinceMs != null) { where += "at>=?"; args += sinceMs }
        if (type != null) { where += "type=?"; args += type }
        if (userId != null) { where += "userId=?"; args += userId }
        val sql = "SELECT id,at,type,userId,deviceId,ip,meta FROM audit" +
            (if (where.isEmpty()) "" else " WHERE " + where.joinToString(" AND ")) +
            " ORDER BY id DESC LIMIT ?"
        args += limit
        return c.queryAll(sql, *args.toTypedArray()) { rs ->
            AuditRow(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7))
        }
    }

    companion object {
        const val DELETED_ACCOUNT_META = "deleted_account"
    }
}

/**
 * Every kind of audit row this server can write (spec 03 §7.3), sorted: the operator's consoles filter and word the
 * audit list by these, and read them from `GET /admin/status`'s `auditKinds` instead of each keeping a list of its own.
 * `AuditKindsTest` reads the server's source and fails when a kind is written that is missing here, or listed here
 * that nothing writes.
 */
object AuditKinds {
    val ALL: List<String> = listOf(
        "account_delete", "account_delete_denied", "account_delete_reauth_fail", "account_delete_stale", "account_device_revoke", "account_recovery_change",
        "attachment_cross_vault", "attachment_upload",
        "device_link_approve", "device_link_claim", "device_link_create", "device_link_pickup", "device_link_pickup_denied", "device_link_reveal",
        "device_revoke_denied",
        "email_dropped", "email_failed", "email_sent",
        "enrol_link_mint", "escrow_self_reseal",
        "instance_card_update", "instance_identity_reset",
        "item_purge", "item_restore",
        "link_answer", "link_create", "link_revoke",
        "login", "login_fail", "login_wait", "logout",
        "operator_delete", "operator_delete_denied", "operator_device_revoke", "operator_disable", "operator_disable_denied", "operator_enable",
        "operator_escrow_read", "operator_policy", "operator_quota", "operator_recovery_fulfil",
        "password_change", "password_change_fail", "push_denied", "reauth_fail", "reauth_wait",
        "recovery_request_commit", "recovery_request_commit_mismatch", "recovery_request_create", "recovery_request_verify", "recovery_request_verify_fail", "recovery_request_veto",
        "recovery_rotation_stored",
        "recovery_self_commit", "recovery_self_confirm", "recovery_self_confirm_stale", "recovery_self_confirm_unbound", "recovery_self_setup",
        "recovery_self_setup_fail", "recovery_self_verify_fail",
        "refresh_grace", "refresh_reuse", "register", "require_link_set", "session_end", "signup_start", "signup_verify_fail",
        "totp_disable", "totp_enroll", "totp_rotate", "totp_setup_reauth_fail", "totp_verify_fail", "totp_verify_wait",
        "vault_grant_self_wrap", "vault_log_append", "vault_purge", "vault_rename",
    )
}
