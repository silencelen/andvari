package io.silencelen.andvari.server

import java.sql.Connection

/**
 * Account-level operations shared by the operator routes and `andvari admin` (spec 03 §7.1).
 */
class Accounts(private val s: Services) {
    /**
     * Disable (spec 03 §7.1): `status = disabled`, `disabledAt`, every session revoked (its sockets get
     * `revoked` once the transaction commits), and the `account_disabled` notice queued. Disabling a
     * disabled account changes nothing. [reason] is `abuse`, `request` or `other`; it goes to the person's
     * email, never the audit meta beyond the category.
     *
     * The notice is queued HERE so that `andvari admin disable` does what the panel does. That
     * command runs in its own process, so its notifier reaches no socket of the server's; the events loop
     * re-checks its session every [Notifier.recheckMs] and closes the socket (VaultData.kt), which covers it.
     */
    fun disable(c: Connection, userId: String, reason: String, actorDeviceId: String?, ip: String?) {
        val changed = c.exec("UPDATE users SET status='disabled', disabledAt=? WHERE userId=? AND status='active'", s.clock.now(), userId)
        if (changed == 0) return
        s.sessions.revokeAllOf(c, userId)
        // The account's open register links stop registering accounts (they stay revoked on re-enable).
        c.exec("UPDATE links SET state='revoked', stateChangedAt=? WHERE creatorUserId=? AND kind='register' AND state='open'", s.clock.now(), userId)
        val operatorId = c.queryOne("SELECT userId FROM users WHERE role='operator'") { it.getString(1) }
        s.audit.on(c, "operator_disable", operatorId, actorDeviceId, ip, "target=$userId reason=$reason")
        notify(s, c, userId, "account_disabled", vars = mapOf("reason" to reason))
        afterCommit(c) { s.notifier.notifyRevokedUser(userId) }
    }

    /**
     * Enable (spec 03 §7.1): `status = active`, clears `disabledAt`, queues `account_enabled` (here, for the
     * same reason as in [disable]). Re-enabling ignores the cap (design S3-Q7).
     */
    fun enable(c: Connection, userId: String, actorDeviceId: String?, ip: String?) {
        val changed = c.exec("UPDATE users SET status='active', disabledAt=NULL WHERE userId=? AND status='disabled'", userId)
        if (changed == 0) return
        val operatorId = c.queryOne("SELECT userId FROM users WHERE role='operator'") { it.getString(1) }
        s.audit.on(c, "operator_enable", operatorId, actorDeviceId, ip, "target=$userId")
        notify(s, c, userId, "account_enabled")
    }
}
