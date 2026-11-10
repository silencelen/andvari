package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.AccountDeleteBlocker
import java.sql.Connection

/**
 * Account deletion (spec 03 §13; design docs/design/2026-11-10-account-deletion.md) — the SQL half. [Service.deleteAccount]
 * owns the gate (typed email, TOTP, master-password reauth, the credential-epoch check) and calls [blockers] and then
 * [deleteRows] inside ONE write tx, so the refusal rules are decided against exactly the state the deletion then
 * destroys: a share, a transfer accept or a push from another device either committed before (and is seen here) or
 * runs after (and finds no account). Nothing here touches the filesystem: the purged attachment ids come back to the
 * caller, which unlinks the blob files only after the tx committed.
 *
 * Owner decisions (binding, 2026-11-10): deletion is REFUSED while the account owns a vault other accounts still hold
 * an active grant to, or is the instance's last active admin while other accounts exist; vaults only it holds go with
 * it; memberships elsewhere are dropped as a leave would; security audit events stay 90 days under a pseudonym that
 * cannot be reversed to the email.
 */
internal object AccountDeletion {

    /** How long a deleted account's retained security events outlive the deletion (owner decision). */
    const val AUDIT_RETENTION_MS = 90 * Service.DAY_MS

    /**
     * Audit types KEPT for [AUDIT_RETENTION_MS] when their row names the deleted account — re-keyed to the pseudonym.
     * The owner's list was "sign-ins, revocations, the deletion itself"; read as the account's security record:
     * authentication, credential and second-factor changes, recovery, denied-write intrusion signals, the deletion's own
     * rows, and the account's ADMIN actions on the instance (who it invited, disabled, revoked, recovered, whose backstop
     * blob it pulled, which policy it set) — the history an incident review of the instance would ask for.
     */
    val RETAINED_AUDIT_TYPES: Set<String> = setOf(
        // sign-in and sessions
        "register", "login", "login_fail", "login_fail_totp", "logout", "refresh_reuse",
        // credentials and the second factor
        "password_change", "password_change_fail", "personal_wrap_reauth_fail", "escrow_self_upload",
        "totp_enroll", "totp_rotate", "totp_disable", "totp_verify_fail", "totp_setup_reauth_fail",
        // self-service recovery
        "recovery_self_verify", "recovery_self_verify_fail", "recovery_self_commit", "recovery_self_setup", "recovery_self_setup_fail",
        // intrusion signals
        "push_denied", "attachment_cross_vault",
        // the deletion itself
        "account_delete", "account_delete_denied", "account_delete_reauth_fail",
        // admin actions on the instance
        "invite_create", "user_disable", "user_disable_denied", "device_revoke", "device_revoke_denied",
        "recovery_apply", "escrow_admin_read", "escrow_legacy_dropped", "escrow_legacy_purged", "policy_update",
    )

    /**
     * Audit types DELETED with the account when their row names it: its own vault, item and sharing activity, lookups
     * and the recovery-capture confirmations — activity about data that no longer exists, kept by nobody. (Types written
     * with no userId, like `vault_purge` and `vault_transfer_expire`, never name the account; they are listed so the
     * classification test sees every type the server writes.) A type in neither set is a build failure: see
     * AccountDeletionTest, which reads every audit type out of the server sources.
     */
    val DROPPED_AUDIT_TYPES: Set<String> = setOf(
        "vault_create", "vault_delete", "vault_restore", "vault_rename", "vault_purge",
        "vault_member_add", "vault_member_role", "vault_member_remove", "vault_member_leave",
        "vault_grant_reissue", "vault_grant_self_wrap",
        "vault_transfer_offer", "vault_transfer_accept", "vault_transfer_cancel", "vault_transfer_expire",
        "attachment_upload", "item_restore", "item_purge",
        "personal_wrap_set", "personal_wrap_redesignate",
        "user_lookup", "user_identity_lookup",
        "recovery_self_confirm", "recovery_self_confirm_unbound", "recovery_self_confirm_stale",
    )

    /**
     * What blocks deleting [userId] right now (empty = nothing). Read inside the deletion's tx (and by the preview):
     *  - `shared_vault`, one per vault the account holds an ACTIVE owner grant to while another account holds an active
     *    grant to it — the members would lose their owner, and no route reassigns one (spec 03 §11, F16);
     *  - `last_admin`, when the account is an active admin, no OTHER account is an active admin, and any other account
     *    exists (whatever its status: a disabled account can only come back through an admin's recovery upload, so
     *    leaving it with no admin strands it too). An instance whose last account deletes itself is empty, not stranded.
     * The order is stable (vaults by id, then the role) so a client can render it as given.
     */
    fun blockers(c: Connection, userId: String): List<AccountDeleteBlocker> {
        val out = mutableListOf<AccountDeleteBlocker>()
        c.queryAll(
            """SELECT g.vaultId,
                      (SELECT COUNT(*) FROM grants o WHERE o.vaultId=g.vaultId AND o.userId<>g.userId AND o.revokedAt IS NULL) AS others
               FROM grants g WHERE g.userId=? AND g.role='owner' AND g.revokedAt IS NULL ORDER BY g.vaultId""",
            userId,
        ) { rs -> rs.getString(1) to rs.getInt(2) }
            .filter { it.second > 0 }
            .forEach { (vaultId, others) -> out += AccountDeleteBlocker("shared_vault", vaultId, others) }
        val admin = c.queryOne("SELECT 1 FROM users WHERE userId=? AND isAdmin=1 AND status='active'", userId) { true } ?: false
        if (admin) {
            val otherAdmins = c.queryOne("SELECT COUNT(*) FROM users WHERE isAdmin=1 AND status='active' AND userId<>?", userId) { it.getInt(1) } ?: 0
            val others = c.queryOne("SELECT COUNT(*) FROM users WHERE userId<>?", userId) { it.getInt(1) } ?: 0
            if (otherAdmins == 0 && others > 0) out += AccountDeleteBlocker("last_admin", null, others)
        }
        return out
    }

    /**
     * The vaults deleted WITH the account: every vault it owns that no other account holds an active grant to — its
     * personal vault, its solely-held shared vaults, and a shared vault it soft-deleted that is still inside its grace
     * window (its owner grant revoked `vault_delete`; nobody else can restore it, so it is purged now rather than left
     * for the janitor). A blocked vault (another active member) never appears here: [blockers] refuses first.
     */
    fun ownedVaults(c: Connection, userId: String): List<String> = c.queryAll(
        """SELECT g.vaultId FROM grants g JOIN vaults v ON v.vaultId=g.vaultId
           WHERE g.userId=? AND g.role='owner' AND v.purgedAt IS NULL
             AND (g.revokedAt IS NULL OR g.revokedReason='vault_delete')
             AND NOT EXISTS(SELECT 1 FROM grants o WHERE o.vaultId=g.vaultId AND o.userId<>g.userId AND o.revokedAt IS NULL)
           ORDER BY g.vaultId""",
        userId,
    ) { it.getString(1) }

    /** Other people's vaults the account holds an ACTIVE non-owner grant to: dropped on deletion, as a leave would. */
    fun memberVaults(c: Connection, userId: String): List<String> =
        c.queryAll("SELECT vaultId FROM grants WHERE userId=? AND revokedAt IS NULL AND role<>'owner' ORDER BY vaultId", userId) { it.getString(1) }

    private fun activeMembers(c: Connection, vaultId: String): Set<String> =
        c.queryAll("SELECT userId FROM grants WHERE vaultId=? AND revokedAt IS NULL", vaultId) { it.getString(1) }.toSet()

    class Outcome(
        /** The fresh random id the account's retained audit rows now carry. Never derived from the userId or the
         *  email, and the mapping is not stored, so nothing on the server reverses it. */
        val pseudonym: String,
        /** Attachment ids whose blob files the caller unlinks after commit. */
        val files: List<String>,
        /** Accounts to ring (co-members of the vaults the account left, members of vaults whose offer to it was
         *  cleared) — never the deleted account itself, whose sockets the route revokes. */
        val notify: Set<String>,
        val purgedVaults: Int,
        val leftVaults: Int,
    )

    /**
     * The deletion itself, inside the caller's write tx, after the gate passed and [blockers] came back empty. Every
     * statement is ordinary SQL on the one connection, so the caller's tx makes the whole list atomic: an exception
     * anywhere rolls ALL of it back and leaves every blob file on disk. Order matters only where a foreign key or a
     * captured set does (the notify set is read before any grant changes; sessions go before devices; the user row
     * goes last, after every row that references it).
     */
    fun deleteRows(c: Connection, repo: Repo, user: UserRow, deviceId: String, ip: String?, nowMs: Long): Outcome {
        val userId = user.userId
        val notify = HashSet<String>()

        // 1. Memberships elsewhere: capture who to ring BEFORE the grant rows go (activeMembers filters revoked), and record
        //    one `changes` row per vault — a leave bumps the grant rev the same way, so the co-members' bell carries a rev
        //    past their cursor instead of one they already hold.
        val left = memberVaults(c, userId)
        for (vaultId in left) {
            notify += activeMembers(c, vaultId)
            repo.nextRev(c, "grant", vaultId, vaultId)
        }

        // 2. Vaults only this account holds: purged now, the janitor's statements minus the grace. The vault row stays as
        //    a purged tombstone (spec 02 §4: vault rows are never hard-deleted and a vaultId is never recycled — a later
        //    POST /vaults with the same id is still refused vault_id_taken). deletedBy is cleared: it named this account.
        val owned = ownedVaults(c, userId)
        val files = ArrayList<String>()
        for (vaultId in owned) {
            files += repo.purgeVaultContents(c, vaultId, nowMs)
            c.exec(
                """UPDATE vaults SET metaBlob='', deletedAt=COALESCE(deletedAt, ?), purgeAt=COALESCE(purgeAt, ?), purgedAt=?, deletedBy=NULL,
                   pendingOwnerId=NULL, pendingOfferId=NULL, pendingOfferProof=NULL, pendingOfferExpiresAt=NULL, pendingOfferSetAt=NULL
                   WHERE vaultId=?""",
                nowMs, nowMs, nowMs, vaultId,
            )
            repo.auditOn(c, "vault_purge", null, null, null, vaultId)
        }

        // 3. Transfer offers naming this account on vaults it does not own: cleared as a leaving target's are (spec 03
        //    §11), with the vault rev bumped so every member's stale offer banner clears. Audited as a system action — the
        //    row is the vault owner's history, not this account's, so it must survive the audit pass below.
        val offers = c.queryAll("SELECT vaultId FROM vaults WHERE pendingOwnerId=?", userId) { it.getString(1) }
        for (vaultId in offers) {
            notify += activeMembers(c, vaultId)
            repo.clearPendingOffer(c, vaultId, bumpVaultRev = true)
            repo.auditOn(c, "vault_transfer_cancel", null, null, ip, "$vaultId:target_deleted")
        }
        // 3b. `deletedBy` can still name the account on vaults outside the purged set: one it deleted that the janitor
        //     already purged, or one it deleted, restored (restore keeps the column) and later handed over. Nothing reads
        //     the column; it is a raw userId, so it goes like every other one.
        c.exec("UPDATE vaults SET deletedBy=NULL WHERE deletedBy=?", userId)

        // 4. Invites: every row naming the account's address (pending ones it received, and the used one it registered
        //    with — both carry the email in plaintext, spec 02 §5), and the UNUSED ones it minted as an admin. Invites have
        //    no issuer column; the issuer's `invite_create` row (meta = the token-hash prefix, written in the same tx as the
        //    invite) is the record, and it outlives every invite (365-day audit vs a 72 h invite), so the join is complete.
        c.exec(
            "DELETE FROM invites WHERE usedAt IS NULL AND substr(tokenHash,1,12) IN (SELECT meta FROM audit WHERE type='invite_create' AND userId=?)",
            userId,
        )
        c.exec("DELETE FROM invites WHERE email=?", user.email)

        // 5. Every session and device (deleting them IS the revocation: authenticate, refresh and the WebSocket re-check
        //    all find nothing), and the idempotency journal of those devices. Sessions first: sessions.deviceId is a FK.
        c.exec("DELETE FROM mutations WHERE deviceId IN (SELECT deviceId FROM devices WHERE userId=?)", userId)
        c.exec("DELETE FROM sessions WHERE userId=? OR deviceId IN (SELECT deviceId FROM devices WHERE userId=?)", userId, userId)
        c.exec("DELETE FROM devices WHERE userId=?", userId)

        // 6. Every grant row of the account (owner rows of the purged vaults, member rows elsewhere — the leave —, revoked
        //    rows anywhere), then the key material and per-account blobs: org escrow and its retained copy, the self-service
        //    recovery piece, the usage ledger, the account state (contact pins, issued grants) and the personal wrap.
        c.exec("DELETE FROM grants WHERE userId=?", userId)
        for (table in PER_ACCOUNT_TABLES) c.exec("DELETE FROM $table WHERE userId=?", userId)

        // 7. Audit. The pseudonym replaces the userId wherever it appears in meta (other accounts' rows: an admin's
        //    user_disable, an owner's vault_member_add), then the account's own rows are either re-keyed to the pseudonym
        //    (RETAINED_AUDIT_TYPES) or deleted. No row names the email (spec 02 §5); after this, none names the userId.
        val pseudonym = uuid()
        c.exec("UPDATE audit SET meta=replace(meta, ?, ?) WHERE instr(meta, ?) > 0", userId, pseudonym, userId)
        val kept = RETAINED_AUDIT_TYPES.toList()
        c.exec(
            "UPDATE audit SET userId=? WHERE userId=? AND type IN (${kept.joinToString(",") { "?" }})",
            pseudonym, userId, *kept.toTypedArray(),
        )
        c.exec("DELETE FROM audit WHERE userId=?", userId)

        // 8. The account row, last.
        val removed = c.exec("DELETE FROM users WHERE userId=?", userId)
        check(removed == 1) { "account row vanished mid-deletion" } // rolls the whole tx back

        // 8b. The instance's LAST account (the only one may delete itself, §5 of the design): every remaining invite goes
        //     with it — the used `*` bootstrap row it registered through included. A household with no accounts left keeps
        //     no enrolment authority, and seedBootstrap mints a fresh bootstrap invite at the next start (it also clears the
        //     table itself when it finds no account, for a database emptied any other way).
        val accountsLeft = c.queryOne("SELECT COUNT(*) FROM users") { it.getInt(1) } ?: 0
        if (accountsLeft == 0) c.exec("DELETE FROM invites")

        // 9. The deletion's own row, under the pseudonym, ids-free.
        repo.auditPseudonymOn(c, "account_delete", pseudonym, deviceId, ip, "vaults=${owned.size},left=${left.size}")

        // 10. Both ids are retired for good: neither the old userId nor the pseudonym may ever name a new account (register
        //     answers `user_id_taken`). Kept as a digest — no column names the deleted userId.
        for (id in listOf(userId, pseudonym)) c.exec("INSERT OR IGNORE INTO retired_ids(idHash) VALUES(?)", retiredIdHash(id))

        notify -= userId
        return Outcome(pseudonym, files, notify, owned.size, left.size)
    }

    /** `retired_ids.idHash` for [id]: lowercase-hex SHA-256 of its UTF-8 text (schema v16). */
    fun retiredIdHash(id: String): String = sha256HexUtf8(id)

    /** True when [id] was retired by an account deletion — the deleted userId or its audit pseudonym (spec 03 §13). */
    fun isRetired(c: Connection, id: String): Boolean =
        c.queryOne("SELECT 1 FROM retired_ids WHERE idHash=?", retiredIdHash(id)) { 1 } != null

    /** The per-account tables keyed by userId alone (each a FK child of users). A new one must be added here, or the
     *  user row's delete fails on its foreign key and the whole deletion rolls back — loud, never a silent leftover. */
    private val PER_ACCOUNT_TABLES = listOf("escrow", "escrow_legacy", "member_recovery", "usage_ledger", "account_state", "personal_wrap")
}
