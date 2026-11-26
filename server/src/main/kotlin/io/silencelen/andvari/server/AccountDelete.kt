package io.silencelen.andvari.server

import io.ktor.server.routing.Route
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.wire.AccountDeleteBlocker
import io.silencelen.andvari.core.model.wire.AccountDeletePreview
import io.silencelen.andvari.core.model.wire.AccountDeleteRequest
import io.silencelen.andvari.core.model.wire.DeleteBlockerKind
import io.silencelen.andvari.core.model.wire.DeleteMembership
import io.silencelen.andvari.core.model.wire.DeletedAtResponse
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.VaultLog
import java.sql.Connection

/** Vault purge (spec 03 §11.1, spec 02 §7): the janitor's statements, shared with account deletion (§13). */
object Purge {
    /**
     * Purge [vaultId] inside [c]: archived versions and attachment rows go (files after commit), items
     * become ciphertext-free tombstones (no rev bump), every grant's key material is blanked, the vault row
     * becomes a tombstone `{finalHead, purgedAt}`. The log rows stay with it when [keepLog] (other accounts
     * may still fetch and verify the owner's `delete`), else they go now. Returns the attachment ids to unlink.
     */
    fun vault(s: Services, c: Connection, vaultId: String, nowMs: Long, keepLog: Boolean): List<String> {
        c.exec("DELETE FROM item_versions WHERE itemId IN (SELECT itemId FROM items WHERE vaultId=?)", vaultId)
        val files = c.queryAll("SELECT attachmentId FROM attachments WHERE vaultId=?", vaultId) { it.getString(1) }
        c.exec("DELETE FROM attachments WHERE vaultId=?", vaultId)
        c.exec("UPDATE items SET deleted=1, conflict=0, blob=NULL, blobSize=0, attachmentIds='[]', updatedAt=? WHERE vaultId=?", nowMs, vaultId)
        c.exec("UPDATE grants SET wrappedVk='', signedGrant=NULL WHERE vaultId=?", vaultId)
        c.exec(
            """UPDATE vaults SET metaBlob='', deletedAt=COALESCE(deletedAt,?), purgeAt=COALESCE(purgeAt,?), purgedAt=?, deletedBy=NULL,
                 finalSeq=logSeq, finalHash=logHash, finalAt=logAt, pendingOfferId=NULL, pendingOwnerId=NULL, pendingOfferExpiresAt=NULL
               WHERE vaultId=?""",
            nowMs, nowMs, nowMs, vaultId,
        )
        if (!keepLog) c.exec("DELETE FROM vault_log WHERE vaultId=?", vaultId)
        s.audit.on(c, "vault_purge", null, null, null, "vault=$vaultId")
        return files
    }
}

/**
 * Account deletion (spec 03 §13) and the operator's deletion of a long-disabled account (§7.1), which is the
 * same transaction without leaves.
 */
object AccountDeletion {
    const val MAX_LEAVES = 500
    const val AUDIT_RETENTION_MS = 90 * Clock.DAY_MS

    /** The account's own audit rows KEPT under the pseudonym for 90 days: its security record (§13). */
    val RETAINED_AUDIT_TYPES: Set<String> = setOf(
        "register", "login", "login_fail", "logout", "session_end", "refresh_grace", "refresh_reuse", "reauth_fail", "password_change", "password_change_fail",
        "totp_enroll", "totp_rotate", "totp_disable", "totp_verify_fail", "totp_setup_reauth_fail",
        "recovery_self_commit", "recovery_self_setup", "recovery_self_setup_fail", "recovery_request_commit", "recovery_request_veto",
        "login_wait", "reauth_wait", "totp_verify_wait", "account_delete_stale",
        "push_denied", "attachment_cross_vault", "account_delete", "account_delete_denied", "account_delete_reauth_fail",
        "account_device_revoke", "require_link_set", "account_recovery_change", "escrow_self_reseal",
        "device_link_create", "device_link_approve", "device_link_pickup", "device_link_pickup_denied",
        "link_create", "link_answer", "link_revoke",
        "operator_disable", "operator_disable_denied", "operator_enable", "operator_delete", "operator_device_revoke",
        "device_revoke_denied", "operator_quota", "operator_policy", "operator_escrow_read", "operator_recovery_fulfil",
        "instance_card_update", "recovery_rotation_stored",
    )

    /** Rows about one vault's data: kept when the vault outlives the deletion, dropped with a purged one. */
    val VAULT_SCOPED_AUDIT_TYPES: Set<String> = setOf("vault_log_append", "vault_rename", "vault_grant_self_wrap", "attachment_upload", "item_restore", "item_purge")

    /** The revocations the account made are its security record wherever they point (§13). */
    private val REVOKING_KINDS = setOf("kind=remove", "kind=leave", "kind=delete")

    /** Types whose deviceId is the TARGET of an operator action, another account's device. */
    val FOREIGN_DEVICE_AUDIT_TYPES: Set<String> = setOf("operator_device_revoke", "device_revoke_denied")

    private const val CHUNK = 500

    /** The `shared_vault` and `operator` blockers, in a stable order (§13). */
    fun blockers(c: Connection, userId: String): List<AccountDeleteBlocker> {
        val out = ArrayList<AccountDeleteBlocker>()
        c.queryAll(
            """SELECT g.vaultId, (SELECT COUNT(*) FROM grants o WHERE o.vaultId=g.vaultId AND o.userId<>g.userId AND o.revokedAt IS NULL)
               FROM grants g JOIN vaults v ON v.vaultId=g.vaultId
               WHERE g.userId=? AND g.role='owner' AND g.revokedAt IS NULL AND v.type='shared' ORDER BY g.vaultId""",
            userId,
        ) { it.getString(1) to it.getInt(2) }.filter { it.second > 0 }.forEach { out += AccountDeleteBlocker(DeleteBlockerKind.SHARED_VAULT, it.first, it.second) }
        if (c.queryOne("SELECT 1 FROM users WHERE userId=? AND role='operator'", userId) { 1 } != null) out += AccountDeleteBlocker(DeleteBlockerKind.OPERATOR, null, 0)
        return out
    }

    /** Vaults deleted with the account: owned, with no other active grant (incl. one it soft-deleted, in grace). */
    fun ownedVaults(c: Connection, userId: String): List<String> = c.queryAll(
        """SELECT g.vaultId FROM grants g JOIN vaults v ON v.vaultId=g.vaultId
           WHERE g.userId=? AND g.role='owner' AND v.purgedAt IS NULL AND (g.revokedAt IS NULL OR g.revokedReason='vault_delete')
             AND NOT EXISTS(SELECT 1 FROM grants o WHERE o.vaultId=g.vaultId AND o.userId<>g.userId AND o.revokedAt IS NULL)
           ORDER BY g.vaultId""",
        userId,
    ) { it.getString(1) }

    /** The vaults that need a leave: a non-owner grant, active or revoked by `vault_delete` (§13). */
    fun memberships(c: Connection, userId: String): List<String> = c.queryAll(
        """SELECT g.vaultId FROM grants g JOIN vaults v ON v.vaultId=g.vaultId
           WHERE g.userId=? AND g.role<>'owner' AND v.type='shared' AND v.purgedAt IS NULL AND (g.revokedAt IS NULL OR g.revokedReason='vault_delete')
           ORDER BY g.vaultId""",
        userId,
    ) { it.getString(1) }

    fun preview(c: Connection, userId: String): AccountDeletePreview {
        val m = memberships(c, userId)
        return AccountDeletePreview(
            blockers = blockers(c, userId),
            deletedVaults = ownedVaults(c, userId).sorted(),
            leftVaults = m.sorted(),
            memberships = m.map { v -> DeleteMembership(v, VaultLogs.headAt(c, v, VaultLogs.vault(c, v)!!.logSeq!!)!!) },
            totpRequired = c.queryOne("SELECT totpSecret FROM users WHERE userId=?", userId) { it.getString(1) != null } ?: false,
        )
    }

    class Outcome(val pseudonym: String, val files: List<String>, val ring: Set<String>)

    /**
     * Delete [userId] inside [c], after the refusal rules and (for a self-deletion) the leaves. Every row that
     * names the account goes; vaults it alone held are purged now; the audit rows are re-keyed to a fresh
     * pseudonym as §13 says; both ids are retired; the user row goes last. [email] is queued by the caller.
     */
    fun deleteRows(s: Services, c: Connection, userId: String, deviceId: String?, ip: String?, nowMs: Long): Outcome {
        val ring = HashSet<String>()
        // Memberships elsewhere: their grants go (an operator deletion leaves the account in those logs' members).
        for (v in c.queryAll("SELECT vaultId FROM grants WHERE userId=? AND role<>'owner'", userId) { it.getString(1) }) {
            ring += Items.members(c, v)
            val rev = nextRev(c, "grant", v, v, nowMs)
            c.exec("UPDATE vaults SET rev=? WHERE vaultId=?", rev, v)
        }
        val owned = ownedVaults(c, userId)
        val files = ArrayList<String>()
        for (v in owned) {
            val othersAtDelete = c.count("SELECT COUNT(*) FROM grants WHERE vaultId=? AND userId<>? AND revokedReason='vault_delete'", v, userId) > 0
            files += Purge.vault(s, c, v, nowMs, keepLog = othersAtDelete)
        }
        for (v in c.queryAll("SELECT vaultId FROM vaults WHERE pendingOwnerId=?", userId) { it.getString(1) }) {
            ring += Items.members(c, v)
            c.exec("UPDATE vaults SET pendingOfferId=NULL, pendingOwnerId=NULL, pendingOfferExpiresAt=NULL WHERE vaultId=?", v)
        }
        c.exec("UPDATE vaults SET deletedBy=NULL WHERE deletedBy=?", userId)
        c.exec("DELETE FROM connections WHERE a=? OR b=?", userId, userId)
        c.exec("DELETE FROM links WHERE creatorUserId=? OR answererUserId=?", userId, userId)
        c.exec("DELETE FROM device_links WHERE userId=?", userId)
        // A request whose mailed code was not entered stays, as a decoy (no account, no code), until it expires like
        // any unverified request: so its poll answers as before the deletion, exactly as a decoy's does, and does not
        // tell whoever opened it that the address had an account. Every other request goes.
        c.exec("UPDATE recovery_requests SET userId=NULL, codeMac=NULL, cancelledAt=NULL WHERE userId=? AND state='unverified'", userId)
        c.exec("DELETE FROM recovery_requests WHERE userId=?", userId)
        // The address's mailbox values go with the account (spec 03 §18.1), before its row does.
        Assisted.forgetMailboxValuesOf(c, s.config, userId)
        // No column keeps the id (§13), and `changes` named it as the entity of its
        // `account` and `grant` revs. The rows are scrubbed, not deleted: the newest rev is MAX(rev) of this
        // table (currentRev), and deleting the newest row would move every client's rev backwards.
        c.exec("UPDATE changes SET entityId='-' WHERE entityId=?", userId)

        val devices = LinkedHashSet<String>().apply {
            addAll(c.queryAll("SELECT deviceId FROM devices WHERE userId=?", userId) { it.getString(1) })
            addAll(c.queryAll(
                "SELECT DISTINCT deviceId FROM audit WHERE userId=? AND deviceId IS NOT NULL AND type NOT IN (${FOREIGN_DEVICE_AUDIT_TYPES.joinToString(",") { "?" }})",
                userId, *FOREIGN_DEVICE_AUDIT_TYPES.toTypedArray(),
            ) { it.getString(1) })
            addAll(c.queryAll("SELECT DISTINCT deviceId FROM mutations WHERE userId=?", userId) { it.getString(1) })
            // An account that was the operator: the device it removed others' devices from, named in those rows' details
            // (`by=`), is one of its own devices, even when its device row was pruned.
            c.queryAll("SELECT meta FROM audit WHERE userId=? AND type='operator_device_revoke'", userId) { it.getString(1) }
                .mapNotNullTo(this) { operatorRevokeBy(it) }
        }.toList()
        c.exec("DELETE FROM mutations WHERE userId=?", userId)
        for (chunk in devices.chunked(CHUNK)) c.exec("DELETE FROM mutations WHERE deviceId IN (${chunk.joinToString(",") { "?" }})", *chunk.toTypedArray())
        c.exec("DELETE FROM session_chains WHERE sessionId IN (SELECT sessionId FROM sessions WHERE userId=?)", userId)
        c.exec("DELETE FROM sessions WHERE userId=?", userId)
        c.exec("DELETE FROM devices WHERE userId=?", userId)
        afterCommit(c) { s.forgetDeviceCounters(devices) }
        c.exec("DELETE FROM grants WHERE userId=?", userId)
        for (t in listOf("escrow", "member_recovery", "usage_ledger", "account_state", "personal_wrap")) c.exec("DELETE FROM $t WHERE userId=?", userId)

        // ---- the audit (§13): pseudonymise the kept rows, drop the rest, rename the device ids ----
        val pseudonym = uuid()
        c.exec("UPDATE audit SET meta=replace(meta, ?, ?) WHERE instr(meta, ?) > 0", userId, pseudonym, userId)
        val purged = owned.toSet()
        val keep = ArrayList<Long>()
        val drop = ArrayList<Long>()
        c.queryAll("SELECT id,type,meta FROM audit WHERE userId=?", userId) { Triple(it.getLong(1), it.getString(2), it.getString(3)) }.forEach { (id, type, meta) ->
            val kept = when {
                type == "vault_log_append" && REVOKING_KINDS.any { meta?.contains(it) == true } -> true
                type in RETAINED_AUDIT_TYPES -> true
                type in VAULT_SCOPED_AUDIT_TYPES -> vaultNamedBy(c, type, meta)?.let { it !in purged } ?: false
                else -> false
            }
            (if (kept) keep else drop) += id
        }
        for (chunk in keep.chunked(CHUNK)) c.exec("UPDATE audit SET userId=? WHERE id IN (${chunk.joinToString(",") { "?" }})", pseudonym, *chunk.toTypedArray())
        for (chunk in drop.chunked(CHUNK)) c.exec("DELETE FROM audit WHERE id IN (${chunk.joinToString(",") { "?" }})", *chunk.toTypedArray())
        c.exec("DELETE FROM audit WHERE userId=?", userId)
        val devicePseudonyms = devices.associateWith { uuid() }
        for ((dev, alias) in devicePseudonyms) c.exec("UPDATE audit SET deviceId=? WHERE deviceId=?", alias, dev)
        // The operator's own device in the details of its device removals (`by=`) gets the same new id as in every other
        // row; the removed device (the row's deviceId) and its account (`target=`) are another account's and are left
        // alone. The rows are this account's, so they are under the pseudonym by now.
        c.queryAll("SELECT id,meta FROM audit WHERE userId=? AND type='operator_device_revoke'", pseudonym) { it.getLong(1) to it.getString(2) }
            .forEach { (id, meta) ->
                val by = operatorRevokeBy(meta) ?: return@forEach
                devicePseudonyms[by]?.let { alias -> c.exec("UPDATE audit SET meta=? WHERE id=?", meta!!.replace(",by=$by", ",by=$alias"), id) }
            }

        check(c.exec("DELETE FROM users WHERE userId=?", userId) == 1) { "account row vanished mid-deletion" }
        s.audit.pseudonymOn(c, "account_delete", pseudonym, deviceId?.let { devicePseudonyms[it] }, ip, "vaults=${owned.size}")
        for (id in listOf(userId, pseudonym)) c.exec("INSERT OR IGNORE INTO retired_ids(idHash) VALUES(?)", sha256Hex(id))
        ring -= userId
        return Outcome(pseudonym, files, ring)
    }

    /** The vault a vault-scoped row names: `vault=<id>`, a leading id, or an attachment's vault. */
    private fun vaultNamedBy(c: Connection, type: String, meta: String?): String? {
        if (meta == null) return null
        Regex("vault=([0-9a-f-]{36})").find(meta)?.let { return it.groupValues[1] }
        val head = meta.substringBefore(':').takeIf { io.silencelen.andvari.core.model.wire.WireGrammar.isUuid(it) } ?: return null
        return if (type == "attachment_upload") c.queryOne("SELECT vaultId FROM attachments WHERE attachmentId=?", head) { it.getString(1) } else head
    }
}

/** `POST /account/delete`'s own bucket (spec 03 §13): 5 an hour per device, with its ceiling per account. */
internal val ACCOUNT_DELETE_BUCKET = Bucket.devicePerHour("account_delete", 5)

fun Route.accountDeleteRoutes(s: Services) {
    /** `GET /account/delete/preview` (spec 03 §13): a snapshot; the deletion re-checks everything. */
    api(WireRoute.ACCOUNT_DELETE_PREVIEW, s) {
        val principal = p
        respond(s.db.read { c -> AccountDeletion.preview(c, principal.userId) })
    }

    /**
     * `POST /account/delete` (spec 03 §13). The gate, outside the writer lock: the typed address
     * (`400 confirm_email_mismatch`); the password before the TOTP code (`429` from the proofs' back-off,
     * `403 reauth_failed`, `401 credential_changed`); then the code (`400 totp_code_required`, `429` from the
     * `totp_verify` bucket or the codes' back-off, `400 bad_totp_code`). Then one transaction: the credential and the
     * session must still be live (`401 credential_changed`), the TOTP step is consumed, the refusal rules
     * (`409 account_delete_blocked`, committed with its audit row), the leaves through §10.3's checks exempt
     * from every bucket (`409 account_delete_log_stale {vaultIds}`, or `400 at_ahead`), and only then the
     * deletion. `account_deleted` goes to the address captured here.
     *
     * **A refusal because a vault's log moved on costs the person nothing** (decided on 2026-11-17): the try's draws on
     * the limits per device, the deletion's own ([ACCOUNT_DELETE_BUCKET]) and the code's ([SharedBuckets.TOTP_VERIFY]),
     * are given back on the device's budgets with `409 account_delete_log_stale`, since nothing about the person was decided (the code's step is
     * rolled back with the transaction, and the back-offs were cleared when the proof and the code verified). A client
     * that tries again with fresh leaves after a co-member's change is then never sent into a wait for the server's own
     * refusals. Every other refusal keeps its draws.
     *
     * The account's ceiling for deletions (four times the device's five an hour) is drawn before the password is judged
     * and is never given back, for this refusal either (decided on 2026-11-17): a caller can produce the refusal at will
     * by leaving a leaf out, and each try runs the password's hash, so without it a member of one shared vault could
     * keep the server's hashing busy without end. Past the ceiling a try is `429` before any hashing.
     */
    api(WireRoute.ACCOUNT_DELETE, s, bucket = null) {
        val deleteDraw = takeHeld(ACCOUNT_DELETE_BUCKET)
        val req = body<AccountDeleteRequest>()
        if (req.leaves.size > AccountDeletion.MAX_LEAVES || req.leaves.any { it.length > VaultLogs.ENTRY_MAX }) badRequest(WireErrors.BAD_LEAVES)
        val principal = p
        val (email, totpSecret, lastStep, verifier) = s.db.read { c ->
            c.queryOne("SELECT email,totpSecret,totpLastStep,verifier FROM users WHERE userId=?", principal.userId) {
                listOf(it.getString(1), it.getString(2), it.getLong(3).toString(), it.getString(4))
            }
        } ?: unauthorized()
        if (Grammar.emailOrNull(req.confirmEmail) != email) badRequest(WireErrors.CONFIRM_EMAIL_MISMATCH)
        // The proof first, on the proofs' back-off like every † route's (Req.reauth), and only then the code: a wrong
        // or missing proof never tells whether the code was right (the code is neither counted, recorded nor consumed).
        // The CAS below is on the verifier it matched, which a change between the two reads makes stale
        // (401 credential_changed).
        val matched = reauth(req.currentAuthKey, "account_delete_reauth_fail", auditMeta = null)
        if (matched != verifier) {
            s.db.tx { c -> s.audit.on(c, "account_delete_reauth_fail", principal.userId, principal.deviceId, ip, "credential_changed") }
            unauthorized(WireErrors.CREDENTIAL_CHANGED)
        }
        var step: Long? = null
        var codeDraw: DeviceDraw? = null
        if (totpSecret != null) {
            val code = req.totp ?: badRequest(WireErrors.TOTP_CODE_REQUIRED)
            codeDraw = takeHeld(SharedBuckets.TOTP_VERIFY)
            // On the codes' own back-off, as every code a session sends (Req.checkSessionCode).
            step = checkSessionCode("account_delete") { TotpCheck.verify(totpSecret, code, lastStep!!.toLong(), now) }
        }
        val nowMs = now
        s.raceHook?.invoke("delete.afterGate")
        val result: Result<AccountDeletion.Outcome> = try { s.db.tx { c ->
            val still = c.queryOne("SELECT verifier FROM users WHERE userId=?", principal.userId) { it.getString(1) }
            if (still != verifier || !s.sessions.sessionLive(c, principal.sessionId)) {
                s.audit.on(c, "account_delete_reauth_fail", principal.userId, principal.deviceId, ip, "credential_changed")
                return@tx Result.failure(ApiException(401, WireErrors.CREDENTIAL_CHANGED))
            }
            if (step != null && !TotpCheck.consume(c, principal.userId, step)) {
                return@tx Result.failure(ApiException(400, WireErrors.BAD_TOTP_CODE))
            }
            val blockers = AccountDeletion.blockers(c, principal.userId)
            if (blockers.isNotEmpty()) {
                s.audit.on(c, "account_delete_denied", principal.userId, principal.deviceId, ip, blockers.joinToString(",") { it.kind })
                return@tx Result.failure(ApiException(409, io.silencelen.andvari.core.model.wire.WireError(WireErrors.ACCOUNT_DELETE_BLOCKED, "account deletion is blocked", blockers = blockers)))
            }
            // The leaves: exactly one per membership, each appended under §10.3's rules, bucket-exempt.
            val needed = AccountDeletion.memberships(c, principal.userId).toSet()
            val byVault = HashMap<String, String>()
            val stale = sortedSetOf<String>()
            for (leaf in req.leaves) {
                val v = runCatching { VaultLog.parse(io.silencelen.andvari.core.crypto.createCryptoProvider(), Bytes.fromB64(leaf)).valueOrNull()?.entry?.vaultId }.getOrNull()
                if (v == null || v !in needed || byVault.put(v, leaf) != null) badRequest(WireErrors.BAD_LEAVES)
            }
            for (v in needed) {
                val leaf = byVault[v]
                if (leaf == null) { stale += v; continue }
                try {
                    val e = VaultLog.parse(io.silencelen.andvari.core.crypto.createCryptoProvider(), Bytes.fromB64(leaf)).valueOrNull()?.entry
                    if (e !is io.silencelen.andvari.core.trust.LogEntry.Leave) { stale += v; continue }
                    VaultLogs.append(s, c, null, principal.userId, principal.deviceId, ip, v, leaf, null, null, null, exemptFromBuckets = true)
                } catch (e: ApiException) {
                    if (e.body.error == WireErrors.AT_AHEAD) throw e
                    stale += v
                }
            }
            if (stale.isNotEmpty()) throw ApiException(409, io.silencelen.andvari.core.model.wire.WireError(WireErrors.ACCOUNT_DELETE_LOG_STALE, "a vault log moved on", vaultIds = stale.toList()))
            val accountId = accountIdOf(c, principal.userId)
            val out = AccountDeletion.deleteRows(s, c, principal.userId, principal.deviceId, ip, nowMs)
            s.mail.enqueue(c, "account_deleted", email!!, Mail.Ctx(accountId, nowMs))
            Result.success(out)
        } } catch (e: ApiException) {
            if (e.body.error == WireErrors.ACCOUNT_DELETE_LOG_STALE) {
                deleteDraw.giveBack()
                codeDraw?.giveBack()
                // The refusal leaves a trace the operator can see (decided on 2026-11-17), once per account per hour and
                // never per try: written after the rollback, in a transaction of its own.
                if (s.refusalTraceDue("account_delete_stale", principal.userId, RefusalTrace.DELETE_STALE_PERIOD_MS)) {
                    s.db.tx { c -> s.audit.on(c, "account_delete_stale", principal.userId, principal.deviceId, ip, "vaults=${e.body.vaultIds?.size ?: 0}") }
                }
            }
            throw e
        }
        val out = result.getOrThrow()
        finishDeletion(s, principal.userId, out)
        respond(DeletedAtResponse(nowMs))
    }
}

/** After a deletion commits: close the account's sockets, unlink purged files, truncate the WAL, ring co-members. */
fun finishDeletion(s: Services, userId: String, out: AccountDeletion.Outcome) {
    s.notifier.notifyRevokedUser(userId)
    s.attachments.unlinkOrphaned(out.files)
    s.db.checkpointTruncate()
    if (out.ring.isNotEmpty()) s.notifier.notifyRev(out.ring, s.db.read { currentRev(it) })
}
