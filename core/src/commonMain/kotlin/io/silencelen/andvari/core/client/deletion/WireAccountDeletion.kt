package io.silencelen.andvari.core.client.deletion

import io.silencelen.andvari.core.client.account.Reauth
import io.silencelen.andvari.core.client.account.ReauthKey
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.AccountDeletePreview
import io.silencelen.andvari.core.model.wire.AccountDeleteRequest
import io.silencelen.andvari.core.model.wire.DeleteMembership
import io.silencelen.andvari.core.model.wire.DeletedAtResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.core.trust.VaultState

/**
 * [AccountDeletion] over `GET /account/delete/preview` and `POST /account/delete` (spec 03 §13, design §3.11).
 *
 * The leaves are signed from a FRESH preview at delete time, one per membership, each at the served head
 * with `at = max(clock, head.at)` ([VaultLog.positionAfter]). When the served `(seq, hash)` is exactly this
 * device's verified head, the leave is placed from the verified state instead ([VaultLog.position]), so the
 * served `at` is never used for it. A head this device has not verified must not be more than one day ahead
 * of the device clock (FS-R7): otherwise nothing is signed for any vault and nothing is sent ([DeletionOutcome.FutureHead]).
 * Every check that needs no secret runs before the re-authentication: blockers, the typed address, the
 * missing code, the head times. An unclear answer is [DeletionOutcome.Unknown]; only a `200` wipes.
 *
 * The verified state of each vault's log comes from the session's own log engine ([StoredVaultLogs.verifiedState]),
 * so no caller can hand the signer a made-up state. [onDeleted] wipes this device's state for the account (the
 * session keeper's sign-out with the self-identity records).
 */
class WireAccountDeletion internal constructor(
    private val me: String,
    private val emailNorm: String,
    private val signer: io.silencelen.andvari.core.client.onboard.GuardedKeyPair,
    private val client: WireClient,
    private val crypto: CryptoProvider,
    private val reauth: Reauth,
    private val verifiedState: (String) -> VaultState?,
    private val clock: () -> Long,
    private val onDeleted: suspend () -> Unit,
) : AccountDeletion {

    /**
     * Account deletion whose leaves are placed from [logs]' own verified state of each vault (design §3.11). The only
     * public constructor: the one that takes a verified-state function is internal, for the engine's own tests.
     */
    constructor(
        me: String,
        emailNorm: String,
        signer: io.silencelen.andvari.core.client.onboard.GuardedKeyPair,
        client: WireClient,
        crypto: CryptoProvider,
        reauth: Reauth,
        logs: StoredVaultLogs,
        clock: () -> Long,
        onDeleted: suspend () -> Unit,
    ) : this(me, emailNorm, signer, client, crypto, reauth, { id: String -> logs.verifiedState(id) }, clock, onDeleted)

    /**
     * The same deletion for [account]'s session, its signing key taken from the opened account itself, so a host never
     * holds it as a value.
     */
    constructor(
        account: io.silencelen.andvari.core.client.onboard.OpenedAccount,
        emailNorm: String,
        client: WireClient,
        crypto: CryptoProvider,
        reauth: Reauth,
        logs: StoredVaultLogs,
        clock: () -> Long,
        onDeleted: suspend () -> Unit,
    ) : this(account.userId, emailNorm, account.signing, client, crypto, reauth, logs, clock, onDeleted)

    private suspend fun fetchPreview(): AccountDeletePreview? =
        (client.call(WireRoute.ACCOUNT_DELETE_PREVIEW, decode = { WireJson.json.decodeFromString(AccountDeletePreview.serializer(), it) }) as? WireResult.Ok)?.value

    override suspend fun preview(): DeletionPreview? = fetchPreview()?.let {
        DeletionPreview(it.blockers, it.deletedVaults, it.leftVaults, it.memberships.size, it.totpRequired)
    }

    /** The leaves for [memberships], or null when one head is too far ahead (FS-R7): then nothing is signed. */
    internal fun leaves(memberships: List<DeleteMembership>, now: Long): List<String>? {
        // A head this device verified is placed from its OWN verified state, `at` included: the served `at` beside
        // a verified (seq, hash) is the server's word and is never signed after. Every other head is the server's
        // alone and is held to the one-day bound.
        val positions = memberships.map { m ->
            val v = verifiedState(m.vaultId)?.takeIf { it.head.seq == m.head.seq && it.head.hash == m.head.hash }
            if (v != null) VaultLog.position(v, now)
            else if (m.head.at - now > FUTURE_LIMIT_MS) return null
            else VaultLog.positionAfter(m.head.seq, m.head.hash, m.head.at, now)
        }
        return memberships.zip(positions).map { (m, pos) ->
            Bytes.toB64(signer.use { VaultLog.sign(crypto, it, LogEntry.Leave(m.vaultId, pos.seq, pos.prev, me, pos.at)) })
        }
    }

    override suspend fun delete(typedEmail: String, password: CharArray, totp: String?): DeletionOutcome {
        // The typed confirmation binds every client; checked here so a typo sends nothing (the server checks it too).
        // Every early exit wipes the password it was handed.
        if (typedEmail.trim().lowercase() != emailNorm) {
            password.fill('\u0000')
            return DeletionOutcome.EmailMismatch
        }
        // Spec 01 §7: the password is proven on this device first. A wrong one
        // fetches nothing, signs no leave and sends nothing. [Reauth.currentAuthKey] wipes it, whatever it answers.
        val key = when (val k = reauth.currentAuthKey(password)) {
            is ReauthKey.Key -> k.currentAuthKey
            ReauthKey.Refused -> return DeletionOutcome.ReauthRefused
            ReauthKey.Unreachable -> return DeletionOutcome.Unreachable
            ReauthKey.WrongPassword -> return DeletionOutcome.WrongPassword
        }
        val p = fetchPreview() ?: return DeletionOutcome.Unreachable
        if (p.blockers.isNotEmpty()) return DeletionOutcome.Blocked(p.blockers)
        if (p.totpRequired && totp.isNullOrEmpty()) return DeletionOutcome.TotpNeeded
        if (p.memberships.size > MAX_LEAVES) return DeletionOutcome.Refused("bad_leaves")
        if (p.memberships.map { it.vaultId }.toSet().size != p.memberships.size) return DeletionOutcome.Refused("bad_preview")
        // A served head outside the grammar cannot be signed after: refuse the preview, sign nothing.
        val leaves = try {
            leaves(p.memberships, clock())
        } catch (e: IllegalArgumentException) {
            return DeletionOutcome.Refused("bad_preview")
        } ?: return DeletionOutcome.FutureHead
        // The re-authentication and the preview were waits, and a lock during them makes the leaves' signing refuse
        // ([io.silencelen.andvari.core.crypto.KeysGoneException]). Nothing signed is sent once the keys are wiped:
        // the guard is asked again just before the send. The engine answers that exception as overtaken.
        signer.guard.check()
        val body = WireJson.json.encodeToString(AccountDeleteRequest.serializer(), AccountDeleteRequest(typedEmail, key, totp?.takeIf { p.totpRequired }, leaves))
        val r = client.call(WireRoute.ACCOUNT_DELETE, bodyJson = body, decode = { WireJson.json.decodeFromString(DeletedAtResponse.serializer(), it) })
        return when (r) {
            is WireResult.Ok -> {
                onDeleted()
                DeletionOutcome.Deleted(r.value.deletedAt)
            }
            is WireResult.NoAnswer -> DeletionOutcome.Unknown
            is WireResult.Refused -> when {
                r.status >= 500 -> DeletionOutcome.Unknown
                r.code == "account_delete_blocked" -> DeletionOutcome.Blocked(r.error.blockers ?: emptyList())
                r.code == "account_delete_log_stale" -> DeletionOutcome.LogStale(r.error.vaultIds ?: emptyList())
                r.code == "at_ahead" -> DeletionOutcome.ClockAhead
                r.code == "totp_code_required" -> DeletionOutcome.TotpNeeded
                r.code == "bad_totp_code" -> DeletionOutcome.BadTotp
                // The server refused the proof: the password was proven here first, so never a wrong password.
                r.code == io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED ->
                    DeletionOutcome.Refused(io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED, r.retryAfterSeconds)
                r.code == "confirm_email_mismatch" -> DeletionOutcome.EmailMismatch
                else -> DeletionOutcome.Refused(r.code, r.retryAfterSeconds)
            }
        }
    }

    companion object {
        /** FS-R7: from an unverified head, a `head.at` more than one day ahead of the device clock is refused. */
        const val FUTURE_LIMIT_MS: Long = 24L * 60 * 60 * 1000

        /** At most 500 leaves (the membership limit). */
        const val MAX_LEAVES = 500
    }
}
