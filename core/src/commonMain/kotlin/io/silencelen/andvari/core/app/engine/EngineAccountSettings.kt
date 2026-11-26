package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.DeletionBlockerKind
import io.silencelen.andvari.core.app.DeletionBlockerRow
import io.silencelen.andvari.core.app.DeletionPlan
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.DeletionScreen
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireAccountSettings
import io.silencelen.andvari.core.client.deletion.DeletionOutcome
import io.silencelen.andvari.core.client.deletion.DeletionPreview
import io.silencelen.andvari.core.client.deletion.WireAccountDeletion
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.model.wire.DeleteBlockerKind
import io.silencelen.andvari.core.model.wire.WireErrors
import kotlinx.coroutines.launch

/**
 * Settings › Change master password (spec 03 §3 `PUT /account/password`) on the engine. The change goes through the
 * engine's one re-authentication path to the session's own server ([WireAccountSettings.change]); the account's key
 * does not change, so the kit and any operator recovery stay valid and no new kit is due (§10 asks one only after a
 * recovery or a followed move). Once the server answered, this device keeps the very wrap the server took, under the
 * new password ([io.silencelen.andvari.core.client.session.SessionKeeper.passwordChangedTo]), so the old one no longer
 * opens it here.
 */
internal class EngineAccountSettings(private val app: EngineAppApi) {
    private fun unlocked() = app.phase == AppPhase.UNLOCKED && app.keeper.established != null && app.vault?.signedOutByServer != true

    private fun settings(): WireAccountSettings? {
        val est = app.keeper.established ?: return null
        val pin = app.trust.pinFor(est.origin) ?: return null
        val reauth = app.keeper.reauth() ?: return null
        return WireAccountSettings(est.origin, est.emailNorm, pin.card0Hash, est.account, app.clientFor(est.origin), app.crypto, reauth, changeCost(est.origin), thisDevice = est.deviceId)
    }

    /**
     * The KDF cost a new master password is derived at: the account's present
     * cost, raised to the policy's when the policy is a legitimate upgrade within the fence
     * ([io.silencelen.andvari.core.client.KdfUpgrade.shouldUpgrade]), and never lower than the account already had.
     */
    private fun changeCost(origin: String): io.silencelen.andvari.core.crypto.KdfParams {
        val account = app.keeper.accountKdfParams() ?: io.silencelen.andvari.core.crypto.KdfParams.DEFAULT
        val policy = app.policies.get(origin)?.kdfParams ?: return account
        return if (io.silencelen.andvari.core.client.KdfUpgrade.shouldUpgrade(account, policy)) policy else account
    }

    suspend fun changeMasterPassword(current: String, replacement: String): PasswordChangeResult {
        if (!unlocked()) return PasswordChangeResult.STALE
        if (current.isEmpty()) return PasswordChangeResult.WRONG_PASSWORD
        val est = app.keeper.established ?: return PasswordChangeResult.STALE
        // A change sent earlier whose answer never came is settled first, against what the
        // server holds now (the read an opening makes), so that no second change replaces its pending wrap. When the
        // server cannot say yet, nothing is sent.
        if (app.keeper.hasPendingWrap(est.userId)) {
            app.working { app.readAccountKeys(est.origin, est.userId) }
            if (!unlocked() || app.keeper.established !== est) return PasswordChangeResult.STALE
            if (app.keeper.hasPendingWrap(est.userId)) return PasswordChangeResult.UNREACHABLE
        }
        val s = settings() ?: return PasswordChangeResult.STALE
        // No key is held here: the new wrap is sealed inside the change, before its
        // re-authentication, and this device keeps that same wrap once the server took it, so no key and no KDF is
        // needed after the answer. The current password is proven on this device first (spec 01 §7): a wrong one sends
        // nothing. The new wrap is kept as pending before the request goes, so a lost answer never leaves
        // the person locked out.
        var sent: String? = null
        val r = try {
            app.working {
                s.changeWrap(current.toCharArray(), replacement.toCharArray()) { w ->
                    sent = w.wrappedUvk
                    app.keeper.passwordChangePending(est.userId, w.kdfSalt, w.kdfParams, w.wrappedUvk)
                }
            }
        } catch (e: KeysGoneException) {
            // A lock before the request went (the seal refused, or the guard's check after the proof): nothing was sent
            // and no pending wrap was kept; the password is unchanged everywhere.
            return PasswordChangeResult.STALE
        }
        when (r) {
            is Reauthed.Done -> {
                // The server's password is the new one now, whatever happens next (a lock that came while the answer was
                // on its way included): this device keeps the very wrap the server took. When the kept session is no
                // longer this account's, nothing is kept and the person is told the previous password still opens this
                // device's copy.
                val followed = app.keeper.passwordChangedTo(est.userId, r.value.kdfSalt, r.value.kdfParams, r.value.wrappedUvk)
                app.publish()
                if (!followed) return PasswordChangeResult.CHANGED_PREVIOUS_OPENS_HERE
            }
            // No answer: the change may have landed. The pending wrap stays, and the next opening settles it.
            Reauthed.Unknown -> Unit
            // The server answered that it was not made (or nothing was sent): this request's pending wrap goes, no other.
            else -> sent?.let { app.keeper.passwordChangeNotTaken(est.userId, it) }
        }
        return result(r)
    }

    // ---- Settings › Delete account (§3.11, the account-deletion design of 2026-11-10) ----

    private var deletionOpen = false
    private var plan: DeletionPlan? = null
    private var retrying = false
    private var shown: DeletionScreen? = null

    /**
     * "We cannot tell yet whether the account was deleted": kept durably for the kept
     * session's origin and account, so a lock, a restart or a session the server ends (the likely sign that the deletion
     * landed) does not drop it. Only a server's answer settles it: a preview that answers (the account is there), the
     * account's keys read at an opening, a refusal by the server at a later attempt, or the deletion's own `200`; and the
     * account's own end (sign-out, "Forget this server", the deletion) clears it.
     */
    private var outcomeUnknown: Boolean
        get() = app.keeper.session?.let { deletionOutcomeUnknown(it.origin, it.userId) } == true
        set(value) {
            val kept = app.keeper.session ?: return
            setDeletionOutcomeUnknown(kept.origin, kept.userId, value)
        }

    internal fun deletionOutcomeUnknown(origin: String, userId: String): Boolean = app.engine.state.get("$OUTCOME_UNKNOWN_KEY$origin|$userId") != null

    /**
     * At a start: a mark of a deletion of unknown outcome whose key names no account ([outcomeUnknownOf] null) is removed.
     * Nothing reads it as any account's, and it would hold the sweep back for good. A removal the store refuses leaves it,
     * and the sweep's diagnostic line names it.
     */
    internal fun dropOutcomeMarksNamingNoAccount() {
        val st = app.engine.state
        val keys = try { st.keys() } catch (e: Exception) { null } ?: return
        for (k in keys) if (k.startsWith(OUTCOME_UNKNOWN_KEY) && outcomeUnknownOf(k) == null) {
            try { st.set(k, null) } catch (e: Exception) { return }
        }
    }

    internal fun setDeletionOutcomeUnknown(origin: String, userId: String, unknown: Boolean) {
        val key = "$OUTCOME_UNKNOWN_KEY$origin|$userId"
        if ((app.engine.state.get(key) != null) == unknown) return
        app.engine.state.set(key, if (unknown) "1" else null)
    }

    /** Moves on at every lock and end, and at every opening of the screen, so a late answer is not applied. */
    private var generation = 0

    /** The vault closed (a lock, an end): the screen closes. A request in flight is not cancelled; its answer is dropped. */
    fun ended() {
        deletionOpen = false
        plan = null
        retrying = false
        // An unknown outcome is not dropped here: it is kept durably until a server's answer settles it.
        shown = null
        generation++
    }

    fun deletionScreen(): DeletionScreen? {
        if (!deletionOpen || !unlocked()) return null
        val email = app.accountEmail ?: app.keeper.established?.emailNorm ?: return null
        val s = shown
        if (s != null && s.email == email && s.plan === plan && s.retrying == retrying && s.outcomeUnknown == outcomeUnknown) return s
        return DeletionScreen(email, plan, retrying, outcomeUnknown).also { shown = it }
    }

    private fun deletion(): WireAccountDeletion? {
        val est = app.keeper.established ?: return null
        val v = app.vault?.takeIf { !it.closed } ?: return null
        val reauth = app.keeper.reauth() ?: return null
        return WireAccountDeletion(est.userId, est.emailNorm, est.account.signing, app.clientFor(est.origin), app.crypto, reauth, v.logs, app.engine.clock) {}
    }

    /** The preview as a plan, the vaults by the names this device can read (the personal vault as "Personal"). */
    private fun planOf(p: DeletionPreview): DeletionPlan {
        val est = app.keeper.established
        val rows = app.snapshot.account?.vaults.orEmpty().associateBy { it.vaultId }
        fun name(id: String): String = if (id == est?.account?.personalVaultId) PERSONAL else rows[id]?.name.orEmpty()
        return DeletionPlan(
            deletedVaults = p.deletedVaults.map(::name),
            leftVaults = p.leftVaults.map(::name),
            blockers = p.blockers.map { b ->
                when (b.kind) {
                    DeleteBlockerKind.SHARED_VAULT -> DeletionBlockerRow(DeletionBlockerKind.SHARED_VAULT_WITH_OTHERS, b.vaultId?.let { rows[it]?.name }, b.others)
                    DeleteBlockerKind.OPERATOR -> DeletionBlockerRow(DeletionBlockerKind.OPERATOR_ACCOUNT, null, b.others)
                    else -> DeletionBlockerRow(DeletionBlockerKind.NOT_KNOWN, null, b.others)
                }
            },
            codeNeeded = p.totpRequired,
        )
    }

    suspend fun openDeletion(): PlainResult {
        if (!unlocked()) return PlainResult.STALE
        val d = deletion() ?: return PlainResult.STALE
        ended()
        deletionOpen = true
        val g = generation
        app.publish()
        val p = app.working { d.preview() }
        if (g != generation || !unlocked()) return PlainResult.STALE
        // The screen stays open without a plan: nothing is offered until the server answered.
        if (p == null) return PlainResult.UNREACHABLE
        // The preview answers only while the account exists: an unknown outcome kept from before is settled.
        outcomeUnknown = false
        plan = planOf(p)
        app.publish()
        return PlainResult.DONE
    }

    fun closeDeletion() {
        if (!deletionOpen) return
        ended()
        app.publish()
    }

    /** Read the preview again for the screen on show (after a refusal that changes what it says). */
    private suspend fun replan(d: WireAccountDeletion, g: Int) {
        val p = d.preview() ?: return
        if (g == generation && deletionOpen) plan = planOf(p)
    }

    suspend fun deleteAccount(screen: DeletionScreen, typedEmail: String, password: String, code: String?): DeletionResult {
        if (!unlocked() || deletionScreen() !== screen) return DeletionResult.STALE
        val d = deletion() ?: return DeletionResult.STALE
        val est = app.keeper.established ?: return DeletionResult.STALE
        if (password.isEmpty()) return DeletionResult.WRONG_PASSWORD
        val g = generation
        var outcome: DeletionOutcome = DeletionOutcome.Unreachable
        var rounds = 0
        app.working {
            while (true) {
                // The engine wipes the password it is handed: each round has its own copy.
                outcome = try {
                    d.delete(typedEmail, password.toCharArray(), code?.trim()?.ifEmpty { null })
                } catch (e: KeysGoneException) {
                    // A lock before the request went: nothing was sent; the closed screen drops the answer.
                    DeletionOutcome.ReauthRefused
                }
                if (outcome !is DeletionOutcome.LogStale || ++rounds >= STALE_ROUNDS || g != generation) break
                // `409 account_delete_log_stale`: a vault's history moved; the engine fetches the heads again.
                retrying = true
                app.publish()
            }
            retrying = false
        }
        val o = outcome
        if (o is DeletionOutcome.Deleted) {
            // The server deleted the account: this device's state for it goes, whatever screen is on show now, as
            // long as the session kept is still that account's (the deletion's own `revoked` may have ended it).
            deleted(est.origin, est.userId)
            return DeletionResult.DONE
        }
        // What the outcome says about "we cannot tell yet": only an answer from
        // the server settles it. An unknown outcome sets it, whatever screen is on show now (a lock, the server's end).
        // An outcome decided on this device (a typo in the address, a wrong password proven locally, a gate's refusal, a
        // far-future head) or no answer at all leaves it as it was; a wrong password or a mismatched address the server
        // answered leaves it too, the safer reading. Every other refusal is the server's word that the account is there.
        when (o) {
            DeletionOutcome.Unknown -> setDeletionOutcomeUnknown(est.origin, est.userId, true)
            DeletionOutcome.EmailMismatch, DeletionOutcome.WrongPassword, DeletionOutcome.ReauthRefused, DeletionOutcome.Unreachable,
            DeletionOutcome.FutureHead -> Unit
            is DeletionOutcome.Blocked, is DeletionOutcome.LogStale, DeletionOutcome.ClockAhead, DeletionOutcome.TotpNeeded,
            DeletionOutcome.BadTotp, is DeletionOutcome.Refused -> setDeletionOutcomeUnknown(est.origin, est.userId, false)
            is DeletionOutcome.Deleted -> Unit
        }
        if (g != generation || !unlocked()) {
            // The screen went meanwhile (a lock, the server's end). An unknown outcome is still said.
            return if (o is DeletionOutcome.Unknown) DeletionResult.OUTCOME_UNKNOWN else DeletionResult.STALE
        }
        val r = when (o) {
            is DeletionOutcome.Deleted -> DeletionResult.DONE
            is DeletionOutcome.Blocked -> DeletionResult.BLOCKED.also { replan(d, g) }
            is DeletionOutcome.LogStale -> DeletionResult.STILL_CHANGING
            DeletionOutcome.FutureHead -> DeletionResult.FAR_FUTURE
            DeletionOutcome.ClockAhead -> DeletionResult.CLOCK_AHEAD
            DeletionOutcome.TotpNeeded -> DeletionResult.CODE_NEEDED.also { replan(d, g) }
            DeletionOutcome.BadTotp -> DeletionResult.WRONG_CODE
            DeletionOutcome.WrongPassword -> DeletionResult.WRONG_PASSWORD
            DeletionOutcome.EmailMismatch -> DeletionResult.EMAIL_MISMATCH
            DeletionOutcome.Unknown -> DeletionResult.OUTCOME_UNKNOWN
            DeletionOutcome.Unreachable -> DeletionResult.UNREACHABLE
            DeletionOutcome.ReauthRefused -> DeletionResult.FAILED
            is DeletionOutcome.Refused -> {
                app.noteRetryAfter(o.retryAfterSeconds)
                when (o.code) {
                    WireErrors.RATE_LIMITED -> DeletionResult.RATE_LIMITED
                    WireErrors.UPGRADE_REQUIRED -> DeletionResult.UPDATE_REQUIRED
                    WireErrors.CREDENTIAL_CHANGED -> DeletionResult.CHANGED_ELSEWHERE
                    Reauthed.PROOF_REFUSED -> app.proofRefused(DeletionResult.KEYS_NOT_KNOWN_HERE, DeletionResult.PROOF_REFUSED)
                    else -> DeletionResult.FAILED
                }
            }
        }
        app.publish()
        return r
    }

    /**
     * After an unknown outcome: the preview answers only while the account exists, so an answer clears the state. No
     * answer says nothing. A session the server ended meanwhile (its `401`) cannot be told from another end of the
     * session (the operator, a password change elsewhere): the account stands as signed out by the server, its copy and
     * its identity record kept, and nothing here says it was deleted (the design's step 7).
     */
    suspend fun checkDeletion(screen: DeletionScreen): PlainResult {
        if (!unlocked() || deletionScreen() !== screen || !outcomeUnknown) return PlainResult.STALE
        val d = deletion() ?: return PlainResult.STALE
        val g = generation
        val p = app.working { d.preview() }
        if (g != generation || !unlocked()) return PlainResult.STALE
        if (p == null) return PlainResult.UNREACHABLE
        outcomeUnknown = false
        plan = planOf(p)
        app.publish()
        return PlainResult.DONE
    }

    /**
     * The account is deleted: the session is forgotten with its identity record, its copy goes (§4.4's own act), and this
     * device is as new for that server (decided on 2026-11-18: nothing stays): everything "Forget this server" removes
     * goes too, the pin and the address with it.
     */
    private fun deleted(origin: String, userId: String) {
        val kept = app.keeper.session
        if (kept == null || kept.origin != origin || kept.userId != userId) {
            setDeletionOutcomeUnknown(origin, userId, false)
            return
        }
        // Whether something at another server ties the account, read once, before anything of the deletion is removed (a
        // tie can run through this server's record of the address, which the keeper removes): it decides the identity
        // record and the records kept by the account's id alone, on both roads. Tied too where the sweep's own rule knows the
        // account apart from what this deletion removes (a copy held at another server, say): the two never disagree.
        val tied = app.keptElsewhere(userId, origin, kept.emailNorm)
        // The first screen says it once (an added field, not a new FirstRunNotice): the address and the server as the pin
        // named it, read before the pin goes.
        // Nothing of another account at that server is taken with it unsaid (its copy, its device row, its trust records,
        // its address's record): where this device keeps any, only this account's records go, and the server stays known
        // (the line says so).
        val othersHeld = app.othersKnownAt(origin, userId, kept.emailNorm)
        val said = app.labelFor(origin)?.let {
            io.silencelen.andvari.core.app.AccountDeletedNotice(app.accountEmail ?: kept.emailNorm, it, serverForgotten = !othersHeld)
        }
        // The mark of a deletion begun, written before anything of it is removed: a stop at any later step is finished at
        // the next start ([settleDeletions]) by the same steps, with what was read here.
        val mark = DeletionMark(origin, userId, kept.emailNorm, tied, othersHeld, app.keptMark())
        setDeletionMarks(deletionMarks().filterNot { it.origin == origin && it.userId == userId } + mark)
        finish(mark, said)
        app.publish()
    }

    /**
     * The steps of a deletion that [DeletionMark.origin] confirmed, after its mark: run once by the deletion itself ([said]:
     * the first screen's notice), and again at a start for a deletion a stop cut part-way ([settleDeletions]). Each step
     * changes nothing that is already done. A mark is finished only while nothing has been taken at its server that uses
     * what it would remove: a take there of the account, or of any account under its address, ends the mark before that
     * take writes anything ([takeEndsDeletions]), so a session of the account kept at that server now is the one the
     * deletion began with. Where that session's take is not the one the mark names (its at-rest mark was lost), nothing
     * tells it from a later take: nothing of the account goes, the mark alone. A session of the account kept at another
     * server, or of another account, decides nothing: the deletion finishes at its own server, and what is kept there and
     * by the account's id for that session stays (the tie, the sweep).
     */
    private fun finish(m: DeletionMark, said: io.silencelen.andvari.core.app.AccountDeletedNotice?) {
        val kept = app.keeper.session
        val here = kept != null && kept.origin == m.origin && kept.userId == m.userId
        if (here && (m.take.isEmpty() || app.keptMark() != m.take)) {
            setDeletionMarks(deletionMarks().filterNot { it.origin == m.origin && it.userId == m.userId })
            return
        }
        // As read when the deletion began; a read now can only add a tie (one that ran through a record already removed is
        // in the mark).
        val tied = m.tied || app.keptElsewhere(m.userId, m.origin, m.emailNorm)
        setDeletionOutcomeUnknown(m.origin, m.userId, false)
        if (here) {
            app.kitFlow.drop()
            app.endVault(null)
            app.keeper.forget(forgetIdentity = true, tied = tied)
        } else {
            // A stop came after the keeper's end of the session (or the account is kept at another server now): what that
            // end removes at this server is removed again, where it is left.
            app.keeper.forgetDeleted(m.origin, m.emailNorm, m.userId, tied)
        }
        // The copy goes as the deletion's own (the reason the content is told), then every other record of that server,
        // the mark that a kit was shown there among them ([EngineKit.SHOWN_KEY] is a record of its server).
        if (said != null || app.phase != AppPhase.STARTING) app.sessionGone(CopyDeletion.ACCOUNT_DELETED, said) else app.settleOwnEndsNow()
        // Another account this device keeps at that server keeps the server known: as read when the deletion began, and as
        // it is now (one taken there since a stop is not forgotten with the server).
        val others = m.othersHeld || app.othersKnownAt(m.origin, m.userId, m.emailNorm) ||
            app.keeper.session?.let { it.origin == m.origin && it.userId != m.userId } == true
        if (others) app.dropDeletedAccountOnly(m.origin, m.emailNorm, m.userId, tied)
        else app.instancePart.forgetOrigin(m.origin, listOf(m.userId), if (tied) listOf(m.userId) else emptyList())
        // The mark of the take whose session ended (kept with its server): gone with the session, also where the server
        // stays known and a stop came before this process let go of it.
        app.keptMarkGone(m.origin, m.userId)
        setDeletionMarks(deletionMarks().filterNot { it.origin == m.origin && it.userId == m.userId })
        // Whatever the tie said: what is kept by the id of an account this device no longer knows anywhere goes.
        app.sweepAccounts()
    }

    /**
     * At a start, after the person's own ends are settled: each deletion begun and not finished (a stop cut it after its
     * mark) is finished by the deletion's own steps ([finish]). A record whose text is not the marks' form, or that holds
     * an entry that is not one, names no deletion this device can finish and would hold back every finish and every sweep
     * for good: it is written again first from the entries that read (none: no record), with a diagnostic line saying how
     * many were dropped. Nothing is removed for a dropped entry: a deletion not finished only keeps more. Nothing is
     * finished while the secure store holds a session record it cannot read now (it may be the account's, taken again);
     * the marks then stay and the sweep reads them as in flight. A record the store throws at is left as it is (the sweep
     * then removes nothing).
     */
    internal fun settleDeletions() {
        val text = try { app.engine.state.get(DELETION_KEY) } catch (e: Exception) { null } ?: return
        val all = deletionEntries(text)
        val marks = all.orEmpty().filterNotNull()
        if (all == null || all.any { it == null }) rewrite(marks, all)
        if (app.keeper.sessionRecordUnreadable()) return
        for (m in marks) finish(m, null)
    }

    /**
     * A take at [origin] of the account [userId] under the address [emailNorm] (as its address record is keyed), told by
     * the session keeper before the take writes anything of its own ([io.silencelen.andvari.core.client.session.SessionKeeper.beforeTake]):
     * every deletion begun at that server of that account, or of any account under that address, ends here, and nothing
     * of it is removed, then or later; the take uses what it would remove (the address's record, the identity record, the
     * server's pin, the records kept by the account's id). A deletion begun there of another account under another
     * address goes on, and so does one of the same account at another server. An entry that does not read is dropped, as
     * at a start. A record that cannot be read stops the take (the exception goes to the take's caller).
     */
    internal fun takeEndsDeletions(origin: String, emailNorm: String, userId: String) {
        val text = app.engine.state.get(DELETION_KEY) ?: return
        val all = deletionEntries(text)
        val marks = all.orEmpty().filterNotNull()
        val left = marks.filterNot { it.origin == origin && (it.userId == userId || it.emailNorm == emailNorm) }
        if (all == null || all.any { it == null }) rewrite(left, all) else if (left.size != marks.size) setDeletionMarks(left)
    }

    /** The record of deletions begun written again as [marks], from [all] as read (null: not the marks' form); said once. */
    private fun rewrite(marks: List<DeletionMark>, all: List<DeletionMark?>?) {
        setDeletionMarks(marks)
        val detail = if (all == null) "the record of deletions begun could not be read: written again with no entry"
            else "the record of deletions begun was written again without ${all.count { it == null }} of its ${all.size} entries, which could not be read"
        app.diagnostics.warn(io.silencelen.andvari.core.client.CoreLog.EVENT_DELETION_RECORD_REWRITTEN, detail)
    }

    private fun deletionMarks(): List<DeletionMark> =
        app.engine.state.get(DELETION_KEY)?.let { deletionEntries(it) }.orEmpty().filterNotNull()

    private fun setDeletionMarks(marks: List<DeletionMark>) {
        app.engine.state.set(DELETION_KEY, marks.takeIf { it.isNotEmpty() }?.let { m ->
            kotlinx.serialization.json.JsonArray(m.map { d ->
                kotlinx.serialization.json.JsonArray(listOf(d.origin, d.userId, d.emailNorm, TIE + yesNo(d.tied), OTHERS + yesNo(d.othersHeld), d.take)
                    .map { kotlinx.serialization.json.JsonPrimitive(it) })
            }).toString()
        })
    }

    // ---- "Forget this account on this device" after a deletion whose outcome is not known ----

    private var forgetShown: io.silencelen.andvari.core.app.ForgetUnknownDeletion? = null

    /** [io.silencelen.andvari.core.app.AppApi.forgetAfterUnknownDeletionCheck]. */
    fun forgetUnknownCheck(): io.silencelen.andvari.core.app.ForgetUnknownDeletion? {
        val kept = app.keeper.session
        if (app.phase == AppPhase.STARTING || kept == null || !deletionOutcomeUnknown(kept.origin, kept.userId)) {
            forgetShown = null
            return null
        }
        val email = app.accountEmail ?: kept.emailNorm
        val label = app.labelFor(kept.origin)
            ?: io.silencelen.andvari.core.app.InstanceLabel("", kept.origin, io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER, selfNamed = true)
        // Counted as a sign-out counts, with the account's signed changes to shared vaults not sent: the confirmation says
        // how many go, or that it cannot tell.
        val unsent = app.unsentForForgetting(kept.origin, kept.userId)
        val s = forgetShown
        if (s != null && s.origin == kept.origin && s.userId == kept.userId && s.email == email && app.sameLabel(s.instance, label) &&
            s.unsentChanges == unsent
        ) return s
        return io.silencelen.andvari.core.app.ForgetUnknownDeletion(email, label, kept.origin, kept.userId, unsent).also { forgetShown = it }
    }

    /**
     * The person confirmed [check]: the keeper removes exactly that account's session and keys and hands back the end of
     * that session at its server; the copy goes with the session; the account's identity record and the address's record
     * stay, as at a sign-out, and so does the pin (the account may still be there, and other accounts there are not this
     * act's). Where the deletion did not happen, the session must not
     * stay open at the server for a device that no longer holds it, so its end is sent.
     */
    fun forgetAfterUnknownDeletion(check: io.silencelen.andvari.core.app.ForgetUnknownDeletion): PlainResult {
        if (forgetUnknownCheck() !== check) return PlainResult.STALE
        val end = app.keeper.forgetAfterUnknownDeletion(check.origin, check.userId) ?: return PlainResult.STALE
        forgetShown = null
        setDeletionOutcomeUnknown(check.origin, check.userId, false)
        ended()
        // Synchronous from the keeper's removal on: the vault closes, then its copy is deleted, before anything else runs.
        app.sessionGone(CopyDeletion.FORGOT_SERVER, null)
        // Then, with the copy closed, its signed changes to shared vaults that were not sent go too, as the confirmation
        // said of every change not sent (kept, the next action on such a vault after a later sign-in would send them
        // unasked); the engine's other records of the account (what it verified of its vaults) stay, as at a sign-out.
        app.dropSignedUnsentLogChanges(check.userId)
        app.scope.launch { end() }
        return PlainResult.DONE
    }

    private fun result(r: Reauthed<*>): PasswordChangeResult = when (r) {
        is Reauthed.Done -> PasswordChangeResult.DONE
        Reauthed.WrongPassword -> PasswordChangeResult.WRONG_PASSWORD
        Reauthed.PasswordTooWeak -> PasswordChangeResult.WEAK_PASSWORD
        Reauthed.NoSession -> PasswordChangeResult.FAILED
        Reauthed.Unknown -> PasswordChangeResult.UNREACHABLE
        is Reauthed.Refused -> {
            app.noteRetryAfter(r.retryAfterSeconds)
            when (r.code) {
                WireErrors.RATE_LIMITED -> PasswordChangeResult.RATE_LIMITED
                WireErrors.UPGRADE_REQUIRED -> PasswordChangeResult.UPDATE_REQUIRED
                WireErrors.CREDENTIAL_CHANGED -> PasswordChangeResult.CHANGED_ELSEWHERE
                Reauthed.PROOF_REFUSED -> app.proofRefused(PasswordChangeResult.KEYS_NOT_KNOWN_HERE, PasswordChangeResult.PROOF_REFUSED)
                else -> PasswordChangeResult.FAILED
            }
        }
    }

    internal companion object {
        /** Device state: "the deletion's outcome is not known yet" for `origin|userId`. */
        const val OUTCOME_UNKNOWN_KEY = "ovh.delunknown|"

        /**
         * Device state: the deletions begun and not finished, a JSON list of `[origin, userId, address, "tie:yes"|"tie:no",
         * "others:yes"|"others:no", take]`: the account's server and id, its address there, whether something kept the
         * account elsewhere and whether the device kept another account at that server (both as read before anything was
         * removed), and the mark of the take whose session the deletion ended ([EngineAppApi.keptMark]). Written before the
         * deletion's first removal and removed after its last; a start finishes what one names ([settleDeletions]); a take at
         * its server of its account, or of any account under its address, removes it first ([takeEndsDeletions]). The sweep
         * reads each as the account's step in flight.
         */
        const val DELETION_KEY = "ovh.app.deleting"

        private const val TIE = "tie:"
        private const val OTHERS = "others:"

        private fun yesNo(b: Boolean) = if (b) "yes" else "no"

        /** A deletion begun ([DELETION_KEY]). */
        internal class DeletionMark(
            val origin: String, val userId: String, val emailNorm: String, val tied: Boolean, val othersHeld: Boolean, val take: String,
        )

        /**
         * The entries of [DELETION_KEY]'s [text]: null where the text is not a JSON list; an entry null where it is not one
         * of six strings in the form above with an account's id. An entry that does not read is never finished: a start
         * writes the record again without it ([settleDeletions]), and until then the sweep removes nothing.
         */
        internal fun deletionEntries(text: String): List<DeletionMark?>? {
            val all = runCatching { io.silencelen.andvari.core.model.wire.WireJson.json.parseToJsonElement(text) }.getOrNull() as? kotlinx.serialization.json.JsonArray
                ?: return null
            return all.map entry@{ e ->
                val f = (e as? kotlinx.serialization.json.JsonArray)?.map { (it as? kotlinx.serialization.json.JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: return@entry null }
                    ?: return@entry null
                if (f.size != 6 || f[0].isEmpty() || !io.silencelen.andvari.core.trust.TrustGrammar.isUuid(f[1])) return@entry null
                val tied = when (f[3]) { TIE + "yes" -> true; TIE + "no" -> false; else -> return@entry null }
                val others = when (f[4]) { OTHERS + "yes" -> true; OTHERS + "no" -> false; else -> return@entry null }
                DeletionMark(f[0], f[1], f[2], tied, others, f[5])
            }
        }

        /**
         * The account an [OUTCOME_UNKNOWN_KEY] record's [key] names, as (origin, user id); null for a key whose part after
         * the origin is not an account's id. The sweep reads none of these marks while one does not read, and a start
         * removes such a one ([dropOutcomeMarksNamingNoAccount]).
         */
        internal fun outcomeUnknownOf(key: String): Pair<String, String>? {
            val f = key.removePrefix(OUTCOME_UNKNOWN_KEY).split('|')
            val id = f.getOrNull(1)?.takeIf { io.silencelen.andvari.core.trust.TrustGrammar.isUuid(it) } ?: return null
            return f[0] to id
        }

        /** How many times a deletion is sent while the vaults' histories keep moving (`409 account_delete_log_stale`). */
        const val STALE_ROUNDS = 3

        /**
         * The personal vault's name in a plan, as the fake names it. GAP (§3.11): the design gives the personal vault no
         * name; a screen may show its own word for it.
         */
        const val PERSONAL = "Personal"
    }
}
