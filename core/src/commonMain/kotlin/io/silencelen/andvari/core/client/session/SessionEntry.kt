package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.EnrollPayload
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.ClientPolicy
import io.silencelen.andvari.core.model.LoginRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** What a sign-in came to (spec 03 §3). */
sealed interface SignInResult {
    /**
     * §4.3 B2-6: an uncommitted invite switch points the client at an origin nobody has verified yet, and a
     * sign-in there would hand it an offline-crackable authKey. Nothing was derived or sent; the switch's
     * reconcile choice is the way on.
     */
    data class PendingSwitch(val pending: PendingServer) : SignInResult

    /** The account needs a one-time code. [codeWasWrong]: one was sent, and refused. Nothing was kept. */
    data class TotpRequired(val codeWasWrong: Boolean) : SignInResult

    /** A14 review N4: the client moved to another origin while this ran. The new session was ended at [origin], which issued it, and not saved. */
    data class OriginMoved(val origin: String) : SignInResult

    /**
     * Signed in, saved and bound; the first sync ran. [captureProof] is set when the account's recovery piece
     * was never confirmed (§F.9): it is the login authKey, the fresh-reauth proof the capture gate presents,
     * and it is password-equivalent. Not a data class, so the proof never reaches a toString.
     */
    class SignedIn(
        val unlocked: VaultSession.Unlocked,
        val keys: AccountKeys,
        val mustChangePassword: Boolean,
        val captureProof: String?,
        val firstSync: FirstSync,
    ) : SignInResult

    /** Bound, but the session ended during its first sync: there is nothing to land on. */
    data object EndedBeforeLanding : SignInResult

    /** Anything else (a wrong password, a refusal, a 426, the server unreachable). Nothing is saved or bound. */
    data class Failed(val cause: Throwable) : SignInResult
}

/**
 * What the enroll form submitted. The verdicts are derived from these raw inputs at enroll time, never taken
 * from the form (A5c).
 */
class EnrollRequest(
    val invite: String,
    val email: String,
    val name: String,
    val password: String,
    /** §F.1 posture: the invite waives org escrow, so there is no sheet to check and no escrow to seal. */
    val waived: Boolean,
    /** The recovery sheet's short form the person typed (the required-typed leg). */
    val typedShortFp: String,
    /**
     * CR-06: the policy the form's gate checked [typedShortFp] against. The escrow seal binds to this same
     * instance, so a policy that changed under the form cannot slip through. Null: fetch it.
     */
    val gatePolicy: ClientPolicy?,
    /** A5: the required-affirm leg, the link's FULL rfp. Null on the typed leg. */
    val affirmedRfp: String? = null,
    /** A5c: the in-person evidence, raw: the link, the code typed from it, the first-person affirmation, and where the invite came from. */
    val linkPayload: EnrollPayload? = null,
    val inPersonEntry: String = "",
    val inPersonAffirmed: Boolean = false,
    val inviteProvenance: InviteProvenance = InviteProvenance.Typed,
)

/** What an enroll came to. */
sealed interface EnrollOutcome {
    /** F60: the master password is below the floor, the one irreversible outcome of this form. Nothing was sent. */
    data object WeakPassword : EnrollOutcome

    /** CR-06 / TM-T10: the recovery-sheet anchor does not match the policy this enroll would seal to. Nothing was sent. */
    data object AnchorMismatch : EnrollOutcome

    /** A14 (F8): the client moved while register was in flight. The new session was ended at [origin] and not saved. */
    data class OriginMoved(val origin: String) : EnrollOutcome

    /**
     * Enrolled, saved and bound; the first sync ran. [recoverySecret] is the shown-once piece register committed
     * (§F.4/§F.7): reveal it, then zero it once the person has typed it back. [pieceId] binds that confirm.
     */
    class Enrolled(
        val unlocked: VaultSession.Unlocked,
        val keys: AccountKeys,
        val mustChangePassword: Boolean,
        val recoverySecret: ByteArray,
        val pieceId: String?,
        val firstSync: FirstSync,
    ) : EnrollOutcome

    /** Bound, but the session ended during its first sync. The recovery secret was zeroed, never shown. */
    data object EndedBeforeLanding : EnrollOutcome

    /** Anything else (a used invite, a refusal, a 426, the server unreachable). Nothing is saved or bound. */
    data class Failed(val cause: Throwable) : EnrollOutcome
}

/**
 * The two ways into a new session (survey step 7): sign-in, and enroll at the origin the client dials. The
 * invite-driven switch to another origin is not here; an enroll honours a pending switch that already
 * exists (its crash marker and its commit), and nothing more.
 *
 * Both capture the origin with the client, write no tokens until the session is committed ([TokenOwner]),
 * commit only while the client still dials that origin ([enrollStillBound]), and bind through [SessionBinder].
 */
class SessionEntry(
    private val store: SessionPersistence,
    private val session: VaultSession,
    private val coordinator: PolicyCoordinator,
    private val clients: SessionClients,
    private val binder: SessionBinder,
) {
    private class Committed(
        val unlocked: VaultSession.Unlocked,
        val keys: AccountKeys,
        val mustChangePassword: Boolean,
        val authKey: String,
        val secret: ByteArray?,
        val pieceId: String?,
    )

    /** Sign in at the origin the client dials. [firstSync] is the first sync after the bind (default: the engine's). */
    suspend fun signIn(email: String, password: String, totp: String? = null, firstSync: suspend (SyncEngine) -> Unit = { it.sync() }): SignInResult {
        // §4.3 B2-6 (sink guard, the authoritative backstop for the pending-state sign-in lockout): an uncommitted
        // pending marker means the client is OPTIMISTICALLY pointed at an unverified invite origin (enroll success is
        // what clears the marker). Deriving a master-password authKey against that origin is exactly the
        // offline-crack leak B2-6 exists to stop.
        store.pendingServer?.let { return SignInResult.PendingSwitch(it) }
        // A14 review N4: the origin and probe generation this sign-in's client is bound to, captured with the
        // client. login() answers whoever this client dialed; the session is saved under THAT origin, and only
        // while nothing moved the client away from it meanwhile.
        val opOrigin = store.baseUrl ?: return SignInResult.Failed(IllegalStateException("no server is chosen"))
        val opKey = OriginCanon.originKey(opOrigin)
        val opTag = coordinator.tag(opKey)
        val client = clients.forNewSession(opOrigin) // writes no tokens until the session below is committed
        val a = client.api
        var account: Account? = null
        // Survey gap 5: from the login's answer until the session is saved, a live server session exists that nothing
        // on this device holds. Every way out in between ends it at the issuer.
        var issued = false
        var saved = false
        val c = try {
            val pre = runBounded(BoundedOps.FLAT_MS) { a.prelogin(email) }
            // Argon2id (64 MiB, twice per sign-in) is CPU-bound: never on the caller's thread.
            val authKey = withContext(Dispatchers.Default) { Account.deriveAuthKey(password, pre.kdfSalt, pre.kdfParams) }
            val s = try {
                runBounded(BoundedOps.FLAT_MS) { a.login(LoginRequest(email, authKey, Account.deviceInfo(clients.deviceName, clients.wirePlatform), totp = totp)) }
                    .also { issued = true }
            } catch (e: ApiException) {
                if (e.code != "totp_required" && e.code != "bad_totp_code") throw e
                a.close()
                return SignInResult.TotpRequired(codeWasWrong = totp != null)
            }
            // A11 (q08): the §2.4 pin is found by the email the person TYPED, not only by the server's userId.
            val acct = withContext(Dispatchers.Default) {
                Account.unlock(s.userId, password, s.accountKeys, selfIdentityPub = store.origin(opKey).identityPins().pinFor(email, s.userId))
            }
            account = acct
            // A14 review N4, second layer: if the client was moved while login and the KDF ran, these tokens are
            // not for the origin it now dials. Do not commit: revoke them at the origin that issued them (this
            // client's own), drop them, and say so.
            if (!enrollStillBound(opOrigin, null, store.baseUrl.orEmpty(), store.pendingServer, coordinator.probeIsCurrent(opTag))) {
                revoke(a)
                a.close()
                acct.wipe()
                return SignInResult.OriginMoved(opOrigin)
            }
            store.origin(opKey).identityPins().record(s.userId, email, acct)
            store.save(StoredSession(opOrigin, s.userId, email, s.accessToken, s.refreshToken))
            saved = true
            client.owner.userId = s.userId // this client's later rotations are this session's
            binder.persistAccountKeys(opKey, s.userId, s.accountKeys)
            val unlocked = binder.bind(a, acct, opKey, VaultSession.UnlockProvenance.PASSWORD)
            // F58: a recovery TEMP password logs in with mustChangePassword=true. Persist it: only a login or
            // register response carries the flag.
            store.mustChangePassword = s.mustChangePassword
            // A1: a real full-password unlock stamps the window.
            binder.stampPasswordUnlock(opKey, s.userId)
            Committed(unlocked, s.accountKeys, s.mustChangePassword, authKey, secret = null, pieceId = null)
        } catch (t: Throwable) {
            // Gap 5: the login answered but the account did not open (or nothing was saved): end that session where it
            // was issued, so no live session is left behind. A saved one stays: an unlock can still reach it.
            if (issued && !saved) revoke(a)
            // F74: no throw path (prelogin, the KDF, login, the unlock, the bind) may leak the transient client.
            // Once bound, the session owns the client and the account.
            if (session.get()?.api !== a) a.close()
            account?.takeIf { session.get()?.account !== it }?.wipe()
            if (t is CancellationException) throw t
            return SignInResult.Failed(t)
        }
        // H10: the first sync has its own bound, and nothing it does keeps the person off the capture gate or the
        // vault (the gate decision must not be lost to a failed sync).
        val first = firstSyncAfterBind { firstSync(c.unlocked.engine) }
        if (!session.isLive(a)) return SignInResult.EndedBeforeLanding
        // §F.9: the server says this account's recovery piece was never durably CONFIRMED (an interrupted reveal,
        // or a migration account): the login authKey is the fresh-reauth proof the capture needs.
        val gate = c.keys.recoveryConfirmed != true
        return SignInResult.SignedIn(c.unlocked, c.keys, c.mustChangePassword, if (gate) c.authKey else null, first)
    }

    /** Enroll at the origin the client dials (honouring a pending invite switch that already exists). */
    suspend fun enroll(request: EnrollRequest, firstSync: suspend (SyncEngine) -> Unit = { it.sync() }): EnrollOutcome {
        val r = request
        if (!Strength.meetsMasterPasswordFloor(r.password)) return EnrollOutcome.WeakPassword
        // CR-06: the policy the form's gate validated the typed sheet against; the fallback fetch only fires when
        // the gate had none (the waived path still needs its kdfParams).
        val policy = try {
            r.gatePolicy ?: run {
                val probe = clients.probe(store.baseUrl ?: throw IllegalStateException("no server is chosen"))
                try { coordinator.boundedPolicy(probe) } finally { probe.close() }
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            return EnrollOutcome.Failed(t)
        }
        // Typed-sheet ceremony re-assert against the policy this enroll actually seals to (CR-06 / spec 04 §2(3),
        // the TM-T10 escrow-redirect defense): the escrow attestation MUST bind to the org being enrolled into.
        // waived seals NO org escrow, so there is no fingerprint to attest. A5: the required-affirm leg compares
        // the link's rfp at FULL length, and only on in-person evidence, which A5c RE-DERIVES here from the raw
        // inputs; the typed-sheet leg keeps the 32-hex human compare.
        val inPersonVerified = inPersonVerdict(createCryptoProvider(), r.linkPayload, r.inPersonEntry, r.inPersonAffirmed, r.inviteProvenance)
        val anchorOk = if (r.affirmedRfp != null) inPersonVerified && affirmRfpMatches(r.affirmedRfp, policy.recoveryFingerprint)
        else Escrow.shortFormMatches(r.typedShortFp, policy.recoveryFingerprint)
        if (!r.waived && !anchorOk) return EnrollOutcome.AnchorMismatch
        // A14 (F8): the origin, pending switch and probe generation this enroll's client is bound to. register()
        // answers whoever this client dialed; the session is saved under THAT origin, and only while nothing moved
        // the client away from it meanwhile.
        val opOrigin = store.baseUrl ?: return EnrollOutcome.Failed(IllegalStateException("no server is chosen"))
        val opKey = OriginCanon.originKey(opOrigin)
        val opPending = store.pendingServer
        val opTag = coordinator.tag(opKey)
        val client = clients.forNewSession(opOrigin) // writes no tokens until the session below is committed
        val a = client.api
        var account: Account? = null
        var secret: ByteArray? = null
        var issued = false // gap 5, as in sign-in: register answered, nothing saved yet
        var saved = false
        val c = try {
            // §F.1 posture: `waived` seals NO org escrow (the key is not even fetched); `required` keeps the
            // verified-fingerprint ceremony, and Account.enroll refuses a served key whose fingerprint differs.
            val recoveryPub = if (r.waived) null else Bytes.fromB64(runBounded(BoundedOps.FLAT_MS) { a.recoveryPubkey() })
            // Key generation and the KDF are CPU-bound (argon2id): off the caller's thread. The third part is the
            // SHOWN-ONCE recovery piece (§F.4).
            val enrolled = withContext(Dispatchers.Default) {
                Account.enroll(
                    inviteToken = r.invite, email = r.email, displayName = r.name.ifBlank { r.email.substringBefore('@') },
                    password = r.password, params = policy.kdfParams,
                    recoveryPublicKey = recoveryPub,
                    // The human-anchored value: the in-person link's full rfp, or the advertised fingerprint the
                    // typed 32 hex matched (A4 binding, A5 anchor).
                    recoveryFingerprint = if (r.waived) null else (r.affirmedRfp ?: policy.recoveryFingerprint),
                    deviceName = clients.deviceName,
                    platform = clients.wirePlatform,
                )
            }
            account = enrolled.account
            secret = enrolled.recoverySecret
            // §4.3 B2-9 crash marker: on a PENDING invite switch, record the enrolling email in the marker BEFORE
            // register, so a crash between register and the commit below is reconciled at next launch with the
            // address to sign in as. No marker on a same-origin enroll.
            store.pendingServer?.let { store.pendingServer = it.copy(email = r.email) }
            val s = runBounded(BoundedOps.FLAT_MS) { a.register(enrolled.request) }.also { issued = true }
            // A14 (F8), second layer: if the client was moved anyway, this account is not the one it now points at.
            // Do not commit: revoke the tokens at the origin that issued them (this client's own), drop them, and
            // say so.
            if (!enrollStillBound(opOrigin, opPending, store.baseUrl.orEmpty(), store.pendingServer, coordinator.probeIsCurrent(opTag))) {
                revoke(a)
                a.close()
                enrolled.recoverySecret.fill(0)
                enrolled.account.wipe()
                return EnrollOutcome.OriginMoved(opOrigin)
            }
            store.save(StoredSession(opOrigin, s.userId, r.email, s.accessToken, s.refreshToken))
            saved = true
            client.owner.userId = s.userId // this client's later rotations are this session's
            binder.persistAccountKeys(opKey, s.userId, s.accountKeys)
            store.origin(opKey).identityPins().record(s.userId, r.email, enrolled.account)
            val unlocked = binder.bind(a, enrolled.account, opKey, VaultSession.UnlockProvenance.PASSWORD)
            // §4.1 rule 3 (B2-6): enrollment SUCCEEDED, so COMMIT a pending invite switch: clearing the marker is the
            // commit (the client already dials this origin). A same-origin enroll has no marker.
            if (store.pendingServer != null) store.pendingServer = null
            // F58: symmetric with sign-in; the register response carries the flag too.
            store.mustChangePassword = s.mustChangePassword
            // A1: a fresh enrollment typed the master password; it is already on the policy's KDF params.
            binder.stampPasswordUnlock(opKey, s.userId)
            Committed(unlocked, s.accountKeys, s.mustChangePassword, authKey = "", secret = enrolled.recoverySecret, pieceId = s.recoveryPieceId)
        } catch (t: Throwable) {
            if (issued && !saved) revoke(a) // gap 5
            // F74: same rule as sign-in; and a piece that was never revealed is zeroed.
            if (session.get()?.api !== a) a.close()
            account?.takeIf { session.get()?.account !== it }?.wipe()
            secret?.fill(0)
            if (t is CancellationException) throw t
            return EnrollOutcome.Failed(t)
        }
        // H10: the first sync has its own bound, and whatever it does the shown-once phrase is revealed next: a
        // failed sync must never strand a committed recovery secret, unshown and unzeroed.
        val first = firstSyncAfterBind { firstSync(c.unlocked.engine) }
        val committedSecret = c.secret!!
        if (!session.isLive(a)) {
            committedSecret.fill(0) // the phrase belongs to a session that no longer exists; it is never shown
            return EnrollOutcome.EndedBeforeLanding
        }
        return EnrollOutcome.Enrolled(c.unlocked, c.keys, c.mustChangePassword, committedSecret, c.pieceId, first)
    }

    /**
     * End the session [a] holds at the origin that issued it: bounded, best effort, and run to the end even when the
     * caller was cancelled (the revocation is the cleanup). The client's token callback writes nothing: its session was
     * never committed.
     */
    private suspend fun revoke(a: io.silencelen.andvari.core.client.AndvariApi) {
        runCatching { withContext(NonCancellable) { withTimeoutOrNull(REVOKE_MS) { a.logout() } } }
    }

    private companion object {
        /** How long an abandoned session's logout may take before it is dropped anyway. */
        const val REVOKE_MS = 5_000L
    }
}
