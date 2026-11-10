package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.UpgradeRequiredException
import kotlinx.coroutines.CancellationException
import kotlinx.io.IOException

/** §F.9: what committing a fresh recovery piece over the live account's UVK came to. */
sealed interface CaptureSetup {
    /**
     * Committed. Reveal [secret] once and zero it when the confirm resolves (§F.7: never persisted, never
     * logged). [pieceId] binds that confirm; null on a pre-binding server. Not a data class: no toString of the secret.
     */
    class Ready(val secret: ByteArray, val pieceId: String?) : CaptureSetup

    /** The session ended while this ran (a lock, a sign-out): the fresh secret was zeroed, and there is nothing to report. */
    data object SessionEnded : CaptureSetup

    /** A 426: the blocking update screen takes over (a Retry loop against a version-pinned server is a dead end). */
    data object UpgradeRequired : CaptureSetup

    /** Not committed, and the secret was zeroed. [offline]: the server could not be reached. */
    data class Failed(val offline: Boolean) : CaptureSetup
}

/** The piece-binding confirm's verdicts (design 2026-07-13 §3). */
enum class CaptureConfirm {
    /** The server recorded the capture. */
    Confirmed,

    /** `409 recovery_piece_stale`: another device's setup replaced the piece; the phrase just typed is dead. */
    Stale,

    /** Network or server trouble: proceed unconfirmed, and the gate re-fires at the next entry. */
    Failed,

    /** The session ended while the confirm ran; whatever ended it owns the cleanup. */
    SessionEnded,
}

/**
 * The §F.9 recovery capture (survey step 7): a member whose recovery piece was never captured gets a fresh one,
 * revealed once and typed back, before the vault opens. A new enrollee's register already committed its piece
 * and only confirms it ([confirmEnrolled]).
 */
class RecoveryCapture(private val session: VaultSession) {
    /**
     * Generate a FRESH per-member piece over [live]'s UVK and commit it (`PUT /recovery/self-setup`).
     * [currentAuthKey] is the fresh master-password reauth the server demands first. The commit does not
     * mark the piece captured: only the type-back confirm may. Bounded, so a caller holding its idle lock open
     * meanwhile holds it for a bounded time. A rotation invalidates any earlier, unconfirmed phrase.
     */
    suspend fun setup(live: VaultSession.Unlocked, currentAuthKey: String): CaptureSetup {
        return try {
            val setup = live.account.setupMemberRecovery(currentAuthKey)
            var committed = false
            val resp = try {
                runBounded(BoundedOps.RECOVERY_CALL_MS) { live.api.recoverySelfSetup(setup.request) }.also { committed = true }
            } finally {
                // §F.7: a failed commit must not leave the raw secret alive.
                if (!committed) setup.recoverySecret.fill(0)
            }
            // B1 identity gate: a lock or a sign-out mid-commit tore this session down, and the fresh phrase must not
            // leak into whatever session renders next.
            if (session.get()?.account !== live.account) {
                setup.recoverySecret.fill(0)
                CaptureSetup.SessionEnded
            } else {
                CaptureSetup.Ready(setup.recoverySecret, resp.pieceId)
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            when {
                t is UpgradeRequiredException -> CaptureSetup.UpgradeRequired
                session.get()?.account !== live.account -> CaptureSetup.SessionEnded // torn down mid-flight
                else -> CaptureSetup.Failed(offline = t is IOException)
            }
        }
    }

    /** The capture gate's BOUND and AWAITED confirm of [pieceId]: the vault must not open on a phrase the server no longer holds. */
    suspend fun confirm(live: VaultSession.Unlocked, pieceId: String?): CaptureConfirm {
        val outcome = try {
            runBounded(BoundedOps.RECOVERY_CALL_MS) { live.api.recoverySelfConfirm(pieceId) }
            CaptureConfirm.Confirmed
        } catch (e: ApiException) {
            if (isStale(e)) CaptureConfirm.Stale else CaptureConfirm.Failed
        } catch (c: CancellationException) {
            throw c
        } catch (_: Throwable) {
            CaptureConfirm.Failed
        }
        // B1 identity gate: decided first, acted on only while the same session is live.
        if (session.get()?.account !== live.account) return CaptureConfirm.SessionEnded
        return outcome
    }

    /**
     * The enroll path's confirm of the piece register committed (§F.9): it tells the server this enrollee saved
     * the phrase, so no vault-entry gate nudges the account again. Its caller does not wait on it to navigate.
     */
    suspend fun confirmEnrolled(api: AndvariApi, pieceId: String?): CaptureConfirm = try {
        api.recoverySelfConfirm(pieceId)
        CaptureConfirm.Confirmed
    } catch (e: ApiException) {
        if (isStale(e)) CaptureConfirm.Stale else CaptureConfirm.Failed
    } catch (c: CancellationException) {
        throw c
    } catch (_: Throwable) {
        CaptureConfirm.Failed
    }

    private fun isStale(e: ApiException) = e.status == 409 && e.code == "recovery_piece_stale"
}
