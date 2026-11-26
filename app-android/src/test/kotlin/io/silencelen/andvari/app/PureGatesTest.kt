package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.session.*
import androidx.compose.ui.text.input.ImeAction
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.client.HouseholdCopy
import io.silencelen.andvari.core.client.KdfPolicyViolationException
import io.silencelen.andvari.core.client.UpgradeRequiredException
import io.silencelen.andvari.core.crypto.KdfParams
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The module's security-critical gates were all deliberately extracted as PURE functions ("so the
 * clock-safety logic is unit-testable without Android/Keystore", [QuickUnlockRules.FreshnessInputs]'s
 * own KDoc) — and then none of them were pinned. This is that missing suite: plain kotlin.test,
 * no Android framework, alongside the existing three under `testDebugUnitTest`.
 *
 * Deliberately NOT covered here: `importFormatLabel` and `effectiveSignupMode`, which are
 * cosmetic/degrade-safe (a wrong label, a conservative default) rather than gates.
 */
class PureGatesTest {

    // ---- A2 biometric freshness (QuickUnlockRules.isFreshPure) ----

    private val window = QuickUnlockRules.WINDOW_MS
    private val day = 24L * 60 * 60 * 1000

    /** A steady same-boot device: stamped [stampAgeMs] ago, wall and monotonic clocks agreeing. */
    private fun sameBoot(stampAgeMs: Long, nowMs: Long = 1_700_000_000_000L, serverFloorMs: Long = 0L) =
        QuickUnlockRules.FreshnessInputs(
            nowMs = nowMs,
            elapsedNowMs = 5 * day,
            stampWallMs = nowMs - stampAgeMs,
            stampElapsedMs = 5 * day - stampAgeMs,
            stampBootRefMs = nowMs - 5 * day,
            highWaterWallMs = nowMs,
            serverFloorMs = serverFloorMs,
        )

    @Test
    fun freshWithinTheWindowOnASteadySameBootDevice() {
        assertTrue(QuickUnlockRules.isFreshPure(sameBoot(stampAgeMs = day)))
        assertTrue(QuickUnlockRules.isFreshPure(sameBoot(stampAgeMs = window - 1)))
    }

    @Test
    fun staleAtAndPastTheWindow() {
        assertFalse(QuickUnlockRules.isFreshPure(sameBoot(stampAgeMs = window)))
        assertFalse(QuickUnlockRules.isFreshPure(sameBoot(stampAgeMs = window + day)))
    }

    @Test
    fun noStampIsNeverFresh() {
        // A1: never a real full-password unlock (or the stamp was cleared) → password.
        assertFalse(QuickUnlockRules.isFreshPure(sameBoot(stampAgeMs = day).copy(stampWallMs = 0L)))
        assertFalse(QuickUnlockRules.isFreshPure(sameBoot(stampAgeMs = day).copy(stampWallMs = -1L)))
    }

    @Test
    fun clockRollbackCanNeverReOpenTheWindow() {
        val stamp = 1_700_000_000_000L
        // Every SAME-BOOT signal says "one day since the stamp" — because the holder wound the
        // wall clock back 39 days and the monotonic clock only ever ran for one. The one thing
        // they can't rewind is the high-water mark this app already advanced to stamp+40d, and
        // that is what the window must be measured against.
        val rolled = QuickUnlockRules.FreshnessInputs(
            nowMs = stamp + day,
            elapsedNowMs = 10 * day,
            stampWallMs = stamp,
            stampElapsedMs = 9 * day,
            stampBootRefMs = stamp + day - 10 * day, // == nowMs − elapsedNowMs, i.e. same boot
            highWaterWallMs = stamp + 40 * day,
            serverFloorMs = 0L,
        )
        assertFalse(QuickUnlockRules.isFreshPure(rolled))
        // Sanity: with the high-water mark still at "now", the very same inputs ARE fresh — so the
        // assertion above is testing the ratchet, not some other guard.
        assertTrue(QuickUnlockRules.isFreshPure(rolled.copy(highWaterWallMs = stamp + day)))
        // …and a stamp in the FUTURE (the clock rolled back PAST it) fails closed too.
        assertFalse(QuickUnlockRules.isFreshPure(sameBoot(stampAgeMs = -day)))
    }

    @Test
    fun sameBootMonotonicRegressionDistrusts() {
        // Wall clock inside the window, but elapsedRealtime went BACKWARDS → distrust.
        val i = sameBoot(stampAgeMs = day).let { it.copy(stampElapsedMs = it.elapsedNowMs + 1) }
        assertFalse(QuickUnlockRules.isFreshPure(i))
    }

    @Test
    fun crossBootWithoutAServerAnchorFailsClosed() {
        // Review 2026-07-10 [2]: a reboot voids the monotonic cross-check, so with no
        // server-attested time taken AFTER the stamp the elapsed duration is unknowable.
        val now = 1_700_000_000_000L
        val crossBoot = QuickUnlockRules.FreshnessInputs(
            nowMs = now,
            elapsedNowMs = 60_000, // just booted
            stampWallMs = now - day,
            stampElapsedMs = 5 * day, // …from a previous boot
            stampBootRefMs = now - 5 * day,
            highWaterWallMs = now,
            serverFloorMs = 0L,
        )
        assertFalse(QuickUnlockRules.isFreshPure(crossBoot))
        // A floor that predates the stamp is not an anchor either.
        assertFalse(QuickUnlockRules.isFreshPure(crossBoot.copy(serverFloorMs = now - 2 * day)))
        // A floor taken AFTER the stamp and within the window IS the trustworthy evidence.
        assertTrue(QuickUnlockRules.isFreshPure(crossBoot.copy(serverFloorMs = now)))
        // A far-older stamp stays stale across the reboot even WITH an anchor.
        assertFalse(QuickUnlockRules.isFreshPure(crossBoot.copy(stampWallMs = now - 2 * window, serverFloorMs = now)))
    }

    @Test
    fun theServerFloorWinsOverAnAttackerSetClock() {
        // now/highWater rolled back inside the window, but the server saw a later time.
        val now = 1_700_000_000_000L
        val i = QuickUnlockRules.FreshnessInputs(
            nowMs = now,
            elapsedNowMs = 40 * day,
            stampWallMs = now - day,
            stampElapsedMs = 40 * day - day,
            stampBootRefMs = now - 40 * day,
            highWaterWallMs = now,
            serverFloorMs = now + window, // server-attested: far past the stamp's window
        )
        assertFalse(QuickUnlockRules.isFreshPure(i))
    }

    // ---- B1-1 hostile-server auto-lock clamp (the desktop OriginNamespaceTest twin) ----

    @Test
    fun autoLockClampsIntoTheClientWindow() {
        // Byte-parity with app-desktop's clampAutoLockSeconds pins: 0/negative (the old "never
        // lock") and anything over the ceiling clamp to the ceiling — a hostile server must not be
        // able to widen this device's exposure window, only narrow it.
        assertEquals(900, clampAutoLockSeconds(0))
        assertEquals(900, clampAutoLockSeconds(-5))
        assertEquals(900, clampAutoLockSeconds(86400))
        assertEquals(900, clampAutoLockSeconds(900))
        assertEquals(300, clampAutoLockSeconds(300))
        assertEquals(1, clampAutoLockSeconds(1))
    }

    // The §F.1 enroll submit gate (enrollReady) went with the old EnrollForm: the new path's
    // sign-up and its recovery choice are pinned by trust/AccountJourneyTest.

    // The old editor's card-expiry gate (cardExpiryBlocked / cardExpiryAssist) went with the old editor;
    // the new editor hands the expiry to the content, which checks it.

    // ---- ux-error--5: which biometric outcomes speak ----

    @Test
    fun aCancelIsSilentButASensorFailurePointsAtThePassword() {
        assertNull(QuickUnlock.fallbackReason(QuickUnlock.Auth.Cancelled))
        assertEquals(QuickUnlock.LOCKOUT_FALLBACK, QuickUnlock.fallbackReason(QuickUnlock.Auth.TempLockout))
        assertEquals(QuickUnlock.LOCKOUT_FALLBACK, QuickUnlock.fallbackReason(QuickUnlock.Auth.PermanentLockout))
        // The silent case that made a failed sensor look like an inert screen.
        assertEquals(QuickUnlock.DEVICE_FALLBACK, QuickUnlock.fallbackReason(QuickUnlock.Auth.Error(code = 1)))
        assertEquals(
            "Couldn't unlock with your device — unlock with your master password.",
            QuickUnlock.DEVICE_FALLBACK,
            "byte-twin of the extension's errors.ts sentence — edit both sides together",
        )
    }

    // ---- ux-parity--5: only the newest copy owns the clipboard auto-clear ----

    @Test
    fun onlyTheNewestCopyClearsTheClipboard() {
        // The first copy's timer must NOT wipe a window the second copy just disclosed, even
        // though the value it checks for is identical. (The rest of the rule: ClipboardClearTest.)
        assertEquals(ClipboardClear.Act.CLEAR, ClipboardClear.decide(2, 2, inFront = true, recordedTimestamp = 7, clipTimestamp = 7, valueStillThere = true))
        assertEquals(ClipboardClear.Act.KEEP, ClipboardClear.decide(1, 2, inFront = true, recordedTimestamp = 7, clipTimestamp = 7, valueStillThere = true))
        assertEquals(ClipboardClear.Act.KEEP, ClipboardClear.decide(1, 2, inFront = false, recordedTimestamp = 7, clipTimestamp = null, valueStillThere = null))
        // In front, something the person copied since is left alone.
        assertEquals(ClipboardClear.Act.KEEP, ClipboardClear.decide(2, 2, inFront = true, recordedTimestamp = 7, clipTimestamp = 9, valueStillThere = false))
    }

    // ---- a11yand-07: the IME action a field actually declares ----

    @Test
    fun multiLineFieldsDropTheImeActionAndOnDoneImpliesDone() {
        val noop = {}
        assertEquals(ImeAction.Done, imeActionFor(singleLine = true, imeAction = ImeAction.Default, onDone = noop))
        assertEquals(ImeAction.Next, imeActionFor(singleLine = true, imeAction = ImeAction.Next, onDone = noop))
        assertEquals(ImeAction.Default, imeActionFor(singleLine = true, imeAction = ImeAction.Default, onDone = null))
        // Enter must stay a newline in a multi-line field — the action is DROPPED, not just unused.
        assertEquals(ImeAction.Default, imeActionFor(singleLine = false, imeAction = ImeAction.Next, onDone = noop))
    }

    // ---- quality-deadcode--1: one session-teardown clear-set ----

    @Test
    fun sessionClearedDropsEverythingADeadSessionMustStopShowing() {
        val live = UiState(
            screen = Screen.Vault,
            needsUpdateCount = 3,
            notice = "hi",
            loginTotpRequired = true,
            totpMessage = "nope",
            escrowStale = true,
            escrowFingerprint = "abc",
            recoveryPhrase = "phrase",
            recoverVerified = true,
            undecryptableSharedVaultCount = 2,
            sharingSettingsVaultId = "v1",
        )
        val cleared = live.sessionCleared(reason = "Vault locked.")
        assertEquals(0, cleared.needsUpdateCount)
        assertNull(cleared.notice)
        assertFalse(cleared.loginTotpRequired)
        assertNull(cleared.totpMessage)
        assertFalse(cleared.escrowStale)
        assertEquals("", cleared.escrowFingerprint)
        assertNull(cleared.recoveryPhrase)
        assertFalse(cleared.recoverVerified)
        assertEquals(0, cleared.undecryptableSharedVaultCount)
        assertNull(cleared.sharingSettingsVaultId)
        assertEquals("Vault locked.", cleared.lockReason)
        // Screen is NOT part of the shared set — each caller decides where it lands.
        assertEquals(Screen.Vault, cleared.screen)
    }

    @Test
    fun sessionClearedDropsThePlaintextCachesSignOutUsedToKeep() {
        // The verified drift: signOut()'s hand-written copy() omitted these five, so an export
        // preflight and the DECRYPTED trash/version docs (passwords included) could survive it.
        val live = UiState(
            csvPreflight = null,
            deletedItems = emptyList(),
            itemVersions = emptyList(),
        )
        val cleared = live.sessionCleared(reason = null)
        assertNull(cleared.deletedItems)
        assertNull(cleared.itemVersions)
        assertNull(cleared.backupPreflight)
        assertNull(cleared.backupResult)
        assertNull(cleared.csvPreflight)
        assertNull(cleared.lockReason)
    }

    @Test
    fun aCurrentPolicyProbeFailureSurvivesTeardownButAStaleOneDoesNot() {
        // N2 §3/§6: with NO policy loaded the failure is CURRENT — Welcome must keep its Retry.
        assertTrue(UiState(policy = null, policyFetchFailed = true).sessionCleared(null).policyFetchFailed)
        assertFalse(UiState(policy = null, policyFetchFailed = false).sessionCleared(null).policyFetchFailed)
    }

    // ---- ux-error--1 import-push outcome (importPushRetryable / importPushError) ----

    /**
     * Every import PUSH failure used to collapse into ONE retryable sentence, so a 403, a
     * weakened-KDF block, or a version pin replayed the same doomed push forever under copy that
     * promised it would finish. Desktop's ImportPushOutcomeTest pins the twin pair; the 426 escape
     * (the catch-all ALSO swallowed UpgradeRequiredException, which drives the blocking upgrade
     * screen everywhere else) is control flow in importConfirm, contract-asserted below.
     */
    @Test
    fun transientImportFailuresKeepTheRetryPromise() {
        for (t in listOf(
            java.io.IOException("Connection reset by peer"),
            ApiException(429, "rate_limited", "slow down"),
            ApiException(500, "internal", "boom"),
            IllegalStateException("mid-chunk"), // idempotent replay converges — "no duplicates" holds
        )) {
            assertTrue(importPushRetryable(t), "$t should keep Retry")
            assertEquals(IMPORT_INTERRUPTED, importPushError(t))
        }
    }

    @Test
    fun terminalImportFailuresDropRetryAndNameTheRefusal() {
        val forbidden = ApiException(403, "forbidden", "forbidden")
        assertFalse(importPushRetryable(forbidden))
        assertEquals("You don't have permission to do that.", importPushError(forbidden))

        val weak = KdfPolicyViolationException("kdf_below_floor", KdfParams())
        assertFalse(importPushRetryable(weak))
        assertEquals(HouseholdCopy.WEAK_KDF_ACTION, importPushError(weak))

        for (t in listOf(
            ApiException(401, "unauthorized", "authentication failed"),
            ApiException(404, "not_found", "no such vault"),
            ApiException(409, "vault_state_changed", "rev mismatch"),
            ApiException(413, "too_large", "quota"),
        )) {
            assertFalse(importPushRetryable(t), "${t.status} replays as the same refusal")
            assertEquals(HouseholdCopy.forError(t), importPushError(t))
        }

        // The audited leak shape: a refusal's copy never carries the server's raw message.
        val leaked = importPushError(ApiException(400, "bad_request", "SQLITE_CONSTRAINT: mutations.id"))
        assertFalse(leaked.contains("SQLITE"), "raw wire text leaked: $leaked")
    }

    /** A version pin must never reach the classifier — importConfirm catches it first for the
     *  blocking upgrade screen (op()/backgroundSync parity). Pinned as terminal anyway, so a
     *  refactor that drops that catch cannot quietly land back on a Retry prompt. */
    @Test
    fun upgradeRequiredIsNeverRetryable() {
        val t = UpgradeRequiredException("upgrade_required", "min version 0.22.0")
        assertFalse(importPushRetryable(t))
        assertEquals(HouseholdCopy.UPGRADE_REQUIRED, importPushError(t))
    }

    // ---- H56: the last-resort crash report never carries an exception MESSAGE ----

    /**
     * The report is written to disk, survives to the next launch, is shown WITHOUT FLAG_SECURE
     * (crash traces are deliberately screenshot-able) and its copy tells the user to send it on.
     * So the one thing it must never contain is an exception message: those quote their input,
     * and on this client the input is decrypted vault material — the exact rule
     * `AutofillDebugLog.exceptionDetail` states for the fill log.
     */
    @Test
    fun theCrashReportCarriesClassNamesAndFramesButNeverAMessage() {
        val secret = "correct-horse-battery-staple"
        val t = IllegalStateException("JSON input: {\"password\":\"$secret\"}")
        val report = scrubbedTrace(t)
        assertFalse(report.contains(secret), "an exception message reached the crash report: $report")
        assertFalse(report.contains("JSON input"), "…messages are dropped whole, not filtered for known secrets")
        assertTrue(report.contains("java.lang.IllegalStateException"), "the CLASS is what a report is for")
        assertTrue(report.contains("theCrashReportCarriesClassNamesAndFramesButNeverAMessage"), "…with frames to place it")
    }

    /** Every level of the cause chain, which is where `printStackTrace` leaked most of them. */
    @Test
    fun everyCauseIsScrubbedToo() {
        val root = IllegalArgumentException("Illegal character in scheme at index 0: https://user:hunter2@example.com")
        val report = scrubbedTrace(RuntimeException("wrapper: hunter2", root))
        assertFalse(report.contains("hunter2"), "a nested message leaked: $report")
        assertTrue(report.contains("Caused by: java.lang.IllegalArgumentException"), "the chain still reads as a chain")
    }

    /** A self-referential cause (a Throwable whose cause was never set answers `this`) and a
     *  long chain must both terminate — this handler runs while the process is already dying. */
    @Test
    fun theCauseWalkAlwaysTerminates() {
        var t = RuntimeException("root")
        repeat(40) { t = RuntimeException("layer", t) }
        val report = scrubbedTrace(t)
        assertEquals(
            AndvariApplication.MAX_CAUSES,
            report.lines().count { it.startsWith("Caused by:") } + 1,
            "the cause chain is capped",
        )
        assertTrue(scrubbedTrace(Throwable()).isNotEmpty(), "a cause-less throwable still reports")
    }
}
