package io.silencelen.andvari.app

import io.silencelen.andvari.core.client.session.*
import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10, branch A14 (F8, the Android twin of the desktop finding). An enroll at a
 * pending invite origin B saved its session as `Session(store.baseUrl, …)`, read AFTER register;
 * "Cancel and return to A" stayed enabled during the enroll and `cancelPendingSwitch` did not check
 * busy, so a cancel mid-register moved `store.baseUrl` to A and the session paired A with B's tokens
 * — the next unlock sent them to A. Reachable, so fixed the same way: the switch is frozen while an
 * op runs, the enroll commits only while its origin is unchanged (else it revokes at B and saves
 * nothing), and a stored session's tokens go only to its own origin. The ViewModel needs an
 * Application, so the decisions are pure functions here and the call sites are pinned.
 */
class A14EnrollOriginTest {
    private val pending = PendingServer(origin = "https://b.example", previousOrigin = "https://a.example", email = null, ts = 1)

    @Test
    fun anEnrollCommitsOnlyWhileItsOriginAndPendingSwitchAreUnchanged() {
        // the enroll's own marker update (the email) is not a change of origin
        assertTrue(enrollStillBound("https://b.example", pending, "https://b.example", pending.copy(email = "m@x.example"), fenceCurrent = true))
        assertTrue(enrollStillBound("https://a.example", null, "https://a.example", null, fenceCurrent = true), "a same-origin enroll")

        assertFalse(enrollStillBound("https://b.example", pending, "https://a.example", null, fenceCurrent = true), "cancelled back to A")
        assertFalse(
            enrollStillBound("https://b.example", pending, "https://c.example", pending.copy(origin = "https://c.example"), fenceCurrent = true),
            "re-pointed to another invite",
        )
        assertFalse(enrollStillBound("https://b.example", pending, "https://b.example", null, fenceCurrent = true), "the pending switch was dropped")
        assertFalse(enrollStillBound("https://a.example", null, "https://a.example", pending, fenceCurrent = true), "a switch began mid-enroll")
        assertFalse(enrollStillBound("https://b.example", pending, "https://b.example", pending, fenceCurrent = false), "A→B→… round trip: the generation moved")
    }

    @Test
    fun aStoredSessionsTokensGoOnlyToItsOwnOrigin() {
        assertTrue(sessionBelongsTo("https://A.example/", "https://a.example"), "the canonical form decides")
        assertTrue(sessionBelongsTo("https://a.example:443", "https://a.example"))
        assertFalse(sessionBelongsTo("https://b.example", "https://a.example"))
        assertFalse(sessionBelongsTo("http://a.example", "https://a.example"))
    }

    // ---- wiring ----

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")
    private val vm by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/AndvariViewModel.kt").readText() }
    private val activity by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/MainActivity.kt").readText() }
    private val autofill by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/autofill/AutofillUnlock.kt").readText() }

    private fun body(of: String, from: String, to: String): String {
        val a = of.indexOf(from)
        assertTrue(a > -1, "missing: $from")
        val b = of.indexOf(to, a)
        assertTrue(b > a, "missing end: $to")
        return of.substring(a, b)
    }

    @Test
    fun theSwitchIsFrozenWhileAnOpRuns() {
        for (fn in listOf("fun cancelPendingSwitch() {", "fun trustGateConnect() {", "fun requestInviteTrustGate(origin: String, email: String) {")) {
            assertTrue(body(vm, fn, "\n    }\n").contains("if (_ui.value.busy) return // A14 (F8)"), "$fn must refuse while busy")
        }
        val notice = body(activity, "private fun PendingSwitchNotice(", "\n}\n")
        assertTrue(notice.contains("enabled = !busy"), "the Cancel button is disabled while an op runs")
    }

    /** Step 7: sign-in and enroll are core's ([SessionEntry]); these pins moved there with the code. */
    private val entry by lazy { sourceFile("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/SessionEntry.kt").readText() }

    @Test
    fun theSignInSavesUnderItsOwnOriginOnlyWhileBound() {
        // A14 review N4: the sign-in saved `Session(store.baseUrl, …)` after its awaits (prelogin, two Argon2id passes,
        // login). It now captures the origin with the client, as the enroll does, and aborts with a revoke if it moved.
        val op = body(entry, "suspend fun signIn(", "firstSyncAfterBind {")
        assertTrue(op.contains("val opOrigin = store.baseUrl"), "the origin is captured with the client")
        assertTrue(op.contains("val client = clients.forNewSession(opOrigin)"))
        val save = "store.save(StoredSession(opOrigin, s.userId, email, s.accessToken, s.refreshToken))"
        assertTrue(op.contains("$save\n            saved = true\n            client.owner.userId = s.userId"), "the client writes tokens only into the session it committed")
        assertTrue(op.contains("if (!enrollStillBound(opOrigin, null, store.baseUrl.orEmpty(), store.pendingServer, coordinator.probeIsCurrent(opTag)))"))
        assertFalse(op.contains("store.save(StoredSession(store.baseUrl"), "never the live origin")
        val abort = op.substring(op.indexOf("if (!enrollStillBound("), op.indexOf(save))
        assertTrue(abort.contains("revoke(a)") && abort.contains("return SignInResult.OriginMoved(opOrigin)"),
            "an unbound commit revokes at the issuer, saves nothing and says so")
        assertTrue(body(entry, "private suspend fun revoke(", "\n    }\n").contains("withTimeoutOrNull(REVOKE_MS) { a.logout() }"), "a bounded logout at the issuer")
        assertTrue(body(vm, "fun signIn(email: String, password: String, totp: String? = null)", "\n    }\n").contains("is SignInResult.OriginMoved -> { _ui.value = _ui.value.copy(busy = false, error = signInOriginMoved(outcome.origin)); return@op }"))
        assertTrue(signInOriginMoved("https://a.example").contains("https://a.example"))
    }

    @Test
    fun theEnrollSavesUnderItsOwnOriginOnlyWhileBound() {
        val op = body(entry, "suspend fun enroll(", "firstSyncAfterBind {")
        assertTrue(op.contains("val opOrigin = store.baseUrl"), "the origin is captured with the client")
        assertTrue(op.contains("if (!enrollStillBound(opOrigin, opPending, store.baseUrl.orEmpty(), store.pendingServer, coordinator.probeIsCurrent(opTag)))"))
        val save = "store.save(StoredSession(opOrigin, s.userId, r.email, s.accessToken, s.refreshToken))"
        assertTrue(op.contains(save))
        val abort = op.substring(op.indexOf("if (!enrollStillBound("), op.indexOf(save))
        assertTrue(abort.contains("revoke(a)") && abort.contains("return EnrollOutcome.OriginMoved(opOrigin)"), "an unbound commit revokes at the issuer and saves nothing")
        assertTrue(body(vm, "private fun enrollOp(", "\n    }\n").contains("is EnrollOutcome.OriginMoved -> { _ui.value = _ui.value.copy(busy = false, error = enrollOriginMoved(outcome.origin)); return@op }"))
    }

    private val sessionStore by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/app/Session.kt").readText() }

    /** F8: the gate above is only as honest as the origin it is handed — the session has to own one. */
    @Test
    fun theStoredSessionOwnsItsOrigin() {
        val load = body(sessionStore, "override fun load(): Session?", "\n    }\n")
        assertTrue(load.contains("prefs.getString(SESSION_ORIGIN, null) ?: return null"), "a session is only ever handed out with its own origin")
        assertTrue(load.contains("baseUrl = origin"))
        assertFalse(load.contains("baseUrl = baseUrl"), "the global key is the origin the app dials, never the session's")
        val save = body(sessionStore, "override fun save(s: Session)", "\n    }\n")
        assertTrue(save.contains(".putString(SESSION_ORIGIN, s.baseUrl)"), "saved in one transaction with the tokens it belongs to")
        for (fn in listOf("override fun clear() {", "override fun clearSessionTokens() {")) {
            assertTrue(body(sessionStore, fn, "\n    }\n").contains(".remove(SESSION_ORIGIN)"), "$fn drops the origin with the tokens")
        }
    }

    /** A session saved before this build gets its origin once, after the default-URL rewrite. */
    @Test
    fun legacySessionsAreBackfilledAfterTheDefaultUrlMigration() {
        val init = body(sessionStore, "migrateDefaultOnce(context.noBackupFilesDir)", "runCatching { bindLegacySelfIdentity() }")
        assertTrue(init.indexOf("adoptNamespacesOnce(context.noBackupFilesDir)") < init.indexOf("backfillSessionOrigin()"))
        val backfill = body(sessionStore, "private fun backfillSessionOrigin() {", "\n    }\n")
        assertTrue(backfill.contains("sessionOriginForBackfill(baseUrl, pendingServer)"), "the pure rule decides")
        assertTrue(backfill.contains("clearSessionTokens()"), "and an unattributable session is dropped, not guessed")
    }

    /**
     * §4.1 rule 1, and the crash window F8 named: a dropped session is gone before the origin moves. The
     * move is core's now (ServerSwitch.moveTo; behaviour pinned by ServerSwitchTest), and every origin
     * change on this side goes through it.
     */
    @Test
    fun aRealSwitchDropsTheTokensBeforeTheOriginMoves() {
        val core = sourceFile("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/ServerSwitch.kt").readText()
        val move = body(core, "fun moveTo(newOrigin: String): Boolean {", "\n    }\n")
        val drop = move.indexOf("store.clearSessionTokens()")
        assertTrue(drop > -1 && move.indexOf("store.moveOrigin(newOrigin)") > drop, "tokens first, origin second")
        assertTrue(body(vm, "fun setBaseUrl(url: String) {", "\n    }\n").contains("serverSwitch.moveTo("), "the app moves its origin only through it")
        assertTrue(!vm.contains("store.baseUrl = "), "and never writes the origin itself")
    }

    @Test
    fun storedTokensNeverGoToAnotherOrigin() {
        // Step 6: the check lives in core's one ladder, once per rung (password and quick unlock), before anything is sent.
        val ladder = sourceFile("../core/src/commonMain/kotlin/io/silencelen/andvari/core/client/session/UnlockLadder.kt").readText()
        val check = "if (dialed == null || !sessionBelongsTo(stored.baseUrl, dialed)) return UnlockResult.Elsewhere(stored.baseUrl)"
        assertTrue(Regex(Regex.escape(check)).findAll(ladder).count() == 2, "password and biometric unlock both check")
        val quick = body(ladder, "suspend fun unlockWithQuick(", "\n    }\n")
        assertTrue(quick.indexOf(check) in 0 until quick.indexOf("quickKeys.recover("), "before the prompt, too")
        assertTrue(vm.contains("ladder.unlockWithPassword(session, password,") && vm.contains("ladder.unlockWithQuick(session, ActivityHost(activity)"), "the main app's unlocks climb it")
        assertTrue(vm.contains("is UnlockResult.Elsewhere -> ") && vm.contains("error = sessionElsewhere(climbed.sessionOrigin)"), "and say where the session belongs")
        assertTrue(vm.contains("val a = newApi(session.tokens(), origin = session.baseUrl)"), "locked sign-out revokes at the session's own origin")
        assertTrue(autofill.contains(".unlockWithPassword(session, password, overlay)") && autofill.contains(".unlockWithQuick(session, ActivityHost(activity)"), "the autofill unlock checks too")
        assertTrue(autofill.contains("is UnlockResult.Elsewhere -> throw IllegalStateException(sessionElsewhere(r.sessionOrigin))"))
    }
}
