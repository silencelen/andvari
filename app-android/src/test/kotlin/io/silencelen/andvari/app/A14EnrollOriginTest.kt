package io.silencelen.andvari.app

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

    @Test
    fun theSignInSavesUnderItsOwnOriginOnlyWhileBound() {
        // A14 review N4: the sign-in saved `Session(store.baseUrl, …)` after its awaits (prelogin, two Argon2id passes,
        // login). It now captures the origin with the client, as enrollOp does, and aborts with a revoke if it moved.
        val op = body(vm, "fun signIn(email: String, password: String, totp: String? = null)", "syncNow(engine!!)")
        assertTrue(op.contains("val opOrigin = store.baseUrl"), "the origin is captured with the client")
        assertTrue(op.contains("val a = newApi(origin = opOrigin)"))
        assertTrue(op.contains("if (!enrollStillBound(opOrigin, null, store.baseUrl, store.pendingServer, probeFence.isCurrent(opTag, store.currentOriginKey())))"))
        assertTrue(op.contains("store.save(Session(opOrigin, s.userId, email, s.accessToken, s.refreshToken))"))
        assertFalse(op.contains("store.save(Session(store.baseUrl,"), "never the live origin")
        val abort = op.substring(op.indexOf("if (!enrollStillBound("), op.indexOf("store.save(Session(opOrigin"))
        assertTrue(abort.contains("a.logout()") && abort.contains("return@op") && abort.contains("signInOriginMoved(opOrigin)"),
            "an unbound commit revokes at the issuer, saves nothing and says so")
        assertTrue(signInOriginMoved("https://a.example").contains("https://a.example"))
    }

    @Test
    fun theEnrollSavesUnderItsOwnOriginOnlyWhileBound() {
        val op = body(vm, "private fun enrollOp(", "syncNow(engine!!)")
        assertTrue(op.contains("val opOrigin = store.baseUrl"), "the origin is captured with the client")
        assertTrue(op.contains("if (!enrollStillBound(opOrigin, opPending, store.baseUrl, store.pendingServer, probeFence.isCurrent(opTag, store.currentOriginKey())))"))
        assertTrue(op.contains("store.save(Session(opOrigin, s.userId, email, s.accessToken, s.refreshToken))"))
        val abort = op.substring(op.indexOf("if (!enrollStillBound("), op.indexOf("store.save(Session(opOrigin"))
        assertTrue(abort.contains("a.logout()") && abort.contains("return@op"), "an unbound commit revokes at the issuer and saves nothing")
    }

    @Test
    fun storedTokensNeverGoToAnotherOrigin() {
        assertTrue(Regex("""if \(!sessionBelongsTo\(session\.baseUrl, store\.baseUrl\)\)""").findAll(vm).count() >= 2, "password and biometric unlock both check")
        assertTrue(vm.contains("val a = newApi(session.tokens(), origin = session.baseUrl)"), "locked sign-out revokes at the session's own origin")
        assertTrue(autofill.contains("if (!sessionBelongsTo(session.baseUrl, baseUrl))"), "the autofill unlock checks too")
    }
}
