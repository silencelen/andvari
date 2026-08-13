package io.silencelen.andvari.core.client

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Audit F26 — the *durable* half of the fix. Promoting the enrollment rows into
 * [HouseholdCopy]'s code map stops today's divergence; this stops the next one: every
 * `BadRequest("…")` the server can throw while registering an account is asserted to have a
 * curated client sentence, off the REAL server source rather than a copy of it (the
 * BrowserAllowlistLockstepTest idiom).
 *
 * The failure this guards against is quiet and asymmetric. A new refusal code ships server-side,
 * every client falls through to the generic 400 — "The server couldn't accept that request — try
 * again, and update andvari if it keeps happening." — and a household member on their first-run
 * device retries forever against advice that is false in both halves. Nothing errors; the release
 * looks green. That is exactly how `escrow_required` reached production with no sentence on any
 * client while the sentence that fits it sat one switch-case away, keyed to a different condition.
 *
 * Two codes are deliberately NOT curated, and say so here rather than by silence:
 * [GENERIC_400_IS_HONEST]. Adding a code to that set is a conscious decision a reviewer sees;
 * adding one to neither set fails.
 */
class RegisterRefusalCoverageTest {

    /**
     * `bad_user_id` / `user_id_taken` are structural faults in what the CLIENT minted (a
     * malformed UUID; an astronomically improbable collision) — never anything the user did or
     * can act on. For those two the generic 400's "try again, and update andvari if it keeps
     * happening" is not filler, it is the accurate advice: a retry mints a fresh id, and a
     * malformed one means this build is broken.
     */
    private val GENERIC_400_IS_HONEST = setOf("bad_user_id", "user_id_taken")

    /** The generic 400 row — a code that still renders THIS is uncurated by definition. */
    private val generic400 = HouseholdCopy.forError(ApiException(400, "definitely_not_a_real_code", "raw"))

    /** Unit tests run with the MODULE dir as cwd; the repo-root fallback keeps the test honest
     *  if that changes, and a missing file FAILS rather than vacuously passing on an empty scan. */
    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("../$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    /**
     * The body of `fun register(` up to the next declaration at the same indentation. Scoped to
     * register on purpose: the whole Service throws hundreds of codes across surfaces that have
     * their own mappers, and enrollment is the surface whose refusals a stranger meets FIRST.
     */
    private fun registerBody(): String {
        val src = sourceFile("server/src/main/kotlin/io/silencelen/andvari/server/Service.kt").readText()
        val start = src.indexOf("fun register(")
        assertTrue(start > 0, "Service.register not found — did the function move or get renamed?")
        val after = src.indexOf("\n    // ---- login ----", start)
        assertTrue(after > start, "could not find the end of Service.register (the `// ---- login ----` marker moved)")
        return src.substring(start, after)
    }

    private val codeRe = Regex("""BadRequest\("([a-z_]+)"\)""")

    /**
     * The rows F26 established, asserted DIRECTLY rather than through the scan. The scan below
     * catches codes nobody has thought about yet; this catches the opposite failure — a scan that
     * has quietly gone blind (register's refusals live partly in helpers, and a helper moving out
     * of the scanned region would make an empty result look like success).
     */
    @Test
    fun theEstablishedEnrollmentRowsStayCurated() {
        val expected = listOf(
            "invalid_invite", "invite_used", "invite_expired", "invite_email_mismatch", "email_taken",
            "escrow_required", "escrow_not_configured", "escrow_not_allowed_when_waived",
            "escrow_fingerprint_mismatch", "recovery_required",
        )
        val lost = expected.filter { HouseholdCopy.forEnrollError(ApiException(400, it, "raw")) == generic400 }
        assertTrue(lost.isEmpty(), "these enrollment rows lost their curated sentence: $lost")
    }

    @Test
    fun everyRegisterRefusalHasACuratedClientSentence() {
        val codes = codeRe.findAll(registerBody()).map { it.groupValues[1] }.toSortedSet()
        // A scan that finds nothing is the vacuous pass this test exists to prevent.
        assertTrue(codes.size >= 8, "only found $codes inside Service.register — the scan pattern has gone stale")
        val uncurated = codes.filter { it !in GENERIC_400_IS_HONEST }
            .filter { HouseholdCopy.forEnrollError(ApiException(400, it, "raw")) == generic400 }
        if (uncurated.isNotEmpty()) {
            fail(
                "Service.register can refuse with $uncurated, and andvari would tell the user " +
                    "\"$generic400\" — which is false advice for an invite/posture refusal. Add a row to " +
                    "HouseholdCopy.apiCopy (and the web twin in Welcome.tsx's enrollError), or, if the " +
                    "generic 400 really is the honest answer, add the code to GENERIC_400_IS_HONEST with " +
                    "a reason.",
            )
        }
    }

    /**
     * The two halves of the F26 mis-keying, asserted as a pair: `escrow_required` is the posture
     * gate (invite wants the admin backstop, none was offered) and `recovery_required` is a
     * missing member-recovery block. They are different conditions and must never share a
     * sentence again — the whole defect was one sentence written for the first and keyed to the
     * second.
     */
    @Test
    fun escrowRequiredAndRecoveryRequiredAreDistinctSentences() {
        val escrow = HouseholdCopy.forEnrollError(ApiException(400, "escrow_required", "raw"))
        val recovery = HouseholdCopy.forEnrollError(ApiException(400, "recovery_required", "raw"))
        assertTrue(escrow != generic400 && recovery != generic400)
        assertTrue(escrow != recovery, "escrow_required and recovery_required must not share a sentence")
        assertEquals(true, escrow.contains("admin backstop"))
        assertEquals(false, recovery.contains("admin backstop"))
    }
}
