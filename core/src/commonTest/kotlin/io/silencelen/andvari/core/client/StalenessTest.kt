package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.Staleness.SNOOZE_MS
import io.silencelen.andvari.core.client.Staleness.StaleBucket
import io.silencelen.andvari.core.client.Staleness.StalenessOptions
import io.silencelen.andvari.core.client.Staleness.isFailing
import io.silencelen.andvari.core.client.Staleness.planCheck
import io.silencelen.andvari.core.client.Staleness.planUnsnooze
import io.silencelen.andvari.core.client.Staleness.stalenessRows
import io.silencelen.andvari.core.client.Staleness.stalenessSummary
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Kotlin twin of `web/src/ui/staleness.test.ts`, ported assertion for assertion
 * (design 2026-08-23 §10). The ranking, the skew clamp, the open `result` vocabulary and the
 * composed verdict doc are all decided in [Staleness] — pinned here so the Android screen stays
 * a renderer/writer, exactly as the web tests keep Health.tsx one.
 */
class StalenessTest {
    private val NOW = 1_755_000_000_000L
    private val DAY = 86_400_000L

    /** `docOver` is LAST so the trailing-lambda call sites below bind to it, not to `vaultId`. */
    private fun login(
        itemId: String,
        updatedAt: Long = NOW,
        vaultId: String = "v1",
        docOver: (ItemDoc) -> ItemDoc = { it },
    ): VaultItem = VaultItem(
        itemId = itemId,
        vaultId = vaultId,
        rev = 1,
        updatedAt = updatedAt,
        doc = docOver(
            ItemDoc(
                type = "login",
                name = itemId,
                login = LoginData(
                    username = "u@example.com",
                    password = "hunter2",
                    uris = listOf("https://example.com/login"),
                ),
            ),
        ),
    )

    private val personal: (String) -> String? = { null }
    private val reader: (String) -> String? = { "reader" }

    private fun opts(now: Long = NOW, includeSnoozed: Boolean = false, lastUsedAt: ((String) -> Long?)? = null) =
        StalenessOptions(now = now, includeSnoozed = includeSnoozed, lastUsedAt = lastUsedAt)

    // ---- stalenessRows ----

    @Test
    fun onlyRanksLogins_notesAndCardsHaveNothingToVerify() {
        val items = listOf(
            login("a"),
            login("n") { it.copy(type = "note", name = "n", login = null) },
            login("c") { it.copy(type = "card", name = "c", login = null) },
        )
        assertEquals(listOf("a"), stalenessRows(items, opts()).map { it.itemId })
    }

    @Test
    fun ordersFailingFirst_thenNeverCheckedOldest_thenLongestSinceChecked() {
        val items = listOf(
            login("recent-check") { it.copy(check = ItemCheck(NOW - DAY, "ok")) },
            login("never-new", updatedAt = NOW - DAY),
            login("stale-check") { it.copy(check = ItemCheck(NOW - 400 * DAY, "ok")) },
            login("never-old", updatedAt = NOW - 900 * DAY),
            login("failed") { it.copy(check = ItemCheck(NOW - 10 * DAY, "bad")) },
        )
        assertEquals(
            listOf(
                "failed", // tier 1: actionable now
                "never-old", // tier 2: never checked, oldest change first
                "never-new",
                "stale-check", // tier 3: longest since a human confirmed it
                "recent-check",
            ),
            stalenessRows(items, opts()).map { it.itemId },
        )
    }

    @Test
    fun ordersMultipleFailuresMostRecentFirst() {
        val items = listOf(
            login("old-fail") { it.copy(check = ItemCheck(NOW - 100 * DAY, "gone")) },
            login("new-fail") { it.copy(check = ItemCheck(NOW - 2 * DAY, "bad")) },
        )
        assertEquals(listOf("new-fail", "old-fail"), stalenessRows(items, opts()).map { it.itemId })
    }

    @Test
    fun bucketsByAgeSinceTheLastCheck() {
        val rows = stalenessRows(
            listOf(
                login("never"),
                login("year") { it.copy(check = ItemCheck(NOW - 400 * DAY, "ok")) },
                login("half") { it.copy(check = ItemCheck(NOW - 200 * DAY, "ok")) },
                login("fresh") { it.copy(check = ItemCheck(NOW - 3 * DAY, "ok")) },
            ),
            opts(),
        )
        assertEquals(
            mapOf(
                "never" to StaleBucket.NEVER,
                "year" to StaleBucket.OVER_YEAR,
                "half" to StaleBucket.SIX_TO_TWELVE,
                "fresh" to StaleBucket.RECENT,
            ),
            rows.associate { it.itemId to it.bucket },
        )
    }

    /** spec 02 §3: the vocabulary is OPEN. A future client's verdict must degrade to "checked",
     *  never to a red row and never to a crash — the forward-compat guarantee. */
    @Test
    fun treatsAnUnrecognizedResultAsCheckedButUnknown_notFailing() {
        val rows = stalenessRows(listOf(login("x") { it.copy(check = ItemCheck(NOW - DAY, "quantum-verified")) }), opts())
        assertEquals(StaleBucket.RECENT, rows[0].bucket)
        assertEquals(false, isFailing("quantum-verified"))
        assertEquals(false, isFailing(null))
        assertEquals(true, isFailing("bad"))
    }

    /** spec 02 §1/§3: `at` is a CLIENT clock. In a shared vault it can come from another
     *  member's skewed — or hostile — device, and must never dominate the ordering. */
    @Test
    fun clampsAFutureCheckAt_insteadOfLettingItSortAboveRealEntries() {
        val rows = stalenessRows(
            listOf(login("future") { it.copy(check = ItemCheck(NOW + 999 * DAY, "ok")) }, login("never")),
            opts(),
        )
        assertEquals(NOW, rows.first { it.itemId == "future" }.checkedAt)
        // never-checked still outranks it
        assertEquals(listOf("never", "future"), rows.map { it.itemId })
    }

    @Test
    fun hidesSnoozedRowsByDefaultAndRevealsThemOnRequest() {
        val items = listOf(
            login("snoozed") { it.copy(check = ItemCheck(NOW - 5 * DAY, "blocked", until = NOW + 10 * DAY)) },
        )
        assertEquals(0, stalenessRows(items, opts()).size)
        val shown = stalenessRows(items, opts(includeSnoozed = true))
        assertEquals(true, shown[0].snoozed)
    }

    @Test
    fun letsAnExpiredSnoozeResurfaceOnItsOwn() {
        val items = listOf(
            login("was-snoozed") { it.copy(check = ItemCheck(NOW - 40 * DAY, "blocked", until = NOW - DAY)) },
        )
        val rows = stalenessRows(items, opts())
        assertEquals(1, rows.size)
        assertEquals(false, rows[0].snoozed)
    }

    @Test
    fun injectsLocalUsageWithoutKnowingWhereItCameFrom_andNeverInventsOne() {
        val rows = stalenessRows(
            listOf(login("used"), login("unused")),
            opts(lastUsedAt = { id -> if (id == "used") NOW - 2 * DAY else null }),
        )
        assertEquals(NOW - 2 * DAY, rows.first { it.itemId == "used" }.lastUsedAt)
        // null = "no local record", NOT "never used" — the caller must render "—".
        assertNull(rows.first { it.itemId == "unused" }.lastUsedAt)
    }

    @Test
    fun exposesOnlyANavigableWebUriAsTheOpenSiteTarget() {
        val rows = stalenessRows(
            listOf(login("app") { it.copy(login = LoginData("u", "p", listOf("androidapp://com.example"))) }),
            opts(),
        )
        assertNull(rows[0].firstUri)
    }

    @Test
    fun summarisesFromTheSameRowsTheTableShows() {
        val rows = stalenessRows(
            listOf(login("a"), login("b"), login("c") { it.copy(check = ItemCheck(NOW, "gone")) }),
            opts(),
        )
        assertEquals(Staleness.StalenessSummary(unchecked = 2, failing = 1), stalenessSummary(rows))
    }

    // ---- planCheck ----

    @Test
    fun composesOneWriteCarryingTheVerdict() {
        val items = listOf(login("a"))
        val plan = planCheck(items, "a", "ok", NOW, personal)
        assertNull(plan.refusal)
        assertEquals("a", plan.write?.itemId)
        assertEquals(items[0].doc.copy(check = ItemCheck(NOW, "ok", okAt = NOW)), plan.write?.doc)
    }

    /** spec 02 §3: okAt carries forward, so "last worked in March, failed in August" survives. */
    @Test
    fun carriesOkAtForwardAcrossALaterFailure() {
        val items = listOf(login("a") { it.copy(check = ItemCheck(NOW - 100 * DAY, "ok", okAt = NOW - 100 * DAY)) })
        assertEquals(
            ItemCheck(at = NOW, result = "bad", okAt = NOW - 100 * DAY),
            planCheck(items, "a", "bad", NOW, personal).write?.doc?.check,
        )
    }

    @Test
    fun omitsOkAtEntirelyWhenALoginHasNeverOnceWorked() {
        assertEquals(
            ItemCheck(at = NOW, result = "bad"),
            planCheck(listOf(login("a")), "a", "bad", NOW, personal).write?.doc?.check,
        )
    }

    @Test
    fun reStampsOkAtWhenAPreviouslyFailingLoginWorksAgain() {
        val items = listOf(login("a") { it.copy(check = ItemCheck(NOW - DAY, "bad", okAt = NOW - 50 * DAY)) })
        assertEquals(NOW, planCheck(items, "a", "ok", NOW, personal).write?.doc?.check?.okAt)
    }

    @Test
    fun recordsASnoozeHorizonWhenOneIsAskedFor() {
        val plan = planCheck(listOf(login("a")), "a", "blocked", NOW, personal, SNOOZE_MS)
        assertEquals(NOW + SNOOZE_MS, plan.write?.doc?.check?.until)
    }

    @Test
    fun preservesEveryOtherFieldOfTheDoc() {
        val items = listOf(login("a") { it.copy(notes = "keep me", favorite = true, dupeAck = "x|y") })
        val doc = planCheck(items, "a", "ok", NOW, personal).write!!.doc
        assertEquals("keep me", doc.notes)
        assertTrue(doc.favorite)
        assertEquals("x|y", doc.dupeAck)
        assertEquals(items[0].doc.login, doc.login)
    }

    /** The server enforces roles (spec 02 §4) — refuse HERE, with the reason, rather than
     *  letting the write fail as an error. The planDismiss refusal idiom. */
    @Test
    fun refusesToRecordIntoAVaultTheUserCanOnlyRead() {
        val plan = planCheck(listOf(login("a")), "a", "ok", NOW, reader)
        assertNull(plan.write)
        assertContains(plan.refusal!!, "only view")
    }

    @Test
    fun refusesAnItemThatVanishedUnderTheUser() {
        assertContains(planCheck(emptyList(), "ghost", "ok", NOW, personal).refusal!!, "changed under you")
    }

    @Test
    fun refusesANonLogin() {
        val note = login("n") { it.copy(type = "note", name = "n", login = null) }
        assertContains(planCheck(listOf(note), "n", "ok", NOW, personal).refusal!!, "Only logins")
    }

    // ---- planUnsnooze ----

    @Test
    fun dropsTheHorizonButKeepsTheVerdict() {
        val items = listOf(
            login("a") { it.copy(check = ItemCheck(NOW - DAY, "blocked", okAt = NOW - 9 * DAY, until = NOW + DAY)) },
        )
        assertEquals(
            ItemCheck(at = NOW - DAY, result = "blocked", okAt = NOW - 9 * DAY),
            planUnsnooze(items, "a", personal).write?.doc?.check,
        )
    }

    @Test
    fun writesNothingWhenThereIsNoSnoozeToClear() {
        val plan = planUnsnooze(listOf(login("a") { it.copy(check = ItemCheck(NOW, "ok")) }), "a", personal)
        assertNull(plan.write)
        assertNull(plan.refusal)
    }

    @Test
    fun refusesAReaderVault() {
        val items = listOf(login("a") { it.copy(check = ItemCheck(NOW, "blocked", until = NOW + DAY)) })
        assertContains(planUnsnooze(items, "a", reader).refusal!!, "only view")
    }
}
