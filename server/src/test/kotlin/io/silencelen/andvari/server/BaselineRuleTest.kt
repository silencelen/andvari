package io.silencelen.andvari.server

import java.io.File
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The rule for changing the baseline before the first release (spec 02 §5.1, the comment at [Db.SCHEMA]): a change
 * either changes the marker or is one the start-up step makes on an older database, never neither.
 */
class BaselineRuleTest {
    /**
     * The baseline's digest, pinned beside its marker. When this fails you changed `Db.SCHEMA`. Then, in the same
     * commit, either (1) change `Db.BASELINE`, add the old marker to `Db.EARLIER_BASELINES` and freeze the old schema
     * under `baseline-history/`, or (2) make sure the change is one `BaselineCatchUp` makes on an older database and add
     * its effect to `BaselineCatchUpTest`. Then update the pair below.
     */
    @Test
    fun theBaselineChangesOnlyByTheRule() {
        val digest = sha256Hex(Db.SCHEMA.joinToString("\n"))
        assertEquals(PINNED, Db.BASELINE to digest, "Db.SCHEMA changed: follow the rule of spec 02 §5.1, then update PINNED")
    }

    /** Every frozen older baseline carries the current marker (then it must start, BaselineCatchUpTest) or an earlier one. */
    @Test
    fun everyFrozenBaselineCarriesAMarkerThisBuildKnows() {
        val dir = File(javaClass.getResource("/baseline-history/onboarding-trust-1-before-decoy-requests.sql")!!.toURI()).parentFile
        val files = dir.listFiles { f -> f.name.endsWith(".sql") }!!.toList()
        assertTrue(files.isNotEmpty())
        for (f in files) {
            val marker = Regex("""VALUES\('baseline','([^']+)'\)""").find(f.readText())!!.groupValues[1]
            assertTrue(marker == Db.BASELINE || marker in Db.EARLIER_BASELINES, "${f.name} carries '$marker'")
        }
    }

    /** A database with an earlier marker is refused as older, with what to do; one with a marker nobody wrote, as another build's. */
    @Test
    fun anOtherMarker_isRefusedWithASentence() {
        fun withMarker(marker: String): String {
            val path = File(TestKit.tempDir(), "andvari.db").path
            DriverManager.getConnection("jdbc:sqlite:$path").use { c ->
                c.createStatement().use { st ->
                    st.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    st.execute("INSERT INTO meta VALUES('baseline','$marker')")
                }
            }
            return path
        }
        for (m in Db.EARLIER_BASELINES) {
            val e = assertFailsWith<IncompatibleDatabase> { Db(withMarker(m), durable = false) }
            assertEquals(Db.olderBuildMessage("baseline '$m', this build expects '${Db.BASELINE}'"), e.message)
        }
        val e = assertFailsWith<IncompatibleDatabase> { Db(withMarker("no-such-baseline"), durable = false) }
        assertTrue(e.message!!.startsWith("This database was created by a different andvari build"), e.message)
        assertTrue(Db.olderBuildMessage("x").contains("Start this build on a new, empty database file"))
    }

    private companion object {
        val PINNED = "onboarding-trust-1" to "f7642cec6950d4836e7d733fabfe28d03fd33aaf2b06c48dc33b269ab0cd2cb7"
    }
}
