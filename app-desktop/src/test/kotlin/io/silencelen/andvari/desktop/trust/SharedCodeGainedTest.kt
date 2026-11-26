package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.CopyKey
import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

/** What the shared code gained, on the desktop. */
class SharedCodeGainedTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"

    @Test
    fun theLockScreenSaysWhenADeletionsOutcomeIsStillUnknown() {
        val lock = File(dir + "AccountScreens.kt").readText().substringAfter("internal fun LockScreen(").substringBefore("\n}\n")
        assertTrue(lock.contains("locked.deletionOutcomeUnknown) Say(UiText.ph(Placeholder.DELETION_OUTCOME_UNKNOWN_LOCKED)"))
        assertTrue(Placeholder.DELETION_OUTCOME_UNKNOWN_LOCKED.gloss.contains("cannot tell yet"))
    }

    @Test
    fun thePeopleListSaysCoresBodyWhicheverItIs() {
        // Core picks the body (PEOPLE_BODY_OPERATOR_UNKNOWN when it could not read who can recover); the desktop says it.
        val view = File(dir + "PeopleScreens.kt").readText().substringAfter("private fun PeopleListView(").substringBefore("\n}\n")
        assertTrue(view.contains("Say(p.body)"))
        assertTrue(UiText.of(CopyKey.PEOPLE_BODY_OPERATOR_UNKNOWN).shown().isNotBlank())
    }
}
