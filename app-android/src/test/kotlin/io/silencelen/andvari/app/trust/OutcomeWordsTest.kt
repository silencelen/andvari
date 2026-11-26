package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.ConnectResult
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.IntentResult
import io.silencelen.andvari.core.app.LinkDeviceEnd
import io.silencelen.andvari.core.app.MoveStage
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.Trouble
import io.silencelen.andvari.core.app.VaultActionResult
import io.silencelen.andvari.core.app.VaultLogState
import java.io.File
import java.util.zip.ZipFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * No internal name on a screen. Every result an intent of the shared code can answer, every trouble, and every state
 * and reason a screen shows has either words (the design's sentence, or the owner's approved words) or a placeholder
 * of its own whose gloss says what happened. The results are found in the shared code itself, so a new one fails here
 * until it has words.
 */
class OutcomeWordsTest {

    /** Every enum of the shared code's app interface that is an intent's result, read off its compiled classes. */
    private fun resultEnums(): List<Class<*>> {
        val where = File(IntentResult::class.java.protectionDomain.codeSource.location.toURI())
        val prefix = "io/silencelen/andvari/core/app/"
        val names = if (where.isDirectory) {
            where.walkTopDown().filter { it.isFile && it.name.endsWith(".class") }
                .map { it.relativeTo(where).invariantSeparatorsPath }.toList()
        } else {
            ZipFile(where).use { z -> z.entries().asSequence().map { it.name }.toList() }
        }
        return names.filter { it.startsWith(prefix) && it.endsWith(".class") && '$' !in it && "/fake/" !in it }
            .map { Class.forName(it.removeSuffix(".class").replace('/', '.'), false, IntentResult::class.java.classLoader) }
            .filter { it.isEnum && IntentResult::class.java.isAssignableFrom(it) }
            .sortedBy { it.name }
    }

    private val internalName = Regex("""\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b""")

    private fun assertNoInternalName(shown: String, vararg names: String) {
        assertTrue(internalName.find(shown) == null, "an internal name shows: $shown")
        names.filter { it.length > 2 }.forEach { n ->
            assertTrue(!Regex("""\b${Regex.escape(n)}\b""").containsMatchIn(shown), "the name $n shows: $shown")
        }
        assertTrue(shown.count { it == '⟦' } <= 1 && shown.count { it == '⟧' } <= 1, "a placeholder nested in another: $shown")
    }

    private fun assertOwnWords(text: UiText?, what: String, vararg names: String) {
        assertNotNull(text, "$what shows nothing")
        if (text is UiText.Ph) {
            assertTrue(text.placeholder != Placeholder.REFUSAL && text.placeholder != Placeholder.TROUBLE, "$what has no placeholder of its own: ${text.shown()}")
            assertTrue((text.ownGloss ?: text.placeholder.gloss).isNotBlank(), "$what: an empty gloss")
        }
        assertNoInternalName(text.shown(), *names)
    }

    @Test
    fun everyResultOfTheSharedCodeHasWordsOrAPlaceholderOfItsOwn() {
        val enums = resultEnums()
        // The walk finds the types (a broken walk would pass vacuously).
        assertTrue(enums.size >= 25, "found only ${enums.map { it.simpleName }}")
        assertTrue(VaultActionResult::class.java in enums && ConnectResult::class.java in enums)
        var withoutWords = 0
        enums.forEach { c ->
            c.enumConstants.forEach { e ->
                val r = e as IntentResult
                if (r.done) {
                    assertEquals(null, UiText.forResult(r, 30), "${c.simpleName}.$e is done and says nothing")
                    return@forEach
                }
                if (r.sentence == null && r != VaultActionResult.SENT_PENDING) withoutWords++
                assertOwnWords(UiText.forResult(r, 30), "${c.simpleName}.$e", c.simpleName, (e as Enum<*>).name)
            }
        }
        // How many results the design gives no sentence for: each now has its own placeholder (counted for the report).
        println("results without the design's words: $withoutWords")
        assertTrue(withoutWords > 0)
    }

    @Test
    fun theTableNamesOnlyResultsThatExistAndNeedIt() {
        OutcomeWords.refusals.keys.forEach { e ->
            val r = e as IntentResult
            assertTrue(!r.done && r.sentence == null && r.trouble == null, "${e.javaClass.simpleName}.$e needs no entry")
        }
        assertTrue(OutcomeWords.refusals.values.all { it.isNotBlank() && internalName.find(it) == null })
    }

    @Test
    fun everyTroubleStateAndReasonAScreenShowsHasItsOwnWords() {
        Trouble.entries.forEach { t ->
            val shown = OutcomeWords.trouble(t, 30)
            assertOwnWords(shown, "Trouble.$t", t.name)
        }
        assertTrue("30" in OutcomeWords.trouble(Trouble.RATE_LIMITED, 30).shown(), "the wait is said")
        LinkDeviceEnd.entries.forEach { assertOwnWords(OutcomeWords.linkDeviceEnd(it), "LinkDeviceEnd.$it", it.name) }
        VaultLogState.entries.filter { it != VaultLogState.VERIFIED }.forEach {
            assertOwnWords(OutcomeWords.vaultLogState(it), "VaultLogState.$it", it.name)
        }
        OperatorHelpStage.entries.forEach { assertOwnWords(operatorHelpStageLine(it), "OperatorHelpStage.$it", it.name) }
        MoveStage.entries.forEach { assertOwnWords(UiText.ph(moveStoppedAt(it)), "MoveStage.$it", it.name) }
        assertEquals(MoveStage.entries.size, MoveStage.entries.map { moveStoppedAt(it) }.toSet().size, "a sentence of its own per step")
        // Each step's sentence is a line of its own: no phrase written into the code fills another sentence's slot.
        assertTrue("moveStageGloss" !in File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultScreens.kt").readText())
        // No key of the shared code is reserved (a reserved key would show its name in its placeholder).
        assertEquals(emptyList(), CopyKey.entries.filter { it.reserved })
    }

    @Test
    fun aPlaceholderInsideAnotherIsShownFlat() {
        val inner = UiText.ph(Placeholder.VAULT_YOU).shown()
        val outer = UiText.ph(Placeholder.VAULT_OWNER, inner).shown()
        // Named by its keys, so it holds before and after their words: the inner line goes in once, without its own marks.
        assertTrue(UiText.unmarked(inner) in outer, outer)
        assertTrue(outer.count { it == '⟦' } <= 1 && outer.count { it == '⟧' } <= 1, outer)
        val nested = UiText.ph(Placeholder.CONNECTION_NOT_MADE, "Bo", UiText.forResult(ConnectResult.EXPIRED, 0)!!.shown()).shown()
        assertEquals(1, nested.count { it == '⟦' })
        assertTrue("Bo" in nested && "ConnectionNotMade" !in nested && "EXPIRED" !in nested, nested)
    }

    @Test
    fun noScreenPutsATypesNameIntoAPlaceholder() {
        val trust = listOf(File("src/main/kotlin/io/silencelen/andvari/app"), File("app-android/src/main/kotlin/io/silencelen/andvari/app"))
            .first { it.isDirectory }
        val sources = trust.walkTopDown().filter { it.isFile && it.extension == "kt" }.associate { it.name to it.readText() }
        sources.forEach { (name, text) ->
            assertTrue("Placeholder.VAULT_LOG_STATE" !in text, "$name: a log state by its name")
            assertTrue(!Regex("""Placeholder\.REFUSAL\s*,(?!\s*emptyList\(\))""").containsMatchIn(text), "$name: a refusal with a name in it")
            assertTrue(!Regex("""Placeholder\.TROUBLE\s*,(?!\s*emptyList\(\))""").containsMatchIn(text), "$name: a trouble with a name in it")
            assertTrue("javaClass.simpleName + \".\"" !in text, "$name: a type's name built for a screen")
        }
        assertTrue("stage.name" !in sources.getValue("RecoverySettingsScreens.kt"))
    }
}
