package io.silencelen.andvari.app.autofill

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Security review 2026-10 (root cause E): card values are planned for ONE frame — the frame of the
 * field the user is filling — so a third-party iframe that declares its own cc-number field beside
 * the merchant's form receives nothing. The rule itself is core's (CardFillTest); this pins the
 * Android wiring that feeds it, by source text (neither `AutofillId` nor `AssistStructure` can be
 * built in this module's JVM suite — the AutofillAuthBindingTest idiom). Each pin fails if the
 * focused frame stops reaching `CardFill.plan`.
 */
class CardFillFrameWiringTest {
    private fun code(name: String): String = File("src/main/kotlin/io/silencelen/andvari/app/autofill/$name").readText()
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lines().joinToString("\n") { it.substringBefore("//") }

    @Test
    fun theServiceTakesTheFocusedViewFromTheSystemFillContext() {
        val svc = code("AndvariAutofillService.kt")
        assertTrue(svc.contains("StructureParser.parse(structure, fillContext.focusedId)"), "the focused id is the FillContext's, not a structure flag")
    }

    @Test
    fun theFocusedViewSurvivesTheAuthenticationBinding() {
        // The locked path fills from the baked form; without the focused id there it would fill no card.
        val fb = code("FillBinding.kt")
        assertTrue(fb.contains("putParcelable(K_FOCUSED, it)"), "bake carries the focused id")
        assertTrue(fb.contains("b.autofillId(K_FOCUSED)"), "resolve reads it back")
    }

    @Test
    fun everyCardPlanIsScopedToTheFocusedFrame() {
        val db = code("DatasetBuilder.kt")
        val calls = Regex("CardFill\\.plan\\(([^)]*)\\)").findAll(db).map { it.groupValues[1] }.toList()
        assertTrue(calls.size >= 2, "both the dataset build and the headroom count plan cards")
        for (args in calls) assertTrue(args.endsWith("frame.domain"), "CardFill.plan($args) must pass the focused frame")
        assertTrue(Regex("val frame = form\\.cardFillFrame \\?: return\\b").findAll(db).count() >= 2, "unknown focus fails closed in both")
        assertFalse(db.contains("groupBy { it.frameDomain }"), "no frame clustering may be re-derived app-side")
    }
}
