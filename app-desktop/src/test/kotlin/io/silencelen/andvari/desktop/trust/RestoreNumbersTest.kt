package io.silencelen.andvari.desktop.trust

import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What the restore button names is what the run stores (decided on 23 November 2026): the button, what the server was
 * asked to store by vault, the account's count before and after, the progress line's "of" and the end line, through the
 * real flow and the real shared restore, in each state of the record and for ticks on and off.
 */
internal class RestoreNumbersTest : RestoreTestKit() {
    private val holdsPrefix = "This account already holds "

    /**
     * 601 personal items; the first refused for good; the second batch refused whole, so the run stops. The same file
     * chosen again shows what is left (the preview's sync sends the batch the stopped run left queued); unticked,
     * nothing is sent for the vault.
     */
    @Test
    fun afterAStopWithARefusalTheButtonNamesWhatIsLeftAndAnUntickedVaultSendsNothing() {
        val w = world("numbers-check")
        val bytes = backup(601)
        val f = flow(w, bytes)
        open(f)
        w.server.rejectFirst = true
        w.server.beforePush = { n -> if (n == 2) w.server.failNext = 503 }
        runBlocking { f.confirm() }
        w.server.beforePush = null
        w.server.rejectFirst = false
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        println("NUMBERS|after the first run: account=${personalItems(w)} pushes=${w.server.pushes}")

        val again = flow(w, bytes)
        open(again)
        val p = assertNotNull(again.views.value.preview)
        val lines = page(w, again)
        println("NUMBERS|record at the preview: vaults=${p.vaults.map { "${it.name}:${it.items}:restoredAt=${it.restoredAt}" }} refused=${p.refused.map { it.name }} accountItems=${p.accountItems}")
        println("NUMBERS|account after the preview's sync=${personalItems(w)} lines=$lines")
        val held = personalItems(w)
        assertEquals(399, held, "the preview's sync sent the batch the stopped run left queued")
        assertFalse(lines.any { it.startsWith(holdsPrefix) }, "every item the account holds came from this file: $lines")
        assertEquals(202, buttonCount(lines), "the button names what is left: $lines")

        again.choose(personal.vaultId, false)
        val unticked = page(w, again)
        println("NUMBERS|unticked: $unticked")
        assertTrue(buttonCount(unticked).let { it == null || it == 0 }, "nothing is offered: $unticked")
        val pushes = w.server.pushes
        runBlocking { again.confirm() }
        assertEquals(held, personalItems(w), "nothing sent for a vault that is not ticked")
        assertEquals(pushes, w.server.pushes)

        again.choose(personal.vaultId, true)
        assertEquals(202, buttonCount(page(w, again)))
        runBlocking { again.confirm() }
        val end = page(w, again)
        println("NUMBERS|ticked and pressed: account=${personalItems(w)} end=$end")
        assertEquals(held + 202, personalItems(w), "the account holds as many more as the button named")
        has(end, "202 items restored into 1 vault.")
        assertEquals(601, personalItems(w))
        assertEquals(1, w.server.uploads.toSet().size)
    }

    /** A code the server chose is drawn through the cleaner, as every name the file brings is. */
    @Test
    fun aServersRefusalCodeIsDrawnSafely() {
        val w = world("numbers-code")
        val f = flow(w, backup(3))
        open(f)
        val hostile = "bad" + Char(0x202E) + "code" + "\n" + "next"
        w.server.failCode = hostile
        w.server.failNext = 503
        runBlocking { f.confirm() }
        assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage)
        val drawn = page(w, f)
        println("CODE|stop=${f.views.value.stop} drawn=${drawn.map { TerminalTextView.of(it) }}")
        assertTrue(drawn.none { Char(0x202E) in it || "\n" in it }, "nothing the server chose is drawn raw: $drawn")
    }
}

/** A line as it can be printed in a test's log: control characters and direction marks as their code points. */
internal object TerminalTextView {
    fun of(s: String): String = buildString {
        for (c in s) if (c.isISOControl() || c.code in 0x200B..0x200F || c.code in 0x202A..0x202E || c.code in 0x2066..0x2069) append("<U+%04X>".format(c.code)) else append(c)
    }
}
