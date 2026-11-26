package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Every string a file or a server chose reaches the restore's page clean, in one place: where the page is made, never on
 * the screen (decided on 23 November 2026). Hostile text goes into every source of such a string, and every string of
 * every page the restore's states draw is walked.
 */
internal class RestoreCleanStringsTest : RestoreTestKit() {
    /** A direction mark, a line break and a control character, each made from its number. */
    private val marks = listOf(0x202E, 0x000A, 0x0007).map { String(Character.toChars(it)) }
    private val evil = marks.joinToString("") { "x$it" }

    private fun hostile(lines: List<String>): List<String> = lines.filter { l -> marks.any { it in l } }

    private val walked = ArrayList<Pair<String, List<String>>>()

    /** The strings of [f]'s page: as the flow made them (every row's), and as the screen drew them. */
    private fun strings(w: World, f: RestoreFlow): List<String> = f.page().texts + page(w, f)

    private fun walk(label: String, lines: List<String>) {
        walked += label to lines
        println("CLEAN|$label|${lines.size} lines")
    }

    @Test
    fun noStringOfAnyPageHoldsTheHostileCharactersAFileOrAServerChose() {
        val w = world("clean")
        val shared = BackupVault(id(), "shared", "Shared $evil", "owner")
        val items = listOf(BackupItem(id(), personal.vaultId, 1, 0, doc("Item $evil"))) +
            (2..3).map { BackupItem(id(), personal.vaultId, 1, 0, doc("Item $it")) } +
            BackupItem(id(), shared.vaultId, 1, 0, doc("In shared"))
        val bytes = build(BackupPayload(exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org/$evil", vaults = listOf(personal, shared), items = items))
        // The file's name, the server's name in the file and the vaults' names: the passphrase step and the preview.
        val f = flow(w, bytes, "backup $evil.andvari")
        walk("passphrase", strings(w, f))
        open(f)
        walk("preview", strings(w, f))
        // An item's name, refused by the server: the end, and the next preview.
        w.server.rejectFirst = true
        runBlocking { f.confirm() }
        walk("end with a refused name", strings(w, f))
        w.server.rejectFirst = false
        val g = flow(w, bytes, "again $evil.andvari")
        open(g)
        walk("preview with a refused name", strings(w, g))
        // A shared vault's name at a stop (the test server does not confirm a new shared vault).
        g.choose(personal.vaultId, false)
        g.choose(shared.vaultId, true)
        runBlocking { g.confirm() }
        walk("stop over a shared vault (${g.views.value.stage})", strings(w, g))
        // A code the server chose, at a stop.
        val h = flow(w, backup(5, familyItems = 0), "codes $evil.andvari")
        open(h)
        w.server.failCode = "refused $evil"
        w.server.failNext = 503
        runBlocking { h.confirm() }
        w.server.failCode = "server_error"
        walk("stop with a server's code (${h.views.value.stage})", strings(w, h))
        // An attached file's name, at a part of the file that cannot be read.
        val key = crypto.randomBytes(32)
        val attachmentId = id()
        val plain = ByteArray(5_000) { (it % 251).toByte() }
        val owner = BackupItem(id(), personal.vaultId, 1, 0, doc("With a part", listOf(AttachmentRef(attachmentId, "part $evil.pdf", plain.size.toLong(), Bytes.toB64(crypto.randomBytes(32))))))
        val damaged = build(
            BackupPayload(
                exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal), items = listOf(owner),
                attachments = listOf(BackupAttachmentEntry(1, attachmentId, owner.itemId, "part $evil.pdf", plain.size.toLong(), Bytes.toB64(key))),
            ),
            listOf(key to plain),
        )
        damaged[damaged.size - 40] = (damaged[damaged.size - 40].toInt() xor 0x55).toByte()
        val d = flow(w, damaged, "part.andvari")
        open(d)
        runBlocking { d.confirm() }
        walk("stop at a part that cannot be read (${d.views.value.stop?.let { it::class.simpleName }})", strings(w, d))

        val raw = walked.flatMap { (label, lines) -> hostile(lines).map { "$label: ${it.map { c -> if (c.code < 32 || c.code == 0x202E) "\\u%04x".format(c.code) else c.toString() }.joinToString("")}" } }
        assertTrue(walked.all { it.second.isNotEmpty() })
        assertEquals(emptyList(), raw)
        // Each hostile source was drawn (made safe), so the walk saw it.
        val all = walked.flatMap { it.second }.joinToString("\n")
        for (seen in listOf("backup ", "vault.example.org", "Shared ", "Item ", "refused ", "part ")) assertTrue(seen in all, "\"$seen\" drawn")
    }

    @Test
    fun theScreenCleansNothing() {
        val code = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/RestoreScreens.kt").readText()
        assertFalse("safeName" in code || "ExportCopy" in code, "RestoreScreens.kt cleans a string itself")
    }
}
