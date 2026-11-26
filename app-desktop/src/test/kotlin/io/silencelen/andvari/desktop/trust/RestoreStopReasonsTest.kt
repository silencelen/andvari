package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.ExportCopy
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.BackupAttachmentEntry
import io.silencelen.andvari.core.client.BackupItem
import io.silencelen.andvari.core.client.BackupPayload
import io.silencelen.andvari.core.client.BackupVault
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.restore.RestoreStop
import io.silencelen.andvari.core.crypto.Bytes
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Why a restore stopped, as the person reads it (decided on 23 November 2026): a phrase for each kind of stop, then,
 * where the stop carries one, what the program saw (the server's code, made safe; that the server did not answer; the
 * kind of failure), so that a server that did not answer is told from one that refused. A stop the same file reaches
 * every time says so and offers no Try again. Through the real flow over the kit's server where it makes the stop;
 * otherwise on the page made from a stopped state that holds it.
 */
internal class RestoreStopReasonsTest : RestoreTestKit() {
    /** Characters a file or a server may choose and a person must never get raw. */
    private val marks = listOf(0x202E, 0x000A, 0x0007).map { String(Character.toChars(it)) }
    private val evil = marks.joinToString("") { "x$it" }

    private fun clean(s: String) = ExportCopy.safeName(s)

    private fun reason(phrase: Placeholder, vararg name: String, seen: String? = null) = ph(phrase, *name) + (seen?.let { ": $it" } ?: "")

    private fun stopped(reason: String) = ph(Placeholder.RESTORE_STOPPED, reason)

    private fun samePlace(reason: String) = ph(Placeholder.RESTORE_STOPPED_SAME_PLACE, reason)

    private fun noneRaw(lines: List<String>) = assertTrue(lines.none { l -> marks.any { it in l } }, "nothing drawn raw: $lines")

    private fun stoppedAt(f: RestoreFlow) = assertEquals(RestoreFlow.Stage.STOPPED, f.views.value.stage, "${f.views.value.stop}")

    // ---- through the real flow ----

    @Test
    fun aNewSharedVaultNotConfirmedSaysSoWithItsNameMadeSafeAndOffersTryAgain() {
        val w = world("stop-not-confirmed")
        val hostile = BackupVault(id(), "shared", "Fam$evil", "owner")
        val bytes = build(
            BackupPayload(
                exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal, hostile),
                items = listOf(BackupItem(id(), personal.vaultId, 1, 0, doc("P")), BackupItem(id(), hostile.vaultId, 1, 0, doc("H"))),
            ),
        )
        val f = flow(w, bytes)
        open(f)
        f.choose(personal.vaultId, false)
        f.choose(hostile.vaultId, true)
        runBlocking { f.confirm() }
        stoppedAt(f)
        assertIs<RestoreStop.VaultNotConfirmed>(f.views.value.stop)
        val lines = page(w, f)
        has(lines, stopped(reason(Placeholder.RESTORE_STOP_VAULT_NOT_CONFIRMED, clean(hostile.name))), "Try again")
        noneRaw(lines)
    }

    @Test
    fun aBatchTheServerRefusedSaysSoFollowedByTheServersCodeMadeSafe() {
        val w = world("stop-batch")
        val f = flow(w, backup(3, familyItems = 0))
        open(f)
        w.server.failCode = "refused$evil"
        w.server.failNext = 503
        runBlocking { f.confirm() }
        w.server.failCode = "server_error"
        stoppedAt(f)
        val lines = page(w, f)
        has(lines, stopped(reason(Placeholder.RESTORE_STOP_BATCH, seen = clean("refused$evil"))), "Try again")
        noneRaw(lines)
        // A plain code is drawn as it is.
        val g = flow(w, backup(3, familyItems = 0))
        open(g)
        w.server.failNext = 503
        runBlocking { g.confirm() }
        has(page(w, g), stopped(reason(Placeholder.RESTORE_STOP_BATCH, seen = "server_error")))
    }

    @Test
    fun aSharedVaultTheServerWouldNotMakeSaysSoFollowedByItsCode() {
        val w = world("stop-not-made")
        val f = flow(w, backup(1, familyItems = 2))
        open(f)
        f.choose(personal.vaultId, false)
        f.choose(family.vaultId, true)
        // Asked to wait with no time named, over and over: the restore gives up on the vault.
        w.server.vaultCreationWait = 0
        runBlocking { f.confirm() }
        w.server.vaultCreationWait = null
        stoppedAt(f)
        assertIs<RestoreStop.VaultNotCreated>(f.views.value.stop)
        has(page(w, f), stopped(reason(Placeholder.RESTORE_STOP_VAULT_NOT_MADE, "Family", seen = "rate_limited")), "Try again")
    }

    @Test
    fun theCheckOfTheAccountsLimitsThatDidNotFinishSaysSoFollowedByTheServersCode() {
        val w = world("stop-room-check")
        val f = flow(w, backup(3, familyItems = 0))
        open(f)
        w.server.refuseAll = 503 to "busy$evil"
        runBlocking { f.confirm() }
        w.server.refuseAll = null
        stoppedAt(f)
        assertIs<RestoreStop.RoomCheckFailed>(f.views.value.stop)
        val lines = page(w, f)
        has(lines, stopped(reason(Placeholder.RESTORE_STOP_ROOM_CHECK, seen = clean("busy$evil"))), "Try again")
        noneRaw(lines)
    }

    @Test
    fun anAttachedFileNotTheSizeTheBackupNamesStopsAtTheSamePlaceEveryTimeAndOffersNoTryAgain() {
        val w = world("stop-file-size")
        val key = crypto.randomBytes(32)
        val aid = id()
        val name = "scan$evil.pdf"
        val owner = BackupItem(id(), personal.vaultId, 1, 0, doc("With a file", listOf(AttachmentRef(aid, name, 10, Bytes.toB64(key)))))
        val bytes = build(
            BackupPayload(
                exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal), items = listOf(owner),
                attachments = listOf(BackupAttachmentEntry(1, aid, owner.itemId, name, 10, Bytes.toB64(key))),
            ),
            listOf(key to ByteArray(20) { 4 }),
        )
        val f = flow(w, bytes)
        open(f)
        runBlocking { f.confirm() }
        stoppedAt(f)
        assertIs<RestoreStop.AttachmentWrongSize>(f.views.value.stop)
        val lines = page(w, f)
        has(lines, samePlace(reason(Placeholder.RESTORE_STOP_FILE_SIZE, clean(name))))
        assertFalse("Try again" in lines, "$lines")
        assertTrue(lines.none { it.startsWith("The restore stopped") && it == stopped(reason(Placeholder.RESTORE_STOP_FILE_SIZE, clean(name))) })
        noneRaw(lines)
        // Asked anyway, nothing runs.
        val pushes = w.server.pushes
        runBlocking { f.tryAgain() }
        assertEquals(pushes, w.server.pushes)
        stoppedAt(f)
    }

    @Test
    fun anItemThatDoesNotReadAsAnItemStopsAtTheSamePlaceEveryTimeAndOffersNoTryAgain() {
        val w = world("stop-item")
        // An attached file's reference whose id no andvari app writes: the item does not read as an item.
        val odd = BackupItem(id(), personal.vaultId, 1, 0, doc("Odd", listOf(AttachmentRef("not an id!", "x.pdf", 10, Bytes.toB64(crypto.randomBytes(32))))))
        val bytes = build(BackupPayload(exportedAt = 1_794_484_800_000L, origin = "https://vault.example.org", vaults = listOf(personal), items = listOf(odd)))
        val f = flow(w, bytes)
        open(f)
        val pushes = w.server.pushes
        runBlocking { f.confirm() }
        stoppedAt(f)
        assertEquals(RestoreStop.ItemUnreadable, f.views.value.stop)
        val lines = page(w, f)
        has(lines, samePlace(reason(Placeholder.RESTORE_STOP_ITEM_UNREADABLE)))
        assertFalse("Try again" in lines, "$lines")
        assertEquals(pushes, w.server.pushes, "nothing was sent")
    }

    // ---- the stops the kit's server does not make: the page made from a stopped state ----

    private fun drawnAt(f: RestoreFlow, stop: RestoreStop): List<String> = f.page(RestoreFlow.View(RestoreFlow.Stage.STOPPED, stop = stop)).texts

    @Test
    fun eachOtherStopHasItsPhraseWithANameMadeSafeAndWhatWasSeenAfterIt() {
        val w = world("stop-others")
        val f = flow(w, backup(1))
        val name = "n$evil"
        val code = "c$evil"
        val noAnswer = ph(Placeholder.RESTORE_SEEN_NO_ANSWER)
        val unreachable = ItemFailure.Unreachable(NoAnswerKind.TIMEOUT)
        val refused = ItemFailure.Refused(code, 403)
        // Each stop, the line it draws, and whether Try again is offered.
        val cases = listOf(
            Triple(RestoreStop.NoPersonalVault, stopped(reason(Placeholder.RESTORE_STOP_NO_PERSONAL_VAULT)), true),
            Triple(RestoreStop.RoomCheckFailed(unreachable), stopped(reason(Placeholder.RESTORE_STOP_ROOM_CHECK, seen = noAnswer)), true),
            Triple(RestoreStop.RoomCheckFailed(ItemFailure.Rollback(false)), stopped(reason(Placeholder.RESTORE_STOP_ROOM_CHECK, seen = "Rollback")), true),
            Triple(RestoreStop.BatchRefused(2, "Personal", unreachable), stopped(reason(Placeholder.RESTORE_STOP_BATCH, seen = noAnswer)), true),
            Triple(RestoreStop.BatchRefused(2, "Personal", refused), stopped(reason(Placeholder.RESTORE_STOP_BATCH, seen = clean(code))), true),
            Triple(RestoreStop.BatchRefused(2, "Personal", ItemFailure.Halted), stopped(reason(Placeholder.RESTORE_STOP_BATCH, seen = "Halted")), true),
            // An item of the batch that does not read as an item: the same file stops there every time.
            Triple(RestoreStop.BatchRefused(2, "Personal", null), samePlace(reason(Placeholder.RESTORE_STOP_ITEM_UNREADABLE)), false),
            // Not proven to come back every time (it rests on this computer's record, which a sign-out removes).
            Triple(RestoreStop.AttachmentKeyUnopenable(name), stopped(reason(Placeholder.RESTORE_STOP_FILE_KEY, clean(name))), true),
            Triple(RestoreStop.AttachmentRefused(name, refused), stopped(reason(Placeholder.RESTORE_STOP_FILE_REFUSED, clean(name), seen = clean(code))), true),
            Triple(RestoreStop.AttachmentRefused(name, unreachable), stopped(reason(Placeholder.RESTORE_STOP_FILE_REFUSED, clean(name), seen = noAnswer)), true),
            Triple(RestoreStop.OtherVaultAnswered(name, "33333333-3333-4333-8333-333333333333"), stopped(reason(Placeholder.RESTORE_STOP_OTHER_VAULT, clean(name))), true),
            Triple(RestoreStop.VaultNotCreated(name, code), stopped(reason(Placeholder.RESTORE_STOP_VAULT_NOT_MADE, clean(name), seen = clean(code))), true),
            Triple(RestoreStop.KeyNotAdopted(name, code, null), stopped(reason(Placeholder.RESTORE_STOP_KEY_NOT_ADOPTED, clean(name), seen = clean(code))), true),
            Triple(RestoreStop.KeyNotAdopted(name, null, "Pending"), stopped(reason(Placeholder.RESTORE_STOP_KEY_NOT_ADOPTED, clean(name))), true),
            Triple(RestoreStop.AttachmentWrongSize(name), samePlace(reason(Placeholder.RESTORE_STOP_FILE_SIZE, clean(name))), false),
            Triple(RestoreStop.ItemUnreadable, samePlace(reason(Placeholder.RESTORE_STOP_ITEM_UNREADABLE)), false),
        )
        for ((stop, line, again) in cases) {
            val lines = drawnAt(f, stop)
            has(lines, line)
            assertEquals(again, "Try again" in lines, "$stop: $lines")
            noneRaw(lines)
        }
    }

    @Test
    fun aPartThatCannotBeReadKeepsItsOwnLine() {
        val w = world("stop-part")
        val f = flow(w, backup(1))
        val lines = drawnAt(f, RestoreStop.AttachmentUnreadable("p$evil", "wrong_passphrase_or_corrupt"))
        has(lines, ph(Placeholder.RESTORE_PART_UNREADABLE, clean("p$evil")))
        assertFalse("Try again" in lines)
        assertTrue(lines.none { it.startsWith("The restore stopped") }, "$lines")
    }
}
