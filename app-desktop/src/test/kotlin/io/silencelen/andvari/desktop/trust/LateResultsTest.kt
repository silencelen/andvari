package io.silencelen.andvari.desktop.trust

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.CopyLine
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.EntryApi
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.MoveStoredNotice
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.ReplacePasswordResult
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** The shared code's results and notices that are new since 2026-11-17, each drawn where it arrives. */
class LateResultsTest {
    private val dir = "src/main/kotlin/io/silencelen/andvari/desktop/trust/"
    private fun body(file: String, head: String) = File(dir + file).readText().substringAfter(head).substringBefore("\n}\n")
    private inline fun <reified T : EntryScreen> on(api: DesktopAppApi): T = assertIs<T>(api.snapshot.entry)

    /**
     * The fake never answers [ReplacePasswordResult.COMMITTED_NOT_OPENED]; here its recovery's last step answers it as the
     * engine does: the commit happened, nothing was opened, and the journey is back at the first screen.
     */
    private class CommitNotOpened(val fake: FakeDesktopAppApi) : DesktopAppApi by fake {
        override val entry: EntryApi = object : EntryApi by fake.entry {
            override suspend fun chooseReplacementPassword(screen: EntryScreen.ReplacePassword, password: String): ReplacePasswordResult {
                fake.entry.startOver()
                return ReplacePasswordResult.COMMITTED_NOT_OPENED
            }
        }
    }

    @Test
    fun aRecoveryCommittedAndNotOpenedHereIsSaidOnTheFirstScreen() {
        val fake = FakeScenes.desktopAt(FakeScene.FIRST_RUN)
        val api = CommitNotOpened(fake)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        val dee = fake.script.publicInstance.addAccount("dee@example.com", FakeScenes.PASSWORD)
        m.act { entry.openSignIn(on(api)) }
        m.act { entry.openForgot(on(api)) }
        m.act { entry.openKitEntry(on(api)) }
        m.run({ entry.submitKit(on(api), fake.script.kitOf(dee), PayloadSource.PASTED) })
        m.run({ entry.confirmKitRecovery(on(api)) })
        val replace = on<EntryScreen.ReplacePassword>(api)
        m.run({ entry.chooseReplacementPassword(replace, "a brand new master password") })
        assertEquals(AppPhase.ENTRY, api.snapshot.phase)
        on<EntryScreen.FirstRun>(api)
        val said = assertNotNull(m.saidOn(api.snapshot), "said where the person now is, not on the screen that is gone")
        assertSame(ReplacePasswordResult.COMMITTED_NOT_OPENED, said.result)
        assertEquals(UiText.of(CopyKey.RECOVERY_COMMITTED_NOT_OPENED).shown(), said.text.shown())
        assertTrue(isKeeperAnswer(ReplacePasswordResult.COMMITTED_NOT_OPENED))
        assertNull(wayOutOf(said.result, said.text, api.snapshot), "no way out but a sign-in with the new password")
    }

    /** From the members of Family, a move whose deletion the server stores later, outside the move: the notice. */
    private fun storedOutside(api: FakeDesktopAppApi, m: TrustModel): MoveStoredNotice {
        api.script.moveDeleteUnanswered = true
        val family = { assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" } }
        // The member who cannot be added to a new vault is the one removed, so that the old vault is not kept.
        m.run({ vaults.openMoveEverything(family()) })
        val cannot = assertNotNull(api.snapshot.account?.moving).members.first { !it.canBeAdded }.userId
        m.act { vaults.closeMoveEverything() }
        m.run({ vaults.openMembers(family()) })
        val member = assertNotNull(api.snapshot.account?.members).members.first { it.userId == cannot }
        m.run({ vaults.openMoveEverythingRemoving(member) })
        m.act { vaults.closeMembers() }
        m.run({ vaults.moveEverything(assertNotNull(api.snapshot.account?.moving), "Family 2") })
        m.act { vaults.closeMoveEverything() }
        assertTrue(api.script.serverStoresMoveDeleteLater(added = 2, changed = 1))
        return assertNotNull(api.snapshot.account).movesStoredOutside.single()
    }

    /**
     * A move's deletion stored outside the move: its notice above the vault, with the copy while it can be made, then how
     * many were copied, and the dismiss. The person's own waiting deletions that the move kept (now the usual outcome)
     * and those it carried are said with it; the fake never counts either, so those two lines are read on a notice made
     * as the shared code makes it.
     */
    @Test
    fun aMoveStoredOutsideTheMoveSaysWhatItKeptAndCarriedWithItsCopyAndDismiss() {
        val api = FakeScenes.desktopAt(FakeScene.VAULTS)
        val m = TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
        m.onSnapshot(api.snapshot)
        val notice = storedOutside(api, m)
        assertEquals(listOf(UiText.of(notice.line).shown()), moveStoredLines(notice).map { it.shown() })
        draw(m, api)
        m.run({ vaults.bringLateIntoMove(notice) })
        val copied = assertNotNull(api.snapshot.account).movesStoredOutside.single()
        assertEquals(listOf(copied.line, assertNotNull(copied.copiedLine)).map { UiText.of(it).shown() }, moveStoredLines(copied).map { it.shown() })
        draw(m, api)
        m.quietly { m.api.vaults.dismissMoveStored(copied) }
        assertEquals(emptyList(), assertNotNull(api.snapshot.account).movesStoredOutside)
        // Kept and carried deletions, on a notice as the shared code makes it (its constructor is the shared code's own).
        val kept = line(notice.line, CopyKey.MOVE_STORED_DELETIONS_KEPT, "2", "Family 2")
        val carried = line(notice.line, CopyKey.MOVE_STORED_DELETIONS_CARRIED, "1", "Family 2")
        val made = sharedCodesNotice(notice, carried, kept)
        assertEquals(listOf(notice.line, carried, kept).map { UiText.of(it).shown() }, moveStoredLines(made).map { it.shown() })
        // Drawn above the vault, with the vault's other notices; the copy only while it can be made and not yet made.
        val area = body("AccountScreens.kt", "private fun AttentionArea(")
        assertTrue(area.contains("for (notice in account.movesStoredOutside) MoveStoredCard(model, s, notice)"))
        val card = body("VaultScreens.kt", "internal fun MoveStoredCard(")
        assertTrue(card.contains("for (line in moveStoredLines(notice)) Say(line)"))
        assertTrue(card.contains("if (notice.canCopy && notice.copiedLine == null)"))
        assertTrue(card.contains("vaults.bringLateIntoMove(notice)") && card.contains("vaults.dismissMoveStored(notice)"))
    }

    /** A [CopyLine] of [key] with [values], rebuilt from [from], a line the shared code made (the fake never says these). */
    private fun line(from: CopyLine, key: CopyKey, vararg values: String): CopyLine =
        rebuilt(from, "key" to key, "values" to values.toList())

    /**
     * A [MoveStoredNotice] like [from] (the fake's, before any copy), with the two counts and their lines the fake never
     * sets; every other field, one the shared code adds among them, carried from [from].
     */
    private fun sharedCodesNotice(from: MoveStoredNotice, carried: CopyLine, kept: CopyLine): MoveStoredNotice {
        check(from.copiedLine == null) { "the notice before its copy" }
        return rebuilt(from, "deletionsCarried" to 1, "carriedLine" to carried, "deletionsKept" to 2, "keptLine" to kept)
    }

    private fun draw(m: TrustModel, api: FakeDesktopAppApi) {
        val scene = ImageComposeScene(760, 1400, Density(1f)) { MaterialTheme { TrustApp(m, null, "log") } }
        try {
            scene.render()
        } finally {
            scene.close()
        }
        assertTrue(api.snapshot.phase == AppPhase.UNLOCKED)
    }

    /** The account was made here and its session refused for a fault of its identity: a keeper's answer, with its kit. */
    @Test
    fun aRegistrationRefusedForItsIdentityIsAKeeperAnswer() {
        assertTrue(isKeeperAnswer(io.silencelen.andvari.core.app.CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT))
        assertEquals(CopyKey.KIT_REGISTERED_IDENTITY_FAULT, io.silencelen.andvari.core.app.CreateAccountResult.ACCOUNT_MADE_IDENTITY_FAULT.sentence)
    }
}
