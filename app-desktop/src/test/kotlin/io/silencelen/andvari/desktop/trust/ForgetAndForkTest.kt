package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** "Forget this server" always asks, and the design's point 7 (what a fork offers). */
class ForgetAndForkTest {
    private val sources: Map<String, String> =
        File("src/main/kotlin").walkTopDown().filter { it.isFile && it.extension == "kt" }.associate { it.name to it.readText() }

    private fun body(src: String, fn: String): String = src.substringAfter("fun $fn(").substringBefore("\n}\n")

    private val entry get() = assertNotNull(sources["EntryScreens.kt"])
    private val account get() = assertNotNull(sources["AccountScreens.kt"])

    @Test
    fun everyForgetAsksTheSameQuestionFirst() {
        // Exactly one screen forgets this server, and one the other: each a confirm of the question, through the model's
        // own intent (a completed forget is a person's own end, which resets the switch).
        val forgets = sources.flatMap { (n, t) -> Regex("""\.forgetServer\(""").findAll(t).map { n }.toList() }.sorted()
        assertEquals(listOf("EntryScreens.kt", "TrustModel.kt"), forgets)
        assertTrue(body(entry, "ForgetServerQuestion").contains("model.forgetServer(instance)"))
        assertTrue(assertNotNull(sources["TrustModel.kt"]).contains("run({ this.instance.forgetServer(instance) }) { personEnded(it) }"))
        val others = sources.flatMap { (n, t) -> Regex("""\.forgetServerAtNewAddress\(""").findAll(t).map { n }.toList() }.sorted()
        assertEquals(listOf("EntryScreens.kt", "TrustModel.kt"), others)
        val other = body(entry, "ForgetOtherServerButton")
        assertTrue(other.indexOf("if (asking) ForgetQuestion(") in 0 until other.indexOf("forgetServerAtNewAddress("))

        // The card's button only opens the question.
        val button = body(entry, "ForgetServerButton")
        assertTrue(button.contains("{ asking = true }"))
        assertTrue(button.contains("if (asking) ForgetServerQuestion(model, instance)"))
        // The question: Cancel is the dismiss, and only its confirm forgets.
        val question = body(entry, "ForgetQuestion")
        assertTrue(question.contains("onDismissRequest = close"))
        assertTrue(question.contains("dismissButton = { DialogButton(UiText.of(CopyKey.CANCEL), onClick = close) }"))
        assertTrue(question.contains("Placeholder.FORGET_DELETES_COPY"))
        // Settings asks the same question.
        assertTrue(body(account, "ServerSection").contains("ForgetServerQuestion(model, instance)"))
        // Every card that offers it goes through the button: fork, damaged, unfinished move, the update notice.
        for (card in listOf(body(entry, "InstanceCard"), body(entry, "UnfinishedMoveCard"), body(assertNotNull(sources["TrustApp.kt"]), "UpdateNotice"))) {
            assertTrue(card.contains("ForgetServerButton(model, s, "), card.take(80))
        }
    }

    @Test
    fun aForkIsSeenSignedInAndLocked() {
        val stopped = FakeScenes.desktopAt(FakeScene.CARD_STOPPED)
        assertEquals(AppPhase.UNLOCKED, stopped.snapshot.phase)
        assertIs<InstanceCardState.Stopped>(assertNotNull(stopped.snapshot.instance).card)
        assertTrue(forked(stopped.snapshot))
        assertFalse(forked(FakeScenes.desktopAt(FakeScene.VAULTS).snapshot))
        val locked = FakeScenes.desktopAt(FakeScene.LOCKED_SERVER_STOPPED)
        assertEquals(AppPhase.LOCKED, locked.snapshot.phase)
        assertIs<InstanceCardState.Stopped>(assertNotNull(locked.snapshot.instance).card)
    }

    /** Design point 7: under a fork the only actions are reading, export and "Forget this server". */
    @Test
    fun underAForkOnlyReadingExportAndForgetAreOffered() {
        val pages = body(account, "SignedInPages")
        // The operator's console page also falls back to the vault for anyone but the operator.
        assertTrue(pages.contains("val page = if (fork || (wanted == SignedInPage.OPERATOR && !operator)) SignedInPage.VAULT else wanted"), "no Sharing or Settings page")
        val unforked = body(account, "AttentionArea").substringAfter("if (!fork) {")
        assertTrue(unforked.contains("PromptsSection(") && unforked.contains("KitAfterMoveCard("), "no prompts or cards that act")
        // The current app's toolbar: under a fork only the name and lock are left.
        val bar = body(account, "SignedInTopBar")
        val guardAt = bar.indexOf("if (!fork && c != null) {")
        assertTrue(guardAt in 0 until bar.indexOf("syncNow()"), "no sync")
        for (page in listOf("go(SignedInPage.SHARING)", "go(SignedInPage.SETTINGS)", "go(SignedInPage.OPERATOR)", "openTrash()", "requestImport()")) {
            assertTrue(guardAt < bar.indexOf(page), "no $page under a fork")
        }
        assertTrue(bar.indexOf("model.lockNow()") > bar.lastIndexOf("syncNow()"), "lock stays: it sends nothing")
        val lock = body(account, "LockScreen")
        assertTrue(lock.contains("if (instance?.card !is InstanceCardState.Stopped) SignOutButton(model, s)"), "no Sign out on the lock screen")
        val stoppedCase = lock.substringAfter("is InstanceCardState.Stopped -> {").substringBefore("is InstanceCardState.Damaged")
        assertTrue(stoppedCase.contains("ForgetServerButton(model, s, instance)"))
        // Nothing saves (the content's own stop), and the export stays on the vault page.
        assertTrue(assertNotNull(sources["VaultItemsScreens.kt"]).contains("internal fun canSaveState(state: ContentState): Boolean = !state.serverStopped"))
    }
}
