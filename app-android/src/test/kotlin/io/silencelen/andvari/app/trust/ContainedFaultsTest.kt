package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.launchOvertakable
import io.silencelen.andvari.core.app.ActionResult
import io.silencelen.andvari.core.app.AppApi
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.ItemSummary
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.VaultAccess
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.File
import java.security.SecureRandom
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * An exception that escapes the shared code's work
 * never takes the app down or leaves it unusable. The fake throws an unexpected exception from a sync, an unlock and a
 * redraw of one vault; the app stays up, says "something went wrong with this vault" (a placeholder, with nothing of the
 * exception), and every other vault and the rest of the app go on.
 */
class ContainedFaultsTest {
    /** What reached the scope uncaught: on the phone, a crash. */
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })

    /** A secret-looking message, to show it never reaches the screen. */
    private val secret = "hunter2-the-vault-key-text"

    @AfterTest
    fun noSink() {
        AppFaults.sink = null
    }

    /** The fake's content, with one vault ([bad]) whose reads and sync throw while [failing] is set. */
    private class OneBadVault(val inner: VaultContent, val bad: String, val secret: String) : VaultContent by inner {
        var failing = true

        private fun boom(): Nothing = throw IllegalStateException(secret)

        override fun vaultName(vaultId: String): String? = if (failing && vaultId == bad) boom() else inner.vaultName(vaultId)
        override fun heldItems(vaultId: String): List<ItemSummary> = if (failing && vaultId == bad) boom() else inner.heldItems(vaultId)
        override suspend fun renameSharedVault(vaultId: String, name: String): ActionResult =
            if (failing && vaultId == bad) boom() else inner.renameSharedVault(vaultId, name)
        override suspend fun saveVaultItemsToPersonal(vaultId: String): ActionResult =
            if (failing && vaultId == bad) boom() else inner.saveVaultItemsToPersonal(vaultId)
        override suspend fun refresh(): ActionResult = if (failing) boom() else inner.refresh()
        override suspend fun syncQuietly(): ActionResult = if (failing) boom() else inner.syncQuietly()
    }

    /** The fake app API, whose content is [OneBadVault] and whose next unlock can throw. */
    private class Faulty(val fake: FakeAppApi, val bad: String, val secret: String) : AppApi by fake {
        var unlockThrows = false
        private var wrapped: OneBadVault? = null

        override val content: VaultContent?
            get() {
                val c = fake.content ?: return null
                val w = wrapped
                return if (w != null && w.inner === c) w else OneBadVault(c, bad, secret).also { wrapped = it }
            }

        val bad0: OneBadVault get() = assertNotNull(content as? OneBadVault)

        override suspend fun unlock(screen: LockedScreen, password: String): VaultUnlockResult {
            if (unlockThrows) throw IllegalStateException(secret)
            return fake.unlock(screen, password)
        }
    }

    private fun openWithVaults(): Triple<Faulty, TrustModel, FakeVaultContent> {
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val api = Faulty(fake, BAD, secret)
        val m = TrustModel(api, scope, BuildConstants.JOIN_BASE, { 0L })
        AppFaults.sink = m::fault
        m.onSnapshot(api.snapshot)
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        val fc = assertNotNull(fake.fakeContent)
        fc.addSharedVault(BAD, "Family", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        fc.addSharedVault(GOOD, "Work", VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED)
        fc.seedNote(GOOD, "Door code", "1234")
        return Triple(api, m, fc)
    }

    private fun shownNothingOf(m: TrustModel, vararg texts: UiText?) {
        for (t in texts) assertFalse(t?.shown().orEmpty().contains(secret), "nothing of the exception is shown: ${t?.shown()}")
        assertFalse(m.wentWrong.value?.text?.shown().orEmpty().contains(secret))
    }

    @Test
    fun aSyncThatThrowsIsContainedSaidInPlaceAndTheAppGoesOn() {
        val (api, m, fc) = openWithVaults()
        val c = assertNotNull(m.content.value)
        var answer: ActionResult? = null
        // As the vault screens launch a sync: through the content, in the screens' launch helper.
        scope.launchOvertakable { answer = c.refresh() }
        assertTrue(crashes.isEmpty(), "no crash: $crashes")
        val failed = assertIs<ActionResult.Failed>(answer, "said in place, never done")
        assertEquals(UiText.ph(Placeholder.VAULT_WENT_WRONG).shown(), failed.message)
        assertFalse(failed.message.contains(secret))
        // The engine's own background sync (a ring, the opening): its scope carries the app's handler.
        val engineScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + AppFaults.handler())
        engineScope.launch { api.bad0.syncQuietly() }
        // The engine's sync names no vault: the general line, above the screen (copy page, PQ16).
        assertEquals(Placeholder.WENT_WRONG, (assertNotNull(m.wentWrong.value).text as UiText.Ph).placeholder, "said above the screen")
        shownNothingOf(m)
        // The rest goes on: the other vault reads, the app locks and unlocks, and the sync works again once the data does.
        assertEquals("Work", c.vaultName(GOOD))
        assertEquals(listOf("Door code"), c.state.items.map { it.name })
        api.bad0.failing = false
        assertIs<ActionResult.Ok>(runBlocking { c.refresh() })
        m.dismissWentWrong()
        assertNull(m.wentWrong.value)
        assertTrue(fc.state.vaults.any { it.vaultId == BAD })
        assertTrue(crashes.isEmpty())
    }

    @Test
    fun anUnlockThatThrowsIsSaidOnTheLockScreenAndTheNextUnlockOpens() {
        val (api, m, _) = openWithVaults()
        m.act { lock() }
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        api.unlockThrows = true
        var after = false
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) }) { after = true }
        assertTrue(crashes.isEmpty(), "no crash: $crashes")
        assertFalse(after, "nothing after it runs: the field keeps what was typed")
        val said = assertNotNull(m.saidOn(api.snapshot), "the lock screen says it")
        // Nothing is open while locked: the general line (copy page, PQ16).
        assertEquals(Placeholder.WENT_WRONG, assertIs<UiText.Ph>(said.text).placeholder)
        shownNothingOf(m, said.text)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the app is still there, at the lock screen")
        // The next unlock opens the vault, and its content works.
        api.unlockThrows = false
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNull(m.saidOn(api.snapshot))
        assertNotNull(m.content.value).let { assertEquals(listOf<ItemSummary>(), it.heldItems(GOOD)) }
        assertTrue(crashes.isEmpty())
    }

    @Test
    fun aRedrawOfOneVaultThatThrowsDrawsNothingForItAndEveryOtherVaultStillWorks() {
        val (api, m, _) = openWithVaults()
        val c = assertNotNull(m.content.value)
        // What the screens read while they draw: the bad vault's name and held rows answer "nothing", and it is said.
        assertNull(c.vaultName(BAD))
        assertEquals(emptyList(), c.heldItems(BAD))
        val w = assertNotNull(m.wentWrong.value)
        assertEquals(BAD, w.vaultId, "about that vault")
        assertEquals(Placeholder.VAULT_WENT_WRONG, assertIs<UiText.Ph>(w.text).placeholder)
        shownNothingOf(m)
        // Every other vault draws as before, and so does the personal one.
        assertEquals("Work", c.vaultName(GOOD))
        assertEquals("Personal", c.vaultName(FakeVaultContent.PERSONAL_VAULT_ID))
        assertEquals(listOf("Door code"), c.state.items.map { it.name })
        // Work on the bad vault answers in place; work on another is done.
        assertIs<ActionResult.Failed>(runBlocking { c.renameSharedVault(BAD, "Ours") })
        assertIs<ActionResult.Ok>(runBlocking { c.renameSharedVault(GOOD, "Office") })
        assertEquals("Office", c.vaultName(GOOD))
        // The rest of the app: the model's own work and a lock.
        m.act { lock() }
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertTrue(crashes.isEmpty(), "no crash: $crashes")
    }

    @Test
    fun theLockAndACancellationAreNeverContained() {
        val (_, m, _) = openWithVaults()
        val inner = object : VaultContent by assertNotNull(m.content.value as? GuardedContent).inner {
            override fun vaultName(vaultId: String): String? = throw KeysGoneException()
            override fun heldItems(vaultId: String): List<ItemSummary> = throw kotlinx.coroutines.CancellationException("ended")
        }
        val g = GuardedContent(inner) { error("not a fault") }
        assertFailsWith<KeysGoneException> { g.vaultName(GOOD) }
        assertFailsWith<kotlinx.coroutines.CancellationException> { g.heldItems(GOOD) }
        assertFalse(Contained.isFault(IllegalStateException("x", KeysGoneException())), "a wrapped lock is the lock")
        assertTrue(Contained.isFault(IllegalStateException("x")))
        // A handler for the engine's scope says a fault, and only a fault.
        var said = 0
        val engineScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + AppFaults.handler { said++ })
        engineScope.launch { throw KeysGoneException() }
        engineScope.launch { throw IllegalArgumentException(secret) }
        assertEquals(1, said)
    }

    @Test
    fun aFaultInTheModelsOwnWorkOrAPlainIntentIsContained() {
        val (api, m, _) = openWithVaults()
        m.act { throw IllegalStateException(secret) }
        val said = assertNotNull(m.saidOn(api.snapshot))
        // A plain intent names no vault: the general line, also while one is open (copy page, PQ16).
        assertEquals(Placeholder.WENT_WRONG, assertIs<UiText.Ph>(said.text).placeholder)
        shownNothingOf(m, said.text)
        // Signed out, the words are about what was asked, not a vault.
        val first = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.FIRST_RUN)
        val m2 = TrustModel(first, scope, BuildConstants.JOIN_BASE, { 0L })
        m2.act { throw IllegalStateException(secret) }
        assertEquals(Placeholder.WENT_WRONG, assertIs<UiText.Ph>(assertNotNull(m2.saidOn(first.snapshot)).text).placeholder)
        assertTrue(crashes.isEmpty(), "no crash: $crashes")
    }

    /** Every place the app starts the shared code's work goes through a containing path (source pins). */
    @Test
    fun everyPlaceTheAppStartsSharedWorkContainsAFault() {
        fun src(p: String) = File("src/main/kotlin/io/silencelen/andvari/app/$p").readText()
        val seam = src("trust/TrustSeam.kt")
        assertTrue(seam.contains("main = Dispatchers.Main.immediate + AppFaults.handler(),"), "the engine's own scope")
        assertTrue(seam.contains("CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate + AppFaults.handler())"), "the model's scope")
        assertTrue(seam.contains("AppFaults.sink = model::fault"))
        val model = src("trust/TrustModel.kt")
        assertTrue(model.contains("contentFlow.value = now?.let { GuardedContent(it, opening, ::fault) }"), "the screens' content")
        assertTrue(src("autofill/ContentFillSession.kt").contains("accessOf(model.api.snapshot, model.contentNow())"), "autofill's content")
        assertTrue(src("trust/TrustApp.kt").contains("model.returnedToForeground()"))
        assertFalse(src("trust/TrustApp.kt").contains("model.api.returnedToForeground()"))
        assertTrue(src("MainActivity.kt").contains("model.start()"))
        val unlock = src("autofill/AutofillUnlockActivity.kt")
        assertFalse(unlock.contains("t.javaClass.simpleName"), "the fill's unlock card names no exception class")
        // The screens launch work only through the helper, which contains a fault.
        for (f in File("src/main/kotlin/io/silencelen/andvari/app/trust").listFiles()!!.filter { it.name.endsWith(".kt") }) {
            val code = f.readText()
            assertFalse(Regex("scope\\.launch\\s*\\{").containsMatchIn(code) && f.name != "TrustModel.kt", "${f.name} launches work outside launchOvertakable")
        }
        assertTrue(src("Overtaken.kt").contains("io.silencelen.andvari.app.trust.Contained.isFault(t) -> onFault()"))
    }

    /**
     * At the app's level: a shared vault named with the text of its own key, holding an item
     * and a note whose content is that text too, shows, syncs and opens like any other. The fake's content is the real
     * shared content controller over a pretend server; the name lends of the engine (where the fault was) are beyond the
     * app's tests, and are the shared code's own test.
     */
    @Test
    fun aSharedVaultNamedWithTheTextOfItsOwnKeyShowsSyncsAndOpensLikeAnyOther() {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val forms = listOf(
            key.joinToString("") { "%02x".format(it) },
            Base64.getUrlEncoder().withoutPadding().encodeToString(key),
            Base64.getEncoder().encodeToString(key),
        )
        val fake = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.LOCKED)
        val m = TrustModel(fake, scope, BuildConstants.JOIN_BASE, { 0L })
        AppFaults.sink = m::fault
        fun unlock() {
            m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
            m.onSnapshot(fake.snapshot)
            assertEquals(AppPhase.UNLOCKED, fake.snapshot.phase, "it opens")
            val fc = assertNotNull(fake.fakeContent)
            forms.forEachIndexed { i, text ->
                fc.addSharedVault("keyed-$i", text, VaultAccess.ROLE_READER, VaultStanding.VERIFIED)
                fc.seedNote("keyed-$i", text, text)
            }
        }
        m.onSnapshot(fake.snapshot)
        repeat(2) { round ->
            unlock()
            val c = assertNotNull(m.content.value)
            forms.forEachIndexed { i, text ->
                assertEquals(text, c.vaultName("keyed-$i"), "shows, round $round")
                assertTrue(c.state.vaults.any { it.vaultId == "keyed-$i" && it.name == text })
            }
            assertEquals(forms.toSet(), c.state.items.map { it.name }.toSet(), "its items list")
            assertIs<ActionResult.Ok>(runBlocking { c.refresh() }, "syncs")
            assertIs<ActionResult.Ok>(runBlocking { c.syncQuietly() })
            val note = c.state.items.first { it.name == forms[0] }
            assertEquals(forms[0], assertNotNull(c.itemDetail(note.itemId)).name, "its item opens")
            assertEquals(forms[0], c.revealSecret(note.itemId, io.silencelen.andvari.core.app.SecretField.NOTES), "and its note")
            assertNull(m.wentWrong.value, "nothing went wrong")
            m.act { lock() }
            m.onSnapshot(fake.snapshot)
            assertEquals(AppPhase.LOCKED, fake.snapshot.phase)
        }
        assertTrue(crashes.isEmpty(), "no crash: $crashes")
    }

    private companion object {
        const val BAD = "vault-bad"
        const val GOOD = "vault-good"
    }
}
