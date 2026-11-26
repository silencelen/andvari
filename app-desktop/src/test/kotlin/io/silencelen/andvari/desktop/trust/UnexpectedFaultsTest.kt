package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.DesktopAppApi
import io.silencelen.andvari.core.app.LockedScreen
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.content.VaultContent
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.client.items.VaultStanding
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Once (a vault whose name was the text of its own key made the shared code
 * throw at every sync, redraw and unlock, and the app's scope had no handler for it). The fake, through a thin wrapper
 * that makes it throw an unexpected exception, from a sync, an unlock and a redraw of one vault: the app stays up, what
 * went wrong is said in place (naming the vault for one vault's work), the other vault still works, a lock still locks,
 * and nothing of the exception's message is shown or logged.
 */
class UnexpectedFaultsTest {
    /** What reached the scope uncaught: on the desktop, the window's failure card. */
    private val crashes = ArrayList<Throwable>()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + CoroutineExceptionHandler { _, t -> crashes += t })
    private val logged = ArrayList<String>()

    /** The secret an exception's message carries in these tests: never shown, never logged. */
    private val secret = "SECRET-vault-key-0123456789abcdef"

    /** The fake, made to throw where a test says. */
    private class Faulty(val inner: FakeDesktopAppApi) : DesktopAppApi by inner {
        var unlockThrows: Throwable? = null
        var lockThrows: Throwable? = null
        var syncThrows: Throwable? = null

        /** A redraw of this vault throws: its name and its items' details. */
        var badVault: String? = null
        var badThrows: Throwable = IllegalStateException("bad")
        private var wrapped: Content? = null

        override suspend fun unlock(screen: LockedScreen, password: String): VaultUnlockResult = unlockThrows?.let { throw it } ?: inner.unlock(screen, password)

        override fun lock() {
            lockThrows?.let { lockThrows = null; throw it }
            inner.lock()
        }

        override val content: VaultContent?
            get() {
                val c = inner.content ?: return null
                return wrapped?.takeIf { it.inner === c } ?: Content(c).also { wrapped = it }
            }

        inner class Content(val inner: VaultContent) : VaultContent by inner {
            override suspend fun refresh() = syncThrows?.let { throw it } ?: inner.refresh()

            override fun vaultName(vaultId: String): String? = if (vaultId == badVault) throw badThrows else inner.vaultName(vaultId)

            override fun itemDetail(itemId: String) = inner.itemDetail(itemId)?.also { if (it.vaultId == badVault) throw badThrows }
        }
    }

    private fun open(): Triple<Faulty, TrustModel, FakeVaultContent> {
        val fake = FakeScenes.desktopAt(FakeScene.LOCKED)
        val api = Faulty(fake)
        val m = TrustModel(api, scope, { 0L }, SignInKeeping.Never, { 0L }, faultLog = { logged += it })
        m.onSnapshot(api.snapshot)
        unlock(api, m)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return Triple(api, m, assertNotNull(fake.fakeContent))
    }

    private fun unlock(api: Faulty, m: TrustModel) {
        m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
    }

    /** What the screen on show says: its placeholder and its values. */
    private fun saidHere(api: Faulty, m: TrustModel): UiText.Ph = assertIs<UiText.Ph>(assertNotNull(m.saidOn(api.snapshot), "said on the screen on show").text)

    private fun assertNothingOfTheMessage(m: TrustModel) {
        assertTrue(crashes.isEmpty(), "nothing crashed: $crashes")
        val shown = m.said.value?.text?.shown().orEmpty()
        assertFalse(secret in shown, "the message is not shown: $shown")
        for (line in logged) {
            assertFalse(secret in line, "the message is not logged: $line")
            assertTrue(line.startsWith("something went wrong :: "), "only the class name is logged: $line")
        }
    }

    @Test
    fun aSyncThatThrowsIsSaidInPlaceAndTheVaultTheOtherVaultsAndTheLockGoOn() {
        val (api, m, fake) = open()
        val item = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        api.syncThrows = IllegalStateException(secret)
        assertNotNull(m.syncNow()).let { runBlocking { it.join() } }
        val said = saidHere(api, m)
        assertEquals(Placeholder.SOMETHING_WENT_WRONG, said.placeholder)
        assertEquals(emptyList(), said.args, "nothing of the exception: its class name goes to the log only")
        assertEquals(listOf("something went wrong :: IllegalStateException"), logged)
        assertNothingOfTheMessage(m)
        // The app stays up: the vault is open and still reads.
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertEquals("Bank", assertNotNull(m.content.value).itemDetail(item)?.name)
        // A lock still locks.
        m.lockNow()
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertTrue(crashes.isEmpty())
    }

    @Test
    fun anUnlockThatThrowsIsSaidOnTheLockScreenAndTheNextUnlockOpens() {
        val (api, m, _) = open()
        m.lockNow()
        m.onSnapshot(api.snapshot)
        api.unlockThrows = RuntimeException(secret)
        unlock(api, m)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "nothing opened, nothing crashed")
        val said = saidHere(api, m)
        assertEquals(Placeholder.SOMETHING_WENT_WRONG, said.placeholder)
        assertEquals(emptyList(), said.args)
        assertNothingOfTheMessage(m)
        api.unlockThrows = null
        unlock(api, m)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "the app is still there: the next unlock opens")
        assertNull(m.saidOn(api.snapshot), "and the unlock clears what was said")
    }

    @Test
    fun aRedrawOfOneVaultThatThrowsNamesThatVaultAndTheOtherVaultStillDraws() {
        val (api, m, fake) = open()
        fake.addSharedVault("v-shared", "Trips", "owner", VaultStanding.VERIFIED)
        val mine = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        val theirs = fake.seedLogin("v-shared", "Hotel", "me", "pw", "https://hotel.example")
        api.badVault = "v-shared"
        api.badThrows = IllegalStateException(secret)
        val c = assertNotNull(m.content.value)
        val state = c.state
        // The screens' reads, as the item detail draws them: the vault named from what is already drawn.
        val name = vaultNamed(state, "v-shared")
        assertEquals("Trips", name)
        assertNull(Overtaken.read(m.fault, name, null) { c.vaultName("v-shared") }, "the read falls back")
        assertNull(Overtaken.read(m.fault, name, null) { c.itemDetail(theirs) })
        val said = saidHere(api, m)
        assertEquals(Placeholder.SOMETHING_WENT_WRONG_IN_VAULT, said.placeholder)
        assertEquals(listOf("Trips"), said.args, "it names the vault, in its one slot")
        // A redraw that throws again says nothing new and logs nothing new (no loop of redraws, no log once a second).
        val first = m.said.value
        Overtaken.read(m.fault, name, null) { c.vaultName("v-shared") }
        assertSame(first, m.said.value)
        assertEquals(1, logged.size, "$logged")
        assertNothingOfTheMessage(m)
        // The other vault still draws, and the app is open.
        assertEquals("Bank", Overtaken.read(m.fault, vaultNamed(state, FakeVaultContent.PERSONAL_VAULT_ID), null) { c.itemDetail(mine) }?.name)
        assertNotNull(Overtaken.read(m.fault, null, null) { c.vaultName(FakeVaultContent.PERSONAL_VAULT_ID) })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        // A lock still locks.
        m.lockNow()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertTrue(crashes.isEmpty())
    }

    @Test
    fun workAClickAndADrawingThatThrowAreFaultsAndTheLockKeepsItsOwnHandling() {
        val (api, m, _) = open()
        // A work scope's launch (the vault screens'), naming its vault.
        WorkScope(scope, m::lockOvertook, m.fault).launch("Trips") { throw IllegalArgumentException(secret) }
        assertEquals(Placeholder.SOMETHING_WENT_WRONG_IN_VAULT, saidHere(api, m).placeholder)
        // A click that calls the shared code at once.
        m.act { throw UnsupportedOperationException(secret) }
        assertEquals(Placeholder.SOMETHING_WENT_WRONG, saidHere(api, m).placeholder, "the click's fault replaces the vault's")
        assertEquals(emptyList(), saidHere(api, m).args)
        // A drawing's read that meets the keys gone falls back and starts nothing.
        assertEquals(3, Overtaken.read(m.fault, null, 3) { throw KeysGoneException() })
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNothingOfTheMessage(m)
        // The keys gone in a click is the lock, as before.
        m.act { throw KeysGoneException() }
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        assertEquals(Placeholder.LOCK_OVERTOOK, saidHere(api, m).placeholder)
        // A cancellation is neither: it is passed on.
        var passedOn = false
        try {
            Overtaken.act(m::lockOvertook, m.fault) { throw kotlinx.coroutines.CancellationException("left") }
        } catch (e: kotlinx.coroutines.CancellationException) {
            passedOn = true
        }
        assertTrue(passedOn)
    }

    @Test
    fun aLockThatThrowsIsSaidAndTheIdleLockKeepsTicking() {
        val (api, m, _) = open()
        api.lockThrows = IllegalStateException(secret)
        m.lockNow()
        assertEquals(Placeholder.SOMETHING_WENT_WRONG, saidHere(api, m).placeholder)
        assertNothingOfTheMessage(m)
        // The next lock (here the idle lock's tick, which never stopped) locks.
        var now = 0L
        val ticking = TrustModel(api, scope, { now }, SignInKeeping.Never, { now }, faultLog = { logged += it })
        ticking.onSnapshot(api.snapshot)
        api.lockThrows = IllegalStateException(secret)
        now += ticking.autoLockMs()
        ticking.tick()
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase, "that lock threw")
        ticking.tick()
        assertEquals(AppPhase.LOCKED, api.snapshot.phase, "the next tick locks")
        assertNothingOfTheMessage(ticking)
    }

    @Test
    fun whatEscapesTheSharedCodesOwnScopeIsSaidAndTheScopeGoesOn() {
        val (api, m, _) = open()
        val faults = TrustSeam.BackgroundFaults(onWindowThread = { it.run() })
        faults.model = m
        // The engine's scope, as the desktop builds it: its context carries the desktop's handler.
        val engineScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined + faults.handler)
        engineScope.launch { throw IllegalStateException(secret) }
        // Nothing on show asked for it: its own line, never "here, and nothing else was affected".
        assertEquals(Placeholder.SOMETHING_WENT_WRONG_IN_BACKGROUND, saidHere(api, m).placeholder)
        assertNothingOfTheMessage(m)
        var ranAfter = false
        engineScope.launch { ranAfter = true }
        assertTrue(ranAfter, "the scope goes on")
        // The keys gone there is a lock that already happened: nothing is done, so a vault open now stays open.
        m.clearSaid()
        engineScope.launch { throw KeysGoneException() }
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        assertNull(m.saidOn(api.snapshot))
        assertTrue(crashes.isEmpty())
    }

    /** Every place the desktop starts work in the shared code goes through a guard (read from the source). */
    @Test
    fun everyPlaceTheDesktopStartsSharedWorkIsGuarded() {
        fun src(f: String) = java.io.File("src/main/kotlin/io/silencelen/andvari/desktop/$f").readText()
        val main = src("Main.kt")
        assertTrue("LaunchedEffect(model) { model?.start() }" in main, "the start")
        assertTrue("model?.cameBack()" in main && "model?.wentAway()" in main && "model?.api?." !in main, "the window's focus, its minimising and hiding")
        val model = src("trust/TrustModel.kt")
        assertTrue("fun returnedToForeground() = quietly { api.returnedToForeground() }" in model && "fun wentAway() = quietly { api.wentAway() }" in model)
        assertFalse("failure.caught(\"start\"" in main)
        val seam = src("trust/TrustSeam.kt")
        assertTrue("main = SwingMain + faults.handler," in seam, "the engine's scope")
        assertTrue("CoroutineScope(SupervisorJob() + SwingMain + faults.handler)" in seam, "the model's scope")
        val ui = src("trust/TrustUi.kt")
        for (control in listOf("Button(onClick = guarded(onClick = onClick)", "OutlinedButton(onClick = guarded(onClick = onClick)", "TextButton(onClick = guarded(onClick = onClick)", "onValueChange = guardedChange(onChange = onChange)", "onClick = guarded(onClick = onSelect)")) {
            assertTrue(control in ui, control)
        }
        // No screen of the path holds a scope of its own: the work scope, or the model's.
        val dir = java.io.File("src/main/kotlin/io/silencelen/andvari/desktop/trust")
        for (f in dir.listFiles()!!.filter { it.name.endsWith("Screens.kt") }) {
            assertFalse("rememberCoroutineScope" in f.readText(), f.name)
        }
    }
}
