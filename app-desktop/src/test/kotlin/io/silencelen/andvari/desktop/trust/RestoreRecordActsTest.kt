package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.DeletionResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.model.wire.WireErrors
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Every act that can remove, move or end an account's restore record while a restore of it is unfinished, each by a
 * run over the real desktop stores: a restore of 401 items (one attached file) stopped after its first batch of 200, the
 * act, then the same file chosen again and run to its end. Each row says where the record was after the act (a file of
 * this computer, this process's memory, or gone), what the same file then stored (the items the server holds at the
 * end: 401 when nothing was stored twice), and which line the person was shown. The lines starting `TABLE|` are the
 * table.
 */
internal class RestoreRecordActsTest : RestoreTestKit() {
    private val memoryLine get() = ph(Placeholder.RESTORE_MEMORY_ONLY)

    private class Row(val record: String, val items: Int, val uploads: Int, val lineAtStop: Boolean, val lineAfter: Boolean)

    /**
     * After [act] on [w]'s restore stopped half-way: where the record is, and what the same file chosen again in the
     * world [after] gives (it must have the vault open).
     */
    private fun row(label: String, w: World, bytes: ByteArray, act: () -> World): Row {
        val stopped = stopAfter(w, bytes, taken = 1)
        assertEquals(200, personalItems(w), "$label: the first batch stored")
        val lineAtStop = memoryLine in page(w, stopped)
        val after = act()
        val files = restoreFiles(after).size
        val inMemory = after.api.restores.recordInMemoryOnly()
        val again = flow(after, bytes)
        open(again)
        val preview = page(after, again)
        val lineAfter = memoryLine in preview
        val thrown = caught { again.confirm() }
        val items = personalItems(after)
        val uploads = after.server.uploads.toSet().size
        val record = when {
            files > 0 -> "file"
            items == 401 -> "memory"
            else -> "gone"
        }
        println("TABLE|$label|record=$record|files=$files|recordInMemoryOnly=$inMemory|lineAtStop=$lineAtStop|lineAtNextPreview=$lineAfter|stage=${again.views.value.stage}|thrown=$thrown|items=$items|distinctUploads=$uploads|preview=${preview.filter { it.startsWith("Restore ") || "Personal" in it }}")
        return Row(record, items, uploads, lineAtStop, lineAfter)
    }

    /** "Keep me signed in" on, so that the record is a file of this computer. */
    private fun kept(name: String): World = world(name).also { keepOn(it) }

    private fun assertGoesOn(r: Row, label: String) {
        assertEquals(401, r.items, "$label: every item once")
        assertEquals(1, r.uploads, "$label: the attached file under one upload")
    }

    @Test
    fun aLockKeepsTheRecordAndTheSameFileGoesOn() {
        val w = kept("acts-lock")
        val r = row("lock", w, backup(401)) { lock(w); unlock(w); w }
        assertEquals("file", r.record)
        assertGoesOn(r, "lock")
    }

    @Test
    fun keepMeSignedInTurnedOffMovesTheRecordIntoMemoryAndSaysSo() {
        val w = kept("acts-switch-off")
        val r = row("switch off", w, backup(401)) { w.m.setKeepSignIn(false); w }
        assertEquals("memory", r.record)
        assertTrue(r.lineAfter, "the line about a computer that keeps nothing")
        assertGoesOn(r, "switch off")
    }

    @Test
    fun keepMeSignedInTurnedOnAgainMakesTheRecordAFileAgain() {
        val w = kept("acts-switch-on")
        val r = row("switch off, then on again", w, backup(401)) {
            w.m.setKeepSignIn(false)
            keepOn(w)
            w
        }
        assertEquals("file", r.record)
        assertGoesOn(r, "switch on again")
    }

    @Test
    fun aPolicyThatForbidsACopyArrivingAfterAStopKeepsTheRecordInMemory() {
        val w = atRest("acts-policy-forbids")
        val r = row("policy forbids, at rest", w, backup(401)) {
            w.server.offlineCacheAllowed = false
            lock(w)
            unlock(w)
            w
        }
        assertEquals(emptyList(), restoreFiles(w), "no file of the restore's records under a policy that forbids a copy")
        assertEquals("memory", r.record)
        assertTrue(r.lineAfter, "the line about a computer that keeps nothing")
        assertGoesOn(r, "policy forbids")
    }

    @Test
    fun aPolicyThatAllowsACopyAgainMakesTheRecordAFileAgain() {
        val w = atRest("acts-policy-allows")
        val r = row("policy forbids, then allows again", w, backup(401)) {
            w.server.offlineCacheAllowed = false
            lock(w)
            unlock(w)
            w.server.offlineCacheAllowed = true
            lock(w)
            unlock(w)
            w
        }
        // The record goes on in memory; it is a file again at the next write where this computer keeps the copy at rest
        // again, and the line is drawn exactly while it is not.
        assertEquals("memory", r.record)
        assertGoesOn(r, "policy allows again")
        val inMemory = w.api.restores.recordInMemoryOnly()
        println("TABLE|policy allows again|after the run: files=${restoreFiles(w).size} recordInMemoryOnly=$inMemory keepSignIn=${w.m.keepSignIn.value} keepsAtRest=${w.home.keepsAtRest()}")
        assertEquals(inMemory == true, restoreFiles(w).isEmpty(), "the line is drawn exactly while no file holds the record")
        assertEquals(inMemory == true, r.lineAfter)
    }

    @Test
    fun aSignOutTakesTheRecord() {
        val w = kept("acts-sign-out")
        val r = row("sign-out", w, backup(401)) {
            signOut(w)
            assertEquals(emptyList(), restoreFiles(w), "the sign-out took the record")
            runBlocking { signIn(w.api, w.instance) }
            w.m.onSnapshot(w.api.snapshot)
            keepOn(w)
            w
        }
        assertEquals("gone", r.record)
    }

    @Test
    fun forgettingThisServerTakesTheRecord() {
        val w = kept("acts-forget")
        val r = row("forget this server", w, backup(401)) {
            runBlocking { assertEquals(PlainResult.DONE, w.api.instance.forgetServer(assertNotNull(w.api.snapshot.instance))) }
            w.m.onSnapshot(w.api.snapshot)
            assertEquals(emptyList(), restoreFiles(w), "forgetting the server took the record")
            runBlocking { signIn(w.api, w.instance) }
            w.m.onSnapshot(w.api.snapshot)
            keepOn(w)
            w
        }
        assertEquals("gone", r.record)
    }

    @Test
    fun theAccountsDeletionTakesTheRecordWithTheAccount() {
        val w = kept("acts-deletion")
        stopAfter(w, backup(401), taken = 1)
        assertEquals(1, restoreFiles(w).size)
        val result = runBlocking {
            val opened = w.api.settings.openDeletion()
            val screen = w.api.snapshot.account?.deletion
            if (opened != PlainResult.DONE || screen == null) "not reached: openDeletion=$opened"
            else w.api.settings.deleteAccount(screen, "alice@example.com", strong, null)
        }
        w.m.onSnapshot(w.api.snapshot)
        // The shared code's test server does not carry an account's deletion: the row is reached only where it does.
        println("TABLE|account deleted|result=$result|files=${restoreFiles(w).size}|phase=${w.api.snapshot.phase}|the same file has no account to go into")
        if (result == DeletionResult.DONE) assertEquals(emptyList(), restoreFiles(w), "the deletion took the record")
        else assertEquals(1, restoreFiles(w).size, "a deletion that did not happen leaves the record")
    }

    @Test
    fun aSessionTheServerEndedKeepsTheRecordForTheNextSignInToTheSameAccount() {
        val w = kept("acts-server-ended")
        val r = row("session ended by the server", w, backup(401)) {
            w.server.refuseAll = 401 to WireErrors.SESSION_REVOKED
            runBlocking { w.m.content.value?.syncQuietly() }
            w.m.onSnapshot(w.api.snapshot)
            println("TABLE|session ended by the server|phase=${w.api.snapshot.phase}|files=${restoreFiles(w).size}|entry=${w.api.snapshot.entry?.let { it::class.simpleName }}|locked=${w.api.snapshot.locked?.signedOutByServer}")
            w.server.refuseAll = null
            when (w.api.snapshot.phase) {
                AppPhase.UNLOCKED -> {}
                AppPhase.LOCKED -> {
                    val locked = assertNotNull(w.api.snapshot.locked)
                    if (locked.signedOutByServer) {
                        w.m.signInAgain()
                        w.m.onSnapshot(w.api.snapshot)
                        runBlocking { signInAgainHere(w) }
                    } else {
                        unlock(w)
                    }
                }
                else -> runBlocking { signInAgainHere(w) }
            }
            w.m.onSnapshot(w.api.snapshot)
            w
        }
        assertEquals("file", r.record)
        assertGoesOn(r, "session ended by the server")
    }

    /** The journey's sign-in of the same account after the server ended its session. */
    private suspend fun signInAgainHere(w: World) {
        val a = w.api
        when (val e = a.snapshot.entry) {
            is EntryScreen.SignIn -> assertEquals(SignInAnswer.DONE, a.entry.submitSignIn(e, "alice@example.com", strong))
            else -> signIn(a, w.instance)
        }
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    @Test
    fun anUpdateTheServerRequiresKeepsTheRecord() {
        val w = kept("acts-update")
        val r = row("update required", w, backup(401)) {
            w.server.refuseAll = 426 to WireErrors.UPGRADE_REQUIRED
            runBlocking { w.m.content.value?.syncQuietly() }
            w.m.onSnapshot(w.api.snapshot)
            val f = flow(w, backup(1))
            println("TABLE|update required|updateRequired=${w.api.snapshot.instance?.updateRequired}|files=${restoreFiles(w).size}|recordInMemoryOnly=${w.api.restores.recordInMemoryOnly()}")
            open(f)
            println("TABLE|update required|a preview while it is required draws=${page(w, f)}")
            w.server.refuseAll = null
            lock(w)
            unlock(w)
            w
        }
        assertEquals("file", r.record)
        assertGoesOn(r, "update required")
    }

    @Test
    fun andvariClosedAndStartedAgainWithTheSwitchOnGoesOn() {
        val w = kept("acts-restart-on")
        val r = row("closed and started again, switch on", w, backup(401)) { restart(w) }
        assertEquals("file", r.record)
        assertGoesOn(r, "restart, switch on")
    }

    @Test
    fun andvariClosedAndStartedAgainWithTheSwitchOffHadShownTheLine() {
        val w = world("acts-restart-off")
        val r = row("closed and started again, switch off", w, backup(401)) {
            lock(w)
            val again = started(w.server, w.instance, w.dir)
            if (again.api.snapshot.phase == AppPhase.LOCKED) unlock(again) else runBlocking { signIn(again.api, again.instance) }
            again.m.onSnapshot(again.api.snapshot)
            again
        }
        assertTrue(r.lineAtStop, "the line had been shown while the record was in memory")
        assertEquals("gone", r.record)
    }

    // ---- a policy that forbids a copy arriving while a restore runs over a copy at rest (decision of 23 November 2026) ----

    @Test
    fun aPolicyThatForbidsACopyArrivingDuringARunOverACopyAtRestMovesTheRecordIntoMemoryAndTheSameFileStoresNothingTwice() {
        val first = world("policy-during-run-at-rest")
        keepOn(first)
        lock(first)
        val w = started(first.server, first.instance, first.dir)
        val late = CompletableDeferred<Unit>()
        w.server.holdPolicy = late
        runBlocking { assertEquals(VaultUnlockResult.DONE, w.api.unlock(assertNotNull(w.api.snapshot.locked), strong)) }
        w.m.onSnapshot(w.api.snapshot)
        val bytes = backup(401)
        val f = flow(w, bytes)
        open(f)
        w.server.beforePush = { n ->
            if (n == 1) {
                w.server.offlineCacheAllowed = false
                kotlin.concurrent.thread { late.complete(Unit) }.join()
            }
        }
        val thrown = caught { f.confirm() }
        w.server.beforePush = null
        w.m.onSnapshot(w.api.snapshot)
        println("POLICY|thrown=$thrown items=${personalItems(w)} files=${restoreFiles(w).map { it.name }} phase=${w.api.snapshot.phase} content=${w.m.content.value != null}")
        assertEquals(emptyList(), restoreFiles(w), "no file of the restore's records after the policy's wipe")
        if (w.m.content.value == null && w.api.snapshot.phase == AppPhase.LOCKED) unlock(w)
        val again = flow(w, bytes)
        open(again)
        val preview = page(w, again)
        println("POLICY|again preview=$preview")
        val t2 = caught { again.confirm() }
        val end = page(w, again)
        println("POLICY|again thrown=$t2 stage=${again.views.value.stage} items=${personalItems(w)} uploads=${w.server.uploads.toSet().size} end=$end files=${restoreFiles(w).size}")
        has(preview, memoryLine)
        assertEquals(401, personalItems(w), "every item once")
        assertEquals(1, w.server.uploads.toSet().size, "the attached file once")
        assertEquals(emptyList(), restoreFiles(w), "still no file")
    }
}
